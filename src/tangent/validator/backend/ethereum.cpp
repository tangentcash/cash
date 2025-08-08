#include "ethereum.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/bip32.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/utils.h"
#include "../internal/libbitcoin/ecc.h"
#include "../internal/libethereum/ecdsa.h"
#include "../internal/libethereum/rlp.h"
#include "../internal/libethereum/keccak256.h"
#include "../internal/libethereum/abi.h"
#include <secp256k1_recovery.h>
extern "C"
{
#include "../../internal/sha3.h"
}

namespace tangent
{
	namespace warden
	{
		namespace backends
		{
			void eth_rlp_uint256(eth_rlp* buffer, const uint256_t* value)
			{
				string hex = value->to_string(16);
				char* hex_data = (char*)hex.data();
				int hex_size = (int)hex.size();
				eth_rlp_hex(buffer, &hex_data, &hex_size);
			}
			void eth_rlp_address336(eth_rlp* buffer, string* value)
			{
				char* data = (char*)value->data();
				eth_rlp_address(buffer, &data);
			}
			void eth_rlp_binary(eth_rlp* buffer, const string* value)
			{
				if (!value->empty())
				{
					uint8_t* data = (uint8_t*)value->data();
					size_t size = value->size();
					eth_rlp_bytes(buffer, &data, &size);
				}
				else
				{
					uint8_t zero = 0;
					eth_rlp_uint8(buffer, &zero);
				}
			}
			void eth_abi_uint256(eth_abi* buffer, const uint256_t* value)
			{
				mpz_t numeric;
				mpz_init_set_str(numeric, value->to_string(16).c_str(), 16);
				eth_abi_mpint(buffer, numeric);
				mpz_clear(numeric);
			}
			void eth_abi_address336(eth_abi* buffer, const string* value)
			{
				char* data = (char*)value->data();
				eth_abi_address(buffer, &data);
			}
			void eth_abi_call_begin(eth_abi* buffer, const char* value)
			{
				eth_abi_call(buffer, (char**)&value, nullptr);
			}
			void eth_abi_to_bytes(eth_abi* buffer, string* value)
			{
				char* hex; size_t hex_size;
				eth_abi_to_hex(buffer, &hex, &hex_size);
				value->assign(hex, hex_size);
				*value = codec::hex_decode(*value);
				free(hex);
			}

			ethereum::evm_signature ethereum::evm_transaction::sign(const binary_data_t& raw_hash, const uint8_t private_key[32])
			{
				eth_ecdsa_signature raw_signature;
				if (eth_ecdsa_sign(&raw_signature, private_key, (uint8_t*)raw_hash.c_str()) != 1)
					return evm_signature();

				return presign(raw_signature.r, raw_signature.s, raw_signature.recid);
			}
			ethereum::evm_signature ethereum::evm_transaction::presign(const uint8_t signature_r[32], const uint8_t signature_s[32], int recovery_id)
			{
				evm_signature signature;
				signature.v = (uint32_t)recovery_id;
				signature.r = binary_data_t((char*)signature_r, 32);
				signature.s = binary_data_t((char*)signature_s, 32);
				return signature;
			}
			ethereum::evm_signed_transaction ethereum::evm_transaction::serialize_and_sign(evm_type type, const uint8_t private_key[32])
			{
				evm_signed_transaction transaction;
				transaction.signature = sign(hash(serialize(type)), private_key);
				if (transaction.signature.r.empty() || transaction.signature.s.empty())
					return transaction;

				transaction.data = serialize(type, &transaction.signature);
				transaction.id = hash(transaction.data);
				return transaction;
			}
			ethereum::evm_signed_transaction ethereum::evm_transaction::serialize_and_presign(evm_type type, const uint8_t signature[65])
			{
				evm_signed_transaction transaction;
				transaction.signature = presign(signature, signature + 32, signature[64]);
				if (transaction.signature.r.empty() || transaction.signature.s.empty())
					return transaction;

				transaction.data = serialize(type, &transaction.signature);
				transaction.id = hash(transaction.data);
				return transaction;
			}
			ethereum::binary_data_t ethereum::evm_transaction::serialize(evm_type type, evm_signature* signature)
			{
				eth_rlp buffer;
				eth_rlp_init(&buffer, ETH_RLP_ENCODE);
				switch (type)
				{
					case evm_type::eip_155:
					{
						eth_rlp_array(&buffer);
						eth_rlp_uint256(&buffer, &nonce);
						eth_rlp_uint256(&buffer, &gas_price);
						eth_rlp_uint256(&buffer, &gas_limit);
						eth_rlp_address336(&buffer, &address);
						eth_rlp_uint256(&buffer, &value);
						eth_rlp_binary(&buffer, &abi_data);
						if (signature)
						{
							uint256_t v = (uint32_t)chain_id * 2 + signature->v + 35;
							eth_rlp_uint256(&buffer, &v);
							eth_rlp_binary(&buffer, &signature->r);
							eth_rlp_binary(&buffer, &signature->s);
						}
						else
						{
							uint8_t zero = 0;
							eth_rlp_uint256(&buffer, &chain_id);
							eth_rlp_uint8(&buffer, &zero);
							eth_rlp_uint8(&buffer, &zero);
						}
						eth_rlp_array_end(&buffer);
						break;
					}
					case evm_type::eip_1559:
					{
						uint8_t transaction_type = 0x02;
						uint256_t max_fee_per_gas = gas_base_price > 0 ? gas_base_price : gas_price;
						uint256_t max_priority_fee_per_gas = gas_base_price > 0 ? gas_price - gas_base_price : uint256_t((uint8_t)0);
						eth_rlp_uint8(&buffer, &transaction_type);
						eth_rlp_array(&buffer);
						eth_rlp_uint256(&buffer, &chain_id);
						eth_rlp_uint256(&buffer, &nonce);
						eth_rlp_uint256(&buffer, &max_priority_fee_per_gas);
						eth_rlp_uint256(&buffer, &max_fee_per_gas);
						eth_rlp_uint256(&buffer, &gas_limit);
						eth_rlp_address336(&buffer, &address);
						eth_rlp_uint256(&buffer, &value);
						eth_rlp_binary(&buffer, &abi_data);
						eth_rlp_array(&buffer);
						eth_rlp_array_end(&buffer);
						if (signature)
						{
							uint8_t v = signature->v;
							eth_rlp_uint8(&buffer, &v);
							eth_rlp_binary(&buffer, &signature->r);
							eth_rlp_binary(&buffer, &signature->s);
						}
						eth_rlp_array_end(&buffer);
						break;
					}
					default:
						break;
				}

				uint8_t* serialized; size_t serialized_size;
				eth_rlp_to_bytes(&serialized, &serialized_size, &buffer);
				eth_rlp_free(&buffer);

				binary_data_t tx_data = binary_data_t((const char*)serialized, serialized_size);
				free(serialized);
				return tx_data;
			}
			ethereum::binary_data_t ethereum::evm_transaction::hash(const binary_data_t& serialized_data)
			{
				size_t serialized_size = serialized_data.size();
				uint8_t* serialized = memory::allocate<uint8_t>(sizeof(uint8_t) * serialized_size);
				memcpy(serialized, serialized_data.data(), sizeof(uint8_t) * serialized_size);

				uint8_t hash[32];
				eth_keccak256(hash, serialized, serialized_size);
				memory::deallocate(serialized);

				return binary_data_t((char*)hash, sizeof(hash));
			}

			const char* ethereum::sc_function::symbol()
			{
				return "symbol()";
			}
			const char* ethereum::sc_function::decimals()
			{
				return "decimals()";
			}
			const char* ethereum::sc_function::balance_of()
			{
				return "balanceOf(address)";
			}
			const char* ethereum::sc_function::transfer()
			{
				return "transfer(address,uint256)";
			}
			const char* ethereum::sc_function::transfer_from()
			{
				return "transferFrom(address,address,uint256)";
			}

			ethereum::binary_data_t ethereum::sc_call::symbol()
			{
				string raw_data;
				struct eth_abi evm;
				eth_abi_init(&evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&evm, sc_function::symbol());
				eth_abi_call_end(&evm);
				eth_abi_to_bytes(&evm, &raw_data);
				eth_abi_free(&evm);
				return raw_data;
			}
			ethereum::binary_data_t ethereum::sc_call::decimals()
			{
				string raw_data;
				struct eth_abi evm;
				eth_abi_init(&evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&evm, sc_function::decimals());
				eth_abi_call_end(&evm);
				eth_abi_to_bytes(&evm, &raw_data);
				eth_abi_free(&evm);
				return raw_data;
			}
			ethereum::binary_data_t ethereum::sc_call::balance_of(const string& address)
			{
				string raw_data;
				struct eth_abi evm;
				eth_abi_init(&evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&evm, sc_function::balance_of());
				eth_abi_address336(&evm, &address);
				eth_abi_call_end(&evm);
				eth_abi_to_bytes(&evm, &raw_data);
				eth_abi_free(&evm);
				return raw_data;
			}
			ethereum::binary_data_t ethereum::sc_call::transfer(const string& address, const uint256_t& value)
			{
				string raw_data;
				struct eth_abi evm;
				eth_abi_init(&evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&evm, sc_function::transfer());
				eth_abi_address336(&evm, &address);
				eth_abi_uint256(&evm, &value);
				eth_abi_call_end(&evm);
				eth_abi_to_bytes(&evm, &raw_data);
				eth_abi_free(&evm);
				return raw_data;
			}

			const char* ethereum::nd_call::get_block_by_number()
			{
				return "eth_getBlockByNumber";
			}
			const char* ethereum::nd_call::get_transaction_receipt()
			{
				return "eth_getTransactionReceipt";
			}
			const char* ethereum::nd_call::get_transaction_count()
			{
				return "eth_getTransactionCount";
			}
			const char* ethereum::nd_call::get_balance()
			{
				return "eth_getBalance";
			}
			const char* ethereum::nd_call::get_chain_id()
			{
				return "eth_chainId";
			}
			const char* ethereum::nd_call::block_number()
			{
				return "eth_blockNumber";
			}
			const char* ethereum::nd_call::estimate_gas()
			{
				return "eth_estimateGas";
			}
			const char* ethereum::nd_call::gas_price()
			{
				return "eth_gasPrice";
			}
			const char* ethereum::nd_call::call()
			{
				return "eth_call";
			}
			const char* ethereum::nd_call::send_raw_transaction()
			{
				return "eth_sendRawTransaction";
			}

			ethereum::ethereum(const algorithm::asset_id& new_asset) noexcept : relay_backend(new_asset)
			{
				netdata.composition = algorithm::composition::type::secp256k1;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 80;
				netdata.divisibility = decimal("1000000000000000000").truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "erc20";
				netdata.supports_bulk_transfer = false;
				netdata.requires_transaction_expiration = false;
				apply_address_to_symbol_whitelist(
				{
					{ "0xdAC17F958D2ee523a2206206994597C13D831ec7", "USDT" },
					{ "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "USDC" }
				});
			}
			expects_promise_rt<schema*> ethereum::get_transaction_receipt(const std::string_view& transaction_id)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(transaction_id)));

				auto tx_data = coawait(execute_rpc(nd_call::get_transaction_receipt(), std::move(map), cache_policy::blob_cache));
				if (tx_data && (tx_data->value.is(var_type::null) || tx_data->value.is(var_type::undefined)))
					coreturn remote_exception("receipt not found");

				coreturn tx_data;
			}
			expects_promise_rt<uint256_t> ethereum::get_transactions_count(const std::string_view& address)
			{
				schema_list latest_map;
				latest_map.emplace_back(var::set::string(decode_non_eth_address(address)));
				latest_map.emplace_back(var::set::string("latest"));

				auto latest_transaction_count = coawait(execute_rpc(nd_call::get_transaction_count(), std::move(latest_map), cache_policy::no_cache));
				if (!latest_transaction_count)
					coreturn expects_rt<uint256_t>(std::move(latest_transaction_count.error()));

				uint256_t transactions_count = hex_to_uint256(latest_transaction_count->value.get_blob());
				memory::release(*latest_transaction_count);

				schema_list pending_map;
				pending_map.emplace_back(var::set::string(decode_non_eth_address(address)));
				pending_map.emplace_back(var::set::string("pending"));

				auto pending_transaction_count = uptr<schema>(coawait(execute_rpc(nd_call::get_transaction_count(), std::move(pending_map), cache_policy::no_cache)));
				if (pending_transaction_count)
				{
					uint256_t pending_transactions_count = hex_to_uint256(pending_transaction_count->value.get_blob());
					if (pending_transactions_count > transactions_count)
						transactions_count = pending_transactions_count;
				}

				coreturn expects_rt<uint256_t>(std::move(transactions_count));
			}
			expects_promise_rt<uint256_t> ethereum::get_chain_id()
			{
				auto hex_chain_id = coawait(execute_rpc(nd_call::get_chain_id(), { }, cache_policy::lifetime_cache));
				if (!hex_chain_id)
					coreturn expects_rt<uint256_t>(std::move(hex_chain_id.error()));

				uint256_t chain_id = hex_to_uint256(hex_chain_id->value.get_blob());
				memory::release(*hex_chain_id);
				coreturn expects_rt<uint256_t>(std::move(chain_id));
			}
			expects_promise_rt<string> ethereum::get_contract_symbol(const std::string_view& contract_address)
			{
				uptr<schema> params = var::set::object();
				params->set("to", var::string(decode_non_eth_address(contract_address)));
				params->set("data", var::string(encode_0xhex(backends::ethereum::sc_call::symbol())));

				schema_list map;
				map.emplace_back(std::move(params));
				map.emplace_back(var::set::string("latest"));

				auto symbol = coawait(execute_rpc(nd_call::call(), std::move(map), cache_policy::lifetime_cache));
				if (!symbol)
					coreturn expects_rt<string>(std::move(symbol.error()));

				struct eth_abi evm;
				eth_abi_init(&evm, ETH_ABI_DECODE);
				eth_abi_from_hex(&evm, (char*)symbol->value.get_string().data(), (int)symbol->value.get_string().size());

				uint8_t* bytes; size_t bytes_size;
				bool has_bytes = eth_abi_bytes(&evm, &bytes, &bytes_size) == 1;
				eth_abi_free(&evm);
				if (!has_bytes)
					coreturn expects_rt<string>(symbol->value.get_blob());

				string result = string((char*)bytes, bytes_size);
				free(bytes);
				coreturn expects_rt<string>(std::move(result));
			}
			expects_promise_rt<decimal> ethereum::get_contract_divisibility(const std::string_view& contract_address)
			{
				uptr<schema> params = var::set::object();
				params->set("to", var::string(decode_non_eth_address(contract_address)));
				params->set("data", var::string(encode_0xhex(backends::ethereum::sc_call::decimals())));

				schema_list map;
				map.emplace_back(std::move(params));
				map.emplace_back(var::set::string("latest"));

				auto decimals = coawait(execute_rpc(nd_call::call(), std::move(map), cache_policy::lifetime_cache));
				if (!decimals)
					coreturn expects_rt<decimal>(std::move(decimals.error()));

				uint64_t divisibility = 1;
				uint64_t value = std::min<uint64_t>((uint64_t)hex_to_uint256(decimals->value.get_blob()), protocol::now().message.precision);
				for (uint64_t i = 0; i < value; i++)
					divisibility *= 10;
				coreturn expects_rt<decimal>(decimal(divisibility));
			}
			expects_promise_rt<uint64_t> ethereum::get_latest_block_height()
			{
				auto block_count = coawait(execute_rpc(nd_call::block_number(), { }, cache_policy::no_cache));
				if (!block_count)
					coreturn expects_rt<uint64_t>(std::move(block_count.error()));

				uint64_t block_height = (uint64_t)hex_to_uint256(block_count->value.get_blob());
				memory::release(*block_count);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> ethereum::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				schema_list map;
				map.emplace_back(var::set::string(uint256_to_hex(block_height)));
				map.emplace_back(var::set::boolean(true));

				auto block_data = coawait(execute_rpc(nd_call::get_block_by_number(), std::move(map), cache_policy::temporary_cache));
				if (!block_data)
					coreturn block_data;

				legacy.eip_155 = block_data->has("baseFeePerGas") ? 0 : 1;
				if (block_hash != nullptr)
					*block_hash = block_data->get_var("hash").get_blob();

				auto* transactions = block_data->get("transactions");
				if (!transactions)
				{
					memory::release(*block_data);
					coreturn expects_rt<schema*>(remote_exception("transactions field not found"));
				}

				transactions->unlink();
				memory::release(*block_data);
				if (!legacy.get_logs)
				{
					auto* query = var::set::array();
					auto* cursor = query->push(var::set::object());
					cursor->set("fromBlock", var::set::string(uint256_to_hex(block_height)));
					cursor->set("toBlock", var::set::string(uint256_to_hex(block_height)));
					cursor->set("topics", var::set::array())->push(var::string(get_token_transfer_signature()));

					schema_list map;
					map.emplace_back(query);

					auto logs_data = coawait(execute_rpc(nd_call::get_block_by_number(), std::move(map), cache_policy::temporary_cache));
					if (logs_data)
					{
						auto* logs = logs_data->get("result");
						if (logs != nullptr && !logs->empty())
						{
							unordered_map<string, schema*> indices;
							for (auto& item : transactions->get_childs())
							{
								string tx_hash = item->get_var("hash").get_blob();
								indices[tx_hash] = item;
							}

							for (auto& item : logs->get_childs())
							{
								string tx_hash = item->get_var("transactionHash").get_blob();
								auto it = indices.find(tx_hash);
								if (it != indices.end())
									it->second->set("logs", item->copy());
							}
						}
						memory::release(*logs_data);
					}
					else
						legacy.get_logs = 1;
				}
				coreturn expects_rt<schema*>(transactions);
			}
			expects_promise_rt<computed_transaction> ethereum::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* chain = get_chain();
				string data = transaction_data->get_var("input").get_blob();
				if (stringify::starts_with(data, chain->bech32_hrp))
					data.erase(0, strlen(chain->bech32_hrp));

				string tx_hash = transaction_data->get_var("hash").get_blob();
				string from = encode_eth_address(transaction_data->get_var("from").get_blob());
				string to = encode_eth_address(transaction_data->get_var("to").get_blob());
				decimal gas_price = to_eth(hex_to_uint256(transaction_data->get_var("gasPrice").get_blob()), get_divisibility_gwei());
				decimal gas_limit = to_eth(hex_to_uint256(get_raw_gas_limit(transaction_data)), get_divisibility_gwei());
				decimal base_value = to_eth(hex_to_uint256(transaction_data->get_var("value").get_blob()), netdata.divisibility);
				decimal fee_value = gas_price * gas_limit;
				decimal total_value = base_value + fee_value;

				computed_transaction result;
				result.transaction_id = tx_hash;
				
				unordered_map<string, unordered_map<algorithm::asset_id, decimal>> inputs;
				unordered_map<string, unordered_map<algorithm::asset_id, decimal>> outputs;
				if (total_value.is_positive())
				{
					inputs[from][native_asset] = total_value;
					outputs[to][native_asset] = base_value;
				}

				if (!data.empty())
				{
					auto* logs = transaction_data->get("logs");
					if (!logs)
					{
						auto tx_receipt = coawait(get_transaction_receipt(transaction_data->get_var("hash").get_blob()));
						if (tx_receipt)
						{
							logs = tx_receipt->get("logs");
							if (logs != nullptr)
							{
								logs->unlink();
								transaction_data->set("logs", logs);
							}
							transaction_data->set("receipt", *tx_receipt);
						}
						else
							transaction_data->set("receipt", var::set::null());
					}

					if (logs != nullptr && !logs->empty())
					{
						for (auto& invocation : logs->get_childs())
						{
							auto* topics = invocation->get("topics");
							auto contract_address = encode_eth_address(invocation->get_var("address").get_blob());
							if (!topics || (topics->size() != 2 && topics->size() != 3) || !is_token_transfer(topics->get_var(0).get_blob()))
								continue;

							auto symbol = coawait(get_contract_symbol(contract_address));
							if (!symbol)
								continue;

							auto token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), *symbol, contract_address);
							decimal divisibility = coawait(get_contract_divisibility(contract_address)).or_else(netdata.divisibility);
							decimal token_value = to_eth(hex_to_uint256(invocation->get_var("data").get_blob()), divisibility);
							if (topics->size() == 3)
							{
								from = encode_eth_address(normalize_topic_address(topics->get_var(1).get_blob()));
								to = encode_eth_address(normalize_topic_address(topics->get_var(2).get_blob()));
							}
							else if (topics->size() == 2)
								to = encode_eth_address(topics->get_var(1).get_blob());

							auto& token_input = inputs[from][token_asset], token_output = outputs[to][token_asset];
							token_input = token_input.is_nan() ? token_value : (token_input + token_value);
							token_output = token_output.is_nan() ? token_value : (token_output + token_value);
							nss::server_node::get()->enable_contract_address(token_asset, contract_address);
						}
					}
				}

				unordered_set<string> addresses;
				addresses.reserve(inputs.size() + outputs.size());
				for (auto& next : inputs)
					addresses.insert(next.first);
				for (auto& next : outputs)
					addresses.insert(next.first);

				auto discovery = find_linked_addresses(addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				schema* tx_receipt_cache = transaction_data->get("receipt");
				schema* tx_receipt = tx_receipt_cache ? tx_receipt_cache : coawait(get_transaction_receipt(tx_hash)).or_else(nullptr);
				bool is_reverted = tx_receipt && tx_receipt->value.is_object() ? hex_to_uint256(tx_receipt->get_var("status").get_blob()) < 1 : true;
				if (is_reverted)
					coreturn expects_rt<computed_transaction>(remote_exception("tx reverted"));

				result.inputs.reserve(inputs.size());
				for (auto& [address, values] : inputs)
				{
					auto target_link = discovery->find(address);
					result.inputs.push_back(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
				}

				result.outputs.reserve(outputs.size());
				for (auto& [address, values] : outputs)
				{
					auto target_link = discovery->find(address);
					result.outputs.push_back(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
				}

				coreturn expects_rt<computed_transaction>(std::move(result));
			}
			expects_promise_rt<computed_fee> ethereum::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				uint256_t vgas_base_price = 0;
				if (!legacy.eip_155)
				{
					auto block_number = coawait(get_latest_block_height());
					if (!block_number)
						coreturn expects_rt<computed_fee>(std::move(block_number.error()));

					schema_list map;
					map.emplace_back(var::set::string(uint256_to_hex(*block_number)));
					map.emplace_back(var::set::boolean(false));

					auto block_data = coawait(execute_rpc(nd_call::get_block_by_number(), std::move(map), cache_policy::temporary_cache));
					if (!block_data)
						coreturn expects_rt<computed_fee>(std::move(block_data.error()));

					auto value = block_data->get("baseFeePerGas");
					if (value)
						vgas_base_price = hex_to_uint256(value->value.get_blob());
					else
						legacy.eip_155 = 1;
				}

				auto gas_price_estimate = coawait(execute_rpc(nd_call::gas_price(), { }, cache_policy::no_cache_no_throttling));
				if (!gas_price_estimate)
					coreturn expects_rt<computed_fee>(std::move(gas_price_estimate.error()));

				auto& output = to.front();
				uptr<schema> params = var::set::object();
				params->set("gasPrice", var::string(gas_price_estimate->value.get_blob()));
				params->set("from", var::string(decode_non_eth_address(from_address)));

				auto contract_address = nss::server_node::get()->get_contract_address(output.asset);
				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				uint64_t default_gas_limit;
				uint256_t value = from_eth(output.value, divisibility);
				if (contract_address)
				{
					default_gas_limit = get_erc20_transfer_gas_limit_gwei();
					params->set("to", var::string(decode_non_eth_address(*contract_address)));
					params->set("value", var::string(uint256_to_hex(0)));
					params->set("gas", var::string(uint256_to_hex(default_gas_limit)));
					params->set("data", var::string(encode_0xhex(backends::ethereum::sc_call::transfer(decode_non_eth_address(output.address), value))));
				}
				else
				{
					default_gas_limit = get_eth_transfer_gas_limit_gwei();
					params->set("to", var::string(decode_non_eth_address(output.address)));
					params->set("value", var::string(uint256_to_hex(value)));
					params->set("gas", var::string(uint256_to_hex(default_gas_limit)));
				}

				schema_list map;
				map.emplace_back(std::move(params));
				if (!legacy.estimate_gas)
					map.emplace_back(var::set::string("latest"));

				decimal gas_base_price = to_eth(vgas_base_price, netdata.divisibility);
				auto gas_limit_estimate = uptr<schema>(coawait(execute_rpc(nd_call::estimate_gas(), std::move(map), cache_policy::no_cache_no_throttling)));
				if (!gas_limit_estimate)
				{
					decimal gas_price = to_eth(hex_to_uint256(gas_price_estimate->value.get_blob()), netdata.divisibility);
					memory::release(*gas_price_estimate);
					coreturn expects_rt<computed_fee>(computed_fee::fee_per_gas_priority(gas_base_price, gas_price, default_gas_limit));
				}

				uint256_t vgas_price = hex_to_uint256(gas_price_estimate->value.get_blob());
				uint256_t vgas_limit = hex_to_uint256(gas_limit_estimate->value.get_blob());
				decimal gas_price = to_eth(vgas_price, netdata.divisibility);
				memory::release(*gas_price_estimate);
				coreturn expects_rt<computed_fee>(computed_fee::fee_per_gas_priority(gas_base_price, gas_price, vgas_limit > 0 ? vgas_limit : uint256_t(default_gas_limit)));
			}
			expects_promise_rt<decimal> ethereum::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				auto contract_address = nss::server_node::get()->get_contract_address(for_asset);
				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				const char* method = nullptr;
				schema* params = nullptr;
				if (contract_address)
				{
					method = nd_call::call();
					params = var::set::object();
					params->set("to", var::string(decode_non_eth_address(*contract_address)));
					params->set("data", var::string(encode_0xhex(backends::ethereum::sc_call::balance_of(decode_non_eth_address(link.address)))));
				}
				else
				{
					method = nd_call::get_balance();
					params = var::set::string(decode_non_eth_address(link.address));
				}

				schema_list map;
				map.emplace_back(params);
				map.emplace_back(var::set::string("latest"));

				auto confirmed_balance = coawait(execute_rpc(method, std::move(map), cache_policy::no_cache));
				if (!confirmed_balance)
					coreturn expects_rt<decimal>(std::move(confirmed_balance.error()));

				decimal balance = to_eth(hex_to_uint256(confirmed_balance->value.get_blob()), divisibility);
				memory::release(*confirmed_balance);
				coreturn expects_rt<decimal>(std::move(balance));
			}
			expects_promise_rt<void> ethereum::broadcast_transaction(const finalized_transaction& finalized)
			{
				auto duplicate = coawait(get_transaction_receipt(format::util::assign_0xhex(finalized.hashdata)));
				if (duplicate)
				{
					memory::release(*duplicate);
					coreturn expects_rt<void>(expectation::met);
				}

				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(finalized.calldata)));

				auto hex_data = coawait(execute_rpc(nd_call::send_raw_transaction(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				memory::release(*hex_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> ethereum::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto chain_id = coawait(get_chain_id());
				if (!chain_id)
					coreturn expects_rt<prepared_transaction>(std::move(chain_id.error()));

				auto& output = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(output.asset);
				decimal fee_value = fee.get_max_fee();
				decimal total_value = output.value;
				if (contract_address)
				{
					auto balance = coawait(calculate_balance(output.asset, from_link));
					if (!balance || *balance < fee_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}
				else if (!algorithm::asset::token_of(output.asset).empty())
					coreturn expects_rt<prepared_transaction>(remote_exception("invalid sending token"));
				else
					total_value += fee_value;

				auto balance = coawait(calculate_balance(output.asset, from_link));
				if (!balance || *balance < total_value)
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

				auto nonce = coawait(get_transactions_count(from_link.address));
				if (!nonce)
					coreturn expects_rt<prepared_transaction>(remote_exception("nonce value invalid"));

				evm_transaction transaction;
				transaction.nonce = *nonce;
				transaction.chain_id = *chain_id;
				transaction.gas_base_price = from_eth(fee.gas.gas_base_price, netdata.divisibility);
				transaction.gas_price = from_eth(fee.gas.gas_price, netdata.divisibility);
				transaction.gas_limit = fee.gas.gas_limit;

				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
					if (contract_divisibility)
						divisibility = std::move(*contract_divisibility);

					transaction.address = decode_non_eth_address(*contract_address);
					transaction.abi_data = sc_call::transfer(output.address, from_eth(output.value, divisibility));
				}
				else
				{
					transaction.address = decode_non_eth_address(output.address);
					transaction.value = from_eth(output.value, divisibility);
				}

				auto public_key = to_composite_public_key(from_link.public_key);
				if (!public_key)
					coreturn expects_rt<prepared_transaction>(remote_exception(std::move(public_key.error().message())));

				legacy.eip_155 = 0;
				auto type = legacy.eip_155 ? evm_transaction::evm_type::eip_155 : evm_transaction::evm_type::eip_1559;
				auto hash = transaction.hash(transaction.serialize(type));
				prepared_transaction result;
				if (contract_address)
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), public_key->data, (uint8_t*)hash.data(), hash.size(), { { output.asset, output.value }, { native_asset, fee_value } });
				else
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), public_key->data, (uint8_t*)hash.data(), hash.size(), { { native_asset, output.value + fee_value } });
				result.requires_account_output(output.address, { { output.asset, output.value } });
				result.requires_abi(format::variable(!!legacy.eip_155));
				result.requires_abi(format::variable(contract_address.or_else(string())));
				result.requires_abi(format::variable(divisibility));
				result.requires_abi(format::variable(transaction.nonce));
				result.requires_abi(format::variable(transaction.chain_id));
				result.requires_abi(format::variable(transaction.gas_base_price));
				result.requires_abi(format::variable(transaction.gas_price));
				result.requires_abi(format::variable(transaction.gas_limit));
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> ethereum::finalize_transaction(warden::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 8)
					return layer_exception("invalid prepared abi");

				auto& input = prepared.inputs.front();
				auto& output = prepared.outputs.front();
				auto output_asset = output.get_asset(native_asset);
				auto type = prepared.abi[0].as_boolean() ? evm_transaction::evm_type::eip_155 : evm_transaction::evm_type::eip_1559;
				auto contract_address = prepared.abi[1].as_string();
				auto divisibility = prepared.abi[2].as_decimal();
				if (algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), algorithm::asset::token_of(output.get_asset(native_asset)), contract_address) != output_asset)
					return layer_exception("invalid prepared abi");

				evm_transaction transaction;
				transaction.nonce = prepared.abi[3].as_uint256();
				transaction.chain_id = prepared.abi[4].as_uint256();
				transaction.gas_base_price = prepared.abi[5].as_uint256();
				transaction.gas_price = prepared.abi[6].as_uint256();
				transaction.gas_limit = prepared.abi[7].as_uint256();
				if (!contract_address.empty())
				{
					if (output.tokens.empty())
						return layer_exception("invalid output");

					auto& output_token = output.tokens.front();
					transaction.address = decode_non_eth_address(contract_address);
					transaction.abi_data = sc_call::transfer(output.link.address, from_eth(output_token.value, divisibility));
				}
				else
				{
					transaction.address = decode_non_eth_address(output.link.address);
					transaction.value = from_eth(output.value, divisibility);
				}

				auto hash = transaction.hash(transaction.serialize(type));
				if (input.message.size() != hash.size() || memcmp(input.message.data(), hash.data(), hash.size()) != 0)
					return layer_exception("invalid input message");

				auto info = transaction.serialize_and_presign(type, input.signature);
				auto result = finalized_transaction(std::move(prepared), encode_0xhex(info.data), encode_0xhex(info.id));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<secret_box> ethereum::encode_secret_key(const secret_box& secret_key)
			{
				auto chain = get_chain();
				char result[128] = { 0 };
				size_t offset = strnlen(chain->bech32_hrp, sizeof(chain->bech32_hrp));
				memcpy(result, chain->bech32_hrp, offset);

				auto data = secret_key.expose<KEY_LIMIT>();
				utils_bin_to_hex(data.buffer, data.view.size(), result + offset);
				return secret_box::secure(std::string_view(result, strnlen(result, sizeof(result))));
			}
			expects_lr<secret_box> ethereum::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				size_t offset = data.view.starts_with("0x") ? 2 : 0;
				uint8_t result[64] = { 0 }; int result_size = (int)sizeof(result);
				utils_hex_to_bin(data.view.data() + offset, result, (int)data.view.size() - (int)offset, &result_size);
				if (result_size != BTC_ECKEY_PKEY_LENGTH)
					return layer_exception("invalid private key");

				return secret_box::secure(std::string_view((char*)result, (size_t)result_size));
			}
			expects_lr<string> ethereum::encode_public_key(const std::string_view& public_key)
			{
				if (public_key.size() == BTC_ECKEY_UNCOMPRESSED_LENGTH)
					return format::util::encode_0xhex(public_key.substr(1));
				else if (public_key.size() == BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
					return format::util::encode_0xhex(public_key);
				else if (public_key.size() != BTC_ECKEY_COMPRESSED_LENGTH)
					return layer_exception("invalid public key size");

				secp256k1_pubkey candidate_public_key;
				secp256k1_context* context = algorithm::signing::get_context();
				if (secp256k1_ec_pubkey_parse(context, &candidate_public_key, (uint8_t*)public_key.data(), public_key.size()) != 1)
					return layer_exception("invalid public key");

				uint8_t raw_public_key[BTC_ECKEY_UNCOMPRESSED_LENGTH] = { 0 };
				size_t raw_public_key_size = sizeof(raw_public_key);
				if (secp256k1_ec_pubkey_serialize(context, raw_public_key, &raw_public_key_size, &candidate_public_key, SECP256K1_EC_UNCOMPRESSED) != 1)
					return layer_exception("invalid public key");

				return format::util::encode_0xhex(std::string_view((char*)raw_public_key, raw_public_key_size).substr(1));
			}
			expects_lr<string> ethereum::decode_public_key(const std::string_view& public_key)
			{
				auto result = format::util::decode_0xhex(public_key);
				if (result.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && result.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1 && result.size() != BTC_ECKEY_COMPRESSED_LENGTH)
					return layer_exception("not a valid hex public key");

				return result;
			}
			expects_lr<string> ethereum::encode_address(const std::string_view& public_key_hash)
			{
				return encode_eth_address(encode_0xhex_checksum((uint8_t*)public_key_hash.data(), public_key_hash.size()));
			}
			expects_lr<string> ethereum::decode_address(const std::string_view& address)
			{
				auto data = codec::hex_decode(decode_non_eth_address(address));
				if (data.size() != 20)
					return layer_exception("invalid address");

				return data;
			}
			expects_lr<string> ethereum::encode_transaction_id(const std::string_view& transaction_id)
			{
				return format::util::encode_0xhex(transaction_id);
			}
			expects_lr<string> ethereum::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = format::util::decode_0xhex(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<algorithm::composition::cpubkey_t> ethereum::to_composite_public_key(const std::string_view& public_key)
			{
				auto input = decode_public_key(public_key);
				if (!input)
					return input.error();

				if (input->size() == BTC_ECKEY_UNCOMPRESSED_LENGTH || input->size() == BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
				{
					auto* context = algorithm::signing::get_context();
					if (input->size() == BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
						input->insert(input->begin(), 4);

					secp256k1_pubkey result_public_key;
					if (secp256k1_ec_pubkey_parse(context, &result_public_key, (uint8_t*)input->data(), input->size()) != 1)
						return layer_exception("bad public key");

					auto result = algorithm::composition::cpubkey_t();
					size_t result_size = sizeof(result);
					if (secp256k1_ec_pubkey_serialize(context, result.data, &result_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("bad public key");

					return expects_lr<algorithm::composition::cpubkey_t>(result);
				}
				else if (input->size() == BTC_ECKEY_COMPRESSED_LENGTH)
					return expects_lr<algorithm::composition::cpubkey_t>(algorithm::composition::cpubkey_t(*input));

				return layer_exception("bad public key");
			}
			expects_lr<address_map> ethereum::to_addresses(const std::string_view& input_public_key)
			{
				auto public_key = decode_public_key(input_public_key).or_else(string(input_public_key));
				if (public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
					return layer_exception("invalid public key");

				SHA3_CTX context;
				sha3_256_Init(&context);
				sha3_Update(&context, (uint8_t*)public_key.data(), public_key.size());

				uint8_t intermediate_public_key_hash[32];
				keccak_Final(&context, intermediate_public_key_hash);

				uint8_t public_key_hash[20];
				memcpy(public_key_hash, intermediate_public_key_hash + 12, sizeof(public_key_hash));

				address_map result = { { (uint8_t)1, encode_eth_address(encode_0xhex_checksum(public_key_hash, sizeof(public_key_hash))) } };
				return expects_lr<address_map>(std::move(result));
			}
			const ethereum::chainparams& ethereum::get_chainparams() const
			{
				return netdata;
			}
			bool ethereum::is_token_transfer(const std::string_view& function_signature)
			{
				return function_signature == get_token_transfer_signature();
			}
			const char* ethereum::get_token_transfer_signature()
			{
				return "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
			}
			const btc_chainparams_* ethereum::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &eth_chainparams_regtest;
					case network_type::testnet:
						return &eth_chainparams_test;
					case network_type::mainnet:
						return &eth_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			string ethereum::encode_0xhex(const std::string_view& data)
			{
				return format::util::encode_0xhex(data);
			}
			string ethereum::encode_0xhex_checksum(const uint8_t* data, size_t data_size)
			{
				string input = codec::hex_encode(std::string_view((char*)data, data_size));
				uint8_t input_hash[BTC_ECKEY_UNCOMPRESSED_LENGTH];
				keccak_256((uint8_t*)input.c_str(), input.size(), input_hash);

				string checksum = codec::hex_encode(std::string_view((char*)input_hash, sizeof(input_hash)));
				size_t input_size = std::min(input.size(), checksum.size());
				for (size_t i = 0; i < input_size; i++)
				{
					uint8_t offset = checksum[i] - '0';
					if (offset >= 8)
						input[i] = toupper(input[i]);
				}
				return get_chain()->bech32_hrp + input;
			}
			string ethereum::encode_eth_address(const std::string_view& eth_address)
			{
				return format::util::assign_0xhex(eth_address);
			}
			string ethereum::decode_non_eth_address(const std::string_view& non_eth_address)
			{
				return format::util::assign_0xhex(non_eth_address);
			}
			string ethereum::normalize_topic_address(const std::string_view& any_address)
			{
				string address = string(any_address); auto* chain = get_chain();
				if (stringify::starts_with(address, chain->bech32_hrp))
					address.erase(0, strlen(chain->bech32_hrp));
				while (address.size() > 40 && address.front() == '0')
					address.erase(address.begin());
				return chain->bech32_hrp + address;
			}
			string ethereum::uint256_to_hex(const uint256_t& data)
			{
				auto* chain = get_chain();
				return chain->bech32_hrp + data.to_string(16);
			}
			string ethereum::get_raw_gas_limit(schema* tx_data)
			{
				if (tx_data->has("receipt.gasUsed"))
					return tx_data->fetch_var("receipt.gasUsed").get_blob();

				if (tx_data->has("gasUsed"))
					return tx_data->get_var("gasUsed").get_blob();

				if (tx_data->has("gas"))
					return tx_data->get_var("gas").get_blob();

				if (tx_data->has("gasLimit"))
					return tx_data->get_var("gasLimit").get_blob();

				return "0";
			}
			uint256_t ethereum::hex_to_uint256(const std::string_view& any_data)
			{
				string data = string(any_data); auto* chain = get_chain();
				if (stringify::starts_with(data, chain->bech32_hrp))
					data.erase(0, strlen(chain->bech32_hrp));

				return uint256_t(data, 16);
			}
			uint256_t ethereum::from_eth(const decimal& value, const decimal& divisibility)
			{
				return uint256_t((value * divisibility).truncate(0).to_string());
			}
			decimal ethereum::to_eth(const uint256_t& value, const decimal& divisibility)
			{
				return value.to_decimal() / decimal(divisibility).truncate(protocol::now().message.precision);
			}
			decimal ethereum::get_divisibility_gwei()
			{
				return decimal("1000000000");
			}
			uint256_t ethereum::get_eth_transfer_gas_limit_gwei()
			{
				return 21000;
			}
			uint256_t ethereum::get_erc20_transfer_gas_limit_gwei()
			{
				return 63000;
			}
		}
	}
}
