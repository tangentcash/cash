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
	namespace mediator
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

				const uint32_t vchain_id = (uint32_t)chain_id;
				const uint32_t vmultiplier = 2;
				const uint32_t vrecovery_id = (uint32_t)raw_signature.recid;
				const uint32_t vderivation = 35;

				evm_signature signature;
				signature.v = vchain_id * vmultiplier + vrecovery_id + vderivation;
				signature.r = binary_data_t((char*)raw_signature.r, sizeof(raw_signature.r));
				signature.s = binary_data_t((char*)raw_signature.s, sizeof(raw_signature.s));
				return signature;
			}
			ethereum::evm_signed_transaction ethereum::evm_transaction::serialize_and_sign(const uint8_t private_key[32])
			{
				evm_signed_transaction transaction;
				transaction.signature = sign(hash(serialize()), private_key);
				if (transaction.signature.r.empty() || transaction.signature.s.empty())
					return transaction;

				transaction.data = serialize(&transaction.signature);
				transaction.id = hash(transaction.data);
				return transaction;
			}
			ethereum::binary_data_t ethereum::evm_transaction::serialize(evm_signature* signature)
			{
				eth_rlp buffer;
				eth_rlp_init(&buffer, ETH_RLP_ENCODE);
				eth_rlp_array(&buffer);
				eth_rlp_uint256(&buffer, &nonce);
				eth_rlp_uint256(&buffer, &gas_price);
				eth_rlp_uint256(&buffer, &gas_limit);
				eth_rlp_address336(&buffer, &address);
				eth_rlp_uint256(&buffer, &value);
				eth_rlp_binary(&buffer, &abi_data);
				if (signature)
				{
					uint256_t v = signature->v;
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
			const char* ethereum::nd_call::get_transaction_by_hash()
			{
				return "eth_getTransactionByHash";
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

			ethereum::ethereum() noexcept : relay_backend()
			{
				netdata.composition = algorithm::composition::type::SECP256K1;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 15;
				netdata.divisibility = decimal("1000000000000000000").truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "erc20";
				netdata.supports_bulk_transfer = false;
			}
			expects_promise_rt<schema*> ethereum::get_transaction_receipt(const algorithm::asset_id& asset, const std::string_view& transaction_id)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(transaction_id)));

				auto tx_data = coawait(execute_rpc(asset, nd_call::get_transaction_receipt(), std::move(map), cache_policy::shortened));
				coreturn tx_data;
			}
			expects_promise_rt<uint256_t> ethereum::get_transactions_count(const algorithm::asset_id& asset, const std::string_view& address)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<uint256_t>(remote_exception("chain not found"));

				schema_list latest_map;
				latest_map.emplace_back(var::set::string(implementation->decode_non_eth_address(address)));
				latest_map.emplace_back(var::set::string("latest"));

				auto latest_transaction_count = coawait(execute_rpc(asset, nd_call::get_transaction_count(), std::move(latest_map), cache_policy::lazy));
				if (!latest_transaction_count)
					coreturn expects_rt<uint256_t>(std::move(latest_transaction_count.error()));

				uint256_t transactions_count = implementation->hex_to_uint256(latest_transaction_count->value.get_blob());
				memory::release(*latest_transaction_count);

				schema_list pending_map;
				pending_map.emplace_back(var::set::string(implementation->decode_non_eth_address(address)));
				pending_map.emplace_back(var::set::string("pending"));

				auto pending_transaction_count = uptr<schema>(coawait(execute_rpc(asset, nd_call::get_transaction_count(), std::move(pending_map), cache_policy::lazy)));
				if (pending_transaction_count)
				{
					uint256_t pending_transactions_count = implementation->hex_to_uint256(pending_transaction_count->value.get_blob());
					if (pending_transactions_count > transactions_count)
						transactions_count = pending_transactions_count;
				}

				coreturn expects_rt<uint256_t>(std::move(transactions_count));
			}
			expects_promise_rt<uint256_t> ethereum::get_chain_id(const algorithm::asset_id& asset)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<uint256_t>(remote_exception("chain not found"));

				auto hex_chain_id = coawait(execute_rpc(asset, nd_call::get_chain_id(), { }, cache_policy::persistent));
				if (!hex_chain_id)
					coreturn expects_rt<uint256_t>(std::move(hex_chain_id.error()));

				uint256_t chain_id = implementation->hex_to_uint256(hex_chain_id->value.get_blob());
				memory::release(*hex_chain_id);
				coreturn expects_rt<uint256_t>(std::move(chain_id));
			}
			expects_promise_rt<string> ethereum::get_contract_symbol(const algorithm::asset_id& asset, backends::ethereum* implementation, const std::string_view& contract_address)
			{
				uptr<schema> params = var::set::object();
				params->set("to", var::string(implementation->decode_non_eth_address(contract_address)));
				params->set("data", var::string(implementation->generate_unchecked_address(backends::ethereum::sc_call::decimals())));

				schema_list map;
				map.emplace_back(std::move(params));
				map.emplace_back(var::set::string("latest"));

				auto symbol = coawait(execute_rpc(asset, nd_call::call(), std::move(map), cache_policy::persistent));
				if (!symbol)
					coreturn expects_rt<string>(std::move(symbol.error()));

				coreturn expects_rt<string>(symbol->value.get_blob());
			}
			expects_promise_rt<decimal> ethereum::get_contract_divisibility(const algorithm::asset_id& asset, backends::ethereum* implementation, const std::string_view& contract_address)
			{
				uptr<schema> params = var::set::object();
				params->set("to", var::string(implementation->decode_non_eth_address(contract_address)));
				params->set("data", var::string(implementation->generate_unchecked_address(backends::ethereum::sc_call::decimals())));

				schema_list map;
				map.emplace_back(std::move(params));
				map.emplace_back(var::set::string("latest"));

				auto decimals = coawait(execute_rpc(asset, nd_call::call(), std::move(map), cache_policy::persistent));
				if (!decimals)
					coreturn expects_rt<decimal>(std::move(decimals.error()));

				uint64_t divisibility = 1;
				uint64_t value = std::min<uint64_t>((uint64_t)implementation->hex_to_uint256(decimals->value.get_blob()), protocol::now().message.precision);
				for (uint64_t i = 0; i < value; i++)
					divisibility *= 10;
				coreturn expects_rt<decimal>(decimal(divisibility));
			}
			expects_promise_rt<void> ethereum::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				auto duplicate = coawait(get_transaction_receipt(asset, format::util::assign_0xhex(tx_data.transaction.transaction_id)));
				if (duplicate)
				{
					memory::release(*duplicate);
					coreturn expects_rt<void>(expectation::met);
				}

				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(tx_data.data)));

				auto hex_data = coawait(execute_rpc(asset, nd_call::send_raw_transaction(), std::move(map), cache_policy::greedy));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				memory::release(*hex_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<uint64_t> ethereum::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<uint64_t>(remote_exception("chain not found"));

				auto block_count = coawait(execute_rpc(asset, nd_call::block_number(), { }, cache_policy::lazy));
				if (!block_count)
					coreturn expects_rt<uint64_t>(std::move(block_count.error()));

				uint64_t block_height = (uint64_t)implementation->hex_to_uint256(block_count->value.get_blob());
				memory::release(*block_count);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> ethereum::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<schema*>(remote_exception("chain not found"));

				schema_list map;
				map.emplace_back(var::set::string(((backends::ethereum*)implementation)->uint256_to_hex(block_height)));
				map.emplace_back(var::set::boolean(true));

				auto block_data = coawait(execute_rpc(asset, nd_call::get_block_by_number(), std::move(map), cache_policy::shortened));
				if (!block_data)
					coreturn block_data;

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
					cursor->set("fromBlock", var::set::string(implementation->uint256_to_hex(block_height)));
					cursor->set("toBlock", var::set::string(implementation->uint256_to_hex(block_height)));
					cursor->set("topics", var::set::array())->push(var::string(implementation->get_token_transfer_signature()));

					schema_list map;
					map.emplace_back(query);

					auto logs_data = coawait(execute_rpc(asset, nd_call::get_block_by_number(), std::move(map), cache_policy::shortened));
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
			expects_promise_rt<schema*> ethereum::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(transaction_id)));

				auto tx_data = coawait(execute_rpc(asset, nd_call::get_transaction_by_hash(), std::move(map), cache_policy::extended));
				coreturn tx_data;
			}
			expects_promise_rt<vector<incoming_transaction>> ethereum::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("chain not found"));

				auto* chain = implementation->get_chain();
				string data = transaction_data->get_var("input").get_blob();
				if (stringify::starts_with(data, chain->bech32_hrp))
					data.erase(0, strlen(chain->bech32_hrp));

				string tx_hash = transaction_data->get_var("hash").get_blob();
				string from = implementation->encode_eth_address(transaction_data->get_var("from").get_blob());
				string to = implementation->encode_eth_address(transaction_data->get_var("to").get_blob());
				decimal gas_price = implementation->to_eth(implementation->hex_to_uint256(transaction_data->get_var("gasPrice").get_blob()), implementation->get_divisibility_gwei());
				decimal gas_limit = implementation->to_eth(implementation->hex_to_uint256(get_raw_gas_limit(transaction_data)), implementation->get_divisibility_gwei());
				decimal base_value = implementation->to_eth(implementation->hex_to_uint256(transaction_data->get_var("value").get_blob()), implementation->netdata.divisibility);;
				decimal fee_value = gas_price * gas_limit;

				incoming_transaction coin_tx;
				coin_tx.set_transaction(asset, block_height, tx_hash, decimal(fee_value));
				coin_tx.set_operations({ transferer(from, optional::none, decimal(base_value)) }, { transferer(to, optional::none, decimal(base_value)) });

				vector<incoming_transaction> results;
				results.push_back(std::move(coin_tx));
				if (!data.empty())
				{
					auto* logs = transaction_data->get("logs");
					if (!logs)
					{
						auto tx_receipt = coawait(get_transaction_receipt(asset, transaction_data->get_var("hash").get_blob()));
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
							auto contract_address = implementation->encode_eth_address(invocation->get_var("address").get_blob());
							if (!topics || (topics->size() != 2 && topics->size() != 3) || !implementation->is_token_transfer(topics->get_var(0).get_blob()))
								continue;

							auto symbol = coawait(get_contract_symbol(asset, implementation, contract_address));
							if (!symbol)
								continue;

							auto token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(asset), *symbol, contract_address);
							if (!nss::server_node::get()->enable_contract_address(token_asset, contract_address))
								continue;

							decimal divisibility = coawait(get_contract_divisibility(asset, implementation, contract_address)).otherwise(implementation->netdata.divisibility);
							decimal token_value = implementation->to_eth(implementation->hex_to_uint256(invocation->get_var("data").get_blob()), divisibility);
							if (topics->size() == 3)
							{
								from = implementation->encode_eth_address(implementation->normalize_topic_address(topics->get_var(1).get_blob()));
								to = implementation->encode_eth_address(implementation->normalize_topic_address(topics->get_var(2).get_blob()));
							}
							else if (topics->size() == 2)
								to = implementation->encode_eth_address(topics->get_var(1).get_blob());

							incoming_transaction token_tx;
							token_tx.set_transaction(std::move(token_asset), block_height, tx_hash, decimal::zero());
							token_tx.set_operations({ transferer(from, optional::none, decimal(token_value)) }, { transferer(to, optional::none, decimal(token_value)) });
							results.push_back(std::move(token_tx));
						}
					}
				}
				results.erase(std::remove_if(results.begin(), results.end(), [](incoming_transaction& v)
				{
					return !v.get_output_value().is_positive();
				}), results.end());

				unordered_set<string> addresses;
				addresses.reserve(results.size() * 2);
				for (auto& item : results)
				{
					for (auto& next : item.from)
						addresses.insert(next.address);
					for (auto& next : item.to)
						addresses.insert(next.address);
				}

				auto discovery = find_checkpoint_addresses(asset, addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				schema* tx_receipt_cache = transaction_data->get("receipt");
				schema* tx_receipt = tx_receipt_cache ? tx_receipt_cache : coawait(get_transaction_receipt(asset, tx_hash)).otherwise(nullptr);
				bool is_reverted = tx_receipt && tx_receipt->value.is_object() ? implementation->hex_to_uint256(tx_receipt->get_var("status").get_blob()) < 1 : false;
				for (auto& item : results)
				{
					for (auto& next : item.from)
					{
						auto address = discovery->find(next.address);
						if (address != discovery->end())
							next.address_index = address->second;
						if (is_reverted)
							next.value = 0.0;
					}
					for (auto& next : item.to)
					{
						auto address = discovery->find(next.address);
						if (address != discovery->end())
							next.address_index = address->second;
						if (is_reverted)
							next.value = 0.0;
					}
				}
				coreturn expects_rt<vector<incoming_transaction>>(results);
			}
			expects_promise_rt<base_fee> ethereum::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				auto gas_price_estimate = coawait(execute_rpc(asset, nd_call::gas_price(), { }, cache_policy::greedy));
				if (!gas_price_estimate)
					coreturn expects_rt<base_fee>(std::move(gas_price_estimate.error()));

				expects_lr<derived_verifying_wallet> from_wallet = layer_exception("signing wallet not found");
				if (wallet.parent)
				{
					auto signing_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
					if (signing_wallet)
						from_wallet = *signing_wallet;
					else
						from_wallet = signing_wallet.error();
				}
				else if (wallet.verifying_child)
					from_wallet = *wallet.verifying_child;
				else if (wallet.signing_child)
					from_wallet = *wallet.signing_child;
				if (!from_wallet)
					coreturn expects_rt<base_fee>(remote_exception(std::move(from_wallet.error().message())));

				auto& subject = to.front();
				uptr<schema> params = var::set::object();
				params->set("gasPrice", var::string(gas_price_estimate->value.get_blob()));
				params->set("from", var::string(implementation->decode_non_eth_address(from_wallet->addresses.begin()->second)));

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal divisibility = implementation->netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(asset, implementation, *contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				uint64_t default_gas_limit;
				uint256_t value = implementation->from_eth(subject.value, divisibility);
				if (contract_address)
				{
					default_gas_limit = implementation->get_erc20_transfer_gas_limit_gwei();
					params->set("to", var::string(implementation->decode_non_eth_address(*contract_address)));
					params->set("value", var::string(implementation->uint256_to_hex(0)));
					params->set("gas", var::string(implementation->uint256_to_hex(default_gas_limit)));
					params->set("data", var::string(implementation->generate_unchecked_address(backends::ethereum::sc_call::transfer(implementation->decode_non_eth_address(subject.address), value))));
				}
				else
				{
					default_gas_limit = implementation->get_eth_transfer_gas_limit_gwei();
					params->set("to", var::string(implementation->decode_non_eth_address(subject.address)));
					params->set("value", var::string(implementation->uint256_to_hex(value)));
					params->set("gas", var::string(implementation->uint256_to_hex(default_gas_limit)));
				}

				schema_list map;
				map.emplace_back(std::move(params));
				map.emplace_back(var::set::string("latest"));

				auto gas_limit_estimate = uptr<schema>(coawait(execute_rpc(asset, nd_call::estimate_gas(), std::move(map), cache_policy::greedy)));
				if (!gas_limit_estimate)
				{
					decimal gas_price = implementation->to_eth(implementation->hex_to_uint256(gas_price_estimate->value.get_blob()), implementation->get_divisibility_gwei());
					decimal gas_limit = implementation->to_eth(default_gas_limit, implementation->get_divisibility_gwei());
					memory::release(*gas_price_estimate);
					coreturn expects_rt<base_fee>(base_fee(gas_price, gas_limit));
				}

				uint256_t vgas_limit = implementation->hex_to_uint256(gas_limit_estimate->value.get_blob());
				decimal gas_price = implementation->to_eth(implementation->hex_to_uint256(gas_price_estimate->value.get_blob()), implementation->get_divisibility_gwei());
				decimal gas_limit = implementation->to_eth(vgas_limit, implementation->get_divisibility_gwei());
				memory::release(*gas_price_estimate);
				coreturn expects_rt<base_fee>(base_fee(gas_price, gas_limit));
			}
			expects_promise_rt<decimal> ethereum::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
			{
				auto* implementation = (backends::ethereum*)nss::server_node::get()->get_chain(asset);
				if (!address)
				{
					expects_lr<derived_verifying_wallet> from_wallet = layer_exception("signing wallet not found");
					if (wallet.parent)
					{
						auto signing_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
						if (signing_wallet)
							from_wallet = *signing_wallet;
						else
							from_wallet = signing_wallet.error();
					}
					else if (wallet.verifying_child)
						from_wallet = *wallet.verifying_child;
					else if (wallet.signing_child)
						from_wallet = *wallet.signing_child;
					if (!from_wallet)
						coreturn expects_rt<decimal>(remote_exception(std::move(from_wallet.error().message())));

					address = from_wallet->addresses.begin()->second;
				}

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal divisibility = implementation->netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(asset, implementation, *contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				const char* method = nullptr;
				schema* params = nullptr;
				if (contract_address)
				{
					method = nd_call::call();
					params = var::set::object();
					params->set("to", var::string(implementation->decode_non_eth_address(*contract_address)));
					params->set("data", var::string(implementation->generate_unchecked_address(backends::ethereum::sc_call::balance_of(implementation->decode_non_eth_address(*address)))));
				}
				else
				{
					method = nd_call::get_balance();
					params = var::set::string(implementation->decode_non_eth_address(*address));
				}

				schema_list map;
				map.emplace_back(params);
				map.emplace_back(var::set::string("latest"));

				auto confirmed_balance = coawait(execute_rpc(asset, method, std::move(map), cache_policy::lazy));
				if (!confirmed_balance)
					coreturn expects_rt<decimal>(std::move(confirmed_balance.error()));

				decimal balance = implementation->to_eth(implementation->hex_to_uint256(confirmed_balance->value.get_blob()), divisibility);
				memory::release(*confirmed_balance);
				coreturn expects_rt<decimal>(std::move(balance));
			}
			expects_promise_rt<outgoing_transaction> ethereum::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> from_wallet = layer_exception();
				if (wallet.parent)
					from_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					from_wallet = *wallet.signing_child;
				if (!from_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("signing wallet not found"));

				auto chain_id = coawait(get_chain_id(asset));
				if (!chain_id)
					coreturn expects_rt<outgoing_transaction>(std::move(chain_id.error()));

				auto& subject = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal fee_value = fee.get_fee();
				decimal total_value = subject.value;
				if (contract_address)
				{
					auto balance = coawait(calculate_balance(algorithm::asset::base_id_of(asset), wallet, from_wallet->addresses.begin()->second));
					if (!balance || *balance < fee_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}
				else
					total_value += fee_value;

				auto balance = coawait(calculate_balance(asset, wallet, from_wallet->addresses.begin()->second));
				if (!balance || *balance < total_value)
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

				auto nonce = coawait(get_transactions_count(asset, from_wallet->addresses.begin()->second));
				if (!nonce)
					coreturn expects_rt<outgoing_transaction>(remote_exception("nonce value invalid"));

				evm_transaction transaction;
				transaction.chain_id = *chain_id;
				transaction.nonce = *nonce;
				transaction.gas_price = from_eth(fee.price, get_divisibility_gwei());
				transaction.gas_limit = from_eth(fee.limit, get_divisibility_gwei());

				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(asset, this, *contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				uint256_t value = from_eth(subject.value, divisibility);
				if (contract_address)
				{
					transaction.address = decode_non_eth_address(*contract_address);
					transaction.abi_data = sc_call::transfer(subject.address, value);
				}
				else
				{
					transaction.address = decode_non_eth_address(subject.address);
					transaction.value = value;
				}

				uint8_t raw_private_key[256];
				auto private_key = from_wallet->signing_key.expose<KEY_LIMIT>();
				generate_private_key_data_from_private_key(private_key.view.data(), private_key.view.size(), raw_private_key);

				evm_signed_transaction info = transaction.serialize_and_sign(raw_private_key);
				if (info.signature.r.empty() || info.signature.s.empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid private key"));
				else if (info.id.empty() || info.data.empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

				incoming_transaction tx;
				tx.set_transaction(asset, 0, info.id, std::move(fee_value));
				tx.set_operations({ transferer(from_wallet->addresses.begin()->second, option<uint64_t>(from_wallet->address_index), decimal(subject.value)) }, vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(info.data)));
			}
			expects_lr<master_wallet> ethereum::new_master_wallet(const std::string_view& seed)
			{
				auto* chain = get_chain();
				btc_hdnode root_node;
				if (!btc_hdnode_from_seed((uint8_t*)seed.data(), (int)seed.size(), &root_node))
					return expects_lr<master_wallet>(layer_exception("seed value invalid"));

				char private_key[256];
				btc_hdnode_serialize_private(&root_node, chain, private_key, sizeof(private_key));

				char public_key[256];
				btc_hdnode_serialize_public(&root_node, chain, public_key, (int)sizeof(public_key));

				return expects_lr<master_wallet>(master_wallet(secret_box::secure(std::move(codec::hex_encode(seed))), secret_box::secure(private_key), public_key));
			}
			expects_lr<derived_signing_wallet> ethereum::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
			{
				auto* chain = get_chain();
				char master_private_key[256];
				{
					auto secret = wallet.signing_key.expose<KEY_LIMIT>();
					if (!hd_derive(chain, secret.view.data(), get_derivation(protocol::now().account.root_address_index).c_str(), master_private_key, sizeof(master_private_key)))
						return expects_lr<derived_signing_wallet>(layer_exception("invalid private key"));
				}

				btc_hdnode node;
				if (!btc_hdnode_deserialize(master_private_key, chain, &node))
					return expects_lr<derived_signing_wallet>(layer_exception("invalid private key"));

				auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> ethereum::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				btc_key private_key;
				btc_privkey_init(&private_key);
				if (signing_key.size() != sizeof(private_key.privkey))
				{
					auto key = format::util::decode_0xhex(signing_key.expose<KEY_LIMIT>().view);
					if (key.size() != sizeof(private_key.privkey))
						return layer_exception("not a valid hex private key");

					memcpy(private_key.privkey, key.data(), sizeof(private_key.privkey));
				}
				else
					memcpy(private_key.privkey, signing_key.expose<KEY_LIMIT>().buffer, sizeof(private_key.privkey));

				char public_key_data[128]; size_t public_key_data_size = BTC_ECKEY_UNCOMPRESSED_LENGTH;
				btc_ecc_get_pubkey(private_key.privkey, (uint8_t*)public_key_data, &public_key_data_size, false);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_key_data + 1, public_key_data_size - 1));
				if (!derived)
					return derived.error();

				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(generate_unchecked_address(std::string_view((char*)private_key.privkey, sizeof(private_key.privkey))))));
			}
			expects_lr<derived_verifying_wallet> ethereum::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				string raw_public_key = string(verifying_key);
				if (raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1 && raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && raw_public_key.size() != BTC_ECKEY_COMPRESSED_LENGTH)
				{
					raw_public_key = format::util::decode_0xhex(raw_public_key);
					if (raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1 && raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && raw_public_key.size() != BTC_ECKEY_COMPRESSED_LENGTH)
						return layer_exception("invalid public key size");
				}

				uint8_t public_key[BTC_ECKEY_UNCOMPRESSED_LENGTH] = { 0 };
				if (raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
				{
					secp256k1_pubkey candidate_public_key;
					secp256k1_context* context = algorithm::signing::get_context();
					if (secp256k1_ec_pubkey_parse(context, &candidate_public_key, (uint8_t*)raw_public_key.data(), raw_public_key.size()) != 1)
						return layer_exception("invalid public key");

					size_t public_key_size = sizeof(public_key);
					if (secp256k1_ec_pubkey_serialize(context, public_key, &public_key_size, &candidate_public_key, SECP256K1_EC_UNCOMPRESSED) != 1)
						return layer_exception("invalid public key");
				}
				else
					memcpy(public_key + 1, raw_public_key.data(), raw_public_key.size());

				char public_key_hash[20];
				generate_public_key_hash_from_public_key(public_key + 1, public_key_hash);
				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, encode_eth_address(generate_pkh_address(public_key_hash)) } }, optional::none, generate_unchecked_address(std::string_view((char*)public_key + 1, sizeof(public_key) - 1))));
			}
			expects_lr<string> ethereum::new_public_key_hash(const std::string_view& address)
			{
				auto data = codec::hex_decode(address);
				if (data.empty())
					return layer_exception("invalid address");

				return data;
			}
			expects_lr<string> ethereum::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				uint8_t raw_private_key[256];
				auto private_key = signing_wallet->signing_key.expose<KEY_LIMIT>();
				generate_private_key_data_from_private_key(private_key.view.data(), private_key.view.size(), raw_private_key);

				uint8_t hash[32];
				generate_message_hash(message, hash);

				eth_ecdsa_signature raw_signature;
				if (eth_ecdsa_sign(&raw_signature, raw_private_key, hash) != 1)
					return layer_exception("private key not valid");

				uint8_t signature[65] = { 0 };
				memcpy(signature + 00, raw_signature.r, sizeof(raw_signature.r));
				memcpy(signature + 32, raw_signature.s, sizeof(raw_signature.s));
				signature[64] = raw_signature.recid;
				return format::util::encode_0xhex(std::string_view((char*)signature, sizeof(signature)));
			}
			expects_lr<void> ethereum::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				string signature_data = signature.size() == 65 ? string(signature) : codec::hex_decode(signature);
				if (signature_data.size() != 65)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				secp256k1_context* context = algorithm::signing::get_context();
				if (!context)
					return layer_exception("context not valid");

				uint8_t hash[32];
				generate_message_hash(message, hash);
				for (auto& item : verifying_wallet->addresses)
				{
					const auto& address = item.second;
					string target_address = generate_checksum_address(decode_non_eth_address(address));
					string raw_signature = signature_data;
					for (int i = 0; i < 4; i++)
					{
						secp256k1_ecdsa_recoverable_signature ecdsa_signature;
						secp256k1_ecdsa_recoverable_signature_parse_compact(context, &ecdsa_signature, (uint8_t*)raw_signature.data(), i);

						secp256k1_pubkey pub_key;
						if (secp256k1_ecdsa_recover(context, &pub_key, &ecdsa_signature, hash) != 1)
							continue;

						char serialized_pub_key[65]; size_t serialized_pub_key_size = sizeof(serialized_pub_key);
						if (secp256k1_ec_pubkey_serialize(context, (uint8_t*)serialized_pub_key, &serialized_pub_key_size, &pub_key, SECP256K1_EC_UNCOMPRESSED) != 1)
							continue;

						char actual_public_key_hash1[20], actual_public_key_hash2[20];
						generate_public_key_hash_from_public_key((uint8_t*)serialized_pub_key, actual_public_key_hash1);
						generate_public_key_hash_from_public_key((uint8_t*)serialized_pub_key + 1, actual_public_key_hash2);
						string actual_address1 = generate_pkh_address(actual_public_key_hash1);
						string actual_address2 = generate_pkh_address(actual_public_key_hash2);
						if (actual_address1 == target_address || actual_address2 == target_address)
							return expectation::met;
					}
				}

				return layer_exception("signature verification failed with used public key");
			}
			string ethereum::get_checksum_hash(const std::string_view& value) const
			{
				string copy = string(value);
				return stringify::to_lower(copy);
			}
			string ethereum::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
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
			void ethereum::generate_public_key_hash_from_public_key(const uint8_t public_key[64], char out_public_key_hash[20])
			{
				SHA3_CTX context;
				sha3_256_Init(&context);
				sha3_Update(&context, public_key, 64);

				uint8_t public_key_hash[32];
				keccak_Final(&context, public_key_hash);
				memcpy(out_public_key_hash, public_key_hash + 12, 20);
			}
			void ethereum::generate_private_key_data_from_private_key(const char* private_key, size_t private_key_size, uint8_t out_private_key_hash[20])
			{
				auto* chain = get_chain();
				size_t prefix_size = strlen(chain->bech32_hrp);
				if (!memcmp(private_key, chain->bech32_hrp, sizeof(char) * prefix_size))
				{
					private_key += prefix_size;
					private_key_size -= prefix_size;
				}

				int out_size = 20;
				utils_hex_to_bin(private_key, out_private_key_hash, (int)private_key_size, &out_size);
			}
			void ethereum::generate_message_hash(const std::string_view& input, uint8_t output[32])
			{
				string header = get_message_magic();
				string payload = stringify::text("%c%s%i%.*s",
					(char)header.size(), header.c_str(),
					(int)input.size(), (int)input.size(), input.data());
				keccak_256((uint8_t*)payload.data(), payload.size(), output);
			}
			string ethereum::get_message_magic()
			{
				return "Ethereum signed message:\n";
			}
			string ethereum::generate_pkh_address(const char* public_key_hash20)
			{
				return generate_checksum_address(codec::hex_encode(std::string_view(public_key_hash20, 20)));
			}
			string ethereum::generate_unchecked_address(const std::string_view& data)
			{
				auto* chain = get_chain();
				return chain->bech32_hrp + codec::hex_encode(data);
			}
			string ethereum::generate_checksum_address(const std::string_view& any_address)
			{
				string address = string(any_address);
				stringify::to_lower(address);

				auto* chain = get_chain();
				if (stringify::starts_with(address, chain->bech32_hrp))
					address.erase(0, strlen(chain->bech32_hrp));

				uint8_t address_raw_hash[BTC_ECKEY_UNCOMPRESSED_LENGTH];
				keccak_256((uint8_t*)address.c_str(), address.size(), address_raw_hash);

				string address_hash = codec::hex_encode(std::string_view((const char*)address_raw_hash, 32));
				size_t address_size = std::min(address.size(), address_hash.size());
				for (size_t i = 0; i < address_size; i++)
				{
					uint8_t offset = address_hash[i] - '0';
					if (offset >= 8)
						address[i] = toupper(address[i]);
				}

				return chain->bech32_hrp + address;
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