#include "ethereum.h"
#include <secp256k1_recovery.h>
#include <gmp.h>
extern "C"
{
#include "../internal/bitcoin.h"
#include "../internal/ethereum.h"
#include "../internal/sha3.h"
}

namespace tangent
{
	namespace superchain
	{
		namespace translations
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
				mpz_t numeric; uint8_t bytes[32] = { 0 };
				mpz_init_set_str(numeric, value->to_string(16).c_str(), 16);
				if (buffer->m == ETH_ABI_ENCODE)
				{
					mpz_t mpztmp, mpzmask;
					mpz_init_set_str(mpzmask, "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0);
					mpz_init(mpztmp);
					mpz_and(mpztmp, numeric, mpzmask);

					size_t size = mpz_sizeinbase(mpztmp, 16);
					size = (size % 2 == 0 ? size : size + 1) / 2;
					mpz_export((bytes + 32) - size, NULL, 1, sizeof(uint8_t), 0, 0, mpztmp);
					mpz_clears(mpztmp, mpzmask, NULL);
					eth_abi_bytes32(buffer, bytes);
				}
				else if (buffer->m == ETH_ABI_DECODE)
				{
					if (eth_abi_bytes32(buffer, bytes) != 0)
						mpz_import(numeric, 32, 1, sizeof(uint8_t), 0, 0, bytes);
				}
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
						uint256_t base_fee_per_gas_2x = gas_premium;
						uint256_t max_priority_fee_per_gas = gas_price;
						uint256_t max_fee_per_gas = base_fee_per_gas_2x + max_priority_fee_per_gas;
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
			const char* ethereum::nd_call::get_logs()
			{
				return "eth_getLogs";
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
			const char* ethereum::nd_call::max_priority_fee_per_gas()
			{
				return "eth_maxPriorityFeePerGas";
			}
			const char* ethereum::nd_call::call()
			{
				return "eth_call";
			}
			const char* ethereum::nd_call::send_raw_transaction()
			{
				return "eth_sendRawTransaction";
			}

			ethereum::ethereum(const algorithm::asset_id& new_asset) noexcept : translation_unit(new_asset)
			{
				netdata.composition = algorithm::composition::type::secp256k1;
				netdata.routing = routing_policy::account;
				netdata.tokenization = token_policy::program;
				netdata.sync_latency = 64;
				netdata.divisibility = algorithm::arithmetic::fixed("1000000000000000000");
				netdata.transaction_expires = false;
			}
			expects_promise_rt<format::tree> ethereum::get_transaction_receipt(const std::string_view& transaction_id, bool cached)
			{
				format::tree map;
				map.push(format::variable(format::util::assign_0xhex(transaction_id)));

				return execute_rpc(nd_call::get_transaction_receipt(), std::move(map), cached ? cache_policy::blob_cache : cache_policy::no_cache_no_throttling, evm_rpc_path).then<expects_rt<format::tree>>([](expects_rt<format::tree>&& tx_data) -> expects_rt<format::tree>
				{
					return tx_data && tx_data.is_none() ? expects_rt<format::tree>(remote_exception("receipt not found")) : expects_rt<format::tree>(std::move(tx_data));
				});
			}
			expects_promise_rt<uint256_t> ethereum::get_transactions_count(const std::string_view& address)
			{
				string address_ref = decode_non_eth_address(address);
				return coasync<expects_rt<uint256_t>>([this, address_ref = std::move(address_ref)]() mutable -> expects_promise_rt<uint256_t>
				{
					format::tree latest_map;
					latest_map.push(format::variable(address_ref));
					latest_map.push(format::variable("latest"));

					auto latest_transaction_count = coawait(execute_rpc(nd_call::get_transaction_count(), std::move(latest_map), cache_policy::no_cache, evm_rpc_path));
					if (!latest_transaction_count)
						coreturn expects_rt<uint256_t>(std::move(latest_transaction_count.error()));

					uint256_t transactions_count = hex_to_uint256(latest_transaction_count->value.as_blob());
					format::tree pending_map;
					pending_map.push(format::variable(address_ref));
					pending_map.push(format::variable("pending"));

					auto pending_transaction_count = coawait(execute_rpc(nd_call::get_transaction_count(), std::move(pending_map), cache_policy::no_cache, evm_rpc_path));
					if (pending_transaction_count)
					{
						uint256_t pending_transactions_count = hex_to_uint256(pending_transaction_count->value.as_blob());
						if (pending_transactions_count > transactions_count)
							transactions_count = pending_transactions_count;
					}

					coreturn expects_rt<uint256_t>(std::move(transactions_count));
				});
			}
			expects_promise_rt<uint256_t> ethereum::get_chain_id()
			{
				return execute_rpc(nd_call::get_chain_id(), format::tree::list(), cache_policy::lifetime_cache, evm_rpc_path).then<expects_rt<uint256_t>>([this](expects_rt<format::tree>&& hex_chain_id) -> expects_rt<uint256_t>
				{
					return hex_chain_id ? expects_rt<uint256_t>(hex_to_uint256(hex_chain_id->value.as_blob())) : expects_rt<uint256_t>(std::move(hex_chain_id.error()));
				});
			}
			expects_promise_rt<string> ethereum::get_contract_symbol(const std::string_view& contract_address)
			{
				format::tree params = format::tree::map();
				params.set("to", format::variable(decode_non_eth_address(contract_address)));
				params.set("data", format::variable(encode_0xhex(translations::ethereum::sc_call::symbol())));

				format::tree map;
				map.push(std::move(params));
				map.push(format::variable("latest"));

				return execute_rpc(nd_call::call(), std::move(map), cache_policy::lifetime_cache, evm_rpc_path).then<expects_rt<string>>([](expects_rt<format::tree>&& symbol) -> expects_rt<string>
				{
					if (!symbol)
						return expects_rt<string>(std::move(symbol.error()));

					struct eth_abi evm;
					eth_abi_init(&evm, ETH_ABI_DECODE);
					eth_abi_from_hex(&evm, (char*)symbol->value.as_string().data(), (int)symbol->value.as_string().size());

					uint8_t* bytes; size_t bytes_size;
					bool has_bytes = eth_abi_bytes(&evm, &bytes, &bytes_size) == 1;
					eth_abi_free(&evm);
					if (!has_bytes)
						return expects_rt<string>(symbol->value.as_blob());

					string result = string((char*)bytes, bytes_size);
					free(bytes);
					return expects_rt<string>(std::move(result));
				});
			}
			expects_promise_rt<decimal> ethereum::get_contract_divisibility(const std::string_view& contract_address)
			{
				format::tree params = format::tree::map();
				params.set("to", format::variable(decode_non_eth_address(contract_address)));
				params.set("data", format::variable(encode_0xhex(translations::ethereum::sc_call::decimals())));

				format::tree map;
				map.push(std::move(params));
				map.push(format::variable("latest"));

				return execute_rpc(nd_call::call(), std::move(map), cache_policy::lifetime_cache, evm_rpc_path).then<expects_rt<decimal>>([this](expects_rt<format::tree>&& decimals) -> expects_rt<decimal>
				{
					return decimals ? expects_rt<decimal>(algorithm::arithmetic::range((uint64_t)hex_to_uint256(decimals->value.as_blob()))) : expects_rt<decimal>(std::move(decimals.error()));
				});
			}
			expects_promise_rt<uint64_t> ethereum::get_latest_block_height()
			{
				return execute_rpc(nd_call::block_number(), format::tree::list(), cache_policy::no_cache, evm_rpc_path).then<expects_rt<uint64_t>>([this](expects_rt<format::tree>&& block_count) -> expects_rt<uint64_t>
				{
					return block_count ? expects_rt<uint64_t>((uint64_t)hex_to_uint256(block_count->value.as_blob())) : expects_rt<uint64_t>(std::move(block_count.error()));
				});
			}
			expects_promise_rt<vector<block_log>> ethereum::get_block_transactions(uint64_t block_height, uint64_t block_count)
			{
				return coasync<expects_rt<vector<block_log>>>([this, block_height, block_count]() -> expects_promise_rt<vector<block_log>>
				{
					format::tree map;
					for (uint64_t i = 0; i < block_count; i++)
					{
						format::tree block_map;
						block_map.push(format::variable(uint256_to_hex(block_height + i)));
						block_map.push(format::variable(true));
						map.push(std::move(block_map));
					}

					auto block_data = coawait(execute_rpc_multi(nd_call::get_block_by_number(), std::move(map), cache_policy::temporary_cache, evm_rpc_path));
					if (!block_data)
						coreturn block_data.error();

					map.childs().clear();
					vector<block_log> results;
					for (auto& block : block_data->childs())
					{
						auto* transactions = (format::tree*)block.child("transactions");
						auto transactions_count = transactions ? transactions->childs().size() : 0;
						auto& log = results.emplace_back();
						log.block_hash = block.child_var("hash").as_blob();
						log.transactions = transactions ? std::move(*transactions) : format::tree::list();
						legacy.eip_155 = block.has("baseFeePerGas") ? 0 : 1;
						if (!transactions_count)
							continue;

						auto logs_map = format::tree::list();
						auto query = format::tree::map();
						query.set("fromBlock", format::variable(uint256_to_hex(block_height)));
						query.set("toBlock", format::variable(uint256_to_hex(block_height)));
						query.set("topics", format::tree::list())->push(format::variable(get_token_transfer_signature()));
						logs_map.push(std::move(query));
						map.push(std::move(logs_map));
					}

					auto logs_batch = map.childs().empty() ? expects_rt<format::tree>(remote_exception::shutdown()) : coawait(execute_rpc_multi(nd_call::get_logs(), std::move(map), cache_policy::temporary_cache, evm_rpc_path));
					if (logs_batch)
					{
						hash_map<string, format::tree*> indices;
						for (auto& [block, transactions] : results)
						{
							for (auto& transaction : transactions.childs())
							{
								auto* logs = (format::tree*)transaction.child("logs");
								if (!logs || !logs->is_list())
									logs = transaction.set("logs", format::tree::list());
								indices[transaction.child_var("hash").as_blob()] = logs;
							}
						}

						for (auto& topics : logs_batch->childs())
						{
							for (auto& topic : topics.childs())
							{
								auto it = indices.find(topic.child_var("transactionHash").as_blob());
								if (it != indices.end())
									it->second->push(topic);
							}
						}
					}
					coreturn expects_rt<vector<block_log>>(std::move(results));
				});
			}
			expects_promise_rt<computed_transaction> ethereum::link_transaction(uint64_t, const std::string_view&, format::tree& transaction_data)
			{
				return coasync<expects_rt<computed_transaction>>([this, &transaction_data]() -> expects_promise_rt<computed_transaction>
				{
					auto* chain = get_chain();
					string data = transaction_data.child_var("input").as_blob();
					if (stringify::starts_with(data, chain->bech32_hrp))
						data.erase(0, strlen(chain->bech32_hrp));

					string tx_hash = transaction_data.child_var("hash").as_blob();
					string from = encode_eth_address(transaction_data.child_var("from").as_blob());
					string to = encode_eth_address(transaction_data.child_var("to").as_blob());
					decimal gas_price = to_eth(hex_to_uint256(transaction_data.child_var("gasPrice").as_blob()), get_divisibility_gwei());
					decimal gas_limit = to_eth(hex_to_uint256(get_raw_gas_limit(transaction_data)), get_divisibility_gwei());
					decimal base_value = to_eth(hex_to_uint256(transaction_data.child_var("value").as_blob()), netdata.divisibility);
					decimal fee_value = gas_price * gas_limit;
					decimal total_value = base_value + fee_value;

					computed_transaction result;
					result.transaction_id = tx_hash;

					hash_map<string, hash_map<algorithm::asset_id, decimal>> inputs;
					hash_map<string, hash_map<algorithm::asset_id, decimal>> outputs;
					if (total_value.is_positive())
					{
						inputs[from][native_asset] = total_value;
						outputs[to][native_asset] = base_value;
					}

					hash_set<string> addresses;
					addresses.reserve(inputs.size() + outputs.size());
					for (auto& next : inputs)
						addresses.insert(next.first);
					for (auto& next : outputs)
						addresses.insert(next.first);

					if (!data.empty())
					{
						auto* logs = transaction_data.child("logs");
						if (!logs)
						{
							auto tx_receipt = coawait(get_transaction_receipt(transaction_data.child_var("hash").as_blob(), true));
							if (tx_receipt)
								logs = transaction_data.set("receipt", std::move(*tx_receipt))->child("logs");
							else
								transaction_data.set("receipt", format::variable());
						}

						if (logs != nullptr && !logs->childs().empty())
						{
							for (auto& invocation : logs->childs())
							{
								auto* topics = invocation.child("topics");
								if (topics && topics->childs().size() == 3 && is_token_transfer(topics->child_var(0).as_blob()))
								{
									addresses.insert(encode_eth_address(normalize_topic_address(topics->child_var(1).as_blob())));
									addresses.insert(encode_eth_address(normalize_topic_address(topics->child_var(2).as_blob())));
								}
								else if (topics && topics->childs().size() == 2 && is_token_transfer(topics->child_var(0).as_blob()))
									addresses.insert(encode_eth_address(topics->child_var(1).as_blob()));
							}
						}
					}

					auto discovery = find_linked_addresses(addresses);
					if (!discovery || discovery->empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					if (!data.empty())
					{
						auto* logs = transaction_data.child("logs");
						if (!logs)
							logs = transaction_data.child("receipt.logs");

						if (logs != nullptr && !logs->childs().empty())
						{
							for (auto& invocation : logs->childs())
							{
								auto* topics = invocation.child("topics");
								if (!topics || (topics->childs().size() != 2 && topics->childs().size() != 3) || !is_token_transfer(topics->child_var(0).as_blob()))
									continue;

								auto contract_address = encode_eth_address(invocation.child_var("address").as_blob());
								auto symbol = coawait(get_contract_symbol(contract_address));
								if (!symbol)
									continue;

								auto token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), *symbol, contract_address);
								decimal divisibility = coawait(get_contract_divisibility(contract_address)).or_else(netdata.divisibility);
								decimal token_value = to_eth(hex_to_uint256(invocation.child_var("data").as_blob()), divisibility);
								if (topics->childs().size() == 3)
								{
									from = encode_eth_address(normalize_topic_address(topics->child_var(1).as_blob()));
									to = encode_eth_address(normalize_topic_address(topics->child_var(2).as_blob()));
								}
								else if (topics->childs().size() == 2)
									to = encode_eth_address(topics->child_var(1).as_blob());

								auto& token_input = inputs[from][token_asset];
								auto& token_output = outputs[to][token_asset];
								token_input = token_input.is_nan() ? token_value : (token_input + token_value);
								token_output = token_output.is_nan() ? token_value : (token_output + token_value);
								bridge::get()->enable_contract_address(token_asset, contract_address);
							}
						}
					}

					addresses.clear();
					for (auto& next : inputs)
						addresses.insert(next.first);
					for (auto& next : outputs)
						addresses.insert(next.first);

					discovery = find_linked_addresses(addresses);
					if (!discovery || discovery->empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					auto* tx_receipt = transaction_data.child("receipt");
					if (!tx_receipt)
					{
						auto receipt = coawait(get_transaction_receipt(tx_hash, true));
						if (receipt)
							tx_receipt = transaction_data.set("receipt", std::move(*receipt));
					}

					bool is_reverted = tx_receipt && tx_receipt->is_map() ? hex_to_uint256(tx_receipt->child_var("status").as_blob()) < 1 : true;
					if (is_reverted)
						coreturn expects_rt<computed_transaction>(remote_exception("tx reverted"));

					for (auto& [address, values] : inputs)
					{
						auto target_link = discovery->find(address);
						auto input = coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values));
						result.add_input(std::move(input));
					}

					for (auto& [address, values] : outputs)
					{
						auto target_link = discovery->find(address);
						auto output = coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values));
						result.add_output(std::move(output));
					}

					coreturn expects_rt<computed_transaction>(std::move(result));
				});
			}
			expects_promise_rt<computed_fee> ethereum::estimate_transaction_fee(const wallet_link& from_link, const value_transfer& to)
			{
				return coasync<expects_rt<computed_fee>>([this, from_link, to]() -> expects_promise_rt<computed_fee>
				{
					auto gas_price_value = coawait(execute_rpc(nd_call::gas_price(), format::tree::list(), cache_policy::no_cache, evm_rpc_path));
					if (!gas_price_value)
						coreturn expects_rt<computed_fee>(std::move(gas_price_value.error()));

					uint256_t vgas_price = hex_to_uint256(gas_price_value->value.as_blob());
					uint256_t vgas_premium = 0;
					if (!legacy.eip_155)
					{
						auto max_priority_fee_per_gas_value = legacy.priority_gas ? expects_rt<format::tree>(remote_exception::retry_later()) : coawait(execute_rpc(nd_call::max_priority_fee_per_gas(), format::tree::list(), cache_policy::no_cache, evm_rpc_path));
						if (!max_priority_fee_per_gas_value)
						{
							auto block_number = coawait(get_latest_block_height());
							if (!block_number)
								coreturn expects_rt<computed_fee>(std::move(block_number.error()));

							format::tree map;
							map.push(format::variable(uint256_to_hex(*block_number)));
							map.push(format::variable(false));

							auto block_data = coawait(execute_rpc(nd_call::get_block_by_number(), std::move(map), cache_policy::temporary_cache, evm_rpc_path));
							if (!block_data)
								coreturn expects_rt<computed_fee>(std::move(block_data.error()));

							auto value = block_data->child("baseFeePerGas");
							if (value)
								vgas_premium = hex_to_uint256(value->value.as_blob());
							legacy.priority_gas = 1;
						}
						else
						{
							uint256_t max_priority_fee_per_gas = hex_to_uint256(max_priority_fee_per_gas_value->value.as_blob());
							if (max_priority_fee_per_gas <= vgas_price)
								vgas_premium = (vgas_price - max_priority_fee_per_gas);
						}
						legacy.eip_155 = vgas_premium > 0 ? 0 : 1;
					}

					format::tree params = format::tree::map();
					params.set("gasPrice", format::variable(uint256_to_hex(vgas_price)));
					params.set("from", format::variable(decode_non_eth_address(from_link.address)));

					auto contract_address = bridge::get()->get_contract_address(to.asset);
					decimal divisibility = netdata.divisibility;
					if (contract_address)
					{
						auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
						if (contract_divisibility)
							divisibility = *contract_divisibility;
					}

					uint64_t default_gas_limit;
					uint256_t value = from_eth(to.value, divisibility);
					if (contract_address)
					{
						default_gas_limit = get_erc20_transfer_gas_limit_gwei();
						params.set("to", format::variable(decode_non_eth_address(*contract_address)));
						params.set("value", format::variable(uint256_to_hex(0)));
						params.set("gas", format::variable(uint256_to_hex(default_gas_limit)));
						params.set("data", format::variable(encode_0xhex(translations::ethereum::sc_call::transfer(decode_non_eth_address(to.address), value))));
					}
					else
					{
						default_gas_limit = get_eth_transfer_gas_limit_gwei();
						params.set("to", format::variable(decode_non_eth_address(to.address)));
						params.set("value", format::variable(uint256_to_hex(value)));
						params.set("gas", format::variable(uint256_to_hex(default_gas_limit)));
					}

					format::tree map;
					map.push(std::move(params));
					if (!legacy.estimate_gas)
						map.push(format::variable("latest"));

					if (vgas_premium > 0 && vgas_premium < vgas_price)
						vgas_price -= vgas_premium;

					decimal gas_premium = to_eth(vgas_premium * 2, netdata.divisibility);
					auto gas_limit_estimate = coawait(execute_rpc(nd_call::estimate_gas(), std::move(map), cache_policy::no_cache, evm_rpc_path));
					if (!gas_limit_estimate)
					{
						decimal gas_price = to_eth(vgas_price, netdata.divisibility);
						coreturn expects_rt<computed_fee>(computed_fee::fee_per_gas_priority(gas_premium, gas_price, default_gas_limit));
					}

					uint256_t vgas_limit = hex_to_uint256(gas_limit_estimate->value.as_blob());
					decimal gas_price = to_eth(vgas_price, netdata.divisibility);
					coreturn expects_rt<computed_fee>(computed_fee::fee_per_gas_priority(gas_premium, gas_price, vgas_limit > 0 ? vgas_limit : uint256_t(default_gas_limit)));
				});
			}
			expects_promise_rt<decimal> ethereum::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				return coasync<expects_rt<decimal>>([this, for_asset, link]() -> expects_promise_rt<decimal>
				{
					auto contract_address = bridge::get()->get_contract_address(for_asset);
					decimal divisibility = netdata.divisibility;
					if (contract_address)
					{
						auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
						if (contract_divisibility)
							divisibility = *contract_divisibility;
					}

					const char* method = nullptr;
					format::tree params;
					if (contract_address)
					{
						method = nd_call::call();
						params = format::tree::map();
						params.set("to", format::variable(decode_non_eth_address(*contract_address)));
						params.set("data", format::variable(encode_0xhex(translations::ethereum::sc_call::balance_of(decode_non_eth_address(link.address)))));
					}
					else
					{
						method = nd_call::get_balance();
						params = format::variable(decode_non_eth_address(link.address));
					}

					format::tree map;
					map.push(params);
					map.push(format::variable("latest"));

					auto confirmed_balance = coawait(execute_rpc(method, std::move(map), cache_policy::no_cache, evm_rpc_path));
					if (!confirmed_balance)
						coreturn expects_rt<decimal>(std::move(confirmed_balance.error()));

					decimal balance = to_eth(hex_to_uint256(confirmed_balance->value.as_blob()), divisibility);
					coreturn expects_rt<decimal>(std::move(balance));
				});
			}
			expects_promise_rt<void> ethereum::broadcast_transaction(const finalized_transaction& finalized)
			{
				format::tree map;
				map.push(format::variable(format::util::assign_0xhex(finalized.calldata)));

				return execute_rpc(nd_call::send_raw_transaction(), std::move(map), cache_policy::no_cache_no_throttling, evm_rpc_path).then<expects_rt<void>>([](expects_rt<format::tree>&& result) -> expects_rt<void>
				{
					return result ? expects_rt<void>(expectation::met) : expects_rt<void>(std::move(result.error()));
				});
			}
			expects_promise_rt<prepared_transaction> ethereum::prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
			{
				return coasync<expects_rt<prepared_transaction>>([this, from_link, to, max_fee]() -> expects_promise_rt<prepared_transaction>
				{
					auto chain_id = coawait(get_chain_id());
					if (!chain_id)
						coreturn expects_rt<prepared_transaction>(std::move(chain_id.error()));

					auto fee = coawait(estimate_transaction_fee(from_link, to));
					if (!fee)
						coreturn expects_rt<prepared_transaction>(std::move(fee.error()));

					decimal fee_value = fee->get_max_fee();
					if (fee_value > max_fee)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

					auto contract_address = bridge::get()->get_contract_address(to.asset);
					if (contract_address)
					{
						auto balance = coawait(calculate_balance(to.asset, from_link));
						if (!balance || *balance < fee_value)
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
					}
					else if (!algorithm::asset::token_of(to.asset).empty())
						coreturn expects_rt<prepared_transaction>(remote_exception("invalid sending token"));

					auto total_value = contract_address ? fee_value : (to.value + fee_value);
					auto balance = coawait(calculate_balance(native_asset, from_link));
					if (!balance || *balance < total_value || total_value.is_negative())
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

					auto nonce = coawait(get_transactions_count(from_link.address));
					if (!nonce)
						coreturn expects_rt<prepared_transaction>(remote_exception("nonce value invalid"));

					evm_transaction transaction;
					transaction.nonce = *nonce;
					transaction.chain_id = *chain_id;
					transaction.gas_premium = from_eth(fee->gas.gas_premium, netdata.divisibility);
					transaction.gas_price = from_eth(fee->gas.gas_price, netdata.divisibility);
					transaction.gas_limit = fee->gas.gas_limit;

					decimal divisibility = netdata.divisibility;
					if (contract_address)
					{
						auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
						if (contract_divisibility)
							divisibility = std::move(*contract_divisibility);

						transaction.address = decode_non_eth_address(*contract_address);
						transaction.abi_data = sc_call::transfer(to.address, from_eth(to.value, divisibility));
					}
					else
					{
						transaction.address = decode_non_eth_address(to.address);
						transaction.value = from_eth(to.value, divisibility);
					}

					auto public_key = to_composite_public_key(from_link.public_key);
					if (!public_key)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(public_key.error().message())));

					auto type = legacy.eip_155 ? evm_transaction::evm_type::eip_155 : evm_transaction::evm_type::eip_1559;
					auto hash = transaction.hash(transaction.serialize(type));
					prepared_transaction result;
					if (contract_address)
						result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), *public_key, (uint8_t*)hash.data(), hash.size(), { { to.asset, to.value }, { native_asset, fee_value } });
					else
						result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), *public_key, (uint8_t*)hash.data(), hash.size(), { { native_asset, total_value } });
					result.requires_account_output(to.address, { { to.asset, to.value } });
					result.requires_abi(format::variable(!!legacy.eip_155));
					result.requires_abi(format::variable(contract_address.or_else(string())));
					result.requires_abi(format::variable(divisibility));
					result.requires_abi(format::variable(transaction.nonce));
					result.requires_abi(format::variable(transaction.chain_id));
					result.requires_abi(format::variable(transaction.gas_premium));
					result.requires_abi(format::variable(transaction.gas_price));
					result.requires_abi(format::variable(transaction.gas_limit));
					coreturn expects_rt<prepared_transaction>(std::move(result));
				});
			}
			expects_lr<finalized_transaction> ethereum::finalize_transaction(superchain::prepared_transaction&& prepared)
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
				transaction.gas_premium = prepared.abi[5].as_uint256();
				transaction.gas_price = prepared.abi[6].as_uint256();
				transaction.gas_limit = prepared.abi[7].as_uint256();
				if (!contract_address.empty())
				{
					if (output.tokens.empty())
						return layer_exception("invalid output");

					auto& output_token = output.tokens.begin()->second;
					transaction.address = decode_non_eth_address(contract_address);
					transaction.abi_data = sc_call::transfer(output.link.address, from_eth(output_token.value, divisibility));
				}
				else
				{
					auto fee_value = computed_fee::fee_per_gas_priority(to_eth(transaction.gas_premium, divisibility), to_eth(transaction.gas_price, divisibility), transaction.gas_limit).get_max_fee();
					transaction.address = decode_non_eth_address(output.link.address);
					transaction.value = from_eth(output.value, divisibility);
				}

				auto hash = transaction.hash(transaction.serialize(type));
				if (input.message.size() != hash.size() || memcmp(input.message.data(), hash.data(), hash.size()) != 0)
					return layer_exception("invalid input message");

				auto info = transaction.serialize_and_presign(type, input.signature.data());
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
					result.resize(BTC_ECKEY_COMPRESSED_LENGTH);
					size_t result_size = result.size();
					if (secp256k1_ec_pubkey_serialize(context, result.data(), &result_size, &result_public_key, SECP256K1_EC_COMPRESSED) != 1)
						return layer_exception("bad public key");

					return expects_lr<algorithm::composition::cpubkey_t>(result);
				}
				else if (input->size() == BTC_ECKEY_COMPRESSED_LENGTH)
					return expects_lr<algorithm::composition::cpubkey_t>(algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*input));

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
			const sc_chainparams_* ethereum::get_chain()
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
			string ethereum::get_raw_gas_limit(const format::tree& tx_data)
			{
				if (tx_data.has("receipt.gasUsed"))
					return tx_data.child_var("receipt.gasUsed").as_blob();

				if (tx_data.has("gasUsed"))
					return tx_data.child_var("gasUsed").as_blob();

				if (tx_data.has("gas"))
					return tx_data.child_var("gas").as_blob();

				if (tx_data.has("gasLimit"))
					return tx_data.child_var("gasLimit").as_blob();

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
				return algorithm::arithmetic::divide(value.to_decimal(), divisibility);
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

			arbitrum::arbitrum(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			avalanche::avalanche(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			base::base(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			blast::blast(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			bnb::bnb(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			celo::celo(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			ethereum_classic::ethereum_classic(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
				legacy.eip_155 = 1;
			}

			gnosis::gnosis(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			linea::linea(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			polygon::polygon(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			optimism::optimism(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			sonic::sonic(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}

			zksync::zksync(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
			}
		}
	}
}
