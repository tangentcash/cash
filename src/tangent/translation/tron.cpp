#include "tron.h"
#include "../service/superchain.h"
extern "C"
{
#include "../internal/bitcoin.h"
#include "../internal/secp256k1.h"
}
#include <secp256k1_recovery.h>

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			struct trx_transaction
			{
				string raw_transaction_id;
				uptr<schema> transaction_data;
			};

			static void pb_varint(format::wo_stream& message, uint64_t value)
			{
				uint64_t bits = value & 0x7f;
				value >>= 7;
				while (value > 0)
				{
					uint8_t byte = (uint8_t)(0x80 | bits);
					message.write_typeless(&byte, 1);
					bits = value & 0x7f;
					value >>= 7;
				}
				message.write_typeless(&bits, 1);
			}
			static void pb_bytes(format::wo_stream& message, uint32_t tag, const uint8_t* data, size_t data_size)
			{
				pb_varint(message, (tag << 3) | 2);
				pb_varint(message, data_size);
				message.write_typeless(data, data_size);
			}
			static void pb_bytes(format::wo_stream& message, uint32_t tag, const std::string_view& hex_data)
			{
				auto raw_data = codec::hex_decode(hex_data);
				pb_bytes(message, tag, (uint8_t*)raw_data.data(), raw_data.size());
			}
			static void pb_int64(format::wo_stream& message, uint32_t tag, int64_t data)
			{
				uint64_t zigzag_data = (static_cast<uint64_t>(data) << 1) ^ static_cast<uint64_t>(data >> 63);
				pb_varint(message, (tag << 3) | 0);
				pb_varint(message, data < 0 ? zigzag_data : data);
			}
			static void pb_message(format::wo_stream& message, uint32_t tag, uint64_t type, const std::string_view& type_url, const format::wo_stream& data)
			{
				format::wo_stream content_message;
				content_message.data.append(data.data);

				format::wo_stream child_message;
				pb_bytes(child_message, 1, (uint8_t*)type_url.data(), type_url.size());
				pb_varint(child_message, (2 << 3) | 2);
				pb_varint(child_message, content_message.data.size());
				child_message.data.append(data.data);

				format::wo_stream parent_message;
				pb_int64(parent_message, 1, type);
				pb_varint(parent_message, (2 << 3) | 2);
				pb_varint(parent_message, child_message.data.size());
				parent_message.data.append(child_message.data);

				pb_varint(message, (tag << 3) | 2);
				pb_varint(message, parent_message.data.size());
				message.data.append(parent_message.data);
			}
			static trx_transaction tx_serialize(const tron::trx_tx_block_header_info& block_header, const std::string_view& contract_address, const string& from_address, const string& to_address, const uint256_t& value, uint64_t fee_limit)
			{
				uint64_t contract_type;
				std::string_view contract_type_name;
				std::string_view contract_type_url;
				string contract_abi = ethereum::sc_call::transfer(to_address, value);
				format::wo_stream contract_message;
				if (!contract_address.empty())
				{
					contract_type = 31;
					contract_type_name = "TriggerSmartContract";
					contract_type_url = "type.googleapis.com/protocol.TriggerSmartContract";
					if (!from_address.empty())
						pb_bytes(contract_message, 1, from_address);
					if (!contract_address.empty())
						pb_bytes(contract_message, 2, contract_address);
					if (!contract_abi.empty())
						pb_bytes(contract_message, 4, (uint8_t*)contract_abi.data(), contract_abi.size());
				}
				else
				{
					contract_type = 1;
					contract_type_name = "TransferContract";
					contract_type_url = "type.googleapis.com/protocol.TransferContract";
					if (!from_address.empty())
						pb_bytes(contract_message, 1, from_address);
					if (!to_address.empty())
						pb_bytes(contract_message, 2, to_address);
					if (value > 0)
						pb_int64(contract_message, 3, (uint64_t)value);
				}

				format::wo_stream tx_message;
				if (!block_header.ref_block_bytes.empty())
					pb_bytes(tx_message, 1, block_header.ref_block_bytes);
				if (!block_header.ref_block_hash.empty())
					pb_bytes(tx_message, 4, block_header.ref_block_hash);
				if (block_header.expiration != 0)
					pb_int64(tx_message, 8, block_header.expiration);
				pb_message(tx_message, 11, contract_type, contract_type_url, contract_message);
				if (block_header.timestamp != 0)
					pb_int64(tx_message, 14, block_header.timestamp);
				if (fee_limit > 0)
					pb_int64(tx_message, 18, fee_limit);

				string& raw_transaction_data = tx_message.data;
				string raw_transaction_id = *crypto::hash(digests::sha256(), raw_transaction_data);
				uptr<schema> transaction_object = var::set::object();
				transaction_object->set("visible", var::boolean(false));
				transaction_object->set("txID", var::string(codec::hex_encode(raw_transaction_id)));
				transaction_object->set("raw_data_hex", var::string(codec::hex_encode(raw_transaction_data)));

				schema* raw_data_object = transaction_object->set("raw_data", var::set::object());
				schema* contract_object = raw_data_object->set("contract", var::set::array())->push(var::set::object());
				schema* parameter_object = contract_object->set("parameter", var::set::object());
				schema* value_object = parameter_object->set("value", var::set::object());
				parameter_object->set("type_url", var::string(contract_type_url));
				contract_object->set("type", var::string(contract_type_name));

				if (!contract_address.empty())
				{
					value_object->set("data", var::string(codec::hex_encode(contract_abi)));
					value_object->set("owner_address", var::string(from_address));
					value_object->set("contract_address", var::string(contract_address));
				}
				else
				{
					value_object->set("to_address", var::string(to_address));
					value_object->set("owner_address", var::string(from_address));
					value_object->set("amount", var::integer((uint64_t)value));
				}

				raw_data_object->set("ref_block_bytes", var::string(block_header.ref_block_bytes));
				raw_data_object->set("ref_block_hash", var::string(block_header.ref_block_hash));
				raw_data_object->set("expiration", var::integer(block_header.expiration));
				raw_data_object->set("timestamp", var::integer(block_header.timestamp));
				if (fee_limit > 0)
					raw_data_object->set("fee_limit", var::integer(fee_limit));

				trx_transaction result;
				result.raw_transaction_id = std::move(raw_transaction_id);
				result.transaction_data = std::move(transaction_object);
				return result;
			}

			const char* tron::trx_nd_call::broadcast_transaction()
			{
				return "/wallet/broadcasttransaction";
			}
			const char* tron::trx_nd_call::get_transaction_info_by_id()
			{
				return "/wallet/gettransactioninfobyid";
			}
			const char* tron::trx_nd_call::get_block()
			{
				return "/wallet/getblock";
			}

			tron::tron(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
				netdata.composition = algorithm::composition::type::secp256k1;
				netdata.routing = routing_policy::account;
				netdata.tokenization = token_policy::program;
				netdata.sync_latency = 20;
				netdata.divisibility = algorithm::arithmetic::fixed(1000000);
				netdata.supports_bulk_transfer = false;
				netdata.requires_transaction_expiration = true;
				legacy.estimate_gas = 1;
			}
			expects_promise_rt<tron::trx_tx_block_header_info> tron::get_block_header_for_tx()
			{
				schema* args = var::set::object();
				args->set("detail", var::boolean(false));

				auto block_data = coawait(execute_rest("POST", trx_nd_call::get_block(), args, cache_policy::no_cache));
				if (!block_data)
					coreturn expects_rt<tron::trx_tx_block_header_info>(std::move(block_data.error()));

				auto ref_block_bytes = uint128_t(block_data->fetch_var("block_header.raw_data.number").get_integer()).to_string(16);
				while (ref_block_bytes.size() < 4)
					ref_block_bytes.insert(ref_block_bytes.begin(), '0');

				auto ref_block_hash = block_data->get_var("blockID").get_blob();
				if (ref_block_hash.size() < 32)
					coreturn expects_rt<tron::trx_tx_block_header_info>(remote_exception("invalid ref block hash"));

				trx_tx_block_header_info info;
				info.ref_block_bytes = ref_block_bytes.substr(ref_block_bytes.size() - 4);
				info.ref_block_hash = ref_block_hash.substr(16, 16);
				info.timestamp = block_data->fetch_var("block_header.raw_data.timestamp").get_integer();
				info.expiration = info.timestamp + 60 * 1000;
				memory::release(*block_data);

				coreturn expects_rt<tron::trx_tx_block_header_info>(std::move(info));
			}
			expects_lr<void> tron::verify_node_compatibility(server_relay* node)
			{
				if (!node->has_distinct_url("jrpc"))
					return layer_exception("trongrid jrpc solidity node is required (default location http://hostname:8545/jsonrpc)");

				if (!node->has_distinct_url("rest"))
					return layer_exception("trongrid rest node is required (default location http://hostname:18190/)");

				return expectation::met;
			}
			expects_promise_rt<computed_transaction> tron::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* chain = get_chain();
				string data = transaction_data->get_var("input").get_blob();
				if (stringify::starts_with(data, chain->bech32_hrp))
					data.erase(0, strlen(chain->bech32_hrp));

				string tx_hash = transaction_data->get_var("hash").get_blob();
				string from = encode_eth_address(transaction_data->get_var("from").get_blob());
				string to = encode_eth_address(transaction_data->get_var("to").get_blob());
				decimal base_value = to_eth(hex_to_uint256(transaction_data->get_var("value").get_blob()), netdata.divisibility);

				computed_transaction result;
				result.transaction_id = tx_hash;

				hash_map<string, hash_map<algorithm::asset_id, decimal>> inputs;
				hash_map<string, hash_map<algorithm::asset_id, decimal>> outputs;
				if (base_value.is_positive())
				{
					inputs[from][native_asset] = base_value;
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
					auto* logs = transaction_data->get("logs");
					if (!logs)
					{
						auto tx_receipt = coawait(get_transaction_receipt(transaction_data->get_var("hash").get_blob(), true));
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
							if (topics && topics->size() == 3 && is_token_transfer(topics->get_var(0).get_blob()))
							{
								addresses.insert(encode_eth_address(normalize_topic_address(topics->get_var(1).get_blob())));
								addresses.insert(encode_eth_address(normalize_topic_address(topics->get_var(2).get_blob())));
							}
							else if (topics && topics->size() == 2 && is_token_transfer(topics->get_var(0).get_blob()))
								addresses.insert(encode_eth_address(topics->get_var(1).get_blob()));
						}
					}
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				if (!data.empty())
				{
					auto* logs = transaction_data->get("logs");
					if (logs != nullptr && !logs->empty())
					{
						for (auto& invocation : logs->get_childs())
						{
							auto* topics = invocation->get("topics");
							if (!topics || (topics->size() != 2 && topics->size() != 3) || !is_token_transfer(topics->get_var(0).get_blob()))
								continue;

							auto contract_address = encode_eth_address(invocation->get_var("address").get_blob());
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

							auto& token_input = inputs[from][token_asset];
							auto& token_output = outputs[to][token_asset];
							token_input = token_input.is_nan() ? token_value : (token_input + token_value);
							token_output = token_output.is_nan() ? token_value : (token_output + token_value);
							superchain::server_node::get()->enable_contract_address(token_asset, contract_address);
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

				auto args = uptr(var::set::object());
				args->set("value", var::string(tx_hash.starts_with("0x") ? std::string_view(tx_hash).substr(2) : std::string_view(tx_hash)));

				auto info = coawait(execute_rest("POST", trx_nd_call::get_transaction_info_by_id(), *args, cache_policy::blob_cache));
				if (!info || info->fetch_var("receipt.result").get_blob() != "SUCCESS")
					coreturn expects_rt<computed_transaction>(remote_exception("tx reverted"));

				auto fee_value = to_eth((uint64_t)info->get_var("fee").get_integer(), netdata.divisibility);
				if (fee_value.is_positive())
				{
					auto& input_value = inputs[from][native_asset];
					input_value = input_value.is_nan() ? fee_value : (input_value + fee_value);
				}

				memory::release(*info);
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
			}
			expects_promise_rt<decimal> tron::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				auto contract_address = superchain::server_node::get()->get_contract_address(for_asset);
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
					params->set("data", var::string(encode_0xhex(translations::ethereum::sc_call::balance_of(decode_non_eth_address(link.address)))));
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
			expects_promise_rt<void> tron::broadcast_transaction(const finalized_transaction& finalized)
			{
				auto native_data = codec::decompress(codec::hex_decode(finalized.calldata));
				if (!native_data)
					coreturn expects_rt<void>(remote_exception(std::move(native_data.error().message())));

				auto transaction_data = schema::from_json(*native_data);
				if (!transaction_data)
					coreturn expects_rt<void>(remote_exception(std::move(transaction_data.error().message())));

				auto hex_data = coawait(execute_rest("POST", trx_nd_call::broadcast_transaction(), *transaction_data, cache_policy::no_cache_no_throttling));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				bool success = hex_data->get_var("result").get_boolean();
				string code = hex_data->get_var("code").get_blob();
				string message = hex_data->get_var("message").get_blob();
				if (code.empty())
					code = hex_data->get_var("Error").get_blob();

				memory::release(*hex_data);
				if (!success)
					coreturn expects_rt<void>(remote_exception(message.empty() ? code : code + ": " + codec::hex_decode(message)));

				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> tron::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const decimal& max_fee)
			{
				auto chain_id = coawait(get_chain_id());
				if (!chain_id)
					coreturn expects_rt<prepared_transaction>(std::move(chain_id.error()));

				auto fee = coawait(estimate_transaction_fee(from_link, to));
				if (!fee)
					coreturn expects_rt<prepared_transaction>(std::move(fee.error()));

				auto& output = to.front();
				auto contract_address = superchain::server_node::get()->get_contract_address(output.asset);
				if (contract_address)
					fee->gas.gas_limit *= 4;

				decimal fee_value = fee->get_max_fee();
				if (fee_value > max_fee)
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

				if (contract_address)
				{
					auto balance = coawait(calculate_balance(output.asset, from_link));
					if (!balance || *balance < fee_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}

				auto total_value = contract_address ? fee_value : (output.value + fee_value);
				auto balance = coawait(calculate_balance(native_asset, from_link));
				if (!balance || *balance < total_value || total_value.is_negative())
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

				auto block_header = coawait(get_block_header_for_tx());
				if (!block_header)
					coreturn expects_rt<prepared_transaction>(std::move(block_header.error()));

				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(*contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				auto public_key = to_composite_public_key(from_link.public_key);
				if (!public_key)
					coreturn expects_rt<prepared_transaction>(remote_exception(std::move(public_key.error().message())));

				auto eth_contract_address = contract_address ? decode_non_eth_address_pf(*contract_address) : string();
				auto eth_from_address = decode_non_eth_address_pf(from_link.address);
				auto eth_to_address = decode_non_eth_address_pf(output.address);
				auto eth_value = from_eth(output.value, divisibility);
				auto fee_limit = from_eth(std::max(fee_value, max_fee), netdata.divisibility);
				auto transaction = tx_serialize(*block_header, eth_contract_address, eth_from_address, eth_to_address, eth_value, fee_limit);
				prepared_transaction result;
				if (contract_address)
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), *public_key, (uint8_t*)transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size(), { { output.asset, output.value }, { native_asset, fee_value } });
				else
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), *public_key, (uint8_t*)transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size(), { { native_asset, total_value } });
				result.requires_account_output(output.address, { { output.asset, output.value } });
				result.requires_abi(format::variable(contract_address.or_else(string())));
				result.requires_abi(format::variable(block_header->ref_block_bytes));
				result.requires_abi(format::variable(block_header->ref_block_hash));
				result.requires_abi(format::variable((uint64_t)block_header->expiration));
				result.requires_abi(format::variable((uint64_t)block_header->timestamp));
				result.requires_abi(format::variable(divisibility));
				result.requires_abi(format::variable(fee_limit));
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> tron::finalize_transaction(superchain::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 7)
					return layer_exception("invalid prepared abi");

				trx_tx_block_header_info block_header;
				block_header.ref_block_bytes = prepared.abi[1].as_blob();
				block_header.ref_block_hash = prepared.abi[2].as_blob();
				block_header.expiration = (int64_t)prepared.abi[3].as_uint64();
				block_header.timestamp = (int64_t)prepared.abi[4].as_uint64();

				auto& input = prepared.inputs.front();
				auto& output = prepared.outputs.front();
				auto divisibility = prepared.abi[5].as_decimal();
				auto contract_address = prepared.abi[0].as_blob();
				auto eth_contract_address = contract_address.empty() ? string() : decode_non_eth_address_pf(contract_address);
				auto eth_from_address = decode_non_eth_address_pf(input.utxo.link.address);
				auto eth_to_address = decode_non_eth_address_pf(output.link.address);
				auto eth_value = from_eth(output.tokens.empty() ? output.value : output.tokens.begin()->second.value, divisibility);
				auto fee_limit = prepared.abi[6].as_uint64();
				auto transaction = tx_serialize(block_header, eth_contract_address, eth_from_address, eth_to_address, eth_value, fee_limit);
				if (input.message.size() != transaction.raw_transaction_id.size() || memcmp(input.message.data(), transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size()))
					return layer_exception("invalid input message");

				uint8_t raw_signature[65];
				memcpy(raw_signature, input.signature.data(), std::min(input.signature.size(), sizeof(raw_signature)));
				if (raw_signature[64] > 0)
					raw_signature[64] = 0x1c;
				else
					raw_signature[64] = 0x1b;

				schema* signature_object = transaction.transaction_data->set("signature", var::array());
				signature_object->push(var::string(codec::hex_encode(std::string_view((char*)raw_signature, sizeof(raw_signature)))));

				auto native_data = codec::compress(schema::to_json(*transaction.transaction_data), compression::best_compression);
				if (!native_data)
					return layer_exception(std::move(native_data.error().message()));

				auto result = finalized_transaction(std::move(prepared), codec::hex_encode(*native_data), codec::hex_encode(transaction.raw_transaction_id));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			string tron::encode_eth_address(const std::string_view& eth_address)
			{
				auto* chain = get_chain();
				if (!stringify::starts_with(eth_address, "0x"))
					return string(eth_address);

				uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
				int offset = (int)base58_prefix_dump(chain->b58prefix_pubkey_address, hash160);
				int hash160_size = sizeof(hash160) - offset;
				utils_hex_to_bin(eth_address.data() + 2, hash160 + offset, (int)eth_address.size() - 2, &hash160_size);

				char address[128];
				btc_base58_encode_check(hash160, sizeof(uint160) + offset, address, 100);
				return address;
			}
			string tron::decode_non_eth_address(const std::string_view& non_eth_address)
			{
				auto* chain = get_chain();
				uint8_t hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
				int prefix_size = (int)base58_prefix_size(chain->b58prefix_pubkey_address);
				int size = btc_base58_decode_check(string(non_eth_address).c_str(), hash160, sizeof(hash160)) - prefix_size - 4;
				if (size < 20)
					return string();

				return encode_0xhex_checksum(hash160 + prefix_size, 20);
			}
			string tron::decode_non_eth_address_pf(const std::string_view& non_eth_address)
			{
				string address = decode_non_eth_address(non_eth_address);
				return stringify::to_lower(stringify::replace(address, "0x", "41"));
			}
			decimal tron::get_divisibility_gwei()
			{
				return decimal("1000000");
			}
			const sc_chainparams_* tron::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &trx_chainparams_regtest;
					case network_type::testnet:
						return &trx_chainparams_test;
					case network_type::mainnet:
						return &trx_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}