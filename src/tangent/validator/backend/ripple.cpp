#include "ripple.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/bip32.h"
#include "../internal/libbitcoin/ripemd160.h"
#include "../internal/libbitcoin/ecc.h"
#include "../internal/libripple/libbase58.h"
extern "C"
{
#include "../../internal/ed25519.h"
}
#include <sodium.h>

namespace tangent
{
	namespace warden
	{
		namespace backends
		{
			static uint64_t get_exponent(const decimal& value)
			{
				string raw_exponent = value.to_exponent();
				size_t index = raw_exponent.rfind("e+");
				if (index == std::string::npos)
					return 0;

				auto exponent = from_string<uint64_t>(raw_exponent.substr(index + 2));
				return exponent ? *exponent : 0;
			}
			static void tx_append(vector<uint8_t>& tx, const uint8_t* data, size_t data_size)
			{
				size_t offset = tx.size();
				tx.resize(tx.size() + data_size);
				memcpy(&tx[offset], data, data_size);
			}
			static void tx_append_uint16(vector<uint8_t>& tx, uint16_t data)
			{
				uint8_t buffer[sizeof(uint16_t)];
				buffer[0] = (uint8_t)(data & 0xFF);
				buffer[1] = (uint8_t)(data >> 8);
				tx_append(tx, buffer, sizeof(buffer));
			}
			static void tx_append_uint32(vector<uint8_t>& tx, uint32_t data)
			{
				uint8_t buffer[sizeof(uint32_t)];
				buffer[0] = (uint8_t)((data >> 24) & 0xFF);
				buffer[1] = (uint8_t)((data >> 16) & 0xFF);
				buffer[2] = (uint8_t)((data >> 8) & 0xFF);
				buffer[3] = (uint8_t)((data >> 0) & 0xFF);
				tx_append(tx, buffer, sizeof(buffer));
			}
			static void tx_append_uint64(vector<uint8_t>& tx, uint64_t data)
			{
				uint8_t buffer[sizeof(uint64_t)];
				buffer[0] = (uint8_t)(data >> 56);
				buffer[1] = (uint8_t)(data >> 48);
				buffer[2] = (uint8_t)(data >> 40);
				buffer[3] = (uint8_t)(data >> 32);
				buffer[4] = (uint8_t)(data >> 24);
				buffer[5] = (uint8_t)(data >> 16);
				buffer[6] = (uint8_t)(data >> 8);
				buffer[7] = (uint8_t)(data >> 0);
				tx_append(tx, buffer, sizeof(buffer));
			}
			static void tx_append_amount(vector<uint8_t>& tx, ripple* implementation, const std::string_view& asset, const std::string_view& issuer, const decimal& token_value, uint64_t base_value)
			{
				bool is_token = (!asset.empty() && !issuer.empty());
				uint64_t value = base_value, exponent = get_exponent(token_value);
				if (is_token)
				{
					string multiplier(1 + (exponent > 15 ? exponent - 15 : 15 - exponent), '0');
					multiplier[0] = '1';

					decimal adjusted_value = token_value * decimal(multiplier);
					value = adjusted_value.truncate(0).to_uint64();
				}

				uint32_t left = (value >> 32);
				uint32_t right = value & 0x00000000ffffffff;
				tx_append_uint32(tx, left);
				tx_append_uint32(tx, right);

				size_t offset = tx.size() - sizeof(uint32_t) * 2;
				uint8_t& bit1 = tx[offset + 0];
				if (!is_token)
				{
					bit1 |= 0x40;
					return;
				}

				uint8_t& bit2 = tx[offset + 1];
				bit1 |= 0x80;
				if (value > 0)
					bit1 |= 0x40;

				int8_t exponent_value = (int8_t)exponent - 15;
				uint8_t exponent_byte = 97 + exponent_value;
				bit1 |= exponent_byte >> 2;
				bit2 |= (exponent_byte & 0x03) << 6;

				uint8_t asset_buffer[20] = { 0 };
				if (asset.size() != 3)
				{
					string asset_data = codec::hex_decode(asset);
					memcpy(asset_buffer, asset_data.data(), std::min<size_t>(asset_data.size(), sizeof(asset_buffer)));
				}
				else
					memcpy(asset_buffer + 12, asset.data(), asset.size());
				tx_append(tx, asset_buffer, sizeof(asset_buffer));

				uint8_t public_key_hash[20] = { 0 };
				auto decoded_address = implementation->decode_address(issuer);
				if (decoded_address && decoded_address->size() == sizeof(public_key_hash))
					memcpy(public_key_hash, decoded_address->data(), sizeof(public_key_hash));
				tx_append(tx, public_key_hash, sizeof(public_key_hash));
			}
			static void tx_append_length(vector<uint8_t>& tx, size_t size)
			{
				uint8_t length[3] = { 0, 0, 0 };
				if (size <= 192)
				{
					length[0] = (uint8_t)size;
					tx_append(tx, length, sizeof(uint8_t) * 1);
				}
				else if (size <= 12480)
				{
					size -= 193;
					length[0] = (uint8_t)(193 + (size >> 8));
					length[1] = (uint8_t)(size & 0xFF);
					tx_append(tx, length, sizeof(uint8_t) * 2);
				}
				else if (size <= 918744)
				{
					size -= 12481;
					length[0] = (uint8_t)(241 + (size >> 16));
					length[1] = (uint8_t)((size >> 8) & 0xFF);
					length[2] = (uint8_t)(size & 0xFF);
					tx_append(tx, length, sizeof(uint8_t) * 3);
				}
			}
			static void tx_append_binary(vector<uint8_t>& tx, const uint8_t* data, size_t data_size)
			{
				tx_append_length(tx, data_size);
				tx_append(tx, data, data_size);
			}
			static void tx_append_public_key(vector<uint8_t>& tx, ripple* implementation, const std::string_view& data)
			{
				uint8_t public_key[33] = { 0xED };
				auto decoded_public_key = implementation->decode_public_key(data);
				if (decoded_public_key && decoded_public_key->size() == sizeof(public_key) - 1)
					memcpy(public_key + 1, decoded_public_key->data(), decoded_public_key->size());
				tx_append_binary(tx, public_key, sizeof(public_key));
			}
			static void tx_append_address(vector<uint8_t>& tx, ripple* implementation, const std::string_view& data)
			{
				uint8_t public_key_hash[20] = { 0 };
				auto decoded_address = implementation->decode_address(data);
				if (decoded_address && decoded_address->size() == sizeof(public_key_hash))
					memcpy(public_key_hash, decoded_address->data(), sizeof(public_key_hash));
				tx_append_binary(tx, public_key_hash, sizeof(public_key_hash));
			}
			static void tx_append_signature(vector<uint8_t>& tx, const std::string_view& data)
			{
				string binary = codec::hex_decode(data);
				tx_append_binary(tx, (uint8_t*)binary.data(), binary.size());
			}

			const char* ripple::nd_call::ledger()
			{
				return "ledger";
			}
			const char* ripple::nd_call::server_info()
			{
				return "server_info";
			}
			const char* ripple::nd_call::account_info()
			{
				return "account_info";
			}
			const char* ripple::nd_call::account_objects()
			{
				return "account_objects";
			}
			const char* ripple::nd_call::submit_transaction()
			{
				return "submit";
			}

			ripple::ripple(const algorithm::asset_id& new_asset) noexcept : relay_backend(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::memo;
				netdata.sync_latency = 0;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.decimal_precision);
				netdata.supports_token_transfer.clear();
				netdata.supports_bulk_transfer = false;
				netdata.requires_transaction_expiration = true;
			}
			expects_promise_rt<ripple::account_info> ripple::get_account_info(const std::string_view& address)
			{
				schema* params = var::set::object();
				params->set("account", var::string(address));
				params->set("ledger_index", var::string("current"));

				schema_list map;
				map.emplace_back(params);

				account_info info;
				auto account_data = coawait(execute_rpc(nd_call::account_info(), std::move(map), cache_policy::no_cache));
				if (account_data)
				{
					info.balance = from_drop(uint256_t(account_data->fetch_var("account_data.Balance").get_blob()));
					info.sequence = account_data->fetch_var("account_data.Sequence").get_integer();
					memory::release(*account_data);
				}
				else
					info.balance = decimal::zero();
				coreturn expects_rt<ripple::account_info>(std::move(info));
			}
			expects_promise_rt<ripple::account_token_info> ripple::get_account_token_info(const algorithm::asset_id& for_asset, const std::string_view& address)
			{
				account_token_info info;
				info.balance = 0.0;

				auto contract_address = nss::server_node::get()->get_contract_address(for_asset);
				size_t marker = 0, limit = 400;
				while (contract_address && limit > 0)
				{
					schema* params = var::set::object();
					params->set("account", var::string(address));
					params->set("ledger_index", var::string("current"));
					params->set("deletion_blockers_only", var::boolean(false));
					params->set("marker", var::integer(marker));
					params->set("limit", var::integer(limit));

					schema_list map;
					map.emplace_back(params);

					auto account_data = uptr<schema>(coawait(execute_rpc(nd_call::account_objects(), std::move(map), cache_policy::no_cache)));
					if (!account_data)
						break;

					auto* objects = account_data->get("account_objects");
					if (!objects || objects->empty())
						break;

					string issuer_checksum = contract_address->substr(contract_address->size() - 6);
					for (auto& object : objects->get_childs())
					{
						string token = object->fetch_var("Balance.currency").get_blob();
						if (token != algorithm::asset::token_of(for_asset))
							continue;

						string issuer = object->fetch_var("Balance.issuer").get_blob();
						if (issuer.substr(issuer.size() - 6) != issuer_checksum)
							continue;

						info.balance = object->fetch_var("Balance.value").get_decimal();
						limit = 0;
						break;
					}

					size_t size = objects->size();
					marker += size;
					if (size < limit)
						break;
				}

				coreturn expects_rt<ripple::account_token_info>(std::move(info));
			}
			expects_promise_rt<ripple::ledger_sequence_info> ripple::get_ledger_sequence_info()
			{
				schema* params = var::set::object();
				params->set("ledger_index", var::string("validated"));

				schema_list map;
				map.emplace_back(params);

				auto block_data = coawait(execute_rpc(nd_call::ledger(), std::move(map), cache_policy::no_cache));
				if (!block_data)
					coreturn expects_rt<ripple::ledger_sequence_info>(block_data.error());

				ledger_sequence_info info;
				info.index = block_data->get_var("ledger_index").get_integer();
				info.sequence = info.index + 20;
				memory::release(*block_data);
				coreturn expects_rt<ripple::ledger_sequence_info>(std::move(info));
			}
			expects_promise_rt<uint64_t> ripple::get_latest_block_height()
			{
				auto ledger_sequence_info = coawait(get_ledger_sequence_info());
				if (!ledger_sequence_info)
					coreturn expects_rt<uint64_t>(ledger_sequence_info.error());

				coreturn expects_rt<uint64_t>(ledger_sequence_info->index);
			}
			expects_promise_rt<schema*> ripple::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				schema* params = var::set::object();
				params->set("ledger_index", var::integer(block_height));
				params->set("transactions", var::boolean(true));
				params->set("expand", var::boolean(true));

				schema_list map;
				map.emplace_back(params);

				auto block_data = coawait(execute_rpc(nd_call::ledger(), std::move(map), cache_policy::blob_cache));
				if (!block_data)
					coreturn block_data;

				if (block_hash != nullptr)
					*block_hash = block_data->get_var("ledger_hash").get_blob();

				auto* transactions = block_data->fetch("ledger.transactions");
				if (!transactions)
				{
					memory::release(*block_data);
					coreturn expects_rt<schema*>(remote_exception("ledger.transactions field not found"));
				}

				transactions->unlink();
				memory::release(*block_data);
				coreturn expects_rt<schema*>(transactions);
			}
			expects_promise_rt<computed_transaction> ripple::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				string tx_hash = transaction_data->get_var("hash").get_blob();
				string type = transaction_data->get_var("TransactionType").get_blob();
				string from = transaction_data->get_var("Account").get_blob();
				string to = transaction_data->get_var("Destination").get_blob();
				decimal fee_value = from_drop(uint256_t(transaction_data->get_var("Fee").get_blob()));
				auto* amount = transaction_data->get("Amount");
				if (type != "Payment" || !amount)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				decimal base_value = 0.0, token_value = 0.0;
				algorithm::asset_id token_asset = native_asset;
				if (amount->value.is_object())
				{
					string token = amount->get_var("currency").get_blob();
					string issuer = amount->fetch_var("issuer").get_blob();
					token_value = amount->get_var("value").get_decimal();
					token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), token, issuer);
					nss::server_node::get()->enable_contract_address(token_asset, issuer);
				}
				else
					base_value = from_drop(uint256_t(amount->value.get_blob()));

				auto destination_tag = transaction_data->get_var("DestinationTag").get_blob();
				auto to_tag = address_util::encode_tag_address(to, destination_tag);
				auto discovery = find_linked_addresses({ from, to, to_tag });
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				computed_transaction tx;
				tx.transaction_id = tx_hash;

				auto total_value = base_value + fee_value;
				auto target_from_link = discovery->find(from);
				auto target_to_link = discovery->find(to);
				auto target_to_tag_link = discovery->find(to_tag);
				unordered_map<algorithm::asset_id, decimal> inputs;
				unordered_map<algorithm::asset_id, decimal> outputs;
				if (total_value.is_positive())
				{
					inputs[native_asset] = total_value;
					outputs[native_asset] = base_value;
				}
				if (token_value.is_positive())
				{
					inputs[token_asset] = token_value;
					outputs[token_asset] = token_value;
				}
				if (!inputs.empty())
					tx.inputs.push_back(coin_utxo(target_from_link != discovery->end() ? target_from_link->second : wallet_link::from_address(from), std::move(inputs)));
				if (!outputs.empty())
					tx.inputs.push_back(coin_utxo(target_to_tag_link != discovery->end() ? target_to_tag_link->second : (target_to_link != discovery->end() ? target_to_link->second : wallet_link::from_address(to)), std::move(outputs)));
				coreturn expects_rt<computed_transaction>(std::move(tx));
			}
			expects_promise_rt<computed_fee> ripple::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				schema_list map;
				map.emplace_back(var::set::object());

				auto server_info = coawait(execute_rpc(nd_call::server_info(), std::move(map), cache_policy::no_cache));
				if (!server_info)
					coreturn expects_rt<computed_fee>(std::move(server_info.error()));

				decimal base_constant_fee = server_info->fetch_var("info.validated_ledger.base_fee_xrp").get_decimal();
				if (!base_constant_fee.is_positive())
					base_constant_fee = get_base_fee_xrp();

				decimal load_factor = server_info->fetch_var("info.load_factor").get_decimal();
				if (!load_factor.is_positive())
					load_factor = 1.0;

				decimal fee_cushion = 1.2;
				memory::release(*server_info);
				coreturn expects_rt<computed_fee>(computed_fee::flat_fee(base_constant_fee * load_factor * fee_cushion));
			}
			expects_promise_rt<decimal> ripple::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				if (!algorithm::asset::token_of(for_asset).empty())
				{
					auto account = coawait(get_account_token_info(for_asset, link.address));
					if (!account)
						coreturn expects_rt<decimal>(std::move(account.error()));

					coreturn expects_rt<decimal>(std::move(account->balance));
				}
				else
				{
					auto account = coawait(get_account_info(link.address));
					if (!account)
						coreturn expects_rt<decimal>(std::move(account.error()));

					coreturn expects_rt<decimal>(std::move(account->balance));
				}
			}
			expects_promise_rt<void> ripple::broadcast_transaction(const finalized_transaction& finalized)
			{
				schema* params = var::set::object();
				params->set("tx_blob", var::string(format::util::clear_0xhex(finalized.calldata, true)));
				params->set("fail_hard", var::boolean(true));

				schema_list map;
				map.emplace_back(params);

				auto hex_data = coawait(execute_rpc(nd_call::submit_transaction(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				string error_message = hex_data->get_var("engine_result_message").get_blob();
				bool is_accepted = hex_data->get_var("accepted").get_boolean();
				memory::release(*hex_data);
				if (is_accepted)
					coreturn expects_rt<void>(expectation::met);
				else if (error_message.empty())
					error_message = "broadcast error";

				coreturn expects_rt<void>(remote_exception(std::move(error_message)));
			}
			expects_promise_rt<prepared_transaction> ripple::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto account_info = coawait(get_account_info(from_link.address));
				if (!account_info)
					coreturn expects_rt<prepared_transaction>(std::move(account_info.error()));

				auto ledger_info = coawait(get_ledger_sequence_info());
				if (!ledger_info)
					coreturn expects_rt<prepared_transaction>(std::move(ledger_info.error()));

				auto& output = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(output.asset);
				decimal total_value = output.value;
				decimal fee_value = fee.get_max_fee();
				if (contract_address)
				{
					auto account_token_info = coawait(get_account_token_info(output.asset, *contract_address));
					if (!account_token_info || account_token_info->balance < total_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (account_token_info ? account_token_info->balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));
					total_value = fee_value;
				}
				else
					total_value += fee_value;

				if (account_info->balance < total_value)
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", account_info->balance.to_string().c_str(), total_value.to_string().c_str())));

				auto [output_address, output_tag] = address_util::decode_tag_address(output.address);
				transaction_buffer buffer;
				buffer.transaction_type = 0;
				buffer.flags = 0;
				buffer.sequence = (uint32_t)account_info->sequence;
				buffer.destination_tag = from_string<uint32_t>(output_tag).or_else(0);
				buffer.last_ledger_sequence = (uint32_t)ledger_info->sequence;
				buffer.fee = (uint64_t)to_drop(fee_value);
				buffer.signing_pub_key = from_link.public_key;
				buffer.account = from_link.address;
				buffer.destination = output_address;
				if (contract_address)
				{
					buffer.amount.token_value = output.value;
					buffer.amount.asset = algorithm::asset::token_of(output.asset);
					buffer.amount.issuer = *contract_address;
				}
				else
					buffer.amount.base_value = (uint64_t)to_drop(output.value);

				auto signing_public_key = decode_public_key(from_link.public_key);
				if (!signing_public_key)
					coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

				auto public_key = algorithm::composition::cpubkey_t(*signing_public_key);
				auto message = tx_serialize(&buffer, true);
				prepared_transaction result;
				if (contract_address)
					result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key.data, message.data(), message.size(), { { output.asset, output.value }, { native_asset, fee_value } });
				else
					result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key.data, message.data(), message.size(), { { native_asset, output.value + fee_value } });
				result.requires_account_output(output.address, { { output.asset, output.value } });
				result.requires_abi(format::variable(contract_address.or_else(string())));
				result.requires_abi(format::variable(buffer.sequence));
				result.requires_abi(format::variable(buffer.last_ledger_sequence));
				result.requires_abi(format::variable(buffer.fee));
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> ripple::finalize_transaction(warden::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 4)
					return layer_exception("invalid prepared abi");

				auto& input = prepared.inputs.front();
				auto& output = prepared.outputs.front();
				auto [output_address, output_tag] = address_util::decode_tag_address(output.link.address);
				auto contract_address = prepared.abi[0].as_string();
				transaction_buffer buffer;
				buffer.transaction_type = 0;
				buffer.flags = 0;
				buffer.sequence = prepared.abi[1].as_uint32();
				buffer.destination_tag = from_string<uint32_t>(output_tag).or_else(0);
				buffer.last_ledger_sequence = prepared.abi[2].as_uint32();
				buffer.fee = prepared.abi[3].as_uint64();
				buffer.signing_pub_key = input.utxo.link.public_key;
				buffer.account = input.utxo.link.address;
				buffer.destination = output_address;
				buffer.txn_signature = codec::hex_encode(std::string_view((char*)input.signature.data, algorithm::composition::size_of_signature(input.alg)));
				if (!contract_address.empty())
				{
					if (output.tokens.empty())
						return layer_exception("invalid output");

					auto& output_token = output.tokens.front();
					buffer.amount.token_value = output_token.value;
					buffer.amount.asset = algorithm::asset::token_of(output_token.get_asset(native_asset));
					buffer.amount.issuer = contract_address;
				}
				else
					buffer.amount.base_value = (uint64_t)to_drop(output.value);

				auto message = tx_serialize(&buffer, true);
				if (input.message.size() != message.size() || memcmp(input.message.data(), message.data(), message.size()) != 0)
					return layer_exception("invalid input message");

				auto raw_transaction_data = tx_serialize(&buffer, false);
				auto result = finalized_transaction(std::move(prepared), codec::hex_encode(std::string_view((char*)&raw_transaction_data[0], raw_transaction_data.size()), true), tx_hash(raw_transaction_data));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<secret_box> ripple::encode_secret_key(const secret_box& secret_key)
			{
				if (secret_key.size() != 32)
					return layer_exception("invalid private key");

				auto data = secret_key.expose<KEY_LIMIT>();
				return secret_box::secure(codec::hex_encode(data.view));
			}
			expects_lr<secret_box> ripple::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				uint8_t raw_secret_key[128]; size_t raw_secret_key_size = sizeof(raw_secret_key);
				if (xb58check_dec(data.view.data(), raw_secret_key, &raw_secret_key_size) || raw_secret_key_size != 19)
					return secret_box::secure(std::string_view((char*)raw_secret_key + 3, raw_secret_key_size - 3));

				string result = codec::hex_decode(data.view);
				if (result.size() != 32)
					return layer_exception("not a valid private key");

				return secret_box::secure(result);
			}
			expects_lr<string> ripple::encode_public_key(const std::string_view& public_key)
			{
				if (public_key.size() != 32 && public_key.size() != 33)
					return layer_exception("not a valid ed25519 public key");

				if (public_key.size() == 33)
					return codec::hex_encode(public_key, true);

				string copy = string(1, '\xED');
				copy.append(public_key);
				return codec::hex_encode(copy, true);
			}
			expects_lr<string> ripple::decode_public_key(const std::string_view& public_key)
			{
				auto result = codec::hex_decode(public_key);
				if (result.size() != 32 && result.size() != 33)
					return layer_exception("not a valid ed25519 public key");

				return result.size() == 33 ? result.substr(1) : result;
			}
			expects_lr<string> ripple::encode_address(const std::string_view& public_key_hash)
			{
				if (public_key_hash.size() < 20)
					return layer_exception("invalid public key hash");

				char intermediate[256];
				size_t intermediate_size = sizeof(intermediate);
				uint8_t versions = 0x0;
				xb58check_enc(intermediate, &intermediate_size, &versions, sizeof(versions), public_key_hash.data(), 20);
				return warden::address_util::encode_tag_address(std::string_view(intermediate, intermediate_size - 1), public_key_hash.substr(20));
			}
			expects_lr<string> ripple::decode_address(const std::string_view& address)
			{
				auto [base_address, tag] = warden::address_util::decode_tag_address(address);
				uint8_t intermediate[128];
				size_t intermediate_size = sizeof(intermediate);
				if (!xb58check_dec(base_address.c_str(), intermediate, &intermediate_size))
					return layer_exception("invalid address");

				if (intermediate_size != 21)
					return layer_exception("invalid address size");

				auto result = string((char*)intermediate + 1, intermediate_size - 1);
				result.append(tag);
				return result;
			}
			expects_lr<string> ripple::encode_transaction_id(const std::string_view& transaction_id)
			{
				return codec::hex_encode(transaction_id, true);
			}
			expects_lr<string> ripple::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = codec::hex_decode(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> ripple::to_addresses(const std::string_view& input_public_key)
			{
				string raw_public_key = string(input_public_key);
				if (raw_public_key.size() != 32 && raw_public_key.size() != 33)
				{
					raw_public_key = codec::hex_decode(raw_public_key);
					if (raw_public_key.size() != 32 && raw_public_key.size() != 33)
						return layer_exception("invalid public key");
				}

				uint8_t public_key[33];
				size_t offset = raw_public_key.size() == 33 ? 1 : 0;
				memcpy(public_key + 1, raw_public_key.data() + offset, raw_public_key.size() - offset);
				public_key[0] = 0xED;

				uint8_t public_key_hash256[32];
				sha256_Raw(public_key, sizeof(public_key), public_key_hash256);

				uint160 public_key_hash160;
				btc_ripemd160(public_key_hash256, sizeof(public_key_hash256), public_key_hash160);

				char intermediate[256];
				size_t intermediate_size = sizeof(intermediate);
				uint8_t versions = 0x0;
				xb58check_enc(intermediate, &intermediate_size, &versions, sizeof(versions), public_key_hash160, sizeof(public_key_hash160));

				address_map result = { { (uint8_t)1, string(intermediate, intermediate_size - 1) } };
				return expects_lr<address_map>(std::move(result));
			}
			const ripple::chainparams& ripple::get_chainparams() const
			{
				return netdata;
			}
			vector<uint8_t> ripple::tx_serialize(transaction_buffer* tx_data, bool signing_data)
			{
				static const uint8_t transaction_type[1] = { 18 };
				static const uint8_t flags[1] = { 34 };
				static const uint8_t sequence[1] = { 36 };
				static const uint8_t destination_tag[1] = { 46 };
				static const uint8_t last_ledger_sequence[2] = { 32, 27 };
				static const uint8_t amount[1] = { 97 };
				static const uint8_t fee[1] = { 104 };
				static const uint8_t signing_pub_key[1] = { 115 };
				static const uint8_t txn_signature[1] = { 116 };
				static const uint8_t account[1] = { 129 };
				static const uint8_t destination[1] = { 131 };

				vector<uint8_t> tx;
				if (signing_data)
					tx_append_uint32(tx, 0x53545800);
				tx_append(tx, transaction_type, sizeof(transaction_type));
				tx_append_uint16(tx, tx_data->transaction_type);
				tx_append(tx, flags, sizeof(flags));
				tx_append_uint32(tx, tx_data->flags);
				tx_append(tx, sequence, sizeof(sequence));
				tx_append_uint32(tx, tx_data->sequence);
				tx_append(tx, destination_tag, sizeof(destination_tag));
				tx_append_uint32(tx, tx_data->destination_tag);
				tx_append(tx, last_ledger_sequence, sizeof(last_ledger_sequence));
				tx_append_uint32(tx, tx_data->last_ledger_sequence);
				tx_append(tx, amount, sizeof(amount));
				tx_append_amount(tx, this, tx_data->amount.asset, tx_data->amount.issuer, tx_data->amount.token_value, tx_data->amount.base_value);
				tx_append(tx, fee, sizeof(fee));
				tx_append_amount(tx, this, string(), string(), decimal::nan(), tx_data->fee);
				tx_append(tx, signing_pub_key, sizeof(signing_pub_key));
				tx_append_public_key(tx, this, tx_data->signing_pub_key);
				if (!signing_data)
				{
					tx_append(tx, txn_signature, sizeof(txn_signature));
					tx_append_signature(tx, tx_data->txn_signature);
				}
				tx_append(tx, account, sizeof(account));
				tx_append_address(tx, this, tx_data->account);
				tx_append(tx, destination, sizeof(destination));
				tx_append_address(tx, this, tx_data->destination);
				return tx;
			}
			string ripple::tx_hash(const vector<uint8_t>& tx_blob)
			{
				vector<uint8_t> tx;
				tx.reserve(sizeof(uint32_t) + tx_blob.size());
				tx_append_uint32(tx, 0x54584e00);
				tx_append(tx, tx_blob.data(), tx_blob.size());

				uint8_t hash512[64];
				sha512_Raw(tx.data(), tx.size(), hash512);
				return codec::hex_encode(std::string_view((char*)hash512, sizeof(hash512) / 2), true);
			}
			decimal ripple::get_base_fee_xrp()
			{
				return 0.00001;
			}
			decimal ripple::from_drop(const uint256_t& value)
			{
				return decimal(value.to_string()) / netdata.divisibility;
			}
			uint256_t ripple::to_drop(const decimal& value)
			{
				return uint256_t((value * netdata.divisibility).truncate(0).to_string());
			}
			const btc_chainparams_* ripple::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &xrp_chainparams_regtest;
					case network_type::testnet:
						return &xrp_chainparams_test;
					case network_type::mainnet:
						return &xrp_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}
