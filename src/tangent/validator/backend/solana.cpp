#include "solana.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/bip32.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/utils.h"
#include "../internal/libbitcoin/ecc.h"
extern "C"
{
#include "../../internal/ed25519.h"
#include "../../internal/base58.h"
}
#include <sodium.h>

namespace tangent
{
	namespace warden
	{
		namespace backends
		{
			struct transaction_header
			{
				uint8_t required_signatures;
				uint8_t readonly_signed_accounts;
				uint8_t readonly_unsigned_accounts;
			};

			static void tx_append(vector<uint8_t>& tx, const uint8_t* data, size_t data_size)
			{
				size_t offset = tx.size();
				tx.resize(tx.size() + data_size);
				memcpy(&tx[offset], data, data_size);
			}

			string solana::nd_call::get_token_metadata(const std::string_view& mint)
			{
				return stringify::text("https://api.solana.fm/v1/tokens/%" PRIu64, (int)mint.size(), mint.data());
			}
			const char* solana::nd_call::get_token_balance()
			{
				return "getTokenAccountsByOwner";
			}
			const char* solana::nd_call::get_balance()
			{
				return "getBalance";
			}
			const char* solana::nd_call::get_block_hash()
			{
				return "getLatestBlockhash";
			}
			const char* solana::nd_call::get_slot()
			{
				return "getSlot";
			}
			const char* solana::nd_call::get_block()
			{
				return "getBlock";
			}
			const char* solana::nd_call::send_transaction()
			{
				return "sendTransaction";
			}

			solana::solana(const algorithm::asset_id& new_asset) noexcept : relay_backend(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 30;
				netdata.divisibility = decimal(1000000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "spl";
				netdata.supports_bulk_transfer = false;
				netdata.requires_transaction_expiration = true;
			}
			expects_promise_rt<uint64_t> solana::get_latest_block_height()
			{
				auto block_height = coawait(execute_rpc(nd_call::get_slot(), { }, cache_policy::no_cache));
				if (!block_height)
					coreturn expects_rt<uint64_t>(std::move(block_height.error()));

				uint64_t value = (uint64_t)block_height->value.get_integer();
				memory::release(*block_height);
				coreturn expects_rt<uint64_t>(value);
			}
			expects_promise_rt<schema*> solana::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				uptr<schema> config = var::set::object();
				config->set("encoding", var::string("jsonParsed"));
				config->set("maxSupportedTransactionVersion", var::integer(0));
				config->set("transactionDetails", var::string("full"));
				config->set("rewards", var::boolean(false));

				schema_list map;
				map.emplace_back(var::set::integer(block_height));
				map.emplace_back(std::move(config));

				auto block_data = coawait(execute_rpc(nd_call::get_block(), std::move(map), cache_policy::blob_cache));
				if (!block_data)
					coreturn block_data;

				if (block_hash != nullptr)
					*block_hash = block_data->get_var("blockhash").get_blob();

				auto* transactions = block_data->get("transactions");
				if (!transactions)
				{
					memory::release(*block_data);
					coreturn expects_rt<schema*>(remote_exception("transactions field not found"));
				}

				transactions->unlink();
				memory::release(*block_data);
				coreturn expects_rt<schema*>(transactions);
			}
			expects_promise_rt<computed_transaction> solana::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* error = transaction_data->fetch("meta.status.Err");
				if (error != nullptr)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				auto* pre_balances = transaction_data->fetch("meta.preBalances");
				auto* post_balances = transaction_data->fetch("meta.postBalances");
				auto* account_keys = transaction_data->fetch("transaction.message.accountKeys");
				if (!pre_balances || !post_balances || pre_balances->size() != post_balances->size() || pre_balances->empty() || !account_keys)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				bool non_transferring = true;
				for (size_t i = 0; i < pre_balances->size(); i++)
				{
					if (pre_balances->get(i)->value.get_decimal() != post_balances->get(i)->value.get_decimal())
					{
						non_transferring = false;
						break;
					}
				}
				if (non_transferring)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				unordered_set<string> addresses;
				for (auto& account_key : account_keys->get_childs())
					addresses.insert(account_key->get_var("pubkey").get_blob());

				auto* pre_token_balances = transaction_data->fetch("meta.preTokenBalances");
				if (pre_token_balances != nullptr)
				{
					for (auto& balance : pre_token_balances->get_childs())
						addresses.insert(balance->get_var("owner").get_blob());
				}

				auto* post_token_balances = transaction_data->fetch("meta.postTokenBalances");
				if (post_token_balances != nullptr)
				{
					for (auto& balance : post_token_balances->get_childs())
						addresses.insert(balance->get_var("owner").get_blob());
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				auto* instructions = transaction_data->fetch("transaction.message.instructions");
				if (!instructions || instructions->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not valid"));

				auto signature = transaction_data->fetch_var("transaction.signatures.0").get_blob();
				auto fee_value = transaction_data->fetch_var("meta.fee").get_decimal() / netdata.divisibility;
				bool fee_included = false;

				computed_transaction tx;
				tx.transaction_id = signature;

				unordered_map<string, unordered_map<algorithm::asset_id, decimal>> inputs;
				unordered_map<string, unordered_map<algorithm::asset_id, decimal>> outputs;
				for (auto& instruction : instructions->get_childs())
				{
					auto* info = instruction->fetch("parsed.info");
					auto type = instruction->fetch_var("parsed.type").get_blob();
					if (!info || type.empty())
						continue;

					if (type == "transfer" || type == "transferWithSeed")
					{
						auto from = info->get_var("source").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;
						else if (value.is_nan())
							continue;

						auto& native_input = inputs[from][native_asset], native_output = outputs[to][native_asset];
						native_input = (native_input.is_nan() ? value : (native_input + value)) + fee_value;
						native_output = native_output.is_nan() ? value : (native_output + value);
						fee_included = true;
					}
					else if (type == "createAccount" || type == "createAccountWithSeed")
					{
						auto from = info->get_var("source").get_blob();
						auto to = info->get_var("newAccount").get_blob();
						auto value = info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;
						else if (value.is_nan())
							continue;

						auto& native_input = inputs[from][native_asset], native_output = outputs[to][native_asset];
						native_input = (native_input.is_nan() ? value : (native_input + value)) + fee_value;
						native_output = native_output.is_nan() ? value : (native_output + value);
						fee_included = true;
					}
					else if (type == "withdrawFromNonce")
					{
						auto from = info->get_var("nonceAccount").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;
						else if (value.is_nan())
							continue;

						auto& native_input = inputs[from][native_asset], native_output = outputs[to][native_asset];
						native_input = (native_input.is_nan() ? value : (native_input + value)) + fee_value;
						native_output = native_output.is_nan() ? value : (native_output + value);
						fee_included = true;
					}
					else if (type == "withdraw")
					{
						auto from = info->get_var("stakeAccount").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;
						else if (value.is_nan())
							continue;

						auto& native_input = inputs[from][native_asset], native_output = outputs[to][native_asset];
						native_input = (native_input.is_nan() ? value : (native_input + value)) + fee_value;
						native_output = native_output.is_nan() ? value : (native_output + value);
						fee_included = true;
					}
					else if (type == "split")
					{
						auto from = info->get_var("stakeAccount").get_blob();
						auto to = info->get_var("newSplitAccount").get_blob();
						auto value = info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;
						else if (value.is_nan())
							continue;

						auto& native_input = inputs[from][native_asset], native_output = outputs[to][native_asset];
						native_input = (native_input.is_nan() ? value : (native_input + value)) + fee_value;
						native_output = native_output.is_nan() ? value : (native_output + value);
						fee_included = true;
					}
				}

				unordered_map<string, unordered_map<string, decimal>> prev_token_state;
				if (pre_token_balances != nullptr && !pre_token_balances->empty())
				{
					for (auto& balance : pre_token_balances->get_childs())
					{
						decimal value = balance->fetch_var("uiTokenAmount.amount").get_decimal();
						if (!value.is_positive())
							continue;

						uint64_t subdivisions = 1;
						uint64_t decimals = std::min<uint64_t>(balance->fetch_var("uiTokenAmount.decimals").get_integer(), protocol::now().message.precision);
						for (uint64_t i = 0; i < decimals; i++)
							subdivisions *= 10;

						string mint = balance->get_var("mint").get_blob();
						string owner = balance->get_var("owner").get_blob();
						auto& change = prev_token_state[mint][owner];
						value /= decimal(subdivisions).truncate(protocol::now().message.precision);
						change = change.is_nan() ? value : (change + value);
					}
				}

				unordered_map<string, unordered_map<string, decimal>> next_token_state;
				if (post_token_balances != nullptr && !post_token_balances->empty())
				{
					for (auto& balance : post_token_balances->get_childs())
					{
						decimal value = balance->fetch_var("uiTokenAmount.amount").get_decimal();
						if (value.is_nan() || value.is_negative())
							continue;

						uint64_t subdivisions = 1;
						uint64_t decimals = std::min<uint64_t>(balance->fetch_var("uiTokenAmount.decimals").get_integer(), protocol::now().message.precision);
						for (uint64_t i = 0; i < decimals; i++)
							subdivisions *= 10;

						string mint = balance->get_var("mint").get_blob();
						string owner = balance->get_var("owner").get_blob();
						auto& change = next_token_state[mint][owner];
						value /= decimal(subdivisions).truncate(protocol::now().message.precision);
						change = change.is_nan() ? value : (value + change);
					}
				}

				auto blockchain = algorithm::asset::blockchain_of(native_asset);
				for (auto& [contract_address, balances] : next_token_state)
				{
					auto symbol = coawait(get_token_symbol(contract_address));
					auto token_asset = algorithm::asset::id_of(blockchain, symbol.or_else(contract_address), contract_address);
					nss::server_node::get()->enable_contract_address(token_asset, contract_address);

					auto& prev_balances = prev_token_state[contract_address];
					for (auto& [owner, next_balance] : balances)
					{
						auto& prev_balance = prev_balances[owner];
						if (prev_balance.is_nan())
							prev_balance = decimal::zero();

						if (prev_balance > next_balance)
						{
							auto token_value = prev_balance - next_balance;
							auto& token_input = inputs[owner][token_asset];
							token_input = token_input.is_nan() ? token_value : (token_input + token_value);
						}
						else if (prev_balance < next_balance)
						{
							auto token_value = next_balance - prev_balance;
							auto& token_output = outputs[owner][token_asset];
							token_output = token_output.is_nan() ? token_value : (token_output + token_value);
						}
					}
				}

				addresses.clear();
				addresses.reserve(inputs.size() + outputs.size());
				for (auto& next : inputs)
					addresses.insert(next.first);
				for (auto& next : outputs)
					addresses.insert(next.first);

				discovery = find_linked_addresses(addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				if (!fee_included && !inputs.empty())
				{
					auto& native_input = inputs.begin()->second[native_asset];
					native_input = (native_input.is_nan() ? fee_value : (native_input + fee_value));
				}

				tx.inputs.reserve(inputs.size());
				for (auto& [address, values] : inputs)
				{
					auto target_link = discovery->find(address);
					tx.inputs.push_back(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
				}

				tx.outputs.reserve(outputs.size());
				for (auto& [address, values] : outputs)
				{
					auto target_link = discovery->find(address);
					tx.outputs.push_back(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
				}

				coreturn expects_rt<computed_transaction>(std::move(tx));
			}
			expects_promise_rt<computed_fee> solana::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				decimal fee = 5000;
				if (!algorithm::asset::token_of(to.front().asset).empty())
					fee += fee * 2;
				fee /= netdata.divisibility;
				coreturn expects_rt<computed_fee>(computed_fee::flat_fee(fee));
			}
			expects_promise_rt<decimal> solana::calculate_balance(const algorithm::asset_id& asset, const wallet_link& link)
			{
				if (algorithm::asset::token_of(asset).empty())
				{
					schema_list map;
					map.emplace_back(var::set::string(link.address));
					map.emplace_back(var::set::null());

					auto balance = coawait(execute_rpc(nd_call::get_balance(), std::move(map), cache_policy::no_cache));
					if (!balance)
						coreturn expects_rt<decimal>(std::move(balance.error()));

					decimal value = balance->get_var("value").get_decimal().truncate(protocol::now().message.precision);
					value /= netdata.divisibility;

					memory::release(*balance);
					coreturn expects_rt<decimal>(to_value(value));
				}
				else
				{
					auto contract_address = nss::server_node::get()->get_contract_address(asset);
					if (!contract_address)
						coreturn expects_rt<decimal>(remote_exception("contract address not found"));

					auto token_balance = coawait(get_token_balance(*contract_address, link.address));
					if (!token_balance)
						coreturn expects_rt<decimal>(std::move(token_balance.error()));

					coreturn expects_rt<decimal>(std::move(token_balance->balance));
				}
			}
			expects_promise_rt<void> solana::broadcast_transaction(const finalized_transaction& finalized)
			{
				schema_list map;
				map.emplace_back(var::set::string(finalized.calldata));
				map.emplace_back(var::set::null());

				auto status = coawait(execute_rpc(nd_call::send_transaction(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!status)
					coreturn expects_rt<void>(std::move(status.error()));

				memory::release(*status);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> solana::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto native_balance = coawait(get_balance(from_link.address));
				if (!native_balance)
					coreturn expects_rt<prepared_transaction>(std::move(native_balance.error()));

				auto recent_block_hash = coawait(get_recent_block_hash());
				if (!recent_block_hash)
					coreturn expects_rt<prepared_transaction>(std::move(recent_block_hash.error()));

				auto& output = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(output.asset);
				option<token_account> from_token = optional::none;
				option<token_account> to_token = optional::none;
				decimal total_value = output.value;
				decimal fee_value = fee.get_max_fee();
				if (contract_address)
				{
					auto from_token_balance = coawait(get_token_balance(*contract_address, from_link.address));
					if (!from_token_balance || from_token_balance->balance < total_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (from_token_balance ? from_token_balance->balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

					auto to_token_balance = coawait(get_token_balance(*contract_address, output.address));
					if (!to_token_balance)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("account %s does not have associated token account (create token account before sending)", output.address.c_str())));

					total_value = fee_value;
					from_token = std::move(*from_token_balance);
					to_token = std::move(*to_token_balance);
				}
				else
					total_value += fee_value;

				if (*native_balance < total_value)
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", native_balance->to_string().c_str(), total_value.to_string().c_str())));

				sol_transaction transaction;
				transaction.token_program_address = from_token ? from_token->program_id : string();
				transaction.from_token_address = from_token ? from_token->account : string();
				transaction.to_token_address = to_token ? to_token->account : string();
				transaction.from_address = from_link.address;
				transaction.to_address = output.address;
				transaction.recent_block_hash = *recent_block_hash;
				transaction.value = (output.value * (from_token ? from_token->divisibility : netdata.divisibility)).to_uint64();

				vector<uint8_t> message_buffer = tx_message_serialize(&transaction);
				if (message_buffer.empty())
					coreturn expects_rt<prepared_transaction>(remote_exception("tx serialization error (one or more addresses is invalid)"));

				auto signing_public_key = decode_public_key(from_link.public_key);
				if (!signing_public_key)
					coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

				auto public_key = algorithm::composition::cpubkey_t(*signing_public_key);
				prepared_transaction result;
				if (contract_address)
					result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key.data, message_buffer.data(), message_buffer.size(), { { output.asset, output.value }, { native_asset, fee_value } });
				else
					result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key.data, message_buffer.data(), message_buffer.size(), { { native_asset, output.value + fee_value } });
				result.requires_account_output(output.address, { { output.asset, output.value } });
				result.requires_abi(format::variable(from_token ? from_token->divisibility : netdata.divisibility));
				result.requires_abi(format::variable(transaction.token_program_address));
				result.requires_abi(format::variable(transaction.from_token_address));
				result.requires_abi(format::variable(transaction.to_token_address));
				result.requires_abi(format::variable(transaction.recent_block_hash));
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> solana::finalize_transaction(warden::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 5)
					return layer_exception("invalid prepared abi");

				auto& input = prepared.inputs.front();
				auto& output = prepared.outputs.front();
				auto divisibility = prepared.abi[0].as_decimal();
				sol_transaction transaction;
				transaction.token_program_address = prepared.abi[1].as_blob();
				transaction.from_token_address = prepared.abi[2].as_blob();
				transaction.to_token_address = prepared.abi[3].as_blob();
				transaction.from_address = input.utxo.link.address;
				transaction.to_address = output.link.address;
				transaction.recent_block_hash = prepared.abi[4].as_blob();
				transaction.value = ((output.tokens.empty() ? output.value : output.tokens.front().value) * divisibility).to_uint64();

				vector<uint8_t> message_buffer = tx_message_serialize(&transaction);
				if (input.message.size() != message_buffer.size() || memcmp(input.message.data(), message_buffer.data(), message_buffer.size()))
					return layer_exception("invalid input message");

				char transaction_id[256]; size_t transaction_id_size = sizeof(transaction_id);
				if (!b58enc(transaction_id, &transaction_id_size, input.signature, algorithm::composition::size_of_signature(input.alg)))
					return layer_exception("invalid signature");

				vector<uint8_t> transaction_buffer = tx_result_serialize(message_buffer, input.signature, algorithm::composition::size_of_signature(input.alg));
				size_t transaction_data_size = transaction_buffer.size() * 4;
				string transaction_data;
				transaction_data.resize(transaction_data_size);
				if (!b58enc(transaction_data.data(), &transaction_data_size, &transaction_buffer[0], transaction_buffer.size()))
					return layer_exception("tx serialization error");

				transaction_data.resize(transaction_data_size - 1);
				auto result = finalized_transaction(std::move(prepared), std::move(transaction_data), string((char*)transaction_id, transaction_id_size - 1));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<secret_box> solana::encode_secret_key(const secret_box& secret_key)
			{
				if (secret_key.size() != 32)
					return layer_exception("bad private key");

				auto data = secret_key.expose<KEY_LIMIT>();
				uint8_t private_key[64];
				ed25519_publickey_ext(data.buffer, private_key + 32);
				memcpy(private_key, data.buffer, data.view.size());

				char encoded_private_key[128]; size_t encoded_private_key_size = sizeof(encoded_private_key);
				if (!b58enc(encoded_private_key, &encoded_private_key_size, private_key, sizeof(private_key)))
					return layer_exception("invalid private key");

				return secret_box::secure(std::string_view((char*)encoded_private_key, encoded_private_key_size - 1));
			}
			expects_lr<secret_box> solana::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				uint8_t private_key[64]; size_t private_key_size = sizeof(private_key);
				if (!b58dec(private_key, &private_key_size, data.view.data(), data.view.size()))
					return layer_exception("bad private key");

				if (private_key_size == 32)
				{
					sha512_Raw(private_key, private_key_size, private_key);
					algorithm::keypair_utils::convert_to_secret_key_ed25519(private_key);
				}

				return secret_box::secure(std::string_view((char*)private_key, sizeof(private_key)));
			}
			expects_lr<string> solana::encode_public_key(const std::string_view& public_key)
			{
				char encoded_public_key[256]; size_t encoded_public_key_size = sizeof(encoded_public_key);
				if (!b58enc(encoded_public_key, &encoded_public_key_size, public_key.data(), public_key.size()))
					return layer_exception("invalid public key");

				return string(encoded_public_key, encoded_public_key_size - 1);
			}
			expects_lr<string> solana::decode_public_key(const std::string_view& public_key)
			{
				uint8_t data[64]; size_t data_size = sizeof(data);
				if (!b58dec(data, &data_size, public_key.data(), public_key.size()))
					return layer_exception("invalid public key");

				return string((char*)data, data_size);
			}
			expects_lr<string> solana::encode_address(const std::string_view& public_key_hash)
			{
				return encode_public_key(public_key_hash);
			}
			expects_lr<string> solana::decode_address(const std::string_view& address)
			{
				return decode_public_key(address);
			}
			expects_lr<string> solana::encode_transaction_id(const std::string_view& transaction_id)
			{
				return format::util::encode_0xhex(transaction_id);
			}
			expects_lr<string> solana::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = format::util::decode_0xhex(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> solana::to_addresses(const std::string_view& input_public_key)
			{
				auto public_key = string(input_public_key);
				if (public_key.size() != 32)
				{
					auto raw_public_key = decode_public_key(public_key);
					if (!raw_public_key)
						return raw_public_key.error();

					public_key = std::move(*raw_public_key);
				}

				auto address = encode_public_key(public_key);
				if (!address)
					return address.error();

				address_map result = { { (uint8_t)1, *address } };
				return expects_lr<address_map>(std::move(result));
			}
			expects_promise_rt<string> solana::get_token_symbol(const std::string_view& mint)
			{
				auto metadata = coawait(execute_http("GET", nd_call::get_token_metadata(mint), std::string_view(), std::string_view(), cache_policy::lifetime_cache));
				if (!metadata)
					coreturn expects_rt<string>(std::move(metadata.error()));

				string symbol1 = metadata->fetch_var("tokenList.symbol").get_blob();
				string symbol2 = metadata->fetch_var("tokenMetadata.onChainInfo.symbol").get_blob();
				memory::release(*metadata);
				if (!symbol2.empty())
					coreturn expects_rt<string>(std::move(symbol2));

				if (!symbol1.empty())
					coreturn expects_rt<string>(std::move(symbol1));

				coreturn expects_rt<string>(remote_exception("mint not found"));
			}
			expects_promise_rt<solana::token_account> solana::get_token_balance(const std::string_view& mint, const std::string_view& owner)
			{
				schema_list map;
				map.emplace_back(var::set::string(owner));
				map.emplace_back(var::set::object());
				map.back()->set("mint", var::string(mint));
				map.emplace_back(var::set::object());
				map.back()->set("encoding", var::string("jsonParsed"));

				auto balance = coawait(execute_rpc(nd_call::get_token_balance(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!balance)
					coreturn expects_rt<token_account>(std::move(balance.error()));

				auto* info = balance->fetch("value.0.account.data.parsed.info.tokenAmount");
				if (!info)
				{
					memory::release(*balance);
					coreturn expects_rt<token_account>(remote_exception("invalid account"));
				}

				uint64_t subdivisions = 1;
				uint64_t decimals = std::min<uint64_t>(info->get_var("decimals").get_integer(), protocol::now().message.precision);
				for (uint64_t i = 0; i < decimals; i++)
					subdivisions *= 10;

				string program_id = balance->fetch_var("value.0.account.owner").get_blob();
				string account = balance->fetch_var("value.0.pubkey").get_blob();
				decimal value = info->get_var("amount").get_decimal();
				memory::release(*balance);
				if (value.is_nan())
					coreturn expects_rt<token_account>(remote_exception("invalid account"));

				token_account result;
				result.program_id = std::move(program_id);
				result.account = std::move(account);
				result.divisibility = decimal(subdivisions).truncate(protocol::now().message.precision);
				result.balance = value / result.divisibility;
				coreturn expects_rt<token_account>(std::move(result));
			}
			expects_promise_rt<decimal> solana::get_balance(const std::string_view& owner)
			{
				schema_list map;
				map.emplace_back(var::set::string(owner));

				auto balance = coawait(execute_rpc(nd_call::get_balance(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!balance)
					coreturn expects_rt<decimal>(std::move(balance.error()));

				decimal value = balance->get_var("value").get_decimal();
				memory::release(*balance);
				if (value.is_nan())
					coreturn expects_rt<decimal>(remote_exception("invalid account"));

				value /= netdata.divisibility;
				coreturn expects_rt<decimal>(std::move(value));
			}
			expects_promise_rt<string> solana::get_recent_block_hash()
			{
				auto hash = coawait(execute_rpc(nd_call::get_block_hash(), { }, cache_policy::no_cache_no_throttling));
				if (!hash)
					coreturn expects_rt<string>(std::move(hash.error()));

				string value = hash->fetch_var("value.blockhash").get_blob();
				memory::release(*hash);
				if (value.empty())
					coreturn expects_rt<string>(remote_exception("invalid hash"));

				coreturn expects_rt<string>(std::move(value));
			}
			vector<uint8_t> solana::tx_message_serialize(sol_transaction* tx_data)
			{
				uint8_t from_token_buffer[32]; size_t from_token_buffer_size = sizeof(from_token_buffer);
				if (!tx_data->from_token_address.empty() && !b58dec(from_token_buffer, &from_token_buffer_size, tx_data->from_token_address.c_str(), tx_data->from_token_address.size()))
					return vector<uint8_t>();

				uint8_t from_buffer[32]; size_t from_buffer_size = sizeof(from_buffer);
				if (!b58dec(from_buffer, &from_buffer_size, tx_data->from_address.c_str(), tx_data->from_address.size()))
					return vector<uint8_t>();

				uint8_t to_token_buffer[32]; size_t to_token_buffer_size = sizeof(to_token_buffer);
				if (!tx_data->to_token_address.empty() && !b58dec(to_token_buffer, &to_token_buffer_size, tx_data->to_token_address.c_str(), tx_data->to_token_address.size()))
					return vector<uint8_t>();

				uint8_t to_buffer[32]; size_t to_buffer_size = sizeof(to_buffer);
				if (!b58dec(to_buffer, &to_buffer_size, tx_data->to_address.c_str(), tx_data->to_address.size()))
					return vector<uint8_t>();

				uint8_t program_id[32]; size_t program_id_size = sizeof(program_id);
				string system_program_id = !tx_data->token_program_address.empty() ? tx_data->token_program_address.c_str() : "11111111111111111111111111111111";
				if (!b58dec(program_id, &program_id_size, system_program_id.c_str(), system_program_id.size()))
					return vector<uint8_t>();

				uint8_t block_hash[32]; size_t block_hash_size = sizeof(block_hash);
				if (!b58dec(block_hash, &block_hash_size, tx_data->recent_block_hash.c_str(), tx_data->recent_block_hash.size()))
					return vector<uint8_t>();

				bool is_token_transfer = !tx_data->from_token_address.empty() || !tx_data->to_token_address.empty() || !tx_data->token_program_address.empty();
				uint8_t prefix = 1 << 7;
				uint8_t account_keys = is_token_transfer ? 4 : 3;
				uint8_t instructions = 1;
				uint8_t lookups = 0;

				transaction_header header;
				header.required_signatures = 1;
				header.readonly_signed_accounts = 0;
				header.readonly_unsigned_accounts = 1;

				vector<uint8_t> message_buffer;
				tx_append(message_buffer, (uint8_t*)&prefix, sizeof(prefix));
				tx_append(message_buffer, (uint8_t*)&header, sizeof(header));
				tx_append(message_buffer, (uint8_t*)&account_keys, sizeof(account_keys));
				tx_append(message_buffer, from_buffer, from_buffer_size);
				if (is_token_transfer)
				{
					tx_append(message_buffer, from_token_buffer, from_token_buffer_size);
					tx_append(message_buffer, to_token_buffer, to_token_buffer_size);
				}
				else
					tx_append(message_buffer, to_buffer, to_buffer_size);
				tx_append(message_buffer, program_id, program_id_size);
				tx_append(message_buffer, block_hash, block_hash_size);
				tx_append(message_buffer, (uint8_t*)&instructions, sizeof(instructions));
				if (is_token_transfer)
				{
					uint8_t indices = 3, size = 9, instruction = 3;
					uint8_t program_id_index = 3, from_index = 0, to_index = 1, owner_index = 2;
					tx_append(message_buffer, (uint8_t*)&program_id_index, sizeof(program_id_index));
					tx_append(message_buffer, (uint8_t*)&indices, sizeof(indices));
					tx_append(message_buffer, (uint8_t*)&to_index, sizeof(to_index));
					tx_append(message_buffer, (uint8_t*)&owner_index, sizeof(owner_index));
					tx_append(message_buffer, (uint8_t*)&from_index, sizeof(from_index));
					tx_append(message_buffer, (uint8_t*)&size, sizeof(size));
					tx_append(message_buffer, (uint8_t*)&instruction, sizeof(instruction));
					tx_append(message_buffer, (uint8_t*)&tx_data->value, sizeof(tx_data->value));
				}
				else
				{
					uint8_t indices = 2, size = 4 + 8;
					uint8_t program_id_index = 2, from_index = 0, to_index = 1;
					uint32_t instruction = os::hw::to_endianness<uint32_t>(os::hw::endian::little, 2);
					tx_append(message_buffer, (uint8_t*)&program_id_index, sizeof(program_id_index));
					tx_append(message_buffer, (uint8_t*)&indices, sizeof(indices));
					tx_append(message_buffer, (uint8_t*)&from_index, sizeof(from_index));
					tx_append(message_buffer, (uint8_t*)&to_index, sizeof(to_index));
					tx_append(message_buffer, (uint8_t*)&size, sizeof(size));
					tx_append(message_buffer, (uint8_t*)&instruction, sizeof(instruction));
					tx_append(message_buffer, (uint8_t*)&tx_data->value, sizeof(tx_data->value));
				}
				tx_append(message_buffer, (uint8_t*)&lookups, sizeof(lookups));
				return message_buffer;
			}
			vector<uint8_t> solana::tx_result_serialize(const vector<uint8_t>& tx_buffer, const algorithm::composition::cpubsig signature, size_t signature_size)
			{
				uint8_t signatures = 1;
				vector<uint8_t> result_buffer;
				tx_append(result_buffer, (uint8_t*)&signatures, sizeof(signatures));
				tx_append(result_buffer, signature, signature_size);

				size_t signature_buffer_size = result_buffer.size();
				result_buffer.resize(signature_buffer_size + tx_buffer.size());
				memcpy(result_buffer.data() + signature_buffer_size, (uint8_t*)tx_buffer.data(), tx_buffer.size());
				return result_buffer;
			}
			const solana::chainparams& solana::get_chainparams() const
			{
				return netdata;
			}
			const btc_chainparams_* solana::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &sol_chainparams_regtest;
					case network_type::testnet:
						return &sol_chainparams_test;
					case network_type::mainnet:
						return &sol_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}