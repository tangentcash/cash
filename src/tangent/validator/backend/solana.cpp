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
	namespace mediator
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
			const char* solana::nd_call::get_block_number()
			{
				return "getBlockHeight";
			}
			const char* solana::nd_call::get_block()
			{
				return "getBlock";
			}
			const char* solana::nd_call::get_transaction()
			{
				return "getTransaction";
			}
			const char* solana::nd_call::send_transaction()
			{
				return "sendTransaction";
			}

			solana::solana() noexcept : relay_backend()
			{
				netdata.composition = algorithm::composition::type::ED25519;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 31;
				netdata.divisibility = decimal(1000000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "spl";
				netdata.supports_bulk_transfer = false;
			}
			expects_promise_rt<void> solana::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				schema_list map;
				map.emplace_back(var::set::string(tx_data.data));
				map.emplace_back(var::set::null());

				auto status = coawait(execute_rpc(asset, nd_call::send_transaction(), std::move(map), cache_policy::greedy));
				if (!status)
					coreturn expects_rt<void>(std::move(status.error()));

				memory::release(*status);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<uint64_t> solana::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto block_height = coawait(execute_rpc(asset, nd_call::get_block_number(), { }, cache_policy::lazy));
				if (!block_height)
					coreturn expects_rt<uint64_t>(std::move(block_height.error()));

				uint64_t value = (uint64_t)block_height->value.get_integer();
				memory::release(*block_height);
				coreturn expects_rt<uint64_t>(value);
			}
			expects_promise_rt<schema*> solana::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				uptr<schema> config = var::set::object();
				config->set("encoding", var::string("jsonParsed"));
				config->set("maxSupportedTransactionVersion", var::integer(0));
				config->set("transactionDetails", var::string("accounts"));
				config->set("rewards", var::boolean(false));

				schema_list map;
				map.emplace_back(var::set::integer(block_height));
				map.emplace_back(std::move(config));

				auto block_data = coawait(execute_rpc(asset, nd_call::get_block(), std::move(map), cache_policy::shortened));
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
			expects_promise_rt<schema*> solana::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::assign_0xhex(transaction_id)));
				map.emplace_back(var::set::null());

				auto tx_data = coawait(execute_rpc(asset, nd_call::get_transaction(), std::move(map), cache_policy::extended));
				coreturn tx_data;
			}
			expects_promise_rt<vector<incoming_transaction>> solana::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* error = transaction_data->fetch("meta.status.Err");
				if (error != nullptr)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				auto* pre_balances = transaction_data->fetch("meta.preBalances");
				auto* post_balances = transaction_data->fetch("meta.postBalances");
				auto* account_keys = transaction_data->fetch("transaction.accountKeys");
				if (!pre_balances || !post_balances || pre_balances->size() != post_balances->size() || pre_balances->empty() || !account_keys)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

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
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				unordered_set<string> addresses;
				for (auto& account_key : account_keys->get_childs())
				{
					if (account_key->get_var("writable").get_boolean() || account_key->get_var("signer").get_boolean())
						addresses.insert(account_key->get_var("pubkey").get_blob());
				}

				auto discovery = find_checkpoint_addresses(asset, addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				auto* instructions = transaction_data->fetch("transaction.message.instructions");
				if (!instructions || instructions->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not valid"));

				vector<incoming_transaction> transactions;
				unordered_map<string, unordered_map<string, decimal>> balances;
				auto signature = transaction_data->fetch_var("transaction.signatures.0").get_blob();
				auto fee_value = transaction_data->fetch_var("meta.fee").get_decimal() / netdata.divisibility;
				for (auto& instruction : instructions->get_childs())
				{
					auto* info = instruction->fetch("parsed.info");
					if (!info)
						continue;

					auto type = info->get_var("type").get_blob();
					if (type == "transfer" || type == "transferWithSeed")
					{
						auto from = info->get_var("source").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = fee_value + info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;

						incoming_transaction tx;
						tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal(fee_value));
						tx.set_operations({ transferer(from, optional::none, decimal(value)) }, { transferer(to, optional::none, decimal(value)) });
						transactions.push_back(std::move(tx));
					}
					else if (type == "createAccount" || type == "createAccountWithSeed")
					{
						auto from = info->get_var("source").get_blob();
						auto to = info->get_var("newAccount").get_blob();
						auto value = fee_value + info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;

						incoming_transaction tx;
						tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal(fee_value));
						tx.set_operations({ transferer(from, optional::none, decimal(value)) }, { transferer(to, optional::none, decimal(value)) });
						transactions.push_back(std::move(tx));
					}
					else if (type == "withdrawFromNonce")
					{
						auto from = info->get_var("nonceAccount").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = fee_value + info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;

						incoming_transaction tx;
						tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal(fee_value));
						tx.set_operations({ transferer(from, optional::none, decimal(value)) }, { transferer(to, optional::none, decimal(value)) });
						transactions.push_back(std::move(tx));
					}
					else if (type == "withdraw")
					{
						auto from = info->get_var("stakeAccount").get_blob();
						auto to = info->get_var("destination").get_blob();
						auto value = fee_value + info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;

						incoming_transaction tx;
						tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal(fee_value));
						tx.set_operations({ transferer(from, optional::none, decimal(value)) }, { transferer(to, optional::none, decimal(value)) });
						transactions.push_back(std::move(tx));
					}
					else if (type == "split")
					{
						auto from = info->get_var("stakeAccount").get_blob();
						auto to = info->get_var("newSplitAccount").get_blob();
						auto value = fee_value + info->get_var("lamports").get_decimal() / netdata.divisibility;
						if (!addresses.count(from) && !addresses.count(to))
							continue;

						incoming_transaction tx;
						tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal(fee_value));
						tx.set_operations({ transferer(from, optional::none, decimal(value)) }, { transferer(to, optional::none, decimal(value)) });
						transactions.push_back(std::move(tx));
					}
				}

				auto* pre_token_balances = transaction_data->fetch("meta.preTokenBalances");
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
						string owner = balance->get_var("mint").get_blob();
						auto& change = balances[mint][owner];
						value /= decimal(subdivisions).truncate(protocol::now().message.precision);
						change = change.is_nan() ? value : (change + value);
					}
				}

				auto* post_token_balances = transaction_data->fetch("meta.postTokenBalances");
				if (post_token_balances != nullptr && !post_token_balances->empty())
				{
					for (auto& balance : post_token_balances->get_childs())
					{
						decimal value = balance->fetch_var("uiTokenAmount.amount").get_decimal();
						if (!value.is_positive())
							continue;

						uint64_t subdivisions = 1;
						uint64_t decimals = std::min<uint64_t>(balance->fetch_var("uiTokenAmount.decimals").get_integer(), protocol::now().message.precision);
						for (uint64_t i = 0; i < decimals; i++)
							subdivisions *= 10;

						string mint = balance->get_var("mint").get_blob();
						string owner = balance->get_var("mint").get_blob();
						auto& change = balances[mint][owner];
						value /= decimal(subdivisions).truncate(protocol::now().message.precision);
						change = change.is_nan() ? value : (value - change);
					}
				}

				for (auto& token : balances)
				{
					size_t index = transactions.size();
					for (auto& a : token.second)
					{
						if (a.second.is_positive())
						{
							incoming_transaction tx;
							tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal::zero());
							for (auto& b : token.second)
							{
								if (!b.second.is_negative())
									continue;

								decimal delta = std::min(a.second, -b.second);
								tx.set_operations({ transferer(b.first, optional::none, decimal(delta)) }, { transferer(a.first, optional::none, decimal(delta)) });
								a.second -= delta;
								b.second += delta;
								if (a.second.is_zero())
									break;
							}
							transactions.push_back(std::move(tx));
						}
						else if (a.second.is_negative())
						{
							incoming_transaction tx;
							tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, signature, decimal::zero());
							for (auto& b : token.second)
							{
								if (!b.second.is_positive())
									continue;

								decimal delta = std::min(-a.second, b.second);
								tx.set_operations({ transferer(a.first, optional::none, decimal(delta)) }, { transferer(b.first, optional::none, decimal(delta)) });
								a.second += delta;
								b.second -= delta;
								if (a.second.is_zero())
									break;
							}
							transactions.push_back(std::move(tx));
						}
					}
					if (index == transactions.size())
						continue;

					auto symbol = coawait(get_token_symbol(token.first));
					auto replacement = algorithm::asset::id_of(algorithm::asset::blockchain_of(asset), symbol ? *symbol : token.first, token.first);
					for (size_t i = index - 1; i < transactions.size(); i++)
						transactions[i].asset = replacement;

					if (!nss::server_node::get()->enable_contract_address(replacement, token.first))
						coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));
				}

				addresses.clear();
				addresses.reserve(transactions.size() * 2);
				for (auto& item : transactions)
				{
					for (auto& next : item.from)
						addresses.insert(next.address);
					for (auto& next : item.to)
						addresses.insert(next.address);
				}

				discovery = find_checkpoint_addresses(asset, addresses);
				if (!discovery || discovery->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				for (auto& item : transactions)
				{
					for (auto& next : item.from)
					{
						auto address = discovery->find(next.address);
						if (address != discovery->end())
							next.address_index = address->second;
					}
					for (auto& next : item.to)
					{
						auto address = discovery->find(next.address);
						if (address != discovery->end())
							next.address_index = address->second;
					}
				}

				coreturn expects_rt<vector<incoming_transaction>>(std::move(transactions));
			}
			expects_promise_rt<base_fee> solana::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				decimal fee = 5000;
				if (!algorithm::asset::token_of(asset).empty())
					fee += fee * 2;
				fee /= netdata.divisibility;
				coreturn expects_rt<base_fee>(base_fee(fee, 1));
			}
			expects_promise_rt<decimal> solana::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
			{
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

				schema_list map;
				map.emplace_back(var::set::string(*address));
				map.emplace_back(var::set::null());

				auto balance = coawait(execute_rpc(asset, nd_call::get_balance(), std::move(map), cache_policy::lazy));
				if (!balance)
					coreturn expects_rt<decimal>(std::move(balance.error()));

				decimal value = balance->get_var("value").get_decimal();
				memory::release(*balance);
				coreturn expects_rt<decimal>(value);
			}
			expects_promise_rt<outgoing_transaction> solana::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> from_wallet = layer_exception();
				if (wallet.parent)
					from_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					from_wallet = *wallet.signing_child;
				if (!from_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("signing wallet not found"));

				auto native_balance = coawait(get_balance(asset, from_wallet->addresses.begin()->second));
				if (!native_balance)
					coreturn expects_rt<outgoing_transaction>(std::move(native_balance.error()));

				auto recent_block_hash = coawait(get_recent_block_hash(asset));
				if (!recent_block_hash)
					coreturn expects_rt<outgoing_transaction>(std::move(recent_block_hash.error()));

				auto& subject = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				option<token_account> from_token = optional::none;
				option<token_account> to_token = optional::none;
				decimal total_value = subject.value;
				decimal fee_value = fee.get_fee();
				if (contract_address)
				{
					auto from_token_balance = coawait(get_token_balance(asset, *contract_address, from_wallet->addresses.begin()->second));
					if (!from_token_balance || from_token_balance->balance < total_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (from_token_balance ? from_token_balance->balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

					auto to_token_balance = coawait(get_token_balance(asset, *contract_address, subject.address));
					if (!to_token_balance)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("account %s does not have associated token account", subject.address.c_str())));

					total_value = fee_value;
					from_token = std::move(*from_token_balance);
					to_token = std::move(*to_token_balance);
				}
				else
					total_value += fee_value;

				if (*native_balance < total_value)
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", native_balance->to_string().c_str(), total_value.to_string().c_str())));

				uint8_t from_token_buffer[32]; size_t from_token_buffer_size = sizeof(from_token_buffer);
				if (from_token && !b58dec(from_token_buffer, &from_token_buffer_size, from_token->account.c_str(), from_token->account.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid sender token account"));

				uint8_t from_buffer[32]; size_t from_buffer_size = sizeof(from_buffer);
				if (!b58dec(from_buffer, &from_buffer_size, from_wallet->addresses.begin()->second.c_str(), from_wallet->addresses.begin()->second.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid sender account"));

				uint8_t to_buffer[32]; size_t to_buffer_size = sizeof(to_buffer);
				if (to_token && !b58dec(to_buffer, &to_buffer_size, to_token->account.c_str(), to_token->account.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid receiver token account"));
				else if (!b58dec(to_buffer, &to_buffer_size, subject.address.c_str(), subject.address.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid receiver account"));

				uint8_t program_id[32]; size_t program_id_size = sizeof(program_id);
				string system_program_id = from_token ? from_token->program_id.c_str() : "11111111111111111111111111111111";
				if (!b58dec(program_id, &program_id_size, system_program_id.c_str(), system_program_id.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid system program id"));

				uint8_t block_hash[32]; size_t block_hash_size = sizeof(block_hash);
				if (!b58dec(block_hash, &block_hash_size, recent_block_hash->c_str(), recent_block_hash->size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid recent block hash"));

				uint64_t value = (subject.value * (from_token ? from_token->divisibility : netdata.divisibility)).to_uint64();
				uint8_t prefix = 1 << 7;
				uint8_t signatures = 1;
				uint8_t account_keys = contract_address ? 4 : 3;
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
				if (contract_address)
					tx_append(message_buffer, from_token_buffer, from_token_buffer_size);
				tx_append(message_buffer, to_buffer, to_buffer_size);
				tx_append(message_buffer, program_id, program_id_size);
				tx_append(message_buffer, block_hash, block_hash_size);
				tx_append(message_buffer, (uint8_t*)&instructions, sizeof(instructions));
				if (contract_address)
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
					tx_append(message_buffer, (uint8_t*)&value, sizeof(value));
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
					tx_append(message_buffer, (uint8_t*)&value, sizeof(value));
				}
				tx_append(message_buffer, (uint8_t*)&lookups, sizeof(lookups));

				uint8_t private_key[64];
				if (!decode_private_key(from_wallet->signing_key.expose<KEY_LIMIT>().view, private_key))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid private key"));

				uint8_t public_key[32]; size_t public_key_size = sizeof(public_key);
				if (!b58dec(public_key, &public_key_size, from_wallet->verifying_key.c_str(), from_wallet->verifying_key.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid public key"));

				ed25519_signature signature;
				ed25519_sign_ext(message_buffer.data(), message_buffer.size(), private_key, private_key + 32, signature);
				if (crypto_sign_ed25519_verify_detached(signature, message_buffer.data(), message_buffer.size(), public_key) != 0)
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid private key"));

				vector<uint8_t> transaction_buffer;
				tx_append(transaction_buffer, (uint8_t*)&signatures, sizeof(signatures));
				tx_append(transaction_buffer, (uint8_t*)&signature, sizeof(signature));
				transaction_buffer.insert(transaction_buffer.end(), message_buffer.begin(), message_buffer.end());

				char transaction_id[256]; size_t transaction_id_size = sizeof(transaction_id);
				if (!b58enc(transaction_id, &transaction_id_size, &signature, sizeof(signature)))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid signature"));

				string transaction_data;
				transaction_data.resize(transaction_buffer.size() * 4);

				size_t transaction_data_size = transaction_data.size();
				if (!b58enc(transaction_data.data(), &transaction_data_size, &transaction_buffer[0], transaction_buffer.size()))
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

				transaction_data.resize(transaction_data_size - 1);
				incoming_transaction tx;
				tx.set_transaction(asset, 0, std::string_view(transaction_id, transaction_id_size - 1), std::move(fee_value));
				tx.set_operations({ transferer(from_wallet->addresses.begin()->second, option<uint64_t>(from_wallet->address_index), decimal(from_token ? subject.value : total_value)) }, vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data)));
			}
			expects_promise_rt<string> solana::get_token_symbol(const std::string_view& mint)
			{
				auto metadata = coawait(execute_http(algorithm::asset::id_of("SOL"), "GET", nd_call::get_token_metadata(mint), std::string_view(), std::string_view(), cache_policy::persistent));
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
			expects_promise_rt<solana::token_account> solana::get_token_balance(const algorithm::asset_id& asset, const std::string_view& mint, const std::string_view& owner)
			{
				schema_list map;
				map.emplace_back(var::set::string(owner));
				map.emplace_back(var::set::object());
				map.back()->set("mint", var::string(mint));
				map.emplace_back(var::set::object());
				map.back()->set("encoding", var::string("jsonParsed"));

				auto balance = coawait(execute_rpc(asset, nd_call::get_token_balance(), std::move(map), cache_policy::greedy));
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
			expects_promise_rt<decimal> solana::get_balance(const algorithm::asset_id& asset, const std::string_view& owner)
			{
				schema_list map;
				map.emplace_back(var::set::string(owner));

				auto balance = coawait(execute_rpc(asset, nd_call::get_balance(), std::move(map), cache_policy::greedy));
				if (!balance)
					coreturn expects_rt<decimal>(std::move(balance.error()));

				decimal value = balance->get_var("value").get_decimal();
				memory::release(*balance);
				if (value.is_nan())
					coreturn expects_rt<decimal>(remote_exception("invalid account"));

				value /= netdata.divisibility;
				coreturn expects_rt<decimal>(std::move(value));
			}
			expects_promise_rt<string> solana::get_recent_block_hash(const algorithm::asset_id& asset)
			{
				auto hash = coawait(execute_rpc(asset, nd_call::get_block_hash(), { }, cache_policy::greedy));
				if (!hash)
					coreturn expects_rt<string>(std::move(hash.error()));

				string value = hash->fetch_var("value.blockhash").get_blob();
				memory::release(*hash);
				if (value.empty())
					coreturn expects_rt<string>(remote_exception("invalid hash"));

				coreturn expects_rt<string>(std::move(value));
			}
			expects_lr<master_wallet> solana::new_master_wallet(const std::string_view& seed)
			{
				auto* chain = get_chain();
				btc_hdnode root_node;
				if (!btc_hdnode_from_seed((uint8_t*)seed.data(), (int)seed.size(), &root_node))
					return expects_lr<master_wallet>(layer_exception("seed value invalid"));

				char private_key[256];
				btc_hdnode_serialize_private(&root_node, chain, private_key, sizeof(private_key));

				char public_key[256];
				btc_hdnode_serialize_public(&root_node, chain, public_key, (int)sizeof(public_key));

				return expects_lr<master_wallet>(master_wallet(secret_box::secure(codec::hex_encode(seed)), secret_box::secure(private_key), public_key));
			}
			expects_lr<derived_signing_wallet> solana::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
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

				auto derived = new_signing_wallet(asset, secret_box::secure(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> solana::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				uint8_t raw_private_key[64]; size_t raw_private_key_size = 0;
				if (signing_key.size() != 32 && signing_key.size() != 64)
				{
					auto data = signing_key.expose<KEY_LIMIT>();
					if (!decode_private_key(data.view, raw_private_key))
					{
						if (!decode_secret_or_public_key(data.view, raw_private_key))
							return layer_exception("bad private key");

						raw_private_key_size = 32;
					}
					else
						raw_private_key_size = 64;
				}
				else
				{
					raw_private_key_size = signing_key.size();
					signing_key.stack((char*)raw_private_key, raw_private_key_size);
				}

				uint8_t private_key[64]; string secret_key;
				if (raw_private_key_size == 32)
				{
					sha512_Raw(raw_private_key, raw_private_key_size, private_key);
					algorithm::composition::convert_to_secret_key_ed25519(private_key);

					char encoded_secret_key[256]; size_t encoded_secret_key_size = sizeof(encoded_secret_key);
					if (!b58enc(encoded_secret_key, &encoded_secret_key_size, raw_private_key, raw_private_key_size))
						return layer_exception("invalid private key");

					secret_key.assign(encoded_secret_key, encoded_secret_key_size - 1);
				}
				else if (raw_private_key_size == 64)
					memcpy(private_key, raw_private_key, raw_private_key_size);

				uint8_t public_key[32];
				ed25519_publickey_ext(private_key, public_key);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_key, sizeof(public_key)));
				if (!derived)
					return derived.error();

				char encoded_private_key[256]; size_t encoded_private_key_size = sizeof(encoded_private_key);
				if (!b58enc(encoded_private_key, &encoded_private_key_size, private_key, sizeof(private_key)))
					return layer_exception("invalid private key");

				string derived_private_key = string(encoded_private_key, encoded_private_key_size - 1);
				if (!secret_key.empty())
					derived_private_key.append(1, ':').append(secret_key);
				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
			}
			expects_lr<derived_verifying_wallet> solana::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				string raw_public_key = string(verifying_key);
				if (raw_public_key.size() != 32)
				{
					uint8_t public_key[32];
					if (!decode_secret_or_public_key(raw_public_key, public_key))
						return layer_exception("invalid public key size");

					raw_public_key = string((char*)public_key, sizeof(public_key));
				}

				char encoded_public_key[256]; size_t encoded_public_key_size = sizeof(encoded_public_key);
				if (!b58enc(encoded_public_key, &encoded_public_key_size, raw_public_key.data(), raw_public_key.size()))
					return layer_exception("invalid public key");

				uint8_t derived_public_key[256]; size_t derived_public_key_size = sizeof(derived_public_key);
				if (!b58dec(derived_public_key, &derived_public_key_size, encoded_public_key, encoded_public_key_size - 1))
					return layer_exception("invalid public key");

				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, string(encoded_public_key, encoded_public_key_size - 1) } }, optional::none, string(encoded_public_key, encoded_public_key_size - 1)));
			}
			expects_lr<string> solana::new_public_key_hash(const std::string_view& address)
			{
				uint8_t data[256]; size_t data_size = sizeof(data);
				if (!b58dec(data, &data_size, address.data(), address.size()))
					return layer_exception("invalid address");

				return string((char*)data, sizeof(data));
			}
			expects_lr<string> solana::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				uint8_t derived_private_key[64];
				auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
				if (!decode_private_key(secret.view, derived_private_key))
					return layer_exception("private key invalid");

				ed25519_signature signature;
				ed25519_sign_ext((uint8_t*)message.data(), message.size(), derived_private_key, derived_private_key + 32, signature);
				return codec::base64_encode(std::string_view((char*)signature, sizeof(signature)));
			}
			expects_lr<void> solana::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				VI_ASSERT(stringify::is_cstring(verifying_key), "verifying key must be c-string");
				string signature_data = signature.size() == 64 ? string(signature) : codec::base64_decode(signature);
				if (signature_data.size() != 64)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				uint8_t derived_public_key[256]; size_t derived_public_key_size = sizeof(derived_public_key);
				if (!b58dec(derived_public_key, &derived_public_key_size, verifying_wallet->verifying_key.data(), (int)verifying_wallet->verifying_key.size()))
					return layer_exception("invalid public key");

				if (crypto_sign_verify_detached((uint8_t*)signature_data.data(), (uint8_t*)message.data(), message.size(), derived_public_key) != 0)
					return layer_exception("signature verification failed with used public key");

				return expectation::met;
			}
			string solana::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/501'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const solana::chainparams& solana::get_chainparams() const
			{
				return netdata;
			}
			bool solana::decode_private_key(const std::string_view& data, uint8_t private_key[64])
			{
				auto slice = string(data.substr(0, data.find(':')));
				uint8_t key[64]; size_t key_size = sizeof(key);
				if (!b58dec(key, &key_size, slice.c_str(), slice.size()) || key_size < 64)
					return false;

				memcpy(private_key, key, 64);
				return true;
			}
			bool solana::decode_secret_or_public_key(const std::string_view& data, uint8_t secret_key[32])
			{
				uint8_t key[32]; size_t key_size = sizeof(key);
				if (!b58dec(key, &key_size, data.data(), data.size()) || key_size < 32)
					return false;

				memcpy(secret_key, key, 32);
				return true;
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