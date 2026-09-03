#include "solana.h"
#include <sodium.h>
extern "C"
{
#include "../internal/bitcoin.h"
#include "../internal/ed25519.h"
#include "../internal/ed25519/ed25519-donna.h"
}

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			struct transaction_header
			{
				uint8_t required_signatures;
				uint8_t readonly_signed_accounts;
				uint8_t readonly_unsigned_accounts;
			};

			static bool is_on_curve_relaxed(const uint8_t* public_key)
			{
				ge25519 p;
				return ge25519_unpack_negative_vartime(&p, public_key) != 0;
			}
			static bool derive_program_address(const std::string_view& seed, const uint8_t* program_id, size_t program_id_size, uint8_t result[32], size_t* result_size)
			{
				string seed_buffer = string(seed);
				size_t seed_index = seed_buffer.size();
				seed_buffer.append(1, ' ');
				seed_buffer.append((char*)program_id, program_id_size);
				seed_buffer.append("ProgramDerivedAddress");
				for (size_t i = 0; i < 255; i++)
				{
					seed_buffer[seed_index] = (char)(255 - i);
					sha256_Raw((uint8_t*)seed_buffer.data(), seed_buffer.size(), result);
					if (!is_on_curve_relaxed(result))
					{
						*result_size = 32;
						return true;
					}
				}

				*result_size = 0;
				return false;
			}
			static void tx_append(vector<uint8_t>& tx, const uint8_t* data, size_t data_size)
			{
				size_t offset = tx.size();
				tx.resize(tx.size() + data_size);
				memcpy(&tx[offset], data, data_size);
			}

			const char* solana::nd_call::get_token_balance()
			{
				return "getTokenAccountsByOwner";
			}
			const char* solana::nd_call::get_account_info()
			{
				return "getAccountInfo";
			}
			const char* solana::nd_call::get_balance()
			{
				return "getBalance";
			}
			const char* solana::nd_call::get_block_hash()
			{
				return "getLatestBlockhash";
			}
			const char* solana::nd_call::get_transaction()
			{
				return "getTransaction";
			}
			const char* solana::nd_call::get_signatures_for_address()
			{
				return "getSignaturesForAddress";
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

			solana::solana(const algorithm::asset_id& new_asset) noexcept : translation_unit(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::account;
				netdata.tokenization = token_policy::native;
				netdata.sync_latency = 64;
				netdata.divisibility = algorithm::arithmetic::fixed(1000000000);
				netdata.transaction_expires = true;
			}
			expects_promise_rt<uint64_t> solana::get_linked_block_height(uint64_t seen_block_height)
			{
				auto unseen_block_height = get_unseen_slot(seen_block_height);
				if (unseen_block_height)
					return expects_promise_rt<uint64_t>(*unseen_block_height);

				return coasync<expects_rt<uint64_t>>([this, seen_block_height]() -> expects_promise_rt<uint64_t>
				{
					size_t offset = 0;
					while (true)
					{
						auto links = find_linked_addresses(offset, ELEMENTS_MANY);
						if (!links)
							break;

						for (auto& link : *links)
						{
							if (link.second.address.empty())
								continue;

							auto& watcher = linker.accounts[link.second.address];
							if (watcher.must_pull_accounts && watcher.can_pull_accounts)
							{
								auto token_accounts = coawait(get_token_accounts(link.second.address));
								if (token_accounts)
								{
									for (auto& token_account : *token_accounts)
										linker.accounts[token_account].can_pull_accounts = false;
								}
								watcher.must_pull_accounts = false;
							}
						}

						offset += links->size();
						if (links->size() != ELEMENTS_MANY)
							break;
					}

					for (auto& [account, watcher] : linker.accounts)
					{
						string before_signature;
					lookback:
						format::tree map, options;
						map.push(format::variable(account));
						if (!before_signature.empty())
							options.set("before", format::variable(before_signature));
						map.push(std::move(options));

						auto result = coawait(execute_rpc(nd_call::get_signatures_for_address(), std::move(map), cache_policy::no_cache));
						if (!result || result->childs().empty())
							continue;

						auto& transactions = result->childs(); bool eof = false;
						for (size_t i = 0; i < transactions.size(); i++)
						{
							auto& transaction = transactions[i];
							uint64_t slot = transaction.child_var("slot").as_uint64();
							eof = (slot <= seen_block_height);
							if (eof)
								break;

							auto& slots = linker.slots[slot];
							watcher.must_pull_accounts = watcher.can_pull_accounts && (slots.find(account) == slots.end());
							slots.insert(account);
							if (i == result->childs().size() - 1)
								before_signature = transaction.child_var("signature").as_blob();
						}
						if (!eof && !before_signature.empty())
							goto lookback;
					}

					auto unseen_block_height = get_unseen_slot(seen_block_height);
					if (unseen_block_height)
						coreturn *unseen_block_height;

					coreturn remote_exception::retry_later();
				});
			}
			expects_promise_rt<uint64_t> solana::get_latest_block_height()
			{
				return execute_rpc(nd_call::get_slot(), format::tree::list(), cache_policy::no_cache).then<expects_rt<uint64_t>>([](expects_rt<format::tree>&& block_height) -> expects_rt<uint64_t>
				{
					return block_height ? expects_rt<uint64_t>(block_height->value.as_uint64()) : expects_rt<uint64_t>(std::move(block_height.error()));
				});
			}
			expects_promise_rt<vector<block_log>> solana::get_block_transactions(uint64_t block_height, uint64_t block_count)
			{
				format::tree config = format::tree::map();
				config.set("encoding", format::variable("json"));
				config.set("maxSupportedTransactionVersion", format::variable((uint8_t)0));
				config.set("transactionDetails", format::variable("accounts"));
				config.set("rewards", format::variable(false));

				format::tree map;
				for (uint64_t i = 0; i < block_count; i++)
				{
					format::tree submap;
					submap.push(format::variable(block_height + i));
					submap.push(config);
					map.push(std::move(submap));
				}

				return execute_rpc_multi(nd_call::get_block(), std::move(map), cache_policy::blob_cache).then<expects_rt<vector<block_log>>>([block_height, block_count](expects_rt<format::tree>&& block_data) -> expects_rt<vector<block_log>>
				{
					if (!block_data && block_data.error().message().find("was skipped, or missing") == std::string::npos)
						return block_data.error();

					vector<block_log> results;
					if (!block_data)
					{
						for (uint64_t i = 0; i < block_count; i++)
						{
							auto& log = results.emplace_back();
							log.block_hash = to_string(block_height + i);
							log.transactions = format::tree::list();
						}

						if (kernel::params().user.superchain.logging)
							VI_WARN("skipping solana block(s) at height %" PRIu64 ": %s", block_height, block_data.error().what());
					}
					else
					{
						for (auto& block : block_data->childs())
						{
							auto* transactions = (format::tree*)block.child("transactions");
							auto& log = results.emplace_back();
							log.block_hash = block.child_var("blockhash").as_blob();
							log.transactions = transactions ? std::move(*transactions) : format::tree::list();
						}
					}
					return expects_rt<vector<block_log>>(std::move(results));
				});
			}
			expects_promise_rt<computed_transaction> solana::link_transaction(uint64_t, const std::string_view&, format::tree& transaction_data)
			{
				bool reverted = false;
				auto* meta = transaction_data.child("meta");
				if (meta != nullptr)
				{
					auto* status = meta->child("status");
					reverted = status != nullptr && status->has("Err");
				}

				auto* transaction = transaction_data.child("transaction");
				if (!transaction)
					return expects_rt<computed_transaction>(remote_exception("tx invalid"));

				auto* signatures = transaction->child("signatures");
				auto* account_keys = transaction->child("accountKeys");
				if (!signatures || !signatures->fields || signatures->childs().empty() || !account_keys || !account_keys->fields || account_keys->childs().empty())
					return expects_rt<computed_transaction>(remote_exception("tx must have one or more signatures and account keys"));

				auto signature = signatures->child(0)->value.as_string();
				if (signature.empty())
					return expects_rt<computed_transaction>(remote_exception("tx must have one or more signatures and account keys"));

				hash_set<string> addresses;
				for (auto& account_key : account_keys->childs())
					addresses.insert(account_key.child_var("pubkey").as_blob());

				auto* pre_token_balances = meta ? meta->child("preTokenBalances") : nullptr;
				auto* post_token_balances = meta ? meta->child("postTokenBalances") : nullptr;
				if (pre_token_balances != nullptr)
				{
					for (auto& balance : pre_token_balances->childs())
						addresses.insert(balance.child_var("owner").as_blob());
				}
				if (post_token_balances != nullptr)
				{
					for (auto& balance : post_token_balances->childs())
						addresses.insert(balance.child_var("owner").as_blob());
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery || discovery->empty())
					return expects_rt<computed_transaction>(remote_exception("tx not involved"));

				return coasync<expects_rt<computed_transaction>>([this, &transaction_data, pre_token_balances, post_token_balances, reverted, signature = std::move(signature), addresses = std::move(addresses), discovery = std::move(discovery)]() mutable -> expects_promise_rt<computed_transaction>
				{
					auto transaction_data_postload = coawait(get_transaction(signature));
					if (!transaction_data_postload)
						coreturn expects_rt<computed_transaction>(transaction_data_postload.error());

					transaction_data = std::move(*transaction_data_postload);
					auto* pre_balances = transaction_data.child("meta.preBalances");
					auto* post_balances = transaction_data.child("meta.postBalances");
					if (!pre_balances || !post_balances || pre_balances->childs().size() != post_balances->childs().size() || pre_balances->childs().empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					bool non_transferring = true;
					for (size_t i = 0; i < pre_balances->childs().size(); i++)
					{
						if (pre_balances->childs()[i].value.as_decimal() != post_balances->childs()[i].value.as_decimal())
						{
							non_transferring = false;
							break;
						}
					}
					if (non_transferring)
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					auto* instructions = transaction_data.child("transaction.message.instructions");
					if (!instructions || instructions->childs().empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not valid"));

					computed_transaction tx;
					tx.transaction_id = signature;
					tx.reverted = reverted;

					hash_map<string, hash_map<algorithm::asset_id, decimal>> inputs;
					hash_map<string, hash_map<algorithm::asset_id, decimal>> outputs;
					for (auto& instruction : instructions->childs())
					{
						auto* info = instruction.child("parsed.info");
						auto type = instruction.child_var("parsed.type").as_blob();
						if (!info || type.empty())
						{
							if (tx.memo.empty())
							{
								auto program = instruction.child_var("program").as_blob();
								auto program_id = instruction.child_var("programId").as_blob();
								auto memo = format::util::decode_0xhex(instruction.child_var("parsed").as_blob());
								if (memo.size() == 64 && program == "spl-memo" && (program_id == "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" || program_id == "Memo4c2pN8afCj432Lb7RMVKi9PbQnnW7ewFFaV3oAH"))
								{
									auto raw = format::util::decode_0xhex(memo);
									if (raw.size() == 32)
									{
										uint8_t checksum[32];
										algorithm::hashing::hash256((uint8_t*)raw.data() + 12, 20, checksum);
										if (memcmp(raw.data(), checksum + 20, 12) == 0)
											tx.memo = algorithm::pubkeyhash_t(std::string_view(raw).substr(12));
									}
								}
							}
						}
						else if (type == "transfer" || type == "transferWithSeed")
						{
							auto from = info->child_var("source").as_blob();
							auto to = info->child_var("destination").as_blob();
							auto value = info->child_var("lamports").as_decimal() / netdata.divisibility;
							if (!addresses.count(from) && !addresses.count(to))
								continue;
							else if (value.is_nan())
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							native_input = native_input.is_nan() ? value : (native_input + value);
							native_output = native_output.is_nan() ? value : (native_output + value);
							if (!from.empty())
								tx.signers.insert(from);
						}
						else if (type == "createAccount" || type == "createAccountWithSeed")
						{
							auto from = info->child_var("source").as_blob();
							auto to = info->child_var("newAccount").as_blob();
							auto value = info->child_var("lamports").as_decimal() / netdata.divisibility;
							if (!addresses.count(from) && !addresses.count(to))
								continue;
							else if (value.is_nan())
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							native_input = native_input.is_nan() ? value : (native_input + value);
							native_output = native_output.is_nan() ? value : (native_output + value);
							if (!from.empty())
								tx.signers.insert(from);
						}
						else if (type == "create" || type == "createIdempotent")
						{
							auto from = info->child_var("source").as_blob();
							auto to = info->child_var("wallet").as_blob();
							if (!addresses.count(from) && !addresses.count(to))
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							if (native_input.is_nan())
								native_input = decimal::zero();
							if (native_output.is_nan())
								native_output = decimal::zero();
							if (!from.empty())
								tx.signers.insert(from);
						}
						else if (type == "withdrawFromNonce")
						{
							auto from = info->child_var("nonceAccount").as_blob();
							auto to = info->child_var("destination").as_blob();
							auto value = info->child_var("lamports").as_decimal() / netdata.divisibility;
							if (!addresses.count(from) && !addresses.count(to))
								continue;
							else if (value.is_nan())
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							native_input = native_input.is_nan() ? value : (native_input + value);
							native_output = native_output.is_nan() ? value : (native_output + value);
							if (!from.empty())
								tx.signers.insert(from);
						}
						else if (type == "withdraw")
						{
							auto from = info->child_var("stakeAccount").as_blob();
							auto to = info->child_var("destination").as_blob();
							auto value = info->child_var("lamports").as_decimal() / netdata.divisibility;
							if (!addresses.count(from) && !addresses.count(to))
								continue;
							else if (value.is_nan())
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							native_input = native_input.is_nan() ? value : (native_input + value);
							native_output = native_output.is_nan() ? value : (native_output + value);
							if (!from.empty())
								tx.signers.insert(from);
						}
						else if (type == "split")
						{
							auto from = info->child_var("stakeAccount").as_blob();
							auto to = info->child_var("newSplitAccount").as_blob();
							auto value = info->child_var("lamports").as_decimal() / netdata.divisibility;
							if (!addresses.count(from) && !addresses.count(to))
								continue;
							else if (value.is_nan())
								continue;

							auto& native_input = inputs[from][native_asset];
							auto& native_output = outputs[to][native_asset];
							native_input = native_input.is_nan() ? value : (native_input + value);
							native_output = native_output.is_nan() ? value : (native_output + value);
							if (!from.empty())
								tx.signers.insert(from);
						}
					}

					bool fee_included = false;
					auto* account_keys = transaction_data.child("transaction.message.accountKeys");
					if (account_keys != nullptr)
					{
						hash_map<uint64_t, string> account_indices;
						for (auto& account_key : account_keys->childs())
							account_indices[(uint64_t)account_indices.size()] = account_key.child_var("pubkey").as_blob();

						hash_map<string, decimal> fees;
						if (pre_balances != nullptr && !pre_balances->childs().empty())
						{
							for (size_t i = 0; i < pre_balances->childs().size(); i++)
							{
								auto it = account_indices.find((uint64_t)i);
								if (it != account_indices.end() && tx.signers.find(it->second) != tx.signers.end())
								{
									auto pre_balance = pre_balances->childs()[i].value.as_decimal();
									auto post_balance = post_balances->childs()[i].value.as_decimal();
									auto delta = (pre_balance - post_balance) / netdata.divisibility;
									if (delta.is_positive())
										fees[it->second] = std::move(delta);
								}
							}
						}

						for (auto& [address, values] : inputs)
						{
							auto fee = fees.find(address);
							if (fee == fees.end())
								continue;

							fee_included = true;
							auto value = values.find(native_asset);
							if (value != values.end())
								value->second = std::max(value->second, fee->second);
							else
								values[native_asset] = fee->second;
						}
					}

					hash_map<string, hash_map<string, decimal>> prev_token_state;
					pre_token_balances = transaction_data.child("meta.preTokenBalances");
					if (pre_token_balances != nullptr && !pre_token_balances->childs().empty())
					{
						for (auto& balance : pre_token_balances->childs())
						{
							decimal value = balance.child_var("uiTokenAmount.amount").as_decimal();
							if (!value.is_positive())
								continue;

							string mint = balance.child_var("mint").as_blob();
							string owner = balance.child_var("owner").as_blob();
							auto& change = prev_token_state[mint][owner];
							value = algorithm::arithmetic::divide(value, algorithm::arithmetic::range(balance.child_var("uiTokenAmount.decimals").as_uint64()));
							change = change.is_nan() ? value : (change + value);
						}
					}

					hash_map<string, hash_map<string, decimal>> next_token_state;
					post_token_balances = transaction_data.child("meta.postTokenBalances");
					if (post_token_balances != nullptr && !post_token_balances->childs().empty())
					{
						for (auto& balance : post_token_balances->childs())
						{
							decimal value = balance.child_var("uiTokenAmount.amount").as_decimal();
							if (value.is_nan() || value.is_negative())
								continue;

							string mint = balance.child_var("mint").as_blob();
							string owner = balance.child_var("owner").as_blob();
							auto& change = next_token_state[mint][owner];
							value = algorithm::arithmetic::divide(value, algorithm::arithmetic::range(balance.child_var("uiTokenAmount.decimals").as_uint64()));
							change = change.is_nan() ? value : (value + change);
						}
					}

					auto blockchain = algorithm::asset::blockchain_of(native_asset);
					for (auto& [contract_address, balances] : next_token_state)
					{
						auto symbol = coawait(get_token_symbol(contract_address));
						auto token_asset = algorithm::asset::id_of(blockchain, symbol.or_else(contract_address), contract_address);
						bridge::get()->enable_contract_address(token_asset, contract_address);

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
								if (!owner.empty())
									tx.signers.insert(owner);
							}
							else if (prev_balance < next_balance)
							{
								auto token_value = next_balance - prev_balance;
								auto& token_output = outputs[owner][token_asset];
								token_output = token_output.is_nan() ? token_value : (token_output + token_value);
							}
						}
					}

					if (!fee_included)
					{
						auto fee_value = (transaction_data.child_var("meta.fee").as_decimal() / netdata.divisibility);
						if (!inputs.empty())
						{
							auto& native_input = inputs.begin()->second[native_asset];
							native_input = (native_input.is_nan() ? fee_value : (native_input + fee_value));
						}
					}

					for (auto& [address, values] : inputs)
					{
						auto target_link = discovery->find(address);
						tx.add_input(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
					}

					for (auto& [address, values] : outputs)
					{
						auto target_link = discovery->find(address);
						tx.add_output(coin_utxo(target_link != discovery->end() ? target_link->second : wallet_link::from_address(address), std::move(values)));
					}

					coreturn expects_rt<computed_transaction>(std::move(tx));
				});
			}
			expects_promise_rt<decimal> solana::calculate_balance(const algorithm::asset_id& asset, const wallet_link& link)
			{
				if (algorithm::asset::token_of(asset).empty())
				{
					format::tree map;
					map.push(format::variable(link.address));
					map.push(format::variable());

					return execute_rpc(nd_call::get_balance(), std::move(map), cache_policy::no_cache).then<expects_rt<decimal>>([this](expects_rt<format::tree>&& balance) -> expects_rt<decimal>
					{
						return balance ? expects_rt<decimal>(to_value(algorithm::arithmetic::divide(balance->child_var("value").as_decimal(), netdata.divisibility))) : expects_rt<decimal>(std::move(balance.error()));
					});
				}
				else
				{
					auto contract_address = bridge::get()->get_contract_address(asset);
					if (!contract_address)
						return expects_rt<decimal>(remote_exception("contract address not found"));

					return get_token_balance(*contract_address, link.address).then<expects_rt<decimal>>([this](expects_rt<token_account>&& token_balance) -> expects_rt<decimal>
					{
						return token_balance ? expects_rt<decimal>(std::move(token_balance->balance)) : expects_rt<decimal>(std::move(token_balance.error()));
					});
				}
			}
			expects_promise_rt<void> solana::broadcast_transaction(const finalized_transaction& finalized)
			{
				format::tree map;
				map.push(format::variable(finalized.calldata));

				return execute_rpc(nd_call::send_transaction(), std::move(map), cache_policy::no_cache_no_throttling).then<expects_rt<void>>([](expects_rt<format::tree>&& result) -> expects_rt<void>
				{
					return result ? expects_rt<void>(expectation::met) : expects_rt<void>(std::move(result.error()));
				});
			}
			expects_promise_rt<prepared_transaction> solana::prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
			{
				return coasync<expects_rt<prepared_transaction>>([this, from_link, to, max_fee]() -> expects_promise_rt<prepared_transaction>
				{
					auto contract_address = bridge::get()->get_contract_address(to.asset);
					if (!contract_address && !algorithm::asset::token_of(to.asset).empty())
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to find a token contract address"));

					option<token_account> from_token = optional::none;
					option<token_account> to_token = optional::none;
					uint64_t fee_constant = contract_address ? 15000 : 5000;
					uint64_t token_constant = 2039280;
					uint64_t rent_constant = 890880;
					if (contract_address)
					{
						auto from_token_balance = coawait(get_token_balance(*contract_address, from_link.address));
						if (!from_token_balance || from_token_balance->balance < to.value)
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (from_token_balance ? from_token_balance->balance : decimal(0.0)).to_string().c_str(), to.value.to_string().c_str())));
						else if (from_token_balance->mint.empty())
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("account %s does not have associated token account (must not happen)", from_link.address.c_str())));

						auto to_token_balance = coawait(get_token_balance(*contract_address, to.address));
						from_token = std::move(*from_token_balance);
						if (to_token_balance)
							to_token = std::move(*to_token_balance);
						if (!to_token)
							fee_constant += token_constant;
					}
					else if (to.value < from_baseline_value(rent_constant))
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("rent cost not met (sending less than %s %s)", from_baseline_value(rent_constant).to_string().c_str(), algorithm::asset::name_of(native_asset).c_str())));

					auto fee = computed_fee::flat_fee(from_baseline_value(fee_constant));
					decimal fee_value = fee.get_max_fee();
					if (fee_value > max_fee)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

					auto native_balance = coawait(get_balance(from_link.address));
					if (!native_balance)
						coreturn expects_rt<prepared_transaction>(std::move(native_balance.error()));

					auto total_value = contract_address ? fee_value : (to.value + fee_value);
					if (*native_balance < total_value || total_value.is_negative())
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", native_balance->to_string().c_str(), total_value.to_string().c_str())));

					auto recent_block_hash = coawait(get_recent_block_hash());
					if (!recent_block_hash)
						coreturn expects_rt<prepared_transaction>(std::move(recent_block_hash.error()));

					sol_transaction transaction;
					transaction.mint_address = from_token ? from_token->mint : string();
					transaction.token_program_address = from_token ? from_token->program_id : string();
					transaction.from_token_address = from_token ? from_token->account : string();
					transaction.to_token_address = to_token ? to_token->account : string();
					transaction.from_address = from_link.address;
					transaction.to_address = to.address;
					transaction.recent_block_hash = *recent_block_hash;
					transaction.value = (to.value * (from_token ? from_token->divisibility : netdata.divisibility)).to_uint64();
					transaction.decimals = (uint8_t)((from_token ? from_token->divisibility : netdata.divisibility).to_string().size() - 1);

					auto to_value = to.value;
					to_value.truncate(transaction.decimals);
					if (!contract_address)
						total_value = to_value + fee_value;

					vector<uint8_t> message_buffer = tx_message_serialize(&transaction);
					if (message_buffer.empty())
						coreturn expects_rt<prepared_transaction>(remote_exception("tx serialization error (one or more addresses is invalid)"));

					auto signing_public_key = decode_public_key(from_link.public_key);
					if (!signing_public_key)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

					auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*signing_public_key);
					prepared_transaction result;
					if (contract_address)
						result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key, message_buffer.data(), message_buffer.size(), { { to.asset, to_value }, { native_asset, fee_value } });
					else
						result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key, message_buffer.data(), message_buffer.size(), { { native_asset, total_value } });
					result.requires_account_output(to.address, { { to.asset, to_value } });
					result.requires_abi(format::variable(from_token ? from_token->divisibility : netdata.divisibility));
					result.requires_abi(format::variable(from_token ? from_token->mint : string()));
					result.requires_abi(format::variable(transaction.token_program_address));
					result.requires_abi(format::variable(transaction.from_token_address));
					result.requires_abi(format::variable(transaction.to_token_address));
					result.requires_abi(format::variable(transaction.recent_block_hash));
					coreturn expects_rt<prepared_transaction>(std::move(result));
				});
			}
			expects_lr<finalized_transaction> solana::finalize_transaction(superchain::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 6)
					return layer_exception("invalid prepared abi");

				if (prepared.inputs.size() != 1 || prepared.outputs.size() != 1)
					return layer_exception("invalid in/out size");

				auto& input = prepared.inputs.front();
				auto& output = prepared.outputs.front();
				if (input.utxo.tokens.size() != output.tokens.size() || input.utxo.tokens.size() > 1)
					return layer_exception("invalid in/out tokens size");

				auto divisibility = prepared.abi[0].as_decimal();
				sol_transaction transaction;
				transaction.mint_address = prepared.abi[1].as_blob();
				transaction.token_program_address = prepared.abi[2].as_blob();
				transaction.from_token_address = prepared.abi[3].as_blob();
				transaction.to_token_address = prepared.abi[4].as_blob();
				transaction.from_address = input.utxo.link.address;
				transaction.to_address = output.link.address;
				transaction.recent_block_hash = prepared.abi[5].as_blob();
				transaction.value = ((output.tokens.empty() ? output.value : output.tokens.begin()->second.value) * divisibility).to_uint64();
				transaction.decimals = (uint8_t)(divisibility.to_string().size() - 1);

				vector<uint8_t> message_buffer = tx_message_serialize(&transaction);
				if (input.message.size() != message_buffer.size() || memcmp(input.message.data(), message_buffer.data(), message_buffer.size()))
					return layer_exception("invalid input message");

				char transaction_id[256]; size_t transaction_id_size = sizeof(transaction_id);
				if (!b58enc(transaction_id, &transaction_id_size, input.signature.data(), input.signature.size()))
					return layer_exception("invalid signature");

				vector<uint8_t> transaction_buffer = tx_result_serialize(message_buffer, input.signature.data(), input.signature.size());
				size_t transaction_data_size = transaction_buffer.size() * 4;
				string transaction_data;
				transaction_data.resize(transaction_data_size);
				if (!b58enc(transaction_data.data(), &transaction_data_size, &transaction_buffer[0], transaction_buffer.size()))
					return layer_exception("tx serialization error");

				auto native_decimals = (uint8_t)(netdata.divisibility.to_string().size() - 1);
				input.utxo.value.truncate(native_decimals);
				output.value.truncate(native_decimals);
				if (!input.utxo.tokens.empty())
				{
					auto input_token = input.utxo.tokens.begin();
					auto output_token = output.tokens.begin();
					input_token->second.value.truncate(transaction.decimals);
					output_token->second.value.truncate(transaction.decimals);
					if (input_token->second.value != output_token->second.value)
						return layer_exception("invalid in/out value");
				}

				transaction_data.resize(transaction_data_size - 1);
				auto result = finalized_transaction(std::move(prepared), std::move(transaction_data), string((char*)transaction_id, transaction_id_size - 1));
				auto validation = result.validate();
				if (!validation)
					return validation.error();

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
				{
					sodium_memzero(private_key, sizeof(private_key));
					return layer_exception("invalid private key");
				}

				auto output = secret_box::secure(std::string_view((char*)encoded_private_key, encoded_private_key_size - 1));
				sodium_memzero(encoded_private_key, sizeof(encoded_private_key));
				sodium_memzero(private_key, sizeof(private_key));
				return output;
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

				auto output = secret_box::secure(std::string_view((char*)private_key, sizeof(private_key)));
				sodium_memzero(private_key, sizeof(private_key));
				return output;
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
			expects_lr<string> solana::encode_signature(const std::string_view& signature)
			{
				return codec::base64_encode(signature);
			}
			expects_lr<string> solana::decode_signature(const std::string_view& signature)
			{
				auto result = codec::base64_decode(signature);
				if (result.size() != 64)
					return layer_exception("invalid base64 signature");

				return result;
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
			expects_promise_rt<string> solana::get_token_symbol(const std::string_view& mint_address)
			{
				string ref_mint_address = string(mint_address);
				return coasync<expects_rt<string>>([this, ref_mint_address = std::move(ref_mint_address)]() mutable -> expects_promise_rt<string>
				{
					format::tree config = format::tree::map();
					config.set("encoding", format::variable("jsonParsed"));

					format::tree map;
					map.push(format::variable(ref_mint_address));
					map.push(config);

					auto account_info = coawait(execute_rpc(nd_call::get_account_info(), std::move(map), cache_policy::lifetime_cache));
					if (account_info)
					{
						auto* token_extensions = account_info->child("value.data.parsed.info.extensions");
						if (token_extensions)
						{
							for (auto& token_extension : token_extensions->childs())
							{
								if (token_extension.child_var("extension").as_blob() != "tokenMetadata")
									continue;

								auto symbol = token_extension.child_var("state.symbol").as_blob();
								if (!symbol.empty())
									coreturn expects_rt<string>(std::move(symbol));
							}
						}
					}

					uint8_t program_id[32]; size_t program_id_size = sizeof(program_id);
					string metaplex_program_id = "metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s";
					if (!b58dec(program_id, &program_id_size, metaplex_program_id.c_str(), metaplex_program_id.size()))
						coreturn expects_rt<string>(remote_exception("metaplex program id not valid"));

					uint8_t mint[32]; size_t mint_size = sizeof(mint);
					if (!b58dec(mint, &mint_size, ref_mint_address.data(), ref_mint_address.size()))
						coreturn expects_rt<string>(remote_exception("mint address not valid"));

					string seed;
					seed.append("metadata");
					seed.append((char*)program_id, program_id_size);
					seed.append((char*)mint, mint_size);

					uint8_t meta[32]; size_t meta_size = sizeof(meta);
					if (!derive_program_address(seed, program_id, program_id_size, meta, &meta_size))
						coreturn expects_rt<string>(remote_exception("metaplex address not found"));

					char meta_address[256]; size_t meta_address_size = sizeof(meta_address);
					if (!b58enc(meta_address, &meta_address_size, meta, sizeof(meta)))
						coreturn expects_rt<string>(remote_exception("metaplex address not valid"));

					map = format::tree();
					map.push(format::variable(meta_address));
					map.push(std::move(config));

					account_info = coawait(execute_rpc(nd_call::get_account_info(), std::move(map), cache_policy::lifetime_cache));
					if (!account_info)
						coreturn expects_rt<string>(std::move(account_info.error()));

					size_t symbol_offset = 105;
					auto data = codec::base64_decode(account_info->child_var("value.data.0").as_blob());
					if (data.size() <= symbol_offset)
						coreturn expects_rt<string>(remote_exception("metaplex address metadata not valid"));

					size_t symbol_size = 0;
					while (symbol_offset + symbol_size < data.size() && data[symbol_offset + symbol_size] != 0)
						++symbol_size;
					coreturn expects_rt<string>(data.substr(symbol_offset, symbol_size));
				});
			}
			expects_promise_rt<solana::token_account> solana::get_token_balance(const std::string_view& mint, const std::string_view& owner)
			{
				format::tree map;
				map.push(format::variable(owner));
				map.push(format::tree::map())->set("mint", format::variable(mint));
				map.push(format::tree::map())->set("encoding", format::variable("jsonParsed"));

				return execute_rpc(nd_call::get_token_balance(), std::move(map), cache_policy::no_cache_no_throttling).then<expects_rt<token_account>>([](expects_rt<format::tree>&& balance) -> expects_rt<token_account>
				{
					if (!balance)
						return expects_rt<token_account>(std::move(balance.error()));

					auto* info = balance->child("value.0.account.data.parsed.info");
					if (!info)
						return expects_rt<token_account>(remote_exception("invalid account"));

					string account = balance->child_var("value.0.pubkey").as_blob();
					string program_id = balance->child_var("value.0.account.owner").as_blob();
					string mint_id = info->child_var("mint").as_blob();
					decimal value = info->child_var("tokenAmount.amount").as_decimal();
					decimal divisibility = algorithm::arithmetic::range(info->child_var("tokenAmount.decimals").as_uint64());
					if (value.is_nan())
						return expects_rt<token_account>(remote_exception("invalid account"));

					token_account result;
					result.mint = std::move(mint_id);
					result.program_id = std::move(program_id);
					result.account = std::move(account);
					result.divisibility = std::move(divisibility);
					result.balance = value / result.divisibility;
					return expects_rt<token_account>(std::move(result));
				});
			}
			expects_promise_rt<hash_set<string>> solana::get_token_accounts(const std::string_view& owner)
			{
				format::tree submap1;
				submap1.push(format::variable(owner));
				submap1.push(format::tree::map())->set("programId", format::variable("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"));
				submap1.push(format::tree::map())->set("encoding", format::variable("jsonParsed"));

				format::tree submap2;
				submap2.push(format::variable(owner));
				submap2.push(format::tree::map())->set("programId", format::variable("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"));
				submap2.push(format::tree::map())->set("encoding", format::variable("jsonParsed"));

				format::tree map;
				map.push(std::move(submap1));
				map.push(std::move(submap2));

				return execute_rpc_multi(nd_call::get_token_balance(), std::move(map), cache_policy::no_cache).then<expects_rt<hash_set<string>>>([](expects_rt<format::tree>&& values) -> expects_rt<hash_set<string>>
				{
					if (!values)
						return expects_rt<hash_set<string>>(std::move(values.error()));

					hash_set<string> results;
					auto token_program_accounts = values->child("0.value");
					auto token_program_2022_accounts = values->child("1.value");
					results.reserve((token_program_accounts ? token_program_accounts->childs().size() : 0) + (token_program_2022_accounts ? token_program_2022_accounts->childs().size() : 0));
					if (token_program_accounts != nullptr)
					{
						for (auto& item : token_program_accounts->childs())
						{
							auto pubkey = item.child_var("pubkey").as_blob();
							if (!pubkey.empty())
								results.insert(std::move(pubkey));
						}
					}
					if (token_program_2022_accounts != nullptr)
					{
						for (auto& item : token_program_2022_accounts->childs())
						{
							auto pubkey = item.child_var("pubkey").as_blob();
							if (!pubkey.empty())
								results.insert(std::move(pubkey));
						}
					}
					return expects_rt<hash_set<string>>(std::move(results));
				});
			}
			expects_promise_rt<decimal> solana::get_balance(const std::string_view& owner)
			{
				format::tree map;
				map.push(format::variable(owner));

				return execute_rpc(nd_call::get_balance(), std::move(map), cache_policy::no_cache_no_throttling).then<expects_rt<decimal>>([this](expects_rt<format::tree>&& balance) -> expects_rt<decimal>
				{
					if (!balance)
						return expects_rt<decimal>(std::move(balance.error()));

					decimal value = balance->child_var("value").as_decimal();
					if (value.is_nan())
						return expects_rt<decimal>(remote_exception("invalid account"));

					value = algorithm::arithmetic::divide(value, netdata.divisibility);
					return expects_rt<decimal>(std::move(value));
				});
			}
			expects_promise_rt<format::tree> solana::get_transaction(const std::string_view& signature)
			{
				format::tree config = format::tree::map();
				config.set("encoding", format::variable("jsonParsed"));
				config.set("maxSupportedTransactionVersion", format::variable((uint8_t)0));

				format::tree map;
				map.push(format::variable(signature));
				map.push(std::move(config));
				return execute_rpc(nd_call::get_transaction(), std::move(map), cache_policy::blob_cache);
			}
			expects_promise_rt<string> solana::get_recent_block_hash()
			{
				return execute_rpc(nd_call::get_block_hash(), format::tree::list(), cache_policy::no_cache_no_throttling).then<expects_rt<string>>([](expects_rt<format::tree>&& hash) -> expects_rt<string>
				{
					if (!hash)
						return expects_rt<string>(std::move(hash.error()));

					string value = hash->child_var("value.blockhash").as_blob();
					if (value.empty())
						return expects_rt<string>(remote_exception("invalid hash"));

					return expects_rt<string>(std::move(value));
				});
			}
			option<uint64_t> solana::get_unseen_slot(uint64_t target_block_height)
			{
				while (!linker.slots.empty() && linker.slots.begin()->first <= target_block_height)
					linker.slots.erase(linker.slots.begin());
				return linker.slots.empty() ? option<uint64_t>(optional::none) : option<uint64_t>(linker.slots.begin()->first);
			}
			vector<uint8_t> solana::tx_message_serialize(sol_transaction* tx_data)
			{
				uint8_t block_hash[32]; size_t block_hash_size = sizeof(block_hash);
				if (!b58dec(block_hash, &block_hash_size, tx_data->recent_block_hash.c_str(), tx_data->recent_block_hash.size()))
					return vector<uint8_t>();

				uint8_t mint_buffer[32]; size_t mint_buffer_size = sizeof(mint_buffer);
				if (!tx_data->mint_address.empty() && !b58dec(mint_buffer, &mint_buffer_size, tx_data->mint_address.c_str(), tx_data->mint_address.size()))
					return vector<uint8_t>();

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

				uint8_t token_program_id[32]; size_t token_program_id_size = sizeof(token_program_id);
				if (!tx_data->token_program_address.empty() && !b58dec(token_program_id, &token_program_id_size, tx_data->token_program_address.c_str(), tx_data->token_program_address.size()))
					return vector<uint8_t>();

				uint8_t system_program_id[32]; size_t system_program_id_size = sizeof(system_program_id);
				std::string_view system_program_id_const = "11111111111111111111111111111111";
				if (!b58dec(system_program_id, &system_program_id_size, system_program_id_const.data(), system_program_id_const.size()))
					return vector<uint8_t>();

				uint8_t associated_token_program_id[32]; size_t associated_token_program_id_size = sizeof(associated_token_program_id);
				std::string_view associated_token_program_id_const = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
				if (!b58dec(associated_token_program_id, &associated_token_program_id_size, associated_token_program_id_const.data(), associated_token_program_id_const.size()))
					return vector<uint8_t>();

				bool is_token_transfer = !tx_data->mint_address.empty() || !tx_data->from_token_address.empty() || !tx_data->to_token_address.empty() || !tx_data->token_program_address.empty();
				bool create_associated_token_account = is_token_transfer && tx_data->to_token_address.empty();
				uint64_t amount = os::hw::to_endianness<uint64_t>(os::hw::endian::little, tx_data->value);
				uint8_t prefix = 1 << 7;
				uint8_t account_keys = is_token_transfer ? (create_associated_token_account ? 8 : 5) : 3;
				uint8_t instructions = create_associated_token_account ? 2 : 1;
				uint8_t lookups = 0;

				transaction_header header;
				header.required_signatures = 1;
				header.readonly_signed_accounts = 0;
				header.readonly_unsigned_accounts = is_token_transfer && create_associated_token_account ? 2 : 1;

				vector<uint8_t> message_buffer;
				tx_append(message_buffer, (uint8_t*)&prefix, sizeof(prefix));
				tx_append(message_buffer, (uint8_t*)&header, sizeof(header));
				tx_append(message_buffer, (uint8_t*)&account_keys, sizeof(account_keys));
				tx_append(message_buffer, from_buffer, from_buffer_size);
				if (is_token_transfer)
				{
					if (create_associated_token_account)
					{
						string seed;
						seed.append((char*)to_buffer, to_buffer_size);
						seed.append((char*)token_program_id, token_program_id_size);
						seed.append((char*)mint_buffer, mint_buffer_size);
						if (!derive_program_address(seed, associated_token_program_id, associated_token_program_id_size, to_token_buffer, &to_token_buffer_size))
							return vector<uint8_t>();
					}
					tx_append(message_buffer, from_token_buffer, from_token_buffer_size);
					tx_append(message_buffer, to_token_buffer, to_token_buffer_size);
					tx_append(message_buffer, mint_buffer, mint_buffer_size);
					tx_append(message_buffer, token_program_id, token_program_id_size);
					if (create_associated_token_account)
					{
						tx_append(message_buffer, to_buffer, to_buffer_size);
						tx_append(message_buffer, system_program_id, system_program_id_size);
						tx_append(message_buffer, associated_token_program_id, associated_token_program_id_size);
					}
				}
				else
				{
					tx_append(message_buffer, to_buffer, to_buffer_size);
					tx_append(message_buffer, system_program_id, system_program_id_size);
				}
				tx_append(message_buffer, block_hash, block_hash_size);
				tx_append(message_buffer, (uint8_t*)&instructions, sizeof(instructions));
				if (is_token_transfer)
				{
					if (create_associated_token_account)
					{
						uint8_t indices = 6, size = 1, instruction = 1;
						uint8_t program_id_index = 7, from_index = 0, to_index = 2, owner_index = 5, mint_index = 3, system_program_id_index = 6, token_program_id_index = 4;
						tx_append(message_buffer, (uint8_t*)&program_id_index, sizeof(program_id_index));
						tx_append(message_buffer, (uint8_t*)&indices, sizeof(indices));
						tx_append(message_buffer, (uint8_t*)&from_index, sizeof(from_index));
						tx_append(message_buffer, (uint8_t*)&to_index, sizeof(to_index));
						tx_append(message_buffer, (uint8_t*)&owner_index, sizeof(owner_index));
						tx_append(message_buffer, (uint8_t*)&mint_index, sizeof(mint_index));
						tx_append(message_buffer, (uint8_t*)&system_program_id_index, sizeof(system_program_id_index));
						tx_append(message_buffer, (uint8_t*)&token_program_id_index, sizeof(token_program_id_index));
						tx_append(message_buffer, (uint8_t*)&size, sizeof(size));
						tx_append(message_buffer, (uint8_t*)&instruction, sizeof(instruction));
					}

					uint8_t indices = 4, size = 10, instruction = 12;
					uint8_t program_id_index = 4, from_index = 1, to_index = 2, owner_index = 0, mint_index = 3;
					tx_append(message_buffer, (uint8_t*)&program_id_index, sizeof(program_id_index));
					tx_append(message_buffer, (uint8_t*)&indices, sizeof(indices));
					tx_append(message_buffer, (uint8_t*)&from_index, sizeof(from_index));
					tx_append(message_buffer, (uint8_t*)&mint_index, sizeof(mint_index));
					tx_append(message_buffer, (uint8_t*)&to_index, sizeof(to_index));
					tx_append(message_buffer, (uint8_t*)&owner_index, sizeof(owner_index));
					tx_append(message_buffer, (uint8_t*)&size, sizeof(size));
					tx_append(message_buffer, (uint8_t*)&instruction, sizeof(instruction));
					tx_append(message_buffer, (uint8_t*)&amount, sizeof(amount));
					tx_append(message_buffer, (uint8_t*)&tx_data->decimals, sizeof(tx_data->decimals));
				}
				else
				{
					uint8_t indices = 2, size = 12;
					uint8_t program_id_index = 2, from_index = 0, to_index = 1;
					uint32_t instruction = os::hw::to_endianness<uint32_t>(os::hw::endian::little, 2);
					tx_append(message_buffer, (uint8_t*)&program_id_index, sizeof(program_id_index));
					tx_append(message_buffer, (uint8_t*)&indices, sizeof(indices));
					tx_append(message_buffer, (uint8_t*)&from_index, sizeof(from_index));
					tx_append(message_buffer, (uint8_t*)&to_index, sizeof(to_index));
					tx_append(message_buffer, (uint8_t*)&size, sizeof(size));
					tx_append(message_buffer, (uint8_t*)&instruction, sizeof(instruction));
					tx_append(message_buffer, (uint8_t*)&amount, sizeof(amount));
				}
				tx_append(message_buffer, (uint8_t*)&lookups, sizeof(lookups));
				return message_buffer;
			}
			vector<uint8_t> solana::tx_result_serialize(const vector<uint8_t>& tx_buffer, const uint8_t* signature, size_t signature_size)
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
			const sc_chainparams_* solana::get_chain()
			{
				switch (kernel::params().user.network)
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