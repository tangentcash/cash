#include "stellar.h"
#include <sodium.h>
extern "C"
{
#include "../internal/stellar.h"
#include "../internal/bitcoin.h"
#include "../internal/base32.h"
#include "../internal/ed25519.h"
}

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			static stellar::asset_type to_asset_type(const std::string_view& type)
			{
				stellar::asset_type token_type = stellar::asset_type::ASSET_TYPE_NATIVE;
				if (type == "credit_alphanum4")
					token_type = stellar::asset_type::ASSET_TYPE_CREDIT_ALPHANUM4;
				else if (type == "credit_alphanum12")
					token_type = stellar::asset_type::ASSET_TYPE_CREDIT_ALPHANUM12;
				return token_type;
			}
			static void tx_append(vector<uint8_t>& tx, const uint8_t* data, size_t data_size)
			{
				size_t offset = tx.size();
				tx.resize(tx.size() + data_size);
				memcpy(&tx[offset], data, data_size);
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
			static void tx_append_address(vector<uint8_t>& tx, const std::string_view& data)
			{
				uint8_t public_key[STELLAR_KEY_SIZE];
				stellar_getAddressBytes((char*)string(data).c_str(), public_key);
				tx_append_uint32(tx, 0);
				tx_append(tx, public_key, sizeof(public_key));
			}
			static void tx_append_hash(vector<uint8_t>& tx, const std::string_view& data)
			{
				string hash = *crypto::hash(digests::sha256(), data);
				tx_append(tx, (uint8_t*)hash.data(), hash.size());
			}
			static void tx_append_op_create_account(vector<uint8_t>& tx, StellarCreateAccountOp& data)
			{
				/* sourceAccount: */
				tx_append_uint32(tx, 0);
				/* type: */
				tx_append_uint32(tx, 0);
				/* destination: */
				tx_append_address(tx, data.new_account);
				/* startingBalance: */
				tx_append_uint64(tx, (uint64_t)data.starting_balance);
			}
			static void tx_append_op_payment(vector<uint8_t>& tx, StellarPaymentOp& data)
			{
				/* sourceAccount: */
				tx_append_uint32(tx, 0);
				/* type: */
				tx_append_uint32(tx, 1);
				/* destination: */
				tx_append_address(tx, data.destination_account);
				/* asset.type: */
				tx_append_uint32(tx, data.asset.type);
				/* asset.assetCode: */
				if (data.asset.has_code)
					tx_append(tx, (uint8_t*)data.asset.code, data.asset.type == (uint32_t)stellar::asset_type::ASSET_TYPE_CREDIT_ALPHANUM4 ? 4 : 12);
				/* asset.issuer: */
				if (data.asset.has_issuer)
					tx_append_address(tx, data.asset.issuer);
				/* amount: */
				tx_append_uint64(tx, (uint64_t)data.amount);
			}
			static void tx_append_decorated_signature(vector<uint8_t>& tx, StellarSignedTx& data)
			{
				/* hint: */
				tx_append(tx, data.public_key.bytes + 28, 4);
				/* signature: */
				tx_append_uint32(tx, data.signature.size);
				tx_append(tx, data.signature.bytes, 64);
			}
			static void tx_append_transaction_v0(vector<uint8_t>& tx, const StellarSignTx& transaction, vector<StellarCreateAccountOp>& accounts, vector<StellarPaymentOp>& payments)
			{
				/* sourceAccountEd25519: */
				tx_append_address(tx, transaction.source_account);
				/* fee: */
				tx_append_uint32(tx, transaction.fee);
				/* seqNum: */
				tx_append_uint64(tx, transaction.sequence_number);
				/* timeBounds: */
				tx_append_uint32(tx, 0);
				/* memo: */
				if (transaction.memo_type == 2)
				{
					tx_append_uint32(tx, transaction.memo_type);
					tx_append_uint64(tx, transaction.memo_id);
				}
				else
					tx_append_uint32(tx, 0);
				/* operations: */
				tx_append_uint32(tx, transaction.num_operations);
				for (auto& item : accounts)
					tx_append_op_create_account(tx, item);
				for (auto& item : payments)
					tx_append_op_payment(tx, item);
				/* ext: */
				tx_append_uint32(tx, 0);
			}
			static void tx_append_transaction_signature_payload(vector<uint8_t>& tx, const StellarSignTx& transaction, vector<StellarCreateAccountOp>& accounts, vector<StellarPaymentOp>& payments)
			{
				/* networkId: */
				tx_append_hash(tx, transaction.network_passphrase);
				/* type: (ENVELOPE_TYPE_TX) */
				tx_append_uint32(tx, 2);
				/* tx: */
				tx_append_transaction_v0(tx, transaction, accounts, payments);
			}
			static void tx_append_transaction_v0_envelope(vector<uint8_t>& tx, const StellarSignTx& transaction, vector<StellarSignedTx>& signatures, vector<StellarCreateAccountOp>& accounts, vector<StellarPaymentOp>& payments)
			{
				/* tx: */
				tx_append_transaction_v0(tx, transaction, accounts, payments);
				/* signatures: */
				tx_append_uint32(tx, (uint32_t)signatures.size());
				for (auto& item : signatures)
					tx_append_decorated_signature(tx, item);
			}
			static vector<uint8_t> tx_data_from_signature(const StellarSignTx& transaction, vector<StellarCreateAccountOp>& accounts, vector<StellarPaymentOp>& payments)
			{
				vector<uint8_t> tx;
				tx.reserve(8192);
				tx_append_transaction_signature_payload(tx, transaction, accounts, payments);

				string hash = *crypto::hash(digests::sha256(), string((char*)tx.data(), tx.size()));
				tx.resize(hash.size());
				memcpy(tx.data(), hash.data(), hash.size());
				return tx;
			}
			static vector<uint8_t> tx_data_from_envelope(const StellarSignTx& transaction, vector<StellarSignedTx>& signatures, vector<StellarCreateAccountOp>& accounts, vector<StellarPaymentOp>& payments)
			{
				vector<uint8_t> tx; tx.reserve(8192);
				tx_append_transaction_v0_envelope(tx, transaction, signatures, accounts, payments);
				return tx;
			}
			static StellarCreateAccountOp tx_create_account_prepared(const std::string_view& new_account, const std::string_view& source_account, uint64_t value, bool is_contract_address)
			{
				StellarCreateAccountOp account;
				memset(&account, 0, sizeof(account));
				strncpy(account.new_account, new_account.data(), std::min<size_t>(sizeof(account.new_account), new_account.size()));
				strncpy(account.source_account, source_account.data(), std::min<size_t>(sizeof(account.source_account), source_account.size()));
				account.has_new_account = true;
				account.has_source_account = true;
				account.has_starting_balance = !is_contract_address;
				account.starting_balance = account.has_starting_balance ? value : 0;
				return account;
			}
			static StellarPaymentOp tx_create_payment_prepared(const std::string_view& destination_account, const std::string_view& source_account, const StellarAssetType& asset, uint64_t value)
			{
				StellarPaymentOp payment;
				memset(&payment, 0, sizeof(payment));
				strncpy(payment.destination_account, destination_account.data(), std::min<size_t>(sizeof(payment.destination_account), destination_account.size()));
				strncpy(payment.source_account, source_account.data(), std::min<size_t>(sizeof(payment.source_account), source_account.size()));
				payment.has_destination_account = true;
				payment.has_source_account = true;
				payment.has_amount = true;
				payment.asset = asset;
				payment.amount = value;
				return payment;
			}
			static StellarAssetType tx_create_token_asset_prepared(const std::string_view& code, const std::string_view& issuer, stellar::asset_type type)
			{
				StellarAssetType stellar_asset;
				memset(&stellar_asset, 0, sizeof(stellar_asset));
				strncpy(stellar_asset.code, code.data(), std::min<size_t>(sizeof(stellar_asset.code), code.size()));
				strncpy(stellar_asset.issuer, issuer.data(), std::min<size_t>(sizeof(stellar_asset.issuer), issuer.size()));
				stellar_asset.type = (uint32_t)type;
				stellar_asset.has_code = true;
				stellar_asset.has_issuer = true;
				stellar_asset.has_type = true;
				return stellar_asset;
			}
			static StellarAssetType tx_create_native_asset_prepared()
			{
				StellarAssetType stellar_asset;
				memset(&stellar_asset, 0, sizeof(stellar_asset));
				stellar_asset.type = (uint32_t)stellar::asset_type::ASSET_TYPE_NATIVE;
				stellar_asset.has_code = false;
				stellar_asset.has_issuer = false;
				stellar_asset.has_type = true;
				return stellar_asset;
			}
			static StellarSignTx tx_create_transaction(const std::string_view& source_account, const std::string_view& network_passphrase, uint64_t sequence_number, uint64_t memo_id, bool has_memo, size_t accounts_count, size_t payments_count, uint64_t base_fee)
			{
				StellarSignTx transaction;
				memset(&transaction, 0, sizeof(transaction));
				strncpy(transaction.source_account, source_account.data(), std::min<size_t>(sizeof(transaction.source_account), source_account.size()));
				strncpy(transaction.network_passphrase, network_passphrase.data(), std::min<size_t>(sizeof(transaction.network_passphrase), network_passphrase.size()));
				transaction.has_source_account = true;
				transaction.has_network_passphrase = true;
				transaction.has_sequence_number = true;
				transaction.has_memo_type = true;
				transaction.has_num_operations = true;
				transaction.has_fee = true;
				transaction.sequence_number = sequence_number;
				transaction.memo_type = has_memo ? 2 : 0;
				transaction.memo_id = memo_id;
				transaction.num_operations = (uint32_t)(accounts_count + payments_count);
				transaction.fee = (uint32_t)(transaction.num_operations * base_fee);
				return transaction;
			}

			string stellar::nd_call::get_ledger(uint64_t block_height)
			{
				return stringify::text("/ledgers/%" PRIu64, (uint64_t)block_height);
			}
			string stellar::nd_call::get_ledger_operations(uint64_t block_height, const std::string_view& cursor, uint64_t count)
			{
				return stringify::text("/ledgers/%" PRIu64 "/operations?include_failed=false%s%.*s&limit=%" PRIu64 "&order=asc", block_height, cursor.empty() ? "" : "&cursor=", (int)cursor.size(), cursor.data(), count);
			}
			string stellar::nd_call::get_transactions(const std::string_view& tx_id)
			{
				return stringify::text("/transactions/%.*s", (int)tx_id.size(), tx_id.data());
			}
			string stellar::nd_call::get_accounts(const std::string_view& address)
			{
				return stringify::text("/accounts/%.*s", (int)address.size(), address.data());
			}
			string stellar::nd_call::get_assets(const std::string_view& issuer, const std::string_view& code)
			{
				return stringify::text("/assets?asset_isser=%.*s&asset_code=%.*s", (int)issuer.size(), issuer.data(), (int)code.size(), code.data());
			}
			const char* stellar::nd_call::get_last_ledger()
			{
				return "/ledgers?order=desc&limit=1";
			}
			const char* stellar::nd_call::submit_transaction()
			{
				return "/transactions";
			}

			stellar::stellar(const algorithm::asset_id& new_asset, chain_config* new_config) noexcept : translation_unit(new_asset)
			{
				if (new_config != nullptr)
					config = *new_config;

				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::memo;
				netdata.tokenization = token_policy::none;
				netdata.sync_latency = 0;
				netdata.divisibility = algorithm::arithmetic::fixed(10000000);
				netdata.transaction_expires = false;
			}
			expects_promise_rt<stellar::asset_info> stellar::get_asset_info(const std::string_view& address, const std::string_view& code)
			{
				string ref_address = string(address);
				return execute_rest("GET", nd_call::get_assets(address, code), format::tree(), cache_policy::lifetime_cache).then<expects_rt<asset_info>>([ref_address = std::move(ref_address)](expects_rt<format::tree>&& asset_data) mutable -> expects_rt<asset_info>
				{
					if (!asset_data)
						return expects_rt<stellar::asset_info>(std::move(asset_data.error()));

					auto* records = asset_data->child("_embedded.records");
					if (!records)
						return expects_rt<stellar::asset_info>(remote_exception("contract address not found"));

					for (auto& asset : records->childs())
					{
						asset_info info;
						info.code = asset.child_var("asset_code").as_blob();
						info.issuer = asset.child_var("asset_isser").as_blob();
						info.type = asset.child_var("asset_type").as_blob();
						if (info.issuer == ref_address)
							return expects_rt<stellar::asset_info>(std::move(info));
					}

					return expects_rt<stellar::asset_info>(remote_exception("contract address not found"));
				});
			}
			expects_promise_rt<stellar::account_info> stellar::get_account_info(const std::string_view& address)
			{
				return execute_rest("GET", nd_call::get_accounts(address), format::tree(), cache_policy::no_cache).then<expects_rt<account_info>>([this](expects_rt<format::tree>&& account_data) -> expects_rt<account_info>
				{
					if (!account_data)
						return expects_rt<stellar::account_info>(std::move(account_data.error()));

					account_info info;
					info.sequence = account_data->child_var("sequence").as_uint64();
					if (account_data->has("balances"))
					{
						auto blockchain = algorithm::asset::blockchain_of(native_asset);
						for (auto& item : account_data->child("balances")->childs())
						{
							asset_balance balance;
							balance.info.type = item.child_var("asset_type").as_blob();
							balance.info.code = item.child_var("asset_code").as_blob();
							balance.info.issuer = item.child_var("asset_issuer").as_blob();
							balance.balance = item.child_var("balance").as_decimal();
							if (balance.info.code.empty())
							{
								if (balance.info.type == "native")
									info.balances[native_asset] = balance;
							}
							else
							{
								auto token_asset = algorithm::asset::id_of(blockchain, balance.info.code, balance.info.issuer);
								info.balances[token_asset] = balance;
							}
						}
					}

					return expects_rt<stellar::account_info>(std::move(info));
				});
			}
			expects_promise_rt<string> stellar::get_transaction_memo(const std::string_view& tx_id)
			{
				return execute_rest("GET", nd_call::get_transactions(format::util::clear_0xhex(tx_id)), format::tree(), cache_policy::blob_cache).then<expects_rt<string>>([](expects_rt<format::tree>&& tx_data) -> expects_rt<string>
				{
					if (!tx_data)
						return expects_rt<string>(std::move(tx_data.error()));

					string memo = tx_data->child_var("memo").as_blob();
					if (memo.empty())
						return expects_rt<string>(remote_exception("transaction memo not found"));

					return expects_rt<string>(std::move(memo));
				});
			}
			expects_promise_rt<bool> stellar::is_account_exists(const std::string_view& address)
			{
				return execute_rest("GET", nd_call::get_accounts(address), format::tree(), cache_policy::no_cache).then<expects_rt<bool>>([](expects_rt<format::tree>&& account_data) -> expects_rt<bool>
				{
					if (!account_data && (account_data.error().is_retry() || account_data.error().is_shutdown()))
						return expects_rt<bool>(account_data.error());

					return expects_rt<bool>(account_data && account_data->has("account_id"));
				});
			}
			expects_promise_rt<uint64_t> stellar::get_latest_block_height()
			{
				return execute_rest("GET", nd_call::get_last_ledger(), format::tree(), cache_policy::no_cache).then<expects_rt<uint64_t>>([](expects_rt<format::tree>&& last_block_data) -> expects_rt<uint64_t>
				{
					if (!last_block_data)
						return expects_rt<uint64_t>(std::move(last_block_data.error()));

					uint64_t block_height = (uint64_t)last_block_data->child_var("_embedded.records.0.sequence").as_uint64();
					return expects_rt<uint64_t>(block_height);
				});
			}
			expects_promise_rt<vector<block_log>> stellar::get_block_transactions(uint64_t block_height, uint64_t block_count)
			{
				return coasync<expects_rt<vector<block_log>>>([this, block_height, block_count]() -> expects_promise_rt<vector<block_log>>
				{
					vector<block_log> results;
					for (uint64_t i = 0; i < block_count; i++)
					{
						auto& log = results.emplace_back();
						log.block_hash = to_string(block_height + i);
						log.transactions = format::tree::list();

						string cursor;
						size_t count = 200;
						while (true)
						{
							auto block_data = coawait(execute_rest("GET", nd_call::get_ledger_operations(block_height + i, cursor, count), format::tree(), cache_policy::blob_cache));
							if (!block_data)
								coreturn block_data.error();

							auto* transactions = (format::tree*)block_data->child("_embedded.records");
							size_t transactions_count = transactions ? transactions->childs().size() : 0;
							if (transactions != nullptr)
							{
								if (!log.transactions.childs().empty())
									log.transactions.childs().insert(log.transactions.childs().end(), std::make_move_iterator(transactions->childs().begin()), std::make_move_iterator(transactions->childs().end()));
								else
									log.transactions = std::move(*transactions);
							}

							auto next_cursor = block_data->child_var("_links.next.href").as_blob();
							if (next_cursor.empty() || transactions_count < count)
								break;

							location href = location(next_cursor);
							auto it = href.query.find("cursor");
							if (it == href.query.end() || it->second.empty())
								break;

							cursor = std::move(it->second);
						}
					}
					coreturn expects_rt<vector<block_log>>(std::move(results));
				});
			}
			expects_promise_rt<computed_transaction> stellar::link_transaction(uint64_t, const std::string_view&, format::tree& transaction_data)
			{
				return coasync<expects_rt<computed_transaction>>([this, &transaction_data]() -> expects_promise_rt<computed_transaction>
				{
					bool is_successful = transaction_data.child_var("successful").as_boolean() || transaction_data.child_var("transaction_successful").as_boolean();
					if (!is_successful)
						coreturn expects_rt<computed_transaction>(remote_exception("tx reverted"));

					algorithm::asset_id token_asset = native_asset;
					string tx_hash = transaction_data.child_var("transaction_hash").as_blob();
					string tx_type = transaction_data.child_var("type").as_blob();
					decimal fee_value = from_stroop(get_base_stroop_fee());
					decimal base_value = 0.0, token_value = 0.0;
					string from = string(), to = string();
					bool is_payment = (tx_type == "payment");
					bool is_create_account = (!is_payment && tx_type == "create_account");
					bool is_native_token = (transaction_data.child_var("asset_type").as_blob() != "native");
					if (is_payment)
					{
						from = transaction_data.child_var("from").as_blob();
						to = transaction_data.child_var("to").as_blob();
						token_value = transaction_data.child_var("amount").as_decimal();
						if (is_native_token)
						{
							string token = transaction_data.child_var("asset_code").as_blob();
							string issuer = transaction_data.child_var("asset_issuer").as_blob();
							token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), token, issuer);
							bridge::get()->enable_contract_address(token_asset, issuer);
						}
						else
						{
							base_value = token_value;
							token_value = 0.0;
						}
					}
					else if (is_create_account)
					{
						from = transaction_data.child_var("funder").as_blob();
						to = transaction_data.child_var("account").as_blob();
						base_value = transaction_data.child_var("starting_balance").as_decimal();
					}

					auto discovery = find_linked_addresses({ from, to });
					if (!discovery || discovery->empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					computed_transaction tx;
					tx.transaction_id = tx_hash;

					auto total_value = base_value + fee_value;
					auto target_from_link = discovery->find(from);
					auto target_to_link = discovery->find(to);
					auto to_link = target_to_link != discovery->end() ? target_to_link->second : wallet_link::from_address(to);
					if (target_to_link != discovery->end())
					{
						auto memo = coawait(get_transaction_memo(tx_hash));
						if (memo && !memo->empty())
							to_link.address = address_util::encode_tag_address(to, *memo);
					}

					hash_map<algorithm::asset_id, decimal> inputs;
					hash_map<algorithm::asset_id, decimal> outputs;
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
						tx.add_input(coin_utxo(target_from_link != discovery->end() ? target_from_link->second : wallet_link::from_address(from), std::move(inputs)));
					if (!outputs.empty())
						tx.add_output(coin_utxo(std::move(to_link), std::move(outputs)));
					coreturn expects_rt<computed_transaction>(std::move(tx));
				});
			}
			expects_promise_rt<decimal> stellar::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				return get_account_info(link.address).then<expects_rt<decimal>>([for_asset](expects_rt<account_info>&& account) -> expects_rt<decimal>
				{
					if (!account)
						return expects_rt<decimal>(std::move(account.error()));

					auto balance = account->balances.find(for_asset);
					if (balance == account->balances.end())
						return expects_rt<decimal>(decimal::zero());

					auto contract_address = bridge::get()->get_contract_address(for_asset);
					if (contract_address && balance->second.info.issuer != *contract_address)
						return expects_rt<decimal>(decimal::zero());

					return expects_rt<decimal>(balance->second.balance);
				});
			}
			expects_promise_rt<void> stellar::broadcast_transaction(const finalized_transaction& finalized)
			{
				uptr<http::query> args = new http::query();
				args->object->set("tx", var::string(finalized.calldata));

				const char* type = "application/x-www-form-urlencoded";
				string body = args->encode(type);
				return execute_http("POST", nd_call::submit_transaction(), type, body, cache_policy::no_cache_no_throttling).then<expects_rt<void>>([](expects_rt<format::tree>&& result) -> expects_rt<void>
				{
					if (!result)
						return expects_rt<void>(std::move(result.error()));

					auto* error_operations = result->child("extras.result_codes.operations");
					auto error_message = result->child_var("extras.result_codes.transaction").as_blob();
					if (error_operations != nullptr)
					{
						for (auto& error_code : error_operations->childs())
							error_message += " " + error_code.value.as_blob();
					}

					stringify::trim(error_message);
					if (!result->child_var("successful").as_boolean() || !error_message.empty())
						return expects_rt<void>(error_message.empty() ? remote_exception("transaction failed without error message") : remote_exception(std::move(error_message)));

					return expects_rt<void>(expectation::met);
				});
			}
			expects_promise_rt<prepared_transaction> stellar::prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
			{
				return coasync<expects_rt<prepared_transaction>>([this, from_link, to, max_fee]() -> expects_promise_rt<prepared_transaction>
				{
					auto contract_address = bridge::get()->get_contract_address(to.asset);
					if (!contract_address && !algorithm::asset::token_of(to.asset).empty())
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to find a token contract address"));

					auto account_info = coawait(get_account_info(from_link.address));
					if (!account_info)
						coreturn expects_rt<prepared_transaction>(std::move(account_info.error()));

					auto& params = get_params();
					uint8_t decoded_public_key[256]; size_t decoded_public_key_size = sizeof(decoded_public_key);
					if (!decode_key(params.ed25519_public_key, from_link.public_key, decoded_public_key, &decoded_public_key_size))
						coreturn expects_rt<prepared_transaction>(remote_exception("input public key invalid"));

					auto [address, memo] = address_util::decode_tag_address(to.address);
					auto memo_id = from_string<uint64_t>(memo);
					if (memo.size() > 28 || (!memo.empty() && !memo_id))
						coreturn expects_rt<prepared_transaction>(remote_exception("input memo invalid"));

					auto has_account = coawait(is_account_exists(to.address));
					if (!has_account)
						coreturn expects_rt<prepared_transaction>(has_account.error());

					option<StellarCreateAccountOp> account = optional::none;
					option<StellarPaymentOp> payment = optional::none;
					if (!*has_account)
						account = tx_create_account_prepared(to.address, from_link.address, (uint64_t)to_stroop(to.value), !!contract_address);

					if (contract_address)
					{
						auto token = account_info->balances.find(to.asset);
						if (token == account_info->balances.end())
							coreturn expects_rt<prepared_transaction>(remote_exception("insufficient funds"));

						asset_type token_type = to_asset_type(token->second.info.type);
						if (token_type == asset_type::ASSET_TYPE_NATIVE)
							coreturn expects_rt<prepared_transaction>(remote_exception("standard not supported"));

						payment = tx_create_payment_prepared(to.address, from_link.address, tx_create_token_asset_prepared(token->second.info.code, token->second.info.issuer, token_type), (uint64_t)to_stroop(to.value));
					}
					else if (!account)
						payment = tx_create_payment_prepared(to.address, from_link.address, tx_create_native_asset_prepared(), (uint64_t)to_stroop(to.value));

					auto passphrase = get_network_passphrase();
					auto accounts = account ? vector<StellarCreateAccountOp>({ *account }) : vector<StellarCreateAccountOp>();
					auto payments = payment ? vector<StellarPaymentOp>({ *payment }) : vector<StellarPaymentOp>();
					StellarSignTx transaction = tx_create_transaction(from_link.address, passphrase, account_info->sequence + 1, memo_id.or_else(0), !memo.empty(), accounts.size(), payments.size(), get_base_stroop_fee());
					decimal fee_value = from_stroop(transaction.fee);
					if (fee_value > max_fee)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

					hash_map<algorithm::asset_id, decimal> inputs = { { to.asset, to.value } };
					auto& fee_input = inputs[native_asset];
					fee_input = fee_input.is_nan() ? fee_value : (fee_input + fee_value);
					transaction = tx_create_transaction(from_link.address, passphrase, account_info->sequence + 1, memo_id.or_else(0), !memo.empty(), accounts.size(), payments.size(), get_base_stroop_fee());
					for (auto& [token_asset, send_value] : inputs)
					{
						auto& total_value = token_asset == native_asset ? inputs[native_asset] : inputs[token_asset];
						auto balance_value = account_info->balances.find(token_asset);
						if (balance_value == account_info->balances.end() || balance_value->second.balance < total_value)
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance_value != account_info->balances.end() ? balance_value->second.balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));
					}

					auto it = account_info->balances.find(native_asset);
					if (it == account_info->balances.end() || it->second.balance - fee_input < 1)
						coreturn expects_rt<prepared_transaction>(remote_exception("spender account must have at least 1 XLM left after this operation"));

					auto signing_public_key = decode_public_key(from_link.public_key);
					if (!signing_public_key)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

					auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*signing_public_key);
					auto token = account_info->balances.find(to.asset);
					vector<uint8_t> raw_data = tx_data_from_signature(transaction, accounts, payments);
					prepared_transaction result;
					result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key, raw_data.data(), raw_data.size(), hash_map<algorithm::asset_id, decimal>(inputs));
					result.requires_account_output(to.address, { { to.asset, to.value } });
					result.requires_abi(format::variable(transaction.sequence_number));
					result.requires_abi(format::variable(!!account));
					result.requires_abi(format::variable(!!payment));
					result.requires_abi(format::variable(token != account_info->balances.end() ? token->second.info.code : string()));
					result.requires_abi(format::variable(token != account_info->balances.end() ? token->second.info.issuer : string()));
					result.requires_abi(format::variable((uint8_t)to_asset_type(token != account_info->balances.end() ? token->second.info.type : string())));
					coreturn expects_rt<prepared_transaction>(std::move(result));
				});
			}
			expects_lr<finalized_transaction> stellar::finalize_transaction(superchain::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 6 || prepared.outputs.size() != 1)
					return layer_exception("invalid prepared abi");

				auto& input = prepared.inputs.front();
				auto& params = get_params();
				uint8_t decoded_public_key[256]; size_t decoded_public_key_size = sizeof(decoded_public_key);
				if (!decode_key(params.ed25519_public_key, input.utxo.link.public_key, decoded_public_key, &decoded_public_key_size))
					return layer_exception("input public key invalid");

				auto& output = prepared.outputs.front();
				auto [address, memo] = address_util::decode_tag_address(output.link.address);
				auto memo_id = from_string<uint64_t>(memo);
				if (memo.size() > 28 || (!memo.empty() && !memo_id))
					return layer_exception("input memo invalid");

				auto create_account = prepared.abi[1].as_boolean();
				auto create_payment = prepared.abi[2].as_boolean();
				auto token_code = prepared.abi[3].as_string();
				auto token_issuer = prepared.abi[4].as_string();
				auto token_type = prepared.abi[5].as_uint8();
				auto passphrase = get_network_passphrase();
				StellarSignTx transaction = tx_create_transaction(input.utxo.link.address, passphrase, prepared.abi[0].as_uint64(), memo_id.or_else(0), !memo.empty(), create_account ? 1 : 0, create_payment ? 1 : 0, get_base_stroop_fee());
				option<StellarCreateAccountOp> account = optional::none;
				option<StellarPaymentOp> payment = optional::none;

				auto& value = output.tokens.empty() ? output.value : output.tokens.begin()->second.value;
				auto asset = output.tokens.empty() ? output.get_asset(native_asset) : output.tokens.begin()->second.get_asset(native_asset);
				auto contract_address = bridge::get()->get_contract_address(asset);
				if (create_account)
					account = tx_create_account_prepared(output.link.address, input.utxo.link.address, (uint64_t)to_stroop(value), !!contract_address);

				if (contract_address)
					payment = tx_create_payment_prepared(output.link.address, input.utxo.link.address, tx_create_token_asset_prepared(token_code, token_issuer, (asset_type)token_type), (uint64_t)to_stroop(value));
				else if (!account)
					payment = tx_create_payment_prepared(output.link.address, input.utxo.link.address, tx_create_native_asset_prepared(), (uint64_t)to_stroop(value));

				auto accounts = account ? vector<StellarCreateAccountOp>({ *account }) : vector<StellarCreateAccountOp>();
				auto payments = payment ? vector<StellarPaymentOp>({ *payment }) : vector<StellarPaymentOp>();
				vector<uint8_t> raw_signature_data = tx_data_from_signature(transaction, accounts, payments);
				if (input.message.size() != raw_signature_data.size() || memcmp(input.message.data(), raw_signature_data.data(), raw_signature_data.size()))
					return layer_exception("invalid input message");

				vector<StellarSignedTx> signatures;
				{
					StellarSignedTx sign;
					memset(&sign, 0, sizeof(sign));
					sign.signature.size = (pb_size_t)std::min<size_t>(sizeof(sign.signature.bytes), input.signature.size());
					sign.public_key.size = (pb_size_t)std::min<size_t>(sizeof(sign.public_key.bytes), decoded_public_key_size);
					memcpy(sign.signature.bytes, input.signature.data(), input.signature.size());
					memcpy(sign.public_key.bytes, decoded_public_key, sign.public_key.size);
					sign.has_public_key = true;
					sign.has_signature = true;
					signatures.push_back(std::move(sign));
				}

				vector<uint8_t> raw_data = tx_data_from_envelope(transaction, signatures, accounts, payments);
				auto result = finalized_transaction(std::move(prepared), codec::base64_encode(std::string_view((char*)raw_data.data(), raw_data.size())), codec::hex_encode(std::string_view((char*)input.message.data(), input.message.size())));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<secret_box> stellar::encode_secret_key(const secret_box& secret_key)
			{
				if (secret_key.size() != 32)
					return layer_exception("invalid private key");

				auto data = secret_key.expose<KEY_LIMIT>();
				return secret_box::secure(codec::hex_encode(data.view, true));
			}
			expects_lr<secret_box> stellar::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				string result = codec::hex_decode(data.view);
				if (result.size() == 32)
					return secret_box::secure(result);

				uint8_t seed_key[64]; size_t seed_key_size = 0;
				if (!decode_key(get_params().ed25519_secret_seed, data.view, seed_key, &seed_key_size) || seed_key_size != 32)
					return layer_exception("bad secret seed");

				uint8_t private_key[64];
				sha512_Raw(seed_key, seed_key_size, private_key);
				algorithm::keypair_utils::convert_to_secret_key_ed25519(private_key);
				return secret_box::secure(std::string_view((char*)private_key, 32));
			}
			expects_lr<string> stellar::encode_public_key(const std::string_view& public_key)
			{
				if (public_key.size() != 32)
					return layer_exception("not a valid public key");

				return encode_key(get_params().ed25519_public_key, (uint8_t*)public_key.data(), public_key.size());
			}
			expects_lr<string> stellar::decode_public_key(const std::string_view& public_key)
			{
				uint8_t raw_public_key[32]; size_t raw_public_key_size = sizeof(raw_public_key);
				if (!decode_key(get_params().ed25519_public_key, public_key, raw_public_key, &raw_public_key_size) || raw_public_key_size != 32)
					return layer_exception("invalid public key");

				return string((char*)raw_public_key, raw_public_key_size);
			}
			expects_lr<string> stellar::encode_address(const std::string_view& public_key_hash)
			{
				auto result = encode_public_key(public_key_hash.substr(0, 32));
				if (result)
					result = superchain::address_util::encode_tag_address(*result, public_key_hash.substr(32));
				return result;
			}
			expects_lr<string> stellar::decode_address(const std::string_view& address)
			{
				auto [base_address, tag] = superchain::address_util::decode_tag_address(address);
				auto result = decode_public_key(base_address);
				if (result && !tag.empty())
					result->append(tag);
				return result;
			}
			expects_lr<string> stellar::encode_transaction_id(const std::string_view& transaction_id)
			{
				return codec::hex_encode(transaction_id, true);
			}
			expects_lr<string> stellar::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = codec::hex_decode(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> stellar::to_addresses(const std::string_view& input_public_key)
			{
				string encoded_public_key = string(input_public_key);
				if (encoded_public_key.size() == 32)
				{
					auto result = encode_public_key(encoded_public_key);
					if (!result)
						return result.error();

					encoded_public_key = std::move(*result);
				}

				address_map result = { { (uint8_t)1, encoded_public_key } };
				return expects_lr<address_map>(std::move(result));
			}
			const stellar::chainparams& stellar::get_chainparams() const
			{
				return netdata;
			}
			string stellar::get_network_passphrase()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
					case network_type::testnet:
						return "Test SDF Network ; September 2015";
					case network_type::mainnet:
						return "Public Global Stellar Network ; September 2015";
					default:
						VI_PANIC(false, "invalid network type");
						return string();
				}
			}
			decimal stellar::from_stroop(const uint256_t& value)
			{
				return decimal(value.to_string()) / netdata.divisibility;
			}
			uint256_t stellar::to_stroop(const decimal& value)
			{
				return uint256_t((value * netdata.divisibility).truncate(0).to_string());
			}
			uint64_t stellar::get_base_stroop_fee()
			{
				return 100;
			}
			uint16_t stellar::calculate_checksum(const uint8_t* value, size_t size)
			{
				uint64_t hash = 0x0; // CRC16 XMODEM
				for (size_t i = 0; i < size; i++)
				{
					uint8_t byte = value[i];
					uint64_t code = (hash >> 8) & 0xff;
					code ^= byte & 0xff;
					code ^= code >> 4;
					hash = (hash << 8) & 0xffff;
					hash ^= code;
					code = (code << 5) & 0xffff;
					hash ^= code;
					code = (code << 7) & 0xffff;
					hash ^= code;
				}
				return (uint16_t)hash;
			}
			bool stellar::decode_key(uint8_t version, const std::string_view& data, uint8_t* out_value, size_t* out_size)
			{
				vector<uint8_t> key(base32_decoded_length(data.size()), 0);
				if (key.size() < 3 || *out_size < key.size() - 3)
					return false;

				*out_size = key.size();
				if (!base32_decode(data.data(), data.size(), &key[0], key.size(), BASE32_ALPHABET_RFC4648))
					return false;

				uint8_t given_version = key[0];
				if (given_version != version)
					return false;

				uint16_t given_checksum = 0;
				uint16_t checksum = calculate_checksum(&key[0], key.size() - 2);
				memcpy(&given_checksum, &key[key.size() - 2], sizeof(uint8_t) * 2);
				if (given_checksum != checksum)
					return false;

				*out_size = key.size() - 3;
				memcpy(out_value, &key[1], sizeof(uint8_t) * (*out_size));
				return true;
			}
			string stellar::encode_key(uint8_t version, const uint8_t* value, size_t size)
			{
				vector<uint8_t> key(1 + size + 2, version);
				memcpy(&key[1], value, sizeof(uint8_t) * size);

				uint16_t checksum = calculate_checksum(&key[0], size + 1);
				memcpy(&key[key.size() - 2], &checksum, sizeof(uint8_t) * 2);

				size_t expected_size = std::max<size_t>(1, base32_encoded_length(key.size()));
				string data(expected_size, '\0');
				if (!base32_encode(&key[0], key.size(), (char*)data.data(), data.size() + 1, BASE32_ALPHABET_RFC4648))
					data.clear();

				return data;
			}
			stellar::chain_info& stellar::get_params()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return config.regtest;
					case network_type::testnet:
						return config.testnet;
					case network_type::mainnet:
						return config.mainnet;
					default:
						VI_PANIC(false, "invalid network type");
						return config.regtest;
				}
			}
			const sc_chainparams_* stellar::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &xlm_chainparams_regtest;
					case network_type::testnet:
						return &xlm_chainparams_test;
					case network_type::mainnet:
						return &xlm_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}