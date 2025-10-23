#include "stellar.h"
#include "../service/oracle.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/chainparams.h"
#include "../internal/libbitcoin/ecc.h"
#include "../internal/libbitcoin/bip32.h"
extern "C"
{
#include "../internal/libstellar/stellar.h"
#include "../../internal/base32.h"
#include "../../internal/ed25519.h"
}
#include <sodium.h>

namespace tangent
{
	namespace warden
	{
		namespace backends
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
			string stellar::nd_call::get_ledger_operations(uint64_t block_height)
			{
				return stringify::text("/ledgers/%" PRIu64 "/operations?include_failed=false", (uint64_t)block_height);
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

			stellar::stellar(const algorithm::asset_id& new_asset, chain_config* new_config) noexcept : relay_backend(new_asset)
			{
				if (new_config != nullptr)
					config = *new_config;

				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::memo;
				netdata.tokenization = token_policy::native;
				netdata.sync_latency = 0;
				netdata.divisibility = decimal(10000000).truncate(protocol::now().message.decimal_precision);
				netdata.supports_bulk_transfer = true;
				netdata.requires_transaction_expiration = false;
			}
			expects_promise_rt<stellar::asset_info> stellar::get_asset_info(const std::string_view& address, const std::string_view& code)
			{
				auto asset_data = coawait(execute_rest("GET", nd_call::get_assets(address, code), nullptr, cache_policy::lifetime_cache));
				if (!asset_data)
					coreturn expects_rt<stellar::asset_info>(std::move(asset_data.error()));

				uptr<schema> asset_wrap = *asset_data;
				schema* records = asset_wrap->fetch("_embedded.records");
				if (!records)
					coreturn expects_rt<stellar::asset_info>(remote_exception("contract address not found"));

				for (auto& asset : records->get_childs())
				{
					asset_info info;
					info.code = asset->get_var("asset_code").get_blob();
					info.issuer = asset->get_var("asset_isser").get_blob();
					info.type = asset->get_var("asset_type").get_blob();
					if (info.issuer == address)
						coreturn expects_rt<stellar::asset_info>(std::move(info));
				}

				coreturn expects_rt<stellar::asset_info>(remote_exception("contract address not found"));
			}
			expects_promise_rt<stellar::account_info> stellar::get_account_info(const std::string_view& address)
			{
				auto account_data = coawait(execute_rest("GET", nd_call::get_accounts(address), nullptr, cache_policy::no_cache));
				if (!account_data)
					coreturn expects_rt<stellar::account_info>(std::move(account_data.error()));

				account_info info;
				info.sequence = account_data->get_var("sequence").get_integer();
				if (account_data->has("balances"))
				{
					auto blockchain = algorithm::asset::blockchain_of(native_asset);
					for (auto& item : account_data->get("balances")->get_childs())
					{
						asset_balance balance;
						balance.info.type = item->get_var("asset_type").get_blob();
						balance.info.code = item->get_var("asset_code").get_blob();
						balance.info.issuer = item->get_var("asset_issuer").get_blob();
						balance.balance = item->get_var("balance").get_decimal();
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

				memory::release(*account_data);
				coreturn expects_rt<stellar::account_info>(std::move(info));
			}
			expects_promise_rt<string> stellar::get_transaction_memo(const std::string_view& tx_id)
			{
				auto tx_data = coawait(execute_rest("GET", nd_call::get_transactions(format::util::clear_0xhex(tx_id)), nullptr, cache_policy::blob_cache));
				if (!tx_data)
					coreturn expects_rt<string>(std::move(tx_data.error()));

				string memo = tx_data->get_var("memo").get_blob();
				if (memo.empty())
					coreturn expects_rt<string>(remote_exception("transaction memo not found"));

				coreturn expects_rt<string>(std::move(memo));
			}
			expects_promise_rt<bool> stellar::is_account_exists(const std::string_view& address)
			{
				auto account_data = coawait(execute_rest("GET", nd_call::get_accounts(address), nullptr, cache_policy::no_cache));
				if (!account_data && (account_data.error().is_retry() || account_data.error().is_shutdown()))
					coreturn expects_rt<bool>(account_data.error());

				auto account = uptr<schema>(account_data.or_else(nullptr));
				coreturn expects_rt<bool>(account && account->has("account_id"));
			}
			expects_promise_rt<uint64_t> stellar::get_latest_block_height()
			{
				auto last_block_data = coawait(execute_rest("GET", nd_call::get_last_ledger(), nullptr, cache_policy::no_cache));
				if (!last_block_data)
					coreturn expects_rt<uint64_t>(std::move(last_block_data.error()));

				uint64_t block_height = (uint64_t)last_block_data->fetch_var("_embedded.records.0.sequence").get_integer();
				memory::release(*last_block_data);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> stellar::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				auto block_data = coawait(execute_rest("GET", nd_call::get_ledger_operations(block_height), nullptr, cache_policy::blob_cache));
				if (!block_data)
					coreturn expects_rt<schema*>(std::move(block_data.error()));

				if (block_hash != nullptr)
					*block_hash = to_string(block_height);

				schema* data = block_data->fetch("_embedded.records");
				if (!data)
				{
					memory::release(*block_data);
					coreturn expects_rt<schema*>(remote_exception("block not found"));
				}

				data->unlink();
				memory::release(*block_data);
				coreturn expects_rt<schema*>(data);
			}
			expects_promise_rt<computed_transaction> stellar::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				algorithm::asset_id token_asset = native_asset;
				string tx_hash = transaction_data->get_var("transaction_hash").get_blob();
				string tx_type = transaction_data->get_var("type").get_blob();
				decimal fee_value = from_stroop(get_base_stroop_fee());
				decimal base_value = 0.0, token_value = 0.0;
				string from = string(), to = string();
				bool is_payment = (tx_type == "payment");
				bool is_create_account = (!is_payment && tx_type == "create_account");
				bool is_native_token = (transaction_data->get_var("asset_type").get_blob() != "native");
				if (is_payment)
				{
					from = transaction_data->get_var("from").get_blob();
					to = transaction_data->get_var("to").get_blob();
					token_value = transaction_data->get_var("amount").get_decimal();
					if (is_native_token)
					{
						string token = transaction_data->get_var("asset_code").get_blob();
						string issuer = transaction_data->get_var("asset_issuer").get_blob();
						token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(native_asset), token, issuer);
						oracle::server_node::get()->enable_contract_address(token_asset, issuer);
					}
					else
					{
						base_value = token_value;
						token_value = 0.0;
					}
				}
				else if (is_create_account)
				{
					from = transaction_data->get_var("funder").get_blob();
					to = transaction_data->get_var("account").get_blob();
					base_value = transaction_data->get_var("starting_balance").get_decimal();
				}

				auto discovery = find_linked_addresses({ from, to });
				if (!discovery || discovery->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				auto to_tag = to;
				auto memo = coawait(get_transaction_memo(tx_hash));
				if (memo && !memo->empty())
				{
					to_tag = address_util::encode_tag_address(to, *memo);
					discovery = find_linked_addresses({ from, to, to_tag });
					if (!discovery || discovery->empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));
				}

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
			expects_promise_rt<computed_fee> stellar::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				if (algorithm::asset::token_of(to.front().asset).empty())
					coreturn expects_rt<computed_fee>(computed_fee::flat_fee(from_stroop(get_base_stroop_fee() * to.size())));

				uint64_t fee = get_base_stroop_fee() * to.size();
				for (auto& item : to)
				{
					auto status = coawait(is_account_exists(item.address));
					if (!status)
						coreturn expects_rt<computed_fee>(status.error());
					else if (!*status)
						fee += get_base_stroop_fee();
				}

				coreturn expects_rt<computed_fee>(computed_fee::flat_fee(from_stroop(fee)));
			}
			expects_promise_rt<decimal> stellar::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				auto account = coawait(get_account_info(link.address));
				if (!account)
					coreturn expects_rt<decimal>(std::move(account.error()));

				auto balance = account->balances.find(for_asset);
				if (balance == account->balances.end())
					coreturn expects_rt<decimal>(decimal::zero());

				auto contract_address = oracle::server_node::get()->get_contract_address(for_asset);
				if (contract_address && balance->second.info.issuer != *contract_address)
					coreturn expects_rt<decimal>(decimal::zero());

				coreturn expects_rt<decimal>(balance->second.balance);
			}
			expects_promise_rt<void> stellar::broadcast_transaction(const finalized_transaction& finalized)
			{
				uptr<http::query> args = new http::query();
				args->object->set("tx", var::string(finalized.calldata));

				const char* type = "application/x-www-form-urlencoded";
				string body = args->encode(type);
				auto hex_data = coawait(execute_http("POST", nd_call::submit_transaction(), type, body, cache_policy::no_cache_no_throttling));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				string detail = hex_data->get_var("detail").get_blob();
				if (!detail.empty())
				{
					string code = hex_data->fetch_var("extras.result_codes.transaction").get_blob();
					coreturn expects_rt<void>(remote_exception(std::move(code.empty() ? detail : code)));
				}

				memory::release(*hex_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> stellar::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee, bool inclusive_fee)
			{
				auto account_info = coawait(get_account_info(from_link.address));
				if (!account_info)
					coreturn expects_rt<prepared_transaction>(std::move(account_info.error()));

				auto& params = get_params();
				uint8_t decoded_public_key[256]; size_t decoded_public_key_size = sizeof(decoded_public_key);
				if (!decode_key(params.ed25519_public_key, from_link.public_key, decoded_public_key, &decoded_public_key_size))
					coreturn expects_rt<prepared_transaction>(remote_exception("input public key invalid"));

				string memo;
				for (auto& item : to)
				{
					auto [address, tag] = address_util::decode_tag_address(item.address);
					if (tag.empty())
						continue;
					else if (!memo.empty())
						coreturn expects_rt<prepared_transaction>(remote_exception("too many memos"));

					memo = std::move(tag);
				}

				auto memo_id = from_string<uint64_t>(memo);
				if (memo.size() > 28 || (!memo.empty() && !memo_id))
					coreturn expects_rt<prepared_transaction>(remote_exception("input memo invalid"));

				unordered_set<string> new_accounts;
				unordered_map<algorithm::asset_id, decimal> inputs;
				vector<StellarCreateAccountOp> accounts;
				vector<StellarPaymentOp> payments;
				accounts.reserve(to.size());
				payments.reserve(to.size());
				for (auto& item : to)
				{
					auto has_account = coawait(is_account_exists(item.address));
					if (!has_account)
						coreturn expects_rt<prepared_transaction>(has_account.error());

					if (inputs.find(item.asset) != inputs.end())
						inputs[item.asset] += item.value;
					else
						inputs[item.asset] = item.value;

					auto contract_address = oracle::server_node::get()->get_contract_address(item.asset);
					if (!*has_account)
					{
						StellarCreateAccountOp account = tx_create_account_prepared(item.address, from_link.address, (uint64_t)to_stroop(item.value), !!contract_address);
						accounts.push_back(account);
						new_accounts.insert(item.address);
						if (account.has_starting_balance)
							continue;
					}

					if (contract_address)
					{
						auto token = account_info->balances.find(item.asset);
						if (token == account_info->balances.end())
							coreturn expects_rt<prepared_transaction>(remote_exception("insufficient funds"));

						asset_type token_type = to_asset_type(token->second.info.type);
						if (token_type == asset_type::ASSET_TYPE_NATIVE)
							coreturn expects_rt<prepared_transaction>(remote_exception("standard not supported"));

						payments.push_back(tx_create_payment_prepared(item.address, from_link.address, tx_create_token_asset_prepared(token->second.info.code, token->second.info.issuer, token_type), (uint64_t)to_stroop(item.value)));
					}
					else
						payments.push_back(tx_create_payment_prepared(item.address, from_link.address, tx_create_native_asset_prepared(), (uint64_t)to_stroop(item.value)));
				}

				auto passphrase = get_network_passphrase();
				StellarSignTx transaction = tx_create_transaction(from_link.address, passphrase, account_info->sequence + 1, memo_id.or_else(0), !memo.empty(), accounts.size(), payments.size(), get_base_stroop_fee());
				if (inclusive_fee)
				{
					size_t outputs_size = 0;
					for (auto& account : accounts)
						outputs_size += account.starting_balance > 0 ? 1 : 0;
					for (auto& payment : payments)
						outputs_size += payment.asset.type == (uint32_t)stellar::asset_type::ASSET_TYPE_NATIVE ? 1 : 0;

					decimal fee_value_per_output = outputs_size > 0 ? from_stroop(transaction.fee) / decimal(outputs_size).truncate(protocol::now().message.decimal_precision) : decimal::zero();
					for (auto& account : accounts)
					{
						if (account.starting_balance <= 0)
							continue;

						auto new_value = from_stroop((uint64_t)account.starting_balance) - fee_value_per_output;
						if (new_value.is_negative())
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s", new_value.to_string().c_str())));

						account.starting_balance = (uint64_t)to_stroop(new_value);
					}
					for (auto& payment : payments)
					{
						if (payment.asset.type != (uint32_t)stellar::asset_type::ASSET_TYPE_NATIVE)
							continue;

						auto new_value = from_stroop((uint64_t)payment.amount) - fee_value_per_output;
						if (new_value.is_negative())
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s", new_value.to_string().c_str())));

						payment.amount = (uint64_t)to_stroop(new_value);
					}

					if (outputs_size > 0)
						transaction = tx_create_transaction(from_link.address, passphrase, account_info->sequence + 1, memo_id.or_else(0), !memo.empty(), accounts.size(), payments.size(), get_base_stroop_fee());
					else if (inputs.find(native_asset) != inputs.end())
						inputs[native_asset] += from_stroop(transaction.fee);
					else
						inputs[native_asset] = from_stroop(transaction.fee);
				}
				else if (inputs.find(native_asset) != inputs.end())
					inputs[native_asset] += from_stroop(transaction.fee);
				else
					inputs[native_asset] = from_stroop(transaction.fee);

				for (auto& [token_asset, send_value] : inputs)
				{
					auto total_value = token_asset == native_asset ? inputs[native_asset] : inputs[token_asset];
					auto balance_value = account_info->balances.find(token_asset);
					if (balance_value == account_info->balances.end() || balance_value->second.balance < total_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance_value != account_info->balances.end() ? balance_value->second.balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));
				}

				auto signing_public_key = decode_public_key(from_link.public_key);
				if (!signing_public_key)
					coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

				auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*signing_public_key);
				vector<uint8_t> raw_data = tx_data_from_signature(transaction, accounts, payments);
				prepared_transaction result;
				result.requires_account_input(algorithm::composition::type::ed25519, wallet_link(from_link), public_key, raw_data.data(), raw_data.size(), unordered_map<algorithm::asset_id, decimal>(inputs));
				for (auto& item : to)
					result.requires_account_output(item.address, { { item.asset, item.value } });
				result.requires_abi(format::variable(transaction.sequence_number));
				result.requires_abi(format::variable((uint32_t)accounts.size()));
				result.requires_abi(format::variable((uint32_t)payments.size()));
				for (auto& item : to)
				{
					auto token = account_info->balances.find(item.asset);
					result.requires_abi(format::variable(new_accounts.find(item.address) != new_accounts.end()));
					result.requires_abi(format::variable(token != account_info->balances.end() ? token->second.info.code : string()));
					result.requires_abi(format::variable(token != account_info->balances.end() ? token->second.info.issuer : string()));
					result.requires_abi(format::variable((uint8_t)to_asset_type(token != account_info->balances.end() ? token->second.info.type : string())));
				}
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> stellar::finalize_transaction(warden::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() < 3)
					return layer_exception("invalid prepared abi");

				auto& input = prepared.inputs.front();
				auto& params = get_params();
				uint8_t decoded_public_key[256]; size_t decoded_public_key_size = sizeof(decoded_public_key);
				if (!decode_key(params.ed25519_public_key, input.utxo.link.public_key, decoded_public_key, &decoded_public_key_size))
					return layer_exception("input public key invalid");

				string memo;
				for (auto& item : prepared.outputs)
				{
					auto [address, tag] = address_util::decode_tag_address(item.link.address);
					if (tag.empty())
						continue;
					else if (!memo.empty())
						return layer_exception("too many memos");

					memo = std::move(tag);
				}

				auto memo_id = from_string<uint64_t>(memo);
				if (memo.size() > 28 || (!memo.empty() && !memo_id))
					return layer_exception("input memo invalid");

				auto passphrase = get_network_passphrase();
				StellarSignTx transaction = tx_create_transaction(input.utxo.link.address, passphrase, prepared.abi[0].as_uint64(), memo_id.or_else(0), !memo.empty(), (size_t)prepared.abi[1].as_uint32(), (size_t)prepared.abi[2].as_uint32(), get_base_stroop_fee());
				size_t abi_pointer = 3;
				vector<StellarCreateAccountOp> accounts;
				vector<StellarPaymentOp> payments;
				for (auto& item : prepared.outputs)
				{
					auto create_account_ptr = prepared.load_abi(&abi_pointer);
					auto token_code_ptr = prepared.load_abi(&abi_pointer);
					auto token_issuer_ptr = prepared.load_abi(&abi_pointer);
					auto token_type_ptr = prepared.load_abi(&abi_pointer);
					if (!create_account_ptr || !token_code_ptr || !token_issuer_ptr || !token_type_ptr)
						return layer_exception("invalid prepared abi");

					auto& value = item.tokens.empty() ? item.value : item.tokens.front().value;
					auto asset = item.tokens.empty() ? item.get_asset(native_asset) : item.tokens.front().get_asset(native_asset);
					auto contract_address = oracle::server_node::get()->get_contract_address(asset);
					if (create_account_ptr->as_boolean())
					{
						StellarCreateAccountOp account = tx_create_account_prepared(item.link.address, input.utxo.link.address, (uint64_t)to_stroop(value), !!contract_address);
						accounts.push_back(account);
						if (account.has_starting_balance)
							continue;
					}

					if (contract_address)
						payments.push_back(tx_create_payment_prepared(item.link.address, input.utxo.link.address, tx_create_token_asset_prepared(token_code_ptr->as_string(), token_issuer_ptr->as_string(), (asset_type)token_type_ptr->as_uint8()), (uint64_t)to_stroop(value)));
					else
						payments.push_back(tx_create_payment_prepared(item.link.address, input.utxo.link.address, tx_create_native_asset_prepared(), (uint64_t)to_stroop(value)));
				}

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
					result = warden::address_util::encode_tag_address(*result, public_key_hash.substr(32));
				return result;
			}
			expects_lr<string> stellar::decode_address(const std::string_view& address)
			{
				auto [base_address, tag] = warden::address_util::decode_tag_address(address);
				auto result = decode_public_key(base_address);
				if (result)
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
			const btc_chainparams_* stellar::get_chain()
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