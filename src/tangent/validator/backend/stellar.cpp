#include "stellar.h"
#include "../service/nss.h"
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
	namespace mediator
	{
		namespace backends
		{
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
				string hash = *crypto::hash_raw(digests::sha256(), data);
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

				string hash = *crypto::hash_raw(digests::sha256(), string((char*)tx.data(), tx.size()));
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

			string stellar::nd_call::get_ledger(uint64_t block_height)
			{
				return stringify::text("/ledgers/%" PRIu64, (uint64_t)block_height);
			}
			string stellar::nd_call::get_ledger_operations(uint64_t block_height)
			{
				return stringify::text("/ledgers/%" PRIu64 "/operations?include_failed=false", (uint64_t)block_height);
			}
			string stellar::nd_call::get_operations(const std::string_view& tx_id)
			{
				return stringify::text("/transactions/%.*s/operations?include_failed=false", (int)tx_id.size(), tx_id.data());
			}
			string stellar::nd_call::get_transactions(const std::string_view& tx_id)
			{
				return stringify::text("/transactions/%" PRIu64, (int)tx_id.size(), tx_id.data());
			}
			string stellar::nd_call::get_accounts(const std::string_view& address)
			{
				return stringify::text("/accounts/%" PRIu64, (int)address.size(), address.data());
			}
			string stellar::nd_call::get_assets(const std::string_view& issuer, const std::string_view& code)
			{
				return stringify::text("/assets?asset_isser=%.*s&asset_code=%" PRIu64, (int)issuer.size(), issuer.data(), (int)code.size(), code.data());
			}
			const char* stellar::nd_call::get_last_ledger()
			{
				return "/ledgers?order=desc&limit=1";
			}
			const char* stellar::nd_call::submit_transaction()
			{
				return "/transactions";
			}

			stellar::stellar(chain_config* new_config) noexcept : relay_backend()
			{
				if (new_config != nullptr)
					config = *new_config;

				netdata.composition = algorithm::composition::type::ED25519;
				netdata.routing = routing_policy::memo;
				netdata.sync_latency = 1;
				netdata.divisibility = decimal(10000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "sac";
				netdata.supports_bulk_transfer = true;
			}
			expects_promise_rt<stellar::asset_info> stellar::get_asset_info(const algorithm::asset_id& asset, const std::string_view& address, const std::string_view& code)
			{
				auto asset_data = coawait(execute_rest(asset, "GET", nd_call::get_assets(address, code), nullptr, cache_policy::persistent));
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
			expects_promise_rt<stellar::account_info> stellar::get_account_info(const algorithm::asset_id& asset, const std::string_view& address)
			{
				auto account_data = coawait(execute_rest(asset, "GET", nd_call::get_accounts(address), nullptr, cache_policy::lazy));
				if (!account_data)
					coreturn expects_rt<stellar::account_info>(std::move(account_data.error()));

				account_info info;
				info.sequence = account_data->get_var("sequence").get_integer();
				if (account_data->has("balances"))
				{
					for (auto& item : account_data->get("balances")->get_childs())
					{
						asset_balance balance;
						balance.info.type = item->get_var("asset_type").get_blob();
						balance.info.code = item->get_var("asset_code").get_blob();
						balance.info.issuer = item->get_var("asset_issuer").get_blob();
						balance.balance = item->get_var("balance").get_decimal();
						if (balance.info.code.empty())
						{
							balance.info.code = algorithm::asset::blockchain_of(asset);
							if (balance.info.type != "native")
								continue;
						}
						info.balances[balance.info.code] = balance;
					}
				}

				memory::release(*account_data);
				coreturn expects_rt<stellar::account_info>(std::move(info));
			}
			expects_promise_rt<string> stellar::get_transaction_memo(const algorithm::asset_id& asset, const std::string_view& tx_id)
			{
				auto tx_data = coawait(execute_rest(asset, "GET", nd_call::get_transactions(format::util::clear_0xhex(tx_id)), nullptr, cache_policy::shortened));
				if (!tx_data)
					coreturn expects_rt<string>(std::move(tx_data.error()));

				string memo = tx_data->get_var("memo").get_blob();
				if (memo.empty())
					coreturn expects_rt<string>(remote_exception("transaction memo not found"));

				coreturn expects_rt<string>(std::move(memo));
			}
			expects_promise_rt<bool> stellar::is_account_exists(const algorithm::asset_id& asset, const std::string_view& address)
			{
				auto account_data = coawait(execute_rest(asset, "GET", nd_call::get_accounts(address), nullptr, cache_policy::lazy));
				if (!account_data && (account_data.error().is_retry() || account_data.error().is_shutdown()))
					coreturn expects_rt<bool>(account_data.error());

				auto account = uptr<schema>(account_data.or_else(nullptr));
				coreturn expects_rt<bool>(account && account->has("account_id"));
			}
			expects_promise_rt<void> stellar::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				uptr<http::query> args = new http::query();
				args->object->set("tx", var::string(tx_data.data));

				const char* type = "application/x-www-form-urlencoded";
				string body = args->encode(type);
				auto hex_data = coawait(execute_http(asset, "POST", nd_call::submit_transaction(), type, body, cache_policy::greedy));
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
			expects_promise_rt<uint64_t> stellar::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto last_block_data = coawait(execute_rest(asset, "GET", nd_call::get_last_ledger(), nullptr, cache_policy::lazy));
				if (!last_block_data)
					coreturn expects_rt<uint64_t>(std::move(last_block_data.error()));

				uint64_t block_height = (uint64_t)last_block_data->fetch_var("_embedded.records.0.sequence").get_integer();
				memory::release(*last_block_data);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> stellar::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				auto block_data = coawait(execute_rest(asset, "GET", nd_call::get_ledger_operations(block_height), nullptr, cache_policy::shortened));
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
			expects_promise_rt<schema*> stellar::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				auto tx_data = coawait(execute_rest(asset, "GET", nd_call::get_operations(format::util::clear_0xhex(transaction_id)), nullptr, cache_policy::extended));
				coreturn tx_data;
			}
			expects_promise_rt<vector<incoming_transaction>> stellar::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* implementation = (backends::stellar*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("chain not found"));

				algorithm::asset_id token_asset = asset;
				string tx_hash = transaction_data->get_var("transaction_hash").get_blob();
				string tx_type = transaction_data->get_var("type").get_blob();
				decimal fee_value = implementation->from_stroop(implementation->get_base_stroop_fee());
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
						token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(asset), token, issuer);
						if (!nss::server_node::get()->enable_contract_address(token_asset, issuer))
							coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));
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

				auto discovery = find_checkpoint_addresses(asset, { from, to });
				if (!discovery || discovery->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				option<uint64_t> to_address_index = optional::none;
				auto from_address = discovery->find(from);
				auto to_address = discovery->find(to);
				if (to_address != discovery->end())
				{
					auto memo = coawait(get_transaction_memo(asset, tx_hash));
					if (memo && !memo->empty())
						to_address_index = from_string<uint64_t>(*memo).or_else(to_address->second);
					else
						to_address_index = to_address->second;
				}

				vector<incoming_transaction> transactions;
				if (fee_value + base_value > 0.0)
				{
					incoming_transaction tx;
					tx.set_transaction(algorithm::asset::base_id_of(asset), block_height, tx_hash, std::move(fee_value));
					tx.set_operations({ transferer(from, from_address != discovery->end() ? option<uint64_t>(from_address->second) : option<uint64_t>(optional::none), decimal(base_value)) }, { transferer(to, to_address_index ? option<uint64_t>(*to_address_index) : option<uint64_t>(optional::none), decimal(base_value)) });
					transactions.push_back(std::move(tx));
				}
				if (token_value.is_positive())
				{
					incoming_transaction tx;
					tx.set_transaction(token_asset, block_height, tx_hash, decimal::zero());
					tx.set_operations({ transferer(from, from_address != discovery->end() ? option<uint64_t>(from_address->second) : option<uint64_t>(optional::none), decimal(token_value)) }, { transferer(to, to_address_index ? option<uint64_t>(*to_address_index) : option<uint64_t>(optional::none), decimal(token_value)) });
					transactions.push_back(std::move(tx));
				}
				coreturn expects_rt<vector<incoming_transaction>>(std::move(transactions));
			}
			expects_promise_rt<base_fee> stellar::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				auto* implementation = (backends::stellar*)nss::server_node::get()->get_chain(asset);
				if (algorithm::asset::token_of(asset).empty())
					coreturn expects_rt<base_fee>(base_fee(implementation->from_stroop(implementation->get_base_stroop_fee() * to.size()), decimal(1.0)));

				uint64_t fee = implementation->get_base_stroop_fee() * to.size();
				for (auto& item : to)
				{
					auto status = coawait(is_account_exists(asset, item.address));
					if (!status)
						coreturn expects_rt<base_fee>(status.error());
					else if (!*status)
						fee += implementation->get_base_stroop_fee();
				}

				coreturn expects_rt<base_fee>(base_fee(implementation->from_stroop(fee), decimal(1.0)));
			}
			expects_promise_rt<decimal> stellar::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
			{
				auto* implementation = (backends::stellar*)nss::server_node::get()->get_chain(asset);
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

				auto account = coawait(get_account_info(asset, *address));
				if (!account)
					coreturn expects_rt<decimal>(std::move(account.error()));

				auto balance = account->balances.find(algorithm::asset::token_of(asset));
				if (balance == account->balances.end())
					coreturn expects_rt<decimal>(decimal::zero());

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				if (contract_address && balance->second.info.issuer != *contract_address)
					coreturn expects_rt<decimal>(decimal::zero());

				coreturn expects_rt<decimal>(balance->second.balance);
			}
			expects_promise_rt<outgoing_transaction> stellar::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> from_wallet = layer_exception();
				if (wallet.parent)
					from_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					from_wallet = *wallet.signing_child;
				if (!from_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("signing wallet not found"));

				auto account_info = coawait(get_account_info(asset, from_wallet->addresses.begin()->second));
				if (!account_info)
					coreturn expects_rt<outgoing_transaction>(std::move(account_info.error()));

				auto& params = get_params();
				uint8_t derived_public_key[256]; size_t derived_public_key_size = sizeof(derived_public_key);
				if (!decode_key(params.ed25519_public_key, from_wallet->verifying_key, derived_public_key, &derived_public_key_size))
					coreturn expects_rt<outgoing_transaction>(remote_exception("input private key invalid"));

				string memo;
				for (auto& item : to)
				{
					if (item.address_index)
					{
						if (memo.empty())
							memo = to_string(*item.address_index);
						else if (memo != to_string(*item.address_index))
							coreturn expects_rt<outgoing_transaction>(remote_exception("input memo invalid"));
					}
					else if (!memo.empty())
						coreturn expects_rt<outgoing_transaction>(remote_exception("input memo invalid"));
				}

				auto memo_id = from_string<uint64_t>(memo);
				if (memo.size() > 28 || (!memo.empty() && !memo_id))
					coreturn expects_rt<outgoing_transaction>(remote_exception("input memo invalid"));

				vector<StellarCreateAccountOp> accounts;
				accounts.reserve(to.size());

				vector<StellarPaymentOp> payments;
				payments.reserve(to.size());

				decimal total_value = 0.0;
				auto passphrase = get_network_passphrase();
				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				for (auto& item : to)
				{
					auto status = coawait(is_account_exists(asset, item.address));
					if (!status)
						coreturn expects_rt<outgoing_transaction>(status.error());

					total_value += item.value;
					if (!*status)
					{
						StellarCreateAccountOp account;
						memset(&account, 0, sizeof(account));
						strncpy(account.new_account, item.address.c_str(), std::min<size_t>(sizeof(account.new_account), item.address.size()));
						strncpy(account.source_account, from_wallet->addresses.begin()->second.c_str(), std::min<size_t>(sizeof(account.source_account), from_wallet->addresses.begin()->second.size()));
						account.has_new_account = true;
						account.has_source_account = true;
						account.has_starting_balance = !contract_address;
						account.starting_balance = account.has_starting_balance ? (uint64_t)to_stroop(item.value) : 0;
						accounts.push_back(account);
						if (account.has_starting_balance)
							continue;
					}

					StellarPaymentOp payment;
					memset(&payment, 0, sizeof(payment));
					strncpy(payment.destination_account, item.address.c_str(), std::min<size_t>(sizeof(payment.destination_account), item.address.size()));
					strncpy(payment.source_account, from_wallet->addresses.begin()->second.c_str(), std::min<size_t>(sizeof(payment.source_account), from_wallet->addresses.begin()->second.size()));
					payment.has_destination_account = true;
					payment.has_source_account = true;
					payment.has_amount = true;
					payment.amount = (uint64_t)to_stroop(item.value);
					payments.push_back(payment);
				}

				StellarSignTx transaction;
				memset(&transaction, 0, sizeof(transaction));
				strncpy(transaction.source_account, from_wallet->addresses.begin()->second.c_str(), std::min<size_t>(sizeof(transaction.source_account), from_wallet->addresses.begin()->second.size()));
				strncpy(transaction.network_passphrase, passphrase.c_str(), std::min<size_t>(sizeof(transaction.network_passphrase), passphrase.size()));
				transaction.has_source_account = true;
				transaction.has_network_passphrase = true;
				transaction.has_sequence_number = true;
				transaction.has_memo_type = true;
				transaction.has_num_operations = true;
				transaction.has_fee = true;
				transaction.sequence_number = account_info->sequence + 1;
				transaction.memo_type = memo.empty() ? 0 : 2;
				transaction.memo_id = memo_id.or_else(0);
				transaction.num_operations = (uint32_t)(accounts.size() + payments.size());
				transaction.fee = (uint32_t)(transaction.num_operations * get_base_stroop_fee());

				decimal fee_value = from_stroop(transaction.fee);
				if (contract_address)
				{
					auto native = account_info->balances.find(algorithm::asset::blockchain_of(asset));
					if (native == account_info->balances.end() || native->second.balance < fee_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (native != account_info->balances.end() ? native->second.balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}
				else
					total_value += fee_value;

				auto token = account_info->balances.find(contract_address ? algorithm::asset::token_of(asset) : algorithm::asset::blockchain_of(asset));
				if (token == account_info->balances.end() || token->second.balance < total_value)
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (token != account_info->balances.end() ? token->second.balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));

				StellarAssetType stellar_asset;
				memset(&stellar_asset, 0, sizeof(stellar_asset));
				if (contract_address)
				{
					strncpy(stellar_asset.code, token->second.info.code.c_str(), std::min<size_t>(sizeof(stellar_asset.code), token->second.info.code.size()));
					strncpy(stellar_asset.issuer, token->second.info.issuer.c_str(), std::min<size_t>(sizeof(stellar_asset.issuer), token->second.info.issuer.size()));
					if (token->second.info.type == "credit_alphanum4")
						stellar_asset.type = (uint32_t)asset_type::ASSET_TYPE_CREDIT_ALPHANUM4;
					else if (token->second.info.type == "credit_alphanum12")
						stellar_asset.type = (uint32_t)asset_type::ASSET_TYPE_CREDIT_ALPHANUM12;
					else
						coreturn expects_rt<outgoing_transaction>(remote_exception("standard not supported"));
					stellar_asset.has_code = true;
					stellar_asset.has_issuer = true;
					stellar_asset.has_type = true;
				}
				else
				{
					stellar_asset.type = (uint32_t)asset_type::ASSET_TYPE_NATIVE;
					stellar_asset.has_code = false;
					stellar_asset.has_issuer = false;
					stellar_asset.has_type = true;
				}

				for (auto& payment : payments)
					payment.asset = stellar_asset;

				string transaction_id;
				uint8_t signature[crypto_sign_BYTES];
				{
					uint8_t derived_private_key[64];
					if (!decode_private_key(from_wallet->signing_key.expose<KEY_LIMIT>().view, derived_private_key))
						coreturn expects_rt<outgoing_transaction>(remote_exception("private key invalid"));

					vector<uint8_t> raw_data = tx_data_from_signature(transaction, accounts, payments);
					ed25519_signature signature;
					ed25519_sign_ext((uint8_t*)&raw_data[0], raw_data.size(), derived_private_key, derived_private_key + 32, signature);
					if (crypto_sign_verify_detached(signature, (uint8_t*)&raw_data[0], raw_data.size(), derived_public_key) != 0)
						coreturn expects_rt<outgoing_transaction>(remote_exception("private key invalid"));

					transaction_id.assign((char*)raw_data.data(), raw_data.size());
					transaction_id = codec::hex_encode(transaction_id);
				}

				vector<StellarSignedTx> signatures;
				{
					StellarSignedTx sign;
					memset(&sign, 0, sizeof(sign));
					sign.signature.size = (pb_size_t)std::min<size_t>(sizeof(sign.signature.bytes), sizeof(signature));
					sign.public_key.size = (pb_size_t)std::min<size_t>(sizeof(sign.public_key.bytes), derived_public_key_size);
					memcpy(sign.signature.bytes, signature, sign.signature.size);
					memcpy(sign.public_key.bytes, derived_public_key, sign.public_key.size);
					sign.has_public_key = true;
					sign.has_signature = true;
					signatures.push_back(std::move(sign));
				}

				vector<uint8_t> raw_data = tx_data_from_envelope(transaction, signatures, accounts, payments);
				string transaction_data = codec::base64_encode(std::string_view((char*)raw_data.data(), raw_data.size()));
				if (transaction_id.empty() || transaction_data.empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

				decimal value = contract_address ? total_value : total_value - fee_value;
				incoming_transaction tx;
				tx.set_transaction(asset, 0, transaction_id, std::move(fee_value));
				tx.set_operations({ transferer(from_wallet->addresses.begin()->second, option<uint64_t>(from_wallet->address_index), std::move(value)) }, vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data)));
			}
			expects_lr<master_wallet> stellar::new_master_wallet(const std::string_view& seed)
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
			expects_lr<derived_signing_wallet> stellar::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
			{
				auto* chain = get_chain();
				char derived_private_key[256];
				{
					auto secret = wallet.signing_key.expose<KEY_LIMIT>();
					if (!hd_derive(chain, secret.view.data(), get_derivation(protocol::now().account.root_address_index).c_str(), derived_private_key, sizeof(derived_private_key)))
						return expects_lr<derived_signing_wallet>(layer_exception("input private key invalid"));
				}

				btc_hdnode node;
				if (!btc_hdnode_deserialize(derived_private_key, chain, &node))
					return expects_lr<derived_signing_wallet>(layer_exception("input private key invalid"));

				auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> stellar::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				uint8_t raw_private_key[64]; size_t raw_private_key_size = 0;
				if (signing_key.size() != 32 && signing_key.size() != 64)
				{
					auto data = signing_key.expose<KEY_LIMIT>();
					if (!decode_private_key(data.view, raw_private_key))
					{
						if (!decode_key(get_params().ed25519_secret_seed, data.view, raw_private_key, &raw_private_key_size) || raw_private_key_size != 32)
							return layer_exception("bad private key");
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
					secret_key = encode_key(get_params().ed25519_secret_seed, raw_private_key, raw_private_key_size);
				}
				else if (raw_private_key_size == 64)
					memcpy(private_key, raw_private_key, raw_private_key_size);

				uint8_t public_key[32];
				ed25519_publickey_ext(private_key, public_key);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_key, sizeof(public_key)));
				if (!derived)
					return derived.error();

				string derived_private_key = encode_private_key(private_key, sizeof(private_key));
				if (!secret_key.empty())
					derived_private_key.append(1, ':').append(secret_key);
				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
			}
			expects_lr<derived_verifying_wallet> stellar::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				string raw_public_key = string(verifying_key);
				if (raw_public_key.size() != 32)
				{
					uint8_t public_key[32]; size_t public_key_size = sizeof(public_key);
					if (!decode_key(get_params().ed25519_public_key, raw_public_key, public_key, &public_key_size) || public_key_size != sizeof(public_key))
						return layer_exception("invalid public key");

					raw_public_key = string((char*)public_key, sizeof(public_key));
				}

				string public_key = encode_key(get_params().ed25519_public_key, (uint8_t*)raw_public_key.data(), raw_public_key.size());
				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, public_key } }, optional::none, std::move(public_key)));
			}
			expects_lr<string> stellar::new_public_key_hash(const std::string_view& address)
			{
				uint8_t data[128]; size_t data_size = sizeof(data);
				if (!decode_key(get_params().ed25519_public_key, address, data, &data_size))
					return layer_exception("invalid address");

				return string((char*)data, sizeof(data));
			}
			expects_lr<string> stellar::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
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
			expects_lr<void> stellar::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				string signature_data = signature.size() == 64 ? string(signature) : codec::base64_decode(signature);
				if (signature_data.size() != 64)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				auto& params = get_params();
				uint8_t derived_public_key[256]; size_t derived_public_key_size = sizeof(derived_public_key);
				if (!decode_key(params.ed25519_public_key, verifying_wallet->verifying_key, derived_public_key, &derived_public_key_size))
					return layer_exception("public key invalid");

				if (crypto_sign_verify_detached((uint8_t*)signature_data.data(), (uint8_t*)message.data(), message.size(), derived_public_key) != 0)
					return layer_exception("signature verification failed with used public key");

				return expectation::met;
			}
			string stellar::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/148'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
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
						return "Standalone network ; february 2017";
					case network_type::testnet:
						return "Test SDF network ; september 2015";
					case network_type::mainnet:
						return "Public global stellar network ; september 2015";
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
			string stellar::encode_private_key(uint8_t* private_key, size_t private_key_size)
			{
				return codec::hex_encode(std::string_view((char*)private_key, private_key_size));
			}
			bool stellar::decode_key(uint8_t version, const std::string_view& data, uint8_t* out_value, size_t* out_size)
			{
				vector<uint8_t> key(base32_decoded_length(data.size()), 0);
				if (key.size() < 3 || *out_size < key.size() - 3)
					return false;

				*out_size = key.size();
				if (!decode_base32(data, &key[0], out_size))
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
			bool stellar::decode_base32(const std::string_view& data, uint8_t* out_value, size_t* out_size)
			{
				size_t expected_size = base32_decoded_length(data.size());
				if (*out_size < expected_size)
					return false;

				*out_size = expected_size;
				return base32_decode(data.data(), data.size(), out_value, *out_size, BASE32_ALPHABET_RFC4648) != nullptr;
			}
			bool stellar::decode_private_key(const std::string_view& data, uint8_t private_key[64])
			{
				auto slice = data.substr(0, data.find(':'));
				string result = codec::hex_decode(slice);
				if (result.size() != 64)
					return false;

				memcpy(private_key, result.data(), result.size());
				return true;
			}
			string stellar::encode_key(uint8_t version, const uint8_t* value, size_t size)
			{
				vector<uint8_t> key(1 + size + 2, version);
				memcpy(&key[1], value, sizeof(uint8_t) * size);

				uint16_t checksum = calculate_checksum(&key[0], size + 1);
				memcpy(&key[key.size() - 2], &checksum, sizeof(uint8_t) * 2);
				return encode_base32(&key[0], key.size());
			}
			string stellar::encode_base32(const uint8_t* value, size_t size)
			{
				size_t expected_size = std::max<size_t>(1, base32_encoded_length(size));
				string data(expected_size, '\0');
				if (!base32_encode(value, size, (char*)data.data(), data.size() + 1, BASE32_ALPHABET_RFC4648))
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