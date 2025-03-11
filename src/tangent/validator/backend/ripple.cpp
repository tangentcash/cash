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
	namespace mediator
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

				uint8_t public_key_hash[20];
				implementation->decode_public_key_hash(issuer, public_key_hash);
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
				uint8_t public_key[33] = { 0 };
				implementation->decode_public_key(data, public_key);
				tx_append_binary(tx, public_key, sizeof(public_key));
			}
			static void tx_append_address(vector<uint8_t>& tx, ripple* implementation, const std::string_view& data)
			{
				uint8_t public_key_hash[20] = { 0 };
				implementation->decode_public_key_hash(data, public_key_hash);
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
			const char* ripple::nd_call::transaction()
			{
				return "tx";
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

			ripple::ripple() noexcept : relay_backend()
			{
				netdata.composition = algorithm::composition::type::ED25519;
				netdata.routing = routing_policy::memo;
				netdata.sync_latency = 1;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "iou";
				netdata.supports_bulk_transfer = false;
			}
			expects_promise_rt<ripple::account_info> ripple::get_account_info(const algorithm::asset_id& asset, const std::string_view& address)
			{
				auto* implementation = (backends::ripple*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<ripple::account_info>(remote_exception("chain not found"));

				schema* params = var::set::object();
				params->set("account", var::string(address));
				params->set("ledger_index", var::string("current"));

				schema_list map;
				map.emplace_back(params);

				auto account_data = coawait(execute_rpc(asset, nd_call::account_info(), std::move(map), cache_policy::lazy));
				if (!account_data)
					coreturn expects_rt<ripple::account_info>(std::move(account_data.error()));

				account_info info;
				info.balance = implementation->from_drop(uint256_t(account_data->fetch_var("account_data.Balance").get_blob()));
				info.sequence = account_data->fetch_var("account_data.Sequence").get_integer();
				memory::release(*account_data);
				coreturn expects_rt<ripple::account_info>(std::move(info));
			}
			expects_promise_rt<ripple::account_token_info> ripple::get_account_token_info(const algorithm::asset_id& asset, const std::string_view& address)
			{
				account_token_info info;
				info.balance = 0.0;

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
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

					auto account_data = uptr<schema>(coawait(execute_rpc(asset, nd_call::account_objects(), std::move(map), cache_policy::lazy)));
					if (!account_data)
						break;

					auto* objects = account_data->get("account_objects");
					if (!objects || objects->empty())
						break;

					string issuer_checksum = contract_address->substr(contract_address->size() - 6);
					for (auto& object : objects->get_childs())
					{
						string token = object->fetch_var("Balance.currency").get_blob();
						if (token != algorithm::asset::token_of(asset))
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
			expects_promise_rt<ripple::ledger_sequence_info> ripple::get_ledger_sequence_info(const algorithm::asset_id& asset)
			{
				schema* params = var::set::object();
				params->set("ledger_index", var::string("validated"));

				schema_list map;
				map.emplace_back(params);

				auto block_data = coawait(execute_rpc(asset, nd_call::ledger(), std::move(map), cache_policy::lazy));
				if (!block_data)
					coreturn expects_rt<ripple::ledger_sequence_info>(block_data.error());

				ledger_sequence_info info;
				info.index = block_data->get_var("ledger_index").get_integer();
				info.sequence = info.index + 20;
				memory::release(*block_data);
				coreturn expects_rt<ripple::ledger_sequence_info>(std::move(info));
			}
			expects_promise_rt<void> ripple::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				schema* params = var::set::object();
				params->set("tx_blob", var::string(format::util::clear_0xhex(tx_data.data, true)));
				params->set("fail_hard", var::boolean(true));

				schema_list map;
				map.emplace_back(params);

				auto hex_data = coawait(execute_rpc(asset, nd_call::submit_transaction(), std::move(map), cache_policy::greedy));
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
			expects_promise_rt<uint64_t> ripple::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto ledger_sequence_info = coawait(get_ledger_sequence_info(asset));
				if (!ledger_sequence_info)
					coreturn expects_rt<uint64_t>(ledger_sequence_info.error());

				coreturn expects_rt<uint64_t>(ledger_sequence_info->index);
			}
			expects_promise_rt<schema*> ripple::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				schema* params = var::set::object();
				params->set("ledger_index", var::integer(block_height));
				params->set("transactions", var::boolean(true));
				params->set("expand", var::boolean(true));

				schema_list map;
				map.emplace_back(params);

				auto block_data = coawait(execute_rpc(asset, nd_call::ledger(), std::move(map), cache_policy::shortened));
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
			expects_promise_rt<schema*> ripple::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				schema* params = var::set::object();
				params->set("transaction", var::string(format::util::clear_0xhex(transaction_id, true)));
				params->set("binary", var::boolean(false));

				schema_list map;
				map.emplace_back(params);

				auto tx_data = coawait(execute_rpc(asset, nd_call::transaction(), std::move(map), cache_policy::extended));
				coreturn tx_data;
			}
			expects_promise_rt<vector<incoming_transaction>> ripple::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* implementation = (backends::ripple*)nss::server_node::get()->get_chain(asset);
				if (!implementation)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("chain not found"));

				string tx_hash = transaction_data->get_var("hash").get_blob();
				string type = transaction_data->get_var("TransactionType").get_blob();
				string from = transaction_data->get_var("Account").get_blob();
				string to = transaction_data->get_var("Destination").get_blob();
				decimal fee_value = implementation->from_drop(uint256_t(transaction_data->get_var("Fee").get_blob()));
				auto* amount = transaction_data->get("Amount");
				if (type != "Payment" || !amount)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				decimal base_value = 0.0, token_value = 0.0;
				algorithm::asset_id token_asset = asset;
				if (amount->value.is_object())
				{
					string token = amount->get_var("currency").get_blob();
					string issuer = amount->fetch_var("issuer").get_blob();
					token_value = amount->get_var("value").get_decimal();
					token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(asset), token, issuer);
					if (!nss::server_node::get()->enable_contract_address(token_asset, issuer))
						coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));
				}
				else
					base_value = implementation->from_drop(uint256_t(amount->value.get_blob()));

				auto discovery = find_checkpoint_addresses(asset, { from, to });
				if (!discovery || discovery->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				auto from_address = discovery->find(from);
				auto to_address = discovery->find(to);
				auto destination_tag = transaction_data->get_var("DestinationTag").get_blob();
				auto to_address_index = from_string<uint64_t>(destination_tag);
				if (!to_address_index && to_address != discovery->end())
					to_address_index = to_address->second;

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
			expects_promise_rt<base_fee> ripple::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				schema_list map;
				map.emplace_back(var::set::object());

				auto server_info = coawait(execute_rpc(asset, nd_call::server_info(), std::move(map), cache_policy::lazy));
				if (!server_info)
					coreturn expects_rt<base_fee>(std::move(server_info.error()));

				decimal base_constant_fee = server_info->fetch_var("info.validated_ledger.base_fee_xrp").get_decimal();
				if (!base_constant_fee.is_positive())
				{
					auto* implementation = (backends::ripple*)nss::server_node::get()->get_chain(asset);
					base_constant_fee = implementation->get_base_fee_xrp();
				}

				decimal load_factor = server_info->fetch_var("info.load_factor").get_decimal();
				if (!load_factor.is_positive())
					load_factor = 1.0;

				decimal fee_cushion = 1.2;
				memory::release(*server_info);
				coreturn expects_rt<base_fee>(base_fee(base_constant_fee * load_factor * fee_cushion, 1.0));
			}
			expects_promise_rt<decimal> ripple::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
			{
				auto* implementation = (backends::ripple*)nss::server_node::get()->get_chain(asset);
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

				if (!algorithm::asset::token_of(asset).empty())
				{
					auto account = coawait(get_account_token_info(asset, *address));
					if (!account)
						coreturn expects_rt<decimal>(std::move(account.error()));

					coreturn expects_rt<decimal>(std::move(account->balance));
				}
				else
				{
					auto account = coawait(get_account_info(asset, *address));
					if (!account)
						coreturn expects_rt<decimal>(std::move(account.error()));

					coreturn expects_rt<decimal>(std::move(account->balance));
				}
			}
			expects_promise_rt<outgoing_transaction> ripple::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
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

				auto ledger_info = coawait(get_ledger_sequence_info(asset));
				if (!ledger_info)
					coreturn expects_rt<outgoing_transaction>(std::move(ledger_info.error()));

				auto& subject = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal total_value = subject.value;
				decimal fee_value = fee.get_fee();
				if (contract_address)
				{
					auto account_token_info = coawait(get_account_token_info(asset, from_wallet->addresses.begin()->second));
					if (!account_token_info || account_token_info->balance < total_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (account_token_info ? account_token_info->balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));
					total_value = fee_value;
				}
				else
					total_value += fee_value;

				if (account_info->balance < total_value)
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", account_info->balance.to_string().c_str(), total_value.to_string().c_str())));

				transaction_buffer buffer;
				buffer.transaction_type = 0;
				buffer.flags = 0;
				buffer.sequence = (uint32_t)account_info->sequence;
				buffer.destination_tag = (uint32_t)subject.address_index.or_else(0);
				buffer.last_ledger_sequence = (uint32_t)ledger_info->sequence;
				if (contract_address)
				{
					buffer.amount.token_value = subject.value;
					buffer.amount.asset = algorithm::asset::token_of(asset);
					buffer.amount.issuer = *contract_address;
				}
				else
					buffer.amount.base_value = (uint64_t)to_drop(subject.value);
				buffer.fee = (uint64_t)to_drop(fee_value);
				buffer.signing_pub_key = from_wallet->verifying_key;
				buffer.account = from_wallet->addresses.begin()->first;
				buffer.destination = subject.address;
				if (!tx_sign_and_verify(&buffer, from_wallet->verifying_key, from_wallet->signing_key))
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid private key"));

				vector<uint8_t> raw_transaction_data = tx_serialize(&buffer, false);
				string transaction_data = codec::hex_encode(std::string_view((char*)&raw_transaction_data[0], raw_transaction_data.size()), true);
				string transaction_id = tx_hash(raw_transaction_data);
				if (transaction_id.empty() || transaction_data.empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

				incoming_transaction tx;
				tx.set_transaction(asset, 0, transaction_id, std::move(fee_value));
				tx.set_operations({ transferer(from_wallet->addresses.begin()->second, option<uint64_t>(from_wallet->address_index), decimal(subject.value)) }, vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data)));
			}
			expects_lr<master_wallet> ripple::new_master_wallet(const std::string_view& seed)
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
			expects_lr<derived_signing_wallet> ripple::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
			{
				auto* chain = get_chain();
				char derived_seed_key[256];
				{
					auto secret = wallet.signing_key.expose<KEY_LIMIT>();
					if (!hd_derive(chain, secret.view.data(), get_derivation(protocol::now().account.root_address_index).c_str(), derived_seed_key, sizeof(derived_seed_key)))
						return expects_lr<derived_signing_wallet>(layer_exception("private key invalid"));
				}

				btc_hdnode node;
				if (!btc_hdnode_deserialize(derived_seed_key, chain, &node))
					return expects_lr<derived_signing_wallet>(layer_exception("private key invalid"));

				auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> ripple::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				uint8_t raw_private_key[65]; size_t raw_private_key_size = 0;
				if (signing_key.size() != 16 && signing_key.size() != 32 && signing_key.size() != 33 && signing_key.size() != 64 && signing_key.size() != 65)
				{
					auto data = signing_key.expose<KEY_LIMIT>();
					if (!decode_private_key(data.view, raw_private_key))
					{
						if (!decode_secret_key(data.view, raw_private_key))
							return layer_exception("bad private key");

						raw_private_key_size = 16;
					}
					else
						raw_private_key_size = 65;
				}
				else
				{
					raw_private_key_size = signing_key.size();
					signing_key.stack((char*)raw_private_key, raw_private_key_size);
				}

				uint8_t private_key[65]; string secret_key;
				if (raw_private_key_size == 16)
				{
					secret_key = encode_secret_key(raw_private_key, raw_private_key_size);
					uint8_t intermediate_private_key[65];
					sha512_Raw(raw_private_key, raw_private_key_size, intermediate_private_key);
					sha512_Raw(intermediate_private_key, sizeof(intermediate_private_key) / 2, private_key + 1);
					algorithm::composition::convert_to_secret_key_ed25519(private_key + 1);
					secret_key = encode_secret_key(raw_private_key, raw_private_key_size);
				}
				else if (raw_private_key_size == 32 || raw_private_key_size == 33)
				{
					size_t offset = raw_private_key_size == 33 ? 1 : 0;
					uint8_t intermediate_private_key[65];
					auto raw_secret_key = *crypto::hash_raw(digests::shake128(), std::string_view((char*)raw_private_key, raw_private_key_size));
					sha512_Raw((uint8_t*)raw_secret_key.data() + offset, raw_secret_key.size() - offset, intermediate_private_key);
					sha512_Raw(intermediate_private_key, sizeof(intermediate_private_key) / 2, private_key + 1);
					algorithm::composition::convert_to_secret_key_ed25519(private_key + 1);
					secret_key = encode_secret_key((uint8_t*)raw_secret_key.data(), raw_secret_key.size());
				}
				else if (raw_private_key_size == 64 || raw_private_key_size == 65)
				{
					size_t offset = raw_private_key_size == 65 ? 1 : 0;
					memcpy(private_key + 1, raw_private_key + offset, raw_private_key_size - offset);
				}
				private_key[0] = 0xED;

				uint8_t public_key[32];
				ed25519_publickey_ext(private_key + 1, public_key);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_key, sizeof(public_key)));
				if (!derived)
					return derived.error();

				string derived_private_key = encode_private_key(private_key, sizeof(private_key));
				if (!secret_key.empty())
					derived_private_key.append(1, ':').append(secret_key);
				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
			}
			expects_lr<derived_verifying_wallet> ripple::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				string raw_public_key = string(verifying_key);
				if (raw_public_key.size() != 32 && raw_public_key.size() != 33)
				{
					uint8_t public_key[33];
					if (!decode_public_key(raw_public_key, public_key))
						return layer_exception("invalid public key");

					raw_public_key = string((char*)public_key, sizeof(public_key));
				}

				uint8_t public_key[33];
				size_t offset = raw_public_key.size() == 33 ? 1 : 0;
				memcpy(public_key + 1, raw_public_key.data() + offset, raw_public_key.size() - offset);
				public_key[0] = 0xED;

				string derived_public_key = encode_public_key(public_key, sizeof(public_key));
				string derived_address = encode_and_hash_public_key(public_key, sizeof(public_key));
				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, derived_address } }, optional::none, std::move(derived_public_key)));
			}
			expects_lr<string> ripple::new_public_key_hash(const std::string_view& address)
			{
				uint8_t data[20];
				if (!decode_public_key_hash(address, data))
					return layer_exception("invalid address");

				return string((char*)data, sizeof(data));
			}
			expects_lr<string> ripple::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				uint8_t private_key[65];
				auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
				if (!decode_private_key(secret.view.data(), private_key))
					return layer_exception("private key invalid");

				ed25519_signature signature;
				ed25519_sign_ext((uint8_t*)message.data(), message.size(), private_key + 1, private_key + 33, signature);
				return codec::base64_encode(std::string_view((char*)signature, sizeof(signature)));
			}
			expects_lr<void> ripple::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				string signature_data = signature.size() == 64 ? string(signature) : codec::base64_decode(signature);
				if (signature_data.size() != 64)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				uint8_t raw_public_key[33];
				if (!decode_public_key(verifying_wallet->verifying_key, raw_public_key))
					return layer_exception("public key invalid");

				if (crypto_sign_ed25519_verify_detached((uint8_t*)signature_data.data(), (uint8_t*)message.data(), message.size(), raw_public_key + 1) != 0)
					return layer_exception("signature verification failed with used public key");

				return expectation::met;
			}
			string ripple::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/144'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const ripple::chainparams& ripple::get_chainparams() const
			{
				return netdata;
			}
			bool ripple::tx_sign_and_verify(transaction_buffer* tx_data, const std::string_view& encoded_public_key, const secret_box& encoded_private_key)
			{
				uint8_t private_key[65];
				if (!decode_private_key(encoded_private_key.expose<KEY_LIMIT>().view, private_key))
					return false;

				uint8_t public_key[33];
				if (!decode_public_key(encoded_public_key, public_key))
					return false;

				vector<uint8_t> tx_blob = tx_serialize(tx_data, true);
				ed25519_signature signature;
				ed25519_sign_ext(tx_blob.data(), tx_blob.size(), private_key + 1, private_key + 33, signature);
				if (crypto_sign_ed25519_verify_detached(signature, tx_blob.data(), tx_blob.size(), public_key) != 0)
					return false;

				tx_data->txn_signature = codec::hex_encode(std::string_view((char*)signature, sizeof(signature)));
				return true;
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
			string ripple::encode_secret_key(uint8_t* secret_key, size_t secret_key_size)
			{
				char intermediate[256];
				size_t intermediate_size = sizeof(intermediate);
				uint8_t versions[3] = { 0x01, 0xe1, 0x4b };
				xb58check_enc(intermediate, &intermediate_size, versions, sizeof(versions), secret_key, secret_key_size);
				return string(intermediate);
			}
			string ripple::encode_private_key(uint8_t* private_key, size_t private_key_size)
			{
				return codec::hex_encode(std::string_view((char*)private_key, private_key_size));
			}
			string ripple::encode_public_key(uint8_t* public_key, size_t public_key_size)
			{
				return codec::hex_encode(std::string_view((char*)public_key, public_key_size));
			}
			string ripple::encode_and_hash_public_key(uint8_t* public_key, size_t public_key_size)
			{
				uint8_t public_key_hash256[32];
				sha256_Raw(public_key, public_key_size, public_key_hash256);

				uint160 public_key_hash160;
				btc_ripemd160(public_key_hash256, sizeof(public_key_hash256), public_key_hash160);

				char intermediate[256];
				size_t intermediate_size = sizeof(intermediate);
				uint8_t versions = 0x0;
				xb58check_enc(intermediate, &intermediate_size, &versions, sizeof(versions), public_key_hash160, sizeof(public_key_hash160));
				return string(intermediate);
			}
			bool ripple::decode_secret_key(const std::string_view& data, uint8_t secret_key[16])
			{
				uint8_t intermediate[128];
				size_t intermediate_size = sizeof(intermediate);
				if (!xb58check_dec(string(data).c_str(), intermediate, &intermediate_size))
					return false;

				if (intermediate_size != 19)
					return false;

				memcpy(secret_key, intermediate + 3, intermediate_size);
				return true;
			}
			bool ripple::decode_private_key(const std::string_view& data, uint8_t private_key[65])
			{
				auto slice = data.substr(0, data.find(':'));
				string result = codec::hex_decode(slice);
				if (result.size() != 65)
					return false;

				memcpy(private_key, result.data(), result.size());
				return true;
			}
			bool ripple::decode_public_key(const std::string_view& data, uint8_t public_key[33])
			{
				string result = codec::hex_decode(data);
				if (result.size() != 33)
					return false;

				memcpy(public_key, result.data(), result.size());
				return true;
			}
			bool ripple::decode_public_key_hash(const std::string_view& data, uint8_t public_key_hash[20])
			{
				uint8_t intermediate[128];
				size_t intermediate_size = sizeof(intermediate);
				if (!xb58check_dec(string(data).c_str(), intermediate, &intermediate_size))
					return false;

				if (intermediate_size != 21)
					return false;

				memcpy(public_key_hash, intermediate + 1, intermediate_size - 1);
				return true;
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
