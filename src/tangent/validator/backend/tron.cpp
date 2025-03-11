#include "tron.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/chainparams.h"
#include "../internal/libbitcoin/ecc_key.h"
#include "../internal/libbitcoin/base58.h"
#include "../internal/libbitcoin/utils.h"
#include "../internal/libtron/TronInternal.pb.h"
extern "C"
{
#include "../../internal/secp256k1.h"
#include "../../internal/ecdsa.h"
}
#include <secp256k1_recovery.h>

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			const char* tron::trx_nd_call::broadcast_transaction()
			{
				return "/wallet/broadcasttransaction";
			}
			const char* tron::trx_nd_call::get_block()
			{
				return "/wallet/getblock";
			}

			tron::tron() noexcept : ethereum()
			{
				netdata.composition = algorithm::composition::type::SECP256K1;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 15;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "trc20";
				netdata.supports_bulk_transfer = false;
			}
			expects_promise_rt<tron::trx_tx_block_header_info> tron::get_block_header_for_tx(const algorithm::asset_id& asset)
			{
				schema* args = var::set::object();
				args->set("detail", var::boolean(false));

				auto block_data = coawait(execute_rest(asset, "POST", trx_nd_call::get_block(), args, cache_policy::lazy));
				if (!block_data)
					coreturn expects_rt<tron::trx_tx_block_header_info>(std::move(block_data.error()));

				trx_tx_block_header_info info;
				info.ref_block_bytes = uint128_t(block_data->fetch_var("block_header.raw_data.number").get_integer()).to_string(16);
				info.ref_block_bytes = info.ref_block_bytes.substr(info.ref_block_bytes.size() - 4);
				info.ref_block_hash = block_data->get_var("blockID").get_blob().substr(16, 16);
				info.timestamp = block_data->fetch_var("block_header.raw_data.timestamp").get_integer();
				info.expiration = info.timestamp + 60 * 1000;
				memory::release(*block_data);

				while (info.ref_block_bytes.size() < 4)
					info.ref_block_bytes.insert(info.ref_block_bytes.begin(), '0');

				coreturn expects_rt<tron::trx_tx_block_header_info>(std::move(info));
			}
			expects_lr<void> tron::verify_node_compatibility(server_relay* node)
			{
				if (!node->has_distinct_url(server_relay::transmit_type::JSONRPC))
					return layer_exception("trongrid jsonrpc node is required");

				if (!node->has_distinct_url(server_relay::transmit_type::HTTP))
					return layer_exception("trongrid rest node is required");

				return expectation::met;
			}
			expects_promise_rt<void> tron::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				auto hex_data = coawait(execute_http(asset, "POST", trx_nd_call::broadcast_transaction(), "application/json", tx_data.data, cache_policy::greedy));
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
			expects_promise_rt<decimal> tron::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
			{
				auto* implementation = (backends::tron*)nss::server_node::get()->get_chain(asset);
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

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal divisibility = implementation->netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(asset, implementation, *contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				const char* method = nullptr;
				schema* params = nullptr;
				if (contract_address)
				{
					method = nd_call::call();
					params = var::set::object();
					params->set("to", var::string(implementation->decode_non_eth_address(*contract_address)));
					params->set("data", var::string(implementation->generate_unchecked_address(backends::ethereum::sc_call::balance_of(implementation->decode_non_eth_address(*address)))));
				}
				else
				{
					method = nd_call::get_balance();
					params = var::set::string(implementation->decode_non_eth_address(*address));
				}

				schema_list map;
				map.emplace_back(params);
				map.emplace_back(var::set::string("latest"));

				auto confirmed_balance = coawait(execute_rpc(asset, method, std::move(map), cache_policy::lazy));
				if (!confirmed_balance)
					coreturn expects_rt<decimal>(std::move(confirmed_balance.error()));

				decimal balance = implementation->to_eth(implementation->hex_to_uint256(confirmed_balance->value.get_blob()), divisibility);
				memory::release(*confirmed_balance);
				coreturn expects_rt<decimal>(std::move(balance));
			}
			expects_promise_rt<outgoing_transaction> tron::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> from_wallet = layer_exception();
				if (wallet.parent)
					from_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					from_wallet = *wallet.signing_child;
				if (!from_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("signing wallet not found"));

				auto chain_id = coawait(get_chain_id(asset));
				if (!chain_id)
					coreturn expects_rt<outgoing_transaction>(std::move(chain_id.error()));

				auto& subject = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				decimal fee_value = fee.get_fee();
				decimal total_value = subject.value;
				if (contract_address)
				{
					auto balance = coawait(calculate_balance(algorithm::asset::base_id_of(asset), wallet, from_wallet->addresses.begin()->second));
					if (!balance || *balance < fee_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}
				else
					total_value += fee_value;

				auto balance = coawait(calculate_balance(asset, wallet, from_wallet->addresses.begin()->second));
				if (!balance || *balance < total_value)
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), total_value.to_string().c_str())));

				auto block_header = coawait(get_block_header_for_tx(asset));
				if (!block_header)
					coreturn expects_rt<outgoing_transaction>(std::move(block_header.error()));

				decimal divisibility = netdata.divisibility;
				if (contract_address)
				{
					auto contract_divisibility = coawait(get_contract_divisibility(asset, this, *contract_address));
					if (contract_divisibility)
						divisibility = *contract_divisibility;
				}

				uint8_t raw_private_key[256];
				auto private_key = from_wallet->signing_key.expose<KEY_LIMIT>();
				generate_private_key_data_from_private_key(private_key.view.data(), private_key.view.size(), raw_private_key);

				uint8_t raw_public_key[256];
				auto public_key = codec::hex_decode(from_wallet->verifying_key);
				memcpy(raw_public_key, public_key.data(), std::min(sizeof(raw_private_key), public_key.size()));

				::protocol::Transaction transaction;
				::protocol::Transaction_raw* raw_data = transaction.mutable_raw_data();
				raw_data->set_ref_block_bytes(copy<std::string>(codec::hex_decode(block_header->ref_block_bytes)));
				raw_data->set_ref_block_hash(copy<std::string>(codec::hex_decode(block_header->ref_block_hash)));
				raw_data->set_expiration(block_header->expiration);
				raw_data->set_timestamp(block_header->timestamp);

				if (contract_address)
				{
					::protocol::TriggerSmartContract transfer;
					transfer.set_data(copy<std::string>(ethereum::sc_call::transfer(decode_non_eth_address_pf(from_wallet->addresses.begin()->second), from_eth(subject.value, divisibility))));
					transfer.set_token_id(0);
					transfer.set_owner_address(copy<std::string>(codec::hex_decode(decode_non_eth_address_pf(from_wallet->addresses.begin()->second))));
					transfer.set_call_token_value((uint64_t)from_eth(subject.value, divisibility));
					transfer.set_call_value(0);
					transfer.set_contract_address(copy<std::string>(codec::hex_decode(decode_non_eth_address_pf(*contract_address))));

					::protocol::Transaction_Contract* contract = raw_data->add_contract();
					contract->set_type(::protocol::Transaction_Contract_ContractType_TriggerSmartContract);
					contract->mutable_parameter()->PackFrom(transfer);
				}
				else
				{
					::protocol::TransferContract transfer;
					transfer.set_owner_address(copy<std::string>(codec::hex_decode(decode_non_eth_address_pf(from_wallet->addresses.begin()->second))));
					transfer.set_to_address(copy<std::string>(codec::hex_decode(decode_non_eth_address_pf(subject.address))));
					transfer.set_amount((uint64_t)from_eth(subject.value, divisibility));

					::protocol::Transaction_Contract* contract = raw_data->add_contract();
					contract->set_type(::protocol::Transaction_Contract_ContractType_TransferContract);
					contract->mutable_parameter()->PackFrom(transfer);
				}

				string transaction_data = copy<string>(transaction.raw_data().SerializeAsString());
				string transaction_id = *crypto::hash_hex(digests::sha256(), transaction_data);
				string message = codec::hex_decode(transaction_id);

				uint8_t raw_signature[65];
				if (ecdsa_sign_digest(&secp256k1, raw_private_key, (uint8_t*)message.data(), raw_signature, raw_signature + 64, nullptr) != 0)
					coreturn expects_rt<outgoing_transaction>(remote_exception("input private key invalid"));

				if (raw_signature[64] > 0)
					raw_signature[64] = 0x1c;
				else
					raw_signature[64] = 0x1b;

				string signature = codec::hex_encode(std::string_view((char*)raw_signature, sizeof(raw_signature)));
				if (ecdsa_verify_digest(&secp256k1, raw_public_key, raw_signature, (uint8_t*)message.data()) != 0)
					coreturn expects_rt<outgoing_transaction>(remote_exception("input private key invalid"));

				uptr<schema> transaction_object = var::set::object();
				transaction_object->set("visible", var::boolean(false));
				transaction_object->set("txID", var::string(transaction_id));
				transaction_object->set("raw_data_hex", var::string(codec::hex_encode(transaction_data)));

				schema* raw_data_object = transaction_object->set("raw_data", var::set::object());
				schema* contract_object = raw_data_object->set("contract", var::set::array())->push(var::set::object());
				schema* parameter_object = contract_object->set("parameter", var::set::object());
				schema* value_object = parameter_object->set("value", var::set::object());
				parameter_object->set("type_url", var::string(copy<string>(raw_data->contract().at(0).parameter().type_url())));
				contract_object->set("type", var::string(copy<string>(::protocol::Transaction_Contract_ContractType_Name(raw_data->contract().at(0).type()))));

				if (contract_address)
				{
					::protocol::TriggerSmartContract contract;
					raw_data->contract().at(0).parameter().UnpackTo(&contract);
					value_object->set("data", var::string(codec::hex_encode(copy<string>(contract.data()))));
					if (contract.token_id() > 0)
						value_object->set("token_id", var::integer(contract.token_id()));
					value_object->set("owner_address", var::string(codec::hex_encode(copy<string>(contract.owner_address()))));
					if (contract.call_token_value() > 0)
						value_object->set("call_token_value", var::integer(contract.call_token_value()));
					if (contract.call_value() > 0)
						value_object->set("call_value", var::integer(contract.call_value()));
					value_object->set("contract_address", var::string(codec::hex_encode(copy<string>(contract.contract_address()))));
				}
				else
				{
					::protocol::TransferContract contract;
					raw_data->contract().at(0).parameter().UnpackTo(&contract);
					value_object->set("to_address", var::string(codec::hex_encode(copy<string>(contract.to_address()))));
					value_object->set("owner_address", var::string(codec::hex_encode(copy<string>(contract.owner_address()))));
					if (contract.amount() > 0)
						value_object->set("amount", var::integer(contract.amount()));
				}

				raw_data_object->set("ref_block_bytes", var::string(codec::hex_encode(copy<string>(raw_data->ref_block_bytes()))));
				raw_data_object->set("ref_block_hash", var::string(codec::hex_encode(copy<string>(raw_data->ref_block_hash()))));
				if (raw_data->ref_block_num() > 0)
					raw_data_object->set("ref_block_num", var::integer(raw_data->ref_block_num()));
				raw_data_object->set("expiration", var::integer(raw_data->expiration()));
				raw_data_object->set("timestamp", var::integer(raw_data->timestamp()));
				if (raw_data->fee_limit() > 0)
					raw_data_object->set("fee_limit", var::integer(raw_data->fee_limit()));

				schema* signature_object = transaction_object->set("signature", var::array());
				signature_object->push(var::string(signature));

				transaction_data = schema::to_json(*transaction_object);
				incoming_transaction tx;
				tx.set_transaction(asset, 0, transaction_id, std::move(fee_value));
				tx.set_operations({ transferer(from_wallet->addresses.begin()->second, option<uint64_t>(from_wallet->address_index), decimal(subject.value)) }, vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data)));
			}
			expects_lr<string> tron::new_public_key_hash(const std::string_view& address)
			{
				return ethereum::new_public_key_hash(decode_non_eth_address(address));
			}
			string tron::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/195'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			string tron::get_message_magic()
			{
				return "\x19TRON signed message:\n";
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

				return generate_pkh_address((char*)hash160 + prefix_size);
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
			void tron::generate_message_hash(const string& input, uint8_t output[32])
			{
				string header = get_message_magic();
				string payload = stringify::text("%s%i%s",
					header.c_str(),
					(int)input.size(),
					input.c_str());
				keccak_256((uint8_t*)payload.data(), payload.size(), output);
			}
			const btc_chainparams_* tron::get_chain()
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