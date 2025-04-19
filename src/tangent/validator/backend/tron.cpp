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
			struct trx_transaction
			{
				string raw_transaction_id;
				uptr<schema> transaction_data;
			};

			static trx_transaction tx_serialize(const tron::trx_tx_block_header_info& block_header, const std::string_view& contract_address, const string& from_address, const string& to_address, const uint256_t& value)
			{
				::protocol::Transaction transaction;
				::protocol::Transaction_raw* raw_data = transaction.mutable_raw_data();
				raw_data->set_ref_block_bytes(copy<std::string>(codec::hex_decode(block_header.ref_block_bytes)));
				raw_data->set_ref_block_hash(copy<std::string>(codec::hex_decode(block_header.ref_block_hash)));
				raw_data->set_expiration(block_header.expiration);
				raw_data->set_timestamp(block_header.timestamp);
				raw_data->set_fee_limit(150000000);

				if (!contract_address.empty())
				{
					::protocol::TriggerSmartContract transfer;
					transfer.set_data(copy<std::string>(ethereum::sc_call::transfer(to_address, value)));
					transfer.set_token_id(0);
					transfer.set_owner_address(copy<std::string>(codec::hex_decode(from_address)));
					transfer.set_call_token_value(0);
					transfer.set_call_value(0);
					transfer.set_contract_address(copy<std::string>(codec::hex_decode(contract_address)));

					::protocol::Transaction_Contract* contract = raw_data->add_contract();
					contract->set_type(::protocol::Transaction_Contract_ContractType_TriggerSmartContract);
					contract->mutable_parameter()->PackFrom(transfer);
				}
				else
				{
					::protocol::TransferContract transfer;
					transfer.set_owner_address(copy<std::string>(codec::hex_decode(from_address)));
					transfer.set_to_address(copy<std::string>(codec::hex_decode(to_address)));
					transfer.set_amount((uint64_t)value);

					::protocol::Transaction_Contract* contract = raw_data->add_contract();
					contract->set_type(::protocol::Transaction_Contract_ContractType_TransferContract);
					contract->mutable_parameter()->PackFrom(transfer);
				}

				string raw_transaction_data = copy<string>(transaction.raw_data().SerializeAsString());
				string raw_transaction_id = *crypto::hash_raw(digests::sha256(), raw_transaction_data);
				uptr<schema> transaction_object = var::set::object();
				transaction_object->set("visible", var::boolean(false));
				transaction_object->set("txID", var::string(codec::hex_encode(raw_transaction_id)));
				transaction_object->set("raw_data_hex", var::string(codec::hex_encode(raw_transaction_data)));

				schema* raw_data_object = transaction_object->set("raw_data", var::set::object());
				schema* contract_object = raw_data_object->set("contract", var::set::array())->push(var::set::object());
				schema* parameter_object = contract_object->set("parameter", var::set::object());
				schema* value_object = parameter_object->set("value", var::set::object());
				parameter_object->set("type_url", var::string(copy<string>(raw_data->contract().at(0).parameter().type_url())));
				contract_object->set("type", var::string(copy<string>(::protocol::Transaction_Contract_ContractType_Name(raw_data->contract().at(0).type()))));

				if (!contract_address.empty())
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

				trx_transaction result;
				result.raw_transaction_id = std::move(raw_transaction_id);
				result.transaction_data = std::move(transaction_object);
				return result;
			}

			const char* tron::trx_nd_call::broadcast_transaction()
			{
				return "/wallet/broadcasttransaction";
			}
			const char* tron::trx_nd_call::get_block()
			{
				return "/wallet/getblock";
			}

			tron::tron(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
			{
				netdata.composition = algorithm::composition::type::secp256k1;
				netdata.routing = routing_policy::account;
				netdata.sync_latency = 15;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "trc20";
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

				trx_tx_block_header_info info;
				info.ref_block_bytes = ref_block_bytes.substr(ref_block_bytes.size() - 4);
				info.ref_block_hash = block_data->get_var("blockID").get_blob().substr(16, 16);
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
			expects_promise_rt<decimal> tron::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
			{
				auto contract_address = nss::server_node::get()->get_contract_address(for_asset);
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
					params->set("data", var::string(encode_0xhex(backends::ethereum::sc_call::balance_of(decode_non_eth_address(link.address)))));
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
			expects_promise_rt<computed_fee> tron::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				auto fee = coawait(ethereum::estimate_fee(from_address, to, options));
				if (fee)
					fee->gas.gas_limit *= 4;
				coreturn fee;
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
			expects_promise_rt<prepared_transaction> tron::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto chain_id = coawait(get_chain_id());
				if (!chain_id)
					coreturn expects_rt<prepared_transaction>(std::move(chain_id.error()));

				auto& output = to.front();
				auto contract_address = nss::server_node::get()->get_contract_address(output.asset);
				decimal fee_value = fee.get_max_fee();
				decimal total_value = output.value;
				if (contract_address)
				{
					auto balance = coawait(calculate_balance(output.asset, from_link));
					if (!balance || *balance < fee_value)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (balance ? *balance : decimal(0.0)).to_string().c_str(), fee_value.to_string().c_str())));
				}
				else
					total_value += fee_value;

				auto balance = coawait(calculate_balance(native_asset, from_link));
				if (!balance || *balance < total_value)
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
				auto transaction = tx_serialize(*block_header, eth_contract_address, eth_from_address, eth_to_address, eth_value);
				prepared_transaction result;
				if (contract_address)
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), public_key->data, (uint8_t*)transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size(), { { output.asset, output.value }, { native_asset, fee_value } });
				else
					result.requires_account_input(algorithm::composition::type::secp256k1, wallet_link(from_link), public_key->data, (uint8_t*)transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size(), { { native_asset, output.value + fee_value } });
				result.requires_account_output(output.address, { { output.asset, output.value } });
				result.requires_abi(format::variable(contract_address.or_else(string())));
				result.requires_abi(format::variable(block_header->ref_block_bytes));
				result.requires_abi(format::variable(block_header->ref_block_hash));
				result.requires_abi(format::variable((uint64_t)block_header->expiration));
				result.requires_abi(format::variable((uint64_t)block_header->timestamp));
				result.requires_abi(format::variable(divisibility));
				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> tron::finalize_transaction(mediator::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 6)
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
				auto eth_value = from_eth(output.tokens.empty() ? output.value : output.tokens.front().value, divisibility);
				auto transaction = tx_serialize(block_header, eth_contract_address, eth_from_address, eth_to_address, eth_value);
				if (input.message.size() != transaction.raw_transaction_id.size() || memcmp(input.message.data(), transaction.raw_transaction_id.data(), transaction.raw_transaction_id.size()))
					return layer_exception("invalid input message");

				uint8_t raw_signature[65];
				memcpy(raw_signature, input.signature, sizeof(raw_signature));
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