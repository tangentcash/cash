#include "bitcoin.h"
#include "../service/oracle.h"
#include "../../policy/compositions.h"
#include "../internal/libbitcoincash/cashaddr.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/chainparams.h"
#include "../internal/libbitcoin/ecc.h"
#include "../internal/libbitcoin/bip32.h"
#include "../internal/libbitcoin/base58.h"
#include "../internal/libbitcoin/ripemd160.h"
#include "../internal/libbitcoin/utils.h"
#include "../internal/libbitcoin/serialize.h"
#undef min
extern "C"
{
#include "../../internal/segwit_addr.h"
}

namespace tangent
{
	namespace warden
	{
		namespace backends
		{
			static bool cash_address_from_legacy_hash(const btc_chainparams_* chain, const uint8_t* address_hash, size_t address_hash_size, char* out_address, size_t out_address_size)
			{
				uint8_t type = (base58_prefix_check(chain->b58prefix_pubkey_address, address_hash) ? 0 : 1);
				if (type == 1 && !base58_prefix_check(chain->b58prefix_script_address, address_hash))
					return false;

				std::vector<uint8_t> raw_hash;
				raw_hash.resize(sizeof(uint160));

				size_t offset = base58_prefix_size(type == 0 ? chain->b58prefix_pubkey_address : chain->b58prefix_script_address);
				memcpy(&raw_hash[0], address_hash + offset, std::min<size_t>(raw_hash.size(), address_hash_size));

				std::vector<uint8_t> hash = cashaddr::PackAddrData(raw_hash, type);
				if (hash.empty())
					return false;

				std::string cash_address = cashaddr::Encode(chain->bech32_cashaddr, hash);
				memcpy(out_address, cash_address.c_str(), std::min(cash_address.size() + 1, out_address_size));
				return true;
			}
			static bool legacy_hash_from_cash_address(const btc_chainparams_* chain, const std::string_view& address, uint8_t* out_address_hash, size_t* out_address_hash_size, size_t* out_prefix_size, bitcoin::address_format* out_type)
			{
				auto decoded_address = cashaddr::Decode(copy<std::string>(address), chain->bech32_cashaddr);
				auto& prefix = decoded_address.first;
				auto& hash = decoded_address.second;
				if (hash.empty() || prefix != chain->bech32_cashaddr)
					return false;

				vector<uint8_t> data;
				data.reserve(hash.size() * 5 / 8);
				if (!cashaddr::ConvertBits<5, 8, false>([&](uint8_t v) { data.push_back(v); }, std::begin(hash), std::end(hash)))
					return false;

				uint8_t version = data[0];
				if (version & 0x80)
					return false;

				uint32_t hash_size = 20 + 4 * (version & 0x03);
				if (version & 0x04)
					hash_size *= 2;

				if (data.size() != hash_size + 1)
					return false;

				uint8_t type = (version >> 3) & 0x1f;
				if (type == 0)
				{
					*out_prefix_size = base58_prefix_size(chain->b58prefix_pubkey_address);
					if (*out_prefix_size > 1)
						data.insert(data.begin(), 0);
					base58_prefix_dump(chain->b58prefix_pubkey_address, &data[0]);
					*out_type = bitcoin::address_format::pay2_cashaddr_public_key_hash;
				}
				else if (type == 1)
				{
					*out_prefix_size = base58_prefix_size(chain->b58prefix_script_address);
					if (*out_prefix_size > 1)
						data.insert(data.begin(), 0);
					base58_prefix_dump(chain->b58prefix_script_address, &data[0]);
					*out_type = bitcoin::address_format::pay2_cashaddr_script_hash;
				}
				else
					*out_type = bitcoin::address_format::unknown;

				memcpy(out_address_hash, data.data(), std::min(data.size(), *out_address_hash_size));
				*out_address_hash_size = data.size();
				return true;
			}
			static bool bitcoin_cash_public_key_get_address_p2pkh(const btc_pubkey* public_key, const btc_chainparams_* chain, char* address_out, size_t address_out_size)
			{
				if (chain->bech32_cashaddr[0] == '\0')
					return false;

				uint8_t public_key_hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t public_key_hash_offset;
				if (btc_pubkey_getaddr_p2pkh_hash(public_key, chain, public_key_hash, &public_key_hash_offset) != 1)
					return false;

				return cash_address_from_legacy_hash(chain, public_key_hash, sizeof(uint160) + public_key_hash_offset, address_out, address_out_size);
			}
			static bool bitcoin_cash_public_key_get_address_p2sh(const btc_pubkey* public_key, const btc_chainparams_* chain, char* address_out, size_t address_out_size)
			{
				if (chain->bech32_cashaddr[0] == '\0')
					return false;

				uint8_t script_hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t script_hash_offset;
				if (btc_pubkey_getaddr_p2sh_p2wpkh_hash(public_key, chain, script_hash, &script_hash_offset) != 1)
					return false;

				return cash_address_from_legacy_hash(chain, script_hash, sizeof(uint160) + script_hash_offset, address_out, address_out_size);
			}
			static size_t resolve_address_types(schema* options)
			{
				size_t types = 0;
				if (options != nullptr && options->value.is(var_type::array))
				{
					types = 0;
					for (auto& type : options->get_childs())
					{
						std::string_view name = type->value.get_string();
						if (name == "p2pk")
							types |= (size_t)bitcoin::address_format::pay2_public_key;
						else if (name == "p2sh_p2wpkh")
							types |= (size_t)bitcoin::address_format::pay2_script_hash;
						else if (name == "p2pkh")
							types |= (size_t)bitcoin::address_format::pay2_public_key_hash;
						else if (name == "p2wsh_p2pkh")
							types |= (size_t)bitcoin::address_format::pay2_witness_script_hash;
						else if (name == "p2wpkh")
							types |= (size_t)bitcoin::address_format::pay2_witness_public_key_hash;
						else if (name == "p2tr")
							types |= (size_t)bitcoin::address_format::pay2_taproot;
					}
				}
				return types;
			}

			const char* bitcoin::nd_call::get_block_count()
			{
				return "getblockcount";
			}
			const char* bitcoin::nd_call::get_block_hash()
			{
				return "getblockhash";
			}
			const char* bitcoin::nd_call::get_block_stats()
			{
				return "getblockstats";
			}
			const char* bitcoin::nd_call::get_block()
			{
				return "getblock";
			}
			const char* bitcoin::nd_call::get_raw_transaction()
			{
				return "getrawtransaction";
			}
			const char* bitcoin::nd_call::send_raw_transaction()
			{
				return "sendrawtransaction";
			}

			bitcoin::btc_tx_context::btc_tx_context() : state(btc_tx_new())
			{
			}
			bitcoin::btc_tx_context::~btc_tx_context()
			{
				if (state != nullptr)
					btc_tx_free(state);

				for (auto& item : scripts)
				{
					cstr_free(item.script, true);
					cstr_free(item.stack, true);
				}
			}
			bool bitcoin::btc_tx_context::is_in_range(size_t index) const
			{
				return index < scripts.size() && index < public_keys.size() && index < values.size() && index < types.size();
			}

			bitcoin::bitcoin(const algorithm::asset_id& new_asset) noexcept : relay_backend_utxo(new_asset)
			{
				btc_ecc_start();
				netdata.composition = algorithm::composition::type::secp256k1;
				netdata.routing = routing_policy::utxo;
				netdata.tokenization = token_policy::none;
				netdata.sync_latency = 6;
				netdata.divisibility = decimal(100000000).truncate(protocol::now().message.decimal_precision);
				netdata.supports_bulk_transfer = true;
				netdata.requires_transaction_expiration = false;
			}
			bitcoin::~bitcoin()
			{
				btc_ecc_stop();
			}
			expects_promise_rt<uint64_t> bitcoin::get_latest_block_height()
			{
				auto block_count = coawait(execute_rpc(nd_call::get_block_count(), { }, cache_policy::no_cache));
				if (!block_count)
					coreturn expects_rt<uint64_t>(std::move(block_count.error()));

				uint64_t block_height = (uint64_t)block_count->value.get_integer();
				memory::release(*block_count);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> bitcoin::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				schema_list hash_map;
				hash_map.emplace_back(var::set::integer(block_height));

				auto block_id = coawait(execute_rpc(nd_call::get_block_hash(), std::move(hash_map), cache_policy::blob_cache));
				if (!block_id)
					coreturn block_id;

				schema_list block_map;
				block_map.emplace_back(var::set::string(block_id->value.get_blob()));
				block_map.emplace_back(legacy.get_block ? var::set::boolean(true) : var::set::integer(2));
				if (block_hash != nullptr)
					*block_hash = block_id->value.get_blob();

				auto block_data = coawait(execute_rpc(nd_call::get_block(), std::move(block_map), cache_policy::temporary_cache));
				if (!block_data)
				{
					schema_list legacy_block_map;
					legacy_block_map.emplace_back(var::set::string(block_id->value.get_blob()));
					legacy_block_map.emplace_back(var::set::boolean(true));

					block_data = coawait(execute_rpc(nd_call::get_block(), std::move(legacy_block_map), cache_policy::temporary_cache));
					if (!block_data)
					{
						memory::release(*block_id);
						coreturn block_data;
					}
					else
						legacy.get_block = 1;
				}

				memory::release(*block_id);
				auto* transactions = block_data->get("tx");
				if (!transactions)
				{
					memory::release(*block_data);
					coreturn expects_rt<schema*>(remote_exception("tx field not found"));
				}

				transactions->unlink();
				memory::release(*block_data);
				coreturn expects_rt<schema*>(transactions);
			}
			expects_promise_rt<computed_transaction> bitcoin::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				unordered_set<string> addresses;
				schema* tx_inputs = transaction_data->get("vin");
				if (tx_inputs != nullptr)
				{
					for (auto& input : tx_inputs->get_childs())
					{
						if (input->has("txid") && input->has("vout"))
						{
							auto output = get_utxo(input->get_var("txid").get_blob(), (uint32_t)input->get_var("vout").get_integer());
							if (output && output->link.has_all())
								addresses.insert(output->link.address);
						}
					}
				}

				schema* tx_outputs = transaction_data->get("vout");
				if (tx_outputs != nullptr)
				{
					for (auto& output : tx_outputs->get_childs())
					{
						bool is_allowed = true;
						auto input = get_output_addresses(output, &is_allowed);
						if (is_allowed)
						{
							for (auto& address : input)
								addresses.insert(address);
						}
					}
				}

				if (!find_linked_addresses(addresses))
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				if (tx_inputs != nullptr)
				{
					for (auto& input : tx_inputs->get_childs())
					{
						if (input->has("txid") && input->has("vout"))
						{
							auto output = coawait(get_transaction_output(input->get_var("txid").get_blob(), input->get_var("vout").get_integer()));
							if (output && output->link.has_all())
								addresses.insert(output->link.address);
						}
					}
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				computed_transaction tx;
				tx.transaction_id = transaction_data->get_var("txid").get_blob();

				bool is_coinbase = false;
				if (tx_inputs != nullptr)
				{
					tx.inputs.reserve(tx_inputs->get_childs().size());
					for (auto& input : tx_inputs->get_childs())
					{
						if (!input->has("coinbase"))
						{
							auto output = coawait(get_transaction_output(input->get_var("txid").get_blob(), input->get_var("vout").get_integer()));
							if (output)
								tx.inputs.push_back(std::move(*output));
						}
						else
							is_coinbase = true;
					}
				}

				if (tx_outputs != nullptr)
				{
					size_t output_index = 0;
					unordered_set<size_t> resets;
					tx.outputs.resize(tx_outputs->get_childs().size());
					for (auto& output : tx_outputs->get_childs())
					{
						coin_utxo new_output;
						new_output.transaction_id = tx.transaction_id;
						new_output.value = output->get_var("value").get_decimal();
						new_output.index = (uint32_t)(output->has("n") ? output->get_var("n").get_integer() : output_index);
						if (new_output.index > (uint32_t)tx.outputs.size())
							new_output.index = (uint32_t)output_index;

						bool is_standard_output = true;
						auto receiver_addresses = get_output_addresses(output, &is_standard_output);
						new_output.link.address = receiver_addresses.empty() ? string() : *receiver_addresses.begin();
						if (is_standard_output)
						{
							auto it = discovery->find(new_output.link.address);
							if (it != discovery->end())
								new_output.link = std::move(it->second);
						}
						else
							resets.insert(new_output.index);

						tx.outputs[(size_t)new_output.index] = std::move(new_output);
						++output_index;
					}

					for (auto& index : resets)
						tx.outputs[index].value = decimal::nan();

					for (auto it = tx.outputs.begin(); it != tx.outputs.end();)
					{
						if (it->value.is_nan())
							it = tx.outputs.erase(it);
						else
							++it;
					}
				}

				if (is_coinbase && !tx.outputs.empty())
				{
					coin_utxo new_input;
					new_input.transaction_id = tx.transaction_id + "!";
					new_input.value = tx.outputs.front().value;
					new_input.index = (uint32_t)tx.inputs.size();
					tx.inputs.push_back(std::move(new_input));
				}

				coreturn expects_rt<computed_transaction>(std::move(tx));
			}
			expects_promise_rt<computed_fee> bitcoin::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				auto block_height = coawait(get_latest_block_height());
				if (!block_height)
					coreturn expects_rt<computed_fee>(std::move(block_height.error()));

				schema_list map;
				map.emplace_back(var::set::integer(*block_height));
				map.emplace_back(var::set::null());

				auto block_stats = coawait(execute_rpc(nd_call::get_block_stats(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!block_stats)
					coreturn expects_rt<computed_fee>(std::move(block_stats.error()));

				decimal fee_rate = block_stats->get_var("avgfeerate").get_decimal();
				size_t tx_size = (size_t)block_stats->get_var("avgtxsize").get_integer();

				const size_t expected_max_tx_size = 1000;
				tx_size = std::min<size_t>(expected_max_tx_size, (size_t)(std::ceil((double)tx_size / 100.0) * 100.0));
				coreturn expects_rt<computed_fee>(computed_fee::fee_per_byte(fee_rate / netdata.divisibility, tx_size));
			}
			expects_promise_rt<void> bitcoin::broadcast_transaction(const finalized_transaction& finalized)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::clear_0xhex(finalized.calldata)));

				auto hex_data = coawait(execute_rpc(nd_call::send_raw_transaction(), std::move(map), cache_policy::no_cache_no_throttling));
				if (!hex_data)
				{
					auto message = hex_data.what();
					if (stringify::find(message, "-27").found || stringify::find(message, "Transaction already in").found)
						coreturn expects_rt<void>(expectation::met);

					coreturn expects_rt<void>(std::move(hex_data.error()));
				}

				memory::release(*hex_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> bitcoin::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto applied_fee = calculate_transaction_fee_from_fee_estimate(from_link, to, fee);
				decimal fee_value = applied_fee ? applied_fee->get_max_fee() : fee.get_max_fee();
				decimal total_value = fee_value;
				for (auto& item : to)
					total_value += item.value;

				auto possible_inputs = calculate_utxo(from_link, balance_query(total_value, { }));
				decimal input_value = possible_inputs ? get_utxo_value(*possible_inputs, optional::none) : 0.0;
				if (!possible_inputs || possible_inputs->empty())
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), total_value.to_string().c_str())));

				prepared_transaction result;
				result.outputs.reserve(to.size() + 1);
				for (auto& item : to)
				{
					auto link = find_linked_addresses({ item.address });
					result.requires_output(coin_utxo(link ? std::move(link->begin()->second) : wallet_link::from_address(item.address), string(), (uint32_t)result.outputs.size(), decimal(item.value)));
				}
				if (input_value > total_value)
					result.requires_output(coin_utxo(wallet_link(possible_inputs->front().link), string(), (uint32_t)result.outputs.size(), decimal(input_value - total_value)));

				btc_tx_context context;
				for (auto& output : result.outputs)
				{
					auto status = add_transaction_output(context, output.link.address, output.value);
					if (!status)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(status.error().message())));
				}

				for (auto& input : *possible_inputs)
				{
					auto link = find_linked_addresses({ input.link.address });
					if (!link)
						coreturn expects_rt<prepared_transaction>(remote_exception("address " + input.link.address + " cannot be used to sign the transaction (wallet not valid)"));

					auto& ref = link->begin()->second;
					auto status = add_transaction_input(context, input, ref.public_key);
					if (!status)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(status.error().message())));
				}

				size_t index = 0;
				for (auto& input : *possible_inputs)
				{
					auto hash = prepare_transaction_input(context, input, index);
					if (!hash)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(hash.error().message())));

					auto signing_public_key = decode_public_key(input.link.public_key);
					if (!signing_public_key)
						coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

					switch ((btc_tx_out_type)context.types[index++])
					{
						case BTC_TX_WITNESS_V1_TAPROOT_KEYPATH:
						case BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH:
						{
							btc_pubkey pubkey;
							btc_pubkey_init(&pubkey);
							memcpy(&pubkey.pubkey, signing_public_key->data(), signing_public_key->size());
							pubkey.compressed = signing_public_key->size() == BTC_ECKEY_COMPRESSED_LENGTH;

							compositions::secp256k1_public_state::point_t public_key;
							btc_pubkey_get_taproot_pubkey(&pubkey, nullptr, public_key.data + 1);
							public_key.data[0] = pubkey.pubkey[0];

							compositions::secp256k1_secret_state::scalar_t tweak;
							btc_key_get_taproot_tweak(&pubkey, nullptr, tweak.data);

							auto xonly_public_key_and_tweak = compositions::secp256k1_schnorr_signature_state::to_tweaked_public_key(public_key, tweak);
							if (!xonly_public_key_and_tweak)
								coreturn expects_rt<prepared_transaction>(remote_exception(std::move(xonly_public_key_and_tweak.error().message())));

							result.requires_input(algorithm::composition::type::secp256k1_schnorr, *xonly_public_key_and_tweak, (uint8_t*)hash->data(), hash->size(), std::move(input));
							break;
						}
						default:
						{
							auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*signing_public_key);
							result.requires_input(algorithm::composition::type::secp256k1, public_key, (uint8_t*)hash->data(), hash->size(), std::move(input));
							break;
						}
					}
				}

				coreturn expects_rt<prepared_transaction>(std::move(result));
			}
			expects_lr<finalized_transaction> bitcoin::finalize_transaction(warden::prepared_transaction&& prepared)
			{
				btc_tx_context context;
				for (auto& output : prepared.outputs)
				{
					auto status = add_transaction_output(context, output.link.address, output.value);
					if (!status)
						return status.error();
				}

				for (auto& input : prepared.inputs)
				{
					auto link = find_linked_addresses({ input.utxo.link.address });
					if (!link)
						return layer_exception("input link not found");

					auto status = add_transaction_input(context, input.utxo, link->begin()->second.public_key);
					if (!status)
						return status.error();
				}

				size_t index = 0;
				for (auto& input : prepared.inputs)
				{
					auto hash = prepare_transaction_input(context, input.utxo, index);
					if (!hash)
						return hash.error();
					else if (input.message.size() != hash->size() || memcmp(input.message.data(), hash->data(), hash->size()) != 0)
						return layer_exception("invalid input message");

					auto finalization = finalize_transaction_input(context, input, index);
					if (!finalization)
						return finalization.error();
					++index;
				}

				auto result = finalized_transaction(std::move(prepared), serialize_transaction_data(context), serialize_transaction_id(context));
				if (!result.is_valid())
					return layer_exception("tx serialization error");

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<secret_box> bitcoin::encode_secret_key(const secret_box& secret_key)
			{
				btc_key private_key;
				btc_privkey_init(&private_key);
				if (secret_key.size() != sizeof(private_key.privkey))
					return layer_exception("not a valid raw private key");

				auto* chain = get_chain();
				char encoded_private_key[256]; size_t encoded_private_key_size = sizeof(encoded_private_key);
				btc_privkey_encode_wif(&private_key, chain, encoded_private_key, &encoded_private_key_size);
				return secret_box::secure(std::string_view(encoded_private_key, strnlen(encoded_private_key, encoded_private_key_size)));
			}
			expects_lr<secret_box> bitcoin::decode_secret_key(const secret_box& secret_key)
			{
				btc_key private_key;
				btc_privkey_init(&private_key);

				auto data = secret_key.expose<KEY_LIMIT>();
				if (!btc_privkey_decode_wif(data.view.data(), get_chain(), &private_key))
					return layer_exception("not a valid wif private key");

				return secret_box::secure(std::string_view((char*)private_key.privkey, sizeof(private_key.privkey)));
			}
			expects_lr<string> bitcoin::encode_public_key(const std::string_view& public_key)
			{
				return codec::hex_encode(public_key);
			}
			expects_lr<string> bitcoin::decode_public_key(const std::string_view& public_key)
			{
				auto result = codec::hex_decode(public_key);
				if (result.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && result.size() != BTC_ECKEY_COMPRESSED_LENGTH && result.size() != BTC_ECKEY_PKEY_LENGTH)
					return layer_exception("not a valid hex public key");

				return result;
			}
			expects_lr<string> bitcoin::encode_address(const std::string_view& public_key_hash)
			{
				auto* chain = get_chain();
				auto* options = oracle::server_node::get()->get_specifications(native_asset);
				auto type = public_key_hash[0];
				auto data = public_key_hash.substr(1);
				size_t types = (size_t)get_address_type() | resolve_address_types(options);
				switch (type)
				{
					case 0xF:
						if (!(types & (size_t)address_format::pay2_public_key))
							return layer_exception("p2pk address not supported");

						return codec::hex_encode(data);
					case 0xE:
					{
						if (!(types & (size_t)address_format::pay2_script_hash))
							return layer_exception("p2sh address not supported");

						uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
						size_t offset = base58_prefix_dump(chain->b58prefix_script_address, hash);
						memcpy(hash + offset, data.data(), std::min(sizeof(uint160), data.size()));

						char encoded_address[128];
						btc_base58_encode_check(hash, (int)(sizeof(uint160) + offset), encoded_address, (int)sizeof(encoded_address));
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0xD:
					{
						if (!(types & (size_t)address_format::pay2_public_key_hash))
							return layer_exception("p2pkh address not supported");

						uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
						size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash);
						memcpy(hash + offset, data.data(), std::min(sizeof(uint160), data.size()));

						char encoded_address[128];
						btc_base58_encode_check(hash, (int)(sizeof(uint160) + offset), encoded_address, (int)sizeof(encoded_address));
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0xC:
					{
						if (!(types & (size_t)address_format::pay2_witness_script_hash))
							return layer_exception("p2wsh address not supported");

						char encoded_address[128];
						segwit_addr_encode(encoded_address, chain->bech32_hrp, 0, (uint8_t*)data.data(), data.size());
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0xB:
					{
						if (!(types & (size_t)address_format::pay2_witness_public_key_hash))
							return layer_exception("p2wpkh address not supported");

						char encoded_address[128];
						segwit_addr_encode(encoded_address, chain->bech32_hrp, 0, (uint8_t*)data.data(), data.size());
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0xA:
					{
						if (!(types & (size_t)address_format::pay2_tapscript))
							return layer_exception("p2ts address not supported");

						char encoded_address[128];
						segwit_addr_encode(encoded_address, chain->bech32_hrp, 1, (uint8_t*)data.data(), data.size());
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0x9:
					{
						if (!(types & (size_t)address_format::pay2_taproot))
							return layer_exception("p2tr address not supported");

						char encoded_address[128];
						segwit_addr_encode(encoded_address, chain->bech32_hrp, 1, (uint8_t*)data.data(), data.size());
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0x8:
					{
						if (!(types & (size_t)address_format::pay2_cashaddr_script_hash))
							return layer_exception("p2cash address not supported");

						uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
						size_t offset = base58_prefix_dump(chain->b58prefix_script_address, hash);
						memcpy(hash + offset, data.data(), std::min(sizeof(uint160), data.size()));

						char encoded_address[128];
						cash_address_from_legacy_hash(chain, hash, sizeof(uint160) + offset, encoded_address, sizeof(encoded_address));
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					case 0x7:
					{
						if (!(types & (size_t)address_format::pay2_cashaddr_public_key_hash))
							return layer_exception("p2capkh address not supported");

						uint8_t hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
						size_t offset = base58_prefix_dump(chain->b58prefix_pubkey_address, hash);
						memcpy(hash + offset, data.data(), std::min(sizeof(uint160), data.size()));

						char encoded_address[128];
						cash_address_from_legacy_hash(chain, hash, sizeof(uint160) + offset, encoded_address, sizeof(encoded_address));
						return string(encoded_address, strnlen(encoded_address, sizeof(encoded_address)));
					}
					default:
						return layer_exception("address data is not valid");
				}
			}
			expects_lr<string> bitcoin::decode_address(const std::string_view& address)
			{
				auto* chain = get_chain();
				uint8_t data[256]; size_t data_size = sizeof(data) - 1;
				switch (parse_address(address, data + 1, &data_size))
				{
					case address_format::pay2_public_key:
						data[0] = 0xF;
						break;
					case address_format::pay2_script_hash:
						data[0] = 0xE;
						break;
					case address_format::pay2_public_key_hash:
						data[0] = 0xD;
						break;
					case address_format::pay2_witness_script_hash:
						data[0] = 0xC;
						break;
					case address_format::pay2_witness_public_key_hash:
						data[0] = 0xB;
						break;
					case address_format::pay2_tapscript:
						data[0] = 0xA;
						break;
					case address_format::pay2_taproot:
						data[0] = 0x9;
						break;
					case address_format::pay2_cashaddr_script_hash:
						data[0] = 0x8;
						break;
					case address_format::pay2_cashaddr_public_key_hash:
						data[0] = 0x7;
						break;
					default:
						return layer_exception("invalid address");
				}

				++data_size;
				return string((char*)data, data_size);
			}
			expects_lr<string> bitcoin::encode_transaction_id(const std::string_view& transaction_id)
			{
				return codec::hex_encode(transaction_id);
			}
			expects_lr<string> bitcoin::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = codec::hex_decode(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> bitcoin::to_addresses(const std::string_view& from_public_key)
			{
				auto* chain = get_chain();
				auto* options = oracle::server_node::get()->get_specifications(native_asset);
				bool is_taproot_public_key = false;
				size_t types = (size_t)get_address_type() | resolve_address_types(options);
				address_map addresses;
				btc_pubkey public_key;
				btc_pubkey_init(&public_key);
				if (from_public_key.size() != BTC_ECKEY_COMPRESSED_LENGTH && from_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
				{
					auto key = decode_public_key(from_public_key);
					if (!key || (key->size() != BTC_ECKEY_COMPRESSED_LENGTH && key->size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && key->size() != BTC_ECKEY_PKEY_LENGTH))
						return layer_exception("not a valid hex public key");

					memcpy(public_key.pubkey, key->data(), std::min(key->size(), sizeof(public_key.pubkey)));
					is_taproot_public_key = (key->size() == BTC_ECKEY_PKEY_LENGTH);
				}
				else
				{
					memcpy(public_key.pubkey, from_public_key.data(), std::min(from_public_key.size(), sizeof(public_key.pubkey)));
					is_taproot_public_key = (from_public_key.size() == BTC_ECKEY_PKEY_LENGTH);
				}
				public_key.compressed = btc_pubkey_get_length(public_key.pubkey[0]) == BTC_ECKEY_COMPRESSED_LENGTH;

				char encoded_address[256];
				if (!is_taproot_public_key)
				{
					if (chain->bech32_cashaddr[0] == '\0')
					{
						if (types & (size_t)address_format::pay2_public_key && btc_pubkey_getaddr_p2pk(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_script_hash || types & (size_t)address_format::pay2_cashaddr_script_hash) && btc_pubkey_getaddr_p2sh_p2wpkh(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_public_key_hash || types & (size_t)address_format::pay2_cashaddr_public_key_hash) && btc_pubkey_getaddr_p2pkh(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_taproot) && btc_pubkey_getaddr_p2tr(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_witness_script_hash) && btc_pubkey_getaddr_p2wsh_p2pkh(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_witness_public_key_hash) && btc_pubkey_getaddr_p2wpkh(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;
					}
					else
					{
						if (types & (size_t)address_format::pay2_public_key && btc_pubkey_getaddr_p2pk(&public_key, chain, encoded_address))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_script_hash || types & (size_t)address_format::pay2_cashaddr_script_hash) && bitcoin_cash_public_key_get_address_p2sh(&public_key, chain, encoded_address, sizeof(encoded_address)))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;

						if ((types & (size_t)address_format::pay2_public_key_hash || types & (size_t)address_format::pay2_cashaddr_public_key_hash) && bitcoin_cash_public_key_get_address_p2pkh(&public_key, chain, encoded_address, sizeof(encoded_address)))
							addresses[(uint8_t)addresses.size() + 1] = encoded_address;
					}
				}
				else if ((types & (size_t)address_format::pay2_taproot) && segwit_addr_encode(encoded_address, chain->bech32_hrp, 1, public_key.pubkey, sizeof(::uint256)) != 0)
					addresses[(uint8_t)addresses.size() + 1] = encoded_address;

				return addresses;
			}
			const bitcoin::chainparams& bitcoin::get_chainparams() const
			{
				return netdata;
			}
			expects_lr<computed_fee> bitcoin::calculate_transaction_fee_from_fee_estimate(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& estimate)
			{
				if (estimate.is_flat_fee())
					return expects_lr<computed_fee>(estimate);

				decimal baseline_fee = estimate.get_max_fee();
				decimal sending_value = baseline_fee;
				for (auto& destination : to)
					sending_value += destination.value;

				auto inputs = calculate_utxo(from_link, balance_query(sending_value, { }));
				decimal input_value = inputs ? get_utxo_value(*inputs, optional::none) : 0.0;
				if (!inputs || inputs->empty())
					return layer_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), sending_value.to_string().c_str()));

				vector<string> outputs = { inputs->front().link.address };
				outputs.reserve(to.size() + 1);
				for (auto& item : to)
					outputs.push_back(item.address);

				bool has_witness = false;
				double virtual_size = 10;
				for (auto& input : *inputs)
				{
					switch (parse_address(input.link.address))
					{
						case address_format::pay2_public_key:
							virtual_size += 152;
							break;
						case address_format::pay2_public_key_hash:
						case address_format::pay2_cashaddr_public_key_hash:
							virtual_size += 148;
							break;
						case address_format::pay2_script_hash:
						case address_format::pay2_cashaddr_script_hash:
							virtual_size = 153;
							break;
						case address_format::pay2_witness_public_key_hash:
						case address_format::pay2_witness_script_hash:
							virtual_size += 67.75;
							has_witness = true;
							break;
						case address_format::pay2_taproot:
						case address_format::pay2_tapscript:
							virtual_size += 57.25;
							has_witness = true;
							break;
						default:
							return layer_exception("invalid input address");
					}
				}

				for (auto& output : outputs)
				{
					switch (parse_address(output))
					{
						case address_format::pay2_public_key:
							virtual_size += 48;
							break;
						case address_format::pay2_public_key_hash:
						case address_format::pay2_cashaddr_public_key_hash:
							virtual_size += 32;
							break;
						case address_format::pay2_script_hash:
						case address_format::pay2_cashaddr_script_hash:
							virtual_size = 32;
							break;
						case address_format::pay2_witness_public_key_hash:
							virtual_size += 31;
							break;
						case address_format::pay2_witness_script_hash:
							virtual_size += 32;
							break;
						case address_format::pay2_taproot:
						case address_format::pay2_tapscript:
							virtual_size += 43;
							break;
						default:
							return layer_exception("invalid input address");
					}
				}

				if (has_witness)
					virtual_size += 0.5 + (double)inputs->size() / 4.0;

				virtual_size = std::ceil(virtual_size);
				return expects_lr<computed_fee>(computed_fee::fee_per_byte(to_value(estimate.fee.fee_rate), (size_t)virtual_size));
			}
			expects_lr<string> bitcoin::prepare_transaction_input(btc_tx_context& context, const coin_utxo& output, size_t index)
			{
				if (!context.is_in_range(index))
					return layer_exception("invalid context input index");

				vector<cstring*> scripts, stacks, redeems;
				for (auto& program : context.scripts)
				{
					scripts.push_back(program.script);
					stacks.push_back(program.stack);
					redeems.push_back(program.redeem);
				}

				btc_tx_witness_stack stack;
				stack.scripts = scripts.data();
				stack.stacks = stacks.data();
				stack.redeems = redeems.data();
				stack.amounts = context.values.data();

				::uint256 message_hash;
				auto type = (btc_tx_out_type)context.types[index];
				auto status = btc_tx_hash_input(context.state, get_sig_hash_type(), type, &stack, (uint32_t)index, message_hash);
				if (status != BTC_SIGN_HASH_OK)
					return layer_exception(btc_tx_sign_result_to_str(status));

				return string((char*)message_hash, sizeof(message_hash));
			}
			expects_lr<void> bitcoin::finalize_transaction_input(btc_tx_context& context, const prepared_transaction::signable_coin_utxo& output, size_t index)
			{
				if (!context.is_in_range(index))
					return layer_exception("invalid context input index");

				btc_pubkey public_key;
				btc_pubkey_init(&public_key);

				auto& key = context.public_keys[index];
				public_key.compressed = key.size() == BTC_ECKEY_COMPRESSED_LENGTH;
				memcpy(public_key.pubkey, key.data(), std::min(key.size(), sizeof(public_key.pubkey)));

				vector<cstring*> scripts, stacks, redeems;
				for (auto& program : context.scripts)
				{
					scripts.push_back(program.script);
					stacks.push_back(program.stack);
					redeems.push_back(program.redeem);
				}

				btc_tx_witness_stack stack;
				stack.scripts = scripts.data();
				stack.stacks = stacks.data();
				stack.redeems = redeems.data();
				stack.amounts = context.values.data();

				auto type = (btc_tx_out_type)context.types[index];
				auto status = btc_tx_finalize_input(context.state, output.signature.data(), output.signature.size(), &public_key, get_sig_hash_type(), type, &stack, (uint32_t)index);
				if (status != BTC_SIGN_FINALIZE_OK)
					return layer_exception(btc_tx_sign_result_to_str(status));

				return expectation::met;
			}
			expects_lr<void> bitcoin::add_transaction_input(btc_tx_context& context, const coin_utxo& output, const std::string_view& encoded_public_key)
			{
				btc_pubkey public_key;
				btc_pubkey_init(&public_key);

				string final_encoded_public_key = format::util::clear_0xhex(encoded_public_key);
				int public_key_size = (int)sizeof(public_key.pubkey);
				utils_hex_to_bin(final_encoded_public_key.data(), public_key.pubkey, (int)final_encoded_public_key.size(), &public_key_size);
				if (public_key_size != BTC_ECKEY_COMPRESSED_LENGTH && public_key_size != BTC_ECKEY_UNCOMPRESSED_LENGTH)
					return layer_exception("input public key invalid");

				public_key.compressed = public_key_size == BTC_ECKEY_COMPRESSED_LENGTH;
				if (!btc_pubkey_is_valid(&public_key))
					return layer_exception("input public key invalid");

				btc_tx_context::program program;
				btc_tx_out_type script_type = BTC_TX_INVALID;
				uint8_t data[256]; size_t data_size = sizeof(data);
				switch (parse_address(output.link.address, data, &data_size))
				{
					case address_format::pay2_public_key:
					{
						program.script = cstr_new_sz(256);
						if (btc_script_build_p2pk(program.script, data, data_size))
						{
							program.stack = cstr_new_cstr(program.script);
							script_type = BTC_TX_PUBKEY;
						}
						break;
					}
					case address_format::pay2_public_key_hash:
					case address_format::pay2_cashaddr_public_key_hash:
					{
						program.script = cstr_new_sz(256);
						if (btc_script_build_p2pkh(program.script, data))
						{
							program.stack = cstr_new_cstr(program.script);
							script_type = BTC_TX_PUBKEYHASH;
						}
						break;
					}
					case address_format::pay2_script_hash:
					case address_format::pay2_cashaddr_script_hash:
					{
						uint8_t public_key_hash[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
						btc_pubkey_get_hash160(&public_key, public_key_hash);

						size_t hash_offset = 0;
						program.script = cstr_new_sz(256);
						btc_pubkey_getaddr_p2sh_p2wpkh_hash(&public_key, get_chain(), public_key_hash, &hash_offset);
						if (btc_script_build_p2sh(program.script, public_key_hash + hash_offset))
						{
							program.stack = cstr_new_sz(256);
							btc_pubkey_get_hash160(&public_key, public_key_hash);
							if (btc_script_build_p2pkh(program.stack, public_key_hash))
							{
								uint8_t version = 0;
								program.redeem = cstr_new_sz(256);
								ser_varlen(program.redeem, 22);
								ser_bytes(program.redeem, &version, 1);
								ser_varlen(program.redeem, 20);
								ser_bytes(program.redeem, public_key_hash, 20);
								script_type = BTC_TX_WITNESS_V0_PUBKEYHASH;
							}
						}
						break;
					}
					case address_format::pay2_witness_script_hash:
					{
						::uint256 script_hash;
						btc_pubkey_getaddr_p2wsh_p2pkh_hash(&public_key, get_chain(), script_hash);

						program.script = cstr_new_sz(256);
						if (btc_script_build_p2wsh(program.script, script_hash))
						{
							uint160 public_key_hash;
							btc_pubkey_get_hash160(&public_key, public_key_hash);

							program.stack = cstr_new_sz(256);
							if (btc_script_build_p2pkh(program.stack, public_key_hash))
								script_type = BTC_TX_WITNESS_V0_SCRIPTHASH;
						}
						break;
					}
					case address_format::pay2_witness_public_key_hash:
					{
						program.script = cstr_new_sz(256);
						if (btc_script_build_p2wpkh(program.script, data))
						{
							program.stack = cstr_new_sz(256);
							if (btc_script_build_p2pkh(program.stack, data))
								script_type = BTC_TX_WITNESS_V0_PUBKEYHASH;
						}
						break;
					}
					case address_format::pay2_taproot:
					{
						uint8_t keypath[32];
						btc_pubkey_get_taproot_pubkey(&public_key, nullptr, keypath);
						
						program.script = cstr_new_sz(256);
						if (btc_script_build_p2tr(program.script, data))
						{
							if (data_size == sizeof(keypath) && !memcmp(keypath, data, data_size))
								script_type = BTC_TX_WITNESS_V1_TAPROOT_KEYPATH;
						}
						break;
					}
					default:
						break;
				}

				if (script_type == BTC_TX_INVALID)
					return layer_exception("invalid transaction input");
				
				string raw_transaction_id = codec::hex_decode(output.transaction_id);
				std::reverse(raw_transaction_id.begin(), raw_transaction_id.end());
				
				context.public_keys.push_back(string((char*)public_key.pubkey, (size_t)public_key_size));
				context.scripts.push_back(program);
				context.values.push_back((uint64_t)to_baseline_value(output.value));
				context.types.push_back(script_type);

				btc_tx_in* input = btc_tx_in_new();
				memcpy(input->prevout.hash, raw_transaction_id.c_str(), sizeof(input->prevout.hash));
				input->script_sig = cstr_new_sz(128);
				input->prevout.n = (uint32_t)output.index;
				vector_add(context.state->vin, input);
				return expectation::met;
			}
			expects_lr<void> bitcoin::add_transaction_output(btc_tx_context& context, const std::string_view& address, const decimal& value)
			{
				uint8_t program[256];
				size_t program_size = sizeof(program);

				bool script_exists = false;
				switch (parse_address(address, program, &program_size))
				{
					case address_format::pay2_public_key:
						script_exists = btc_tx_add_p2pk_out(context.state, (uint64_t)to_baseline_value(value), program, program_size);
						break;
					case address_format::pay2_public_key_hash:
					case address_format::pay2_cashaddr_public_key_hash:
						script_exists = btc_tx_add_p2pkh_hash160_out(context.state, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_script_hash:
					case address_format::pay2_cashaddr_script_hash:
						script_exists = btc_tx_add_p2sh_hash160_out(context.state, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_witness_script_hash:
						script_exists = btc_tx_add_p2wsh_hash256_out(context.state, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_witness_public_key_hash:
						script_exists = btc_tx_add_p2wpkh_hash160_out(context.state, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_tapscript:
					case address_format::pay2_taproot:
						script_exists = btc_tx_add_p2tr_hash256_out(context.state, (uint64_t)to_baseline_value(value), program);
						break;
					default:
						return layer_exception("output address type invalid");
				}

				if (!script_exists)
					return layer_exception("output address script type invalid");

				return expectation::met;
			}
			expects_promise_rt<coin_utxo> bitcoin::get_transaction_output(const std::string_view& transaction_id, uint64_t index)
			{
				auto output = get_utxo(transaction_id, index);
				if (output)
					coreturn expects_rt<coin_utxo>(std::move(*output));

				schema_list transaction_map;
				transaction_map.emplace_back(var::set::string(format::util::clear_0xhex(transaction_id)));
				transaction_map.emplace_back(legacy.get_raw_transaction ? var::set::boolean(true) : var::set::integer(2));

				auto tx_data = coawait(execute_rpc(nd_call::get_raw_transaction(), std::move(transaction_map), cache_policy::blob_cache));
				if (!tx_data)
				{
					schema_list legacy_transaction_map;
					legacy_transaction_map.emplace_back(var::set::string(format::util::clear_0xhex(transaction_id)));
					legacy_transaction_map.emplace_back(var::set::boolean(true));

					tx_data = coawait(execute_rpc(nd_call::get_raw_transaction(), std::move(legacy_transaction_map), cache_policy::blob_cache));
					if (!tx_data)
						coreturn expects_rt<coin_utxo>(std::move(tx_data.error()));
					else
						legacy.get_raw_transaction = 1;
				}

				if (!tx_data->has("vout"))
				{
					memory::release(*tx_data);
					coreturn expects_rt<coin_utxo>(remote_exception("transaction does not have any utxo"));
				}

				auto* vout = tx_data->fetch("vout." + to_string(index));
				if (!vout)
				{
					memory::release(*tx_data);
					coreturn expects_rt<coin_utxo>(remote_exception("transaction does not have specified utxo"));
				}

				coin_utxo input;
				input.transaction_id = transaction_id;
				input.value = vout->get_var("value").get_decimal();
				input.index = index;

				bool is_allowed = true;
				auto addresses = get_output_addresses(vout, &is_allowed);
				if (is_allowed && !addresses.empty())
				{
					auto discovery = find_linked_addresses(addresses);
					if (discovery && !discovery->empty())
						input.link = std::move(discovery->begin()->second);
					else
						input.link = wallet_link::from_address(*addresses.begin());
				}

				memory::release(*tx_data);
				coreturn expects_rt<coin_utxo>(std::move(input));
			}
			unordered_set<string> bitcoin::get_output_addresses(schema* tx_output, bool* is_allowed)
			{
				bool allowance = true;
				unordered_set<string> addresses;
				auto* script_pub_key = tx_output->get("scriptPubKey");
				if (script_pub_key != nullptr)
				{
					if (script_pub_key->has("address"))
					{
						string value = script_pub_key->get_var("address").get_blob();
						if (!value.empty())
							addresses.insert(value);
					}

					if (script_pub_key->has("addresses"))
					{
						for (auto& item : script_pub_key->get("addresses")->get_childs())
						{
							string value = item->value.get_blob();
							if (!value.empty())
								addresses.insert(value);
						}
					}

					if (script_pub_key->has("type"))
					{
						string type = script_pub_key->get_var("type").get_blob();
						if (type == "pubkey")
						{
							string raw = script_pub_key->get_var("asm").get_blob();
							size_t index = raw.find(' ');
							allowance = index != std::string::npos;
							if (allowance)
							{
								auto public_key = codec::hex_decode(raw.substr(0, index));
								allowance = public_key.size() == BTC_ECKEY_COMPRESSED_LENGTH || public_key.size() == BTC_ECKEY_UNCOMPRESSED_LENGTH;
								if (allowance)
									addresses.insert(codec::hex_encode(public_key));
							}
						}
						else if (type != "nulldata" && type != "pubkeyhash" && type != "scripthash" && type != "witness_v0_keyhash" && type != "witness_v0_scripthash" && type != "witness_v1_taproot")
							allowance = false;
					}
				}

				if (is_allowed)
					*is_allowed = allowance && !addresses.empty();

				return addresses;
			}
			string bitcoin::serialize_transaction_data(btc_tx_context& context)
			{
				cstring* data = cstr_new_sz(1024);
				btc_tx_serialize(data, context.state, true);

				string hex_data(data->len * 2, '\0');
				utils_bin_to_hex((uint8_t*)data->str, data->len, (char*)hex_data.data());
				cstr_free(data, true);
				return hex_data;
			}
			string bitcoin::serialize_transaction_id(btc_tx_context& context)
			{
				uint8_t hash[32];
				btc_tx_hash(context.state, hash);

				string intermediate = string((char*)hash, sizeof(hash));
				std::reverse(intermediate.begin(), intermediate.end());
				return codec::hex_encode(intermediate);
			}
			bitcoin::address_format bitcoin::parse_address(const std::string_view& address, uint8_t* data_out, size_t* data_size_out)
			{
				auto* chain = get_chain();
				if (address.empty())
					return address_format::unknown;

				uint8_t data[256]; size_t data_size = sizeof(data);
				if (chain->bech32_cashaddr[0] != '\0')
				{
					address_format type; size_t prefix_size;
					if (legacy_hash_from_cash_address(chain, address, data, &data_size, &prefix_size, &type))
					{
						if (data_out && data_size_out)
						{
							*data_size_out = std::min(data_size - prefix_size, *data_size_out);
							memcpy(data_out, data + prefix_size, *data_size_out);
						}
						return type;
					}
				}
				if (chain->bech32_hrp[0] == '\0' || stringify::starts_with(address, chain->bech32_hrp))
				{
					int32_t witness_version = 0;
					if (segwit_addr_decode(&witness_version, data, &data_size, chain->bech32_hrp, string(address).c_str()))
					{
						if (data_out && data_size_out)
						{
							*data_size_out = std::min(data_size, *data_size_out);
							memcpy(data_out, data, *data_size_out);
						}

						if (data_size == 32)
						{
							if (witness_version == 1)
								return address_format::pay2_taproot;

							return address_format::pay2_witness_script_hash;
						}
						else if (data_size == 20)
							return address_format::pay2_witness_public_key_hash;
					}
				}

				data_size = sizeof(uint8_t) * address.size() * 2;
				int new_size = btc_base58_decode_check(string(address).c_str(), data, data_size);
				if (!new_size)
				{
				try_public_key:
					if (!format::util::is_hex_encoding(address))
						return address_format::unknown;

					auto raw_public_key = codec::hex_decode(address);
					if (raw_public_key.size() != BTC_ECKEY_COMPRESSED_LENGTH && raw_public_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
						return address_format::unknown;

					btc_pubkey public_key;
					btc_pubkey_init(&public_key);
					memcpy(public_key.pubkey, raw_public_key.data(), raw_public_key.size());
					public_key.compressed = raw_public_key.size() == BTC_ECKEY_COMPRESSED_LENGTH;
					if (!btc_pubkey_is_valid(&public_key))
						return address_format::unknown;

					memcpy(data, raw_public_key.data(), raw_public_key.size());
					if (data_out && data_size_out)
					{
						*data_size_out = std::min(raw_public_key.size(), *data_size_out);
						memcpy(data_out, raw_public_key.data(), *data_size_out);
					}

					return address_format::pay2_public_key;
				}

				data_size = (size_t)(new_size - 4);
				if (base58_prefix_check(chain->b58prefix_pubkey_address, data))
				{
					size_t prefix_size = base58_prefix_size(chain->b58prefix_pubkey_address);
					if (data_size != sizeof(uint160) + prefix_size)
						goto try_public_key;

					if (data_out && data_size_out)
					{
						*data_size_out = std::min(data_size - prefix_size, *data_size_out);
						memcpy(data_out, data + prefix_size, *data_size_out);
					}

					return address_format::pay2_public_key_hash;
				}
				else if (base58_prefix_check(chain->b58prefix_script_address, data))
				{
					size_t prefix_size = base58_prefix_size(chain->b58prefix_script_address);
					if (data_size != sizeof(uint160) + prefix_size)
						goto try_public_key;

					if (data_out && data_size_out)
					{
						*data_size_out = std::min(data_size - prefix_size, *data_size_out);
						memcpy(data_out, data + prefix_size, *data_size_out);
					}

					return address_format::pay2_script_hash;
				}

				goto try_public_key;
			}
			const btc_chainparams_* bitcoin::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &btc_chainparams_regtest;
					case network_type::testnet:
						return &btc_chainparams_test;
					case network_type::mainnet:
						return &btc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			bitcoin::address_format bitcoin::get_address_type()
			{
				return (address_format)((size_t)address_format::pay2_public_key_hash | (size_t)address_format::pay2_witness_public_key_hash | (size_t)address_format::pay2_taproot);
			}
			uint32_t bitcoin::get_sig_hash_type()
			{
				return SIGHASH_ALL;
			}
		}
	}
}
