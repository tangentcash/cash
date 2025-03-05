#include "bitcoin.h"
#include "../service/nss.h"
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
	namespace mediator
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
					*out_type = bitcoin::address_format::pay2_public_key_hash;
				}
				else if (type == 1)
				{
					*out_prefix_size = base58_prefix_size(chain->b58prefix_script_address);
					if (*out_prefix_size > 1)
						data.insert(data.begin(), 0);
					base58_prefix_dump(chain->b58prefix_script_address, &data[0]);
					*out_type = bitcoin::address_format::pay2_script_hash;
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

			bitcoin::sighash_context::~sighash_context()
			{
				for (auto& item : scripts.locking)
					cstr_free(item, true);

				for (auto& items : scripts.unlocking)
				{
					for (auto& item : items)
						cstr_free(item, true);
				}
			}

			bitcoin::bitcoin() noexcept : relay_backend_utxo()
			{
				btc_ecc_start();
				netdata.composition = algorithm::composition::type::SECP256K1;
				netdata.routing = routing_policy::UTXO;
				netdata.sync_latency = 2;
				netdata.divisibility = decimal(100000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer.clear();
				netdata.supports_bulk_transfer = true;
			}
			bitcoin::~bitcoin()
			{
				btc_ecc_stop();
			}
			expects_promise_rt<void> bitcoin::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				schema_list map;
				map.emplace_back(var::set::string(format::util::clear_0xhex(tx_data.data)));

				auto hex_data = coawait(execute_rpc(asset, nd_call::send_raw_transaction(), std::move(map), cache_policy::greedy));
				if (!hex_data)
				{
					auto message = hex_data.what();
					if (stringify::find(message, "-27").found || stringify::find(message, "Transaction already in").found)
						coreturn expects_rt<void>(expectation::met);

					coreturn expects_rt<void>(std::move(hex_data.error()));
				}

				memory::release(*hex_data);
				update_coins(asset, tx_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<uint64_t> bitcoin::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto block_count = coawait(execute_rpc(asset, nd_call::get_block_count(), { }, cache_policy::lazy));
				if (!block_count)
					coreturn expects_rt<uint64_t>(std::move(block_count.error()));

				uint64_t block_height = (uint64_t)block_count->value.get_integer();
				memory::release(*block_count);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> bitcoin::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				schema_list hash_map;
				hash_map.emplace_back(var::set::integer(block_height));

				auto block_id = coawait(execute_rpc(asset, nd_call::get_block_hash(), std::move(hash_map), cache_policy::shortened));
				if (!block_id)
					coreturn block_id;

				schema_list block_map;
				block_map.emplace_back(var::set::string(block_id->value.get_blob()));
				block_map.emplace_back(legacy.get_block ? var::set::boolean(true) : var::set::integer(2));
				if (block_hash != nullptr)
					*block_hash = block_id->value.get_blob();

				auto block_data = coawait(execute_rpc(asset, nd_call::get_block(), std::move(block_map), cache_policy::shortened));
				if (!block_data)
				{
					schema_list legacy_block_map;
					legacy_block_map.emplace_back(var::set::string(block_id->value.get_blob()));
					legacy_block_map.emplace_back(var::set::boolean(true));

					block_data = coawait(execute_rpc(asset, nd_call::get_block(), std::move(legacy_block_map), cache_policy::shortened));
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
			expects_promise_rt<schema*> bitcoin::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				schema_list transaction_map;
				transaction_map.emplace_back(var::set::string(format::util::clear_0xhex(transaction_id)));
				transaction_map.emplace_back(legacy.get_raw_transaction ? var::set::boolean(true) : var::set::integer(2));

				auto tx_data = coawait(execute_rpc(asset, nd_call::get_raw_transaction(), std::move(transaction_map), cache_policy::persistent));
				if (!tx_data)
				{
					schema_list legacy_transaction_map;
					legacy_transaction_map.emplace_back(var::set::string(format::util::clear_0xhex(transaction_id)));
					legacy_transaction_map.emplace_back(var::set::boolean(true));

					tx_data = coawait(execute_rpc(asset, nd_call::get_raw_transaction(), std::move(legacy_transaction_map), cache_policy::persistent));
					if (!tx_data)
						coreturn tx_data;
					else
						legacy.get_raw_transaction = 1;
				}

				coreturn tx_data;
			}
			expects_promise_rt<vector<incoming_transaction>> bitcoin::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				unordered_set<string> addresses;
				schema* tx_inputs = transaction_data->get("vin");
				if (tx_inputs != nullptr)
				{
					for (auto& input : tx_inputs->get_childs())
					{
						if (input->has("txid") && input->has("vout"))
						{
							auto output = get_coins(asset, input->get_var("txid").get_blob(), (uint32_t)input->get_var("vout").get_integer());
							if (output && !output->address.empty())
								addresses.insert(output->address);
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

				if (!find_checkpoint_addresses(asset, addresses))
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				if (tx_inputs != nullptr)
				{
					for (auto& input : tx_inputs->get_childs())
					{
						if (input->has("txid") && input->has("vout"))
						{
							auto output = coawait(get_transaction_output(asset, input->get_var("txid").get_blob(), (uint32_t)input->get_var("vout").get_integer()));
							if (output && !output->address.empty())
								addresses.insert(output->address);
						}
					}
				}

				auto discovery = find_checkpoint_addresses(asset, addresses);
				if (!discovery)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				incoming_transaction tx;
				tx.set_transaction(asset, block_height, transaction_data->get_var("txid").get_blob(), decimal::zero());

				bool is_coinbase = false;
				if (tx_inputs != nullptr)
				{
					tx.from.reserve(tx_inputs->get_childs().size());
					for (auto& input : tx_inputs->get_childs())
					{
						if (input->has("coinbase"))
						{
							is_coinbase = true;
							continue;
						}

						auto output = coawait(get_transaction_output(asset, input->get_var("txid").get_blob(), (uint32_t)input->get_var("vout").get_integer()));
						if (output)
						{
							remove_coins(asset, output->transaction_id, output->index);
							tx.from.emplace_back(output->address, option<uint64_t>(output->address_index), decimal(output->value));
							tx.fee += output->value;
						}
					}
				}

				if (tx_outputs != nullptr)
				{
					size_t output_index = 0;
					unordered_set<size_t> resets;
					tx.to.resize(tx_outputs->get_childs().size());
					for (auto& output : tx_outputs->get_childs())
					{
						coin_utxo new_output;
						new_output.transaction_id = tx.transaction_id;
						new_output.value = output->get_var("value").get_decimal();
						new_output.index = (uint32_t)(output->has("n") ? output->get_var("n").get_integer() : output_index);
						if (new_output.index > (uint32_t)tx.to.size())
							new_output.index = (uint32_t)output_index;

						bool is_allowed = true;
						auto receiver_addresses = get_output_addresses(output, &is_allowed);
						new_output.address = receiver_addresses.empty() ? string() : *receiver_addresses.begin();
						if (is_allowed)
						{
							auto it = discovery->find(new_output.address);
							if (it != discovery->end())
								new_output.address_index = it->second;
						}
						else
							resets.insert(new_output.index);

						if (new_output.address_index)
							add_coins(asset, new_output);

						tx.to[(size_t)new_output.index] = transferer(new_output.address, std::move(new_output.address_index), decimal(new_output.value));
						tx.fee -= new_output.value;
						++output_index;
					}

					for (auto& index : resets)
						tx.to[index].value = decimal::nan();

					for (auto it = tx.to.begin(); it != tx.to.end();)
					{
						if (it->value.is_nan())
							it = tx.to.erase(it);
						else
							++it;
					}
				}

				if (tx.fee.is_negative())
					tx.fee = 0.0;

				if (is_coinbase && !tx.to.empty())
					tx.from.emplace_back(string("null"), option<uint64_t>(optional::none), decimal(tx.to.front().value));

				coreturn expects_rt<vector<incoming_transaction>>({ std::move(tx) });
			}
			expects_promise_rt<base_fee> bitcoin::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				auto block_height = coawait(get_latest_block_height(asset));
				if (!block_height)
					coreturn expects_rt<base_fee>(std::move(block_height.error()));

				schema_list map;
				map.emplace_back(var::set::integer(*block_height));
				map.emplace_back(var::set::null());

				auto block_stats = coawait(execute_rpc(asset, nd_call::get_block_stats(), std::move(map), cache_policy::greedy));
				if (!block_stats)
					coreturn expects_rt<base_fee>(std::move(block_stats.error()));

				decimal fee_rate = block_stats->get_var("avgfeerate").get_decimal();
				size_t tx_size = (size_t)block_stats->get_var("avgtxsize").get_integer();

				const size_t expected_max_tx_size = 1000;
				tx_size = std::min<size_t>(expected_max_tx_size, (size_t)(std::ceil((double)tx_size / 100.0) * 100.0));
				coreturn expects_rt<base_fee>(base_fee(fee_rate / netdata.divisibility, decimal(tx_size)));
			}
			expects_promise_rt<coin_utxo> bitcoin::get_transaction_output(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
			{
				auto output = get_coins(asset, transaction_id, index);
				if (output)
					coreturn remote_exception(std::move(output.error().message()));

				auto tx_data = coawait(get_block_transaction(asset, 0, std::string_view(), transaction_id));
				if (!tx_data)
					coreturn expects_rt<coin_utxo>(std::move(tx_data.error()));

				if (!tx_data->has("vout"))
				{
					memory::release(*tx_data);
					coreturn expects_rt<coin_utxo>(remote_exception("transaction does not have any UTXO"));
				}

				auto* VOUT = tx_data->fetch("vout." + to_string(index));
				if (!VOUT)
				{
					memory::release(*tx_data);
					coreturn expects_rt<coin_utxo>(remote_exception("transaction does not have specified UTXO"));
				}

				coin_utxo input;
				input.transaction_id = transaction_id;
				input.value = VOUT->get_var("value").get_decimal();
				input.index = index;

				bool is_allowed = true;
				auto addresses = get_output_addresses(VOUT, &is_allowed);
				if (is_allowed && !addresses.empty())
				{
					input.address = *addresses.begin();
					auto discovery = find_checkpoint_addresses(asset, addresses);
					if (discovery && !discovery->empty())
						input.address_index = discovery->begin()->second;
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
									addresses.insert(format::util::encode_0xhex(public_key));
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
			expects_promise_rt<outgoing_transaction> bitcoin::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> change_wallet = layer_exception();
				if (wallet.parent)
					change_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					change_wallet = *wallet.signing_child;
				if (!change_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid output change address"));

				auto applied_fee = coawait(calculate_transaction_fee_from_fee_estimate(asset, wallet, to, fee, change_wallet->addresses.begin()->second));
				decimal fee_value = applied_fee ? applied_fee->get_fee() : fee.get_fee();
				decimal total_value = fee_value;
				for (auto& item : to)
					total_value += item.value;

				auto inputs = calculate_coins(asset, wallet, total_value, optional::none);
				decimal input_value = inputs ? get_coins_value(*inputs, optional::none) : 0.0;
				if (!inputs || inputs->empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), total_value.to_string().c_str())));

				vector<coin_utxo> outputs;
				outputs.reserve(to.size() + 1);
				for (auto& item : to)
					outputs.push_back(coin_utxo(string(), item.address, option<uint64_t>(item.address_index), decimal(item.value), (uint32_t)outputs.size()));

				decimal change_value = input_value - total_value;
				if (change_value.is_positive())
					outputs.push_back(coin_utxo(string(), change_wallet->addresses.begin()->second, option<uint64_t>(change_wallet->address_index), decimal(change_value), (uint32_t)outputs.size()));

				btc_tx* builder = btc_tx_new();
				for (auto& output : outputs)
				{
					auto status = add_transaction_output(builder, output.address, output.value);
					if (status)
					{
						btc_tx_free(builder);
						coreturn expects_rt<outgoing_transaction>(remote_exception(std::move((*status).message())));
					}
				}

				sighash_context context;
				for (auto& input : *inputs)
				{
					if (!input.address_index)
						coreturn expects_rt<outgoing_transaction>(remote_exception("address " + input.address + " cannot be used to sign the transaction (wallet not found)"));

					expects_lr<derived_signing_wallet> signing_wallet = layer_exception();
					if (wallet.parent)
						signing_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, *input.address_index);
					else if (wallet.signing_child)
						signing_wallet = *wallet.signing_child;
					if (!signing_wallet)
						coreturn expects_rt<outgoing_transaction>(remote_exception("address " + input.address + " cannot be used to sign the transaction (wallet not valid)"));

					auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
					auto status = add_transaction_input(builder, input, context, secret.view.data());
					if (status)
					{
						btc_tx_free(builder);
						coreturn expects_rt<outgoing_transaction>(std::move(remote_exception(std::move((*status).message()))));
					}
				}

				vector<transferer> from;
				for (auto& input : *inputs)
				{
					auto status = sign_transaction_input(builder, input, context, from.size());
					if (status)
					{
						btc_tx_free(builder);
						coreturn expects_rt<outgoing_transaction>(std::move(remote_exception(std::move((*status).message()))));
					}
					from.emplace_back(input.address, option<uint64_t>(input.address_index), decimal(input.value));
				}

				string transaction_data = serialize_transaction_data(builder);
				string transaction_id = serialize_transaction_id(builder);
				for (auto& output : outputs)
					output.transaction_id = transaction_id;

				btc_tx_free(builder);
				if (transaction_id.empty() || transaction_data.empty() || inputs->empty() || outputs.empty())
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

				incoming_transaction tx;
				tx.set_transaction(asset, 0, transaction_id, std::move(fee_value));
				tx.set_operations(std::move(from), vector<transferer>(to));
				coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data), std::move(*inputs), std::move(outputs)));
			}
			expects_lr<master_wallet> bitcoin::new_master_wallet(const std::string_view& seed)
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
			expects_lr<derived_signing_wallet> bitcoin::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
			{
				auto* chain = get_chain();
				char master_private_key[256];
				{
					auto secret = wallet.signing_key.expose<KEY_LIMIT>();
					if (!hd_derive(chain, secret.view.data(), get_derivation(address_index).c_str(), master_private_key, sizeof(master_private_key)))
						return expects_lr<derived_signing_wallet>(layer_exception("invalid private key"));
				}

				btc_hdnode node;
				if (!btc_hdnode_deserialize(master_private_key, chain, &node))
					return layer_exception("input address derivation invalid");

				auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> bitcoin::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				btc_key private_key;
				btc_privkey_init(&private_key);
				if (signing_key.size() != sizeof(private_key.privkey))
				{
					auto data = signing_key.expose<KEY_LIMIT>();
					if (!btc_privkey_decode_wif(data.view.data(), get_chain(), &private_key))
						return layer_exception("not a valid wif private key");
				}
				else
					memcpy(private_key.privkey, signing_key.expose<KEY_LIMIT>().buffer, sizeof(private_key.privkey));

				btc_pubkey public_key;
				btc_pubkey_from_key(&private_key, &public_key);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_key.pubkey, btc_pubkey_get_length(public_key.pubkey[0])));
				if (!derived)
					return derived.error();

				auto* chain = get_chain();
				char derived_private_key[256]; size_t derived_private_key_size = sizeof(derived_private_key);
				btc_privkey_encode_wif(&private_key, chain, derived_private_key, &derived_private_key_size);
				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
			}
			expects_lr<derived_verifying_wallet> bitcoin::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				auto* chain = get_chain();
				auto* options = nss::server_node::get()->get_specifications(asset);
				size_t types = (size_t)get_address_type();
				if (options != nullptr && options->value.is(var_type::array))
				{
					types = 0;
					for (auto& type : options->get_childs())
					{
						std::string_view name = type->value.get_string();
						if (name == "p2pk")
							types |= (size_t)address_format::pay2_public_key;
						else if (name == "p2sh_p2wpkh")
							types |= (size_t)address_format::pay2_script_hash;
						else if (name == "p2pkh")
							types |= (size_t)address_format::pay2_public_key_hash;
						else if (name == "p2wsh_p2pkh")
							types |= (size_t)address_format::pay2_witness_script_hash;
						else if (name == "p2wpkh")
							types |= (size_t)address_format::pay2_witness_public_key_hash;
						else if (name == "p2tr")
							types |= (size_t)address_format::pay2_taproot;
					}
				}

				address_map addresses;
				btc_pubkey public_key;
				btc_pubkey_init(&public_key);
				if (verifying_key.size() != BTC_ECKEY_COMPRESSED_LENGTH && verifying_key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
				{
					auto key = format::util::decode_0xhex(verifying_key);
					if (key.size() != BTC_ECKEY_COMPRESSED_LENGTH && key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
						return layer_exception("not a valid hex public key");

					memcpy(public_key.pubkey, key.data(), std::min(key.size(), sizeof(public_key.pubkey)));
				}
				else
					memcpy(public_key.pubkey, verifying_key.data(), std::min(verifying_key.size(), sizeof(public_key.pubkey)));
				public_key.compressed = btc_pubkey_get_length(public_key.pubkey[0]) == BTC_ECKEY_COMPRESSED_LENGTH;

				char derived_address[128];
				if (chain->bech32_cashaddr[0] == '\0')
				{
					if (types & (size_t)address_format::pay2_public_key && btc_pubkey_getaddr_p2pk(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_script_hash || types & (size_t)address_format::pay2_cashaddr_script_hash) && btc_pubkey_getaddr_p2sh_p2wpkh(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_public_key_hash || types & (size_t)address_format::pay2_cashaddr_public_key_hash) && btc_pubkey_getaddr_p2pkh(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if (false && (types & (size_t)address_format::pay2_tapscript) && btc_pubkey_getaddr_p2tr_p2pk(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_taproot) && btc_pubkey_getaddr_p2tr(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_witness_script_hash) && btc_pubkey_getaddr_p2wsh_p2pkh(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_witness_public_key_hash) && btc_pubkey_getaddr_p2wpkh(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;
				}
				else
				{
					if (types & (size_t)address_format::pay2_public_key && btc_pubkey_getaddr_p2pk(&public_key, chain, derived_address))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_script_hash || types & (size_t)address_format::pay2_cashaddr_script_hash) && bitcoin_cash_public_key_get_address_p2sh(&public_key, chain, derived_address, sizeof(derived_address)))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;

					if ((types & (size_t)address_format::pay2_public_key_hash || types & (size_t)address_format::pay2_cashaddr_public_key_hash) && bitcoin_cash_public_key_get_address_p2pkh(&public_key, chain, derived_address, sizeof(derived_address)))
						addresses[(uint8_t)addresses.size() + 1] = derived_address;
				}

				if (addresses.empty())
					return expects_lr<derived_verifying_wallet>(layer_exception("address generation not supported"));

				char derived_public_key[256]; size_t derived_public_key_size = sizeof(derived_public_key);
				btc_pubkey_get_hex(&public_key, derived_public_key, &derived_public_key_size);
				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet(std::move(addresses), optional::none, derived_public_key));
			}
			expects_lr<string> bitcoin::new_public_key_hash(const std::string_view& address)
			{
				uint8_t data[256]; size_t data_size = sizeof(data);
				if (parse_address(address, data, &data_size) == address_format::unknown)
					return layer_exception("invalid address");

				return string((char*)data, data_size);
			}
			expects_lr<string> bitcoin::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				btc_key private_key;
				auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
				if (btc_privkey_decode_wif(secret.view.data(), get_chain(), &private_key) != 1)
					return layer_exception("private key not valid");

				uint8_t hash[32];
				generate_message_hash(message, hash);

				uint8_t raw_signature[64]; size_t raw_signature_size = sizeof(raw_signature); int recovery_id = 0;
				if (btc_key_sign_hash_compact_recoverable(&private_key, hash, raw_signature, &raw_signature_size, &recovery_id) != 1)
					return layer_exception("private key not valid");

				uint8_t signature[65];
				memcpy(signature + 1, raw_signature, sizeof(raw_signature));
				signature[0] = recovery_id;
				return codec::base64_encode(std::string_view((char*)signature, sizeof(signature)));
			}
			expects_lr<void> bitcoin::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				string signature_data = signature.size() == 64 || signature.size() == 65 ? string(signature) : codec::base64_decode(signature);
				if (signature_data.size() != 64 && signature_data.size() != 65)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				uint8_t hash[32];
				generate_message_hash(message, hash);
				for (auto& item : verifying_wallet->addresses)
				{
					const auto& address = item.second;
					uint8_t target_program[256];
					size_t target_program_size = sizeof(target_program);
					if (parse_address(address, target_program, &target_program_size) == address_format::unknown)
						continue;

					for (int i = 0; i < 4; i++)
					{
						btc_pubkey public_key;
						if (btc_key_sign_recover_pubkey((uint8_t*)(signature_data.size() == 65 ? signature_data.data() + 1 : signature_data.data()), hash, i, &public_key) != 1)
							continue;

						if (!memcmp(public_key.pubkey, target_program, std::min(target_program_size, sizeof(public_key.pubkey))))
							return expectation::met;

						uint160 actual_program;
						btc_pubkey_get_hash160(&public_key, actual_program);
						if (memcmp(target_program, actual_program, std::min(target_program_size, sizeof(actual_program))) == 0)
							return expectation::met;

						char signer_address[256];
						if (btc_pubkey_getaddr_p2sh_p2wpkh(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (btc_pubkey_getaddr_p2pkh(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (btc_pubkey_getaddr_p2wsh_p2pkh(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (btc_pubkey_getaddr_p2wpkh(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (btc_pubkey_getaddr_p2tr_p2pk(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (btc_pubkey_getaddr_p2tr(&public_key, get_chain(), signer_address) && address == signer_address)
							return expectation::met;
						else if (bitcoin_cash_public_key_get_address_p2sh(&public_key, get_chain(), signer_address, sizeof(signer_address)) && address == signer_address)
							return expectation::met;
						else if (bitcoin_cash_public_key_get_address_p2pkh(&public_key, get_chain(), signer_address, sizeof(signer_address)) && address == signer_address)
							return expectation::met;
					}
				}

				return layer_exception("signature verification failed with used public key");
			}
			string bitcoin::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/0'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const bitcoin::chainparams& bitcoin::get_chainparams() const
			{
				return netdata;
			}
			expects_promise_rt<base_fee> bitcoin::calculate_transaction_fee_from_fee_estimate(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& estimate, const std::string_view& change_address)
			{
				decimal baseline_fee = estimate.get_fee();
				decimal sending_value = baseline_fee;
				for (auto& destination : to)
					sending_value += destination.value;

				auto inputs = calculate_coins(asset, wallet, sending_value, optional::none);
				decimal input_value = inputs ? get_coins_value(*inputs, optional::none) : 0.0;
				if (!inputs || inputs->empty())
					coreturn expects_rt<base_fee>(remote_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), sending_value.to_string().c_str())));

				vector<string> outputs = { string(change_address) };
				outputs.reserve(to.size() + 1);
				for (auto& item : to)
					outputs.push_back(item.address);

				bool has_witness = false;
				double virtual_size = 10;
				for (auto& input : *inputs)
				{
					switch (parse_address(input.address))
					{
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
							virtual_size += 57.25;
							has_witness = true;
							break;
						default:
							coreturn expects_rt<base_fee>(remote_exception("invalid input address"));
					}
				}

				for (auto& output : outputs)
				{
					switch (parse_address(output))
					{
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
							virtual_size += 43;
							break;
						default:
							coreturn expects_rt<base_fee>(remote_exception("invalid input address"));
					}
				}

				if (has_witness)
					virtual_size += 0.5 + (double)inputs->size() / 4.0;
				virtual_size = std::ceil(virtual_size);

				decimal fee_per_vbyte = estimate.price;
				if (estimate.limit <= 1.0)
					fee_per_vbyte /= decimal(virtual_size).truncate(protocol::now().message.precision);
				coreturn expects_rt<base_fee>(base_fee(fee_per_vbyte, virtual_size));
			}
			option<layer_exception> bitcoin::sign_transaction_input(btc_tx_* transaction, const coin_utxo& output, const sighash_context& context, size_t index)
			{
				if (index >= context.keys.size())
					return layer_exception("invalid sighash keys data");
				else if (index >= context.scripts.locking.size())
					return layer_exception("invalid sighash locking scripts data");
				else if (index >= context.scripts.unlocking.size())
					return layer_exception("invalid sighash unlocking scripts data");
				else if (index >= context.values.size())
					return layer_exception("invalid sighash values data");
				else if (index >= context.types.size())
					return layer_exception("invalid sighash types data");

				auto& key = context.keys[index];
				auto& unlocking_scripts = context.scripts.unlocking[index];
				auto type = (btc_tx_out_type)context.types[index];

				btc_key private_key;
				btc_privkey_init(&private_key);
				memcpy(private_key.privkey, key.data(), std::min(key.size(), sizeof(private_key)));

				auto status = btc_tx_sign_input(transaction, &private_key, get_sig_hash_type(), type, unlocking_scripts.data(), unlocking_scripts.size(), context.scripts.locking.data(), context.values.data(), (uint32_t)index, nullptr, nullptr);
				if (status != BTC_SIGN_OK)
					return layer_exception(btc_tx_sign_result_to_str(status));

				return optional::none;
			}
			option<layer_exception> bitcoin::add_transaction_input(btc_tx_* transaction, const coin_utxo& output, sighash_context& context, const char* private_key_wif)
			{
				btc_key private_key;
				if (btc_privkey_decode_wif(private_key_wif, get_chain(), &private_key) != 1)
					return layer_exception("input private key invalid");

				btc_pubkey public_key;
				btc_pubkey_init(&public_key);
				btc_pubkey_from_key(&private_key, &public_key);
				if (!btc_pubkey_is_valid(&public_key))
					return layer_exception("input public key invalid");

				btc_tx_out_type script_type = BTC_TX_INVALID;
				cstring* locking_script = cstr_new_sz(256), * unlocking_script = nullptr;
				uint8_t program[256]; size_t program_size = sizeof(program);
				switch (parse_address(output.address, program, &program_size))
				{
					case address_format::pay2_public_key:
						if (btc_script_build_p2pk(locking_script, program, program_size))
							script_type = BTC_TX_PUBKEY;
						break;
					case address_format::pay2_public_key_hash:
						if (btc_script_build_p2pkh(locking_script, program))
							script_type = BTC_TX_PUBKEYHASH;
						break;
					case address_format::pay2_script_hash:
					{
						program_size = sizeof(uint160);
						btc_pubkey_get_hash160(&public_key, program);
						if (btc_script_build_p2pkh(locking_script, program))
						{
							uint8_t version = 0;
							unlocking_script = cstr_new_sz(256);
							ser_varlen(unlocking_script, 22);
							ser_bytes(unlocking_script, &version, 1);
							ser_varlen(unlocking_script, 20);
							ser_bytes(unlocking_script, program, 20);
							script_type = BTC_TX_WITNESS_V0_PUBKEYHASH;
						}
						break;
					}
					case address_format::pay2_witness_script_hash:
					{
						program_size = sizeof(uint160);
						btc_pubkey_get_hash160(&public_key, program);
						if (btc_script_build_p2pkh(locking_script, program))
						{
							unlocking_script = cstr_new_cstr(locking_script);
							script_type = BTC_TX_WITNESS_V0_SCRIPTHASH;
						}
						break;
					}
					case address_format::pay2_witness_public_key_hash:
						if (btc_script_build_p2pkh(locking_script, program))
							script_type = BTC_TX_WITNESS_V0_PUBKEYHASH;
						break;
					case address_format::pay2_taproot:
					{
						uint8_t keypath_program[32];
						btc_pubkey_get_taproot_pubkey(&public_key, nullptr, keypath_program);
						if (!btc_script_build_p2tr(locking_script, program))
							break;

						if (program_size != sizeof(keypath_program) || memcmp(keypath_program, program, program_size) != 0)
						{
							if (false)
							{
								unlocking_script = cstr_new_sz(256);
								if (btc_script_build_p2pk(unlocking_script, keypath_program, sizeof(keypath_program)))
									script_type = BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH;
							}
						}
						else
							script_type = BTC_TX_WITNESS_V1_TAPROOT_KEYPATH;
						break;
					}
					default:
						break;
				}

				string raw_transaction_id = codec::hex_decode(output.transaction_id);
				std::reverse(raw_transaction_id.begin(), raw_transaction_id.end());

				context.scripts.unlocking.emplace_back();
				auto& unlocking_scripts = context.scripts.unlocking.back();
				if (unlocking_script != nullptr)
					unlocking_scripts.push_back(unlocking_script);

				context.scripts.locking.push_back(locking_script);
				context.keys.push_back(string((char*)private_key.privkey, sizeof(private_key.privkey)));
				context.values.push_back((uint64_t)to_baseline_value(output.value));
				context.types.push_back(script_type);

				btc_tx_in* input = btc_tx_in_new();
				memcpy(input->prevout.hash, raw_transaction_id.c_str(), sizeof(input->prevout.hash));
				input->script_sig = cstr_new_sz(128);
				input->prevout.n = output.index;
				vector_add(transaction->vin, input);
				return optional::none;
			}
			option<layer_exception> bitcoin::add_transaction_output(btc_tx_* transaction, const std::string_view& address, const decimal& value)
			{
				uint8_t program[256];
				size_t program_size = sizeof(program);

				bool script_exists = false;
				switch (parse_address(address, program, &program_size))
				{
					case address_format::pay2_public_key:
						script_exists = btc_tx_add_p2pk_out(transaction, (uint64_t)to_baseline_value(value), program, program_size);
						break;
					case address_format::pay2_public_key_hash:
						script_exists = btc_tx_add_p2pkh_hash160_out(transaction, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_script_hash:
						script_exists = btc_tx_add_p2sh_hash160_out(transaction, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_witness_script_hash:
						script_exists = btc_tx_add_p2wsh_hash256_out(transaction, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_witness_public_key_hash:
						script_exists = btc_tx_add_p2wpkh_hash160_out(transaction, (uint64_t)to_baseline_value(value), program);
						break;
					case address_format::pay2_tapscript:
					case address_format::pay2_taproot:
						script_exists = btc_tx_add_p2tr_hash256_out(transaction, (uint64_t)to_baseline_value(value), program);
						break;
					default:
						return layer_exception("output address type invalid");
				}

				if (!script_exists)
					return layer_exception("output address script type invalid");

				return optional::none;
			}
			string bitcoin::serialize_transaction_data(btc_tx_* transaction)
			{
				cstring* data = cstr_new_sz(1024);
				btc_tx_serialize(data, transaction, true);

				string hex_data(data->len * 2, '\0');
				utils_bin_to_hex((uint8_t*)data->str, data->len, (char*)hex_data.data());
				cstr_free(data, true);
				return hex_data;
			}
			string bitcoin::serialize_transaction_id(btc_tx_* transaction)
			{
				uint8_t hash[32];
				btc_tx_hash(transaction, hash);

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
						*data_size_out = std::min(data_size - prefix_size, *data_size_out);
						memcpy(data_out, data + prefix_size, *data_size_out);
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
			string bitcoin::get_message_magic()
			{
				return "Bitcoin signed message:\n";
			}
			void bitcoin::generate_message_hash(const std::string_view& input, uint8_t output[32])
			{
				string size(1, (char)input.size());
				if (input.size() > 253)
				{
					uint16_t size16 = os::hw::to_endianness(os::hw::endian::little, (uint16_t)input.size());
					size.append((char*)&size16, sizeof(size16));
				}

				string header = get_message_magic();
				string payload = stringify::text("%c%s%.*s%.*s", (char)header.size(), header.c_str(), (int)size.size(), size.c_str(), (int)input.size(), input.data());
				btc_hash((uint8_t*)payload.data(), payload.size(), output);
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