#include "cardano.h"
#include "../service/nss.h"
#include "../internal/libcardano/include/cardanoplusplus.h"
#include "../internal/libcardano/include/cardanoplusplus/hash/bech32.hpp"
extern "C"
{
#include "../../internal/ed25519.h"
#include "../../internal/sha2.h"
}

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			const char* cardano::nd_call::network_status()
			{
				return "/network/status";
			}
			const char* cardano::nd_call::block_data()
			{
				return "/block";
			}
			const char* cardano::nd_call::transaction_data()
			{
				return "/block/transaction";
			}
			const char* cardano::nd_call::submit_transaction()
			{
				return "submitTransaction";
			}

			cardano::cardano() noexcept : relay_backend_utxo()
			{
				netdata.composition = algorithm::composition::type::ED25519;
				netdata.routing = routing_policy::UTXO;
				netdata.sync_latency = 12;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "native";
				netdata.supports_bulk_transfer = true;
			}
			expects_promise_rt<void> cardano::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				schema* transaction = var::set::object();
				transaction->set("cbor", var::string(format::util::clear_0xhex(tx_data.data)));

				schema_args map;
				map["transaction"] = transaction;

				auto hex_data = coawait(execute_rpc3(asset, nd_call::submit_transaction(), std::move(map), cache_policy::lazy));
				if (!hex_data)
					coreturn expects_rt<void>(std::move(hex_data.error()));

				memory::release(*hex_data);
				update_coins(asset, tx_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<uint64_t> cardano::get_latest_block_height(const algorithm::asset_id& asset)
			{
				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));

				auto netstat = coawait(execute_rest(asset, "POST", nd_call::network_status(), args, cache_policy::lazy));
				if (!netstat)
					coreturn expects_rt<uint64_t>(netstat.error());

				uint64_t block_height = netstat->fetch_var("current_block_identifier.index").get_integer();
				memory::release(*netstat);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> cardano::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));
				schema* block_query = args->set("block_identifier", var::object());
				block_query->set("index", var::integer(block_height));

				auto block_data = coawait(execute_rest(asset, "POST", nd_call::block_data(), args, cache_policy::shortened));
				if (!block_data)
					coreturn expects_rt<schema*>(block_data.error());

				if (block_hash)
					*block_hash = block_data->fetch_var("block.block_identifier.hash").get_blob();

				auto* transactions = block_data->fetch("block.transactions");
				if (!transactions)
				{
					memory::release(*block_data);
					coreturn remote_exception("block.transactions field not found");
				}

				transactions->unlink();
				memory::release(*block_data);
				coreturn expects_rt<schema*>(transactions);
			}
			expects_promise_rt<schema*> cardano::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				string target_block_hash = format::util::clear_0xhex(block_hash);
				if (target_block_hash.empty())
				{
					auto transactions_data = coawait(get_block_transactions(asset, block_height, &target_block_hash));
					if (!transactions_data)
						coreturn expects_rt<schema*>(transactions_data.error());

					memory::release(*transactions_data);
				}

				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));
				schema* block_query = args->set("block_identifier", var::object());
				block_query->set("index", var::integer(block_height));
				block_query->set("hash", var::string(target_block_hash));
				schema* transaction_query = args->set("transaction_identifier", var::object());
				transaction_query->set("hash", var::string(format::util::clear_0xhex(transaction_id)));

				auto transaction_data = coawait(execute_rest(asset, "POST", nd_call::transaction_data(), args, cache_policy::shortened));
				if (!transaction_data)
					coreturn expects_rt<schema*>(transaction_data.error());

				auto* transaction_object = transaction_data->get("transaction");
				if (!transaction_object)
				{
					memory::release(*transaction_data);
					coreturn remote_exception("transaction field not found");
				}

				transaction_object->unlink();
				memory::release(*transaction_data);
				coreturn expects_rt<schema*>(transaction_object);
			}
			expects_promise_rt<vector<incoming_transaction>> cardano::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* base_implementation = (cardano*)nss::server_node::get()->get_chain(asset);
				if (!base_implementation)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("chain not found"));

				if (!transaction_data->value.is_object())
				{
					auto internal_info = uptr<schema>(coawait(get_block_transaction(asset, block_height, block_hash, transaction_data->value.get_blob())));
					if (!internal_info)
						coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not found"));

					transaction_data->value = internal_info->value;
					transaction_data->join(*internal_info, true);
				}


				auto* operations_data = transaction_data->get("operations");
				if (!operations_data || operations_data->empty())
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				unordered_set<string> addresses;
				for (auto& tx_operation : operations_data->get_childs())
				{
					string status = tx_operation->get_var("status").get_blob();
					if (status == "success")
						addresses.insert(tx_operation->fetch_var("account.address").get_blob());
				}

				auto discovery = find_checkpoint_addresses(asset, addresses);
				if (!discovery)
					coreturn expects_rt<vector<incoming_transaction>>(remote_exception("tx not involved"));

				incoming_transaction tx;
				tx.set_transaction(asset, block_height, transaction_data->fetch_var("transaction_identifier.hash").get_blob(), decimal::zero());

				decimal output_value = 0.0;
				decimal input_value = 0.0;
				for (auto& tx_operation : operations_data->get_childs())
				{
					string status = tx_operation->get_var("status").get_blob();
					if (status != "success")
						continue;

					auto identifier = stringify::split(tx_operation->fetch_var("coin_change.coin_identifier.identifier").get_blob(), ':');
					uint32_t index = from_string<uint32_t>(identifier.back()).or_else(0);
					string transaction_id = identifier.front();
					string symbol = tx_operation->fetch_var("amount.currency.symbol").get_blob();
					string address = tx_operation->fetch_var("account.address").get_blob();
					string type = tx_operation->get_var("type").get_blob();
					decimal value = math0::abs(tx_operation->fetch_var("amount.value").get_decimal()) / base_implementation->netdata.divisibility;
					if (type == "output")
					{
						auto target_address = discovery->find(address);
						if (target_address != discovery->end())
						{
							coin_utxo output;
							output.transaction_id = transaction_id;
							output.address = target_address->first;
							output.address_index = target_address->second;
							output.value = value;
							output.index = index;

							schema* token_bundle = tx_operation->fetch("metadata.tokenBundle");
							if (token_bundle != nullptr)
							{
								for (auto& token_operation : token_bundle->get_childs())
								{
									schema* tokens = token_operation->get("tokens");
									if (tokens != nullptr)
									{
										string contract_address = token_operation->get_var("policyId").get_blob();
										for (auto& item : tokens->get_childs())
										{
											string symbol = item->fetch_var("currency.symbol").get_blob();
											auto token_asset = algorithm::asset::id_of(algorithm::asset::blockchain_of(asset), symbol, contract_address);
											if (!nss::server_node::get()->enable_contract_address(token_asset, contract_address))
												continue;

											uint8_t decimals = (uint8_t)item->fetch_var("currency.decimals").get_integer();
											decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
											decimal token_value = math0::abs(item->get_var("value").get_decimal()) / divisibility.truncate(protocol::now().message.precision);
											output.apply_token_value(contract_address, symbol, token_value, decimals);
										}
									}
								}
							}

							add_coins(asset, output);
							tx.to.push_back(transferer(std::move(output.address), std::move(output.address_index), decimal(value)));
						}
						else
							tx.to.push_back(transferer(address, optional::none, decimal(value)));
						output_value += value;
					}
					else if (type == "input")
					{
						auto output = get_coins(asset, transaction_id, index);
						if (!output)
						{
							auto target_address = discovery->find(address);
							tx.from.push_back(transferer(address, target_address != discovery->end() ? option<uint64_t>(target_address->second) : option<uint64_t>(optional::none), decimal(value)));
						}
						else
						{
							tx.from.push_back(transferer(address, optional::none, decimal(value)));
							remove_coins(asset, output->transaction_id, output->index);
						}
						input_value += value;
					}
				}

				if (input_value > output_value)
					tx.fee = input_value - output_value;
				coreturn expects_rt<vector<incoming_transaction>>({ std::move(tx) });
			}
			expects_promise_rt<base_fee> cardano::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				auto* base_implementation = (backends::cardano*)nss::server_node::get()->get_chain(asset);
				if (!base_implementation)
					coreturn expects_rt<base_fee>(remote_exception("chain not found"));

				auto block_height = coawait(get_latest_block_height(asset));
				if (!block_height)
					coreturn expects_rt<base_fee>(std::move(block_height.error()));

				if (!tx_analytics.block_height || *block_height < tx_analytics.block_height || *block_height - tx_analytics.block_height > get_tx_fee_block_delta())
				{
					size_t offset = 0, count = 0;
					size_t max_count = std::min<size_t>(*block_height - tx_analytics.block_height, get_tx_fee_blocks());
					tx_analytics.block_height = *block_height;
					while (count < max_count)
					{
						auto transactions = uptr<schema>(coawait(get_block_transactions(asset, *block_height - (offset++), nullptr)));
						if (!transactions || transactions->empty())
							continue;

						++count;
						for (auto& tx_data : transactions->get_childs())
						{
							tx_analytics.total_size += (size_t)tx_data->fetch_var("metadata.size").get_integer();
							tx_analytics.transactions++;
						}
					}

					if (!tx_analytics.transactions)
						tx_analytics.transactions = 1;

					size_t bottom = tx_analytics.transactions * get_tx_fee_base_size();
					if (tx_analytics.total_size < bottom)
						tx_analytics.total_size = bottom;
				}

				decimal fee_rate_a = decimal(base_implementation->get_min_protocol_fee_a()) / base_implementation->netdata.divisibility;
				decimal fee_rate_b = decimal(base_implementation->get_min_protocol_fee_b()) / base_implementation->netdata.divisibility;
				size_t tx_size = (size_t)((double)tx_analytics.total_size / (double)tx_analytics.transactions);

				const uint64_t expected_max_tx_size = 1000;
				tx_size = std::min<size_t>(expected_max_tx_size, (size_t)(std::ceil((double)tx_size / 100.0) * 100.0));
				coreturn expects_rt<base_fee>(base_fee(fee_rate_a * decimal(tx_size) + fee_rate_b, 1.0));
			}
			expects_promise_rt<coin_utxo> cardano::get_transaction_output(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
			{
				auto result = get_coins(asset, transaction_id, index);
				if (!result)
					return expects_promise_rt<coin_utxo>(remote_exception(std::move(result.error().message())));

				return expects_promise_rt<coin_utxo>(std::move(*result));
			}
			expects_promise_rt<uint64_t> cardano::get_latest_block_slot(const algorithm::asset_id& asset)
			{
				auto block_height = coawait(cardano::get_latest_block_height(asset));
				if (!block_height)
					coreturn expects_rt<uint64_t>(block_height.error());

				auto block_data = coawait(cardano::get_block_transactions(asset, *block_height, nullptr));
				if (!block_data)
					coreturn expects_rt<uint64_t>(block_data.error());

				uint64_t block_slot = block_data->fetch_var("metadata.slotNo").get_integer();
				memory::release(*block_data);
				coreturn expects_rt<uint64_t>(block_slot);
			}
			expects_promise_rt<outgoing_transaction> cardano::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				expects_lr<derived_signing_wallet> change_wallet = layer_exception();
				if (wallet.parent)
					change_wallet = nss::server_node::get()->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				else if (wallet.signing_child)
					change_wallet = *wallet.signing_child;
				if (!change_wallet)
					coreturn expects_rt<outgoing_transaction>(remote_exception("invalid output change address"));

				auto block_slot = coawait(get_latest_block_slot(asset));
				if (!block_slot)
					coreturn expects_rt<outgoing_transaction>(remote_exception("latest block slot not found"));

				option<base_fee> actual_fee = optional::none;
				option<vector<coin_utxo>> inputs = optional::none;
				decimal fee_value = actual_fee ? actual_fee->get_fee() : fee.get_fee();
				decimal input_native_value = 0.0;
				decimal input_token_value = 0.0;
				decimal min_output_value = get_min_value_per_output();
			retry_with_actual_fee:
				decimal total_value = fee_value + min_output_value;
				decimal spending_value = 0.0;
				for (auto& item : to)
				{
					spending_value += item.value;
					if (item.value < min_output_value)
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (value is less than minimum required by protocol)", item.value.to_string().c_str(), min_output_value.to_string().c_str())));
				}

				auto contract_address = nss::server_node::get()->get_contract_address(asset);
				if (!contract_address)
					total_value += spending_value;

				if (!inputs || (actual_fee ? fee_value > actual_fee->get_fee() : true))
				{
					auto new_inputs = calculate_coins(asset, wallet, total_value, contract_address ? option<token_utxo>(token_utxo(*contract_address, spending_value)) : option<token_utxo>(optional::none));
					input_native_value = new_inputs ? get_coins_value(*new_inputs, optional::none) : 0.0;
					input_token_value = new_inputs && contract_address ? get_coins_value(*new_inputs, *contract_address) : 0.0;
					if (!new_inputs || new_inputs->empty())
						coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", (contract_address ? spending_value : total_value).to_string().c_str(), (contract_address ? input_token_value : input_native_value).to_string().c_str())));
					inputs = std::move(*new_inputs);
				}

				unordered_map<string, token_utxo> tokens;
				for (auto& item : *inputs)
				{
					for (auto& token : item.tokens)
					{
						auto& next = tokens[token.contract_address];
						if (next.is_coin_valid())
							next.value += token.value;
						else
							next = token;
					}
				}

				vector<coin_utxo> outputs;
				outputs.reserve(to.size() + 1);
				for (auto& item : to)
				{
					auto output = coin_utxo(string(), item.address, option<uint64_t>(item.address_index), decimal(item.value), (uint32_t)outputs.size());
					if (contract_address)
					{
						auto& token = tokens[*contract_address];
						if (!token.is_coin_valid() || token.value < spending_value)
							coreturn expects_rt<outgoing_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s", spending_value.to_string().c_str(), token.value.to_string().c_str())));

						output.apply_token_value(*contract_address, token.symbol, spending_value, token.decimals);
						output.value = decimal::zero();
						token.value -= spending_value;
					}
					outputs.push_back(std::move(output));
				}

				auto change_output = coin_utxo(string(), change_wallet->addresses.begin()->second, option<uint64_t>(change_wallet->address_index), decimal(input_native_value - (total_value - min_output_value)), (uint32_t)outputs.size());
				for (auto& token : tokens)
				{
					if (token.second.is_coin_valid() && token.second.value.is_positive())
						change_output.apply_token_value(token.second.contract_address, token.second.symbol, token.second.value, token.second.decimals);
				}
				if (change_output.value.is_positive() || !change_output.tokens.empty())
					outputs.push_back(std::move(change_output));

				try
				{
					::Cardano::Transaction builder = ::Cardano::Transaction();
					for (auto& input : *inputs)
						builder.Body.TransactionInput.addInput(copy<std::string>(input.transaction_id), input.index);
					for (auto& output : outputs)
					{
						builder.Body.TransactionOutput.addOutput(copy<std::string>(output.address), (uint64_t)to_lovelace(output.value));
						for (auto& token : output.tokens)
							builder.Body.TransactionOutput.addAsset(copy<std::string>(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					builder.Body.addFee((uint64_t)to_lovelace(fee_value));
					builder.Body.addInvalidAfter(*block_slot + get_block_slot_offset());

					vector<transferer> from;
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
							throw std::invalid_argument("address " + copy<std::string>(input.address) + " cannot be used to sign the transaction (wallet not valid)");

						auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
						uint8_t raw_private_key[XSK_LENGTH];
						if (!decode_private_key(secret.view.data(), raw_private_key, nullptr))
							throw std::invalid_argument("could not get a valid private key for address " + copy<std::string>(input.address));

						builder.addExtendedSigningKey(raw_private_key);
						from.emplace_back(input.address, option<uint64_t>(input.address_index), decimal(input.value));
					}

					uint8_t raw_transaction_id[BLAKE256_LENGTH];
					auto& raw_body_data = builder.Body.Build();
					crypto_generichash_blake2b(raw_transaction_id, sizeof(raw_transaction_id), raw_body_data.data(), raw_body_data.size(), nullptr, 0);

					auto& raw_tx_data = builder.Build();
					if (!actual_fee)
					{
						decimal lovelace_fee = builder.getFeeTransacion_PostBuild(0);
						actual_fee = base_fee(lovelace_fee / netdata.divisibility, 1.0);
						fee_value = actual_fee->get_fee();
						goto retry_with_actual_fee;
					}

					string transaction_data = codec::hex_encode(std::string_view((const char*)raw_tx_data.data(), raw_tx_data.size()));
					string transaction_id = codec::hex_encode(std::string_view((const char*)raw_transaction_id, sizeof(raw_transaction_id)));
					for (auto& output : outputs)
						output.transaction_id = transaction_id;

					if (transaction_id.empty() || transaction_data.empty() || inputs->empty() || outputs.empty())
						coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));

					incoming_transaction tx;
					tx.set_transaction(asset, 0, transaction_id, std::move(fee_value));
					tx.set_operations(std::move(from), vector<transferer>(to));
					coreturn expects_rt<outgoing_transaction>(outgoing_transaction(std::move(tx), std::move(transaction_data), std::move(*inputs), std::move(outputs)));
				}
				catch (const std::invalid_argument& error)
				{
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error: " + string(error.what())));
				}
				catch (...)
				{
					coreturn expects_rt<outgoing_transaction>(remote_exception("tx serialization error"));
				}
			}
			expects_lr<master_wallet> cardano::new_master_wallet(const std::string_view& seed)
			{
				try
				{
					uint8_t private_key[MASTERSECRETKEY_LENGTH];
					if (!::Cardano::getRawMasterKey((const uint8_t*)seed.data(), seed.size(), nullptr, 0, private_key))
						return expects_lr<master_wallet>(layer_exception("seed value invalid"));

					uint8_t public_key[XVK_LENGTH];
					::Cardano::rawprivatekey_to_rawpublickey(private_key, public_key);

					std::string encoded_private_key, encoded_public_key;
					::Cardano::Hash::bech32_encode("xprv", private_key, sizeof(private_key), encoded_private_key);
					::Cardano::Hash::bech32_encode("xpub", public_key, sizeof(public_key), encoded_public_key);

					return expects_lr<master_wallet>(master_wallet(secret_box::secure(codec::hex_encode(seed)), secret_box::secure(encoded_private_key), string(encoded_public_key.begin(), encoded_public_key.end())));
				}
				catch (const std::invalid_argument& error)
				{
					return expects_lr<master_wallet>(layer_exception("seed value invalid: " + string(error.what())));
				}
				catch (...)
				{
					return expects_lr<master_wallet>(layer_exception("seed value invalid"));
				}
			}
			expects_lr<derived_signing_wallet> cardano::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
			{
				const uint32_t account_index = 0;
				const auto network = (protocol::now().is(network_type::mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);

				try
				{
					auto secret = wallet.signing_key.expose<KEY_LIMIT>();
					uint8_t master_key[MASTERSECRETKEY_LENGTH]; uint16_t master_key_size = (uint16_t)sizeof(master_key);
					if (!::Cardano::Hash::bech32_decode_extended(secret.view.data(), master_key, &master_key_size, sizeof(master_key)))
						throw std::invalid_argument("could not get a valid master key");

					uint8_t raw_derived_private_key[XSK_LENGTH];
					if (!::Cardano::getRawKey(::Cardano::InputKey::MasterKey, master_key, ::Cardano::Wallet::HD, ::Cardano::OutputKey::Private, account_index, ::Cardano::Role::Extern, (uint32_t)address_index, raw_derived_private_key))
						throw std::invalid_argument("could not get a valid private key");

					auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)raw_derived_private_key, sizeof(raw_derived_private_key))));
					if (derived)
						derived->address_index = address_index;
					return derived;
				}
				catch (const std::invalid_argument& error)
				{
					return expects_lr<derived_signing_wallet>(layer_exception("private key invalid: " + string(error.what())));
				}
				catch (...)
				{
					return expects_lr<derived_signing_wallet>(layer_exception("private key invalid"));
				}
			}
			expects_lr<derived_signing_wallet> cardano::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				const auto network = (protocol::now().is(network_type::mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);
				uint8_t private_key[XSK_LENGTH]; size_t private_key_size = 0;
				if (signing_key.size() != 32 && signing_key.size() != 64 && signing_key.size() != XSK_LENGTH)
				{
					if (!decode_private_key(signing_key.expose<KEY_LIMIT>().view, private_key, &private_key_size))
						return layer_exception("invalid private key");
				}
				else
				{
					private_key_size = signing_key.size();
					signing_key.stack((char*)private_key, private_key_size);
				}

				try
				{
					if (private_key_size == XSK_LENGTH)
					{
						uint8_t raw_derived_public_key[XVK_LENGTH];
						if (!::Cardano::rawprivatekey_to_rawpublickey(private_key, raw_derived_public_key))
							throw std::invalid_argument("could not get a valid public key");

						auto derived = new_verifying_wallet(asset, std::string_view((char*)raw_derived_public_key, sizeof(raw_derived_public_key)));
						if (!derived)
							return derived.error();

						std::string derived_private_key;
						::Cardano::Hash::bech32_encode("addr_xsk", private_key, (uint16_t)private_key_size, derived_private_key);
						return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
					}
					else
					{
						uint8_t raw_derived_public_key[32];
						ed25519_publickey_ext(private_key, raw_derived_public_key);

						auto derived = new_verifying_wallet(asset, std::string_view((char*)raw_derived_public_key, sizeof(raw_derived_public_key)));
						if (!derived)
							return derived.error();

						std::string derived_private_key;
						::Cardano::Hash::bech32_encode("ed25519e_sk", private_key, (uint16_t)private_key_size, derived_private_key);
						return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(derived_private_key)));
					}
				}
				catch (const std::invalid_argument& error)
				{
					return expects_lr<derived_signing_wallet>(layer_exception("private key invalid: " + string(error.what())));
				}
				catch (...)
				{
					return expects_lr<derived_signing_wallet>(layer_exception("private key invalid"));
				}
			}
			expects_lr<derived_verifying_wallet> cardano::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				const auto network = (protocol::now().is(network_type::mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);
				string raw_public_key = string(verifying_key);
				if (raw_public_key.size() != 32 && raw_public_key.size() != XVK_LENGTH)
				{
					uint8_t xvk[XSK_LENGTH]; size_t xvk_size = 0;
					if (!decode_public_key(raw_public_key, xvk, &xvk_size))
						return layer_exception("invalid public key");

					raw_public_key = string((char*)xvk, xvk_size);
				}

				try
				{
					if (raw_public_key.size() == XVK_LENGTH)
					{
						std::string derived_public_key;
						::Cardano::Hash::bech32_encode("addr_xvk", (uint8_t*)raw_public_key.data(), (uint16_t)raw_public_key.size(), derived_public_key);

						std::string address;
						::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, (uint8_t*)raw_public_key.data(), network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, address);
						return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, copy<string>(address) } }, optional::none, string(derived_public_key.begin(), derived_public_key.end())));
					}
					else
					{
						std::string derived_public_key;
						::Cardano::Hash::bech32_encode("ed25519_pk", (uint8_t*)raw_public_key.data(), (uint16_t)raw_public_key.size(), derived_public_key);

						uint8_t extended_public_key[XVK_LENGTH] = { 0 };
						memcpy(extended_public_key, (uint8_t*)raw_public_key.data(), raw_public_key.size());

						std::string address;
						::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, extended_public_key, network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, address);
						return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, copy<string>(address) } }, optional::none, string(derived_public_key.begin(), derived_public_key.end())));
					}
				}
				catch (const std::invalid_argument& error)
				{
					return expects_lr<derived_verifying_wallet>(layer_exception("public key invalid: " + string(error.what())));
				}
				catch (...)
				{
					return expects_lr<derived_verifying_wallet>(layer_exception("public key invalid"));
				}
			}
			expects_lr<string> cardano::new_public_key_hash(const std::string_view& address)
			{
				uint8_t data[256]; uint16_t data_size = sizeof(data);
				if (!::Cardano::Hash::bech32_decode("addr", data, &data_size))
				{
					if (!::Cardano::Hash::bech32_decode("stake", data, &data_size))
					{
						if (!::Cardano::Hash::bech32_decode("addr_test", data, &data_size))
						{
							if (!::Cardano::Hash::bech32_decode("stake_test", data, &data_size))
								return layer_exception("invalid address");
						}
					}
				}

				return string((char*)data, data_size);
			}
			expects_lr<string> cardano::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				uint8_t raw_private_key[XSK_LENGTH];
				auto secret = signing_wallet->signing_key.expose<KEY_LIMIT>();
				if (!decode_private_key(secret.view.data(), raw_private_key, nullptr))
					return expects_lr<string>(layer_exception("input private key invalid"));

				uint8_t hash[32];
				crypto_generichash_blake2b(hash, sizeof(hash), (uint8_t*)message.data(), message.size(), nullptr, 0);

				uint8_t signature[64];
				if (!::Cardano::signature(raw_private_key, hash, sizeof(hash), signature))
					return expects_lr<string>(layer_exception("input private key invalid"));

				return codec::base64_url_encode(std::string_view((char*)signature, sizeof(signature)));
			}
			expects_lr<void> cardano::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				string signature_data = signature.size() == 64 ? string(signature) : codec::base64_url_decode(signature);
				if (signature_data.size() != 64)
					return layer_exception("signature not valid");

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				uint8_t raw_public_key[XVK_LENGTH];
				if (!decode_public_key(verifying_wallet->verifying_key, raw_public_key, nullptr))
					return layer_exception("input public key invalid");

				uint8_t hash[32];
				crypto_generichash_blake2b(hash, sizeof(hash), (uint8_t*)message.data(), message.size(), nullptr, 0);
				if (!::Cardano::verify(raw_public_key, hash, sizeof(hash), (uint8_t*)signature_data.data()))
					return layer_exception("signature verification failed with used public key");

				return expectation::met;
			}
			expects_lr<void> cardano::verify_node_compatibility(server_relay* node)
			{
				if (!node->has_distinct_url(server_relay::transmit_type::JSONRPC))
					return layer_exception("cardano ogmios jsonrpc node is required");

				if (!node->has_distinct_url(server_relay::transmit_type::REST))
					return layer_exception("cardano rosetta rest node is required");

				return expectation::met;
			}
			string cardano::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/1852'/1815'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const cardano::chainparams& cardano::get_chainparams() const
			{
				return netdata;
			}
			bool cardano::decode_private_key(const std::string_view& data, uint8_t private_key[96], size_t* private_key_size)
			{
				uint8_t derived_private_key[XSK_LENGTH]; uint16_t derived_private_key_size = sizeof(derived_private_key);
				if (!::Cardano::Hash::bech32_decode_extended(data.data(), derived_private_key, &derived_private_key_size, sizeof(derived_private_key)))
					return false;

				if (private_key_size != nullptr)
					*private_key_size = (size_t)derived_private_key_size;

				memset(private_key, 0, sizeof(derived_private_key));
				memcpy(private_key, derived_private_key, derived_private_key_size);
				return derived_private_key_size == sizeof(derived_private_key) || derived_private_key_size == 64;
			}
			bool cardano::decode_public_key(const std::string_view& data, uint8_t public_key[64], size_t* public_key_size)
			{
				uint16_t derived_public_key_size = 64;
				if (!::Cardano::Hash::bech32_decode_extended(data.data(), public_key, &derived_public_key_size, XVK_LENGTH))
					return false;

				if (public_key_size != nullptr)
					*public_key_size = (size_t)derived_public_key_size;

				return derived_public_key_size == XVK_LENGTH || derived_public_key_size == 32;
			}
			decimal cardano::get_min_value_per_output()
			{
				return 1.0;
			}
			uint256_t cardano::to_lovelace(const decimal& value)
			{
				return uint256_t((value * netdata.divisibility).truncate(0).to_string());
			}
			uint64_t cardano::get_min_protocol_fee_a()
			{
				return PROTOCOL_FEE_A;
			}
			uint64_t cardano::get_min_protocol_fee_b()
			{
				return PROTOCOL_FEE_B;
			}
			size_t cardano::get_block_slot_offset()
			{
				return 300;
			}
			string cardano::get_blockchain()
			{
				return "cardano";
			}
			string cardano::get_network()
			{
				return protocol::now().is(network_type::mainnet) ? "mainnet" : "preview";
			}
			size_t cardano::get_tx_fee_blocks()
			{
				return 6;
			}
			size_t cardano::get_tx_fee_block_delta()
			{
				return 32;
			}
			size_t cardano::get_tx_fee_base_size()
			{
				return 300;
			}
		}
	}
}
