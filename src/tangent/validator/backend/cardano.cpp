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
			const char* cardano::nd_call::submit_transaction()
			{
				return "/construction/submit";
			}

			cardano::cardano(const algorithm::asset_id& new_asset) noexcept : relay_backend_utxo(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::utxo;
				netdata.sync_latency = 12;
				netdata.divisibility = decimal(1000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer = "native";
				netdata.supports_bulk_transfer = true;
				netdata.requires_transaction_expiration = false;
			}
			expects_promise_rt<uint64_t> cardano::get_latest_block_height()
			{
				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));

				auto netstat = coawait(execute_rest("POST", nd_call::network_status(), args, cache_policy::no_cache));
				if (!netstat)
					coreturn expects_rt<uint64_t>(netstat.error());

				uint64_t block_height = netstat->fetch_var("current_block_identifier.index").get_integer();
				memory::release(*netstat);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> cardano::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));
				schema* block_query = args->set("block_identifier", var::object());
				block_query->set("index", var::integer(block_height));

				auto block_data = coawait(execute_rest("POST", nd_call::block_data(), args, cache_policy::blob_cache));
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
			expects_promise_rt<coin_utxo> cardano::get_transaction_output(const std::string_view& transaction_id, uint64_t index)
			{
				auto result = get_utxo(transaction_id, index);
				if (!result)
					return expects_promise_rt<coin_utxo>(remote_exception(std::move(result.error().message())));

				return expects_promise_rt<coin_utxo>(std::move(*result));
			}
			expects_promise_rt<uint64_t> cardano::get_latest_block_slot()
			{
				auto block_height = coawait(cardano::get_latest_block_height());
				if (!block_height)
					coreturn expects_rt<uint64_t>(block_height.error());

				auto block_data = coawait(cardano::get_block_transactions(*block_height, nullptr));
				if (!block_data)
					coreturn expects_rt<uint64_t>(block_data.error());

				uint64_t block_slot = block_data->fetch_var("metadata.slotNo").get_integer();
				memory::release(*block_data);
				coreturn expects_rt<uint64_t>(block_slot);
			}
			expects_promise_rt<computed_transaction> cardano::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto* operations_data = transaction_data->get("operations");
				if (!operations_data || operations_data->empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				unordered_set<string> addresses;
				for (auto& tx_operation : operations_data->get_childs())
				{
					string status = tx_operation->get_var("status").get_blob();
					if (status == "success")
						addresses.insert(tx_operation->fetch_var("account.address").get_blob());
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				computed_transaction tx;
				tx.transaction_id = transaction_data->fetch_var("transaction_identifier.hash").get_blob();
				tx.block_id = block_height;

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
					decimal value = math0::abs(tx_operation->fetch_var("amount.value").get_decimal()) / netdata.divisibility;
					schema* token_bundle = tx_operation->fetch("metadata.tokenBundle");
					if (type == "output")
					{
						auto target_address = discovery->find(address);
						coin_utxo new_output;
						new_output.transaction_id = transaction_id;
						new_output.link = target_address != discovery->end() ? target_address->second : wallet_link::from_address(address);
						new_output.value = value;
						new_output.index = index;

						if (token_bundle != nullptr)
						{
							auto blockchain = algorithm::asset::blockchain_of(native_asset);
							for (auto& token_operation : token_bundle->get_childs())
							{
								schema* tokens = token_operation->get("tokens");
								if (tokens != nullptr)
								{
									string contract_address = token_operation->get_var("policyId").get_blob();
									for (auto& item : tokens->get_childs())
									{
										string symbol = item->fetch_var("currency.symbol").get_blob();
										if (format::util::is_hex_encoding(symbol))
											symbol = codec::hex_decode(symbol);

										auto token_asset = algorithm::asset::id_of(blockchain, symbol, contract_address);
										uint8_t decimals = (uint8_t)item->fetch_var("currency.decimals").get_integer();
										decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
										decimal token_value = math0::abs(item->get_var("value").get_decimal()) / divisibility.truncate(protocol::now().message.precision);
										new_output.apply_token_value(contract_address, symbol, token_value, decimals);
										nss::server_node::get()->enable_contract_address(token_asset, contract_address);
									}
								}
							}
						}

						tx.outputs.push_back(std::move(new_output));
					}
					else if (type == "input")
					{
						auto target_address = discovery->find(address);
						coin_utxo new_input;
						new_input.transaction_id = transaction_id;
						new_input.link = target_address != discovery->end() ? target_address->second : wallet_link::from_address(address);
						new_input.value = value;
						new_input.index = index;

						if (token_bundle != nullptr)
						{
							auto blockchain = algorithm::asset::blockchain_of(native_asset);
							for (auto& token_operation : token_bundle->get_childs())
							{
								schema* tokens = token_operation->get("tokens");
								if (tokens != nullptr)
								{
									string contract_address = token_operation->get_var("policyId").get_blob();
									for (auto& item : tokens->get_childs())
									{
										string symbol = item->fetch_var("currency.symbol").get_blob();
										if (format::util::is_hex_encoding(symbol))
											symbol = codec::hex_decode(symbol);

										auto token_asset = algorithm::asset::id_of(blockchain, symbol, contract_address);
										uint8_t decimals = (uint8_t)item->fetch_var("currency.decimals").get_integer();
										decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
										decimal token_value = math0::abs(item->get_var("value").get_decimal()) / divisibility.truncate(protocol::now().message.precision);
										new_input.apply_token_value(contract_address, symbol, token_value, decimals);
										nss::server_node::get()->enable_contract_address(token_asset, contract_address);
									}
								}
							}
						}

						tx.inputs.push_back(std::move(new_input));
					}
				}

				unordered_map<algorithm::asset_id, decimal> balance;
				for (auto& input : tx.inputs)
				{
					auto& value = balance[native_asset];
					value = value.is_nan() ? input.value : (value + input.value);
					for (auto& token : input.tokens)
					{
						value = balance[token.get_asset(native_asset)];
						value = value.is_nan() ? token.value : (value + token.value);
					}
				}
				for (auto& output : tx.outputs)
				{
					auto& value = balance[native_asset];
					value = value.is_nan() ? -output.value : (value - output.value);
					for (auto& token : output.tokens)
					{
						value = balance[token.get_asset(native_asset)];
						value = value.is_nan() ? -token.value : (value - token.value);
					}
				}

				coin_utxo new_input;
				new_input.transaction_id = tx.transaction_id + "!";
				new_input.value = decimal::zero();
				new_input.index = (uint32_t)tx.inputs.size();

				bool is_coinbase = false;
				for (auto& [asset, value] : balance)
				{
					if (!value.is_negative())
						continue;

					is_coinbase = true;
					if (asset != native_asset)
					{
						for (auto& output : tx.outputs)
						{
							coin_utxo::token_utxo* token_utxo = nullptr;
							for (auto& token : output.tokens)
							{
								if (token.get_asset(native_asset) == asset)
								{
									token_utxo = &token;
									break;
								}
							}
							if (token_utxo != nullptr)
							{
								new_input.apply_token_value(token_utxo->contract_address, token_utxo->symbol, -value, token_utxo->decimals);
								break;
							}
						}
					}
					else
						new_input.value = -value;
				}

				if (is_coinbase)
					tx.inputs.push_back(std::move(new_input));

				coreturn expects_rt<computed_transaction>(std::move(tx));
			}
			expects_promise_rt<computed_fee> cardano::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				auto block_height = coawait(get_latest_block_height());
				if (!block_height)
					coreturn expects_rt<computed_fee>(std::move(block_height.error()));

				if (!tx_analytics.block_height || *block_height < tx_analytics.block_height || *block_height - tx_analytics.block_height > get_tx_fee_block_delta())
				{
					size_t offset = 0, count = 0;
					size_t max_count = std::min<size_t>(*block_height - tx_analytics.block_height, get_tx_fee_blocks());
					tx_analytics.block_height = *block_height;
					while (count < max_count)
					{
						auto transactions = uptr<schema>(coawait(get_block_transactions(*block_height - (offset++), nullptr)));
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

				decimal fee_rate_fixed = get_min_protocol_fee_fixed();
				decimal fee_rate_per_byte = get_min_protocol_fee_per_byte();
				size_t tx_size = (size_t)((double)tx_analytics.total_size / (double)tx_analytics.transactions);

				const uint64_t expected_max_tx_size = 1000;
				tx_size = std::min<size_t>(expected_max_tx_size, (size_t)(std::ceil((double)tx_size / 100.0) * 100.0));
				coreturn expects_rt<computed_fee>(computed_fee::flat_fee(fee_rate_fixed * decimal(tx_size) + fee_rate_per_byte));
			}
			expects_promise_rt<void> cardano::broadcast_transaction(const finalized_transaction& finalized)
			{
				Cardano::Utils::CborSerialize rosetta_transaction;
				rosetta_transaction.createArray(1);
				rosetta_transaction.addString(copy<std::string>(finalized.calldata));
				
				auto& rosetta_data = rosetta_transaction.getCbor();
				schema* args = var::set::object();
				schema* network_query = args->set("network_identifier", var::object());
				network_query->set("blockchain", var::string(get_blockchain()));
				network_query->set("network", var::string(get_network()));
				args->set("signed_transaction", var::string(codec::hex_encode(std::string_view((char*)rosetta_data.data(), rosetta_data.size()))));

				auto tx_hash = coawait(execute_rest("POST", nd_call::submit_transaction(), args, cache_policy::no_cache));
				if (!tx_hash)
					coreturn expects_rt<void>(tx_hash.error());

				memory::release(*tx_hash);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> cardano::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				auto block_slot = coawait(get_latest_block_slot());
				if (!block_slot)
					coreturn expects_rt<prepared_transaction>(remote_exception("latest block slot not found"));

				option<computed_fee> actual_fee = optional::none;
				decimal fee_value = actual_fee ? actual_fee->get_max_fee() : fee.get_max_fee();
			retry_with_actual_fee:
				prepared_transaction result;
				result.requires_abi(format::variable(to_lovelace(fee_value)));

				unordered_map<algorithm::asset_id, decimal> total_token_value;
				decimal total_value = fee_value;
				for (auto& item : to)
				{
					auto min_output_value = get_min_protocol_value_per_output(item.asset != native_asset ? 1 : 0);
					if (item.asset != native_asset)
					{
						auto& value = total_token_value[item.asset];
						value = value.is_nan() ? item.value : (value + item.value);
						total_value += min_output_value;
					}
					else
					{
						total_value += item.value;
						if (item.asset == native_asset && item.value < min_output_value)
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (value is less than minimum required by protocol)", item.value.to_string().c_str(), min_output_value.to_string().c_str())));
					}
				}

				auto possible_inputs = calculate_utxo(from_link, balance_query(total_value, total_token_value));
				auto remaining_value = possible_inputs ? get_utxo_value(*possible_inputs, optional::none) : 0.0;
				if (!possible_inputs || possible_inputs->empty())
					coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (or not enough token funds)", total_value.to_string().c_str(), remaining_value.to_string().c_str())));

				unordered_map<algorithm::asset_id, coin_utxo::token_utxo> change_tokens;
				for (auto& item : *possible_inputs)
				{
					for (auto& token : item.tokens)
					{
						auto token_asset = token.get_asset(native_asset);
						auto& next = change_tokens[token_asset];
						if (next.is_valid())
							next.value += token.value;
						else
							next = token;
					}
				}

				result.outputs.reserve(to.size() + 1);
				for (auto& item : to)
				{
					auto link = find_linked_addresses({ item.address });
					auto min_output_value = get_min_protocol_value_per_output(item.asset != native_asset ? 1 : 0);
					auto output = coin_utxo(link ? std::move(link->begin()->second) : wallet_link::from_address(item.address), string(), (uint32_t)result.outputs.size(), item.asset == native_asset ? decimal(item.value) : std::move(min_output_value));
					if (item.asset != native_asset)
					{
						auto& change_token = change_tokens[item.asset];
						output.apply_token_value(change_token.contract_address, change_token.symbol, item.value, change_token.decimals);
						change_token.value -= item.value;
					}
					result.requires_output(std::move(output));
				}

				auto change_output = coin_utxo(wallet_link(possible_inputs->front().link), string(), (uint32_t)result.outputs.size(), decimal(remaining_value - total_value));
				for (auto& token : change_tokens)
				{
					if (token.second.is_valid() && token.second.value.is_positive())
						change_output.apply_token_value(token.second.contract_address, token.second.symbol, token.second.value, token.second.decimals);
				}

				if (change_output.value.is_positive() || !change_output.tokens.empty())
				{
					auto min_change_output_value = get_min_protocol_value_per_output(change_output.tokens.size());
					if (change_output.value < min_change_output_value)
					{
						if (!change_output.tokens.empty())
							coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (change value is less than minimum required by protocol)", change_output.value.to_string().c_str(), min_change_output_value.to_string().c_str())));

						if (change_output.value > fee_value)
							fee_value = std::move(change_output.value);
						else
							fee_value += change_output.value;
					}
					else
						result.requires_output(std::move(change_output));
				}

				try
				{
					::Cardano::Transaction builder = ::Cardano::Transaction();
					uint8_t dummy_private_key[XSK_LENGTH] = { 0 };
					for (auto& input : *possible_inputs)
					{
						builder.Body.TransactionInput.addInput(copy<std::string>(input.transaction_id), input.index);
						builder.addExtendedSigningKey(dummy_private_key);
					}
					for (auto& output : result.outputs)
					{
						builder.Body.TransactionOutput.addOutput(copy<std::string>(output.link.address), (uint64_t)to_lovelace(output.value));
						for (auto& token : output.tokens)
							builder.Body.TransactionOutput.addAsset(copy<std::string>(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					builder.Body.addFee((uint64_t)to_lovelace(fee_value));

					std::vector<::Cardano::Transaction::Digest> digests;
					auto& raw_tx_data = builder.build(&digests);
					if (!actual_fee)
					{
						decimal lovelace_fee = builder.getFeeTransacion_PostBuild(0);
						actual_fee = computed_fee::flat_fee(lovelace_fee / netdata.divisibility);
						fee_value = actual_fee->get_max_fee();
						goto retry_with_actual_fee;
					}

					for (size_t i = 0; i < digests.size(); i++)
					{
						auto& digest = digests[i];
						auto& input = possible_inputs->at(i);
						auto signing_public_key = decode_public_key(input.link.public_key);
						if (!signing_public_key)
							coreturn expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

						auto public_key = algorithm::composition::cpubkey_t(*signing_public_key);
						result.requires_input(algorithm::composition::type::ed25519, public_key.data, digest.Hash, sizeof(digest.Hash), std::move(input));
					}

					coreturn expects_rt<prepared_transaction>(std::move(result));
				}
				catch (const std::invalid_argument& error)
				{
					coreturn expects_rt<prepared_transaction>(remote_exception("tx serialization error: " + string(error.what())));
				}
				catch (...)
				{
					coreturn expects_rt<prepared_transaction>(remote_exception("tx serialization error"));
				}
			}
			expects_lr<finalized_transaction> cardano::finalize_transaction(mediator::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 1)
					return layer_exception("invalid prepared abi");

				auto fee_value = prepared.abi.front().as_uint64();
				try
				{
					::Cardano::Transaction verifier = ::Cardano::Transaction();
					uint8_t dummy_private_key[XSK_LENGTH] = { 0 };
					for (auto& input : prepared.inputs)
					{
						verifier.Body.TransactionInput.addInput(copy<std::string>(input.utxo.transaction_id), input.utxo.index);
						verifier.addExtendedSigningKey(dummy_private_key);
					}
					for (auto& output : prepared.outputs)
					{
						verifier.Body.TransactionOutput.addOutput(copy<std::string>(output.link.address), (uint64_t)to_lovelace(output.value));
						for (auto& token : output.tokens)
							verifier.Body.TransactionOutput.addAsset(copy<std::string>(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					verifier.Body.addFee(fee_value);

					std::vector<::Cardano::Transaction::Digest> digests;
					verifier.build(&digests);

					for (size_t i = 0; i < digests.size(); i++)
					{
						auto& digest = digests[i];
						auto& input = prepared.inputs[i];
						if (input.message.size() != sizeof(digest.Hash) || memcmp(input.message.data(), digest.Hash, sizeof(digest.Hash)) != 0)
							return layer_exception("invalid input message");
					}

					::Cardano::Transaction builder = ::Cardano::Transaction();
					for (auto& input : prepared.inputs)
					{
						auto raw_public_key = decode_public_key(input.utxo.link.public_key);
						if (!raw_public_key)
							return raw_public_key.error();

						builder.Body.TransactionInput.addInput(copy<std::string>(input.utxo.transaction_id), input.utxo.index);
						builder.addExtendedVerifyingKey((uint8_t*)raw_public_key->data(), input.signature);
					}
					for (auto& output : prepared.outputs)
					{
						builder.Body.TransactionOutput.addOutput(copy<std::string>(output.link.address), (uint64_t)to_lovelace(output.value));
						for (auto& token : output.tokens)
							builder.Body.TransactionOutput.addAsset(copy<std::string>(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					builder.Body.addFee(fee_value);

					uint8_t raw_transaction_id[BLAKE256_LENGTH];
					auto raw_tx_data = builder.build(nullptr);
					auto& raw_body_data = builder.Body.getcbor_afterBuild();
					crypto_generichash_blake2b(raw_transaction_id, sizeof(raw_transaction_id), raw_body_data.data(), raw_body_data.size(), nullptr, 0);

					auto result = finalized_transaction(std::move(prepared), codec::hex_encode(std::string_view((const char*)raw_tx_data.data(), raw_tx_data.size())), codec::hex_encode(std::string_view((const char*)raw_transaction_id, sizeof(raw_transaction_id))));
					if (!result.is_valid())
						return layer_exception("tx serialization error");

					return expects_lr<finalized_transaction>(std::move(result));
				}
				catch (const std::invalid_argument& error)
				{
					return layer_exception("tx serialization error: " + string(error.what()));
				}
				catch (...)
				{
					return layer_exception("tx serialization error");
				}
			}
			expects_lr<secret_box> cardano::encode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				std::string encoded_private_key;
				if (!::Cardano::Hash::bech32_encode(data.view.size() == XSK_LENGTH ? "addr_xsk" : "ed25519e_sk", data.buffer, (uint16_t)data.view.size(), encoded_private_key))
					return layer_exception("invalid decoded private key");

				return secret_box::secure(encoded_private_key);
			}
			expects_lr<secret_box> cardano::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				uint8_t decoded_private_key[XSK_LENGTH]; uint16_t decoded_private_key_size = sizeof(decoded_private_key);
				if (!::Cardano::Hash::bech32_decode_extended(data.view.data(), decoded_private_key, &decoded_private_key_size, sizeof(decoded_private_key)))
					return layer_exception("invalid encoded private key");
				else if (decoded_private_key_size != XSK_LENGTH && decoded_private_key_size != 64)
					return layer_exception("invalid decoded private key size");

				return secret_box::secure(std::string_view((char*)decoded_private_key, decoded_private_key_size));
			}
			expects_lr<string> cardano::encode_public_key(const std::string_view& public_key)
			{
				std::string encoded_public_key;
				if (!::Cardano::Hash::bech32_encode("addr_xvk", (uint8_t*)public_key.data(), (uint16_t)public_key.size(), encoded_public_key))
					return layer_exception("invalid decoded public key");

				return copy<string>(encoded_public_key);
			}
			expects_lr<string> cardano::decode_public_key(const std::string_view& public_key)
			{
				uint8_t decoded_public_key[XVK_LENGTH];
				uint16_t decoded_public_key_size = sizeof(decoded_public_key);
				if (!::Cardano::Hash::bech32_decode_extended(public_key.data(), decoded_public_key, &decoded_public_key_size, sizeof(decoded_public_key)))
					return layer_exception("invalid encoded public key");
				else if (decoded_public_key_size != XVK_LENGTH && decoded_public_key_size != 32)
					return layer_exception("invalid decoded public key size");

				return string((char*)decoded_public_key, decoded_public_key_size);
			}
			expects_lr<string> cardano::encode_address(const std::string_view& public_key_hash)
			{
				std::string encoded_address;
				if (!::Cardano::Hash::bech32_encode(protocol::now().is(network_type::mainnet) ? "addr" : "addr_test", (uint8_t*)public_key_hash.data(), (uint16_t)public_key_hash.size(), encoded_address))
					return layer_exception("invalid decoded public key hash");

				return copy<string>(encoded_address);
			}
			expects_lr<string> cardano::decode_address(const std::string_view& address)
			{
				uint8_t data[256]; uint16_t data_size = sizeof(data); auto copy = string(address);
				if (!::Cardano::Hash::bech32_decode_extended(copy.c_str(), data, &data_size, sizeof(data)))
					return layer_exception("invalid address");

				return string((char*)data, data_size);
			}
			expects_lr<string> cardano::encode_transaction_id(const std::string_view& transaction_id)
			{
				return codec::hex_encode(transaction_id);
			}
			expects_lr<string> cardano::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = codec::hex_decode(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> cardano::to_addresses(const std::string_view& public_key)
			{
				string raw_public_key = string(public_key);
				if (raw_public_key.size() != 32 && raw_public_key.size() != XVK_LENGTH)
				{
					auto decoded_public_key = decode_public_key(public_key);
					if (!decoded_public_key)
						return decoded_public_key.error();

					raw_public_key = std::move(*decoded_public_key);
				}

				std::string address;
				const auto network = (protocol::now().is(network_type::mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);
				if (raw_public_key.size() != XVK_LENGTH)
				{
					uint8_t extended_public_key[XVK_LENGTH] = { 0 };
					memcpy(extended_public_key, (uint8_t*)raw_public_key.data(), raw_public_key.size());
					::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, extended_public_key, network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, address);
				}
				else
					::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, (uint8_t*)raw_public_key.data(), network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, address);

				address_map result = { { (uint8_t)1, copy<string>(address) } };
				return expects_lr<address_map>(std::move(result));
			}
			const cardano::chainparams& cardano::get_chainparams() const
			{
				return netdata;
			}
			decimal cardano::get_min_protocol_value_per_output(size_t tokens)
			{
				static const uint64_t ada_output_lovelace = netdata.divisibility.to_uint64();
				static const uint64_t token_output_lovelace = PROTOCOL_UTXO_VALUE_PER_WORD * 48;
				return decimal(std::max(ada_output_lovelace, token_output_lovelace * tokens)) / netdata.divisibility;
			}
			decimal cardano::get_min_protocol_fee_fixed()
			{
				return decimal(PROTOCOL_FEE_FIXED) / netdata.divisibility;
			}
			decimal cardano::get_min_protocol_fee_per_byte()
			{
				return decimal(PROTOCOL_FEE_PER_BYTE) / netdata.divisibility;
			}
			uint256_t cardano::to_lovelace(const decimal& value)
			{
				return uint256_t((value * netdata.divisibility).truncate(0).to_string());
			}
			string cardano::get_blockchain()
			{
				return "cardano";
			}
			string cardano::get_network()
			{
				return protocol::now().is(network_type::mainnet) ? "mainnet" : "preprod";
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
