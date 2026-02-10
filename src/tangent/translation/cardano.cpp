#include "cardano.h"
#include "../internal/cardano.h"
extern "C"
{
#include "../internal/ed25519.h"
#include "../internal/sha2.h"
}
#include <cctype>

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			static std::string to_unprefixed_hex(const std::string_view& value)
			{
				return stringify::starts_with(value, "0x") ? std::string(value.substr(2)) : std::string(value);
			}
			static string to_token_symbol(const std::string_view& data)
			{
				string token_symbol = string(data);
				if (format::util::is_hex_encoding(token_symbol))
					token_symbol = codec::hex_decode(token_symbol);
				return token_symbol;
			}

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

			cardano::cardano(const algorithm::asset_id& new_asset) noexcept : utxo_translation_unit(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519;
				netdata.routing = routing_policy::utxo;
				netdata.tokenization = token_policy::native;
				netdata.sync_latency = 11;
				netdata.divisibility = algorithm::arithmetic::fixed(1000000);
				netdata.transaction_expires = false;
			}
			expects_promise_rt<uint64_t> cardano::get_latest_block_height()
			{
				auto args = format::tree::map();
				auto* network_query = args.set("network_identifier", format::tree::map());
				network_query->set("blockchain", format::variable(get_blockchain()));
				network_query->set("network", format::variable(get_network()));
				return execute_rest("POST", nd_call::network_status(), std::move(args), cache_policy::no_cache).then<expects_rt<uint64_t>>([](expects_rt<format::tree>&& netstat) -> expects_rt<uint64_t>
				{
					return netstat ? expects_rt<uint64_t>(netstat->child_var("current_block_identifier.index").as_uint64()) : expects_rt<uint64_t>(netstat.error());
				});
			}
			expects_promise_rt<vector<block_log>> cardano::get_block_transactions(uint64_t block_height, uint64_t block_count)
			{
				return coasync<expects_rt<vector<block_log>>>([this, block_height, block_count]() -> expects_promise_rt<vector<block_log>>
				{
					vector<block_log> results;
					for (uint64_t i = 0; i < block_count; i++)
					{
						auto args = format::tree::map();
						args.childs().reserve(2);
						auto* network_query = args.set("network_identifier", format::tree::map());
						network_query->set("blockchain", format::variable(get_blockchain()));
						network_query->set("network", format::variable(get_network()));
						auto* block_query = args.set("block_identifier", format::tree::map());
						block_query->set("index", format::variable(block_height + i));

						auto block_data = coawait(execute_rest("POST", nd_call::block_data(), std::move(args), cache_policy::blob_cache));
						if (!block_data)
							coreturn expects_rt<vector<block_log>>(block_data.error());

						auto* transactions = (format::tree*)block_data->child("block.transactions");
						auto& log = results.emplace_back();
						log.block_hash = block_data->child_var("block.block_identifier.hash").as_blob();
						log.transactions = transactions ? std::move(*transactions) : format::tree::list();
					}
					coreturn expects_rt<vector<block_log>>(std::move(results));
				});
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
				return coasync<expects_rt<uint64_t>>([this]() -> expects_promise_rt<uint64_t>
				{
					auto block_height = coawait(cardano::get_latest_block_height());
					if (!block_height)
						coreturn expects_rt<uint64_t>(block_height.error());

					auto args = format::tree::map();
					args.childs().reserve(2);
					auto* network_query = args.set("network_identifier", format::tree::map());
					network_query->set("blockchain", format::variable(get_blockchain()));
					network_query->set("network", format::variable(get_network()));
					auto* block_query = args.set("block_identifier", format::tree::map());
					block_query->set("index", format::variable(*block_height));

					auto block_data = coawait(execute_rest("POST", nd_call::block_data(), std::move(args), cache_policy::blob_cache));
					if (!block_data)
						coreturn expects_rt<uint64_t>(block_data.error());

					uint64_t block_slot = block_data->child_var("block.metadata.slotNo").as_uint64();
					coreturn expects_rt<uint64_t>(block_slot);
				});
			}
			expects_promise_rt<computed_transaction> cardano::link_transaction(uint64_t, const std::string_view&, format::tree& transaction_data)
			{
				auto* operations_data = transaction_data.child("operations");
				if (!operations_data || operations_data->childs().empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				hash_set<string> addresses;
				for (auto& tx_operation : operations_data->childs())
				{
					string status = tx_operation.child_var("status").as_blob();
					if (status == "success")
						addresses.insert(tx_operation.child_var("account.address").as_blob());
				}

				auto discovery = find_linked_addresses(addresses);
				if (!discovery)
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				computed_transaction tx;
				tx.transaction_id = transaction_data.child_var("transaction_identifier.hash").as_blob();

				for (auto& tx_operation : operations_data->childs())
				{
					string status = tx_operation.child_var("status").as_blob();
					if (stringify::to_lower(status) != "success")
						continue;

					auto identifier = stringify::split(tx_operation.child_var("coin_change.coin_identifier.identifier").as_blob(), ':');
					uint32_t index = from_string<uint32_t>(identifier.back()).or_else(0);
					string transaction_id = identifier.front();
					string address = tx_operation.child_var("account.address").as_blob();
					string type = tx_operation.child_var("type").as_blob();
					decimal value = math0::abs(tx_operation.child_var("amount.value").as_decimal()) / netdata.divisibility;
					auto* token_bundle = tx_operation.child("metadata.tokenBundle");
					stringify::to_lower(type);
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
							for (auto& token_operation : token_bundle->childs())
							{
								auto* tokens = token_operation.child("tokens");
								if (tokens != nullptr)
								{
									string contract_address = token_operation.child_var("policyId").as_blob();
									for (auto& item : tokens->childs())
									{
										auto token_symbol = to_token_symbol(item.child_var("currency.symbol").as_blob());
										auto token_asset = algorithm::asset::id_of(blockchain, token_symbol.empty() ? contract_address : token_symbol, contract_address);
										uint8_t decimals = item.child_var("currency.decimals").as_uint8();
										decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
										decimal token_value = algorithm::arithmetic::divide(math0::abs(item.child_var("value").as_decimal()), divisibility);
										new_output.apply_token_value(contract_address, token_symbol, token_value, decimals);
										bridge::get()->enable_contract_address(token_asset, contract_address);
									}
								}
							}
						}

						tx.add_output(std::move(new_output));
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
							for (auto& token_operation : token_bundle->childs())
							{
								auto* tokens = token_operation.child("tokens");
								if (tokens != nullptr)
								{
									string contract_address = token_operation.child_var("policyId").as_blob();
									for (auto& item : tokens->childs())
									{
										auto token_symbol = to_token_symbol(item.child_var("currency.symbol").as_blob());
										auto token_asset = algorithm::asset::id_of(blockchain, token_symbol, contract_address);
										uint8_t decimals = item.child_var("currency.decimals").as_uint8();
										decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
										decimal token_value = algorithm::arithmetic::divide(math0::abs(item.child_var("value").as_decimal()), divisibility);
										new_input.apply_token_value(contract_address, token_symbol, token_value, decimals);
										bridge::get()->enable_contract_address(token_asset, contract_address);
									}
								}
							}
						}

						tx.add_input(std::move(new_input));
					}
				}

				hash_map<algorithm::asset_id, decimal> balance;
				for (auto& [hash, input] : tx.inputs)
				{
					auto& value = balance[native_asset];
					value = value.is_nan() ? input.value : (value + input.value);
					for (auto& [token_hash, token] : input.tokens)
					{
						auto& token_value = balance[token.get_asset(native_asset)];
						token_value = token_value.is_nan() ? token.value : (token_value + token.value);
					}
				}
				for (auto& [hash, output] : tx.outputs)
				{
					auto& value = balance[native_asset];
					value = value.is_nan() ? -output.value : (value - output.value);
					for (auto& [token_hash, token] : output.tokens)
					{
						auto& token_value = balance[token.get_asset(native_asset)];
						token_value = token_value.is_nan() ? -token.value : (token_value - token.value);
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
						for (auto& [hash, output] : tx.outputs)
						{
							coin_utxo::token_utxo* token_utxo = nullptr;
							for (auto& [token_hash, token] : output.tokens)
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
					tx.add_input(std::move(new_input));

				coreturn expects_rt<computed_transaction>(std::move(tx));
			}
			expects_promise_rt<void> cardano::broadcast_transaction(const finalized_transaction& finalized)
			{
				Cardano::CborSerialize rosetta_transaction;
				rosetta_transaction.createArray(1);
				rosetta_transaction.addString(copy<std::string>(finalized.calldata));

				auto& rosetta_data = rosetta_transaction.getCbor();
				format::tree args = format::tree::map();
				auto* network_query = args.set("network_identifier", format::tree::map());
				network_query->set("blockchain", format::variable(get_blockchain()));
				network_query->set("network", format::variable(get_network()));
				args.set("signed_transaction", format::variable(codec::hex_encode(std::string_view((char*)rosetta_data.data(), rosetta_data.size()))));

				return execute_rest("POST", nd_call::submit_transaction(), std::move(args), cache_policy::no_cache).then<expects_rt<void>>([](expects_rt<format::tree>&& tx_hash) -> expects_rt<void>
				{
					if (!tx_hash)
						return expects_rt<void>(tx_hash.error());

					auto result = tx_hash->child("transaction_identifier.hash");
					if (!result || result->value.as_string().empty())
						return expects_rt<void>(remote_exception(tx_hash->as_json()));

					return expects_rt<void>(expectation::met);
				});
			}
			expects_promise_rt<prepared_transaction> cardano::prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
			{
				return get_latest_block_slot().then<expects_rt<prepared_transaction>>([this, from_link, to, max_fee](expects_rt<uint64_t>&& block_slot) -> expects_rt<prepared_transaction>
				{
					option<std::pair<computed_fee, size_t>> fee = optional::none;
					option<decimal> additional_value = optional::none;
				retry_with_fee:
					decimal fee_value = fee ? fee->first.get_max_fee() : decimal::zero();
					auto str = fee_value.to_string();
					if (fee && fee_value > max_fee)
						return expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

					prepared_transaction result;
					result.requires_abi(format::variable(to_lovelace(fee_value)));

					hash_map<algorithm::asset_id, decimal> total_token_value; decimal total_value = fee_value;
					auto min_output_value = get_min_protocol_value_per_output(to.asset != native_asset ? 1 : 0);
					if (to.asset == native_asset)
					{
						total_value += to.value;
						if (to.asset == native_asset && to.value < min_output_value)
							return expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (value is less than minimum required by protocol)", to.value.to_string().c_str(), min_output_value.to_string().c_str())));
					}
					else
					{
						auto& value = total_token_value[to.asset];
						value = value.is_nan() ? to.value : (value + to.value);
						total_value += min_output_value;
					}

					auto possible_inputs = calculate_utxo(from_link, balance_query(additional_value ? total_value + *additional_value : total_value, total_token_value));
					auto remaining_value = possible_inputs ? get_utxo_value(*possible_inputs, optional::none) : 0.0;
					if (!possible_inputs || possible_inputs->empty())
						return expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (or not enough token funds)", total_value.to_string().c_str(), remaining_value.to_string().c_str())));

					hash_map<algorithm::asset_id, coin_utxo::token_utxo> change_tokens;
					for (auto& item : *possible_inputs)
					{
						for (auto& [token_hash, token] : item.tokens)
						{
							auto token_asset = token.get_asset(native_asset);
							auto& next = change_tokens[token_asset];
							if (next.validate())
								next.value += token.value;
							else
								next = token;
						}
					}

					auto to_link = find_linked_addresses({ to.address });
					auto output = coin_utxo(to_link ? std::move(to_link->begin()->second) : wallet_link::from_address(to.address), string(), (uint32_t)result.outputs.size(), to.asset == native_asset ? decimal(to.value) : std::move(min_output_value));
					if (to.asset != native_asset)
					{
						auto& change_token = change_tokens[to.asset];
						output.apply_token_value(change_token.contract_address, change_token.symbol, to.value, change_token.decimals);
						change_token.value -= to.value;
					}
					result.requires_output(std::move(output));

					auto change_output = coin_utxo(wallet_link(possible_inputs->front().link), string(), (uint32_t)result.outputs.size(), decimal(remaining_value - total_value));
					for (auto& token : change_tokens)
					{
						if (token.second.validate() && token.second.value.is_positive())
							change_output.apply_token_value(token.second.contract_address, token.second.symbol, token.second.value, token.second.decimals);
					}

					if (change_output.value.is_positive() || !change_output.tokens.empty())
					{
						auto min_change_output_value = get_min_protocol_value_per_output(change_output.tokens.size());
						if (change_output.value < min_change_output_value)
						{
							if (!change_output.tokens.empty())
							{
								if (!additional_value)
								{
									additional_value = min_change_output_value - change_output.value;
									goto retry_with_fee;
								}

								return expects_rt<prepared_transaction>(remote_exception(stringify::text("insufficient funds: %s < %s (change value is less than minimum required by protocol)", change_output.value.to_string().c_str(), min_change_output_value.to_string().c_str())));
							}

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
						Cardano::Transaction builder = Cardano::Transaction();
						uint8_t dummy_signature[XVK_LENGTH] = { 1 };
						uint8_t dummy_public_key[BLAKE256_LENGTH] = { 1 };
						uint8_t dummy_private_key[XSK_LENGTH] = { 1 };
						for (auto& finalized_input : *possible_inputs)
						{
							builder.Body.TransactionInput.addInput(to_unprefixed_hex(finalized_input.transaction_id), finalized_input.index);
							if (!fee)
							{
								crypto::fill_random_bytes(dummy_public_key, sizeof(dummy_public_key));
								builder.addExtendedVerifyingKey(dummy_public_key, dummy_signature);
							}
							else
								builder.addExtendedSigningKey(dummy_private_key);
						}
						for (auto& finalized_output : result.outputs)
						{
							builder.Body.TransactionOutput.addOutput(copy<std::string>(finalized_output.link.address), (uint64_t)to_lovelace(finalized_output.value));
							for (auto& [token_hash, token] : finalized_output.tokens)
								builder.Body.TransactionOutput.addAsset(to_unprefixed_hex(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
						}
						builder.Body.addFee((uint64_t)to_lovelace(fee_value));

						std::vector<Cardano::Transaction::Digest> digests;
						auto& raw_tx_data = builder.build(&digests);
						uint64_t tx_size = raw_tx_data.size() + 8;
						if (!fee || fee->second < tx_size)
						{
							uint64_t lovelace_fee = PROTOCOL_FEE_FIXED + PROTOCOL_FEE_PER_BYTE * tx_size;
							fee = std::make_pair(computed_fee::flat_fee(lovelace_fee / netdata.divisibility), tx_size);
							goto retry_with_fee;
						}

						for (size_t i = 0; i < digests.size(); i++)
						{
							auto& digest = digests[i];
							auto& input = possible_inputs->at(i);
							auto signing_public_key = decode_public_key(input.link.public_key);
							if (!signing_public_key)
								return expects_rt<prepared_transaction>(remote_exception(std::move(signing_public_key.error().message())));

							auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*signing_public_key);
							result.requires_input(algorithm::composition::type::ed25519, public_key, digest.Hash, sizeof(digest.Hash), std::move(input));
						}

						return expects_rt<prepared_transaction>(std::move(result));
					}
					catch (const std::invalid_argument& error)
					{
						return expects_rt<prepared_transaction>(remote_exception("tx serialization error: " + string(error.what())));
					}
					catch (...)
					{
						return expects_rt<prepared_transaction>(remote_exception("tx serialization error"));
					}
				});
			}
			expects_lr<finalized_transaction> cardano::finalize_transaction(superchain::prepared_transaction&& prepared)
			{
				if (prepared.abi.size() != 1)
					return layer_exception("invalid prepared abi");

				auto fee_value = prepared.abi.front().as_uint64();
				try
				{
					Cardano::Transaction verifier = Cardano::Transaction();
					uint8_t dummy_private_key[XSK_LENGTH] = { 0 };
					for (auto& input : prepared.inputs)
					{
						verifier.Body.TransactionInput.addInput(to_unprefixed_hex(input.utxo.transaction_id), input.utxo.index);
						verifier.addExtendedSigningKey(dummy_private_key);
					}
					for (auto& output : prepared.outputs)
					{
						verifier.Body.TransactionOutput.addOutput(copy<std::string>(output.link.address), (uint64_t)to_lovelace(output.value));
						for (auto& [token_hash, token] : output.tokens)
							verifier.Body.TransactionOutput.addAsset(to_unprefixed_hex(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					verifier.Body.addFee(fee_value);

					std::vector<Cardano::Transaction::Digest> digests;
					verifier.build(&digests);

					size_t index = 0;
					for (auto& input : prepared.inputs)
					{
						auto& digest = digests[index++];
						if (input.message.size() != sizeof(digest.Hash) || memcmp(input.message.data(), digest.Hash, sizeof(digest.Hash)) != 0)
							return layer_exception("invalid input message");
					}

					Cardano::Transaction builder = Cardano::Transaction();
					for (auto& input : prepared.inputs)
					{
						auto raw_public_key = decode_public_key(input.utxo.link.public_key);
						if (!raw_public_key)
							return raw_public_key.error();

						uint8_t signature[64] = { 0 };
						memcpy(signature, input.signature.data(), std::min(sizeof(signature), input.signature.size()));
						builder.Body.TransactionInput.addInput(to_unprefixed_hex(input.utxo.transaction_id), input.utxo.index);
						builder.addExtendedVerifyingKey((uint8_t*)raw_public_key->data(), signature);
					}
					for (auto& output : prepared.outputs)
					{
						builder.Body.TransactionOutput.addOutput(copy<std::string>(output.link.address), (uint64_t)to_lovelace(output.value));
						for (auto& [token_hash, token] : output.tokens)
							builder.Body.TransactionOutput.addAsset(to_unprefixed_hex(token.contract_address), copy<std::string>(token.symbol), (uint64_t)uint256_t((token.value * token.get_divisibility()).truncate(0).to_string()));
					}
					builder.Body.addFee(fee_value);

					uint8_t raw_transaction_id[BLAKE256_LENGTH];
					auto raw_tx_data = builder.build(nullptr);
					auto& raw_body_data = builder.Body.getcbor_afterBuild();
					crypto_generichash_blake2b(raw_transaction_id, sizeof(raw_transaction_id), raw_body_data.data(), raw_body_data.size(), nullptr, 0);

					auto result = finalized_transaction(std::move(prepared), codec::hex_encode(std::string_view((const char*)raw_tx_data.data(), raw_tx_data.size())), codec::hex_encode(std::string_view((const char*)raw_transaction_id, sizeof(raw_transaction_id))));
					auto validation = result.validate();
					if (!validation)
						return validation.error();

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
				if (!Cardano::bech32_encode(data.view.size() == XSK_LENGTH ? "addr_xsk" : "ed25519e_sk", data.buffer, (uint16_t)data.view.size(), encoded_private_key))
					return layer_exception("invalid decoded private key");

				return secret_box::secure(encoded_private_key);
			}
			expects_lr<secret_box> cardano::decode_secret_key(const secret_box& secret_key)
			{
				auto data = secret_key.expose<KEY_LIMIT>();
				uint8_t decoded_private_key[XSK_LENGTH]; uint16_t decoded_private_key_size = sizeof(decoded_private_key);
				if (!Cardano::bech32_decode_extended(data.view.data(), decoded_private_key, &decoded_private_key_size, sizeof(decoded_private_key)))
					return layer_exception("invalid encoded private key");
				else if (decoded_private_key_size != XSK_LENGTH && decoded_private_key_size != 64)
					return layer_exception("invalid decoded private key size");

				return secret_box::secure(std::string_view((char*)decoded_private_key, decoded_private_key_size));
			}
			expects_lr<string> cardano::encode_public_key(const std::string_view& public_key)
			{
				std::string encoded_public_key;
				if (!Cardano::bech32_encode("addr_xvk", (uint8_t*)public_key.data(), (uint16_t)public_key.size(), encoded_public_key))
					return layer_exception("invalid decoded public key");

				return copy<string>(encoded_public_key);
			}
			expects_lr<string> cardano::decode_public_key(const std::string_view& public_key)
			{
				uint8_t decoded_public_key[XVK_LENGTH];
				uint16_t decoded_public_key_size = sizeof(decoded_public_key);
				if (!Cardano::bech32_decode_extended(public_key.data(), decoded_public_key, &decoded_public_key_size, sizeof(decoded_public_key)))
					return layer_exception("invalid encoded public key");
				else if (decoded_public_key_size != XVK_LENGTH && decoded_public_key_size != 32)
					return layer_exception("invalid decoded public key size");

				return string((char*)decoded_public_key, decoded_public_key_size);
			}
			expects_lr<string> cardano::encode_address(const std::string_view& public_key_hash)
			{
				std::string encoded_address;
				if (!Cardano::bech32_encode(protocol::now().is(network_type::mainnet) ? "addr" : "addr_test", (uint8_t*)public_key_hash.data(), (uint16_t)public_key_hash.size(), encoded_address))
					return layer_exception("invalid decoded public key hash");

				return copy<string>(encoded_address);
			}
			expects_lr<string> cardano::decode_address(const std::string_view& address)
			{
				uint8_t data[256]; uint16_t data_size = sizeof(data); auto copy = string(address);
				if (!Cardano::bech32_decode_extended(copy.c_str(), data, &data_size, sizeof(data)))
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
				const auto network = (protocol::now().is(network_type::mainnet) ? Cardano::Network::Mainnet : Cardano::Network::Testnet);
				if (raw_public_key.size() != XVK_LENGTH)
				{
					uint8_t extended_public_key[XVK_LENGTH] = { 0 };
					memcpy(extended_public_key, (uint8_t*)raw_public_key.data(), raw_public_key.size());
					Cardano::getBech32Address(Cardano::InputKey::AccountKey_xvk, extended_public_key, network, Cardano::Wallet::HD, Cardano::Address::Enterprise_Extern, 0, 0, address);
				}
				else
					Cardano::getBech32Address(Cardano::InputKey::AccountKey_xvk, (uint8_t*)raw_public_key.data(), network, Cardano::Wallet::HD, Cardano::Address::Enterprise_Extern, 0, 0, address);

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
