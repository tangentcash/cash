#include "monero.h"
#include "../policy/compositions.h"
#include "../internal/bpp.h"
#include <random>
#include <sodium.h>
extern "C"
{
#include "../internal/monero.h"
}

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			using unsigned_transaction = compositions::ed25519_clsag_compositor::clsag_message;
			using cryptonote = compositions::ed25519_clsag_compositor;

			static void pack_prev_out(coin_utxo& out, const unsigned_transaction::txin_to_key::out& value)
			{
				uint8_t message[72]; uint64_t index = os::hw::to_endianness(os::hw::endian::little, value.index);
				memcpy(message + 00, value.commitment_mask, sizeof(value.commitment_mask));
				memcpy(message + 32, value.derivation_scalar, sizeof(value.derivation_scalar));
				memcpy(message + 64, &index, sizeof(index));
				out.extra.assign((char*)message, sizeof(message));
			}
			static option<unsigned_transaction::txin_to_key::out> unpack_prev_out(const coin_utxo& in)
			{
				if (in.extra.size() != 72)
					return optional::none;

				unsigned_transaction::txin_to_key::out result;
				memcpy(result.commitment_mask, in.extra.data() + 00, sizeof(result.commitment_mask));
				memcpy(result.derivation_scalar, in.extra.data() + 32, sizeof(result.derivation_scalar));
				memcpy(&result.index, in.extra.data() + 64, sizeof(result.index));
				result.index = os::hw::to_endianness(os::hw::endian::little, result.index);
				return result;
			}
			static bool is_subaddress(const std::string_view& decoded_public_key)
			{
				if (decoded_public_key.size() != 65)
					return false;

				uint8_t network_tag = (uint8_t)decoded_public_key[64];
				return network_tag == 0x2a || network_tag == 0x24 || network_tag == 0x3f;
			}

			const char* monero::nd_call::json_rpc()
			{
				return "/json_rpc";
			}
			const char* monero::nd_call::send_raw_transaction()
			{
				return "/send_raw_transaction";
			}
			const char* monero::nd_call::get_transactions()
			{
				return "/get_transactions";
			}
			const char* monero::nd_call::get_height()
			{
				return "/get_height";
			}
			const char* monero::nd_call::get_block()
			{
				return "getblock";
			}
			const char* monero::nd_call::get_output_distribution()
			{
				return "get_output_distribution";
			}
			const char* monero::nd_call::get_outs()
			{
				return "/get_outs";
			}
			const char* monero::nd_call::get_fee_estimate()
			{
				return "get_fee_estimate";
			}
			const char* monero::nd_call::get_o_indexes()
			{
				return "/get_o_indexes.bin";
			}

			monero::monero(const algorithm::asset_id& new_asset) noexcept : utxo_translation_unit(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519_clsag;
				netdata.routing = routing_policy::utxo;
				netdata.tokenization = token_policy::none;
				netdata.sync_latency = 20;
				netdata.divisibility = algorithm::arithmetic::fixed(1000000000000);
				netdata.transaction_expires = false;
			}
			expects_promise_rt<vector<uint64_t>> monero::get_output_indices(const std::string_view& transaction_id)
			{
				string request = codec::hex_decode(stringify::text("0111010101010201010404747869640a80%.*s", (int)transaction_id.size(), transaction_id.data()));
				return execute_http("POST", nd_call::get_o_indexes(), "application/octet-stream", request, cache_policy::blob_cache).then<expects_rt<vector<uint64_t>>>([](expects_rt<format::tree>&& response) -> expects_rt<vector<uint64_t>>
				{
					if (!response)
						return expects_rt<vector<uint64_t>>(response.error());

					auto begin_message = std::string_view("o_indexes");
					auto end_message = std::string_view("status");
					auto message = response->value.as_string();
					auto begin = message.find(begin_message), end = message.find(end_message);
					if (begin == std::string::npos || end == std::string::npos)
						return expects_rt<vector<uint64_t>>(vector<uint64_t>());

					begin += begin_message.size() + 2; end -= 1;
					if (begin >= end)
						return expects_rt<vector<uint64_t>>(vector<uint64_t>());

					begin += (end - begin) % sizeof(uint64_t);
					auto size = (end - begin) / sizeof(uint64_t);
					vector<uint64_t> result;
					result.reserve(size);

					for (size_t i = 0; i < size; i++)
					{
						uint64_t index;
#ifdef VI_ENDIAN_BIG
						auto copy = string(message.substr(begin + sizeof(uint64_t) * i, sizeof(uint64_t)));
						std::reverse(copy.begin(), copy.end());
						memcpy(&index, copy.data(), copy.size());
#else
						auto copy = message.substr(begin + sizeof(uint64_t) * i, sizeof(uint64_t));
						memcpy(&index, copy.data(), copy.size());
#endif
						result.push_back(index);
					}

					return expects_rt<vector<uint64_t>>(std::move(result));
				});
			}
			expects_promise_rt<uint64_t> monero::get_latest_block_height()
			{
				return execute_rest("POST", nd_call::get_height(), format::tree(), cache_policy::no_cache).then<expects_rt<uint64_t>>([](expects_rt<format::tree>&& height) -> expects_rt<uint64_t>
				{
					if (!height)
						return expects_rt<uint64_t>(height.error());

					uint64_t block_height = height->child_var("height").as_uint64();
					return expects_rt<uint64_t>(block_height > 1 ? block_height - 1 : 1);
				});
			}
			expects_promise_rt<vector<block_log>> monero::get_block_transactions(uint64_t block_height, uint64_t block_count)
			{
				return coasync<expects_rt<vector<block_log>>>([this, block_height, block_count]() -> expects_promise_rt<vector<block_log>>
				{
					format::tree map;
					for (uint64_t i = 0; i < block_count; i++)
					{
						format::tree args;
						args.set("height", format::variable(block_height));
						args.set("fill_pow_hash", format::variable(true));
						map.push(std::move(args));
					}

					auto block_data = coawait(execute_rpc_multi(nd_call::get_block(), std::move(map), cache_policy::temporary_cache, nd_call::json_rpc()));
					if (!block_data)
						coreturn block_data.error();

					vector<block_log> results;
					for (auto& block : block_data->childs())
					{
						auto block_blob = format::tree::from_json(block.child_var("json").as_blob());
						if (!block_blob)
							coreturn expects_rt<vector<block_log>>(remote_exception(std::move(block_blob.error().message())));

						auto transaction_data = format::tree::list();
						auto miner_tx = (format::tree*)block_blob->child("miner_tx");
						if (miner_tx != nullptr)
						{
							miner_tx->set("hash", block.child_var("block_header.miner_tx_hash"));
							transaction_data.push(std::move(*miner_tx));
						}

						auto transaction_hashes = (format::tree*)block_blob->child("tx_hashes");
						if (transaction_hashes != nullptr && !transaction_hashes->childs().empty())
						{
							auto args = format::tree::map();
							args.set("txs_hashes", std::move(*transaction_hashes));
							args.set("decode_as_json", format::variable(true));
							args.set("prune", format::variable(true));

							auto transactions = coawait(execute_rest("POST", nd_call::get_transactions(), std::move(args), cache_policy::blob_cache));
							if (transactions)
							{
								auto* list = transactions->child("txs");
								if (list != nullptr)
								{
									size_t offset = transaction_data.childs().size();
									for (auto& transaction : list->childs())
									{
										auto transaction_blob = format::tree::from_json(transaction.child_var("as_json").as_blob());
										if (transaction_blob)
										{
											transaction_blob->set("hash", transaction.child_var("tx_hash"));
											transaction_data.push(*transaction_blob);
										}
									}
								}
							}
						}

						auto& log = results.emplace_back();
						log.block_hash = block.child_var("block_header.hash").as_blob();
						log.transactions = std::move(transaction_data);
						if (log.block_hash.empty())
							log.block_hash = to_string(block_height + results.size() - 1);
					}
					coreturn expects_rt<vector<block_log>>(std::move(results));
				});
			}
			expects_promise_rt<coin_utxo> monero::get_transaction_output(const std::string_view& transaction_id, uint64_t index)
			{
				auto result = get_utxo(transaction_id, index);
				if (!result)
					return expects_promise_rt<coin_utxo>(remote_exception(std::move(result.error().message())));

				return expects_promise_rt<coin_utxo>(std::move(*result));
			}
			expects_promise_rt<computed_transaction> monero::link_transaction(uint64_t, const std::string_view&, format::tree& transaction_data)
			{
				return coasync<expects_rt<computed_transaction>>([this, &transaction_data]() -> expects_promise_rt<computed_transaction>
				{
					auto pseudo = decode_pseudo_transaction(transaction_data);
					size_t offset = 0, count = 64;
					hash_set<size_t> unresolved_outputs;
					unresolved_outputs.reserve(pseudo.outputs.size());
					for (size_t i = 0; i < pseudo.outputs.size(); i++)
						unresolved_outputs.insert(i);

					computed_transaction result;
					result.transaction_id = pseudo.hash;

					auto* offchain = superchain::bridge::get();
					for (auto& input : pseudo.inputs)
					{
						if (input.is_coinbase)
							continue;

						auto ref = offchain->load_cache(native_asset, cache_policy::lifetime_cache, string("K").append(codec::base64_encode(std::string_view((char*)input.key_image, sizeof(input.key_image)))));
						if (!ref)
							continue;

						auto buffer = ref->value.as_blob();
						auto message = format::ro_stream(buffer);
						if (!ref)
							continue;

						auto transaction_id = string(); auto index = uint64_t(0);
						if (!message.read_string(message.read_type(), &transaction_id) || !message.read_integer(message.read_type(), &index))
							continue;

						auto utxo = get_utxo(transaction_id, index, false);
						if (!utxo)
							continue;

						if (!utxo->link.address.empty())
							result.signers.insert(utxo->link.address);
						result.add_input(std::move(*utxo));
					}

					while (true)
					{
						auto links = find_linked_addresses(0, offset, count);
						if (!links)
							coreturn expects_rt<computed_transaction>(remote_exception(std::move(links.error().message())));

						for (auto& link : *links)
						{
							auto public_spend_view_key = decode_public_key(link.second.public_key);
							if (!public_spend_view_key)
								continue;

							uint8_t private_view_key[32];
							uint8_t* public_spend_key = (uint8_t*)public_spend_view_key->data();
							cryptonote::derive_known_private_view_key(public_spend_key, private_view_key);
							for (auto& transaction_public_key : pseudo.public_keys)
							{
								uint8_t derivation_key[32];
								if (!cryptonote::generate_derivation_key(transaction_public_key.blob, private_view_key, derivation_key))
									continue;

								for (size_t i = 0; i < pseudo.outputs.size(); i++)
								{
									if (unresolved_outputs.find(i) == unresolved_outputs.end())
										continue;

									uint8_t output_scalar[32];
									cryptonote::derivation_to_scalar(derivation_key, (uint64_t)i, output_scalar);

									uint8_t output_public_key[32];
									if (!cryptonote::derive_public_key(output_scalar, public_spend_key, output_public_key))
										continue;

									auto& output = pseudo.outputs[i];
									if (memcmp(output_public_key, output.key, sizeof(output.key)) != 0)
										continue;

									unsigned_transaction::txin_to_key::out out;
									memset(out.commitment_mask, 0, sizeof(out.commitment_mask));
									memcpy(out.derivation_scalar, output_scalar, sizeof(output_scalar));
									out.index = 0;

									decimal value;
									if (!output.ecdh_amount.empty())
									{
										uint8_t mask[32] = { 0 }, amount[32] = { 0 };
										size_t amount_size = sizeof(amount);
										if (output.ecdh_mask.empty())
										{
											char mask_tag[] = "commitment_mask";
											constexpr size_t mask_tag_size = sizeof(mask_tag) - 1;
											uint8_t mask_commitment[mask_tag_size + sizeof(output_scalar)];
											memcpy(mask_commitment, mask_tag, mask_tag_size);
											memcpy(mask_commitment + mask_tag_size, output_scalar, sizeof(output_scalar));
											cryptonote::hash_to_scalar(mask_commitment, sizeof(mask_commitment), mask);

											char amount_tag[] = "amount";
											constexpr size_t amount_tag_size = sizeof(amount_tag) - 1;
											uint8_t amount_commitment[amount_tag_size + sizeof(output_scalar)];
											memcpy(amount_commitment, amount_tag, amount_tag_size);
											memcpy(amount_commitment + amount_tag_size, output_scalar, sizeof(output_scalar));
											xmr_fast_hash(amount, amount_commitment, sizeof(amount_commitment));

											amount_size = std::min<size_t>(output.ecdh_amount.size(), sizeof(uint64_t));
											for (size_t j = 0; j < amount_size; j++)
												amount[j] ^= (uint8_t)output.ecdh_amount[j];
											for (size_t j = amount_size; j < sizeof(amount); j++)
												amount[j] = 0;
										}
										else
										{
											uint8_t ecdh_mask[32] = { 0 }, ecdh_amount[32] = { 0 };
											memcpy(ecdh_mask, output.ecdh_mask.data(), std::min(sizeof(ecdh_mask), output.ecdh_mask.size()));
											memcpy(ecdh_amount, output.ecdh_amount.data(), std::min(sizeof(ecdh_amount), output.ecdh_amount.size()));

											uint8_t mask_scalar[32], amount_scalar[32];
											cryptonote::hash_to_scalar(output_scalar, sizeof(output_scalar), mask_scalar);
											cryptonote::hash_to_scalar(mask_scalar, sizeof(mask_scalar), amount_scalar);

											sc_sub(mask, ecdh_mask, mask_scalar);
											sc_sub(amount, ecdh_amount, amount_scalar);
										}

										uint8_t ring_out_key[32];
										if (!cryptonote::pedersen_commit(mask, amount, ring_out_key))
											continue;
										else if (memcmp(ring_out_key, output.ring_out_key, sizeof(output.ring_out_key)) != 0)
											continue;

										std::array<uint8_t, 32> swap_amount = { 0 };
										memcpy(swap_amount.data(), amount, amount_size);
										std::reverse(swap_amount.begin(), swap_amount.end());
										memcpy(out.commitment_mask, mask, sizeof(mask));

										uint256_t value256 = uint256_t(codec::hex_encode(std::string_view((char*)swap_amount.data(), swap_amount.size())), 16);
										value = from_baseline_value(value256);
									}
									else
										value = from_baseline_value(output.amount);

									coin_utxo new_output;
									new_output.transaction_id = result.transaction_id;
									new_output.link = link.second;
									new_output.value = std::move(value);
									new_output.index = (uint64_t)i;
									pack_prev_out(new_output, out);
									result.add_output(std::move(new_output));
									unresolved_outputs.erase(i);
								}
							}

							if (unresolved_outputs.empty())
								break;
						}

						offset += links->size();
						if (links->size() != count || unresolved_outputs.empty())
							break;
					}

					if (result.inputs.empty() && result.outputs.empty())
						coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

					auto indices = coawait(get_output_indices(result.transaction_id));
					if (!indices)
						coreturn expects_rt<computed_transaction>(indices.error());

					for (auto& [hash, output] : result.outputs)
					{
						auto out = output.index < indices->size() ? unpack_prev_out(output) : option<unsigned_transaction::txin_to_key::out>(optional::none);
						if (out)
						{
							out->index = indices->at(output.index);
							pack_prev_out(output, *out);
						}
					}

					decimal sending_value = decimal::zero();
					decimal receiving_value = decimal::zero();
					for (auto& [hash, input] : result.inputs)
						sending_value += input.value;
					for (auto& [hash, output] : result.outputs)
						receiving_value += output.value;

					uint8_t null_key[64] = { 0 };
					if (sending_value < receiving_value)
					{
						coin_utxo new_input;
						new_input.transaction_id = algorithm::asset::handle_of(native_asset);
						new_input.index = std::numeric_limits<uint32_t>::max();
						new_input.link = wallet_link::from_address(encode_address(std::string_view((char*)null_key, sizeof(null_key))).or_else(string()));
						new_input.value = pseudo.fee + receiving_value - sending_value;
						result.add_input(std::move(new_input));
					}
					else if (sending_value > receiving_value)
					{
						coin_utxo new_output;
						new_output.transaction_id = algorithm::asset::handle_of(native_asset);
						new_output.index = std::numeric_limits<uint32_t>::max();
						new_output.value = sending_value - receiving_value - pseudo.fee;
						auto ref = offchain->load_cache(native_asset, cache_policy::lifetime_cache, string("T").append(result.transaction_id));
						auto to_address = ref ? ref->value.as_blob() : string();
						if (!to_address.empty() && decode_address(to_address))
						{
							auto to_link = find_linked_addresses({ to_address });
							new_output.link = to_link ? std::move(to_link->begin()->second) : wallet_link::from_address(to_address);
						}
						else
							new_output.link = wallet_link::from_address(encode_address(std::string_view((char*)null_key, sizeof(null_key))).or_else(string()));
						result.add_output(std::move(new_output));
					}
					coreturn expects_rt<computed_transaction>(std::move(result));
				});
			}
			expects_promise_rt<void> monero::broadcast_transaction(const finalized_transaction& finalized)
			{
				auto args = format::tree::map();
				args.set("tx_as_hex", format::variable(format::util::clear_0xhex(finalized.calldata)));
				return execute_rest("POST", nd_call::send_raw_transaction(), std::move(args), cache_policy::no_cache).then<expects_rt<void>>([](expects_rt<format::tree>&& hex_data) -> expects_rt<void>
				{
					if (!hex_data)
						return expects_rt<void>(hex_data.error());

					bool double_spend = hex_data->child_var("double_spend").as_boolean();
					bool fee_too_low = hex_data->child_var("fee_too_low").as_boolean();
					bool invalid_input = hex_data->child_var("invalid_input").as_boolean();
					bool invalid_output = hex_data->child_var("invalid_output").as_boolean();
					bool low_mixin = hex_data->child_var("low_mixin").as_boolean();
					bool nonzero_unlock_time = hex_data->child_var("nonzero_unlock_time").as_boolean();
					bool not_relayed = hex_data->child_var("not_relayed").as_boolean();
					bool overspend = hex_data->child_var("overspend").as_boolean();
					bool sanity_check_failed = hex_data->child_var("sanity_check_failed").as_boolean();
					bool too_big = hex_data->child_var("too_big").as_boolean();
					bool too_few_outputs = hex_data->child_var("too_few_outputs").as_boolean();
					bool tx_extra_too_big = hex_data->child_var("tx_extra_too_big").as_boolean();
					if (double_spend)
						return expects_rt<void>(remote_exception("transaction double spends inputs"));
					else if (fee_too_low)
						return expects_rt<void>(remote_exception("transaction fee is too low"));
					else if (invalid_input)
						return expects_rt<void>(remote_exception("transaction uses invalid input"));
					else if (invalid_output)
						return expects_rt<void>(remote_exception("transaction uses invalid output"));
					else if (low_mixin)
						return expects_rt<void>(remote_exception("transaction mixin count is too low"));
					else if (nonzero_unlock_time)
						return expects_rt<void>(remote_exception("transaction unlock time is invalid"));
					else if (not_relayed)
						return expects_rt<void>(remote_exception("transaction failed to relay"));
					else if (overspend)
						return expects_rt<void>(remote_exception("transaction overspends inputs"));
					else if (sanity_check_failed)
						return expects_rt<void>(remote_exception("transaction sanity check failed"));
					else if (too_big)
						return expects_rt<void>(remote_exception("transaction is too big"));
					else if (too_few_outputs)
						return expects_rt<void>(remote_exception("transaction has too few outputs"));
					else if (tx_extra_too_big)
						return expects_rt<void>(remote_exception("transaction extra is too big"));

					auto status = hex_data->child_var("status").as_blob();
					auto reason = hex_data->child_var("reason").as_blob();
					if (status != "OK")
						return expects_rt<void>(remote_exception(reason.empty() ? "send transaction failed" : reason));

					return expects_rt<void>(expectation::met);
				});
			}
			expects_promise_rt<prepared_transaction> monero::prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
			{
				return coasync<expects_rt<prepared_transaction>>([this, from_link, to, max_fee]() -> expects_promise_rt<prepared_transaction>
				{
					format::tree args;
					args.set("grace_blocks", format::variable((uint8_t)10));

					auto fee_estimate = coawait(execute_rpc(nd_call::get_fee_estimate(), std::move(args), cache_policy::no_cache_no_throttling, nd_call::json_rpc()));
					if (!fee_estimate)
						coreturn expects_rt<prepared_transaction>(fee_estimate.error());

					size_t inputs_count = 0;
					uint256_t avg_fee_per_byte = fee_estimate->child_var("fee").as_uint256();
					uint256_t slow_fee_per_byte = fee_estimate->child_var("fees.0").as_uint256();
					uint256_t normal_fee_per_byte = fee_estimate->child_var("fees.1").as_uint256();
					uint256_t fee_per_byte = std::max(std::max(avg_fee_per_byte, slow_fee_per_byte), normal_fee_per_byte);
				recalculate_fee:
					uint256_t fee_per_tx = fee_per_byte * uint256_t(776 + inputs_count * 771);
					decimal fee_value = from_atomic(fee_per_tx);
					if (fee_value > max_fee)
						coreturn expects_rt<prepared_transaction>(remote_exception(stringify::text("fee limit overflow: %s (max: %s)", fee_value.to_string().c_str(), max_fee.to_string().c_str())));

					decimal total_value = to.value + fee_value;
					auto possible_inputs = calculate_utxo(from_link, balance_query(total_value, { }), true);
					decimal input_value = possible_inputs ? get_utxo_value(*possible_inputs, optional::none) : 0.0;
					if (!possible_inputs || possible_inputs->empty())
					{
						auto unconfirmed_inputs = calculate_utxo(from_link, balance_query(total_value, { }), false);
						bool pending_confirmations = unconfirmed_inputs && !unconfirmed_inputs->empty();
						coreturn expects_rt<prepared_transaction>(pending_confirmations ? remote_exception::retry_later("awaiting utxo confirmation") : remote_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), total_value.to_string().c_str())));
					}

					if (inputs_count != possible_inputs->size())
					{
						inputs_count = possible_inputs->size();
						goto recalculate_fee;
					}

					auto to_public_spend_view_key = decode_address(to.address);
					if (!to_public_spend_view_key)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to decode to address"));

					auto change_link = possible_inputs->front().link;
					auto change_public_spend_view_key = decode_address(change_link.address);
					if (!change_public_spend_view_key)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to decode change address"));
					else if (is_subaddress(*change_public_spend_view_key))
						coreturn expects_rt<prepared_transaction>(remote_exception("invalid change address (must be standard address)"));

					uint8_t value256[32], link256[32], input256[32];
					to_atomic(total_value).encode(value256);
					from_link.as_hash(true).encode(link256);

					vector<uint8_t> seed;
					seed.insert(seed.end(), value256, value256 + 32);
					seed.insert(seed.end(), link256, link256 + 32);
					seed.insert(seed.end(), (uint8_t*)to_public_spend_view_key->data(), (uint8_t*)to_public_spend_view_key->data() + 64);
					seed.insert(seed.end(), (uint8_t*)change_public_spend_view_key->data(), (uint8_t*)change_public_spend_view_key->data() + 64);
					for (auto& input : *possible_inputs)
					{
						input.as_hash(true).encode(input256);
						seed.insert(seed.end(), input256, input256 + 32);
					}

					unsigned_transaction tx;
					cryptonote::hash_to_scalar(seed.data(), seed.size(), tx.tx_key);
					tx.fee = (uint64_t)to_atomic(fee_value);
					tx.extra.resize(33, TX_EXTRA_TAG_PUBKEY);
					sc_mul_g(tx.extra.data() + 1, tx.tx_key);
					if (is_subaddress(*to_public_spend_view_key))
					{
						uint8_t additional_pubkeys[34] = { TX_EXTRA_TAG_ADDITIONAL_PUBKEYS, 1 };
						ge_scalarmult_s(additional_pubkeys + 2, (uint8_t*)to_public_spend_view_key->data(), tx.tx_key);
						tx.extra.insert(tx.extra.end(), additional_pubkeys, additional_pubkeys + sizeof(additional_pubkeys));
					}

					auto make_vout = [&](size_t index, const std::string_view& public_spend_view_key, const decimal& value) -> option<unsigned_transaction::tx_out>
					{
						uint8_t derivation_key[32];
						if (!cryptonote::generate_derivation_key((uint8_t*)public_spend_view_key.data() + 32, tx.tx_key, derivation_key))
							return optional::none;

						uint8_t output_scalar[32];
						cryptonote::derivation_to_scalar(derivation_key, (uint64_t)index, output_scalar);

						unsigned_transaction::tx_out vout;
						vout.target.tag = cryptonote::derivation_to_view_tag(derivation_key, (uint64_t)index);
						if (!cryptonote::derive_public_key(output_scalar, (uint8_t*)public_spend_view_key.data(), vout.target.key))
							return optional::none;

						char mask_tag[] = "commitment_mask";
						constexpr size_t mask_tag_size = sizeof(mask_tag) - 1;
						uint8_t mask_commitment[mask_tag_size + sizeof(output_scalar)];
						memcpy(mask_commitment, mask_tag, mask_tag_size);
						memcpy(mask_commitment + mask_tag_size, output_scalar, sizeof(output_scalar));
						cryptonote::hash_to_scalar(mask_commitment, sizeof(mask_commitment), vout.out_pk.blinding_factor);

						char amount_tag[] = "amount";
						constexpr size_t amount_tag_size = sizeof(amount_tag) - 1;
						uint8_t amount_commitment[amount_tag_size + sizeof(output_scalar)];
						memcpy(amount_commitment, amount_tag, amount_tag_size);
						memcpy(amount_commitment + amount_tag_size, output_scalar, sizeof(output_scalar));

						uint8_t amount_hash[32];
						xmr_fast_hash(amount_hash, amount_commitment, sizeof(amount_commitment));
						cryptonote::encode_amount_256((uint64_t)to_atomic(value), vout.ecdh_info.amount);
						for (size_t j = 0; j < 8; j++)
							vout.ecdh_info.amount[j] ^= amount_hash[j];

						return option<unsigned_transaction::tx_out>(std::move(vout));
					};
					auto change_value = input_value - total_value;
					auto main_output = make_vout(0, *to_public_spend_view_key, to.value);
					auto change_output = make_vout(1, *change_public_spend_view_key, change_value);
					if (!main_output)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to build the main output"));
					else if (!change_output)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to build the change output"));

					auto block_height = coawait(get_latest_block_height());
					if (!block_height)
						coreturn block_height.error();

					uint64_t ring_size = 16;
					uint64_t total_ring_size = ring_size * possible_inputs->size();
					uint64_t min_total_ring_size = 1 + total_ring_size * 8 / 10;
					uint64_t lower_block_margin = 60 + total_ring_size;
					uint64_t upper_block_margin = 60;
					format::tree map;
					map.set("amounts", format::tree::list())->push(format::variable((uint8_t)0));
					map.set("from_height", format::variable(*block_height <= lower_block_margin ? 1 : *block_height - lower_block_margin));
					map.set("to_height", format::variable(*block_height <= upper_block_margin ? 1 : *block_height - upper_block_margin));
					map.set("cumulative", format::variable(true));
					map.set("binary", format::variable(false));

					auto decoy_outputs = coawait(execute_rpc(nd_call::get_output_distribution(), std::move(map), cache_policy::no_cache, nd_call::json_rpc()));
					if (!decoy_outputs)
						coreturn decoy_outputs.error();

					auto* decoy_outputs_distribution = decoy_outputs->child("distributions.0.distribution");
					if (!decoy_outputs_distribution)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to find any decoy outputs"));

					hash_set<uint64_t> unique_output_indices;
					for (auto& index : decoy_outputs_distribution->childs())
						unique_output_indices.insert(index.value.as_uint64());
					for (auto& utxo : *possible_inputs)
					{
						auto prev_out = unpack_prev_out(utxo);
						if (!prev_out)
							coreturn expects_rt<prepared_transaction>(remote_exception("failed to decode the input"));

						unique_output_indices.insert(prev_out->index);
					}

					if (unique_output_indices.size() < min_total_ring_size)
						coreturn expects_rt<prepared_transaction>(remote_exception("failed to find enough decoy outputs"));

					vector<uint64_t> output_indices;
					output_indices.assign(unique_output_indices.begin(), unique_output_indices.end());

					map = format::tree::map();
					auto* outputs_data = map.set("outputs", format::tree::list());
					for (auto& index : output_indices)
						outputs_data->push(format::tree::map())->set("index", format::variable(index));

					auto output_key_set = coawait(execute_rest("POST", nd_call::get_outs(), std::move(map), cache_policy::no_cache));
					if (!output_key_set)
						coreturn output_key_set.error();

					hash_map<uint64_t, std::pair<string, string>> output_keys;
					auto output_key_outs = output_key_set->child("outs");
					if (output_key_outs)
					{
						for (auto& item : output_key_outs->childs())
						{
							auto key = format::util::decode_0xhex(item.child_var("key").as_blob());
							auto mask = format::util::decode_0xhex(item.child_var("mask").as_blob());
							output_keys[output_indices[output_keys.size()]] = std::make_pair(std::move(key), std::move(mask));
						}
					}

					size_t output_indices_offset = 0;
					std::random_device random;
					std::mt19937_64 generator(random());
					std::shuffle(output_indices.begin(), output_indices.end(), generator);
					tx.vout.push_back(std::move(*main_output));
					tx.vout.push_back(std::move(*change_output));
					for (auto& utxo : *possible_inputs)
					{
						auto prev_out = unpack_prev_out(utxo);
						if (!prev_out)
							coreturn expects_rt<prepared_transaction>(remote_exception("failed to decode the input"));

						auto out = output_keys.find(prev_out->index);
						if (out == output_keys.end())
							coreturn expects_rt<prepared_transaction>(remote_exception("failed to find input index"));

						unique_output_indices.clear();
						unique_output_indices.insert(out->first);
						while (unique_output_indices.size() < ring_size)
							unique_output_indices.insert(output_indices[(output_indices_offset++) % output_indices.size()]);
		
						unsigned_transaction::txin_to_key vin;
						vin.prev_out = *prev_out;
						vin.keys.reserve(unique_output_indices.size());
						for (auto index : unique_output_indices)
						{
							unsigned_transaction::txin_to_key::ref ref;
							auto it = output_keys.find(index);
							if (it == output_keys.end() || it->second.first.size() != sizeof(ref.key) || it->second.second.size() != sizeof(ref.mask))
								coreturn expects_rt<prepared_transaction>(remote_exception("failed to bind input index"));

							memcpy(ref.key, it->second.first.data(), it->second.first.size());
							memcpy(ref.mask, it->second.second.data(), it->second.second.size());
							ref.index = index;
							ref.decoy = index != out->first;
							vin.keys.push_back(std::move(ref));
						}
						std::sort(vin.keys.begin(), vin.keys.end(), [](const unsigned_transaction::txin_to_key::ref& a, const unsigned_transaction::txin_to_key::ref& b)
						{
							return a.index < b.index;
						});

						auto intermediate_keys = vin.keys;
						for (size_t i = 1; i < vin.keys.size(); i++)
							vin.keys[i].index -= intermediate_keys[i - 1].index;

						tx.vin.push_back(vin);
					}

					try
					{
						xmr_bpp::seed_t seeder;
						memcpy(seeder.seed, tx.tx_key, sizeof(tx.tx_key));
						seeder.nonce = (uint64_t)(tx.as_hash() % uint256_t(std::numeric_limits<uint64_t>::max()));

						xmr_bpp::scalar_vec_t blinding_factors = { xmr_bpp::scalar_t(tx.vout[0].out_pk.blinding_factor), xmr_bpp::scalar_t(tx.vout[1].out_pk.blinding_factor) };
						std::vector<uint64_t> amounts = { (uint64_t)to_atomic(to.value), (uint64_t)to_atomic(change_value) };
						auto [proof, pedersen_commitments] = xmr_bpp::prove(seeder, amounts, blinding_factors);
						memcpy(tx.bpp.a, proof.A.b32, sizeof(proof.A.b32));
						memcpy(tx.bpp.a1, proof.A1.b32, sizeof(proof.A1.b32));
						memcpy(tx.bpp.b, proof.B.b32, sizeof(proof.B.b32));
						memcpy(tx.bpp.r1, proof.r1.b32, sizeof(proof.r1.b32));
						memcpy(tx.bpp.s1, proof.s1.b32, sizeof(proof.s1.b32));
						memcpy(tx.bpp.d1, proof.d1.b32, sizeof(proof.d1.b32));
						tx.bpp.l.resize(proof.L.size());
						tx.bpp.r.resize(proof.R.size());
						for (size_t i = 0; i < proof.L.size(); i++)
							memcpy(tx.bpp.l[i].data(), proof.L[i].b32, sizeof(proof.L[i].b32));
						for (size_t i = 0; i < proof.R.size(); i++)
							memcpy(tx.bpp.r[i].data(), proof.R[i].b32, sizeof(proof.R[i].b32));

						uint8_t sum_out[32] = { 0 };
						for (size_t i = 0; i < pedersen_commitments.size(); i++)
						{
							auto& vout = tx.vout[i];
							memcpy(vout.out_pk.mask, pedersen_commitments[i].b32, sizeof(vout.out_pk.mask));
							sc_add(sum_out, sum_out, vout.out_pk.blinding_factor);
						}

						uint8_t sum_in[32] = { 0 };
						for (size_t i = 0; i < tx.vin.size(); i++)
						{
							auto& vin = tx.vin[i];
							if (i < tx.vin.size() - 1)
							{
								crypto::fill_random_bytes(vin.pseudo_out.mask, sizeof(vin.pseudo_out.mask));
								cryptonote::hash_to_scalar(vin.pseudo_out.mask, sizeof(vin.pseudo_out.mask), vin.pseudo_out.mask);
								sc_add(sum_in, sum_in, vin.pseudo_out.mask);
							}
							else
								sc_sub(vin.pseudo_out.mask, sum_out, sum_in);

							uint8_t amount[32];
							cryptonote::encode_amount_256((uint64_t)to_atomic(possible_inputs->at(i).value), amount);
							if (!cryptonote::pedersen_commit(vin.pseudo_out.mask, amount, vin.pseudo_out.key))
								coreturn expects_rt<prepared_transaction>(remote_exception("failed to commit to vin amount"));
						}
					}
					catch (const std::exception& error)
					{
						coreturn expects_rt<prepared_transaction>(remote_exception(string("bulletproofs+ error: ") + string(error.what())));
					}

					algorithm::composition::shared_message shared;
					format::wo_stream message = tx.as_message();
					shared.checksum = message.hash();
					shared.message.resize(message.data.size());
					memcpy(shared.message.data(), message.data.data(), message.data.size());

					prepared_transaction result;
					result.requires_shared_message(shared);
					for (auto& utxo : *possible_inputs)
					{
						auto signing_public_key = decode_public_key(utxo.link.public_key);
						if (!signing_public_key)
							coreturn expects_rt<prepared_transaction>(remote_exception("invalid input public key"));

						auto public_key = algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(std::string_view(*signing_public_key).substr(0, 32));
						result.requires_shared_input(algorithm::composition::type::ed25519_clsag, public_key, std::move(utxo));
					}

					auto to_link = find_linked_addresses({ to.address });
					result.requires_output(coin_utxo(to_link ? std::move(to_link->begin()->second) : wallet_link::from_address(to.address), string(), 0, decimal(to.value)));
					if (change_value.is_positive())
						result.requires_output(coin_utxo(wallet_link(change_link), string(), 1, decimal(change_value)));
					coreturn expects_rt<prepared_transaction>(std::move(result));
				});
			}
			expects_lr<finalized_transaction> monero::finalize_transaction(prepared_transaction&& prepared)
			{
				auto shared = prepared.as_shared_message();
				if (!shared)
					return layer_exception("invalid prepared abi");

				unsigned_transaction tx;
				format::ro_stream message = format::ro_stream(std::string_view((char*)shared->message.data(), shared->message.size()));
				if (!tx.load(message) || tx.vin.size() != prepared.inputs.size() ||  prepared.outputs.size() > 2 || tx.vout.size() != 2)
					return layer_exception("invalid tx abi");

				unsigned_transaction checksum_tx = tx;
				for (auto& vin : checksum_tx.vin)
				{
					vin.clsag = unsigned_transaction::txin_to_key::sig();
					memset(vin.key_image, 0, sizeof(vin.key_image));
				}
				if (checksum_tx.as_hash(true) != shared->checksum)
					return layer_exception("invalid shared message");

				for (size_t i = 0; i < tx.vin.size(); i++)
				{
					auto& vin = tx.vin[i];
					auto& sig = prepared.inputs[i].signature;
					size_t offset = sizeof(vin.key_image) * 2 + sizeof(vin.clsag.c1) + sizeof(vin.clsag.d);
					size_t size = offset + sizeof(std::array<uint8_t, 32>) * vin.keys.size();
					if (sig.size() != size)
						return layer_exception("invalid signature");

					auto ring_member = std::find_if(vin.keys.begin(), vin.keys.end(), [](const unsigned_transaction::txin_to_key::ref& r) { return !r.decoy; });
					if (ring_member == vin.keys.end() || memcmp(ring_member->key, sig.data(), sizeof(ring_member->key)) != 0)
						return layer_exception("invalid ring member key");

					vin.clsag.s.resize(vin.keys.size());
					memcpy(vin.key_image, sig.data() + sizeof(vin.key_image), sizeof(vin.key_image));
					memcpy(vin.clsag.c1, sig.data() + sizeof(vin.key_image) * 2, sizeof(vin.clsag.c1));
					memcpy(vin.clsag.d, sig.data() + sizeof(vin.key_image) * 2 + sizeof(vin.clsag.c1), sizeof(vin.clsag.d));
					for (size_t i = 0; i < vin.clsag.s.size(); i++)
						memcpy(vin.clsag.s[i].data(), sig.data() + offset + sizeof(std::array<uint8_t, 32>) * i, vin.clsag.s[i].size());
				}

				uint8_t tx_id[32];
				vector<uint8_t> tx_data;
				tx.optimize_index(nullptr);
				tx.write_all(tx_data);
				tx.as_id_hash(tx_id);

				auto result = finalized_transaction(std::move(prepared), codec::hex_encode(std::string_view((char*)tx_data.data(), tx_data.size())), codec::hex_encode(std::string_view((char*)tx_id, sizeof(tx_id))));
				auto validation = result.validate();
				if (!validation)
					return validation.error();

				for (size_t i = 0; i < tx.vin.size(); i++)
				{
					auto& utxo = result.prepared.inputs[i];
					if (utxo.utxo.transaction_id.empty())
						return layer_exception("invalid input utxo");
				}

				return expects_lr<finalized_transaction>(std::move(result));
			}
			expects_lr<void> monero::update_utxo(const computed_transaction& computed, const finalized_transaction* finalized)
			{
				if (finalized)
				{
					auto shared = finalized->prepared.as_shared_message();
					if (shared)
					{
						unsigned_transaction tx;
						format::ro_stream message = format::ro_stream(std::string_view((char*)shared->message.data(), shared->message.size()));
						if (tx.load(message))
						{
							auto* offchain = superchain::bridge::get();
							for (size_t i = 0; i < tx.vin.size(); i++)
							{
								auto& utxo = finalized->prepared.inputs[i];
								if (!utxo.utxo.transaction_id.empty())
								{
									auto& vin = tx.vin[i];
									auto message = format::wo_stream();
									message.write_string(utxo.utxo.transaction_id);
									message.write_integer(utxo.utxo.index);
									offchain->store_cache(native_asset, cache_policy::lifetime_cache, string("K").append(codec::base64_encode(std::string_view((char*)vin.key_image, sizeof(vin.key_image)))), format::variable(message.data));
								}
							}
							offchain->store_cache(native_asset, cache_policy::lifetime_cache, string("T").append(finalized->hashdata), format::variable(finalized->prepared.outputs.front().link.address));
						}
					}
				}
				return utxo_translation_unit::update_utxo(computed, finalized);
			}
			expects_lr<secret_box> monero::encode_secret_key(const secret_box& secret_key)
			{
				if (secret_key.size() == 64)
				{
					auto data = secret_key.expose<KEY_LIMIT>();
					string private_spend_view_key = codec::hex_encode(data.view.substr(0, 32));
					private_spend_view_key.append(1, ':').append(codec::hex_encode(data.view.substr(32)));
					auto output = secret_box::secure(private_spend_view_key);
					sodium_memzero(private_spend_view_key.data(), private_spend_view_key.size());
					return output;
				}
				else if (secret_key.size() == 32)
				{
					uint8_t private_spend_key[32];
					auto data = secret_key.expose<KEY_LIMIT>();
					memcpy(private_spend_key, data.buffer, sizeof(private_spend_key));

					uint8_t public_spend_key[32];
					if (crypto_scalarmult_ed25519_base_noclamp(public_spend_key, private_spend_key) != 0)
					{
						sodium_memzero(private_spend_key, sizeof(private_spend_key));
						return layer_exception("not a valid private spend-view key");
					}

					uint8_t private_view_key[32];
					cryptonote::derive_known_private_view_key(public_spend_key, private_view_key);
					sodium_memzero(private_spend_key, sizeof(private_spend_key));

					string private_spend_view_key = codec::hex_encode(std::string_view((char*)private_spend_key, sizeof(private_spend_key)));
					private_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)private_view_key, sizeof(private_view_key))));
					auto output = secret_box::secure(private_spend_view_key);
					sodium_memzero(private_view_key, sizeof(private_view_key));
					sodium_memzero(private_spend_view_key.data(), private_spend_view_key.size());
					return output;
				}

				return layer_exception("private key is not a pair of private spend key and private view key");
			}
			expects_lr<secret_box> monero::decode_secret_key(const secret_box& secret_key)
			{
				auto signing_keypair = secret_key.expose<KEY_LIMIT>();
				uint8_t private_spend_key[32], private_view_key[32];
				size_t split = signing_keypair.view.find(':');
				auto raw_spend_key = codec::hex_decode(signing_keypair.view.substr(0, split));
				if (raw_spend_key.size() != 32)
					return layer_exception("not a valid hex private spend-view keypair");

				memcpy(private_spend_key, raw_spend_key.data(), sizeof(private_spend_key));
				auto raw_view_key = codec::hex_decode(signing_keypair.view.substr(split + 1));
				if (raw_view_key.size() != 32)
				{
					uint8_t public_spend_key[32];
					if (crypto_scalarmult_ed25519_base_noclamp(public_spend_key, private_spend_key) != 0)
						return layer_exception("not a valid private spend-view key");

					cryptonote::derive_known_private_view_key(public_spend_key, private_view_key);
				}
				else
					memcpy(private_view_key, raw_view_key.data(), sizeof(private_view_key));

				uint8_t private_spend_view_key[64] = { 0 };
				memcpy(private_spend_view_key, private_spend_key, sizeof(private_spend_key));
				memcpy(private_spend_view_key + 32, private_view_key, sizeof(private_view_key));
				return secret_box::secure(std::string_view((char*)private_spend_view_key, sizeof(private_spend_view_key)));
			}
			expects_lr<string> monero::encode_public_key(const std::string_view& public_key)
			{
				if (public_key.size() == 64)
				{
					string public_spend_view_key = codec::hex_encode(public_key.substr(0, 32));
					public_spend_view_key.append(1, ':').append(codec::hex_encode(public_key.substr(32)));
					return public_spend_view_key;
				}
				else if (public_key.size() == 32)
				{
					uint8_t public_spend_key[32];
					memcpy(public_spend_key, public_key.data(), sizeof(public_spend_key));

					uint8_t public_view_key[32];
					cryptonote::derive_known_public_view_key(public_spend_key, public_view_key);

					string public_spend_view_key = codec::hex_encode(std::string_view((char*)public_spend_key, sizeof(public_spend_key)));
					public_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)public_view_key, sizeof(public_view_key))));
					return public_spend_view_key;
				}

				return layer_exception("public key is not a pair of public spend key and public view key");
			}
			expects_lr<string> monero::decode_public_key(const std::string_view& public_key)
			{
				uint8_t public_spend_key[32], public_view_key[32];
				size_t split = public_key.find(':');
				auto raw_spend_key = codec::hex_decode(public_key.substr(0, split));
				if (raw_spend_key.size() != 32)
					return layer_exception("not a valid hex public spend-view keypair (expected format: public-spend-key:public-view-key)");

				memcpy(public_spend_key, raw_spend_key.data(), sizeof(public_spend_key));
				auto raw_view_key = codec::hex_decode(public_key.substr(split + 1));
				if (raw_view_key.size() != 32)
					cryptonote::derive_known_public_view_key(public_spend_key, public_view_key);
				else
					memcpy(public_view_key, raw_view_key.data(), sizeof(public_view_key));

				uint8_t public_spend_view_key[64] = { 0 };
				memcpy(public_spend_view_key, public_spend_key, sizeof(public_spend_key));
				memcpy(public_spend_view_key + 32, public_view_key, sizeof(public_view_key));
				return string((char*)public_spend_view_key, sizeof(public_spend_view_key));
			}
			expects_lr<string> monero::encode_address(const std::string_view& public_key_hash)
			{
				if (public_key_hash.size() != 64 && public_key_hash.size() != 65)
					return layer_exception("not a valid raw public spend-view keypair");

				char address[256] = { 0 };
				uint64_t type = public_key_hash.size() == 65 ? (uint8_t)public_key_hash[64] : get_address_prefix().standard_address;
				if (xmr_base58_addr_encode_check(type, (uint8_t*)public_key_hash.data(), 64, address, sizeof(address)) == 0)
					return layer_exception("not a valid public spend-view key");

				return string(address, strnlen(address, sizeof(address)));
			}
			expects_lr<string> monero::decode_address(const std::string_view& address)
			{
				uint8_t buffer[128]; uint64_t type;
				if (xmr_base58_addr_decode_check(address.data(), address.size(), &type, buffer, sizeof(buffer)) == 0)
					return layer_exception("not a valid address data");

				auto prefix = get_address_prefix();
				if (type != prefix.standard_address && type != prefix.integrated_address && type != prefix.subaddress)
					return layer_exception("invalid address type");

				buffer[64] = (uint8_t)type;
				return string((char*)buffer, 65);
			}
			expects_lr<string> monero::encode_signature(const std::string_view& signature)
			{
				if (signature.size() != 64)
					return layer_exception("invalid signature");

				char buffer[256]; size_t buffer_size = sizeof(buffer);
				if (!xmr_base58_encode(buffer, &buffer_size, signature.data(), signature.size()))
					return layer_exception("invalid signature");

				string result = "SigV2";
				result.append(buffer, buffer_size);
				return result;
			}
			expects_lr<string> monero::decode_signature(const std::string_view& signature)
			{
				if (!stringify::starts_with(signature, "SigV2"))
					return layer_exception("invalid sigv2+base58 signature");

				uint8_t buffer[128]; size_t buffer_size = sizeof(buffer); auto small_signature = signature.substr(5);
				if (!xmr_base58_decode(small_signature.data(), small_signature.size(), buffer, &buffer_size) || buffer_size != 64)
					return layer_exception("invalid sigv2+base58 signature");

				return string((char*)buffer, buffer_size);
			}
			expects_lr<string> monero::encode_transaction_id(const std::string_view& transaction_id)
			{
				return format::util::encode_0xhex(transaction_id);
			}
			expects_lr<string> monero::decode_transaction_id(const std::string_view& transaction_id)
			{
				auto result = format::util::decode_0xhex(transaction_id);
				if (result.size() != 64)
					return layer_exception("invalid transaction id");

				return result;
			}
			expects_lr<address_map> monero::to_addresses(const std::string_view& input_public_key)
			{
				string raw_public_key = string(input_public_key);
				if (raw_public_key.size() != 32 && raw_public_key.size() != 64)
				{
					auto result = decode_public_key(raw_public_key);
					if (!result)
						return result.error();

					raw_public_key = std::move(*result);
				}
				else if (raw_public_key.size() == 32)
				{
					raw_public_key.resize(64);
					cryptonote::derive_known_public_view_key((uint8_t*)raw_public_key.data(), (uint8_t*)raw_public_key.data() + 32);
				}

				auto address = encode_address(raw_public_key);
				if (!address)
					return address.error();

				address_map result = { { (uint8_t)1, *address } };
				return expects_lr<address_map>(std::move(result));
			}
			monero::address_prefix monero::get_address_prefix() const
			{
				switch (kernel::params().user.network)
				{
					case network_type::regtest:
					case network_type::mainnet:
					{
						address_prefix prefix;
						prefix.standard_address = 0x12;
						prefix.integrated_address = 0x13;
						prefix.subaddress = 0x2a;
						return prefix;
					}
					case network_type::testnet:
					{
						address_prefix prefix;
						prefix.standard_address = 0x18;
						prefix.integrated_address = 0x19;
						prefix.subaddress = 0x24;
						return prefix;
					}
					default:
						VI_PANIC(false, "invalid network type");
						return address_prefix();
				}
			}
			const monero::chainparams& monero::get_chainparams() const
			{
				return netdata;
			}
			decimal monero::from_atomic(const uint256_t& value)
			{
				return decimal(value.to_string()) / netdata.divisibility;
			}
			uint256_t monero::to_atomic(const decimal& value)
			{
				return uint256_t((value * netdata.divisibility).truncate(0).to_string());
			}
			monero::pseudo_transaction monero::decode_pseudo_transaction(const format::tree& transaction_data)
			{
				string extra_buffer;
				auto* extra = transaction_data.child("extra");
				if (extra != nullptr)
				{
					extra_buffer.reserve(extra->childs().size());
					for (auto& byte : extra->childs())
						extra_buffer.push_back((int8_t)byte.value.as_uint8());
				}

				pseudo_transaction result;
				result.hash = transaction_data.child_var("hash").as_blob();
				result.fee = from_atomic(transaction_data.child_var("rct_signatures.txnFee").as_uint256());

				auto* inputs = transaction_data.child("vin");
				if (inputs != nullptr)
				{
					for (auto& item : inputs->childs())
					{
						uint64_t coinbase_height = item.child_var("gen.height").as_uint64();
						if (!coinbase_height)
						{
							pseudo_transaction::input input;
							input.amount = item.child_var("key.amount").as_uint64();
							input.is_coinbase = false;

							string key_image = codec::hex_decode(item.child_var("key.k_image").as_blob());
							memcpy(input.key_image, key_image.data(), std::min(sizeof(input.key_image), key_image.size()));

							auto* key_offsets = item.child("key.key_offsets");
							if (key_offsets != nullptr)
							{
								input.key_offsets.reserve(key_offsets->childs().size());
								for (auto& offset : key_offsets->childs())
									input.key_offsets.push_back((uint64_t)offset.value.as_uint64() + (input.key_offsets.empty() ? 0 : input.key_offsets.back()));
							}
							result.inputs.push_back(std::move(input));
						}
						else
						{
							pseudo_transaction::input input;
							memset(input.key_image, 0, sizeof(input.key_image));
							input.amount = 0;
							input.is_coinbase = true;
							result.inputs.push_back(std::move(input));
						}
					}
				}

				auto* outputs = transaction_data.child("vout");
				auto* ecdh_info = transaction_data.child("rct_signatures.ecdhInfo");
				auto* out_pk = transaction_data.child("rct_signatures.outPk");
				if (outputs != nullptr)
				{
					for (auto& item : outputs->childs())
					{
						pseudo_transaction::output output;
						output.amount = item.child_var("amount").as_uint64();
						if (ecdh_info != nullptr)
						{
							auto* ecdh_output_info = ecdh_info->child(result.outputs.size());
							if (ecdh_output_info != nullptr)
							{
								output.ecdh_amount = codec::hex_decode(ecdh_output_info->child_var("amount").as_blob());
								output.ecdh_mask = codec::hex_decode(ecdh_output_info->child_var("mask").as_blob());
							}
						}
						if (out_pk != nullptr)
						{
							string ring_out_key = codec::hex_decode(out_pk->child_var(result.outputs.size()).as_blob());
							memcpy(output.ring_out_key, ring_out_key.data(), std::min(sizeof(output.ring_out_key), ring_out_key.size()));
						}

						string key = codec::hex_decode(item.child_var("target.tagged_key.key").as_blob());
						if (key.empty())
							key = codec::hex_decode(item.child_var("target.key").as_blob());
						memcpy(output.key, key.data(), std::min(sizeof(output.key), key.size()));

						string view_tag = codec::hex_decode(item.child_var("target.tagged_key.view_tag").as_blob());
						memcpy(&output.view_tag, view_tag.data(), std::min(sizeof(output.view_tag), view_tag.size()));
						result.outputs.push_back(std::move(output));
					}
				}

				hash_set<uint8_t> tags =
				{
					TX_EXTRA_TAG_PUBKEY,
					TX_EXTRA_TAG_ADDITIONAL_PUBKEYS,
					TX_EXTRA_NONCE,
					TX_EXTRA_MERGE_MINING_TAG,
					TX_EXTRA_MYSTERIOUS_MINERGATE_TAG,
					TX_EXTRA_TAG_PADDING
				};
				auto buffer = std::string_view(extra_buffer);
				for (size_t i = 0; i < buffer.size() && !tags.empty(); i++)
				{
					auto possible_tag = tags.find(buffer[i]);
					if (possible_tag == tags.end())
						break;

					uint8_t tag = *possible_tag;
					if (tag == TX_EXTRA_TAG_PUBKEY)
					{
						if (++i >= buffer.size())
							break;

						auto public_key = algorithm::storage_type<uint8_t, 32>(buffer.substr(i, 32));
						if (!result.public_keys.empty())
							result.public_keys.insert(result.public_keys.begin(), public_key);
						else
							result.public_keys.push_back(public_key);

						tags.erase(TX_EXTRA_TAG_PUBKEY);
						i += 32 - 1;
					}
					else if (tag == TX_EXTRA_TAG_ADDITIONAL_PUBKEYS)
					{
						if (++i >= buffer.size())
							break;

						uint8_t count = buffer[i];
						if (i + 32 * count >= buffer.size())
							break;

						i++;
						for (size_t j = 0; j < count; j++)
						{
							result.public_keys.push_back(algorithm::storage_type<uint8_t, 32>(buffer.substr(i, 32)));
							i += 32;
						}
						i--;
						tags.erase(TX_EXTRA_TAG_ADDITIONAL_PUBKEYS);
					}
					else if (tag == TX_EXTRA_NONCE)
					{
						if (++i >= buffer.size())
							break;

						uint8_t nonce_size = buffer[i];
						if (++i + nonce_size > buffer.size())
							break;

						auto nonce = buffer.substr(i, nonce_size);
						for (size_t j = 0; j < nonce.size(); j++)
						{
							if (nonce[j] == TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID)
							{
								if (++j >= nonce.size())
									break;

								result.encrypted_payment_id = nonce.substr(j, 8);
								j += 8 - 1;
								continue;
							}
							if (nonce[j] == TX_EXTRA_NONCE_PAYMENT_ID)
							{
								if (++j >= nonce.size())
									break;

								result.payment_id = nonce.substr(j, 32);
								j += 32 - 1;
								continue;
							}
						}

						i += nonce_size;
						tags.erase(TX_EXTRA_NONCE);
					}
					else if (tag == TX_EXTRA_MERGE_MINING_TAG)
					{
						if (++i >= buffer.size())
							break;

						uint8_t size = buffer[i];
						if (i + size >= buffer.size())
							break;

						i += size;
						tags.erase(TX_EXTRA_MERGE_MINING_TAG);
					}
					else if (tag == TX_EXTRA_MYSTERIOUS_MINERGATE_TAG)
					{
						if (++i >= buffer.size())
							break;

						uint8_t size = buffer[i];
						if (i + size >= buffer.size())
							break;

						i += size;
						tags.erase(TX_EXTRA_MYSTERIOUS_MINERGATE_TAG);
					}
					else if (tag == TX_EXTRA_TAG_PADDING)
					{
						for (size_t j = 1; j < TX_EXTRA_PADDING_MAX_COUNT; j++)
						{
							if (i + 1 >= buffer.size() || buffer[i + 1] != TX_EXTRA_TAG_PADDING)
								break;
							i++;
						}
						tags.erase(TX_EXTRA_TAG_PADDING);
					}
				}
				return result;
			}
		}
	}
}
