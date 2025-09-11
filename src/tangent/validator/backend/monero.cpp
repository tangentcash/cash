#include "monero.h"
#include "../service/oracle.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/bip32.h"
#include <sodium.h>
extern "C"
{
#include "../../internal/monero/base58.h"
#include "../../internal/monero/xmr.h"
#include "../../internal/monero/serialize.h"
#include "../../internal/monero/crypto.h"
#include "../../internal/sha3.h"
}
/*
	WARNING! This implementation is all about deanonymization of Monero
	transactions. That is because Tangent requires transactions to be
	at least partially transparent. Following changes were implemented
	to make transactions partially public:
		1. Private view key is derived from public spend key instead
		   of private spend key: everyone can derive private view key
		   if they know an address of Tangent-Monero address. This
		   allows one to view Monero received to this address.
		2. Transactions that are sent from Tangent network uses more
		   data in extra field and does it in non-standard way. The
		   TX_EXTRA_MYSTERIOUS_MINERGATE_TAG is a serialized message
		   that contains input_index-global_index mapping and also
		   output_index-address mapping. This allows one to view
		   Monero sent from this address and a receiver address of
		   Monero output as well as change address.
	It is recommended to use front Monero address which will receive
	from Tangent address and then send to back Monero address which
	will be the actual receiver of payment if you must have standard
	privacy features where front address is your routing address and
	back address is your actual spender address. These modifications
	greatly improve Tangent bridge address transparency which is a
	good thing and greatly reduce Tangent router address opacity which
	is a bad thing however this is the only way for now.
	
	CRITICAL WARNING! This is not yet a complete implementation as it
	requires 'prepare' and 'finalize' functions to be implemented which
	will be done later as it does require severe breaking changes to
	Tangent's composition API which would allow one to generate k_image
	for each input and perform sign operation on that k_image both of
	which require private spend key. Because of this, for now, Monero
	backend has a retirement block number set to zero which would not
	allow any transactions with Monero assets.
*/

namespace tangent
{
	namespace warden
	{
		namespace backends
		{
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
			const char* monero::nd_call::get_fee_estimate()
			{
				return "get_fee_estimate";
			}
			const char* monero::nd_call::get_o_indexes()
			{
				return "/get_o_indexes.bin";
			}

			monero::monero(const algorithm::asset_id& new_asset) noexcept : relay_backend_utxo(new_asset)
			{
				netdata.composition = algorithm::composition::type::ed25519_clsag;
				netdata.routing = routing_policy::utxo;
				netdata.tokenization = token_policy::none;
				netdata.sync_latency = 10;
				netdata.divisibility = decimal(1000000000000).truncate(protocol::now().message.decimal_precision);
				netdata.supports_bulk_transfer = true;
				netdata.requires_transaction_expiration = false;
			}
			expects_promise_rt<vector<uint64_t>> monero::get_output_indices(const std::string_view& transaction_id)
			{
				string request = codec::hex_decode(stringify::text("0111010101010201010404747869640a80%.*s", (int)transaction_id.size(), transaction_id.data()));
				auto response = coawait(execute_http("POST", nd_call::get_o_indexes(), "application/octet-stream", request, cache_policy::blob_cache));
				if (!response)
					coreturn expects_rt<vector<uint64_t>>(response.error());

				auto begin_message = std::string_view("o_indexes");
				auto end_message = std::string_view("status");
				auto message = response->value.get_string();
				auto begin = message.find(begin_message), end = message.find(end_message);
				if (begin == std::string::npos || end == std::string::npos)
					coreturn expects_rt<vector<uint64_t>>(vector<uint64_t>());

				begin += begin_message.size() + 2; end -= 1;
				if (begin >= end)
					coreturn expects_rt<vector<uint64_t>>(vector<uint64_t>());

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

				coreturn expects_rt<vector<uint64_t>>(std::move(result));
			}
			expects_promise_rt<uint64_t> monero::get_latest_block_height()
			{
				auto height = coawait(execute_rest("POST", nd_call::get_height(), nullptr, cache_policy::no_cache));
				if (!height)
					coreturn expects_rt<uint64_t>(height.error());

				uint64_t block_height = height->get_var("height").get_integer();
				memory::release(*height);
				coreturn expects_rt<uint64_t>(block_height > 1 ? block_height - 1 : 1);
			}
			expects_promise_rt<schema*> monero::get_block_transactions(uint64_t block_height, string* block_hash)
			{
				schema_args args;
				args["height"] = var::set::integer(block_height);
				args["fill_pow_hash"] = var::set::boolean(true);

				auto block_data = coawait(execute_rpc3(nd_call::get_block(), std::move(args), cache_policy::temporary_cache, nd_call::json_rpc()));
				if (!block_data)
					coreturn expects_rt<schema*>(block_data.error());

				auto block_blob = schema::from_json(block_data->get_var("json").get_blob());
				auto destructor1 = uptr<schema>(*block_data);
				if (!block_blob)
					coreturn expects_rt<schema*>(remote_exception(std::move(block_blob.error().message())));

				schema* transaction_data = var::set::array();
				auto destructor2 = uptr<schema>(*block_blob);
				auto miner_tx = block_blob->get("miner_tx");
				if (miner_tx != nullptr)
				{
					miner_tx->unlink();
					miner_tx->set("hash", block_data->fetch_var("block_header.miner_tx_hash"));
					transaction_data->push(miner_tx);
				}

				auto transaction_hashes = block_blob->get("tx_hashes");
				if (transaction_hashes != nullptr && !transaction_hashes->empty())
				{
					transaction_hashes->unlink();
					schema* args = var::set::object();
					args->set("txs_hashes", transaction_hashes);
					args->set("decode_as_json", var::boolean(true));
					args->set("prune", var::boolean(true));
					transaction_hashes->add_ref();

					auto transactions = uptr<schema>(coawait(execute_rest("POST", nd_call::get_transactions(), args, cache_policy::blob_cache)));
					if (transactions)
					{
						auto* list = transactions->get("txs");
						if (list != nullptr)
						{
							size_t offset = transaction_data->size();
							for (auto& transaction : list->get_childs())
							{
								auto transaction_blob = schema::from_json(transaction->get_var("as_json").get_blob());
								if (transaction_blob)
								{
									transaction_blob->set("hash", transaction_hashes->get_var(transaction_data->size() - offset));
									transaction_data->push(*transaction_blob);
								}
							}
						}
					}
					transaction_hashes->release();
				}

				if (block_hash != nullptr)
				{
					auto header_block_hash = block_data->fetch_var("block_header.hash").get_blob();
					if (!header_block_hash.empty())
						*block_hash = std::move(header_block_hash);
				}

				coreturn expects_rt<schema*>(transaction_data);
			}
			expects_promise_rt<coin_utxo> monero::get_transaction_output(const std::string_view& transaction_id, uint64_t index)
			{
				auto result = get_utxo(transaction_id, index);
				if (result)
					return expects_promise_rt<coin_utxo>(remote_exception(std::move(result.error().message())));

				return expects_promise_rt<coin_utxo>(std::move(*result));
			}
			expects_promise_rt<computed_transaction> monero::link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				auto info = decode_transaction_info(transaction_data);
				auto inputs = decode_transaction_inputs(transaction_data);
				auto outputs = decode_transaction_outputs(transaction_data);
				const size_t count = 64;
				size_t offset = 0;

				unordered_set<size_t> unresolved_outputs;
				unresolved_outputs.reserve(outputs.size());
				for (size_t i = 0; i < outputs.size(); i++)
					unresolved_outputs.insert(i);

				computed_transaction result;
				result.transaction_id = info.hash;

				bool is_coinbase = false;
				for (size_t i = 0; i < inputs.size(); i++)
				{
					auto& input = inputs[i];
					if (!input.is_coinbase)
					{
						if (info.key_offset_indices.size() == inputs.size() && info.key_offset_indices[i] < input.key_offsets.size())
						{
							auto& key_offset = input.key_offsets[info.key_offset_indices[i]];
							auto utxo = get_utxo(to_string(key_offset, 16), 0);
							if (utxo)
								result.inputs.push_back(std::move(*utxo));
						}
					}
					else
						is_coinbase = true;
				}

				while (true)
				{
					auto links = find_linked_addresses(algorithm::pubkeyhash_t(), offset, count);
					if (!links)
						coreturn expects_rt<computed_transaction>(remote_exception(std::move(links.error().message())));

					for (auto& link : *links)
					{
						auto public_spend_view_key = decode_public_key(link.second.public_key);
						if (!public_spend_view_key)
							continue;

						uint8_t private_view_key[32];
						uint8_t* public_spend_key = (uint8_t*)public_spend_view_key->data();
						uint8_t* public_view_key = (uint8_t*)public_spend_view_key->data() + 32;
						derive_known_private_view_key(public_spend_key, private_view_key);
						for (auto& transaction_public_key : info.public_keys)
						{
							uint8_t derivation_key[32];
							if (!generate_derivation_key(transaction_public_key.data, private_view_key, derivation_key))
								continue;
							
							for (size_t i = 0; i < outputs.size(); i++)
							{
								if (unresolved_outputs.find(i) == unresolved_outputs.end())
									continue;

								uint8_t output_scalar[32];
								derivation_to_scalar(derivation_key, (uint64_t)i, output_scalar);

								uint8_t output_public_key[32];
								if (!derive_public_key(output_scalar, public_spend_key, output_public_key))
									continue;

								auto& output = outputs[i];
								if (memcmp(output_public_key, output.key, sizeof(output.key)) != 0)
									continue;

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
										hash_to_scalar(mask_commitment, sizeof(mask_commitment), mask);

										char amount_tag[] = "amount";
										constexpr size_t amount_tag_size = sizeof(amount_tag) - 1;
										uint8_t amount_commitment[amount_tag_size + sizeof(output_scalar)];
										memcpy(amount_commitment, amount_tag, amount_tag_size);
										memcpy(amount_commitment + amount_tag_size, output_scalar, sizeof(output_scalar));
										xmr_fast_hash(amount, amount_commitment, sizeof(amount_commitment));

										amount_size = std::min<size_t>(output.ecdh_amount.size(), sizeof(uint64_t));
										for (size_t i = 0; i < amount_size; i++)
											amount[i] ^= (uint8_t)output.ecdh_amount[i];
										for (size_t i = amount_size; i < sizeof(amount); i++)
											amount[i] = 0;
									}
									else
									{
										uint8_t ecdh_mask[32] = { 0 }, ecdh_amount[32] = { 0 };
										memcpy(ecdh_mask, output.ecdh_mask.data(), std::min(sizeof(ecdh_mask), output.ecdh_mask.size()));
										memcpy(ecdh_amount, output.ecdh_amount.data(), std::min(sizeof(ecdh_amount), output.ecdh_amount.size()));

										uint8_t mask_scalar[32], amount_scalar[32];
										hash_to_scalar(output_scalar, sizeof(output_scalar), mask_scalar);
										hash_to_scalar(mask_scalar, sizeof(mask_scalar), amount_scalar);

										sc_sub(mask, ecdh_mask, mask_scalar);
										sc_sub(amount, ecdh_amount, amount_scalar);
									}
									
									uint8_t ring_out_key[32];
									if (!pedersen_commit(mask, amount, ring_out_key))
										continue;
									else if (memcmp(ring_out_key, output.ring_out_key, sizeof(output.ring_out_key)) != 0)
										continue;

									std::array<uint8_t, 32> swap_amount = { 0 };
									memcpy(swap_amount.data(), amount, amount_size);
									std::reverse(swap_amount.begin(), swap_amount.end());

									uint256_t value256 = uint256_t(codec::hex_encode(std::string_view((char*)swap_amount.data(), swap_amount.size())), 16);
									value = from_baseline_value(value256);
								}
								else
									value = from_baseline_value(output.amount);

								coin_utxo new_output;
								new_output.transaction_id = string();
								new_output.link = link.second;
								new_output.value = value;
								new_output.index = (uint64_t)i;
								result.outputs.push_back(std::move(new_output));
							}
						}

						if (unresolved_outputs.empty())
							break;
					}

					offset += links->size();
					if (links->size() != count || unresolved_outputs.empty())
						break;
				}

				for (auto& [output_index8, output_address] : info.output_addresses)
				{
					auto output_index = (size_t)output_index8;
					if (unresolved_outputs.find(output_index) == unresolved_outputs.end())
						continue;

					auto& output = outputs[output_index];
					if (!output.ecdh_amount.empty())
						continue;

					auto address = encode_address(output_address.view());
					if (!address)
						continue;

					auto links = find_linked_addresses({ *address });
					if (!links || links->empty())
						continue;

					coin_utxo new_output;
					new_output.transaction_id = string();
					new_output.link = links->begin()->second;
					new_output.value = from_baseline_value(output.amount);
					new_output.index = (uint64_t)output_index;
					result.outputs.push_back(std::move(new_output));
				}

				if (result.inputs.empty() && result.outputs.empty())
					coreturn expects_rt<computed_transaction>(remote_exception("tx not involved"));

				if (!result.outputs.empty())
				{
					auto indices = coawait(get_output_indices(result.transaction_id));
					if (!indices)
						coreturn expects_rt<computed_transaction>(indices.error());

					for (auto& output : result.outputs)
					{
						if (output.index < indices->size())
						{
							output.transaction_id = to_string(indices->at(output.index), 16);
							output.index = 0;
						}
						else
							output.index = std::numeric_limits<uint64_t>::max();
					}
					result.outputs.erase(std::remove_if(result.outputs.begin(), result.outputs.end(), [](coin_utxo& item) { return item.index == std::numeric_limits<uint64_t>::max(); }), result.outputs.end());
				}

				decimal sending_value = decimal::zero();
				decimal receiving_value = decimal::zero();
				for (auto& input : result.inputs)
					sending_value += input.value;
				for (auto& output : result.outputs)
					receiving_value += output.value;

				if (sending_value < receiving_value)
				{
					coin_utxo new_input;
					new_input.value = receiving_value - sending_value;
					result.inputs.push_back(std::move(new_input));
				}
				else if (sending_value > receiving_value)
				{
					coin_utxo new_output;
					new_output.value = sending_value - receiving_value;
					result.outputs.push_back(std::move(new_output));
				}

				coreturn expects_rt<computed_transaction>(std::move(result));
			}
			expects_promise_rt<computed_fee> monero::estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options)
			{
				schema_args args;
				args["grace_blocks"] = var::set::integer(10);

				auto fee = coawait(execute_rpc3(nd_call::get_fee_estimate(), std::move(args), cache_policy::no_cache_no_throttling, nd_call::json_rpc()));
				if (!fee)
					coreturn expects_rt<computed_fee>(fee.error());

				uint64_t fee_rate = fee->get_var("fee").get_integer();
				coreturn expects_rt<computed_fee>(computed_fee::fee_per_kilobyte(fee_rate / netdata.divisibility));
			}
			expects_promise_rt<void> monero::broadcast_transaction(const finalized_transaction& finalized)
			{
				schema* args = var::set::object();
				args->set("tx_as_hex", var::string(format::util::clear_0xhex(finalized.calldata)));

				auto hex_data = coawait(execute_rest("POST", nd_call::send_raw_transaction(), args, cache_policy::no_cache));
				if (!hex_data)
					coreturn expects_rt<void>(hex_data.error());

				bool double_spend = hex_data->get_var("double_spend").get_boolean();
				bool fee_too_low = hex_data->get_var("fee_too_low").get_boolean();
				bool invalid_input = hex_data->get_var("invalid_input").get_boolean();
				bool invalid_output = hex_data->get_var("invalid_output").get_boolean();
				bool low_mixin = hex_data->get_var("low_mixin").get_boolean();
				bool overspend = hex_data->get_var("overspend").get_boolean();
				bool too_big = hex_data->get_var("too_big").get_boolean();
				memory::release(*hex_data);

				if (double_spend)
					coreturn expects_rt<void>(remote_exception("transaction double spends inputs"));
				else if (fee_too_low)
					coreturn expects_rt<void>(remote_exception("transaction fee is too low"));
				else if (invalid_input)
					coreturn expects_rt<void>(remote_exception("transaction uses invalid input"));
				else if (invalid_output)
					coreturn expects_rt<void>(remote_exception("transaction uses invalid output"));
				else if (low_mixin)
					coreturn expects_rt<void>(remote_exception("transaction mixin count is too low"));
				else if (overspend)
					coreturn expects_rt<void>(remote_exception("transaction overspends inputs"));
				else if (too_big)
					coreturn expects_rt<void>(remote_exception("transaction is too big"));

				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<prepared_transaction> monero::prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee)
			{
				coreturn expects_rt<prepared_transaction>(remote_exception("not implemented"));
			}
			expects_lr<finalized_transaction> monero::finalize_transaction(prepared_transaction&& prepared)
			{
				return layer_exception("not implemented");
			}
			expects_lr<secret_box> monero::encode_secret_key(const secret_box& secret_key)
			{
				if (secret_key.size() == 64)
				{
					auto data = secret_key.expose<KEY_LIMIT>();
					string private_spend_view_key = codec::hex_encode(data.view.substr(0, 32));
					private_spend_view_key.append(1, ':').append(codec::hex_encode(data.view.substr(32)));
					return secret_box::secure(private_spend_view_key);
				}
				else if (secret_key.size() == 32)
				{
					uint8_t private_spend_key[32];
					auto data = secret_key.expose<KEY_LIMIT>();
					memcpy(private_spend_key, data.buffer, sizeof(private_spend_key));

					uint8_t public_spend_key[32];
					if (crypto_scalarmult_ed25519_base_noclamp(public_spend_key, private_spend_key) != 0)
						return layer_exception("not a valid private spend-view key");

					uint8_t private_view_key[32];
					derive_known_private_view_key(public_spend_key, private_view_key);

					string private_spend_view_key = codec::hex_encode(std::string_view((char*)private_spend_key, sizeof(private_spend_key)));
					private_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)private_view_key, sizeof(private_view_key))));
					return secret_box::secure(private_spend_view_key);
				}

				return layer_exception("private key is not a pair of private spend key and private view key");
			}
			expects_lr<secret_box> monero::decode_secret_key(const secret_box& secret_key)
			{
				bool use_publicly_known_keypair = false;
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

					derive_known_private_view_key(public_spend_key, private_view_key);
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
					derive_known_public_view_key(public_spend_key, public_view_key);

					string public_spend_view_key = codec::hex_encode(std::string_view((char*)public_spend_key, sizeof(public_spend_key)));
					public_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)public_view_key, sizeof(public_view_key))));
					return public_spend_view_key;
				}

				return layer_exception("public key is not a pair of public spend key and public view key");
			}
			expects_lr<string> monero::decode_public_key(const std::string_view& public_key)
			{
				bool use_publicly_known_keypair = false;
				uint8_t public_spend_key[32], public_view_key[32];
				size_t split = public_key.find(':');
				auto raw_spend_key = codec::hex_decode(public_key.substr(0, split));
				if (raw_spend_key.size() != 32)
					return layer_exception("not a valid hex public spend-view keypair");

				memcpy(public_spend_key, raw_spend_key.data(), sizeof(public_spend_key));
				auto raw_view_key = codec::hex_decode(public_key.substr(split + 1));
				if (raw_view_key.size() != 32)
					derive_known_public_view_key(public_spend_key, public_view_key);
				else
					memcpy(public_view_key, raw_view_key.data(), sizeof(public_view_key));

				uint8_t public_spend_view_key[64] = { 0 };
				memcpy(public_spend_view_key, public_spend_key, sizeof(public_spend_key));
				memcpy(public_spend_view_key + 32, public_view_key, sizeof(public_view_key));
				return string((char*)public_spend_view_key, sizeof(public_spend_view_key));
			}
			expects_lr<string> monero::encode_address(const std::string_view& public_key_hash)
			{
				if (public_key_hash.size() != 64)
					return layer_exception("not a valid raw public spend-view keypair");

				char address[256] = { 0 };
				if (xmr_base58_addr_encode_check(get_network_type(), (uint8_t*)public_key_hash.data(), public_key_hash.size(), address, sizeof(address)) == 0)
					return layer_exception("not a valid public spend-view key");

				return string(address, strnlen(address, sizeof(address)));
			}
			expects_lr<string> monero::decode_address(const std::string_view& address)
			{
				uint8_t buffer[128]; uint64_t tag;
				if (xmr_base58_addr_decode_check(address.data(), address.size(), &tag, buffer, sizeof(buffer)) == 0)
					return layer_exception("not a valid address data");
				else if (tag != get_network_type())
					return layer_exception("not a valid address type");
				return string((char*)buffer, 64);
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
					derive_known_public_view_key((uint8_t*)raw_public_key.data(), (uint8_t*)raw_public_key.data() + 32);
				}

				auto address = encode_address(raw_public_key);
				if (!address)
					return address.error();

				address_map result = { { (uint8_t)1, *address } };
				return expects_lr<address_map>(std::move(result));
			}
			uint64_t monero::get_retirement_block_number() const
			{
				return 0;
			}
			const btc_chainparams_* monero::get_chain()
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
			const monero::chainparams& monero::get_chainparams() const
			{
				return netdata;
			}
			uint64_t monero::get_network_type() const
			{
				switch (protocol::now().user.network)
				{
					case network_type::mainnet:
					case network_type::regtest:
						return 18;
					case network_type::testnet:
						return 53;
					default:
						VI_PANIC(false, "invalid network type");
						return 24;
				}
			}
			monero::transaction_info monero::decode_transaction_info(schema* transaction_data)
			{
				const uint8_t TX_EXTRA_TAG_PADDING = 0x00;
				const uint8_t TX_EXTRA_TAG_PUBKEY = 0x01;
				const uint8_t TX_EXTRA_NONCE = 0x02;
				const uint8_t TX_EXTRA_NONCE_PAYMENT_ID = 0x00;
				const uint8_t TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01;
				const uint8_t TX_EXTRA_MERGE_MINING_TAG = 0x03;
				const uint8_t TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04;
				const uint8_t TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xDE;
				const uint8_t TX_EXTRA_PADDING_MAX_COUNT = 255;

				string extra_buffer;
				auto* extra = transaction_data->get("extra");
				if (extra != nullptr)
				{
					extra_buffer.reserve(extra->size());
					for (auto& byte : extra->get_childs())
						extra_buffer.push_back((int8_t)byte->value.get_integer());
				}

				transaction_info result;
				result.hash = transaction_data->get_var("hash").get_blob();

				unordered_set<uint8_t> tags =
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

						format::ro_stream message = format::ro_stream(buffer.substr(i + 1, size));
						if (!message.data.empty())
						{
							string key_offset_indices; auto type = message.read_type();
							if (format::util::get_string_size(type) > 0 && message.read_string(type, &key_offset_indices))
							{
								result.key_offset_indices.resize(key_offset_indices.size());
								memcpy(result.key_offset_indices.data(), key_offset_indices.data(), key_offset_indices.size());

								string output_addresses; type = message.read_type();
								if (format::util::get_string_size(type) > 0 && message.read_string(type, &output_addresses) && output_addresses.size() % 65 == 0)
								{
									size_t output_addresses_size = output_addresses.size() / 65;
									for (size_t j = 0; j < output_addresses_size; j++)
									{
										auto output_address = std::string_view(output_addresses).substr(j * 65, 65);
										result.output_addresses[output_address.front()] = output_address.substr(1);
									}
								}
							}
						}

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
			vector<monero::transaction_input> monero::decode_transaction_inputs(schema* transaction_data)
			{
				vector<transaction_input> result;
				auto* inputs = transaction_data->get("vin");
				if (inputs != nullptr)
				{
					for (auto& item : inputs->get_childs())
					{
						uint64_t coinbase_height = item->fetch_var("gen.height").get_integer();
						if (!coinbase_height)
						{
							transaction_input input;
							input.amount = item->fetch_var("key.amount").get_integer();
							input.is_coinbase = false;

							string key_image = codec::hex_decode(item->fetch_var("key.k_image").get_blob());
							memcpy(input.key_image, key_image.data(), std::min(sizeof(input.key_image), key_image.size()));

							auto* key_offsets = item->fetch("key.key_offsets");
							if (key_offsets != nullptr)
							{
								input.key_offsets.reserve(key_offsets->size());
								for (auto& offset : key_offsets->get_childs())
									input.key_offsets.push_back((uint64_t)offset->value.get_integer() + (input.key_offsets.empty() ? 0 : input.key_offsets.back()));
							}
							result.push_back(std::move(input));
						}
						else
						{
							transaction_input input;
							memset(input.key_image, 0, sizeof(input.key_image));
							input.amount = 0;
							input.is_coinbase = true;
							result.push_back(std::move(input));
						}
					}
				}
				return result;
			}
			vector<monero::transaction_output> monero::decode_transaction_outputs(schema* transaction_data)
			{
				vector<transaction_output> result;
				auto* outputs = transaction_data->get("vout");
				auto* ecdh_info = transaction_data->fetch("rct_signatures.ecdhInfo");
				auto* out_pk = transaction_data->fetch("rct_signatures.outPk");
				if (outputs != nullptr)
				{
					for (auto& item : outputs->get_childs())
					{
						transaction_output output;
						output.amount = item->get_var("amount").get_integer();
						if (ecdh_info != nullptr)
						{
							auto* ecdh_output_info = ecdh_info->get(result.size());
							if (ecdh_output_info != nullptr)
							{
								output.ecdh_amount = codec::hex_decode(ecdh_output_info->get_var("amount").get_blob());
								output.ecdh_mask = codec::hex_decode(ecdh_output_info->get_var("mask").get_blob());
							}
						}
						if (out_pk != nullptr)
						{
							string ring_out_key = codec::hex_decode(out_pk->get_var(result.size()).get_blob());
							memcpy(output.ring_out_key, ring_out_key.data(), std::min(sizeof(output.ring_out_key), ring_out_key.size()));
						}

						string key = codec::hex_decode(item->fetch_var("target.tagged_key.key").get_blob());
						if (key.empty())
							key = codec::hex_decode(item->fetch_var("target.key").get_blob());
						memcpy(output.key, key.data(), std::min(sizeof(output.key), key.size()));

						string view_tag = codec::hex_decode(item->fetch_var("target.tagged_key.view_tag").get_blob());
						memcpy(&output.view_tag, view_tag.data(), std::min(sizeof(output.view_tag), view_tag.size()));
						result.push_back(std::move(output));
					}
				}
				return result;
			}
			bool monero::generate_key_image(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], const uint8_t public_view_key[32], const uint8_t private_spend_key[32], uint8_t key_image[32])
			{
				uint8_t ephimeral_public_key[32];
				if (!derive_public_key(derivation_scalar, public_spend_key, ephimeral_public_key))
					return false;

				uint8_t ephimeral_private_key[32];
				derive_private_key(derivation_scalar, private_spend_key, ephimeral_private_key);
				if (sc_check(ephimeral_private_key) != 0)
					return false;

				uint8_t p32[32];
				hash_to_point(ephimeral_public_key, sizeof(ephimeral_public_key), p32);

				ge_p3 m3;
				if (ge_frombytes_vartime(&m3, p32) != 0)
					return false;

				ge_p2 m2;
				ge_scalarmult(&m2, ephimeral_private_key, &m3);
				ge_tobytes(key_image, &m2);
				return false;
			}
			bool monero::generate_derivation_key(const uint8_t transaction_public_key[32], const uint8_t private_view_key[32], uint8_t derivation_key[32])
			{
				ge_p3 m3;
				if (ge_frombytes_vartime(&m3, transaction_public_key) != 0)
					return false;

				ge_p2 m2;
				ge_scalarmult(&m2, private_view_key, &m3);

				ge_p1p1 m11;
				ge_mul8(&m11, &m2);
				ge_p1p1_to_p2(&m2, &m11);
				ge_tobytes(derivation_key, &m2);
				return true;
			}
			void monero::derive_private_key(const uint8_t derivation_scalar[32], const uint8_t private_spend_key[32], uint8_t private_key[32])
			{
				sc_add(private_key, private_spend_key, derivation_scalar);
			}
			bool monero::derive_public_key(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], uint8_t public_key[32])
			{
				ge_p3 m3_1;
				if (ge_frombytes_vartime(&m3_1, public_spend_key) != 0)
					return false;

				ge_p3 m3_2;
				ge_scalarmult_base(&m3_2, derivation_scalar);

				ge_cached m3_3;
				ge_p3_to_cached(&m3_3, &m3_2);

				ge_p1p1 m11;
				ge_add(&m11, &m3_1, &m3_3);

				ge_p2 m2;
				ge_p1p1_to_p2(&m2, &m11);
				ge_tobytes(public_key, &m2);
				return true;
			}
			void monero::derivation_to_scalar(const uint8_t derivation_key[32], uint64_t derivation_index, uint8_t derivation_scalar[32])
			{
				auto di = uint256_t(derivation_index);
				size_t di_size = std::max<size_t>(1, di.bytes());
				uint8_t derivation[64] = { 0 };
				memcpy(derivation, derivation_key, 32);
				di.encode(derivation + 32);
				hash_to_scalar(derivation, 32 + di_size, derivation_scalar);
			}
			void monero::hash_to_scalar(const uint8_t* buffer, size_t buffer_size, uint8_t scalar[32])
			{
				xmr_fast_hash(scalar, buffer, buffer_size);
				sc_reduce32(scalar);
			}
			void monero::hash_to_point(const uint8_t* buffer, size_t buffer_size, uint8_t point[32])
			{
				ge_p2 m2;
				xmr_fast_hash(point, buffer, buffer_size);
				ge_fromfe2_frombytes_vartime(&m2, point);

				ge_p1p1 m11;
				ge_mul8(&m11, &m2);

				ge_p3 m3;
				ge_p1p1_to_p3(&m3, &m11);
				ge_p3_tobytes(point, &m3);
			}
			bool monero::pedersen_commit(uint8_t mask[32], uint8_t amount[32], uint8_t commitment[32])
			{
				static uint8_t h[32] = { 139, 101, 89, 112, 21, 55, 153, 175, 42, 234, 220, 159, 241, 173, 208, 234, 108, 114, 81, 213, 65, 84, 207, 169, 44, 23, 58, 13, 211, 156, 31, 148 };

				ge_p3 m3;
				ge_frombytes_vartime(&m3, h);
				if (sc_check(amount) != 0 || sc_check(mask) != 0)
					return false;

				ge_p2 m2;
				ge_double_scalarmult_base_vartime(&m2, amount, &m3, mask);
				ge_tobytes(commitment, &m2);
				return true;
			}
			void monero::derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32])
			{
				uint8_t hash[32];
				xmr_fast_hash(hash, public_spend_key, sizeof(hash));
				memcpy(private_view_key, hash, sizeof(hash));
				sc_reduce32(private_view_key);
			}
			void monero::derive_known_public_view_key(const uint8_t public_spend_key[32], uint8_t public_view_key[32])
			{
				uint8_t private_view_key[32];
				derive_known_private_view_key(public_spend_key, private_view_key);
				crypto_scalarmult_ed25519_base_noclamp(public_view_key, private_view_key);
			}
		}
	}
}
