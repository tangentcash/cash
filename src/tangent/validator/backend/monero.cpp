#include "monero.h"
#include "../service/nss.h"
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

namespace tangent
{
	namespace mediator
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

			const char* monero::nd_call_restricted::get_block()
			{
				return "get_block";
			}
			const char* monero::nd_call_restricted::get_fee_estimate()
			{
				return "get_fee_estimate";
			}

			monero::monero() noexcept : relay_backend_utxo()
			{
				netdata.composition = algorithm::composition::type::ED25519;
				netdata.routing = routing_policy::UTXO;
				netdata.sync_latency = 5;
				netdata.divisibility = decimal(1000000000000).truncate(protocol::now().message.precision);
				netdata.supports_token_transfer.clear();
				netdata.supports_bulk_transfer = true;
			}
			expects_promise_rt<void> monero::broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
			{
				schema* args = var::set::object();
				args->set("tx_as_hex", var::string(format::util::clear_0xhex(tx_data.data)));

				auto hex_data = coawait(execute_rest(asset, "POST", nd_call::send_raw_transaction(), args, cache_policy::lazy));
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

				update_coins(asset, tx_data);
				coreturn expects_rt<void>(expectation::met);
			}
			expects_promise_rt<uint64_t> monero::get_latest_block_height(const algorithm::asset_id& asset)
			{
				auto height = coawait(execute_rest(asset, "POST", nd_call::get_height(), nullptr, cache_policy::lazy));
				if (!height)
					coreturn expects_rt<uint64_t>(height.error());

				uint64_t block_height = height->get_var("height").get_integer();
				memory::release(*height);
				coreturn expects_rt<uint64_t>(block_height);
			}
			expects_promise_rt<schema*> monero::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash)
			{
				schema_args args;
				args["height"] = var::set::integer(block_height);

				auto block_data = coawait(execute_rpc3(asset, nd_call_restricted::get_block(), std::move(args), cache_policy::shortened, nd_call::json_rpc()));
				if (!block_data)
					coreturn expects_rt<schema*>(block_data.error());

				auto block_blob = schema::from_json(block_data->get_var("json").get_blob());
				memory::release(*block_data);
				if (!block_blob)
					coreturn expects_rt<schema*>(remote_exception(std::move(block_blob.error().message())));

				schema* transaction_data = var::set::array();
				auto destructor = uptr<schema>(*block_blob);
				auto coinbase_tx = block_blob->get("miner_tx");
				if (coinbase_tx != nullptr)
				{
					transaction_data->push(coinbase_tx);
					coinbase_tx->unlink();
				}

				auto transaction_hashes = block_blob->get("tx_hashes");
				if (transaction_hashes != nullptr && !transaction_hashes->empty())
				{
					schema* args = var::set::object();
					args->set("tx_hashes", transaction_hashes);
					transaction_hashes->unlink();

					auto transactions = uptr<schema>(coawait(execute_rest(asset, "POST", nd_call::get_transactions(), nullptr, cache_policy::shortened)));
					if (transactions)
					{
						auto* list = transactions->get("txs");
						if (list != nullptr)
						{
							for (auto& transaction : list->get_childs())
							{
								auto transaction_blob = schema::from_json(transaction->get_var("as_json").get_blob());
								if (transaction_blob)
									transaction_data->push(*transaction_blob);
							}
						}
					}
				}

				coreturn expects_rt<schema*>(transaction_data);
			}
			expects_promise_rt<schema*> monero::get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id)
			{
				schema* args = var::set::object();
				schema* hashes = args->set("tx_hashes", var::set::array());
				hashes->push(var::string(transaction_id));

				auto transactions = coawait(execute_rest(asset, "POST", nd_call::get_transactions(), nullptr, cache_policy::shortened));
				if (!transactions)
					coreturn expects_rt<schema*>(transactions.error());

				auto destructor = uptr<schema>(transactions);
				auto* list = transactions->get("txs");
				if (!list || list->empty())
					coreturn expects_rt<schema*>(remote_exception("transaction not found"));

				auto transaction_blob = schema::from_json(list->get_childs().front()->get_var("as_json").get_blob());
				if (!transaction_blob)
					coreturn expects_rt<schema*>(remote_exception(std::move(transaction_blob.error().message())));

				coreturn expects_rt<schema*>(*transaction_blob);
			}
			expects_promise_rt<vector<incoming_transaction>> monero::get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data)
			{
				coreturn expects_rt<vector<incoming_transaction>>(remote_exception("not implemented"));
			}
			expects_promise_rt<base_fee> monero::estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options)
			{
				schema_args args;
				args["grace_blocks"] = var::set::integer(10);

				auto fee = coawait(execute_rpc3(asset, nd_call_restricted::get_fee_estimate(), std::move(args), cache_policy::greedy, nd_call::json_rpc()));
				if (!fee)
					coreturn expects_rt<base_fee>(fee.error());

				uint64_t fee_rate = fee->get_var("fee").get_integer();
				const size_t expected_max_tx_size = 1000;
				coreturn expects_rt<base_fee>(base_fee(fee_rate / netdata.divisibility, decimal(expected_max_tx_size)));
			}
			expects_promise_rt<coin_utxo> monero::get_transaction_output(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
			{
				auto result = get_coins(asset, transaction_id, index);
				if (result)
					return expects_promise_rt<coin_utxo>(remote_exception(std::move(result.error().message())));

				return expects_promise_rt<coin_utxo>(std::move(*result));
			}
			expects_promise_rt<outgoing_transaction> monero::new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee)
			{
				coreturn expects_rt<outgoing_transaction>(remote_exception("not implemented"));
			}
			expects_lr<master_wallet> monero::new_master_wallet(const std::string_view& seed)
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
			expects_lr<derived_signing_wallet> monero::new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index)
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

				algorithm::composition::convert_to_scalar_ed25519(node.private_key);
				auto derived = new_signing_wallet(asset, secret_box::view(std::string_view((char*)node.private_key, sizeof(node.private_key))));
				if (derived)
					derived->address_index = address_index;
				return derived;
			}
			expects_lr<derived_signing_wallet> monero::new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key)
			{
				bool use_publicly_known_keypair = false;
				auto signing_keypair = signing_key.expose<KEY_LIMIT>();
				uint8_t private_spend_key[32], private_view_key[32];
				size_t split = signing_keypair.view.find(':');
				if (signing_keypair.view.size() != 32 && signing_keypair.view.size() != 64)
				{
					auto raw_spend_key = codec::hex_decode(signing_keypair.view.substr(0, split));
					if (raw_spend_key.size() != 32)
						return layer_exception("not a valid hex private spend-view keypair");

					memcpy(private_spend_key, raw_spend_key.data(), sizeof(private_spend_key));
					auto raw_view_key = codec::hex_decode(signing_keypair.view.substr(split + 1));
					if (raw_view_key.size() == 32)
						memcpy(private_view_key, raw_view_key.data(), sizeof(private_view_key));
					else
						use_publicly_known_keypair = true;
				}
				else
				{
					memcpy(private_spend_key, signing_keypair.view.data(), sizeof(private_spend_key));
					if (signing_keypair.view.size() == 64)
						memcpy(private_view_key, signing_keypair.view.data() + sizeof(private_spend_key), sizeof(private_view_key));
					else
						use_publicly_known_keypair = true;
				}

				uint8_t public_spend_key[32];
				if (crypto_scalarmult_ed25519_base_noclamp(public_spend_key, private_spend_key) != 0)
					return layer_exception("not a valid private spend-view key");

				if (use_publicly_known_keypair)
					derive_known_private_view_key(public_spend_key, private_view_key);

				auto derived = new_verifying_wallet(asset, std::string_view((char*)public_spend_key, sizeof(public_spend_key)));
				if (!derived)
					return derived.error();

				string private_spend_view_key = codec::hex_encode(std::string_view((char*)private_spend_key, sizeof(private_spend_key)));
				private_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)private_view_key, sizeof(private_view_key))));
				return expects_lr<derived_signing_wallet>(derived_signing_wallet(std::move(*derived), secret_box::secure(private_spend_view_key)));
			}
			expects_lr<derived_verifying_wallet> monero::new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key)
			{
				bool use_publicly_known_keypair = false;
				uint8_t public_spend_key[32], public_view_key[32];
				size_t split = verifying_key.find(':');
				if (verifying_key.size() != 32 && verifying_key.size() != 64)
				{
					auto raw_spend_key = codec::hex_decode(verifying_key.substr(0, split));
					if (raw_spend_key.size() != 32)
						return layer_exception("not a valid hex public spend-view keypair");

					memcpy(public_spend_key, raw_spend_key.data(), sizeof(public_spend_key));
					auto raw_view_key = codec::hex_decode(verifying_key.substr(split + 1));
					if (raw_view_key.size() == 32)
						memcpy(public_view_key, raw_view_key.data(), sizeof(public_view_key));
					else
						use_publicly_known_keypair = true;
				}
				else
				{
					memcpy(public_spend_key, verifying_key.data(), sizeof(public_spend_key));
					if (verifying_key.size() == 64)
						memcpy(public_view_key, verifying_key.data() + sizeof(public_spend_key), sizeof(public_view_key));
					else
						use_publicly_known_keypair = true;
				}

				if (use_publicly_known_keypair)
					derive_known_public_view_key(public_spend_key, public_view_key);

				uint8_t buffer[64];
				memcpy((char*)buffer, public_spend_key, sizeof(public_spend_key));
				memcpy((char*)buffer + sizeof(public_spend_key), public_view_key, sizeof(public_view_key));

				char address[256] = { 0 };
				if (xmr_base58_addr_encode_check(get_network_type(), buffer, sizeof(buffer), address, sizeof(address)) == 0)
					return layer_exception("not a valid public spend key");

				string public_spend_view_key = codec::hex_encode(std::string_view((char*)public_spend_key, sizeof(public_spend_key)));
				public_spend_view_key.append(1, ':').append(codec::hex_encode(std::string_view((char*)public_view_key, sizeof(public_view_key))));
				return expects_lr<derived_verifying_wallet>(derived_verifying_wallet({ { (uint8_t)1, string(address) } }, optional::none, std::move(public_spend_view_key)));
			}
			expects_lr<string> monero::new_public_key_hash(const std::string_view& address)
			{
				uint8_t buffer[128]; uint64_t tag;
				if (xmr_base58_addr_decode_check(address.data(), address.size(), &tag, buffer, sizeof(buffer)) == 0)
					return layer_exception("not a valid address data");
				else if (tag != get_network_type())
					return layer_exception("not a valid address type");
				return string((char*)buffer, 64);
			}
			expects_lr<string> monero::sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key)
			{
				auto signing_wallet = new_signing_wallet(asset, signing_key);
				if (!signing_wallet)
					return signing_wallet.error();

				auto private_keypair = signing_wallet->signing_key.expose<KEY_LIMIT>();
				auto private_spend_key_buffer = codec::hex_decode(private_keypair.view.substr(0, private_keypair.view.find(':')));
				auto public_split = signing_wallet->verifying_key.find(':');
				auto public_spend_key_buffer = codec::hex_decode(signing_wallet->verifying_key.substr(0, public_split));
				auto public_view_key_buffer = codec::hex_decode(signing_wallet->verifying_key.substr(public_split + 1));
				if (private_spend_key_buffer.size() != 32 || public_spend_key_buffer.size() != 32 || public_view_key_buffer.size() != 32)
					return layer_exception("bad signing/verifying keypair");

				uint8_t body[96];
				uint8_t signature_data[64];
				uint8_t* signature_c = (uint8_t*)((char*)signature_data + 00);
				uint8_t* signature_r = (uint8_t*)((char*)signature_data + 32);
				uint8_t* private_spend_key = (uint8_t*)private_spend_key_buffer.data();
				uint8_t* public_spend_key = (uint8_t*)public_spend_key_buffer.data();
				uint8_t* public_view_key = (uint8_t*)public_view_key_buffer.data();
				memcpy((char*)body + 32, public_spend_key, public_spend_key_buffer.size());
				message_hash(body, (uint8_t*)message.data(), message.size(), public_spend_key, public_view_key, 1);
			retry:
				ge_p3 point3;
				uint8_t scalar[32];
				crypto::fill_random_bytes(scalar, sizeof(scalar));
				sc_reduce32(scalar);
				ge_scalarmult_base(&point3, scalar);
				ge_p3_tobytes((uint8_t*)((char*)body + 64), &point3);
				xmr_fast_hash(signature_c, body, sizeof(body));
				sc_reduce32(signature_c);
				if (!sc_isnonzero(signature_c))
					goto retry;

				sc_mulsub(signature_r, signature_c, private_spend_key, scalar);
				if (!sc_isnonzero(signature_r))
					goto retry;

				char encoded_signature[256];
				size_t encoded_signature_size = sizeof(encoded_signature);
				if (!xmr_base58_encode(encoded_signature, &encoded_signature_size, signature_data, sizeof(signature_data)))
					return layer_exception("failed to encode the signature");

				string result = "SigV2";
				result.append(encoded_signature, encoded_signature_size);
				return expects_lr<string>(std::move(result));
			}
			expects_lr<void> monero::verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature)
			{
				uint8_t signature_data[64]; size_t signature_size = sizeof(signature_data);
				uint8_t* signature_c = (uint8_t*)((char*)signature_data + 00);
				uint8_t* signature_r = (uint8_t*)((char*)signature_data + 32);
				if (signature.size() != 64)
				{
					auto signature_digest = signature.substr(5);
					if (!xmr_base58_decode(signature_digest.data(), signature_digest.size(), signature_data, &signature_size))
						return layer_exception("failed to decode the signature");
					else if (signature_size != 64)
						return layer_exception("failed to decode the signature");
				}
				else
					memcpy(signature_data, signature.data(), signature.size());

				auto verifying_wallet = new_verifying_wallet(asset, verifying_key);
				if (!verifying_wallet)
					return verifying_wallet.error();

				auto public_split = verifying_wallet->verifying_key.find(':');
				auto public_spend_key_buffer = codec::hex_decode(verifying_wallet->verifying_key.substr(0, public_split));
				auto public_view_key_buffer = codec::hex_decode(verifying_wallet->verifying_key.substr(public_split + 1));
				if (public_spend_key_buffer.size() != 32 || public_view_key_buffer.size() != 32)
					return layer_exception("bad verifying keypair");

				uint8_t body[96];
				uint8_t* body_comm = (uint8_t*)((char*)body + 64);
				uint8_t* public_spend_key = (uint8_t*)public_spend_key_buffer.data();
				uint8_t* public_view_key = (uint8_t*)public_view_key_buffer.data();
				memcpy((char*)body + 32, public_spend_key, public_spend_key_buffer.size());
				message_hash(body, (uint8_t*)message.data(), message.size(), public_spend_key, public_view_key, 1);

				ge_p2 point2; ge_p3 point3;
				if (ge_frombytes_vartime(&point3, public_spend_key) != 0)
					return layer_exception("bad signature");
				else if (sc_check(signature_c) != 0 || sc_check(signature_r) != 0 || !sc_isnonzero(signature_c))
					return layer_exception("bad signature");

				static uint8_t infinity[32] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
				ge_double_scalarmult_base_vartime(&point2, signature_c, &point3, signature_r);
				ge_tobytes(body_comm, &point2);
				if (memcmp(body_comm, infinity, sizeof(infinity)) == 0)
					return layer_exception("bad signature");

				uint8_t c[32];
				xmr_fast_hash(c, body, sizeof(body));
				sc_reduce32(c);
				sc_sub(c, c, signature_c);
				if (sc_isnonzero(c) != 0)
					return layer_exception("bad signature");

				return expectation::met;
			}
			string monero::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/128'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
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
			uint64_t monero::get_retirement_block_number() const
			{
				return 0;
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
			bool monero::message_hash(uint8_t hash[32], const uint8_t* message, size_t message_size, const uint8_t public_spend_key[32], const uint8_t public_view_key[32], const uint8_t mode)
			{
				static const char HASH_KEY_MESSAGE_SIGNING[] = "MoneroMessageSignature";

				SHA3_CTX context;
				keccak_256_Init(&context);
				keccak_Update(&context, (const uint8_t*)HASH_KEY_MESSAGE_SIGNING, sizeof(HASH_KEY_MESSAGE_SIGNING));
				keccak_Update(&context, public_spend_key, sizeof(uint8_t) * 32);
				keccak_Update(&context, public_view_key, sizeof(uint8_t) * 32);
				keccak_Update(&context, (const uint8_t*)&mode, sizeof(uint8_t));

				uint8_t length_buffer[(sizeof(size_t) * 8 + 6) / 7];
				int length_buffer_size = xmr_write_varint(length_buffer, sizeof(length_buffer), message_size);
				if (length_buffer_size == -1)
					return false;

				keccak_Update(&context, length_buffer, (size_t)length_buffer_size);
				keccak_Update(&context, message, message_size);
				keccak_Final(&context, hash);
				return true;
			}
			void monero::derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32])
			{
				uint8_t hash[32];
				xmr_fast_hash(hash, public_spend_key, sizeof(hash));
				memcpy(private_view_key, hash, sizeof(hash));
				algorithm::composition::convert_to_scalar_ed25519(private_view_key);
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
