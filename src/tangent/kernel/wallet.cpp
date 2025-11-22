#include "wallet.h"
#include "../validator/storage/mempoolstate.h"
#include "../validator/storage/chainstate.h"
#include "../validator/service/consensus.h"

namespace tangent
{
	namespace ledger
	{
		bool wallet::set_secret_key(const algorithm::seckey_t& value)
		{
			secret_key = value;
			public_key.clear();
			public_key_hash.clear();
			if (!has_secret_key())
				return false;

			if (!algorithm::signing::derive_public_key(secret_key, public_key))
				return false;

			algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
			return true;
		}
		void wallet::set_public_key(const algorithm::pubkey_t& value)
		{
			secret_key.clear();
			public_key = value;
			public_key_hash.clear();
			if (has_public_key())
				algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
		}
		void wallet::set_public_key_hash(const algorithm::pubkeyhash_t& value)
		{
			secret_key.clear();
			public_key.clear();
			public_key_hash = value;
		}
		bool wallet::verify_secret_key() const
		{
			return has_secret_key() && algorithm::signing::verify_secret_key(secret_key);
		}
		bool wallet::verify_public_key() const
		{
			if (!verify_secret_key())
				return false;

			algorithm::pubkey_t copy;
			algorithm::signing::derive_public_key(secret_key, copy);
			if (public_key != copy)
				return false;

			return has_public_key() && algorithm::signing::verify_public_key(public_key);
		}
		bool wallet::verify_address() const
		{
			if (!verify_public_key())
				return false;

			algorithm::pubkeyhash_t copy;
			algorithm::signing::derive_public_key_hash(public_key, copy);
			if (public_key_hash != copy)
				return false;

			return has_public_key_hash() && algorithm::signing::verify_address(get_address());
		}
		bool wallet::verify(const messages::authentic& message) const
		{
			return has_public_key() && message.verify(public_key);
		}
		bool wallet::recovers(const messages::authentic& message) const
		{
			algorithm::pubkeyhash_t recover_public_key_hash;
			return message.recover_hash(recover_public_key_hash) && recover_public_key_hash == public_key_hash;
		}
		bool wallet::sign(messages::authentic& message) const
		{
			return has_secret_key() && message.sign(secret_key);
		}
		bool wallet::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(secret_key.optimized_view());
			stream->write_string(public_key.optimized_view());
			stream->write_string(public_key_hash.optimized_view());
			return true;
		}
		bool wallet::load_payload(format::ro_stream& stream)
		{
			string secret_key_assembly; secret_key.clear();
			if (!stream.read_string(stream.read_type(), &secret_key_assembly))
				return false;

			if (!secret_key_assembly.empty())
			{
				if (secret_key_assembly.size() != sizeof(secret_key))
					return false;

				memcpy(secret_key.data, secret_key_assembly.data(), sizeof(secret_key));
			}

			string public_key_assembly; public_key.clear();
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			if (!public_key_assembly.empty())
			{
				if (public_key_assembly.size() != sizeof(public_key))
					return false;

				memcpy(public_key.data, public_key_assembly.data(), sizeof(public_key));
			}

			string public_key_hash_assembly; public_key_hash.clear();
			if (!stream.read_string(stream.read_type(), &public_key_hash_assembly))
				return false;

			if (!public_key_hash_assembly.empty())
			{
				if (public_key_hash_assembly.size() != sizeof(public_key_hash))
					return false;

				memcpy(public_key_hash.data, public_key_hash_assembly.data(), sizeof(public_key_hash));
			}

			return true;
		}
		bool wallet::has_secret_key() const
		{
			return !secret_key.empty();
		}
		bool wallet::has_public_key() const
		{
			return !public_key.empty();
		}
		bool wallet::has_public_key_hash() const
		{
			return !public_key_hash.empty();
		}
		option<string> wallet::seal_message(const std::string_view& plaintext, const algorithm::pubkey_t& recipient_public_key, const uint256_t& entropy) const
		{
			return algorithm::signing::public_encrypt(recipient_public_key, plaintext, entropy);
		}
		option<string> wallet::open_message(const std::string_view& ciphertext) const
		{
			if (!has_secret_key())
				return optional::none;

			return algorithm::signing::private_decrypt(secret_key, ciphertext);
		}
		option<string> wallet::open_message(const std::string_view& ciphertext, const uint256_t& entropy) const
		{
			if (!has_secret_key())
				return optional::none;

			algorithm::seckey_t child_secret_key;
			algorithm::signing::derive_secret_key_from_parent(secret_key, entropy, child_secret_key);
			return algorithm::signing::private_decrypt(child_secret_key, ciphertext);
		}
		string wallet::get_secret_key() const
		{
			string value;
			if (!has_secret_key())
				return value;

			algorithm::signing::encode_secret_key(secret_key, value);
			return value;
		}
		string wallet::get_public_key() const
		{
			string value;
			if (!has_public_key())
				return value;

			algorithm::signing::encode_public_key(public_key, value);
			return value;
		}
		string wallet::get_address() const
		{
			string value;
			if (!has_public_key_hash())
				return value;

			algorithm::signing::encode_address(public_key_hash, value);
			return value;
		}
		expects_lr<uint64_t> wallet::get_latest_nonce() const
		{
			auto mempool = storages::mempoolstate();
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(public_key_hash), 0);
			uint64_t pending_nonce = mempool.get_highest_transaction_nonce(public_key_hash).or_else(0);
			uint64_t finalized_nonce = (state ? state->as<states::account_nonce>()->nonce : 0);
			return std::max(finalized_nonce, pending_nonce);
		}
		uptr<schema> wallet::as_schema() const
		{
			schema* data = var::set::object();
			data->set("secret_key", algorithm::signing::serialize_secret_key(secret_key));
			data->set("public_key", algorithm::signing::serialize_public_key(public_key));
			data->set("public_key_hash", var::string(format::util::encode_0xhex(public_key_hash.optimized_view())));
			data->set("address", algorithm::signing::serialize_address(public_key_hash));
			return data;
		}
		uptr<schema> wallet::as_public_schema() const
		{
			schema* data = var::set::object();
			data->set("public_key", algorithm::signing::serialize_public_key(public_key));
			data->set("public_key_hash", var::string(format::util::encode_0xhex(public_key_hash.optimized_view())));
			data->set("address", algorithm::signing::serialize_address(public_key_hash));
			return data;
		}
		uint32_t wallet::as_type() const
		{
			return as_instance_type();
		}
		std::string_view wallet::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t wallet::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view wallet::as_instance_typename()
		{
			return "wallet";
		}
		wallet wallet::from_mnemonic(const std::string_view& mnemonic)
		{
			algorithm::seckey_t key;
			algorithm::signing::derive_secret_key_from_mnemonic(mnemonic, key);
			return from_secret_key(key);
		}
		wallet wallet::from_seed(const std::string_view& seed)
		{
			return from_entropy(algorithm::hashing::hash256i(seed.empty() ? *crypto::random_bytes(64) : seed));
		}
		wallet wallet::from_entropy(const uint256_t& entropy)
		{
			algorithm::seckey_t key;
			algorithm::signing::derive_secret_key(entropy, key);
			return from_secret_key(key);
		}
		wallet wallet::from_secret_key(const algorithm::seckey_t& key)
		{
			wallet result;
			result.set_secret_key(key);
			return result;
		}
		wallet wallet::from_public_key(const algorithm::pubkey_t& key)
		{
			wallet result;
			result.set_public_key(key);
			return result;
		}
		wallet wallet::from_public_key_hash(const algorithm::pubkeyhash_t& key)
		{
			wallet result;
			result.set_public_key_hash(key);
			return result;
		}

		bool node::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(address.get_ip_address().or_else(string()));
			stream->write_integer(address.get_ip_port().or_else(0));
			stream->write_integer(version);
			stream->write_integer(availability.latency);
			stream->write_integer(availability.timestamp);
			stream->write_integer(availability.calls);
			stream->write_integer(availability.errors);
			stream->write_boolean(availability.reachable);
			stream->write_integer(ports.consensus);
			stream->write_integer(ports.discovery);
			stream->write_integer(ports.rpc);
			stream->write_boolean(services.has_consensus);
			stream->write_boolean(services.has_discovery);
			stream->write_boolean(services.has_oracle);
			stream->write_boolean(services.has_rpc);
			stream->write_boolean(services.has_rpc_web_sockets);
			stream->write_boolean(services.has_production);
			stream->write_boolean(services.has_participation);
			stream->write_boolean(services.has_attestation);
			return true;
		}
		bool node::load_payload(format::ro_stream& stream)
		{
			string ip_address;
			if (!stream.read_string(stream.read_type(), &ip_address))
				return false;

			uint16_t ip_port;
			if (!stream.read_integer(stream.read_type(), &ip_port))
				return false;

			if (!stream.read_integer(stream.read_type(), &version))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.latency))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.timestamp))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.calls))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.errors))
				return false;

			if (!stream.read_boolean(stream.read_type(), &availability.reachable))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.consensus))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.discovery))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.rpc))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_consensus))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_discovery))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_oracle))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_rpc))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_rpc_web_sockets))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_production))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_participation))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_attestation))
				return false;

			address = socket_address(ip_address, ip_port);
			return true;
		}
		bool node::is_valid() const
		{
			if (!address.is_valid())
				return false;

			return !consensus::routing_util::is_address_reserved(address);
		}
		uint64_t node::get_preference() const
		{
			const double min_step = 32.0, max_latency = 500.0;
			double responses = std::max((double)availability.calls, min_step);
			double errors = std::min(std::max((double)availability.errors, 0.0), responses);
			double latency = mathd::exp(-(double)availability.latency / max_latency);
			double reliability = availability.calls > 0 ? 1.0 - errors / responses : 1;
			double index = latency * 0.75 + reliability * 0.25;
			return (uint64_t)(1000000.0 * index);
		}
		uptr<schema> node::as_schema() const
		{
			schema* data = var::set::object();
			data->set("address", var::string(address.get_ip_address().or_else("[bad_address]") + ":" + to_string(address.get_ip_port().or_else(0))));
			data->set("version", var::string(as_version()));

			auto* availability_data = data->set("availability");
			availability_data->set("latency", algorithm::encoding::serialize_uint256(availability.latency));
			availability_data->set("timestamp", algorithm::encoding::serialize_uint256(availability.timestamp));
			availability_data->set("calls", algorithm::encoding::serialize_uint256(availability.calls));
			availability_data->set("errors", algorithm::encoding::serialize_uint256(availability.errors));
			availability_data->set("reachable", var::boolean(availability.reachable));

			auto* ports_data = data->set("ports");
			ports_data->set("consensus", var::integer(ports.consensus));
			ports_data->set("discovery", var::integer(ports.discovery));
			ports_data->set("rpc", var::integer(ports.rpc));

			auto* services_data = data->set("services");
			services_data->set("consensus", var::boolean(services.has_consensus));
			services_data->set("discovery", var::boolean(services.has_discovery));
			services_data->set("oracle", var::boolean(services.has_oracle));
			services_data->set("rpc", var::boolean(services.has_rpc));
			services_data->set("rpc_web_sockets", var::boolean(services.has_rpc_web_sockets));
			services_data->set("production", var::boolean(services.has_production));
			services_data->set("participation", var::boolean(services.has_participation));
			services_data->set("attestation", var::boolean(services.has_attestation));
			return data;
		}
		string node::as_version() const
		{
			uint8_t data[16]; size_t data_size = sizeof(data);
			uint128_t(version).encode_compact(data, &data_size);
			return "0x" + codec::hex_encode(std::string_view((char*)data, data_size));
		}
		uint32_t node::as_type() const
		{
			return as_instance_type();
		}
		std::string_view node::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t node::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view node::as_instance_typename()
		{
			return "node";
		}
	}
}