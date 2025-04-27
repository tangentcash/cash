#include "wallet.h"
#include "../validator/storage/mempoolstate.h"
#include "../validator/storage/chainstate.h"
#include "../validator/service/p2p.h"

namespace tangent
{
	namespace ledger
	{
		bool wallet::set_secret_key(const algorithm::seckey value)
		{
			memset(secret_key, 0, sizeof(secret_key));
			memset(public_key, 0, sizeof(public_key));
			memset(public_key_hash, 0, sizeof(public_key_hash));
			if (value != nullptr)
				memcpy(secret_key, value, sizeof(secret_key));

			if (!has_secret_key())
				return false;

			if (!algorithm::signing::derive_public_key(secret_key, public_key))
				return false;

			algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
			return true;
		}
		void wallet::set_public_key(const algorithm::pubkey value)
		{
			memset(secret_key, 0, sizeof(secret_key));
			memset(public_key, 0, sizeof(public_key));
			memset(public_key_hash, 0, sizeof(public_key_hash));
			if (value != nullptr)
				memcpy(public_key, value, sizeof(public_key));

			if (has_public_key())
				algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
		}
		void wallet::set_public_key_hash(const algorithm::pubkeyhash value)
		{
			memset(secret_key, 0, sizeof(secret_key));
			memset(public_key, 0, sizeof(public_key));
			memset(public_key_hash, 0, sizeof(public_key_hash));
			if (value != nullptr)
				memcpy(public_key_hash, value, sizeof(public_key_hash));
		}
		bool wallet::verify_secret_key() const
		{
			return has_secret_key() && algorithm::signing::verify_secret_key(secret_key);
		}
		bool wallet::verify_public_key() const
		{
			if (!verify_secret_key())
				return false;

			algorithm::pubkey copy = { 0 };
			algorithm::signing::derive_public_key(secret_key, copy);
			if (memcmp(public_key, copy, sizeof(copy)) != 0)
				return false;

			return has_public_key() && algorithm::signing::verify_public_key(public_key);
		}
		bool wallet::verify_address() const
		{
			if (!verify_public_key())
				return false;

			algorithm::pubkeyhash copy;
			algorithm::signing::derive_public_key_hash(public_key, copy);
			if (memcmp(public_key_hash, copy, sizeof(copy)) != 0)
				return false;

			return has_public_key_hash() && algorithm::signing::verify_address(get_address());
		}
		bool wallet::verify(const messages::authentic& message) const
		{
			return has_public_key() && message.verify(public_key);
		}
		bool wallet::recovers(const messages::authentic& message) const
		{
			algorithm::pubkeyhash recover_public_key_hash;
			return message.recover_hash(recover_public_key_hash) && memcmp(recover_public_key_hash, public_key_hash, sizeof(public_key_hash)) == 0;
		}
		bool wallet::sign(messages::authentic& message) const
		{
			return has_secret_key() && message.sign(secret_key);
		}
		bool wallet::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(std::string_view((char*)secret_key, has_secret_key() ? sizeof(secret_key) : 0));
			stream->write_string(std::string_view((char*)public_key, has_public_key() ? sizeof(public_key) : 0));
			stream->write_string(std::string_view((char*)public_key_hash, has_public_key_hash() ? sizeof(public_key_hash) : 0));
			return true;
		}
		bool wallet::load_payload(format::stream& stream)
		{
			string secret_key_assembly; memset(secret_key, 0, sizeof(secret_key));
			if (!stream.read_string(stream.read_type(), &secret_key_assembly))
				return false;

			if (!secret_key_assembly.empty())
			{
				if (secret_key_assembly.size() != sizeof(secret_key))
					return false;

				memcpy(secret_key, secret_key_assembly.data(), sizeof(secret_key));
			}

			string public_key_assembly; memset(public_key, 0, sizeof(public_key));
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			if (!public_key_assembly.empty())
			{
				if (public_key_assembly.size() != sizeof(public_key))
					return false;

				memcpy(public_key, public_key_assembly.data(), sizeof(public_key));
			}

			string public_key_hash_assembly; memset(public_key_hash, 0, sizeof(public_key_hash));
			if (!stream.read_string(stream.read_type(), &public_key_hash_assembly))
				return false;

			if (!public_key_hash_assembly.empty())
			{
				if (public_key_hash_assembly.size() != sizeof(public_key_hash))
					return false;

				memcpy(public_key_hash, public_key_hash_assembly.data(), sizeof(public_key_hash));
			}

			return true;
		}
		bool wallet::has_secret_key() const
		{
			algorithm::seckey null = { 0 };
			return memcmp(secret_key, null, sizeof(null)) != 0;
		}
		bool wallet::has_public_key() const
		{
			algorithm::pubkey null = { 0 };
			return memcmp(public_key, null, sizeof(null)) != 0;
		}
		bool wallet::has_public_key_hash() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(public_key_hash, null, sizeof(null)) != 0;
		}
		option<string> wallet::seal_message(const std::string_view& plaintext, const algorithm::pubkey cipher_public_key, const std::string_view& entropy) const
		{
			return algorithm::signing::public_encrypt(cipher_public_key, plaintext, entropy);
		}
		option<string> wallet::open_message(const uint256_t& nonce, const std::string_view& ciphertext) const
		{
			if (!has_secret_key())
				return optional::none;

			algorithm::seckey cipher_secret_key;
			algorithm::pubkey cipher_public_key;
			algorithm::signing::derive_cipher_keypair(secret_key, nonce, cipher_secret_key, cipher_public_key);
			return algorithm::signing::private_decrypt(cipher_secret_key, cipher_public_key, ciphertext);
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
			auto mempool = storages::mempoolstate(__func__);
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::account_nonce::as_instance_index(public_key_hash), 0);
			uint64_t pending_nonce = mempool.get_highest_transaction_nonce(public_key_hash).or_else(0);
			uint64_t finalized_nonce = (state ? ((states::account_nonce*)**state)->nonce : 0);
			return std::max(finalized_nonce, pending_nonce);
		}
		uptr<schema> wallet::as_schema() const
		{
			schema* data = var::set::object();
			data->set("secret_key", algorithm::signing::serialize_secret_key(secret_key));
			data->set("public_key", algorithm::signing::serialize_public_key(public_key));
			data->set("public_key_hash", var::string(format::util::encode_0xhex(std::string_view((char*)public_key_hash, sizeof(public_key_hash)))));
			data->set("address", algorithm::signing::serialize_address(public_key_hash));
			return data;
		}
		uptr<schema> wallet::as_public_schema() const
		{
			schema* data = var::set::object();
			data->set("public_key", algorithm::signing::serialize_public_key(public_key));
			data->set("public_key_hash", var::string(format::util::encode_0xhex(std::string_view((char*)public_key_hash, sizeof(public_key_hash)))));
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
			algorithm::seckey key;
			algorithm::signing::derive_secret_key_from_mnemonic(mnemonic, key);
			return from_secret_key(key);
		}
		wallet wallet::from_seed(const std::string_view& seed)
		{
			algorithm::seckey key;
			if (seed.empty())
			{
				auto entropy = *crypto::random_bytes(64);
				algorithm::signing::derive_secret_key(entropy, key);
			}
			else
				algorithm::signing::derive_secret_key(seed, key);
			return from_secret_key(key);
		}
		wallet wallet::from_secret_key(const algorithm::seckey key)
		{
			wallet result;
			result.set_secret_key(key);
			return result;
		}
		wallet wallet::from_public_key(const algorithm::pubkey key)
		{
			wallet result;
			result.set_public_key(key);
			return result;
		}
		wallet wallet::from_public_key_hash(const algorithm::pubkeyhash key)
		{
			wallet result;
			result.set_public_key_hash(key);
			return result;
		}

		bool validator::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(address.get_ip_address().or_else(string()));
			stream->write_integer(address.get_ip_port().or_else(0));
			stream->write_integer(availability.latency);
			stream->write_integer(availability.timestamp);
			stream->write_integer(availability.calls);
			stream->write_integer(availability.errors);
			stream->write_integer(ports.p2p);
			stream->write_integer(ports.nds);
			stream->write_integer(ports.rpc);
			stream->write_boolean(services.has_consensus);
			stream->write_boolean(services.has_discovery);
			stream->write_boolean(services.has_synchronization);
			stream->write_boolean(services.has_interfaces);
			stream->write_boolean(services.has_production);
			stream->write_boolean(services.has_participation);
			stream->write_boolean(services.has_attestation);
			stream->write_boolean(services.has_querying);
			stream->write_boolean(services.has_streaming);
			return true;
		}
		bool validator::load_payload(format::stream& stream)
		{
			string ip_address;
			if (!stream.read_string(stream.read_type(), &ip_address))
				return false;

			uint16_t ip_port;
			if (!stream.read_integer(stream.read_type(), &ip_port))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.latency))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.timestamp))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.calls))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.errors))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.p2p))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.nds))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.rpc))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_consensus))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_discovery))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_synchronization))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_interfaces))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_production))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_participation))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_attestation))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_querying))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_streaming))
				return false;

			address = socket_address(ip_address, ip_port);
			return true;
		}
		bool validator::is_valid() const
		{
			if (!address.is_valid())
				return false;

			return !p2p::routing::is_address_reserved(address);
		}
		uint64_t validator::get_preference() const
		{
			double messages = (double)availability.calls;
			double confidence = messages > 0.0 ? mathd::exp((double)(availability.calls < availability.errors ? 0 : availability.calls - availability.errors) / messages) : 0.0;
			double uncertainty = messages > 0.0 ? mathd::exp((double)availability.errors / messages) : 0.0;
			double preference = availability.latency > 0.0 ? 1000.0 / (double)availability.latency : 1000.0;
			double score = (confidence - uncertainty) * preference + preference * 0.1;
			return (uint64_t)(1000.0 * score);
		}
		uptr<schema> validator::as_schema() const
		{
			schema* data = var::set::object();
			data->set("address", var::string(address.get_ip_address().or_else("[bad_address]") + ":" + to_string(address.get_ip_port().or_else(0))));

			auto* availability_data = data->set("availability");
			availability_data->set("latency", algorithm::encoding::serialize_uint256(availability.latency));
			availability_data->set("timestamp", algorithm::encoding::serialize_uint256(availability.timestamp));
			availability_data->set("calls", algorithm::encoding::serialize_uint256(availability.calls));
			availability_data->set("errors", algorithm::encoding::serialize_uint256(availability.errors));

			auto* ports_data = data->set("ports");
			ports_data->set("p2p", var::integer(ports.p2p));
			ports_data->set("nds", var::integer(ports.nds));
			ports_data->set("rpc", var::integer(ports.rpc));

			auto* services_data = data->set("services");
			services_data->set("consensus", var::boolean(services.has_consensus));
			services_data->set("discovery", var::boolean(services.has_discovery));
			services_data->set("synchronization", var::boolean(services.has_synchronization));
			services_data->set("interfaces", var::boolean(services.has_interfaces));
			services_data->set("production", var::boolean(services.has_production));
			services_data->set("participation", var::boolean(services.has_participation));
			services_data->set("attestation", var::boolean(services.has_attestation));
			services_data->set("querying", var::boolean(services.has_querying));
			services_data->set("streaming", var::boolean(services.has_streaming));
			return data;
		}
		uint32_t validator::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t validator::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator::as_instance_typename()
		{
			return "validator";
		}
	}
}