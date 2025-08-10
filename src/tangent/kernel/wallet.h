#ifndef TAN_KERNEL_WALLET_H
#define TAN_KERNEL_WALLET_H
#include "../policy/messages.h"

namespace tangent
{
	namespace ledger
	{
		struct wallet : messages::uniform
		{
			algorithm::seckey_t secret_key;
			algorithm::pubkey_t public_key;
			algorithm::pubkeyhash_t public_key_hash;

			bool set_secret_key(const algorithm::seckey_t& value);
			void set_public_key(const algorithm::pubkey_t& value);
			void set_public_key_hash(const algorithm::pubkeyhash_t& value);
			bool verify_secret_key() const;
			bool verify_public_key() const;
			bool verify_address() const;
			bool verify(const messages::authentic& message) const;
			bool recovers(const messages::authentic& message) const;
			bool sign(messages::authentic& message) const;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool has_secret_key() const;
			bool has_public_key() const;
			bool has_public_key_hash() const;
			option<string> seal_message(const std::string_view& plaintext, const algorithm::pubkey_t& cipher_public_key, const std::string_view& entropy) const;
			option<string> open_message(const uint256_t& nonce, const std::string_view& ciphertext) const;
			string get_secret_key() const;
			string get_public_key() const;
			string get_address() const;
			expects_lr<uint64_t> get_latest_nonce() const;
			uptr<schema> as_schema() const override;
			uptr<schema> as_public_schema() const;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static wallet from_mnemonic(const std::string_view& mnemonic);
			static wallet from_seed(const std::string_view& seed = std::string_view());
			static wallet from_secret_key(const algorithm::seckey_t& key);
			static wallet from_public_key(const algorithm::pubkey_t& key);
			static wallet from_public_key_hash(const algorithm::pubkeyhash_t& key);
		};

		struct validator final : messages::uniform
		{
			struct
			{
				uint64_t latency = (uint64_t)std::numeric_limits<int64_t>::max();
				uint64_t timestamp = 0;
				uint64_t calls = 0;
				uint64_t errors = 0;
			} availability;

			struct
			{
				uint16_t p2p = 0;
				uint16_t nds = 0;
				uint16_t rpc = 0;
			} ports;

			struct
			{
				bool has_consensus = false;
				bool has_discovery = false;
				bool has_interfaces = false;
				bool has_synchronization = false;
				bool has_production = false;
				bool has_participation = false;
				bool has_attestation = false;
				bool has_querying = false;
				bool has_streaming = false;
			} services;

			socket_address address;

			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_valid() const;
			uint64_t get_preference() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};
	}
}
#endif