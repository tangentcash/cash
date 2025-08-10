#ifndef TAN_POLICY_MESSAGES_H
#define TAN_POLICY_MESSAGES_H
#include "../kernel/algorithm.h"

namespace tangent
{
	namespace messages
	{
		struct uniform
		{
			uint256_t checksum;

			uniform();
			virtual ~uniform() = default;
			virtual bool store(format::wo_stream* stream) const;
			virtual bool load(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const = 0;
			virtual bool load_payload(format::ro_stream& stream) = 0;
			virtual uint256_t as_hash(bool renew = false) const;
			virtual uint32_t as_type() const = 0;
			virtual std::string_view as_typename() const = 0;
			virtual uptr<schema> as_schema() const = 0;
			virtual format::wo_stream as_message() const;
			virtual format::wo_stream as_signable() const;
		};

		struct authentic
		{
			algorithm::hashsig_t signature;
			uint256_t checksum;

			authentic();
			virtual ~authentic() = default;
			virtual bool store(format::wo_stream* stream) const;
			virtual bool load(format::ro_stream& stream);
			virtual bool store_payload(format::wo_stream* stream) const = 0;
			virtual bool load_payload(format::ro_stream& stream) = 0;
			virtual bool sign(const algorithm::seckey_t& secret_key);
			virtual bool verify(const algorithm::pubkey_t& public_key) const;
			virtual bool recover(algorithm::pubkey_t& public_key) const;
			virtual bool recover_hash(algorithm::pubkeyhash_t& public_key_hash) const;
			virtual uint256_t as_hash(bool renew = false) const;
			virtual uint32_t as_type() const = 0;
			virtual std::string_view as_typename() const = 0;
			virtual uptr<schema> as_schema() const = 0;
			virtual format::wo_stream as_message() const;
			virtual format::wo_stream as_signable() const;
		};
	}
}
#endif