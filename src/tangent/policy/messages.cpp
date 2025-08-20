#include "messages.h"

namespace tangent
{
	namespace messages
	{
		uniform::uniform() : checksum(0)
		{
		}
		bool uniform::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			return store_payload(stream);
		}
		bool uniform::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		uint256_t uniform::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::wo_stream message;
			((uniform*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::wo_stream uniform::as_message() const
		{
			format::wo_stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::wo_stream uniform::as_signable() const
		{
			format::wo_stream message;
			message.write_integer(as_type());
			if (!store_payload(&message))
				message.clear();
			return message;
		}

		authentic::authentic() : checksum(0)
		{
		}
		bool authentic::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_string(signature.optimized_view());
			return store_payload(stream);
		}
		bool authentic::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			string signature_assembly;
			if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, signature.data, sizeof(signature.data)))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool authentic::sign(const algorithm::seckey_t& secret_key)
		{
			return algorithm::signing::sign(as_signable().hash(), secret_key, signature);
		}
		bool authentic::verify(const algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::verify(as_signable().hash(), public_key, signature);
		}
		bool authentic::recover(algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::recover(as_signable().hash(), public_key, signature);
		}
		bool authentic::recover_hash(algorithm::pubkeyhash_t& public_key_hash) const
		{
			return algorithm::signing::recover_hash(as_signable().hash(), public_key_hash, signature);
		}
		uint256_t authentic::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::wo_stream message;
			((authentic*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::wo_stream authentic::as_message() const
		{
			format::wo_stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::wo_stream authentic::as_signable() const
		{
			format::wo_stream message;
			message.write_integer(as_type());
			if (!store_payload(&message))
				message.clear();
			return message;
		}
	}
}