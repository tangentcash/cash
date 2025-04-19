#include "messages.h"

namespace tangent
{
	namespace messages
	{
		uniform::uniform() : checksum(0)
		{
		}
		bool uniform::store(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			return store_payload(stream);
		}
		bool uniform::load(format::stream& stream)
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

			format::stream message;
			((uniform*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::stream uniform::as_message() const
		{
			format::stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::stream uniform::as_payload() const
		{
			format::stream message;
			if (!store_payload(&message))
				message.clear();
			return message;
		}

		authentic::authentic() : checksum(0)
		{
		}
		bool authentic::store(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::recpubsig null = { 0 };
			stream->write_integer(as_type());
			stream->write_string(std::string_view((char*)signature, memcmp(signature, null, sizeof(null)) != 0 ? sizeof(signature) : 0));
			return store_payload(stream);
		}
		bool authentic::load(format::stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			string signature_assembly;
			if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_uint_blob(signature_assembly, signature, sizeof(signature)))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool authentic::sign(const algorithm::seckey secret_key)
		{
			format::stream message;
			if (!store_payload(&message))
				return false;

			return algorithm::signing::sign(message.hash(), secret_key, signature);
		}
		bool authentic::verify(const algorithm::pubkey public_key) const
		{
			format::stream message;
			if (!store_payload(&message))
				return false;

			return algorithm::signing::verify(message.hash(), public_key, signature);
		}
		bool authentic::recover(algorithm::pubkey public_key) const
		{
			format::stream message;
			if (!store_payload(&message))
				return false;

			return algorithm::signing::recover(message.hash(), public_key, signature);
		}
		bool authentic::recover_hash(algorithm::pubkeyhash public_key_hash) const
		{
			format::stream message;
			if (!store_payload(&message))
				return false;

			return algorithm::signing::recover_hash(message.hash(), public_key_hash, signature);
		}
		void authentic::set_signature(const algorithm::recpubsig new_value)
		{
			VI_ASSERT(new_value != nullptr, "new value should be set");
			memcpy(signature, new_value, sizeof(algorithm::recpubsig));
		}
		bool authentic::is_signature_null() const
		{
			algorithm::recpubsig null = { 0 };
			return memcmp(signature, null, sizeof(null)) == 0;
		}
		uint256_t authentic::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::stream message;
			((authentic*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::stream authentic::as_message() const
		{
			format::stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::stream authentic::as_payload() const
		{
			format::stream message;
			if (!store_payload(&message))
				message.clear();
			return message;
		}
	}
}