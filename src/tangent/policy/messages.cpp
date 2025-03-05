#include "messages.h"

namespace tangent
{
	namespace messages
	{
		standard::standard() : checksum(0), version(protocol::now().message.protocol_version)
		{
		}
		bool standard::store(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(version);
			stream->write_integer(as_type());
			return store_payload(stream);
		}
		bool standard::load(format::stream& stream)
		{
			auto type = resolve_type(stream, &version);
			if (!type || *type != as_type())
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		uint256_t standard::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::stream message;
			((standard*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::stream standard::as_message() const
		{
			format::stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::stream standard::as_payload() const
		{
			format::stream message;
			if (!store_payload(&message))
				message.clear();
			return message;
		}
		option<uint32_t> standard::resolve_type(format::stream& stream, uint32_t* out_version)
		{
			uint32_t version; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &version))
			{
				if (!out_version)
					stream.seek = seek;
				return optional::none;
			}

			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type))
				return optional::none;

			if (out_version)
				*out_version = version;
			else
				stream.seek = seek;
			return type;
		}

		authentic::authentic() : checksum(0), version(protocol::now().message.protocol_version)
		{
		}
		bool authentic::store(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(version);
			stream->write_integer(as_type());
			stream->write_string(std::string_view((char*)signature, sizeof(signature)));
			return store_payload(stream);
		}
		bool authentic::load(format::stream& stream)
		{
			auto type = resolve_type(stream, &version);
			if (!type || *type != as_type())
				return false;

			string signature_assembly;
			if (!stream.read_string(stream.read_type(), &signature_assembly) || signature_assembly.size() != sizeof(algorithm::recsighash))
				return false;

			memcpy(signature, signature_assembly.data(), signature_assembly.size());
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
		void authentic::set_signature(const algorithm::recsighash new_value)
		{
			VI_ASSERT(new_value != nullptr, "new value should be set");
			memcpy(signature, new_value, sizeof(algorithm::recsighash));
		}
		bool authentic::is_signature_null() const
		{
			algorithm::recsighash null = { 0 };
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
		option<uint32_t> authentic::resolve_type(format::stream& stream, uint32_t* out_version)
		{
			uint32_t version; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &version))
			{
				if (!out_version)
					stream.seek = seek;
				return optional::none;
			}

			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type))
				return optional::none;

			if (out_version)
				*out_version = version;
			else
				stream.seek = seek;
			return type;
		}
	}
}