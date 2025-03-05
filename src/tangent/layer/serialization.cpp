#include "serialization.h"
#include "../kernel/algorithm.h"

namespace tangent
{
	namespace format
	{
		static uint256_t contextual_parse_uint256(const std::string_view& numeric)
		{
			if (numeric.size() < 3)
				return uint256_t(*from_string<uint8_t>(numeric));
			else if (numeric.size() < 5)
				return uint256_t(*from_string<uint16_t>(numeric));
			else if (numeric.size() < 10)
				return uint256_t(*from_string<uint32_t>(numeric));
			else if (numeric.size() < 20)
				return uint256_t(*from_string<uint64_t>(numeric));

			return uint256_t(numeric);
		}

		stream::stream() : checksum(0), seek(0)
		{
		}
		stream::stream(const std::string_view& new_data) : data(new_data), checksum(0), seek(0)
		{
		}
		stream::stream(string&& new_data) : data(std::move(new_data)), checksum(0), seek(0)
		{
		}
		size_t stream::read(void* value, uint32_t size)
		{
			if (!value || !size || size + seek > data.size())
				return 0;

			memcpy(value, data.data() + seek, (size_t)size);
			seek += size;
			return size;
		}
		viewable stream::read_type()
		{
			viewable type = viewable::invalid;
			return read_type(&type) ? type : viewable::invalid;
		}
		bool stream::read_type(viewable* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			return read(value, sizeof(uint8_t)) == sizeof(uint8_t);
		}
		bool stream::read_string(viewable type, string* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			if (util::is_string(type))
			{
				char buffer[256];
				uint8_t size = util::get_string_size(type);
				if (read(buffer, size) != size)
					return false;

				if (util::is_string16(type))
					value->assign(util::encode_0xhex(std::string_view(buffer, (size_t)size)));
				else
					value->assign(buffer, (size_t)size);
				return true;
			}
			else if (type != viewable::string_any10 && type != viewable::string_any16)
				return false;

			viewable subtype; uint32_t size = 0;
			if (!read_type(&subtype) || !read_integer(subtype, &size) || size > protocol::now().message.max_message_size)
				return false;

			vector<char> data;
			data.resize((size_t)size);
			if (read((void*)data.data(), size) != size)
				return false;

			switch (type)
			{
				case viewable::string_any10:
					value->assign(data.begin(), data.end());
					return true;
				case viewable::string_any16:
					value->assign(util::encode_0xhex(std::string_view(data.data(), data.size())));
					return true;
				default:
					return false;
			}
		}
		bool stream::read_decimal(viewable type, decimal* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			viewable subtype;
			if (type == viewable::decimal_nan)
			{
				*value = decimal::nan();
				return true;
			}
			else if (type == viewable::decimal_zero)
			{
				*value = decimal::zero();
				return true;
			}
			else if (type != viewable::decimal_neg1 && type != viewable::decimal_neg2 && type != viewable::decimal_pos1 && type != viewable::decimal_pos2)
				return false;

			uint256_t left;
			if (!read_type(&subtype) || !read_integer(subtype, &left))
				return false;

			string numeric = "-";
			numeric.append(left.to_string());
			if (type == viewable::decimal_neg2 || type == viewable::decimal_pos2)
			{
				uint256_t right;
				if (!read_type(&subtype) || !read_integer(subtype, &right))
					return false;

				numeric.append(1, '.');
				size_t offset = numeric.size();
				numeric.append(right.to_string());
				std::reverse(numeric.begin() + offset, numeric.end());
			}

			if (type != viewable::decimal_neg1 && type != viewable::decimal_neg2)
				*value = decimal(std::string_view(numeric).substr(1));
			else
				*value = decimal(numeric);
			return true;
		}
		bool stream::read_integer(viewable type, uint8_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint8_t>::max())
				return false;

			*value = (uint8_t)base;
			return true;
		}
		bool stream::read_integer(viewable type, uint16_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint16_t>::max())
				return false;

			*value = (uint16_t)base;
			return true;
		}
		bool stream::read_integer(viewable type, uint32_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint32_t>::max())
				return false;

			*value = (uint32_t)base;
			return true;
		}
		bool stream::read_integer(viewable type, uint64_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint64_t>::max())
				return false;

			*value = (uint64_t)base;
			return true;
		}
		bool stream::read_integer(viewable type, uint128_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > uint128_t::max())
				return false;

			*value = (uint128_t)base;
			return true;
		}
		bool stream::read_integer(viewable type, uint256_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			if (!util::is_integer(type))
				return false;

			uint64_t array[4] = { 0 };
			uint8_t size = util::get_integer_size(type);
			if (read(array, size) != size)
				return false;

			auto& bits0 = value->low().low();
			auto& bits1 = value->low().high();
			auto& bits2 = value->high().low();
			auto& bits3 = value->high().high();
			array[0] = os::hw::to_endianness(os::hw::endian::little, array[0]);
			array[1] = os::hw::to_endianness(os::hw::endian::little, array[1]);
			array[2] = os::hw::to_endianness(os::hw::endian::little, array[2]);
			array[3] = os::hw::to_endianness(os::hw::endian::little, array[3]);
			memcpy((uint64_t*)&bits0, &array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&bits1, &array[1], sizeof(uint64_t));
			memcpy((uint64_t*)&bits2, &array[2], sizeof(uint64_t));
			memcpy((uint64_t*)&bits3, &array[3], sizeof(uint64_t));
			return true;
		}
		bool stream::read_boolean(viewable type, bool* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			if (type != viewable::true_type && type != viewable::false_type)
				return false;

			*value = (type == viewable::true_type);
			return true;
		}
		stream& stream::clear()
		{
			data.clear();
			checksum = 0;
			seek = 0;
			return *this;
		}
		stream& stream::rewind(size_t offset)
		{
			seek = (offset <= data.size() ? offset : data.size());
			return *this;
		}
		void stream::write(const void* value, uint32_t size)
		{
			if (size > 0 && value != nullptr)
			{
				size_t index = data.size();
				data.resize(data.size() + (size_t)size);
				memcpy((char*)data.data() + index, value, (size_t)size);
				checksum = 0;
			}
		}
		stream& stream::write_string(const std::string_view& value)
		{
			if (util::is_hex_encoding(value))
			{
				string source = codec::hex_decode(value);
				if (source.size() > util::get_max_string_size())
				{
					uint8_t type = (uint8_t)util::get_string_type(source, true);
					uint32_t size = std::min<uint32_t>(protocol::now().message.max_message_size, (uint32_t)source.size());
					write(&type, sizeof(uint8_t));
					write_integer(size);
					write(source.data(), size);
				}
				else
				{
					uint8_t type = (uint8_t)util::get_string_type(source, true);
					uint8_t size = util::get_string_size((viewable)type);
					write(&type, sizeof(uint8_t));
					write(source.data(), size);
				}
			}
			else if (value.size() > util::get_max_string_size())
			{
				uint32_t size = std::min<uint32_t>(protocol::now().message.max_message_size, (uint32_t)value.size());
				uint8_t type = (uint8_t)util::get_string_type(value, false);
				write(&type, sizeof(uint8_t));
				write_integer(size);
				write(value.data(), size);
			}
			else
			{
				uint8_t type = (uint8_t)util::get_string_type(value, false);
				uint8_t size = util::get_string_size((viewable)type);
				write(&type, sizeof(uint8_t));
				write(value.data(), size);
			}
			return *this;
		}
		stream& stream::write_decimal(const decimal& value)
		{
			if (value.is_nan())
			{
				uint8_t type = (uint8_t)viewable::decimal_nan;
				write(&type, sizeof(uint8_t));
				return *this;
			}
			else if (value.is_zero())
			{
				uint8_t type = (uint8_t)viewable::decimal_zero;
				write(&type, sizeof(uint8_t));
				return *this;
			}

			string numeric = value.numeric();
			uint16_t decimals = value.decimal_places();
			int8_t position = value.position();
			uint8_t type = (uint8_t)(decimals > 0 ? (position < 0 ? viewable::decimal_neg2 : viewable::decimal_pos2) : (position < 0 ? viewable::decimal_neg1 : viewable::decimal_pos1));
			std::reverse(numeric.begin() + decimals, numeric.end());

			auto left = std::string_view(numeric).substr(decimals);
			write(&type, sizeof(uint8_t));
			write_integer(contextual_parse_uint256(left));
			if (decimals > 0)
			{
				auto right = std::string_view(numeric).substr(0, decimals);
				write_integer(contextual_parse_uint256(right));
			}
			return *this;
		}
		stream& stream::write_integer(const uint256_t& value)
		{
			uint8_t type = (uint8_t)util::get_integer_type(value);
			uint8_t size = util::get_integer_size((viewable)type);
			write(&type, sizeof(uint8_t));

			uint64_t array[4];
			if (size > sizeof(uint64_t) * 0)
			{
				array[0] = os::hw::to_endianness(os::hw::endian::little, value.low().low());
				if (size > sizeof(uint64_t) * 1)
				{
					array[1] = os::hw::to_endianness(os::hw::endian::little, value.low().high());
					if (size > sizeof(uint64_t) * 2)
					{
						array[2] = os::hw::to_endianness(os::hw::endian::little, value.high().low());
						if (size > sizeof(uint64_t) * 3)
							array[3] = os::hw::to_endianness(os::hw::endian::little, value.high().high());
					}
				}
			}
			write(array, size);
			return *this;
		}
		stream& stream::write_boolean(bool value)
		{
			uint8_t type = (uint8_t)(value ? viewable::true_type : viewable::false_type);
			write(&type, sizeof(uint8_t));
			return *this;
		}
		stream& stream::write_typeless(const uint256_t& value)
		{
			uint8_t size = util::get_integer_size(util::get_integer_type(value));
			uint64_t array[4];
			if (size > sizeof(uint64_t) * 0)
			{
				array[0] = os::hw::to_endianness(os::hw::endian::little, value.low().low());
				if (size > sizeof(uint64_t) * 1)
				{
					array[1] = os::hw::to_endianness(os::hw::endian::little, value.low().high());
					if (size > sizeof(uint64_t) * 2)
					{
						array[2] = os::hw::to_endianness(os::hw::endian::little, value.high().low());
						if (size > sizeof(uint64_t) * 3)
							array[3] = os::hw::to_endianness(os::hw::endian::little, value.high().high());
					}
				}
			}
			write(array, size);
			return *this;
		}
		stream& stream::write_typeless(const char* data, uint8_t size)
		{
			write(data, size);
			return *this;
		}
		stream& stream::write_typeless(const char* data, uint32_t size)
		{
			write(data, size);
			return *this;
		}
		bool stream::is_eof() const
		{
			return seek >= data.size();
		}
		string stream::compress() const
		{
			auto status = codec::compress(data, compression::best_compression);
			return status ? *status : data;
		}
		string stream::encode() const
		{
			return util::encode_0xhex(data);
		}
		uint256_t stream::hash(bool renew) const
		{
			if (renew || !checksum)
				((stream*)this)->checksum = algorithm::hashing::hash256i(data);
			return checksum;
		}
		stream stream::decompress(const std::string_view& data)
		{
			auto raw = util::is_hex_encoding(data) ? util::decode_0xhex(data) : string(data);
			auto status = codec::decompress(raw);
			return stream(status ? *status : raw);
		}
		stream stream::decode(const std::string_view& data)
		{
			return util::is_hex_encoding(data) ? stream(util::decode_0xhex(data)) : stream(data);
		}

		string util::encode_0xhex(const std::string_view& data)
		{
			return assign_0xhex(codec::hex_encode(data));
		}
		string util::decode_0xhex(const std::string_view& data)
		{
			return codec::hex_decode(data);
		}
		string util::assign_0xhex(const std::string_view& data)
		{
			string result = stringify::starts_with(data, "0x") ? string() : string(data.empty() ? "0x0" : "0x");
			return result.append(data);
		}
		string util::clear_0xhex(const std::string_view& data, bool uppercase)
		{
			string result = string(stringify::starts_with(data, "0x") ? data.substr(2) : data);
			return uppercase ? stringify::to_upper(result) : stringify::to_lower(result);
		}
		bool util::is_hex_encoding(const std::string_view& data)
		{
			static std::string_view alphabet = "0123456789abcdefABCDEF";
			if (data.empty() || data.size() % 2 != 0)
				return false;

			auto text = (data.size() < 2 || data[0] != '0' || data[1] != 'x' ? data : data.substr(2));
			return text.find_first_not_of(alphabet) == std::string::npos;
		}
		bool util::is_base64_encoding(const std::string_view& data)
		{
			static std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
			if (data.empty())
				return false;

			return data.find_first_not_of(alphabet) == std::string::npos;
		}
		bool util::is_base64_url_encoding(const std::string_view& data)
		{
			static std::string_view alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
			if (data.empty())
				return false;

			return data.find_first_not_of(alphabet) == std::string::npos;
		}
		bool util::is_integer(viewable type)
		{
			return (uint8_t)type >= (uint8_t)viewable::uint_min && (uint8_t)type <= (uint8_t)viewable::uint_max;
		}
		bool util::is_string(viewable type)
		{
			return is_string10(type) || is_string16(type);
		}
		bool util::is_string10(viewable type)
		{
			return (uint8_t)type >= (uint8_t)viewable::string_min10 && (uint8_t)type <= (uint8_t)viewable::string_max10;
		}
		bool util::is_string16(viewable type)
		{
			return (uint8_t)type >= (uint8_t)viewable::string_min16;
		}
		uint8_t util::get_integer_size(viewable type)
		{
			if ((uint8_t)type < (uint8_t)viewable::uint_min)
				return 0;

			return (uint8_t)type - (uint8_t)viewable::uint_min;
		}
		viewable util::get_integer_type(const uint256_t& data)
		{
			uint64_t array[4] =
			{
				os::hw::to_endianness(os::hw::endian::little, data.low().low()),
				os::hw::to_endianness(os::hw::endian::little, data.low().high()),
				os::hw::to_endianness(os::hw::endian::little, data.high().low()),
				os::hw::to_endianness(os::hw::endian::little, data.high().high())
			};
			uint8_t bytes = sizeof(array);
			char* inline_data = (char*)array;
			while (bytes > 0 && !inline_data[bytes - 1])
				--bytes;
			uint8_t type = (uint8_t)viewable::uint_min + bytes;
			return (viewable)type;
		}
		uint8_t util::get_string_size(viewable type)
		{
			if (is_string10(type))
				return (uint8_t)type - (uint8_t)viewable::string_min10;

			if (is_string16(type))
				return (uint8_t)type - (uint8_t)viewable::string_min16;

			return 0;
		}
		viewable util::get_string_type(const std::string_view& data, bool hex_encoding)
		{
			auto limit = util::get_max_string_size();
			if (hex_encoding)
			{
				if (data.size() > limit)
					return viewable::string_any16;

				return (viewable)((uint8_t)viewable::string_min16 + (uint8_t)std::min<size_t>(data.size(), limit));
			}
			else
			{
				if (data.size() > limit)
					return viewable::string_any10;

				return (viewable)((uint8_t)viewable::string_min10 + (uint8_t)std::min<size_t>(data.size(), limit));
			}
		}
		size_t util::get_max_string_size()
		{
			return (size_t)viewable::string_max10 - (size_t)viewable::string_min10;
		}
	}
}