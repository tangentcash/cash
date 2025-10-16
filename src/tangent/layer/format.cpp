#include "format.h"
#include "../kernel/algorithm.h"

namespace tangent
{
	namespace format
	{
		variable::variable() noexcept : type(viewable::invalid), length(0)
		{
			value.pointer = nullptr;
		}
		variable::variable(const char* new_value) noexcept : variable(std::string_view(new_value))
		{
		}
		variable::variable(const std::string_view& new_value) noexcept : variable(viewable::string_any10)
		{
			length = (uint32_t)new_value.size();
			size_t string_size = sizeof(char) * (length + 1);
			if (length > get_max_small_string_size())
				value.pointer = memory::allocate<char>(string_size);

			char* data = (char*)as_string().data();
			memcpy(data, new_value.data(), string_size - sizeof(char));
			data[string_size - 1] = '\0';
		}
		variable::variable(const string& new_value) noexcept : variable(std::string_view(new_value))
		{
		}
		variable::variable(const decimal& new_value) noexcept : variable(viewable::decimal_zero)
		{
			value.pointer = (char*)memory::init<decimal>(new_value);
		}
		variable::variable(const uint8_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(const uint16_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(const uint32_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(const uint64_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(const uint128_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(const uint256_t& new_value) noexcept : variable(viewable::uint_min)
		{
			value.integer = new_value;
		}
		variable::variable(bool new_value) noexcept : variable(new_value ? viewable::true_type : viewable::false_type)
		{
			value.boolean = new_value;
		}
		variable::variable(viewable new_type) noexcept : type(new_type), length(0)
		{
			value.pointer = nullptr;
		}
		variable::variable(const variable& other) noexcept
		{
			copy(other);
		}
		variable::variable(variable&& other) noexcept
		{
			move(std::move(other));
		}
		variable::~variable() noexcept
		{
			free();
		}
		string variable::as_constant() const
		{
			switch (type)
			{
				case viewable::string_any10:
				{
					auto value = string(as_string());
					if (!variables_util::is_ascii_encoding(value))
						return util::encode_0xhex(value);

					stringify::replace(value, "\"", "\\\"");
					value.insert(value.begin(), '\"');
					value.append(1, '\"');
					return value;
				}
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_string();
				case viewable::uint_min:
					return value.integer.to_string();
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? "true" : "false";
				case viewable::invalid:
				default:
					return "null";
			}
		}
		string variable::as_blob() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return string(as_string());
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_string();
				case viewable::uint_min:
					return value.integer.to_string();
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? "1" : "0";
				case viewable::invalid:
				default:
					return string();
			}
		}
		decimal variable::as_decimal() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return decimal(as_string());
				case viewable::decimal_zero:
					return *(decimal*)value.pointer;
				case viewable::uint_min:
					return decimal(value.integer.to_string());
				case viewable::true_type:
				case viewable::false_type:
					return decimal(value.boolean ? 1 : 0);
				case viewable::invalid:
				default:
					return decimal::nan();
			}
		}
		uptr<schema> variable::as_schema() const
		{
			switch (type)
			{
				case viewable::string_any10:
				{
					auto value = as_string();
					if (!variables_util::is_ascii_encoding(value))
						return var::set::string(util::encode_0xhex(value));

					return var::set::string(value);
				}
				case viewable::decimal_zero:
					return var::set::decimal(*(decimal*)value.pointer);
				case viewable::uint_min:
					return algorithm::encoding::serialize_uint256(value.integer);
				case viewable::true_type:
				case viewable::false_type:
					return var::set::boolean(value.boolean);
				case viewable::invalid:
				default:
					return var::set::null();
			}
		}
		std::string_view variable::as_string() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return std::string_view(length <= get_max_small_string_size() ? value.string : value.pointer, length);
				default:
					return std::string_view("", 0);
			}
		}
		uint8_t variable::as_uint8() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<uint8_t>(as_string()).or_else(0);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_uint8();
				case viewable::uint_min:
					return (uint8_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1 : 0;
				case viewable::invalid:
				default:
					return 0;
			}
		}
		uint16_t variable::as_uint16() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<uint16_t>(as_string()).or_else(0);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_uint16();
				case viewable::uint_min:
					return (uint16_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1 : 0;
				case viewable::invalid:
				default:
					return 0;
			}
		}
		uint32_t variable::as_uint32() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<uint32_t>(as_string()).or_else(0);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_uint32();
				case viewable::uint_min:
					return (uint32_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1 : 0;
				case viewable::invalid:
				default:
					return 0;
			}
		}
		uint64_t variable::as_uint64() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<uint64_t>(as_string()).or_else(0);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_uint64();
				case viewable::uint_min:
					return (uint64_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1 : 0;
				case viewable::invalid:
				default:
					return 0;
			}
		}
		uint128_t variable::as_uint128() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return uint128_t(as_string(), util::is_hex_encoding(as_string()) ? 16 : 10);
				case viewable::decimal_zero:
					return uint128_t(((decimal*)value.pointer)->to_string());
				case viewable::uint_min:
					return uint128_t(value.integer);
				case viewable::true_type:
				case viewable::false_type:
					return uint128_t(value.boolean ? 1 : 0);
				case viewable::invalid:
				default:
					return uint128_t(0);
			}
		}
		uint256_t variable::as_uint256() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return uint256_t(as_string(), util::is_hex_encoding(as_string()) ? 16 : 10);
				case viewable::decimal_zero:
					return uint256_t(((decimal*)value.pointer)->to_string());
				case viewable::uint_min:
					return value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return uint256_t(value.boolean ? 1 : 0);
				case viewable::invalid:
				default:
					return uint256_t(0);
			}
		}
		float variable::as_float() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<float>(as_string()).or_else(0.0f);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_float();
				case viewable::uint_min:
					return (float)(uint64_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1.0f : 0.0f;
				case viewable::invalid:
				default:
					return 0.0f;
			}
		}
		double variable::as_double() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return from_string<double>(as_string()).or_else(0.0);
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_double();
				case viewable::uint_min:
					return (double)(uint64_t)value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean ? 1.0 : 0.0;
				case viewable::invalid:
				default:
					return 0.0;
			}
		}
		bool variable::as_boolean() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return !as_string().empty();
				case viewable::decimal_zero:
					return !((decimal*)value.pointer)->is_zero_or_nan();
				case viewable::uint_min:
					return value.integer > 0;
				case viewable::true_type:
				case viewable::false_type:
					return value.boolean;
				case viewable::invalid:
				default:
					return false;
			}
		}
		bool variable::is_string() const
		{
			switch (type)
			{
				case viewable::string_any10:
					return true;
				default:
					return false;
			}
		}
		bool variable::is_decimal() const
		{
			switch (type)
			{
				case viewable::decimal_zero:
					return true;
				default:
					return false;
			}
		}
		bool variable::is_integer() const
		{
			switch (type)
			{
				case viewable::uint_min:
					return true;
				default:
					return false;
			}
		}
		viewable variable::type_of() const
		{
			return type;
		}
		bool variable::operator== (const variable& other) const
		{
			return same(other);
		}
		bool variable::operator!= (const variable& other) const
		{
			return !same(other);
		}
		variable& variable::operator= (const variable& other) noexcept
		{
			free();
			copy(other);

			return *this;
		}
		variable& variable::operator= (variable&& other) noexcept
		{
			free();
			move(std::move(other));

			return *this;
		}
		bool variable::same(const variable& other) const
		{
			if (type != other.type)
				return false;

			switch (type)
			{
				case viewable::string_any10:
					return as_string() == other.as_string();
				case viewable::decimal_zero:
					return as_decimal() == other.as_decimal();
				case viewable::uint_min:
					return value.integer == other.value.integer;
				case viewable::true_type:
				case viewable::false_type:
					return as_boolean() == other.as_boolean();
				case viewable::invalid:
					return true;
				default:
					return false;
			}
		}
		void variable::copy(const variable& other)
		{
			type = other.type;
			length = other.length;

			switch (type)
			{
				case viewable::string_any10:
				{
					size_t string_size = sizeof(char) * (length + 1);
					if (length > get_max_small_string_size())
						value.pointer = memory::allocate<char>(string_size);
					memcpy((void*)as_string().data(), other.as_string().data(), string_size);
					break;
				}
				case viewable::decimal_zero:
				{
					decimal* from = (decimal*)other.value.pointer;
					value.pointer = (char*)memory::init<decimal>(*from);
					break;
				}
				case viewable::uint_min:
					value.integer = other.value.integer;
					break;
				case viewable::true_type:
				case viewable::false_type:
					value.boolean = other.value.boolean;
					break;
				case viewable::invalid:
				default:
					value.pointer = nullptr;
					break;
			}
		}
		void variable::move(variable&& other)
		{
			type = other.type;
			length = other.length;
			switch (type)
			{
				case viewable::string_any10:
					if (length <= get_max_small_string_size())
						memcpy((void*)as_string().data(), other.as_string().data(), sizeof(char) * (length + 1));
					else
						value.pointer = other.value.pointer;
					other.value.pointer = nullptr;
					break;
				case viewable::decimal_zero:
					value.pointer = other.value.pointer;
					other.value.pointer = nullptr;
					break;
				case viewable::uint_min:
					value.integer = other.value.integer;
					break;
				case viewable::true_type:
				case viewable::false_type:
					value.boolean = other.value.boolean;
					break;
				case viewable::invalid:
				default:
					break;
			}

			other.type = viewable::invalid;
			other.length = 0;
		}
		void variable::free()
		{
			switch (type)
			{
				case viewable::string_any10:
				{
					if (!value.pointer || length <= get_max_small_string_size())
						break;

					memory::deallocate(value.pointer);
					value.pointer = nullptr;
					break;
				}
				case viewable::decimal_zero:
				{
					if (!value.pointer)
						break;

					decimal* buffer = (decimal*)value.pointer;
					memory::deinit(buffer);
					value.pointer = nullptr;
					break;
				}
				default:
					break;
			}
		}
		size_t variable::get_max_small_string_size()
		{
			return sizeof(tag::string) - 1;
		}
		variable variable::from(const std::string_view& any)
		{
			if (stringify::has_integer(any) && any.find('-') == std::string_view::npos)
				return variable(uint256_t(any, 10));
			else if (stringify::has_number(any))
				return variable(decimal(any));
			else if (any == "true")
				return variable(true);
			else if (any == "false")
				return variable(false);
			return variable(any);
		}

		bool variables_util::is_ascii_encoding(const std::string_view& data)
		{
			return !std::any_of(data.begin(), data.end(), [](char v) { return static_cast<unsigned char>(v) > 127; });
		}
		bool variables_util::deserialize_flat_from(ro_stream& stream, variables* result)
		{
			return deserialize_from(stream, result, false);
		}
		bool variables_util::serialize_flat_into(const variables& data, wo_stream* result)
		{
			return serialize_into(data, result, false);
		}
		bool variables_util::deserialize_merge_from(ro_stream& stream, variables* result)
		{
			return deserialize_from(stream, result, true);
		}
		bool variables_util::serialize_merge_into(const variables& data, wo_stream* result)
		{
			return serialize_into(data, result, true);
		}
		bool variables_util::deserialize_from(ro_stream& stream, variables* result, bool merging)
		{
			VI_ASSERT(result != nullptr, "result should be set");
			uint16_t size = std::numeric_limits<uint16_t>::max();
			if (merging && !stream.read_integer(stream.read_type(), &size))
				return false;
			else if (!size)
				return true;

			while (!stream.is_eof() && size-- != 0)
			{
				auto type = stream.read_type();
				if (type == viewable::invalid)
					return !size;

				switch (type)
				{
					case viewable::string_any10:
					case viewable::string_any16:
					{
						string value;
						if (!stream.read_string(type, &value))
							return false;

						result->emplace_back(std::string_view(value));
						break;
					}
					case viewable::decimal_nan:
					case viewable::decimal_zero:
					case viewable::decimal_neg1:
					case viewable::decimal_neg2:
					case viewable::decimal_pos1:
					case viewable::decimal_pos2:
					{
						decimal value;
						if (!stream.read_decimal(type, &value))
							return false;

						result->emplace_back(value);
						break;
					}
					case viewable::true_type:
					case viewable::false_type:
					{
						bool value;
						if (!stream.read_boolean(type, &value))
							return false;

						result->emplace_back(value);
						break;
					}
					default:
					{
						if (util::is_string(type))
						{
							string value;
							if (!stream.read_string(type, &value))
								return false;

							result->emplace_back(std::string_view(value));
							break;
						}
						else if (util::is_integer(type))
						{
							uint256_t value;
							if (!stream.read_integer(type, &value))
								return false;

							result->emplace_back(value);
							break;
						}
						return false;
					}
				}
			}
			return true;
		}
		bool variables_util::serialize_into(const variables& data, wo_stream* result, bool merging)
		{
			if (data.size() > std::numeric_limits<uint16_t>::max())
				return false;

			auto& message = protocol::now().message;
			if (merging)
				result->write_integer(data.size());

			for (auto& item : data)
			{
				auto type = item.type_of();
				if (type == viewable::invalid || result->data.size() > message.max_body_size)
					return false;

				switch (type)
				{
					case viewable::string_any10:
						result->write_string(item.as_string());
						break;
					case viewable::decimal_zero:
						result->write_decimal(item.as_decimal());
						break;
					case viewable::uint_min:
						result->write_integer(item.as_uint256());
						break;
					case viewable::true_type:
					case viewable::false_type:
						result->write_boolean(item.as_boolean());
						break;
					default:
						return false;
				}
			}
			return true;
		}
		string variables_util::as_constant(const variables& data)
		{
			string result;
			for (size_t i = 0; i < data.size(); i++)
			{
				result += data[i].as_constant();
				if (i < data.size() - 1)
					result += ", ";
			}
			return result;
		}
		string variables_util::as_constant_json(const variables& data, size_t spaces)
		{
			string space(spaces, ' ');
			string result = "[";
			for (size_t i = 0; i < data.size(); i++)
			{
				if (i == 0)
					result += '\n';
				result += space;
				result += data[i].as_constant();
				if (i < data.size() - 1)
					result += ",\n";
				else
					result += '\n';
			}
			result.append(1, ']');
			return result;
		}
		schema* variables_util::serialize(const variables& value)
		{
			schema* data = var::set::array();
			for (auto& item : value)
				data->push(item.as_schema().reset());
			return data;
		}
	}
}