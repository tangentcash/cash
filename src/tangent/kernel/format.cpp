#include "format.h"
#include "algorithm.h"
#include <rapidjson/document.h>
extern "C"
{
#include "../internal/memzero.h"
}

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
		static void append_uint256_base_10(string& buffer, const uint256_t& value)
		{
			if (!value)
				return buffer.push_back('0');

			uint8_t data[sizeof(value)];
			value.encode(data);

			uint8_t base[sizeof(data)];
			for (size_t i = 0; i < sizeof(base); ++i)
				base[i] = data[31 - i];

			size_t begin = buffer.size();
			bool eof = false;
			while (!eof)
			{
				uint8_t remainder = 0; eof = true;
				for (int i = 31; i >= 0; --i)
				{
					uint16_t temp = (remainder << 8) | base[i];
					base[i] = temp / 10;
					remainder = temp % 10;
					if (base[i] != 0)
						eof = false;
				}
				buffer.push_back('0' + remainder);
			}
			if (buffer.size() > begin)
				std::reverse(buffer.begin() + begin, buffer.end());
		}
		static void convert_from_schema(schema* from, tree& to)
		{
			if (from != nullptr)
				to.key.assign(from->key);

			auto type = from ? from->value.get_type() : var_type::undefined;
			switch (type)
			{
				case var_type::object:
					to = tree();
					to.childs().reserve(from->size());
					for (auto& child : from->get_childs())
						to.push(tree::from_schema(child));
					to.type = structure::map;
					break;
				case var_type::array:
					to = tree();
					to.childs().reserve(from->size());
					for (auto& child : from->get_childs())
						to.push(tree::from_schema(child));
					break;
				case var_type::string:
				case var_type::binary:
					to = tree(variable(from->value.get_blob()));
					break;
				case var_type::integer:
				{
					auto integer = from->value.get_integer();
					to = tree(integer < 0 ? variable(decimal(integer)) : variable(decimal((uint64_t)integer)));
					break;
				}
				case var_type::number:
				case var_type::decimal:
					to = tree(variable(from->value.get_decimal()));
					break;
				case var_type::boolean:
					to = tree(variable(from->value.get_boolean()));
					break;
				case var_type::null:
				case var_type::undefined:
				case var_type::pointer:
				default:
					to = tree(variable());
					break;
			}
		}
		static bool convert_from_message(format::ro_stream& from, tree& to, uint32_t depth_left)
		{
			if (!from.read_string(from.read_type(), &to.key))
				return false;

			if (!from.read_integer(from.read_type(), (uint8_t*)&to.type))
				return false;

			switch (to.type)
			{
				case structure::flat:
				{
					viewable type;
					if (!from.read_integer(from.read_type(), (uint8_t*)&type))
						return false;

					switch (type)
					{
						case viewable::string_any10:
						{
							string value;
							if (!from.read_string(from.read_type(), &value))
								return false;

							to.value = format::variable(value);
							return true;
						}
						case viewable::decimal_zero:
						{
							decimal value;
							if (!from.read_decimal(from.read_type(), &value))
								return false;

							to.value = format::variable(value);
							return true;
						}
						case viewable::uint_min:
						{
							uint256_t value;
							if (!from.read_integer(from.read_type(), &value))
								return false;

							to.value = format::variable(value);
							return true;
						}
						case viewable::true_type:
						case viewable::false_type:
						{
							bool value;
							if (!from.read_boolean(from.read_type(), &value))
								return false;

							to.value = format::variable(value);
							return true;
						}
						default:
							return false;
					}
				}
				case structure::list:
				case structure::map:
				{
					uint32_t childs_size;
					if (!from.read_integer(from.read_type(), &childs_size))
						return false;
					else if (!depth_left)
						return false;

					uint32_t child_depth_left = depth_left - 1;
					for (uint32_t i = 0; i < childs_size; i++)
					{
						tree child;
						if (!convert_from_message(from, child, child_depth_left))
							return false;

						to.childs().push_back(std::move(child));
					}

					return true;
				}
				default:
					return false;
			}
		}
		static void convert_from_json_value(rapidjson::Value* from, tree& to, bool optimized)
		{
			if (from->IsObject())
			{
				to.type = structure::map;
				if (!from->MemberCount())
					return;

				to.childs().reserve((size_t)from->MemberCount());
				for (auto it = from->MemberBegin(); it != from->MemberEnd(); ++it)
				{
					if (!it->name.IsString())
						continue;
					
					auto& child = to.fields->emplace_back();
					child.key.assign(it->name.GetString(), (size_t)it->name.GetStringLength());
					convert_from_json_value(&it->value, child, optimized);
				}
			}
			else if (from->IsArray())
			{
				to.type = structure::list;
				if (!from->Size())
					return;

				to.childs().reserve((size_t)from->Size());
				for (auto it = from->Begin(); it != from->End(); ++it)
				{
					auto& child = to.fields->emplace_back();
					convert_from_json_value(it, child, optimized);
				}
			}
			else
			{
				switch (from->GetType())
				{
					case rapidjson::kFalseType:
					{
						to.value = variable(false);
						break;
					}
					case rapidjson::kTrueType:
					{
						to.value = variable(true);
						break;
					}
					case rapidjson::kStringType:
					{
						std::string_view text(from->GetString(), from->GetStringLength());
						if (optimized)
						{
							if (text.find('-') == std::string::npos && stringify::has_integer(text))
							{
								auto number = from_string<uint64_t>(text);
								if (!number)
								{
									if (number.error() == std::errc::result_out_of_range)
									{
										auto number256 = uint256_t(text, 10);
										if (number256.to_string() == text)
											to.value = variable(number256);
										else
											to.value = variable(decimal(text));
									}
									else
										to.value = variable(decimal(text));
								}
								else
									to.value = variable(*number);
							}
							else if (stringify::has_number(text))
								to.value = variable(decimal(text));
							else
								to.value = variable(text);
						}
						else
							to.value = variable(text);
						break;
					}
					case rapidjson::kNumberType:
					{
						if (from->IsUint())
							to.value = variable(from->GetUint());
						else if (from->IsUint64())
							to.value = variable(from->GetUint64());
						else if (from->IsInt())
							to.value = variable(decimal(from->GetInt()));
						else if (from->IsInt64())
							to.value = variable(decimal(from->GetInt64()));
						else
							to.value = variable(decimal(from->GetDouble()));
						break;
					}
					default:
					{
						to.value = variable();
						break;
					}
				}
			}
		}
		static void convert_to_json(const tree& from, string& to, string* depth, bool has_parent = false)
		{
			auto depth_push = [&]()
			{
				if (depth != nullptr)
					depth->append(2, ' ');
			};
			auto depth_tab = [&]()
			{
				if (depth != nullptr)
					to.append(*depth);
			};
			auto depth_space = [&]()
			{
				if (depth != nullptr)
					to.append(" ");
			};
			auto depth_line = [&]()
			{
				if (depth != nullptr)
					to.append("\n");
			};
			auto depth_pop = [&]()
			{
				if (depth != nullptr)
					depth->erase(depth->size() - 2);
			};

			if (from.type == structure::flat)
			{
				switch (from.value.type_of())
				{
					case viewable::string_any10:
					{
						auto value = string(from.value.as_string());
						if (!variables_util::is_ascii_encoding(value))
							 value = util::encode_0xhex(value);

						stringify::escape(value);
						to.append("\"");
						to.append(value);
						to.append("\"");
						return;
					}
					case viewable::decimal_zero:
					{
						auto value = from.value.as_decimal();
						if (!value.is_nan())
						{
							bool big_number = !value.is_safe_number();
							if (big_number)
								to.append("\"");
							to.append(value.to_string());
							if (big_number)
								to.append("\"");
						}
						else
							to.append("null");
						return;
					}
					case viewable::uint_min:
					{
						string numeric;
						auto value = from.value.as_uint256();
						bool big_integer = value > (uint64_t)std::numeric_limits<int64_t>::max();
						append_uint256_base_10(numeric, value);
						if (big_integer)
							to.append("\"");
						to.append(numeric);
						if (big_integer)
							to.append("\"");
						return;
					}
					case viewable::true_type:
					{
						to.append("true");
						return;
					}
					case viewable::false_type:
					{
						to.append("false");
						return;
					}
					case viewable::invalid:
					default:
					{
						to.append("null");
						return;
					}
				}
				string value = from.value.as_constant();
				stringify::escape(value);
				to.append(value);
			}

			size_t size = from.fields ? from.fields->size() : 0;
			bool array = (from.type == structure::list);
			if (!size)
			{
				to.append(array ? "[]" : "{}");
				return;
			}

			to.append(array ? "[" : "{");
			depth_push();

			for (size_t i = 0; i < size; i++)
			{
				auto& next = (*from.fields)[i];
				if (!array)
				{
					depth_line();
					depth_tab();
					to.append("\"");
					to.append(next.key);
					to.append("\":");
					depth_space();
				}

				if (array)
				{
					depth_line();
					depth_tab();
				}

				convert_to_json(next, to, depth, true);
				if (i + 1 < size)
					to.append(",");
			}

			depth_pop();
			depth_line();
			if (has_parent)
				depth_tab();
			to.append(array ? "]" : "}");
		}
		static void convert_to_message(const tree& from, format::wo_stream& to)
		{
			to.write_string(from.key);
			to.write_integer((uint8_t)from.type);
			switch (from.type)
			{
				case structure::flat:
				{
					auto type = from.value.type_of();
					to.write_integer((uint8_t)type);
					switch (type)
					{
						case viewable::string_any10:
							to.write_string(from.value.as_string());
							break;
						case viewable::decimal_zero:
							to.write_decimal(from.value.as_decimal());
							break;
						case viewable::uint_min:
							to.write_integer(from.value.as_uint256());
							break;
						case viewable::true_type:
						case viewable::false_type:
							to.write_boolean(from.value.as_boolean());
							break;
						default:
							break;
					}
					break;
				}
				case structure::list:
				case structure::map:
				{
					to.write_integer((uint32_t)(from.fields ? from.fields->size() : 0));
					if (from.fields)
					{
						for (auto& item : *from.fields)
							convert_to_message(item, to);
					}
					break;
				}
				default:
					break;
			}
		}

		wo_stream::wo_stream() : checksum(0), zeroing(false)
		{
		}
		wo_stream::wo_stream(const std::string_view& new_data) : data(new_data), checksum(0), zeroing(false)
		{
		}
		wo_stream::wo_stream(string&& new_data) : data(std::move(new_data)), checksum(0), zeroing(false)
		{
		}
		wo_stream::~wo_stream()
		{
			if (zeroing)
				memzero(data.data(), data.size());
		}
		wo_stream& wo_stream::clear()
		{
			data.clear();
			checksum = 0;
			return *this;
		}
		void wo_stream::write(const void* value, uint32_t size)
		{
			if (size > 0 && value != nullptr)
			{
				size_t index = data.size();
				data.resize(data.size() + (size_t)size);
				memcpy((char*)data.data() + index, value, (size_t)size);
				checksum = 0;
			}
		}
		wo_stream& wo_stream::write_string(const std::string_view& value)
		{
			if (util::is_strict_hex_encoding(value))
			{
				string source = codec::hex_decode(value);
				if (source.size() > util::get_max_string_size())
				{
					uint8_t type = (uint8_t)util::get_string_type(source, true);
					uint32_t size = (uint32_t)source.size();
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
				uint32_t size = (uint32_t)value.size();
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
		wo_stream& wo_stream::write_decimal(const decimal& value)
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
			uint16_t decimals = value.decimal_size();
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
		wo_stream& wo_stream::write_integer(const uint256_t& value)
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
		wo_stream& wo_stream::write_boolean(bool value)
		{
			uint8_t type = (uint8_t)(value ? viewable::true_type : viewable::false_type);
			write(&type, sizeof(uint8_t));
			return *this;
		}
		wo_stream& wo_stream::write_typeless(const uint256_t& value)
		{
			return write_typeless(value, util::get_integer_size(util::get_integer_type(value)));
		}
		wo_stream& wo_stream::write_typeless(const uint256_t& value, size_t size)
		{
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
			write(array, (uint32_t)std::min(sizeof(value), size));
			return *this;
		}
		wo_stream& wo_stream::write_typeless(const void* buffer, size_t size)
		{
			write(buffer, (uint32_t)size);
			return *this;
		}
		string wo_stream::compress() const
		{
			auto status = codec::compress(data, compression::best_compression);
			return status ? *status : data;
		}
		string wo_stream::encode() const
		{
			return util::encode_0xhex(data);
		}
		uint256_t wo_stream::hash(bool renew) const
		{
			if (renew || !checksum)
				((wo_stream*)this)->checksum = algorithm::hashing::hash256i(data);
			return checksum;
		}
		ro_stream wo_stream::ro() const
		{
			return ro_stream(data);
		}

		ro_stream::ro_stream() : checksum(0), seek(0)
		{
		}
		ro_stream::ro_stream(const std::string_view& new_data) : data(new_data), checksum(0), seek(0)
		{
		}
		ro_stream& ro_stream::rewind(size_t offset)
		{
			seek = (offset <= data.size() ? offset : data.size());
			return *this;
		}
		ro_stream& ro_stream::clear()
		{
			data = std::string_view();
			checksum = 0;
			seek = 0;
			return *this;
		}
		size_t ro_stream::read(void* value, uint32_t size)
		{
			if (!value || !size || size + seek > data.size())
				return 0;

			memcpy(value, data.data() + seek, (size_t)size);
			seek += size;
			return size;
		}
		viewable ro_stream::read_type()
		{
			viewable type = viewable::invalid;
			return read_type(&type) ? type : viewable::invalid;
		}
		bool ro_stream::read_type(viewable* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			return read(value, sizeof(uint8_t)) == sizeof(uint8_t);
		}
		bool ro_stream::read_string(viewable type, string* value)
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
			if (!read_type(&subtype) || !read_integer(subtype, &size) || size > kernel::params().message.max_message_size)
				return false;

			vector<char> buffer;
			buffer.resize((size_t)size);
			if (read((void*)buffer.data(), size) != size)
				return false;

			switch (type)
			{
				case viewable::string_any10:
					value->assign(buffer.begin(), buffer.end());
					return true;
				case viewable::string_any16:
					value->assign(util::encode_0xhex(std::string_view(buffer.data(), buffer.size())));
					return true;
				default:
					return false;
			}
		}
		bool ro_stream::read_view(viewable type, uint8_t* value, size_t value_size)
		{
			return read_optimized_view(type, value, value_size, false);
		}
		bool ro_stream::read_optimized_view(viewable type, uint8_t* value, size_t value_size, bool strict)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			string intermediate;
			if (!read_string(type, &intermediate))
				return false;
			else if (intermediate.size() > value_size)
				return false;
			else if (intermediate.size() < value_size)
				memzero(value, value_size);

			memcpy(value, intermediate.data(), intermediate.size());
			if (!strict)
				return true;

			size_t size = value_size;
			auto* ptr = value + size;
			while (size > 0 && !*(--ptr))
				--size;
			return size == intermediate.size();
		}
		bool ro_stream::read_decimal(viewable type, decimal* value)
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
			append_uint256_base_10(numeric, left);
			if (type == viewable::decimal_neg2 || type == viewable::decimal_pos2)
			{
				uint256_t right;
				if (!read_type(&subtype) || !read_integer(subtype, &right))
					return false;

				numeric.append(1, '.');
				size_t offset = numeric.size();
				append_uint256_base_10(numeric, right);
				std::reverse(numeric.begin() + offset, numeric.end());
			}

			if (type != viewable::decimal_neg1 && type != viewable::decimal_neg2)
				*value = decimal(std::string_view(numeric).substr(1));
			else
				*value = decimal(numeric);
			return true;
		}
		bool ro_stream::read_decimal_or_integer(format::viewable type, decimal* value)
		{
			if (!format::util::is_integer(type))
				return read_decimal(type, value);

			uint256_t value256;
			if (!read_integer(type, &value256))
				return false;

			*value = value256.to_decimal();
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint8_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint8_t>::max())
				return false;

			*value = (uint8_t)base;
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint16_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint16_t>::max())
				return false;

			*value = (uint16_t)base;
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint32_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint32_t>::max())
				return false;

			*value = (uint32_t)base;
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint64_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > std::numeric_limits<uint64_t>::max())
				return false;

			*value = (uint64_t)base;
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint128_t* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			uint256_t base;
			if (!read_integer(type, &base) || base > uint128_t::max())
				return false;

			*value = (uint128_t)base;
			return true;
		}
		bool ro_stream::read_integer(viewable type, uint256_t* value)
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
		bool ro_stream::read_boolean(viewable type, bool* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			if (type != viewable::true_type && type != viewable::false_type)
				return false;

			*value = (type == viewable::true_type);
			return true;
		}
		bool ro_stream::is_eof() const
		{
			return seek >= data.size();
		}
		uint256_t ro_stream::hash(bool renew) const
		{
			if (renew || !checksum)
				((ro_stream*)this)->checksum = algorithm::hashing::hash256i(data);
			return checksum;
		}
		wo_stream ro_stream::wo() const
		{
			return wo_stream(data);
		}

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
					auto buffer = string(as_string());
					if (!variables_util::is_ascii_encoding(buffer))
						return util::encode_0xhex(buffer);

					stringify::replace(buffer, "\"", "\\\"");
					buffer.insert(buffer.begin(), '\"');
					buffer.append(1, '\"');
					return buffer;
				}
				case viewable::decimal_zero:
					return ((decimal*)value.pointer)->to_string();
				case viewable::uint_min:
				{
					string numeric;
					append_uint256_base_10(numeric, value.integer);
					return numeric;
				}
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
				{
					string numeric;
					append_uint256_base_10(numeric, value.integer);
					return numeric;
				}
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
				{
					string numeric;
					append_uint256_base_10(numeric, value.integer);
					return decimal(numeric);
				}
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
					auto buffer = as_string();
					if (!variables_util::is_ascii_encoding(buffer))
						return var::set::string(util::encode_0xhex(buffer));

					return var::set::string(buffer);
				}
				case viewable::decimal_zero:
					return var::set::decimal(*(decimal*)value.pointer);
				case viewable::uint_min:
					return algorithm::encoding::serialize_uint256(value.integer).as_schema();
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
		bool variable::is_boolean() const
		{
			switch (type)
			{
				case viewable::true_type:
				case viewable::false_type:
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
			else if (any == "nan")
				return variable(decimal::nan());
			else if (any == "true")
				return variable(true);
			else if (any == "false")
				return variable(false);
			return variable(any);
		}

		tree::tree() noexcept : fields(nullptr), type(structure::flat)
		{
		}
		tree::tree(const variable& base) noexcept : value(base), fields(nullptr), type(structure::flat)
		{
		}
		tree::tree(variable&& base) noexcept : value(std::move(base)), fields(nullptr), type(structure::flat)
		{
		}
		tree::tree(const tree& other) noexcept : key(other.key), value(other.value), fields(nullptr), type(other.type)
		{
			if (!other.fields || other.fields->empty())
				return;

			fields = tree_pool::get()->allocate();
			fields->assign(other.fields->begin(), other.fields->end());
		}
		tree::tree(tree&& other) noexcept : key(std::move(other.key)), value(std::move(other.value)), fields(other.fields), type(other.type)
		{
			other.fields = nullptr;
		}
		tree& tree::operator=(const tree& other) noexcept
		{
			if (this == &other)
				return *this;

			if (other.fields != nullptr && !other.fields->empty())
			{
				fields = fields ? fields : tree_pool::get()->allocate();
				fields->assign(other.fields->begin(), other.fields->end());
			}
			else
				this->~tree();

			key = other.key;
			value = other.value;
			type = other.type;
			return *this;
		}
		tree& tree::operator=(tree&& other) noexcept
		{
			if (this == &other)
				return *this;

			fields = other.fields;
			other.fields = nullptr;

			key = std::move(other.key);
			value = std::move(other.value);
			type = other.type;
			return *this;
		}
		tree::~tree() noexcept
		{
			if (fields != nullptr)
			{
				tree_pool::get()->deallocate(fields);
				fields = nullptr;
			}
		}
		variable tree::child_var(const std::string_view& notation) const
		{
			auto* result = child(notation);
			if (!result)
				return variable();

			return result->value;
		}
		variable tree::child_var(size_t index) const
		{
			auto result = child(index);
			return result ? result->value : variable();
		}
		tree* tree::child(const std::string_view& notation) const
		{
			if (notation.find('.') == std::string::npos)
				return at(notation);

			vector<string> names = stringify::split(notation, '.');
			if (names.empty())
				return nullptr;

			auto* current = at(*names.begin());
			if (!current)
				return nullptr;

			for (auto it = names.begin() + 1; it != names.end(); ++it)
			{
				current = current->at(*it);
				if (!current)
					return nullptr;
			}

			return current;
		}
		tree* tree::child(size_t index) const
		{
			return fields && index < fields->size() ? (tree*)&(*fields)[index] : nullptr;
		}
		tree* tree::at(const std::string_view& name) const
		{
			if (!fields || fields->empty())
				return nullptr;

			if (stringify::has_integer(name))
				return child((size_t)*from_string<uint64_t>(name));

			for (auto& k : *fields)
			{
				if (k.key == name)
					return (tree*)&k;
			}

			return nullptr;
		}
		tree* tree::set(const std::string_view& name, const variable& base)
		{
			type = structure::map;
			for (auto& child : childs())
			{
				if (child.key == name)
				{
					child.type = structure::flat;
					child.value = base;
					return &child;
				}
			}

			fields->push_back(tree(base));
			auto& result = fields->back();
			result.key.assign(name);
			return &result;
		}
		tree* tree::set(const std::string_view& name, variable&& base)
		{
			type = structure::map;
			for (auto& child : childs())
			{
				if (child.key == name)
				{
					child.type = structure::flat;
					child.value = std::move(base);
					return &child;
				}
			}

			fields->push_back(tree(std::move(base)));
			auto& result = fields->back();
			result.key.assign(name);
			return &result;
		}
		tree* tree::set(const std::string_view& name, const tree& base)
		{
			type = structure::map;
			for (auto& child : childs())
			{
				if (child.key == name)
				{
					child = base;
					child.key.assign(name);
					return &child;
				}
			}

			fields->push_back(base);
			auto& result = fields->back();
			result.key.assign(name);
			return &result;
		}
		tree* tree::set(const std::string_view& name, tree&& base)
		{
			type = structure::map;
			for (auto& child : childs())
			{
				if (child.key == name)
				{
					child = std::move(base);
					child.key.assign(name);
					return &child;
				}
			}

			fields->push_back(std::move(base));
			auto& result = fields->back();
			result.key.assign(name);
			return &result;
		}
		tree* tree::push(const variable& base)
		{
			type = structure::list;
			childs().push_back(tree(base));
			auto& result = fields->back();
			return &result;
		}
		tree* tree::push(variable&& base)
		{
			type = structure::list;
			childs().push_back(tree(std::move(base)));
			auto& result = fields->back();
			return &result;
		}
		tree* tree::push(const tree& base)
		{
			type = structure::list;
			childs().push_back(tree(base));
			auto& result = fields->back();
			result.key.clear();
			return &result;
		}
		tree* tree::push(tree&& base)
		{
			type = structure::list;
			childs().push_back(std::move(base));
			auto& result = fields->back();
			result.key.clear();
			return &result;
		}
		tree* tree::pop(const std::string_view& name)
		{
			if (!fields)
				return this;

			for (auto it = fields->begin(); it != fields->end(); ++it)
			{
				if (it->key == name)
				{
					fields->erase(it);
					break;
				}
			}

			return this;
		}
		vector<tree>& tree::childs()
		{
			if (!fields)
				fields = tree_pool::get()->allocate();
			return *fields;
		}
		bool tree::has(const std::string_view& name) const
		{
			return child(name) != nullptr;
		}
		bool tree::is_flat() const
		{
			return type == structure::flat;
		}
		bool tree::is_list() const
		{
			return type == structure::list;
		}
		bool tree::is_map() const
		{
			return type == structure::map;
		}
		bool tree::is_none() const
		{
			return type == structure::flat && value.type_of() == format::viewable::invalid;
		}
		uptr<schema> tree::as_schema() const
		{
			switch (type)
			{
				case structure::flat:
					return value.as_schema();
				case structure::list:
				{
					uptr<schema> result = var::set::array();
					if (fields)
					{
						result->reserve(fields->size());
						for (auto& child : *fields)
							result->push(child.as_schema().reset());
					}
					return result;
				}
				case structure::map:
				{
					uptr<schema> result = var::set::object();
					if (fields)
					{
						result->reserve(fields->size());
						for (auto& child : *fields)
							result->set(child.key, child.as_schema().reset());
					}
					return result;
				}
				default:
					return nullptr;
			}
		}
		wo_stream tree::as_message() const
		{
			wo_stream result;
			convert_to_message(*this, result);
			return result;
		}
		string tree::as_json(bool pretty) const
		{
			string result, depth;
			convert_to_json(*this, result, pretty ? &depth : nullptr);
			return result;
		}
		tree tree::list()
		{
			tree result;
			result.type = structure::list;
			return result;
		}
		tree tree::map()
		{
			tree result;
			result.type = structure::map;
			return result;
		}
		tree tree::from_schema(schema* base)
		{
			tree result;
			convert_from_schema(base, result);
			return result;
		}
		option<tree> tree::from_message(format::ro_stream& stream)
		{
			tree result;
			if (!convert_from_message(stream, result, kernel::params().message.max_message_depth))
				return optional::none;

			return option<tree>(std::move(result));
		}
		expects_parser<tree> tree::from_json(const std::string_view& buffer, bool optimized)
		{
			if (buffer.empty())
				return parser_exception(parser_error::json_document_empty, 0);

			rapidjson::Document from;
			if (optimized)
				from.Parse<rapidjson::kParseNumbersAsStringsFlag>(buffer.data(), buffer.size());
			else
				from.Parse(buffer.data(), buffer.size());
			if (from.HasParseError())
			{
				size_t offset = from.GetErrorOffset();
				switch (from.GetParseError())
				{
					case rapidjson::kParseErrorDocumentEmpty:
						return parser_exception(parser_error::json_document_empty, offset);
					case rapidjson::kParseErrorDocumentRootNotSingular:
						return parser_exception(parser_error::json_document_root_not_singular, offset);
					case rapidjson::kParseErrorValueInvalid:
						return parser_exception(parser_error::json_value_invalid, offset);
					case rapidjson::kParseErrorObjectMissName:
						return parser_exception(parser_error::json_object_miss_name, offset);
					case rapidjson::kParseErrorObjectMissColon:
						return parser_exception(parser_error::json_object_miss_colon, offset);
					case rapidjson::kParseErrorObjectMissCommaOrCurlyBracket:
						return parser_exception(parser_error::json_object_miss_comma_or_curly_bracket, offset);
					case rapidjson::kParseErrorArrayMissCommaOrSquareBracket:
						return parser_exception(parser_error::json_array_miss_comma_or_square_bracket, offset);
					case rapidjson::kParseErrorStringUnicodeEscapeInvalidHex:
						return parser_exception(parser_error::json_string_unicode_escape_invalid_hex, offset);
					case rapidjson::kParseErrorStringUnicodeSurrogateInvalid:
						return parser_exception(parser_error::json_string_unicode_surrogate_invalid, offset);
					case rapidjson::kParseErrorStringEscapeInvalid:
						return parser_exception(parser_error::json_string_escape_invalid, offset);
					case rapidjson::kParseErrorStringMissQuotationMark:
						return parser_exception(parser_error::json_string_miss_quotation_mark, offset);
					case rapidjson::kParseErrorStringInvalidEncoding:
						return parser_exception(parser_error::json_string_invalid_encoding, offset);
					case rapidjson::kParseErrorNumberTooBig:
						return parser_exception(parser_error::json_number_too_big, offset);
					case rapidjson::kParseErrorNumberMissFraction:
						return parser_exception(parser_error::json_number_miss_fraction, offset);
					case rapidjson::kParseErrorNumberMissExponent:
						return parser_exception(parser_error::json_number_miss_exponent, offset);
					case rapidjson::kParseErrorTermination:
						return parser_exception(parser_error::json_termination, offset);
					case rapidjson::kParseErrorUnspecificSyntaxError:
						return parser_exception(parser_error::json_unspecific_syntax_error, offset);
					default:
						return parser_exception(parser_error::bad_value);
				}
			}

			auto to = tree();
			convert_from_json_value(&from, to, optimized);
			return expects_parser<tree>(std::move(to));
		}

		tree_pool::tree_pool() : full(false), max_queue_size(64 * 1024), max_vector_capacity(48)
		{
		}
		vector<tree>* tree_pool::allocate()
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!queue.empty())
			{
				auto* cache = queue.front();
				queue.pop();
				full = false;
				return cache;
			}
			return memory::init<vector<tree>>();
		}
		void tree_pool::deallocate(vector<tree>* value)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			if (full)
				return memory::deinit(value);
			
			if (value->capacity() > max_vector_capacity)
			{
				value->resize(max_vector_capacity);
				value->shrink_to_fit();
			}

			value->clear();
			umutex<std::recursive_mutex> unique(mutex);
			queue.push(value);
			full = queue.size() >= max_queue_size;
		}

		string util::decompress_stream(const std::string_view& data)
		{
			auto raw = util::is_hex_encoding(data) ? util::decode_0xhex(data) : string(data);
			auto status = codec::decompress(raw, kernel::params().message.max_message_size);
			if (status)
				raw = std::move(*status);
			return raw;
		}
		string util::decode_stream(const std::string_view& data)
		{
			return util::is_hex_encoding(data) ? util::decode_0xhex(data) : string(data);
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
		bool util::is_strict_hex_encoding(const std::string_view& data)
		{
			static std::string_view alphabet = "0123456789abcdef";
			if (data.size() < 2 || data.size() % 2 != 0 || data[0] != '0' || data[1] != 'x')
				return false;

			return data.substr(2).find_first_not_of(alphabet) == std::string::npos;
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
			return (uint8_t)type >= (uint8_t)viewable::string_min16 && (uint8_t)type <= (uint8_t)viewable::string_max16;
		}
		uint8_t util::get_integer_size(viewable type)
		{
			if ((uint8_t)type < (uint8_t)viewable::uint_min)
				return 0;

			return (uint8_t)type - (uint8_t)viewable::uint_min;
		}
		viewable util::get_integer_type(const uint256_t& data)
		{
			return (viewable)((uint8_t)viewable::uint_min + data.bytes());
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

			auto& message = kernel::params().message;
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
		tree variables_util::serialize(const variables& value)
		{
			tree data = tree::list();
			data.childs().reserve(value.size());
			for (auto& item : value)
				data.push(item.is_integer() ? algorithm::encoding::serialize_uint256(item.as_uint256()) : tree(item));
			return data;
		}
	}
}