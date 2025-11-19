#include "cell.h"
#include "../policy/transactions.h"
#include "../validator/storage/chainstate.h"
#include <gmp.h>
#include <iostream>
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_QUERY_PREFETCH 16
#define SCRIPT_TAG_ARRAY 19192
#define SCRIPT_TAG_MUTABLE_PROGRAM 19190
#define SCRIPT_TAG_IMMUTABLE_PROGRAM 19191
#define SCRIPT_TYPE_ADDRESS "address"
#define SCRIPT_TYPE_STRING "string"
#define SCRIPT_TYPE_UINT128 "uint128"
#define SCRIPT_TYPE_UINT256 "uint256"
#define SCRIPT_TYPE_REAL320 "real320"
#define SCRIPT_TYPE_ARRAY "array"
#define SCRIPT_TYPE_VARYING "varying"
#define SCRIPT_TYPE_MAPPING "mapping"
#define SCRIPT_TYPE_RANGING "ranging"
#define SCRIPT_TYPE_PMUT "pmut"
#define SCRIPT_TYPE_PCONST "pconst"
#define SCRIPT_FUNCTION_CONSTRUCT "construct"
#define SCRIPT_VM "cell"

namespace tangent
{
	namespace cell
	{
		typedef unordered_map<string_repr, std::atomic<int32_t>> string_repr_cache_type;

		static std::string_view type_name_of(int type_id)
		{
			return factory::get()->get_vm()->get_type_info_by_id(type_id).get_name();
		}
		static string mpf_to_string(const mpf_t target)
		{
			char buffer[1024]; string result; mp_exp_t exp;
			char* str = mpf_get_str(buffer, &exp, 10, sizeof(buffer) - 2, target);
			if (str != nullptr)
			{
				size_t negative = str[0] == '-' ? 1 : 0, len = strlen(str);
				result.assign(std::string_view(str, len));
				if (exp > 0)
				{
					len -= negative;
					if (exp >= len)
					{
						result.resize(exp + negative);
						memset(result.data() + negative + len, '0', exp - len);
					}
					else
						result.insert(exp + negative, ".");
				}
				else if (exp < 0)
				{
					result.insert(negative, "0.");
					result.insert(negative + 2, (size_t)(-exp), '0');
				}
				else
					result.insert(negative, "0.");
			}
			if (!result.empty() && result.back() == '.')
				result.pop_back();
			return result;
		}

		struct mpz_value
		{
			mpz_t target = { };
			mpz_t field = { };

			mpz_value()
			{
				mpz_init(target);
				mpz_init_set_ui(field, 1);
			}
			mpz_value(int type_id, void* value)
			{
				switch (type_id)
				{
					case (int)type_id::int8_t:
						mpz_init_set_si(target, *(int8_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint8_t>::max());
						break;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						mpz_init_set_ui(target, *(uint8_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint8_t>::max());
						break;
					case (int)type_id::int16_t:
						mpz_init_set_si(target, *(int16_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint16_t>::max());
						break;
					case (int)type_id::uint16_t:
						mpz_init_set_ui(target, *(uint16_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint16_t>::max());
						break;
					case (int)type_id::int32_t:
						mpz_init_set_si(target, *(int32_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint32_t>::max());
						break;
					case (int)type_id::uint32_t:
						mpz_init_set_ui(target, *(uint32_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint32_t>::max());
						break;
					case (int)type_id::int64_t:
						mpz_init_set_si(target, *(int64_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint64_t>::max());
						break;
					case (int)type_id::uint64_t:
						mpz_init_set_ui(target, *(uint64_t*)value);
						mpz_init_set_ui(field, std::numeric_limits<uint64_t>::max());
						break;
					default:
					{
						auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						value = type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
						if (name == SCRIPT_TYPE_UINT128)
						{
							uint8_t buffer[sizeof(uint128_t)];
							(*(uint128_t*)value).encode(buffer);
							mpz_init(target);
							mpz_import(target, sizeof(buffer), 1, 1, 1, 0, buffer);
							mpz_init_set_ui(field, 2);
							mpz_mul_ui(field, field, sizeof(uint128_t));
							mpz_sub_ui(field, field, 1);
							break;
						}
						else if (name == SCRIPT_TYPE_UINT256)
						{
							uint8_t buffer[sizeof(uint256_t)];
							(*(uint256_t*)value).encode(buffer);
							mpz_init(target);
							mpz_import(target, sizeof(buffer), 1, 1, 1, 0, buffer);
							mpz_init_set_ui(field, 2);
							mpz_mul_ui(field, field, sizeof(uint256_t));
							mpz_sub_ui(field, field, 1);
							break;
						}
						else if (type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							mpz_init_set_ui(target, *(int32_t*)value);
							mpz_init_set_ui(field, std::numeric_limits<uint32_t>::max());
							break;
						}

						mpz_init(target);
						mpz_init_set_ui(field, 1);
						break;
					}
				}
			}
			mpz_value(const mpz_value& other)
			{
				mpz_init_set(target, other.target);
				mpz_init_set(field, other.field);
			}
			mpz_value(mpz_value&& other) noexcept
			{
				mpz_init(target);
				mpz_init(field);
				mpz_swap(target, other.target);
				mpz_swap(field, other.field);
			}
			~mpz_value()
			{
				mpz_clear(target);
				mpz_clear(field);
			}
			mpz_value& operator=(const mpz_value& other)
			{
				if (this == &other)
					return *this;

				mpz_set(target, other.target);
				mpz_init_set(field, other.field);
				return *this;
			}
			mpz_value& operator=(mpz_value&& other) noexcept
			{
				if (this == &other)
					return *this;

				mpz_swap(target, other.target);
				mpz_swap(field, other.field);
				return *this;
			}
			bool into(generic_context& inout)
			{
				int type_id = inout.get_return_addressable_type_id();
				mpz_mod(target, target, field);
				switch (type_id)
				{
					case (int)type_id::int8_t:
						inout.set_return_byte((uint8_t)mpz_get_si(target));
						return true;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						inout.set_return_byte((uint8_t)mpz_get_ui(target));
						return true;
					case (int)type_id::int16_t:
						inout.set_return_word((uint16_t)mpz_get_si(target));
						return true;
					case (int)type_id::uint16_t:
						inout.set_return_word((uint16_t)mpz_get_ui(target));
						return true;
					case (int)type_id::int32_t:
						inout.set_return_dword((uint32_t)mpz_get_si(target));
						return true;
					case (int)type_id::uint32_t:
						inout.set_return_dword((uint32_t)mpz_get_ui(target));
						return true;
					case (int)type_id::int64_t:
						inout.set_return_qword((uint64_t)mpz_get_si(target));
						return true;
					case (int)type_id::uint64_t:
						inout.set_return_qword((uint64_t)mpz_get_ui(target));
						return true;
					default:
					{
						auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						if (name == SCRIPT_TYPE_UINT128)
						{
							size_t size = 0;
							char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, target);
							uint8_t buffer[sizeof(uint128_t)] = { 0 };
							memcpy((char*)buffer + (sizeof(buffer) - size), data, size);
							free(data);

							uint128_t result;
							result.decode(buffer);
							new (inout.get_address_of_return_location()) uint128_t(result);
							return true;
						}
						else if (name == SCRIPT_TYPE_UINT256)
						{
							size_t size = 0;
							char* data = (char*)mpz_export(nullptr, &size, 1, 1, 1, 0, target);
							uint8_t buffer[sizeof(uint256_t)] = { 0 };
							memcpy((char*)buffer + (sizeof(buffer) - size), data, size);
							free(data);

							uint256_t result;
							result.decode(buffer);
							new (inout.get_address_of_return_location()) uint256_t(result);
							return true;
						}
						else if (type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							inout.set_return_dword((uint32_t)mpz_get_si(target));
							return true;
						}
						return false;
					}
				}
			}
		};

		struct mpf_value
		{
			mpf_t target = { };

			mpf_value()
			{
				mpf_init(target);
				mpf_set_prec(target, 8);
			}
			mpf_value(int type_id, void* value)
			{
				switch (type_id)
				{
					case (int)type_id::float_t:
					case (int)type_id::double_t:
						contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
						break;
					default:
					{
						auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						value = type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
						if (name == SCRIPT_TYPE_REAL320)
						{
							auto str = (*(decimal*)value).to_string();
							mpf_init(target);
							mpf_set_prec(target, real320_repr::target_bits());
							mpf_set_str(target, str.c_str(), 10);
							break;
						}

						mpf_init(target);
						mpf_set_prec(target, 8);
						break;
					}
				}
			}
			mpf_value(const mpf_value& other)
			{
				mpf_init_set(target, other.target);
			}
			mpf_value(mpf_value&& other) noexcept
			{
				mpf_init(target);
				mpf_swap(target, other.target);
			}
			~mpf_value()
			{
				mpf_clear(target);
			}
			mpf_value& operator=(const mpf_value& other)
			{
				if (this == &other)
					return *this;

				mpf_set(target, other.target);
				return *this;
			}
			mpf_value& operator=(mpf_value&& other) noexcept
			{
				if (this == &other)
					return *this;

				mpf_swap(target, other.target);
				return *this;
			}
			bool into(generic_context& inout)
			{
				int type_id = inout.get_return_addressable_type_id();
				auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view();
				if (name == SCRIPT_TYPE_REAL320)
				{
					decimal result = decimal(mpf_to_string(target));
					real320_repr::truncate_or_throw(result, true);
					new (inout.get_address_of_return_location()) decimal(std::move(result));
					return true;
				}

				return false;
			}
			size_t bits()
			{
				char buffer[1024]; mp_exp_t exp;
				mpf_get_str(buffer, &exp, 10, sizeof(buffer) - 2, target);
				return real320_repr::estimate_bits((uint32_t)strlen(buffer));
			}
			static bool requires_fixed_point(int type_id)
			{
				auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view();
				return name == SCRIPT_TYPE_REAL320;
			}
		};

		static void mpf_value_to_mpz_value(const mpf_value& input, mpz_value& output)
		{
			auto str = mpf_to_string(input.target);
			mpz_set_str(output.target, str.c_str(), 10);
		}
		static void mpz_value_to_mpf_value(const mpz_value& input, mpf_value& output)
		{
			char* str = mpz_get_str(nullptr, 10, input.target);
			if (str != nullptr)
			{
				mpf_set_prec(output.target, (mp_bitcnt_t)mpz_sizeinbase(input.field, 2));
				mpf_set_str(output.target, str, 10);
				free(str);
			}
		}

		std::string_view exception_repr::category::generic()
		{
			return std::string_view("generic_error");
		}
		std::string_view exception_repr::category::requirement()
		{
			return std::string_view("requirement_error");
		}
		std::string_view exception_repr::category::argument()
		{
			return std::string_view("argument_error");
		}
		std::string_view exception_repr::category::memory()
		{
			return std::string_view("memory_error");
		}
		std::string_view exception_repr::category::storage()
		{
			return std::string_view("storage_error");
		}
		std::string_view exception_repr::category::execution()
		{
			return std::string_view("execution_error");
		}

		exception_repr::exception_repr() : context(nullptr)
		{
		}
		exception_repr::exception_repr(immediate_context* new_context) : context(new_context)
		{
			auto value = context ? context->get_exception_string() : std::string_view();
			if (!value.empty() && (context ? !context->will_exception_be_caught() : false))
			{
				load_exception_data(value);
				origin = load_stack_here();
			}
		}
		exception_repr::exception_repr(const std::string_view& value) : context(immediate_context::get())
		{
			load_exception_data(value);
			origin = load_stack_here();
		}
		exception_repr::exception_repr(const std::string_view& new_type, const std::string_view& new_text) : type(new_type), text(new_text), context(immediate_context::get())
		{
			origin = load_stack_here();
		}
		exception_repr::exception_repr(const string_repr& new_type, const string_repr& new_text) : type(new_type.view()), text(new_text.view()), context(immediate_context::get())
		{
			origin = load_stack_here();
		}
		void exception_repr::load_exception_data(const std::string_view& value)
		{
			size_t offset = value.find(':');
			if (offset != std::string::npos)
			{
				type = value.substr(0, offset);
				text = value.substr(offset + 1);
			}
			else if (!value.empty())
			{
				type = category::generic();
				text = value;
			}
		}
		string_repr exception_repr::get_type() const
		{
			return string_repr(type);
		}
		string_repr exception_repr::get_text() const
		{
			return string_repr(text);
		}
		string_repr exception_repr::get_what() const
		{
			return string_repr(to_full_exception_string());
		}
		string exception_repr::to_exception_string() const
		{
			if (empty())
				return string();

			string result = type;
			result.append(std::string_view(":"));
			result.append(text);
			return result;
		}
		string exception_repr::to_full_exception_string() const
		{
			string data = type;
			if (!text.empty())
			{
				data.append(std::string_view(": "));
				data.append(text);
			}

			data.append(std::string_view(" "));
			data.append(origin.empty() ? load_stack_here() : origin);
			return data;
		}
		string exception_repr::load_stack_here() const
		{
			string data;
			if (!context)
				return data;

			string_stream stream;
			stream << '\n';

			virtual_machine* vm = context->get_vm();
			size_t callstack_size = context->get_callstack_size();
			size_t top_callstack_size = callstack_size;
			for (size_t i = 0; i < callstack_size; i++)
			{
				int column_number = 0;
				int line_number = context->get_line_number(i, &column_number);
				function next = context->get_function(i);
				auto section_name = next.get_section_name();
				stream << "  #" << --top_callstack_size << " at " << os::path::get_filename(section_name);
				if (line_number > 0)
					stream << ":" << line_number;
				if (column_number > 0)
					stream << "," << column_number;
				stream << " in " << (next.get_decl().empty() ? "[optimized]" : next.get_decl());
				if (top_callstack_size > 0)
					stream << "\n";
			}

			auto copy = stream.str();
			data = std::string_view(copy);
			return data;
		}
		bool exception_repr::empty() const
		{
			return type.empty() && text.empty();
		}

		array_repr::array_repr(uint32_t length, asITypeInfo* info) noexcept : obj_type(info), buffer(nullptr), element_size(0), sub_type_id(-1)
		{
			VI_ASSERT(info && string(obj_type.get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			precache();

			if (sub_type_id & (uint32_t)type_id::mask_object_t)
				element_size = (uint32_t)sizeof(uintptr_t);
			else
				element_size = (uint32_t)obj_type.get_vm()->get_size_of_primitive_type(sub_type_id).or_else(0);

			if (!check_max_size(length))
				return;

			create_buffer(&buffer, length);
			if (obj_type.flags() & (uint32_t)object_behaviours::gc)
				obj_type.get_vm()->notify_of_new_object(this, obj_type);
		}
		array_repr::array_repr(const array_repr& other) noexcept : obj_type(other.obj_type), buffer(nullptr), element_size(0), sub_type_id(-1)
		{
			VI_ASSERT(obj_type.is_valid() && string(obj_type.get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			precache();

			element_size = other.element_size;
			if (obj_type.flags() & (uint32_t)object_behaviours::gc)
				obj_type.get_vm()->notify_of_new_object(this, obj_type);

			create_buffer(&buffer, 0);
			*this = other;
		}
		array_repr::array_repr(uint32_t length, void* default_value, asITypeInfo* info) noexcept : obj_type(info), buffer(nullptr), element_size(0), sub_type_id(-1)
		{
			VI_ASSERT(info && string(vitex::scripting::type_info(info).get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			precache();

			if (sub_type_id & (uint32_t)type_id::mask_object_t)
				element_size = (uint32_t)sizeof(uintptr_t);
			else
				element_size = (uint32_t)obj_type.get_vm()->get_size_of_primitive_type(sub_type_id).or_else(0);

			if (!check_max_size(length))
				return;

			create_buffer(&buffer, length);
			if (obj_type.flags() & (uint32_t)object_behaviours::gc)
				obj_type.get_vm()->notify_of_new_object(this, obj_type);

			for (uint32_t i = 0; i < size(); i++)
				set_value(i, default_value);
		}
		array_repr::~array_repr() noexcept
		{
			if (buffer)
			{
				delete_buffer(buffer);
				buffer = nullptr;
			}
			obj_type.release();
		}
		array_repr& array_repr::operator=(const array_repr& other) noexcept
		{
			if (&other != this && other.get_array_object_type() == get_array_object_type())
			{
				if (other.buffer != nullptr)
				{
					resize(other.buffer->num_elements);
					copy_buffer(buffer, other.buffer);
				}
				else
					clear();
			}

			return *this;
		}
		void array_repr::set_value(uint32_t index, void* value)
		{
			void* ptr = at(index);
			if (ptr == 0)
				return;

			if ((sub_type_id & ~(uint32_t)type_id::mask_seqnbr_t) && !(sub_type_id & (uint32_t)type_id::handle_t))
				obj_type.get_vm()->assign_object(ptr, value, obj_type.get_sub_type());
			else if (sub_type_id & (uint32_t)type_id::handle_t)
			{
				void* swap = *(void**)ptr;
				*(void**)ptr = *(void**)value;
				obj_type.get_vm()->add_ref_object(*(void**)value, obj_type.get_sub_type());
				if (swap)
					obj_type.get_vm()->release_object(swap, obj_type.get_sub_type());
			}
			else if (sub_type_id == (uint32_t)type_id::float_t || sub_type_id == (uint32_t)type_id::double_t)
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
			else if (sub_type_id == (uint32_t)type_id::bool_t || sub_type_id == (uint32_t)type_id::int8_t || sub_type_id == (uint32_t)type_id::uint8_t)
				*(char*)ptr = *(char*)value;
			else if (sub_type_id == (uint32_t)type_id::int16_t || sub_type_id == (uint32_t)type_id::uint16_t)
				*(short*)ptr = *(short*)value;
			else if (sub_type_id == (uint32_t)type_id::int32_t || sub_type_id == (uint32_t)type_id::uint32_t || sub_type_id > (uint32_t)type_id::double_t)
				*(int*)ptr = *(int*)value;
			else if (sub_type_id == (uint32_t)type_id::int64_t || sub_type_id == (uint32_t)type_id::uint64_t)
				*(int64_t*)ptr = *(int64_t*)value;
		}
		uint32_t array_repr::size() const
		{
			return buffer ? buffer->num_elements : 0;
		}
		uint32_t array_repr::capacity() const
		{
			return buffer ? buffer->max_elements : 0;
		}
		bool array_repr::empty() const
		{
			return buffer ? buffer->num_elements == 0 : true;
		}
		void array_repr::reserve(uint32_t max_elements)
		{
			if (max_elements <= (buffer ? buffer->max_elements : 0))
				return;

			if (!check_max_size(max_elements))
				return;

			sbuffer* new_buffer = program::request_gas_memory<sbuffer>(sizeof(sbuffer) - 1 + (size_t)element_size * (size_t)max_elements);
			if (!new_buffer)
				return;

			if (buffer != nullptr)
			{
				new_buffer->num_elements = buffer->num_elements;
				new_buffer->max_elements = max_elements;
				memcpy(new_buffer->data, buffer->data, (size_t)buffer->num_elements * (size_t)element_size);
				memory::deallocate(buffer);
				buffer = new_buffer;
			}
			else
			{
				new_buffer->num_elements = 0;
				new_buffer->max_elements = max_elements;
				buffer = new_buffer;
			}
		}
		void array_repr::resize(uint32_t num_elements)
		{
			if (!check_max_size(num_elements))
				return;

			resize((int64_t)num_elements - (int64_t)(buffer ? buffer->num_elements : 0), (uint32_t)-1);
		}
		void array_repr::remove_range(uint32_t start, uint32_t count)
		{
			if (count == 0)
				return;

			if (buffer == 0 || start > buffer->num_elements)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", start, start + count, buffer ? buffer->num_elements : 0)));

			if (start + count > buffer->num_elements)
				count = buffer->num_elements - start;

			destroy(buffer, start, start + count);
			memmove(buffer->data + start * (size_t)element_size, buffer->data + (start + count) * (size_t)element_size, (size_t)(buffer->num_elements - start - count) * (size_t)element_size);
			buffer->num_elements -= count;
		}
		void array_repr::remove_if(void* value, uint32_t start_at)
		{
			scache* cache; uint32_t count = size();
			if (!is_eligible_for_find(&cache) || !count || !program::request_gas_mop(0))
				return;

			immediate_context* context = immediate_context::get();
			for (uint32_t i = start_at; i < count; i++)
			{
				if (equals(at(i), value, context, cache))
				{
					remove_at(i--);
					--count;
				}
			}
		}
		void array_repr::resize(int64_t delta, uint32_t where)
		{
			uint32_t buffer_size = buffer ? buffer->num_elements : 0;
			if (delta < 0)
			{
				if (-delta > (int64_t)buffer_size)
					delta = -(int64_t)buffer_size;

				if (where > buffer_size + delta)
					where = buffer_size + delta;
			}
			else if (delta > 0)
			{
				if (!check_max_size(buffer_size + delta))
					return;

				if (where > buffer_size)
					where = buffer_size;
			}

			if (delta == 0)
				return;

			if (buffer_size < buffer_size + delta)
			{
				size_t count = (size_t)buffer_size + (size_t)delta, size = (size_t)element_size;
				sbuffer* new_buffer = program::request_gas_memory<sbuffer>(sizeof(sbuffer) - 1 + size * count);
				if (!new_buffer)
					return;

				new_buffer->num_elements = buffer_size + delta;
				new_buffer->max_elements = new_buffer->num_elements;
				if (buffer != nullptr)
				{
					memcpy(new_buffer->data, buffer->data, (size_t)where * (size_t)element_size);
					if (where < buffer->num_elements)
						memcpy(new_buffer->data + (where + delta) * (size_t)element_size, buffer->data + where * (size_t)element_size, (size_t)(buffer->num_elements - where) * (size_t)element_size);
				}
				create(new_buffer, where, where + delta);
				memory::deallocate(buffer);
				buffer = new_buffer;
			}
			else if (delta < 0)
			{
				if (buffer != nullptr)
				{
					destroy(buffer, where, where - delta);
					memmove(buffer->data + where * (size_t)element_size, buffer->data + (where - delta) * (size_t)element_size, (size_t)(buffer->num_elements - (where - delta)) * (size_t)element_size);
					buffer->num_elements += delta;
				}
			}
			else if (buffer != nullptr)
			{
				memmove(buffer->data + (where + delta) * (size_t)element_size, buffer->data + where * (size_t)element_size, (size_t)(buffer->num_elements - where) * (size_t)element_size);
				create(buffer, where, where + delta);
				buffer->num_elements += delta;
			}
		}
		bool array_repr::check_max_size(uint32_t num_elements)
		{
			uint32_t max_size = 0xFFFFFFFFul - sizeof(sbuffer) + 1;
			if (element_size > 0)
				max_size /= (uint32_t)element_size;

			if (num_elements <= max_size)
				return true;

			contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("size %i is illegal (max_size: %i)", num_elements, max_size)));
			return false;
		}
		asITypeInfo* array_repr::get_array_object_type() const
		{
			return obj_type.get_type_info();
		}
		int array_repr::get_array_type_id() const
		{
			return obj_type.get_type_id();
		}
		int array_repr::get_element_type_id() const
		{
			return sub_type_id;
		}
		void array_repr::insert_at(uint32_t index, void* value)
		{
			if (index > (buffer ? buffer->num_elements : 0))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));

			resize(1, index);
			set_value(index, value);
		}
		void array_repr::insert_at(uint32_t index, const array_repr& array)
		{
			if (index > (buffer ? buffer->num_elements : 0))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));

			if (obj_type.get_type_info() != array.obj_type.get_type_info())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("array types (%s, %s) are incompatible", obj_type.get_name().data(), array.obj_type.get_name().data())));

			uint32_t new_size = array.size();
			resize((int)new_size, index);

			if (&array != this)
			{
				for (uint32_t i = 0; i < array.size(); i++)
				{
					void* value = const_cast<void*>(array.at(i));
					set_value(index + i, value);
				}
			}
			else
			{
				for (uint32_t i = 0; i < index; i++)
				{
					void* value = const_cast<void*>(array.at(i));
					set_value(index + i, value);
				}

				for (uint32_t i = index + new_size, k = 0; i < array.size(); i++, k++)
				{
					void* value = const_cast<void*>(array.at(i));
					set_value(index + index + k, value);
				}
			}
		}
		void array_repr::insert_last(void* value)
		{
			insert_at(buffer ? buffer->num_elements : 0, value);
		}
		void array_repr::remove_at(uint32_t index)
		{
			if (index >= (buffer ? buffer->num_elements : 0))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));
			resize(-1, index);
		}
		void array_repr::remove_last()
		{
			remove_at(buffer->num_elements - 1);
		}
		const void* array_repr::at(uint32_t index) const
		{
			if (buffer == 0 || index >= buffer->num_elements)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));
				return nullptr;
			}
			else if ((sub_type_id & (uint32_t)type_id::mask_object_t) && !(sub_type_id & (uint32_t)type_id::handle_t))
				return *(void**)(buffer->data + (size_t)element_size * index);

			return buffer->data + (size_t)element_size * index;
		}
		void* array_repr::at(uint32_t index)
		{
			return const_cast<void*>(const_cast<const array_repr*>(this)->at(index));
		}
		void* array_repr::front()
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
				return nullptr;
			}

			return at(0);
		}
		const void* array_repr::front() const
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
				return nullptr;
			}

			return at(0);
		}
		void* array_repr::back()
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
				return nullptr;
			}

			return at(size() - 1);
		}
		const void* array_repr::back() const
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
				return nullptr;
			}

			return at(size() - 1);
		}
		void* array_repr::get_buffer()
		{
			return buffer ? buffer->data : nullptr;
		}
		void array_repr::create_buffer(sbuffer** buffer_ptr, uint32_t num_elements)
		{
			*buffer_ptr = program::request_gas_memory<sbuffer>(sizeof(sbuffer) - 1 + (size_t)element_size * (size_t)num_elements);
			if (!*buffer_ptr)
				return;

			(*buffer_ptr)->num_elements = num_elements;
			(*buffer_ptr)->max_elements = num_elements;
			create(*buffer_ptr, 0, num_elements);
		}
		void array_repr::delete_buffer(sbuffer* buffer_ptr)
		{
			destroy(buffer_ptr, 0, buffer_ptr->num_elements);
			memory::deallocate(buffer_ptr);
		}
		void array_repr::create(sbuffer* buffer_ptr, uint32_t start, uint32_t end)
		{
			if ((sub_type_id & (uint32_t)type_id::mask_object_t) && !(sub_type_id & (uint32_t)type_id::handle_t))
			{
				void** max = (void**)(buffer_ptr->data + end * sizeof(void*));
				void** d = (void**)(buffer_ptr->data + start * sizeof(void*));

				virtual_machine* engine = obj_type.get_vm();
				vitex::scripting::type_info sub_type = obj_type.get_sub_type();

				for (; d < max; d++)
				{
					*d = (void*)engine->create_object(sub_type);
					if (*d == 0)
					{
						memset(d, 0, sizeof(void*) * (max - d));
						return;
					}
				}
			}
			else
			{
				void* d = (void*)(buffer_ptr->data + start * (size_t)element_size);
				memset(d, 0, (size_t)(end - start) * (size_t)element_size);
			}
		}
		void array_repr::destroy(sbuffer* buffer_ptr, uint32_t start, uint32_t end)
		{
			if (sub_type_id & (uint32_t)type_id::mask_object_t)
			{
				virtual_machine* engine = obj_type.get_vm();
				vitex::scripting::type_info sub_type = obj_type.get_sub_type();
				void** max = (void**)(buffer_ptr->data + end * sizeof(void*));
				void** d = (void**)(buffer_ptr->data + start * sizeof(void*));

				for (; d < max; d++)
				{
					if (*d)
						engine->release_object(*d, sub_type);
				}
			}
		}
		void array_repr::reverse()
		{
			uint32_t length = size();
			if (length >= 2 && program::request_gas_mop(1))
			{
				unsigned char temp[16];
				for (uint32_t i = 0; i < length / 2; i++)
				{
					copy(temp, get_array_item_pointer((int)i));
					copy(get_array_item_pointer((int)i), get_array_item_pointer((int)(length - i - 1)));
					copy(get_array_item_pointer((int)(length - i - 1)), temp);
				}
			}
		}
		void array_repr::clear()
		{
			resize(0);
		}
		bool array_repr::operator==(const array_repr& other) const
		{
			if (obj_type.get_type_info() != other.obj_type.get_type_info())
				return false;

			if (size() != other.size())
				return false;

			immediate_context* cmp_context = 0;
			bool is_nested = false;

			if (sub_type_id & ~(uint32_t)type_id::mask_seqnbr_t)
			{
				cmp_context = immediate_context::get();
				if (cmp_context)
				{
					if (cmp_context->get_vm() == obj_type.get_vm() && cmp_context->push_state())
						is_nested = true;
					else
						cmp_context = 0;
				}

				if (cmp_context == 0)
					cmp_context = obj_type.get_vm()->request_context();
			}

			bool is_equal = true;
			scache* cache = reinterpret_cast<scache*>(obj_type.get_user_data(SCRIPT_TAG_ARRAY));
			for (uint32_t n = 0; n < size(); n++)
			{
				if (!equals(at(n), other.at(n), cmp_context, cache))
				{
					is_equal = false;
					break;
				}
			}

			if (cmp_context)
			{
				if (is_nested)
				{
					auto state = cmp_context->get_state();
					cmp_context->pop_state();
					if (state == execution::aborted)
						cmp_context->abort();
				}
				else
					obj_type.get_vm()->return_context(cmp_context);
			}

			return is_equal;
		}
		bool array_repr::less(const void* a, const void* b, immediate_context* context, scache* cache)
		{
			if (sub_type_id & ~(uint32_t)type_id::mask_seqnbr_t)
			{
				if (sub_type_id & (uint32_t)type_id::handle_t)
				{
					if (*(void**)a == 0)
						return true;

					if (*(void**)b == 0)
						return false;
				}

				if (!cache || !cache->comparator)
					return false;

				bool is_less = false;
				context->execute_subcall(cache->comparator, [a, b](immediate_context* context)
				{
					context->set_object((void*)a);
					context->set_arg_object(0, (void*)b);
				}, [&is_less](immediate_context* context) { is_less = (context->get_return_dword() < 0); });
				return is_less;
			}

			switch (sub_type_id)
			{
#define COMPARE(t) *((t*)a) < *((t*)b)
				case (uint32_t)type_id::bool_t: return COMPARE(bool);
				case (uint32_t)type_id::int8_t: return COMPARE(signed char);
				case (uint32_t)type_id::uint8_t: return COMPARE(unsigned char);
				case (uint32_t)type_id::int16_t: return COMPARE(signed short);
				case (uint32_t)type_id::uint16_t: return COMPARE(unsigned short);
				case (uint32_t)type_id::int32_t: return COMPARE(signed int);
				case (uint32_t)type_id::uint32_t: return COMPARE(uint32_t);
				case (uint32_t)type_id::float_t:
				case (uint32_t)type_id::double_t:
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
					return false;
				default: return COMPARE(signed int);
#undef COMPARE
			}

			return false;
		}
		bool array_repr::equals(const void* a, const void* b, immediate_context* context, scache* cache) const
		{
			if (sub_type_id & ~(uint32_t)type_id::mask_seqnbr_t)
			{
				if (sub_type_id & (uint32_t)type_id::handle_t)
				{
					if (*(void**)a == *(void**)b)
						return true;
				}

				if (cache && cache->equals)
				{
					bool is_matched = false;
					context->execute_subcall(cache->equals, [a, b](immediate_context* context)
					{
						context->set_object((void*)a);
						context->set_arg_object(0, (void*)b);
					}, [&is_matched](immediate_context* context) { is_matched = (context->get_return_byte() != 0); });
					return is_matched;
				}

				if (cache && cache->comparator)
				{
					bool is_matched = false;
					context->execute_subcall(cache->comparator, [a, b](immediate_context* context)
					{
						context->set_object((void*)a);
						context->set_arg_object(0, (void*)b);
					}, [&is_matched](immediate_context* context) { is_matched = (context->get_return_dword() == 0); });
					return is_matched;
				}

				return false;
			}

			switch (sub_type_id)
			{
#define COMPARE(t) *((t*)a) == *((t*)b)
				case (uint32_t)type_id::bool_t: return COMPARE(bool);
				case (uint32_t)type_id::int8_t: return COMPARE(signed char);
				case (uint32_t)type_id::uint8_t: return COMPARE(unsigned char);
				case (uint32_t)type_id::int16_t: return COMPARE(signed short);
				case (uint32_t)type_id::uint16_t: return COMPARE(unsigned short);
				case (uint32_t)type_id::int32_t: return COMPARE(signed int);
				case (uint32_t)type_id::uint32_t: return COMPARE(uint32_t);
				case (uint32_t)type_id::float_t:
				case (uint32_t)type_id::double_t:
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
					return false;
				default: return COMPARE(signed int);
#undef COMPARE
			}
		}
		uint32_t array_repr::find_by_ref(void* value, uint32_t start_at) const
		{
			uint32_t length = size();
			if (!length || !program::request_gas_mop(0))
				return string_repr::npos;

			if (sub_type_id & (uint32_t)type_id::handle_t)
			{
				value = *(void**)value;
				for (uint32_t i = start_at; i < length; i++)
				{
					if (*(void**)at(i) == value)
						return i;
				}
			}
			else
			{
				for (uint32_t i = start_at; i < length; i++)
				{
					if (at(i) == value)
						return i;
				}
			}

			return string_repr::npos;
		}
		uint32_t array_repr::find(void* value, uint32_t start_at) const
		{
			scache* cache; uint32_t count = size();
			if (!is_eligible_for_find(&cache) || !count || !program::request_gas_mop(0))
				return string_repr::npos;

			immediate_context* context = immediate_context::get();
			for (uint32_t i = start_at; i < count; i++)
			{
				if (equals(at(i), value, context, cache))
					return i;
			}

			return string_repr::npos;
		}
		void array_repr::copy(void* dest, void* src)
		{
			memcpy(dest, src, element_size);
		}
		void* array_repr::get_array_item_pointer(uint32_t index)
		{
			return buffer ? buffer->data + index * element_size : nullptr;
		}
		void* array_repr::get_data_pointer(void* buffer_ptr)
		{
			if ((sub_type_id & (uint32_t)type_id::mask_object_t) && !(sub_type_id & (uint32_t)type_id::handle_t))
				return reinterpret_cast<void*>(*(size_t*)buffer_ptr);
			else
				return buffer_ptr;
		}
		void array_repr::swap(uint32_t index1, uint32_t index2)
		{
			if (index1 >= size() || index2 >= size())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index1, index2, buffer->num_elements)));

			unsigned char swap[16];
			copy(swap, get_array_item_pointer(index1));
			copy(get_array_item_pointer(index1), get_array_item_pointer(index2));
			copy(get_array_item_pointer(index2), swap);
		}
		void array_repr::sort(asIScriptFunction* callback)
		{
			scache* cache; uint32_t count = size();
			if (!is_eligible_for_sort(&cache) || count < 2 || !program::request_gas_mop(4))
				return;

			unsigned char swap[16];
			immediate_context* context = immediate_context::get();
			if (callback != nullptr)
			{
				function_delegate delegatef(callback);
				for (uint32_t i = 1; i < count; i++)
				{
					int64_t j = (int64_t)(i - 1);
					copy(swap, get_array_item_pointer(i));
					while (j >= 0)
					{
						void* a = get_data_pointer(swap), * b = at(j); bool is_less = false;
						context->execute_subcall(delegatef.callable(), [a, b](immediate_context* context)
						{
							context->set_arg_address(0, a);
							context->set_arg_address(1, b);
						}, [&is_less](immediate_context* context) { is_less = (context->get_return_byte() > 0); });
						if (!is_less)
							break;

						copy(get_array_item_pointer(j + 1), get_array_item_pointer(j));
						j--;
					}
					copy(get_array_item_pointer(j + 1), swap);
				}
			}
			else
			{
				for (uint32_t i = 1; i < count; i++)
				{
					int64_t j = (int64_t)(i - 1);
					copy(swap, get_array_item_pointer(i));
					while (j >= 0 && less(get_data_pointer(swap), at(j), context, cache))
					{
						copy(get_array_item_pointer(j + 1), get_array_item_pointer(j));
						j--;
					}
					copy(get_array_item_pointer(j + 1), swap);
				}
			}
		}
		void array_repr::copy_buffer(sbuffer* dest, sbuffer* src)
		{
			virtual_machine* engine = obj_type.get_vm();
			if (sub_type_id & (uint32_t)type_id::handle_t)
			{
				if (dest->num_elements > 0 && src->num_elements > 0)
				{
					int count = (int)(dest->num_elements > src->num_elements ? src->num_elements : dest->num_elements);
					void** max = (void**)(dest->data + count * sizeof(void*));
					void** d = (void**)dest->data;
					void** s = (void**)src->data;

					for (; d < max; d++, s++)
					{
						void* swap = *d;
						*d = *s;

						if (*d)
							engine->add_ref_object(*d, obj_type.get_sub_type());

						if (swap)
							engine->release_object(swap, obj_type.get_sub_type());
					}
				}
			}
			else
			{
				if (dest->num_elements > 0 && src->num_elements > 0)
				{
					int count = (int)(dest->num_elements > src->num_elements ? src->num_elements : dest->num_elements);
					if (sub_type_id & (uint32_t)type_id::mask_object_t)
					{
						void** max = (void**)(dest->data + count * sizeof(void*));
						void** d = (void**)dest->data;
						void** s = (void**)src->data;

						auto sub_type = obj_type.get_sub_type();
						for (; d < max; d++, s++)
							engine->assign_object(*d, *s, sub_type);
					}
					else
						memcpy(dest->data, src->data, (size_t)count * (size_t)element_size);
				}
			}
		}
		void array_repr::precache()
		{
			sub_type_id = obj_type.get_sub_type_id();
			if (!(sub_type_id & ~(uint32_t)type_id::mask_seqnbr_t))
				return;

			scache* cache = reinterpret_cast<scache*>(obj_type.get_user_data(SCRIPT_TAG_ARRAY));
			if (cache)
				return;

			umutex<std::mutex> unique(factory::get()->exclusive);
			cache = reinterpret_cast<scache*>(obj_type.get_user_data(SCRIPT_TAG_ARRAY));
			if (cache)
				return;

			cache = memory::allocate<scache>(sizeof(scache));
			if (!cache)
				return;

			memset(cache, 0, sizeof(scache));
			bool must_be_const = (sub_type_id & (uint32_t)type_id::const_handle_t) ? true : false;

			auto sub_type = obj_type.get_vm()->get_type_info_by_id(sub_type_id);
			if (sub_type.is_valid())
			{
				for (uint32_t i = 0; i < sub_type.get_methods_count(); i++)
				{
					auto function = sub_type.get_method_by_index((int)i);
					if (function.get_args_count() == 1 && (!must_be_const || function.is_read_only()))
					{
						size_t flags = 0;
						int return_type_id = function.get_return_type_id(&flags);
						if (flags != (size_t)modifiers::none)
							continue;

						bool is_cmp = false, is_equals = false;
						if (return_type_id == (uint32_t)type_id::int32_t && function.get_name() == "opCmp")
							is_cmp = true;
						if (return_type_id == (uint32_t)type_id::bool_t && function.get_name() == "opEquals")
							is_equals = true;

						if (!is_cmp && !is_equals)
							continue;

						int param_type_id;
						function.get_arg(0, &param_type_id, &flags);

						if ((param_type_id & ~((uint32_t)type_id::handle_t | (uint32_t)type_id::const_handle_t)) != (sub_type_id & ~((uint32_t)type_id::handle_t | (uint32_t)type_id::const_handle_t)))
							continue;

						if ((flags & (size_t)modifiers::in_ref))
						{
							if ((param_type_id & (uint32_t)type_id::handle_t) || (must_be_const && !(flags & (size_t)modifiers::constant)))
								continue;
						}
						else if (param_type_id & (uint32_t)type_id::handle_t)
						{
							if (must_be_const && !(param_type_id & (uint32_t)type_id::const_handle_t))
								continue;
						}
						else
							continue;

						if (is_cmp)
						{
							if (cache->comparator || cache->comparator_return_code)
							{
								cache->comparator = 0;
								cache->comparator_return_code = (int)virtual_error::multiple_functions;
							}
							else
								cache->comparator = function.get_function();
						}
						else if (is_equals)
						{
							if (cache->equals || cache->equals_return_code)
							{
								cache->equals = 0;
								cache->equals_return_code = (int)virtual_error::multiple_functions;
							}
							else
								cache->equals = function.get_function();
						}
					}
				}
			}

			if (cache->equals == 0 && cache->equals_return_code == 0)
				cache->equals_return_code = (int)virtual_error::no_function;
			if (cache->comparator == 0 && cache->comparator_return_code == 0)
				cache->comparator_return_code = (int)virtual_error::no_function;
			obj_type.set_user_data(cache, SCRIPT_TAG_ARRAY);
		}
		void array_repr::enum_references(asIScriptEngine* engine)
		{
			if (sub_type_id & (uint32_t)type_id::mask_object_t)
			{
				if (!buffer)
					return;

				void** data = (void**)buffer->data;
				virtual_machine* vm = virtual_machine::get(engine);
				auto sub_type = vm->get_type_info_by_id(sub_type_id);
				if ((sub_type.flags() & (uint32_t)object_behaviours::ref))
				{
					for (uint32_t i = 0; i < buffer->num_elements; i++)
						function_factory::gc_enum_callback(engine, data[i]);
				}
				else if ((sub_type.flags() & (size_t)object_behaviours::value) && (sub_type.flags() & (size_t)object_behaviours::gc))
				{
					for (uint32_t i = 0; i < buffer->num_elements; i++)
					{
						if (data[i])
							vm->forward_enum_references(data[i], sub_type);
					}
				}
			}
		}
		void array_repr::release_references(asIScriptEngine*)
		{
			resize(0);
		}
		array_repr* array_repr::create(asITypeInfo* info, uint32_t length)
		{
			array_repr* result = new array_repr(length, info);
			if (!result)
				contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

			return result;
		}
		array_repr* array_repr::create(asITypeInfo* info, uint32_t length, void* default_value)
		{
			array_repr* result = new array_repr(length, default_value, info);
			if (!result)
				contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

			return result;
		}
		array_repr* array_repr::create(asITypeInfo* info)
		{
			return array_repr::create(info, (uint32_t)0);
		}
		void array_repr::cleanup_type_info_cache(asITypeInfo* type_context)
		{
			vitex::scripting::type_info type(type_context);
			array_repr::scache* cache = reinterpret_cast<array_repr::scache*>(type.get_user_data(SCRIPT_TAG_ARRAY));
			if (cache != nullptr)
			{
				cache->~scache();
				memory::deallocate(cache);
			}
		}
		bool array_repr::template_callback(asITypeInfo* info_context, bool& dont_garbage_collect)
		{
			vitex::scripting::type_info info(info_context);
			int type_id = info.get_sub_type_id();
			if (type_id == (uint32_t)type_id::void_t || type_id == (uint32_t)type_id::float_t || type_id == (uint32_t)type_id::double_t)
				return false;

			if ((type_id & (uint32_t)type_id::mask_object_t) && !(type_id & (uint32_t)type_id::handle_t))
			{
				virtual_machine* engine = info.get_vm();
				auto sub_type = engine->get_type_info_by_id(type_id);
				size_t flags = sub_type.flags();

				if ((flags & (size_t)object_behaviours::value) && !(flags & (size_t)object_behaviours::pod))
				{
					bool found = false;
					for (uint32_t i = 0; i < sub_type.get_behaviour_count(); i++)
					{
						behaviours properties;
						function func = sub_type.get_behaviour_by_index(i, &properties);
						if (properties != behaviours::construct)
							continue;

						if (func.get_args_count() == 0)
						{
							found = true;
							break;
						}
					}

					if (!found)
					{
						engine->write_message(SCRIPT_TYPE_ARRAY, 0, 0, log_category::err, "The subtype has no default constructor");
						return false;
					}
				}
				else if ((flags & (size_t)object_behaviours::ref))
				{
					bool found = false;
					if (!engine->get_property(features::disallow_value_assign_for_ref_type))
					{
						for (uint32_t i = 0; i < sub_type.get_factories_count(); i++)
						{
							function func = sub_type.get_factory_by_index(i);
							if (func.get_args_count() == 0)
							{
								found = true;
								break;
							}
						}
					}

					if (!found)
					{
						engine->write_message(SCRIPT_TYPE_ARRAY, 0, 0, log_category::err, "The subtype has no default factory");
						return false;
					}
				}

				if (!(flags & (size_t)object_behaviours::gc))
					dont_garbage_collect = true;
			}
			else if (!(type_id & (uint32_t)type_id::handle_t))
			{
				dont_garbage_collect = true;
			}
			else
			{
				auto sub_type = info.get_vm()->get_type_info_by_id(type_id);
				size_t flags = sub_type.flags();

				if (!(flags & (size_t)object_behaviours::gc))
				{
					if ((flags & (size_t)object_behaviours::script_object))
					{
						if ((flags & (size_t)object_behaviours::noinherit))
							dont_garbage_collect = true;
					}
					else
						dont_garbage_collect = true;
				}
			}

			return true;
		}
		bool array_repr::is_eligible_for_find(scache** output) const
		{
			scache* cache = reinterpret_cast<scache*>(obj_type.get_user_data(SCRIPT_TAG_ARRAY));
			if (!(sub_type_id & ~((int)type_id::mask_seqnbr_t)))
			{
				*output = cache;
				return true;
			}

			if (cache != nullptr && cache->equals != nullptr)
			{
				*output = cache;
				return true;
			}

			immediate_context* context = immediate_context::get();
			if (context != nullptr)
			{
				if (cache && cache->comparator_return_code == (int)virtual_error::multiple_functions)
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "too many opCmp implementations for find function"));
				else
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "no opCmp implementation for find function"));
			}
			*output = nullptr;
			return false;
		}
		bool array_repr::is_eligible_for_sort(scache** output) const
		{
			scache* cache = reinterpret_cast<scache*>(obj_type.get_user_data(SCRIPT_TAG_ARRAY));
			if (!(sub_type_id & ~((int)type_id::mask_seqnbr_t)))
			{
				*output = cache;
				return true;
			}

			if (cache != nullptr && cache->comparator != nullptr)
			{
				*output = cache;
				return true;
			}

			immediate_context* context = immediate_context::get();
			if (context != nullptr)
			{
				if (cache && cache->comparator_return_code == (int)virtual_error::multiple_functions)
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "too many opCmp implementations for find function"));
				else
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "no opCmp implementation for find function"));
			}
			*output = nullptr;
			return false;
		}
		size_t array_repr::get_id()
		{
			return SCRIPT_TAG_ARRAY;
		}

		string_repr::string_repr()
		{
			char init = '\0';
			memset((void*)this, 0, sizeof(*this));
			copy_buffer(&init, 0);
		}
		string_repr::string_repr(const string_repr& other)
		{
			memset((void*)this, 0, sizeof(*this));
			copy_buffer(other.data(), other.size());
		}
		string_repr::string_repr(const std::string_view& other)
		{
			memset((void*)this, 0, sizeof(*this));
			copy_buffer(other.data(), (uint32_t)other.size());
		}
		string_repr::string_repr(string_repr&& other) noexcept
		{
			memset((void*)this, 0, sizeof(*this));
			move_buffer(std::move(other));
		}
		string_repr& string_repr::operator=(const string_repr& other)
		{
			if (this == &other)
				return *this;

			copy_buffer(other.data(), other.size());
			return *this;
		}
		string_repr& string_repr::operator=(const std::string_view& other)
		{
			copy_buffer(other.data(), (uint32_t)other.size());
			return *this;
		}
		string_repr& string_repr::operator=(string_repr&& other) noexcept
		{
			if (this == &other)
				return *this;

			move_buffer(std::move(other));
			return *this;
		}
		string_repr::~string_repr()
		{
			if (heap_buffer)
				memory::deallocate(heap.data);
		}
		string_repr& string_repr::operator+=(const string_repr& other)
		{
			return assign_append(other);
		}
		string_repr& string_repr::operator+=(char c)
		{
			return assign_append_char(c);
		}
		string_repr string_repr::operator+(const string_repr& other) const
		{
			string_repr result(*this);
			result.append(other);
			return result;
		}
		string_repr string_repr::operator+(char c) const
		{
			string_repr result(*this);
			result.append_char(c);
			return result;
		}
		string_repr& string_repr::assign(const string_repr& other)
		{
			copy_buffer(other.data(), other.size());
			return *this;
		}
		string_repr& string_repr::assign_view(const std::string_view& other)
		{
			copy_buffer(other.data(), (uint32_t)other.size());
			return *this;
		}
		string_repr& string_repr::assign_append(const string_repr& other)
		{
			if (other.empty())
				return *this;

			uint32_t offset = size();
			uint32_t count = offset + other.size();
			if (count < offset)
				return *this;

			resize_buffer(count);
			char* buffer = data();
			memcpy(buffer + offset, other.data(), other.size());
			return *this;
		}
		string_repr& string_repr::assign_append_char(char c)
		{
			uint32_t offset = size();
			if (offset + 1 < offset)
				return *this;

			resize_buffer(offset + 1);
			char* buffer = data();
			buffer[offset] = c;
			return *this;
		}
		string_repr string_repr::append(const string_repr& other)
		{
			auto copy = *this;
			copy.assign_append(other);
			return copy;
		}
		string_repr string_repr::append_char(char c)
		{
			auto copy = *this;
			copy.assign_append_char(c);
			return copy;
		}
		bool string_repr::operator==(const string_repr& other) const
		{
			return compare(other) == 0;
		}
		int string_repr::compare(const string_repr& other) const
		{
			uint32_t min_size = std::min(size(), other.size());
			int result = memcmp(data(), other.data(), min_size);
			if (result != 0)
				return result;
			if (size() < other.size())
				return -1;
			else if (size() > other.size())
				return 1;
			return 0;
		}
		const char* string_repr::at(uint32_t index) const
		{
			if (index >= size())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, size())));
				return nullptr;
			}

			return data() + index;
		}
		const char* string_repr::front() const
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", size())));
				return nullptr;
			}

			return data();
		}
		const char* string_repr::back() const
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", size())));
				return nullptr;
			}

			return data() + (size() - 1);
		}
		bool string_repr::empty() const
		{
			return size() == 0;
		}
		uint32_t string_repr::size() const
		{
			return heap_buffer ? heap.size : stack.size;
		}
		uint32_t string_repr::capacity() const
		{
			return heap_buffer ? heap.capacity : stack_capacity;
		}
		void string_repr::clear()
		{
			resize_buffer(0);
		}
		void string_repr::push_front(char c)
		{
			char* buffer = data();
			uint32_t buffer_size = size();
			resize_buffer(buffer_size + 1);
			memmove(buffer + 1, buffer, buffer_size);
			buffer[0] = c;
		}
		void string_repr::pop_front()
		{
			if (empty())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", size())));

			char* buffer = data();
			uint32_t buffer_size = size() - 1;
			memmove(buffer, buffer + 1, buffer_size);
			resize_buffer(buffer_size);
		}
		void string_repr::push_back(char c)
		{
			append_char(c);
		}
		void string_repr::pop_back()
		{
			if (empty())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", size())));

			resize_buffer(size() - 1);
		}
		bool string_repr::starts_with(const string_repr& other, uint32_t offset) const
		{
			return stringify::starts_with(view(), other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
		}
		bool string_repr::ends_with(const string_repr& other) const
		{
			return stringify::ends_with(view(), other.view());
		}
		string_repr string_repr::substring(uint32_t offset) const
		{
			return string_repr(view().substr(offset == npos ? std::string_view::npos : (size_t)offset));
		}
		string_repr string_repr::substring_sized(uint32_t offset, uint32_t len) const
		{
			return string_repr(view().substr(offset == npos ? std::string_view::npos : (size_t)offset, len == npos ? std::string_view::npos : (size_t)len));
		}
		string_repr& string_repr::trim()
		{
			trim_start();
			trim_end();
			return *this;
		}
		string_repr& string_repr::trim_start()
		{
			while (!empty() && stringify::is_whitespace(*front()))
				pop_front();
			return *this;
		}
		string_repr& string_repr::trim_end()
		{
			while (!empty() && stringify::is_whitespace(*back()))
				pop_back();
			return *this;
		}
		string_repr& string_repr::to_lower()
		{
			if (empty())
				return *this;

			char* buffer = data();
			uint32_t len = size();
			for (uint32_t i = 0; i < len; ++i)
				buffer[i] = std::tolower(buffer[i]);
			return *this;
		}
		string_repr& string_repr::to_upper()
		{
			if (empty())
				return *this;

			char* buffer = data();
			uint32_t len = size();
			for (uint32_t i = 0; i < len; ++i)
				buffer[i] = std::toupper(buffer[i]);

			return *this;
		}
		string_repr& string_repr::reverse()
		{
			if (empty() || !program::request_gas_mop(1))
				return *this;

			char* buffer = data();
			uint32_t len = size();
			uint32_t half_len = len / 2;
			for (uint32_t i = 0; i < half_len; ++i)
				std::swap(buffer[i], buffer[len - 1 - i]);

			return *this;
		}
		std::string_view string_repr::view() const
		{
			return std::string_view(data(), (size_t)size());
		}
		uint32_t string_repr::rfind(const string_repr& other) const
		{
			return rfind_offset(other, npos);
		}
		uint32_t string_repr::rfind_char(uint8_t other) const
		{
			return rfind_char_offset(other, npos);
		}
		uint32_t string_repr::rfind_offset(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().rfind(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::rfind_char_offset(uint8_t other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().rfind(other, offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find_char(uint8_t other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find(other, offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find_first_of(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find_first_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find_first_not_of(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find_first_not_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find_last_of(const string_repr& other) const
		{
			return find_last_of_offset(other, npos);
		}
		uint32_t string_repr::find_last_not_of(const string_repr& other) const
		{
			return find_last_not_of_offset(other, npos);
		}
		uint32_t string_repr::find_last_of_offset(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find_last_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		uint32_t string_repr::find_last_not_of_offset(const string_repr& other, uint32_t offset) const
		{
			if (!program::request_gas_mop(0))
				return npos;

			size_t result = view().find_last_not_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
			return result == std::string_view::npos ? npos : (uint32_t)result;
		}
		array_repr* string_repr::split(const string_repr& delimiter) const
		{
			if (!program::request_gas_mop(2))
				return nullptr;

			virtual_machine* vm = virtual_machine::get();
			asITypeInfo* array_type = vm->get_type_info_by_decl(SCRIPT_TYPE_ARRAY "<" SCRIPT_TYPE_STRING ">@").get_type_info();
			array_repr* array = array_repr::create(array_type);
			auto values = stringify::split(view(), delimiter.view());
			array->resize(values.size());
			for (size_t i = 0; i < values.size(); i++)
				((string_repr*)array->at((uint32_t)i))->assign(std::string_view(values[i]));
			return array;
		}
		char* string_repr::data()
		{
			return heap_buffer ? heap.data : stack.data;
		}
		const char* string_repr::data() const
		{
			return heap_buffer ? heap.data : stack.data;
		}
		void string_repr::copy_buffer(const char* buffer, uint32_t buffer_size)
		{
			resize_buffer(buffer_size);
			memcpy(data(), buffer, buffer_size);
		}
		void string_repr::move_buffer(string_repr&& other)
		{
			clear();
			memcpy((void*)this, (void*)&other, sizeof(other));
			memset((void*)&other, 0, sizeof(other));
		}
		void string_repr::resize_buffer(uint32_t required_size)
		{
			require_buffer_capacity(buffer_capacity_of(required_size));
			if (heap_buffer)
			{
				heap.size = required_size;
				heap.data[heap.size] = '\0';
			}
			else
			{
				stack.size = required_size;
				stack.data[stack.size] = '\0';
			}
		}
		void string_repr::require_buffer_capacity(uint32_t required_capacity)
		{
			if (!required_capacity)
				required_capacity = buffer_capacity_of(required_capacity);

			if (capacity() >= required_capacity)
				return;

			if (heap_buffer)
			{
				heap.capacity = required_capacity;
				char* copy = program::request_gas_memory<char>(heap.capacity + 1);
				memset(copy, 0, heap.capacity + 1);
				memcpy(copy, heap.data, heap.size);
				memory::deallocate(heap.data);
				heap.data = copy;
			}
			else
			{
				uint32_t size = stack.size;
				char copy[stack_capacity];
				memcpy(copy, stack.data, stack_capacity);

				heap.size = size;
				heap.capacity = required_capacity;
				heap.data = program::request_gas_memory<char>(heap.capacity + 1);
				memset(heap.data, 0, heap.capacity + 1);
				memcpy(heap.data, copy, stack_capacity);
				heap_buffer = true;
			}
		}
		uint128_t string_repr::from_string_uint128(int base) const
		{
			return uint128_t(view(), base);
		}
		uint256_t string_repr::from_string_uint256(int base) const
		{
			return uint256_t(view(), base);
		}
		decimal string_repr::from_string_decimal(int base) const
		{
			return decimal::from(view(), base);
		}
		string_repr string_repr::to_string_uint128(const uint128_t& other, int base)
		{
			return string_repr(other.to_string(base));
		}
		string_repr string_repr::to_string_uint256(const uint256_t& other, int base)
		{
			return string_repr(other.to_string(base));
		}
		string_repr string_repr::to_string_decimal(const decimal& other)
		{
			return string_repr(other.to_string());
		}
		string_repr string_repr::to_string_address(const address_repr& other)
		{
			return other.to_string();
		}
		void string_repr::create(string_repr* base)
		{
			new(base) string_repr();
		}
		void string_repr::create_copy(string_repr* base, const string_repr& other)
		{
			new(base) string_repr(other);
		}
		void string_repr::destroy(string_repr* base)
		{
			base->~string_repr();
		}
		uint32_t string_repr::buffer_capacity_of(size_t required_size)
		{
			uint32_t pages_needed = ((uint32_t)required_size + stack_capacity - 1) / stack_capacity;
			return pages_needed * stack_capacity;
		}

		void real320_repr::custom_constructor_bool(decimal* base, bool value)
		{
			new(base) decimal(value ? "1" : "0");
			truncate_or_throw(*base, true);
		}
		void real320_repr::custom_constructor_string(decimal* base, const string_repr& value)
		{
			new(base) decimal(value.view());
			truncate_or_throw(*base, true);
		}
		void real320_repr::custom_constructor_copy(decimal* base, const decimal& value)
		{
			new(base) decimal(value);
			truncate_or_throw(*base, true);
		}
		void real320_repr::custom_constructor(decimal* base)
		{
			new(base) decimal(decimal::zero());
			truncate_or_throw(*base, true);
		}
		bool real320_repr::is_not_zero_or_nan(decimal& base)
		{
			return !base.is_zero_or_nan();
		}
		bool real320_repr::truncate_or_throw(decimal& base, bool require_decimal_precision)
		{
			auto* vm = virtual_machine::get();
			if (!vm)
				return true;

			auto& message = protocol::now().message;
			if (require_decimal_precision || base.decimal_size() > message.decimal_precision)
				base.truncate(message.decimal_precision);

			bool throws = base.integer_size() > message.integer_precision || base.decimal_size() > message.decimal_precision;
			if (throws)
				contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("fixed point overflow of number \"%s\" (sp: %i, fp: %i)", base.to_string().c_str(), base.integer_size(), base.decimal_size())));
			return !throws;
		}
		uint128_t real320_repr::to_uint128(decimal& base)
		{
			decimal copy = base;
			copy.truncate(0);
			return uint128_t(copy.to_string());
		}
		uint256_t real320_repr::to_uint256(decimal& base)
		{
			decimal copy = base;
			copy.truncate(0);
			return uint256_t(copy.to_string());
		}
		string_repr real320_repr::to_string(decimal& base)
		{
			return string_repr(base.to_string());
		}
		string_repr real320_repr::to_exponent(decimal& base)
		{
			return string_repr(base.to_exponent());
		}
		decimal real320_repr::negate(decimal& base)
		{
			decimal result = -base;
			truncate_or_throw(result, false);
			return result;
		}
		decimal& real320_repr::mul_eq(decimal& base, const decimal& v)
		{
			truncate_or_throw(base *= v, false);
			return base;
		}
		decimal& real320_repr::div_eq(decimal& base, const decimal& v)
		{
			truncate_or_throw(base, true);
			truncate_or_throw(base /= v, false);
			return base;
		}
		decimal& real320_repr::add_eq(decimal& base, const decimal& v)
		{
			truncate_or_throw(base += v, false);
			return base;
		}
		decimal& real320_repr::sub_eq(decimal& base, const decimal& v)
		{
			truncate_or_throw(base -= v, false);
			return base;
		}
		decimal& real320_repr::fpp(decimal& base)
		{
			truncate_or_throw(++base, false);
			return base;
		}
		decimal& real320_repr::fmm(decimal& base)
		{
			truncate_or_throw(--base, false);
			return base;
		}
		decimal& real320_repr::pp(decimal& base)
		{
			truncate_or_throw(base++, false);
			return base;
		}
		decimal& real320_repr::mm(decimal& base)
		{
			truncate_or_throw(base--, false);
			return base;
		}
		bool real320_repr::eq(decimal& base, const decimal& right)
		{
			return base == right;
		}
		int real320_repr::cmp(decimal& base, const decimal& right)
		{
			if (base == right)
				return 0;

			return base > right ? 1 : -1;
		}
		decimal real320_repr::add(const decimal& left, const decimal& right)
		{
			decimal result = left + right;
			truncate_or_throw(result, false);
			return result;
		}
		decimal real320_repr::sub(const decimal& left, const decimal& right)
		{
			decimal result = left - right;
			truncate_or_throw(result, false);
			return result;
		}
		decimal real320_repr::mul(const decimal& left, const decimal& right)
		{
			decimal result = left * right;
			truncate_or_throw(result, false);
			return result;
		}
		decimal real320_repr::div(const decimal& left, const decimal& right)
		{
			decimal left_allocated = left;
			return div_eq(left_allocated, right);
		}
		decimal real320_repr::per(const decimal& left, const decimal& right)
		{
			decimal result = left % right;
			truncate_or_throw(result, false);
			return result;
		}
		decimal real320_repr::from(const string_repr& data, uint8_t base)
		{
			decimal result = decimal::from(data.view(), base);
			truncate_or_throw(result, false);
			return result;
		}
		uint32_t real320_repr::estimate_bits(uint32_t digits)
		{
			const uint64_t LOG2_10_NUMERATOR = 3321928095ULL;
			const uint64_t LOG2_10_DENOMINATOR = 1000000000ULL;
			uint64_t numerator = LOG2_10_NUMERATOR * digits;
			uint64_t bits = (numerator + LOG2_10_DENOMINATOR - 1) / LOG2_10_DENOMINATOR;
			return (uint32_t)(bits + (bits % 2));
		}
		uint32_t real320_repr::target_bits()
		{
			auto& message = protocol::now().message;
			return estimate_bits(message.integer_precision + message.decimal_precision);
		}

		void uint128_repr::default_construct(uint128_t* base)
		{
			new(base) uint128_t();
			memset(base, 0, sizeof(uint128_t));
		}
		void uint128_repr::construct_string(uint128_t* base, const string_repr& other)
		{
			new(base) uint128_t(other.view());
		}
		bool uint128_repr::to_bool(uint128_t& value)
		{
			return !!value;
		}
		int8_t uint128_repr::to_int8(uint128_t& value)
		{
			return (int8_t)(uint8_t)value;
		}
		uint8_t uint128_repr::to_uint8(uint128_t& value)
		{
			return (uint8_t)value;
		}
		int16_t uint128_repr::to_int16(uint128_t& value)
		{
			return (int16_t)(uint16_t)value;
		}
		uint16_t uint128_repr::to_uint16(uint128_t& value)
		{
			return (uint16_t)value;
		}
		int32_t uint128_repr::to_int32(uint128_t& value)
		{
			return (int32_t)(uint32_t)value;
		}
		uint32_t uint128_repr::to_uint32(uint128_t& value)
		{
			return (uint32_t)value;
		}
		int64_t uint128_repr::to_int64(uint128_t& value)
		{
			return (int64_t)(uint64_t)value;
		}
		uint64_t uint128_repr::to_uint64(uint128_t& value)
		{
			return (uint64_t)value;
		}
		uint256_t uint128_repr::to_uint256(uint128_t& value)
		{
			return uint256_t(value);
		}
		string_repr uint128_repr::to_string(uint128_t& base)
		{
			return string_repr(base.to_string());
		}
		uint128_t& uint128_repr::mul_eq(uint128_t& base, const uint128_t& v)
		{
			base *= v;
			return base;
		}
		uint128_t& uint128_repr::div_eq(uint128_t& base, const uint128_t& v)
		{
			base /= v;
			return base;
		}
		uint128_t& uint128_repr::add_eq(uint128_t& base, const uint128_t& v)
		{
			base += v;
			return base;
		}
		uint128_t& uint128_repr::sub_eq(uint128_t& base, const uint128_t& v)
		{
			base -= v;
			return base;
		}
		uint128_t& uint128_repr::fpp(uint128_t& base)
		{
			return ++base;
		}
		uint128_t& uint128_repr::fmm(uint128_t& base)
		{
			return --base;
		}
		uint128_t& uint128_repr::pp(uint128_t& base)
		{
			base++;
			return base;
		}
		uint128_t& uint128_repr::mm(uint128_t& base)
		{
			base--;
			return base;
		}
		bool uint128_repr::eq(uint128_t& base, const uint128_t& right)
		{
			return base == right;
		}
		int uint128_repr::cmp(uint128_t& base, const uint128_t& right)
		{
			if (base == right)
				return 0;

			return base > right ? 1 : -1;
		}
		uint128_t uint128_repr::add(const uint128_t& left, const uint128_t& right)
		{
			return left + right;
		}
		uint128_t uint128_repr::sub(const uint128_t& left, const uint128_t& right)
		{
			return left - right;
		}
		uint128_t uint128_repr::mul(const uint128_t& left, const uint128_t& right)
		{
			return left * right;
		}
		uint128_t uint128_repr::div(const uint128_t& left, const uint128_t& right)
		{
			return left / right;
		}
		uint128_t uint128_repr::per(const uint128_t& left, const uint128_t& right)
		{
			return left % right;
		}

		void uint256_repr::default_construct(uint256_t* base)
		{
			new(base) uint256_t();
			memset(base, 0, sizeof(uint256_t));
		}
		void uint256_repr::construct_string(uint256_t* base, const string_repr& other)
		{
			new(base) uint256_t(other.view());
		}
		bool uint256_repr::to_bool(uint256_t& value)
		{
			return !!value;
		}
		int8_t uint256_repr::to_int8(uint256_t& value)
		{
			return (int8_t)(uint8_t)value;
		}
		uint8_t uint256_repr::to_uint8(uint256_t& value)
		{
			return (uint8_t)value;
		}
		int16_t uint256_repr::to_int16(uint256_t& value)
		{
			return (int16_t)(uint16_t)value;
		}
		uint16_t uint256_repr::to_uint16(uint256_t& value)
		{
			return (uint16_t)value;
		}
		int32_t uint256_repr::to_int32(uint256_t& value)
		{
			return (int32_t)(uint32_t)value;
		}
		uint32_t uint256_repr::to_uint32(uint256_t& value)
		{
			return (uint32_t)value;
		}
		int64_t uint256_repr::to_int64(uint256_t& value)
		{
			return (int64_t)(uint64_t)value;
		}
		uint64_t uint256_repr::to_uint64(uint256_t& value)
		{
			return (uint64_t)value;
		}
		uint128_t uint256_repr::to_uint128(uint256_t& value)
		{
			return value.low();
		}
		string_repr uint256_repr::to_string(uint256_t& base)
		{
			return string_repr(base.to_string());
		}
		uint256_t& uint256_repr::mul_eq(uint256_t& base, const uint256_t& v)
		{
			base *= v;
			return base;
		}
		uint256_t& uint256_repr::div_eq(uint256_t& base, const uint256_t& v)
		{
			base /= v;
			return base;
		}
		uint256_t& uint256_repr::add_eq(uint256_t& base, const uint256_t& v)
		{
			base += v;
			return base;
		}
		uint256_t& uint256_repr::sub_eq(uint256_t& base, const uint256_t& v)
		{
			base -= v;
			return base;
		}
		uint256_t& uint256_repr::fpp(uint256_t& base)
		{
			return ++base;
		}
		uint256_t& uint256_repr::fmm(uint256_t& base)
		{
			return --base;
		}
		uint256_t& uint256_repr::pp(uint256_t& base)
		{
			base++;
			return base;
		}
		uint256_t& uint256_repr::mm(uint256_t& base)
		{
			base--;
			return base;
		}
		bool uint256_repr::eq(uint256_t& base, const uint256_t& right)
		{
			return base == right;
		}
		int uint256_repr::cmp(uint256_t& base, const uint256_t& right)
		{
			if (base == right)
				return 0;

			return base > right ? 1 : -1;
		}
		uint256_t uint256_repr::add(const uint256_t& left, const uint256_t& right)
		{
			return left + right;
		}
		uint256_t uint256_repr::sub(const uint256_t& left, const uint256_t& right)
		{
			return left - right;
		}
		uint256_t uint256_repr::mul(const uint256_t& left, const uint256_t& right)
		{
			return left * right;
		}
		uint256_t uint256_repr::div(const uint256_t& left, const uint256_t& right)
		{
			return left / right;
		}
		uint256_t uint256_repr::per(const uint256_t& left, const uint256_t& right)
		{
			return left % right;
		}

		address_repr::address_repr(const algorithm::pubkeyhash_t& owner) : hash(owner)
		{
		}
		address_repr::address_repr(const string_repr& address)
		{
			algorithm::signing::decode_address(address.view(), hash);
		}
		address_repr::address_repr(const uint256_t& owner_data)
		{
			uint8_t owner_raw_data[32];
			owner_data.encode(owner_raw_data);
			memcpy(hash.data, owner_raw_data, sizeof(hash.data));
		}
		void address_repr::pay(const uint256_t& asset, const decimal& value)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p || !value.is_positive())
				return;

			auto payment = p->context->apply_payment(asset, p->callable().data, hash.data, value);
			if (!payment)
				return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(payment.error().message())));
		}
		decimal address_repr::balance_of(const uint256_t& asset) const
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->get_account_balance(asset, hash.data).or_else(states::account_balance(algorithm::pubkeyhash_t(), asset, nullptr)).get_balance() : decimal::zero();
		}
		string_repr address_repr::to_string() const
		{
			return string_repr(algorithm::signing::encode_address(hash));
		}
		uint256_t address_repr::to_public_key_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.data, sizeof(algorithm::pubkeyhash_t));

			uint256_t numeric = 0;
			numeric.decode(data);
			return numeric;
		}
		bool address_repr::empty() const
		{
			return hash.empty();
		}
		void address_repr::paid_call(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto& value = *inout.get_arg_object<decimal>(1);
			if (!value.is_zero() && !value.is_positive())
				contract::throw_ptr(exception_repr(exception_repr::category::execution(), "illegal call value paid"));
			else
				call(generic, value);
		}
		void address_repr::free_call(asIScriptGeneric* generic)
		{
			call(generic, decimal::nan());
		}
		void address_repr::call(asIScriptGeneric* generic, const decimal& value)
		{
			generic_context inout = generic_context(generic);
			auto object = (address_repr*)inout.get_object_address();
			auto& function = *inout.get_arg_object<string_repr>(0);
			void* output_value = inout.get_address_of_return_location();
			int output_type_id = inout.get_return_addressable_type_id();
			VI_ASSERT(inout.get_generic() != nullptr, "generic context should be set");
			VI_ASSERT(object != nullptr, "this object should be set");

			format::wo_stream stream;
			for (size_t i = value.is_nan() ? 1 : 2; i < inout.get_args_count(); i++)
			{
				void* input_value = inout.get_arg_address(i);
				int input_type_id = inout.get_arg_type_id(i);
				auto serialization = marshall::store(&stream, input_value, input_type_id);
				if (!serialization)
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), stringify::text("call to %s::%.*s: %s (argument: %i)", object->to_string().data(), (int)function.size(), function.data(), serialization.error().what(), (int)i - 1)));
			}

			auto reader = stream.ro(); format::variables function_args;
			if (!reader.data.empty() && !format::variables_util::deserialize_flat_from(reader, &function_args))
				return contract::throw_ptr(exception_repr(exception_repr::category::execution(), stringify::text("call to %s::%.*s: argument pack builder failed", object->to_string().data(), (int)function.size(), function.data())));

			auto* p = program::fetch_mutable();
			if (p != nullptr)
			{
				auto execution = p->subexecute(object->hash, value.is_nan() ? decimal::zero() : value, ccall::paying_call, function.view(), std::move(function_args), output_value, output_type_id);
				if (!execution)
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(execution.error().message())));
			}
			else
			{
				auto* immutable_program = program::fetch_immutable_or_throw();
				if (immutable_program != nullptr)
				{
					auto execution = immutable_program->subexecute(object->hash, decimal::zero(), ccall::const_call, function.view(), std::move(function_args), output_value, output_type_id);
					if (!execution)
						return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(execution.error().message())));
				}
			}
		}
		bool address_repr::equals(const address_repr& a, const address_repr& b)
		{
			return a.hash.equals(b.hash.data);
		}

		abi_repr::abi_repr(const string_repr& data) : output(data.view())
		{
			input.data = output.data;
		}
		void abi_repr::seek(uint32_t offset)
		{
			input.seek = (size_t)offset;
		}
		void abi_repr::clear()
		{
			input.clear();
			output.clear();
		}
		void abi_repr::wboolean(bool value)
		{
			output.write_boolean(value);
			input.data = output.data;
		}
		void abi_repr::wuint160(const address_repr& value)
		{
			output.write_string(value.hash.optimized_view());
			input.data = output.data;
		}
		void abi_repr::wuint256(const uint256_t& value)
		{
			output.write_integer(value);
			input.data = output.data;
		}
		void abi_repr::wreal320(const decimal& value)
		{
			output.write_decimal(value);
			input.data = output.data;
		}
		void abi_repr::merge(const string_repr& value)
		{
			output.data.append(value.data(), (size_t)value.size());
			input.data = output.data;
		}
		void abi_repr::wstr(const string_repr& value)
		{
			output.write_string(value.view());
			input.data = output.data;
		}
		void abi_repr::wrstr(const string_repr& value)
		{
			output.write_string_raw(value.view());
			input.data = output.data;
		}
		bool abi_repr::rboolean(bool& value)
		{
			return input.read_boolean(input.read_type(), &value);
		}
		bool abi_repr::ruint160(address_repr& value)
		{
			string_repr result;
			if (!rstr(result))
				return false;

			algorithm::pubkeyhash_t blob;
			if (!algorithm::encoding::decode_bytes(result.view(), blob.data, sizeof(blob.data)))
				return false;

			value = address_repr(blob);
			return true;
		}
		bool abi_repr::ruint256(uint256_t& value)
		{
			return input.read_integer(input.read_type(), &value);
		}
		bool abi_repr::rreal320(decimal& value)
		{
			return input.read_decimal_or_integer(input.read_type(), &value);
		}
		bool abi_repr::rstr(string_repr& value)
		{
			string intermediate_value;
			bool result = input.read_string(input.read_type(), &intermediate_value);
			value = std::string_view(intermediate_value);
			return result;
		}
		string_repr abi_repr::data()
		{
			return string_repr(std::string_view(output.data));
		}

		void storage_repr::destroy(const vitex::scripting::type_info& type)
		{
			auto* vm = type.get_vm();
			if (vm != nullptr && value != nullptr)
				vm->release_object(value, type);
			memset(buffer, 0, sizeof(buffer));
			value = nullptr;
			hidden = true;
		}
		bool storage_repr::copy(const void* input_value, int input_type_id, const vitex::scripting::type_info& input_type)
		{
			auto* vm = virtual_machine::get();
			if (!vm)
				return false;

			if ((input_type_id & ~(uint32_t)type_id::mask_seqnbr_t) && !(input_type_id & (uint32_t)type_id::handle_t))
			{
				if (value != nullptr)
				{
					if (!input_value)
					{
						void* temp_value = vm->create_object(input_type);
						if (!temp_value)
							return false;
						
						bool copy = !!vm->assign_object(value, (void*)input_value, input_type);
						vm->release_object(temp_value, input_type);
						if (!copy)
							return false;
					}
					else if (!vm->assign_object(value, (void*)input_value, input_type))
						return false;
				}
				else
					value = input_value ? vm->create_object_copy((void*)input_value, input_type) : vm->create_object(input_type);
			}
			else if (!(input_type_id & (uint32_t)type_id::handle_t))
			{
				if (input_value != nullptr)
					memcpy(buffer, input_value, vm->get_size_of_primitive_type(input_type_id).or_else(0));
				else
					memset(buffer, 0, sizeof(buffer));
				value = buffer;
			}
			
			hidden = !value;
			return !hidden;
		}
		const void* storage_repr::address()
		{
			return hidden ? nullptr : value;
		}
		bool storage_repr::template_callback(const vitex::scripting::type_info& input_type, int input_type_id)
		{
			auto vm = input_type.get_vm();
			if (input_type_id == (uint32_t)type_id::void_t || input_type_id == (uint32_t)type_id::float_t || input_type_id == (uint32_t)type_id::double_t)
				return false;

			if ((input_type_id & ~(uint32_t)type_id::mask_seqnbr_t) && !(input_type_id & (uint32_t)type_id::handle_t))
			{
				size_t flags = input_type.flags();
				if ((flags & (size_t)object_behaviours::value) && !(flags & (size_t)object_behaviours::pod))
				{
					bool has_default_constructor = false, has_copy_constructor = false;
					for (uint32_t i = 0; i < input_type.get_behaviour_count(); i++)
					{
						behaviours behaviour;
						function func = input_type.get_behaviour_by_index(i, &behaviour);
						size_t args = func.get_args_count();
						if (behaviour == behaviours::construct && args == 1)
						{
							int sub_type_id = 0;
							if (func.get_arg(0, &sub_type_id) && vm->get_type_info_by_id(sub_type_id).get_type_info() == input_type.get_type_info())
								has_copy_constructor = true;
						}
						else if (behaviour == behaviours::construct && args == 0)
							has_default_constructor = true;
						if (has_default_constructor && has_copy_constructor)
							break;
					}

					if (!has_default_constructor || !has_copy_constructor)
					{
						if (has_default_constructor)
						{
							for (uint32_t i = 0; i < input_type.get_methods_count(); i++)
							{
								function func = input_type.get_method_by_index(i);
								if (func.get_args_count() == 1 && func.get_name() == "opAssign")
								{
									int sub_type_id = 0;
									if (func.get_arg(0, &sub_type_id) && vm->get_type_info_by_id(sub_type_id).get_type_info() == input_type.get_type_info())
										has_copy_constructor = true;
								}
								if (has_copy_constructor)
									break;
							}
						}

						if (!has_default_constructor || !has_copy_constructor)
						{
							vm->write_message("state_variable", 0, 0, log_category::err, "Type must have a default contructor and a copy contrustructor");
							return false;
						}
					}
				}
				else if (flags & (size_t)object_behaviours::ref)
				{
					bool has_default_constructor = false, has_copy_constructor = false;
					if (!vm->get_property(features::disallow_value_assign_for_ref_type))
					{
						for (uint32_t i = 0; i < input_type.get_factories_count(); i++)
						{
							function func = input_type.get_factory_by_index(i);
							size_t args = func.get_args_count();
							if (args == 1)
							{
								int sub_type_id = 0;
								if (func.get_arg(0, &sub_type_id) && vm->get_type_info_by_id(sub_type_id).get_type_info() == input_type.get_type_info())
									has_copy_constructor = true;
							}
							else if (args == 0)
								has_default_constructor = true;
							if (has_default_constructor && has_copy_constructor)
								break;
						}
					}

					if (!has_default_constructor || !has_copy_constructor)
					{
						vm->write_message("state_variable", 0, 0, log_category::err, "Type must have a default contructor and a copy contrustructor");
						return false;
					}
				}
				return true;
			}
			else if (!(input_type_id & (uint32_t)type_id::handle_t))
				return true;

			vm->write_message("state_variable", 0, 0, log_category::err, "Handle type cannot be used in state variable");
			return false;
		}

		container_repr::container_repr(asITypeInfo* new_type) : type(new_type), slot(0)
		{
			type.add_ref();
		}
		container_repr::~container_repr()
		{
			type.release();
			type = nullptr;
		}

		varying_repr::varying_repr(asITypeInfo* new_type) : container_repr(new_type), known(false)
		{
		}
		varying_repr::~varying_repr()
		{
			reset();
		}
		void varying_repr::reset()
		{
			container.destroy(type.get_sub_type(0));
			known = false;
		}
		void varying_repr::erase()
		{
			if (slot > 0)
				contract::uniform_erase(&slot, (int)type_id::uint8_t);
			container.hidden = known = true;
		}
		void varying_repr::store(const void* new_value)
		{
			if (!slot || !container.copy(new_value, type.get_sub_type_id(0), type.get_sub_type(0)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "varying store failed"));

			contract::uniform_store(&slot, (int)type_id::uint8_t, container.value, type.get_sub_type_id(0));
			known = true;
		}
		void varying_repr::store_if(bool condition, const void* new_value)
		{
			if (condition)
				store(new_value);
			else
				erase();
		}
		const void* varying_repr::load()
		{
			if (!try_load())
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), "varying load failed"));
			return container.address();
		}
		const void* varying_repr::try_load()
		{
			if (!known && slot > 0 && type.is_valid())
			{
				known = true;
				if (container.copy(nullptr, type.get_sub_type_id(0), type.get_sub_type(0)))
				{
					if (!contract::uniform_load(&slot, (int)type_id::uint8_t, container.value, type.get_sub_type_id(0), false))
						container.destroy(type.get_sub_type(0));
				}
			}
			return container.address();
		}
		bool varying_repr::empty()
		{
			return !try_load();
		}
		bool varying_repr::template_callback(asITypeInfo* t, bool& dont_garbage_collect)
		{
			auto type = vitex::scripting::type_info(t);
			if (!storage_repr::template_callback(type.get_sub_type(0), type.get_sub_type_id(0)))
				return false;

			dont_garbage_collect = true;
			return true;
		}

		mapping_repr::mapping_repr(asITypeInfo* new_type) : container_repr(new_type)
		{
		}
		mapping_repr::~mapping_repr()
		{
			reset();
		}
		void mapping_repr::reset()
		{
			auto key_type = type.get_sub_type(0);
			auto value_type = type.get_sub_type(1);
			for (auto& [index, key_value] : map)
			{
				auto& [key, value] = key_value;
				key.destroy(key_type);
				value.destroy(value_type);
			}
			map.clear();
		}
		void mapping_repr::erase(const void* new_key)
		{
			auto& [key, value] = map[to_key(new_key)];
			if (!slot || !key.copy(new_key, type.get_sub_type_id(0), type.get_sub_type(0)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "mapping erase failed"));

			contract::uniform_store_slot(slot, key.value, type.get_sub_type_id(0), nullptr, (int)type_id::void_t);
			key.hidden = true;
			value.hidden = true;
		}
		void mapping_repr::store(const void* new_key, const void* new_value)
		{
			auto& [key, value] = map[to_key(new_key)];
			if (!slot || !key.copy(new_key, type.get_sub_type_id(0), type.get_sub_type(0)) || !value.copy(new_value, type.get_sub_type_id(1), type.get_sub_type(1)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "mapping store failed"));
			
			contract::uniform_store_slot(slot, key.value, type.get_sub_type_id(0), value.value, type.get_sub_type_id(1));
		}
		void mapping_repr::store_if(bool condition, const void* new_key, const void* new_value)
		{
			if (condition)
				store(new_key, new_value);
			else
				erase(new_key);
		}
		const void* mapping_repr::load(const void* new_key)
		{
			const void* new_value = try_load(new_key);
			if (!new_value)
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), "mapping load failed"));
			return new_value;
		}
		const void* mapping_repr::try_load(const void* new_key)
		{
			auto* vm = type.get_vm();
			if (!slot || !vm)
				return nullptr;

			auto index = to_key(new_key);
			auto it = map.find(index);
			if (it != map.end())
				return it->second.second.address();

			auto& [key, value] = map[index];
			if (!key.copy(new_key, type.get_sub_type_id(0), type.get_sub_type(0)) || !value.copy(nullptr, type.get_sub_type_id(1), type.get_sub_type(1)))
			{
			error:
				key.hidden = true;
				value.hidden = true;
				return nullptr;
			}
			else if (!contract::uniform_load_slot(slot, key.value, type.get_sub_type_id(0), value.value, type.get_sub_type_id(1), false))
				goto error;

			return value.address();
		}
		bool mapping_repr::has(const void* new_key)
		{
			return !!try_load(new_key);
		}
		string mapping_repr::to_key(const void* new_key)
		{
			format::wo_stream index;
			marshall::store(&index, new_key, type.get_sub_type_id(0));
			return string(std::move(index.data));
		}
		bool mapping_repr::template_callback(asITypeInfo* t, bool& dont_garbage_collect)
		{
			auto type = vitex::scripting::type_info(t);
			if (!storage_repr::template_callback(type.get_sub_type(0), type.get_sub_type_id(0)))
				return false;

			if (!storage_repr::template_callback(type.get_sub_type(1), type.get_sub_type_id(1)))
				return false;

			dont_garbage_collect = true;
			return true;
		}

		bool ranging_slice_repr::next(void* object_value, int object_type_id)
		{
			return next_index_ranked(object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
		}
		bool ranging_slice_repr::next_index(void* object_value, int object_type_id, void* other_index_value, int other_index_type_id)
		{
			return next_index_ranked(object_value, object_type_id, other_index_value, other_index_type_id, nullptr);
		}
		bool ranging_slice_repr::next_index_ranked(void* object_value, int object_type_id, void* other_index_value, int other_index_type_id, uint256_t* filter_value)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			bool is_column = mode == cquery::column || mode == cquery::column_filter;
			auto& cache = ((program*)p)->cache.index[is_column ? 0 : 1][subject.data];
		retry:
			auto it = cache.find((size_t)offset);
			if (it == cache.end())
			{
				expects_lr<vector<uptr<states::account_multiform>>> results = layer_exception();
				switch (mode)
				{
					case tangent::cell::cquery::column:
						results = p->context->get_account_multiforms_by_column(p->callable().data, subject.data, (size_t)offset, count);
						break;
					case tangent::cell::cquery::column_filter:
						results = p->context->get_account_multiforms_by_column_filter(p->callable().data, subject.data, comparator, value, order, (size_t)offset, count);
						break;
					case tangent::cell::cquery::row:
						results = p->context->get_account_multiforms_by_row(p->callable().data, subject.data, (size_t)offset, count);
						break;
					case tangent::cell::cquery::row_filter:
						results = p->context->get_account_multiforms_by_row_filter(p->callable().data, subject.data, comparator, value, order, (size_t)offset, count);
						break;
					default:
						break;
				}
				if (!results || results->empty())
					return false;

				size_t index = (size_t)offset;
				for (auto& result : *results)
					cache[index++] = std::move(result);
				goto retry;
			}

			if (object_value != nullptr && object_type_id != (int)type_id::void_t)
			{
				auto stream = format::ro_stream(it->second->data);
				auto status = marshall::load(stream, object_value, object_type_id);
				if (!status)
					return false;
			}

			if (other_index_value != nullptr && other_index_type_id != (int)type_id::void_t)
			{
				auto index_slot = uint8_t(0);
				auto stream = format::ro_stream(is_column ? it->second->row : it->second->column);
				if (slot > 0 && (!stream.read_integer(stream.read_type(), &index_slot) || index_slot != slot))
					return false;

				auto status = marshall::load(stream, other_index_value, other_index_type_id);
				if (!status)
					return false;
			}

			if (filter_value != nullptr)
				*filter_value = it->second->filter;

			++offset;
			return true;
		}
		ranging_slice_repr& ranging_slice_repr::with_offset(uint32_t new_offset)
		{
			offset = new_offset;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::with_count(uint32_t new_count)
		{
			count = new_count > 0 ? new_count : SCRIPT_QUERY_PREFETCH;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_gt(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::greater;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_gte(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::greater_equal;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_eq(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::equal;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_neq(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::not_equal;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_lt(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::less;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::where_lte(const uint256_t& new_value)
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			comparator = ledger::filter_comparator::less_equal;
			value = new_value;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::order_asc()
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			order = ledger::filter_order::ascending;
			return *this;
		}
		ranging_slice_repr& ranging_slice_repr::order_desc()
		{
			mode = (mode == cquery::column || mode == cquery::column_filter ? cquery::column_filter : cquery::row_filter);
			order = ledger::filter_order::descending;
			return *this;
		}
		ranging_slice_repr ranging_slice_repr::from_column(const void* index_value, int index_type_id)
		{
			return from(cquery::column, 0, index_value, index_type_id);
		}
		ranging_slice_repr ranging_slice_repr::from_row(const void* index_value, int index_type_id)
		{
			return from(cquery::row, 0, index_value, index_type_id);
		}
		ranging_slice_repr ranging_slice_repr::from(cquery new_mode, uint8_t new_slot, const void* index_value, int index_type_id)
		{
			ranging_slice_repr result;
			result.mode = new_mode;
			result.slot = new_slot;
			result.value = 0;
			result.offset = 0;
			result.with_count(0);
			if (result.slot > 0)
				result.subject.write_integer(result.slot);

			auto status = marshall::store(&result.subject, index_value, index_type_id);
			if (!status)
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
			return result;
		}

		ranging_repr::ranging_repr(asITypeInfo * new_type) : container_repr(new_type)
		{
		}
		ranging_repr::~ranging_repr()
		{
			reset();
		}
		void ranging_repr::reset()
		{
			auto column_type = type.get_sub_type(0);
			auto row_type = type.get_sub_type(1);
			auto value_type = type.get_sub_type(2);
			for (auto& [index, item] : map)
			{
				item.column.destroy(column_type);
				item.row.destroy(row_type);
				item.value.destroy(value_type);
			}
			map.clear();
		}
		const void* ranging_repr::from(ranging_slice_repr& slice)
		{
			range_item item;
			auto column_type = type.get_sub_type(0);
			auto row_type = type.get_sub_type(1);
			auto value_type = type.get_sub_type(2);
			if (item.column.copy(nullptr, type.get_sub_type_id(0), column_type) && item.row.copy(nullptr, type.get_sub_type_id(1), row_type) && item.value.copy(nullptr, type.get_sub_type_id(2), value_type))
			{
				auto index_slot = uint8_t(0);
				auto stream = slice.subject.ro();
				if (stream.read_integer(stream.read_type(), &index_slot) && index_slot == slot)
				{
					bool is_column = slice.mode == cquery::column || slice.mode == cquery::column_filter;
					auto status = marshall::load(stream, is_column ? item.column.value : item.row.value, type.get_sub_type_id(is_column ? 0 : 1));
					if (status && slice.next_index(item.value.value, type.get_sub_type_id(2), is_column ? item.row.value : item.column.value, type.get_sub_type_id(is_column ? 1 : 0)))
					{
						auto index = to_key(item.column.value, item.row.value);
						auto it = map.find(index);
						if (it != map.end())
						{
							if (it->second.column.copy(item.column.value, type.get_sub_type_id(0), column_type) && item.row.copy(item.row.value, type.get_sub_type_id(1), row_type) && item.value.copy(item.value.value, type.get_sub_type_id(2), value_type))
								return it->second.value.address();
						}
						else
						{
							map[index] = item;
							return item.value.address();
						}
					}
				}
			}
			item.column.destroy(column_type);
			item.row.destroy(row_type);
			item.value.destroy(value_type);
			contract::throw_ptr(exception_repr(exception_repr::category::storage(), "range state load failed"));
			return nullptr;
		}
		ranging_slice_repr ranging_repr::from_column(const void* new_column)
		{
			return ranging_slice_repr::from(cquery::column, slot, new_column, type.get_sub_type_id(0));
		}
		ranging_slice_repr ranging_repr::from_row(const void* new_row)
		{
			return ranging_slice_repr::from(cquery::row, slot, new_row, type.get_sub_type_id(1));
		}
		void ranging_repr::erase(const void* new_column, const void* new_row)
		{
			auto& item = map[to_key(new_column, new_row)];
			if (!slot || !item.column.copy(new_column, type.get_sub_type_id(0), type.get_sub_type(0)) || !item.row.copy(new_row, type.get_sub_type_id(1), type.get_sub_type(1)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "ranging erase failed"));

			contract::multiform_store_slot(slot, item.column.value, type.get_sub_type_id(0), item.row.value, type.get_sub_type_id(1), nullptr, (int)type_id::void_t, 0);
			item.column.hidden = true;
			item.row.hidden = true;
			item.value.hidden = true;
		}
		void ranging_repr::store(const void* new_column, const void* new_row, void* new_value)
		{
			store_positioned(new_column, new_row, new_value, 0);
		}
		void ranging_repr::store_if(bool condition, const void* new_column, const void* new_row, void* new_value)
		{
			if (condition)
				store(new_column, new_row, new_value);
			else
				erase(new_column, new_row);
		}
		void ranging_repr::store_positioned(const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position)
		{
			auto& item = map[to_key(new_column, new_row)];
			if (!slot || !item.column.copy(new_column, type.get_sub_type_id(0), type.get_sub_type(0)) || !item.row.copy(new_row, type.get_sub_type_id(1), type.get_sub_type(1)) || !item.value.copy(new_value, type.get_sub_type_id(2), type.get_sub_type(2)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "ranging store failed"));

			contract::multiform_store_slot(slot, item.column.value, type.get_sub_type_id(0), item.row.value, type.get_sub_type_id(1), item.value.value, type.get_sub_type_id(2), new_position);
		}
		void ranging_repr::store_positioned_if(bool condition, const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position)
		{
			if (condition)
				store_positioned(new_column, new_row, new_value, new_position);
			else
				erase(new_column, new_row);
		}
		const void* ranging_repr::load(const void* new_column, const void* new_row)
		{
			const void* new_value = try_load(new_column, new_row);
			if (!new_value)
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), "ranging load failed"));
			return new_value;
		}
		const void* ranging_repr::try_load(const void* new_column, const void* new_row)
		{
			auto* vm = type.get_vm();
			if (!slot || !vm)
				return nullptr;

			auto index = to_key(new_column, new_row);
			auto it = map.find(index);
			if (it != map.end())
				return it->second.value.address();

			auto& item = map[index];
			if (!item.column.copy(new_column, type.get_sub_type_id(0), type.get_sub_type(0)) || !item.row.copy(new_row, type.get_sub_type_id(1), type.get_sub_type(1)) || !item.value.copy(nullptr, type.get_sub_type_id(2), type.get_sub_type(2)))
			{
			error:
				item.column.hidden = true;
				item.row.hidden = true;
				item.value.hidden = true;
				return nullptr;
			}
			else if (!contract::multiform_load_slot(slot, item.column.value, type.get_sub_type_id(0), item.row.value, type.get_sub_type_id(1), item.value.value, type.get_sub_type_id(2), nullptr, false))
				goto error;

			return item.value.address();
		}
		bool ranging_repr::has(const void* new_column, const void* new_row)
		{
			return !!try_load(new_column, new_row);
		}
		bool ranging_repr::has_column(const void* new_column)
		{
			return from_column(new_column).with_count(1).next(nullptr, (int)type_id::void_t);
		}
		bool ranging_repr::has_row(const void* new_row)
		{
			return from_row(new_row).with_count(1).next(nullptr, (int)type_id::void_t);
		}
		string ranging_repr::to_key(const void* new_column, const void* new_row)
		{
			format::wo_stream index;
			marshall::store(&index, new_column, type.get_sub_type_id(0));
			marshall::store(&index, new_row, type.get_sub_type_id(1));
			return string(std::move(index.data));
		}
		bool ranging_repr::template_callback(asITypeInfo* t, bool& dont_garbage_collect)
		{
			auto type = vitex::scripting::type_info(t);
			if (!storage_repr::template_callback(type.get_sub_type(0), type.get_sub_type_id(0)))
				return false;

			if (!storage_repr::template_callback(type.get_sub_type(1), type.get_sub_type_id(1)))
				return false;

			if (!storage_repr::template_callback(type.get_sub_type(2), type.get_sub_type_id(2)))
				return false;

			dont_garbage_collect = true;
			return true;
		}

		void contract::uniform_store(const void* index_value, int index_type_id, const void* object_value, int object_type_id)
		{
			uniform_store_slot(0, index_value, index_type_id, object_value, object_type_id);
		}
		void contract::uniform_store_slot(uint8_t slot, const void* index_value, int index_type_id, const void* object_value, int object_type_id)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream index;
			if (slot > 0)
				index.write_integer(slot);

			auto status = marshall::store(&index, index_value, index_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			format::wo_stream stream;
			status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			if (!object_value || object_type_id == (int)type_id::void_t)
			{
				auto requires_erase = p->context->get_account_uniform(p->callable().data, index.data);
				if (!requires_erase)
					return;
			}

			auto data = p->context->apply_account_uniform(p->callable().data, index.data, stream.data);
			if (!data)
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));
		}
		bool contract::uniform_load(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error)
		{
			return uniform_load_slot(0, index_value, index_type_id, object_value, object_type_id, throw_on_error);
		}
		bool contract::uniform_load_slot(uint8_t slot, const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			format::wo_stream index;
			if (slot > 0)
				index.write_integer(slot);

			auto status = marshall::store(&index, index_value, index_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			auto data = p->context->get_account_uniform(p->callable().data, index.data);
			if (!data)
			{
				if (throw_on_error)
					contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));
				return false;
			}

			format::ro_stream stream = format::ro_stream(data->data);
			status = marshall::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(status.error().message())));
				return false;
			}

			return true;
		}
		void contract::uniform_set(const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			uniform_store(index_value, index_type_id, object_value, object_type_id);
		}
		void contract::uniform_erase(const void* index_value, int index_type_id)
		{
			uniform_store(index_value, index_type_id, nullptr, (int)type_id::void_t);
		}
		void contract::uniform_set_if(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool condition)
		{
			if (condition)
				uniform_set(index_value, index_type_id, object_value, object_type_id);
			else
				uniform_erase(index_value, index_type_id);
		}
		bool contract::uniform_has(const void* index_value, int index_type_id)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			format::wo_stream index;
			auto status = marshall::store(&index, index_value, index_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			auto data = p->context->get_account_uniform(p->callable().data, index.data);
			return data && !data->data.empty();
		}
		bool contract::uniform_into(const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			return uniform_load(index_value, index_type_id, object_value, object_type_id, false);
		}
		void contract::uniform_get(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			void* index_value = inout.get_arg_address(0);
			int index_type_id = inout.get_arg_type_id(0);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			uniform_load(index_value, index_type_id, object_value, object_type_id, true);
		}
		void contract::multiform_store(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value)
		{
			multiform_store_slot(0, column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
		}
		void contract::multiform_store_slot(uint8_t slot, const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream column;
			if (slot > 0)
				column.write_integer(slot);

			auto status = marshall::store(&column, column_value, column_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			format::wo_stream row;
			if (slot > 0)
				row.write_integer(slot);

			status = marshall::store(&row, row_value, row_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			format::wo_stream stream;
			status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			if (!object_value || object_type_id == (int)type_id::void_t)
			{
				auto requires_erase = p->context->get_account_multiform(p->callable().data, column.data, row.data);
				if (!requires_erase)
					return;
			}

			auto data = p->context->apply_account_multiform(p->callable().data, column.data, row.data, stream.data, filter_value);
			if (!data)
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));

			auto it = p->cache.index[(size_t)cquery::column].find(column.data);
			if (it != p->cache.index[(size_t)cquery::column].end())
				it->second.clear();

			it = p->cache.index[(size_t)cquery::row].find(row.data);
			if (it != p->cache.index[(size_t)cquery::row].end())
				it->second.clear();
		}
		bool contract::multiform_load(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error)
		{
			return multiform_load_slot(0, column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value, throw_on_error);
		}
		bool contract::multiform_load_slot(uint8_t slot, const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			format::wo_stream column;
			if (slot > 0)
				column.write_integer(slot);

			auto status = marshall::store(&column, column_value, column_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			format::wo_stream row;
			if (slot > 0)
				row.write_integer(slot);

			status = marshall::store(&row, row_value, row_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			auto data = p->context->get_account_multiform(p->callable().data, column.data, row.data);
			if (!data)
			{
				if (throw_on_error)
					contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));
				return false;
			}

			format::ro_stream stream = format::ro_stream(data->data);
			status = marshall::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(status.error().message())));
				return false;
			}

			if (filter_value != nullptr)
				*filter_value = data->filter;

			return true;
		}
		void contract::multiform_set_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value)
		{
			multiform_store(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
		}
		void contract::multiform_set(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			multiform_set_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0);
		}
		void contract::multiform_erase(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
		{
			multiform_store(column_value, column_type_id, row_value, row_type_id, nullptr, (int)type_id::void_t, 0);
		}
		void contract::multiform_set_if_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value, bool condition)
		{
			if (condition)
				multiform_set_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
			else
				multiform_erase(column_value, column_type_id, row_value, row_type_id);
		}
		void contract::multiform_set_if(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool condition)
		{
			return multiform_set_if_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0, condition);
		}
		bool contract::multiform_into_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value)
		{
			return multiform_load(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value, false);
		}
		bool contract::multiform_into(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			return multiform_into_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr);
		}
		bool contract::multiform_has(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			format::wo_stream column;
			auto status = marshall::store(&column, column_value, column_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			format::wo_stream row;
			status = marshall::store(&row, row_value, row_type_id);
			if (!status)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			auto data = p->context->get_account_multiform(p->callable().data, column.data, row.data);
			return data && !data->data.empty();
		}
		void contract::multiform_get(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			void* column_value = inout.get_arg_address(0);
			int column_type_id = inout.get_arg_type_id(0);
			void* row_value = inout.get_arg_address(1);
			int row_type_id = inout.get_arg_type_id(1);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			multiform_load(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr, true);
		}
		void contract::log_emit(const void* object_value, int object_type_id)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream stream;
			auto status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto reader = stream.ro();
			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s load failed", (int)name.size(), name.data())));

			auto data = p->context->emit_event(algorithm::hashing::hash32d(name), std::move(returns), true);
			if (!data)
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));

			p->dispatch_event(object_type_id, object_value, object_type_id);
		}
		void contract::log_event(const void* event_value, int event_type_id, const void* object_value, int object_type_id)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream stream;
			auto status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto reader = stream.ro();
			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s load failed", (int)name.size(), name.data())));

			auto data = p->context->emit_event(algorithm::hashing::hash32d(name), std::move(returns), true);
			if (!data)
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));

			p->dispatch_event(event_type_id, object_value, object_type_id);
		}
		bool contract::log_into(int32_t event_index, void* object_value, int object_type_id)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->context->receipt.reverse_find_event(id, (size_t)(-event_index)) : p->context->receipt.find_event(id, (size_t)event_index);
			if (!event)
				return false;

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(*event, &writer))
				return false;

			format::ro_stream reader = writer.ro();
			return !!marshall::load(reader, object_value, object_type_id);
		}
		void contract::log_event_into(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return;

			generic_context inout = generic_context(generic);
			int event_type_id = inout.get_arg_type_id(0);
			int32_t event_index = inout.get_arg_dword(1);
			void* object_value = inout.get_arg_address(2);
			int object_type_id = inout.get_arg_type_id(2);
			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->context->receipt.reverse_find_event(id, (size_t)(-event_index)) : p->context->receipt.find_event(id, (size_t)event_index);
			if (!event)
			{
				inout.set_return_byte(false);
				return;
			}

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(*event, &writer))
			{
				inout.set_return_byte(false);
				return;
			}

			format::ro_stream reader = writer.ro();
			inout.set_return_byte(!!marshall::load(reader, object_value, object_type_id));
		}
		void contract::log_get(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return;

			generic_context inout = generic_context(generic);
			int32_t event_index = inout.get_arg_dword(0);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->context->receipt.reverse_find_event(id, (size_t)(-event_index - 1)) : p->context->receipt.find_event(id, (size_t)event_index);
			if (!event)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] not found", (int)name.size(), name.data(), event_index)));

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(*event, &writer))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] store failed", (int)name.size(), name.data(), event_index)));

			format::ro_stream reader = writer.ro();
			auto status = marshall::load(reader, object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] load failed", (int)name.size(), name.data(), event_index)));
		}
		void contract::log_get_event(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return;

			generic_context inout = generic_context(generic);
			int event_type_id = inout.get_arg_type_id(0);
			int32_t event_index = inout.get_arg_dword(1);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->context->receipt.reverse_find_event(id, (size_t)(-event_index - 1)) : p->context->receipt.find_event(id, (size_t)event_index);
			if (!event)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] not found", (int)name.size(), name.data(), event_index)));

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(*event, &writer))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] store failed", (int)name.size(), name.data(), event_index)));

			format::ro_stream reader = writer.ro();
			auto status = marshall::load(reader, object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] load failed", (int)name.size(), name.data(), event_index)));
		}
		address_repr contract::block_proposer()
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return address_repr();

			size_t index = (size_t)p->context->block->priority;
			return index < p->context->environment->producers.size() ? address_repr(algorithm::pubkeyhash_t(p->context->environment->producers[index].owner)) : address_repr();
		}
		uint256_t contract::block_parent_hash()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->parent_hash : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_use()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_left()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->gas_limit - p->context->block->gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_limit()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->gas_limit : uint256_t((uint8_t)0);
		}
		uint128_t contract::block_difficulty()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? algorithm::wesolowski::kdifficulty(p->context->block->difficulty) : uint128_t((uint8_t)0);
		}
		uint64_t contract::block_time()
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return 0;

			uint64_t milliseconds = p->context->block->generation_time - p->context->block->generation_time % protocol::now().policy.consensus_proof_time;
			return milliseconds / 1000;
		}
		uint64_t contract::block_time_between(uint64_t block_number_a, uint64_t block_number_b)
		{
			uint64_t left = std::min(block_number_a, block_number_b);
			uint64_t right = std::max(block_number_a, block_number_b);
			return (right - left) * protocol::now().policy.consensus_proof_time / 1000;
		}
		uint64_t contract::block_priority()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->priority : 0;
		}
		uint64_t contract::block_number()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->block->number : 0;
		}
		decimal contract::tx_value()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->payable() : decimal::nan();
		}
		bool contract::tx_paid()
		{
			return tx_value().is_positive();
		}
		address_repr contract::tx_from()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? address_repr(p->context->receipt.from) : address_repr();
		}
		address_repr contract::tx_to()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? address_repr(p->callable()) : address_repr();
		}
		string_repr contract::tx_blockchain()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::blockchain_of(p->context->transaction->asset)) : string_repr();
		}
		string_repr contract::tx_token()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::token_of(p->context->transaction->asset)) : string_repr();
		}
		string_repr contract::tx_contract()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::checksum_of(p->context->transaction->asset)) : string_repr();
		}
		decimal contract::tx_gas_price()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->transaction->gas_price : decimal::zero();
		}
		uint256_t contract::tx_gas_use()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->receipt.relative_gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_gas_left()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->get_gas_left() : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_gas_limit()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->transaction->gas_limit : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_asset()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->context->transaction->asset : uint256_t((uint8_t)0);
		}
		uint256_t contract::coin_native()
		{
			return algorithm::asset::native();
		}
		uint256_t contract::coin_from_decimal(const decimal& value)
		{
			if (value.is_nan())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), string_repr(value.to_string() + " as uint256 - not a number")));
				return 0;
			}

			if (value.is_negative())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), string_repr(value.to_string() + " as uint256 - negative number")));
				return 0;
			}

			if (value.integer_size() > protocol::now().message.integer_precision || value.decimal_size() > protocol::now().message.decimal_precision)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), string_repr(value.to_string() + " as uint256 - fixed point overflow")));
				return 0;
			}

			auto copy = value;
			copy *= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.decimal_precision);

			auto result = uint256_t::max();
			if (copy < result.to_decimal())
				result = uint256_t(copy.truncate(0).to_string(), 10);
			return result;
		}
		decimal contract::coin_to_decimal(const uint256_t& value)
		{
			auto precision = protocol::now().message.decimal_precision;
			auto result = value.to_decimal().truncate(precision);
			result /= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.decimal_precision);
			return result;
		}
		uint256_t contract::coin_id_of(const string_repr& blockchain, const string_repr& token, const string_repr& contract_address)
		{
			return algorithm::asset::id_of(blockchain.view(), token.view(), contract_address.view());
		}
		string_repr contract::coin_blockchain_of(const uint256_t& value)
		{
			return string_repr(algorithm::asset::blockchain_of(value));
		}
		string_repr contract::coin_token_of(const uint256_t& value)
		{
			return string_repr(algorithm::asset::token_of(value));
		}
		string_repr contract::coin_checksum_of(const uint256_t& value)
		{
			return string_repr(algorithm::asset::checksum_of(value));
		}
		string_repr contract::coin_name_of(const uint256_t& value)
		{
			return string_repr(algorithm::asset::name_of(value));
		}
		string_repr contract::alg_encode_bytes256(const uint256_t& value)
		{
			uint8_t data[32];
			value.encode(data);
			return string_repr(std::string_view((char*)data, sizeof(data)));
		}
		uint256_t contract::alg_decode_bytes256(const string_repr& value)
		{
			uint8_t data[32];
			memcpy(data, value.data(), std::min(sizeof(data), (size_t)value.size()));

			uint256_t buffer;
			buffer.decode(data);
			return buffer;
		}
		address_repr contract::alg_erecover160(const uint256_t& hash, const string_repr& signature)
		{
			if (signature.size() != sizeof(algorithm::hashsig_t) || !program::request_gas_mop(10))
				return address_repr();

			algorithm::pubkeyhash_t public_key_hash;
			if (!algorithm::signing::recover_hash(hash, public_key_hash, (uint8_t*)signature.data()) || public_key_hash.empty())
				return address_repr();

			return address_repr(public_key_hash);
		}
		string_repr contract::alg_erecover264(const uint256_t& hash, const string_repr& signature)
		{
			if (signature.size() != sizeof(algorithm::hashsig_t) || !program::request_gas_mop(10))
				return string_repr();

			algorithm::pubkey_t public_key;
			if (!algorithm::signing::recover(hash, public_key, (uint8_t*)signature.data()) || public_key.empty())
				return string_repr();

			return string_repr(public_key.view());
		}
		string_repr contract::alg_crc32(const string_repr& data)
		{
			if (!program::request_gas_mop(1))
				return string_repr();

			uint8_t buffer[32];
			uint256_t value = algorithm::hashing::hash32d(data.view());
			value.encode(buffer);
			return string_repr(std::string_view((char*)buffer + (sizeof(uint256_t) - sizeof(uint32_t)), sizeof(uint32_t)));
		}
		string_repr contract::alg_ripemd160(const string_repr& data)
		{
			if (!program::request_gas_mop(1))
				return string_repr();

			return string_repr(algorithm::hashing::hash160((uint8_t*)data.data(), data.size()));
		}
		uint256_t contract::alg_blake2b256(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return uint256_t((uint8_t)0);

			return algorithm::hashing::hash256i((uint8_t*)data.data(), data.size());
		}
		string_repr contract::alg_blake2b256s(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return string_repr();

			return string_repr(algorithm::hashing::hash256((uint8_t*)data.data(), data.size()));
		}
		uint256_t contract::alg_keccak256(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return uint256_t((uint8_t)0);

			uint256_t value;
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
			value.decode(buffer);
			return value;
		}
		string_repr contract::alg_keccak256s(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return string_repr();

			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
			return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
		}
		string_repr contract::alg_keccak512(const string_repr& data)
		{
			if (!program::request_gas_mop(3))
				return string_repr();

			uint8_t buffer[SHA3_512_DIGEST_LENGTH];
			keccak_512((uint8_t*)data.data(), data.size(), buffer);
			return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
		}
		uint256_t contract::alg_sha256(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return uint256_t((uint8_t)0);

			uint256_t value;
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			keccak_256((uint8_t*)data.data(), data.size(), buffer);
			value.decode(buffer);
			return value;
		}
		string_repr contract::alg_sha256s(const string_repr& data)
		{
			if (!program::request_gas_mop(2))
				return string_repr();

			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			keccak_256((uint8_t*)data.data(), data.size(), buffer);
			return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
		}
		string_repr contract::alg_sha512(const string_repr& data)
		{
			if (!program::request_gas_mop(4))
				return string_repr();

			return string_repr(algorithm::hashing::hash512((uint8_t*)data.data(), data.size()));
		}
		uint256_t contract::alg_prandom()
		{
			if (!program::request_gas_mop(6))
				return uint256_t((uint8_t)0);

			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return uint256_t((uint8_t)0);

			if (!p->cache.distribution)
			{
				auto candidate = p->context->calculate_random(p->context->get_gas_use());
				if (!candidate)
				{
					contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(candidate.error().message())));
					return uint256_t((uint8_t)0);
				}
				p->cache.distribution = std::move(*candidate);
			}

			return p->cache.distribution->derive();
		}
		void contract::math_min_value(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte((uint8_t)std::numeric_limits<int8_t>::min());
					break;
				case (int)type_id::bool_t:
				case (int)type_id::uint8_t:
					inout.set_return_byte(std::numeric_limits<uint8_t>::min());
					break;
				case (int)type_id::int16_t:
					inout.set_return_word((uint16_t)std::numeric_limits<int16_t>::min());
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(std::numeric_limits<uint16_t>::min());
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword((uint32_t)std::numeric_limits<int32_t>::min());
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(std::numeric_limits<uint32_t>::min());
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword((uint64_t)std::numeric_limits<int64_t>::min());
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(std::numeric_limits<uint64_t>::min());
					break;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
				default:
				{
					auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (name == SCRIPT_TYPE_UINT128)
					{
						new (inout.get_address_of_return_location()) uint128_t(uint128_t::min());
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						new (inout.get_address_of_return_location()) uint256_t(uint256_t::min());
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						size_t decimal_size = protocol::now().message.decimal_precision;
						size_t integer_size = protocol::now().message.integer_precision;
						string result;
						result.reserve(integer_size + decimal_size + 2);
						result.append(1, '-');
						if (integer_size > 0)
							result.append(integer_size, '9');
						else
							result.append(1, '0');
						if (decimal_size > 0)
							result.append(1, '.').append(decimal_size, '9');

						new (inout.get_address_of_return_location()) decimal(result);
						break;
					}
					else if (type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)std::numeric_limits<int32_t>::min());
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_max_value(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte((uint8_t)std::numeric_limits<int8_t>::max());
					break;
				case (int)type_id::bool_t:
				case (int)type_id::uint8_t:
					inout.set_return_byte(std::numeric_limits<uint8_t>::max());
					break;
				case (int)type_id::int16_t:
					inout.set_return_word((uint16_t)std::numeric_limits<int16_t>::max());
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(std::numeric_limits<uint16_t>::max());
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword((uint32_t)std::numeric_limits<int32_t>::max());
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(std::numeric_limits<uint32_t>::max());
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword((uint64_t)std::numeric_limits<int64_t>::max());
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(std::numeric_limits<uint64_t>::max());
					break;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
				default:
				{
					auto type = factory::get()->get_vm()->get_type_info_by_id(type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (name == SCRIPT_TYPE_UINT128)
					{
						new (inout.get_address_of_return_location()) uint128_t(uint128_t::max());
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						new (inout.get_address_of_return_location()) uint256_t(uint256_t::max());
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						size_t decimal_size = protocol::now().message.decimal_precision;
						size_t integer_size = protocol::now().message.integer_precision;
						string result;
						result.reserve(integer_size + decimal_size + 1);
						if (integer_size > 0)
							result.append(integer_size, '9');
						else
							result.append(1, '0');
						if (decimal_size > 0)
							result.append(1, '.').append(decimal_size, '9');

						new (inout.get_address_of_return_location()) decimal(result);
						break;
					}
					else if (type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)std::numeric_limits<int32_t>::max());
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_min(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value left = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value right = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				auto& lowest = mpf_cmp(left.target, right.target) < 0 ? left : right;
				if (!lowest.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value left = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpz_value right = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				auto& lowest = mpz_cmp(left.target, right.target) < 0 ? left : right;
				if (!lowest.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::math_max(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value left = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value right = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				auto& highest = mpf_cmp(left.target, right.target) > 0 ? left : right;
				if (!highest.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value left = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpz_value right = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				auto& highest = mpz_cmp(left.target, right.target) > 0 ? left : right;
				if (!highest.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::math_clamp(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value left = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				mpf_value right = mpf_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
				auto& clamped = mpf_cmp(value.target, left.target) < 0 ? left : (mpf_cmp(value.target, right.target) > 0 ? right : value);
				if (!clamped.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpz_value left = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				mpz_value right = mpz_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
				auto& clamped = mpz_cmp(value.target, left.target) < 0 ? left : (mpz_cmp(value.target, right.target) > 0 ? right : value);
				if (!clamped.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::math_lerp(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value left = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value right = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				mpf_value time = mpf_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
				mpf_value result = left;
				mpf_set_ui(result.target, 1);
				mpf_sub(result.target, result.target, time.target);
				mpf_mul(result.target, result.target, left.target);
				mpf_mul(time.target, time.target, right.target);
				mpf_add(result.target, result.target, time.target);
				if (!result.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value left = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpz_value right = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				mpz_value time = mpz_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
				mpz_value result = left;
				mpz_set_ui(result.target, 1);
				mpz_sub(result.target, result.target, time.target);
				mpz_mul(result.target, result.target, left.target);
				mpz_mod(result.target, result.target, result.field);
				mpz_mul(time.target, time.target, right.target);
				mpz_mod(time.target, time.target, time.field);
				mpz_add(result.target, result.target, time.target);
				if (!result.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::math_pow(asIScriptGeneric* generic)
		{
			if (!program::request_gas_mop(0))
				return;

			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value count = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				auto exponent = mpf_get_ui(count.target);
				if (exponent > 0)
				{
					auto bits_required = uint128_t(value.bits()) * uint128_t(exponent);
					auto bits_limit = uint128_t(mpf_get_prec(value.target));
					if (bits_required > bits_limit)
						return contract::throw_ptr(exception_repr(exception_repr::category::execution(), stringify::text("fixed point overflow (bits_required: %s, bits_limit: %s)", bits_required.to_string().c_str(), bits_limit.to_string().c_str())));
				}

				mpf_value result = value;
				mpf_pow_ui(result.target, value.target, exponent);
				if (!result.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpz_value count = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
				mpz_value result = value;
				mpz_powm(result.target, value.target, count.target, value.field);
				if (!result.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::math_sqrt(asIScriptGeneric* generic)
		{
			if (!program::request_gas_mop(0))
				return;

			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			if (mpf_value::requires_fixed_point(type_id))
			{
				mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_sqrt(value.target, value.target);
				if (!value.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be fixed point"));
			}
			else
			{
				mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
				mpf_value pf_value;
				mpz_value_to_mpf_value(value, pf_value);
				mpf_sqrt(pf_value.target, pf_value.target);
				mpf_value_to_mpz_value(pf_value, value);
				if (!value.into(inout))
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be integer"));
			}
		}
		void contract::require(bool condition, const string_repr& message)
		{
			if (!condition)
				contract::throw_ptr(exception_repr(exception_repr::category::requirement(), message.empty() ? std::string_view("requirement not met") : message));
		}
		void contract::throw_ptr_at(immediate_context* context, const exception_repr& data)
		{
			if (context != nullptr)
				context->set_exception(data.to_exception_string(), false);
		}
		void contract::throw_ptr(const exception_repr& data)
		{
			throw_ptr_at(immediate_context::get(), data);
		}
		void contract::rethrow_at(immediate_context* context)
		{
			if (context != nullptr)
				context->set_exception(context->get_exception_string(), false);
		}
		void contract::rethrow()
		{
			rethrow_at(immediate_context::get());
		}
		bool contract::has_exception_at(immediate_context* context)
		{
			return context ? !context->get_exception_string().empty() : false;
		}
		bool contract::has_exception()
		{
			return has_exception_at(immediate_context::get());
		}
		exception_repr contract::get_exception_at(immediate_context* context)
		{
			return exception_repr(context);
		}
		exception_repr contract::get_exception()
		{
			return get_exception_at(immediate_context::get());
		}

		expects_lr<void> marshall::store(format::wo_stream* stream, const void* value, int value_type_id)
		{
			if (!value)
				return expectation::met;

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					stream->write_boolean(*(bool*)value);
					return expectation::met;
				case (int)type_id::int8_t:
				case (int)type_id::uint8_t:
					stream->write_integer(*(uint8_t*)value);
					return expectation::met;
				case (int)type_id::int16_t:
				case (int)type_id::uint16_t:
					stream->write_integer(*(uint16_t*)value);
					return expectation::met;
				case (int)type_id::int32_t:
				case (int)type_id::uint32_t:
					stream->write_integer(*(uint32_t*)value);
					return expectation::met;
				case (int)type_id::int64_t:
				case (int)type_id::uint64_t:
					stream->write_integer(*(uint64_t*)value);
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					auto type = factory::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_TYPE_ADDRESS)
					{
						stream->write_string(((address_repr*)value)->hash.optimized_view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						stream->write_string(((string_repr*)value)->view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						stream->write_integer(*(uint128_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						stream->write_integer(*(uint256_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						stream->write_decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						auto* array = (array_repr*)value;
						uint32_t size = (uint32_t)array->size();
						int type_id = array->get_element_type_id();
						stream->write_integer(size);
						for (uint32_t i = 0; i < size; i++)
						{
							void* address = array->at(i);
							auto status = store(stream, address, type_id);
							if (!status)
								return status;
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						for (size_t i = 0; i < properties; i++)
						{
							void* address = object.get_address_of_property(i);
							int type_id = object.get_property_type_id(i);
							auto status = store(stream, address, type_id);
							if (!status)
								return status;
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						stream->write_integer((uint32_t) * (int*)value);
						return expectation::met;
					}
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> marshall::store(schema* stream, const void* value, int value_type_id)
		{
			if (!value)
				return expectation::met;

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					stream->value = var::null();
					return expectation::met;
				case (int)type_id::bool_t:
					stream->value = var::boolean(*(bool*)value);
					return expectation::met;
				case (int)type_id::int8_t:
					stream->value = var::integer(*(int8_t*)value);
					return expectation::met;
				case (int)type_id::uint8_t:
					stream->value = var::integer(*(uint8_t*)value);
					return expectation::met;
				case (int)type_id::int16_t:
					stream->value = var::integer(*(int16_t*)value);
					return expectation::met;
				case (int)type_id::uint16_t:
					stream->value = var::integer(*(uint16_t*)value);
					return expectation::met;
				case (int)type_id::int32_t:
					stream->value = var::integer(*(int32_t*)value);
					return expectation::met;
				case (int)type_id::uint32_t:
					stream->value = var::integer(*(uint32_t*)value);
					return expectation::met;
				case (int)type_id::int64_t:
					stream->value = var::integer(*(int64_t*)value);
					return expectation::met;
				case (int)type_id::uint64_t:
					stream->value = var::integer(*(uint64_t*)value);
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					auto type = factory::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_TYPE_ADDRESS)
					{
						uptr<schema> data = algorithm::signing::serialize_address(((address_repr*)value)->hash);
						stream->value = std::move(data->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						stream->value = var::string(((string_repr*)value)->view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint128_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint256_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						stream->value = var::decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						auto* array = (array_repr*)value;
						uint32_t size = (uint32_t)array->size();
						int type_id = array->get_element_type_id();
						stream->value = var::array();
						for (uint32_t i = 0; i < size; i++)
						{
							void* address = array->at(i);
							auto status = store(stream->push(var::undefined()), address, type_id);
							if (!status)
								return status;
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						stream->value = var::object();
						for (size_t i = 0; i < properties; i++)
						{
							std::string_view name = object.get_property_name(i);
							void* address = object.get_address_of_property(i);
							int type_id = object.get_property_type_id(i);
							auto status = store(stream->set(name, var::undefined()), address, type_id);
							if (!status)
								return status;
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						stream->value = var::integer(*(int*)value);
						return expectation::met;
					}
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> marshall::load(format::ro_stream& stream, void* value, int value_type_id)
		{
			if (!value)
				return layer_exception("load failed for null type");

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					if (!stream.read_boolean(stream.read_type(), (bool*)value))
						return layer_exception("load failed for bool type");
					return expectation::met;
				case (int)type_id::int8_t:
				case (int)type_id::uint8_t:
					if (!stream.read_integer(stream.read_type(), (uint8_t*)value))
						return layer_exception("load failed for uint8 type");
					return expectation::met;
				case (int)type_id::int16_t:
				case (int)type_id::uint16_t:
					if (!stream.read_integer(stream.read_type(), (uint16_t*)value))
						return layer_exception("load failed for uint16 type");
					return expectation::met;
				case (int)type_id::int32_t:
				case (int)type_id::uint32_t:
					if (!stream.read_integer(stream.read_type(), (uint32_t*)value))
						return layer_exception("load failed for uint32 type");
					return expectation::met;
				case (int)type_id::int64_t:
				case (int)type_id::uint64_t:
					if (!stream.read_integer(stream.read_type(), (uint64_t*)value))
						return layer_exception("load failed for uint64 type");
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					bool managing = false;
					auto* vm = factory::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						void* address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("%s has no default constructor", name.data()));

						*(void**)value = address;
						value = address;
						managing = true;
					}

					auto unique = cobject(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_TYPE_ADDRESS)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for address type");

						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::pubkeyhash_t))
						{
							if (!algorithm::signing::decode_address(data, ((address_repr*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							((address_repr*)value)->hash = algorithm::pubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for string type");

						((string_repr*)value)->assign_view(data);
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						if (!stream.read_integer(stream.read_type(), (uint128_t*)value))
							return layer_exception("load failed for uint128 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						if (!stream.read_integer(stream.read_type(), (uint256_t*)value))
							return layer_exception("load failed for uint256 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						if (!stream.read_decimal_or_integer(stream.read_type(), (decimal*)value))
							return layer_exception("load failed for decimal type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						uint32_t size;
						if (!stream.read_integer(stream.read_type(), &size))
							return layer_exception("load failed for uint32 type");

						auto* array = (array_repr*)value;
						int type_id = array->get_element_type_id();
						array->clear();
						array->resize(size);
						for (uint32_t i = 0; i < size; i++)
						{
							void* address = array->at(i);
							auto status = load(stream, address, type_id);
							if (!status)
								return status;
						}

						unique.address = nullptr;
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						for (size_t i = 0; i < properties; i++)
						{
							void* address = object.get_address_of_property(i);
							int type_id = object.get_property_type_id(i);
							auto status = load(stream, address, type_id);
							if (!status)
								return status;
						}

						unique.address = nullptr;
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						if (!stream.read_integer(stream.read_type(), (uint32_t*)value))
							return layer_exception("load failed for uint32 type");
						return expectation::met;
					}
					return layer_exception(stringify::text("load not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> marshall::load(schema* stream, void* value, int value_type_id)
		{
			if (!value)
				return layer_exception("load failed for null type");

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					*(bool*)value = stream->value.get_boolean();
					return expectation::met;
				case (int)type_id::int8_t:
				case (int)type_id::uint8_t:
					*(uint8_t*)value = (uint8_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int16_t:
				case (int)type_id::uint16_t:
					*(uint16_t*)value = (uint16_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int32_t:
				case (int)type_id::uint32_t:
					*(uint32_t*)value = (uint32_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int64_t:
				case (int)type_id::uint64_t:
					*(uint64_t*)value = (uint64_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					bool managing = false;
					auto* vm = factory::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						void* address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("%s has no default constructor", name.data()));

						*(void**)value = address;
						value = address;
						managing = true;
					}

					auto unique = cobject(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_TYPE_ADDRESS)
					{
						string data = stream->value.get_blob();
						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::pubkeyhash_t))
						{
							if (!algorithm::signing::decode_address(data, ((address_repr*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							((address_repr*)value)->hash = algorithm::pubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						((string_repr*)value)->assign_view(stream->value.get_blob());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						*(uint128_t*)value = uint128_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						*(uint256_t*)value = uint256_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						*(decimal*)value = stream->value.get_decimal();
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						uint32_t size = (uint32_t)stream->size();
						auto* array = (array_repr*)value;
						int type_id = array->get_element_type_id();
						array->clear();
						array->resize(size);
						for (uint32_t i = 0; i < size; i++)
						{
							void* address = array->at(i);
							auto* substream = stream->get(i);
							if (!substream)
								return layer_exception(stringify::text("load failed for %s type while searching for %i index", i));

							auto status = load(substream, address, type_id);
							if (!status)
								return status;
						}

						unique.address = nullptr;
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						for (size_t i = 0; i < properties; i++)
						{
							std::string_view name = object.get_property_name(i);
							auto* substream = stream->get(name);
							if (!substream)
								return layer_exception(stringify::text("load failed for %s type while searching for %s property", name.data(), name.data()));

							void* address = object.get_address_of_property(i);
							int type_id = object.get_property_type_id(i);
							auto status = load(substream, address, type_id);
							if (!status)
								return status;
						}

						unique.address = nullptr;
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						*(uint32_t*)value = (uint32_t)stream->value.get_integer();
						return expectation::met;
					}
					return layer_exception(stringify::text("load not supported for %s type", name.data()));
				}
			}
		}

		cmodule::cmodule() noexcept : ref(nullptr)
		{
		}
		cmodule::cmodule(library&& new_ref) noexcept : ref(std::move(new_ref))
		{
		}
		cmodule::cmodule(cmodule&& other) noexcept : ref(std::move(other.ref))
		{
			other.ref = nullptr;
		}
		cmodule::~cmodule()
		{
			destroy();
		}
		cmodule& cmodule::operator= (cmodule&& other) noexcept
		{
			if (this == &other)
				return *this;

			destroy();
			ref = std::move(other.ref);
			other.ref = nullptr;
			return *this;
		}
		cmodule::operator bool() const
		{
			return ref.is_valid();
		}
		library* cmodule::operator-> ()
		{
			return &ref;
		}
		const library* cmodule::operator-> () const
		{
			return &ref;
		}
		library& cmodule::operator* ()
		{
			return ref;
		}
		const library& cmodule::operator* () const
		{
			return ref;
		}
		library cmodule::reset()
		{
			library result = std::move(ref);
			ref = nullptr;
			return result;
		}
		void cmodule::destroy()
		{
			if (!ref.is_valid())
				return;

			if (factory::has_instance())
				factory::get()->return_module(reset());
			else
				ref.discard();
			ref = nullptr;
		}

		factory::factory() noexcept
		{
			strings = memory::init<string_repr_cache_type>();
			vm = new virtual_machine();
			vm->set_type_def("usize", "uint32");
			initialize_opcode_table();

			auto pmut = vm->set_interface_class<program>("pmut");
			auto pconst = vm->set_interface_class<program>("pconst");
			auto array_type = vm->set_template_class<array_repr>("array<class t>", "array<t>", true);
			auto string_type = vm->set_struct_address("string", sizeof(string_repr), (size_t)object_behaviours::value | bridge::type_traits_of<string_repr>());
			auto uint128_type = vm->set_struct_trivial<uint128_t>("uint128", (size_t)object_behaviours::app_class_allints);
			auto uint256_type = vm->set_struct_trivial<uint256_t>("uint256", (size_t)object_behaviours::app_class_allints);
			auto real320_type = vm->set_struct_trivial<decimal>("real320");
			auto address_type = vm->set_struct_trivial<address_repr>("address");
			auto abi_type = vm->set_struct_trivial<abi_repr>("abi");
			auto varying_type = vm->set_template_class_address("varying<class t>", "varying<t>", sizeof(varying_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<varying_repr>());
			auto mapping_type = vm->set_template_class_address("mapping<class k, class v>", "mapping<k, v>", sizeof(mapping_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<mapping_repr>());
			auto ranging_type = vm->set_template_class_address("ranging<class c, class r, class v>", "ranging<c, r, v>", sizeof(ranging_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<ranging_repr>());
			auto ranging_slice_type = vm->set_struct_trivial<ranging_slice_repr>("ranging_slice");
			array_type->set_template_callback(&array_repr::template_callback);
			array_type->set_function_def("bool array<t>::less_sync(const t&in a, const t&in b)");
			array_type->set_constructor_extern<array_repr, asITypeInfo*>("array<t>@ f(int&in)", &array_repr::create);
			array_type->set_constructor_extern<array_repr, asITypeInfo*, uint32_t>("array<t>@ f(int&in, usize) explicit", &array_repr::create);
			array_type->set_constructor_extern<array_repr, asITypeInfo*, uint32_t, void*>("array<t>@ f(int&in, usize, const t&in)", &array_repr::create);
			array_type->set_operator_copy<array_repr>();
			array_type->set_enum_refs(&array_repr::enum_references);
			array_type->set_release_refs(&array_repr::release_references);
			array_type->set_method("bool opEquals(const array<t>&in) const", &array_repr::operator==);
			array_type->set_method<array_repr, void*, uint32_t>("t& opIndex(usize)", &array_repr::at);
			array_type->set_method<array_repr, const void*, uint32_t>("const t& opIndex(usize) const", &array_repr::at);
			array_type->set_method<array_repr, void*>("t& front()", &array_repr::front);
			array_type->set_method<array_repr, const void*>("const t& front() const", &array_repr::front);
			array_type->set_method<array_repr, void*>("t& back()", &array_repr::back);
			array_type->set_method<array_repr, const void*>("const t& back() const", &array_repr::back);
			array_type->set_method("bool empty() const", &array_repr::empty);
			array_type->set_method("usize size() const", &array_repr::size);
			array_type->set_method("usize capacity() const", &array_repr::capacity);
			array_type->set_method("void reserve(usize)", &array_repr::reserve);
			array_type->set_method<array_repr, void, uint32_t>("void resize(usize)", &array_repr::resize);
			array_type->set_method("void clear()", &array_repr::clear);
			array_type->set_method("void push(const t&in)", &array_repr::insert_last);
			array_type->set_method("void pop()", &array_repr::remove_last);
			array_type->set_method<array_repr, void, uint32_t, void*>("void insert(usize, const t&in)", &array_repr::insert_at);
			array_type->set_method<array_repr, void, uint32_t, const array_repr&>("void insert(usize, const array<t>&)", &array_repr::insert_at);
			array_type->set_method("void erase_if(const t&in if_handle_then_const, usize = 0)", &array_repr::remove_if);
			array_type->set_method("void erase(usize)", &array_repr::remove_at);
			array_type->set_method("void erase(usize, usize)", &array_repr::remove_range);
			array_type->set_method("void reverse()", &array_repr::reverse);
			array_type->set_method("void swap(usize, usize)", &array_repr::swap);
			array_type->set_method("void sort(less_sync@ = null)", &array_repr::sort);
			array_type->set_method<array_repr, uint32_t, void*, uint32_t>("usize find(const t&in if_handle_then_const, usize = 0) const", &array_repr::find);
			array_type->set_method<array_repr, uint32_t, void*, uint32_t>("usize find_ref(const t&in if_handle_then_const, usize = 0) const", &array_repr::find_by_ref);
			string_type->set_constructor_extern("void f()", &string_repr::create);
			string_type->set_constructor_extern("void f(const string&in)", &string_repr::create_copy);
			string_type->set_destructor_extern("void f()", &string_repr::destroy);
			string_type->set_method("string& opAssign(const string&in)", &string_repr::assign);
			string_type->set_method("string& opAddAssign(const string&in)", &string_repr::assign_append);
			string_type->set_method("string& opAddAssign(uint8)", &string_repr::assign_append_char);
			string_type->set_method("string opAdd(const string&in) const", &string_repr::append);
			string_type->set_method("string opAdd(uint8) const", &string_repr::append_char);
			string_type->set_method("string opAdd_r(uint8) const", &string_repr::append_char);
			string_type->set_method("int opCmp(const string&in) const", &string_repr::compare);
			string_type->set_method("uint8& opIndex(usize)", &string_repr::at);
			string_type->set_method("const uint8& opIndex(usize) const", &string_repr::at);
			string_type->set_method("uint8& at(usize)", &string_repr::at);
			string_type->set_method("const uint8& at(usize) const", &string_repr::at);
			string_type->set_method("uint8& front()", &string_repr::front);
			string_type->set_method("const uint8& front() const", &string_repr::front);
			string_type->set_method("uint8& back()", &string_repr::back);
			string_type->set_method("const uint8& back() const", &string_repr::back);
			string_type->set_method("bool empty() const", &string_repr::empty);
			string_type->set_method("usize size() const", &string_repr::size);
			string_type->set_method("void clear()", &string_repr::clear);
			string_type->set_method("string& append(const string&in)", &string_repr::assign_append);
			string_type->set_method("string& append(uint8)", &string_repr::assign_append_char);
			string_type->set_method("void push(uint8)", &string_repr::push_back);
			string_type->set_method("void pop()", &string_repr::pop_back);
			string_type->set_method("bool starts_with(const string&in, usize = 0) const", &string_repr::starts_with);
			string_type->set_method("bool ends_with(const string&in) const", &string_repr::ends_with);
			string_type->set_method("string substring(usize) const", &string_repr::substring);
			string_type->set_method("string substring(usize, usize) const", &string_repr::substring_sized);
			string_type->set_method("string& trim()", &string_repr::trim);
			string_type->set_method("string& trim_front()", &string_repr::trim_start);
			string_type->set_method("string& trim_back()", &string_repr::trim_end);
			string_type->set_method("string& lower()", &string_repr::to_lower);
			string_type->set_method("string& upper()", &string_repr::to_upper);
			string_type->set_method("string& reverse()", &string_repr::reverse);
			string_type->set_method("usize rfind(const string&in) const", &string_repr::rfind);
			string_type->set_method("usize rfind(uint8) const", &string_repr::rfind_char);
			string_type->set_method("usize rfind(const string&in, usize) const", &string_repr::rfind_offset);
			string_type->set_method("usize rfind(uint8, usize) const", &string_repr::rfind_char_offset);
			string_type->set_method("usize find(const string&in, usize = 0) const", &string_repr::find);
			string_type->set_method("usize find(uint8, usize = 0) const", &string_repr::find_char);
			string_type->set_method("usize find_first_of(const string&in, usize = 0) const", &string_repr::find_first_of);
			string_type->set_method("usize find_first_not_of(const string&in, usize = 0) const", &string_repr::find_first_not_of);
			string_type->set_method("usize find_last_of(const string&in) const", &string_repr::find_last_of);
			string_type->set_method("usize find_last_not_of(const string&in) const", &string_repr::find_last_not_of);
			string_type->set_method("usize find_last_of(const string&in, usize) const", &string_repr::find_last_of_offset);
			string_type->set_method("usize find_last_not_of(const string&in, usize) const", &string_repr::find_last_not_of_offset);
			string_type->set_method("array<string>@ split(const string&in) const", &string_repr::split);
			string_type->set_method("int8 i8(int = 10)", &string_repr::from_string<int8_t>);
			string_type->set_method("int16 i16(int = 10)", &string_repr::from_string<int16_t>);
			string_type->set_method("int32 i32(int = 10)", &string_repr::from_string<int32_t>);
			string_type->set_method("int64 i64(int = 10)", &string_repr::from_string<int64_t>);
			string_type->set_method("uint8 u8(int = 10)", &string_repr::from_string<uint8_t>);
			string_type->set_method("uint16 u16(int = 10)", &string_repr::from_string<uint16_t>);
			string_type->set_method("uint32 u32(int = 10)", &string_repr::from_string<uint32_t>);
			string_type->set_method("uint64 u64(int = 10)", &string_repr::from_string<uint64_t>);
			string_type->set_method("uint128 u128(int = 10)", &string_repr::from_string_uint128);
			string_type->set_method("uint256 u256(int = 10)", &string_repr::from_string_uint256);
			string_type->set_method("real320 r320(int = 10)", &string_repr::from_string_decimal);
			uint128_type->set_constructor_extern("void f()", &uint128_repr::default_construct);
			uint128_type->set_constructor_extern("void f(const string&in)", &uint128_repr::construct_string);
			uint128_type->set_constructor<uint128_t, int16_t>("void f(int16)");
			uint128_type->set_constructor<uint128_t, uint16_t>("void f(uint16)");
			uint128_type->set_constructor<uint128_t, int32_t>("void f(int32)");
			uint128_type->set_constructor<uint128_t, uint32_t>("void f(uint32)");
			uint128_type->set_constructor<uint128_t, int64_t>("void f(int64)");
			uint128_type->set_constructor<uint128_t, uint64_t>("void f(uint64)");
			uint128_type->set_constructor<uint128_t, const uint128_t&>("void f(const uint128&in)");
			uint128_type->set_method_extern("bool opImplConv() const", &uint128_repr::to_bool);
			uint128_type->set_method_extern("int8 i8() const", &uint128_repr::to_int8);
			uint128_type->set_method_extern("int16 i16() const", &uint128_repr::to_int16);
			uint128_type->set_method_extern("int32 i32() const", &uint128_repr::to_int32);
			uint128_type->set_method_extern("int64 i64() const", &uint128_repr::to_int64);
			uint128_type->set_method_extern("uint8 u8() const", &uint128_repr::to_uint8);
			uint128_type->set_method_extern("uint16 u16() const", &uint128_repr::to_uint16);
			uint128_type->set_method_extern("uint32 u32() const", &uint128_repr::to_uint32);
			uint128_type->set_method_extern("uint64 u64() const", &uint128_repr::to_uint64);
			uint128_type->set_method_extern("uint256 u256() const", &uint128_repr::to_uint256);
			uint128_type->set_method("real320 r320() const", &uint128_t::to_decimal);
			uint128_type->set_method<uint128_t, const uint64_t&>("const uint64& low() const", &uint128_t::low);
			uint128_type->set_method<uint128_t, const uint64_t&>("const uint64& high() const", &uint128_t::high);
			uint128_type->set_method("uint8 bits() const", &uint128_t::bits);
			uint128_type->set_method("uint8 bytes() const", &uint128_t::bits);
			uint128_type->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &uint128_repr::mul_eq);
			uint128_type->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &uint128_repr::div_eq);
			uint128_type->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &uint128_repr::add_eq);
			uint128_type->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &uint128_repr::sub_eq);
			uint128_type->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "uint128&", "", &uint128_repr::fpp);
			uint128_type->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "uint128&", "", &uint128_repr::fmm);
			uint128_type->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "uint128&", "", &uint128_repr::pp);
			uint128_type->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "uint128&", "", &uint128_repr::mm);
			uint128_type->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const uint128&in", &uint128_repr::eq);
			uint128_type->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const uint128&in", &uint128_repr::cmp);
			uint128_type->set_operator_extern(operators::add_t, (uint32_t)position::constant, "uint128", "const uint128&in", &uint128_repr::add);
			uint128_type->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "uint128", "const uint128&in", &uint128_repr::sub);
			uint128_type->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "uint128", "const uint128&in", &uint128_repr::mul);
			uint128_type->set_operator_extern(operators::div_t, (uint32_t)position::constant, "uint128", "const uint128&in", &uint128_repr::div);
			uint128_type->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "uint128", "const uint128&in", &uint128_repr::per);
			uint256_type->set_constructor_extern("void f()", &uint256_repr::default_construct);
			uint256_type->set_constructor_extern("void f(const string&in)", &uint256_repr::construct_string);
			uint256_type->set_constructor<uint256_t, int16_t>("void f(int16)");
			uint256_type->set_constructor<uint256_t, uint16_t>("void f(uint16)");
			uint256_type->set_constructor<uint256_t, int32_t>("void f(int32)");
			uint256_type->set_constructor<uint256_t, uint32_t>("void f(uint32)");
			uint256_type->set_constructor<uint256_t, int64_t>("void f(int64)");
			uint256_type->set_constructor<uint256_t, uint64_t>("void f(uint64)");
			uint256_type->set_constructor<uint256_t, const uint128_t&>("void f(const uint128&in)");
			uint256_type->set_constructor<uint256_t, const uint128_t&, const uint128_t&>("void f(const uint128&in, const uint128&in)");
			uint256_type->set_constructor<uint256_t, const uint256_t&>("void f(const uint256&in)");
			uint256_type->set_method_extern("bool opImplConv() const", &uint256_repr::to_bool);
			uint256_type->set_method_extern("int8 i8() const", &uint256_repr::to_int8);
			uint256_type->set_method_extern("int16 i16() const", &uint256_repr::to_int16);
			uint256_type->set_method_extern("int32 i32() const", &uint256_repr::to_int32);
			uint256_type->set_method_extern("int64 i64() const", &uint256_repr::to_int64);
			uint256_type->set_method_extern("uint8 u8() const", &uint256_repr::to_uint8);
			uint256_type->set_method_extern("uint16 u16() const", &uint256_repr::to_uint16);
			uint256_type->set_method_extern("uint32 u32() const", &uint256_repr::to_uint32);
			uint256_type->set_method_extern("uint64 u64() const", &uint256_repr::to_uint64);
			uint256_type->set_method_extern("uint128 u128() const", &uint256_repr::to_uint128);
			uint256_type->set_method("real320 r320() const", &uint256_t::to_decimal);
			uint256_type->set_method<uint256_t, const uint128_t&>("const uint128& low() const", &uint256_t::low);
			uint256_type->set_method<uint256_t, const uint128_t&>("const uint128& high() const", &uint256_t::high);
			uint256_type->set_method("uint16 bits() const", &uint256_t::bits);
			uint256_type->set_method("uint16 bytes() const", &uint256_t::bytes);
			uint256_type->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &uint256_repr::mul_eq);
			uint256_type->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &uint256_repr::div_eq);
			uint256_type->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &uint256_repr::add_eq);
			uint256_type->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &uint256_repr::sub_eq);
			uint256_type->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "uint256&", "", &uint256_repr::fpp);
			uint256_type->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "uint256&", "", &uint256_repr::fmm);
			uint256_type->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "uint256&", "", &uint256_repr::pp);
			uint256_type->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "uint256&", "", &uint256_repr::mm);
			uint256_type->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const uint256&in", &uint256_repr::eq);
			uint256_type->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const uint256&in", &uint256_repr::cmp);
			uint256_type->set_operator_extern(operators::add_t, (uint32_t)position::constant, "uint256", "const uint256&in", &uint256_repr::add);
			uint256_type->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "uint256", "const uint256&in", &uint256_repr::sub);
			uint256_type->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "uint256", "const uint256&in", &uint256_repr::mul);
			uint256_type->set_operator_extern(operators::div_t, (uint32_t)position::constant, "uint256", "const uint256&in", &uint256_repr::div);
			uint256_type->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "uint256", "const uint256&in", &uint256_repr::per);
			real320_type->set_constructor_extern<decimal*>("void f()", &real320_repr::custom_constructor);
			real320_type->set_constructor_extern<decimal*, bool>("void f(bool)", &real320_repr::custom_constructor_bool);
			real320_type->set_constructor_extern<decimal*, int8_t>("void f(int8)", &real320_repr::custom_constructor_arithmetic<int8_t>);
			real320_type->set_constructor_extern<decimal*, uint8_t>("void f(uint8)", &real320_repr::custom_constructor_arithmetic<uint8_t>);
			real320_type->set_constructor_extern<decimal*, int16_t>("void f(int16)", &real320_repr::custom_constructor_arithmetic<int16_t>);
			real320_type->set_constructor_extern<decimal*, uint16_t>("void f(uint16)", &real320_repr::custom_constructor_arithmetic<uint16_t>);
			real320_type->set_constructor_extern<decimal*, int32_t>("void f(int32)", &real320_repr::custom_constructor_arithmetic<int32_t>);
			real320_type->set_constructor_extern<decimal*, uint32_t>("void f(uint32)", &real320_repr::custom_constructor_arithmetic<uint32_t>);
			real320_type->set_constructor_extern<decimal*, int64_t>("void f(int64)", &real320_repr::custom_constructor_arithmetic<int64_t>);
			real320_type->set_constructor_extern<decimal*, uint64_t>("void f(uint64)", &real320_repr::custom_constructor_arithmetic<uint64_t>);
			real320_type->set_constructor_extern<decimal*, const string_repr&>("void f(const string&in)", &real320_repr::custom_constructor_string);
			real320_type->set_constructor_extern<decimal*, const decimal&>("void f(const real320&in)", &real320_repr::custom_constructor_copy);
			real320_type->set_method_extern("bool opImplConv() const", &real320_repr::is_not_zero_or_nan);
			real320_type->set_method("bool is_nan() const", &decimal::is_nan);
			real320_type->set_method("bool is_zero() const", &decimal::is_zero);
			real320_type->set_method("bool is_zero_or_nan() const", &decimal::is_zero_or_nan);
			real320_type->set_method("bool is_positive() const", &decimal::is_positive);
			real320_type->set_method("bool is_negative() const", &decimal::is_negative);
			real320_type->set_method("bool is_integer() const", &decimal::is_integer);
			real320_type->set_method("bool is_fractional() const", &decimal::is_fractional);
			real320_type->set_method("int8 i8() const", &decimal::to_int8);
			real320_type->set_method("int16 i16() const", &decimal::to_int16);
			real320_type->set_method("int32 i32() const", &decimal::to_int32);
			real320_type->set_method("int64 i64() const", &decimal::to_int64);
			real320_type->set_method("uint8 u8() const", &decimal::to_uint8);
			real320_type->set_method("uint16 u16() const", &decimal::to_uint16);
			real320_type->set_method("uint32 u32() const", &decimal::to_uint32);
			real320_type->set_method("uint64 u64() const", &decimal::to_uint64);
			real320_type->set_method_extern("uint128 u128() const", &real320_repr::to_uint128);
			real320_type->set_method_extern("uint256 u256() const", &real320_repr::to_uint256);
			real320_type->set_method_extern("string exponent() const", &real320_repr::to_exponent);
			real320_type->set_method("uint32 decimal_size() const", &decimal::decimal_size);
			real320_type->set_method("uint32 integer_size() const", &decimal::integer_size);
			real320_type->set_method("uint32 size() const", &decimal::size);
			real320_type->set_operator_extern(operators::neg_t, (uint32_t)position::constant, "real320", "", &real320_repr::negate);
			real320_type->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "real320&", "const real320&in", &real320_repr::mul_eq);
			real320_type->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "real320&", "const real320&in", &real320_repr::div_eq);
			real320_type->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "real320&", "const real320&in", &real320_repr::add_eq);
			real320_type->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "real320&", "const real320&in", &real320_repr::sub_eq);
			real320_type->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "real320&", "", &real320_repr::fpp);
			real320_type->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "real320&", "", &real320_repr::fmm);
			real320_type->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "real320&", "", &real320_repr::pp);
			real320_type->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "real320&", "", &real320_repr::mm);
			real320_type->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const real320&in", &real320_repr::eq);
			real320_type->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const real320&in", &real320_repr::cmp);
			real320_type->set_operator_extern(operators::add_t, (uint32_t)position::constant, "real320", "const real320&in", &real320_repr::add);
			real320_type->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "real320", "const real320&in", &real320_repr::sub);
			real320_type->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "real320", "const real320&in", &real320_repr::mul);
			real320_type->set_operator_extern(operators::div_t, (uint32_t)position::constant, "real320", "const real320&in", &real320_repr::div);
			real320_type->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "real320", "const real320&in", &real320_repr::per);
			real320_type->set_method_static("real320 nan()", &decimal::nan);
			real320_type->set_method_static("real320 zero()", &decimal::zero);
			real320_type->set_method_static("real320 from(const string&in, uint8)", &real320_repr::from);
			address_type->set_constructor<address_repr>("void f()");
			address_type->set_constructor<address_repr, const string_repr&>("void f(const string&in)");
			address_type->set_constructor<address_repr, const uint256_t&>("void f(const uint256&in)");
			address_type->set_constructor<address_repr, const address_repr&>("void f(const address&in)");
			address_type->set_method("uint256 u256() const", &address_repr::to_public_key_hash);
			address_type->set_method("bool empty() const", &address_repr::empty);
			address_type->set_method("void pay(const uint256&in, const real320&in) const", &address_repr::pay);
			address_type->set_method("real320 balance_of(const uint256&in) const", &address_repr::balance_of);
			address_type->set_method_extern("t call<t>(const string&in, const ?&in ...) const", &address_repr::free_call, convention::generic_call);
			address_type->set_method_extern("t paid_call<t>(const string&in, const real320&in, const ?&in ...) const", &address_repr::paid_call, convention::generic_call);
			address_type->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const address&in", &address_repr::equals);
			abi_type->set_constructor<abi_repr>("void f()");
			abi_type->set_constructor<abi_repr, const string_repr&>("void f(const string&in)");
			abi_type->set_constructor<abi_repr, const abi_repr&>("void f(const abi&in)");
			abi_type->set_method("void seek(usize)", &abi_repr::seek);
			abi_type->set_method("void clear()", &abi_repr::clear);
			abi_type->set_method("void wu8(bool)", &abi_repr::wboolean);
			abi_type->set_method("void wu160(const address&in)", &abi_repr::wuint160);
			abi_type->set_method("void wu256(const uint256&in)", &abi_repr::wuint256);
			abi_type->set_method("void wr320(const real320&in)", &abi_repr::wreal320);
			abi_type->set_method("void merge(const string&in)", &abi_repr::merge);
			abi_type->set_method("void wstr(const string&in)", &abi_repr::wstr);
			abi_type->set_method("void wrstr(const string&in)", &abi_repr::wrstr);
			abi_type->set_method("bool rstr(string&out)", &abi_repr::rstr);
			abi_type->set_method("bool ru8(bool&out)", &abi_repr::rboolean);
			abi_type->set_method("bool ru160(address&out)", &abi_repr::ruint160);
			abi_type->set_method("bool ru256(uint256&out)", &abi_repr::ruint256);
			abi_type->set_method("bool rr320(real320&out)", &abi_repr::rreal320);
			abi_type->set_method("string data()", &abi_repr::data);
			varying_type->set_template_callback(&varying_repr::template_callback);
			varying_type->set_type_constructor<varying_repr, asITypeInfo*>("void f(int&in)");
			varying_type->set_type_destructor<varying_repr>("void f()");
			varying_type->set_method("void erase()", &varying_repr::erase);
			varying_type->set_method("void opAssign(const t&in)", &varying_repr::store);
			varying_type->set_method("void set(const t&in)", &varying_repr::store);
			varying_type->set_method("void set_if(bool, const t&in)", &varying_repr::store_if);
			varying_type->set_method<varying_repr, const void*>("const t& get_ref() const property", &varying_repr::load);
			varying_type->set_method("bool empty() const", &varying_repr::empty);
			mapping_type->set_template_callback(&mapping_repr::template_callback);
			mapping_type->set_type_constructor<mapping_repr, asITypeInfo*>("void f(int&in)");
			mapping_type->set_type_destructor<mapping_repr>("void f()");
			mapping_type->set_method("void erase(const k&in)", &mapping_repr::erase);
			mapping_type->set_method("void insert(const k&in, const v&in)", &mapping_repr::store);
			mapping_type->set_method("void insert_if(bool, const k&in, const v&in)", &mapping_repr::store_if);
			mapping_type->set_method<mapping_repr, const void*>("const v& opIndex(const k&in) const", &mapping_repr::load);
			mapping_type->set_method("bool has(const k&in) const", &mapping_repr::has);
			ranging_type->set_template_callback(&ranging_repr::template_callback);
			ranging_type->set_type_constructor<ranging_repr, asITypeInfo*>("void f(int&in)");
			ranging_type->set_type_destructor<ranging_repr>("void f()");
			ranging_type->set_method("const v& from(ranging_slice&in) const", &ranging_repr::from);
			ranging_type->set_method("ranging_slice x(const c&in) const", &ranging_repr::from_column);
			ranging_type->set_method("ranging_slice y(const r&in) const", &ranging_repr::from_row);
			ranging_type->set_method("void erase(const c&in, const r&in)", &ranging_repr::erase);
			ranging_type->set_method("void insert(const c&in, const r&in, const v&in)", &ranging_repr::store);
			ranging_type->set_method("void insert(const c&in, const r&in, const v&in, const uint256&in)", &ranging_repr::store_positioned);
			ranging_type->set_method("void insert_if(bool, const c&in, const r&in, const v&in)", &ranging_repr::store_if);
			ranging_type->set_method("void insert_if(bool, const c&in, const r&in, const v&in, const uint256&in)", &ranging_repr::store_positioned_if);
			ranging_type->set_method<ranging_repr, const void*>("const v& opIndex(const c&in, const r&in) const", &ranging_repr::load);
			ranging_type->set_method("bool has(const c&in, const r&in) const", &ranging_repr::has);
			ranging_type->set_method("bool has_x(const c&in) const", &ranging_repr::has_column);
			ranging_type->set_method("bool has_y(const r&in) const", &ranging_repr::has_row);
			ranging_slice_type->set_constructor<ranging_slice_repr>("void f()");
			ranging_slice_type->set_method("bool next(?&out) const", &ranging_slice_repr::next);
			ranging_slice_type->set_method("bool next(?&out, ?&out) const", &ranging_slice_repr::next_index);
			ranging_slice_type->set_method("bool next(?&out, ?&out, uint256&out) const", &ranging_slice_repr::next_index_ranked);
			ranging_slice_type->set_method("ranging_slice& offset(usize = 0)", &ranging_slice_repr::with_offset);
			ranging_slice_type->set_method("ranging_slice& count(usize = 0)", &ranging_slice_repr::with_count);
			ranging_slice_type->set_method("ranging_slice& gt(const uint256&in)", &ranging_slice_repr::where_gt);
			ranging_slice_type->set_method("ranging_slice& gte(const uint256&in)", &ranging_slice_repr::where_gte);
			ranging_slice_type->set_method("ranging_slice& eq(const uint256&in)", &ranging_slice_repr::where_eq);
			ranging_slice_type->set_method("ranging_slice& neq(const uint256&in)", &ranging_slice_repr::where_neq);
			ranging_slice_type->set_method("ranging_slice& lt(const uint256&in)", &ranging_slice_repr::where_lt);
			ranging_slice_type->set_method("ranging_slice& lte(const uint256&in)", &ranging_slice_repr::where_lte);
			ranging_slice_type->set_method("ranging_slice& asc()", &ranging_slice_repr::order_asc);
			ranging_slice_type->set_method("ranging_slice& desc()", &ranging_slice_repr::order_desc);

			vm->begin_namespace("log");
			vm->set_function("void emit(const ?&in)", &contract::log_emit);
			vm->set_function("void event(const ?&in, const ?&in)", &contract::log_event);
			vm->set_function("bool into(int32, ?&out)", &contract::log_into);
			vm->set_function("bool event_into(const ?&in, int32, ?&out)", &contract::log_event_into, convention::generic_call);
			vm->set_function("t get<t>(int32)", &contract::log_get, convention::generic_call);
			vm->set_function("t get_event<t>(const ?&in, int32)", &contract::log_get_event, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("sv");
			vm->set_function("void set(const ?&in, const ?&in)", &contract::uniform_set);
			vm->set_function("void set(const ?&in, const ?&in, bool)", &contract::uniform_set_if);
			vm->set_function("void erase(const ?&in)", &contract::uniform_erase);
			vm->set_function("bool has(const ?&in)", &contract::uniform_has);
			vm->set_function("bool into(const ?&in, ?&out)", &contract::uniform_into);
			vm->set_function("t get<t>(const ?&in)", &contract::uniform_get, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("sv::range");
			vm->set_function("void set(const ?&in, const ?&in, const ?&in)", &contract::multiform_set);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in, const uint256&in)", &contract::multiform_set_ranked);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in, bool)", &contract::multiform_set_if);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in, const uint256&in, bool)", &contract::multiform_set_if_ranked);
			vm->set_function("void erase(const ?&in, const ?&in)", &contract::multiform_erase);
			vm->set_function("bool has(const ?&in, const ?&in)", &contract::multiform_has);
			vm->set_function("bool into(const ?&in, const ?&in, ?&out)", &contract::multiform_into);
			vm->set_function("bool into(const ?&in, const ?&in, ?&out, uint256&out)", &contract::multiform_into_ranked);
			vm->set_function("t get<t>(const ?&in, const ?&in)", &contract::multiform_get, convention::generic_call);
			vm->set_function("ranging_slice x(const ?&in)", &ranging_slice_repr::from_column);
			vm->set_function("ranging_slice y(const ?&in)", &ranging_slice_repr::from_row);
			vm->end_namespace();

			vm->begin_namespace("block");
			vm->set_function("address proposer()", &contract::block_proposer);
			vm->set_function("uint256 parent_hash()", &contract::block_parent_hash);
			vm->set_function("uint256 gas_use()", &contract::block_gas_use);
			vm->set_function("uint256 gas_left()", &contract::block_gas_left);
			vm->set_function("uint256 gas_limit()", &contract::block_gas_limit);
			vm->set_function("uint128 difficulty()", &contract::block_difficulty);
			vm->set_function("uint64 time()", &contract::block_time);
			vm->set_function("uint64 time_between(uint64, uint64)", &contract::block_time_between);
			vm->set_function("uint64 priority()", &contract::block_priority);
			vm->set_function("uint64 number()", &contract::block_number);
			vm->end_namespace();

			vm->begin_namespace("tx");
			vm->set_function("bool paid()", &contract::tx_paid);
			vm->set_function("address from()", &contract::tx_from);
			vm->set_function("address to()", &contract::tx_to);
			vm->set_function("real320 value()", &contract::tx_value);
			vm->set_function("string blockchain()", &contract::tx_blockchain);
			vm->set_function("string token()", &contract::tx_token);
			vm->set_function("string contract()", &contract::tx_contract);
			vm->set_function("real320 gas_price()", &contract::tx_gas_price);
			vm->set_function("uint256 gas_use()", &contract::tx_gas_use);
			vm->set_function("uint256 gas_left()", &contract::tx_gas_left);
			vm->set_function("uint256 gas_limit()", &contract::tx_gas_limit);
			vm->set_function("uint256 asset()", &contract::tx_asset);
			vm->end_namespace();

			vm->begin_namespace("coin");
			vm->set_function("uint256 native()", &contract::coin_native);
			vm->set_function("uint256 from(const real320&in)", &contract::coin_from_decimal);
			vm->set_function("real320 r320(const uint256&in)", &contract::coin_to_decimal);
			vm->set_function("uint256 id_of(const string&in, const string&in = string(), const string&in = string())", &contract::coin_id_of);
			vm->set_function("string blockchain_of(const uint256&in)", &contract::coin_blockchain_of);
			vm->set_function("string token_of(const uint256&in)", &contract::coin_token_of);
			vm->set_function("string contract_of(const uint256&in)", &contract::coin_checksum_of);
			vm->set_function("string name_of(const uint256&in)", &contract::coin_name_of);
			vm->end_namespace();

			vm->begin_namespace("alg");
			vm->set_function("string from_u256(const uint256&in)", &contract::alg_encode_bytes256);
			vm->set_function("uint256 to_u256(const string&in)", &contract::alg_decode_bytes256);
			vm->set_function("address erecover160(const uint256&in, const string&in)", &contract::alg_erecover160);
			vm->set_function("string erecover264(const uint256&in, const string&in)", &contract::alg_erecover264);
			vm->set_function("uint256 prandom256()", &contract::alg_prandom);
			vm->set_function("string crc32(const string&in)", &contract::alg_crc32);
			vm->set_function("string ripemd160(const string&in)", &contract::alg_ripemd160);
			vm->set_function("uint256 blake2b256(const string&in)", &contract::alg_blake2b256);
			vm->set_function("string blake2b256s(const string&in)", &contract::alg_blake2b256s);
			vm->set_function("uint256 keccak256(const string&in)", &contract::alg_keccak256);
			vm->set_function("string keccak256s(const string&in)", &contract::alg_keccak256s);
			vm->set_function("string keccak512(const string&in)", &contract::alg_keccak512);
			vm->set_function("uint256 sha256(const string&in)", &contract::alg_sha256);
			vm->set_function("string sha256s(const string&in)", &contract::alg_sha256s);
			vm->set_function("string sha512(const string&in)", &contract::alg_sha512);
			vm->end_namespace();

			vm->begin_namespace("math");
			vm->set_function("t min_value<t>()", &contract::math_min_value, convention::generic_call);
			vm->set_function("t max_value<t>()", &contract::math_max_value, convention::generic_call);
			vm->set_function("t min<t>(const t&in, const t&in)", &contract::math_min, convention::generic_call);
			vm->set_function("t max<t>(const t&in, const t&in)", &contract::math_max, convention::generic_call);
			vm->set_function("t clamp<t>(const t&in, const t&in, const t&in)", &contract::math_clamp, convention::generic_call);
			vm->set_function("t lerp<t>(const t&in, const t&in, const t&in)", &contract::math_lerp, convention::generic_call);
			vm->set_function("t pow<t>(const t&in, const t&in)", &contract::math_pow, convention::generic_call);
			vm->set_function("t sqrt<t>(const t&in)", &contract::math_sqrt, convention::generic_call);
			vm->end_namespace();

			vm->set_function("void require(bool, const string&in = string())", &contract::require);
			vm->set_default_array_type("array<t>");
			vm->begin_namespace("array");
			vm->set_property("const usize npos", &string_repr::npos);
			vm->end_namespace();
			vm->set_string_factory_type("string");
			vm->begin_namespace("string");
			vm->set_function("string from(int8, int = 10)", &string_repr::to_string<int8_t>);
			vm->set_function("string from(int16, int = 10)", &string_repr::to_string<int16_t>);
			vm->set_function("string from(int32, int = 10)", &string_repr::to_string<int32_t>);
			vm->set_function("string from(int64, int = 10)", &string_repr::to_string<int64_t>);
			vm->set_function("string from(uint8, int = 10)", &string_repr::to_string<uint8_t>);
			vm->set_function("string from(uint16, int = 10)", &string_repr::to_string<uint16_t>);
			vm->set_function("string from(uint32, int = 10)", &string_repr::to_string<uint32_t>);
			vm->set_function("string from(uint64, int = 10)", &string_repr::to_string<uint64_t>);
			vm->set_function("string from(const uint128&in, int = 10)", &string_repr::to_string_uint128);
			vm->set_function("string from(const uint256&in, int = 10)", &string_repr::to_string_uint256);
			vm->set_function("string from(const real320&in)", &string_repr::to_string_decimal);
			vm->set_function("string from(const address&in)", &string_repr::to_string_address);
			vm->set_property("const usize npos", &string_repr::npos);
			vm->end_namespace();

			preprocessor::desc compiler_features;
			compiler_features.conditions = false;
			compiler_features.defines = false;
			compiler_features.includes = false;
			compiler_features.pragmas = false;
			vm->set_compiler_features(compiler_features);
			vm->set_library_property(library_features::promise_no_constructor, 1);
			vm->set_library_property(library_features::promise_no_callbacks, 1);
			vm->set_library_property(library_features::ctypes_no_pointer_cast, 1);
			vm->set_library_property(library_features::decimal_target_precision, (size_t)protocol::now().message.decimal_precision);
			vm->set_property(features::allow_unsafe_references, 0);
			vm->set_property(features::optimize_bytecode, 1);
			vm->set_property(features::copy_script_sections, 1);
			vm->set_property(features::max_stack_size, 1024 * 64);
			vm->set_property(features::use_character_literals, 1);
			vm->set_property(features::allow_multiline_strings, 0);
			vm->set_property(features::allow_implicit_handle_types, 0);
			vm->set_property(features::build_without_line_cues, 0);
			vm->set_property(features::init_global_vars_after_build, 0);
			vm->set_property(features::require_enum_scope, 0);
			vm->set_property(features::script_scanner, 1);
			vm->set_property(features::include_jit_instructions, 0);
			vm->set_property(features::string_encoding, 0);
			vm->set_property(features::property_accessor_mode, 3);
			vm->set_property(features::expand_def_array_to_impl, 1);
			vm->set_property(features::auto_garbage_collect, 1);
			vm->set_property(features::disallow_global_vars, 0);
			vm->set_property(features::always_impl_default_construct, 0);
			vm->set_property(features::compiler_warnings, 2);
			vm->set_property(features::disallow_value_assign_for_ref_type, 0);
			vm->set_property(features::alter_syntax_named_args, 0);
			vm->set_property(features::disable_integer_division, 0);
			vm->set_property(features::disallow_empty_list_elements, 1);
			vm->set_property(features::private_prop_as_protected, 0);
			vm->set_property(features::allow_unicode_identifiers, 0);
			vm->set_property(features::heredoc_trim_mode, 1);
			vm->set_property(features::max_nested_calls, 128);
			vm->set_property(features::generic_call_mode, 1);
			vm->set_property(features::init_stack_size, 4096);
			vm->set_property(features::init_call_stack_size, 10);
			vm->set_property(features::max_call_stack_size, 256);
			vm->set_property(features::ignore_duplicate_shared_int, 0);
			vm->set_property(features::no_debug_output, 0);
			vm->set_property(features::disable_script_class_gc, 0);
			vm->set_property(features::jit_interface_version, 1);
			vm->set_property(features::always_impl_default_copy, 0);
			vm->set_property(features::always_impl_default_copy_construct, 0);
			vm->set_property(features::member_init_mode, 0);
			vm->set_property(features::bool_conversion_mode, 0);
			vm->set_property(features::foreach_support, 0);
			vm->set_string_factory_functions(this, to_string_constant, from_string_constant, free_string_constant);
			vm->set_type_info_user_data_cleanup_callback(array_repr::cleanup_type_info_cache, array_repr::get_id());
			vm->set_full_stack_tracing(false);
			vm->set_cache(!protocol::now().user.storage.module_cache_path.empty());
			vm->set_ts_imports(false);
			vm->set_keyword_restriction("auto", true);
			vm->set_keyword_restriction("auto&", true);
			vm->set_keyword_restriction("auto@", true);
			vm->set_keyword_restriction("float", true);
			vm->set_keyword_restriction("double", true);
			vm->set_cache_callback([](byte_code_info* info)
			{
				auto path = stringify::text("%s%c%s.casm", protocol::now().user.storage.module_cache_path.c_str(), VI_SPLITTER, info->name.c_str());
				if (info->valid)
					return !!os::file::write(path, info->data.data(), info->data.size());

				auto target = uptr<stream>(os::file::open(path, file_mode::binary_read_only));
				return target && !!target->read_all([&info](uint8_t* buffer, size_t size)
				{
					size_t prev_size = info->data.size();
					info->data.resize(prev_size + size);
					memcpy(info->data.data() + prev_size, buffer, size);
				});
			});
		}
		factory::~factory() noexcept
		{
			if (compiler)
				compiler->unlink_module();
			for (auto& [id, link] : modules)
				library(link.reset()).discard();
			modules.clear();
			memory::deinit((string_repr_cache_type*)strings);
		}
		void factory::initialize_opcode_table()
		{
			unordered_set<std::string_view> illegal_opcodes =
			{
				"NEGf", "NEGd", "INCf", "DECf", "INCd", "DECd", "CMPd",
				"CMPf", "CMPIf", "iTOf", "fTOi", "uTOf", "fTOu", "dTOi",
				"dTOu", "dTOf", "iTOd", "uTOd", "fTOd", "ADDf", "SUBf",
				"MULf", "DIVf", "MODf", "ADDd", "SUBd", "MULd", "DIVd",
				"MODd", "ADDIf", "SUBIf", "MULIf", "fTOi64", "dTOi64",
				"fTOu64", "dTOu64", "i64TOf", "u64TOf", "i64TOd",
				"u64TOd", "POWf", "POWd", "POWdi"
			};
			unordered_set<std::string_view> internal_opcodes =
			{
				"SUSPEND"
			};
			unordered_map<std::string_view, uint8_t> name_to_opcode;
			name_to_opcode.reserve(opcodes.size());
			for (size_t i = 0; i < opcodes.size(); i++)
			{
				auto opcode = (uint8_t)i;
				auto type = virtual_machine::get_byte_code_info(opcode);
				bool illegal = illegal_opcodes.find(type.name) != illegal_opcodes.end();
				bool internal = internal_opcodes.find(type.name) != internal_opcodes.end();
				opcodes[opcode] = illegal ? -1 : (internal ? 0 : 1);
				name_to_opcode[type.name] = opcode;
			}
		}
		void factory::return_module(cmodule&& value)
		{
			if (!value->is_valid())
				return;

			auto scoped_name = value->get_name();
			auto index = scoped_name.rfind(':');
			auto name = index == std::string_view::npos ? scoped_name : scoped_name.substr(0, index);
			umutex<std::recursive_mutex> unique(mutex);
			auto it = modules.find(key_lookup_cast(name));
			if (it != modules.end())
			{
				value->discard();
				value.ref = nullptr;
			}
			else
				modules.insert(std::make_pair(string(name), std::move(value)));
		}
		expects_lr<cmodule> factory::compile_module(const std::string_view& hashcode, const std::function<expects_lr<string>()>& unpacked_code_callback)
		{
			VI_ASSERT(unpacked_code_callback, "callback should be set");
			umutex<std::recursive_mutex> unique(mutex);
			auto it = modules.find(key_lookup_cast(hashcode));
			if (it != modules.end())
			{
				cmodule result = std::move(it->second);
				modules.erase(it);
				return expects_lr<cmodule>(std::move(result));
			}

			compiler_log.clear();
			vm->set_compiler_error_callback([this](const std::string_view& message) { compiler_log.append(message).append("\r\n"); });
			if (!compiler)
				compiler = vm->create_compiler();
			else
				compiler->clear();

			auto preparation = compiler->prepare(hashcode, hashcode, true, true);
			if (!preparation)
			{
				compiler_log.append(SCRIPT_VM " preparation: " + preparation.error().message() + "\r\n");
			error:
				vm->set_compiler_error_callback(nullptr);
				stringify::replace(compiler_log, hashcode, SCRIPT_VM "c");
				return layer_exception(string(compiler_log));
			}

			if (!compiler->is_cached())
			{
				auto code = unpacked_code_callback();
				if (!code)
					return code.error();

				auto injection = compiler->load_code(hashcode, *code);
				if (!injection)
				{
					compiler_log.append(SCRIPT_VM " generation: " + injection.error().message() + "\r\n");
					goto error;
				}
			}

			auto compilation = compiler->compile_sync();
			if (!compilation)
			{
				compiler_log.append(SCRIPT_VM " compilation: " + compilation.error().message() + "\r\n");
				goto error;
			}

			auto module = cmodule(compiler->unlink_module());
			if (module->get_properties_count() > std::numeric_limits<uint16_t>::max())
			{
				compiler_log.append(SCRIPT_VM " property validation: too many global properties\r\n");
				goto error;
			}

			for (size_t i = 0; i < module->get_properties_count(); i++)
			{
				property_info info;
				auto status = module->get_property(i, &info);
				if (!status)
				{
					compiler_log.append(SCRIPT_VM " property validation: " + status.error().message() + "\r\n");
					goto error;
				}

				auto type = vm->get_type_info_by_id(info.type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("?");
				if (name != SCRIPT_TYPE_VARYING && name != SCRIPT_TYPE_MAPPING && name != SCRIPT_TYPE_RANGING)
				{
					auto decl = module->get_property_decl(i, true);
					compiler_log.append(stringify::text(SCRIPT_VM " illegal property declaration \"%.*s\"\r\n", (int)decl.size(), decl.data()));
					goto error;
				}
			}
			for (size_t i = 0; i < module->get_objects_count(); i++)
			{
				auto object = module->get_object_by_index(i);
				for (size_t j = 0; j < object.get_methods_count(); j++)
				{
					auto validation = validate_bytecode(object.get_method_by_index(j));
					if (!validation)
					{
						compiler_log.append(SCRIPT_VM " method validation: " + validation.error().message() + "\r\n");
						goto error;
					}
				}
			}
			for (size_t i = 0; i < module->get_function_count(); i++)
			{
				auto validation = validate_bytecode(module->get_function_by_index(i));
				if (!validation)
				{
					compiler_log.append(SCRIPT_VM " function validation: " + validation.error().message() + "\r\n");
					goto error;
				}
			}

			return expects_lr<cmodule>(std::move(module));
		}
		expects_lr<void> factory::reset_properties(library& module, immediate_context* context)
		{
			auto status = module.reset_properties(context->get_context());
			if (!status)
				return layer_exception(std::move(status.error().message()));

			auto* vm = module.get_vm();
			size_t count = module.get_properties_count();
			for (size_t i = 0; i < count; i++)
			{
				property_info info;
				if (!module.get_property(i, &info))
					continue;

				auto type = vm->get_type_info_by_id(info.type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("?");
				if (name == SCRIPT_TYPE_VARYING || name == SCRIPT_TYPE_MAPPING || name == SCRIPT_TYPE_RANGING)
				{
					auto value = (container_repr*)module.get_address_of_property(i);
					value->slot = (uint16_t)(i + 1);
					value->reset();
				}
			}

			return expectation::met;
		}
		string factory::hashcode(const std::string_view& unpacked_code)
		{
			static std::string_view lines = "\r\n";
			static std::string_view erasable = " \r\n\t\'\"()<>=%&^*/+-,.!?:;@~";
			static std::string_view quotes = "\"'`";
			string hashable = string(unpacked_code);
			stringify::replace_in_between(stringify::trim(hashable), "/*", "*/", "", false);
			stringify::replace_starts_with_ends_of(stringify::trim(hashable), "//", lines, "");
			stringify::compress(stringify::trim(hashable), erasable, quotes);
			return algorithm::hashing::hash512((uint8_t*)hashable.data(), hashable.size());
		}
		expects_lr<string> factory::pack(const std::string_view& unpacked_code)
		{
			auto packed_code = codec::compress(unpacked_code, compression::best_compression);
			if (!packed_code)
				return layer_exception(std::move(packed_code.error().message()));

			return *packed_code;
		}
		expects_lr<string> factory::unpack(const std::string_view& packed_code)
		{
			auto unpacked_code = codec::decompress(packed_code);
			if (!unpacked_code)
				return layer_exception(std::move(unpacked_code.error().message()));

			return *unpacked_code;
		}
		int8_t factory::opcode_type(uint8_t opcode)
		{
			return opcodes[opcode];
		}
		virtual_machine* factory::get_vm()
		{
			return *vm;
		}
		expects_lr<void> factory::validate_bytecode(const function& compiled_function)
		{
			size_t byte_code_size = 0;
			uint32_t* byte_code = compiled_function.get_byte_code(&byte_code_size);
			for (size_t i = 0; i < byte_code_size;)
			{
				uint8_t code = *(uint8_t*)(&byte_code[i]);
				auto type = virtual_machine::get_byte_code_info(code);
				auto cost = opcodes[code];
				if (cost < 0)
				{
					auto name = string(type.name);
					auto decl = compiled_function.get_decl(true, true, true);
					return layer_exception(stringify::text("declaration \"%.*s\" contains illegal instruction \"%s\"", (int)decl.size(), decl.data(), stringify::to_lower(name).c_str()));
				}
				i += type.size;
			}
			return expectation::met;
		}
		const void* factory::to_string_constant(void* context, const char* buffer, size_t buffer_size)
		{
			auto* container = (factory*)context;
			auto& strings = *(string_repr_cache_type*)container->strings;
			auto copy = string_repr(std::string_view(buffer, buffer_size));
			virtual_machine::global_shared_lock();
			auto it = strings.find(copy);
			if (it != strings.end())
			{
				it->second++;
				virtual_machine::global_shared_unlock();
				return reinterpret_cast<const void*>(&it->first);
			}

			virtual_machine::global_shared_unlock();
			virtual_machine::global_exclusive_lock();
			it = strings.insert(std::make_pair(std::move(copy), 1)).first;
			virtual_machine::global_exclusive_unlock();
			return reinterpret_cast<const void*>(&it->first);
		}
		int factory::from_string_constant(void* context, const void* object, char* buffer, size_t* buffer_size)
		{
			if (buffer_size != nullptr)
				*buffer_size = reinterpret_cast<const string_repr*>(object)->size();

			if (buffer != nullptr)
				memcpy(buffer, reinterpret_cast<const string_repr*>(object)->data(), (size_t)reinterpret_cast<const string_repr*>(object)->size());

			return (int)virtual_error::success;
		}
		int factory::free_string_constant(void* context, const void* object)
		{
			if (!object)
				return (int)virtual_error::success;

			auto* container = (factory*)context;
			auto& strings = *(string_repr_cache_type*)container->strings;
			virtual_machine::global_shared_lock();
			auto it = strings.find(*reinterpret_cast<const string_repr*>(object));
			if (it == strings.end())
			{
				virtual_machine::global_shared_unlock();
				return (int)virtual_error::err;
			}
			else if (--it->second > 0)
			{
				virtual_machine::global_shared_unlock();
				return (int)virtual_error::success;
			}

			virtual_machine::global_shared_unlock();
			virtual_machine::global_exclusive_lock();
			strings.erase(it);
			virtual_machine::global_exclusive_unlock();
			return (int)virtual_error::success;
		}

		program::program(ledger::transaction_context* new_context, library&& new_module) : context(new_context), module(new_module)
		{
		}
		expects_lr<void> program::execute(ccall mutability, const std::string_view& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			auto candidate = module.get_function_by_name(entrypoint);
			return execute(mutability, candidate.is_valid() ? candidate : module.get_function_by_decl(entrypoint), args, std::move(return_callback));
		}
		expects_lr<void> program::execute(ccall mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			if (!entrypoint.is_valid())
			{
				if (mutability == ccall::upgrade_call)
					return expectation::met;

				return layer_exception("illegal call to function: null function");
			}

			auto binders = dispatch_arguments(&mutability, entrypoint, args);
			if (!binders)
				return binders.error();

			auto* vm = entrypoint.get_vm();
			auto* caller = immediate_context::get();
			auto* coroutine = caller ? caller : vm->request_context();
			auto* prev_mutable_program = coroutine->get_user_data(SCRIPT_TAG_MUTABLE_PROGRAM);
			auto* prev_immutable_program = coroutine->get_user_data(SCRIPT_TAG_IMMUTABLE_PROGRAM);
			coroutine->set_user_data(mutability == ccall::upgrade_call || mutability == ccall::paying_call ? (caller ? prev_mutable_program : this) : nullptr, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(this, SCRIPT_TAG_IMMUTABLE_PROGRAM);

			auto execution = expects_vm<vitex::scripting::execution>(vitex::scripting::execution::error);
			auto resolver = expects_lr<void>(layer_exception());
			auto resolve = [this, &resolver, &entrypoint, &return_callback](immediate_context* coroutine)
			{
				int output_type_id = entrypoint.get_return_type_id();
				void* output_value = coroutine->get_return_address();
				if (!output_value && output_type_id > 0 && output_type_id <= (int)type_id::double_t)
					output_value = coroutine->get_address_of_return_value();

				resolver = expectation::met;
				if (!output_value || output_type_id <= 0)
					return;

				if (!return_callback)
				{
					format::wo_stream stream;
					auto serialization = marshall::store(&stream, output_value, output_type_id);
					if (serialization)
					{
						auto reader = stream.ro();
						format::variables returns;
						if (format::variables_util::deserialize_flat_from(reader, &returns))
						{
							auto type = factory::get()->get_vm()->get_type_info_by_id(output_type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view("?");
							auto status = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns), true);
							if (!status)
								resolver = std::move(status);
						}
						else
							resolver = layer_exception("return value conversion error");
					}
					else
						resolver = layer_exception("return value error: " + serialization.error().message());
				}
				else
				{
					auto status = return_callback(output_value, output_type_id);
					if (!status)
						resolver = std::move(status);
				}
			};
			if (caller != coroutine)
			{
				coroutine->set_line_callback(std::bind(&program::dispatch_coroutine, this, std::placeholders::_1));
				coroutine->set_exception_callback(std::bind(&program::dispatch_exception, this, std::placeholders::_1));
				auto status = factory::get()->reset_properties(module, coroutine);
				if (status)
					execution = coroutine->execute_inline_call(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); });
				resolve(coroutine);
			}
			else
				execution = coroutine->execute_subcall(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); }, resolve);

			auto exception = coroutine->get_state() == execution::aborted ? exception_repr(exception_repr::category::execution(), "ran out of gas") : contract::get_exception_at(coroutine);
			coroutine->set_user_data(prev_mutable_program, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(prev_immutable_program, SCRIPT_TAG_IMMUTABLE_PROGRAM);
			if (!execution || (execution && *execution != execution::finished) || !exception.empty())
			{
				auto name = entrypoint.get_module_name();
				if (caller != coroutine)
					vm->return_context(coroutine);
				if (exception.empty())
					return layer_exception(execution ? "execution error" : execution.error().message());

				string error_message = stringify::text("(%s) ", exception.type.c_str());
				error_message.append(exception.text);
				error_message.append(exception.origin);
				stringify::replace(error_message, name, SCRIPT_VM "c");
				return layer_exception(std::move(error_message));
			}

			if (caller != coroutine)
				vm->return_context(coroutine);
			return resolver;
		}
		expects_lr<void> program::subexecute(const algorithm::pubkeyhash_t& target, const decimal& value, ccall mutability, const std::string_view& entrypoint, format::variables&& args, void* output_value, int output_type_id) const
		{
			if (entrypoint.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", address_repr(target).to_string().data()));

			auto link = context->get_account_program(target.data);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", address_repr(target).to_string().data(), (int)entrypoint.size(), entrypoint.data()));

			auto transaction = transactions::call();
			transaction.program_call(target, value, entrypoint, std::move(args));
			transaction.asset = context->transaction->asset;
			transaction.gas_price = context->transaction->gas_price;
			transaction.gas_limit = context->get_gas_left();
			transaction.nonce = 0;

			ledger::receipt receipt;
			receipt.transaction_hash = transaction.as_hash();
			receipt.absolute_gas_use = context->block->gas_use;
			receipt.block_number = context->block->number;
			receipt.from = callable();

			auto subcontext = ledger::transaction_context(context->environment, context->block, context->changelog, &transaction, std::move(receipt));
			auto subexecution = transaction.subexecute(&subcontext, [&](asIScriptModule* module_ptr)
			{
				auto script = cell::program(&subcontext, module_ptr);
				return script.execute(mutability, entrypoint, transaction.args, [&](void* result_value, int return_type_id) -> expects_lr<void>
				{
					format::wo_stream stream;
					auto serialization = marshall::store(&stream, result_value, return_type_id);
					if (!serialization)
						return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": return serialization error", address_repr(target).to_string().data(), (int)entrypoint.size(), entrypoint.data()));

					auto reader = stream.ro();
					serialization = marshall::load(reader, output_value, output_type_id);
					if (!serialization)
						return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", address_repr(target).to_string().data(), (int)entrypoint.size(), entrypoint.data(), serialization.error().what()));

					return expectation::met;
				});
			});
			context->receipt.events.insert(context->receipt.events.begin(), subcontext.receipt.events.begin(), subcontext.receipt.events.end());
			context->receipt.relative_gas_use += subcontext.receipt.relative_gas_use;
			return subexecution;
		}
		expects_lr<vector<std::function<void(immediate_context*)>>> program::dispatch_arguments(ccall* mutability, const function& entrypoint, const format::variables& args) const
		{
			VI_ASSERT(mutability != nullptr, "mutability should be set");
			auto function_name = entrypoint.get_name();
			if (!entrypoint.get_namespace().empty())
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			if (function_name == SCRIPT_FUNCTION_CONSTRUCT && *mutability != ccall::upgrade_call)
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			auto* vm = entrypoint.get_vm();
			size_t args_count = entrypoint.get_args_count();
			if (args_count != args.size() + 1)
				return layer_exception(stringify::text("illegal call to function \"%s\": expected exactly %i arguments", entrypoint.get_decl().data(), (int)args_count));

			vector<std::function<void(immediate_context*)>> frames = { };
			frames.reserve(args_count);

			for (size_t i = 0; i < args_count; i++)
			{
				int type_id;
				if (!entrypoint.get_arg(i, &type_id))
					return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), (int)i));

				size_t index = i - 1;
				auto type = vm->get_type_info_by_id(type_id);
				if (i > 0)
				{
					if (index >= args.size())
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), (int)i));

					if (type.flags() & (size_t)object_behaviours::enumerator)
						type_id = (int)type_id::int32_t;

					switch (type_id)
					{
						case (int)type_id::bool_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)args[index].as_boolean()); });
							break;
						case (int)type_id::int8_t:
						case (int)type_id::uint8_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)args[index].as_uint8()); });
							break;
						case (int)type_id::int16_t:
						case (int)type_id::uint16_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg16(i, (uint16_t)args[index].as_uint16()); });
							break;
						case (int)type_id::int32_t:
						case (int)type_id::uint32_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg32(i, (uint32_t)args[index].as_uint32()); });
							break;
						case (int)type_id::int64_t:
						case (int)type_id::uint64_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg64(i, (uint64_t)args[index].as_uint64()); });
							break;
						case (int)type_id::float_t:
						case (int)type_id::double_t:
							return layer_exception("floating point value not permitted");
						default:
						{
							void* address = nullptr;
							auto& value = args[index];
							format::wo_stream stream;
							format::variables_util::serialize_flat_into({ value }, &stream);

							auto reader = stream.ro();
							auto status = marshall::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
							if (!status)
							{
								auto reader_message = format::util::decode_stream(value.as_string());
								reader = format::ro_stream(reader_message); address = nullptr;
								status = marshall::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
								if (!status)
									return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program (%s)", entrypoint.get_decl().data(), i, status.error().what()));
							}

							auto object = cobject(vm, type.get_type_info(), address);
							frames.emplace_back([i, type_id, object = std::move(object)](immediate_context* coroutine) mutable { coroutine->set_arg_object(i, (void*)object.address); });
							break;
						}
					}
				}
				else
				{
					if (!type.is_valid())
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to any instruction set", entrypoint.get_decl().data(), (int)i));

					if (type.get_name() == SCRIPT_TYPE_PMUT)
					{
						if (*mutability != ccall::upgrade_call && *mutability != ccall::paying_call)
							return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_TYPE_PMUT ")", entrypoint.get_decl().data(), (int)i));

						*mutability = ccall::paying_call;
					}
					else if (type.get_name() != SCRIPT_TYPE_PCONST)
					{
						auto name = type.get_name();
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_TYPE_PMUT " or " SCRIPT_TYPE_PCONST ") - \"%s\" type", entrypoint.get_decl().data(), (int)i, name.data()));
					}
					else
						*mutability = ccall::const_call;
					frames.emplace_back([i, index, &args, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (program*)this); });
				}
			}
			return std::move(frames);
		}
		void program::dispatch_event(int event_type_id, const void* object_value, int object_type_id)
		{
		}
		void program::dispatch_exception(immediate_context* coroutine)
		{
		}
		void program::dispatch_coroutine(immediate_context* coroutine)
		{
			auto status = context->burn_gas((uint64_t)ledger::gas_cost::program_iop);
			if (!status)
				coroutine->abort();
		}
		ccall program::mutability_of(const function& entrypoint) const
		{
			int type_id;
			if (entrypoint.get_arg(0, &type_id))
			{
				auto* vm = entrypoint.get_vm();
				auto type = vm->get_type_info_by_id(type_id);
				auto name = type.get_name();
				if (name == SCRIPT_TYPE_PMUT)
					return ccall::paying_call;
			}
			return ccall::const_call;
		}
		algorithm::pubkeyhash_t program::callable() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->callable;
			else if (type == transactions::upgrade::as_instance_type())
				return ((transactions::upgrade*)context->transaction)->get_account();

			return context->receipt.from;
		}
		decimal program::payable() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->value;
			else if (type == transactions::upgrade::as_instance_type())
				return decimal::zero();

			return decimal::nan();
		}
		function program::upgrade_function() const
		{
			return module.get_function_by_name(SCRIPT_FUNCTION_CONSTRUCT);
		}
		string program::function_declaration() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->function;
			else if (type == transactions::upgrade::as_instance_type())
				return string(SCRIPT_FUNCTION_CONSTRUCT);

			return string();
		}
		const format::variables* program::function_arguments() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::upgrade::as_instance_type())
			{
				auto& args = ((transactions::upgrade*)context->transaction)->args;
				return &args;
			}
			else if (type == transactions::call::as_instance_type())
			{
				auto& args = ((transactions::call*)context->transaction)->args;
				return &args;
			}
			return nullptr;
		}
		program* program::fetch_mutable(immediate_context* coroutine)
		{
			return coroutine ? (program*)coroutine->get_user_data(SCRIPT_TAG_MUTABLE_PROGRAM) : nullptr;
		}
		const program* program::fetch_immutable(immediate_context* coroutine)
		{
			return coroutine ? (const program*)coroutine->get_user_data(SCRIPT_TAG_IMMUTABLE_PROGRAM) : nullptr;
		}
		program* program::fetch_mutable_or_throw(immediate_context* coroutine)
		{
			auto* result = fetch_mutable(coroutine);
			if (!result)
				contract::throw_ptr_at(coroutine, exception_repr(exception_repr::category::requirement(), "non-read-only instruction called from read-only program"));

			return result;
		}
		const program* program::fetch_immutable_or_throw(immediate_context* coroutine)
		{
			auto* result = fetch_immutable(coroutine);
			if (!result)
				contract::throw_ptr_at(coroutine, exception_repr(exception_repr::category::requirement(), "real-only instruction called from write-only program"));

			return result;
		}
		bool program::request_gas_mop(size_t difficulty)
		{
			auto* program = program::fetch_immutable();
			if (program && !program->context->burn_gas((size_t)ledger::gas_cost::program_mop * (1 + difficulty)))
			{
				contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view("ran out of gas")));
				return false;
			}
			return true;
		}
	}
}
