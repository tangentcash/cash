#include "svm_abi.h"
#include <gmp.h>
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_QUERY_PREFETCH 16
#define SCRIPT_TAG_ARRAY 19192
#define SCRIPT_TYPENAME_UINT128 "uint128"
#define SCRIPT_TYPENAME_UINT256 "uint256"
#define SCRIPT_TYPENAME_DECIMAL "real320"
#define SCRIPT_TYPENAME_ARRAY "array"
#define SCRIPT_TYPENAME_STRING "string"
#include <iostream>
using namespace vitex::scripting;

namespace tangent
{
	namespace ledger
	{
		namespace svm_abi
		{
			static std::string_view type_name_of(int type_id)
			{
				return svm_container::get()->get_vm()->get_type_info_by_id(type_id).get_name();
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
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view();
							value = type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
							if (name == SCRIPT_TYPENAME_UINT128)
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
							else if (name == SCRIPT_TYPENAME_UINT256)
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
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view();
							if (name == SCRIPT_TYPENAME_UINT128)
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
							else if (name == SCRIPT_TYPENAME_UINT256)
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
							mpf_init_set_d(target, (double)*(float*)value);
							mpf_set_prec(target, 32);
							break;
						case (int)type_id::double_t:
							mpf_init_set_d(target, *(double*)value);
							mpf_set_prec(target, 64);
							break;
						default:
						{
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view();
							value = type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
							if (name == SCRIPT_TYPENAME_DECIMAL)
							{
								auto str = (*(decimal*)value).to_string();
								mpf_init(target);
								mpf_set_prec(target, decimal_repr::target_bits());
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
					switch (type_id)
					{
						case (int)type_id::float_t:
							inout.set_return_float((float)mpf_get_d(target));
							return true;
						case (int)type_id::double_t:
							inout.set_return_double((double)mpf_get_d(target));
							return true;
						default:
						{
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view();
							if (name == SCRIPT_TYPENAME_DECIMAL)
							{
								decimal result = decimal(mpf_to_string(target));
								decimal_repr::truncate_or_throw(result, true);
								new (inout.get_address_of_return_location()) decimal(std::move(result));
								return true;
							}
							return false;
						}
					}
				}
				size_t bits()
				{
					char buffer[1024]; mp_exp_t exp;
					mpf_get_str(buffer, &exp, 10, sizeof(buffer) - 2, target);
					return decimal_repr::estimate_bits((uint32_t)strlen(buffer));
				}
				static bool requires_floating_point(int type_id)
				{
					switch (type_id)
					{
						case (int)type_id::float_t:
						case (int)type_id::double_t:
							return true;
						default:
						{
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view();
							return name == SCRIPT_TYPENAME_DECIMAL;
						}
					}
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

			exception::pointer::pointer() : context(nullptr)
			{
			}
			exception::pointer::pointer(immediate_context* new_context) : context(new_context)
			{
				auto value = context ? context->get_exception_string() : std::string_view();
				if (!value.empty() && (context ? !context->will_exception_be_caught() : false))
				{
					load_exception_data(value);
					origin = load_stack_here();
				}
			}
			exception::pointer::pointer(const std::string_view& value) : context(immediate_context::get())
			{
				load_exception_data(value);
				origin = load_stack_here();
			}
			exception::pointer::pointer(const std::string_view& new_type, const std::string_view& new_text) : type(new_type), text(new_text), context(immediate_context::get())
			{
				origin = load_stack_here();
			}
			exception::pointer::pointer(const string_repr& new_type, const string_repr& new_text) : type(new_type.view()), text(new_text.view()), context(immediate_context::get())
			{
				origin = load_stack_here();
			}
			void exception::pointer::load_exception_data(const std::string_view& value)
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
			string_repr exception::pointer::get_type() const
			{
				return string_repr(type);
			}
			string_repr exception::pointer::get_text() const
			{
				return string_repr(text);
			}
			string_repr exception::pointer::get_what() const
			{
				return string_repr(to_full_exception_string());
			}
			string exception::pointer::to_exception_string() const
			{
				if (empty())
					return string();

				string result = type;
				result.append(std::string_view(":"));
				result.append(text);
				return result;
			}
			string exception::pointer::to_full_exception_string() const
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
			string exception::pointer::load_stack_here() const
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
			bool exception::pointer::empty() const
			{
				return type.empty() && text.empty();
			}

			void exception::throw_ptr_at(immediate_context* context, const pointer& data)
			{
				if (context != nullptr)
					context->set_exception(data.to_exception_string());
			}
			void exception::throw_ptr(const pointer& data)
			{
				throw_ptr_at(immediate_context::get(), data);
			}
			void exception::rethrow_at(immediate_context* context)
			{
				if (context != nullptr)
					context->set_exception(context->get_exception_string());
			}
			void exception::rethrow()
			{
				rethrow_at(immediate_context::get());
			}
			bool exception::has_exception_at(immediate_context* context)
			{
				return context ? !context->get_exception_string().empty() : false;
			}
			bool exception::has_exception()
			{
				return has_exception_at(immediate_context::get());
			}
			exception::pointer exception::get_exception_at(immediate_context* context)
			{
				return pointer(context);
			}
			exception::pointer exception::get_exception()
			{
				return get_exception_at(immediate_context::get());
			}
			expects_vm<void> exception::generator_callback(preprocessor*, const std::string_view& path, string& code)
			{
				return parser::replace_inline_preconditions("throw", code, [](const std::string_view& expression) -> expects_vm<string>
				{
					string result = "exception::throw(";
					result.append(expression);
					result.append(1, ')');
					return result;
				});
			}

			std::string_view exception::category::generic()
			{
				return std::string_view("generic_error");
			}
			std::string_view exception::category::requirement()
			{
				return std::string_view("requirement_error");
			}
			std::string_view exception::category::argument()
			{
				return std::string_view("argument_error");
			}
			std::string_view exception::category::memory()
			{
				return std::string_view("memory_error");
			}
			std::string_view exception::category::storage()
			{
				return std::string_view("storage_error");
			}
			std::string_view exception::category::execution()
			{
				return std::string_view("execution_error");
			}

			array_repr::array_repr(uint32_t length, asITypeInfo* info) noexcept : obj_type(info), buffer(nullptr), element_size(0), sub_type_id(-1)
			{
				VI_ASSERT(info && string(obj_type.get_name()) == SCRIPT_TYPENAME_ARRAY, "array type is invalid");
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
				VI_ASSERT(obj_type.is_valid() && string(obj_type.get_name()) == SCRIPT_TYPENAME_ARRAY, "array type is invalid");
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
				VI_ASSERT(info && string(vitex::scripting::type_info(info).get_name()) == SCRIPT_TYPENAME_ARRAY, "array type is invalid");
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
				else if (sub_type_id == (uint32_t)type_id::bool_t || sub_type_id == (uint32_t)type_id::int8_t || sub_type_id == (uint32_t)type_id::uint8_t)
					*(char*)ptr = *(char*)value;
				else if (sub_type_id == (uint32_t)type_id::int16_t || sub_type_id == (uint32_t)type_id::uint16_t)
					*(short*)ptr = *(short*)value;
				else if (sub_type_id == (uint32_t)type_id::int32_t || sub_type_id == (uint32_t)type_id::uint32_t || sub_type_id == (uint32_t)type_id::float_t || sub_type_id > (uint32_t)type_id::double_t)
					*(int*)ptr = *(int*)value;
				else if (sub_type_id == (uint32_t)type_id::int64_t || sub_type_id == (uint32_t)type_id::uint64_t || sub_type_id == (uint32_t)type_id::double_t)
					*(double*)ptr = *(double*)value;
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

				sbuffer* new_buffer = gas_allocate<sbuffer>(sizeof(sbuffer) - 1 + (size_t)element_size * (size_t)max_elements);
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", start, start + count, buffer ? buffer->num_elements : 0)));

				if (start + count > buffer->num_elements)
					count = buffer->num_elements - start;

				destroy(buffer, start, start + count);
				memmove(buffer->data + start * (size_t)element_size, buffer->data + (start + count) * (size_t)element_size, (size_t)(buffer->num_elements - start - count) * (size_t)element_size);
				buffer->num_elements -= count;
			}
			void array_repr::remove_if(void* value, uint32_t start_at)
			{
				scache* cache; uint32_t count = size();
				if (!is_eligible_for_find(&cache) || !count)
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
					sbuffer* new_buffer = gas_allocate<sbuffer>(sizeof(sbuffer) - 1 + size * count);
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

				exception::throw_ptr(exception::pointer(exception::category::memory(), stringify::text("size %i is illegal (max_size: %i)", num_elements, max_size)));
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));

				resize(1, index);
				set_value(index, value);
			}
			void array_repr::insert_at(uint32_t index, const array_repr& array)
			{
				if (index > (buffer ? buffer->num_elements : 0))
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));

				if (obj_type.get_type_info() != array.obj_type.get_type_info())
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("array types (%s, %s) are incompatible", obj_type.get_name().data(), array.obj_type.get_name().data())));

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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
					return nullptr;
				}

				return at(0);
			}
			const void* array_repr::front() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
					return nullptr;
				}

				return at(0);
			}
			void* array_repr::back()
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
					return nullptr;
				}

				return at(size() - 1);
			}
			const void* array_repr::back() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", buffer ? buffer->num_elements : 0)));
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
				*buffer_ptr = gas_allocate<sbuffer>(sizeof(sbuffer) - 1 + (size_t)element_size * (size_t)num_elements);
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
				if (length >= 2)
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
					case (uint32_t)type_id::float_t: return COMPARE(float);
					case (uint32_t)type_id::double_t: return COMPARE(double);
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
					case (uint32_t)type_id::float_t: return COMPARE(float);
					case (uint32_t)type_id::double_t: return COMPARE(double);
					default: return COMPARE(signed int);
#undef COMPARE
				}
			}
			uint32_t array_repr::find_by_ref(void* value, uint32_t start_at) const
			{
				uint32_t length = size();
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
				if (!is_eligible_for_find(&cache) || !count)
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index1, index2, buffer->num_elements)));

				unsigned char swap[16];
				copy(swap, get_array_item_pointer(index1));
				copy(get_array_item_pointer(index1), get_array_item_pointer(index2));
				copy(get_array_item_pointer(index2), swap);
			}
			void array_repr::sort(asIScriptFunction* callback)
			{
				scache* cache; uint32_t count = size();
				if (!is_eligible_for_sort(&cache) || count < 2)
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

				umutex<std::mutex> unique(svm_container::get()->exclusive);
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
					exception::throw_ptr(exception::pointer(exception::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

				return result;
			}
			array_repr* array_repr::create(asITypeInfo* info, uint32_t length, void* default_value)
			{
				array_repr* result = new array_repr(length, default_value, info);
				if (!result)
					exception::throw_ptr(exception::pointer(exception::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

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
				if (type_id == (uint32_t)type_id::void_t)
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
							engine->write_message(SCRIPT_TYPENAME_ARRAY, 0, 0, log_category::err, "The subtype has no default constructor");
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
							engine->write_message(SCRIPT_TYPENAME_ARRAY, 0, 0, log_category::err, "The subtype has no default factory");
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
						exception::throw_ptr(exception::pointer(exception::category::argument(), "too many opCmp implementations for find function"));
					else
						exception::throw_ptr(exception::pointer(exception::category::argument(), "no opCmp implementation for find function"));
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
						exception::throw_ptr(exception::pointer(exception::category::argument(), "too many opCmp implementations for find function"));
					else
						exception::throw_ptr(exception::pointer(exception::category::argument(), "no opCmp implementation for find function"));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, size())));
					return nullptr;
				}

				return data() + index;
			}
			const char* string_repr::front() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", size())));
					return nullptr;
				}

				return data();
			}
			const char* string_repr::back() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", size())));
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [0; 1) is out of bounds (size: %i)", size())));

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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("range [-1; -2) is out of bounds (size: %i)", size())));

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
				if (empty())
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
				size_t result = view().rfind(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::rfind_char_offset(uint8_t other, uint32_t offset) const
			{
				size_t result = view().rfind(other, offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::find(const string_repr& other, uint32_t offset) const
			{
				size_t result = view().find(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::find_char(uint8_t other, uint32_t offset) const
			{
				size_t result = view().find(other, offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::find_first_of(const string_repr& other, uint32_t offset) const
			{
				size_t result = view().find_first_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::find_first_not_of(const string_repr& other, uint32_t offset) const
			{
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
				size_t result = view().find_last_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			uint32_t string_repr::find_last_not_of_offset(const string_repr& other, uint32_t offset) const
			{
				size_t result = view().find_last_not_of(other.view(), offset == npos ? std::string_view::npos : (size_t)offset);
				return result == std::string_view::npos ? npos : (uint32_t)result;
			}
			array_repr* string_repr::split(const string_repr& delimiter) const
			{
				virtual_machine* vm = virtual_machine::get();
				asITypeInfo* array_type = vm->get_type_info_by_decl(SCRIPT_TYPENAME_ARRAY "<" SCRIPT_TYPENAME_STRING ">@").get_type_info();
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
					char* copy = gas_allocate<char>(heap.capacity + 1);
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
					heap.data = gas_allocate<char>(heap.capacity + 1);
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
			string_repr string_repr::to_string_address(const address& other)
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
				double capacity = (double)stack_capacity, page = (double)required_size;
				return (uint32_t)(std::ceil(page / capacity) * capacity);
			}

			void decimal_repr::custom_constructor_bool(decimal* base, bool value)
			{
				new(base) decimal(value ? "1" : "0");
				truncate_or_throw(*base, true);
			}
			void decimal_repr::custom_constructor_string(decimal* base, const string_repr& value)
			{
				new(base) decimal(value.view());
				truncate_or_throw(*base, true);
			}
			void decimal_repr::custom_constructor_copy(decimal* base, const decimal& value)
			{
				new(base) decimal(value);
				truncate_or_throw(*base, true);
			}
			void decimal_repr::custom_constructor(decimal* base)
			{
				new(base) decimal(decimal::zero());
				truncate_or_throw(*base, true);
			}
			bool decimal_repr::is_not_zero_or_nan(decimal& base)
			{
				return !base.is_zero_or_nan();
			}
			bool decimal_repr::truncate_or_throw(decimal& base, bool require_decimal_precision)
			{
				auto* vm = virtual_machine::get();
				if (!vm)
					return true;

				auto& message = protocol::now().message;
				if (require_decimal_precision || base.decimal_size() > message.decimal_precision)
					base.truncate(message.decimal_precision);

				bool throws = base.integer_size() > message.integer_precision || base.decimal_size() > message.decimal_precision;
				if (throws)
					exception::throw_ptr(exception::pointer(exception::category::memory(), stringify::text("fixed point overflow of number \"%s\" (sp: %i, fp: %i)", base.to_string().c_str(), base.integer_size(), base.decimal_size())));
				return !throws;
			}
			uint128_t decimal_repr::to_uint128(decimal& base)
			{
				decimal copy = base;
				copy.truncate(0);
				return uint128_t(copy.to_string());
			}
			uint256_t decimal_repr::to_uint256(decimal& base)
			{
				decimal copy = base;
				copy.truncate(0);
				return uint256_t(copy.to_string());
			}
			string_repr decimal_repr::to_string(decimal& base)
			{
				return string_repr(base.to_string());
			}
			string_repr decimal_repr::to_exponent(decimal& base)
			{
				return string_repr(base.to_exponent());
			}
			decimal decimal_repr::negate(decimal& base)
			{
				decimal result = -base;
				truncate_or_throw(result, false);
				return result;
			}
			decimal& decimal_repr::mul_eq(decimal& base, const decimal& v)
			{
				truncate_or_throw(base *= v, false);
				return base;
			}
			decimal& decimal_repr::div_eq(decimal& base, const decimal& v)
			{
				truncate_or_throw(base, true);
				truncate_or_throw(base /= v, false);
				return base;
			}
			decimal& decimal_repr::add_eq(decimal& base, const decimal& v)
			{
				truncate_or_throw(base += v, false);
				return base;
			}
			decimal& decimal_repr::sub_eq(decimal& base, const decimal& v)
			{
				truncate_or_throw(base -= v, false);
				return base;
			}
			decimal& decimal_repr::fpp(decimal& base)
			{
				truncate_or_throw(++base, false);
				return base;
			}
			decimal& decimal_repr::fmm(decimal& base)
			{
				truncate_or_throw(--base, false);
				return base;
			}
			decimal& decimal_repr::pp(decimal& base)
			{
				truncate_or_throw(base++, false);
				return base;
			}
			decimal& decimal_repr::mm(decimal& base)
			{
				truncate_or_throw(base--, false);
				return base;
			}
			bool decimal_repr::eq(decimal& base, const decimal& right)
			{
				return base == right;
			}
			int decimal_repr::cmp(decimal& base, const decimal& right)
			{
				if (base == right)
					return 0;

				return base > right ? 1 : -1;
			}
			decimal decimal_repr::add(const decimal& left, const decimal& right)
			{
				decimal result = left + right;
				truncate_or_throw(result, false);
				return result;
			}
			decimal decimal_repr::sub(const decimal& left, const decimal& right)
			{
				decimal result = left - right;
				truncate_or_throw(result, false);
				return result;
			}
			decimal decimal_repr::mul(const decimal& left, const decimal& right)
			{
				decimal result = left * right;
				truncate_or_throw(result, false);
				return result;
			}
			decimal decimal_repr::div(const decimal& left, const decimal& right)
			{
				decimal left_allocated = left;
				return div_eq(left_allocated, right);
			}
			decimal decimal_repr::per(const decimal& left, const decimal& right)
			{
				decimal result = left % right;
				truncate_or_throw(result, false);
				return result;
			}
			decimal decimal_repr::from(const string_repr& data, uint8_t base)
			{
				decimal result = decimal::from(data.view(), base);
				truncate_or_throw(result, false);
				return result;
			}
			uint32_t decimal_repr::estimate_bits(uint32_t digits)
			{
				static double log10 = log2(10);
				auto bits = (uint32_t)ceil(log10 * (double)digits);
				return bits + bits % 2;
			}
			uint32_t decimal_repr::target_bits()
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

			address::address(const algorithm::pubkeyhash_t& owner) : hash(owner)
			{
			}
			address::address(const string_repr& address)
			{
				algorithm::signing::decode_address(address.view(), hash);
			}
			address::address(const uint256_t& owner_data)
			{
				uint8_t owner_raw_data[32];
				owner_data.encode(owner_raw_data);
				memcpy(hash.data, owner_raw_data, sizeof(hash.data));
			}
			void address::pay(const uint256_t& asset, const decimal& value)
			{
				auto* program = svm_program::fetch_mutable_or_throw();
				if (!program || !value.is_positive())
					return;

				auto payment = program->context->apply_payment(asset, program->callable().data, hash.data, value);
				if (!payment)
					return exception::throw_ptr(exception::pointer(exception::category::execution(), std::string_view(payment.error().message())));
			}
			decimal address::balance_of(const uint256_t& asset) const
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->get_account_balance(asset, hash.data).or_else(states::account_balance(algorithm::pubkeyhash_t(), asset, nullptr)).get_balance() : decimal::zero();
			}
			string_repr address::to_string() const
			{
				string address;
				algorithm::signing::encode_address(hash, address);
				return string_repr(std::string_view(address));
			}
			uint256_t address::to_public_key_hash() const
			{
				uint8_t data[32] = { 0 };
				memcpy(data, hash.data, sizeof(algorithm::pubkeyhash_t));

				uint256_t numeric = 0;
				numeric.decode(data);
				return numeric;
			}
			bool address::empty() const
			{
				return hash.empty();
			}
			void address::call(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				auto object = (address*)inout.get_object_address();
				auto& function = *inout.get_arg_object<string_repr>(0);
				void* output_value = inout.get_address_of_return_location();
				int output_type_id = inout.get_return_addressable_type_id();
				VI_ASSERT(inout.get_generic() != nullptr, "generic context should be set");
				VI_ASSERT(object != nullptr, "this object should be set");

				format::wo_stream stream;
				for (size_t i = 1; i < inout.get_args_count(); i++)
				{
					void* input_value = inout.get_arg_address(i);
					int input_type_id = inout.get_arg_type_id(i);
					auto serialization = svm_marshalling::store(&stream, input_value, input_type_id);
					if (!serialization)
						return exception::throw_ptr(exception::pointer(exception::category::execution(), stringify::text("call to %s::%.*s: %s (argument: %i)", object->to_string().data(), (int)function.size(), function.data(), serialization.error().what(), (int)i - 1)));
				}

				auto reader = stream.ro(); format::variables function_args;
				if (!reader.data.empty() && !format::variables_util::deserialize_flat_from(reader, &function_args))
					return exception::throw_ptr(exception::pointer(exception::category::execution(), stringify::text("call to %s::%.*s: argument pack builder failed", object->to_string().data(), (int)function.size(), function.data())));

				auto* program = svm_program::fetch_mutable();
				if (program != nullptr)
				{
					auto execution = program->subexecute(object->hash, svm_call::mutable_call, function.view(), std::move(function_args), output_value, output_type_id);
					if (!execution)
						return exception::throw_ptr(exception::pointer(exception::category::execution(), std::string_view(execution.error().message())));
				}
				else
				{
					auto* immutable_program = svm_program::fetch_immutable_or_throw();
					if (immutable_program != nullptr)
					{
						auto execution = immutable_program->subexecute(object->hash, svm_call::immutable_call, function.view(), std::move(function_args), output_value, output_type_id);
						if (!execution)
							return exception::throw_ptr(exception::pointer(exception::category::execution(), std::string_view(execution.error().message())));
					}
				}
			}
			bool address::equals(const address& a, const address& b)
			{
				return a.hash.equals(b.hash.data);
			}

			abi::abi(const string_repr& data) : output(data.view())
			{
				input.data = output.data;
			}
			void abi::seek(uint32_t offset)
			{
				input.seek = (size_t)offset;
			}
			void abi::clear()
			{
				input.clear();
				output.clear();
			}
			void abi::merge(const string_repr& value)
			{
				output.data.append(value.data(), (size_t)value.size());
				input.data = output.data;
			}
			void abi::wstr(const string_repr& value)
			{
				output.write_string(value.view());
				input.data = output.data;
			}
			void abi::wrstr(const string_repr& value)
			{
				output.write_string_raw(value.view());
				input.data = output.data;
			}
			void abi::wdecimal(const decimal& value)
			{
				output.write_decimal(value);
				input.data = output.data;
			}
			void abi::wboolean(bool value)
			{
				output.write_boolean(value);
				input.data = output.data;
			}
			void abi::wuint160(const address& value)
			{
				output.write_string(value.hash.optimized_view());
				input.data = output.data;
			}
			void abi::wuint256(const uint256_t& value)
			{
				output.write_integer(value);
				input.data = output.data;
			}
			bool abi::rstr(string_repr& value)
			{
				string intermediate_value;
				bool result = input.read_string(input.read_type(), &intermediate_value);
				value = std::string_view(intermediate_value);
				return result;
			}
			bool abi::rdecimal(decimal& value)
			{
				return input.read_decimal_or_integer(input.read_type(), &value);
			}
			bool abi::rboolean(bool& value)
			{
				return input.read_boolean(input.read_type(), &value);
			}
			bool abi::ruint160(address& value)
			{
				string_repr result;
				if (!rstr(result))
					return false;

				algorithm::pubkeyhash_t blob;
				if (!algorithm::encoding::decode_bytes(result.view(), blob.data, sizeof(blob.data)))
					return false;

				value = address(blob);
				return true;
			}
			bool abi::ruint256(uint256_t& value)
			{
				return input.read_integer(input.read_type(), &value);
			}
			string_repr abi::data()
			{
				return string_repr(std::string_view(output.data));
			}

			filter::filter() : comparator(ledger::filter_comparator::equal), order(ledger::filter_order::ascending), value(0)
			{
			}
			filter::filter(ledger::filter_comparator new_condition, ledger::filter_order new_order, const uint256_t& new_value) : comparator(new_condition), order(new_order), value(new_value)
			{
			}
			filter filter::greater(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::greater, order, value };
			}
			filter filter::greater_equal(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::greater_equal, order, value };
			}
			filter filter::equal(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::equal, order, value };
			}
			filter filter::not_equal(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::not_equal, order, value };
			}
			filter filter::less(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::less, order, value };
			}
			filter filter::less_equal(const uint256_t& value, ledger::filter_order order)
			{
				return { ledger::filter_comparator::less_equal, order, value };
			}

			void xc::reset()
			{
				offset = 0;
			}
			bool xc::next(void* object_value, int object_type_id)
			{
				return next_row_ranked(object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool xc::next_row(void* object_value, int object_type_id, void* row_value, int row_type_id)
			{
				return next_row_ranked(object_value, object_type_id, row_value, row_type_id, nullptr);
			}
			bool xc::next_row_ranked(void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				auto& cache = ((svm_program*)program)->cache.columns[column.data];
			retry:
				auto it = cache.find((size_t)offset);
				if (it == cache.end())
				{
					auto results = program->context->get_account_multiforms_by_column(program->callable().data, column.data, (size_t)offset, count);
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
					auto status = svm_marshalling::load(stream, object_value, object_type_id);
					if (!status)
						return false;
				}

				if (row_value != nullptr && row_type_id != (int)type_id::void_t)
				{
					auto stream = format::ro_stream(it->second->row);
					auto status = svm_marshalling::load(stream, row_value, row_type_id);
					if (!status)
						return false;
				}

				if (filter_value != nullptr)
					*filter_value = it->second->filter;

				++offset;
				return true;
			}
			xc xc::from(const void* column_value, int column_type_id, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return xc();

				xc result;
				result.offset = 0;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			void xfc::reset()
			{
				offset = 0;
			}
			bool xfc::next(void* object_value, int object_type_id)
			{
				return next_row_ranked(object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool xfc::next_row(void* object_value, int object_type_id, void* row_value, int row_type_id)
			{
				return next_row_ranked(object_value, object_type_id, row_value, row_type_id, nullptr);
			}
			bool xfc::next_row_ranked(void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				auto& cache = ((svm_program*)program)->cache.columns[column.data];
			retry:
				auto it = cache.find((size_t)offset);
				if (it == cache.end())
				{
					auto results = program->context->get_account_multiforms_by_column_filter(program->callable().data, column.data, query.comparator, query.value, query.order, (size_t)offset, count);
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
					auto status = svm_marshalling::load(stream, object_value, object_type_id);
					if (!status)
						return false;
				}

				if (row_value != nullptr && row_type_id != (int)type_id::void_t)
				{
					auto stream = format::ro_stream(it->second->row);
					auto status = svm_marshalling::load(stream, row_value, row_type_id);
					if (!status)
						return false;
				}

				if (filter_value != nullptr)
					*filter_value = it->second->filter;

				++offset;
				return true;
			}
			xfc xfc::from(const void* column_value, int column_type_id, const filter& query, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return xfc();

				xfc result;
				result.query = query;
				result.offset = 0;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			void yc::reset()
			{
				offset = 0;
			}
			bool yc::next(void* object_value, int object_type_id)
			{
				return next_column_ranked(object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool yc::next_column(void* object_value, int object_type_id, void* column_value, int column_type_id)
			{
				return next_column_ranked(object_value, object_type_id, column_value, column_type_id, nullptr);
			}
			bool yc::next_column_ranked(void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				auto& cache = ((svm_program*)program)->cache.rows[row.data];
			retry:
				auto it = cache.find((size_t)offset);
				if (it == cache.end())
				{
					auto results = program->context->get_account_multiforms_by_row(program->callable().data, row.data, (size_t)offset, count);
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
					auto status = svm_marshalling::load(stream, object_value, object_type_id);
					if (!status)
						return false;
				}

				if (column_value != nullptr && column_type_id != (int)type_id::void_t)
				{
					auto stream = format::ro_stream(it->second->column);
					auto status = svm_marshalling::load(stream, column_value, column_type_id);
					if (!status)
						return false;
				}

				if (filter_value != nullptr)
					*filter_value = it->second->filter;

				++offset;
				return true;
			}
			yc yc::from(const void* row_value, int row_type_id, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return yc();

				yc result;
				result.offset = 0;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.row, row_value, row_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			void yfc::reset()
			{
				offset = 0;
			}
			bool yfc::next(void* object_value, int object_type_id)
			{
				return next_column_ranked(object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool yfc::next_column(void* object_value, int object_type_id, void* column_value, int column_type_id)
			{
				return next_column_ranked(object_value, object_type_id, column_value, column_type_id, nullptr);
			}
			bool yfc::next_column_ranked(void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				auto& cache = ((svm_program*)program)->cache.rows[row.data];
			retry:
				auto it = cache.find((size_t)offset);
				if (it == cache.end())
				{
					auto results = program->context->get_account_multiforms_by_row_filter(program->callable().data, row.data, query.comparator, query.value, query.order, (size_t)offset, count);
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
					auto status = svm_marshalling::load(stream, object_value, object_type_id);
					if (!status)
						return false;
				}

				if (column_value != nullptr && column_type_id != (int)type_id::void_t)
				{
					auto stream = format::ro_stream(it->second->column);
					auto status = svm_marshalling::load(stream, column_value, column_type_id);
					if (!status)
						return false;
				}

				if (filter_value != nullptr)
					*filter_value = it->second->filter;

				++offset;
				return true;
			}
			yfc yfc::from(const void* row_value, int row_type_id, const filter& query, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return yfc();

				yfc result;
				result.query = query;
				result.offset = 0;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.row, row_value, row_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			bool log::emit(const void* object_value, int object_type_id)
			{
				auto* program = svm_program::fetch_mutable_or_throw();
				return program ? program->emit_event(object_value, object_type_id) : false;
			}
			bool log::into(int32_t event_index, void* object_value, int object_type_id)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				auto type = svm_container::get()->get_vm()->get_type_info_by_id(object_type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("?");
				auto id = algorithm::hashing::hash32d(name);
				auto* event = event_index < 0 ? program->context->receipt.reverse_find_event(id, (size_t)(-event_index)) : program->context->receipt.find_event(id, (size_t)event_index);
				if (!event)
					return false;

				format::wo_stream writer;
				if (!format::variables_util::serialize_flat_into(*event, &writer))
					return false;

				format::ro_stream reader = writer.ro();
				return !!svm_marshalling::load(reader, object_value, object_type_id);
			}
			void log::get(asIScriptGeneric* generic)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return;

				generic_context inout = generic_context(generic);
				int32_t event_index = inout.get_arg_dword(0);
				void* object_value = inout.get_address_of_return_location();
				int object_type_id = inout.get_return_addressable_type_id();
				auto type = svm_container::get()->get_vm()->get_type_info_by_id(object_type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("?");
				auto id = algorithm::hashing::hash32d(name);
				auto* event = event_index < 0 ? program->context->receipt.reverse_find_event(id, (size_t)(-event_index-1)) : program->context->receipt.find_event(id, (size_t)event_index);
				if (!event)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("event %.*s[%i] not found", (int)name.size(), name.data(), event_index)));

				format::wo_stream writer;
				if (!format::variables_util::serialize_flat_into(*event, &writer))
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("event %.*s[%i] store failed", (int)name.size(), name.data(), event_index)));

				format::ro_stream reader = writer.ro();
				auto status = svm_marshalling::load(reader, object_value, object_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), stringify::text("event %.*s[%i] load failed", (int)name.size(), name.data(), event_index)));
			}

			void sv::store(const void* index_value, int index_type_id, const void* object_value, int object_type_id)
			{
				auto* program = svm_program::fetch_mutable_or_throw();
				if (!program)
					return;

				format::wo_stream index;
				auto status = svm_marshalling::store(&index, index_value, index_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				format::wo_stream stream;
				status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				if (!object_value || object_type_id == (int)type_id::void_t)
				{
					auto requires_erase = program->context->get_account_uniform(program->callable().data, index.data);
					if (!requires_erase)
						return;
				}

				auto data = program->context->apply_account_uniform(program->callable().data, index.data, stream.data);
				if (!data)
					return exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(data.error().message())));
			}
			bool sv::load(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				format::wo_stream index;
				auto status = svm_marshalling::store(&index, index_value, index_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				auto data = program->context->get_account_uniform(program->callable().data, index.data);
				if (!data)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(data.error().message())));
					return false;
				}

				format::ro_stream stream = format::ro_stream(data->data);
				status = svm_marshalling::load(stream, object_value, object_type_id);
				if (!status)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(status.error().message())));
					return false;
				}

				return true;
			}
			void sv::set(const void* index_value, int index_type_id, void* object_value, int object_type_id)
			{
				store(index_value, index_type_id, object_value, object_type_id);
			}
			void sv::erase(const void* index_value, int index_type_id)
			{
				store(index_value, index_type_id, nullptr, (int)type_id::void_t);
			}
			void sv::set_if(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool condition)
			{
				if (condition)
					set(index_value, index_type_id, object_value, object_type_id);
				else
					erase(index_value, index_type_id);
			}
			bool sv::has(const void* index_value, int index_type_id)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				format::wo_stream index;
				auto status = svm_marshalling::store(&index, index_value, index_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				auto data = program->context->get_account_uniform(program->callable().data, index.data);
				return data && !data->data.empty();
			}
			bool sv::into(const void* index_value, int index_type_id, void* object_value, int object_type_id)
			{
				return load(index_value, index_type_id, object_value, object_type_id, false);
			}
			void sv::get(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				void* index_value = inout.get_arg_address(0);
				int index_type_id = inout.get_arg_type_id(0);
				void* object_value = inout.get_address_of_return_location();
				int object_type_id = inout.get_return_addressable_type_id();
				load(index_value, index_type_id, object_value, object_type_id, true);
			}

			void qsv::store(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value)
			{
				auto* program = svm_program::fetch_mutable_or_throw();
				if (!program)
					return;

				format::wo_stream column;
				auto status = svm_marshalling::store(&column, column_value, column_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				format::wo_stream row;
				status = svm_marshalling::store(&row, row_value, row_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				format::wo_stream stream;
				status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
				if (!status)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				if (!object_value || object_type_id == (int)type_id::void_t)
				{
					auto requires_erase = program->context->get_account_multiform(program->callable().data, column.data, row.data);
					if (!requires_erase)
						return;
				}

				auto data = program->context->apply_account_multiform(program->callable().data, column.data, row.data, stream.data, filter_value);
				if (!data)
					return exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(data.error().message())));

				auto it = program->cache.columns.find(column.data);
				if (it != program->cache.columns.end())
					it->second.clear();

				it = program->cache.rows.find(row.data);
				if (it != program->cache.rows.end())
					it->second.clear();
			}
			bool qsv::load(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				format::wo_stream column;
				auto status = svm_marshalling::store(&column, column_value, column_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				format::wo_stream row;
				status = svm_marshalling::store(&row, row_value, row_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				auto data = program->context->get_account_multiform(program->callable().data, column.data, row.data);
				if (!data)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(data.error().message())));
					return false;
				}

				format::ro_stream stream = format::ro_stream(data->data);
				status = svm_marshalling::load(stream, object_value, object_type_id);
				if (!status)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), std::string_view(status.error().message())));
					return false;
				}

				if (filter_value != nullptr)
					*filter_value = data->filter;

				return true;
			}
			void qsv::set_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value)
			{
				store(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
			}
			void qsv::set(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
			{
				set_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0);
			}
			void qsv::erase(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
			{
				store(column_value, column_type_id, row_value, row_type_id, nullptr, (int)type_id::void_t, 0);
			}
			void qsv::set_if_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value, bool condition)
			{
				if (condition)
					set_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
				else
					erase(column_value, column_type_id, row_value, row_type_id);
			}
			void qsv::set_if(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool condition)
			{
				return set_if_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0, condition);
			}
			bool qsv::into_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value)
			{
				return load(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value, false);
			}
			bool qsv::into(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
			{
				return into_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr);
			}
			bool qsv::has(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return false;

				format::wo_stream column;
				auto status = svm_marshalling::store(&column, column_value, column_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				format::wo_stream row;
				status = svm_marshalling::store(&row, row_value, row_type_id);
				if (!status)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));
					return false;
				}

				auto data = program->context->get_account_multiform(program->callable().data, column.data, row.data);
				return data && !data->data.empty();
			}
			void qsv::get(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				void* column_value = inout.get_arg_address(0);
				int column_type_id = inout.get_arg_type_id(0);
				void* row_value = inout.get_arg_address(1);
				int row_type_id = inout.get_arg_type_id(1);
				void* object_value = inout.get_address_of_return_location();
				int object_type_id = inout.get_return_addressable_type_id();
				load(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr, true);
			}

			address block::proposer()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return address();

				size_t index = (size_t)program->context->block->priority;
				return index < program->context->environment->producers.size() ? address(algorithm::pubkeyhash_t(program->context->environment->producers[index].owner)) : address();
			}
			uint256_t block::parent_hash()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->parent_hash : uint256_t((uint8_t)0);
			}
			uint256_t block::gas_use()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->gas_use : uint256_t((uint8_t)0);
			}
			uint256_t block::gas_left()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->gas_limit - program->context->block->gas_use : uint256_t((uint8_t)0);
			}
			uint256_t block::gas_limit()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->gas_limit : uint256_t((uint8_t)0);
			}
			uint128_t block::difficulty()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->target.difficulty() : uint128_t((uint8_t)0);
			}
			uint64_t block::time()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return 0;

				uint64_t milliseconds = program->context->block->generation_time - program->context->block->generation_time % protocol::now().policy.consensus_proof_time;
				return milliseconds / 1000;
			}
			uint64_t block::time_between(uint64_t block_number_a, uint64_t block_number_b)
			{
				uint64_t left = std::min(block_number_a, block_number_b);
				uint64_t right = std::max(block_number_a, block_number_b);
				return (right - left) * protocol::now().policy.consensus_proof_time / 1000;
			}
			uint64_t block::priority()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->priority : 0;
			}
			uint64_t block::number()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->block->number : 0;
			}

			decimal tx::value()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->payable() : decimal::nan();
			}
			bool tx::paid()
			{
				return value().is_positive();
			}
			address tx::from()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? address(program->context->receipt.from) : address();
			}
			address tx::to()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? address(program->callable()) : address();
			}
			string_repr tx::blockchain()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? string_repr(algorithm::asset::blockchain_of(program->context->transaction->asset)) : string_repr();
			}
			string_repr tx::token()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? string_repr(algorithm::asset::token_of(program->context->transaction->asset)) : string_repr();
			}
			string_repr tx::contract()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? string_repr(algorithm::asset::checksum_of(program->context->transaction->asset)) : string_repr();
			}
			decimal tx::gas_price()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->transaction->gas_price : decimal::zero();
			}
			uint256_t tx::gas_use()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->receipt.relative_gas_use : uint256_t((uint8_t)0);
			}
			uint256_t tx::gas_left()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->get_gas_left() : uint256_t((uint8_t)0);
			}
			uint256_t tx::gas_limit()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->transaction->gas_limit : uint256_t((uint8_t)0);
			}
			uint256_t tx::asset()
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				return program ? program->context->transaction->asset : uint256_t((uint8_t)0);
			}

			uint256_t currency::from_decimal(const decimal& value)
			{
				if (value.is_nan())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), string_repr(value.to_string() + " as uint256 - not a number")));
					return 0;
				}

				if (value.is_negative())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), string_repr(value.to_string() + " as uint256 - negative number")));
					return 0;
				}

				if (value.integer_size() > protocol::now().message.integer_precision || value.decimal_size() > protocol::now().message.decimal_precision)
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), string_repr(value.to_string() + " as uint256 - fixed point overflow")));
					return 0;
				}

				auto copy = value;
				copy *= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.decimal_precision);

				auto result = uint256_t::max();
				if (copy < result.to_decimal())
					result = uint256_t(copy.truncate(0).to_string(), 10);
				return result;
			}
			decimal currency::to_decimal(const uint256_t& value)
			{
				auto precision = protocol::now().message.decimal_precision;
				auto result = value.to_decimal().truncate(precision);
				result /= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.decimal_precision);
				return result;
			}
			uint256_t currency::id_of(const string_repr& blockchain, const string_repr& token, const string_repr& contract_address)
			{
				return algorithm::asset::id_of(blockchain.view(), token.view(), contract_address.view());
			}
			string_repr currency::blockchain_of(const uint256_t& value)
			{
				return string_repr(algorithm::asset::blockchain_of(value));
			}
			string_repr currency::token_of(const uint256_t& value)
			{
				return string_repr(algorithm::asset::token_of(value));
			}
			string_repr currency::checksum_of(const uint256_t& value)
			{
				return string_repr(algorithm::asset::checksum_of(value));
			}
			string_repr currency::name_of(const uint256_t& value)
			{
				return string_repr(algorithm::asset::name_of(value));
			}

			string_repr repr::encode_bytes256(const uint256_t& value)
			{
				uint8_t data[32];
				value.encode(data);
				return string_repr(std::string_view((char*)data, sizeof(data)));
			}
			uint256_t repr::decode_bytes256(const string_repr& value)
			{
				uint8_t data[32];
				memcpy(data, value.data(), std::min(sizeof(data), (size_t)value.size()));

				uint256_t buffer;
				buffer.decode(data);
				return buffer;
			}

			address dsa::erecover160(const uint256_t& hash, const string_repr& signature)
			{
				if (signature.size() != sizeof(algorithm::hashsig_t))
					return address();

				algorithm::pubkeyhash_t public_key_hash;
				if (!algorithm::signing::recover_hash(hash, public_key_hash, (uint8_t*)signature.data()) || public_key_hash.empty())
					return address();

				return address(public_key_hash);
			}
			string_repr dsa::erecover264(const uint256_t& hash, const string_repr& signature)
			{
				if (signature.size() != sizeof(algorithm::hashsig_t))
					return string_repr();

				algorithm::pubkey_t public_key;
				if (!algorithm::signing::recover(hash, public_key, (uint8_t*)signature.data()) || public_key.empty())
					return string_repr();

				return string_repr(public_key.view());
			}

			string_repr alg::crc32(const string_repr& data)
			{
				uint8_t buffer[32];
				uint256_t value = algorithm::hashing::hash32d(data.view());
				value.encode(buffer);
				return string_repr(std::string_view((char*)buffer + (sizeof(uint256_t) - sizeof(uint32_t)), sizeof(uint32_t)));
			}
			string_repr alg::ripemd160(const string_repr& data)
			{
				return string_repr(algorithm::hashing::hash160((uint8_t*)data.data(), data.size()));
			}
			uint256_t alg::blake2b256(const string_repr& data)
			{
				return algorithm::hashing::hash256i((uint8_t*)data.data(), data.size());
			}
			string_repr alg::blake2b256s(const string_repr& data)
			{
				return string_repr(algorithm::hashing::hash256((uint8_t*)data.data(), data.size()));
			}
			uint256_t alg::keccak256(const string_repr& data)
			{
				uint256_t value;
				uint8_t buffer[SHA3_256_DIGEST_LENGTH];
				sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
				value.decode(buffer);
				return value;
			}
			string_repr alg::keccak256s(const string_repr& data)
			{
				uint8_t buffer[SHA3_256_DIGEST_LENGTH];
				sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
				return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
			}
			string_repr alg::keccak512(const string_repr& data)
			{
				uint8_t buffer[SHA3_512_DIGEST_LENGTH];
				keccak_512((uint8_t*)data.data(), data.size(), buffer);
				return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
			}
			uint256_t alg::sha256(const string_repr& data)
			{
				uint256_t value;
				uint8_t buffer[SHA3_256_DIGEST_LENGTH];
				keccak_256((uint8_t*)data.data(), data.size(), buffer);
				value.decode(buffer);
				return value;
			}
			string_repr alg::sha256s(const string_repr& data)
			{
				uint8_t buffer[SHA3_256_DIGEST_LENGTH];
				keccak_256((uint8_t*)data.data(), data.size(), buffer);
				return string_repr(std::string_view((char*)buffer, sizeof(buffer)));
			}
			string_repr alg::sha512(const string_repr& data)
			{
				return string_repr(algorithm::hashing::hash512((uint8_t*)data.data(), data.size()));
			}
			uint256_t alg::random()
			{
				auto* program = svm_program::fetch_mutable_or_throw();
				if (!program)
					return uint256_t((uint8_t)0);

				if (!program->cache.distribution)
				{
					auto candidate = program->context->calculate_random(program->context->get_gas_use());
					if (!candidate)
					{
						exception::throw_ptr(exception::pointer(exception::category::execution(), std::string_view(candidate.error().message())));
						return uint256_t((uint8_t)0);
					}
					program->cache.distribution = std::move(*candidate);
				}

				return program->cache.distribution->derive();
			}

			void math::min_value(asIScriptGeneric* generic)
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
						inout.set_return_float(std::numeric_limits<float>::min());
						break;
					case (int)type_id::double_t:
						inout.set_return_double(std::numeric_limits<double>::min());
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							new (inout.get_address_of_return_location()) uint128_t(uint128_t::min());
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							new (inout.get_address_of_return_location()) uint256_t(uint256_t::min());
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
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
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic"));
					}
				}
			}
			void math::max_value(asIScriptGeneric* generic)
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
						inout.set_return_float(std::numeric_limits<float>::max());
						break;
					case (int)type_id::double_t:
						inout.set_return_double(std::numeric_limits<double>::max());
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							new (inout.get_address_of_return_location()) uint128_t(uint128_t::max());
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							new (inout.get_address_of_return_location()) uint256_t(uint256_t::max());
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
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
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic"));
					}
				}
			}
			void math::min(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
				{
					mpf_value left = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_value right = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					auto& lowest = mpf_cmp(left.target, right.target) < 0 ? left : right;
					if (!lowest.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
				}
				else
				{
					mpz_value left = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpz_value right = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					auto& lowest = mpz_cmp(left.target, right.target) < 0 ? left : right;
					if (!lowest.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}
			void math::max(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
				{
					mpf_value left = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_value right = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					auto& highest = mpf_cmp(left.target, right.target) > 0 ? left : right;
					if (!highest.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
				}
				else
				{
					mpz_value left = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpz_value right = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					auto& highest = mpz_cmp(left.target, right.target) > 0 ? left : right;
					if (!highest.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}
			void math::clamp(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
				{
					mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_value left = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					mpf_value right = mpf_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
					auto& clamped = mpf_cmp(value.target, left.target) < 0 ? left : (mpf_cmp(value.target, right.target) > 0 ? right : value);
					if (!clamped.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
				}
				else
				{
					mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpz_value left = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					mpz_value right = mpz_value(inout.get_arg_type_id(2), inout.get_arg_address(2));
					auto& clamped = mpz_cmp(value.target, left.target) < 0 ? left : (mpz_cmp(value.target, right.target) > 0 ? right : value);
					if (!clamped.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}
			void math::lerp(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
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
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
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
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}
			void math::pow(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
				{
					mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_value count = mpf_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					auto exponent = mpf_get_ui(count.target);
					if (exponent > 0)
					{
						auto bits_required = uint128_t(value.bits()) * uint128_t(exponent);
						auto bits_limit = uint128_t(mpf_get_prec(value.target));
						if (bits_required > bits_limit)
							return exception::throw_ptr(exception::pointer(exception::category::execution(), stringify::text("fixed point overflow (bits_required: %s, bits_limit: %s)", bits_required.to_string().c_str(), bits_limit.to_string().c_str())));
					}

					mpf_value result = value;
					mpf_pow_ui(result.target, value.target, exponent);
					if (!result.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
				}
				else
				{
					mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpz_value count = mpz_value(inout.get_arg_type_id(1), inout.get_arg_address(1));
					mpz_value result = value;
					mpz_powm(result.target, value.target, count.target, value.field);
					if (!result.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}
			void math::sqrt(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int type_id = inout.get_return_addressable_type_id();
				if (mpf_value::requires_floating_point(type_id))
				{
					mpf_value value = mpf_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_sqrt(value.target, value.target);
					if (!value.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be fixed point"));
				}
				else
				{
					mpz_value value = mpz_value(inout.get_arg_type_id(0), inout.get_arg_address(0));
					mpf_value pf_value;
					mpz_value_to_mpf_value(value, pf_value);
					mpf_sqrt(pf_value.target, pf_value.target);
					mpf_value_to_mpz_value(pf_value, value);
					if (!value.into(inout))
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be integer"));
				}
			}

			void assertion::require(bool condition, const string_repr& message)
			{
				if (!condition)
					exception::throw_ptr(exception::pointer(exception::category::requirement(), message.empty() ? std::string_view("requirement not met") : message));
			}
		}
	}
}
