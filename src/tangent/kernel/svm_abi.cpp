#include "svm_abi.h"
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_QUERY_PREFETCH ((uint32_t)gas_cost::query_byte / (uint32_t)gas_cost::bulk_query_byte)
#define SCRIPT_TAG_ARRAY 19192
#define SCRIPT_TYPENAME_UINT128 "uint128"
#define SCRIPT_TYPENAME_UINT256 "uint256"
#define SCRIPT_TYPENAME_DECIMAL "float768"
#define SCRIPT_TYPENAME_ARRAY "array"
#define SCRIPT_TYPENAME_STRING "string"

using namespace vitex::scripting;

namespace tangent
{
	namespace ledger
	{
		namespace svm_abi
		{
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
					resize(other.buffer->num_elements);
					copy_buffer(buffer, other.buffer);
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
				return buffer->num_elements;
			}
			uint32_t array_repr::capacity() const
			{
				return buffer->max_elements;
			}
			bool array_repr::empty() const
			{
				return buffer->num_elements == 0;
			}
			void array_repr::reserve(uint32_t max_elements)
			{
				if (max_elements <= buffer->max_elements)
					return;

				if (!check_max_size(max_elements))
					return;

				sbuffer* new_buffer = gas_allocate<sbuffer>(sizeof(sbuffer) - 1 + (size_t)element_size * (size_t)max_elements);
				if (!new_buffer)
					return;

				new_buffer->num_elements = buffer->num_elements;
				new_buffer->max_elements = max_elements;
				memcpy(new_buffer->data, buffer->data, (size_t)buffer->num_elements * (size_t)element_size);
				memory::deallocate(buffer);
				buffer = new_buffer;
			}
			void array_repr::resize(uint32_t num_elements)
			{
				if (!check_max_size(num_elements))
					return;

				resize((int64_t)num_elements - (int64_t)buffer->num_elements, (uint32_t)-1);
			}
			void array_repr::remove_range(uint32_t start, uint32_t count)
			{
				if (count == 0)
					return;

				if (buffer == 0 || start > buffer->num_elements)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

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
				if (delta < 0)
				{
					if (-delta > (int64_t)buffer->num_elements)
						delta = -(int64_t)buffer->num_elements;

					if (where > buffer->num_elements + delta)
						where = buffer->num_elements + delta;
				}
				else if (delta > 0)
				{
					if (!check_max_size(buffer->num_elements + delta))
						return;

					if (where > buffer->num_elements)
						where = buffer->num_elements;
				}

				if (delta == 0)
					return;

				if (buffer->max_elements < buffer->num_elements + delta)
				{
					size_t count = (size_t)buffer->num_elements + (size_t)delta, size = (size_t)element_size;
					sbuffer* new_buffer = gas_allocate<sbuffer>(sizeof(sbuffer) - 1 + size * count);
					if (!new_buffer)
						return;

					new_buffer->num_elements = buffer->num_elements + delta;
					new_buffer->max_elements = new_buffer->num_elements;
					memcpy(new_buffer->data, buffer->data, (size_t)where * (size_t)element_size);
					if (where < buffer->num_elements)
						memcpy(new_buffer->data + (where + delta) * (size_t)element_size, buffer->data + where * (size_t)element_size, (size_t)(buffer->num_elements - where) * (size_t)element_size);

					create(new_buffer, where, where + delta);
					memory::deallocate(buffer);
					buffer = new_buffer;
				}
				else if (delta < 0)
				{
					destroy(buffer, where, where - delta);
					memmove(buffer->data + where * (size_t)element_size, buffer->data + (where - delta) * (size_t)element_size, (size_t)(buffer->num_elements - (where - delta)) * (size_t)element_size);
					buffer->num_elements += delta;
				}
				else
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

				exception::throw_ptr(exception::pointer(exception::category::memory(), "illegal allocation"));
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
				if (index > buffer->num_elements)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

				resize(1, index);
				set_value(index, value);
			}
			void array_repr::insert_at(uint32_t index, const array_repr& array)
			{
				if (index > buffer->num_elements)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

				if (obj_type.get_type_info() != array.obj_type.get_type_info())
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "template type mismatch"));

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
				insert_at(buffer->num_elements, value);
			}
			void array_repr::remove_at(uint32_t index)
			{
				if (index >= buffer->num_elements)
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return at(0);
			}
			const void* array_repr::front() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return at(0);
			}
			void* array_repr::back()
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return at(size() - 1);
			}
			const void* array_repr::back() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return at(size() - 1);
			}
			void* array_repr::get_buffer()
			{
				return buffer->data;
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
				return buffer->data + index * element_size;
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

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

				cache = gas_allocate<scache>(sizeof(scache));
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
					exception::throw_ptr(exception::pointer(exception::category::memory(), "out of memory"));

				return result;
			}
			array_repr* array_repr::create(asITypeInfo* info, uint32_t length, void* default_value)
			{
				array_repr* result = new array_repr(length, default_value, info);
				if (!result)
					exception::throw_ptr(exception::pointer(exception::category::memory(), "out of memory"));

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
						exception::throw_ptr(exception::pointer(exception::category::argument(), "template type has multiple opCmp implementations"));
					else
						exception::throw_ptr(exception::pointer(exception::category::argument(), "template type has no opCmp implementation"));
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
						exception::throw_ptr(exception::pointer(exception::category::argument(), "template type has multiple opCmp implementations"));
					else
						exception::throw_ptr(exception::pointer(exception::category::argument(), "template type has no opCmp implementation"));
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return data() + index;
			}
			const char* string_repr::front() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
					return nullptr;
				}

				return data();
			}
			const char* string_repr::back() const
			{
				if (empty())
				{
					exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));
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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

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
					return exception::throw_ptr(exception::pointer(exception::category::argument(), "out of bounds"));

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
				new(base) decimal();
				truncate_or_throw(*base, true);
			}
			bool decimal_repr::is_not_zero_or_nan(decimal& base)
			{
				return !base.is_zero_or_nan();
			}
			bool decimal_repr::truncate_or_throw(decimal& base, bool require_decimal_precision)
			{
				auto* vm = virtual_machine::get();
				if (vm != nullptr)
				{
					auto& message = protocol::now().message;
					if (require_decimal_precision || base.decimal_size() > message.decimal_precision)
						base.truncate(message.decimal_precision);

					if (base.integer_size() > message.integer_precision)
					{
						exception::throw_ptr(exception::pointer(exception::category::memory(), "real number is overflowing significant places limit"));
						return false;
					}
				}
				return true;
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
						return exception::throw_ptr(exception::pointer(exception::category::execution(), stringify::text("illegal subcall to %s program on function \"%.*s\": %s (argument %i)", object->to_string().data(), (int)function.size(), function.data(), serialization.error().what(), (int)i - 1)));
				}

				auto reader = stream.ro(); format::variables function_args;
				if (!reader.data.empty() && !format::variables_util::deserialize_flat_from(reader, &function_args))
					return exception::throw_ptr(exception::pointer(exception::category::execution(), stringify::text("illegal subcall to %s program on function \"%.*s\": argument serialization error", object->to_string().data(), (int)function.size(), function.data())));

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

			bool xc::at(uint32_t offset, void* object_value, int object_type_id)
			{
				return at_row_ranked(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool xc::at_row(uint32_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id)
			{
				return at_row_ranked(offset, object_value, object_type_id, row_value, row_type_id, nullptr);
			}
			bool xc::at_row_ranked(uint32_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
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

				return true;
			}
			xc xc::from(const void* column_value, int column_type_id, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return xc();

				xc result;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			bool xfc::at(uint32_t offset, void* object_value, int object_type_id)
			{
				return at_row_ranked(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool xfc::at_row(uint32_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id)
			{
				return at_row_ranked(offset, object_value, object_type_id, row_value, row_type_id, nullptr);
			}
			bool xfc::at_row_ranked(uint32_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
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

				return true;
			}
			xfc xfc::from(const void* column_value, int column_type_id, const filter& query, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return xfc();

				xfc result;
				result.query = query;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			bool yc::at(uint32_t offset, void* object_value, int object_type_id)
			{
				return at_column_ranked(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool yc::at_column(uint32_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id)
			{
				return at_column_ranked(offset, object_value, object_type_id, column_value, column_type_id, nullptr);
			}
			bool yc::at_column_ranked(uint32_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
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

				return true;
			}
			yc yc::from(const void* row_value, int row_type_id, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return yc();

				yc result;
				result.count = count > 0 ? count : SCRIPT_QUERY_PREFETCH;

				auto status = svm_marshalling::store(&result.row, row_value, row_type_id);
				if (!status)
					exception::throw_ptr(exception::pointer(exception::category::argument(), std::string_view(status.error().message())));

				return result;
			}

			bool yfc::at(uint32_t offset, void* object_value, int object_type_id)
			{
				return at_column_ranked(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
			}
			bool yfc::at_column(uint32_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id)
			{
				return at_column_ranked(offset, object_value, object_type_id, column_value, column_type_id, nullptr);
			}
			bool yfc::at_column_ranked(uint32_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
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

				return true;
			}
			yfc yfc::from(const void* row_value, int row_type_id, const filter& query, uint32_t count)
			{
				auto* program = svm_program::fetch_immutable_or_throw();
				if (!program)
					return yfc();

				yfc result;
				result.query = query;
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
				if (!data || data->data.empty())
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), "program variable missing"));
					return false;
				}

				format::ro_stream stream = format::ro_stream(data->data);
				status = svm_marshalling::load(stream, object_value, object_type_id);
				if (!status)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), "program variable corrupted"));
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
			bool sv::at(const void* index_value, int index_type_id, void* object_value, int object_type_id)
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
				if (!data || data->data.empty())
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), "program variable missing"));
					return false;
				}

				format::ro_stream stream = format::ro_stream(data->data);
				status = svm_marshalling::load(stream, object_value, object_type_id);
				if (!status)
				{
					if (throw_on_error)
						exception::throw_ptr(exception::pointer(exception::category::storage(), "program variable corrupted"));
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
			bool qsv::at_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value)
			{
				return load(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value, false);
			}
			bool qsv::at(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
			{
				return at_ranked(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr);
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
					exception::throw_ptr(exception::pointer(exception::category::argument(), string_repr(value.to_string() + " as uint256 - decimal precision too high")));
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
				int result_type_id = inout.get_return_addressable_type_id();
				switch (result_type_id)
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
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
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
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
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
				int result_type_id = inout.get_return_addressable_type_id();
				switch (result_type_id)
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
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
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
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
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
				int left_type_id = inout.get_arg_type_id(0);
				int right_type_id = inout.get_arg_type_id(1);
				int result_type_id = inout.get_return_addressable_type_id();
				if (left_type_id != right_type_id || left_type_id != result_type_id)
					return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type mismatch"));

				void* left_value = inout.get_arg_address(0);
				void* right_value = inout.get_arg_address(1);
				switch (result_type_id)
				{
					case (int)type_id::int8_t:
						inout.set_return_byte((uint8_t)std::min<int8_t>(*(int8_t*)left_value, *(int8_t*)right_value));
						break;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						inout.set_return_byte(std::min<uint8_t>(*(uint8_t*)left_value, *(uint8_t*)right_value));
						break;
					case (int)type_id::int16_t:
						inout.set_return_word((uint16_t)std::min<int16_t>(*(int16_t*)left_value, *(int16_t*)right_value));
						break;
					case (int)type_id::uint16_t:
						inout.set_return_word(std::min<uint16_t>(*(uint16_t*)left_value, *(uint16_t*)right_value));
						break;
					case (int)type_id::int32_t:
						inout.set_return_dword((uint32_t)std::min<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
						break;
					case (int)type_id::uint32_t:
						inout.set_return_dword(std::min<uint32_t>(*(uint32_t*)left_value, *(uint32_t*)right_value));
						break;
					case (int)type_id::int64_t:
						inout.set_return_qword((uint64_t)std::min<int64_t>(*(int64_t*)left_value, *(int64_t*)right_value));
						break;
					case (int)type_id::uint64_t:
						inout.set_return_qword(std::min<uint64_t>(*(uint64_t*)left_value, *(uint64_t*)right_value));
						break;
					case (int)type_id::float_t:
						inout.set_return_float(std::min<float>(*(float*)left_value, *(float*)right_value));
						break;
					case (int)type_id::double_t:
						inout.set_return_double(std::min<double>(*(double*)left_value, *(double*)right_value));
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
						right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							new (inout.get_address_of_return_location()) uint128_t(std::min<uint128_t>(*(uint128_t*)left_value, *(uint128_t*)right_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							new (inout.get_address_of_return_location()) uint256_t(std::min<uint256_t>(*(uint256_t*)left_value, *(uint256_t*)right_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
						{
							new (inout.get_address_of_return_location()) decimal(std::min<decimal>(*(decimal*)left_value, *(decimal*)right_value));
							break;
						}
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							inout.set_return_dword((uint32_t)std::min<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
							break;
						}
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic"));
					}
				}
			}
			void math::max(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int left_type_id = inout.get_arg_type_id(0);
				int right_type_id = inout.get_arg_type_id(1);
				int result_type_id = inout.get_return_addressable_type_id();
				if (left_type_id != right_type_id || left_type_id != result_type_id)
					return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type mismatch"));

				void* left_value = inout.get_arg_address(0);
				void* right_value = inout.get_arg_address(1);
				switch (result_type_id)
				{
					case (int)type_id::int8_t:
						inout.set_return_byte((uint8_t)std::max<int8_t>(*(int8_t*)left_value, *(int8_t*)right_value));
						break;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						inout.set_return_byte(std::max<uint8_t>(*(uint8_t*)left_value, *(uint8_t*)right_value));
						break;
					case (int)type_id::int16_t:
						inout.set_return_word((uint16_t)std::max<int16_t>(*(int16_t*)left_value, *(int16_t*)right_value));
						break;
					case (int)type_id::uint16_t:
						inout.set_return_word(std::max<uint16_t>(*(uint16_t*)left_value, *(uint16_t*)right_value));
						break;
					case (int)type_id::int32_t:
						inout.set_return_dword((uint32_t)std::max<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
						break;
					case (int)type_id::uint32_t:
						inout.set_return_dword(std::max<uint32_t>(*(uint32_t*)left_value, *(uint32_t*)right_value));
						break;
					case (int)type_id::int64_t:
						inout.set_return_qword((uint64_t)std::max<int64_t>(*(int64_t*)left_value, *(int64_t*)right_value));
						break;
					case (int)type_id::uint64_t:
						inout.set_return_qword(std::max<uint64_t>(*(uint64_t*)left_value, *(uint64_t*)right_value));
						break;
					case (int)type_id::float_t:
						inout.set_return_float(std::max<float>(*(float*)left_value, *(float*)right_value));
						break;
					case (int)type_id::double_t:
						inout.set_return_double(std::max<double>(*(double*)left_value, *(double*)right_value));
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
						right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							new (inout.get_address_of_return_location()) uint128_t(std::max<uint128_t>(*(uint128_t*)left_value, *(uint128_t*)right_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							new (inout.get_address_of_return_location()) uint256_t(std::max<uint256_t>(*(uint256_t*)left_value, *(uint256_t*)right_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
						{
							decimal* ptr = (decimal*)inout.get_address_of_return_location();
							new (inout.get_address_of_return_location()) decimal(std::max<decimal>(*(decimal*)left_value, *(decimal*)right_value));
							break;
						}
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							inout.set_return_dword((uint32_t)std::max<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
							break;
						}
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic"));
					}
				}
			}
			void math::pow(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int left_type_id = inout.get_arg_type_id(0);
				int right_type_id = inout.get_arg_type_id(1);
				int result_type_id = inout.get_return_addressable_type_id();
				if (left_type_id != right_type_id || left_type_id != result_type_id)
					return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type mismatch"));

				void* left_value = inout.get_arg_address(0);
				void* right_value = inout.get_arg_address(1);
				switch (result_type_id)
				{
					case (int)type_id::int8_t:
						inout.set_return_byte((uint8_t)std::pow((double)*(int8_t*)left_value, (double)*(int8_t*)right_value));
						break;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						inout.set_return_byte((uint8_t)std::pow((double)*(uint8_t*)left_value, (double)*(uint8_t*)right_value));
						break;
					case (int)type_id::int16_t:
						inout.set_return_word((uint16_t)std::pow((double)*(int16_t*)left_value, (double)*(int16_t*)right_value));
						break;
					case (int)type_id::uint16_t:
						inout.set_return_word((uint16_t)std::pow((double)*(uint16_t*)left_value, (double)*(uint16_t*)right_value));
						break;
					case (int)type_id::int32_t:
						inout.set_return_dword((uint32_t)std::pow((double)*(int32_t*)left_value, (double)*(int32_t*)right_value));
						break;
					case (int)type_id::uint32_t:
						inout.set_return_dword((uint32_t)std::pow((double)*(uint32_t*)left_value, (double)*(uint32_t*)right_value));
						break;
					case (int)type_id::int64_t:
						inout.set_return_qword((uint64_t)std::pow((double)*(int64_t*)left_value, (double)*(int64_t*)right_value));
						break;
					case (int)type_id::uint64_t:
						inout.set_return_qword((uint64_t)std::pow((double)*(uint64_t*)left_value, (double)*(uint64_t*)right_value));
						break;
					case (int)type_id::float_t:
						inout.set_return_float(std::pow(*(float*)left_value, *(float*)right_value));
						break;
					case (int)type_id::double_t:
						inout.set_return_double(std::pow(*(double*)left_value, *(double*)right_value));
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
						right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							uint128_t result = uint128_t(1);
							uint128_t exponent = *(uint128_t*)right_value;
							uint128_t base = *(uint128_t*)left_value;
							while (exponent > 0)
							{
								if (exponent & 1)
									result *= base;
								base *= base;
								exponent >>= 1;
							}
							new (inout.get_address_of_return_location()) uint128_t(result);
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							uint256_t result = uint256_t(1);
							uint256_t exponent = *(uint256_t*)right_value;
							uint256_t base = *(uint256_t*)left_value;
							while (exponent > 0)
							{
								if (exponent & 1)
									result *= base;
								base *= base;
								exponent >>= 1;
							}
							new (inout.get_address_of_return_location()) uint256_t(result);
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
						{
							decimal result = decimal(1);
							int64_t exponent = ((decimal*)right_value)->to_int64();
							decimal base = *(decimal*)left_value;
							bool invertion = exponent < 0;

							exponent = invertion ? -exponent : exponent;
							while (exponent > 0)
							{
								if ((exponent & 1) && !decimal_repr::truncate_or_throw(result *= base, false))
									break;

								if (!decimal_repr::truncate_or_throw(base *= base, false))
									break;

								exponent >>= 1;
							}

							if (invertion)
								result = decimal(1.0) / result;

							new (inout.get_address_of_return_location()) decimal(std::move(result));
							break;
						}
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							inout.set_return_dword((uint32_t)std::pow((double)*(int32_t*)left_value, (double)*(int32_t*)right_value));
							break;
						}
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic and trivial"));
					}
				}
			}
			void math::lerp(asIScriptGeneric* generic)
			{
				generic_context inout = generic_context(generic);
				int left_type_id = inout.get_arg_type_id(0);
				int right_type_id = inout.get_arg_type_id(1);
				int delta_type_id = inout.get_arg_type_id(2);
				int result_type_id = inout.get_return_addressable_type_id();
				if (left_type_id != right_type_id || left_type_id != result_type_id || left_type_id != delta_type_id)
					return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type mismatch"));

				void* left_value = inout.get_arg_address(0);
				void* right_value = inout.get_arg_address(1);
				void* delta_value = inout.get_arg_address(2);
				switch (result_type_id)
				{
					case (int)type_id::int8_t:
						inout.set_return_byte((uint8_t)vitex::compute::math<int8_t>::strong_lerp(*(int8_t*)left_value, *(int8_t*)right_value, *(int8_t*)delta_value));
						break;
					case (int)type_id::bool_t:
					case (int)type_id::uint8_t:
						inout.set_return_byte(vitex::compute::math<uint8_t>::strong_lerp(*(uint8_t*)left_value, *(uint8_t*)right_value, *(int8_t*)delta_value));
						break;
					case (int)type_id::int16_t:
						inout.set_return_word((uint16_t)vitex::compute::math<int16_t>::strong_lerp(*(int16_t*)left_value, *(int16_t*)right_value, *(int16_t*)delta_value));
						break;
					case (int)type_id::uint16_t:
						inout.set_return_word(vitex::compute::math<uint16_t>::strong_lerp(*(uint16_t*)left_value, *(uint16_t*)right_value, *(uint16_t*)delta_value));
						break;
					case (int)type_id::int32_t:
						inout.set_return_dword((uint32_t)vitex::compute::math<int32_t>::strong_lerp(*(int32_t*)left_value, *(int32_t*)right_value, *(int32_t*)delta_value));
						break;
					case (int)type_id::uint32_t:
						inout.set_return_dword(vitex::compute::math<uint32_t>::strong_lerp(*(uint32_t*)left_value, *(uint32_t*)right_value, *(uint32_t*)delta_value));
						break;
					case (int)type_id::int64_t:
						inout.set_return_qword((uint64_t)vitex::compute::math<int64_t>::strong_lerp(*(int64_t*)left_value, *(int64_t*)right_value, *(int64_t*)delta_value));
						break;
					case (int)type_id::uint64_t:
						inout.set_return_qword(vitex::compute::math<uint64_t>::strong_lerp(*(uint64_t*)left_value, *(uint64_t*)right_value, *(uint64_t*)delta_value));
						break;
					case (int)type_id::float_t:
						inout.set_return_float(vitex::compute::math<float>::strong_lerp(*(float*)left_value, *(float*)right_value, *(double*)delta_value));
						break;
					case (int)type_id::double_t:
						inout.set_return_double(vitex::compute::math<double>::strong_lerp(*(double*)left_value, *(double*)right_value, *(double*)delta_value));
						break;
					default:
					{
						auto type = svm_container::get()->get_vm()->get_type_info_by_id(result_type_id);
						auto name = type.is_valid() ? type.get_name() : std::string_view();
						left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
						right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
						if (name == SCRIPT_TYPENAME_UINT128)
						{
							new (inout.get_address_of_return_location()) uint128_t(vitex::compute::math<uint128_t>::strong_lerp(*(uint128_t*)left_value, *(uint128_t*)right_value, *(uint128_t*)delta_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_UINT256)
						{
							new (inout.get_address_of_return_location()) uint256_t(vitex::compute::math<uint256_t>::strong_lerp(*(uint256_t*)left_value, *(uint256_t*)right_value, *(uint256_t*)delta_value));
							break;
						}
						else if (name == SCRIPT_TYPENAME_DECIMAL)
						{
							new (inout.get_address_of_return_location()) decimal(vitex::compute::math<decimal>::strong_lerp(*(decimal*)left_value, *(decimal*)right_value, *(decimal*)delta_value));
							break;
						}
						else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
						{
							inout.set_return_dword((uint32_t)vitex::compute::math<int32_t>::strong_lerp(*(int32_t*)left_value, *(int32_t*)right_value, *(int32_t*)delta_value));
							break;
						}
						return exception::throw_ptr(exception::pointer(exception::category::execution(), "template type must be arithmetic"));
					}
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
