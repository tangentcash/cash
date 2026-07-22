#include "script.h"
#include "../policy/transactions.h"
#include "../storage/chainstate.h"
#include "../internal/as_autowrapper.h"
#include <vitex/bindings.h>
#include <gmp.h>
#include <iostream>
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_QUERY_PREFETCH 16
#define SCRIPT_TAG_MUTABLE_PROGRAM 19190
#define SCRIPT_TAG_IMMUTABLE_PROGRAM 19191
#define SCRIPT_TYPE_PAYABLE "payable"
#define SCRIPT_TYPE_ADDRESS "address"
#define SCRIPT_TYPE_STRING "string"
#define SCRIPT_TYPE_UINT128 "uint128"
#define SCRIPT_TYPE_UINT256 "uint256"
#define SCRIPT_TYPE_REAL320 "real320"
#define SCRIPT_TYPE_ARRAY "array"
#define SCRIPT_TYPE_VARYING "varying"
#define SCRIPT_TYPE_MAPPING "mapping"
#define SCRIPT_TYPE_LISTING "listing"
#define SCRIPT_TYPE_RANGING "ranging"
#define SCRIPT_TYPE_PMUT "pmut"
#define SCRIPT_TYPE_PCONST "pconst"
#define SCRIPT_FUNCTION_CONSTRUCT "construct"
#define SCRIPT_VM "program"

namespace tangent
{
	namespace script
	{
		typedef hash_map<string_repr, std::atomic<int32_t>> string_repr_cache_type;

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
					if (exp >= (mp_exp_t)len)
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
		static void any_store(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			((script::bindings::any*)inout.get_object_address())->store(inout.get_arg_address(0), inout.get_arg_type_id(0));
		}
		static void any_retrieve(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			bool result = ((script::bindings::any*)inout.get_object_address())->retrieve(inout.get_arg_address(0), inout.get_arg_type_id(0));
			inout.set_return_byte(result);
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
		exception_repr::exception_repr(immediate_context* new_context, size_t offset) : context(new_context)
		{
			auto value = context ? context->get_exception_string() : std::string_view();
			if (!value.empty() && (context ? !context->will_exception_be_caught() : false))
			{
				load_exception_data(value);
				origin = load_stack_here(offset);
			}
		}
		exception_repr::exception_repr(const std::string_view& value, size_t offset) : context(immediate_context::get())
		{
			load_exception_data(value);
			origin = load_stack_here(offset);
		}
		exception_repr::exception_repr(const std::string_view& new_type, const std::string_view& new_text, size_t offset) : type(new_type), text(new_text), context(immediate_context::get())
		{
			origin = load_stack_here(offset);
		}
		exception_repr::exception_repr(const string_repr& new_type, const string_repr& new_text, size_t offset) : type(new_type.view()), text(new_text.view()), context(immediate_context::get())
		{
			origin = load_stack_here(offset);
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
		string exception_repr::load_stack_here(size_t offset) const
		{
			string data;
			if (!context)
				return data;

			string_stream stream;
			stream << '\n';

			size_t callstack_size = context->get_callstack_size();
			callstack_size = offset < callstack_size ? callstack_size - offset : 0;

			size_t top_callstack_size = callstack_size;
			for (size_t i = 0; i < callstack_size; i++)
			{
				int column_number = 0;
				int line_number = context->get_line_number(i, &column_number);
				function next = context->get_function(i);
				stream << "  #" << (--top_callstack_size) + offset;
				if (line_number > 0 || column_number > 0)
					stream << " at program:" << (line_number > 0 ? line_number : 0) << ":" << (column_number > 0 ? column_number : 0);
				else
					stream << " at [optimized]";
				stream << " in \"" << (next.get_decl().empty() ? "[optimized]" : next.get_decl()) << "\"";
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

		array_repr::array_repr(uint32_t length, asITypeInfo* info) : obj_type(info), buffer(nullptr), element_size(0), sub_type_id(-1)
		{
			VI_ASSERT(info && string(obj_type.get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			sub_type_id = obj_type.get_sub_type_id();
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
		array_repr::array_repr(const array_repr& other) : reference<array_repr>(), obj_type(other.obj_type), buffer(nullptr), element_size(other.element_size), sub_type_id(other.sub_type_id)
		{
			VI_ASSERT(obj_type.is_valid() && string(obj_type.get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			if (obj_type.flags() & (uint32_t)object_behaviours::gc)
				obj_type.get_vm()->notify_of_new_object(this, obj_type);

			create_buffer(&buffer, 0);
			*this = other;
		}
		array_repr::array_repr(uint32_t length, void* default_value, asITypeInfo* info) : obj_type(info), buffer(nullptr), element_size(0), sub_type_id(-1)
		{
			VI_ASSERT(info && string(vitex::scripting::type_info(info).get_name()) == SCRIPT_TYPE_ARRAY, "array type is invalid");
			obj_type.add_ref();
			sub_type_id = obj_type.get_sub_type_id();
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
		array_repr::~array_repr()
		{
			if (buffer)
			{
				delete_buffer(buffer);
				buffer = nullptr;
			}
			obj_type.release();
		}
		array_repr& array_repr::operator=(const array_repr& other)
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

			if ((sub_type_id & ~(int32_t)type_id::mask_seqnbr_t) && !(sub_type_id & (int32_t)type_id::handle_t))
				obj_type.get_vm()->assign_object(ptr, value, obj_type.get_sub_type());
			else if (sub_type_id & (int32_t)type_id::handle_t)
			{
				void* swap = *(void**)ptr;
				*(void**)ptr = *(void**)value;
				obj_type.get_vm()->add_ref_object(*(void**)value, obj_type.get_sub_type());
				if (swap)
					obj_type.get_vm()->release_object(swap, obj_type.get_sub_type());
			}
			else if (sub_type_id == (int32_t)type_id::float_t || sub_type_id == (int32_t)type_id::double_t)
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), "floating point value not permitted"));
			else if (sub_type_id == (int32_t)type_id::bool_t || sub_type_id == (int32_t)type_id::int8_t || sub_type_id == (int32_t)type_id::uint8_t)
				*(char*)ptr = *(char*)value;
			else if (sub_type_id == (int32_t)type_id::int16_t || sub_type_id == (int32_t)type_id::uint16_t)
				*(short*)ptr = *(short*)value;
			else if (sub_type_id == (int32_t)type_id::int32_t || sub_type_id == (int32_t)type_id::uint32_t || sub_type_id > (int32_t)type_id::double_t)
				*(int*)ptr = *(int*)value;
			else if (sub_type_id == (int32_t)type_id::int64_t || sub_type_id == (int32_t)type_id::uint64_t)
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

			resize_buffer((int64_t)num_elements - (int64_t)(buffer ? buffer->num_elements : 0), (uint32_t)-1);
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
		void array_repr::resize_buffer(int32_t delta, uint32_t where)
		{
			uint32_t buffer_size = buffer ? buffer->num_elements : 0;
			if (delta < 0)
			{
				if (-delta > (int32_t)buffer_size)
					delta = -(int32_t)buffer_size;

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

			resize_buffer(1, index);
			set_value(index, value);
		}
		void array_repr::insert_array_at(uint32_t index, const array_repr& array)
		{
			if (index > (buffer ? buffer->num_elements : 0))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));

			if (obj_type.get_type_info() != array.obj_type.get_type_info())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("array types (%s, %s) are incompatible", obj_type.get_name().data(), array.obj_type.get_name().data())));

			uint32_t new_size = array.size();
			resize_buffer((int)new_size, index);

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
		void array_repr::insert_first(void* value)
		{
			insert_at(0, value);
		}
		void array_repr::insert_last(void* value)
		{
			insert_at(buffer ? buffer->num_elements : 0, value);
		}
		void array_repr::remove_at(uint32_t index)
		{
			if (index >= (buffer ? buffer->num_elements : 0))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, buffer ? buffer->num_elements : 0)));
			resize_buffer(-1, index);
		}
		void array_repr::remove_first()
		{
			remove_at(0);
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
		array_repr* array_repr::construct(asITypeInfo* info)
		{
			return array_repr::construct(info, (uint32_t)0);
		}
		array_repr* array_repr::construct(asITypeInfo* info, uint32_t length)
		{
			array_repr* result = new array_repr(length, info);
			if (!result)
				contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

			return result;
		}
		array_repr* array_repr::construct(asITypeInfo* info, uint32_t length, void* default_value)
		{
			array_repr* result = new array_repr(length, default_value, info);
			if (!result)
				contract::throw_ptr(exception_repr(exception_repr::category::memory(), stringify::text("size %i is illegal (out of memory)", length)));

			return result;
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
		string_repr::string_repr(string_repr&& other)
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
		string_repr& string_repr::operator=(string_repr&& other)
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
			result.append_char_back(c);
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
		string_repr string_repr::append_char_back(char c)
		{
			auto copy = *this;
			copy.assign_append_char(c);
			return copy;
		}
		string_repr string_repr::append_char_front(char c)
		{
			auto copy = *this;
			copy.push_front(c);
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
			assign_append_char(c);
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
			array_repr* array = array_repr::construct(array_type);
			auto values = stringify::split(view(), delimiter.view());
			array->resize((uint32_t)values.size());
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
			if (!stringify::has_integer(view(), base))
				return uint128_t();

			return uint128_t(view(), base);
		}
		uint256_t string_repr::from_string_uint256(int base) const
		{
			if (!stringify::has_integer(view(), base))
				return uint256_t();

			return uint256_t(view(), base);
		}
		decimal string_repr::from_string_decimal(int base) const
		{
			if (stringify::has_integer(view(), base))
				return decimal::from(view(), base);
			else if (base == 10 && stringify::has_number(view(), base))
				return decimal(view());

			return decimal::nan();
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
		void string_repr::construct(string_repr* base)
		{
			new(base) string_repr();
		}
		void string_repr::construct_copy(string_repr* base, const string_repr& other)
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
		void real320_repr::custom_constructor_string(decimal* base, const string_repr& other)
		{
			auto view = other.view();
			if (view.size() > 2 && view[0] == '0' && view[1] == 'x')
			{
				uint8_t data[sizeof(uint256_t)] = { 0 };
				auto raw = format::util::decode_0xhex(view);
				if (raw.size() > sizeof(data))
					return contract::throw_ptr(exception_repr(exception_repr::category::memory(), "hexadecimal constant overflow with number larger than 256 bits"));

				size_t raw_size = std::min(sizeof(data), raw.size());
				memcpy(data + (sizeof(data) - raw_size), raw.data(), raw_size);

				uint256_t value;
				value.decode(data);
				new(base) decimal(value.to_decimal());
			}
			else
				new(base) decimal(view);
			truncate_or_throw(*base, true);
		}
		void real320_repr::custom_constructor_uint128(decimal* base, const uint128_t& value)
		{
			new(base) decimal(value.to_decimal());
			truncate_or_throw(*base, true);
		}
		void real320_repr::custom_constructor_uint256(decimal* base, const uint256_t& value)
		{
			new(base) decimal(value.to_decimal());
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
		decimal real320_repr::from(const string_repr& data, uint8_t base)
		{
			decimal result = base == 10 ? decimal(data.view()) : decimal::from(data.view(), base);
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
			auto view = other.view();
			if (view.size() > 2 && view[0] == '0' && view[1] == 'x')
			{
				auto raw = format::util::decode_0xhex(view);
				uint8_t data[sizeof(uint128_t)] = { 0 };
				size_t raw_size = std::min(sizeof(data), raw.size());
				memcpy(data + (sizeof(data) - raw_size), raw.data(), raw_size);

				auto value = new(base) uint128_t();
				value->decode(data);
			}
			else
				new(base) uint128_t(view);
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
			if (v != 0)
				base /= v;
			else
				base = 0;
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
			auto view = other.view();
			if (view.size() > 2 && view[0] == '0' && view[1] == 'x')
			{
				auto raw = format::util::decode_0xhex(view);
				uint8_t data[sizeof(uint256_t)] = { 0 };
				size_t raw_size = std::min(sizeof(data), raw.size());
				memcpy(data + (sizeof(data) - raw_size), raw.data(), raw_size);

				auto value = new(base) uint256_t();
				value->decode(data);
			}
			else
				new(base) uint256_t(view);
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
			if (v != 0)
				base /= v;
			else
				base = 0;
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

		payable_repr::payable_repr() : total_value(decimal::zero())
		{
		}
		payable_repr::payable_repr(vector<std::pair<algorithm::asset_id, decimal>>&& new_payments) : payments(std::move(new_payments)), total_value(decimal::zero())
		{
			recalculate();
		}
		void payable_repr::recalculate()
		{
			hash_set<algorithm::asset_id> duplicates;
			for (auto& [paying_asset, paying_value] : payments)
			{
				if (!algorithm::asset::is_any(paying_asset) || !paying_value.is_positive())
				{
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "payment contains bad asset or value"));
					return;
				}
				else if (duplicates.find(paying_asset) != duplicates.end())
				{
					contract::throw_ptr(exception_repr(exception_repr::category::argument(), "duplicate payment"));
					return;
				}
				total_value += paying_value;
			}
		}
		bool payable_repr::plus(const algorithm::asset_id& new_asset, const decimal& new_value)
		{
			if (new_value.is_nan())
				return false;
			else if (new_value.is_zero())
				return true;

			for (auto it = payments.begin(); it != payments.end(); it++)
			{
				auto& [paying_asset, paying_value] = *it;
				if (paying_asset != new_asset)
					continue;
				else if (new_value.is_negative() && paying_value < -new_value)
					return false;

				paying_value += new_value;
				total_value += new_value;
				if (!paying_value.is_positive())
					payments.erase(it);
				return true;
			}

			if (new_value.is_negative())
				return false;

			payments.push_back(std::make_pair(new_asset, new_value));
			total_value += new_value;
			return true;
		}
		bool payable_repr::minus(const algorithm::asset_id& new_asset, const decimal& new_value)
		{
			return plus(new_asset, -new_value);
		}
		bool payable_repr::minus_total(const decimal& new_value)
		{
			if (new_value.is_nan() || new_value.is_negative() || payments.empty() || total_value < new_value)
				return false;
			else if (new_value.is_zero())
				return true;

			auto leftover_value = new_value;
			auto it = payments.begin();
			while (it != payments.end() && leftover_value.is_positive())
			{
				if (it->second.is_positive())
				{
					auto step_value = std::min(it->second, leftover_value);
					it->second -= step_value;
					leftover_value -= step_value;
				}
				++it;
			}

			std::erase_if(payments, [](const std::pair<algorithm::asset_id, decimal>& item) { return !item.second.is_positive(); });
			total_value -= new_value;
			return true;
		}
		bool payable_repr::has(const algorithm::asset_id& new_asset) const
		{
			for (auto& [paying_asset, paying_value] : payments)
			{
				if (paying_asset == new_asset)
					return true;
			}
			return false;
		}
		decimal payable_repr::of(const algorithm::asset_id& new_asset) const
		{
			for (auto& [paying_asset, paying_value] : payments)
			{
				if (paying_asset == new_asset)
					return paying_value;
			}
			return decimal::zero();
		}
		const decimal& payable_repr::total() const
		{
			return total_value;
		}
		algorithm::asset_id payable_repr::at(uint32_t index) const
		{
			if (index >= (uint32_t)payments.size())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, (int)payments.size())));
				return 0;
			}

			return payments[index].first;
		}
		uint32_t payable_repr::size() const
		{
			return (uint32_t)payments.size();
		}
		uint32_t payable_repr::empty() const
		{
			return payments.empty() || !total_value.is_positive();
		}

		address_repr::address_repr(const algorithm::pubkeyhash_t& owner) : hash(owner)
		{
		}
		address_repr::address_repr(const string_repr& address)
		{
			if (!algorithm::signing::decode_address(address.view(), hash))
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), "failed to decode account address"));
		}
		address_repr::address_repr(const uint256_t& owner_data)
		{
			uint8_t owner_raw_data[32]; size_t owner_raw_data_size;
			owner_data.encode_compact(owner_raw_data, &owner_raw_data_size);
			memcpy(hash.blob, owner_raw_data, std::min(owner_raw_data_size, sizeof(hash.blob)));
		}
		void address_repr::pay(const uint256_t& asset, const decimal& value)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p || !value.is_positive())
				return;

			auto payment = p->executor->apply_payment(asset, p->callable(), hash, value);
			if (!payment)
				return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(payment.error().message())));
		}
		void address_repr::pay_all(const payable_repr& payable)
		{
			auto* p = program::fetch_mutable_or_throw();
			for (auto& [paying_asset, paying_value] : payable.payments)
			{
				auto payment = p->executor->apply_payment(paying_asset, p->callable(), hash, paying_value);
				if (!payment)
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(payment.error().message())));
			}
		}
		void address_repr::mint(const string_repr& token, const decimal& supply, const decimal& reserve)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p || token.empty() || (!supply.is_positive() && !reserve.is_positive()))
				return;

			auto payment = p->executor->apply_transfer(contract::coin_token(token), hash, supply.is_positive() ? supply : decimal::zero(), reserve.is_positive() ? reserve : decimal::zero());
			if (!payment)
				return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(payment.error().message())));
		}
		void address_repr::burn(const string_repr& token, const decimal& supply, const decimal& reserve)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p || token.empty() || (!supply.is_positive() && !reserve.is_positive()))
				return;

			auto payment = p->executor->apply_transfer(contract::coin_token(token), hash, supply.is_positive() ? -supply : decimal::zero(), reserve.is_positive() ? -reserve : decimal::zero());
			if (!payment)
				return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(payment.error().message())));
		}
		bool address_repr::callable(const string_repr& entrypoint) const
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return false;

			auto mutability = p->external_mutability_of(hash, entrypoint.view());
			return mutability.is_value();
		}
		decimal address_repr::token_balance_of(const string_repr& token) const
		{
			return balance_of(contract::coin_token(token));
		}
		decimal address_repr::token_reserve_of(const string_repr& token) const
		{
			return reserve_of(contract::coin_token(token));
		}
		decimal address_repr::balance_of(const uint256_t& asset) const
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->get_account_balance(asset, hash).or_else(states::account_balance(algorithm::pubkeyhash_t(), asset, nullptr)).get_balance() : decimal::zero();
		}
		decimal address_repr::reserve_of(const uint256_t& asset) const
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->get_account_balance(asset, hash).or_else(states::account_balance(algorithm::pubkeyhash_t(), asset, nullptr)).reserve : decimal::zero();
		}
		string_repr address_repr::to_string() const
		{
			return string_repr(algorithm::signing::encode_address(hash));
		}
		uint256_t address_repr::to_public_key_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.blob, sizeof(algorithm::pubkeyhash_t));

			uint256_t numeric = 0;
			numeric.decode(data);
			return numeric;
		}
		bool address_repr::empty() const
		{
			return hash.empty();
		}
		void address_repr::call(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			execute_call(generic, *inout.get_arg_object<payable_repr>(1), 2);
		}
		void address_repr::static_call(asIScriptGeneric* generic)
		{
			execute_call(generic, payable_repr(), 1);
		}
		void address_repr::execute_call(asIScriptGeneric* generic, const payable_repr& payable, size_t args_offset)
		{
			generic_context inout = generic_context(generic);
			auto object = (address_repr*)inout.get_object_address();
			auto& function = *inout.get_arg_object<string_repr>(0);
			auto* context = immediate_context::get();
			void* output_value = inout.get_address_of_return_location();
			int output_type_id = inout.get_return_addressable_type_id();
			VI_ASSERT(inout.get_generic() != nullptr, "generic context should be set");
			VI_ASSERT(object != nullptr, "this object should be set");
			VI_ASSERT(context != nullptr, "context should be set");

			format::wo_stream stream;
			for (size_t i = args_offset; i < inout.get_args_count(); i++)
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
				auto execution = p->subexecute(object->hash, payable, ccall::paying_call, function.view(), std::move(function_args), output_value, output_type_id);
				if (!execution)
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(execution.error().message())));
			}
			else
			{
				auto* immutable_program = (program*)program::fetch_immutable_or_throw();
				if (immutable_program != nullptr)
				{
					auto execution = immutable_program->subexecute(object->hash, payable, ccall::const_call, function.view(), std::move(function_args), output_value, output_type_id);
					if (!execution)
						return contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view(execution.error().message())));
				}
			}
		}
		bool address_repr::equals(const address_repr& a, const address_repr& b)
		{
			return a.hash.equals(b.hash);
		}

		void batch_payout_repr::to(const address_repr& new_to, const algorithm::asset_id& new_asset, const decimal& new_value)
		{
			if (new_value.is_nan())
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("trying to pay invalid value to %s", (int)new_to.to_string().size(), new_to.to_string().data())));
			else if (new_value.is_zero())
				return;

			auto& total_value = payouts[new_to.hash][new_asset];
			total_value = total_value.is_nan() ? new_value : (total_value + new_value);
		}
		void batch_payout_repr::pay()
		{
			auto* p = program::fetch_mutable_or_throw();
			if (p != nullptr)
			{
				for (auto& [account, payments] : payouts)
				{
					for (auto& [asset, value] : payments)
					{
						if (value.is_negative())
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("trying to pay negative value to %s", algorithm::signing::encode_address(account).c_str())));
						else if (!value.is_positive())
							continue;

						auto payment = p->executor->apply_payment(asset, p->callable(), account, value);
						if (!payment)
							return contract::throw_ptr(exception_repr(exception_repr::category::execution(), stringify::text("payout to %s failed: %s", algorithm::signing::encode_address(account).c_str(), payment.error().message().c_str())));
					}
				}
				payouts.clear();
			}
		}

		abi_repr::abi_repr(const string_repr& data) : output(data.view())
		{
			input.data = output.data;
		}
		void abi_repr::merge(const string_repr& value)
		{
			size_t prev_size = output.data.size();
			output.data.append(value.data(), (size_t)value.size());
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
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
			size_t prev_size = output.data.size();
			output.write_boolean(value);
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
		}
		void abi_repr::wuint160(const address_repr& value)
		{
			size_t prev_size = output.data.size();
			output.write_string(value.hash.optimized_view());
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
		}
		void abi_repr::wuint256(const uint256_t& value)
		{
			size_t prev_size = output.data.size();
			output.write_integer(value);
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
		}
		void abi_repr::wreal320(const decimal& value)
		{
			size_t prev_size = output.data.size();
			output.write_decimal(value);
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
		}
		void abi_repr::wstr(const string_repr& value)
		{
			size_t prev_size = output.data.size();
			output.write_string(value.view());
			input.data = output.data;
			if (prev_size < output.data.size())
				program::request_gas_vmemory(output.data.size() - prev_size);
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
			if (!algorithm::encoding::decode_bytes(result.view(), blob.blob, sizeof(blob)))
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
		void varying_repr::save()
		{
			if (!slot)
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "varying store failed"));

			contract::uniform_store(&slot, (int)type_id::uint8_t, container.value, type.get_sub_type_id(0));
			known = true;
		}
		void varying_repr::store(const void* new_value)
		{
			if (!slot || !container.copy(new_value, type.get_sub_type_id(0), type.get_sub_type(0)))
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "varying store failed"));

			save();
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

		listing_repr::listing_repr(asITypeInfo* new_type) : container_repr(new_type), length(optional::none)
		{
		}
		listing_repr::~listing_repr()
		{
			reset();
		}
		void listing_repr::reset()
		{
			auto value_type = type.get_sub_type(0);
			for (auto& [index, value] : list)
				value.destroy(value_type);
			length = optional::none;
			list.clear();
		}
		void listing_repr::clear()
		{
			uint32_t count = size() + 1;
			auto value_type = type.get_sub_type_id(0);
			for (uint32_t i = 0; i < count; i++)
				contract::uniform_store_slot(slot, &i, (int)type_id::uint32_t, nullptr, i > 0 ? value_type : (int)type_id::uint32_t);
			reset();
			length = 0;
		}
		uint32_t listing_repr::size()
		{
			if (!length)
			{
				uint32_t length_index = 0, length_value = 0;
				length = contract::uniform_load_slot(slot, &length_index, (int)type_id::uint32_t, &length_value, (int)type_id::uint32_t, false) ? length_value : 0;
			}
			return *length;
		}
		bool listing_repr::empty()
		{
			return !size();
		}
		const void* listing_repr::load_first()
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), "range [0; 1) is out of bounds (size: 0)"));
				return nullptr;
			}
			return load_at(0);
		}
		const void* listing_repr::load_last()
		{
			if (empty())
			{
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), "range [0; 1) is out of bounds (size: 0)"));
				return nullptr;
			}
			return load_at(size() - 1);
		}
		const void* listing_repr::load_at(uint32_t index)
		{
			const void* new_value = try_load_at(index);
			if (!new_value)
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, size())));
			return new_value;
		}
		const void* listing_repr::try_load_at(uint32_t index)
		{
			auto* vm = type.get_vm();
			if (!slot || !vm)
				return nullptr;

			auto it = list.find(index);
			if (it != list.end())
				return it->second.address();

			auto& value = list[index]; uint32_t value_index = index + 1;
			if (!value.copy(nullptr, type.get_sub_type_id(0), type.get_sub_type(0)))
			{
			error:
				value.hidden = true;
				return nullptr;
			}
			else if (!contract::uniform_load_slot(slot, &value_index, (int)type_id::uint32_t, value.value, type.get_sub_type_id(0), false))
				goto error;

			return value.address();
		}
		void listing_repr::store_at(uint32_t index, const void* new_value)
		{
			if (index > size())
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, size())));

			uint32_t length_index = 0;
			if (!new_value)
			{
				uint32_t new_value_index = size();
				if (index == new_value_index)
					return contract::throw_ptr(exception_repr(exception_repr::category::storage(), stringify::text("range [%i; %i) is out of bounds (size: %i)", index, index + 1, size())));

				uint32_t old_value_index = index + 1;
				if (old_value_index != size() && new_value_index > 1)
				{
					const void* back_value = load_at(new_value_index - 1);
					if (!back_value)
						return;

					contract::uniform_store_slot(slot, &old_value_index, (int)type_id::uint32_t, back_value, type.get_sub_type_id(0));
				}
				*length = new_value_index - 1;
				contract::uniform_store_slot(slot, &new_value_index, (int)type_id::uint32_t, nullptr, type.get_sub_type_id(0));
				contract::uniform_store_slot(slot, &length_index, (int)type_id::uint32_t, length.address(), (int)type_id::uint32_t);

				auto cache = list.find(index);
				if (cache != list.end())
					cache->second.destroy(type.get_sub_type(0));
				cache = list.find(new_value_index - 1);
				if (cache != list.end())
					cache->second.destroy(type.get_sub_type(0));
			}
			else
			{
				auto& value = list[index];
				if (!slot || !value.copy(new_value, type.get_sub_type_id(0), type.get_sub_type(0)))
					return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "listing store failed"));

				uint32_t value_index = index + 1;
				contract::uniform_store_slot(slot, &value_index, (int)type_id::uint32_t, value.value, type.get_sub_type_id(0));
				if (index == size())
				{
					*length = value_index;
					contract::uniform_store_slot(slot, &length_index, (int)type_id::uint32_t, length.address(), (int)type_id::uint32_t);
				}
			}
		}
		void listing_repr::erase_at(uint32_t index)
		{
			store_at(index, nullptr);
		}
		void listing_repr::insert_last(const void* value)
		{
			store_at(size(), value);
		}
		void listing_repr::insert_first(const void* value)
		{
			if (!empty())
			{
				const void* prev_value = load_at(0);
				if (!prev_value)
					return;

				insert_last(prev_value);
			}
			store_at(0, value);
		}
		void listing_repr::remove_last()
		{
			if (empty())
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "range [0; 1) is out of bounds (size: 0)"));

			erase_at(size() - 1);
		}
		void listing_repr::remove_first()
		{
			if (empty())
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), "range [0; 1) is out of bounds (size: 0)"));

			erase_at(0);
		}
		bool listing_repr::template_callback(asITypeInfo* t, bool& dont_garbage_collect)
		{
			auto type = vitex::scripting::type_info(t);
			if (!storage_repr::template_callback(type.get_sub_type(0), type.get_sub_type_id(0)))
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

			auto& cache = ((program*)p)->cache.index[mode == cquery::column || mode == cquery::column_filter ? 0 : 1][subject.data];
			auto index_storage = format::wo_stream();
			auto index_at = [&](uint32_t index) -> string&
			{
				index_storage.clear();
				index_storage.write_typeless(index);
				if (mode != cquery::row && mode != cquery::column)
				{
					index_storage.write_typeless((char*)&comparator, sizeof(comparator));
					index_storage.write_typeless((char*)&order, sizeof(order));
					index_storage.write_typeless(value);
				}
				return index_storage.data;
			};
		retry:
			auto& key = index_at(offset);
			auto it = cache.find(key);
			if (it == cache.end())
			{
				expects_lr<vector<uptr<states::account_multiform>>> results = layer_exception();
				if (mode == cquery::column)
					results = p->executor->get_account_multiforms_by_column(p->callable(), subject.data, (size_t)offset, count);
				else if (mode == cquery::column_filter)
					results = p->executor->get_account_multiforms_by_column_filter(p->callable(), subject.data, comparator, value, order, (size_t)offset, count);
				else if (mode == cquery::row)
					results = p->executor->get_account_multiforms_by_row(p->callable(), subject.data, (size_t)offset, count);
				else if (mode == cquery::row_filter)
					results = p->executor->get_account_multiforms_by_row_filter(p->callable(), subject.data, comparator, value, order, (size_t)offset, count);

				if (!results || results->empty())
				{
					cache[key] = nullptr;
					return false;
				}

				uint32_t index = offset;
				for (auto& result : *results)
					cache[index_at(index++)] = std::move(result);

				goto retry;
			}
			else if (!it->second)
				return false;

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
				auto stream = format::ro_stream(mode == cquery::column || mode == cquery::column_filter ? it->second->row : it->second->column);
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
		void ranging_slice_repr::wrapped_next(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			bool result = ((ranging_slice_repr*)inout.get_object_address())->next(nullptr, (int)type_id::void_t);
			inout.set_return_byte(result);
		}
		void ranging_slice_repr::wrapped_next_object(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			bool result = ((ranging_slice_repr*)inout.get_object_address())->next(inout.get_arg_address(0), inout.get_arg_type_id(0));
			inout.set_return_byte(result);
		}
		void ranging_slice_repr::wrapped_next_object_index(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			bool result = ((ranging_slice_repr*)inout.get_object_address())->next_index(inout.get_arg_address(0), inout.get_arg_type_id(0), inout.get_arg_address(1), inout.get_arg_type_id(1));
			inout.set_return_byte(result);
		}
		void ranging_slice_repr::wrapped_next_object_index_ranked(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			bool result = ((ranging_slice_repr*)inout.get_object_address())->next_index_ranked(inout.get_arg_address(0), inout.get_arg_type_id(0), inout.get_arg_address(1), inout.get_arg_type_id(1), (uint256_t*)inout.get_arg_address(2));
			inout.set_return_byte(result);
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
		void ranging_repr::wrapped_store_positioned_if(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			((ranging_repr*)inout.get_object_address())->store_positioned_if((bool)inout.get_arg_byte(0), inout.get_arg_address(1), inout.get_arg_address(2), inout.get_arg_address(3), *inout.get_arg_object<uint256_t>(4));
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
				auto requires_erase = p->executor->get_account_uniform(p->callable(), index.data);
				if (!requires_erase)
					return;
			}

			auto data = p->executor->apply_account_uniform(p->callable(), index.data, stream.data);
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

			auto data = p->executor->get_account_uniform(p->callable(), index.data);
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

			auto data = p->executor->get_account_uniform(p->callable(), index.data);
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
				auto requires_erase = p->executor->get_account_multiform(p->callable(), column.data, row.data);
				if (!requires_erase)
					return;
			}

			auto data = p->executor->apply_account_multiform(p->callable(), column.data, row.data, stream.data, filter_value);
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

			auto data = p->executor->get_account_multiform(p->callable(), column.data, row.data);
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

			auto data = p->executor->get_account_multiform(p->callable(), column.data, row.data);
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
		void contract::log_emit(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream stream;
			generic_context inout = generic_context(generic);
			void* object_value = inout.get_arg_address(0);
			int object_type_id = inout.get_arg_type_id(0);
			auto status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			format::variables returns;
			auto reader = stream.ro();
			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto id = type.is_valid() ? type.get_name() : std::string_view("primitive");
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s load failed", (int)id.size(), id.data())));

			auto code = algorithm::hashing::hash32d(id);
			auto data = immediate_context::get()->is_nested() ? p->executor->emit_forwarded_event(code, p->callable(), std::move(returns), true) : p->executor->emit_event(code, std::move(returns), true);
			if (!data)
				return contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));

			p->dispatch_event(object_type_id, object_value, object_type_id);
		}
		void contract::log_event(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_mutable_or_throw();
			if (!p)
				return;

			format::wo_stream stream;
			generic_context inout = generic_context(generic);
			void* object_value = inout.get_arg_address(1);
			int object_type_id = inout.get_arg_type_id(1);
			int event_type_id = inout.get_arg_type_id(0);
			auto status = marshall::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), std::string_view(status.error().message())));

			format::variables returns;
			auto reader = stream.ro();
			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto id = type.is_valid() ? type.get_name() : std::string_view("primitive");
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s load failed", (int)id.size(), id.data())));
			
			auto code = algorithm::hashing::hash32d(id);
			auto data = immediate_context::get()->is_nested() ? p->executor->emit_forwarded_event(code, p->callable(), std::move(returns), true) : p->executor->emit_event(code, std::move(returns), true);
			if (!data)
				contract::throw_ptr(exception_repr(exception_repr::category::storage(), std::string_view(data.error().message())));

			p->dispatch_event(event_type_id, object_value, object_type_id);
		}
		void contract::log_into(asIScriptGeneric* generic)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p)
				return;

			generic_context inout = generic_context(generic);
			int32_t event_index = inout.get_arg_dword(0);
			void* object_value = inout.get_arg_address(1);
			int object_type_id = inout.get_arg_type_id(1);
			address_repr* target_address = (address_repr*)inout.get_arg_address(2);
			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->executor->receipt.reverse_find_event(id, (size_t)(-event_index)) : p->executor->receipt.find_event(id, (size_t)event_index);
			if (!event || (target_address && !target_address->empty() ? (event->emitter.empty() ? target_address->hash == p->callable() : target_address->hash == event->emitter) : false))
			{
				inout.set_return_byte(false);
				return;
			}

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(event->args, &writer))
			{
				inout.set_return_byte(false);
				return;
			}

			format::ro_stream reader = writer.ro();
			inout.set_return_byte(!!marshall::load(reader, object_value, object_type_id));
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
			address_repr* target_address = (address_repr*)inout.get_arg_address(3);
			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->executor->receipt.reverse_find_event(id, (size_t)(-event_index)) : p->executor->receipt.find_event(id, (size_t)event_index);
			if (!event || (target_address && !target_address->empty() ? (event->emitter.empty() ? target_address->hash == p->callable() : target_address->hash == event->emitter) : false))
			{
				inout.set_return_byte(false);
				return;
			}

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(event->args, &writer))
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
			address_repr* target_address = (address_repr*)inout.get_arg_address(1);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto type = factory::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->executor->receipt.reverse_find_event(id, (size_t)(-event_index - 1)) : p->executor->receipt.find_event(id, (size_t)event_index);
			if (!event || (target_address && !target_address->empty() ? (event->emitter.empty() ? target_address->hash == p->callable() : target_address->hash == event->emitter) : false))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] not found", (int)name.size(), name.data(), event_index)));

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(event->args, &writer))
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
			address_repr* target_address = (address_repr*)inout.get_arg_address(2);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto type = factory::get()->get_vm()->get_type_info_by_id(event_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
			auto id = algorithm::hashing::hash32d(name);
			auto* event = event_index < 0 ? p->executor->receipt.reverse_find_event(id, (size_t)(-event_index - 1)) : p->executor->receipt.find_event(id, (size_t)event_index);
			if (!event || (target_address && !target_address->empty() ? (event->emitter.empty() ? target_address->hash == p->callable() : target_address->hash == event->emitter) : false))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] not found", (int)name.size(), name.data(), event_index)));

			format::wo_stream writer;
			if (!format::variables_util::serialize_flat_into(event->args, &writer))
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] store failed", (int)name.size(), name.data(), event_index)));

			format::ro_stream reader = writer.ro();
			auto status = marshall::load(reader, object_value, object_type_id);
			if (!status)
				return contract::throw_ptr(exception_repr(exception_repr::category::argument(), stringify::text("event %.*s[%i] load failed", (int)name.size(), name.data(), event_index)));
		}
		address_repr contract::block_proposer()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? address_repr(p->executor->solver->state.public_key_hash) : address_repr();
		}
		uint256_t contract::block_parent_hash()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->parent_hash : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_use()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_left()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->gas_limit - p->executor->block->gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::block_gas_limit()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->gas_limit : uint256_t((uint8_t)0);
		}
		uint128_t contract::block_difficulty()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? algorithm::wesolowski::kdifficulty(p->executor->block->difficulty) : uint128_t((uint8_t)0);
		}
		uint64_t contract::block_time()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->generation_time : 0;
		}
		uint64_t contract::block_time_between(uint64_t block_number_a, uint64_t block_number_b)
		{
			uint64_t left = std::min(block_number_a, block_number_b);
			uint64_t right = std::max(block_number_a, block_number_b);
			return (right - left) * protocol::now().policy.pow.time;
		}
		uint64_t contract::block_priority()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->block->priority : 0;
		}
		uint64_t contract::block_number()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->virtual_block_number() : 0;
		}
		payable_repr contract::tx_value()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->payable_value() : payable_repr();
		}
		bool contract::tx_paid()
		{
			return !tx_value().empty();
		}
		address_repr contract::tx_from()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? address_repr(p->executor->receipt.from) : address_repr();
		}
		address_repr contract::tx_to()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? address_repr(p->callable()) : address_repr();
		}
		string_repr contract::tx_blockchain()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::blockchain_of(p->executor->transaction->asset)) : string_repr();
		}
		string_repr contract::tx_token()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::token_of(p->executor->transaction->asset)) : string_repr();
		}
		string_repr contract::tx_contract()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? string_repr(algorithm::asset::checksum_of(p->executor->transaction->asset)) : string_repr();
		}
		decimal contract::tx_gas_price()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->transaction->gas_price : decimal::zero();
		}
		uint256_t contract::tx_gas_use()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->receipt.relative_gas_use : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_gas_left()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->get_gas_left() : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_gas_limit()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->transaction->gas_limit : uint256_t((uint8_t)0);
		}
		uint256_t contract::tx_asset()
		{
			auto* p = program::fetch_immutable_or_throw();
			return p ? p->executor->transaction->asset : uint256_t((uint8_t)0);
		}
		uint256_t contract::coin_native()
		{
			return algorithm::asset::native();
		}
		uint256_t contract::coin_token(const string_repr& token)
		{
			auto* p = program::fetch_immutable_or_throw();
			if (!p || token.empty())
				return algorithm::asset::native();

			return algorithm::asset::id_of(protocol::now().policy.token, token.view(), algorithm::signing::encode_address(p->callable()));
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
		uint256_t contract::alg_to_r256(const decimal& value)
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

			uint32_t integer_size = value.integer_size();
			if (integer_size > 60 || integer_size > protocol::now().message.integer_precision || value.decimal_size() > protocol::now().message.decimal_precision)
			{
				contract::throw_ptr(exception_repr(exception_repr::category::argument(), string_repr(value.to_string() + " as uint256 - fixed point overflow")));
				return 0;
			}

			auto copy = value;
			copy *= algorithm::arithmetic::integer_pow<uint64_t>(10, protocol::now().message.decimal_precision);

			auto result = uint256_t::max();
			if (copy < result.to_decimal())
				result = uint256_t(copy.truncate(0).to_string(), 10);
			return result;
		}
		decimal contract::alg_from_r256(const uint256_t& value)
		{
			auto precision = protocol::now().message.decimal_precision;
			auto result = value.to_decimal().truncate(precision);
			result /= algorithm::arithmetic::integer_pow<uint64_t>(10, protocol::now().message.decimal_precision);
			return result;
		}
		string_repr contract::alg_from_u256(const uint256_t& value)
		{
			uint8_t data[32];
			value.encode(data);
			return string_repr(std::string_view((char*)data, sizeof(data)));
		}
		uint256_t contract::alg_to_u256(const string_repr& value)
		{
			uint8_t data[32];
			memcpy(data, value.data(), std::min(sizeof(data), (size_t)value.size()));

			uint256_t buffer;
			buffer.decode(data);
			return buffer;
		}
		string_repr contract::alg_from_e16(const string_repr& value)
		{
			return string_repr(format::util::decode_0xhex(value.view()));
		}
		string_repr contract::alg_to_e16(const string_repr& value)
		{
			return string_repr(format::util::encode_0xhex(value.view()));
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
				p->cache.distribution = p->executor->get_random(p->executor->get_gas_use());

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
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_abs(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* v = inout.get_arg_address(0);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte((uint8_t)std::abs(*(int8_t*)v));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(*(uint8_t*)v);
					break;
				case (int)type_id::int16_t:
					inout.set_return_word((uint16_t)std::abs(*(int16_t*)v));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(*(uint16_t*)v);
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword((uint32_t)std::abs(*(int32_t*)v));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(*(uint32_t*)v);
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword((uint64_t)std::abs(*(int64_t*)v));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(*(uint64_t*)v);
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
						new (inout.get_address_of_return_location()) uint128_t(*(uint128_t*)v);
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						new (inout.get_address_of_return_location()) uint256_t(*(uint256_t*)v);
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						auto copy = *(decimal*)v;
						if (copy.is_negative())
							copy = -copy;
						new (inout.get_address_of_return_location()) decimal(std::move(copy));
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
			void* a = inout.get_arg_address(0);
			void* b = inout.get_arg_address(1);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte(std::min<int8_t>(*(int8_t*)a, *(int8_t*)b));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(std::min<uint8_t>(*(uint8_t*)a, *(uint8_t*)b));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word(std::min<int16_t>(*(int16_t*)a, *(int16_t*)b));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(std::min<uint16_t>(*(uint16_t*)a, *(uint16_t*)b));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword(std::min<int32_t>(*(int32_t*)a, *(int32_t*)b));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(std::min<uint32_t>(*(uint32_t*)a, *(uint32_t*)b));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword(std::min<int64_t>(*(int64_t*)a, *(int64_t*)b));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(std::min<uint64_t>(*(uint64_t*)a, *(uint64_t*)b));
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
						uint128_t& a_v = *(uint128_t*)a;
						uint128_t& b_v = *(uint128_t*)b;
						new (inout.get_address_of_return_location()) uint128_t(a_v < b_v ? a_v : b_v);
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						uint256_t& a_v = *(uint256_t*)a;
						uint256_t& b_v = *(uint256_t*)b;
						new (inout.get_address_of_return_location()) uint256_t(a_v < b_v ? a_v : b_v);
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& a_v = *(decimal*)a;
						decimal& b_v = *(decimal*)b;
						new (inout.get_address_of_return_location()) decimal(a_v < b_v ? a_v : b_v);
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_max(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* a = inout.get_arg_address(0);
			void* b = inout.get_arg_address(1);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte(std::max<int8_t>(*(int8_t*)a, *(int8_t*)b));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(std::max<uint8_t>(*(uint8_t*)a, *(uint8_t*)b));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word(std::max<int16_t>(*(int16_t*)a, *(int16_t*)b));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(std::max<uint16_t>(*(uint16_t*)a, *(uint16_t*)b));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword(std::max<int32_t>(*(int32_t*)a, *(int32_t*)b));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(std::max<uint32_t>(*(uint32_t*)a, *(uint32_t*)b));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword(std::max<int64_t>(*(int64_t*)a, *(int64_t*)b));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(std::max<uint64_t>(*(uint64_t*)a, *(uint64_t*)b));
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
						uint128_t& a_v = *(uint128_t*)a;
						uint128_t& b_v = *(uint128_t*)b;
						new (inout.get_address_of_return_location()) uint128_t(a_v > b_v ? a_v : b_v);
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						uint256_t& a_v = *(uint256_t*)a;
						uint256_t& b_v = *(uint256_t*)b;
						new (inout.get_address_of_return_location()) uint256_t(a_v > b_v ? a_v : b_v);
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& a_v = *(decimal*)a;
						decimal& b_v = *(decimal*)b;
						new (inout.get_address_of_return_location()) decimal(a_v > b_v ? a_v : b_v);
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_clamp(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* a = inout.get_arg_address(0);
			void* b = inout.get_arg_address(1);
			void* c = inout.get_arg_address(2);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte(std::min<int8_t>(std::max<int8_t>(*(int8_t*)a, *(int8_t*)b), *(int8_t*)c));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(std::min<uint8_t>(std::max<uint8_t>(*(uint8_t*)a, *(uint8_t*)b), *(uint8_t*)c));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word(std::min<int16_t>(std::max<int16_t>(*(int16_t*)a, *(int16_t*)b), *(int16_t*)c));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(std::min<uint16_t>(std::max<uint16_t>(*(uint16_t*)a, *(uint16_t*)b), *(uint16_t*)c));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword(std::min<int32_t>(std::max<int32_t>(*(int32_t*)a, *(int32_t*)b), *(int32_t*)c));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(std::min<uint32_t>(std::max<uint32_t>(*(uint32_t*)a, *(uint32_t*)b), *(uint32_t*)c));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword(std::min<int64_t>(std::max<int64_t>(*(int64_t*)a, *(int64_t*)b), *(int64_t*)c));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(std::min<uint64_t>(std::max<uint64_t>(*(uint64_t*)a, *(uint64_t*)b), *(uint64_t*)c));
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
						uint128_t& a_v = *(uint128_t*)a;
						uint128_t& b_v = *(uint128_t*)b;
						uint128_t& c_v = *(uint128_t*)c;
						uint128_t& ab_v = a_v > b_v ? a_v : b_v;
						new (inout.get_address_of_return_location()) uint128_t(ab_v < c_v ? ab_v : c_v);
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						uint256_t& a_v = *(uint256_t*)a;
						uint256_t& b_v = *(uint256_t*)b;
						uint256_t& c_v = *(uint256_t*)c;
						uint256_t& ab_v = a_v > b_v ? a_v : b_v;
						new (inout.get_address_of_return_location()) uint256_t(ab_v < c_v ? ab_v : c_v);
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& a_v = *(decimal*)a;
						decimal& b_v = *(decimal*)b;
						decimal& c_v = *(decimal*)c;
						decimal& ab_v = a_v > b_v ? a_v : b_v;
						new (inout.get_address_of_return_location()) decimal(ab_v < c_v ? ab_v : c_v);
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_lerp(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* a = inout.get_arg_address(0);
			void* b = inout.get_arg_address(1);
			void* c = inout.get_arg_address(2);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte(math<int8_t>::lerp(*(int8_t*)a, *(int8_t*)b, *(int8_t*)c));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(math<uint8_t>::lerp(*(uint8_t*)a, *(uint8_t*)b, *(uint8_t*)c));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word(math<int16_t>::lerp(*(int16_t*)a, *(int16_t*)b, *(int16_t*)c));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(math<uint16_t>::lerp(*(uint16_t*)a, *(uint16_t*)b, *(uint16_t*)c));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword(math<int32_t>::lerp(*(int32_t*)a, *(int32_t*)b, *(int32_t*)c));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(math<uint32_t>::lerp(*(uint32_t*)a, *(uint32_t*)b, *(uint32_t*)c));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword(math<int64_t>::lerp(*(int64_t*)a, *(int64_t*)b, *(int64_t*)c));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(math<uint64_t>::lerp(*(uint64_t*)a, *(uint64_t*)b, *(uint64_t*)c));
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
						uint128_t& a_v = *(uint128_t*)a;
						uint128_t& b_v = *(uint128_t*)b;
						uint128_t& c_v = *(uint128_t*)c;
						new (inout.get_address_of_return_location()) uint128_t(math<uint128_t>::lerp(a_v, b_v, c_v));
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						uint256_t& a_v = *(uint256_t*)a;
						uint256_t& b_v = *(uint256_t*)b;
						uint256_t& c_v = *(uint256_t*)c;
						new (inout.get_address_of_return_location()) uint256_t(math<uint256_t>::lerp(a_v, b_v, c_v));
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& a_v = *(decimal*)a;
						decimal& b_v = *(decimal*)b;
						decimal& c_v = *(decimal*)c;
						new (inout.get_address_of_return_location()) decimal(math<decimal>::lerp(a_v, b_v, c_v));
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_pow(asIScriptGeneric* generic)
		{
			if (!program::request_gas_mop(0))
				return;

			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* a = inout.get_arg_address(0);
			void* b = inout.get_arg_address(1);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte(algorithm::arithmetic::integer_pow<int8_t>(*(int8_t*)a, *(int8_t*)b));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(algorithm::arithmetic::integer_pow<uint8_t>(*(uint8_t*)a, *(uint8_t*)b));
					break;
				case (int)type_id::int16_t:
					if (*(int16_t*)b > (int16_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_word(algorithm::arithmetic::integer_pow<int16_t>(*(int16_t*)a, *(int16_t*)b));
					break;
				case (int)type_id::uint16_t:
					if (*(uint16_t*)b > (uint16_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_word(algorithm::arithmetic::integer_pow<uint16_t>(*(uint16_t*)a, *(uint16_t*)b));
					break;
				case (int)type_id::int32_t:
					if (*(int32_t*)b > (int32_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_dword(algorithm::arithmetic::integer_pow<int32_t>(*(int32_t*)a, *(int32_t*)b));
					break;
				case (int)type_id::uint32_t:
					if (*(uint32_t*)b > (uint32_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_dword(algorithm::arithmetic::integer_pow<uint32_t>(*(uint32_t*)a, *(uint32_t*)b));
					break;
				case (int)type_id::int64_t:
					if (*(int64_t*)b > (int64_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_qword(algorithm::arithmetic::integer_pow<int64_t>(*(int64_t*)a, *(int64_t*)b));
					break;
				case (int)type_id::uint64_t:
					if (*(uint64_t*)b > (uint64_t)std::numeric_limits<uint8_t>::max())
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

					inout.set_return_qword(algorithm::arithmetic::integer_pow<uint64_t>(*(uint64_t*)a, *(uint64_t*)b));
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
						uint128_t& a_v = *(uint128_t*)a;
						uint128_t& b_v = *(uint128_t*)b;
						if (b_v > uint128_t(std::numeric_limits<uint8_t>::max()))
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));
						
						new (inout.get_address_of_return_location()) uint128_t(algorithm::arithmetic::integer_pow<uint128_t>(a_v, b_v));
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						uint256_t& a_v = *(uint256_t*)a;
						uint256_t& b_v = *(uint256_t*)b;
						if (b_v > uint256_t(std::numeric_limits<uint8_t>::max()))
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));

						new (inout.get_address_of_return_location()) uint256_t(algorithm::arithmetic::integer_pow<uint256_t>(a_v, b_v));
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& a_v = *(decimal*)a;
						decimal& b_v = *(decimal*)b;
						if (b_v > decimal(std::numeric_limits<uint8_t>::max()))
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent overflow (max: 255)"));
						else if (b_v.is_negative())
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent must be positive"));
						else if (b_v != b_v.truncate(0))
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "exponent must be an integer"));

						mpf_t result;
						mpf_init(result);
						mpf_set_prec(result, real320_repr::target_bits());
						mpf_set_str(result, a_v.to_string().c_str(), 10);
						mpf_pow_ui(result, result, b_v.to_uint32());

						decimal r_v = decimal(mpf_to_string(result));
						real320_repr::truncate_or_throw(r_v, true);
						new (inout.get_address_of_return_location()) decimal(std::move(r_v));
						mpf_clear(result);
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
			}
		}
		void contract::math_sqrt(asIScriptGeneric* generic)
		{
			if (!program::request_gas_mop(0))
				return;

			generic_context inout = generic_context(generic);
			int type_id = inout.get_return_addressable_type_id();
			void* v = inout.get_arg_address(0);
			switch (type_id)
			{
				case (int)type_id::int8_t:
					if (*(int8_t*)v < 0)
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "value must be positive"));

					inout.set_return_byte(algorithm::arithmetic::integer_sqrt<int8_t>(*(int8_t*)v));
					break;
				case (int)type_id::uint8_t:
					inout.set_return_byte(algorithm::arithmetic::integer_sqrt<uint8_t>(*(uint8_t*)v));
					break;
				case (int)type_id::int16_t:
					if (*(int16_t*)v < 0)
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "value must be positive"));

					inout.set_return_word(algorithm::arithmetic::integer_sqrt<int16_t>(*(int16_t*)v));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(algorithm::arithmetic::integer_sqrt<uint16_t>(*(uint16_t*)v));
					break;
				case (int)type_id::int32_t:
					if (*(int32_t*)v < 0)
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "value must be positive"));

					inout.set_return_dword(algorithm::arithmetic::integer_sqrt<int32_t>(*(int32_t*)v));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(algorithm::arithmetic::integer_sqrt<uint32_t>(*(uint32_t*)v));
					break;
				case (int)type_id::int64_t:
					if (*(int64_t*)v < 0)
						return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "value must be positive"));

					inout.set_return_qword(algorithm::arithmetic::integer_sqrt<int64_t>(*(int64_t*)v));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(algorithm::arithmetic::integer_sqrt<uint64_t>(*(uint64_t*)v));
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
						new (inout.get_address_of_return_location()) uint128_t(algorithm::arithmetic::integer_sqrt<uint128_t>(*(uint128_t*)v));
						break;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						new (inout.get_address_of_return_location()) uint256_t(algorithm::arithmetic::integer_sqrt<uint256_t>(*(uint256_t*)v));
						break;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						decimal& v_v = (*(decimal*)v);
						if ((*(decimal*)v).is_negative())
							return contract::throw_ptr(exception_repr(exception_repr::category::argument(), "value must be positive"));

						mpf_t result;
						mpf_init(result);
						mpf_set_prec(result, real320_repr::target_bits());
						mpf_set_str(result, v_v.to_string().c_str(), 10);
						mpf_sqrt(result, result);

						decimal r_v = decimal(mpf_to_string(result));
						real320_repr::truncate_or_throw(r_v, true);
						new (inout.get_address_of_return_location()) decimal(std::move(r_v));
						mpf_clear(result);
						break;
					}
					return contract::throw_ptr(exception_repr(exception_repr::category::execution(), "template type must be arithmetic"));
				}
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
		exception_repr contract::get_exception_at(immediate_context* context, size_t offset)
		{
			return exception_repr(context, offset);
		}
		exception_repr contract::get_exception(size_t offset)
		{
			return get_exception_at(immediate_context::get(), offset);
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
					else if (name == SCRIPT_TYPE_PAYABLE)
					{
						stream->write_integer((uint8_t)((payable_repr*)value)->payments.size());
						for (auto& [paying_asset, paying_value] : ((payable_repr*)value)->payments)
						{
							stream->write_integer(paying_asset);
							stream->write_decimal(paying_value);
						}
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
		expects_lr<void> marshall::store(format::tree& stream, const void* value, int value_type_id)
		{
			if (!value)
				return expectation::met;

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					stream = format::tree();
					return expectation::met;
				case (int)type_id::bool_t:
					stream = format::tree(format::variable(*(bool*)value));
					return expectation::met;
				case (int)type_id::int8_t:
					stream = format::tree(format::variable(decimal(*(int8_t*)value)));
					return expectation::met;
				case (int)type_id::uint8_t:
					stream = format::tree(format::variable(*(uint8_t*)value));
					return expectation::met;
				case (int)type_id::int16_t:
					stream = format::tree(format::variable(decimal(*(int16_t*)value)));
					return expectation::met;
				case (int)type_id::uint16_t:
					stream = format::tree(format::variable(*(uint16_t*)value));
					return expectation::met;
				case (int)type_id::int32_t:
					stream = format::tree(format::variable(decimal(*(int32_t*)value)));
					return expectation::met;
				case (int)type_id::uint32_t:
					stream = format::tree(format::variable(*(uint32_t*)value));
					return expectation::met;
				case (int)type_id::int64_t:
					stream = format::tree(format::variable(decimal(*(int64_t*)value)));
					return expectation::met;
				case (int)type_id::uint64_t:
					stream = format::tree(format::variable(*(uint64_t*)value));
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
						stream = format::tree(algorithm::signing::serialize_address(((address_repr*)value)->hash));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_PAYABLE)
					{
						stream = format::tree::list();
						for (auto& [paying_asset, paying_value] : ((payable_repr*)value)->payments)
						{
							auto paying = stream.push(format::tree::map());
							paying->set("asset", algorithm::asset::serialize(paying_asset));
							paying->set("value", format::variable(paying_value));
						}
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						stream = format::tree(format::variable(((string_repr*)value)->view()));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						stream = algorithm::encoding::serialize_uint256(*(uint128_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						stream = algorithm::encoding::serialize_uint256(*(uint256_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						stream = format::tree(format::variable(*(decimal*)value));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						auto* array = (array_repr*)value;
						uint32_t size = (uint32_t)array->size();
						int type_id = array->get_element_type_id();
						stream = format::tree::list();
						stream.childs().reserve(size);
						for (uint32_t i = 0; i < size; i++)
						{
							void* address = array->at(i);
							auto status = store(*stream.push(format::tree()), address, type_id);
							if (!status)
								return status;
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						stream = format::tree::map();
						stream.childs().reserve(properties);
						for (size_t i = 0; i < properties; i++)
						{
							std::string_view field = object.get_property_name(i);
							void* address = object.get_address_of_property(i);
							int type_id = object.get_property_type_id(i);
							auto child = format::tree();
							auto status = store(child, address, type_id);
							if (!status)
								return status;

							stream.set(field, std::move(child));
						}
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						stream = format::tree(format::variable((uint32_t)*(int*)value));
						return expectation::met;
					}
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> marshall::load(format::ro_stream& stream, void* value, int value_type_id, bool allow_partial)
		{
			if (!value)
				return layer_exception("load failed for null type");

			size_t seek = stream.seek;
			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					if (!stream.read_boolean(stream.read_type(), (bool*)value))
						return layer_exception("load failed for bool type");

					program::request_gas_vmemory_marshall(stream, seek);
					return expectation::met;
				case (int)type_id::int8_t:
				case (int)type_id::uint8_t:
					if (!stream.read_integer(stream.read_type(), (uint8_t*)value))
						return layer_exception("load failed for uint8 type");

					program::request_gas_vmemory_marshall(stream, seek);
					return expectation::met;
				case (int)type_id::int16_t:
				case (int)type_id::uint16_t:
					if (!stream.read_integer(stream.read_type(), (uint16_t*)value))
						return layer_exception("load failed for uint16 type");

					program::request_gas_vmemory_marshall(stream, seek);
					return expectation::met;
				case (int)type_id::int32_t:
				case (int)type_id::uint32_t:
					if (!stream.read_integer(stream.read_type(), (uint32_t*)value))
						return layer_exception("load failed for uint32 type");

					program::request_gas_vmemory_marshall(stream, seek);
					return expectation::met;
				case (int)type_id::int64_t:
				case (int)type_id::uint64_t:
					if (!stream.read_integer(stream.read_type(), (uint64_t*)value))
						return layer_exception("load failed for uint64 type");

					program::request_gas_vmemory_marshall(stream, seek);
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					auto* vm = factory::get()->get_vm();
					void* address = nullptr, *address_ptr = value;
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (((value_type_id & (int)vitex::scripting::type_id::handle_t) || (type.flags() & (size_t)object_behaviours::ref)) && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("%s has no default constructor", name.data()));

						*(void**)value = address;
						value = address;
					}

					auto unique = cobject(vm, type.get_type_info(), address, address ? (void**)address_ptr : nullptr);
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

						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_PAYABLE)
					{
						uint8_t payments_size;
						if (!stream.read_integer(stream.read_type(), &payments_size))
							return layer_exception("load failed for payable type");

						auto* payable = new (value) payable_repr();
						payable->payments.reserve((size_t)payments_size);
						for (uint8_t i = 0; i < payments_size; i++)
						{
							algorithm::asset_id payment_asset;
							if (!stream.read_integer(stream.read_type(), &payment_asset))
								return layer_exception("load failed for payable type");

							decimal payment_value;
							if (!stream.read_decimal(stream.read_type(), &payment_value))
								return layer_exception("load failed for payable type");

							if (!algorithm::asset::is_any(payment_asset) || payment_value.is_nan() || payment_value.is_negative())
								return layer_exception("load failed for payable type");

							payable->payments.push_back(std::make_pair(std::move(payment_asset), std::move(payment_value)));
						}

						payable->recalculate();
						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for string type");

						new (value) string_repr(data);
						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						auto* data = new (value) uint128_t();
						if (!stream.read_integer(stream.read_type(), data))
							return layer_exception("load failed for uint128 type");

						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						auto* data = new (value) uint256_t();
						if (!stream.read_integer(stream.read_type(), data))
							return layer_exception("load failed for uint256 type");

						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						auto* data = new (value) decimal();
						if (!stream.read_decimal_or_integer(stream.read_type(), data))
							return layer_exception("load failed for decimal type");

						unique.reset();
						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						uint32_t size;
						if (!stream.read_integer(stream.read_type(), &size))
							return layer_exception("load failed for uint32 type");

						int sub_type_id = type.get_sub_type_id();
						auto* array = (array_repr*)value;
						array->clear();
						array->resize(size);
						for (uint32_t i = 0; i < size; i++)
						{
							auto status = load(stream, array->at(i), sub_type_id, false);
							if (!status)
								return status;
						}

						unique.reset();
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						for (size_t i = 0; i < properties; i++)
						{
							if (allow_partial && stream.is_eof())
								break;

							auto status = load(stream, object.get_address_of_property(i), object.get_property_type_id(i), false);
							if (!status)
								return status;
						}

						unique.reset();
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						if (!stream.read_integer(stream.read_type(), (uint32_t*)value))
							return layer_exception("load failed for uint32 type");

						program::request_gas_vmemory_marshall(stream, seek);
						return expectation::met;
					}
					return layer_exception(stringify::text("load not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> marshall::load(format::tree& stream, void* value, int value_type_id, bool allow_partial)
		{
			if (!value)
				return layer_exception("load failed for null type");

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					*(bool*)value = stream.value.as_boolean();
					program::request_gas_vmemory(sizeof(bool));
					return expectation::met;
				case (int)type_id::int8_t:
					*(int8_t*)value = stream.value.as_decimal().to_int8();
					program::request_gas_vmemory(sizeof(int8_t));
					return expectation::met;
				case (int)type_id::uint8_t:
					*(uint8_t*)value = stream.value.as_uint8();
					program::request_gas_vmemory(sizeof(uint8_t));
					return expectation::met;
				case (int)type_id::int16_t:
					*(int16_t*)value = stream.value.as_decimal().to_int16();
					program::request_gas_vmemory(sizeof(int16_t));
					return expectation::met;
				case (int)type_id::uint16_t:
					*(uint16_t*)value = stream.value.as_uint16();
					program::request_gas_vmemory(sizeof(uint16_t));
					return expectation::met;
				case (int)type_id::int32_t:
					*(int32_t*)value = stream.value.as_decimal().to_int32();
					program::request_gas_vmemory(sizeof(int32_t));
					return expectation::met;
				case (int)type_id::uint32_t:
					*(uint32_t*)value = stream.value.as_uint32();
					program::request_gas_vmemory(sizeof(uint32_t));
					return expectation::met;
				case (int)type_id::int64_t:
					*(int64_t*)value = stream.value.as_decimal().to_int64();
					program::request_gas_vmemory(sizeof(int64_t));
					return expectation::met;
				case (int)type_id::uint64_t:
					*(uint64_t*)value = stream.value.as_uint64();
					program::request_gas_vmemory(sizeof(uint64_t));
					return expectation::met;
				case (int)type_id::float_t:
				case (int)type_id::double_t:
					return layer_exception("floating point value not permitted");
				default:
				{
					auto* vm = factory::get()->get_vm();
					void* address = nullptr, * address_ptr = value;
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (((value_type_id & (int)vitex::scripting::type_id::handle_t) || (type.flags() & (size_t)object_behaviours::ref)) && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("%s has no default constructor", name.data()));

						*(void**)value = address;
						value = address;
					}

					auto unique = cobject(vm, type.get_type_info(), address, address ? (void**)address_ptr : nullptr);
					if (name == SCRIPT_TYPE_ADDRESS)
					{
						string data = stream.value.as_blob();
						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::pubkeyhash_t))
						{
							if (!algorithm::signing::decode_address(data, ((address_repr*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							((address_repr*)value)->hash = algorithm::pubkeyhash_t(data);

						unique.reset();
						program::request_gas_vmemory(data.size());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_PAYABLE)
					{
						auto* payable = new (value) payable_repr();
						payable->payments.reserve(stream.childs().size());
						for (auto& payment : stream.childs())
						{
							algorithm::asset_id payment_asset = payment.child_var("asset.id").as_uint256();;
							decimal payment_value = payment.child_var("value").as_decimal();
							if (!algorithm::asset::is_any(payment_asset) || payment_value.is_nan() || payment_value.is_negative())
								return layer_exception("load failed for payable type");

							payable->payments.push_back(std::make_pair(std::move(payment_asset), std::move(payment_value)));
						}

						payable->recalculate();
						unique.reset();
						program::request_gas_vmemory(payable->payments.size() * sizeof(uint256_t));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_STRING)
					{
						auto* data = new (value) string_repr(stream.value.as_blob());
						unique.reset();
						program::request_gas_vmemory(data->size());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT128)
					{
						new (value) uint128_t(stream.value.as_uint128());
						unique.reset();
						program::request_gas_vmemory(sizeof(uint128_t));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_UINT256)
					{
						new (value) uint256_t(stream.value.as_uint256());
						unique.reset();
						program::request_gas_vmemory(sizeof(uint256_t));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_REAL320)
					{
						new (value) decimal(stream.value.as_decimal());
						unique.reset();
						program::request_gas_vmemory(sizeof(uint256_t));
						return expectation::met;
					}
					else if (name == SCRIPT_TYPE_ARRAY)
					{
						uint32_t size = (uint32_t)stream.childs().size();
						int sub_type_id = type.get_sub_type_id();
						auto* array = (array_repr*)value;
						array->clear();
						array->resize(size);
						for (uint32_t i = 0; i < size; i++)
						{
							auto status = load(stream.childs()[i], array->at(i), sub_type_id, false);
							if (!status)
								return status;
						}

						unique.reset();
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::script_object_t)
					{
						auto object = script_object((asIScriptObject*)value);
						size_t properties = object.get_properties_count();
						for (size_t i = 0; i < properties; i++)
						{
							std::string_view field = object.get_property_name(i);
							auto* substream = (format::tree*)stream.child(field);
							if (!substream && !allow_partial)
								return layer_exception(stringify::text("load failed for %s type while searching for %s property", field.data(), field.data()));
							else if (!substream && allow_partial)
								break;

							auto status = load(*substream, object.get_address_of_property(i), object.get_property_type_id(i), false);
							if (!status)
								return status;
						}

						unique.reset();
						return expectation::met;
					}
					else if (value_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						*(int*)value = stream.value.as_decimal().to_int32();
						program::request_gas_vmemory(sizeof(int32_t));
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

		factory::factory() noexcept : vm(new virtual_machine()), vmc_tools(false), strings(memory::init<string_repr_cache_type>())
		{
			vm->set_type_def("usize", "uint32");
			auto pmut = vm->set_class_address("pmut", sizeof(program), (size_t)object_behaviours::ref | (size_t)object_behaviours::nocount);
			auto pconst = vm->set_class_address("pconst", sizeof(program), (size_t)object_behaviours::ref | (size_t)object_behaviours::nocount);
			auto array_type = vm->set_template_class_address("array<class t>", "array<t>", sizeof(array_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::ref | (size_t)object_behaviours::gc);
			auto string_type = vm->set_struct_address("string", sizeof(string_repr), (size_t)object_behaviours::value | bridge::type_traits_of<string_repr>());
			auto uint128_type = vm->set_struct_address("uint128", sizeof(uint128_t), (size_t)object_behaviours::value | (size_t)object_behaviours::app_class_allints | bridge::type_traits_of<uint128_t>());
			auto uint256_type = vm->set_struct_address("uint256", sizeof(uint256_t), (size_t)object_behaviours::value | (size_t)object_behaviours::app_class_allints | bridge::type_traits_of<uint256_t>());
			auto real320_type = vm->set_struct_address("real320", sizeof(decimal), (size_t)object_behaviours::value | bridge::type_traits_of<decimal>());
			auto payable_type = vm->set_struct_address("payable", sizeof(payable_repr), (size_t)object_behaviours::value | bridge::type_traits_of<payable_repr>());
			auto address_type = vm->set_struct_address("address", sizeof(address_repr), (size_t)object_behaviours::value | bridge::type_traits_of<address_repr>());
			auto batch_payout_type = vm->set_struct_address("batch_payout", sizeof(batch_payout_repr), (size_t)object_behaviours::value | bridge::type_traits_of<batch_payout_repr>());
			auto abi_type = vm->set_struct_address("abi", sizeof(abi_repr), (size_t)object_behaviours::value | bridge::type_traits_of<abi_repr>());
			auto varying_type = vm->set_template_class_address("varying<class t>", "varying<t>", sizeof(varying_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<varying_repr>());
			auto mapping_type = vm->set_template_class_address("mapping<class k, class v>", "mapping<k, v>", sizeof(mapping_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<mapping_repr>());
			auto listing_type = vm->set_template_class_address("listing<class v>", "listing<v>", sizeof(listing_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<listing_repr>());
			auto ranging_type = vm->set_template_class_address("ranging<class c, class r, class v>", "ranging<c, r, v>", sizeof(ranging_repr), (size_t)object_behaviours::pattern | (size_t)object_behaviours::value | bridge::type_traits_of<ranging_repr>());
			auto ranging_slice_type = vm->set_struct_address("ranging_slice", sizeof(ranging_slice_repr), (size_t)object_behaviours::value | bridge::type_traits_of<ranging_slice_repr>());
			array_type->set_behaviour_address("array<t>@ f(int&in)", behaviours::factory, WRAP_FN_PR(array_repr::construct, (asITypeInfo*), array_repr*), convention::generic_call);
			array_type->set_behaviour_address("array<t>@ f(int&in, usize) explicit", behaviours::factory, WRAP_FN_PR(array_repr::construct, (asITypeInfo*, uint32_t), array_repr*), convention::generic_call);
			array_type->set_behaviour_address("array<t>@ f(int&in, usize, const t&in) explicit", behaviours::factory, WRAP_FN_PR(array_repr::construct, (asITypeInfo*, uint32_t, void*), array_repr*), convention::generic_call);
			array_type->set_behaviour_address("bool f(int&in, bool&out)", behaviours::template_callback, WRAP_FN(array_repr::template_callback), convention::generic_call);
			array_type->set_behaviour_address("void f()", behaviours::add_ref, WRAP_OBJ_FIRST(ref_base_class::gc_add_ref<array_repr>), convention::generic_call);
			array_type->set_behaviour_address("void f()", behaviours::release, WRAP_OBJ_FIRST(ref_base_class::gc_release<array_repr>), convention::generic_call);
			array_type->set_behaviour_address("void f()", behaviours::set_gc_flag, WRAP_OBJ_FIRST(ref_base_class::gc_mark_ref<array_repr>), convention::generic_call);
			array_type->set_behaviour_address("bool f()", behaviours::get_gc_flag, WRAP_OBJ_FIRST(ref_base_class::gc_is_marked_ref<array_repr>), convention::generic_call);
			array_type->set_behaviour_address("int f()", behaviours::get_ref_count, WRAP_OBJ_FIRST(ref_base_class::gc_get_ref_count<array_repr>), convention::generic_call);
			array_type->set_behaviour_address("void f(int &in)", behaviours::enum_refs, WRAP_MFN(array_repr, enum_references), convention::generic_call);
			array_type->set_behaviour_address("void f(int &in)", behaviours::release_refs, WRAP_MFN(array_repr, release_references), convention::generic_call);
			array_type->set_operator_copy_address(WRAP_MFN(array_repr, operator=), convention::generic_call);
			array_type->set_method_address("t& opIndex(usize)", WRAP_MFN_PR(array_repr, at, (uint32_t), void*), convention::generic_call);
			array_type->set_method_address("const t& opIndex(usize) const", WRAP_MFN_PR(array_repr, at, (uint32_t) const, const void*), convention::generic_call);
			array_type->set_method_address("t& front()", WRAP_MFN_PR(array_repr, front, (), void*), convention::generic_call);
			array_type->set_method_address("const t& front() const", WRAP_MFN_PR(array_repr, front, () const, const void*), convention::generic_call);
			array_type->set_method_address("t& back()", WRAP_MFN_PR(array_repr, back, (), void*), convention::generic_call);
			array_type->set_method_address("const t& back() const", WRAP_MFN_PR(array_repr, back, () const, const void*), convention::generic_call);
			array_type->set_method_address("bool empty() const", WRAP_MFN(array_repr, empty), convention::generic_call);
			array_type->set_method_address("usize size() const", WRAP_MFN(array_repr, size), convention::generic_call);
			array_type->set_method_address("void resize(usize)", WRAP_MFN(array_repr, resize), convention::generic_call);
			array_type->set_method_address("void clear()", WRAP_MFN(array_repr, clear), convention::generic_call);
			array_type->set_method_address("void push(const t&in)", WRAP_MFN(array_repr, insert_last), convention::generic_call);
			array_type->set_method_address("void push_front(const t&in)", WRAP_MFN(array_repr, insert_first), convention::generic_call);
			array_type->set_method_address("void pop()", WRAP_MFN(array_repr, remove_last), convention::generic_call);
			array_type->set_method_address("void pop_front()", WRAP_MFN(array_repr, remove_first), convention::generic_call);
			array_type->set_method_address("void insert(usize, const t&in)", WRAP_MFN(array_repr, insert_at), convention::generic_call);
			array_type->set_method_address("void insert(usize, const array<t>&)", WRAP_MFN(array_repr, insert_array_at), convention::generic_call);
			array_type->set_method_address("void erase(usize)", WRAP_MFN(array_repr, remove_at), convention::generic_call);
			array_type->set_method_address("void erase(usize, usize)", WRAP_MFN(array_repr, remove_range), convention::generic_call);
			array_type->set_method_address("void reverse()", WRAP_MFN(array_repr, reverse), convention::generic_call);
			array_type->set_method_address("void swap(usize, usize)", WRAP_MFN(array_repr, swap), convention::generic_call);
			string_type->set_behaviour_address("void f()", behaviours::construct, WRAP_OBJ_FIRST(string_repr::construct), convention::generic_call);
			string_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_OBJ_FIRST(string_repr::construct_copy), convention::generic_call);
			string_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_OBJ_FIRST(string_repr::destroy), convention::generic_call);
			string_type->set_operator_copy_address(WRAP_MFN(string_repr, assign), convention::generic_call);
			string_type->set_method_address("string& opAddAssign(const string&in)", WRAP_MFN(string_repr, assign_append), convention::generic_call);
			string_type->set_method_address("string& opAddAssign(uint8)", WRAP_MFN(string_repr, assign_append_char), convention::generic_call);
			string_type->set_method_address("string opAdd(const string&in) const", WRAP_MFN(string_repr, append), convention::generic_call);
			string_type->set_method_address("string opAdd(uint8) const", WRAP_MFN(string_repr, append_char_back), convention::generic_call);
			string_type->set_method_address("string opAdd_r(uint8) const", WRAP_MFN(string_repr, append_char_front), convention::generic_call);
			string_type->set_method_address("int opCmp(const string&in) const", WRAP_MFN(string_repr, compare), convention::generic_call);
			string_type->set_method_address("uint8& opIndex(usize)", WRAP_MFN(string_repr, at), convention::generic_call);
			string_type->set_method_address("const uint8& opIndex(usize) const", WRAP_MFN(string_repr, at), convention::generic_call);
			string_type->set_method_address("uint8& at(usize)", WRAP_MFN(string_repr, at), convention::generic_call);
			string_type->set_method_address("const uint8& at(usize) const", WRAP_MFN(string_repr, at), convention::generic_call);
			string_type->set_method_address("uint8& front()", WRAP_MFN(string_repr, front), convention::generic_call);
			string_type->set_method_address("const uint8& front() const", WRAP_MFN(string_repr, front), convention::generic_call);
			string_type->set_method_address("uint8& back()", WRAP_MFN(string_repr, back), convention::generic_call);
			string_type->set_method_address("const uint8& back() const", WRAP_MFN(string_repr, back), convention::generic_call);
			string_type->set_method_address("bool empty() const", WRAP_MFN(string_repr, empty), convention::generic_call);
			string_type->set_method_address("usize size() const", WRAP_MFN(string_repr, size), convention::generic_call);
			string_type->set_method_address("void clear()", WRAP_MFN(string_repr, clear), convention::generic_call);
			string_type->set_method_address("string& append(const string&in)", WRAP_MFN(string_repr, assign_append), convention::generic_call);
			string_type->set_method_address("string& append(uint8)", WRAP_MFN(string_repr, assign_append_char), convention::generic_call);
			string_type->set_method_address("void push(uint8)", WRAP_MFN(string_repr, push_back), convention::generic_call);
			string_type->set_method_address("void pop()", WRAP_MFN(string_repr, pop_back), convention::generic_call);
			string_type->set_method_address("bool starts_with(const string&in, usize = 0) const", WRAP_MFN(string_repr, starts_with), convention::generic_call);
			string_type->set_method_address("bool ends_with(const string&in) const", WRAP_MFN(string_repr, ends_with), convention::generic_call);
			string_type->set_method_address("string substring(usize) const", WRAP_MFN(string_repr, substring), convention::generic_call);
			string_type->set_method_address("string substring(usize, usize) const", WRAP_MFN(string_repr, substring_sized), convention::generic_call);
			string_type->set_method_address("string& trim()", WRAP_MFN(string_repr, trim), convention::generic_call);
			string_type->set_method_address("string& trim_front()", WRAP_MFN(string_repr, trim_start), convention::generic_call);
			string_type->set_method_address("string& trim_back()", WRAP_MFN(string_repr, trim_end), convention::generic_call);
			string_type->set_method_address("string& lower()", WRAP_MFN(string_repr, to_lower), convention::generic_call);
			string_type->set_method_address("string& upper()", WRAP_MFN(string_repr, to_upper), convention::generic_call);
			string_type->set_method_address("string& reverse()", WRAP_MFN(string_repr, reverse), convention::generic_call);
			string_type->set_method_address("usize rfind(const string&in) const", WRAP_MFN(string_repr, rfind), convention::generic_call);
			string_type->set_method_address("usize rfind(uint8) const", WRAP_MFN(string_repr, rfind_char), convention::generic_call);
			string_type->set_method_address("usize rfind(const string&in, usize) const", WRAP_MFN(string_repr, rfind_offset), convention::generic_call);
			string_type->set_method_address("usize rfind(uint8, usize) const", WRAP_MFN(string_repr, rfind_char_offset), convention::generic_call);
			string_type->set_method_address("usize find(const string&in, usize = 0) const", WRAP_MFN(string_repr, find), convention::generic_call);
			string_type->set_method_address("usize find(uint8, usize = 0) const", WRAP_MFN(string_repr, find_char), convention::generic_call);
			string_type->set_method_address("usize find_first_of(const string&in, usize = 0) const", WRAP_MFN(string_repr, find_first_of), convention::generic_call);
			string_type->set_method_address("usize find_first_not_of(const string&in, usize = 0) const", WRAP_MFN(string_repr, find_first_not_of), convention::generic_call);
			string_type->set_method_address("usize find_last_of(const string&in) const", WRAP_MFN(string_repr, find_last_of), convention::generic_call);
			string_type->set_method_address("usize find_last_not_of(const string&in) const", WRAP_MFN(string_repr, find_last_not_of), convention::generic_call);
			string_type->set_method_address("usize find_last_of(const string&in, usize) const", WRAP_MFN(string_repr, find_last_of_offset), convention::generic_call);
			string_type->set_method_address("usize find_last_not_of(const string&in, usize) const", WRAP_MFN(string_repr, find_last_not_of_offset), convention::generic_call);
			string_type->set_method_address("array<string>@ split(const string&in) const", WRAP_MFN(string_repr, split), convention::generic_call);
			string_type->set_method_address("int8 i8(int = 10)", WRAP_MFN(string_repr, from_string<int8_t>), convention::generic_call);
			string_type->set_method_address("int16 i16(int = 10)", WRAP_MFN(string_repr, from_string<int16_t>), convention::generic_call);
			string_type->set_method_address("int32 i32(int = 10)", WRAP_MFN(string_repr, from_string<int32_t>), convention::generic_call);
			string_type->set_method_address("int64 i64(int = 10)", WRAP_MFN(string_repr, from_string<int64_t>), convention::generic_call);
			string_type->set_method_address("uint8 u8(int = 10)", WRAP_MFN(string_repr, from_string<uint8_t>), convention::generic_call);
			string_type->set_method_address("uint16 u16(int = 10)", WRAP_MFN(string_repr, from_string<uint16_t>), convention::generic_call);
			string_type->set_method_address("uint32 u32(int = 10)", WRAP_MFN(string_repr, from_string<uint32_t>), convention::generic_call);
			string_type->set_method_address("uint64 u64(int = 10)", WRAP_MFN(string_repr, from_string<uint64_t>), convention::generic_call);
			string_type->set_method_address("uint128 u128(int = 10)", WRAP_MFN(string_repr, from_string_uint128), convention::generic_call);
			string_type->set_method_address("uint256 u256(int = 10)", WRAP_MFN(string_repr, from_string_uint256), convention::generic_call);
			string_type->set_method_address("real320 r320(int = 10)", WRAP_MFN(string_repr, from_string_decimal), convention::generic_call);
			uint128_type->set_behaviour_address("void f()", behaviours::construct, WRAP_OBJ_FIRST(uint128_repr::default_construct), convention::generic_call);
			uint128_type->set_behaviour_address("void f(int8)", behaviours::construct, WRAP_CON(uint128_t, (int8_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(uint8)", behaviours::construct, WRAP_CON(uint128_t, (uint8_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(int16)", behaviours::construct, WRAP_CON(uint128_t, (int16_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(uint16)", behaviours::construct, WRAP_CON(uint128_t, (uint16_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(int32)", behaviours::construct, WRAP_CON(uint128_t, (int32_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(uint32)", behaviours::construct, WRAP_CON(uint128_t, (uint32_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(int64)", behaviours::construct, WRAP_CON(uint128_t, (int64_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(uint64)", behaviours::construct, WRAP_CON(uint128_t, (uint64_t)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(const uint128&in)", behaviours::construct, WRAP_CON(uint128_t, (const uint128_t&)), convention::generic_call);
			uint128_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_OBJ_FIRST(uint128_repr::construct_string), convention::generic_call);
			uint128_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(uint128_t), convention::generic_call);
			uint128_type->set_operator_copy_address(WRAP_MFN_PR(uint128_t, operator=, (const uint128_t&), uint128_t&), convention::generic_call);
			uint128_type->set_operator_address("uint128& opMulAssign(const uint128&in)", WRAP_OBJ_FIRST(uint128_repr::mul_eq), convention::generic_call);
			uint128_type->set_operator_address("uint128& opDivAssign(const uint128&in)", WRAP_OBJ_FIRST(uint128_repr::div_eq), convention::generic_call);
			uint128_type->set_operator_address("uint128& opAddAssign(const uint128&in)", WRAP_OBJ_FIRST(uint128_repr::add_eq), convention::generic_call);
			uint128_type->set_operator_address("uint128& opSubAssign(const uint128&in)", WRAP_OBJ_FIRST(uint128_repr::sub_eq), convention::generic_call);
			uint128_type->set_operator_address("uint128& opPreInc()", WRAP_OBJ_FIRST(uint128_repr::fpp), convention::generic_call);
			uint128_type->set_operator_address("uint128& opPreDec()", WRAP_OBJ_FIRST(uint128_repr::fmm), convention::generic_call);
			uint128_type->set_operator_address("uint128& opPostInc()", WRAP_OBJ_FIRST(uint128_repr::pp), convention::generic_call);
			uint128_type->set_operator_address("uint128& opPostDec()", WRAP_OBJ_FIRST(uint128_repr::mm), convention::generic_call);
			uint128_type->set_operator_address("bool opEquals(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::eq), convention::generic_call);
			uint128_type->set_operator_address("int opCmp(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::cmp), convention::generic_call);
			uint128_type->set_operator_address("uint128 opMul(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::mul), convention::generic_call);
			uint128_type->set_operator_address("uint128 opDiv(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::div), convention::generic_call);
			uint128_type->set_operator_address("uint128 opAdd(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::add), convention::generic_call);
			uint128_type->set_operator_address("uint128 opSub(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::sub), convention::generic_call);
			uint128_type->set_operator_address("uint128 opMod(const uint128&in) const", WRAP_OBJ_FIRST(uint128_repr::per), convention::generic_call);
			uint128_type->set_method_address("bool opImplConv() const", WRAP_OBJ_FIRST(uint128_repr::to_bool), convention::generic_call);
			uint128_type->set_method_address("int8 i8() const", WRAP_OBJ_FIRST(uint128_repr::to_int8), convention::generic_call);
			uint128_type->set_method_address("int16 i16() const", WRAP_OBJ_FIRST(uint128_repr::to_int16), convention::generic_call);
			uint128_type->set_method_address("int32 i32() const", WRAP_OBJ_FIRST(uint128_repr::to_int32), convention::generic_call);
			uint128_type->set_method_address("int64 i64() const", WRAP_OBJ_FIRST(uint128_repr::to_int64), convention::generic_call);
			uint128_type->set_method_address("uint8 u8() const", WRAP_OBJ_FIRST(uint128_repr::to_uint8), convention::generic_call);
			uint128_type->set_method_address("uint16 u16() const", WRAP_OBJ_FIRST(uint128_repr::to_uint16), convention::generic_call);
			uint128_type->set_method_address("uint32 u32() const", WRAP_OBJ_FIRST(uint128_repr::to_uint32), convention::generic_call);
			uint128_type->set_method_address("uint64 u64() const", WRAP_OBJ_FIRST(uint128_repr::to_uint64), convention::generic_call);
			uint128_type->set_method_address("uint256 u256() const", WRAP_OBJ_FIRST(uint128_repr::to_uint256), convention::generic_call);
			uint128_type->set_method_address("real320 r320() const", WRAP_MFN(uint128_t, to_decimal), convention::generic_call);
			uint128_type->set_method_address("uint8 bits() const", WRAP_MFN(uint128_t, bits), convention::generic_call);
			uint128_type->set_method_address("uint8 bytes() const", WRAP_MFN(uint128_t, bytes), convention::generic_call);
			uint256_type->set_behaviour_address("void f()", behaviours::construct, WRAP_OBJ_FIRST(uint256_repr::default_construct), convention::generic_call);
			uint256_type->set_behaviour_address("void f(int8)", behaviours::construct, WRAP_CON(uint256_t, (int8_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(uint8)", behaviours::construct, WRAP_CON(uint256_t, (uint8_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(int16)", behaviours::construct, WRAP_CON(uint256_t, (int16_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(uint16)", behaviours::construct, WRAP_CON(uint256_t, (uint16_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(int32)", behaviours::construct, WRAP_CON(uint256_t, (int32_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(uint32)", behaviours::construct, WRAP_CON(uint256_t, (uint32_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(int64)", behaviours::construct, WRAP_CON(uint256_t, (int64_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(uint64)", behaviours::construct, WRAP_CON(uint256_t, (uint64_t)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(const uint256&in)", behaviours::construct, WRAP_CON(uint256_t, (const uint256_t&)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(const uint128&in)", behaviours::construct, WRAP_CON(uint256_t, (const uint128_t&)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(const uint128&in, const uint128&in)", behaviours::construct, WRAP_CON(uint256_t, (const uint128_t&, const uint128_t&)), convention::generic_call);
			uint256_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_OBJ_FIRST(uint256_repr::construct_string), convention::generic_call);
			uint256_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(uint256_t), convention::generic_call);
			uint256_type->set_operator_copy_address(WRAP_MFN_PR(uint256_t, operator=, (const uint256_t&), uint256_t&), convention::generic_call);
			uint256_type->set_operator_address("uint256& opMulAssign(const uint256&in)", WRAP_OBJ_FIRST(uint256_repr::mul_eq), convention::generic_call);
			uint256_type->set_operator_address("uint256& opDivAssign(const uint256&in)", WRAP_OBJ_FIRST(uint256_repr::div_eq), convention::generic_call);
			uint256_type->set_operator_address("uint256& opAddAssign(const uint256&in)", WRAP_OBJ_FIRST(uint256_repr::add_eq), convention::generic_call);
			uint256_type->set_operator_address("uint256& opSubAssign(const uint256&in)", WRAP_OBJ_FIRST(uint256_repr::sub_eq), convention::generic_call);
			uint256_type->set_operator_address("uint256& opPreInc()", WRAP_OBJ_FIRST(uint256_repr::fpp), convention::generic_call);
			uint256_type->set_operator_address("uint256& opPreDec()", WRAP_OBJ_FIRST(uint256_repr::fmm), convention::generic_call);
			uint256_type->set_operator_address("uint256& opPostInc()", WRAP_OBJ_FIRST(uint256_repr::pp), convention::generic_call);
			uint256_type->set_operator_address("uint256& opPostDec()", WRAP_OBJ_FIRST(uint256_repr::mm), convention::generic_call);
			uint256_type->set_operator_address("bool opEquals(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::eq), convention::generic_call);
			uint256_type->set_operator_address("int opCmp(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::cmp), convention::generic_call);
			uint256_type->set_operator_address("uint256 opMul(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::mul), convention::generic_call);
			uint256_type->set_operator_address("uint256 opDiv(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::div), convention::generic_call);
			uint256_type->set_operator_address("uint256 opAdd(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::add), convention::generic_call);
			uint256_type->set_operator_address("uint256 opSub(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::sub), convention::generic_call);
			uint256_type->set_operator_address("uint256 opMod(const uint256&in) const", WRAP_OBJ_FIRST(uint256_repr::per), convention::generic_call);
			uint256_type->set_method_address("bool opImplConv() const", WRAP_OBJ_FIRST(uint256_repr::to_bool), convention::generic_call);
			uint256_type->set_method_address("int8 i8() const", WRAP_OBJ_FIRST(uint256_repr::to_int8), convention::generic_call);
			uint256_type->set_method_address("int16 i16() const", WRAP_OBJ_FIRST(uint256_repr::to_int16), convention::generic_call);
			uint256_type->set_method_address("int32 i32() const", WRAP_OBJ_FIRST(uint256_repr::to_int32), convention::generic_call);
			uint256_type->set_method_address("int64 i64() const", WRAP_OBJ_FIRST(uint256_repr::to_int64), convention::generic_call);
			uint256_type->set_method_address("uint8 u8() const", WRAP_OBJ_FIRST(uint256_repr::to_uint8), convention::generic_call);
			uint256_type->set_method_address("uint16 u16() const", WRAP_OBJ_FIRST(uint256_repr::to_uint16), convention::generic_call);
			uint256_type->set_method_address("uint32 u32() const", WRAP_OBJ_FIRST(uint256_repr::to_uint32), convention::generic_call);
			uint256_type->set_method_address("uint64 u64() const", WRAP_OBJ_FIRST(uint256_repr::to_uint64), convention::generic_call);
			uint256_type->set_method_address("uint128 u128() const", WRAP_OBJ_FIRST(uint256_repr::to_uint128), convention::generic_call);
			uint256_type->set_method_address("real320 r320() const", WRAP_MFN(uint256_t, to_decimal), convention::generic_call);
			uint256_type->set_method_address("uint16 bits() const", WRAP_MFN(uint256_t, bits), convention::generic_call);
			uint256_type->set_method_address("uint16 bytes() const", WRAP_MFN(uint256_t, bytes), convention::generic_call);
			real320_type->set_behaviour_address("void f()", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor), convention::generic_call);
			real320_type->set_behaviour_address("void f(bool)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_bool), convention::generic_call);
			real320_type->set_behaviour_address("void f(int8)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<int8_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(uint8)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<uint8_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(int16)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<int16_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(uint16)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<uint16_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(int32)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<int32_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(uint32)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<uint32_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(int64)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<int64_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(uint64)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_arithmetic<uint64_t>), convention::generic_call);
			real320_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_string), convention::generic_call);
			real320_type->set_behaviour_address("void f(const uint128&in)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_uint128), convention::generic_call);
			real320_type->set_behaviour_address("void f(const uint256&in)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_uint256), convention::generic_call);
			real320_type->set_behaviour_address("void f(const real320&in)", behaviours::construct, WRAP_OBJ_FIRST(real320_repr::custom_constructor_copy), convention::generic_call);
			real320_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(decimal), convention::generic_call);
			real320_type->set_operator_copy_address(WRAP_MFN_PR(decimal, operator=, (const decimal&), decimal&), convention::generic_call);
			real320_type->set_method_address("bool opImplConv() const", WRAP_OBJ_FIRST(real320_repr::is_not_zero_or_nan), convention::generic_call);
			real320_type->set_method_address("bool nan() const", WRAP_MFN(decimal, is_nan), convention::generic_call);
			real320_type->set_method_address("bool zero() const", WRAP_MFN(decimal, is_zero), convention::generic_call);
			real320_type->set_method_address("bool zero_or_nan() const", WRAP_MFN(decimal, is_zero_or_nan), convention::generic_call);
			real320_type->set_method_address("bool positive() const", WRAP_MFN(decimal, is_positive), convention::generic_call);
			real320_type->set_method_address("bool negative() const", WRAP_MFN(decimal, is_negative), convention::generic_call);
			real320_type->set_method_address("int8 i8() const", WRAP_MFN(decimal, to_int8), convention::generic_call);
			real320_type->set_method_address("int16 i16() const", WRAP_MFN(decimal, to_int16), convention::generic_call);
			real320_type->set_method_address("int32 i32() const", WRAP_MFN(decimal, to_int32), convention::generic_call);
			real320_type->set_method_address("int64 i64() const", WRAP_MFN(decimal, to_int64), convention::generic_call);
			real320_type->set_method_address("uint8 u8() const", WRAP_MFN(decimal, to_uint8), convention::generic_call);
			real320_type->set_method_address("uint16 u16() const", WRAP_MFN(decimal, to_uint16), convention::generic_call);
			real320_type->set_method_address("uint32 u32() const", WRAP_MFN(decimal, to_uint32), convention::generic_call);
			real320_type->set_method_address("uint64 u64() const", WRAP_MFN(decimal, to_uint64), convention::generic_call);
			real320_type->set_method_address("uint128 u128() const", WRAP_OBJ_FIRST(real320_repr::to_uint128), convention::generic_call);
			real320_type->set_method_address("uint256 u256() const", WRAP_OBJ_FIRST(real320_repr::to_uint256), convention::generic_call);
			real320_type->set_operator_address("real320& opMulAssign(const real320&in)", WRAP_OBJ_FIRST(real320_repr::mul_eq), convention::generic_call);
			real320_type->set_operator_address("real320& opDivAssign(const real320&in)", WRAP_OBJ_FIRST(real320_repr::div_eq), convention::generic_call);
			real320_type->set_operator_address("real320& opAddAssign(const real320&in)", WRAP_OBJ_FIRST(real320_repr::add_eq), convention::generic_call);
			real320_type->set_operator_address("real320& opSubAssign(const real320&in)", WRAP_OBJ_FIRST(real320_repr::sub_eq), convention::generic_call);
			real320_type->set_operator_address("real320& opPreInc()", WRAP_OBJ_FIRST(real320_repr::fpp), convention::generic_call);
			real320_type->set_operator_address("real320& opPreDec()", WRAP_OBJ_FIRST(real320_repr::fmm), convention::generic_call);
			real320_type->set_operator_address("real320& opPostInc()", WRAP_OBJ_FIRST(real320_repr::pp), convention::generic_call);
			real320_type->set_operator_address("real320& opPostDec()", WRAP_OBJ_FIRST(real320_repr::mm), convention::generic_call);
			real320_type->set_operator_address("bool opEquals(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::eq), convention::generic_call);
			real320_type->set_operator_address("int opCmp(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::cmp), convention::generic_call);
			real320_type->set_operator_address("real320 opMul(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::mul), convention::generic_call);
			real320_type->set_operator_address("real320 opDiv(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::div), convention::generic_call);
			real320_type->set_operator_address("real320 opAdd(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::add), convention::generic_call);
			real320_type->set_operator_address("real320 opSub(const real320&in) const", WRAP_OBJ_FIRST(real320_repr::sub), convention::generic_call);
			real320_type->set_operator_address("real320 opNeg() const", WRAP_OBJ_FIRST(real320_repr::negate), convention::generic_call);
			real320_type->set_method_static_address("real320 enan()", WRAP_FN(decimal::nan), convention::generic_call);
			real320_type->set_method_static_address("real320 from(const string&in, uint8)", WRAP_FN(real320_repr::from), convention::generic_call);
			payable_type->set_behaviour_address("void f()", behaviours::construct, WRAP_CON(payable_repr, ()), convention::generic_call);
			payable_type->set_behaviour_address("void f(const payable&in)", behaviours::construct, WRAP_CON(payable_repr, (const payable_repr&)), convention::generic_call);
			payable_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(payable_repr), convention::generic_call);
			payable_type->set_operator_copy_address(WRAP_MFN_PR(payable_repr, operator=, (const payable_repr&), payable_repr&), convention::generic_call);
			payable_type->set_method_address("bool plus(const uint256&in, const real320&in)", WRAP_MFN(payable_repr, plus), convention::generic_call);
			payable_type->set_method_address("bool minus(const uint256&in, const real320&in)", WRAP_MFN(payable_repr, minus), convention::generic_call);
			payable_type->set_method_address("bool minus(const real320&in)", WRAP_MFN(payable_repr, minus_total), convention::generic_call);
			payable_type->set_method_address("bool has(const uint256&in) const", WRAP_MFN(payable_repr, has), convention::generic_call);
			payable_type->set_method_address("real320 of(const uint256&in) const", WRAP_MFN(payable_repr, of), convention::generic_call);
			payable_type->set_method_address("const real320& total() const", WRAP_MFN(payable_repr, total), convention::generic_call);
			payable_type->set_method_address("uint256 opIndex(usize)", WRAP_MFN(payable_repr, at), convention::generic_call);
			payable_type->set_method_address("uint256 opIndex(usize) const", WRAP_MFN(payable_repr, at), convention::generic_call);
			payable_type->set_method_address("bool empty() const", WRAP_MFN(payable_repr, empty), convention::generic_call);
			payable_type->set_method_address("usize size() const", WRAP_MFN(payable_repr, size), convention::generic_call);
			address_type->set_behaviour_address("void f()", behaviours::construct, WRAP_CON(address_repr, ()), convention::generic_call);
			address_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_CON(address_repr, (const string_repr&)), convention::generic_call);
			address_type->set_behaviour_address("void f(const uint256&in)", behaviours::construct, WRAP_CON(address_repr, (const uint256_t&)), convention::generic_call);
			address_type->set_behaviour_address("void f(const address&in)", behaviours::construct, WRAP_CON(address_repr, (const address_repr&)), convention::generic_call);
			address_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(address_repr), convention::generic_call);
			address_type->set_operator_copy_address(WRAP_MFN_PR(address_repr, operator=, (const address_repr&), address_repr&), convention::generic_call);
			address_type->set_method_address("uint256 u256() const", WRAP_MFN(address_repr, to_public_key_hash), convention::generic_call);
			address_type->set_method_address("bool empty() const", WRAP_MFN(address_repr, empty), convention::generic_call);
			address_type->set_method_address("void pay(const uint256&in, const real320&in) const", WRAP_MFN(address_repr, pay), convention::generic_call);
			address_type->set_method_address("void pay(const payable&in) const", WRAP_MFN(address_repr, pay_all), convention::generic_call);
			address_type->set_method_address("void mint(const string&in, const real320&in, const real320&in = real320()) const", WRAP_MFN(address_repr, mint), convention::generic_call);
			address_type->set_method_address("void burn(const string&in, const real320&in, const real320&in = real320()) const", WRAP_MFN(address_repr, burn), convention::generic_call);
			address_type->set_method_address("real320 token_balance_of(const string&in) const", WRAP_MFN(address_repr, token_balance_of), convention::generic_call);
			address_type->set_method_address("real320 token_reserve_of(const string&in) const", WRAP_MFN(address_repr, token_reserve_of), convention::generic_call);
			address_type->set_method_address("real320 balance_of(const uint256&in) const", WRAP_MFN(address_repr, balance_of), convention::generic_call);
			address_type->set_method_address("real320 reserve_of(const uint256&in) const", WRAP_MFN(address_repr, reserve_of), convention::generic_call);
			address_type->set_method_address("bool callable(const string&in) const", WRAP_MFN(address_repr, callable), convention::generic_call);
			address_type->set_method_extern("t static_call<t>(const string&in, const ?&in ...) const", &address_repr::static_call, convention::generic_call);
			address_type->set_method_extern("t call<t>(const string&in, const payable&in, const ?&in ...) const", &address_repr::call, convention::generic_call);
			address_type->set_operator_address("bool opEquals(const address&in) const", WRAP_OBJ_FIRST(address_repr::equals), convention::generic_call);
			batch_payout_type->set_behaviour_address("void f()", behaviours::construct, WRAP_CON(batch_payout_repr, ()), convention::generic_call);
			batch_payout_type->set_behaviour_address("void f(const batch_payout&in)", behaviours::construct, WRAP_CON(batch_payout_repr, (const batch_payout_repr&)), convention::generic_call);
			batch_payout_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(batch_payout_repr), convention::generic_call);
			batch_payout_type->set_operator_copy_address(WRAP_MFN_PR(batch_payout_repr, operator=, (const batch_payout_repr&), batch_payout_repr&), convention::generic_call);
			batch_payout_type->set_method_address("void to(const address&in, const uint256&in, const real320&in)", WRAP_MFN(batch_payout_repr, to), convention::generic_call);
			batch_payout_type->set_method_address("void pay()", WRAP_MFN(batch_payout_repr, pay), convention::generic_call);
			abi_type->set_behaviour_address("void f()", behaviours::construct, WRAP_CON(abi_repr, ()), convention::generic_call);
			abi_type->set_behaviour_address("void f(const string&in)", behaviours::construct, WRAP_CON(abi_repr, (const string_repr&)), convention::generic_call);
			abi_type->set_behaviour_address("void f(const address&in)", behaviours::construct, WRAP_CON(abi_repr, (const abi_repr&)), convention::generic_call);
			abi_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(abi_repr), convention::generic_call);
			abi_type->set_operator_copy_address(WRAP_MFN_PR(abi_repr, operator=, (const abi_repr&), abi_repr&), convention::generic_call);
			abi_type->set_method_address("void merge(const string&in)", WRAP_MFN(abi_repr, merge), convention::generic_call);
			abi_type->set_method_address("void seek(usize)", WRAP_MFN(abi_repr, seek), convention::generic_call);
			abi_type->set_method_address("void clear()", WRAP_MFN(abi_repr, clear), convention::generic_call);
			abi_type->set_method_address("void wu8(bool)", WRAP_MFN(abi_repr, wboolean), convention::generic_call);
			abi_type->set_method_address("void wu160(const address&in)", WRAP_MFN(abi_repr, wuint160), convention::generic_call);
			abi_type->set_method_address("void wu256(const uint256&in)", WRAP_MFN(abi_repr, wuint256), convention::generic_call);
			abi_type->set_method_address("void wr320(const real320&in)", WRAP_MFN(abi_repr, wreal320), convention::generic_call);
			abi_type->set_method_address("void wstr(const string&in)", WRAP_MFN(abi_repr, wstr), convention::generic_call);
			abi_type->set_method_address("bool rstr(string&out)", WRAP_MFN(abi_repr, rstr), convention::generic_call);
			abi_type->set_method_address("bool ru8(bool&out)", WRAP_MFN(abi_repr, rboolean), convention::generic_call);
			abi_type->set_method_address("bool ru160(address&out)", WRAP_MFN(abi_repr, ruint160), convention::generic_call);
			abi_type->set_method_address("bool ru256(uint256&out)", WRAP_MFN(abi_repr, ruint256), convention::generic_call);
			abi_type->set_method_address("bool rr320(real320&out)", WRAP_MFN(abi_repr, rreal320), convention::generic_call);
			abi_type->set_method_address("string data()", WRAP_MFN(abi_repr, data), convention::generic_call);
			varying_type->set_behaviour_address("void f(int&in)", behaviours::construct, WRAP_CON(varying_repr, (asITypeInfo*)), convention::generic_call);
			varying_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(varying_repr), convention::generic_call);
			varying_type->set_behaviour_address("bool f(int&in, bool&out)", behaviours::template_callback, WRAP_FN(varying_repr::template_callback), convention::generic_call);
			varying_type->set_method_address("void erase()", WRAP_MFN(varying_repr, erase), convention::generic_call);
			varying_type->set_method_address("void opAssign(const t&in)", WRAP_MFN(varying_repr, store), convention::generic_call);
			varying_type->set_method_address("void set()", WRAP_MFN(varying_repr, save), convention::generic_call);
			varying_type->set_method_address("void set(const t&in)", WRAP_MFN(varying_repr, store), convention::generic_call);
			varying_type->set_method_address("void set_if(bool, const t&in)", WRAP_MFN(varying_repr, store_if), convention::generic_call);
			varying_type->set_method_address("const t& get_ref() const property", WRAP_MFN(varying_repr, load), convention::generic_call);
			varying_type->set_method_address("bool empty() const", WRAP_MFN(varying_repr, empty), convention::generic_call);
			mapping_type->set_behaviour_address("void f(int&in)", behaviours::construct, WRAP_CON(mapping_repr, (asITypeInfo*)), convention::generic_call);
			mapping_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(mapping_repr), convention::generic_call);
			mapping_type->set_behaviour_address("bool f(int&in, bool&out)", behaviours::template_callback, WRAP_FN(mapping_repr::template_callback), convention::generic_call);
			mapping_type->set_method_address("void erase(const k&in)", WRAP_MFN(mapping_repr, erase), convention::generic_call);
			mapping_type->set_method_address("void insert(const k&in, const v&in)", WRAP_MFN(mapping_repr, store), convention::generic_call);
			mapping_type->set_method_address("void insert_if(bool, const k&in, const v&in)", WRAP_MFN(mapping_repr, store_if), convention::generic_call);
			mapping_type->set_method_address("const v& opIndex(const k&in) const", WRAP_MFN(mapping_repr, load), convention::generic_call);
			mapping_type->set_method_address("bool has(const k&in) const", WRAP_MFN(mapping_repr, has), convention::generic_call);
			listing_type->set_behaviour_address("void f(int&in)", behaviours::construct, WRAP_CON(listing_repr, (asITypeInfo*)), convention::generic_call);
			listing_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(listing_repr), convention::generic_call);
			listing_type->set_behaviour_address("bool f(int&in, bool&out)", behaviours::template_callback, WRAP_FN(listing_repr::template_callback), convention::generic_call);
			listing_type->set_method_address("usize size() const", WRAP_MFN(listing_repr, size), convention::generic_call);
			listing_type->set_method_address("bool empty() const", WRAP_MFN(listing_repr, empty), convention::generic_call);
			listing_type->set_method_address("void clear()", WRAP_MFN(listing_repr, clear), convention::generic_call);
			listing_type->set_method_address("void erase(usize)", WRAP_MFN(listing_repr, erase_at), convention::generic_call);
			listing_type->set_method_address("void set(usize, const v&in)", WRAP_MFN(listing_repr, store_at), convention::generic_call);
			listing_type->set_method_address("void push(const v&in)", WRAP_MFN(listing_repr, insert_last), convention::generic_call);
			listing_type->set_method_address("void push_front(const v&in)", WRAP_MFN(listing_repr, insert_first), convention::generic_call);
			listing_type->set_method_address("void pop()", WRAP_MFN(listing_repr, remove_last), convention::generic_call);
			listing_type->set_method_address("void pop_front()", WRAP_MFN(listing_repr, remove_first), convention::generic_call);
			listing_type->set_method_address("const v& front() const", WRAP_MFN(listing_repr, load_first), convention::generic_call);
			listing_type->set_method_address("const v& back() const", WRAP_MFN(listing_repr, load_last), convention::generic_call);
			listing_type->set_method_address("const v& opIndex(usize) const", WRAP_MFN(listing_repr, load_at), convention::generic_call);
			ranging_type->set_behaviour_address("void f(int&in)", behaviours::construct, WRAP_CON(ranging_repr, (asITypeInfo*)), convention::generic_call);
			ranging_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(ranging_repr), convention::generic_call);
			ranging_type->set_behaviour_address("bool f(int&in, bool&out)", behaviours::template_callback, WRAP_FN(ranging_repr::template_callback), convention::generic_call);
			ranging_type->set_method_address("ranging_slice x(const c&in) const", WRAP_MFN(ranging_repr, from_column), convention::generic_call);
			ranging_type->set_method_address("ranging_slice y(const r&in) const", WRAP_MFN(ranging_repr, from_row), convention::generic_call);
			ranging_type->set_method_address("void erase(const c&in, const r&in)", WRAP_MFN(ranging_repr, erase), convention::generic_call);
			ranging_type->set_method_address("void insert(const c&in, const r&in, const v&in)", WRAP_MFN(ranging_repr, store), convention::generic_call);
			ranging_type->set_method_address("void insert(const c&in, const r&in, const v&in, const uint256&in)", WRAP_MFN(ranging_repr, store_positioned), convention::generic_call);
			ranging_type->set_method_address("void insert_if(bool, const c&in, const r&in, const v&in)", WRAP_MFN(ranging_repr, store_if), convention::generic_call);
			ranging_type->set_method_extern("void insert_if(bool, const c&in, const r&in, const v&in, const uint256&in)", &ranging_repr::wrapped_store_positioned_if, convention::generic_call);
			ranging_type->set_method_address("const v& opIndex(const c&in, const r&in) const", WRAP_MFN(ranging_repr, load), convention::generic_call);
			ranging_type->set_method_address("bool has(const c&in, const r&in) const", WRAP_MFN(ranging_repr, has), convention::generic_call);
			ranging_type->set_method_address("bool has_x(const c&in) const", WRAP_MFN(ranging_repr, has_column), convention::generic_call);
			ranging_type->set_method_address("bool has_y(const r&in) const", WRAP_MFN(ranging_repr, has_row), convention::generic_call);
			ranging_slice_type->set_behaviour_address("void f()", behaviours::construct, WRAP_CON(ranging_slice_repr, ()), convention::generic_call);
			ranging_slice_type->set_behaviour_address("void f(const address&in)", behaviours::construct, WRAP_CON(ranging_slice_repr, (const ranging_slice_repr&)), convention::generic_call);
			ranging_slice_type->set_behaviour_address("void f()", behaviours::destruct, WRAP_DES(ranging_slice_repr), convention::generic_call);
			ranging_slice_type->set_operator_copy_address(WRAP_MFN_PR(ranging_slice_repr, operator=, (const ranging_slice_repr&), ranging_slice_repr&), convention::generic_call);
			ranging_slice_type->set_method_extern("bool next()", &ranging_slice_repr::wrapped_next, convention::generic_call);
			ranging_slice_type->set_method_extern("bool next(?&out)", &ranging_slice_repr::wrapped_next_object, convention::generic_call);
			ranging_slice_type->set_method_extern("bool next(?&out, ?&out)", &ranging_slice_repr::wrapped_next_object_index, convention::generic_call);
			ranging_slice_type->set_method_extern("bool next(?&out, ?&out, uint256&out)", &ranging_slice_repr::wrapped_next_object_index_ranked, convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& offset(usize = 0)", WRAP_MFN(ranging_slice_repr, with_offset), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& count(usize = 0)", WRAP_MFN(ranging_slice_repr, with_count), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& gt(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_gt), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& gte(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_gte), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& eq(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_eq), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& neq(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_neq), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& lt(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_lt), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& lte(const uint256&in)", WRAP_MFN(ranging_slice_repr, where_lte), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& asc()", WRAP_MFN(ranging_slice_repr, order_asc), convention::generic_call);
			ranging_slice_type->set_method_address("ranging_slice& desc()", WRAP_MFN(ranging_slice_repr, order_desc), convention::generic_call);

			vm->begin_namespace("log");
			vm->set_function("void emit(const ?&in)", &contract::log_emit, convention::generic_call);
			vm->set_function("void event(const ?&in, const ?&in)", &contract::log_event, convention::generic_call);
			vm->set_function("bool into(int32, ?&out, const address&in = address())", &contract::log_into, convention::generic_call);
			vm->set_function("bool event_into(const ?&in, int32, ?&out, const address&in = address())", &contract::log_event_into, convention::generic_call);
			vm->set_function("t get<t>(int32, const address&in = address())", &contract::log_get, convention::generic_call);
			vm->set_function("t get_event<t>(const ?&in, int32, const address&in = address())", &contract::log_get_event, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("block");
			vm->set_function_address("address proposer()", WRAP_FN(contract::block_proposer), convention::generic_call);
			vm->set_function_address("uint256 parent_hash()", WRAP_FN(contract::block_parent_hash), convention::generic_call);
			vm->set_function_address("uint256 gas_use()", WRAP_FN(contract::block_gas_use), convention::generic_call);
			vm->set_function_address("uint256 gas_left()", WRAP_FN(contract::block_gas_left), convention::generic_call);
			vm->set_function_address("uint256 gas_limit()", WRAP_FN(contract::block_gas_limit), convention::generic_call);
			vm->set_function_address("uint128 difficulty()", WRAP_FN(contract::block_difficulty), convention::generic_call);
			vm->set_function_address("uint64 time()", WRAP_FN(contract::block_time), convention::generic_call);
			vm->set_function_address("uint64 time_between(uint64, uint64)", WRAP_FN(contract::block_time_between), convention::generic_call);
			vm->set_function_address("uint64 priority()", WRAP_FN(contract::block_priority), convention::generic_call);
			vm->set_function_address("uint64 number()", WRAP_FN(contract::block_number), convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("tx");
			vm->set_function_address("bool paid()", WRAP_FN(contract::tx_paid), convention::generic_call);
			vm->set_function_address("address from()", WRAP_FN(contract::tx_from), convention::generic_call);
			vm->set_function_address("address to()", WRAP_FN(contract::tx_to), convention::generic_call);
			vm->set_function_address("payable value()", WRAP_FN(contract::tx_value), convention::generic_call);
			vm->set_function_address("string blockchain()", WRAP_FN(contract::tx_blockchain), convention::generic_call);
			vm->set_function_address("string token()", WRAP_FN(contract::tx_token), convention::generic_call);
			vm->set_function_address("string contract()", WRAP_FN(contract::tx_contract), convention::generic_call);
			vm->set_function_address("real320 gas_price()", WRAP_FN(contract::tx_gas_price), convention::generic_call);
			vm->set_function_address("uint256 gas_use()", WRAP_FN(contract::tx_gas_use), convention::generic_call);
			vm->set_function_address("uint256 gas_left()", WRAP_FN(contract::tx_gas_left), convention::generic_call);
			vm->set_function_address("uint256 gas_limit()", WRAP_FN(contract::tx_gas_limit), convention::generic_call);
			vm->set_function_address("uint256 asset()", WRAP_FN(contract::tx_asset), convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("coin");
			vm->set_function_address("uint256 native()", WRAP_FN(contract::coin_native), convention::generic_call);
			vm->set_function_address("uint256 token(const string&in)", WRAP_FN(contract::coin_token), convention::generic_call);
			vm->set_function_address("uint256 id_of(const string&in, const string&in = string(), const string&in = string())", WRAP_FN(contract::coin_id_of), convention::generic_call);
			vm->set_function_address("string blockchain_of(const uint256&in)", WRAP_FN(contract::coin_blockchain_of), convention::generic_call);
			vm->set_function_address("string token_of(const uint256&in)", WRAP_FN(contract::coin_token_of), convention::generic_call);
			vm->set_function_address("string contract_of(const uint256&in)", WRAP_FN(contract::coin_checksum_of), convention::generic_call);
			vm->set_function_address("string name_of(const uint256&in)", WRAP_FN(contract::coin_name_of), convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("alg");
			vm->set_function_address("real320 from_r256(const uint256&in)", WRAP_FN(contract::alg_from_r256), convention::generic_call);
			vm->set_function_address("uint256 to_r256(const real320&in)", WRAP_FN(contract::alg_to_r256), convention::generic_call);
			vm->set_function_address("string from_u256(const uint256&in)", WRAP_FN(contract::alg_from_u256), convention::generic_call);
			vm->set_function_address("uint256 to_u256(const string&in)", WRAP_FN(contract::alg_to_u256), convention::generic_call);
			vm->set_function_address("string from_e16(const string&in)", WRAP_FN(contract::alg_from_e16), convention::generic_call);
			vm->set_function_address("string to_e16(const string&in)", WRAP_FN(contract::alg_to_e16), convention::generic_call);
			vm->set_function_address("address erecover160(const uint256&in, const string&in)", WRAP_FN(contract::alg_erecover160), convention::generic_call);
			vm->set_function_address("string erecover264(const uint256&in, const string&in)", WRAP_FN(contract::alg_erecover264), convention::generic_call);
			vm->set_function_address("uint256 prandom256()", WRAP_FN(contract::alg_prandom), convention::generic_call);
			vm->set_function_address("string crc32(const string&in)", WRAP_FN(contract::alg_crc32), convention::generic_call);
			vm->set_function_address("string ripemd160(const string&in)", WRAP_FN(contract::alg_ripemd160), convention::generic_call);
			vm->set_function_address("uint256 blake2b256(const string&in)", WRAP_FN(contract::alg_blake2b256), convention::generic_call);
			vm->set_function_address("string blake2b256s(const string&in)", WRAP_FN(contract::alg_blake2b256s), convention::generic_call);
			vm->set_function_address("uint256 keccak256(const string&in)", WRAP_FN(contract::alg_keccak256), convention::generic_call);
			vm->set_function_address("string keccak256s(const string&in)", WRAP_FN(contract::alg_keccak256s), convention::generic_call);
			vm->set_function_address("string keccak512(const string&in)", WRAP_FN(contract::alg_keccak512), convention::generic_call);
			vm->set_function_address("uint256 sha256(const string&in)", WRAP_FN(contract::alg_sha256), convention::generic_call);
			vm->set_function_address("string sha256s(const string&in)", WRAP_FN(contract::alg_sha256s), convention::generic_call);
			vm->set_function_address("string sha512(const string&in)", WRAP_FN(contract::alg_sha512), convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("math");
			vm->set_function("t min_value<t>()", &contract::math_min_value, convention::generic_call);
			vm->set_function("t max_value<t>()", &contract::math_max_value, convention::generic_call);
			vm->set_function("t abs<t>(const t&in)", &contract::math_abs, convention::generic_call);
			vm->set_function("t min<t>(const t&in, const t&in)", &contract::math_min, convention::generic_call);
			vm->set_function("t max<t>(const t&in, const t&in)", &contract::math_max, convention::generic_call);
			vm->set_function("t clamp<t>(const t&in, const t&in, const t&in)", &contract::math_clamp, convention::generic_call);
			vm->set_function("t lerp<t>(const t&in, const t&in, const t&in)", &contract::math_lerp, convention::generic_call);
			vm->set_function("t pow<t>(const t&in, const t&in)", &contract::math_pow, convention::generic_call);
			vm->set_function("t sqrt<t>(const t&in)", &contract::math_sqrt, convention::generic_call);
			vm->end_namespace();

			vm->set_function_address("void require(bool, const string&in = string())", WRAP_FN(contract::require), convention::generic_call);
			vm->set_default_array_type("array<t>");
			vm->set_string_factory_type("string");
			vm->begin_namespace("string");
			vm->set_function_address("string from(int8, int = 10)", WRAP_FN(string_repr::to_string<int8_t>), convention::generic_call);
			vm->set_function_address("string from(int16, int = 10)", WRAP_FN(string_repr::to_string<int16_t>), convention::generic_call);
			vm->set_function_address("string from(int32, int = 10)", WRAP_FN(string_repr::to_string<int32_t>), convention::generic_call);
			vm->set_function_address("string from(int64, int = 10)", WRAP_FN(string_repr::to_string<int64_t>), convention::generic_call);
			vm->set_function_address("string from(uint8, int = 10)", WRAP_FN(string_repr::to_string<uint8_t>), convention::generic_call);
			vm->set_function_address("string from(uint16, int = 10)", WRAP_FN(string_repr::to_string<uint16_t>), convention::generic_call);
			vm->set_function_address("string from(uint32, int = 10)", WRAP_FN(string_repr::to_string<uint32_t>), convention::generic_call);
			vm->set_function_address("string from(uint64, int = 10)", WRAP_FN(string_repr::to_string<uint64_t>), convention::generic_call);
			vm->set_function_address("string from(const uint128&in, int = 10)", WRAP_FN(string_repr::to_string_uint128), convention::generic_call);
			vm->set_function_address("string from(const uint256&in, int = 10)", WRAP_FN(string_repr::to_string_uint256), convention::generic_call);
			vm->set_function_address("string from(const real320&in)", WRAP_FN(string_repr::to_string_decimal), convention::generic_call);
			vm->set_function_address("string from(const address&in)", WRAP_FN(string_repr::to_string_address), convention::generic_call);
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
			vm->set_property(features::max_stack_size, 1024 * 128);
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
			vm->set_full_stack_tracing(false);
			vm->set_ts_imports(false);
			vm->set_cache(!protocol::now().user.storage.module_cache_path.empty());
			vm->set_cache_callback([](byte_code_info* info)
			{
				auto path = stringify::text("%s%c%s.o", protocol::now().user.storage.module_cache_path.c_str(), VI_SPLITTER, info->name.c_str());
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
			if (vmc)
				vmc->unlink_module();
			for (auto& [id, link] : modules)
			{
				VI_ASSERT(!link.count, "someone still holds a reference to a module");
				link.ref.discard();
			}
			modules.clear();
			memory::deinit((string_repr_cache_type*)strings);
		}
		void factory::bind_debugger_tools(debugger_context* debugger)
		{
			VI_ASSERT(debugger != nullptr, "debugger should be set");
			umutex<std::mutex> unique(exclusive);
			if (!vmc_tools)
			{
				auto any_type = vm->set_class_address("any", sizeof(script::bindings::any), (size_t)object_behaviours::ref | (size_t)object_behaviours::gc);
				any_type->set_behaviour_address("any@ f()", behaviours::factory, WRAP_FN(script::bindings::any::factory1), convention::generic_call);
				any_type->set_constructor_extern("any@ f(?&in) explicit", &script::bindings::any::factory2, convention::generic_call);
				any_type->set_behaviour_address("void f()", behaviours::add_ref, WRAP_OBJ_FIRST(ref_base_class::gc_add_ref<script::bindings::any>), convention::generic_call);
				any_type->set_behaviour_address("void f()", behaviours::release, WRAP_OBJ_FIRST(ref_base_class::gc_release<script::bindings::any>), convention::generic_call);
				any_type->set_behaviour_address("void f()", behaviours::set_gc_flag, WRAP_OBJ_FIRST(ref_base_class::gc_mark_ref<script::bindings::any>), convention::generic_call);
				any_type->set_behaviour_address("bool f()", behaviours::get_gc_flag, WRAP_OBJ_FIRST(ref_base_class::gc_is_marked_ref<script::bindings::any>), convention::generic_call);
				any_type->set_behaviour_address("int f()", behaviours::get_ref_count, WRAP_OBJ_FIRST(ref_base_class::gc_get_ref_count<script::bindings::any>), convention::generic_call);
				any_type->set_behaviour_address("void f(int &in)", behaviours::enum_refs, WRAP_MFN(script::bindings::any, enum_references), convention::generic_call);
				any_type->set_behaviour_address("void f(int &in)", behaviours::release_refs, WRAP_MFN(script::bindings::any, release_references), convention::generic_call);
				any_type->set_operator_copy_address(WRAP_MFN(script::bindings::any, operator=), convention::generic_call);
				any_type->set_method_extern("void store(?&in)", &any_store, convention::generic_call);
				any_type->set_method_extern("bool retrieve(?&out)", &any_retrieve, convention::generic_call);
				vmc_tools = true;
			}
			debugger->add_to_string_callback("string", [](string&, int, void* object, int)
			{
				script::string_repr& source = *(script::string_repr*)object;
				string_stream stream;
				stream << "\"" << source.view() << "\"";
				stream << " (string, " << source.size() << " chars)";
				return stream.str();
			});
			debugger->add_to_string_callback("uint128", [](string&, int, void* object, int)
			{
				uint128& source = *(uint128*)object;
				return source.to_string() + " (uint128)";
			});
			debugger->add_to_string_callback("uint256", [](string&, int, void* object, int)
			{
				uint256_t& source = *(uint256_t*)object;
				if (algorithm::asset::is_any(source))
					return source.to_string() + " (uint256; " + algorithm::asset::name_of(source) + " as asset)";

				return source.to_string() + " (uint256)";
			});
			debugger->add_to_string_callback("real320", [](string&, int, void* object, int)
			{
				decimal& source = *(decimal*)object;
				return source.to_string() + " (real320)";
			});
			debugger->add_to_string_callback("array", [debugger](string& indent, int depth, void* object, int)
			{
				auto* source = (script::array_repr*)object;
				int base_type_id = source->get_element_type_id();
				uint32_t size = source->size();
				string_stream stream;
				stream << "0x" << (void*)source << " (array<t>, " << size << " elements)";

				if (!depth || !size)
					return stream.str();

				if (size > 128)
				{
					stream << "\n";
					indent.append("  ");
					for (uint32_t i = 0; i < size; i++)
					{
						stream << indent << "[" << i << "]: " << debugger->to_string(indent, depth - 1, source->at(i), base_type_id);
						if (i + 1 < size)
							stream << "\n";
					}
					indent.erase(indent.end() - 2, indent.end());
				}
				else
				{
					stream << " [";
					for (uint32_t i = 0; i < size; i++)
					{
						stream << debugger->to_string(indent, depth - 1, source->at(i), base_type_id);
						if (i + 1 < size)
							stream << ", ";
					}
					stream << "]";
				}

				return stream.str();
			});
			debugger->add_to_string_callback("payable", [](string&, int depth, void* object, int)
			{
				auto& source = *(script::payable_repr*)object;
				string_stream stream;
				stream << "0x" << object << " (payable, " << source.payments.size() << " payments)";
				if (!depth || source.payments.empty())
					return stream.str();

				stream << " [";
				for (size_t i = 0; i < source.payments.size(); i++)
				{
					auto& [paying_asset, paying_value] = source.payments[i];
					stream << paying_value.to_string() << " " << algorithm::asset::name_of(paying_asset);
					if (i + 1 < source.payments.size())
						stream << ", ";
				}
				stream << "]";
				return stream.str();
			});
			debugger->add_to_string_callback("batch_payout", [](string&, int depth, void* object, int)
			{
				auto& source = *(script::batch_payout_repr*)object;
				string_stream stream;
				stream << "0x" << object << " (batch_payout, " << source.payouts.size() << " recipients)";
				if (!depth || source.payouts.empty())
					return stream.str();

				stream << " [";
				for (auto it = source.payouts.begin(); it != source.payouts.end(); it++)
				{
					auto& [account, payments] = *it;
					for (auto jit = payments.begin(); jit != payments.end(); jit++)
					{
						auto& [asset, value] = *jit; auto cit = it; auto cjit = jit;
						stream << value.to_string() << " " << algorithm::asset::name_of(asset) << " to " << algorithm::signing::encode_address(account);
						if (++cit != source.payouts.end() || ++cjit != payments.end())
							stream << ", ";
					}
				}
				stream << "]";
				return stream.str();
			});
			debugger->add_to_string_callback("address", [](string&, int, void* object, int)
			{
				auto& source = *(script::address_repr*)object;
				return string(source.to_string().view()) + " (address)";
			});
			debugger->add_to_string_callback("abi", [](string&, int, void* object, int)
			{
				auto& source = *(script::abi_repr*)object;
				return source.output.encode() + " (abi)";
			});
			debugger->add_to_string_callback("any", [debugger](string& indent, int depth, void* object, int)
			{
				auto* source = (script::bindings::any*)object;
				return debugger->to_string(indent, depth - 1, source->get_address_of_object(), source->get_type_id());
			});
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
				if (it->second.ref.get_module() == value->get_module())
				{
					VI_ASSERT(it->second.count > 0, "module was returned too many times");
					--it->second.count;
				}
				else
					value->discard();
			}
			else
			{
				module_ref next;
				next.ref = value.ref;
				modules.insert(std::make_pair(string(name), std::move(next)));
			}
			value.ref = nullptr;
		}
		string factory::export_predefined_symbols()
		{
			string_stream stream;
			asIScriptEngine* engine = vm->get_engine();
			for (asUINT i = 0; i < engine->GetEnumCount(); i++)
			{
				auto* type = engine->GetEnumByIndex(i);
				std::string_view name_space = type->GetNamespace();
				asUINT values_count = type->GetEnumValueCount();
				if (values_count > 0)
				{
					if (!name_space.empty())
						stream << "namespace " << name_space << "\n{\n\t";

					stream << "enum " << type->GetName() << (name_space.empty() ? "\n{\n" : "\n\t{\n");
					for (asUINT j = 0; j < values_count; ++j)
					{
						stream << (name_space.empty() ? "\t" : "\t\t") << type->GetEnumValueByIndex(j, nullptr);
						if (j < values_count - 1)
							stream << ",";
						stream << "\n";
					}
					stream << (name_space.empty() ? "}\n" : "\t}\n}\n");
				}
				else if (!name_space.empty())
					stream << "namespace " << name_space << " { enum " << type->GetName() << " { } }\n";
				else
					stream << "enum " << type->GetName() << " { }\n";
			}
			for (asUINT i = 0; i < engine->GetObjectTypeCount(); i++)
			{
				auto* type = engine->GetObjectTypeByIndex(i);
				std::string_view name_space = type->GetNamespace();
				asUINT behaviours_count = type->GetBehaviourCount();
				asUINT methods_count = type->GetMethodCount();
				asUINT properties_count = type->GetPropertyCount();
				asUINT funcdefs_count = type->GetChildFuncdefCount();
				bool has_children = behaviours_count > 0 || methods_count > 0 || properties_count > 0 || funcdefs_count > 0;
				if (!name_space.empty())
					stream << "namespace " << name_space << (has_children ? "\n{\n\t" : " { ");

				std::string_view name = type->GetName();
				stream << "class " << name;
				if (type->GetSubTypeCount() > 0)
				{
					stream << "<";
					for (asUINT j = 0; j < type->GetSubTypeCount(); ++j)
					{
						auto* subtype = type->GetSubType(j);
						stream << subtype->GetName();
						if (j < type->GetSubTypeCount() - 1)
							stream << ", ";
					}
					stream << ">";
				}

				if (has_children)
				{
					stream << (name_space.empty() ? "\n{\n" : "\n\t{\n");
					if (name == SCRIPT_TYPE_ARRAY)
					{
						stream << (name_space.empty() ? "\t" : "\t\t") << name << "(usize) explicit;\n";
						stream << (name_space.empty() ? "\t" : "\t\t") << name << "(usize, const ?&in) explicit;\n";
					}
					else if (name == SCRIPT_TYPE_STRING)
						stream << (name_space.empty() ? "\t" : "\t\t") << name << "(uint64);\n";
					for (asUINT j = 0; j < behaviours_count; ++j)
					{
						asEBehaviours behaviours;
						auto* behaviour = type->GetBehaviourByIndex(j, &behaviours);
						if (behaviours == asBEHAVE_CONSTRUCT || behaviours == asBEHAVE_DESTRUCT)
							stream << (name_space.empty() ? "\t" : "\t\t") << behaviour->GetDeclaration(false, true, true) << ";\n";
					}
					for (asUINT j = 0; j < methods_count; ++j)
					{
						auto* method = type->GetMethodByIndex(j);
						stream << (name_space.empty() ? "\t" : "\t\t") << method->GetDeclaration(false, true, true) << (method->IsProperty() ? " property;\n" : ";\n");
					}
					for (asUINT j = 0; j < properties_count; ++j)
						stream << (name_space.empty() ? "\t" : "\t\t") << type->GetPropertyDeclaration(j, true) << ";\n";
					for (asUINT j = 0; j < funcdefs_count; ++j)
						stream << (name_space.empty() ? "\t" : "\t\t") << "funcdef " << type->GetChildFuncdef(j)->GetFuncdefSignature()->GetDeclaration(false) << ";\n";
					stream << (name_space.empty() ? "}\n" : "\t}\n}\n");
				}
				else if (!name_space.empty())
					stream << " { } }\n";
				else
					stream << " { }\n";
			}
			for (asUINT i = 0; i < engine->GetGlobalFunctionCount(); i++)
			{
				auto* function = engine->GetGlobalFunctionByIndex(i);
				std::string_view name_space = function->GetNamespace();
				if (!name_space.empty())
					stream << "namespace " << name_space << " { ";
				stream << function->GetDeclaration(false, false, true) << ";";
				stream << (name_space.empty() ? "\n" : " }\n");
			}
			for (asUINT i = 0; i < engine->GetGlobalPropertyCount(); i++)
			{
				const char* name; const char* name_space_ptr; int type_id;
				engine->GetGlobalPropertyByIndex(i, &name, &name_space_ptr, &type_id, nullptr, nullptr, nullptr, nullptr);
				std::string_view declaration = engine->GetTypeDeclaration(type_id, true);
				std::string_view name_space = name_space_ptr;
				if (!name_space.empty())
					stream << "namespace " << name_space << " { ";
				stream << declaration << " " << name << ";";
				stream << (name_space.empty() ? "\n" : " }\n");
			}
			for (asUINT i = 0; i < engine->GetTypedefCount(); ++i)
			{
				auto* type = engine->GetTypedefByIndex(i);
				std::string_view name_space = type->GetNamespace();
				if (!name_space.empty())
					stream << "namespace " << name_space << " { ";
				stream << "typedef " << engine->GetTypeDeclaration(type->GetUnderlyingTypeId()) << " " << type->GetName() << ";";
				stream << (name_space.empty() ? "\n" : " }\n");
			}
			return stream.str();
		}
		expects_lr<cmodule> factory::compile_module(const std::string_view& hashcode, const std::function<expects_lr<string>()>& unpacked_code_callback)
		{
			VI_ASSERT(unpacked_code_callback, "callback should be set");
			umutex<std::recursive_mutex> unique(mutex);
			auto it = modules.find(key_lookup_cast(hashcode));
			if (it != modules.end())
			{
				cmodule result = library(it->second.ref);
				++it->second.count;
				return expects_lr<cmodule>(std::move(result));
			}

			vmc_log.clear();
			vm->set_compiler_error_callback([this](const std::string_view& message) { vmc_log.append(message).append("\r\n"); });
			if (!vmc)
				vmc = vm->create_compiler();
			else
				vmc->clear();

			auto preparation = vmc->prepare(hashcode, hashcode, true, true);
			if (!preparation)
			{
				vmc_log.append(SCRIPT_VM " preparation: " + preparation.error().message() + "\r\n");
			error:
				vm->set_compiler_error_callback(nullptr);
				return layer_exception(string(vmc_log));
			}

			if (!vmc->is_cached())
			{
				auto code = unpacked_code_callback();
				if (!code)
					return code.error();

				auto injection = vmc->load_code(SCRIPT_VM, *code);
				if (!injection)
				{
					vmc_log.append(SCRIPT_VM " generation: " + injection.error().message() + "\r\n");
					goto error;
				}
			}

			auto compilation = vmc->compile_sync();
			if (!compilation)
			{
				vmc_log.append(SCRIPT_VM " compilation: " + compilation.error().message() + "\r\n");
				goto error;
			}

			auto module = cmodule(vmc->unlink_module());
			if (module->get_properties_count() > std::numeric_limits<uint16_t>::max())
			{
				vmc_log.append(SCRIPT_VM " property validation: too many global properties\r\n");
				goto error;
			}

			for (size_t i = 0; i < module->get_properties_count(); i++)
			{
				property_info info;
				auto status = module->get_property(i, &info);
				if (!status)
				{
					vmc_log.append(SCRIPT_VM " property validation: " + status.error().message() + "\r\n");
					goto error;
				}

				auto type = vm->get_type_info_by_id(info.type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
				if (name != SCRIPT_TYPE_VARYING && name != SCRIPT_TYPE_MAPPING && name != SCRIPT_TYPE_LISTING && name != SCRIPT_TYPE_RANGING)
				{
					auto decl = module->get_property_decl(i, true);
					vmc_log.append(stringify::text(SCRIPT_VM " illegal property declaration \"%.*s\"\r\n", (int)decl.size(), decl.data()));
					goto error;
				}
			}

			return expects_lr<cmodule>(std::move(module));
		}
		expects_lr<void> factory::reset_module(library& module, immediate_context* target_context)
		{
			auto* context = target_context ? target_context : vm->request_context();
			if (!context)
				return layer_exception("failed to allocate the context");

			auto status = module.reset_properties(context->get_context());
			if (!target_context)
				vm->return_context(context);

			if (!status)
				return layer_exception(std::move(status.error().message()));

			size_t count = module.get_properties_count();
			for (size_t i = 0; i < count; i++)
			{
				property_info info;
				if (!module.get_property(i, &info))
					continue;

				auto type = vm->get_type_info_by_id(info.type_id);
				auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
				if (name == SCRIPT_TYPE_VARYING || name == SCRIPT_TYPE_MAPPING || name == SCRIPT_TYPE_LISTING || name == SCRIPT_TYPE_RANGING)
				{
					auto value = (container_repr*)module.get_address_of_property(i);
					value->slot = (uint8_t)(i + 1);
					value->reset();
				}
			}

			return expectation::met;
		}
		virtual_machine* factory::get_vm()
		{
			return *vm;
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
		int factory::from_string_constant(void*, const void* object, char* buffer, size_t* buffer_size)
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

		program::program(ledger::executor_context* new_executor, library&& new_module, program* new_parent) : executor(new_executor), module(new_module)
		{
		}
		expects_lr<void> program::execute(const payable_repr& payable, ccall mutability, const std::string_view& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			auto candidate = module.get_function_by_name(entrypoint);
			return execute(payable, mutability, candidate.is_valid() ? candidate : module.get_function_by_decl(entrypoint), args, std::move(return_callback));
		}
		expects_lr<void> program::execute(const payable_repr& payable, ccall mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			if (!entrypoint.is_valid())
			{
				if (mutability == ccall::deploy_call)
					return expectation::met;

				return layer_exception("illegal call to function: null function");
			}

			auto binders = dispatch_arguments(&mutability, entrypoint, &args);
			if (!binders)
				return binders.error();

			size_t depth_in = 0, depth_out = 0;
			auto* vm = entrypoint.get_vm();
			auto* caller = immediate_context::get();
			auto* coroutine = caller ? caller : vm->request_context();
			auto* prev_mutable_program = coroutine->get_user_data(SCRIPT_TAG_MUTABLE_PROGRAM);
			auto* prev_immutable_program = coroutine->get_user_data(SCRIPT_TAG_IMMUTABLE_PROGRAM);
			bool inline_call = caller != coroutine;
			auto resolver = expects_lr<void>(layer_exception());
			auto execution = expects_vm<vitex::scripting::execution>(vitex::scripting::execution::error);
			auto resolve = [this, &resolver, &entrypoint, &return_callback](immediate_context* coroutine)
			{
				int output_type_id = entrypoint.get_return_type_id();
				void* output_value = coroutine->get_return_address();
				if (!output_value && output_type_id > 0 && output_type_id <= (int)type_id::double_t)
					output_value = coroutine->get_address_of_return_value();

				if (return_callback)
					resolver = return_callback(output_value, output_type_id);
				else
					resolver = expectation::met;
			};
			coroutine->set_user_data(mutability == ccall::deploy_call || mutability == ccall::paying_call ? this : nullptr, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(this, SCRIPT_TAG_IMMUTABLE_PROGRAM);
			coroutine->is_nested(&depth_in);
			cache.payable = payable;
			if (inline_call)
			{
				coroutine->set_line_callback(std::bind(&program::dispatch_coroutine, this, std::placeholders::_1));
				coroutine->set_exception_callback(std::bind(&program::dispatch_exception, this, std::placeholders::_1));
			}

			auto preparation = factory::get()->reset_module(module, inline_call ? coroutine : nullptr);
			if (preparation)
			{
				auto binder = [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); };
				execution = inline_call ? coroutine->execute_inline_call(entrypoint, binder) : coroutine->execute_subcall(entrypoint, binder, resolve);
				if (inline_call)
					resolve(coroutine);
			}

			auto name = entrypoint.get_module_name();
			auto exception = coroutine->get_state() == execution::aborted ? exception_repr(exception_repr::category::execution(), "ran out of gas") : contract::get_exception_at(coroutine, inline_call ? 0 : (depth_in + 1));
			coroutine->set_user_data(prev_mutable_program, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(prev_immutable_program, SCRIPT_TAG_IMMUTABLE_PROGRAM);
			coroutine->is_nested(&depth_out);
			if (inline_call)
				vm->return_context(coroutine);
			else if (depth_in < depth_out)
				coroutine->pop_state();
			if (execution && *execution == execution::finished && preparation && exception.empty())
				return resolver;

			string base_message = exception.text.empty() ? (preparation ? string("illegal operation") : preparation.error().message()) : exception.text;
			string error_message;
			if (base_message.empty() || base_message.front() != '(')
				error_message.append(1, '(').append(exception.type.empty() ? exception_repr::category::execution() : exception.type).append(") ");
			error_message.append(base_message);
			error_message.append(exception.origin);
			return layer_exception(std::move(error_message));
		}
		expects_lr<void> program::subexecute(const algorithm::pubkeyhash_t& target, const payable_repr& payable, ccall mutability, const std::string_view& entrypoint, format::variables&& args, void* output_value, int output_type_id)
		{
			if (entrypoint.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", address_repr(target).to_string().data()));

			auto link = executor->get_account_program(target);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", address_repr(target).to_string().data(), (int)entrypoint.size(), entrypoint.data()));

			auto transaction = transactions::call();
			transaction.call_to(target, entrypoint, std::move(args), false);
			transaction.pays = payable.payments;
			transaction.asset = executor->transaction->asset;
			transaction.gas_price = executor->transaction->gas_price;
			transaction.gas_limit = executor->get_gas_left();
			transaction.nonce = 0;

			auto subexecutor = ledger::executor_context(executor->changelog, executor->solver, executor->block, &transaction);
			subexecutor.receipt.transaction_hash = transaction.as_hash();
			subexecutor.receipt.absolute_gas_use = executor->block->gas_use;
			subexecutor.receipt.block_number = executor->block->number;
			subexecutor.receipt.from = callable();

			auto prev_cache = std::move(cache);
			auto* prev_executor = executor;
			auto prev_module = module;
			auto subexecution = transaction.subexecute(&subexecutor, [&](const transactions::call::payable_array& payable_ptr, void* module_ptr)
			{
				executor = &subexecutor;
				cache = cache_storage();
				module = library((asIScriptModule*)module_ptr);
				return execute(payable_repr(transactions::call::payable_array(payable_ptr)), mutability, entrypoint, transaction.args, [&](void* result_value, int return_type_id) -> expects_lr<void>
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
			cache = std::move(prev_cache);
			module = prev_module;
			executor = prev_executor;
			executor->receipt.events.insert(executor->receipt.events.end(), subexecutor.receipt.events.begin(), subexecutor.receipt.events.end());
			executor->receipt.relative_gas_use += subexecutor.receipt.relative_gas_use;
			return subexecution;
		}
		expects_lr<vector<std::function<void(immediate_context*)>>> program::dispatch_arguments(ccall* mutability, const function& entrypoint, const format::variables* args) const
		{
			VI_ASSERT(mutability != nullptr, "mutability should be set");
			auto function_name = entrypoint.get_name();
			if (!entrypoint.get_namespace().empty())
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			if (function_name == SCRIPT_FUNCTION_CONSTRUCT && *mutability != ccall::deploy_call)
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			auto* vm = entrypoint.get_vm();
			size_t args_count = entrypoint.get_args_count();
			if (!args)
			{
				if (args_count < 1)
					return layer_exception(stringify::text("illegal call to function \"%s\": expected exactly %i arguments", entrypoint.get_decl().data(), (int)args_count));

				args_count = 1;
			}
			else if (args_count != args->size() + 1)
				return layer_exception(stringify::text("illegal call to function \"%s\": expected exactly %i arguments", entrypoint.get_decl().data(), (int)args_count));

			vector<std::function<void(immediate_context*)>> frames = { };
			frames.reserve(args_count);

			for (size_t i = 0; i < args_count; i++)
			{
				int type_id;
				if (!entrypoint.get_arg(i, &type_id))
					return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), (int)i));

				auto type = vm->get_type_info_by_id(type_id);
				if (i > 0)
				{
					size_t index = i - 1;
					if (index >= args->size())
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), (int)i));

					if (type.is_valid() && (type.flags() & (size_t)object_behaviours::enumerator))
						type_id = (int)type_id::int32_t;

					switch (type_id)
					{
						case (int)type_id::bool_t:
							frames.emplace_back([i, index, args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)(*args)[index].as_boolean()); });
							break;
						case (int)type_id::int8_t:
						case (int)type_id::uint8_t:
							frames.emplace_back([i, index, args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)(*args)[index].as_uint8()); });
							break;
						case (int)type_id::int16_t:
						case (int)type_id::uint16_t:
							frames.emplace_back([i, index, args](immediate_context* coroutine) { coroutine->set_arg16(i, (uint16_t)(*args)[index].as_uint16()); });
							break;
						case (int)type_id::int32_t:
						case (int)type_id::uint32_t:
							frames.emplace_back([i, index, args](immediate_context* coroutine) { coroutine->set_arg32(i, (uint32_t)(*args)[index].as_uint32()); });
							break;
						case (int)type_id::int64_t:
						case (int)type_id::uint64_t:
							frames.emplace_back([i, index, args](immediate_context* coroutine) { coroutine->set_arg64(i, (uint64_t)(*args)[index].as_uint64()); });
							break;
						case (int)type_id::float_t:
						case (int)type_id::double_t:
							return layer_exception("floating point value not permitted");
						default:
						{
							void* address = nullptr;
							auto& value = (*args)[index];
							format::wo_stream stream;
							format::variables_util::serialize_flat_into({ value }, &stream);

							auto reader = stream.ro();
							auto status = marshall::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
							if (!status)
							{
								auto reader_message = format::util::decode_stream(value.as_string());
								reader = format::ro_stream(reader_message);
								status = marshall::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
								if (!status)
									return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program (%s)", entrypoint.get_decl().data(), i, status.error().what()));
							}

							auto object = cobject(vm, type.get_type_info(), address, nullptr);
							frames.emplace_back([i, object = std::move(object)](immediate_context* coroutine) mutable { coroutine->set_arg_object(i, (void*)object.address); });
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
						if (*mutability != ccall::deploy_call && *mutability != ccall::paying_call)
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
					frames.emplace_back([i, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (program*)this); });
				}
			}
			return expects_lr<vector<std::function<void(immediate_context*)>>>(std::move(frames));
		}
		void program::dispatch_event(int, const void*, int)
		{
		}
		void program::dispatch_exception(immediate_context*)
		{
		}
		void program::dispatch_coroutine(immediate_context* coroutine)
		{
			auto status = executor->burn_gas((uint64_t)ledger::gas_cost::program_iop);
			if (!status)
				coroutine->abort();
		}
		option<ccall> program::external_mutability_of(const algorithm::pubkeyhash_t& target, const std::string_view& entrypoint) const
		{
			auto index = executor->get_account_program(target);
			if (!index)
				return optional::none;

			auto& hashcode = index->hashcode;
			auto program = executor->get_witness_program(hashcode);
			if (!program)
				return optional::none;

			auto pmodule = script::factory::get()->compile_module(format::util::encode_0xhex(hashcode), [&]() { return program->as_code(); });
			if (!pmodule)
				return optional::none;

			auto candidate = module.get_function_by_name(entrypoint);
			if (!candidate.is_valid())
				candidate = module.get_function_by_decl(entrypoint);
			if (!candidate.is_valid())
				return optional::none;

			ccall mutability = ccall::paying_call;
			if (!dispatch_arguments(&mutability, candidate, nullptr))
				return optional::none;

			return mutability;
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
			uint32_t type = executor->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)executor->transaction)->callable;
			else if (type == transactions::deploy::as_instance_type())
				return ((transactions::deploy*)executor->transaction)->get_account();

			return executor->receipt.from;
		}
		payable_repr program::payable_value() const
		{
			return cache.payable ? *cache.payable : payable_repr();
		}
		function program::deploy_function() const
		{
			return module.get_function_by_name(SCRIPT_FUNCTION_CONSTRUCT);
		}
		string program::function_declaration() const
		{
			uint32_t type = executor->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)executor->transaction)->function;
			else if (type == transactions::deploy::as_instance_type())
				return string(SCRIPT_FUNCTION_CONSTRUCT);

			return string();
		}
		const format::variables* program::function_arguments() const
		{
			uint32_t type = executor->transaction->as_type();
			if (type == transactions::deploy::as_instance_type())
			{
				auto& args = ((transactions::deploy*)executor->transaction)->args;
				return &args;
			}
			else if (type == transactions::call::as_instance_type())
			{
				auto& args = ((transactions::call*)executor->transaction)->args;
				return &args;
			}
			return nullptr;
		}
		uint64_t program::virtual_block_number() const
		{
			return executor->block->number;
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
			if (program && !program->executor->burn_gas((size_t)ledger::gas_cost::program_mop * (1 + difficulty)))
			{
				contract::throw_ptr(exception_repr(exception_repr::category::execution(), std::string_view("ran out of gas")));
				return false;
			}
			return true;
		}
		bool program::request_gas_vmemory(size_t size)
		{
			auto* program = program::fetch_immutable();
			if (program != nullptr)
			{
				size_t paid_blocks = std::max(size / sizeof(uint128_t), sizeof(uint128_t));
				size_t paid_gas = (size_t)ledger::gas_cost::program_memory * paid_blocks;
				if (paid_gas > 0 && !program->executor->burn_gas(paid_gas))
				{
					contract::throw_ptr(exception_repr(exception_repr::category::memory(), std::string_view("ran out of gas")));
					return false;
				}
			}
			return true;
		}
		bool program::request_gas_vmemory_marshall(const format::ro_stream& stream, size_t prev_seek)
		{
			return prev_seek < stream.seek ? request_gas_vmemory(stream.seek - prev_seek) : true;
		}
	}
}
