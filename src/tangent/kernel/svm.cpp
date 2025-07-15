#include "svm.h"
#include "../policy/transactions.h"
#include "../validator/storage/chainstate.h"
#include <vitex/bindings.h>
#include <sstream>
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_QUERY_PREFETCH ((size_t)gas_cost::query_byte / (size_t)gas_cost::bulk_query_byte)
#define SCRIPT_TAG_MUTABLE_PROGRAM 19190
#define SCRIPT_TAG_IMMUTABLE_PROGRAM 19191
#define SCRIPT_NAMESPACE_INSTRSET "instrset"
#define SCRIPT_ENUM_COMPARATOR "comparator"
#define SCRIPT_ENUM_ORDER "order"
#define SCRIPT_CLASS_RWPTR "rwptr"
#define SCRIPT_CLASS_RPTR "rptr"
#define SCRIPT_CLASS_ADDRESS "address"
#define SCRIPT_CLASS_ABI "abi"
#define SCRIPT_CLASS_FILTER "filter"
#define SCRIPT_CLASS_COLUMN_CURSOR "xc"
#define SCRIPT_CLASS_COLUMN_FILTER_CURSOR "xfc"
#define SCRIPT_CLASS_ROW_CURSOR "yc"
#define SCRIPT_CLASS_ROW_FILTER_CURSOR "yfc"
#define SCRIPT_CLASS_STRINGVIEW "string_view"
#define SCRIPT_CLASS_STRING "string"
#define SCRIPT_CLASS_UINT128 "uint128"
#define SCRIPT_CLASS_UINT256 "uint256"
#define SCRIPT_CLASS_DECIMAL "decimal"
#define SCRIPT_CLASS_ARRAY "array"
#define SCRIPT_EXCEPTION_REQUIREMENT "requirement_error"
#define SCRIPT_EXCEPTION_ARGUMENT "argument_error"
#define SCRIPT_EXCEPTION_STORAGE "storage_error"
#define SCRIPT_EXCEPTION_EXECUTION "execution_error"
#define SCRIPT_FUNCTION_CONSTRUCTOR "construct"

namespace tangent
{
	namespace ledger
	{
		struct uscript_object
		{
			virtual_machine* vm;
			asITypeInfo* type;
			void* address;

			uscript_object(virtual_machine* new_vm, asITypeInfo* new_type, void* new_address) noexcept : vm(new_vm), type(new_type), address(new_address)
			{
			}
			uscript_object(const uscript_object& other) noexcept : vm(other.vm), type(other.type), address(other.address)
			{
				((uscript_object*)&other)->address = nullptr;
			}
			uscript_object(uscript_object&& other) noexcept : vm(other.vm), type(other.type), address(other.address)
			{
				other.address = nullptr;
			}
			~uscript_object()
			{
				destroy();
			}
			uscript_object& operator= (const uscript_object& other) noexcept
			{
				if (this == &other)
					return *this;

				destroy();
				vm = other.vm;
				type = other.type;
				address = other.address;
				((uscript_object*)&other)->address = nullptr;
				return *this;
			}
			uscript_object& operator= (uscript_object&& other) noexcept
			{
				if (this == &other)
					return *this;

				destroy();
				vm = other.vm;
				type = other.type;
				address = other.address;
				other.address = nullptr;
				return *this;
			}
			inline void destroy()
			{
				if (vm != nullptr && type != nullptr && address != nullptr)
					vm->release_object(address, type);
			}
		};

		static svm_multiform_filter svm_multiform_greater(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::greater, order, value }; }
		static svm_multiform_filter svm_multiform_greater_equal(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::greater_equal, order, value }; }
		static svm_multiform_filter svm_multiform_equal(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::equal, order, value }; }
		static svm_multiform_filter svm_multiform_not_equal(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::not_equal, order, value }; }
		static svm_multiform_filter svm_multiform_less(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::less, order, value }; }
		static svm_multiform_filter svm_multiform_less_equal(const uint256_t& value, ledger::filter_order order) { return { ledger::filter_comparator::less_equal, order, value }; }
		static void svm_address_pay(svm_address& to, const uint256_t& asset, const decimal& value)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->pay(to, asset, value);
		}
		static void svm_address_call(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto& target = *(svm_address*)inout.get_object_address();
			auto& function = *inout.get_arg_object<std::string_view>(0);
			void* input_value = inout.get_arg_address(1);
			int input_type_id = inout.get_arg_type_id(1);
			void* output_value = inout.get_address_of_return_location();
			int output_type_id = inout.get_return_addressable_type_id();

			auto* program = svm_program::fetch_mutable();
			if (program != nullptr)
				return program->internal_call(target, function, input_value, input_type_id, output_value, output_type_id);

			auto* immutable_program = svm_program::fetch_immutable_or_throw();
			if (immutable_program != nullptr)
				return immutable_program->internal_call(target, function, input_value, input_type_id, output_value, output_type_id);
		}
		static void log_emit(void* object_value, int object_type_id)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->emit_event(object_value, object_type_id);
		}
		static void uniform_set(const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->store_uniform(index_value, index_type_id, object_value, object_type_id);
		}
		static void uniform_erase(const void* index_value, int index_type_id)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->store_uniform(index_value, index_type_id, nullptr, (int)type_id::void_t);
		}
		static void uniform_set_if(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool condition)
		{
			if (condition)
				uniform_set(index_value, index_type_id, object_value, object_type_id);
			else
				uniform_erase(index_value, index_type_id);
		}
		static bool uniform_has(const void* index_value, int index_type_id)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->has_uniform(index_value, index_type_id) : false;
		}
		static bool uniform_at(const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->load_uniform(index_value, index_type_id, object_value, object_type_id, false) : false;
		}
		static void uniform_get(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			void* index_value = inout.get_arg_address(0);
			int index_type_id = inout.get_arg_type_id(0);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto* program = svm_program::fetch_immutable_or_throw();
			if (program != nullptr)
				program->load_uniform(index_value, index_type_id, object_value, object_type_id, true);
		}
		static void multiform_set_2(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, int64_t filter_value)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->store_multiform(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
		}
		static void multiform_set_1(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			multiform_set_2(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0);
		}
		static void multiform_erase(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			if (program != nullptr)
				program->store_multiform(column_value, column_type_id, row_value, row_type_id, nullptr, (int)type_id::void_t, 0);
		}
		static void multiform_set_if_2(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, int64_t filter_value, bool condition)
		{
			if (condition)
				multiform_set_2(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value);
			else
				multiform_erase(column_value, column_type_id, row_value, row_type_id);
		}
		static void multiform_set_if_1(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool condition)
		{
			return multiform_set_if_2(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, 0, condition);
		}
		static bool multiform_at_2(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->load_multiform(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, filter_value, false) : false;
		}
		static bool multiform_at_1(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			return multiform_at_2(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr);
		}
		static bool multiform_has(const void* column_value, int column_type_id, const void* row_value, int row_type_id)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->has_multiform(column_value, column_type_id, row_value, row_type_id) : false;
		}
		static void multiform_get(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			void* column_value = inout.get_arg_address(0);
			int column_type_id = inout.get_arg_type_id(0);
			void* row_value = inout.get_arg_address(1);
			int row_type_id = inout.get_arg_type_id(1);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			auto* program = svm_program::fetch_immutable_or_throw();
			if (program != nullptr)
				program->load_multiform(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, nullptr, true);
		}
		static svm_multiform_column_cursor multiform_query_column_cursor(const void* column_value, int column_type_id, size_t count)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->multiform_column_cursor(column_value, column_type_id, count > 0 ? count : SCRIPT_QUERY_PREFETCH) : svm_multiform_column_cursor();
		}
		static svm_multiform_column_filter_cursor multiform_query_column_filter_cursor(const void* column_value, int column_type_id, const svm_multiform_filter& filter, size_t count)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->multiform_column_filter_cursor(column_value, column_type_id, filter, count > 0 ? count : SCRIPT_QUERY_PREFETCH) : svm_multiform_column_filter_cursor();
		}
		static svm_multiform_row_cursor multiform_query_row_cursor(const void* row_value, int row_type_id, size_t count)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->multiform_row_cursor(row_value, row_type_id, count > 0 ? count : SCRIPT_QUERY_PREFETCH) : svm_multiform_row_cursor();
		}
		static svm_multiform_row_filter_cursor multiform_query_row_filter_cursor(const void* row_value, int row_type_id, const svm_multiform_filter& filter, size_t count)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->multiform_row_filter_cursor(row_value, row_type_id, filter, count > 0 ? count : SCRIPT_QUERY_PREFETCH) : svm_multiform_row_filter_cursor();
		}
		static void math_min(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int left_type_id = inout.get_arg_type_id(0);
			int right_type_id = inout.get_arg_type_id(1);
			int result_type_id = inout.get_return_addressable_type_id();
			if (left_type_id != right_type_id || left_type_id != result_type_id)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type mismatch"));

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
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(result_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
					right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
					if (name == SCRIPT_CLASS_UINT128)
					{
						uint128_t& object_value = *(uint128_t*)inout.get_address_of_return_location();
						object_value = std::min<uint128_t>(*(uint128_t*)left_value, *(uint128_t*)right_value);
						break;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						uint256_t& object_value = *(uint256_t*)inout.get_address_of_return_location();
						object_value = std::min<uint256_t>(*(uint256_t*)left_value, *(uint256_t*)right_value);
						break;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						decimal& object_value = *(decimal*)inout.get_address_of_return_location();
						object_value = std::min<decimal>(*(decimal*)left_value, *(decimal*)right_value);
						break;
					}
					else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)std::min<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
						break;
					}
					return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type must be arithmetic"));
				}
			}
		}
		static void math_max(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int left_type_id = inout.get_arg_type_id(0);
			int right_type_id = inout.get_arg_type_id(1);
			int result_type_id = inout.get_return_addressable_type_id();
			if (left_type_id != right_type_id || left_type_id != result_type_id)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type mismatch"));

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
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(result_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
					right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
					if (name == SCRIPT_CLASS_UINT128)
					{
						uint128_t& object_value = *(uint128_t*)inout.get_address_of_return_location();
						object_value = std::max<uint128_t>(*(uint128_t*)left_value, *(uint128_t*)right_value);
						break;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						uint256_t& object_value = *(uint256_t*)inout.get_address_of_return_location();
						object_value = std::max<uint256_t>(*(uint256_t*)left_value, *(uint256_t*)right_value);
						break;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						decimal& object_value = *(decimal*)inout.get_address_of_return_location();
						object_value = std::max<decimal>(*(decimal*)left_value, *(decimal*)right_value);
						break;
					}
					else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)std::max<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
						break;
					}
					return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type must be arithmetic"));
				}
			}
		}
		static void math_pow(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int left_type_id = inout.get_arg_type_id(0);
			int right_type_id = inout.get_arg_type_id(1);
			int result_type_id = inout.get_return_addressable_type_id();
			if (left_type_id != right_type_id || left_type_id != result_type_id)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type mismatch"));

			void* left_value = inout.get_arg_address(0);
			void* right_value = inout.get_arg_address(1);
			switch (result_type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte((uint8_t)std::pow<int8_t>(*(int8_t*)left_value, *(int8_t*)right_value));
					break;
				case (int)type_id::bool_t:
				case (int)type_id::uint8_t:
					inout.set_return_byte((uint8_t)std::pow<uint8_t>(*(uint8_t*)left_value, *(uint8_t*)right_value));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word((uint16_t)std::pow<int16_t>(*(int16_t*)left_value, *(int16_t*)right_value));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word((uint16_t)std::pow<uint16_t>(*(uint16_t*)left_value, *(uint16_t*)right_value));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword((uint32_t)std::pow<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword((uint32_t)std::pow<uint32_t>(*(uint32_t*)left_value, *(uint32_t*)right_value));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword((uint64_t)std::pow<int64_t>(*(int64_t*)left_value, *(int64_t*)right_value));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword((uint64_t)std::pow<uint64_t>(*(uint64_t*)left_value, *(uint64_t*)right_value));
					break;
				case (int)type_id::float_t:
					inout.set_return_float(std::pow<float>(*(float*)left_value, *(float*)right_value));
					break;
				case (int)type_id::double_t:
					inout.set_return_double(std::pow<double>(*(double*)left_value, *(double*)right_value));
					break;
				default:
				{
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(result_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
					right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
					if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)std::pow<int32_t>(*(int32_t*)left_value, *(int32_t*)right_value));
						break;
					}
					return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type must be arithmetic and trivial"));
				}
			}
		}
		static void math_lerp(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			int left_type_id = inout.get_arg_type_id(0);
			int right_type_id = inout.get_arg_type_id(1);
			int delta_type_id = inout.get_arg_type_id(1);
			int result_type_id = inout.get_return_addressable_type_id();
			if (left_type_id != right_type_id || left_type_id != result_type_id || left_type_id != delta_type_id)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type mismatch"));

			void* left_value = inout.get_arg_address(0);
			void* right_value = inout.get_arg_address(1);
			void* delta_value = inout.get_arg_address(1);
			switch (result_type_id)
			{
				case (int)type_id::int8_t:
					inout.set_return_byte((uint8_t)math<int8_t>::lerp(*(int8_t*)left_value, *(int8_t*)right_value, *(int8_t*)delta_value));
					break;
				case (int)type_id::bool_t:
				case (int)type_id::uint8_t:
					inout.set_return_byte(math<uint8_t>::lerp(*(uint8_t*)left_value, *(uint8_t*)right_value, *(int8_t*)delta_value));
					break;
				case (int)type_id::int16_t:
					inout.set_return_word((uint16_t)math<int16_t>::lerp(*(int16_t*)left_value, *(int16_t*)right_value, *(int16_t*)delta_value));
					break;
				case (int)type_id::uint16_t:
					inout.set_return_word(math<uint16_t>::lerp(*(uint16_t*)left_value, *(uint16_t*)right_value, *(uint16_t*)delta_value));
					break;
				case (int)type_id::int32_t:
					inout.set_return_dword((uint32_t)math<int32_t>::lerp(*(int32_t*)left_value, *(int32_t*)right_value, *(int32_t*)delta_value));
					break;
				case (int)type_id::uint32_t:
					inout.set_return_dword(math<uint32_t>::lerp(*(uint32_t*)left_value, *(uint32_t*)right_value, *(uint32_t*)delta_value));
					break;
				case (int)type_id::int64_t:
					inout.set_return_qword((uint64_t)math<int64_t>::lerp(*(int64_t*)left_value, *(int64_t*)right_value, *(int64_t*)delta_value));
					break;
				case (int)type_id::uint64_t:
					inout.set_return_qword(math<uint64_t>::lerp(*(uint64_t*)left_value, *(uint64_t*)right_value, *(uint64_t*)delta_value));
					break;
				case (int)type_id::float_t:
					inout.set_return_float(math<float>::lerp(*(float*)left_value, *(float*)right_value, *(double*)delta_value));
					break;
				case (int)type_id::double_t:
					inout.set_return_double(math<double>::lerp(*(double*)left_value, *(double*)right_value, *(double*)delta_value));
					break;
				default:
				{
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(result_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					left_value = left_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)left_value : left_value;
					right_value = right_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)right_value : right_value;
					if (name == SCRIPT_CLASS_UINT128)
					{
						uint128_t& object_value = *(uint128_t*)inout.get_address_of_return_location();
						object_value = math<uint128_t>::lerp(*(uint128_t*)left_value, *(uint128_t*)right_value, *(uint128_t*)delta_value);
						break;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						uint256_t& object_value = *(uint256_t*)inout.get_address_of_return_location();
						object_value = math<uint256_t>::lerp(*(uint256_t*)left_value, *(uint256_t*)right_value, *(uint256_t*)delta_value);
						break;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						decimal& object_value = *(decimal*)inout.get_address_of_return_location();
						object_value = math<decimal>::lerp(*(decimal*)left_value, *(decimal*)right_value, *(decimal*)delta_value);
						break;
					}
					else if (result_type_id & (int)vitex::scripting::type_id::mask_seqnbr_t)
					{
						inout.set_return_dword((uint32_t)math<int32_t>::lerp(*(int32_t*)left_value, *(int32_t*)right_value, *(int32_t*)delta_value));
						break;
					}
					return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "template type must be arithmetic"));
				}
			}
		}
		static uint256_t block_parent_hash()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->parent_block_hash() : 0;
		}
		static uint256_t block_gas_left()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_gas_left() : 0;
		}
		static uint256_t block_gas_use()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_gas_use() : 0;
		}
		static uint256_t block_gas_limit()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_gas_limit() : 0;
		}
		static uint128_t block_difficulty()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_difficulty() : 0;
		}
		static uint64_t block_time()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_time() : 0;
		}
		static uint64_t block_time_between(uint64_t block_number_a, uint64_t block_number_b)
		{
			uint64_t left = std::min(block_number_a, block_number_b);
			uint64_t right = std::max(block_number_a, block_number_b);
			return (right - left) * protocol::now().policy.consensus_proof_time / 1000;
		}
		static uint64_t block_priority()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_priority() : 0;
		}
		static uint64_t block_number()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->block_number() : 0;
		}
		static decimal tx_value()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->value() : decimal::zero();
		}
		static bool tx_paid()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->value().is_positive() : false;
		}
		static svm_address tx_from()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->from() : svm_address();
		}
		static svm_address tx_to()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->to() : svm_address();
		}
		static string tx_blockchain()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->blockchain() : string();
		}
		static string tx_token()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->token() : string();
		}
		static string tx_contract()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->contract() : string();
		}
		static decimal tx_gas_price()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->gas_price() : decimal::zero();
		}
		static uint256_t tx_gas_left()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->gas_left() : 0;
		}
		static uint256_t tx_gas_use()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->gas_use() : 0;
		}
		static uint256_t tx_gas_limit()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->gas_limit() : 0;
		}
		static uint256_t tx_asset()
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			return program ? program->asset() : 0;
		}
		static string crc32(const std::string_view& data)
		{
			uint8_t buffer[32];
			uint256_t value = algorithm::hashing::hash32d(data);
			algorithm::encoding::decode_uint256(value, buffer);
			return string((char*)buffer + (sizeof(uint256_t) - sizeof(uint32_t)), sizeof(uint32_t));
		}
		static string ripe_md160(const std::string_view& data)
		{
			return algorithm::hashing::hash160((uint8_t*)data.data(), data.size());
		}
		static svm_address erecover160(const uint256_t& hash, const std::string_view& signature)
		{
			if (signature.size() != sizeof(algorithm::recpubsig))
				return svm_address();

			algorithm::pubkeyhash public_key_hash = { 0 }, null = { 0 };
			if (!algorithm::signing::recover_hash(hash, public_key_hash, (uint8_t*)signature.data()) || !memcmp(public_key_hash, null, sizeof(null)))
				return svm_address();

			return svm_address(algorithm::pubkeyhash_t(public_key_hash));
		}
		static string erecover264(const uint256_t& hash, const std::string_view& signature)
		{
			if (signature.size() != sizeof(algorithm::recpubsig))
				return string();

			algorithm::pubkey public_key = { 0 }, null = { 0 };
			if (!algorithm::signing::recover(hash, public_key, (uint8_t*)signature.data()) || !memcmp(public_key, null, sizeof(null)))
				return string();

			return string((char*)public_key, sizeof(public_key));
		}
		static uint256_t blake2b256(const std::string_view& data)
		{
			return algorithm::hashing::hash256i((uint8_t*)data.data(), data.size());
		}
		static string blake2b256s(const std::string_view& data)
		{
			return algorithm::hashing::hash256((uint8_t*)data.data(), data.size());
		}
		static uint256_t keccak256(const std::string_view& data)
		{
			uint256_t value;
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
			algorithm::encoding::encode_uint256(buffer, value);
			return value;
		}
		static string keccak256s(const std::string_view& data)
		{
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			sha256_Raw((uint8_t*)data.data(), data.size(), buffer);
			return string((char*)buffer, sizeof(buffer));
		}
		static string keccak512(const std::string_view& data)
		{
			uint8_t buffer[SHA3_512_DIGEST_LENGTH];
			keccak_512((uint8_t*)data.data(), data.size(), buffer);
			return string((char*)buffer, sizeof(buffer));
		}
		static uint256_t sha256(const std::string_view& data)
		{
			uint256_t value;
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			keccak_256((uint8_t*)data.data(), data.size(), buffer);
			algorithm::encoding::encode_uint256(buffer, value);
			return value;
		}
		static string sha256s(const std::string_view& data)
		{
			uint8_t buffer[SHA3_256_DIGEST_LENGTH];
			keccak_256((uint8_t*)data.data(), data.size(), buffer);
			return string((char*)buffer, sizeof(buffer));
		}
		static string sha512(const std::string_view& data)
		{
			return algorithm::hashing::hash512((uint8_t*)data.data(), data.size());
		}
		static string encode_bytes256(const uint256_t& value)
		{
			uint8_t data[32];
			algorithm::encoding::decode_uint256(value, data);
			return string((char*)data, sizeof(data));
		}
		static uint256_t decode_bytes256(const std::string_view& value)
		{
			uint8_t data[32];
			memcpy(data, value.data(), std::min(sizeof(data), value.size()));

			uint256_t buffer;
			algorithm::encoding::encode_uint256(data, buffer);
			return buffer;
		}
		static uint256_t random()
		{
			auto* program = svm_program::fetch_mutable_or_throw();
			return program ? program->random() : 0;
		}
		static uint256_t asset_value_from_decimal(const decimal& value)
		{
			if (value.is_nan())
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, value.to_string() + " as uint256 - not a number"));
				return 0;
			}

			if (value.is_negative())
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, value.to_string() + " as uint256 - negative number"));
				return 0;
			}

			if (value.decimal_places() > protocol::now().message.precision)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, value.to_string() + " as uint256 - decimal precision too high"));
				return 0;
			}

			auto copy = value;
			copy *= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.precision);

			auto max = uint256_t::max();
			if (copy > max.to_decimal())
				return max;

			return uint256_t(copy.truncate(0).to_string(), 10);
		}
		static decimal asset_value_to_decimal(const uint256_t& value)
		{
			auto precision = protocol::now().message.precision;
			auto result = value.to_decimal().truncate(precision);
			result /= (uint64_t)std::pow<uint64_t>(10, protocol::now().message.precision);
			return result;
		}
		static void require(bool condition, const std::string_view& message)
		{
			if (!condition)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_REQUIREMENT, message.empty() ? "requirement not met" : message));
		}
		static bool read_decimal_or_integer(format::ro_stream& stream, format::viewable type, decimal* value)
		{
			if (!format::util::is_integer(type))
				return stream.read_decimal(type, value);

			uint256_t value256;
			if (!stream.read_integer(type, &value256))
				return false;

			*value = value256.to_decimal();
			return true;
		}
		static size_t gas_cost_of(const byte_code_label& opcode)
		{
			auto gas = (size_t)(opcode.offset_of_arg2 + opcode.size_of_arg2) * (size_t)gas_cost::opcode;
			return gas;
		}

		expects_lr<void> svm_marshalling::store(format::wo_stream* stream, const void* value, int value_type_id)
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
					stream->write_decimal(decimal(*(float*)value));
					return expectation::met;
				case (int)type_id::double_t:
					stream->write_decimal(decimal(*(double*)value));
					return expectation::met;
				default:
				{
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->write_string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						stream->write_string(((svm_address*)value)->hash.optimized_view());
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_STRING)
					{
						stream->write_string(*(string*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT128)
					{
						stream->write_integer(*(uint128_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						stream->write_integer(*(uint256_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						stream->write_decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ARRAY)
					{
						auto* array = (bindings::array*)value;
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
						stream->write_integer((uint32_t)*(int*)value);
						return expectation::met;
					}
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> svm_marshalling::store(schema* stream, const void* value, int value_type_id)
		{
			if (!value)
				return expectation::met;

			switch (value_type_id)
			{
				case (int)type_id::void_t:
					return expectation::met;
				case (int)type_id::bool_t:
					stream->value = var::boolean(*(bool*)value);
					return expectation::met;
				case (int)type_id::int8_t:
				case (int)type_id::uint8_t:
					stream->value = var::integer(*(uint8_t*)value);
					return expectation::met;
				case (int)type_id::int16_t:
				case (int)type_id::uint16_t:
					stream->value = var::integer(*(uint16_t*)value);
					return expectation::met;
				case (int)type_id::int32_t:
				case (int)type_id::uint32_t:
					stream->value = var::integer(*(uint32_t*)value);
					return expectation::met;
				case (int)type_id::int64_t:
				case (int)type_id::uint64_t:
					stream->value = var::integer(*(uint64_t*)value);
					return expectation::met;
				case (int)type_id::float_t:
					stream->value = var::number(*(float*)value);
					return expectation::met;
				case (int)type_id::double_t:
					stream->value = var::number(*(double*)value);
					return expectation::met;
				default:
				{
					auto type = svm_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->value = var::string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						uptr<schema> data = algorithm::signing::serialize_subaddress(((svm_address*)value)->hash.data);
						stream->value = std::move(data->value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_STRING)
					{
						stream->value = var::string(*(string*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT128)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint128_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint256_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						stream->value = var::decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ARRAY)
					{
						auto* array = (bindings::array*)value;
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
		expects_lr<void> svm_marshalling::load(format::ro_stream& stream, void* value, int value_type_id)
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
				{
					decimal wrapper;
					if (!read_decimal_or_integer(stream, stream.read_type(), &wrapper))
						return layer_exception("load failed for float type");

					*(float*)value = wrapper.to_float();
					return expectation::met;
				}
				case (int)type_id::double_t:
				{
					decimal wrapper;
					if (!read_decimal_or_integer(stream, stream.read_type(), &wrapper))
						return layer_exception("load failed for double type");

					*(double*)value = wrapper.to_double();
					return expectation::met;
				}
				default:
				{
					bool managing = false;
					auto* vm = svm_host::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						void* address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("allocation failed for %s type", name.data()));

						*(void**)value = address;
						value = address;
						managing = true;
					}

					auto unique = uscript_object(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_CLASS_ADDRESS)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for address type");

						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::subpubkeyhash))
						{
							if (!algorithm::signing::decode_subaddress(data, ((svm_address*)value)->hash.data))
								return layer_exception("load failed for address type");
						}
						else
							((svm_address*)value)->hash = algorithm::subpubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_STRING)
					{
						if (!stream.read_string(stream.read_type(), (string*)value))
							return layer_exception("load failed for string type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT128)
					{
						if (!stream.read_integer(stream.read_type(), (uint128_t*)value))
							return layer_exception("load failed for uint128 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						if (!stream.read_integer(stream.read_type(), (uint256_t*)value))
							return layer_exception("load failed for uint256 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						if (!read_decimal_or_integer(stream, stream.read_type(), (decimal*)value))
							return layer_exception("load failed for decimal type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ARRAY)
					{
						uint32_t size;
						if (!stream.read_integer(stream.read_type(), &size))
							return layer_exception("load failed for uint32 type");

						auto* array = (bindings::array*)value;
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
		expects_lr<void> svm_marshalling::load(schema* stream, void* value, int value_type_id)
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
					*(float*)value = (float)stream->value.get_number();
					return expectation::met;
				case (int)type_id::double_t:
					*(double*)value = (double)stream->value.get_number();
					return expectation::met;
				default:
				{
					bool managing = false;
					auto* vm = svm_host::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !(type.flags() & (size_t)object_behaviours::enumerator) && !*(void**)value)
					{
						void* address = vm->create_object(type);
						if (!address)
							return layer_exception(stringify::text("allocation failed for %s type", name.data()));

						*(void**)value = address;
						value = address;
						managing = true;
					}

					auto unique = uscript_object(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_CLASS_ADDRESS)
					{
						string data = stream->value.get_blob();
						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::subpubkeyhash))
						{
							if (!algorithm::signing::decode_subaddress(data, ((svm_address*)value)->hash.data))
								return layer_exception("load failed for address type");
						}
						else
							((svm_address*)value)->hash = algorithm::subpubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_STRING)
					{
						*(string*)value = stream->value.get_blob();
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT128)
					{
						*(uint128_t*)value = uint128_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						*(uint256_t*)value = uint256_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_DECIMAL)
					{
						*(decimal*)value = stream->value.get_decimal();
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ARRAY)
					{
						uint32_t size = (uint32_t)stream->size();
						auto* array = (bindings::array*)value;
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

		svm_host::svm_host() noexcept
		{
			preprocessor::desc compiler_features;
			compiler_features.conditions = false;
			compiler_features.defines = false;
			compiler_features.includes = false;
			compiler_features.pragmas = false;

			vm = new virtual_machine();
			vm->set_compiler_features(compiler_features);
			vm->set_library_property(library_features::promise_no_constructor, 1);
			vm->set_library_property(library_features::promise_no_callbacks, 1);
			vm->set_library_property(library_features::ctypes_no_pointer_cast, 1);
			vm->set_library_property(library_features::decimal_default_precision, (size_t)protocol::now().message.precision);
			vm->set_property(features::disallow_global_vars, 1);
			vm->set_ts_imports(false);
			vm->set_full_stack_tracing(false);
			vm->set_cache(false);

			bindings::registry::import_ctypes(*vm);
			bindings::registry::import_array(*vm);
			bindings::registry::import_safe_string(*vm);
			bindings::registry::import_exception(*vm);
			bindings::registry::import_decimal(*vm);
			bindings::registry::import_uint128(*vm);
			bindings::registry::import_uint256(*vm);

			vm->begin_namespace(SCRIPT_NAMESPACE_INSTRSET);
			auto instrset_rwptr = vm->set_interface_class<svm_program>(SCRIPT_CLASS_RWPTR);
			auto instrset_rptr = vm->set_interface_class<svm_program>(SCRIPT_CLASS_RPTR);
			vm->end_namespace();

			auto address = vm->set_pod<svm_address>(SCRIPT_CLASS_ADDRESS);
			address->set_constructor<svm_address>("void f()");
			address->set_constructor<svm_address, const std::string_view&>("void f(const string_view&in)");
			address->set_constructor<svm_address, const uint256_t&>("void f(const uint256&in)");
			address->set_constructor<svm_address, const uint256_t&, const uint256_t&>("void f(const uint256&in, const uint256&in)");
			address->set_method("address to_address() const", &svm_address::to_address);
			address->set_method("address to_subaddress_from_hash(const uint256&in) const", &svm_address::to_subaddress_from_hash);
			address->set_method("address to_subaddress_from_data(const string_view&in) const", &svm_address::to_subaddress_from_data);
			address->set_method("string to_string() const", &svm_address::to_string);
			address->set_method("uint256 to_public_key_hash() const", &svm_address::to_public_key_hash);
			address->set_method("uint256 to_derivation_hash() const", &svm_address::to_derivation_hash);
			address->set_method("bool empty() const", &svm_address::empty);
			address->set_method_extern("void pay(const uint256&in, const decimal&in) const", &svm_address_pay);
			address->set_method_extern("t call<t>(const string_view&in, const ?&in) const", &svm_address_call, convention::generic_call);
			address->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const address&in", &svm_address::equals);

			auto abi = vm->set_struct_trivial<svm_abi>(SCRIPT_CLASS_ABI);
			abi->set_constructor<svm_abi>("void f()");
			abi->set_constructor<svm_abi, const std::string_view&>("void f(const string_view&in)");
			abi->set_method("void seek(usize)", &svm_abi::seek);
			abi->set_method("void clear()", &svm_abi::clear);
			abi->set_method("void merge(const string_view&in)", &svm_abi::merge);
			abi->set_method("void wstr(const string_view&in)", &svm_abi::wstr);
			abi->set_method("void wrstr(const string_view&in)", &svm_abi::wrstr);
			abi->set_method("void wbn(const decimal&in)", &svm_abi::wdecimal);
			abi->set_method("void wu8(bool)", &svm_abi::wboolean);
			abi->set_method("void wu160(const address&in)", &svm_abi::wuint160);
			abi->set_method("void wu256(const uint256&in)", &svm_abi::wuint256);
			abi->set_method("bool rstr(string&out)", &svm_abi::rstr);
			abi->set_method("bool rbn(decimal&out)", &svm_abi::rdecimal);
			abi->set_method("bool ru8(bool&out)", &svm_abi::rboolean);
			abi->set_method("bool ru160(address&out)", &svm_abi::ruint160);
			abi->set_method("bool ru256(uint256&out)", &svm_abi::ruint256);
			abi->set_method("string& data()", &svm_abi::data);
			abi->set_method("const string& data() const", &svm_abi::data_const);

			vm->begin_namespace("log");
			vm->set_function("void emit(const ?&in)", &log_emit);
			vm->end_namespace();

			vm->begin_namespace("sv");
			vm->set_function("void set(const ?&in, const ?&in)", &uniform_set);
			vm->set_function("void set_if(const ?&in, const ?&in, bool)", &uniform_set_if);
			vm->set_function("void erase(const ?&in)", &uniform_erase);
			vm->set_function("bool has(const ?&in)", &uniform_has);
			vm->set_function("bool at(const ?&in, ?&out)", &uniform_at);
			vm->set_function("t as<t>(const ?&in)", &uniform_get, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("qsv");
			auto multiform_condition = vm->set_enum(SCRIPT_ENUM_COMPARATOR);
			multiform_condition->set_value("greater", (int)ledger::filter_comparator::greater);
			multiform_condition->set_value("greater_equal", (int)ledger::filter_comparator::greater_equal);
			multiform_condition->set_value("equal", (int)ledger::filter_comparator::equal);
			multiform_condition->set_value("not_equal", (int)ledger::filter_comparator::not_equal);
			multiform_condition->set_value("less", (int)ledger::filter_comparator::less);
			multiform_condition->set_value("less_equal", (int)ledger::filter_comparator::less_equal);
			auto multiform_order = vm->set_enum(SCRIPT_ENUM_ORDER);
			multiform_order->set_value("ascending", (int)ledger::filter_order::ascending);
			multiform_order->set_value("descending", (int)ledger::filter_order::descending);
			auto multiform_filter = vm->set_struct_trivial<svm_multiform_filter>(SCRIPT_CLASS_FILTER);
			multiform_filter->set_constructor<svm_multiform_filter>("void f()");
			multiform_filter->set_property("comparator comparator", &svm_multiform_filter::comparator);
			multiform_filter->set_property("order order", &svm_multiform_filter::order);
			multiform_filter->set_property("uint256 value", &svm_multiform_filter::value);
			auto multiform_column_cursor = vm->set_struct_trivial<svm_multiform_column_cursor>(SCRIPT_CLASS_COLUMN_CURSOR);
			multiform_column_cursor->set_constructor<svm_multiform_column_cursor>("void f()");
			multiform_column_cursor->set_method("bool at(usize, ?&out) const", &svm_multiform_column_cursor::at1);
			multiform_column_cursor->set_method("bool at(usize, ?&out, ?&out) const", &svm_multiform_column_cursor::at2);
			multiform_column_cursor->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_multiform_column_cursor::at3);
			auto multiform_column_filter_cursor = vm->set_struct_trivial<svm_multiform_column_filter_cursor>(SCRIPT_CLASS_COLUMN_FILTER_CURSOR);
			multiform_column_filter_cursor->set_constructor<svm_multiform_column_filter_cursor>("void f()");
			multiform_column_filter_cursor->set_method("bool at(usize, ?&out) const", &svm_multiform_column_filter_cursor::at1);
			multiform_column_filter_cursor->set_method("bool at(usize, ?&out, ?&out) const", &svm_multiform_column_filter_cursor::at2);
			multiform_column_filter_cursor->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_multiform_column_filter_cursor::at3);
			auto multiform_row_cursor = vm->set_struct_trivial<svm_multiform_row_cursor>(SCRIPT_CLASS_ROW_CURSOR);
			multiform_row_cursor->set_constructor<svm_multiform_row_cursor>("void f()");
			multiform_row_cursor->set_method("bool at(usize, ?&out) const", &svm_multiform_row_cursor::at1);
			multiform_row_cursor->set_method("bool at(usize, ?&out, ?&out) const", &svm_multiform_row_cursor::at2);
			multiform_row_cursor->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_multiform_row_cursor::at3);
			auto multiform_row_filter_cursor = vm->set_struct_trivial<svm_multiform_row_filter_cursor>(SCRIPT_CLASS_ROW_FILTER_CURSOR);
			multiform_row_filter_cursor->set_constructor<svm_multiform_row_filter_cursor>("void f()");
			multiform_row_filter_cursor->set_method("bool at(usize, ?&out) const", &svm_multiform_row_filter_cursor::at1);
			multiform_row_filter_cursor->set_method("bool at(usize, ?&out, ?&out) const", &svm_multiform_row_filter_cursor::at2);
			multiform_row_filter_cursor->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_multiform_row_filter_cursor::at3);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in)", &multiform_set_1);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in, const uint256&in)", &multiform_set_2);
			vm->set_function("void set_if(const ?&in, const ?&in, const ?&in, bool)", &multiform_set_if_1);
			vm->set_function("void set_if(const ?&in, const ?&in, const ?&in, const uint256&in, bool)", &multiform_set_if_2);
			vm->set_function("void erase(const ?&in, const ?&in)", &multiform_erase);
			vm->set_function("bool has(const ?&in, const ?&in)", &multiform_has);
			vm->set_function("bool at(const ?&in, const ?&in, ?&out)", &multiform_at_1);
			vm->set_function("bool at(const ?&in, const ?&in, ?&out, uint256&out)", &multiform_at_2);
			vm->set_function("t as<t>(const ?&in, const ?&in)", &multiform_get, convention::generic_call);
			vm->set_function("xc query_x(const ?&in, usize = 1)", &multiform_query_column_cursor);
			vm->set_function("xfc query_x(const ?&in, const filter&in, usize = 1)", &multiform_query_column_filter_cursor);
			vm->set_function("yc query_y(const ?&in, usize = 1)", &multiform_query_row_cursor);
			vm->set_function("yfc query_y(const ?&in, const filter&in, usize = 1)", &multiform_query_row_filter_cursor);
			vm->set_function("filter gt(const uint256&in, order)", &svm_multiform_greater);
			vm->set_function("filter gte(const uint256&in, order)", &svm_multiform_greater_equal);
			vm->set_function("filter eq(const uint256&in, order)", &svm_multiform_equal);
			vm->set_function("filter neq(const uint256&in, order)", &svm_multiform_not_equal);
			vm->set_function("filter lt(const uint256&in, order)", &svm_multiform_less);
			vm->set_function("filter lte(const uint256&in, order)", &svm_multiform_less_equal);
			vm->end_namespace();

			vm->begin_namespace("block");
			vm->set_function("uint256 parent_hash()", &block_parent_hash);
			vm->set_function("uint256 gas_use()", &block_gas_use);
			vm->set_function("uint256 gas_limit()", &block_gas_limit);
			vm->set_function("uint128 difficulty()", &block_difficulty);
			vm->set_function("uint64 time()", &block_time);
			vm->set_function("uint64 time_between(uint64, uint64)", &block_time_between);
			vm->set_function("uint64 priority()", &block_priority);
			vm->set_function("uint64 number()", &block_number);
			vm->end_namespace();

			vm->begin_namespace("tx");
			vm->set_function("bool paid()", &tx_paid);
			vm->set_function("address from()", &tx_from);
			vm->set_function("address to()", &tx_to);
			vm->set_function("decimal value()", &tx_value);
			vm->set_function("string blockchain()", &tx_blockchain);
			vm->set_function("string token()", &tx_token);
			vm->set_function("string contract()", &tx_contract);
			vm->set_function("decimal gas_price()", &tx_gas_price);
			vm->set_function("uint256 gas_use()", &tx_gas_use);
			vm->set_function("uint256 gas_limit()", &tx_gas_limit);
			vm->set_function("uint256 asset()", &tx_asset);
			vm->end_namespace();

			vm->begin_namespace("currency");
			vm->set_function("uint256 from_decimal(const decimal&in)", &asset_value_from_decimal);
			vm->set_function("decimal to_decimal(const uint256&in)", &asset_value_to_decimal);
			vm->set_function("uint256 id_of(const string_view&in, const string_view&in = string_view(), const string_view&in = string_view())", &algorithm::asset::id_of);
			vm->set_function("string blockchain_of(const uint256&in)", &algorithm::asset::blockchain_of);
			vm->set_function("string token_of(const uint256&in)", &algorithm::asset::token_of);
			vm->set_function("string contract_of(const uint256&in)", &algorithm::asset::checksum_of);
			vm->set_function("string name_of(const uint256&in)", &algorithm::asset::name_of);
			vm->end_namespace();

			vm->begin_namespace("repr");
			vm->set_function("string from256(const uint256&in)", &encode_bytes256);
			vm->set_function("uint256 to256(const string_view&in)", &decode_bytes256);
			vm->end_namespace();

			vm->begin_namespace("dsa");
			vm->set_function("address erecover160(const uint256&in, const string_view&in)", &erecover160);
			vm->set_function("string erecover264(const uint256&in, const string_view&in)", &erecover264);
			vm->end_namespace();

			vm->begin_namespace("alg");
			vm->set_function("uint256 random256()", &random);
			vm->set_function("string crc32(const string_view&in)", &crc32);
			vm->set_function("string ripemd160(const string_view&in)", &ripe_md160);
			vm->set_function("uint256 blake2b256(const string_view&in)", &blake2b256);
			vm->set_function("string blake2b256s(const string_view&in)", &blake2b256s);
			vm->set_function("uint256 keccak256(const string_view&in)", &keccak256);
			vm->set_function("string keccak256s(const string_view&in)", &keccak256s);
			vm->set_function("string keccak512(const string_view&in)", &keccak512);
			vm->set_function("uint256 sha256(const string_view&in)", &sha256);
			vm->set_function("string sha256s(const string_view&in)", &sha256s);
			vm->set_function("string sha512(const string_view&in)", &sha512);
			vm->end_namespace();

			vm->begin_namespace("math");
			vm->set_function("t min<t>(const t&in, const t&in)", &math_min, convention::generic_call);
			vm->set_function("t max<t>(const t&in, const t&in)", &math_max, convention::generic_call);
			vm->set_function("t pow<t>(const t&in, const t&in)", &math_pow, convention::generic_call);
			vm->set_function("t lerp<t>(const t&in, const t&in, const t&in)", &math_lerp, convention::generic_call);
			vm->end_namespace();

			vm->set_function("void require(bool, const string_view&in = string_view())", &require);
		}
		svm_host::~svm_host() noexcept
		{
			for (auto& link : modules)
				library(link.second).discard();
			modules.clear();
		}
		uptr<compiler> svm_host::allocate()
		{
			umutex<std::mutex> unique(mutex);
			if (!compilers.empty())
			{
				auto compiler = std::move(compilers.front());
				compilers.pop();
				return compiler;
			}

			uptr<compiler> compiler = vm->create_compiler();
			compiler->clear();
			return compiler;
		}
		void svm_host::deallocate(uptr<compiler>&& compiler)
		{
			if (!compiler)
				return;

			umutex<std::mutex> unique(mutex);
			compiler->unlink_module();
			compilers.push(std::move(compiler));
		}
		expects_lr<void> svm_host::compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& program_name, const std::string_view& unpacked_program_code)
		{
			VI_ASSERT(compiler != nullptr, "compiler should not be null");
			string messages, id = string(program_hashcode);
			vm->set_compile_callback(program_name, [&messages](const std::string_view& message) { messages.append(message).append("\r\n"); });

			auto preparation = compiler->prepare(program_name, true);
			if (!preparation)
			{
				messages.append("svm preparation: " + preparation.error().message() + "\r\n");
			error:
				vm->set_compile_callback(program_name, nullptr);
				return layer_exception(std::move(messages));
			}

			auto injection = compiler->load_code(program_name, unpacked_program_code);
			if (!injection)
			{
				messages.append("svm generation: " + injection.error().message() + "\r\n");
				goto error;
			}

			auto compilation = compiler->compile_sync();
			if (!compilation)
			{
				messages.append("svm compilation: " + compilation.error().message() + "\r\n");
				goto error;
			}

			umutex<std::mutex> unique(mutex);
			if (modules.size() <= protocol::now().user.storage.svm_cache_size)
			{
				auto& link = modules[id];
				if (link != nullptr)
					::library(link).discard();

				link = compiler->get_module().get_module();
				return expectation::met;
			}

			for (auto& link : modules)
				::library(link.second).discard();

			modules.clear();
			modules[id] = compiler->get_module().get_module();
			return expectation::met;
		}
		bool svm_host::precompile(compiler* compiler, const std::string_view& program_hashcode)
		{
			VI_ASSERT(compiler != nullptr, "compiler should not be null");
			string id = string(program_hashcode);
			umutex<std::mutex> unique(mutex);
			auto it = modules.find(id);
			return it != modules.end() ? !!compiler->prepare(it->second) : false;
		}
		string svm_host::hashcode(const std::string_view& unpacked_program_code)
		{
			static std::string_view lines = "\r\n";
			static std::string_view erasable = " \r\n\t\'\"()<>=%&^*/+-,.!?:;@~";
			static std::string_view quotes = "\"'`";
			string hashable = string(unpacked_program_code);
			stringify::replace_in_between(stringify::trim(hashable), "/*", "*/", "", false);
			stringify::replace_starts_with_ends_of(stringify::trim(hashable), "//", lines, "");
			stringify::compress(stringify::trim(hashable), erasable, quotes);
			return algorithm::hashing::hash512((uint8_t*)hashable.data(), hashable.size());
		}
		expects_lr<string> svm_host::pack(const std::string_view& unpacked_program_code)
		{
			auto packed_program_code = codec::compress(unpacked_program_code, compression::best_compression);
			if (!packed_program_code)
				return layer_exception(std::move(packed_program_code.error().message()));

			return *packed_program_code;
		}
		expects_lr<string> svm_host::unpack(const std::string_view& packed_program_code)
		{
			auto unpacked_program_code = codec::decompress(packed_program_code);
			if (!unpacked_program_code)
				return layer_exception(std::move(unpacked_program_code.error().message()));

			return *unpacked_program_code;
		}
		virtual_machine* svm_host::get_vm()
		{
			return *vm;
		}

		svm_address::svm_address()
		{
		}
		svm_address::svm_address(const algorithm::pubkeyhash_t& owner)
		{
			if (!owner.empty())
				hash = algorithm::encoding::to_subaddress(owner.data);
		}
		svm_address::svm_address(const algorithm::subpubkeyhash_t& owner) : hash(owner)
		{
		}
		svm_address::svm_address(const std::string_view& address)
		{
			algorithm::signing::decode_subaddress(address, hash.data);
		}
		svm_address::svm_address(const uint256_t& owner_data)
		{
			uint8_t owner_raw_data[32];
			algorithm::encoding::decode_uint256(owner_data, owner_raw_data);
			hash = algorithm::encoding::to_subaddress(owner_raw_data);
		}
		svm_address::svm_address(const uint256_t& owner_data, const uint256_t& derivation_data)
		{
			uint8_t owner_raw_data[32], derivation_raw_data[32];
			algorithm::encoding::decode_uint256(owner_data, owner_raw_data);
			algorithm::encoding::decode_uint256(derivation_data, derivation_raw_data);
			hash = algorithm::encoding::to_subaddress(owner_raw_data, derivation_raw_data);
		}
		svm_address svm_address::to_address() const
		{
			auto result = svm_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data);
			return result;
		}
		svm_address svm_address::to_subaddress_from_hash(const uint256_t& derivation_data) const
		{
			uint8_t derivation_raw_data[32];
			algorithm::encoding::decode_uint256(derivation_data, derivation_raw_data);

			auto result = svm_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data, derivation_raw_data);
			return result;
		}
		svm_address svm_address::to_subaddress_from_data(const std::string_view& derivation_data) const
		{
			auto result = svm_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data, derivation_data);
			return result;
		}
		string svm_address::to_string() const
		{
			string address;
			algorithm::signing::encode_subaddress(hash.data, address);
			return address;
		}
		uint256_t svm_address::to_public_key_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.data, sizeof(algorithm::pubkeyhash));

			uint256_t numeric = 0;
			algorithm::encoding::encode_uint256(data, numeric);
			return numeric;
		}
		uint256_t svm_address::to_derivation_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.data + sizeof(algorithm::pubkeyhash), sizeof(algorithm::pubkeyhash));

			uint256_t numeric = 0;
			algorithm::encoding::encode_uint256(data, numeric);
			return numeric;
		}
		bool svm_address::empty() const
		{
			return hash.empty();
		}
		bool svm_address::equals(const svm_address& a, const svm_address& b)
		{
			return a.hash.equals(b.hash.data);
		}

		svm_abi::svm_abi(const std::string_view& data) : output(data)
		{
			input.data = output.data;
		}
		void svm_abi::seek(size_t offset)
		{
			input.seek = offset;
		}
		void svm_abi::clear()
		{
			input.clear();
			output.clear();
		}
		void svm_abi::merge(const std::string_view& value)
		{
			output.data.append(value);
			input.data = output.data;
		}
		void svm_abi::wstr(const std::string_view& value)
		{
			output.write_string(value);
			input.data = output.data;
		}
		void svm_abi::wrstr(const std::string_view& value)
		{
			output.write_string_raw(value);
			input.data = output.data;
		}
		void svm_abi::wdecimal(const decimal& value)
		{
			output.write_decimal(value);
			input.data = output.data;
		}
		void svm_abi::wboolean(bool value)
		{
			output.write_boolean(value);
			input.data = output.data;
		}
		void svm_abi::wuint160(const svm_address& value)
		{
			output.write_string(value.hash.optimized_view());
			input.data = output.data;
		}
		void svm_abi::wuint256(const uint256_t& value)
		{
			output.write_integer(value);
			input.data = output.data;
		}
		bool svm_abi::rstr(string& value)
		{
			return input.read_string(input.read_type(), &value);
		}
		bool svm_abi::rdecimal(decimal& value)
		{
			return read_decimal_or_integer(input, input.read_type(), &value);
		}
		bool svm_abi::rboolean(bool& value)
		{
			return input.read_boolean(input.read_type(), &value);
		}
		bool svm_abi::ruint160(svm_address& value)
		{
			string result;
			if (!rstr(result))
				return false;

			algorithm::subpubkeyhash_t blob;
			if (!algorithm::encoding::decode_uint_blob(result, blob.data, sizeof(blob.data)))
				return false;

			value = svm_address(blob);
			return true;
		}
		bool svm_abi::ruint256(uint256_t& value)
		{
			return input.read_integer(input.read_type(), &value);
		}
		string& svm_abi::data()
		{
			return output.data;
		}
		const string& svm_abi::data_const() const
		{
			return output.data;
		}

		svm_multiform_filter::svm_multiform_filter() : comparator(ledger::filter_comparator::equal), order(ledger::filter_order::ascending), value(0)
		{
		}
		svm_multiform_filter::svm_multiform_filter(ledger::filter_comparator new_condition, ledger::filter_order new_order, const uint256_t& new_value) : comparator(new_condition), order(new_order), value(new_value)
		{

		}

		bool svm_multiform_column_cursor::at1(size_t offset, void* object_value, int object_type_id)
		{
			return at3(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
		}
		bool svm_multiform_column_cursor::at2(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id)
		{
			return at3(offset, object_value, object_type_id, row_value, row_type_id, nullptr);
		}
		bool svm_multiform_column_cursor::at3(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			if (!program)
				return false;
			
			auto& cache = ((svm_program*)program)->cache.columns[column.data];
		retry:
			auto it = cache.find(offset);
			if (it == cache.end())
			{
				auto results = program->context->get_account_multiforms_by_column(program->to().hash.data, column.data, offset, count);
				if (!results)
					return false;

				size_t index = offset;
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

		bool svm_multiform_column_filter_cursor::at1(size_t offset, void* object_value, int object_type_id)
		{
			return at3(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
		}
		bool svm_multiform_column_filter_cursor::at2(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id)
		{
			return at3(offset, object_value, object_type_id, row_value, row_type_id, nullptr);
		}
		bool svm_multiform_column_filter_cursor::at3(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			if (!program)
				return false;

			auto& cache = ((svm_program*)program)->cache.columns[column.data];
		retry:
			auto it = cache.find(offset);
			if (it == cache.end())
			{
				auto results = program->context->get_account_multiforms_by_column_filter(program->to().hash.data, column.data, filter.comparator, filter.value, filter.order, offset, count);
				if (!results)
					return false;

				size_t index = offset;
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

		bool svm_multiform_row_cursor::at1(size_t offset, void* object_value, int object_type_id)
		{
			return at3(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
		}
		bool svm_multiform_row_cursor::at2(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id)
		{
			return at3(offset, object_value, object_type_id, column_value, column_type_id, nullptr);
		}
		bool svm_multiform_row_cursor::at3(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			if (!program)
				return false;

			auto& cache = ((svm_program*)program)->cache.rows[row.data];
		retry:
			auto it = cache.find(offset);
			if (it == cache.end())
			{
				auto results = program->context->get_account_multiforms_by_row(program->to().hash.data, row.data, offset, count);
				if (!results)
					return false;

				size_t index = offset;
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

		bool svm_multiform_row_filter_cursor::at1(size_t offset, void* object_value, int object_type_id)
		{
			return at3(offset, object_value, object_type_id, nullptr, (int)type_id::void_t, nullptr);
		}
		bool svm_multiform_row_filter_cursor::at2(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id)
		{
			return at3(offset, object_value, object_type_id, column_value, column_type_id, nullptr);
		}
		bool svm_multiform_row_filter_cursor::at3(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value)
		{
			auto* program = svm_program::fetch_immutable_or_throw();
			if (!program)
				return false;

			auto& cache = ((svm_program*)program)->cache.rows[row.data];
		retry:
			auto it = cache.find(offset);
			if (it == cache.end())
			{
				auto results = program->context->get_account_multiforms_by_row_filter(program->to().hash.data, row.data, filter.comparator, filter.value, filter.order, offset, count);
				if (!results)
					return false;

				size_t index = offset;
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

		svm_program::svm_program(ledger::transaction_context* new_context) : context(new_context)
		{
			VI_ASSERT(context != nullptr, "transaction context should be set");
		}
		expects_lr<void> svm_program::construct(compiler* compiler, const format::variables& args)
		{
			return execute(svm_call::system_call, compiler->get_module().get_function_by_name(SCRIPT_FUNCTION_CONSTRUCTOR), args, nullptr);
		}
		expects_lr<void> svm_program::mutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args)
		{
			if (function_decl.empty())
				return layer_exception("illegal call to function: function not found");

			auto module = compiler->get_module();
			auto candidate = module.get_function_by_name(function_decl);
			return execute(svm_call::mutable_call, candidate.is_valid() ? candidate : module.get_function_by_decl(function_decl), args, nullptr);
		}
		expects_lr<void> svm_program::immutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args)
		{
			if (function_decl.empty())
				return layer_exception("illegal call to function: function not found");

			auto module = compiler->get_module();
			auto candidate = module.get_function_by_name(function_decl);
			return execute(svm_call::immutable_call, candidate.is_valid() ? candidate : module.get_function_by_decl(function_decl), args, nullptr);
		}
		expects_lr<void> svm_program::execute(svm_call mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			if (!entrypoint.is_valid())
			{
				if (mutability == svm_call::system_call)
					return expectation::met;

				return layer_exception("illegal call to function: null function");
			}

			auto binders = load_arguments(&mutability, entrypoint, args);
			if (!binders)
				return binders.error();

			auto* vm = entrypoint.get_vm();
			auto* caller = immediate_context::get();
			auto* coroutine = caller ? caller : vm->request_context();
			auto* prev_mutable_program = coroutine->get_user_data(SCRIPT_TAG_MUTABLE_PROGRAM);
			auto* prev_immutable_program = coroutine->get_user_data(SCRIPT_TAG_IMMUTABLE_PROGRAM);
			coroutine->set_user_data(mutability == svm_call::system_call || mutability == svm_call::mutable_call ? (caller ? prev_mutable_program : this) : nullptr, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(this, SCRIPT_TAG_IMMUTABLE_PROGRAM);

			auto execution = expects_vm<vitex::scripting::execution>(vitex::scripting::execution::error);
			auto resolver = expects_lr<void>(layer_exception());
			auto resolve = [this, &resolver, &entrypoint, &return_callback](immediate_context* coroutine)
			{
				void* address = coroutine->get_return_address();
				int type_id = entrypoint.get_return_type_id();
				resolver = expectation::met;
				if (!address || type_id <= 0)
					return;

				if (!return_callback)
				{
					format::wo_stream stream;
					auto serialization = svm_marshalling::store(&stream, address, type_id);
					if (serialization)
					{
						auto reader = stream.ro();
						format::variables returns;
						if (format::variables_util::deserialize_flat_from(reader, &returns))
						{
							auto type = svm_host::get()->get_vm()->get_type_info_by_id(type_id);
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
					auto status = return_callback(address, type_id);
					if (!status)
						resolver = std::move(status);
				}
			};
			if (caller != coroutine)
			{
				vector<svm_frame> frames;
				coroutine->set_exception_callback(std::bind(&svm_program::load_exception, this, std::placeholders::_1));
				coroutine->set_line_callback(std::bind(&svm_program::load_coroutine, this, std::placeholders::_1, frames));
				execution = coroutine->execute_inline_call(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); });
				resolve(coroutine);
			}
			else
				execution = coroutine->execute_subcall(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); }, resolve);

			auto exception = bindings::exception::get_exception_at(coroutine);
			coroutine->set_user_data(prev_mutable_program, SCRIPT_TAG_MUTABLE_PROGRAM);
			coroutine->set_user_data(prev_immutable_program, SCRIPT_TAG_IMMUTABLE_PROGRAM);
			if (!execution || (execution && *execution != execution::finished) || !exception.empty())
			{
				if (caller != coroutine)
					vm->return_context(coroutine);
				if (exception.empty())
					return layer_exception(execution ? "execution error" : execution.error().message());

				string error_message = stringify::text("(%s) ", exception.get_type().c_str());
				error_message.append(exception.get_text());
				error_message.append(exception.origin);
				return layer_exception(std::move(error_message));
			}

			if (caller != coroutine)
				vm->return_context(coroutine);
			return resolver;
		}
		expects_lr<void> svm_program::subexecute(const svm_address& target, svm_call mutability, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const
		{
			if (function_decl.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", target.to_string().c_str()));

			auto link = context->get_account_program(target.hash.data);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));

			auto* host = ledger::svm_host::get();
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, link->hashcode))
			{
				auto program = context->get_witness_program(link->hashcode);
				if (!program)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), program.error().what()));
				}

				auto code = program->as_code();
				if (!code)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), code.error().what()));
				}

				auto compilation = host->compile(*compiler, link->hashcode, format::util::encode_0xhex(link->hashcode), *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), compilation.error().what()));
				}
			}

			format::variables args;
			if (input_value != nullptr && input_type_id > 0)
			{
				format::wo_stream stream;
				auto serialization = svm_marshalling::store(&stream, input_value, input_type_id);
				if (!serialization)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), serialization.error().what()));
				}

				auto reader = stream.ro();
				if (!format::variables_util::deserialize_flat_from(reader, &args))
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": argument serialization error", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));
				}
			}

			auto transaction = transactions::call();
			transaction.program_call(target.hash, algorithm::hashing::hash32d(link->hashcode), function_decl, std::move(args));
			transaction.asset = context->transaction->asset;
			transaction.gas_price = context->transaction->gas_price;
			transaction.gas_limit = context->get_gas_left();
			transaction.nonce = 0;

			ledger::receipt receipt;
			receipt.transaction_hash = transaction.as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.absolute_gas_use = context->block->gas_use;
			receipt.block_number = context->block->number;
			memcpy(receipt.from, to().hash.data, sizeof(receipt.from));

			auto next = transaction_context(context->environment, context->block, context->changelog, &transaction, std::move(receipt));
			auto* prev = context;
			auto* main = (svm_program*)this;
			main->context = &next;

			auto execution = main->execute(mutability, compiler->get_module().get_function_by_decl(function_decl), transaction.args, [&target, &function_decl, output_value, output_type_id](void* address, int type_id) -> expects_lr<void>
			{
				format::wo_stream stream;
				auto serialization = svm_marshalling::store(&stream, address, type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": return serialization error", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));

				auto reader = stream.ro();
				serialization = svm_marshalling::load(reader, output_value, output_type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), serialization.error().what()));

				return expectation::met;
			});

			prev->receipt.events.insert(prev->receipt.events.begin(), next.receipt.events.begin(), next.receipt.events.end());
			prev->receipt.relative_gas_use += next.receipt.relative_gas_use;
			main->context = prev;
			host->deallocate(std::move(compiler));
			return execution;
		}
		expects_lr<vector<std::function<void(immediate_context*)>>> svm_program::load_arguments(svm_call* mutability, const function& entrypoint, const format::variables& args) const
		{
			VI_ASSERT(mutability != nullptr, "mutability should be set");
			auto function_name = entrypoint.get_name();
			if (!entrypoint.get_namespace().empty())
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			if (function_name == SCRIPT_FUNCTION_CONSTRUCTOR && *mutability != svm_call::system_call)
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
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg_float(i, (float)args[index].as_float()); });
							break;
						case (int)type_id::double_t:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg_double(i, (double)args[index].as_double()); });
							break;
						default:
						{
							void* address = nullptr;
							auto& value = args[index];
							format::wo_stream stream;
							format::variables_util::serialize_flat_into({ value }, &stream);

							auto reader = stream.ro();
							auto status = svm_marshalling::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
							if (!status)
							{
								auto reader_message = format::util::decode_stream(value.as_string());
								reader = format::ro_stream(reader_message); address = nullptr;
								status = svm_marshalling::load(reader, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
								if (!status)
									return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program (%s)", entrypoint.get_decl().data(), i, status.error().what()));
							}

							auto object = uscript_object(vm, type.get_type_info(), address);
							frames.emplace_back([i, type_id, object = std::move(object)](immediate_context* coroutine) mutable { coroutine->set_arg_object(i, type_id & (int)vitex::scripting::type_id::handle_t ? (void*)&object.address : (void*)object.address); });
							break;
						}
					}
				}
				else
				{
					if (!type.is_valid() || type.get_namespace() != SCRIPT_NAMESPACE_INSTRSET)
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to any instruction set", entrypoint.get_decl().data(), (int)i));

					if (type.get_name() == SCRIPT_CLASS_RWPTR)
					{
						if (*mutability != svm_call::system_call && *mutability != svm_call::mutable_call)
							return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_CLASS_RWPTR ")", entrypoint.get_decl().data(), (int)i));
					}
					else if (type.get_name() != SCRIPT_CLASS_RPTR)
					{
						auto name = type.get_name();
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_CLASS_RWPTR " or " SCRIPT_CLASS_RPTR ") - \"%s\" type", entrypoint.get_decl().data(), (int)i, name.data()));
					}
					frames.emplace_back([i, index, &args, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (svm_program*)this); });
				}
			}
			return std::move(frames);
		}
		bool svm_program::dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
		{
			auto gas = gas_cost_of(opcode);
			auto status = context->burn_gas(gas);
			if (status)
				return true;

			coroutine = coroutine ? coroutine : immediate_context::get();
			if (coroutine != nullptr)
				coroutine->set_exception(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, status.error().message()).to_exception_string(), false);

			return false;
		}
		void svm_program::load_exception(immediate_context* coroutine)
		{
		}
		void svm_program::load_coroutine(immediate_context* coroutine, vector<svm_frame>& frames)
		{
			svm_frame current_frame; size_t current_depth = coroutine->get_callstack_size();
			if (!coroutine->get_call_state_registers(0, nullptr, &current_frame.call, &current_frame.pointer, nullptr, nullptr))
				return;

			size_t latest_depth = frames.size();
			if (latest_depth < current_depth)
			{
				auto latest_frame = current_frame;
				latest_frame.byte_code = current_frame.call.get_byte_code(&latest_frame.byte_code_size);
				latest_frame.pointer = 0;
				frames.push_back(std::move(latest_frame));
			}
			else if (latest_depth > current_depth)
				frames.pop_back();

			if (frames.empty() || !frames.back().byte_code)
				return;

			auto& last_frame = frames.back();
			auto* vm = coroutine->get_vm();
			bool step = last_frame.call.get_function() != current_frame.call.get_function();
			size_t start = step ? 0 : std::min<size_t>(last_frame.byte_code_size, current_frame.pointer > last_frame.pointer ? last_frame.pointer : current_frame.pointer);
			size_t count = step ? current_frame.pointer : (current_frame.pointer > last_frame.pointer ? current_frame.pointer - last_frame.pointer : last_frame.pointer - current_frame.pointer);
			size_t end = std::min<size_t>(last_frame.byte_code_size, start + count);
			while (start < end)
			{
				auto* pointer = (uint8_t*)(last_frame.byte_code + start);
				auto opcode = virtual_machine::get_byte_code_info(*pointer);
				start += opcode.size;
				if (!dispatch_instruction(vm, coroutine, last_frame.byte_code, start, opcode))
					return;
			}
			last_frame.pointer = current_frame.pointer;
		}
		void svm_program::internal_call(const svm_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id)
		{
			auto execution = subexecute(target, svm_call::mutable_call, function_decl, input_value, input_type_id, output_value, output_type_id);
			if (!execution)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
		}
		void svm_program::internal_call(const svm_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const
		{
			auto execution = subexecute(target, svm_call::immutable_call, function_decl, input_value, input_type_id, output_value, output_type_id);
			if (!execution)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
		}
		void svm_program::store_uniform(const void* index_value, int index_type_id, const void* object_value, int object_type_id)
		{
			format::wo_stream index;
			auto status = svm_marshalling::store(&index, index_value, index_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::wo_stream stream;
			status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			if (!object_value || object_type_id == (int)type_id::void_t)
			{
				auto requires_erase = context->get_account_uniform(to().hash.data, index.data);
				if (!requires_erase)
					return;
			}

			auto data = context->apply_account_uniform(to().hash.data, index.data, stream.data);
			if (!data)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
		}
		bool svm_program::load_uniform(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error) const
		{
			format::wo_stream index;
			auto status = svm_marshalling::store(&index, index_value, index_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_uniform(to().hash.data, index.data);
			if (!data || data->data.empty())
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "program variable missing"));
				return false;
			}

			format::ro_stream stream = format::ro_stream(data->data);
			status = svm_marshalling::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "program variable corrupted"));
				return false;
			}

			return true;
		}
		bool svm_program::has_uniform(const void* index_value, int index_type_id) const
		{
			format::wo_stream index;
			auto status = svm_marshalling::store(&index, index_value, index_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_uniform(to().hash.data, index.data);
			return data && !data->data.empty();
		}
		void svm_program::store_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value)
		{
			format::wo_stream column;
			auto status = svm_marshalling::store(&column, column_value, column_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::wo_stream row;
			status = svm_marshalling::store(&column, row_value, row_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::wo_stream stream;
			status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			if (!object_value || object_type_id == (int)type_id::void_t)
			{
				auto requires_erase = context->get_account_multiform(to().hash.data, column.data, row.data);
				if (!requires_erase)
					return;
			}

			auto data = context->apply_account_multiform(to().hash.data, column.data, row.data, stream.data, filter_value);
			if (!data)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));

			auto it = cache.columns.find(column.data);
			if (it != cache.columns.end())
				it->second.clear();

			it = cache.rows.find(row.data);
			if (it != cache.rows.end())
				it->second.clear();
		}
		bool svm_program::load_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error) const
		{
			format::wo_stream column;
			auto status = svm_marshalling::store(&column, column_value, column_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			format::wo_stream row;
			status = svm_marshalling::store(&column, row_value, row_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_multiform(to().hash.data, column.data, row.data);
			if (!data || data->data.empty())
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "program variable missing"));
				return false;
			}

			format::ro_stream stream = format::ro_stream(data->data);
			status = svm_marshalling::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "program variable corrupted"));
				return false;
			}

			if (filter_value != nullptr)
				*filter_value = data->filter;

			return true;
		}
		bool svm_program::has_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id) const
		{
			format::wo_stream column;
			auto status = svm_marshalling::store(&column, column_value, column_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			format::wo_stream row;
			status = svm_marshalling::store(&column, row_value, row_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_multiform(to().hash.data, column.data, row.data);
			return data && !data->data.empty();
		}
		bool svm_program::emit_event(const void* object_value, int object_type_id)
		{
			format::wo_stream stream;
			auto status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto reader = stream.ro();
			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit value conversion error"));
				return false;
			}

			auto type = svm_host::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto data = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns), true);
			if (!data)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
				return false;
			}

			return true;
		}
		void svm_program::pay(const svm_address& target, const uint256_t& asset, const decimal& value)
		{
			if (!value.is_positive())
				return;

			auto payment = context->apply_payment(asset, to().hash.data, target.hash.data, value);
			if (!payment)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, payment.error().message()));
		}
		svm_multiform_column_cursor svm_program::multiform_column_cursor(const void* column_value, int column_type_id, size_t count) const
		{
			svm_multiform_column_cursor result;
			result.count = count;

			auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
			if (!status)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			return result;
		}
		svm_multiform_column_filter_cursor svm_program::multiform_column_filter_cursor(const void* column_value, int column_type_id, const svm_multiform_filter& filter, size_t count) const
		{
			svm_multiform_column_filter_cursor result;
			result.filter = filter;
			result.count = count;

			auto status = svm_marshalling::store(&result.column, column_value, column_type_id);
			if (!status)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			return result;
		}
		svm_multiform_row_cursor svm_program::multiform_row_cursor(const void* row_value, int row_type_id, size_t count) const
		{
			svm_multiform_row_cursor result;
			result.count = count;

			auto status = svm_marshalling::store(&result.row, row_value, row_type_id);
			if (!status)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			return result;
		}
		svm_multiform_row_filter_cursor svm_program::multiform_row_filter_cursor(const void* row_value, int row_type_id, const svm_multiform_filter& filter, size_t count) const
		{
			svm_multiform_row_filter_cursor result;
			result.filter = filter;
			result.count = count;

			auto status = svm_marshalling::store(&result.row, row_value, row_type_id);
			if (!status)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			return result;
		}
		uint256_t svm_program::random()
		{
			if (!cache.distribution)
			{
				auto candidate = context->calculate_random(context->get_gas_use());
				if (!candidate)
				{
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, candidate.error().message()));
					return 0;
				}
				cache.distribution = std::move(*candidate);
			}
			return cache.distribution->derive();
		}
		svm_address svm_program::from() const
		{
			return svm_address(algorithm::pubkeyhash_t(context->receipt.from));
		}
		svm_address svm_program::to() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return svm_address(algorithm::subpubkeyhash_t(((transactions::call*)context->transaction)->callable));

			return svm_address(algorithm::pubkeyhash_t(context->receipt.from));
		}
		decimal svm_program::value() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->value;
			return decimal::zero();
		}
		string svm_program::blockchain() const
		{
			return algorithm::asset::blockchain_of(context->transaction->asset);
		}
		string svm_program::token() const
		{
			return algorithm::asset::token_of(context->transaction->asset);
		}
		string svm_program::contract() const
		{
			return algorithm::asset::checksum_of(context->transaction->asset);
		}
		string svm_program::declaration() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->function;
			return string();
		}
		decimal svm_program::gas_price() const
		{
			return context->transaction->gas_price;
		}
		uint256_t svm_program::gas_left() const
		{
			return context->get_gas_left();
		}
		uint256_t svm_program::gas_use() const
		{
			return context->receipt.relative_gas_use;
		}
		uint256_t svm_program::gas_limit() const
		{
			return context->transaction->gas_limit;
		}
		uint256_t svm_program::asset() const
		{
			return context->transaction->asset;
		}
		svm_address svm_program::block_proposer() const
		{
			size_t index = (size_t)context->block->priority;
			return index < context->environment->producers.size() ? svm_address(algorithm::pubkeyhash_t(context->environment->producers[index].owner)) : svm_address();
		}
		uint256_t svm_program::parent_block_hash() const
		{
			return context->block->parent_hash;
		}
		uint256_t svm_program::block_gas_use() const
		{
			return context->block->gas_use;
		}
		uint256_t svm_program::block_gas_left() const
		{
			return context->block->gas_limit - context->block->gas_use;
		}
		uint256_t svm_program::block_gas_limit() const
		{
			return context->block->gas_limit;
		}
		uint128_t svm_program::block_difficulty() const
		{
			return context->block->target.difficulty();
		}
		uint64_t svm_program::block_time() const
		{
			uint64_t milliseconds = context->block->time - context->block->time % protocol::now().policy.consensus_proof_time;
			return milliseconds / 1000;
		}
		uint64_t svm_program::block_priority() const
		{
			return context->block->priority;
		}
		uint64_t svm_program::block_number() const
		{
			return context->block->number;
		}
		const format::variables* svm_program::arguments() const
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
		svm_program* svm_program::fetch_mutable(immediate_context* coroutine)
		{
			return coroutine ? (svm_program*)coroutine->get_user_data(SCRIPT_TAG_MUTABLE_PROGRAM) : nullptr;
		}
		const svm_program* svm_program::fetch_immutable(immediate_context* coroutine)
		{
			return coroutine ? (const svm_program*)coroutine->get_user_data(SCRIPT_TAG_IMMUTABLE_PROGRAM) : nullptr;
		}
		svm_program* svm_program::fetch_mutable_or_throw(immediate_context* coroutine)
		{
			auto* result = fetch_mutable(coroutine);
			if (!result)
				bindings::exception::throw_ptr_at(coroutine, bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "contract is required to be mutable"));

			return result;
		}
		const svm_program* svm_program::fetch_immutable_or_throw(immediate_context* coroutine)
		{
			auto* result = fetch_immutable(coroutine);
			if (!result)
				bindings::exception::throw_ptr_at(coroutine, bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, "contract is required to be immutable"));

			return result;
		}

		svm_program_trace::svm_program_trace(evaluation_context* new_environment) : svm_program(new_environment ? &new_environment->validation.context : nullptr), environment(new_environment)
		{
			VI_ASSERT(new_environment != nullptr, "env should be set");
		}
		expects_lr<void> svm_program_trace::assign_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::subpubkeyhash_t& to, const decimal& value, const std::string_view& function_decl, const format::variables& args)
		{
			VI_ASSERT(from != nullptr, "from should be set");
			transactions::call transaction;
			transaction.asset = asset;
			transaction.signature[0] = 0xFF;
			transaction.nonce = std::max<size_t>(1, environment->validation.context.get_account_nonce(from).or_else(states::account_nonce(nullptr, nullptr)).nonce);
			transaction.program_call(to, value, function_decl, format::variables(args));
			transaction.set_gas(decimal::zero(), ledger::block::get_gas_limit());
			return assign_transaction(from, memory::init<transactions::call>(std::move(transaction)));
		}
		expects_lr<void> svm_program_trace::assign_transaction(const algorithm::pubkeyhash from, uptr<ledger::transaction>&& transaction)
		{
			VI_ASSERT(from != nullptr && transaction, "from and transaction should be set");
			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			if (tip)
				environment->tip = std::move(*tip);

			ledger::receipt receipt;
			block.set_parent_block(environment->tip.address());
			receipt.transaction_hash = transaction->as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.block_number = block.number + 1;
			memcpy(receipt.from, from, sizeof(algorithm::pubkeyhash));

			contextual = std::move(transaction);
			memset(environment->validator.public_key_hash, 0xFF, sizeof(algorithm::pubkeyhash));
			memset(environment->validator.secret_key, 0xFF, sizeof(algorithm::seckey));
			environment->validation.context = transaction_context(environment, &block, &environment->validation.changelog, *contextual, std::move(receipt));
			return expectation::met;
		}
		expects_lr<uptr<compiler>> svm_program_trace::compile_transaction()
		{
			VI_ASSERT(contextual, "transaction should be assigned");
			auto index = environment->validation.context.get_account_program(to().hash.data);
			if (!index)
				return layer_exception("program not assigned to address");

			auto* host = ledger::svm_host::get();
			auto& hashcode = index->hashcode;
			auto result = host->allocate();
			if (host->precompile(*result, hashcode))
				return expects_lr<uptr<compiler>>(std::move(result));

			auto program = environment->validation.context.get_witness_program(hashcode);
			if (!program)
			{
				host->deallocate(std::move(result));
				return layer_exception("program not stored to address");
			}

			auto code = program->as_code();
			if (!code)
			{
				host->deallocate(std::move(result));
				return code.error();
			}

			auto compilation = host->compile(*result, hashcode, format::util::encode_0xhex(hashcode), *code);
			if (!compilation)
			{
				host->deallocate(std::move(result));
				return compilation.error();
			}

			return expects_lr<uptr<compiler>>(std::move(result));
		}
		expects_lr<void> svm_program_trace::compile_and_call(svm_call mutability, const std::string_view& function_decl, const format::variables& args)
		{
			auto compiler = compile_transaction();
			if (!compiler)
				return compiler.error();

			auto execution = call_compiled(**compiler, mutability, function_decl, args);
			svm_host::get()->deallocate(std::move(*compiler));
			return execution;
		}
		expects_lr<void> svm_program_trace::call_compiled(compiler* module, svm_call mutability, const std::string_view& function_decl, const format::variables& args)
		{
			VI_ASSERT(contextual, "transaction should be assigned");
			auto function = module->get_module().get_function_by_decl(function_decl);
			if (!function.is_valid())
				function = module->get_module().get_function_by_name(function_decl);
			if (!function.is_valid())
				return layer_exception("illegal call to function: null function");

			auto execution = execute(mutability, function, args, [this](void* address, int type_id) -> expects_lr<void>
			{
				returning = var::set::object();
				auto serialization = svm_marshalling::store(*returning, address, type_id);
				if (!serialization)
				{
					returning.destroy();
					return layer_exception("return value error: " + serialization.error().message());
				}

				return expectation::met;
			});
			context->receipt.successful = !!execution;
			context->receipt.finalization_time = protocol::now().time.now();
			if (!context->receipt.successful)
				context->emit_event(0, { format::variable(execution.what()) }, false);
			return execution;
		}
		void svm_program_trace::load_exception(immediate_context* coroutine)
		{
			auto* vm = coroutine->get_vm();
			if (vm->has_debugger())
				vm->get_debugger()->exception_callback(coroutine->get_context());
		}
		void svm_program_trace::load_coroutine(immediate_context* coroutine, vector<svm_frame>& frames)
		{
			auto* vm = coroutine->get_vm();
			if (vm->has_debugger())
				vm->get_debugger()->line_callback(coroutine->get_context());
			return svm_program::load_coroutine(coroutine, frames);
		}
		bool svm_program_trace::emit_event(const void* object_value, int object_type_id)
		{
			if (!svm_program::emit_event(object_value, object_type_id))
				return false;

			if (!events)
				events = var::set::array();

			auto type = svm_host::get()->get_vm()->get_type_info_by_id(object_type_id).get_name();
			auto* event = events->push(var::set::object());
			event->set("type", var::integer(context->receipt.events.back().first));
			event->set("name", type.empty() ? var::null() : var::string(type));

			auto serialization = svm_marshalling::store(event->set("data", var::set::object()), object_value, object_type_id);
			if (!serialization)
				event->set("data", format::variables_util::serialize(context->receipt.events.back().second));

			return true;
		}
		bool svm_program_trace::dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
		{
			string_stream stream;
			debugger_context::byte_code_label_to_text(stream, vm, program_data, program_counter, false, true);

			string instruction = stream.str();
			stringify::trim(instruction);
#if VI_64
			instruction.erase(2, 8);
#endif
			auto gas = gas_cost_of(opcode);
			instruction.append(instruction.find('%') != std::string::npos ? ", %gas:" : " %gas:");
			instruction.append(to_string(gas));
			instructions.push_back(std::move(instruction));
			return svm_program::dispatch_instruction(vm, coroutine, program_data, program_counter, opcode);
		}
		uptr<schema> svm_program_trace::as_schema() const
		{
			schema* data = var::set::object();
			data->set("block_hash", var::string(algorithm::encoding::encode_0xhex256(block.number > 0 ? block.as_hash() : uint256_t(0))));
			data->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(context->receipt.transaction_hash)));
			data->set("from", algorithm::signing::serialize_subaddress(((svm_program_trace*)this)->from().hash.data));
			data->set("to", algorithm::signing::serialize_subaddress(((svm_program_trace*)this)->to().hash.data));
			data->set("gas", algorithm::encoding::serialize_uint256(context->receipt.relative_gas_use));
			data->set("time", algorithm::encoding::serialize_uint256(context->receipt.finalization_time - context->receipt.generation_time));
			data->set("successful", var::boolean(context->receipt.successful));
			data->set("returns", returning ? returning->copy() : var::set::null());
			data->set("events", events ? events->copy() : var::set::null());
			if (!context->changelog->outgoing.pending.empty())
			{
				auto* states_data = data->set("changelog", var::set::array());
				for (auto& [index, change] : context->changelog->outgoing.pending)
					states_data->push(change.as_schema().reset());
			}
			if (!instructions.empty())
			{
				auto* instructions_data = data->set("instructions", var::set::array());
				for (auto& item : instructions)
					instructions_data->push(var::string(item));
			}
			return data;
		}
	}
}
