#include "svm.h"
#include "svm_abi.h"
#include "../policy/transactions.h"
#include "../validator/storage/chainstate.h"
#define SCRIPT_TAG_MUTABLE_PROGRAM 19190
#define SCRIPT_TAG_IMMUTABLE_PROGRAM 19191
#define SCRIPT_TYPENAME_ADDRESS "address"
#define SCRIPT_TYPENAME_STRING "string"
#define SCRIPT_TYPENAME_UINT128 "uint128"
#define SCRIPT_TYPENAME_UINT256 "uint256"
#define SCRIPT_TYPENAME_DECIMAL "float768"
#define SCRIPT_TYPENAME_ARRAY "array"
#define SCRIPT_TYPENAME_RWPTR "rwptr"
#define SCRIPT_TYPENAME_RPTR "rptr"
#define SCRIPT_NAMESPACE_INSTRSET "instrset"
#define SCRIPT_FUNCTION_CONSTRUCT "construct"

namespace tangent
{
	namespace ledger
	{
		typedef unordered_map<svm_abi::string_repr, std::atomic<int32_t>> string_repr_cache_type;

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
					auto type = svm_container::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_TYPENAME_ADDRESS)
					{
						stream->write_string(((svm_abi::address*)value)->hash.optimized_view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_STRING)
					{
						stream->write_string(((svm_abi::string_repr*)value)->view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT128)
					{
						stream->write_integer(*(uint128_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT256)
					{
						stream->write_integer(*(uint256_t*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_DECIMAL)
					{
						stream->write_decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_ARRAY)
					{
						auto* array = (svm_abi::array_repr*)value;
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
					auto type = svm_container::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_TYPENAME_ADDRESS)
					{
						uptr<schema> data = algorithm::signing::serialize_address(((svm_abi::address*)value)->hash);
						stream->value = std::move(data->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_STRING)
					{
						stream->value = var::string(((svm_abi::string_repr*)value)->view());
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT128)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint128_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT256)
					{
						auto serializable = uptr<schema>(algorithm::encoding::serialize_uint256(*(uint256_t*)value));
						stream->value = std::move(serializable->value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_DECIMAL)
					{
						stream->value = var::decimal(*(decimal*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_ARRAY)
					{
						auto* array = (svm_abi::array_repr*)value;
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
					if (!stream.read_decimal_or_integer(stream.read_type(), &wrapper))
						return layer_exception("load failed for float type");

					*(float*)value = wrapper.to_float();
					return expectation::met;
				}
				case (int)type_id::double_t:
				{
					decimal wrapper;
					if (!stream.read_decimal_or_integer(stream.read_type(), &wrapper))
						return layer_exception("load failed for double type");

					*(double*)value = wrapper.to_double();
					return expectation::met;
				}
				default:
				{
					bool managing = false;
					auto* vm = svm_container::get()->get_vm();
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

					auto unique = svm_abi::uobject(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_TYPENAME_ADDRESS)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for address type");

						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::pubkeyhash_t))
						{
							if (!algorithm::signing::decode_address(data, ((svm_abi::address*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							((svm_abi::address*)value)->hash = algorithm::pubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_STRING)
					{
						string data;
						if (!stream.read_string(stream.read_type(), &data))
							return layer_exception("load failed for string type");

						((svm_abi::string_repr*)value)->assign_view(data);
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT128)
					{
						if (!stream.read_integer(stream.read_type(), (uint128_t*)value))
							return layer_exception("load failed for uint128 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT256)
					{
						if (!stream.read_integer(stream.read_type(), (uint256_t*)value))
							return layer_exception("load failed for uint256 type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_DECIMAL)
					{
						if (!stream.read_decimal_or_integer(stream.read_type(), (decimal*)value))
							return layer_exception("load failed for decimal type");

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_ARRAY)
					{
						uint32_t size;
						if (!stream.read_integer(stream.read_type(), &size))
							return layer_exception("load failed for uint32 type");

						auto* array = (svm_abi::array_repr*)value;
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
					auto* vm = svm_container::get()->get_vm();
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

					auto unique = svm_abi::uobject(vm, type.get_type_info(), managing ? value : nullptr);
					if (name == SCRIPT_TYPENAME_ADDRESS)
					{
						string data = stream->value.get_blob();
						data = format::util::is_hex_encoding(data) ? format::util::decode_0xhex(data) : data;
						if (data.size() > sizeof(algorithm::pubkeyhash_t))
						{
							if (!algorithm::signing::decode_address(data, ((svm_abi::address*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							((svm_abi::address*)value)->hash = algorithm::pubkeyhash_t(data);

						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_STRING)
					{
						((svm_abi::string_repr*)value)->assign_view(stream->value.get_blob());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT128)
					{
						*(uint128_t*)value = uint128_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_UINT256)
					{
						*(uint256_t*)value = uint256_t(stream->value.get_decimal().to_string());
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_DECIMAL)
					{
						*(decimal*)value = stream->value.get_decimal();
						unique.address = nullptr;
						return expectation::met;
					}
					else if (name == SCRIPT_TYPENAME_ARRAY)
					{
						uint32_t size = (uint32_t)stream->size();
						auto* array = (svm_abi::array_repr*)value;
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

		svm_container::svm_container() noexcept
		{
			illegal_instructions =
			{
				"NEGf",
				"NEGd",
				"INCf",
				"DECf",
				"INCd",
				"DECd",
				"CMPd",
				"CMPf",
				"CMPIf",
				"iTOf",
				"fTOi",
				"uTOf",
				"fTOu",
				"dTOi",
				"dTOu",
				"dTOf",
				"iTOd",
				"uTOd",
				"fTOd",
				"ADDf",
				"SUBf",
				"MULf",
				"DIVf",
				"MODf",
				"ADDd",
				"SUBd",
				"MULd",
				"DIVd",
				"MODd",
				"ADDIf",
				"SUBIf",
				"MULIf",
				"fTOi64",
				"dTOi64",
				"fTOu64",
				"dTOu64",
				"i64TOf",
				"u64TOf",
				"i64TOd",
				"u64TOd",
				"POWf",
				"POWd",
				"POWdi"
			};

			preprocessor::desc compiler_features;
			compiler_features.conditions = false;
			compiler_features.defines = false;
			compiler_features.includes = false;
			compiler_features.pragmas = false;
			strings = memory::init<string_repr_cache_type>();

			vm = new virtual_machine();
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
			vm->set_property(features::property_accessor_mode, 0);
			vm->set_property(features::expand_def_array_to_impl, 1);
			vm->set_property(features::auto_garbage_collect, 1);
			vm->set_property(features::disallow_global_vars, 1);
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
			vm->set_type_info_user_data_cleanup_callback(svm_abi::array_repr::cleanup_type_info_cache, svm_abi::array_repr::get_id());
			vm->set_full_stack_tracing(false);
			vm->set_cache(false);
			vm->set_ts_imports(false);
			vm->set_keyword_restriction("auto", true);
			vm->set_keyword_restriction("auto@", true);
			vm->set_keyword_restriction("float", true);
			vm->set_keyword_restriction("double", true);
			vm->set_type_def("usize", "uint32");

			auto array_repr = vm->set_template_class<svm_abi::array_repr>("array<class t>", "array<t>", true);
			auto string_repr = vm->set_struct_address("string", sizeof(svm_abi::string_repr), (size_t)object_behaviours::value | bridge::type_traits_of<svm_abi::string_repr>());
			auto decimal_repr = vm->set_struct_trivial<decimal>("float768");
			auto uint128_repr = vm->set_struct_trivial<uint128_t>("uint128", (size_t)object_behaviours::app_class_allints);
			auto uint256_repr = vm->set_struct_trivial<uint256_t>("uint256", (size_t)object_behaviours::app_class_allints);
			array_repr->set_template_callback(&svm_abi::array_repr::template_callback);
			array_repr->set_function_def("bool array<t>::less_sync(const t&in a, const t&in b)");
			array_repr->set_constructor_extern<svm_abi::array_repr, asITypeInfo*>("array<t>@ f(int&in)", &svm_abi::array_repr::create);
			array_repr->set_constructor_extern<svm_abi::array_repr, asITypeInfo*, uint32_t>("array<t>@ f(int&in, usize) explicit", &svm_abi::array_repr::create);
			array_repr->set_constructor_extern<svm_abi::array_repr, asITypeInfo*, uint32_t, void*>("array<t>@ f(int&in, usize, const t&in)", &svm_abi::array_repr::create);
			array_repr->set_enum_refs(&svm_abi::array_repr::enum_references);
			array_repr->set_release_refs(&svm_abi::array_repr::release_references);
			array_repr->set_method("bool opEquals(const array<t>&in) const", &svm_abi::array_repr::operator==);
			array_repr->set_method("array<t>& opAssign(const array<t>&in)", &svm_abi::array_repr::operator=);
			array_repr->set_method<svm_abi::array_repr, void*, uint32_t>("t& opIndex(usize)", &svm_abi::array_repr::at);
			array_repr->set_method<svm_abi::array_repr, const void*, uint32_t>("const t& opIndex(usize) const", &svm_abi::array_repr::at);
			array_repr->set_method<svm_abi::array_repr, void*>("t& front()", &svm_abi::array_repr::front);
			array_repr->set_method<svm_abi::array_repr, const void*>("const t& front() const", &svm_abi::array_repr::front);
			array_repr->set_method<svm_abi::array_repr, void*>("t& back()", &svm_abi::array_repr::back);
			array_repr->set_method<svm_abi::array_repr, const void*>("const t& back() const", &svm_abi::array_repr::back);
			array_repr->set_method("bool empty() const", &svm_abi::array_repr::empty);
			array_repr->set_method("usize size() const", &svm_abi::array_repr::size);
			array_repr->set_method("usize capacity() const", &svm_abi::array_repr::capacity);
			array_repr->set_method("void reserve(usize)", &svm_abi::array_repr::reserve);
			array_repr->set_method<svm_abi::array_repr, void, uint32_t>("void resize(usize)", &svm_abi::array_repr::resize);
			array_repr->set_method("void clear()", &svm_abi::array_repr::clear);
			array_repr->set_method("void push(const t&in)", &svm_abi::array_repr::insert_last);
			array_repr->set_method("void pop()", &svm_abi::array_repr::remove_last);
			array_repr->set_method<svm_abi::array_repr, void, uint32_t, void*>("void insert(usize, const t&in)", &svm_abi::array_repr::insert_at);
			array_repr->set_method<svm_abi::array_repr, void, uint32_t, const svm_abi::array_repr&>("void insert(usize, const array<t>&)", &svm_abi::array_repr::insert_at);
			array_repr->set_method("void erase_if(const t&in if_handle_then_const, usize = 0)", &svm_abi::array_repr::remove_if);
			array_repr->set_method("void erase(usize)", &svm_abi::array_repr::remove_at);
			array_repr->set_method("void erase(usize, usize)", &svm_abi::array_repr::remove_range);
			array_repr->set_method("void reverse()", &svm_abi::array_repr::reverse);
			array_repr->set_method("void swap(usize, usize)", &svm_abi::array_repr::swap);
			array_repr->set_method("void sort(less_sync@ = null)", &svm_abi::array_repr::sort);
			array_repr->set_method<svm_abi::array_repr, uint32_t, void*, uint32_t>("usize find(const t&in if_handle_then_const, usize = 0) const", &svm_abi::array_repr::find);
			array_repr->set_method<svm_abi::array_repr, uint32_t, void*, uint32_t>("usize find_ref(const t&in if_handle_then_const, usize = 0) const", &svm_abi::array_repr::find_by_ref);	
			string_repr->set_constructor_extern("void f()", &svm_abi::string_repr::create);
			string_repr->set_constructor_extern("void f(const string&in)", &svm_abi::string_repr::create_copy);
			string_repr->set_destructor_extern("void f()", &svm_abi::string_repr::destroy);
			string_repr->set_method("string& opAssign(const string&in)", &svm_abi::string_repr::assign);
			string_repr->set_method("string& opAddAssign(const string&in)", &svm_abi::string_repr::assign_append);
			string_repr->set_method("string& opAddAssign(uint8)", &svm_abi::string_repr::assign_append_char);
			string_repr->set_method("string opAdd(const string&in) const", &svm_abi::string_repr::append);
			string_repr->set_method("string opAdd(uint8) const", &svm_abi::string_repr::append_char);
			string_repr->set_method("string opAdd_r(uint8) const", &svm_abi::string_repr::append_char);
			string_repr->set_method("int opCmp(const string&in) const", &svm_abi::string_repr::compare);
			string_repr->set_method("uint8& opIndex(usize)", &svm_abi::string_repr::at);
			string_repr->set_method("const uint8& opIndex(usize) const", &svm_abi::string_repr::at);
			string_repr->set_method("uint8& at(usize)", &svm_abi::string_repr::at);
			string_repr->set_method("const uint8& at(usize) const", &svm_abi::string_repr::at);
			string_repr->set_method("uint8& front()", &svm_abi::string_repr::front);
			string_repr->set_method("const uint8& front() const", &svm_abi::string_repr::front);
			string_repr->set_method("uint8& back()", &svm_abi::string_repr::back);
			string_repr->set_method("const uint8& back() const", &svm_abi::string_repr::back);
			string_repr->set_method("bool empty() const", &svm_abi::string_repr::empty);
			string_repr->set_method("usize size() const", &svm_abi::string_repr::size);
			string_repr->set_method("void clear()", &svm_abi::string_repr::clear);
			string_repr->set_method("string& append(const string&in)", &svm_abi::string_repr::assign_append);
			string_repr->set_method("string& append(uint8)", &svm_abi::string_repr::assign_append_char);
			string_repr->set_method("void push(uint8)", &svm_abi::string_repr::push_back);
			string_repr->set_method("void pop()", &svm_abi::string_repr::pop_back);
			string_repr->set_method("bool starts_with(const string&in, usize = 0) const", &svm_abi::string_repr::starts_with);
			string_repr->set_method("bool ends_with(const string&in) const", &svm_abi::string_repr::ends_with);
			string_repr->set_method("string substring(usize) const", &svm_abi::string_repr::substring);
			string_repr->set_method("string substring(usize, usize) const", &svm_abi::string_repr::substring_sized);
			string_repr->set_method("string& trim()", &svm_abi::string_repr::trim);
			string_repr->set_method("string& trim_front()", &svm_abi::string_repr::trim_start);
			string_repr->set_method("string& trim_back()", &svm_abi::string_repr::trim_end);
			string_repr->set_method("string& lower()", &svm_abi::string_repr::to_lower);
			string_repr->set_method("string& upper()", &svm_abi::string_repr::to_upper);
			string_repr->set_method("string& reverse()", &svm_abi::string_repr::reverse);
			string_repr->set_method("usize rfind(const string&in) const", &svm_abi::string_repr::rfind);
			string_repr->set_method("usize rfind(uint8) const", &svm_abi::string_repr::rfind_char);
			string_repr->set_method("usize rfind(const string&in, usize) const", &svm_abi::string_repr::rfind_offset);
			string_repr->set_method("usize rfind(uint8, usize) const", &svm_abi::string_repr::rfind_char_offset);
			string_repr->set_method("usize find(const string&in, usize = 0) const", &svm_abi::string_repr::find);
			string_repr->set_method("usize find(uint8, usize = 0) const", &svm_abi::string_repr::find_char);
			string_repr->set_method("usize find_first_of(const string&in, usize = 0) const", &svm_abi::string_repr::find_first_of);
			string_repr->set_method("usize find_first_not_of(const string&in, usize = 0) const", &svm_abi::string_repr::find_first_not_of);
			string_repr->set_method("usize find_last_of(const string&in) const", &svm_abi::string_repr::find_last_of);
			string_repr->set_method("usize find_last_not_of(const string&in) const", &svm_abi::string_repr::find_last_not_of);
			string_repr->set_method("usize find_last_of(const string&in, usize) const", &svm_abi::string_repr::find_last_of_offset);
			string_repr->set_method("usize find_last_not_of(const string&in, usize) const", &svm_abi::string_repr::find_last_not_of_offset);
			string_repr->set_method("array<string>@ split(const string&in) const", &svm_abi::string_repr::split);
			string_repr->set_method("int8 i8(int = 10)", &svm_abi::string_repr::from_string<int8_t>);
			string_repr->set_method("int16 i16(int = 10)", &svm_abi::string_repr::from_string<int16_t>);
			string_repr->set_method("int32 i32(int = 10)", &svm_abi::string_repr::from_string<int32_t>);
			string_repr->set_method("int64 i64(int = 10)", &svm_abi::string_repr::from_string<int64_t>);
			string_repr->set_method("uint8 u8(int = 10)", &svm_abi::string_repr::from_string<uint8_t>);
			string_repr->set_method("uint16 u16(int = 10)", &svm_abi::string_repr::from_string<uint16_t>);
			string_repr->set_method("uint32 u32(int = 10)", &svm_abi::string_repr::from_string<uint32_t>);
			string_repr->set_method("uint64 u64(int = 10)", &svm_abi::string_repr::from_string<uint64_t>);
			string_repr->set_method("uint128 u128(int = 10)", &svm_abi::string_repr::from_string_uint128);
			string_repr->set_method("uint256 u256(int = 10)", &svm_abi::string_repr::from_string_uint256);
			string_repr->set_method("float768 f768(int = 10)", &svm_abi::string_repr::from_string_decimal);
			decimal_repr->set_constructor_extern<decimal*>("void f()", &svm_abi::decimal_repr::custom_constructor);
			decimal_repr->set_constructor_extern<decimal*, int8_t>("void f(int8)", &svm_abi::decimal_repr::custom_constructor_arithmetic<int8_t>);
			decimal_repr->set_constructor_extern<decimal*, uint8_t>("void f(uint8)", &svm_abi::decimal_repr::custom_constructor_arithmetic<uint8_t>);
			decimal_repr->set_constructor_extern<decimal*, int16_t>("void f(int16)", &svm_abi::decimal_repr::custom_constructor_arithmetic<int16_t>);
			decimal_repr->set_constructor_extern<decimal*, uint16_t>("void f(uint16)", &svm_abi::decimal_repr::custom_constructor_arithmetic<uint16_t>);
			decimal_repr->set_constructor_extern<decimal*, int32_t>("void f(int32)", &svm_abi::decimal_repr::custom_constructor_arithmetic<int32_t>);
			decimal_repr->set_constructor_extern<decimal*, uint32_t>("void f(uint32)", &svm_abi::decimal_repr::custom_constructor_arithmetic<uint32_t>);
			decimal_repr->set_constructor_extern<decimal*, int64_t>("void f(int64)", &svm_abi::decimal_repr::custom_constructor_arithmetic<int64_t>);
			decimal_repr->set_constructor_extern<decimal*, uint64_t>("void f(uint64)", &svm_abi::decimal_repr::custom_constructor_arithmetic<uint64_t>);
			decimal_repr->set_constructor_extern<decimal*, const svm_abi::string_repr&>("void f(const string&in)", &svm_abi::decimal_repr::custom_constructor_string);
			decimal_repr->set_constructor_extern<decimal*, const decimal&>("void f(const float768&in)", &svm_abi::decimal_repr::custom_constructor_copy);
			decimal_repr->set_method_extern("bool opImplConv() const", &svm_abi::decimal_repr::is_not_zero_or_nan);
			decimal_repr->set_method("bool is_nan() const", &decimal::is_nan);
			decimal_repr->set_method("bool is_zero() const", &decimal::is_zero);
			decimal_repr->set_method("bool is_zero_or_nan() const", &decimal::is_zero_or_nan);
			decimal_repr->set_method("bool is_positive() const", &decimal::is_positive);
			decimal_repr->set_method("bool is_negative() const", &decimal::is_negative);
			decimal_repr->set_method("bool is_integer() const", &decimal::is_integer);
			decimal_repr->set_method("bool is_fractional() const", &decimal::is_fractional);
			decimal_repr->set_method("int8 i8() const", &decimal::to_int8);
			decimal_repr->set_method("int16 i16() const", &decimal::to_int16);
			decimal_repr->set_method("int32 i32() const", &decimal::to_int32);
			decimal_repr->set_method("int64 i64() const", &decimal::to_int64);
			decimal_repr->set_method("uint8 u8() const", &decimal::to_uint8);
			decimal_repr->set_method("uint16 u16() const", &decimal::to_uint16);
			decimal_repr->set_method("uint32 u32() const", &decimal::to_uint32);
			decimal_repr->set_method("uint64 u64() const", &decimal::to_uint64);
			decimal_repr->set_method_extern("uint128 u128() const", &svm_abi::decimal_repr::to_uint128);
			decimal_repr->set_method_extern("uint256 u256() const", &svm_abi::decimal_repr::to_uint256);
			decimal_repr->set_method_extern("string exponent() const", &svm_abi::decimal_repr::to_exponent);
			decimal_repr->set_method("uint32 decimal_size() const", &decimal::decimal_size);
			decimal_repr->set_method("uint32 integer_size() const", &decimal::integer_size);
			decimal_repr->set_method("uint32 size() const", &decimal::size);
			decimal_repr->set_operator_extern(operators::neg_t, (uint32_t)position::constant, "float768", "", &svm_abi::decimal_repr::negate);
			decimal_repr->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "float768&", "const float768&in", &svm_abi::decimal_repr::mul_eq);
			decimal_repr->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "float768&", "const float768&in", &svm_abi::decimal_repr::div_eq);
			decimal_repr->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "float768&", "const float768&in", &svm_abi::decimal_repr::add_eq);
			decimal_repr->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "float768&", "const float768&in", &svm_abi::decimal_repr::sub_eq);
			decimal_repr->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "float768&", "", &svm_abi::decimal_repr::fpp);
			decimal_repr->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "float768&", "", &svm_abi::decimal_repr::fmm);
			decimal_repr->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "float768&", "", &svm_abi::decimal_repr::pp);
			decimal_repr->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "float768&", "", &svm_abi::decimal_repr::mm);
			decimal_repr->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const float768&in", &svm_abi::decimal_repr::eq);
			decimal_repr->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const float768&in", &svm_abi::decimal_repr::cmp);
			decimal_repr->set_operator_extern(operators::add_t, (uint32_t)position::constant, "float768", "const float768&in", &svm_abi::decimal_repr::add);
			decimal_repr->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "float768", "const float768&in", &svm_abi::decimal_repr::sub);
			decimal_repr->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "float768", "const float768&in", &svm_abi::decimal_repr::mul);
			decimal_repr->set_operator_extern(operators::div_t, (uint32_t)position::constant, "float768", "const float768&in", &svm_abi::decimal_repr::div);
			decimal_repr->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "float768", "const float768&in", &svm_abi::decimal_repr::per);
			decimal_repr->set_method_static("float768 nan()", &decimal::nan);
			decimal_repr->set_method_static("float768 zero()", &decimal::zero);
			decimal_repr->set_method_static("float768 from(const string&in, uint8)", &svm_abi::decimal_repr::from);
			uint128_repr->set_constructor_extern("void f()", &svm_abi::uint128_repr::default_construct);
			uint128_repr->set_constructor_extern("void f(const string&in)", &svm_abi::uint128_repr::construct_string);
			uint128_repr->set_constructor<uint128_t, int16_t>("void f(int16)");
			uint128_repr->set_constructor<uint128_t, uint16_t>("void f(uint16)");
			uint128_repr->set_constructor<uint128_t, int32_t>("void f(int32)");
			uint128_repr->set_constructor<uint128_t, uint32_t>("void f(uint32)");
			uint128_repr->set_constructor<uint128_t, int64_t>("void f(int64)");
			uint128_repr->set_constructor<uint128_t, uint64_t>("void f(uint64)");
			uint128_repr->set_constructor<uint128_t, const uint128_t&>("void f(const uint128&in)");
			uint128_repr->set_method_extern("bool opImplConv() const", &svm_abi::uint128_repr::to_bool);
			uint128_repr->set_method_extern("int8 i8() const", &svm_abi::uint128_repr::to_int8);
			uint128_repr->set_method_extern("int16 i16() const", &svm_abi::uint128_repr::to_int16);
			uint128_repr->set_method_extern("int32 i32() const", &svm_abi::uint128_repr::to_int32);
			uint128_repr->set_method_extern("int64 i64() const", &svm_abi::uint128_repr::to_int64);
			uint128_repr->set_method_extern("uint8 u8() const", &svm_abi::uint128_repr::to_uint8);
			uint128_repr->set_method_extern("uint16 u16() const", &svm_abi::uint128_repr::to_uint16);
			uint128_repr->set_method_extern("uint32 u32() const", &svm_abi::uint128_repr::to_uint32);
			uint128_repr->set_method_extern("uint64 u64() const", &svm_abi::uint128_repr::to_uint64);
			uint128_repr->set_method_extern("uint256 u256() const", &svm_abi::uint128_repr::to_uint256);
			uint128_repr->set_method("float768 f768() const", &uint128_t::to_decimal);
			uint128_repr->set_method<uint128_t, const uint64_t&>("const uint64& low() const", &uint128_t::low);
			uint128_repr->set_method<uint128_t, const uint64_t&>("const uint64& high() const", &uint128_t::high);
			uint128_repr->set_method("uint8 bits() const", &uint128_t::bits);
			uint128_repr->set_method("uint8 bytes() const", &uint128_t::bits);
			uint128_repr->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &svm_abi::uint128_repr::mul_eq);
			uint128_repr->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &svm_abi::uint128_repr::div_eq);
			uint128_repr->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &svm_abi::uint128_repr::add_eq);
			uint128_repr->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "uint128&", "const uint128&in", &svm_abi::uint128_repr::sub_eq);
			uint128_repr->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "uint128&", "", &svm_abi::uint128_repr::fpp);
			uint128_repr->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "uint128&", "", &svm_abi::uint128_repr::fmm);
			uint128_repr->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "uint128&", "", &svm_abi::uint128_repr::pp);
			uint128_repr->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "uint128&", "", &svm_abi::uint128_repr::mm);
			uint128_repr->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const uint128&in", &svm_abi::uint128_repr::eq);
			uint128_repr->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const uint128&in", &svm_abi::uint128_repr::cmp);
			uint128_repr->set_operator_extern(operators::add_t, (uint32_t)position::constant, "uint128", "const uint128&in", &svm_abi::uint128_repr::add);
			uint128_repr->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "uint128", "const uint128&in", &svm_abi::uint128_repr::sub);
			uint128_repr->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "uint128", "const uint128&in", &svm_abi::uint128_repr::mul);
			uint128_repr->set_operator_extern(operators::div_t, (uint32_t)position::constant, "uint128", "const uint128&in", &svm_abi::uint128_repr::div);
			uint128_repr->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "uint128", "const uint128&in", &svm_abi::uint128_repr::per);
			uint256_repr->set_constructor_extern("void f()", &svm_abi::uint256_repr::default_construct);
			uint256_repr->set_constructor_extern("void f(const string&in)", &svm_abi::uint256_repr::construct_string);
			uint256_repr->set_constructor<uint256_t, int16_t>("void f(int16)");
			uint256_repr->set_constructor<uint256_t, uint16_t>("void f(uint16)");
			uint256_repr->set_constructor<uint256_t, int32_t>("void f(int32)");
			uint256_repr->set_constructor<uint256_t, uint32_t>("void f(uint32)");
			uint256_repr->set_constructor<uint256_t, int64_t>("void f(int64)");
			uint256_repr->set_constructor<uint256_t, uint64_t>("void f(uint64)");
			uint256_repr->set_constructor<uint256_t, const uint128_t&>("void f(const uint128&in)");
			uint256_repr->set_constructor<uint256_t, const uint128_t&, const uint128_t&>("void f(const uint128&in, const uint128&in)");
			uint256_repr->set_constructor<uint256_t, const uint256_t&>("void f(const uint256&in)");
			uint256_repr->set_method_extern("bool opImplConv() const", &svm_abi::uint256_repr::to_bool);
			uint256_repr->set_method_extern("int8 i8() const", &svm_abi::uint256_repr::to_int8);
			uint256_repr->set_method_extern("int16 i16() const", &svm_abi::uint256_repr::to_int16);
			uint256_repr->set_method_extern("int32 i32() const", &svm_abi::uint256_repr::to_int32);
			uint256_repr->set_method_extern("int64 i64() const", &svm_abi::uint256_repr::to_int64);
			uint256_repr->set_method_extern("uint8 u8() const", &svm_abi::uint256_repr::to_uint8);
			uint256_repr->set_method_extern("uint16 u16() const", &svm_abi::uint256_repr::to_uint16);
			uint256_repr->set_method_extern("uint32 u32() const", &svm_abi::uint256_repr::to_uint32);
			uint256_repr->set_method_extern("uint64 u64() const", &svm_abi::uint256_repr::to_uint64);
			uint256_repr->set_method_extern("uint128 u128() const", &svm_abi::uint256_repr::to_uint128);
			uint256_repr->set_method("float768 f768() const", &uint256_t::to_decimal);
			uint256_repr->set_method<uint256_t, const uint128_t&>("const uint128& low() const", &uint256_t::low);
			uint256_repr->set_method<uint256_t, const uint128_t&>("const uint128& high() const", &uint256_t::high);
			uint256_repr->set_method("uint16 bits() const", &uint256_t::bits);
			uint256_repr->set_method("uint16 bytes() const", &uint256_t::bytes);
			uint256_repr->set_operator_extern(operators::mul_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &svm_abi::uint256_repr::mul_eq);
			uint256_repr->set_operator_extern(operators::div_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &svm_abi::uint256_repr::div_eq);
			uint256_repr->set_operator_extern(operators::add_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &svm_abi::uint256_repr::add_eq);
			uint256_repr->set_operator_extern(operators::sub_assign_t, (uint32_t)position::left, "uint256&", "const uint256&in", &svm_abi::uint256_repr::sub_eq);
			uint256_repr->set_operator_extern(operators::pre_inc_t, (uint32_t)position::left, "uint256&", "", &svm_abi::uint256_repr::fpp);
			uint256_repr->set_operator_extern(operators::pre_dec_t, (uint32_t)position::left, "uint256&", "", &svm_abi::uint256_repr::fmm);
			uint256_repr->set_operator_extern(operators::post_inc_t, (uint32_t)position::left, "uint256&", "", &svm_abi::uint256_repr::pp);
			uint256_repr->set_operator_extern(operators::post_dec_t, (uint32_t)position::left, "uint256&", "", &svm_abi::uint256_repr::mm);
			uint256_repr->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const uint256&in", &svm_abi::uint256_repr::eq);
			uint256_repr->set_operator_extern(operators::cmp_t, (uint32_t)position::constant, "int", "const uint256&in", &svm_abi::uint256_repr::cmp);
			uint256_repr->set_operator_extern(operators::add_t, (uint32_t)position::constant, "uint256", "const uint256&in", &svm_abi::uint256_repr::add);
			uint256_repr->set_operator_extern(operators::sub_t, (uint32_t)position::constant, "uint256", "const uint256&in", &svm_abi::uint256_repr::sub);
			uint256_repr->set_operator_extern(operators::mul_t, (uint32_t)position::constant, "uint256", "const uint256&in", &svm_abi::uint256_repr::mul);
			uint256_repr->set_operator_extern(operators::div_t, (uint32_t)position::constant, "uint256", "const uint256&in", &svm_abi::uint256_repr::div);
			uint256_repr->set_operator_extern(operators::mod_t, (uint32_t)position::constant, "uint256", "const uint256&in", &svm_abi::uint256_repr::per);

			auto exception_ptr = vm->set_struct_trivial<svm_abi::exception::pointer>("exception_ptr");
			exception_ptr->set_constructor<svm_abi::exception::pointer>("void f()");
			exception_ptr->set_constructor<svm_abi::exception::pointer, const svm_abi::string_repr&, const svm_abi::string_repr&>("void f(const string&in, const string&in)");
			exception_ptr->set_method("string type() const", &svm_abi::exception::pointer::get_type);
			exception_ptr->set_method("string text() const", &svm_abi::exception::pointer::get_text);
			exception_ptr->set_method("string what() const", &svm_abi::exception::pointer::get_what);
			exception_ptr->set_method("bool empty() const", &svm_abi::exception::pointer::empty);

			vm->begin_namespace("instrset");
			auto instrset_rwptr = vm->set_interface_class<svm_program>("rwptr");
			auto instrset_rptr = vm->set_interface_class<svm_program>("rptr");
			vm->end_namespace();

			auto address = vm->set_pod<svm_abi::address>("address");
			address->set_constructor<svm_abi::address>("void f()");
			address->set_constructor<svm_abi::address, const svm_abi::string_repr&>("void f(const string&in)");
			address->set_constructor<svm_abi::address, const uint256_t&>("void f(const uint256&in)");
			address->set_method("uint256 u256() const", &svm_abi::address::to_public_key_hash);
			address->set_method("bool empty() const", &svm_abi::address::empty);
			address->set_method("void pay(const uint256&in, const float768&in) const", &svm_abi::address::pay);
			address->set_method("float768 balance_of(const uint256&in) const", &svm_abi::address::balance_of);
			address->set_method_extern("t call<t>(const string&in, const ?&in ...) const", &svm_abi::address::call, convention::generic_call);
			address->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const address&in", &svm_abi::address::equals);

			auto abi = vm->set_struct_trivial<svm_abi::abi>("abi");
			abi->set_constructor<svm_abi::abi>("void f()");
			abi->set_constructor<svm_abi::abi, const svm_abi::string_repr&>("void f(const string&in)");
			abi->set_method("void seek(usize)", &svm_abi::abi::seek);
			abi->set_method("void clear()", &svm_abi::abi::clear);
			abi->set_method("void merge(const string&in)", &svm_abi::abi::merge);
			abi->set_method("void wstr(const string&in)", &svm_abi::abi::wstr);
			abi->set_method("void wrstr(const string&in)", &svm_abi::abi::wrstr);
			abi->set_method("void wu8(bool)", &svm_abi::abi::wboolean);
			abi->set_method("void wu160(const address&in)", &svm_abi::abi::wuint160);
			abi->set_method("void wu256(const uint256&in)", &svm_abi::abi::wuint256);
			abi->set_method("void wf768(const float768&in)", &svm_abi::abi::wdecimal);
			abi->set_method("bool rstr(string&out)", &svm_abi::abi::rstr);
			abi->set_method("bool ru8(bool&out)", &svm_abi::abi::rboolean);
			abi->set_method("bool ru160(address&out)", &svm_abi::abi::ruint160);
			abi->set_method("bool ru256(uint256&out)", &svm_abi::abi::ruint256);
			abi->set_method("bool rf768(float768&out)", &svm_abi::abi::rdecimal);
			abi->set_method("string data()", &svm_abi::abi::data);

			vm->begin_namespace("log");
			vm->set_function("bool emit(const ?&in)", &svm_abi::log::emit);
			vm->end_namespace();

			vm->begin_namespace("sv");
			vm->set_function("void set(const ?&in, const ?&in)", &svm_abi::sv::set);
			vm->set_function("void set_if(const ?&in, const ?&in, bool)", &svm_abi::sv::set_if);
			vm->set_function("void erase(const ?&in)", &svm_abi::sv::erase);
			vm->set_function("bool has(const ?&in)", &svm_abi::sv::has);
			vm->set_function("bool at(const ?&in, ?&out)", &svm_abi::sv::at);
			vm->set_function("t as<t>(const ?&in)", &svm_abi::sv::get, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("qsv");
			auto qsv_comparator = vm->set_enum("comparator");
			qsv_comparator->set_value("greater", (int)ledger::filter_comparator::greater);
			qsv_comparator->set_value("greater_equal", (int)ledger::filter_comparator::greater_equal);
			qsv_comparator->set_value("equal", (int)ledger::filter_comparator::equal);
			qsv_comparator->set_value("not_equal", (int)ledger::filter_comparator::not_equal);
			qsv_comparator->set_value("less", (int)ledger::filter_comparator::less);
			qsv_comparator->set_value("less_equal", (int)ledger::filter_comparator::less_equal);
			auto qsv_order = vm->set_enum("order");
			qsv_order->set_value("ascending", (int)ledger::filter_order::ascending);
			qsv_order->set_value("descending", (int)ledger::filter_order::descending);
			auto qsv_filter = vm->set_struct_trivial<svm_abi::filter>("filter");
			qsv_filter->set_constructor<svm_abi::filter>("void f()");
			qsv_filter->set_property("comparator comparator", &svm_abi::filter::comparator);
			qsv_filter->set_property("order order", &svm_abi::filter::order);
			qsv_filter->set_property("uint256 value", &svm_abi::filter::value);
			auto qsv_xc = vm->set_struct_trivial<svm_abi::xc>("xc");
			qsv_xc->set_constructor<svm_abi::xc>("void f()");
			qsv_xc->set_method("bool at(usize, ?&out) const", &svm_abi::xc::at);
			qsv_xc->set_method("bool at(usize, ?&out, ?&out) const", &svm_abi::xc::at_row);
			qsv_xc->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_abi::xc::at_row_ranked);
			auto qsv_xfc = vm->set_struct_trivial<svm_abi::xfc>("xfc");
			qsv_xfc->set_constructor<svm_abi::xfc>("void f()");
			qsv_xfc->set_method("bool at(usize, ?&out) const", &svm_abi::xfc::at);
			qsv_xfc->set_method("bool at(usize, ?&out, ?&out) const", &svm_abi::xfc::at_row);
			qsv_xfc->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_abi::xfc::at_row_ranked);
			auto qsv_yc = vm->set_struct_trivial<svm_abi::yc>("yc");
			qsv_yc->set_constructor<svm_abi::yc>("void f()");
			qsv_yc->set_method("bool at(usize, ?&out) const", &svm_abi::yc::at);
			qsv_yc->set_method("bool at(usize, ?&out, ?&out) const", &svm_abi::yc::at_column);
			qsv_yc->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_abi::yc::at_column_ranked);
			auto qsv_yfc = vm->set_struct_trivial<svm_abi::yfc>("yfc");
			qsv_yfc->set_constructor<svm_abi::yfc>("void f()");
			qsv_yfc->set_method("bool at(usize, ?&out) const", &svm_abi::yfc::at);
			qsv_yfc->set_method("bool at(usize, ?&out, ?&out) const", &svm_abi::yfc::at_column);
			qsv_yfc->set_method("bool at(usize, ?&out, ?&out, uint256&out) const", &svm_abi::yfc::at_column_ranked);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in)", &svm_abi::qsv::set);
			vm->set_function("void set(const ?&in, const ?&in, const ?&in, const uint256&in)", &svm_abi::qsv::set_ranked);
			vm->set_function("void set_if(const ?&in, const ?&in, const ?&in, bool)", &svm_abi::qsv::set_if);
			vm->set_function("void set_if(const ?&in, const ?&in, const ?&in, const uint256&in, bool)", &svm_abi::qsv::set_if_ranked);
			vm->set_function("void erase(const ?&in, const ?&in)", &svm_abi::qsv::erase);
			vm->set_function("bool has(const ?&in, const ?&in)", &svm_abi::qsv::has);
			vm->set_function("bool at(const ?&in, const ?&in, ?&out)", &svm_abi::qsv::at);
			vm->set_function("bool at(const ?&in, const ?&in, ?&out, uint256&out)", &svm_abi::qsv::at_ranked);
			vm->set_function("t as<t>(const ?&in, const ?&in)", &svm_abi::qsv::get, convention::generic_call);
			vm->set_function("xc query_x(const ?&in, usize = 1)", &svm_abi::xc::from);
			vm->set_function("xfc query_x(const ?&in, const filter&in, usize = 1)", &svm_abi::xfc::from);
			vm->set_function("yc query_y(const ?&in, usize = 1)", &svm_abi::yc::from);
			vm->set_function("yfc query_y(const ?&in, const filter&in, usize = 1)", &svm_abi::yfc::from);
			vm->set_function("filter gt(const uint256&in, order)", &svm_abi::filter::greater);
			vm->set_function("filter gte(const uint256&in, order)", &svm_abi::filter::greater_equal);
			vm->set_function("filter eq(const uint256&in, order)", &svm_abi::filter::equal);
			vm->set_function("filter neq(const uint256&in, order)", &svm_abi::filter::not_equal);
			vm->set_function("filter lt(const uint256&in, order)", &svm_abi::filter::less);
			vm->set_function("filter lte(const uint256&in, order)", &svm_abi::filter::less_equal);
			vm->end_namespace();

			vm->begin_namespace("block");
			vm->set_function("address proposer()", &svm_abi::block::proposer);
			vm->set_function("uint256 parent_hash()", &svm_abi::block::parent_hash);
			vm->set_function("uint256 gas_use()", &svm_abi::block::gas_use);
			vm->set_function("uint256 gas_left()", &svm_abi::block::gas_left);
			vm->set_function("uint256 gas_limit()", &svm_abi::block::gas_limit);
			vm->set_function("uint128 difficulty()", &svm_abi::block::difficulty);
			vm->set_function("uint64 time()", &svm_abi::block::time);
			vm->set_function("uint64 time_between(uint64, uint64)", &svm_abi::block::time_between);
			vm->set_function("uint64 priority()", &svm_abi::block::priority);
			vm->set_function("uint64 number()", &svm_abi::block::number);
			vm->end_namespace();

			vm->begin_namespace("tx");
			vm->set_function("bool paid()", &svm_abi::tx::paid);
			vm->set_function("address from()", &svm_abi::tx::from);
			vm->set_function("address to()", &svm_abi::tx::to);
			vm->set_function("float768 value()", &svm_abi::tx::value);
			vm->set_function("string blockchain()", &svm_abi::tx::blockchain);
			vm->set_function("string token()", &svm_abi::tx::token);
			vm->set_function("string contract()", &svm_abi::tx::contract);
			vm->set_function("float768 gas_price()", &svm_abi::tx::gas_price);
			vm->set_function("uint256 gas_use()", &svm_abi::tx::gas_use);
			vm->set_function("uint256 gas_left()", &svm_abi::tx::gas_left);
			vm->set_function("uint256 gas_limit()", &svm_abi::tx::gas_limit);
			vm->set_function("uint256 asset()", &svm_abi::tx::asset);
			vm->end_namespace();

			vm->begin_namespace("currency");
			vm->set_function("uint256 from(const float768&in)", &svm_abi::currency::from_decimal);
			vm->set_function("float768 f768(const uint256&in)", &svm_abi::currency::to_decimal);
			vm->set_function("uint256 id_of(const string&in, const string&in = string(), const string&in = string())", &svm_abi::currency::id_of);
			vm->set_function("string blockchain_of(const uint256&in)", &svm_abi::currency::blockchain_of);
			vm->set_function("string token_of(const uint256&in)", &svm_abi::currency::token_of);
			vm->set_function("string contract_of(const uint256&in)", &svm_abi::currency::checksum_of);
			vm->set_function("string name_of(const uint256&in)", &svm_abi::currency::name_of);
			vm->end_namespace();

			vm->begin_namespace("repr256");
			vm->set_function("string from(const uint256&in)", &svm_abi::repr::encode_bytes256);
			vm->set_function("uint256 u256(const string&in)", &svm_abi::repr::decode_bytes256);
			vm->end_namespace();

			vm->begin_namespace("dsa");
			vm->set_function("address erecover160(const uint256&in, const string&in)", &svm_abi::dsa::erecover160);
			vm->set_function("string erecover264(const uint256&in, const string&in)", &svm_abi::dsa::erecover264);
			vm->end_namespace();

			vm->begin_namespace("alg");
			vm->set_function("uint256 random256()", &svm_abi::alg::random);
			vm->set_function("string crc32(const string&in)", &svm_abi::alg::crc32);
			vm->set_function("string ripemd160(const string&in)", &svm_abi::alg::ripemd160);
			vm->set_function("uint256 blake2b256(const string&in)", &svm_abi::alg::blake2b256);
			vm->set_function("string blake2b256s(const string&in)", &svm_abi::alg::blake2b256s);
			vm->set_function("uint256 keccak256(const string&in)", &svm_abi::alg::keccak256);
			vm->set_function("string keccak256s(const string&in)", &svm_abi::alg::keccak256s);
			vm->set_function("string keccak512(const string&in)", &svm_abi::alg::keccak512);
			vm->set_function("uint256 sha256(const string&in)", &svm_abi::alg::sha256);
			vm->set_function("string sha256s(const string&in)", &svm_abi::alg::sha256s);
			vm->set_function("string sha512(const string&in)", &svm_abi::alg::sha512);
			vm->end_namespace();

			vm->begin_namespace("math");
			vm->set_function("t min_value<t>()", &svm_abi::math::min_value, convention::generic_call);
			vm->set_function("t max_value<t>()", &svm_abi::math::max_value, convention::generic_call);
			vm->set_function("t min<t>(const t&in, const t&in)", &svm_abi::math::min, convention::generic_call);
			vm->set_function("t max<t>(const t&in, const t&in)", &svm_abi::math::max, convention::generic_call);
			vm->set_function("t pow<t>(const t&in, const t&in)", &svm_abi::math::pow, convention::generic_call);
			vm->set_function("t lerp<t>(const t&in, const t&in, const t&in)", &svm_abi::math::lerp, convention::generic_call);
			vm->end_namespace();

			vm->set_function("void require(bool, const string&in = string())", &svm_abi::assertion::require);
			vm->set_default_array_type("array<t>");
			vm->begin_namespace("array");
			vm->set_property("const usize npos", &svm_abi::string_repr::npos);
			vm->end_namespace();
			vm->set_string_factory_type("string");
			vm->begin_namespace("string");
			vm->set_function("string from(int8, int = 10)", &svm_abi::string_repr::to_string<int8_t>);
			vm->set_function("string from(int16, int = 10)", &svm_abi::string_repr::to_string<int16_t>);
			vm->set_function("string from(int32, int = 10)", &svm_abi::string_repr::to_string<int32_t>);
			vm->set_function("string from(int64, int = 10)", &svm_abi::string_repr::to_string<int64_t>);
			vm->set_function("string from(uint8, int = 10)", &svm_abi::string_repr::to_string<uint8_t>);
			vm->set_function("string from(uint16, int = 10)", &svm_abi::string_repr::to_string<uint16_t>);
			vm->set_function("string from(uint32, int = 10)", &svm_abi::string_repr::to_string<uint32_t>);
			vm->set_function("string from(uint64, int = 10)", &svm_abi::string_repr::to_string<uint64_t>);
			vm->set_function("string from(const uint128&in, int = 10)", &svm_abi::string_repr::to_string_uint128);
			vm->set_function("string from(const uint256&in, int = 10)", &svm_abi::string_repr::to_string_uint256);
			vm->set_function("string from(const float768&in)", &svm_abi::string_repr::to_string_decimal);
			vm->set_function("string from(const address&in)", &svm_abi::string_repr::to_string_address);
			vm->set_property("const usize npos", &svm_abi::string_repr::npos);
			vm->end_namespace();
			vm->set_code_generator("throw-syntax", &svm_abi::exception::generator_callback);
			vm->begin_namespace("exception");
			vm->set_function("void throw(const exception_ptr&in)", &svm_abi::exception::throw_ptr);
			vm->set_function("void rethrow()", &svm_abi::exception::rethrow);
			vm->set_function("exception_ptr unwrap()", &svm_abi::exception::get_exception);
			vm->end_namespace();
		}
		svm_container::~svm_container() noexcept
		{
			while (!compilers.empty())
			{
				auto& compiler = compilers.front();
				compiler->unlink_module();
				compilers.pop();
			}
			for (auto& link : modules)
				library(link.second).discard();
			modules.clear();
			memory::deinit((string_repr_cache_type*)strings);
		}
		svm_compiler svm_container::allocate()
		{
			umutex<std::mutex> unique(mutex);
			if (!compilers.empty())
			{
				auto compiler = std::move(compilers.front());
				compilers.pop();
				return compiler.reset();
			}

			auto* compiler = vm->create_compiler();
			compiler->clear();
			return compiler;
		}
		void svm_container::deallocate(uptr<compiler>&& compiler)
		{
			if (!compiler)
				return;

			umutex<std::mutex> unique(mutex);
			compiler->unlink_module();
			compilers.push(std::move(compiler));
		}
		expects_lr<void> svm_container::compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& program_name, const std::string_view& unpacked_program_code)
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
				stringify::replace(messages, id, "svmc");
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

			auto module = compiler->get_module();
			for (size_t i = 0; i < module.get_objects_count(); i++)
			{
				auto object = module.get_object_by_index(i);
				for (size_t j = 0; j < object.get_methods_count(); j++)
				{
					auto validation = validate_bytecode(object.get_method_by_index(j));
					if (!validation)
					{
						messages.append("svm method validation: " + validation.error().message() + "\r\n");
						goto error;
					}
				}
			}
			for (size_t i = 0; i < module.get_function_count(); i++)
			{
				auto validation = validate_bytecode(module.get_function_by_index(i));
				if (!validation)
				{
					messages.append("svm function validation: " + validation.error().message() + "\r\n");
					goto error;
				}
			}

			umutex<std::mutex> unique(mutex);
			if (modules.size() <= protocol::now().user.storage.svm_cache_size)
			{
				auto& link = modules[id];
				if (link != nullptr)
					vitex::scripting::library(link).discard();

				link = module.get_module();
				return expectation::met;
			}

			for (auto& link : modules)
				vitex::scripting::library(link.second).discard();

			modules.clear();
			modules[id] = module.get_module();
			return expectation::met;
		}
		bool svm_container::precompile(compiler* compiler, const std::string_view& program_hashcode)
		{
			VI_ASSERT(compiler != nullptr, "compiler should not be null");
			string id = string(program_hashcode);
			umutex<std::mutex> unique(mutex);
			auto it = modules.find(id);
			return it != modules.end() ? !!compiler->prepare(it->second) : false;
		}
		string svm_container::hashcode(const std::string_view& unpacked_program_code)
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
		expects_lr<string> svm_container::pack(const std::string_view& unpacked_program_code)
		{
			auto packed_program_code = codec::compress(unpacked_program_code, compression::best_compression);
			if (!packed_program_code)
				return layer_exception(std::move(packed_program_code.error().message()));

			return *packed_program_code;
		}
		expects_lr<string> svm_container::unpack(const std::string_view& packed_program_code)
		{
			auto unpacked_program_code = codec::decompress(packed_program_code);
			if (!unpacked_program_code)
				return layer_exception(std::move(unpacked_program_code.error().message()));

			return *unpacked_program_code;
		}
		virtual_machine* svm_container::get_vm()
		{
			return *vm;
		}
		expects_lr<void> svm_container::validate_bytecode(const function& compiled_function)
		{
			size_t byte_code_size = 0;
			uint32_t* byte_code = compiled_function.get_byte_code(&byte_code_size);
			for (size_t i = 0; i < byte_code_size;)
			{
				uint8_t code = *(uint8_t*)(&byte_code[i]);
				auto type = virtual_machine::get_byte_code_info(code);
				if (illegal_instructions.find(type.name) != illegal_instructions.end())
				{
					auto name = string(type.name);
					auto decl = compiled_function.get_decl(true, true, true);
					return layer_exception(stringify::text("declaration \"%.*s\" contains illegal instruction \"%s\"", (int)decl.size(), decl.data(), stringify::to_lower(name).c_str()));
				}
				i += type.size;
			}
			return expectation::met;
		}
		const void* svm_container::to_string_constant(void* context, const char* buffer, size_t buffer_size)
		{
			auto* container = (svm_container*)context;
			auto& strings = *(string_repr_cache_type*)container->strings;
			auto copy = svm_abi::string_repr(std::string_view(buffer, buffer_size));
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
		int svm_container::from_string_constant(void* context, const void* object, char* buffer, size_t* buffer_size)
		{
			if (buffer_size != nullptr)
				*buffer_size = reinterpret_cast<const svm_abi::string_repr*>(object)->size();

			if (buffer != nullptr)
				memcpy(buffer, reinterpret_cast<const svm_abi::string_repr*>(object)->data(), (size_t)reinterpret_cast<const svm_abi::string_repr*>(object)->size());

			return (int)virtual_error::success;
		}
		int svm_container::free_string_constant(void* context, const void* object)
		{
			if (!object)
				return (int)virtual_error::success;

			auto* container = (svm_container*)context;
			auto& strings = *(string_repr_cache_type*)container->strings;
			virtual_machine::global_shared_lock();
			auto it = strings.find(*reinterpret_cast<const svm_abi::string_repr*>(object));
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

		size_t svm_stackframe::gas_cost_of(const byte_code_label& opcode)
		{
			auto gas = (size_t)opcode.stride * (size_t)gas_cost::opcode;
			return gas;
		}

		svm_program::svm_program(ledger::transaction_context* new_context) : context(new_context)
		{
		}
		expects_lr<void> svm_program::construct(compiler* compiler, const format::variables& args)
		{
			return execute(svm_call::system_call, compiler->get_module().get_function_by_name(SCRIPT_FUNCTION_CONSTRUCT), args, nullptr);
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

			auto binders = dispatch_arguments(&mutability, entrypoint, args);
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
							auto type = svm_container::get()->get_vm()->get_type_info_by_id(type_id);
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
				vector<svm_stackframe> frames;
				coroutine->set_exception_callback(std::bind(&svm_program::dispatch_exception, this, std::placeholders::_1));
				coroutine->set_line_callback(std::bind(&svm_program::dispatch_coroutine, this, std::placeholders::_1, frames));
				execution = coroutine->execute_inline_call(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); });
				resolve(coroutine);
			}
			else
				execution = coroutine->execute_subcall(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); }, resolve);

			auto exception = svm_abi::exception::get_exception_at(coroutine);
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
				stringify::replace(error_message, name, "svmc");
				return layer_exception(std::move(error_message));
			}

			if (caller != coroutine)
				vm->return_context(coroutine);
			return resolver;
		}
		expects_lr<void> svm_program::subexecute(const algorithm::pubkeyhash_t& target, svm_call mutability, const std::string_view& function_decl, format::variables&& function_args, void* output_value, int output_type_id) const
		{
			if (function_decl.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", svm_abi::address(target).to_string().data()));

			auto link = context->get_account_program(target.data);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data()));

			auto* host = ledger::svm_container::get();
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, link->hashcode))
			{
				auto program = context->get_witness_program(link->hashcode);
				if (!program)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data(), program.error().what()));

				auto code = program->as_code();
				if (!code)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data(), code.error().what()));

				auto compilation = host->compile(*compiler, link->hashcode, format::util::encode_0xhex(link->hashcode), *code);
				if (!compilation)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data(), compilation.error().what()));
			}

			auto transaction = transactions::call();
			transaction.program_call(target, algorithm::hashing::hash32d(link->hashcode), function_decl, std::move(function_args));
			transaction.asset = context->transaction->asset;
			transaction.gas_price = context->transaction->gas_price;
			transaction.gas_limit = context->get_gas_left();
			transaction.nonce = 0;

			ledger::receipt receipt;
			receipt.transaction_hash = transaction.as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.absolute_gas_use = context->block->gas_use;
			receipt.block_number = context->block->number;
			receipt.from = callable();

			auto next = transaction_context(context->environment, context->block, context->changelog, &transaction, std::move(receipt));
			auto* prev = context;
			auto* main = (svm_program*)this;
			main->context = &next;

			auto execution = main->execute(mutability, compiler->get_module().get_function_by_decl(function_decl), transaction.args, [&target, &function_decl, output_value, output_type_id](void* address, int type_id) -> expects_lr<void>
			{
				format::wo_stream stream;
				auto serialization = svm_marshalling::store(&stream, address, type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": return serialization error", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data()));

				auto reader = stream.ro();
				serialization = svm_marshalling::load(reader, output_value, output_type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", svm_abi::address(target).to_string().data(), (int)function_decl.size(), function_decl.data(), serialization.error().what()));

				return expectation::met;
			});

			prev->receipt.events.insert(prev->receipt.events.begin(), next.receipt.events.begin(), next.receipt.events.end());
			prev->receipt.relative_gas_use += next.receipt.relative_gas_use;
			main->context = prev;
			return execution;
		}
		expects_lr<vector<std::function<void(immediate_context*)>>> svm_program::dispatch_arguments(svm_call* mutability, const function& entrypoint, const format::variables& args) const
		{
			VI_ASSERT(mutability != nullptr, "mutability should be set");
			auto function_name = entrypoint.get_name();
			if (!entrypoint.get_namespace().empty())
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			if (function_name == SCRIPT_FUNCTION_CONSTRUCT && *mutability != svm_call::system_call)
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

							auto object = svm_abi::uobject(vm, type.get_type_info(), address);
							frames.emplace_back([i, type_id, object = std::move(object)](immediate_context* coroutine) mutable { coroutine->set_arg_object(i, (void*)object.address); });
							break;
						}
					}
				}
				else
				{
					if (!type.is_valid() || type.get_namespace() != SCRIPT_NAMESPACE_INSTRSET)
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to any instruction set", entrypoint.get_decl().data(), (int)i));

					if (type.get_name() == SCRIPT_TYPENAME_RWPTR)
                    {
                        if (*mutability != svm_call::system_call && *mutability != svm_call::mutable_call)
                            return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_TYPENAME_RWPTR ")", entrypoint.get_decl().data(), (int)i));
                        
                        *mutability = svm_call::mutable_call;
                    }
					else if (type.get_name() != "rptr")
					{
						auto name = type.get_name();
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to required instruction set (" SCRIPT_TYPENAME_RWPTR " or " SCRIPT_TYPENAME_RPTR ") - \"%s\" type", entrypoint.get_decl().data(), (int)i, name.data()));
					}
                    else
                        *mutability = svm_call::immutable_call;
					frames.emplace_back([i, index, &args, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (svm_program*)this); });
				}
			}
			return std::move(frames);
		}
		void svm_program::dispatch_exception(immediate_context* coroutine)
		{
		}
		void svm_program::dispatch_coroutine(immediate_context* coroutine, vector<svm_stackframe>& frames)
		{
			svm_stackframe current_frame; size_t current_depth = coroutine->get_callstack_size();
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
		bool svm_program::dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
		{
			auto gas = svm_stackframe::gas_cost_of(opcode);
			auto status = context->burn_gas(gas);
			if (status)
				return true;

			coroutine = coroutine ? coroutine : immediate_context::get();
			if (coroutine != nullptr)
				coroutine->set_exception(svm_abi::exception::pointer(svm_abi::exception::category::execution(), status.error().message()).to_exception_string(), false);

			return false;
		}
		bool svm_program::emit_event(const void* object_value, int object_type_id)
		{
			format::wo_stream stream;
			auto status = svm_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
			{
				svm_abi::exception::throw_ptr(svm_abi::exception::pointer(svm_abi::exception::category::argument(), std::string_view(status.error().message())));
				return false;
			}

			auto reader = stream.ro();
			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(reader, &returns))
			{
				svm_abi::exception::throw_ptr(svm_abi::exception::pointer(svm_abi::exception::category::argument(), "emit value conversion error"));
				return false;
			}

			auto type = svm_container::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto data = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns), true);
			if (!data)
			{
				svm_abi::exception::throw_ptr(svm_abi::exception::pointer(svm_abi::exception::category::storage(), std::string_view(data.error().message())));
				return false;
			}

			return true;
		}
        svm_call svm_program::mutability_of(const function& entrypoint) const
        {
            int type_id;
            if (entrypoint.get_arg(0, &type_id))
            {
                auto* vm = entrypoint.get_vm();
                auto type = vm->get_type_info_by_id(type_id);
                auto name = type.get_name();
                if (name == SCRIPT_TYPENAME_RWPTR)
                    return svm_call::mutable_call;
            }
            return svm_call::immutable_call;
        }
		algorithm::pubkeyhash_t svm_program::callable() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->callable;
			else if (type == transactions::upgrade::as_instance_type())
				return ((transactions::upgrade*)context->transaction)->get_account();

			return context->receipt.from;
		}
		decimal svm_program::payable() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->value;
			else if (type == transactions::upgrade::as_instance_type())
				return decimal::zero();

			return decimal::nan();
		}
		string svm_program::function_declaration() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::call::as_instance_type())
				return ((transactions::call*)context->transaction)->function;
			else if (type == transactions::upgrade::as_instance_type())
				return string(SCRIPT_FUNCTION_CONSTRUCT);

			return string();
		}
		const format::variables* svm_program::function_arguments() const
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
				svm_abi::exception::throw_ptr_at(coroutine, svm_abi::exception::pointer(svm_abi::exception::category::requirement(), "contract is required to be mutable"));

			return result;
		}
		const svm_program* svm_program::fetch_immutable_or_throw(immediate_context* coroutine)
		{
			auto* result = fetch_immutable(coroutine);
			if (!result)
				svm_abi::exception::throw_ptr_at(coroutine, svm_abi::exception::pointer(svm_abi::exception::category::requirement(), "contract is required to be immutable"));

			return result;
		}
	}
}
