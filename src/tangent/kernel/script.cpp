#include "script.h"
#include "chain.h"
#include "../policy/transactions.h"
#include "../validator/storage/chainstate.h"
#include <vitex/bindings.h>
#include <sstream>
extern "C"
{
#include "../internal/sha2.h"
#include "../internal/sha3.h"
}
#define SCRIPT_TAG_PROGRAM 1944
#define SCRIPT_CLASS_ADDRESS "address"
#define SCRIPT_CLASS_PROGRAM "program"
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
#define SCRIPT_FUNCTION_DESTRUCTOR "destruct"

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

		static void script_address_send(script_address& to, script_program* program, const uint256_t& asset, const decimal& value)
		{
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			program->send(to, asset, value);
		}
		static void script_address_call_mutable_function(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto* program = inout.get_arg_object<script_program>(0);
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			auto& target = *(script_address*)inout.get_object_address();
			auto& function = *inout.get_arg_object<std::string_view>(1);
			void* input_value = inout.get_arg_address(2);
			int input_type_id = inout.get_arg_type_id(2);
			void* output_value = inout.get_address_of_return_location();
			int output_type_id = inout.get_return_addressable_type_id();
			program->call_mutable_function(target, function, input_value, input_type_id, output_value, output_type_id);
		}
		static void script_address_call_immutable_function(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto* program = inout.get_arg_object<const script_program>(0);
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			auto& target = *(script_address*)inout.get_object_address();
			auto& function = *inout.get_arg_object<std::string_view>(1);
			void* input_value = inout.get_arg_address(2);
			int input_type_id = inout.get_arg_type_id(2);
			void* output_value = inout.get_address_of_return_location();
			int output_type_id = inout.get_return_addressable_type_id();
			program->call_immutable_function(target, function, input_value, input_type_id, output_value, output_type_id);
		}
		static void log_emit(script_program* program, const void* event_value, int event_type_id, void* object_value, int object_type_id)
		{
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			program->emit_event(event_value, event_type_id, object_value, object_type_id);
		}
		static void uniform_store(script_program* program, const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			program->store_uniform(index_value, index_type_id, object_value, object_type_id);
		}
		static bool uniform_load(const script_program* program, const void* index_value, int index_type_id, void* object_value, int object_type_id)
		{
			if (!program)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));
				return false;
			}

			return program->load_uniform(index_value, index_type_id, object_value, object_type_id, false);
		}
		static void uniform_from(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto* program = inout.get_arg_object<const script_program>(0);
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			void* index_value = inout.get_arg_address(1);
			int index_type_id = inout.get_arg_type_id(1);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			program->load_uniform(index_value, index_type_id, object_value, object_type_id, true);
		}
		static void multiform_store(script_program* program, const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			program->store_multiform(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id);
		}
		static bool multiform_load_composition(const script_program* program, const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id)
		{
			if (!program)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));
				return false;
			}

			return program->load_multiform_by_composition(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, false);
		}
		static bool multiform_load_column(const script_program* program, const void* column_value, int column_type_id, size_t offset, void* object_value, int object_type_id)
		{
			if (!program)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));
				return false;
			}

			return program->load_multiform_by_column(column_value, column_type_id, object_value, object_type_id, offset, false);
		}
		static void multiform_from_composition(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto* program = inout.get_arg_object<const script_program>(0);
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			void* column_value = inout.get_arg_address(1);
			int column_type_id = inout.get_arg_type_id(1);
			void* row_value = inout.get_arg_address(2);
			int row_type_id = inout.get_arg_type_id(2);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			program->load_multiform_by_composition(column_value, column_type_id, row_value, row_type_id, object_value, object_type_id, true);
		}
		static void multiform_from_column(asIScriptGeneric* generic)
		{
			generic_context inout = generic_context(generic);
			auto* program = inout.get_arg_object<const script_program>(0);
			if (!program)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));

			void* column_value = inout.get_arg_address(1);
			int column_type_id = inout.get_arg_type_id(1);
			size_t offset = inout.get_arg_dword(2);
			void* object_value = inout.get_address_of_return_location();
			int object_type_id = inout.get_return_addressable_type_id();
			program->load_multiform_by_column(column_value, column_type_id, object_value, object_type_id, offset, true);
		}
		static uint256_t block_parent_hash()
		{
			auto* program = script_program::get();
			return program ? program->parent_block_hash() : 0;
		}
		static uint256_t block_gas_left()
		{
			auto* program = script_program::get();
			return program ? program->block_gas_left() : 0;
		}
		static uint256_t block_gas_use()
		{
			auto* program = script_program::get();
			return program ? program->block_gas_use() : 0;
		}
		static uint256_t block_gas_limit()
		{
			auto* program = script_program::get();
			return program ? program->block_gas_limit() : 0;
		}
		static uint128_t block_difficulty()
		{
			auto* program = script_program::get();
			return program ? program->block_difficulty() : 0;
		}
		static uint64_t block_time()
		{
			auto* program = script_program::get();
			return program ? program->block_time() : 0;
		}
		static uint64_t block_priority()
		{
			auto* program = script_program::get();
			return program ? program->block_priority() : 0;
		}
		static uint64_t block_number()
		{
			auto* program = script_program::get();
			return program ? program->block_number() : 0;
		}
		static decimal tx_value()
		{
			auto* program = script_program::get();
			return program ? program->value() : decimal::zero();
		}
		static script_address tx_from()
		{
			auto* program = script_program::get();
			return program ? program->from() : script_address();
		}
		static script_address tx_to()
		{
			auto* program = script_program::get();
			return program ? program->to() : script_address();
		}
		static string tx_blockchain()
		{
			auto* program = script_program::get();
			return program ? program->blockchain() : string();
		}
		static string tx_token()
		{
			auto* program = script_program::get();
			return program ? program->token() : string();
		}
		static string tx_contract()
		{
			auto* program = script_program::get();
			return program ? program->contract() : string();
		}
		static decimal tx_gas_price()
		{
			auto* program = script_program::get();
			return program ? program->gas_price() : decimal::zero();
		}
		static uint256_t tx_gas_left()
		{
			auto* program = script_program::get();
			return program ? program->gas_left() : 0;
		}
		static uint256_t tx_gas_use()
		{
			auto* program = script_program::get();
			return program ? program->gas_use() : 0;
		}
		static uint256_t tx_gas_limit()
		{
			auto* program = script_program::get();
			return program ? program->gas_limit() : 0;
		}
		static uint256_t tx_asset()
		{
			auto* program = script_program::get();
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
		static script_address erecover160(const uint256_t& hash, const std::string_view& signature)
		{
			if (signature.size() != sizeof(algorithm::recpubsig))
				return script_address();

			algorithm::pubkeyhash public_key_hash = { 0 }, null = { 0 };
			if (!algorithm::signing::recover_hash(hash, public_key_hash, (uint8_t*)signature.data()) || !memcmp(public_key_hash, null, sizeof(null)))
				return script_address();

			return script_address(public_key_hash);
		}
		static string erecover256(const uint256_t& hash, const std::string_view& signature)
		{
			if (signature.size() != sizeof(algorithm::recpubsig))
				return string();

			algorithm::pubkey public_key = { 0 }, null = { 0 };
			if (!algorithm::signing::recover(hash, public_key, (uint8_t*)signature.data()) || !memcmp(public_key, null, sizeof(null)))
				return string();

			return string((char*)public_key, sizeof(public_key));
		}
		static string blake2b256(const std::string_view& data)
		{
			return algorithm::hashing::hash256((uint8_t*)data.data(), data.size());
		}
		static string keccak256(const std::string_view& data)
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
		static string sha256(const std::string_view& data)
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
		static string wstring(const std::string_view& value)
		{
			format::stream message;
			message.write_string(value);
			return message.data;
		}
		static string wbytes(const std::string_view& value)
		{
			format::stream message;
			message.write_string_raw(value);
			return message.data;
		}
		static string wdecimal(const decimal& value)
		{
			format::stream message;
			message.write_decimal(value);
			return message.data;
		}
		static string wboolean(bool value)
		{
			format::stream message;
			message.write_boolean(value);
			return message.data;
		}
		static string wuint256(const uint256_t& value)
		{
			format::stream message;
			message.write_integer(value);
			return message.data;
		}
		static uint256_t random(script_program* program)
		{
			if (!program)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "program is required"));
				return 0;
			}

			return program->random();
		}
		static void require(bool condition, const std::string_view& message)
		{
			if (!condition)
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_REQUIREMENT, message.empty() ? "requirement not met" : message));
		}

		expects_lr<void> script_marshalling::store(format::stream* stream, const void* value, int value_type_id)
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
					auto type = script_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->write_string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						stream->write_string(((script_address*)value)->hash.optimized_view());
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
		expects_lr<void> script_marshalling::store(schema* stream, const void* value, int value_type_id)
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
					auto type = script_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::handle_t ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->value = var::string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						uptr<schema> data = algorithm::signing::serialize_subaddress(((script_address*)value)->hash.data);
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
						stream->value = var::decimal_string(((uint128_t*)value)->to_string());
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_UINT256)
					{
						stream->value = var::decimal_string(((uint256_t*)value)->to_string());
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
		expects_lr<void> script_marshalling::load(format::stream& stream, void* value, int value_type_id)
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
					if (!stream.read_decimal(stream.read_type(), &wrapper))
						return layer_exception("load failed for float type");

					*(float*)value = wrapper.to_float();
					return expectation::met;
				}
				case (int)type_id::double_t:
				{
					decimal wrapper;
					if (!stream.read_decimal(stream.read_type(), &wrapper))
						return layer_exception("load failed for double type");

					*(double*)value = wrapper.to_double();
					return expectation::met;
				}
				default:
				{
					bool managing = false;
					auto* vm = script_host::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !*(void**)value)
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
							if (!algorithm::signing::decode_subaddress(data, ((script_address*)value)->hash.data))
								return layer_exception("load failed for address type");
						}
						else
							((script_address*)value)->hash = algorithm::subpubkeyhash_t(data);

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
						if (!stream.read_decimal(stream.read_type(), (decimal*)value))
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
		expects_lr<void> script_marshalling::load(schema* stream, void* value, int value_type_id)
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
					auto* vm = script_host::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::handle_t && !*(void**)value)
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
							if (!algorithm::signing::decode_subaddress(data, ((script_address*)value)->hash.data))
								return layer_exception("load failed for address type");
						}
						else
							((script_address*)value)->hash = algorithm::subpubkeyhash_t(data);

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

		script_host::script_host() noexcept
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
			vm->set_property(features::disallow_global_vars, 1);
			vm->set_ts_imports(false);
			vm->set_cache(false);

			bindings::registry::import_ctypes(*vm);
			bindings::registry::import_array(*vm);
			bindings::registry::import_safe_string(*vm);
			bindings::registry::import_exception(*vm);
			bindings::registry::import_decimal(*vm);
			bindings::registry::import_uint128(*vm);
			bindings::registry::import_uint256(*vm);

			auto program = vm->set_interface_class<script_program>(SCRIPT_CLASS_PROGRAM);
			auto address = vm->set_pod<script_address>(SCRIPT_CLASS_ADDRESS);
			address->set_constructor<script_address>("void f()");
			address->set_constructor<script_address, const std::string_view&>("void f(const string_view&in)");
			address->set_constructor<script_address, const uint256_t&>("void f(const uint256&in)");
			address->set_constructor<script_address, const uint256_t&, const uint256_t&>("void f(const uint256&in, const uint256&in)");
			address->set_method("address to_address() const", &script_address::to_address);
			address->set_method("address to_subaddress_from_hash(const uint256&in) const", &script_address::to_subaddress_from_hash);
			address->set_method("address to_subaddress_from_data(const string_view&in) const", &script_address::to_subaddress_from_data);
			address->set_method("string to_string() const", &script_address::to_string);
			address->set_method("uint256 to_public_key_hash() const", &script_address::to_public_key_hash);
			address->set_method("uint256 to_derivation_hash() const", &script_address::to_derivation_hash);
			address->set_method("bool empty() const", &script_address::empty);
			address->set_method_extern("void send(program@, const uint256&in, const decimal&in)", &script_address_send);
			address->set_method_extern("t rw_call<t>(program@, const string_view&in, const ?&in)", &script_address_call_mutable_function, convention::generic_call);
			address->set_method_extern("t call<t>(program@ const, const string_view&in, const ?&in) const", &script_address_call_immutable_function, convention::generic_call);
			address->set_operator_extern(operators::equals_t, (uint32_t)position::constant, "bool", "const address&in", &script_address::equals);

			vm->begin_namespace("log");
			vm->set_function("void emit(program@, const ?&in, const ?&in)", &log_emit);
			vm->end_namespace();

			vm->begin_namespace("uniform");
			vm->set_function("void store(program@, const ?&in, const ?&in)", &uniform_store);
			vm->set_function("void load(program@ const, const ?&in, ?&out)", &uniform_load);
			vm->set_function("t from<t>(program@ const, const ?&in)", &uniform_from, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("multiform");
			vm->set_function("void store(program@, const ?&in, const ?&in, const ?&in)", &multiform_store);
			vm->set_function("void load(program@ const, const ?&in, const ?&in, ?&out)", &multiform_load_composition);
			vm->set_function("void load_index(program@ const, const ?&in, usize, ?&out)", &multiform_load_column);
			vm->set_function("t from<t>(program@ const, const ?&in, const ?&in)", &multiform_from_composition, convention::generic_call);
			vm->set_function("t from_index<t>(program@ const, const ?&in, usize)", &multiform_from_column, convention::generic_call);
			vm->end_namespace();

			vm->begin_namespace("block");
			vm->set_function("uint256 parent_hash()", &block_parent_hash);
			vm->set_function("uint256 gas_use()", &block_gas_use);
			vm->set_function("uint256 gas_limit()", &block_gas_limit);
			vm->set_function("uint128 difficulty()", &block_difficulty);
			vm->set_function("uint64 time()", &block_time);
			vm->set_function("uint64 priority()", &block_priority);
			vm->set_function("uint64 number()", &block_number);
			vm->end_namespace();

			vm->begin_namespace("tx");
			vm->set_function("decimal value()", &tx_value);
			vm->set_function("address from()", &tx_from);
			vm->set_function("address to()", &tx_to);
			vm->set_function("string blockchain()", &tx_blockchain);
			vm->set_function("string token()", &tx_token);
			vm->set_function("string contract()", &tx_contract);
			vm->set_function("decimal gas_price()", &tx_gas_price);
			vm->set_function("uint256 gas_use()", &tx_gas_use);
			vm->set_function("uint256 gas_limit()", &tx_gas_limit);
			vm->set_function("uint256 asset()", &tx_asset);
			vm->end_namespace();

			vm->begin_namespace("alg");
			vm->set_function("uint256 random256(program@)", &random);
			vm->set_function("uint256 asset_handle(const string_view&in, const string_view&in = string_view(), const string_view&in = string_view())", &algorithm::asset::id_of);
			vm->set_function("string asset_blockchain(const uint256&in)", &algorithm::asset::blockchain_of);
			vm->set_function("string asset_token(const uint256&in)", &algorithm::asset::token_of);
			vm->set_function("string asset_contract(const uint256&in)", &algorithm::asset::checksum_of);
			vm->set_function("string encode256(const uint256&in)", &encode_bytes256);
			vm->set_function("uint256 decode256(const string_view&in)", &decode_bytes256);
			vm->set_function("string wstring(const string_view&in)", &wstring);
			vm->set_function("string wbytes(const string_view&in)", &wbytes);
			vm->set_function("string wdecimal(const decimal&in)", &wdecimal);
			vm->set_function("string wboolean(bool)", &wboolean);
			vm->set_function("string wuint256(const uint256&in)", &wuint256);
			vm->set_function("string crc32(const string_view&in)", &crc32);
			vm->set_function("string ripemd160(const string_view&in)", &ripe_md160);
			vm->set_function("address erecover160(const uint256&in, const string_view&in)", &erecover160);
			vm->set_function("string erecover256(const uint256&in, const string_view&in)", &erecover256);
			vm->set_function("string blake2b256(const string_view&in)", &blake2b256);
			vm->set_function("string keccak256(const string_view&in)", &keccak256);
			vm->set_function("string keccak512(const string_view&in)", &keccak512);
			vm->set_function("string sha256(const string_view&in)", &sha256);
			vm->set_function("string sha512(const string_view&in)", &sha512);
			vm->end_namespace();

			vm->set_function("void require(bool, const string_view&in = string_view())", &require);
		}
		script_host::~script_host() noexcept
		{
			for (auto& link : modules)
				library(link.second).discard();
			modules.clear();
		}
		uptr<compiler> script_host::allocate()
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
		void script_host::deallocate(uptr<compiler>&& compiler)
		{
			if (!compiler)
				return;

			umutex<std::mutex> unique(mutex);
			compiler->unlink_module();
			compilers.push(std::move(compiler));
		}
		expects_lr<void> script_host::compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& unpacked_program_code)
		{
			VI_ASSERT(compiler != nullptr, "compiler should not be null");
			string messages, id = string(program_hashcode), scope = format::util::encode_0xhex(program_hashcode);
			vm->set_compile_callback(scope, [&messages](const std::string_view& message) { messages.append(message).append("\r\n"); });

			auto preparation = compiler->prepare(scope, true);
			if (!preparation)
			{
				messages.append("ERR preparation failed: " + preparation.error().message() + "\r\n");
			error:
				vm->set_compile_callback(scope, nullptr);
				return layer_exception(std::move(messages));
			}

			auto injection = compiler->load_code(scope, unpacked_program_code);
			if (!injection)
			{
				messages.append("ERR injection failed: " + injection.error().message() + "\r\n");
				goto error;
			}

			auto compilation = compiler->compile_sync();
			if (!compilation)
			{
				messages.append("ERR compilation failed: " + compilation.error().message() + "\r\n");
				goto error;
			}

			unordered_set<string> mapping;
			auto library = compiler->get_module();
			size_t functions = library.get_function_count();
			for (size_t i = 0; i < functions; i++)
			{
				auto function = library.get_function_by_index(i);
				string name = string(function.get_name());
				if (mapping.find(name) != mapping.end())
					return layer_exception(stringify::text("program function %s is ambiguous", name.c_str()));

				mapping.insert(name);
			}

			umutex<std::mutex> unique(mutex);
			if (modules.size() <= protocol::now().user.storage.script_cache_size)
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
		bool script_host::precompile(compiler* compiler, const std::string_view& program_hashcode)
		{
			VI_ASSERT(compiler != nullptr, "compiler should not be null");
			string id = string(program_hashcode);
			umutex<std::mutex> unique(mutex);
			auto it = modules.find(id);
			return it != modules.end() ? !!compiler->prepare(it->second) : false;
		}
		string script_host::hashcode(const std::string_view& unpacked_program_code)
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
		expects_lr<string> script_host::pack(const std::string_view& unpacked_program_code)
		{
			auto packed_program_code = codec::compress(unpacked_program_code, compression::best_compression);
			if (!packed_program_code)
				return layer_exception(std::move(packed_program_code.error().message()));

			return *packed_program_code;
		}
		expects_lr<string> script_host::unpack(const std::string_view& packed_program_code)
		{
			auto unpacked_program_code = codec::decompress(packed_program_code);
			if (!unpacked_program_code)
				return layer_exception(std::move(unpacked_program_code.error().message()));

			return *unpacked_program_code;
		}
		virtual_machine* script_host::get_vm()
		{
			return *vm;
		}

		script_address::script_address()
		{
		}
		script_address::script_address(const algorithm::pubkeyhash owner)
		{
			if (owner != nullptr)
				hash = algorithm::encoding::to_subaddress(owner);
		}
		script_address::script_address(const std::string_view& address)
		{
			algorithm::signing::decode_subaddress(address, hash.data);
		}
		script_address::script_address(const uint256_t& owner_data)
		{
			uint8_t owner_raw_data[32];
			algorithm::encoding::decode_uint256(owner_data, owner_raw_data);
			hash = algorithm::encoding::to_subaddress(owner_raw_data);
		}
		script_address::script_address(const uint256_t& owner_data, const uint256_t& derivation_data)
		{
			uint8_t owner_raw_data[32], derivation_raw_data[32];
			algorithm::encoding::decode_uint256(owner_data, owner_raw_data);
			algorithm::encoding::decode_uint256(derivation_data, derivation_raw_data);
			hash = algorithm::encoding::to_subaddress(owner_raw_data, derivation_raw_data);
		}
		script_address script_address::to_address() const
		{
			auto result = script_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data);
			return result;
		}
		script_address script_address::to_subaddress_from_hash(const uint256_t& derivation_data) const
		{
			uint8_t derivation_raw_data[32];
			algorithm::encoding::decode_uint256(derivation_data, derivation_raw_data);

			auto result = script_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data, derivation_raw_data);
			return result;
		}
		script_address script_address::to_subaddress_from_data(const std::string_view& derivation_data) const
		{
			auto result = script_address();
			result.hash = algorithm::encoding::to_subaddress(hash.data, derivation_data);
			return result;
		}
		string script_address::to_string() const
		{
			string address;
			algorithm::signing::encode_subaddress(hash.data, address);
			return address;
		}
		uint256_t script_address::to_public_key_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.data, sizeof(algorithm::pubkeyhash));

			uint256_t numeric = 0;
			algorithm::encoding::encode_uint256(data, numeric);
			return numeric;
		}
		uint256_t script_address::to_derivation_hash() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash.data + sizeof(algorithm::pubkeyhash), sizeof(algorithm::pubkeyhash));

			uint256_t numeric = 0;
			algorithm::encoding::encode_uint256(data, numeric);
			return numeric;
		}
		bool script_address::empty() const
		{
			return hash.empty();
		}
		bool script_address::equals(const script_address& a, const script_address& b)
		{
			return a.hash.equals(b.hash.data);
		}

		script_program::script_program(ledger::transaction_context* new_context) : distribution(optional::none), context(new_context)
		{
			VI_ASSERT(context != nullptr, "transaction context should be set");
		}
		expects_lr<void> script_program::construct(compiler* compiler, const format::variables& args)
		{
			return execute(compiler->get_module().get_function_by_name(SCRIPT_FUNCTION_CONSTRUCTOR), args, 1, nullptr);
		}
		expects_lr<void> script_program::destruct(compiler* compiler)
		{
			return destruct(compiler->get_module().get_function_by_name(SCRIPT_FUNCTION_DESTRUCTOR));
		}
		expects_lr<void> script_program::destruct(const function& entrypoint)
		{
			auto destruction = execute(entrypoint, { }, 1, nullptr);
			if (!destruction)
				return destruction;

			auto wipe = context->apply_account_program(to().hash.data, std::string_view());
			if (!wipe)
				return wipe.error();

			return expectation::met;
		}
		expects_lr<void> script_program::mutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args)
		{
			if (function_decl.empty())
				return layer_exception("illegal call to function: function not found");

			return execute(compiler->get_module().get_function_by_name(function_decl), args, -1, nullptr);
		}
		expects_lr<void> script_program::immutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args)
		{
			if (function_decl.empty())
				return layer_exception("illegal call to function: function not found");
			
			return execute(compiler->get_module().get_function_by_name(function_decl), args, 0, nullptr);
		}
		expects_lr<void> script_program::execute(const function& entrypoint, const format::variables& args, int8_t mutability, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			if (!entrypoint.is_valid())
			{
				if (mutability == 1)
					return expectation::met;

				return layer_exception("illegal call to function: null function");
			}

			auto function_name = entrypoint.get_name();
			if (mutability != 1 && (function_name == SCRIPT_FUNCTION_CONSTRUCTOR || function_name == SCRIPT_FUNCTION_DESTRUCTOR))
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));
			else if (!entrypoint.get_namespace().empty())
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			auto binders = load_arguments(entrypoint, args, mutability);
			if (!binders)
				return binders.error();

			auto* vm = entrypoint.get_vm();
			auto* caller = immediate_context::get();
			auto* coroutine = caller ? caller : vm->request_context();
			auto* prev_program = coroutine->get_user_data(SCRIPT_TAG_PROGRAM);
			coroutine->set_user_data(this, SCRIPT_TAG_PROGRAM);

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
					format::stream stream;
					auto serialization = script_marshalling::store(&stream, address, type_id);
					if (serialization)
					{
						format::variables returns;
						if (format::variables_util::deserialize_flat_from(stream, &returns))
						{
							auto type = script_host::get()->get_vm()->get_type_info_by_id(type_id);
							auto name = type.is_valid() ? type.get_name() : std::string_view("?");
							auto status = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns));
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
				vector<script_frame> frames;
				coroutine->set_line_callback(std::bind(&script_program::load_coroutine, this, std::placeholders::_1, frames));
				execution = coroutine->execute_inline_call(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); });
				resolve(coroutine);
			}
			else
				execution = coroutine->execute_subcall(entrypoint, [&binders](immediate_context* coroutine) { for (auto& bind : *binders) bind(coroutine); }, resolve);

			auto exception = bindings::exception::get_exception_at(coroutine);
			coroutine->set_user_data(prev_program, SCRIPT_TAG_PROGRAM);
			if (!execution || (execution && *execution != execution::finished) || !exception.empty())
			{
				if (caller != coroutine)
					vm->return_context(coroutine);
				return layer_exception(exception.empty() ? (execution ? "execution error" : execution.error().message()) : exception.what());
			}

			if (caller != coroutine)
				vm->return_context(coroutine);
			return resolver;
		}
		expects_lr<void> script_program::subexecute(const script_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id, int8_t mutability) const
		{
			if (function_decl.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", target.to_string().c_str()));

			auto link = context->get_account_program(target.hash.data);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));

			auto* host = ledger::script_host::get();
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

				auto compilation = host->compile(*compiler, link->hashcode, *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), compilation.error().what()));
				}
			}

			format::variables args;
			if (input_value != nullptr && input_type_id > 0)
			{
				format::stream stream;
				auto serialization = script_marshalling::store(&stream, input_value, input_type_id);
				if (!serialization)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_decl.size(), function_decl.data(), serialization.error().what()));
				}

				if (!format::variables_util::deserialize_flat_from(stream, &args))
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": argument serialization error", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));
				}
			}

			auto transaction = transactions::invocation();
			transaction.set_asset("ETH");
			transaction.set_calldata(target.hash, algorithm::hashing::hash32d(link->hashcode), function_decl, std::move(args));
			transaction.gas_price = context->transaction->gas_price;
			transaction.gas_limit = context->get_gas_left();
			transaction.nonce = 0;

			ledger::receipt receipt;
			receipt.transaction_hash = transaction.as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.absolute_gas_use = context->block->gas_use;
			receipt.block_number = context->block->number;
			memcpy(receipt.from, to().hash.data, sizeof(receipt.from));

			auto next = transaction_context(context->block, context->environment, &transaction, std::move(receipt));
			auto* prev = context;
			auto* main = (script_program*)this;
			main->context = &next;

			auto execution = main->execute(compiler->get_module().get_function_by_decl(function_decl), transaction.args, mutability, [&target, &function_decl, output_value, output_type_id](void* address, int type_id) -> expects_lr<void>
			{
				format::stream stream;
				auto serialization = script_marshalling::store(&stream, address, type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": return serialization error", target.to_string().c_str(), (int)function_decl.size(), function_decl.data()));

				serialization = script_marshalling::load(stream, output_value, output_type_id);
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
		expects_lr<vector<std::function<void(immediate_context*)>>> script_program::load_arguments(const function& entrypoint, const format::variables& args, int8_t mutability) const
		{
			auto* vm = entrypoint.get_vm();
			size_t args_count = entrypoint.get_args_count();
			if (args_count != args.size() + 1)
				return layer_exception(stringify::text("illegal call to function \"%s\": expected exactly %i arguments", entrypoint.get_decl().data(), (int)args_count));

			vector<std::function<void(immediate_context*)>> frames = { };
			frames.reserve(args_count);

			for (size_t i = 0; i < args_count; i++)
			{
				int type_id; size_t flags;
				if (!entrypoint.get_arg(i, &type_id, &flags))
					return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), i));

				size_t index = i - 1;
				auto type = vm->get_type_info_by_id(type_id);
				if (i > 0)
				{
					if (index >= args.size())
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound", entrypoint.get_decl().data(), i));

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
							format::stream stream;
							format::variables_util::serialize_flat_into({ value }, &stream);
							auto status = script_marshalling::load(stream, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
							if (!status)
							{
								stream = format::stream::decode(value.as_string());
								status = script_marshalling::load(stream, (void*)&address, type_id | (int)vitex::scripting::type_id::handle_t);
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
					if (!type.is_valid() || type.get_name() != SCRIPT_CLASS_PROGRAM)
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program", entrypoint.get_decl().data()));

					bool is_const = mutability == 0;
					if (mutability != -1 && is_const != (!!(flags & (size_t)modifiers::constant)))
						return layer_exception(stringify::text("illegal call to function \"%s\": mutability not preserved", entrypoint.get_decl().data()));

					frames.emplace_back([i, index, &args, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (script_program*)this); });
				}
			}
			return std::move(frames);
		}
		bool script_program::dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
		{
			auto gas = (size_t)(opcode.offset_of_arg2 + opcode.size_of_arg2) * (size_t)gas_cost::opcode;
			auto status = context->burn_gas(gas);
			if (status)
				return true;

			coroutine = coroutine ? coroutine : immediate_context::get();
			if (coroutine != nullptr)
				coroutine->set_exception(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, status.error().message()).to_exception_string(), false);

			return false;
		}
		void script_program::load_coroutine(immediate_context* coroutine, vector<script_frame>& frames)
		{
			script_frame current_frame; size_t current_depth = coroutine->get_callstack_size();
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

			auto& latest_frame = frames.back();
			auto* vm = coroutine->get_vm();
			size_t start = std::min<size_t>(latest_frame.byte_code_size - 1, current_frame.pointer > latest_frame.pointer ? latest_frame.pointer : current_frame.pointer);
			size_t count = (current_frame.pointer > latest_frame.pointer ? current_frame.pointer - latest_frame.pointer : latest_frame.pointer - current_frame.pointer);
			size_t end = std::min<size_t>(latest_frame.byte_code_size, start + std::max<size_t>(1, count));
			while (start < end)
			{
				auto opcode = virtual_machine::get_byte_code_info((uint8_t) * (latest_frame.byte_code + start));
				start += opcode.size;
				if (!dispatch_instruction(vm, coroutine, latest_frame.byte_code, start, opcode))
					return;
			}

			latest_frame.pointer = current_frame.pointer;
		}
		void script_program::call_mutable_function(const script_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id)
		{
			auto execution = subexecute(target, function_decl, input_value, input_type_id, output_value, output_type_id, -1);
			if (!execution)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
		}
		void script_program::call_immutable_function(const script_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const
		{
			auto execution = subexecute(target, function_decl, input_value, input_type_id, output_value, output_type_id, 0);
			if (!execution)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
		}
		void script_program::store_uniform(const void* index_value, int index_type_id, const void* object_value, int object_type_id)
		{
			format::stream index;
			auto status = script_marshalling::store(&index, index_value, index_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::stream stream;
			status = script_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			auto data = context->apply_account_uniform(to().hash.data, index.data, stream.data);
			if (!data)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
		}
		bool script_program::load_uniform(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error) const
		{
			format::stream index;
			auto status = script_marshalling::store(&index, index_value, index_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_uniform(to().hash.data, index.data);
			if (!data || data->data.empty())
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			format::stream stream = format::stream(data->data);
			status = script_marshalling::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			return true;
		}
		void script_program::store_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id)
		{
			format::stream column;
			auto status = script_marshalling::store(&column, column_value, column_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::stream row;
			status = script_marshalling::store(&column, row_value, row_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::stream stream;
			status = script_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			auto data = context->apply_account_multiform(to().hash.data, column.data, row.data, stream.data);
			if (!data)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
		}
		bool script_program::load_multiform_by_composition(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool throw_on_error) const
		{
			format::stream column;
			auto status = script_marshalling::store(&column, column_value, column_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			format::stream row;
			status = script_marshalling::store(&column, row_value, row_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_multiform(to().hash.data, column.data, row.data);
			if (!data || data->data.empty())
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			format::stream stream = format::stream(data->data);
			status = script_marshalling::load(stream, object_value, object_type_id);
			if (!status)
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			return true;
		}
		bool script_program::load_multiform_by_column(const void* column_value, int column_type_id, void* object_value, int object_type_id, size_t offset, bool throw_on_error) const
		{
			format::stream column;
			auto status = script_marshalling::store(&column, column_value, column_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->get_account_multiforms(to().hash.data, column.data, offset, 1);
			if (!data || data->empty())
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			format::stream stream = format::stream(data->front().data);
			status = script_marshalling::load(stream, object_value, object_type_id);
			if (!status && throw_on_error)
			{
				if (throw_on_error)
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, "index is not in use"));
				return false;
			}

			return true;
		}
		void script_program::emit_event(const void* event_value, int event_type_id, const void* object_value, int object_type_id)
		{
			format::stream location;
			auto status = script_marshalling::store(&location, event_value, event_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
			else if (location.data.size() > std::numeric_limits<uint8_t>::max())
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "store location max length is 256 bytes"));

			format::stream stream;
			status = script_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));

			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(stream, &returns))
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit value conversion error"));

			auto type = script_host::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("?");
			auto data = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns));
			if (!data)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
		}
		void script_program::send(const script_address& target, const uint256_t& asset, const decimal& value)
		{
			if (!value.is_positive())
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "transfer value must be positive"));

			auto payment = context->apply_payment(asset, to().hash.data, target.hash.data, value);
			if (!payment)
				return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, payment.error().message()));
		}
		void script_program::destroy()
		{
			auto* caller = immediate_context::get();
			if (caller != nullptr)
			{
				auto entrypoint = caller->get_function().get_module().get_function_by_name(SCRIPT_FUNCTION_DESTRUCTOR);
				auto destruction = destruct(entrypoint);
				if (!destruction)
					return bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, destruction.error().message()));
			}
		}
		uint256_t script_program::random()
		{
			if (!distribution)
			{
				auto candidate = context->calculate_random(context->get_gas_use());
				if (!candidate)
				{
					bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, candidate.error().message()));
					return 0;
				}
				distribution = std::move(*candidate);
			}
			return distribution->derive();
		}
		decimal script_program::value() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::transfer::as_instance_type())
			{
				auto target = to();
				auto total = decimal::zero();
				for (auto& [owner, value] : ((transactions::transfer*)context->transaction)->to)
				{
					if (owner.equals(target.hash.data))
						total += value;
				}
				return total;
			}
			return decimal::zero();
		}
		script_address script_program::from() const
		{
			return script_address(context->receipt.from);
		}
		script_address script_program::to() const
		{
			uint32_t type = context->transaction->as_type();
			if (type == transactions::deployment::as_instance_type())
			{
				algorithm::pubkeyhash owner;
				if (((transactions::deployment*)context->transaction)->recover_location(owner))
					return script_address(owner);
			}
			else if (type == transactions::invocation::as_instance_type())
				return script_address(((transactions::invocation*)context->transaction)->to);

			return script_address(context->receipt.from);
		}
		string script_program::blockchain() const
		{
			return algorithm::asset::blockchain_of(context->transaction->asset);
		}
		string script_program::token() const
		{
			return algorithm::asset::token_of(context->transaction->asset);
		}
		string script_program::contract() const
		{
			return algorithm::asset::checksum_of(context->transaction->asset);
		}
		decimal script_program::gas_price() const
		{
			return context->transaction->gas_price;
		}
		uint256_t script_program::gas_left() const
		{
			return context->get_gas_left();
		}
		uint256_t script_program::gas_use() const
		{
			return context->receipt.relative_gas_use;
		}
		uint256_t script_program::gas_limit() const
		{
			return context->transaction->gas_limit;
		}
		uint256_t script_program::asset() const
		{
			return context->transaction->asset;
		}
		uint256_t script_program::parent_block_hash() const
		{
			return context->block->parent_hash;
		}
		uint256_t script_program::block_gas_use() const
		{
			return context->block->gas_use;
		}
		uint256_t script_program::block_gas_left() const
		{
			return context->block->gas_limit - context->block->gas_use;
		}
		uint256_t script_program::block_gas_limit() const
		{
			return context->block->gas_limit;
		}
		uint128_t script_program::block_difficulty() const
		{
			return context->block->target.difficulty();
		}
		uint64_t script_program::block_time() const
		{
			return context->block->time;
		}
		uint64_t script_program::block_priority() const
		{
			return context->block->priority;
		}
		uint64_t script_program::block_number() const
		{
			return context->block->number;
		}
		script_program* script_program::get(immediate_context* coroutine)
		{
			return coroutine ? (script_program*)coroutine->get_user_data(SCRIPT_TAG_PROGRAM) : nullptr;
		}

		script_program_trace::script_program_trace(ledger::transaction* transaction, const algorithm::pubkeyhash from, bool tracing) : script_program(&environment.validation.context), debugging(tracing)
		{
			VI_ASSERT(transaction != nullptr && from != nullptr, "transaction and from should be set");

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			if (tip)
				environment.tip = std::move(*tip);

			ledger::receipt receipt;
			block.set_parent_block(environment.tip.address());
			receipt.transaction_hash = transaction->as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.block_number = block.number + 1;
			memcpy(receipt.from, from, sizeof(algorithm::pubkeyhash));

			memset(environment.validator.public_key_hash, 0xFF, sizeof(algorithm::pubkeyhash));
			memset(environment.validator.secret_key, 0xFF, sizeof(algorithm::seckey));
			environment.validation.context = transaction_context(&block, &environment, transaction, std::move(receipt));
		}
		expects_lr<void> script_program_trace::trace_call(const std::string_view& function, const format::variables& args, int8_t mutability)
		{
			auto index = environment.validation.context.get_account_program(to().hash.data);
			if (!index)
				return layer_exception("program not assigned to address");

			auto* host = ledger::script_host::get();
			auto& hashcode = index->hashcode;
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, hashcode))
			{
				auto program = environment.validation.context.get_witness_program(hashcode);
				if (!program)
				{
					host->deallocate(std::move(compiler));
					return layer_exception("program not stored to address");
				}

				auto code = program->as_code();
				if (!code)
				{
					host->deallocate(std::move(compiler));
					return code.error();
				}

				auto compilation = host->compile(*compiler, hashcode, *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return compilation.error();
				}
			}

			auto execution = execute(compiler->get_module().get_function_by_name(function), args, mutability, [this](void* address, int type_id) -> expects_lr<void>
			{
				returning = var::set::object();
				auto serialization = script_marshalling::store(*returning, address, type_id);
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

			host->deallocate(std::move(compiler));
			return execution;
		}
		bool script_program_trace::dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
		{
			if (debugging)
			{
				string_stream stream;
				debugger_context::byte_code_label_to_text(stream, vm, program_data, program_counter, false, true);

				string instruction = stream.str();
				stringify::trim(instruction);
#if VI_64
				instruction.erase(2, 8);
#endif
				auto gas = (size_t)(opcode.offset_of_arg2 + opcode.size_of_arg2) * (size_t)gas_cost::opcode;
				instruction.append(instruction.find('%') != std::string::npos ? ", %gc:" : " %gc:");
				instruction.append(to_string(gas));
				instructions.push_back(std::move(instruction));
			}
			return script_program::dispatch_instruction(vm, coroutine, program_data, program_counter, opcode);
		}
		uptr<schema> script_program_trace::as_schema() const
		{
			schema* data = var::set::object();
			data->set("block_hash", var::string(algorithm::encoding::encode_0xhex256(block.number > 0 ? block.as_hash() : uint256_t(0))));
			data->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(context->receipt.transaction_hash)));
			data->set("from", algorithm::signing::serialize_subaddress(((script_program_trace*)this)->from().hash.data));
			data->set("to", algorithm::signing::serialize_subaddress(((script_program_trace*)this)->to().hash.data));
			data->set("gas", algorithm::encoding::serialize_uint256(context->receipt.relative_gas_use));
			data->set("time", algorithm::encoding::serialize_uint256(context->receipt.finalization_time - context->receipt.generation_time));
			data->set("successful", var::boolean(context->receipt.successful));
			data->set("returns", returning ? returning->copy() : var::set::null());
			if (!context->receipt.events.empty())
			{
				auto* events_data = data->set("events", var::set::array());
				for (auto& item : context->receipt.events)
				{
					auto* event_data = events_data->push(var::set::object());
					event_data->set("event", var::integer(item.first));
					event_data->set("args", format::variables_util::serialize(item.second));
				}
			}
			if (!context->delta.outgoing->at(work_commitment::pending).empty())
			{
				auto* states_data = data->set("states", var::set::array());
				for (auto& item : context->delta.outgoing->at(work_commitment::pending))
					states_data->push(item.second->as_schema().reset());
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
