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
#define SCRIPT_CLASS_ADDRESS "address"
#define SCRIPT_CLASS_PROGRAM "program"
#define SCRIPT_CLASS_STRINGVIEW "string_view"
#define SCRIPT_CLASS_STRING "string"
#define SCRIPT_CLASS_UINT128 "uint128"
#define SCRIPT_CLASS_UINT256 "uint256"
#define SCRIPT_CLASS_DECIMAL "decimal"
#define SCRIPT_EXCEPTION_ARGUMENT "argument_error"
#define SCRIPT_EXCEPTION_STORAGE "storage_error"
#define SCRIPT_EXCEPTION_EXECUTION "execution_error"
#define SCRIPT_FUNCTION_INITIALIZE "initialize"

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
					vm->release_object(address, typeinfo(type));
			}
		};

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
		static string erecover160(const uint256_t& hash, const std::string_view& signature)
		{
			if (signature.size() != sizeof(algorithm::recpubsig))
				return string();

			algorithm::pubkeyhash public_key_hash = { 0 }, null = { 0 };
			if (!algorithm::signing::recover_hash(hash, public_key_hash, (uint8_t*)signature.data()) || !memcmp(public_key_hash, null, sizeof(null)))
				return string();

			return string((char*)public_key_hash, sizeof(public_key_hash));
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
		static string encode_bytes(const uint256_t& value)
		{
			uint8_t data[32];
			algorithm::encoding::decode_uint256(value, data);
			return string((char*)data, sizeof(data));
		}
		static uint256_t decode_bytes(const std::string_view& value)
		{
			uint8_t data[32];
			memcpy(data, value.data(), std::min(sizeof(data), value.size()));

			uint256_t buffer;
			algorithm::encoding::encode_uint256(data, buffer);
			return buffer;
		}

		expects_lr<void> script_marshalling::store(format::stream* stream, void* value, int value_type_id)
		{
			switch (value_type_id)
			{
				case (int)type_id::voidf:
					return layer_exception("store not supported for void type");
				case (int)type_id::boolf:
					stream->write_boolean(*(bool*)value);
					return expectation::met;
				case (int)type_id::int8:
				case (int)type_id::uint8:
					stream->write_integer(*(uint8_t*)value);
					return expectation::met;
				case (int)type_id::int16:
				case (int)type_id::uint16:
					stream->write_integer(*(uint16_t*)value);
					return expectation::met;
				case (int)type_id::int32:
				case (int)type_id::uint32:
					stream->write_integer(*(uint32_t*)value);
					return expectation::met;
				case (int)type_id::int64:
				case (int)type_id::uint64:
					stream->write_integer(*(uint64_t*)value);
					return expectation::met;
				case (int)type_id::floatf:
					stream->write_decimal(decimal(*(float*)value));
					return expectation::met;
				case (int)type_id::doublef:
					stream->write_decimal(decimal(*(double*)value));
					return expectation::met;
				default:
				{
					auto type = script_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::objhandle ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->write_string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						stream->write_string(format::util::encode_0xhex(std::string_view((char*)((script_address*)value)->hash, sizeof(algorithm::pubkeyhash))));
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
					else if (value_type_id & (int)vitex::scripting::type_id::scriptobject)
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
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> script_marshalling::store(schema* stream, void* value, int value_type_id)
		{
			switch (value_type_id)
			{
				case (int)type_id::voidf:
					return layer_exception("store not supported for void type");
				case (int)type_id::boolf:
					stream->value = var::boolean(*(bool*)value);
					return expectation::met;
				case (int)type_id::int8:
				case (int)type_id::uint8:
					stream->value = var::integer(*(uint8_t*)value);
					return expectation::met;
				case (int)type_id::int16:
				case (int)type_id::uint16:
					stream->value = var::integer(*(uint16_t*)value);
					return expectation::met;
				case (int)type_id::int32:
				case (int)type_id::uint32:
					stream->value = var::integer(*(uint32_t*)value);
					return expectation::met;
				case (int)type_id::int64:
				case (int)type_id::uint64:
					stream->value = var::integer(*(uint64_t*)value);
					return expectation::met;
				case (int)type_id::floatf:
					stream->value = var::number(*(float*)value);
					return expectation::met;
				case (int)type_id::doublef:
					stream->value = var::number(*(double*)value);
					return expectation::met;
				default:
				{
					auto type = script_host::get()->get_vm()->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					value = value_type_id & (int)vitex::scripting::type_id::objhandle ? *(void**)value : value;
					if (name == SCRIPT_CLASS_STRINGVIEW)
					{
						stream->value = var::string(*(std::string_view*)value);
						return expectation::met;
					}
					else if (name == SCRIPT_CLASS_ADDRESS)
					{
						uptr<schema> data = algorithm::signing::serialize_address(((script_address*)value)->hash);
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
					else if (value_type_id & (int)vitex::scripting::type_id::scriptobject)
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
					return layer_exception(stringify::text("store not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> script_marshalling::load(format::stream& stream, void* value, int value_type_id)
		{
			switch (value_type_id)
			{
				case (int)type_id::voidf:
					return layer_exception("load not supported for void type");
				case (int)type_id::boolf:
					if (!stream.read_boolean(stream.read_type(), (bool*)value))
						return layer_exception("load failed for bool type");
					return expectation::met;
				case (int)type_id::int8:
				case (int)type_id::uint8:
					if (!stream.read_integer(stream.read_type(), (uint8_t*)value))
						return layer_exception("load failed for uint8 type");
					return expectation::met;
				case (int)type_id::int16:
				case (int)type_id::uint16:
					if (!stream.read_integer(stream.read_type(), (uint16_t*)value))
						return layer_exception("load failed for uint16 type");
					return expectation::met;
				case (int)type_id::int32:
				case (int)type_id::uint32:
					if (!stream.read_integer(stream.read_type(), (uint32_t*)value))
						return layer_exception("load failed for uint32 type");
					return expectation::met;
				case (int)type_id::int64:
				case (int)type_id::uint64:
					if (!stream.read_integer(stream.read_type(), (uint64_t*)value))
						return layer_exception("load failed for uint64 type");
					return expectation::met;
				case (int)type_id::floatf:
				{
					decimal wrapper;
					if (!stream.read_decimal(stream.read_type(), &wrapper))
						return layer_exception("load failed for float type");

					*(float*)value = wrapper.to_float();
					return expectation::met;
				}
				case (int)type_id::doublef:
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
					if (value_type_id & (int)vitex::scripting::type_id::objhandle && !*(void**)value)
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
						if (data.size() != sizeof(algorithm::pubkeyhash))
						{
							if (!algorithm::signing::decode_address(data, ((script_address*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							memcpy(((script_address*)value)->hash, data.data(), data.size());

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
					else if (value_type_id & (int)vitex::scripting::type_id::scriptobject)
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
					return layer_exception(stringify::text("load not supported for %s type", name.data()));
				}
			}
		}
		expects_lr<void> script_marshalling::load(schema* stream, void* value, int value_type_id)
		{
			switch (value_type_id)
			{
				case (int)type_id::voidf:
					return layer_exception("load not supported for void type");
				case (int)type_id::boolf:
					*(bool*)value = stream->value.get_boolean();
					return expectation::met;
				case (int)type_id::int8:
				case (int)type_id::uint8:
					*(uint8_t*)value = (uint8_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int16:
				case (int)type_id::uint16:
					*(uint16_t*)value = (uint16_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int32:
				case (int)type_id::uint32:
					*(uint32_t*)value = (uint32_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::int64:
				case (int)type_id::uint64:
					*(uint64_t*)value = (uint64_t)stream->value.get_integer();
					return expectation::met;
				case (int)type_id::floatf:
					*(float*)value = (float)stream->value.get_number();
					return expectation::met;
				case (int)type_id::doublef:
					*(double*)value = (double)stream->value.get_number();
					return expectation::met;
				default:
				{
					bool managing = false;
					auto* vm = script_host::get()->get_vm();
					auto type = vm->get_type_info_by_id(value_type_id);
					auto name = type.is_valid() ? type.get_name() : std::string_view();
					if (value_type_id & (int)vitex::scripting::type_id::objhandle && !*(void**)value)
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
						if (data.size() != sizeof(algorithm::pubkeyhash))
						{
							if (!algorithm::signing::decode_address(data, ((script_address*)value)->hash))
								return layer_exception("load failed for address type");
						}
						else
							memcpy(((script_address*)value)->hash, data.data(), data.size());

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
					else if (value_type_id & (int)vitex::scripting::type_id::scriptobject)
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

			auto address = vm->set_pod<script_address>(SCRIPT_CLASS_ADDRESS);
			address->set_constructor<script_address>("void f()");
			address->set_constructor<script_address, const std::string_view&>("void f(const string_view&in)");
			address->set_constructor<script_address, const uint256_t&>("void f(const uint256&in)");
			address->set_method("string to_string() const", &script_address::to_string);
			address->set_method("uint256 to_uint256() const", &script_address::to_uint256);
			address->set_method("bool is_null() const", &script_address::is_null);
			address->set_operator_ex(operators::equals, (uint32_t)position::constant, "bool", "const address&in", &script_address::equals);

			auto program = vm->set_interface_class<script_program>(SCRIPT_CLASS_PROGRAM);
			program->set_method("bool call(const address&in, const string_view&in, const ?&in, ?&out)", &script_program::call_mutable_function);
			program->set_method("bool call(const address&in, const string_view&in, const ?&in, ?&out) const", &script_program::call_immutable_function);
			program->set_method("bool store(const address&in, const ?&in)", &script_program::store_by_address);
			program->set_method("bool store(const string_view&in, const ?&in)", &script_program::store_by_location);
			program->set_method("bool load(const address&in, ?&out) const", &script_program::load_by_address);
			program->set_method("bool load(const string_view&in, ?&out) const", &script_program::load_by_location);
			program->set_method("bool load_from(const address&in, const address&in, ?&out) const", &script_program::load_by_address);
			program->set_method("bool load_from(const address&in, const string_view&in, ?&out) const", &script_program::load_by_location);
			program->set_method("bool emit(const address&in, const ?&in)", &script_program::emit_by_address);
			program->set_method("bool emit(const string_view&in, const ?&in)", &script_program::emit_by_location);
			program->set_method("uint256 random()", &script_program::random);
			program->set_method("address from() const", &script_program::from);
			program->set_method("address to() const", &script_program::to);
			program->set_method("string blockchain() const", &script_program::blockchain);
			program->set_method("string token() const", &script_program::token);
			program->set_method("string contract() const", &script_program::contract);
			program->set_method("decimal gas_price() const", &script_program::gas_price);
			program->set_method("uint256 gas_use() const", &script_program::gas_use);
			program->set_method("uint256 gas_limit() const", &script_program::gas_limit);
			program->set_method("uint256 asset() const", &script_program::asset);
			program->set_method("uint256 parent_block_hash() const", &script_program::parent_block_hash);
			program->set_method("uint256 block_gas_use() const", &script_program::block_gas_use);
			program->set_method("uint256 block_gas_limit() const", &script_program::block_gas_limit);
			program->set_method("uint128 block_difficulty() const", &script_program::block_difficulty);
			program->set_method("uint64 block_time() const", &script_program::block_time);
			program->set_method("uint64 block_priority() const", &script_program::block_priority);
			program->set_method("uint64 block_number() const", &script_program::block_number);

			vm->begin_namespace("asset_utils");
			vm->set_function("uint256 to_asset(const string_view&in, const string_view&in = string_view(), const string_view&in = string_view())", &algorithm::asset::id_of);
			vm->set_function("string to_blockchain(const uint256&in)", &algorithm::asset::blockchain_of);
			vm->set_function("string to_token(const uint256&in)", &algorithm::asset::token_of);
			vm->set_function("string to_contract(const uint256&in)", &algorithm::asset::checksum_of);
			vm->end_namespace();

			vm->begin_namespace("byte_utils");
			vm->set_function("string encode256(const uint256&in)", &encode_bytes);
			vm->set_function("uint256 decode256(const string_view&in)", &decode_bytes);
			vm->end_namespace();

			vm->begin_namespace("hash_utils");
			vm->set_function("string crc32(const string_view&in)", &crc32);
			vm->set_function("string ripemd160(const string_view&in)", &ripe_md160);
			vm->set_function("string erecover160(const string_view&in, const string_view&in)", &erecover160);
			vm->set_function("string erecover256(const string_view&in, const string_view&in)", &erecover256);
			vm->set_function("string blake2b256(const string_view&in)", &blake2b256);
			vm->set_function("string keccak256(const string_view&in)", &keccak256);
			vm->set_function("string keccak512(const string_view&in)", &keccak512);
			vm->set_function("string sha256(const string_view&in)", &sha256);
			vm->set_function("string sha512(const string_view&in)", &sha512);
			vm->end_namespace();
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
				memcpy(hash, owner, sizeof(hash));
		}
		script_address::script_address(const std::string_view& address)
		{
			algorithm::signing::decode_address(address, hash);
		}
		script_address::script_address(const uint256_t& numeric)
		{
			uint8_t data[32];
			algorithm::encoding::decode_uint256(numeric, data);
			memcpy(hash, data, sizeof(hash));
		}
		string script_address::to_string() const
		{
			string address;
			algorithm::signing::encode_address(hash, address);
			return address;
		}
		uint256_t script_address::to_uint256() const
		{
			uint8_t data[32] = { 0 };
			memcpy(data, hash, sizeof(hash));

			uint256_t numeric = 0;
			algorithm::encoding::encode_uint256(data, numeric);
			return numeric;
		}
		bool script_address::is_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(hash, null, sizeof(null));
		}
		bool script_address::equals(const script_address& a, const script_address& b)
		{
			return !memcmp(a.hash, b.hash, sizeof(a.hash));
		}

		script_program::script_program(ledger::transaction_context* new_context) : distribution(optional::none), context(new_context)
		{
			VI_ASSERT(context != nullptr, "transaction context should be set");
		}
		expects_lr<void> script_program::initialize(compiler* compiler, const format::variables& args)
		{
			return execute(compiler, std::string_view(), args, 1, nullptr);
		}
		expects_lr<void> script_program::mutable_call(compiler* compiler, const std::string_view& function_name, const format::variables& args)
		{
			if (function_name.empty())
				return layer_exception("illegal call to function: function not found");

			return execute(compiler, function_name, args, -1, nullptr);
		}
		expects_lr<void> script_program::immutable_call(compiler* compiler, const std::string_view& function_name, const format::variables& args)
		{
			if (function_name.empty())
				return layer_exception("illegal call to function: function not found");

			return execute(compiler, function_name, args, 0, nullptr);
		}
		expects_lr<void> script_program::execute(compiler* compiler, const std::string_view& function_name, const format::variables& args, int8_t mutability, std::function<expects_lr<void>(void*, int)>&& return_callback)
		{
			if (!function_name.empty() && (function_name == SCRIPT_FUNCTION_INITIALIZE || stringify::starts_with(function_name, "_")))
				return layer_exception(stringify::text("illegal call to function \"%.*s\": illegal operation", (int)function_name.size(), function_name.data()));

			function entrypoint = compiler->get_module().get_function_by_name(function_name.empty() ? SCRIPT_FUNCTION_INITIALIZE : function_name);
			if (!entrypoint.is_valid())
			{
				if (function_name.empty())
					return expectation::met;

				return layer_exception(stringify::text("illegal call to function \"%.*s\": function not found", (int)function_name.size(), function_name.data()));
			}

			auto binders = load_arguments(entrypoint, args, mutability);
			if (!binders)
				return binders.error();

			auto* vm = entrypoint.get_vm();
			auto* caller = immediate_context::get();
			auto* coroutine = caller ? caller : vm->request_context();
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
							auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
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
		expects_lr<void> script_program::subexecute(const script_address& target, const std::string_view& function_name, void* input_value, int input_type_id, void* output_value, int output_type_id, int8_t mutability) const
		{
			if (function_name.empty())
				return layer_exception(stringify::text("illegal subcall to %s program: illegal operation", target.to_string().c_str()));

			auto link = context->get_account_program(target.hash);
			if (!link)
				return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": illegal operation", target.to_string().c_str(), (int)function_name.size(), function_name.data()));

			auto* host = ledger::script_host::get();
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, link->hashcode))
			{
				auto program = context->get_witness_program(link->hashcode);
				if (!program)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_name.size(), function_name.data(), program.error().what()));
				}

				auto code = program->as_code();
				if (!code)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_name.size(), function_name.data(), code.error().what()));
				}

				auto compilation = host->compile(*compiler, link->hashcode, *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_name.size(), function_name.data(), compilation.error().what()));
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
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_name.size(), function_name.data(), serialization.error().what()));
				}

				if (!format::variables_util::deserialize_flat_from(stream, &args))
				{
					host->deallocate(std::move(compiler));
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": argument serialization error", target.to_string().c_str(), (int)function_name.size(), function_name.data()));
				}
			}

			auto transaction = transactions::invocation();
			transaction.set_asset("ETH");
			transaction.set_calldata(target.hash, algorithm::hashing::hash32d(link->hashcode), function_name, std::move(args));
			transaction.gas_price = context->transaction->gas_price;
			transaction.gas_limit = context->get_gas_left();
			transaction.nonce = 0;

			ledger::receipt receipt;
			receipt.transaction_hash = transaction.as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.absolute_gas_use = context->block->gas_use;
			receipt.block_number = context->block->number;
			memcpy(receipt.from, to().hash, sizeof(receipt.from));

			auto next = transaction_context(context->block, context->environment, &transaction, std::move(receipt));
			auto* prev = context;
			auto* main = (script_program*)this;
			main->context = &next;

			auto execution = main->execute(*compiler, function_name, transaction.args, mutability, [&target, &function_name, output_value, output_type_id](void* address, int type_id) -> expects_lr<void>
			{
				format::stream stream;
				auto serialization = script_marshalling::store(&stream, address, type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": return serialization error", target.to_string().c_str(), (int)function_name.size(), function_name.data()));

				serialization = script_marshalling::load(stream, output_value, output_type_id);
				if (!serialization)
					return layer_exception(stringify::text("illegal subcall to %s program on function \"%.*s\": %s", target.to_string().c_str(), (int)function_name.size(), function_name.data(), serialization.error().what()));

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
						case (int)type_id::boolf:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)args[index].as_boolean()); });
							break;
						case (int)type_id::int8:
						case (int)type_id::uint8:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg8(i, (uint8_t)args[index].as_uint8()); });
							break;
						case (int)type_id::int16:
						case (int)type_id::uint16:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg16(i, (uint16_t)args[index].as_uint16()); });
							break;
						case (int)type_id::int32:
						case (int)type_id::uint32:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg32(i, (uint32_t)args[index].as_uint32()); });
							break;
						case (int)type_id::int64:
						case (int)type_id::uint64:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg64(i, (uint64_t)args[index].as_uint64()); });
							break;
						case (int)type_id::floatf:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg_float(i, (float)args[index].as_float()); });
							break;
						case (int)type_id::doublef:
							frames.emplace_back([i, index, &args](immediate_context* coroutine) { coroutine->set_arg_double(i, (double)args[index].as_double()); });
							break;
						default:
						{
							void* address = nullptr;
							auto& value = args[index];
							format::stream stream;
							format::variables_util::serialize_flat_into({ value }, &stream);
							auto status = script_marshalling::load(stream, (void*)&address, type_id | (int)vitex::scripting::type_id::objhandle);
							if (!status)
							{
								stream = format::stream::decode(value.as_string());
								status = script_marshalling::load(stream, (void*)&address, type_id | (int)vitex::scripting::type_id::objhandle);
								if (!status)
									return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program (%s)", entrypoint.get_decl().data(), i, status.error().what()));
							}

							auto object = uscript_object(vm, type.get_type_info(), address);
							frames.emplace_back([i, type_id, object = std::move(object)](immediate_context* coroutine) mutable { coroutine->set_arg_object(i, type_id & (int)vitex::scripting::type_id::objhandle ? (void*)&object.address : (void*)object.address); });
							break;
						}
					}
				}
				else
				{
					if (!type.is_valid() || type.get_name() != SCRIPT_CLASS_PROGRAM)
						return layer_exception(stringify::text("illegal call to function \"%s\": argument #%i not bound to program", entrypoint.get_decl().data()));

					bool is_const = mutability == 0;
					if (mutability != -1 && is_const != (!!(flags & (size_t)modifiers::constf)))
						return layer_exception(stringify::text("illegal call to function \"%s\": mutability not preserved", entrypoint.get_decl().data()));

					frames.emplace_back([i, index, &args, this](immediate_context* coroutine) { coroutine->set_arg_object(i, (script_program*)this); });
				}
			}
			return std::move(frames);
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
		bool script_program::call_mutable_function(const script_address& target, const std::string_view& function, void* input_value, int input_type_id, void* output_value, int output_type_id)
		{
			auto execution = subexecute(target, function, input_value, input_type_id, output_value, output_type_id, -1);
			if (!execution)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
				return false;
			}

			return true;
		}
		bool script_program::call_immutable_function(const script_address& target, const std::string_view& function, void* input_value, int input_type_id, void* output_value, int output_type_id) const
		{
			auto execution = subexecute(target, function, input_value, input_type_id, output_value, output_type_id, 0);
			if (!execution)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_EXECUTION, execution.error().message()));
				return false;
			}

			return true;
		}
		bool script_program::store_by_address(const script_address& location, const void* object_value, int object_type_id)
		{
			string data = string((char*)location.hash, sizeof(location.hash));
			return store_by_location(data, object_value, object_type_id);
		}
		bool script_program::store_by_location(const std::string_view& location, const void* object_value, int object_type_id)
		{
			if (!object_value)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "store not supported for null value"));
				return false;
			}
			else if (location.size() > std::numeric_limits<uint8_t>::max())
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "store location max length is 256 bytes"));
				return false;
			}

			format::stream stream;
			auto status = script_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			auto data = context->apply_account_storage(to().hash, location, stream.data);
			if (!data)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
				return false;
			}

			return true;
		}
		bool script_program::load_by_address(const script_address& location, void* object_value, int object_type_id) const
		{
			return load_from_by_address(to(), location, object_value, object_type_id);
		}
		bool script_program::load_by_location(const std::string_view& location, void* object_value, int object_type_id) const
		{
			return load_from_by_location(to(), location, object_value, object_type_id);
		}
		bool script_program::load_from_by_address(const script_address& target, const script_address& location, void* object_value, int object_type_id) const
		{
			string data = string((char*)location.hash, sizeof(location.hash));
			return load_from_by_location(target, data, object_value, object_type_id);
		}
		bool script_program::load_from_by_location(const script_address& target, const std::string_view& location, void* object_value, int object_type_id) const
		{
			if (!object_value)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "load not supported for null value"));
				return false;
			}
			else if (location.size() > std::numeric_limits<uint8_t>::max())
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "load location max length is 256 bytes"));
				return false;
			}

			auto data = context->get_account_storage(target.hash, location);
			if (!data || data->storage.empty())
				return false;

			format::stream stream = format::stream(data->storage);
			auto status = script_marshalling::load(stream, object_value, object_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			return true;
		}
		bool script_program::emit_by_address(const script_address& location, const void* object_value, int object_type_id)
		{
			string data = string((char*)location.hash, sizeof(location.hash));
			return emit_by_location(data, object_value, object_type_id);
		}
		bool script_program::emit_by_location(const std::string_view& location, const void* object_value, int object_type_id)
		{
			if (!object_value)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit not supported for null value"));
				return false;
			}
			else if (location.size() > std::numeric_limits<uint8_t>::max())
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit location max length is 256 bytes"));
				return false;
			}

			format::stream stream;
			auto status = script_marshalling::store(&stream, (void*)object_value, object_type_id);
			if (!status)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, status.error().message()));
				return false;
			}

			format::variables returns;
			if (!format::variables_util::deserialize_flat_from(stream, &returns))
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit value conversion error"));
				return false;
			}

			auto type = script_host::get()->get_vm()->get_type_info_by_id(object_type_id);
			auto name = type.is_valid() ? type.get_name() : std::string_view("primitive");
			auto data = context->emit_event(algorithm::hashing::hash32d(name), std::move(returns));
			if (!data)
			{
				bindings::exception::throw_ptr(bindings::exception::pointer(SCRIPT_EXCEPTION_STORAGE, data.error().message()));
				return false;
			}

			return true;
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
			auto index = environment.validation.context.get_account_program(to().hash);
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

			auto execution = execute(*compiler, function, args, mutability, [this](void* address, int type_id) -> expects_lr<void>
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
			data->set("from", algorithm::signing::serialize_address(((script_program_trace*)this)->from().hash));
			data->set("to", algorithm::signing::serialize_address(((script_program_trace*)this)->to().hash));
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
