#include "script.h"
#include <sstream>
extern "C"
{
#include "../../utils/trezor-crypto/sha2.h"
#include "../../utils/trezor-crypto/sha3.h"
}
#include "../policy/transactions.h"
#ifdef TAN_VALIDATOR
#include "../storage/chainstate.h"
#endif
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

namespace Tangent
{
	namespace Ledger
	{
		struct UScriptObject
		{
			VirtualMachine* VM;
			asITypeInfo* Type;
			void* Address;

			UScriptObject(VirtualMachine* NewVM, asITypeInfo* NewType, void* NewAddress) noexcept : VM(NewVM), Type(NewType), Address(NewAddress)
			{
			}
			UScriptObject(const UScriptObject& Other) noexcept : VM(Other.VM), Type(Other.Type), Address(Other.Address)
			{
				((UScriptObject*)&Other)->Address = nullptr;
			}
			UScriptObject(UScriptObject&& Other) noexcept : VM(Other.VM), Type(Other.Type), Address(Other.Address)
			{
				Other.Address = nullptr;
			}
			~UScriptObject()
			{
				Destroy();
			}
			UScriptObject& operator= (const UScriptObject& Other) noexcept
			{
				if (this == &Other)
					return *this;

				Destroy();
				VM = Other.VM;
				Type = Other.Type;
				Address = Other.Address;
				((UScriptObject*)&Other)->Address = nullptr;
				return *this;
			}
			UScriptObject& operator= (UScriptObject&& Other) noexcept
			{
				if (this == &Other)
					return *this;

				Destroy();
				VM = Other.VM;
				Type = Other.Type;
				Address = Other.Address;
				Other.Address = nullptr;
				return *this;
			}
			inline void Destroy()
			{
				if (VM != nullptr && Type != nullptr && Address != nullptr)
					VM->ReleaseObject(Address, TypeInfo(Type));
			}
		};

		static String Crc32(const std::string_view& Data)
		{
			uint8_t Buffer[32];
			uint256_t Value = Algorithm::Hashing::Hash32d(Data);
			Algorithm::Encoding::DecodeUint256(Value, Buffer);
			return String((char*)Buffer + (sizeof(uint256_t) - sizeof(uint32_t)), sizeof(uint32_t));
		}
		static String RipeMD160(const std::string_view& Data)
		{
			return Algorithm::Hashing::Hash160((uint8_t*)Data.data(), Data.size());
		}
		static String ERecover160(const uint256_t& Hash, const std::string_view& Signature)
		{
			if (Signature.size() != sizeof(Algorithm::Sighash))
				return String();

			Algorithm::Pubkeyhash PublicKeyHash = { 0 }, Null = { 0 };
			if (!Algorithm::Signing::RecoverNormalHash(Hash, PublicKeyHash, (uint8_t*)Signature.data()) || !memcmp(PublicKeyHash, Null, sizeof(Null)))
				return String();

			return String((char*)PublicKeyHash, sizeof(PublicKeyHash));
		}
		static String ERecover160T(const uint256_t& Hash, const std::string_view& Signature)
		{
			if (Signature.size() != sizeof(Algorithm::Sighash))
				return String();

			Algorithm::Pubkeyhash PublicKeyHash = { 0 }, Null = { 0 };
			if (!Algorithm::Signing::RecoverTweakedHash(Hash, PublicKeyHash, (uint8_t*)Signature.data()) || !memcmp(PublicKeyHash, Null, sizeof(Null)))
				return String();

			return String((char*)PublicKeyHash, sizeof(PublicKeyHash));
		}
		static String ERecover256T(const uint256_t& Hash, const std::string_view& Signature)
		{
			if (Signature.size() != sizeof(Algorithm::Sighash))
				return String();

			Algorithm::Pubkey PublicKey = { 0 }, Null = { 0 };
			if (!Algorithm::Signing::RecoverTweaked(Hash, PublicKey, (uint8_t*)Signature.data()) || !memcmp(PublicKey, Null, sizeof(Null)))
				return String();

			return String((char*)PublicKey, sizeof(PublicKey));
		}
		static String ERecover256(const uint256_t& Hash, const std::string_view& Signature)
		{
			if (Signature.size() != sizeof(Algorithm::Sighash))
				return String();

			Algorithm::Pubkey PublicKey = { 0 }, Null = { 0 };
			if (!Algorithm::Signing::RecoverNormal(Hash, PublicKey, (uint8_t*)Signature.data()) || !memcmp(PublicKey, Null, sizeof(Null)))
				return String();

			return String((char*)PublicKey, sizeof(PublicKey));
		}
		static String Blake2b256(const std::string_view& Data)
		{
			return Algorithm::Hashing::Hash256((uint8_t*)Data.data(), Data.size());
		}
		static String Keccak256(const std::string_view& Data)
		{
			uint8_t Buffer[SHA3_256_DIGEST_LENGTH];
			sha256_Raw((uint8_t*)Data.data(), Data.size(), Buffer);
			return String((char*)Buffer, sizeof(Buffer));
		}
		static String Keccak512(const std::string_view& Data)
		{
			uint8_t Buffer[SHA3_512_DIGEST_LENGTH];
			keccak_512((uint8_t*)Data.data(), Data.size(), Buffer);
			return String((char*)Buffer, sizeof(Buffer));
		}
		static String Sha256(const std::string_view& Data)
		{
			uint8_t Buffer[SHA3_256_DIGEST_LENGTH];
			keccak_256((uint8_t*)Data.data(), Data.size(), Buffer);
			return String((char*)Buffer, sizeof(Buffer));
		}
		static String Sha512(const std::string_view& Data)
		{
			return Algorithm::Hashing::Hash512((uint8_t*)Data.data(), Data.size());
		}
		static String EncodeBytes(const uint256_t& Value)
		{
			uint8_t Data[32];
			Algorithm::Encoding::DecodeUint256(Value, Data);
			return String((char*)Data, sizeof(Data));
		}
		static uint256_t DecodeBytes(const std::string_view& Value)
		{
			uint8_t Data[32];
			memcpy(Data, Value.data(), std::min(sizeof(Data), Value.size()));

			uint256_t Buffer;
			Algorithm::Encoding::EncodeUint256(Data, Buffer);
			return Buffer;
		}
		
		ExpectsLR<void> ScriptMarshalling::Store(Format::Stream* Stream, void* Value, int ValueTypeId)
		{
			switch (ValueTypeId)
			{
				case (int)TypeId::VOIDF:
					return LayerException("store not supported for void type");
				case (int)TypeId::BOOL:
					Stream->WriteBoolean(*(bool*)Value);
					return Expectation::Met;
				case (int)TypeId::INT8:
				case (int)TypeId::UINT8:
					Stream->WriteInteger(*(uint8_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT16:
				case (int)TypeId::UINT16:
					Stream->WriteInteger(*(uint16_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT32:
				case (int)TypeId::UINT32:
					Stream->WriteInteger(*(uint32_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT64:
				case (int)TypeId::UINT64:
					Stream->WriteInteger(*(uint64_t*)Value);
					return Expectation::Met;
				case (int)TypeId::FLOAT:
					Stream->WriteDecimal(Decimal(*(float*)Value));
					return Expectation::Met;
				case (int)TypeId::DOUBLE:
					Stream->WriteDecimal(Decimal(*(double*)Value));
					return Expectation::Met;
				default:
				{
					auto Type = ScriptHost::Get()->GetVM()->GetTypeInfoById(ValueTypeId);
					auto Typename = Type.IsValid() ? Type.GetName() : std::string_view();
					Value = ValueTypeId & (int)Vitex::Scripting::TypeId::OBJHANDLE ? *(void**)Value : Value;
					if (Typename == SCRIPT_CLASS_STRINGVIEW)
					{
						Stream->WriteString(*(std::string_view*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_ADDRESS)
					{
						Stream->WriteString(Format::Util::Encode0xHex(std::string_view((char*)((ScriptAddress*)Value)->Hash, sizeof(Algorithm::Pubkeyhash))));
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_STRING)
					{
						Stream->WriteString(*(String*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT128)
					{
						Stream->WriteInteger(*(uint128_t*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT256)
					{
						Stream->WriteInteger(*(uint256_t*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_DECIMAL)
					{
						Stream->WriteDecimal(*(Decimal*)Value);
						return Expectation::Met;
					}
					else if (ValueTypeId & (int)Vitex::Scripting::TypeId::SCRIPTOBJECT)
					{
						auto Object = ScriptObject((asIScriptObject*)Value);
						size_t Properties = Object.GetPropertiesCount();
						for (size_t i = 0; i < Properties; i++)
						{
							void* Address = Object.GetAddressOfProperty(i);
							int TypeId = Object.GetPropertyTypeId(i);
							auto Status = Store(Stream, Address, TypeId);
							if (!Status)
								return Status;
						}
						return Expectation::Met;
					}
					return LayerException(Stringify::Text("store not supported for %s type", Typename.data()));
				}
			}
		}
		ExpectsLR<void> ScriptMarshalling::Store(Schema* Stream, void* Value, int ValueTypeId)
		{
			switch (ValueTypeId)
			{
				case (int)TypeId::VOIDF:
					return LayerException("store not supported for void type");
				case (int)TypeId::BOOL:
					Stream->Value = Var::Boolean(*(bool*)Value);
					return Expectation::Met;
				case (int)TypeId::INT8:
				case (int)TypeId::UINT8:
					Stream->Value = Var::Integer(*(uint8_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT16:
				case (int)TypeId::UINT16:
					Stream->Value = Var::Integer(*(uint16_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT32:
				case (int)TypeId::UINT32:
					Stream->Value = Var::Integer(*(uint32_t*)Value);
					return Expectation::Met;
				case (int)TypeId::INT64:
				case (int)TypeId::UINT64:
					Stream->Value = Var::Integer(*(uint64_t*)Value);
					return Expectation::Met;
				case (int)TypeId::FLOAT:
					Stream->Value = Var::Number(*(float*)Value);
					return Expectation::Met;
				case (int)TypeId::DOUBLE:
					Stream->Value = Var::Number(*(double*)Value);
					return Expectation::Met;
				default:
				{
					auto Type = ScriptHost::Get()->GetVM()->GetTypeInfoById(ValueTypeId);
					auto Typename = Type.IsValid() ? Type.GetName() : std::string_view();
					Value = ValueTypeId & (int)Vitex::Scripting::TypeId::OBJHANDLE ? *(void**)Value : Value;
					if (Typename == SCRIPT_CLASS_STRINGVIEW)
					{
						Stream->Value = Var::String(*(std::string_view*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_ADDRESS)
					{
						UPtr<Schema> Data = Algorithm::Signing::SerializeAddress(((ScriptAddress*)Value)->Hash);
						Stream->Value = std::move(Data->Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_STRING)
					{
						Stream->Value = Var::String(*(String*)Value);
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT128)
					{
						Stream->Value = Var::DecimalString(((uint128_t*)Value)->ToString());
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT256)
					{
						Stream->Value = Var::DecimalString(((uint256_t*)Value)->ToString());
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_DECIMAL)
					{
						Stream->Value = Var::Decimal(*(Decimal*)Value);
						return Expectation::Met;
					}
					else if (ValueTypeId & (int)Vitex::Scripting::TypeId::SCRIPTOBJECT)
					{
						auto Object = ScriptObject((asIScriptObject*)Value);
						size_t Properties = Object.GetPropertiesCount();
						for (size_t i = 0; i < Properties; i++)
						{
							std::string_view Name = Object.GetPropertyName(i);
							void* Address = Object.GetAddressOfProperty(i);
							int TypeId = Object.GetPropertyTypeId(i);
							auto Status = Store(Stream->Set(Name, Var::Undefined()), Address, TypeId);
							if (!Status)
								return Status;
						}
						return Expectation::Met;
					}
					return LayerException(Stringify::Text("store not supported for %s type", Typename.data()));
				}
			}
		}
		ExpectsLR<void> ScriptMarshalling::Load(Format::Stream& Stream, void* Value, int ValueTypeId)
		{
			switch (ValueTypeId)
			{
				case (int)TypeId::VOIDF:
					return LayerException("load not supported for void type");
				case (int)TypeId::BOOL:
					if (!Stream.ReadBoolean(Stream.ReadType(), (bool*)Value))
						return LayerException("load failed for bool type");
					return Expectation::Met;
				case (int)TypeId::INT8:
				case (int)TypeId::UINT8:
					if (!Stream.ReadInteger(Stream.ReadType(), (uint8_t*)Value))
						return LayerException("load failed for uint8 type");
					return Expectation::Met;
				case (int)TypeId::INT16:
				case (int)TypeId::UINT16:
					if (!Stream.ReadInteger(Stream.ReadType(), (uint16_t*)Value))
						return LayerException("load failed for uint16 type");
					return Expectation::Met;
				case (int)TypeId::INT32:
				case (int)TypeId::UINT32:
					if (!Stream.ReadInteger(Stream.ReadType(), (uint32_t*)Value))
						return LayerException("load failed for uint32 type");
					return Expectation::Met;
				case (int)TypeId::INT64:
				case (int)TypeId::UINT64:
					if (!Stream.ReadInteger(Stream.ReadType(), (uint64_t*)Value))
						return LayerException("load failed for uint64 type");
					return Expectation::Met;
				case (int)TypeId::FLOAT:
				{
					Decimal Wrapper;
					if (!Stream.ReadDecimal(Stream.ReadType(), &Wrapper))
						return LayerException("load failed for float type");

					*(float*)Value = Wrapper.ToFloat();
					return Expectation::Met;
				}
				case (int)TypeId::DOUBLE:
				{
					Decimal Wrapper;
					if (!Stream.ReadDecimal(Stream.ReadType(), &Wrapper))
						return LayerException("load failed for double type");

					*(double*)Value = Wrapper.ToDouble();
					return Expectation::Met;
				}
				default:
				{
					bool Managing = false;
					auto* VM = ScriptHost::Get()->GetVM();
					auto Type = VM->GetTypeInfoById(ValueTypeId);
					auto Typename = Type.IsValid() ? Type.GetName() : std::string_view();
					if (ValueTypeId & (int)Vitex::Scripting::TypeId::OBJHANDLE && !*(void**)Value)
					{
						void* Address = VM->CreateObject(Type);
						if (!Address)
							return LayerException(Stringify::Text("allocation failed for %s type", Typename.data()));

						*(void**)Value = Address;
						Value = Address;
						Managing = true;
					}

					auto Unique = UScriptObject(VM, Type.GetTypeInfo(), Managing ? Value : nullptr);
					if (Typename == SCRIPT_CLASS_ADDRESS)
					{
						String Data;
						if (!Stream.ReadString(Stream.ReadType(), &Data))
							return LayerException("load failed for address type");

						Data = Format::Util::IsHexEncoding(Data) ? Format::Util::Decode0xHex(Data) : Data;
						if (Data.size() != sizeof(Algorithm::Pubkeyhash))
						{
							if (!Algorithm::Signing::DecodeAddress(Data, ((ScriptAddress*)Value)->Hash))
								return LayerException("load failed for address type");
						}
						else
							memcpy(((ScriptAddress*)Value)->Hash, Data.data(), Data.size());

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_STRING)
					{
						if (!Stream.ReadString(Stream.ReadType(), (String*)Value))
							return LayerException("load failed for string type");

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT128)
					{
						if (!Stream.ReadInteger(Stream.ReadType(), (uint128_t*)Value))
							return LayerException("load failed for uint128 type");

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT256)
					{
						if (!Stream.ReadInteger(Stream.ReadType(), (uint256_t*)Value))
							return LayerException("load failed for uint256 type");

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_DECIMAL)
					{
						if (!Stream.ReadDecimal(Stream.ReadType(), (Decimal*)Value))
							return LayerException("load failed for decimal type");

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (ValueTypeId & (int)Vitex::Scripting::TypeId::SCRIPTOBJECT)
					{
						auto Object = ScriptObject((asIScriptObject*)Value);
						size_t Properties = Object.GetPropertiesCount();
						for (size_t i = 0; i < Properties; i++)
						{
							void* Address = Object.GetAddressOfProperty(i);
							int TypeId = Object.GetPropertyTypeId(i);
							auto Status = Load(Stream, Address, TypeId);
							if (!Status)
								return Status;
						}

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					return LayerException(Stringify::Text("load not supported for %s type", Typename.data()));
				}
			}
		}
		ExpectsLR<void> ScriptMarshalling::Load(Schema* Stream, void* Value, int ValueTypeId)
		{
			switch (ValueTypeId)
			{
				case (int)TypeId::VOIDF:
					return LayerException("load not supported for void type");
				case (int)TypeId::BOOL:
					*(bool*)Value = Stream->Value.GetBoolean();
					return Expectation::Met;
				case (int)TypeId::INT8:
				case (int)TypeId::UINT8:
					*(uint8_t*)Value = (uint8_t)Stream->Value.GetInteger();
					return Expectation::Met;
				case (int)TypeId::INT16:
				case (int)TypeId::UINT16:
					*(uint16_t*)Value = (uint16_t)Stream->Value.GetInteger();
					return Expectation::Met;
				case (int)TypeId::INT32:
				case (int)TypeId::UINT32:
					*(uint32_t*)Value = (uint32_t)Stream->Value.GetInteger();
					return Expectation::Met;
				case (int)TypeId::INT64:
				case (int)TypeId::UINT64:
					*(uint64_t*)Value = (uint64_t)Stream->Value.GetInteger();
					return Expectation::Met;
				case (int)TypeId::FLOAT:
					*(float*)Value = (float)Stream->Value.GetNumber();
					return Expectation::Met;
				case (int)TypeId::DOUBLE:
					*(double*)Value = (double)Stream->Value.GetNumber();
					return Expectation::Met;
				default:
				{
					bool Managing = false;
					auto* VM = ScriptHost::Get()->GetVM();
					auto Type = VM->GetTypeInfoById(ValueTypeId);
					auto Typename = Type.IsValid() ? Type.GetName() : std::string_view();
					if (ValueTypeId & (int)Vitex::Scripting::TypeId::OBJHANDLE && !*(void**)Value)
					{
						void* Address = VM->CreateObject(Type);
						if (!Address)
							return LayerException(Stringify::Text("allocation failed for %s type", Typename.data()));

						*(void**)Value = Address;
						Value = Address;
						Managing = true;
					}

					auto Unique = UScriptObject(VM, Type.GetTypeInfo(), Managing ? Value : nullptr);
					if (Typename == SCRIPT_CLASS_ADDRESS)
					{
						String Data = Stream->Value.GetBlob();
						Data = Format::Util::IsHexEncoding(Data) ? Format::Util::Decode0xHex(Data) : Data;
						if (Data.size() != sizeof(Algorithm::Pubkeyhash))
						{
							if (!Algorithm::Signing::DecodeAddress(Data, ((ScriptAddress*)Value)->Hash))
								return LayerException("load failed for address type");
						}
						else
							memcpy(((ScriptAddress*)Value)->Hash, Data.data(), Data.size());

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_STRING)
					{
						*(String*)Value = Stream->Value.GetBlob();
						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT128)
					{
						*(uint128_t*)Value = uint128_t(Stream->Value.GetDecimal().ToString());
						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_UINT256)
					{
						*(uint256_t*)Value = uint256_t(Stream->Value.GetDecimal().ToString());
						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (Typename == SCRIPT_CLASS_DECIMAL)
					{
						*(Decimal*)Value = Stream->Value.GetDecimal();
						Unique.Address = nullptr;
						return Expectation::Met;
					}
					else if (ValueTypeId & (int)Vitex::Scripting::TypeId::SCRIPTOBJECT)
					{
						auto Object = ScriptObject((asIScriptObject*)Value);
						size_t Properties = Object.GetPropertiesCount();
						for (size_t i = 0; i < Properties; i++)
						{
							std::string_view Name = Object.GetPropertyName(i);
							auto* Substream = Stream->Get(Name);
							if (!Substream)
								return LayerException(Stringify::Text("load failed for %s type while searching for %s property", Typename.data(), Name.data()));

							void* Address = Object.GetAddressOfProperty(i);
							int TypeId = Object.GetPropertyTypeId(i);
							auto Status = Load(Substream, Address, TypeId);
							if (!Status)
								return Status;
						}

						Unique.Address = nullptr;
						return Expectation::Met;
					}
					return LayerException(Stringify::Text("load not supported for %s type", Typename.data()));
				}
			}
		}

		ScriptHost::ScriptHost() noexcept
		{
			Preprocessor::Desc CompilerFeatures;
			CompilerFeatures.Conditions = false;
			CompilerFeatures.Defines = false;
			CompilerFeatures.Includes = false;
			CompilerFeatures.Pragmas = false;

			VM = new VirtualMachine();
			VM->SetCompilerFeatures(CompilerFeatures);
			VM->SetLibraryProperty(LibraryFeatures::PromiseNoConstructor, 1);
			VM->SetLibraryProperty(LibraryFeatures::PromiseNoCallbacks, 1);
			VM->SetLibraryProperty(LibraryFeatures::CTypesNoPointerCast, 1);
			VM->SetProperty(Features::DISALLOW_GLOBAL_VARS, 1);
			VM->SetTsImports(false);
			VM->SetCache(false);

			Bindings::Registry::ImportCTypes(*VM);
			Bindings::Registry::ImportArray(*VM);
			Bindings::Registry::ImportSafeString(*VM);
			Bindings::Registry::ImportException(*VM);
			Bindings::Registry::ImportDecimal(*VM);
			Bindings::Registry::ImportUInt128(*VM);
			Bindings::Registry::ImportUInt256(*VM);

			auto Address = VM->SetPod<ScriptAddress>(SCRIPT_CLASS_ADDRESS);
			Address->SetConstructor<ScriptAddress>("void f()");
			Address->SetConstructor<ScriptAddress, const std::string_view&>("void f(const string_view&in)");
			Address->SetConstructor<ScriptAddress, const uint256_t&>("void f(const uint256&in)");
			Address->SetMethod("string to_string() const", &ScriptAddress::ToString);
			Address->SetMethod("uint256 to_uint256() const", &ScriptAddress::ToUint256);
			Address->SetMethod("bool is_null() const", &ScriptAddress::IsNull);
			Address->SetOperatorEx(Operators::Equals, (uint32_t)Position::Const, "bool", "const address&in", &ScriptAddress::Equals);

			auto Program = VM->SetInterfaceClass<ScriptProgram>(SCRIPT_CLASS_PROGRAM);
			Program->SetMethod("bool call(const address&in, const string_view&in, const ?&in, ?&out)", &ScriptProgram::CallMutableFunction);
			Program->SetMethod("bool call(const address&in, const string_view&in, const ?&in, ?&out) const", &ScriptProgram::CallImmutableFunction);
			Program->SetMethod("bool store(const address&in, const ?&in)", &ScriptProgram::StoreByAddress);
			Program->SetMethod("bool store(const string_view&in, const ?&in)", &ScriptProgram::StoreByLocation);
			Program->SetMethod("bool load(const address&in, ?&out) const", &ScriptProgram::LoadByAddress);
			Program->SetMethod("bool load(const string_view&in, ?&out) const", &ScriptProgram::LoadByLocation);
			Program->SetMethod("bool load_from(const address&in, const address&in, ?&out) const", &ScriptProgram::LoadByAddress);
			Program->SetMethod("bool load_from(const address&in, const string_view&in, ?&out) const", &ScriptProgram::LoadByLocation);
			Program->SetMethod("bool emit(const address&in, const ?&in)", &ScriptProgram::EmitByAddress);
			Program->SetMethod("bool emit(const string_view&in, const ?&in)", &ScriptProgram::EmitByLocation);
			Program->SetMethod("bool transfer(const address&in, const uint256&in, const decimal&in)", &ScriptProgram::Transfer);
			Program->SetMethod("uint64 account_sequence_of(const address&in)", &ScriptProgram::AccountSequenceOf);
			Program->SetMethod("uint256 account_work_of(const address&in)", &ScriptProgram::AccountWorkOf);
			Program->SetMethod("string account_program_of(const address&in)", &ScriptProgram::AccountProgramOf);
			Program->SetMethod("decimal account_incoming_reward_of(const address&in, const uint256&in, const decimal&in)", &ScriptProgram::AccountIncomingRewardOf);
			Program->SetMethod("decimal account_outgoing_reward_of(const address&in, const uint256&in, const decimal&in)", &ScriptProgram::AccountOutgoingRewardOf);
			Program->SetMethod("uint64 account_derivation_of(const address&in, const uint256&in)", &ScriptProgram::AccountDerivationOf);
			Program->SetMethod("decimal account_balance_of(const address&in, const uint256&in)", &ScriptProgram::AccountBalanceOf);
			Program->SetMethod("decimal account_contribution_of(const address&in, const uint256&in)", &ScriptProgram::AccountContributionOf);
			Program->SetMethod("bool has_witness_program_of(const string_view&in)", &ScriptProgram::HasWitnessProgramOf);
			Program->SetMethod("uint256 witness_event_of(const uint256&in)", &ScriptProgram::WitnessEventOf);
			Program->SetMethod("address witness_address_of(const uint256&in, const string_view&in, uint64, usize)", &ScriptProgram::WitnessAddressOf);
			Program->SetMethod("bool has_witness_transaction_of(const uint256&in, const string_view&in)", &ScriptProgram::HasWitnessTransactionOf);
			Program->SetMethod("uint256 random()", &ScriptProgram::Random);
			Program->SetMethod("address from() const", &ScriptProgram::From);
			Program->SetMethod("address to() const", &ScriptProgram::To);
			Program->SetMethod("string blockchain() const", &ScriptProgram::Blockchain);
			Program->SetMethod("string token() const", &ScriptProgram::Token);
			Program->SetMethod("string contract() const", &ScriptProgram::Contract);
			Program->SetMethod("decimal gas_price() const", &ScriptProgram::GasPrice);
			Program->SetMethod("uint256 gas_use() const", &ScriptProgram::GasUse);
			Program->SetMethod("uint256 gas_limit() const", &ScriptProgram::GasLimit);
			Program->SetMethod("uint256 asset() const", &ScriptProgram::Asset);
			Program->SetMethod("uint256 parent_block_hash() const", &ScriptProgram::ParentBlockHash);
			Program->SetMethod("uint256 block_gas_use() const", &ScriptProgram::BlockGasUse);
			Program->SetMethod("uint256 block_gas_limit() const", &ScriptProgram::BlockGasLimit);
			Program->SetMethod("uint128 block_difficulty() const", &ScriptProgram::BlockDifficulty);
			Program->SetMethod("uint64 block_time() const", &ScriptProgram::BlockTime);
			Program->SetMethod("uint64 block_priority() const", &ScriptProgram::BlockPriority);
			Program->SetMethod("uint64 block_number() const", &ScriptProgram::BlockNumber);

			VM->BeginNamespace("asset_utils");
			VM->SetFunction("uint256 to_asset(const string_view&in, const string_view&in = string_view(), const string_view&in = string_view())", &Algorithm::Asset::IdOf);
			VM->SetFunction("string to_blockchain(const uint256&in)", &Algorithm::Asset::BlockchainOf);
			VM->SetFunction("string to_token(const uint256&in)", &Algorithm::Asset::TokenOf);
			VM->SetFunction("string to_contract(const uint256&in)", &Algorithm::Asset::ChecksumOf);
			VM->EndNamespace();

			VM->BeginNamespace("byte_utils");
			VM->SetFunction("string encode256(const uint256&in)", &EncodeBytes);
			VM->SetFunction("uint256 decode256(const string_view&in)", &DecodeBytes);
			VM->EndNamespace();

			VM->BeginNamespace("hash_utils");
			VM->SetFunction("string crc32(const string_view&in)", &Crc32);
			VM->SetFunction("string ripemd160(const string_view&in)", &RipeMD160);
			VM->SetFunction("string erecover160(const string_view&in, const string_view&in)", &ERecover160);
			VM->SetFunction("string erecover160t(const string_view&in, const string_view&in)", &ERecover160T);
			VM->SetFunction("string erecover256(const string_view&in, const string_view&in)", &ERecover256);
			VM->SetFunction("string erecover256t(const string_view&in, const string_view&in)", &ERecover256T);
			VM->SetFunction("string blake2b256(const string_view&in)", &Blake2b256);
			VM->SetFunction("string keccak256(const string_view&in)", &Keccak256);
			VM->SetFunction("string keccak512(const string_view&in)", &Keccak512);
			VM->SetFunction("string sha256(const string_view&in)", &Sha256);
			VM->SetFunction("string sha512(const string_view&in)", &Sha512);
			VM->EndNamespace();
		}
		ScriptHost::~ScriptHost() noexcept
		{
			for (auto& Link : Modules)
				Module(Link.second).Discard();
			Modules.clear();
		}
		UPtr<Compiler> ScriptHost::Allocate()
		{
			UMutex<std::mutex> Unique(Mutex);
			if (!Compilers.empty())
			{
				auto Compiler = std::move(Compilers.front());
				Compilers.pop();
				return Compiler;
			}

			UPtr<Compiler> Compiler = VM->CreateCompiler();
			Compiler->Clear();
			return Compiler;
		}
		void ScriptHost::Deallocate(UPtr<Compiler>&& Compiler)
		{
			if (!Compiler)
				return;

			UMutex<std::mutex> Unique(Mutex);
			Compiler->UnlinkModule();
			Compilers.push(std::move(Compiler));
		}
		ExpectsLR<void> ScriptHost::Compile(Compiler* Compiler, const std::string_view& ProgramHashcode, const std::string_view& UnpackedProgramCode)
		{
			VI_ASSERT(Compiler != nullptr, "compiler should not be null");
			String Messages, Id = String(ProgramHashcode), Scope = Format::Util::Encode0xHex(ProgramHashcode);
			VM->SetCompileCallback(Scope, [&Messages](const std::string_view& Message) { Messages.append(Message).append("\r\n"); });

			auto Preparation = Compiler->Prepare(Scope, true);
			if (!Preparation)
			{
				Messages.append("ERR preparation failed: " + Preparation.Error().message() + "\r\n");
			Error:
				VM->SetCompileCallback(Scope, nullptr);
				return LayerException(std::move(Messages));
			}

			auto Injection = Compiler->LoadCode(Scope, UnpackedProgramCode);
			if (!Injection)
			{
				Messages.append("ERR injection failed: " + Injection.Error().message() + "\r\n");
				goto Error;
			}

			auto Compilation = Compiler->CompileSync();
			if (!Compilation)
			{
				Messages.append("ERR compilation failed: " + Compilation.Error().message() + "\r\n");
				goto Error;
			}

			UnorderedSet<String> Mapping;
			auto Module = Compiler->GetModule();
			size_t Functions = Module.GetFunctionCount();
			for (size_t i = 0; i < Functions; i++)
			{
				auto Function = Module.GetFunctionByIndex(i);
				String Name = String(Function.GetName());
				if (Mapping.find(Name) != Mapping.end())
					return LayerException(Stringify::Text("program function %s is ambiguous", Name.c_str()));

				Mapping.insert(Name);
			}

			UMutex<std::mutex> Unique(Mutex);
			if (Modules.size() <= Protocol::Now().User.Storage.ScriptCacheSize)
			{
				auto& Link = Modules[Id];
				if (Link != nullptr)
					::Module(Link).Discard();

				Link = Compiler->GetModule().GetModule();
				return Expectation::Met;
			}
			
			for (auto& Link : Modules)
				::Module(Link.second).Discard();

			Modules.clear();
			Modules[Id] = Compiler->GetModule().GetModule();
			return Expectation::Met;
		}
		bool ScriptHost::Precompile(Compiler* Compiler, const std::string_view& ProgramHashcode)
		{
			VI_ASSERT(Compiler != nullptr, "compiler should not be null");
			String Id = String(ProgramHashcode);
			UMutex<std::mutex> Unique(Mutex);
			auto It = Modules.find(Id);
			return It != Modules.end() ? !!Compiler->Prepare(It->second) : false;
		}
		String ScriptHost::Hashcode(const std::string_view& UnpackedProgramCode)
		{
			static std::string_view Lines = "\r\n";
			static std::string_view Erasable = " \r\n\t\'\"()<>=%&^*/+-,.!?:;@~";
			static std::string_view Quotes = "\"'`";
			String Hashable = String(UnpackedProgramCode);
			Stringify::ReplaceInBetween(Stringify::Trim(Hashable), "/*", "*/", "", false);
			Stringify::ReplaceStartsWithEndsOf(Stringify::Trim(Hashable), "//", Lines, "");
			Stringify::Compress(Stringify::Trim(Hashable), Erasable, Quotes);
			return Algorithm::Hashing::Hash512((uint8_t*)Hashable.data(), Hashable.size());
		}
		ExpectsLR<String> ScriptHost::Pack(const std::string_view& UnpackedProgramCode)
		{
			auto PackedProgramCode = Codec::Compress(UnpackedProgramCode, Compression::BestCompression);
			if (!PackedProgramCode)
				return LayerException(std::move(PackedProgramCode.Error().message()));

			return *PackedProgramCode;
		}
		ExpectsLR<String> ScriptHost::Unpack(const std::string_view& PackedProgramCode)
		{
			auto UnpackedProgramCode = Codec::Decompress(PackedProgramCode);
			if (!UnpackedProgramCode)
				return LayerException(std::move(UnpackedProgramCode.Error().message()));

			return *UnpackedProgramCode;
		}
		VirtualMachine* ScriptHost::GetVM()
		{
			return *VM;
		}

		ScriptAddress::ScriptAddress()
		{
		}
		ScriptAddress::ScriptAddress(const Algorithm::Pubkeyhash Owner)
		{
			if (Owner != nullptr)
				memcpy(Hash, Owner, sizeof(Hash));
		}
		ScriptAddress::ScriptAddress(const std::string_view& Address)
		{
			Algorithm::Signing::DecodeAddress(Address, Hash);
		}
		ScriptAddress::ScriptAddress(const uint256_t& Numeric)
		{
			uint8_t Data[32];
			Algorithm::Encoding::DecodeUint256(Numeric, Data);
			memcpy(Hash, Data, sizeof(Hash));
		}
		String ScriptAddress::ToString() const
		{
			String Address;
			Algorithm::Signing::EncodeAddress(Hash, Address);
			return Address;
		}
		uint256_t ScriptAddress::ToUint256() const
		{
			uint8_t Data[32] = { 0 };
			memcpy(Data, Hash, sizeof(Hash));

			uint256_t Numeric = 0;
			Algorithm::Encoding::EncodeUint256(Data, Numeric);
			return Numeric;
		}
		bool ScriptAddress::IsNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Hash, Null, sizeof(Null));
		}
		bool ScriptAddress::Equals(const ScriptAddress& A, const ScriptAddress& B)
		{
			return !memcmp(A.Hash, B.Hash, sizeof(A.Hash));
		}

		ScriptProgram::ScriptProgram(Ledger::TransactionContext* NewContext) : Distribution(Optional::None), Context(NewContext)
		{
			VI_ASSERT(Context != nullptr, "transaction context should be set");
		}
		ExpectsLR<void> ScriptProgram::Initialize(Compiler* Compiler, const Format::Variables& Args)
		{
			return Execute(Compiler, std::string_view(), Args, 1, nullptr);
		}
		ExpectsLR<void> ScriptProgram::MutableCall(Compiler* Compiler, const std::string_view& FunctionName, const Format::Variables& Args)
		{
			if (FunctionName.empty())
				return LayerException("illegal call to function: function not found");

			return Execute(Compiler, FunctionName, Args, -1, nullptr);
		}
		ExpectsLR<void> ScriptProgram::ImmutableCall(Compiler* Compiler, const std::string_view& FunctionName, const Format::Variables& Args)
		{
			if (FunctionName.empty())
				return LayerException("illegal call to function: function not found");

			return Execute(Compiler, FunctionName, Args, 0, nullptr);
		}
		ExpectsLR<void> ScriptProgram::Execute(Compiler* Compiler, const std::string_view& FunctionName, const Format::Variables& Args, int8_t Mutable, std::function<ExpectsLR<void>(void*, int)>&& ReturnCallback)
		{
			if (!FunctionName.empty() && (FunctionName == SCRIPT_FUNCTION_INITIALIZE || Stringify::StartsWith(FunctionName, "_")))
				return LayerException(Stringify::Text("illegal call to function \"%.*s\": illegal operation", (int)FunctionName.size(), FunctionName.data()));

			Function Entrypoint = Compiler->GetModule().GetFunctionByName(FunctionName.empty() ? SCRIPT_FUNCTION_INITIALIZE : FunctionName);
			if (!Entrypoint.IsValid())
			{
				if (FunctionName.empty())
					return Expectation::Met;

				return LayerException(Stringify::Text("illegal call to function \"%.*s\": function not found", (int)FunctionName.size(), FunctionName.data()));
			}

			auto Binders = LoadArguments(Entrypoint, Args, Mutable);
			if (!Binders)
				return Binders.Error();

			auto* VM = Entrypoint.GetVM();
			auto* Caller = ImmediateContext::Get();
			auto* Coroutine = Caller ? Caller : VM->RequestContext();			
			auto Execution = ExpectsVM<Vitex::Scripting::Execution>(Vitex::Scripting::Execution::Error);
			auto Resolver = ExpectsLR<void>(LayerException());
			auto Resolve = [this, &Resolver, &Entrypoint, &ReturnCallback](ImmediateContext* Coroutine)
			{
				void* Address = Coroutine->GetReturnAddress();
				int TypeId = Entrypoint.GetReturnTypeId();
				Resolver = Expectation::Met;
				if (!Address || TypeId <= 0)
					return;

				if (!ReturnCallback)
				{
					Format::Stream Stream;
					auto Serialization = ScriptMarshalling::Store(&Stream, Address, TypeId);
					if (Serialization)
					{
						Format::Variables Returns;
						if (Format::VariablesUtil::DeserializeFlatFrom(Stream, &Returns))
						{
							auto Type = ScriptHost::Get()->GetVM()->GetTypeInfoById(TypeId);
							auto Typename = Type.IsValid() ? Type.GetName() : std::string_view("primitive");
							auto Status = Context->EmitEvent(Algorithm::Hashing::Hash32d(Typename), std::move(Returns));
							if (!Status)
								Resolver = std::move(Status);
						}
						else
							Resolver = LayerException("return value conversion error");
					}
					else
						Resolver = LayerException("return value error: " + Serialization.Error().Info);
				}
				else
				{
					auto Status = ReturnCallback(Address, TypeId);
					if (!Status)
						Resolver = std::move(Status);
				}
			};
			if (Caller != Coroutine)
			{
				Vector<ScriptFrame> Frames;
				Coroutine->SetLineCallback(std::bind(&ScriptProgram::LoadCoroutine, this, std::placeholders::_1, Frames));
				Execution = Coroutine->ExecuteInlineCall(Entrypoint, [&Binders](ImmediateContext* Coroutine) { for (auto& Bind : *Binders) Bind(Coroutine); });
				Resolve(Coroutine);
			}
			else
				Execution = Coroutine->ExecuteSubcall(Entrypoint, [&Binders](ImmediateContext* Coroutine) { for (auto& Bind : *Binders) Bind(Coroutine); }, Resolve);

			auto Exception = Bindings::Exception::GetExceptionAt(Coroutine);
			if (!Execution || (Execution && *Execution != Execution::Finished) || !Exception.Empty())
			{
				if (Caller != Coroutine)
					VM->ReturnContext(Coroutine);
				return LayerException(Exception.Empty() ? (Execution ? "execution error" : Execution.Error().message()) : Exception.What());
			}

			if (Caller != Coroutine)
				VM->ReturnContext(Coroutine);
			return Resolver;
		}
		ExpectsLR<void> ScriptProgram::Subexecute(const ScriptAddress& Target, const std::string_view& FunctionName, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId, int8_t Mutable) const
		{
			if (FunctionName.empty())
				return LayerException(Stringify::Text("illegal subcall to %s program: illegal operation", Target.ToString().c_str()));

			auto Link = Context->GetAccountProgram(Target.Hash);
			if (!Link)
				return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": illegal operation", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data()));

			auto* Host = Ledger::ScriptHost::Get();
			auto Compiler = Host->Allocate();
			if (!Host->Precompile(*Compiler, Link->Hashcode))
			{
				auto Program = Context->GetWitnessProgram(Link->Hashcode);
				if (!Program)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": %s", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data(), Program.Error().what()));
				}

				auto Code = Program->AsCode();
				if (!Code)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": %s", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data(), Code.Error().what()));
				}

				auto Compilation = Host->Compile(*Compiler, Link->Hashcode, *Code);
				if (!Compilation)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": %s", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data(), Compilation.Error().what()));
				}
			}

			Format::Variables Args;
			if (InputValue != nullptr && InputTypeId > 0)
			{
				Format::Stream Stream;
				auto Serialization = ScriptMarshalling::Store(&Stream, InputValue, InputTypeId);
				if (!Serialization)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": %s", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data(), Serialization.Error().what()));
				}

				if (!Format::VariablesUtil::DeserializeFlatFrom(Stream, &Args))
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": argument serialization error", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data()));
				}
			}

			auto Transaction = Transactions::Invocation();
			Transaction.SetAsset("ETH");
			Transaction.SetCalldata(Target.Hash, Algorithm::Hashing::Hash32d(Link->Hashcode), FunctionName, std::move(Args));
			Transaction.GasPrice = Context->Transaction->GasPrice;
			Transaction.GasLimit = Context->GetGasLeft();
			Transaction.Sequence = 1;

			Ledger::Receipt Receipt;
			Receipt.TransactionHash = Transaction.AsHash();
			Receipt.GenerationTime = Protocol::Now().Time.Now();
			Receipt.AbsoluteGasUse = Context->Block->GasUse;
			Receipt.BlockNumber = Context->Block->Number;
			memcpy(Receipt.From, To().Hash, sizeof(Receipt.From));

			auto Next = TransactionContext(Context->Block, Context->Environment, &Transaction, std::move(Receipt));
			auto* Prev = Context;
			auto* Main = (ScriptProgram*)this;
			Main->Context = &Next;

			auto Execution = Main->Execute(*Compiler, FunctionName, Transaction.Args, Mutable, [&Target, &FunctionName, OutputValue, OutputTypeId](void* Address, int TypeId) -> ExpectsLR<void>
			{
				Format::Stream Stream;
				auto Serialization = ScriptMarshalling::Store(&Stream, Address, TypeId);
				if (!Serialization)
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": return serialization error", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data()));

				Serialization = ScriptMarshalling::Load(Stream, OutputValue, OutputTypeId);
				if (!Serialization)
					return LayerException(Stringify::Text("illegal subcall to %s program on function \"%.*s\": %s", Target.ToString().c_str(), (int)FunctionName.size(), FunctionName.data(), Serialization.Error().what()));

				return Expectation::Met;
			});

			Prev->Receipt.Events.insert(Prev->Receipt.Events.begin(), Next.Receipt.Events.begin(), Next.Receipt.Events.end());
			Prev->Receipt.RelativeGasUse += Next.Receipt.RelativeGasUse;
			Main->Context = Prev;
			Host->Deallocate(std::move(Compiler));
			return Execution;
		}
		ExpectsLR<Vector<std::function<void(ImmediateContext*)>>> ScriptProgram::LoadArguments(const Function& Entrypoint, const Format::Variables& Args, int8_t Mutable) const
		{
			auto* VM = Entrypoint.GetVM();
			size_t ArgsCount = Entrypoint.GetArgsCount();
			if (ArgsCount != Args.size() + 1)
				return LayerException(Stringify::Text("illegal call to function \"%s\": expected exactly %i arguments", Entrypoint.GetDecl().data(), (int)ArgsCount));

			Vector<std::function<void(ImmediateContext*)>> Frames = { };
			Frames.reserve(ArgsCount);

			for (size_t i = 0; i < ArgsCount; i++)
			{
				int TypeId; size_t Flags;
				if (!Entrypoint.GetArg(i, &TypeId, &Flags))
					return LayerException(Stringify::Text("illegal call to function \"%s\": argument #%i not bound", Entrypoint.GetDecl().data(), i));

				size_t Index = i - 1;
				auto Type = VM->GetTypeInfoById(TypeId);
				if (i > 0)
				{
					if (Index >= Args.size())
						return LayerException(Stringify::Text("illegal call to function \"%s\": argument #%i not bound", Entrypoint.GetDecl().data(), i));

					switch (TypeId)
					{
						case (int)TypeId::BOOL:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArg8(i, (uint8_t)Args[Index].AsBoolean()); });
							break;
						case (int)TypeId::INT8:
						case (int)TypeId::UINT8:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArg8(i, (uint8_t)Args[Index].AsUint8()); });
							break;
						case (int)TypeId::INT16:
						case (int)TypeId::UINT16:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArg16(i, (uint16_t)Args[Index].AsUint16()); });
							break;
						case (int)TypeId::INT32:
						case (int)TypeId::UINT32:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArg32(i, (uint32_t)Args[Index].AsUint32()); });
							break;
						case (int)TypeId::INT64:
						case (int)TypeId::UINT64:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArg64(i, (uint64_t)Args[Index].AsUint64()); });
							break;
						case (int)TypeId::FLOAT:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArgFloat(i, (float)Args[Index].AsFloat()); });
							break;
						case (int)TypeId::DOUBLE:
							Frames.emplace_back([i, Index, &Args](ImmediateContext* Coroutine) { Coroutine->SetArgDouble(i, (double)Args[Index].AsDouble()); });
							break;
						default:
						{
							void* Address = nullptr;
							auto& Value = Args[Index];
							Format::Stream Stream;
							Format::VariablesUtil::SerializeFlatInto({ Value }, &Stream);
							auto Status = ScriptMarshalling::Load(Stream, (void*)&Address, TypeId | (int)Vitex::Scripting::TypeId::OBJHANDLE);
							if (!Status)
							{
								Stream = Format::Stream::Decode(Value.AsString());
								Status = ScriptMarshalling::Load(Stream, (void*)&Address, TypeId | (int)Vitex::Scripting::TypeId::OBJHANDLE);
								if (!Status)
									return LayerException(Stringify::Text("illegal call to function \"%s\": argument #%i not bound to program (%s)", Entrypoint.GetDecl().data(), i, Status.Error().what()));
							}

							auto Object = UScriptObject(VM, Type.GetTypeInfo(), Address);
							Frames.emplace_back([i, TypeId, Object = std::move(Object)](ImmediateContext* Coroutine) mutable { Coroutine->SetArgObject(i, TypeId & (int)Vitex::Scripting::TypeId::OBJHANDLE ? (void*)&Object.Address : (void*)Object.Address); });
							break;
						}
					}
				}
				else
				{
					if (!Type.IsValid() || Type.GetName() != SCRIPT_CLASS_PROGRAM)
						return LayerException(Stringify::Text("illegal call to function \"%s\": argument #%i not bound to program", Entrypoint.GetDecl().data()));

					bool IsConst = Mutable == 0;
					if (Mutable != -1 && IsConst != (!!(Flags & (size_t)Modifiers::CONSTF)))
						return LayerException(Stringify::Text("illegal call to function \"%s\": mutability not preserved", Entrypoint.GetDecl().data()));

					Frames.emplace_back([i, Index, &Args, this](ImmediateContext* Coroutine) { Coroutine->SetArgObject(i, (ScriptProgram*)this); });
				}
			}
			return std::move(Frames);
		}
		void ScriptProgram::LoadCoroutine(ImmediateContext* Coroutine, Vector<ScriptFrame>& Frames)
		{
			ScriptFrame CurrentFrame; size_t CurrentDepth = Coroutine->GetCallstackSize();
			if (!Coroutine->GetCallStateRegisters(0, nullptr, &CurrentFrame.Call, &CurrentFrame.Pointer, nullptr, nullptr))
				return;

			size_t LatestDepth = Frames.size();
			if (LatestDepth < CurrentDepth)
			{
				auto LatestFrame = CurrentFrame;
				LatestFrame.ByteCode = CurrentFrame.Call.GetByteCode(&LatestFrame.ByteCodeSize);
				LatestFrame.Pointer = 0;
				Frames.push_back(std::move(LatestFrame));
			}
			else if (LatestDepth > CurrentDepth)
				Frames.pop_back();

			if (Frames.empty() || !Frames.back().ByteCode)
				return;

			auto& LatestFrame = Frames.back();
			auto* VM = Coroutine->GetVM();
			size_t Start = std::min<size_t>(LatestFrame.ByteCodeSize - 1, CurrentFrame.Pointer > LatestFrame.Pointer ? LatestFrame.Pointer : CurrentFrame.Pointer);
			size_t Count = (CurrentFrame.Pointer > LatestFrame.Pointer ? CurrentFrame.Pointer - LatestFrame.Pointer : LatestFrame.Pointer - CurrentFrame.Pointer);
			size_t End = std::min<size_t>(LatestFrame.ByteCodeSize, Start + std::max<size_t>(1, Count));
			while (Start < End)
			{
				auto Opcode = VirtualMachine::GetByteCodeInfo((uint8_t) * (LatestFrame.ByteCode + Start));
				Start += Opcode.Size;
				if (!DispatchInstruction(VM, Coroutine, LatestFrame.ByteCode, Start, Opcode))
					return;
			}

			LatestFrame.Pointer = CurrentFrame.Pointer;
		}
		bool ScriptProgram::DispatchInstruction(VirtualMachine* VM, ImmediateContext* Coroutine, uint32_t* ProgramData, size_t ProgramCounter, ByteCodeLabel& Opcode)
		{
			auto Gas = (size_t)(Opcode.OffsetOfArg2 + Opcode.SizeOfArg2) * (size_t)GasCost::Opcode;
			auto Status = Context->BurnGas(Gas);
			if (Status)
				return true;
			
			Coroutine = Coroutine ? Coroutine : ImmediateContext::Get();
			if (Coroutine != nullptr)
				Coroutine->SetException(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_EXECUTION, Status.Error().Info).ToExceptionString(), false);

			return false;
		}
		bool ScriptProgram::CallMutableFunction(const ScriptAddress& Target, const std::string_view& Function, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId)
		{
			auto Execution = Subexecute(Target, Function, InputValue, InputTypeId, OutputValue, OutputTypeId, -1);
			if (!Execution)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_EXECUTION, Execution.Error().Info));
				return false;
			}

			return true;
		}
		bool ScriptProgram::CallImmutableFunction(const ScriptAddress& Target, const std::string_view& Function, void* InputValue, int InputTypeId, void* OutputValue, int OutputTypeId) const
		{
			auto Execution = Subexecute(Target, Function, InputValue, InputTypeId, OutputValue, OutputTypeId, 0);
			if (!Execution)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_EXECUTION, Execution.Error().Info));
				return false;
			}

			return true;
		}
		bool ScriptProgram::StoreByAddress(const ScriptAddress& Location, const void* ObjectValue, int ObjectTypeId)
		{
			String Data = String((char*)Location.Hash, sizeof(Location.Hash));
			return StoreByLocation(Data, ObjectValue, ObjectTypeId);
		}
		bool ScriptProgram::StoreByLocation(const std::string_view& Location, const void* ObjectValue, int ObjectTypeId)
		{
			if (!ObjectValue)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "store not supported for null value"));
				return false;
			}
			else if (Location.size() > std::numeric_limits<uint8_t>::max())
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "store location max length is 256 bytes"));
				return false;
			}

			Format::Stream Stream;
			auto Status = ScriptMarshalling::Store(&Stream, (void*)ObjectValue, ObjectTypeId);
			if (!Status)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, Status.Error().Info));
				return false;
			}

			auto Data = Context->ApplyAccountStorage(To().Hash, Location, Stream.Data);
			if (!Data)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_STORAGE, Data.Error().Info));
				return false;
			}

			return true;
		}
		bool ScriptProgram::LoadByAddress(const ScriptAddress& Location, void* ObjectValue, int ObjectTypeId) const
		{
			return LoadFromByAddress(To(), Location, ObjectValue, ObjectTypeId);
		}
		bool ScriptProgram::LoadByLocation(const std::string_view& Location, void* ObjectValue, int ObjectTypeId) const
		{
			return LoadFromByLocation(To(), Location, ObjectValue, ObjectTypeId);
		}
		bool ScriptProgram::LoadFromByAddress(const ScriptAddress& Target, const ScriptAddress& Location, void* ObjectValue, int ObjectTypeId) const
		{
			String Data = String((char*)Location.Hash, sizeof(Location.Hash));
			return LoadFromByLocation(Target, Data, ObjectValue, ObjectTypeId);
		}
		bool ScriptProgram::LoadFromByLocation(const ScriptAddress& Target, const std::string_view& Location, void* ObjectValue, int ObjectTypeId) const
		{
			if (!ObjectValue)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "load not supported for null value"));
				return false;
			}
			else if (Location.size() > std::numeric_limits<uint8_t>::max())
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "load location max length is 256 bytes"));
				return false;
			}

			auto Data = Context->GetAccountStorage(Target.Hash, Location);
			if (!Data || Data->Storage.empty())
				return false;

			Format::Stream Stream = Format::Stream(Data->Storage);
			auto Status = ScriptMarshalling::Load(Stream, ObjectValue, ObjectTypeId);
			if (!Status)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, Status.Error().Info));
				return false;
			}

			return true;
		}
		bool ScriptProgram::EmitByAddress(const ScriptAddress& Location, const void* ObjectValue, int ObjectTypeId)
		{
			String Data = String((char*)Location.Hash, sizeof(Location.Hash));
			return EmitByLocation(Data, ObjectValue, ObjectTypeId);
		}
		bool ScriptProgram::EmitByLocation(const std::string_view& Location, const void* ObjectValue, int ObjectTypeId)
		{
			if (!ObjectValue)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit not supported for null value"));
				return false;
			}
			else if (Location.size() > std::numeric_limits<uint8_t>::max())
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit location max length is 256 bytes"));
				return false;
			}

			Format::Stream Stream;
			auto Status = ScriptMarshalling::Store(&Stream, (void*)ObjectValue, ObjectTypeId);
			if (!Status)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, Status.Error().Info));
				return false;
			}

			Format::Variables Returns;
			if (!Format::VariablesUtil::DeserializeFlatFrom(Stream, &Returns))
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_ARGUMENT, "emit value conversion error"));
				return false;
			}

			auto Type = ScriptHost::Get()->GetVM()->GetTypeInfoById(ObjectTypeId);
			auto Typename = Type.IsValid() ? Type.GetName() : std::string_view("primitive");
			auto Data = Context->EmitEvent(Algorithm::Hashing::Hash32d(Typename), std::move(Returns));
			if (!Data)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_STORAGE, Data.Error().Info));
				return false;
			}

			return true;
		}
		bool ScriptProgram::Transfer(const ScriptAddress& To, const uint256_t& Asset, const Decimal& Value)
		{
			auto Status = Context->ApplyPayment(Asset, Context->Receipt.From, To.Hash, Value);
			if (!Status)
			{
				Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_EXECUTION, Status.Error().Info));
				return false;
			}

			return true;
		}
		uint64_t ScriptProgram::AccountSequenceOf(const ScriptAddress& Target) const
		{
			auto Data = Context->GetAccountSequence(Target.Hash);
			return Data ? Data->Sequence : 0;
		}
		uint256_t ScriptProgram::AccountWorkOf(const ScriptAddress& Target) const
		{
			auto Data = Context->GetAccountWork(Target.Hash);
			return Data ? Data->GetGasUse() : uint256_t(0);
		}
		String ScriptProgram::AccountProgramOf(const ScriptAddress& Target) const
		{
			auto Data = Context->GetAccountProgram(Target.Hash);
			return Data ? Data->Hashcode : String();
		}
		Decimal ScriptProgram::AccountIncomingRewardOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset, const Decimal& Value) const
		{
			auto Data = Context->GetAccountReward(Asset, Target.Hash);
			return Data ? Data->CalculateIncomingFee(Value) : Decimal::NaN();
		}
		Decimal ScriptProgram::AccountOutgoingRewardOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset, const Decimal& Value) const
		{
			auto Data = Context->GetAccountReward(Asset, Target.Hash);
			return Data ? Data->CalculateOutgoingFee(Value) : Decimal::NaN();
		}
		uint64_t ScriptProgram::AccountDerivationOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const
		{
			auto Data = Context->GetAccountDerivation(Asset, Target.Hash);
			return Data ? Data->MaxAddressIndex : 0;
		}
		Decimal ScriptProgram::AccountBalanceOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const
		{
			auto Data = Context->GetAccountBalance(Asset, Target.Hash);
			return Data ? Data->GetBalance() : Decimal::Zero();
		}
		Decimal ScriptProgram::AccountContributionOf(const ScriptAddress& Target, const Algorithm::AssetId& Asset) const
		{
			auto Data = Context->GetAccountContribution(Asset, Target.Hash);
			return Data && Data->Honest ? Data->GetCoverage() : Decimal::NaN();
		}
		bool ScriptProgram::HasWitnessProgramOf(const std::string_view& Hashcode) const
		{
			return !!Context->GetWitnessProgram(Hashcode);
		}
		uint256_t ScriptProgram::WitnessEventOf(const uint256_t& TransactionHash) const
		{
			auto Data = Context->GetWitnessEvent(TransactionHash);
			return Data ? Data->ChildTransactionHash : uint256_t(0);
		}
		ScriptAddress ScriptProgram::WitnessAddressOf(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const
		{
			auto Data = Context->GetWitnessAddress(Asset, Address, AddressIndex, Offset);
			return Data ? ScriptAddress(Data->Owner) : ScriptAddress();
		}
		bool ScriptProgram::HasWitnessTransactionOf(const Algorithm::AssetId& Asset, const std::string_view& TransactionId) const
		{
			return !!Context->GetWitnessTransaction(Asset, TransactionId);
		}
		uint256_t ScriptProgram::Random()
		{
			if (!Distribution)
			{
				auto Candidate = Context->CalculateRandom(Context->GetGasUse());
				if (!Candidate)
				{
					Bindings::Exception::Throw(Bindings::Exception::Pointer(SCRIPT_EXCEPTION_EXECUTION, Candidate.Error().Info));
					return 0;
				}
				Distribution = std::move(*Candidate);
			}
			return Distribution->Derive();
		}
		ScriptAddress ScriptProgram::From() const
		{
			return ScriptAddress(Context->Receipt.From);
		}
		ScriptAddress ScriptProgram::To() const
		{
			uint32_t Type = Context->Transaction->AsType();
			if (Type == Transactions::Deployment::AsInstanceType())
			{
				Algorithm::Pubkeyhash Owner;
				if (((Transactions::Deployment*)Context->Transaction)->RecoverLocation(Owner))
					return ScriptAddress(Owner);
			}
			else if (Type == Transactions::Invocation::AsInstanceType())
				return ScriptAddress(((Transactions::Invocation*)Context->Transaction)->To);

			return ScriptAddress(Context->Receipt.From);
		}
		String ScriptProgram::Blockchain() const
		{
			return Algorithm::Asset::BlockchainOf(Context->Transaction->Asset);
		}
		String ScriptProgram::Token() const
		{
			return Algorithm::Asset::TokenOf(Context->Transaction->Asset);
		}
		String ScriptProgram::Contract() const
		{
			return Algorithm::Asset::ChecksumOf(Context->Transaction->Asset);
		}
		Decimal ScriptProgram::GasPrice() const
		{
			return Context->Transaction->GasPrice;
		}
		uint256_t ScriptProgram::GasLeft() const
		{
			return Context->GetGasLeft();
		}
		uint256_t ScriptProgram::GasUse() const
		{
			return Context->Receipt.RelativeGasUse;
		}
		uint256_t ScriptProgram::GasLimit() const
		{
			return Context->Transaction->GasLimit;
		}
		uint256_t ScriptProgram::Asset() const
		{
			return Context->Transaction->Asset;
		}
		uint256_t ScriptProgram::ParentBlockHash() const
		{
			return Context->Block->ParentHash;
		}
		uint256_t ScriptProgram::BlockGasUse() const
		{
			return Context->Block->GasUse;
		}
		uint256_t ScriptProgram::BlockGasLeft() const
		{
			return Context->Block->GasLimit - Context->Block->GasUse;
		}
		uint256_t ScriptProgram::BlockGasLimit() const
		{
			return Context->Block->GasLimit;
		}
		uint128_t ScriptProgram::BlockDifficulty() const
		{
			return Context->Block->Target.Difficulty();
		}
		uint64_t ScriptProgram::BlockTime() const
		{
			return Context->Block->Time;
		}
		uint64_t ScriptProgram::BlockPriority() const
		{
			return Context->Block->Priority;
		}
		uint64_t ScriptProgram::BlockNumber() const
		{
			return Context->Block->Number;
		}

		ScriptProgramTrace::ScriptProgramTrace(Ledger::Transaction* Transaction, const Algorithm::Pubkeyhash From, bool Tracing) : ScriptProgram(&Environment.Validation.Context), Debugging(Tracing)
		{
			VI_ASSERT(Transaction != nullptr && From != nullptr, "transaction and from should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto Tip = Chain.GetLatestBlockHeader();
			if (Tip)
				Environment.Tip = std::move(*Tip);
#endif
			Ledger::Receipt Receipt;
			Block.SetParentBlock(Environment.Tip.Address());
			Receipt.TransactionHash = Transaction->AsHash();
			Receipt.GenerationTime = Protocol::Now().Time.Now();
			Receipt.BlockNumber = Block.Number + 1;
			memcpy(Receipt.From, From, sizeof(Algorithm::Pubkeyhash));

			memset(Environment.Proposer.PublicKeyHash, 0xFF, sizeof(Algorithm::Pubkeyhash));
			memset(Environment.Proposer.PrivateKey, 0xFF, sizeof(Algorithm::Seckey));
			Environment.Validation.Context = TransactionContext(&Block, &Environment, Transaction, std::move(Receipt));
		}
		ExpectsLR<void> ScriptProgramTrace::TraceCall(const std::string_view& Function, const Format::Variables& Args, int8_t Mutable)
		{
			auto Index = Environment.Validation.Context.GetAccountProgram(To().Hash);
			if (!Index)
				return LayerException("program not assigned to address");

			auto* Host = Ledger::ScriptHost::Get();
			auto& Hashcode = Index->Hashcode;
			auto Compiler = Host->Allocate();
			if (!Host->Precompile(*Compiler, Hashcode))
			{
				auto Program = Environment.Validation.Context.GetWitnessProgram(Hashcode);
				if (!Program)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException("program not stored to address");
				}

				auto Code = Program->AsCode();
				if (!Code)
				{
					Host->Deallocate(std::move(Compiler));
					return Code.Error();
				}

				auto Compilation = Host->Compile(*Compiler, Hashcode, *Code);
				if (!Compilation)
				{
					Host->Deallocate(std::move(Compiler));
					return Compilation.Error();
				}
			}

			auto Execution = Execute(*Compiler, Function, Args, Mutable, [this](void* Address, int TypeId) -> ExpectsLR<void>
			{
				Returning = Var::Set::Object();
				auto Serialization = ScriptMarshalling::Store(*Returning, Address, TypeId);
				if (!Serialization)
				{
					Returning.Destroy();
					return LayerException("return value error: " + Serialization.Error().Info);
				}

				return Expectation::Met;
			});
			Context->Receipt.Successful = !!Execution;
			Context->Receipt.FinalizationTime = Protocol::Now().Time.Now();
			if (!Context->Receipt.Successful)
				Context->EmitEvent(0, { Format::Variable(Execution.What()) }, false);

			Host->Deallocate(std::move(Compiler));
			return Execution;
		}
		bool ScriptProgramTrace::DispatchInstruction(VirtualMachine* VM, ImmediateContext* Coroutine, uint32_t* ProgramData, size_t ProgramCounter, ByteCodeLabel& Opcode)
		{
			if (Debugging)
			{
				StringStream Stream;
				DebuggerContext::ByteCodeLabelToText(Stream, VM, ProgramData, ProgramCounter, false, true);

				String Instruction = Stream.str();
				Stringify::Trim(Instruction);
#if VI_64
				Instruction.erase(2, 8);
#endif
				auto Gas = (size_t)(Opcode.OffsetOfArg2 + Opcode.SizeOfArg2) * (size_t)GasCost::Opcode;
				Instruction.append(Instruction.find('%') != std::string::npos ? ", %gc:" : " %gc:");
				Instruction.append(ToString(Gas));
				Instructions.push_back(std::move(Instruction));
			}
			return ScriptProgram::DispatchInstruction(VM, Coroutine, ProgramData, ProgramCounter, Opcode);
		}
		UPtr<Schema> ScriptProgramTrace::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("block_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Block.Number > 0 ? Block.AsHash() : uint256_t(0))));
			Data->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Context->Receipt.TransactionHash)));
			Data->Set("from", Algorithm::Signing::SerializeAddress(((ScriptProgramTrace*)this)->From().Hash));
			Data->Set("to", Algorithm::Signing::SerializeAddress(((ScriptProgramTrace*)this)->To().Hash));
			Data->Set("gas", Algorithm::Encoding::SerializeUint256(Context->Receipt.RelativeGasUse));
			Data->Set("time", Algorithm::Encoding::SerializeUint256(Context->Receipt.FinalizationTime - Context->Receipt.GenerationTime));
			Data->Set("successful", Var::Boolean(Context->Receipt.Successful));
			Data->Set("returns", Returning ? Returning->Copy() : Var::Set::Null());
			if (!Context->Receipt.Events.empty())
			{
				auto* EventsData = Data->Set("events", Var::Set::Array());
				for (auto& Item : Context->Receipt.Events)
				{
					auto* EventData = EventsData->Push(Var::Set::Object());
					EventData->Set("event", Var::Integer(Item.first));
					EventData->Set("args", Format::VariablesUtil::Serialize(Item.second));
				}
			}
			if (!Context->Delta.Outgoing->At(WorkCommitment::Pending).empty())
			{
				auto* StatesData = Data->Set("states", Var::Set::Array());
				for (auto& Item : Context->Delta.Outgoing->At(WorkCommitment::Pending))
					StatesData->Push(Item.second->AsSchema().Reset());
			}
			if (!Instructions.empty())
			{
				auto* InstructionsData = Data->Set("instructions", Var::Set::Array());
				for (auto& Item : Instructions)
					InstructionsData->Push(Var::String(Item));
			}
			return Data;
		}
	}
}
