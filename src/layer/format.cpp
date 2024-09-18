#include "format.h"
#include "../kernel/algorithm.h"
extern "C"
{
#include "../utils/trezor-crypto/blake256.h"
#include "../utils/trezor-crypto/ripemd160.h"
#include "../utils/trezor-crypto/sha3.h"
}

namespace Tangent
{
	namespace Format
	{
		Variable::Variable() noexcept : Type(Viewable::Invalid), Length(0)
		{
			Value.Pointer = nullptr;
		}
		Variable::Variable(const char* NewValue) noexcept : Variable(std::string_view(NewValue))
		{
		}
		Variable::Variable(const std::string_view& NewValue) noexcept : Variable(Viewable::StringAny10)
		{
			Length = (uint32_t)NewValue.size();
			size_t StringSize = sizeof(char) * (Length + 1);
			if (Length > GetMaxSmallStringSize())
				Value.Pointer = Memory::Allocate<char>(StringSize);

			char* Data = (char*)AsString().data();
			memcpy(Data, NewValue.data(), StringSize - sizeof(char));
			Data[StringSize - 1] = '\0';
		}
		Variable::Variable(const String& NewValue) noexcept : Variable(std::string_view(NewValue))
		{
		}
		Variable::Variable(const Decimal& NewValue) noexcept : Variable(Viewable::DecimalZero)
		{
			Value.Pointer = (char*)Memory::New<Decimal>(NewValue);
		}
		Variable::Variable(const uint8_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(const uint16_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(const uint32_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(const uint64_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(const uint128_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(const uint256_t& NewValue) noexcept : Variable(Viewable::UintMin)
		{
			Value.Integer = NewValue;
		}
		Variable::Variable(bool NewValue) noexcept : Variable(NewValue ? Viewable::True : Viewable::False)
		{
			Value.Boolean = NewValue;
		}
		Variable::Variable(Schema* NewValue) noexcept : Variable(Viewable::Variative)
		{
			Value.Pointer = (char*)NewValue;
		}
		Variable::Variable(Viewable NewType) noexcept : Type(NewType), Length(0)
		{
			Value.Pointer = nullptr;
		}
		Variable::Variable(const Variable& Other) noexcept
		{
			Copy(Other);
		}
		Variable::Variable(Variable&& Other) noexcept
		{
			Move(std::move(Other));
		}
		Variable::~Variable() noexcept
		{
			Free();
		}
		String Variable::AsConstant() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
				{
					auto Value = String(AsString());
					if (!VariablesUtil::IsAsciiEncoding(Value))
						return Util::Encode0xHex(Value);

					Stringify::Replace(Value, "\"", "\\\"");
					Value.insert(Value.begin(), '\"');
					Value.append(1, '\"');
					return Value;
				}
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToString();
				case Viewable::UintMin:
					return Value.Integer.ToString();
				case Viewable::Variative:
					return Value.Pointer ? Schema::ToJSON((Schema*)Value.Pointer) : "null";
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? "true" : "false";
				case Viewable::Invalid:
				default:
					return "null";
			}
		}
		String Variable::AsBlob() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return String(AsString());
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToString();
				case Viewable::UintMin:
					return Value.Integer.ToString();
				case Viewable::Variative:
					return Value.Pointer ? Schema::ToJSON((Schema*)Value.Pointer) : String();
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? "1" : "0";
				case Viewable::Invalid:
				default:
					return String();
			}
		}
		Decimal Variable::AsDecimal() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return Decimal(AsString());
				case Viewable::DecimalZero:
					return *(Decimal*)Value.Pointer;
				case Viewable::UintMin:
					return Decimal(Value.Integer.ToString());
				case Viewable::Variative:
					return Value.Pointer ? ((Schema*)Value.Pointer)->Value.GetDecimal() : Decimal::NaN();
				case Viewable::True:
				case Viewable::False:
					return Decimal(Value.Boolean ? 1 : 0);
				case Viewable::Invalid:
				default:
					return Decimal::NaN();
			}
		}
		UPtr<Schema> Variable::AsVariative() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
				{
					auto Value = AsString();
					if (!VariablesUtil::IsAsciiEncoding(Value))
						return Var::Set::String(Util::Encode0xHex(Value));

					return Var::Set::String(Value);
				}
				case Viewable::DecimalZero:
					return Var::Set::Decimal(*(Decimal*)Value.Pointer);
				case Viewable::UintMin:
					return Algorithm::Encoding::SerializeUint256(Value.Integer);
				case Viewable::Variative:
				{
					auto* Result = (Schema*)Value.Pointer;
					if (Result != nullptr)
						Result->AddRef();
					return Result;
				}
				case Viewable::True:
				case Viewable::False:
					return Var::Set::Boolean(Value.Boolean);
				case Viewable::Invalid:
				default:
					return Var::Set::Null();
			}
		}
		std::string_view Variable::AsString() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return std::string_view(Length <= GetMaxSmallStringSize() ? Value.String : Value.Pointer, Length);
				default:
					return std::string_view("", 0);
			}
		}
		uint8_t Variable::AsUint8() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<uint8_t>(AsString()).Or(0);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToUInt8();
				case Viewable::UintMin:
					return (uint8_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (uint8_t)((Schema*)Value.Pointer)->Value.GetInteger() : 0;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1 : 0;
				case Viewable::Invalid:
				default:
					return 0;
			}
		}
		uint16_t Variable::AsUint16() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<uint16_t>(AsString()).Or(0);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToUInt16();
				case Viewable::UintMin:
					return (uint16_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (uint16_t)((Schema*)Value.Pointer)->Value.GetInteger() : 0;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1 : 0;
				case Viewable::Invalid:
				default:
					return 0;
			}
		}
		uint32_t Variable::AsUint32() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<uint32_t>(AsString()).Or(0);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToUInt32();
				case Viewable::UintMin:
					return (uint32_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (uint32_t)((Schema*)Value.Pointer)->Value.GetInteger() : 0;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1 : 0;
				case Viewable::Invalid:
				default:
					return 0;
			}
		}
		uint64_t Variable::AsUint64() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<uint64_t>(AsString()).Or(0);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToUInt64();
				case Viewable::UintMin:
					return (uint64_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (uint64_t)((Schema*)Value.Pointer)->Value.GetInteger() : 0;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1 : 0;
				case Viewable::Invalid:
				default:
					return 0;
			}
		}
		uint128_t Variable::AsUint128() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return uint128_t(AsString(), Util::IsHexEncoding(AsString()) ? 16 : 10);
				case Viewable::DecimalZero:
					return uint128_t(((Decimal*)Value.Pointer)->ToString());
				case Viewable::UintMin:
					return uint128_t(Value.Integer);
				case Viewable::Variative:
					return Value.Pointer ? (uint128_t)((Schema*)Value.Pointer)->Value.GetInteger() : uint128_t(0);
				case Viewable::True:
				case Viewable::False:
					return uint128_t(Value.Boolean ? 1 : 0);
				case Viewable::Invalid:
				default:
					return uint128_t(0);
			}
		}
		uint256_t Variable::AsUint256() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return uint256_t(AsString(), Util::IsHexEncoding(AsString()) ? 16 : 10);
				case Viewable::DecimalZero:
					return uint256_t(((Decimal*)Value.Pointer)->ToString());
				case Viewable::UintMin:
					return Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (uint256_t)((Schema*)Value.Pointer)->Value.GetInteger() : uint256_t(0);
				case Viewable::True:
				case Viewable::False:
					return uint256_t(Value.Boolean ? 1 : 0);
				case Viewable::Invalid:
				default:
					return uint256_t(0);
			}
		}
		float Variable::AsFloat() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<float>(AsString()).Or(0.0f);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToFloat();
				case Viewable::UintMin:
					return (float)(uint64_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (float)((Schema*)Value.Pointer)->Value.GetNumber() : 0.0f;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1.0f : 0.0f;
				case Viewable::Invalid:
				default:
					return 0.0f;
			}
		}
		double Variable::AsDouble() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return FromString<double>(AsString()).Or(0.0);
				case Viewable::DecimalZero:
					return ((Decimal*)Value.Pointer)->ToDouble();
				case Viewable::UintMin:
					return (double)(uint64_t)Value.Integer;
				case Viewable::Variative:
					return Value.Pointer ? (double)((Schema*)Value.Pointer)->Value.GetNumber() : 0.0;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean ? 1.0 : 0.0;
				case Viewable::Invalid:
				default:
					return 0.0;
			}
		}
		bool Variable::AsBoolean() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return !AsString().empty();
				case Viewable::DecimalZero:
					return !((Decimal*)Value.Pointer)->IsZeroOrNaN();
				case Viewable::UintMin:
					return Value.Integer > 0;
				case Viewable::Variative:
					return Value.Pointer ? ((Schema*)Value.Pointer)->Value.GetBoolean() : false;
				case Viewable::True:
				case Viewable::False:
					return Value.Boolean;
				case Viewable::Invalid:
				default:
					return false;
			}
		}
		bool Variable::IsString() const
		{
			switch (Type)
			{
				case Viewable::StringAny10:
					return true;
				default:
					return false;
			}
		}
		bool Variable::IsDecimal() const
		{
			switch (Type)
			{
				case Viewable::DecimalZero:
					return true;
				default:
					return false;
			}
		}
		bool Variable::IsInteger() const
		{
			switch (Type)
			{
				case Viewable::UintMin:
					return true;
				default:
					return false;
			}
		}
		bool Variable::IsVariative() const
		{
			switch (Type)
			{
				case Viewable::Variative:
					return true;
				default:
					return false;
			}
		}
		Viewable Variable::TypeOf() const
		{
			return Type;
		}
		bool Variable::operator== (const Variable& Other) const
		{
			return Same(Other);
		}
		bool Variable::operator!= (const Variable& Other) const
		{
			return !Same(Other);
		}
		Variable& Variable::operator= (const Variable& Other) noexcept
		{
			Free();
			Copy(Other);

			return *this;
		}
		Variable& Variable::operator= (Variable&& Other) noexcept
		{
			Free();
			Move(std::move(Other));

			return *this;
		}
		bool Variable::Same(const Variable& Other) const
		{
			if (Type != Other.Type)
				return false;

			switch (Type)
			{
				case Viewable::StringAny10:
					return AsString() == Other.AsString();
				case Viewable::DecimalZero:
					return AsDecimal() == Other.AsDecimal();
				case Viewable::UintMin:
					return Value.Integer == Other.Value.Integer;
				case Viewable::True:
				case Viewable::False:
					return AsBoolean() == Other.AsBoolean();
				case Viewable::Variative:
					if (!Value.Pointer || !Other.Value.Pointer)
						return Value.Pointer == Other.Value.Pointer;

					return ((Schema*)Value.Pointer)->Value == ((Schema*)Other.Value.Pointer)->Value;
				case Viewable::Invalid:
					return true;
				default:
					return false;
			}
		}
		void Variable::Copy(const Variable& Other)
		{
			Type = Other.Type;
			Length = Other.Length;

			switch (Type)
			{
				case Viewable::StringAny10:
				{
					size_t StringSize = sizeof(char) * (Length + 1);
					if (Length > GetMaxSmallStringSize())
						Value.Pointer = Memory::Allocate<char>(StringSize);
					memcpy((void*)AsString().data(), Other.AsString().data(), StringSize);
					break;
				}
				case Viewable::DecimalZero:
				{
					Decimal* From = (Decimal*)Other.Value.Pointer;
					Value.Pointer = (char*)Memory::New<Decimal>(*From);
					break;
				}
				case Viewable::Variative:
				{
					Schema* From = (Schema*)Other.Value.Pointer;
					Value.Pointer = From ? (char*)From->Copy() : nullptr;
					break;
				}
				case Viewable::UintMin:
					Value.Integer = Other.Value.Integer;
					break;
				case Viewable::True:
				case Viewable::False:
					Value.Boolean = Other.Value.Boolean;
					break;
				case Viewable::Invalid:
				default:
					Value.Pointer = nullptr;
					break;
			}
		}
		void Variable::Move(Variable&& Other)
		{
			Type = Other.Type;
			Length = Other.Length;
			switch (Type)
			{
				case Viewable::StringAny10:
					if (Length <= GetMaxSmallStringSize())
						memcpy((void*)AsString().data(), Other.AsString().data(), sizeof(char) * (Length + 1));
					else
						Value.Pointer = Other.Value.Pointer;
					Other.Value.Pointer = nullptr;
					break;
				case Viewable::DecimalZero:
				case Viewable::Variative:
					Value.Pointer = Other.Value.Pointer;
					Other.Value.Pointer = nullptr;
					break;
				case Viewable::UintMin:
					Value.Integer = Other.Value.Integer;
					break;
				case Viewable::True:
				case Viewable::False:
					Value.Boolean = Other.Value.Boolean;
					break;
				case Viewable::Invalid:
				default:
					break;
			}

			Other.Type = Viewable::Invalid;
			Other.Length = 0;
		}
		void Variable::Free()
		{
			switch (Type)
			{
				case Viewable::StringAny10:
				{
					if (!Value.Pointer || Length <= GetMaxSmallStringSize())
						break;

					Memory::Deallocate(Value.Pointer);
					Value.Pointer = nullptr;
					break;
				}
				case Viewable::DecimalZero:
				{
					if (!Value.Pointer)
						break;

					Decimal* Buffer = (Decimal*)Value.Pointer;
					Memory::Delete(Buffer);
					Value.Pointer = nullptr;
					break;
				}
				case Viewable::Variative:
				{
					if (!Value.Pointer)
						break;

					Schema* Buffer = (Schema*)Value.Pointer;
					Memory::Delete(Buffer);
					Value.Pointer = nullptr;
					break;
				}
				default:
					break;
			}
		}
		size_t Variable::GetMaxSmallStringSize()
		{
			return sizeof(Tag::String) - 1;
		}

		bool VariablesUtil::IsAsciiEncoding(const std::string_view& Data)
		{
			return !std::any_of(Data.begin(), Data.end(), [](char V) { return static_cast<unsigned char>(V) > 127; });
		}
		bool VariablesUtil::DeserializeFlatFrom(Stream& Stream, Variables* Result)
		{
			return DeserializeFrom(Stream, Result, false);
		}
		bool VariablesUtil::SerializeFlatInto(const Variables& Data, Stream* Result)
		{
			return SerializeInto(Data, Result, false);
		}
		bool VariablesUtil::DeserializeMergeFrom(Stream& Stream, Variables* Result)
		{
			return DeserializeFrom(Stream, Result, true);
		}
		bool VariablesUtil::SerializeMergeInto(const Variables& Data, Stream* Result)
		{
			return SerializeInto(Data, Result, true);
		}
		bool VariablesUtil::DeserializeFrom(Stream& Stream, Variables* Result, bool Merging)
		{
			VI_ASSERT(Result != nullptr, "result should be set");
			uint16_t Size = std::numeric_limits<uint16_t>::max();
			if (Merging && !Stream.ReadInteger(Stream.ReadType(), &Size))
				return false;
			else if (!Size)
				return true;
			
			while (!Stream.IsEof() && Size-- != 0)
			{
				auto Type = Stream.ReadType();
				if (Type == Viewable::Invalid)
					return !Size;

				switch (Type)
				{
					case Viewable::StringAny10:
					case Viewable::StringAny16:
					{
						String Value;
						if (!Stream.ReadString(Type, &Value))
							return false;

						Result->emplace_back(std::string_view(Value));
						break;
					}
					case Viewable::DecimalNaN:
					case Viewable::DecimalZero:
					case Viewable::DecimalNeg1:
					case Viewable::DecimalNeg2:
					case Viewable::DecimalPos1:
					case Viewable::DecimalPos2:
					{
						Decimal Value;
						if (!Stream.ReadDecimal(Type, &Value))
							return false;

						Result->emplace_back(Value);
						break;
					}
					case Viewable::True:
					case Viewable::False:
					{
						bool Value;
						if (!Stream.ReadBoolean(Type, &Value))
							return false;

						Result->emplace_back(Value);
						break;
					}
					case Viewable::Variative:
					{
						Schema* Value;
						if (!Stream.ReadVariative(Type, &Value))
							return false;

						Result->emplace_back(Value);
						break;
					}
					default:
					{
						if (Util::IsString(Type))
						{
							String Value;
							if (!Stream.ReadString(Type, &Value))
								return false;

							Result->emplace_back(std::string_view(Value));
							break;
						}
						else if (Util::IsInteger(Type))
						{
							uint256_t Value;
							if (!Stream.ReadInteger(Type, &Value))
								return false;

							Result->emplace_back(Value);
							break;
						}
						return false;
					}
				}
			}
			return true;
		}
		bool VariablesUtil::SerializeInto(const Variables& Data, Stream* Result, bool Merging)
		{
			if (Data.size() > std::numeric_limits<uint16_t>::max())
				return false;

			auto& Message = Protocol::Now().Message;
			if (Merging)
				Result->WriteInteger(Data.size());

			for (auto& Item : Data)
			{
				auto Type = Item.TypeOf();
				if (Type == Viewable::Invalid || Result->Data.size() > Message.MaxBodySize)
					return false;

				switch (Type)
				{
					case Viewable::StringAny10:
						Result->WriteString(Item.AsString());
						break;
					case Viewable::DecimalZero:
						Result->WriteDecimal(Item.AsDecimal());
						break;
					case Viewable::UintMin:
						Result->WriteInteger(Item.AsUint256());
						break;
					case Viewable::True:
					case Viewable::False:
						Result->WriteBoolean(Item.AsBoolean());
						break;
					case Viewable::Variative:
					{
						auto Value = Item.AsVariative();
						Result->WriteVariative(*Value);
						break;
					}
					default:
						return false;
				}
			}
			return true;
		}
		String VariablesUtil::AsConstant(const Variables& Data)
		{
			String Result;
			for (size_t i = 0; i < Data.size(); i++)
			{
				Result += Data[i].AsConstant();
				if (i < Data.size() - 1)
					Result += ", ";
			}
			return Result;
		}
		String VariablesUtil::AsConstantJSON(const Variables& Data, size_t Spaces)
		{
			String Space(Spaces, ' ');
			String Result = "[";
			for (size_t i = 0; i < Data.size(); i++)
			{
				if (i == 0)
					Result += '\n';
				Result += Space;
				Result += Data[i].AsConstant();
				if (i < Data.size() - 1)
					Result += ",\n";
				else
					Result += '\n';
			}
			Result.append(1, ']');
			return Result;
		}
		Schema* VariablesUtil::Serialize(const Variables& Value)
		{
			Schema* Data = Var::Set::Array();
			for (auto& Item : Value)
				Data->Push(Item.AsVariative().Reset());
			return Data;
		}
	}
}