#include "serialization.h"

namespace Tangent
{
	namespace Format
	{
		static uint256_t ContextualParseUint256(const std::string_view& Numeric)
		{
			if (Numeric.size() < 3)
				return uint256_t(*FromString<uint8_t>(Numeric));
			else if (Numeric.size() < 5)
				return uint256_t(*FromString<uint16_t>(Numeric));
			else if (Numeric.size() < 10)
				return uint256_t(*FromString<uint32_t>(Numeric));
			else if (Numeric.size() < 20)
				return uint256_t(*FromString<uint64_t>(Numeric));

			return uint256_t(Numeric);
		}

		Stream::Stream() : Checksum(0), Seek(0)
		{
		}
		Stream::Stream(const std::string_view& NewData) : Data(NewData), Checksum(0), Seek(0)
		{
		}
		Stream::Stream(String&& NewData) : Data(std::move(NewData)), Checksum(0), Seek(0)
		{
		}
		size_t Stream::ReadCompact(void* Value, uint8_t Size)
		{
			return ReadExtended(Value, (uint32_t)Size);
		}
		size_t Stream::ReadExtended(void* Value, uint32_t Size)
		{
			if (!Size || !Value)
				return 0;

			if (Size + Seek > Data.size())
				return 0;

			memcpy(Value, Data.data() + Seek, (size_t)Size);
			Seek += Size;

			return Size;
		}
		Viewable Stream::ReadType()
		{
			Viewable Type = Viewable::Invalid;
			return ReadType(&Type) ? Type : Viewable::Invalid;
		}
		bool Stream::ReadType(Viewable* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			return ReadCompact(Value, sizeof(uint8_t)) == sizeof(uint8_t);
		}
		bool Stream::ReadString(Viewable Type, String* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			if (Util::IsString(Type))
			{
				char Buffer[256];
				uint8_t Size = Util::GetStringSize(Type);
				if (ReadCompact(Buffer, Size) != Size)
					return false;

				if (Util::IsString16(Type))
					Value->assign(Util::Encode0xHex(std::string_view(Buffer, (size_t)Size)));
				else
					Value->assign(Buffer, (size_t)Size);
				return true;
			}
			else if (Type != Viewable::StringAny10 && Type != Viewable::StringAny16)
				return false;

			Viewable Subtype; uint32_t Size = 0;
			if (!ReadType(&Subtype) || !ReadInteger(Subtype, &Size) || Size > Protocol::Now().Message.MaxMessageSize)
				return false;

			Vector<char> Data;
			Data.resize((size_t)Size);
			if (ReadExtended((void*)Data.data(), Size) != Size)
				return false;

			switch (Type)
			{
				case Viewable::StringAny10:
					Value->assign(Data.begin(), Data.end());
					return true;
				case Viewable::StringAny16:
					Value->assign(Util::Encode0xHex(std::string_view(Data.data(), Data.size())));
					return true;
				default:
					return false;
			}
		}
		bool Stream::ReadVariative(Viewable Type, Schema** Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			if (Type != Viewable::Variative)
				return false;

			String RawBuffer;
			if (!ReadString(ReadType(), &RawBuffer))
				return false;

			Vector<char> Buffer(RawBuffer.begin(), RawBuffer.end());
			auto Data = Schema::FromJSONB(Buffer);
			if (!Data)
				return false;

			*Value = *Data;
			return true;
		}
		bool Stream::ReadDecimal(Viewable Type, Decimal* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			Viewable Subtype;
			if (Type == Viewable::DecimalNaN)
			{
				*Value = Decimal::NaN();
				return true;
			}
			else if (Type == Viewable::DecimalZero)
			{
				*Value = Decimal::Zero();
				return true;
			}
			else if (Type != Viewable::DecimalNeg1 && Type != Viewable::DecimalNeg2 && Type != Viewable::DecimalPos1 && Type != Viewable::DecimalPos2)
				return false;

			uint256_t Left;
			if (!ReadType(&Subtype) || !ReadInteger(Subtype, &Left))
				return false;

			String Numeric = "-";
			Numeric.append(Left.ToString());
			if (Type == Viewable::DecimalNeg2 || Type == Viewable::DecimalPos2)
			{
				uint256_t Right;
				if (!ReadType(&Subtype) || !ReadInteger(Subtype, &Right))
					return false;

				Numeric.append(1, '.');
				size_t Offset = Numeric.size();
				Numeric.append(Right.ToString());
				std::reverse(Numeric.begin() + Offset, Numeric.end());
			}

			if (Type != Viewable::DecimalNeg1 && Type != Viewable::DecimalNeg2)
				*Value = Decimal(std::string_view(Numeric).substr(1));
			else
				*Value = Decimal(Numeric);
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint8_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint256_t Base;
			if (!ReadInteger(Type, &Base) || Base > std::numeric_limits<uint8_t>::max())
				return false;

			*Value = (uint8_t)Base;
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint16_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint256_t Base;
			if (!ReadInteger(Type, &Base) || Base > std::numeric_limits<uint16_t>::max())
				return false;

			*Value = (uint16_t)Base;
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint32_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint256_t Base;
			if (!ReadInteger(Type, &Base) || Base > std::numeric_limits<uint32_t>::max())
				return false;

			*Value = (uint32_t)Base;
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint64_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint256_t Base;
			if (!ReadInteger(Type, &Base) || Base > std::numeric_limits<uint64_t>::max())
				return false;

			*Value = (uint64_t)Base;
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint128_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint256_t Base;
			if (!ReadInteger(Type, &Base) || Base > uint128_t::Max())
				return false;

			*Value = (uint128_t)Base;
			return true;
		}
		bool Stream::ReadInteger(Viewable Type, uint256_t* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			if (!Util::IsInteger(Type))
				return false;

			uint64_t Array[4] = { 0 };
			uint8_t Size = Util::GetIntegerSize(Type);
			if (ReadCompact(Array, Size) != Size)
				return false;

			auto& Bits0 = Value->Low().Low();
			auto& Bits1 = Value->Low().High();
			auto& Bits2 = Value->High().Low();
			auto& Bits3 = Value->High().High();
			Array[0] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Array[0]);
			Array[1] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Array[1]);
			Array[2] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Array[2]);
			Array[3] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Array[3]);
			memcpy((uint64_t*)&Bits0, &Array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits1, &Array[1], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits2, &Array[2], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits3, &Array[3], sizeof(uint64_t));
			return true;
		}
		bool Stream::ReadBoolean(Viewable Type, bool* Value)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			if (Type != Viewable::True && Type != Viewable::False)
				return false;

			*Value = (Type == Viewable::True);
			return true;
		}
		Stream& Stream::Clear()
		{
			Data.clear();
			Checksum = 0;
			Seek = 0;
			return *this;
		}
		Stream& Stream::Rewind(size_t Offset)
		{
			Seek = (Offset <= Data.size() ? Offset : Data.size());
			return *this;
		}
		void Stream::WriteCompact(const void* Value, uint8_t Size)
		{
			WriteExtended(Value, (uint32_t)Size);
		}
		void Stream::WriteExtended(const void* Value, uint32_t Size)
		{
			if (Size > 0 && Value != nullptr)
			{
				size_t Index = Data.size();
				Data.resize(Data.size() + (size_t)Size);
				memcpy((char*)Data.data() + Index, Value, (size_t)Size);
				Checksum = 0;
			}
		}
		Stream& Stream::WriteString(const std::string_view& Value)
		{
			if (Util::IsHexEncoding(Value))
			{
				String Source = Codec::HexDecode(Value);
				if (Source.size() > Util::GetMaxStringSize())
				{
					uint8_t Type = (uint8_t)Util::GetStringType(Source, true);
					uint32_t Size = std::min<uint32_t>(Protocol::Now().Message.MaxMessageSize, (uint32_t)Source.size());
					WriteCompact(&Type, sizeof(uint8_t));
					WriteInteger(Size);
					WriteExtended(Source.data(), Size);
				}
				else
				{
					String Source = Codec::HexDecode(Value);
					uint8_t Type = (uint8_t)Util::GetStringType(Source, true);
					uint8_t Size = Util::GetStringSize((Viewable)Type);
					WriteCompact(&Type, sizeof(uint8_t));
					WriteCompact(Source.data(), Size);
				}
			}
			else if (Value.size() > Util::GetMaxStringSize())
			{
				uint32_t Size = std::min<uint32_t>(Protocol::Now().Message.MaxMessageSize, (uint32_t)Value.size());
				uint8_t Type = (uint8_t)Util::GetStringType(Value, false);
				WriteCompact(&Type, sizeof(uint8_t));
				WriteInteger(Size);
				WriteExtended(Value.data(), Size);
			}
			else
			{
				uint8_t Type = (uint8_t)Util::GetStringType(Value, false);
				uint8_t Size = Util::GetStringSize((Viewable)Type);
				WriteCompact(&Type, sizeof(uint8_t));
				WriteCompact(Value.data(), Size);
			}
			return *this;
		}
		Stream& Stream::WriteDecimal(const Decimal& Value)
		{
			if (Value.IsNaN())
			{
				uint8_t Type = (uint8_t)Viewable::DecimalNaN;
				WriteCompact(&Type, sizeof(uint8_t));
				return *this;
			}
			else if (Value.IsZero())
			{
				uint8_t Type = (uint8_t)Viewable::DecimalZero;
				WriteCompact(&Type, sizeof(uint8_t));
				return *this;
			}

			String Numeric = Value.Numeric();
			uint16_t Decimals = Value.Decimals();
			int8_t Position = Value.Position();
			uint8_t Type = (uint8_t)(Decimals > 0 ? (Position < 0 ? Viewable::DecimalNeg2 : Viewable::DecimalPos2) : (Position < 0 ? Viewable::DecimalNeg1 : Viewable::DecimalPos1));
			std::reverse(Numeric.begin() + Decimals, Numeric.end());

			auto Left = std::string_view(Numeric).substr(Decimals);
			WriteCompact(&Type, sizeof(uint8_t));
			WriteInteger(ContextualParseUint256(Left));
			if (Decimals > 0)
			{
				auto Right = std::string_view(Numeric).substr(0, Decimals);
				WriteInteger(ContextualParseUint256(Right));
			}
			return *this;
		}
		Stream& Stream::WriteVariative(Schema* Value)
		{
			uint8_t Type = (uint8_t)Viewable::Variative;
			WriteCompact(&Type, sizeof(uint8_t));
			if (Value != nullptr)
			{
				auto Buffer = Schema::ToJSONB(Value);
				WriteString(std::string_view(Buffer.data(), Buffer.size()));
			}
			else
				WriteString(std::string_view());
			return *this;
		}
		Stream& Stream::WriteInteger(const uint256_t& Value)
		{
			uint8_t Type = (uint8_t)Util::GetIntegerType(Value);
			uint8_t Size = Util::GetIntegerSize((Viewable)Type);
			WriteCompact(&Type, sizeof(uint8_t));

			uint64_t Array[4];
			if (Size > sizeof(uint64_t) * 0)
			{
				Array[0] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.Low().Low());
				if (Size > sizeof(uint64_t) * 1)
				{
					Array[1] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.Low().High());
					if (Size > sizeof(uint64_t) * 2)
					{
						Array[2] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.High().Low());
						if (Size > sizeof(uint64_t) * 3)
							Array[3] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.High().High());
					}
				}
			}
			WriteCompact(Array, Size);
			return *this;
		}
		Stream& Stream::WriteBoolean(bool Value)
		{
			uint8_t Type = (uint8_t)(Value ? Viewable::True : Viewable::False);
			WriteCompact(&Type, sizeof(uint8_t));
			return *this;
		}
		Stream& Stream::WriteTypeless(const uint256_t& Value)
		{
			uint8_t Size = Util::GetIntegerSize(Util::GetIntegerType(Value));
			uint64_t Array[4];
			if (Size > sizeof(uint64_t) * 0)
			{
				Array[0] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.Low().Low());
				if (Size > sizeof(uint64_t) * 1)
				{
					Array[1] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.Low().High());
					if (Size > sizeof(uint64_t) * 2)
					{
						Array[2] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.High().Low());
						if (Size > sizeof(uint64_t) * 3)
							Array[3] = OS::CPU::ToEndianness(OS::CPU::Endian::Little, Value.High().High());
					}
				}
			}
			WriteCompact(Array, Size);
			return *this;
		}
		Stream& Stream::WriteTypeless(const char* Data, uint8_t Size)
		{
			WriteCompact(Data, Size);
			return *this;
		}
		Stream& Stream::WriteTypeless(const char* Data, uint32_t Size)
		{
			WriteExtended(Data, Size);
			return *this;
		}
		bool Stream::IsEof() const
		{
			return Seek >= Data.size();
		}
		String Stream::Compress() const
		{
			auto Status = Codec::Compress(Data, Compression::BestCompression);
			return Status ? *Status : Data;
		}
		String Stream::Encode() const
		{
			return Util::Encode0xHex(Data);
		}
		uint256_t Stream::Hash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			((Stream*)this)->Checksum = Algorithm::Hashing::Hash256i(Data);
			return Checksum;
		}
		Stream Stream::Decompress(const std::string_view& Data)
		{
			auto Raw = Util::IsHexEncoding(Data) ? Util::Decode0xHex(Data) : String(Data);
			auto Status = Codec::Decompress(Raw);
			return Stream(Status ? *Status : Raw);
		}
		Stream Stream::Decode(const std::string_view& Data)
		{
			return Util::IsHexEncoding(Data) ? Stream(Util::Decode0xHex(Data)) : Stream(Data);
		}

		String Util::Encode0xHex(const std::string_view& Data)
		{
			return Assign0xHex(Codec::HexEncode(Data));
		}
		String Util::Decode0xHex(const std::string_view& Data)
		{
			return Codec::HexDecode(Data);
		}
		String Util::Assign0xHex(const std::string_view& Data)
		{
			String Result = Stringify::StartsWith(Data, "0x") ? String() : String(Data.empty() ? "0x0" : "0x");
			return Result.append(Data);
		}
		String Util::Clear0xHex(const std::string_view& Data, bool Uppercase)
		{
			String Result = String(Stringify::StartsWith(Data, "0x") ? Data.substr(2) : Data);
			return Uppercase ? Stringify::ToUpper(Result) : Stringify::ToLower(Result);
		}
		bool Util::IsHexEncoding(const std::string_view& Data)
		{
			static std::string_view Alphabet = "0123456789abcdefABCDEF";
			if (Data.empty() || Data.size() % 2 != 0)
				return false;

			auto Text = (Data.size() < 2 || Data[0] != '0' || Data[1] != 'x' ? Data : Data.substr(2));
			return Text.find_first_not_of(Alphabet) == std::string::npos;
		}
		bool Util::IsInteger(Viewable Type)
		{
			return (uint8_t)Type >= (uint8_t)Viewable::UintMin && (uint8_t)Type <= (uint8_t)Viewable::UintMax;
		}
		bool Util::IsString(Viewable Type)
		{
			return IsString10(Type) || IsString16(Type);
		}
		bool Util::IsString10(Viewable Type)
		{
			return (uint8_t)Type >= (uint8_t)Viewable::StringMin10 && (uint8_t)Type <= (uint8_t)Viewable::StringMax10;
		}
		bool Util::IsString16(Viewable Type)
		{
			return (uint8_t)Type >= (uint8_t)Viewable::StringMin16;
		}
		uint8_t Util::GetIntegerSize(Viewable Type)
		{
			if ((uint8_t)Type < (uint8_t)Viewable::UintMin)
				return 0;

			return (uint8_t)Type - (uint8_t)Viewable::UintMin;
		}
		Viewable Util::GetIntegerType(const uint256_t& Data)
		{
			uint64_t Array[4] =
			{
				OS::CPU::ToEndianness(OS::CPU::Endian::Little, Data.Low().Low()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Little, Data.Low().High()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Little, Data.High().Low()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Little, Data.High().High())
			};
			uint8_t Bytes = sizeof(Array);
			char* Inline = (char*)Array;
			while (Bytes > 0 && !Inline[Bytes - 1])
				--Bytes;
			uint8_t Type = (uint8_t)Viewable::UintMin + Bytes;
			return (Viewable)Type;
		}
		uint8_t Util::GetStringSize(Viewable Type)
		{
			if (IsString10(Type))
				return (uint8_t)Type - (uint8_t)Viewable::StringMin10;

			if (IsString16(Type))
				return (uint8_t)Type - (uint8_t)Viewable::StringMin16;

			return 0;
		}
		Viewable Util::GetStringType(const std::string_view& Data, bool HexEncoding)
		{
			auto Limit = Util::GetMaxStringSize();
			if (HexEncoding)
			{
				if (Data.size() > Limit)
					return Viewable::StringAny16;

				return (Viewable)((uint8_t)Viewable::StringMin16 + (uint8_t)std::min<size_t>(Data.size(), Limit));
			}
			else
			{
				if (Data.size() > Limit)
					return Viewable::StringAny10;

				return (Viewable)((uint8_t)Viewable::StringMin10 + (uint8_t)std::min<size_t>(Data.size(), Limit));
			}
		}
		size_t Util::GetMaxStringSize()
		{
			return (size_t)Viewable::StringMax10 - (size_t)Viewable::StringMin10;
		}
	}
}