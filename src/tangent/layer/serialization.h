#ifndef TAN_LAYER_SERIALIZATION_H
#define TAN_LAYER_SERIALIZATION_H
#include "types.hpp"

namespace Tangent
{
	namespace Format
	{
		typedef Vector<struct Variable> Variables;

		enum class Viewable : uint8_t
		{
			Variative,
			DecimalNaN,
			DecimalZero,
			DecimalNeg1,
			DecimalNeg2,
			DecimalPos1,
			DecimalPos2,
			True,
			False,
			UintMin,
			UintMax = UintMin + sizeof(uint256_t),
			StringAny10,
			StringMin10,
			StringMax10 = StringMin10 + 104,
			StringAny16,
			StringMin16,
			StringMax16 = StringMin16 + 104,
			Invalid = 255
		};

		struct Stream
		{
			String Data;
			uint256_t Checksum;
			size_t Seek;

			Stream();
			explicit Stream(const std::string_view& NewData);
			explicit Stream(String&& NewData);
			Stream(const Stream&) = default;
			Stream(Stream&&) noexcept = default;
			Stream& operator= (const Stream&) = default;
			Stream& operator= (Stream&&) noexcept = default;
			Stream& Clear();
			Stream& Rewind(size_t Offset = 0);
			Stream& WriteString(const std::string_view& Value);
			Stream& WriteDecimal(const Decimal& Value);
			Stream& WriteInteger(const uint256_t& Value);
			Stream& WriteBoolean(bool Value);
			Stream& WriteVariative(Schema* Value);
			Stream& WriteTypeless(const uint256_t& Value);
			Stream& WriteTypeless(const char* Data, uint8_t Size);
			Stream& WriteTypeless(const char* Data, uint32_t Size);
			Viewable ReadType();
			bool ReadType(Viewable* Value);
			bool ReadString(Viewable Type, String* Value);
			bool ReadDecimal(Viewable Type, Decimal* Value);
			bool ReadVariative(Viewable Type, Schema** Value);
			bool ReadInteger(Viewable Type, uint8_t* Value);
			bool ReadInteger(Viewable Type, uint16_t* Value);
			bool ReadInteger(Viewable Type, uint32_t* Value);
			bool ReadInteger(Viewable Type, uint64_t* Value);
			bool ReadInteger(Viewable Type, uint128_t* Value);
			bool ReadInteger(Viewable Type, uint256_t* Value);
			bool ReadBoolean(Viewable Type, bool* Value);
			bool IsEof() const;
			String Compress() const;
			String Encode() const;
			uint256_t Hash(bool Renew = false) const;

		private:
			void WriteCompact(const void* Value, uint8_t Size);
			void WriteExtended(const void* Value, uint32_t Size);
			size_t ReadCompact(void* Value, uint8_t Size);
			size_t ReadExtended(void* Value, uint32_t Size);

		public:
			static Stream Decompress(const std::string_view& Data);
			static Stream Decode(const std::string_view& Data);
		};

		class Util
		{
		public:
			static String Encode0xHex(const std::string_view& Data);
			static String Decode0xHex(const std::string_view& Data);
			static String Assign0xHex(const std::string_view& Data);
			static String Clear0xHex(const std::string_view& Data, bool Uppercase = false);
			static bool IsHexEncoding(const std::string_view& Data);
			static bool IsInteger(Viewable Type);
			static bool IsString(Viewable Type);
			static bool IsString10(Viewable Type);
			static bool IsString16(Viewable Type);
			static uint8_t GetIntegerSize(Viewable Type);
			static Viewable GetIntegerType(const uint256_t& Data);
			static uint8_t GetStringSize(Viewable Type);
			static Viewable GetStringType(const std::string_view& Data, bool HexEncoding);
			static size_t GetMaxStringSize();
		};
	}
}
#endif