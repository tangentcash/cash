#ifndef TAN_LAYER_FORMAT_H
#define TAN_LAYER_FORMAT_H
#include "serialization.h"

namespace Tangent
{
	namespace Format
	{
		typedef Vector<struct Variable> Variables;

		struct Variable
		{
		private:
			union Tag
			{
				char String[52];
				char* Pointer;
				uint256_t Integer;
				bool Boolean;
			} Value;

		private:
			Viewable Type;
			uint32_t Length;

		public:
			Variable() noexcept;
			explicit Variable(const char* Value) noexcept;
			explicit Variable(const std::string_view& Value) noexcept;
			explicit Variable(const String& Value) noexcept;
			explicit Variable(const Decimal& Value) noexcept;
			explicit Variable(const uint8_t& Value) noexcept;
			explicit Variable(const uint16_t& Value) noexcept;
			explicit Variable(const uint32_t& Value) noexcept;
			explicit Variable(const uint64_t& Value) noexcept;
			explicit Variable(const uint128_t& Value) noexcept;
			explicit Variable(const uint256_t& Value) noexcept;
			explicit Variable(bool Value) noexcept;
			explicit Variable(Schema* Value) noexcept;
			Variable(const Variable& Other) noexcept;
			Variable(Variable&& Other) noexcept;
			~Variable() noexcept;
			String AsConstant() const;
			String AsBlob() const;
			Decimal AsDecimal() const;
			UPtr<Schema> AsVariative() const;
			std::string_view AsString() const;
			uint8_t AsUint8() const;
			uint16_t AsUint16() const;
			uint32_t AsUint32() const;
			uint64_t AsUint64() const;
			uint128_t AsUint128() const;
			uint256_t AsUint256() const;
			float AsFloat() const;
			double AsDouble() const;
			bool AsBoolean() const;
			bool IsString() const;
			bool IsDecimal() const;
			bool IsInteger() const;
			bool IsVariative() const;
			Viewable TypeOf() const;
			Variable& operator= (const Variable& Other) noexcept;
			Variable& operator= (Variable&& Other) noexcept;
			bool operator== (const Variable& Other) const;
			bool operator!= (const Variable& Other) const;

		private:
			Variable(Viewable NewType) noexcept;
			bool Same(const Variable& Value) const;
			void Copy(const Variable& Other);
			void Move(Variable&& Other);
			void Free();

		private:
			static size_t GetMaxSmallStringSize();
		};

		class VariablesUtil
		{
		public:
			static bool IsAsciiEncoding(const std::string_view& Data);
			static bool DeserializeFlatFrom(Stream& Stream, Variables* Result);
			static bool SerializeFlatInto(const Variables& Data, Stream* Result);
			static bool DeserializeMergeFrom(Stream& Stream, Variables* Result);
			static bool SerializeMergeInto(const Variables& Data, Stream* Result);
			static String AsConstant(const Variables& Data);
			static String AsConstantJSON(const Variables& Data, size_t Spaces = 2);
			static Schema* Serialize(const Variables& Data);

		private:
			static bool DeserializeFrom(Stream& Stream, Variables* Result, bool Merging);
			static bool SerializeInto(const Variables& Data, Stream* Result, bool Merging);
		};
	}
}
#endif