#ifndef TAN_LAYER_TYPES_HPP
#define TAN_LAYER_TYPES_HPP
#include "../kernel/chain.h"

namespace Vitex
{
	namespace Core
	{
		template <>
		struct KeyHasher<uint256_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const uint256_t& Value) const noexcept
			{
				return KeyHasher<std::string_view>()(std::string_view((char*)&Value, sizeof(Value)));
			}
		};

		template <>
		struct KeyHasher<uint128_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const uint128_t& Value) const noexcept
			{
				return KeyHasher<std::string_view>()(std::string_view((char*)&Value, sizeof(Value)));
			}
		};

		struct InsensitiveComparator
		{
			bool operator() (const String& A, const String& B) const
			{
				return std::lexicographical_compare(A.begin(), A.end(), B.begin(), B.end(), [](char A, char B) { return std::tolower(A) < std::tolower(B); });
			}
		};

		struct InversionComparator
		{
			bool operator() (uint8_t A, uint8_t B) const
			{
				return A > B;
			}
		};

		using AccountValueMap = OrderedMap<String, Decimal>;
		using AddressValueMap = OrderedMap<String, Decimal, InsensitiveComparator>;
		using AddressMap = OrderedMap<uint8_t, String, InversionComparator>;
	}
}
#endif