#ifndef TAN_LAYER_TYPES_HPP
#define TAN_LAYER_TYPES_HPP
#include "../kernel/chain.h"

namespace vitex
{
	namespace core
	{
		template <>
		struct key_hasher<uint256_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const uint256_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)&value, sizeof(value)));
			}
		};

		template <>
		struct key_hasher<uint128_t>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const uint128_t& value) const noexcept
			{
				return key_hasher<std::string_view>()(std::string_view((char*)&value, sizeof(value)));
			}
		};

		struct insensitive_comparator
		{
			bool operator() (const string& a, const string& b) const
			{
				return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return std::tolower(a) < std::tolower(b); });
			}
		};

		struct inversion_comparator
		{
			bool operator() (uint8_t a, uint8_t b) const
			{
				return a > b;
			}
		};

		using account_value_map = ordered_map<string, decimal>;
		using address_value_map = ordered_map<string, decimal, insensitive_comparator>;
		using address_map = ordered_map<uint8_t, string, inversion_comparator>;
	}
}
#endif