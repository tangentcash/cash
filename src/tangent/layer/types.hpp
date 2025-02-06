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

		template <typename Iterator, typename Function>
		static Core::Vector<Core::Promise<void>> ParallelForEach(Iterator Begin, Iterator End, Function Callback)
		{
			Core::Vector<Core::Promise<void>> Tasks;
			size_t Size = End - Begin;
			if (!Size)
				return Tasks;

			size_t Threads = std::max<size_t>(1, Layer::Parallel::GetThreads());
			if (Schedule::IsAvailable() && Threads > 1)
			{
				size_t Step = Size / Threads;
				size_t Remains = Size % Threads;
				Tasks.reserve(Threads);
				while (Begin != End)
				{
					auto Offset = Begin;
					Begin += Remains > 0 ? --Remains, Step + 1 : Step;
					Tasks.emplace_back(Cotask<void>(std::bind(std::for_each<Iterator, Function>, Offset, Begin, Callback), false));
				}
			}
			else
				std::for_each(Begin, End, Callback);
			return Tasks;
		}
		template <typename Iterator, typename Function>
		static Core::Vector<Core::Promise<void>> ParallelForEachNode(Iterator Begin, Iterator End, size_t Size, Function Callback)
		{
			Core::Vector<Core::Promise<void>> Tasks;
			if (!Size)
				return Tasks;

			size_t Threads = std::max<size_t>(1, Layer::Parallel::GetThreads());
			if (Schedule::IsAvailable() && Threads > 1)
			{
				size_t Step = Size / Threads;
				size_t Remains = Size % Threads;
				Tasks.reserve(Threads);
				while (Begin != End)
				{
					auto Offset = Begin;
					size_t Count = Remains > 0 ? --Remains, Step + 1 : Step;
					while (Count-- > 0)
						++Begin;
					Tasks.emplace_back(Cotask<void>(std::bind(std::for_each<Iterator, Function>, Offset, Begin, Callback), false));
				}
			}
			else
				std::for_each(Begin, End, Callback);
			return Tasks;
		}
	}
}
#endif