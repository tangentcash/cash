#ifndef TAN_KERNEL_FORMAT_H
#define TAN_KERNEL_FORMAT_H
#include "chain.h"

namespace tangent
{
	namespace format
	{
		struct ro_stream;

		typedef vector<struct variable> variables;

		enum class viewable : uint8_t
		{
			decimal_nan,
			decimal_zero,
			decimal_neg1,
			decimal_neg2,
			decimal_pos1,
			decimal_pos2,
			true_type,
			false_type,
			uint_min,
			uint_max = uint_min + sizeof(uint256_t),
			string_any10,
			string_min10,
			string_max10 = string_min10 + 104,
			string_any16,
			string_min16,
			string_max16 = string_min16 + 104,
			invalid = 255
		};

		struct wo_stream
		{
			string data;
			uint256_t checksum;

			wo_stream();
			explicit wo_stream(const std::string_view& new_data);
			explicit wo_stream(string&& new_data);
			wo_stream(const wo_stream&) = default;
			wo_stream(wo_stream&&) noexcept = default;
			wo_stream& operator= (const wo_stream&) = default;
			wo_stream& operator= (wo_stream&&) noexcept = default;
			wo_stream& clear();
			wo_stream& write_string(const std::string_view& value);
			wo_stream& write_string_raw(const std::string_view& value);
			wo_stream& write_decimal(const decimal& value);
			wo_stream& write_integer(const uint256_t& value);
			wo_stream& write_boolean(bool value);
			wo_stream& write_typeless(const uint256_t& value);
			wo_stream& write_typeless(const uint256_t& value, size_t size);
			wo_stream& write_typeless(const void* data, size_t size);
			string compress() const;
			string encode() const;
			uint256_t hash(bool renew = false) const;
			ro_stream ro() const;

		private:
			void write(const void* value, uint32_t size);
		};

		struct ro_stream
		{
			std::string_view data;
			uint256_t checksum;
			size_t seek;

			ro_stream();
			explicit ro_stream(const std::string_view& new_data);
			ro_stream(const ro_stream&) = default;
			ro_stream(ro_stream&&) noexcept = default;
			ro_stream& operator= (const ro_stream&) = default;
			ro_stream& operator= (ro_stream&&) noexcept = default;
			ro_stream& rewind(size_t offset = 0);
			ro_stream& clear();
			viewable read_type();
			bool read_type(viewable* value);
			bool read_string(viewable type, string* value);
			bool read_decimal(viewable type, decimal* value);
			bool read_decimal_or_integer(format::viewable type, decimal* value);
			bool read_integer(viewable type, uint8_t* value);
			bool read_integer(viewable type, uint16_t* value);
			bool read_integer(viewable type, uint32_t* value);
			bool read_integer(viewable type, uint64_t* value);
			bool read_integer(viewable type, uint128_t* value);
			bool read_integer(viewable type, uint256_t* value);
			bool read_boolean(viewable type, bool* value);
			bool is_eof() const;
			uint256_t hash(bool renew = false) const;
			wo_stream wo() const;

		private:
			size_t read(void* value, uint32_t size);
		};

		struct variable
		{
		private:
			union tag
			{
				char string[52];
				char* pointer;
				uint256_t integer;
				bool boolean;
			} value;

		private:
			viewable type;
			uint32_t length;

		public:
			variable() noexcept;
			explicit variable(const char* value) noexcept;
			explicit variable(const std::string_view& value) noexcept;
			explicit variable(const string& value) noexcept;
			explicit variable(const decimal& value) noexcept;
			explicit variable(const uint8_t& value) noexcept;
			explicit variable(const uint16_t& value) noexcept;
			explicit variable(const uint32_t& value) noexcept;
			explicit variable(const uint64_t& value) noexcept;
			explicit variable(const uint128_t& value) noexcept;
			explicit variable(const uint256_t& value) noexcept;
			explicit variable(bool value) noexcept;
			variable(const variable& other) noexcept;
			variable(variable&& other) noexcept;
			~variable() noexcept;
			string as_constant() const;
			string as_blob() const;
			decimal as_decimal() const;
			uptr<schema> as_schema() const;
			std::string_view as_string() const;
			uint8_t as_uint8() const;
			uint16_t as_uint16() const;
			uint32_t as_uint32() const;
			uint64_t as_uint64() const;
			uint128_t as_uint128() const;
			uint256_t as_uint256() const;
			float as_float() const;
			double as_double() const;
			bool as_boolean() const;
			bool is_string() const;
			bool is_decimal() const;
			bool is_integer() const;
			viewable type_of() const;
			variable& operator= (const variable& other) noexcept;
			variable& operator= (variable&& other) noexcept;
			bool operator== (const variable& other) const;
			bool operator!= (const variable& other) const;

		private:
			variable(viewable new_type) noexcept;
			bool same(const variable& value) const;
			void copy(const variable& other);
			void move(variable&& other);
			void free();

		private:
			static size_t get_max_small_string_size();

		public:
			static variable from(const std::string_view& any);
		};

		class util
		{
		public:
			static string decompress_stream(const std::string_view& data);
			static string decode_stream(const std::string_view& data);
			static string encode_0xhex(const std::string_view& data);
			static string decode_0xhex(const std::string_view& data);
			static string assign_0xhex(const std::string_view& data);
			static string clear_0xhex(const std::string_view& data, bool uppercase = false);
			static bool is_hex_encoding(const std::string_view& data);
			static bool is_base64_encoding(const std::string_view& data);
			static bool is_base64_url_encoding(const std::string_view& data);
			static bool is_integer(viewable type);
			static bool is_string(viewable type);
			static bool is_string10(viewable type);
			static bool is_string16(viewable type);
			static uint8_t get_integer_size(viewable type);
			static viewable get_integer_type(const uint256_t& data);
			static uint8_t get_string_size(viewable type);
			static viewable get_string_type(const std::string_view& data, bool hex_encoding);
			static size_t get_max_string_size();
		};

		class variables_util
		{
		public:
			static bool is_ascii_encoding(const std::string_view& data);
			static bool deserialize_flat_from(ro_stream& stream, variables* result);
			static bool serialize_flat_into(const variables& data, wo_stream* result);
			static bool deserialize_merge_from(ro_stream& stream, variables* result);
			static bool serialize_merge_into(const variables& data, wo_stream* result);
			static string as_constant(const variables& data);
			static string as_constant_json(const variables& data, size_t spaces = 2);
			static schema* serialize(const variables& data);

		private:
			static bool deserialize_from(ro_stream& stream, variables* result, bool merging);
			static bool serialize_into(const variables& data, wo_stream* result, bool merging);
		};
	}
}

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