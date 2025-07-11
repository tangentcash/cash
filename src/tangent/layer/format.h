#ifndef TAN_LAYER_FORMAT_H
#define TAN_LAYER_FORMAT_H
#include "serialization.h"

namespace tangent
{
	namespace format
	{
		typedef vector<struct variable> variables;

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
#endif