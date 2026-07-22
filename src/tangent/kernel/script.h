#ifndef TAN_KERNEL_SCRIPT_H
#define TAN_KERNEL_SCRIPT_H
#include "block.h"
#include <vitex/scripting.h>

namespace tangent
{
	namespace script
	{
		using namespace vitex::scripting;

		struct program;

		struct address_repr;

		class array_repr;

		enum class ccall
		{
			deploy_call,
			paying_call,
			const_call
		};

		enum class cquery
		{
			column = 0,
			row = 1,
			column_filter = 2,
			row_filter = 3
		};

		struct cobject
		{
			virtual_machine* vm;
			asITypeInfo* type;
			void* address;
			void** address_ptr;

			cobject(virtual_machine* new_vm, asITypeInfo* new_type, void* new_address, void** new_address_ptr) noexcept : vm(new_vm), type(new_type), address(new_address), address_ptr(new_address_ptr)
			{
			}
			cobject(const cobject& other) noexcept : vm(other.vm), type(other.type), address(other.address), address_ptr(other.address_ptr)
			{
				((cobject*)&other)->address = nullptr;
				((cobject*)&other)->address_ptr = nullptr;
			}
			cobject(cobject&& other) noexcept : vm(other.vm), type(other.type), address(other.address), address_ptr(other.address_ptr)
			{
				other.address = nullptr;
				other.address_ptr = nullptr;
			}
			~cobject()
			{
				destroy();
			}
			cobject& operator= (const cobject& other) noexcept
			{
				if (this == &other)
					return *this;

				destroy();
				vm = other.vm;
				type = other.type;
				address = other.address;
				address_ptr = other.address_ptr;
				((cobject*)&other)->address = nullptr;
				((cobject*)&other)->address_ptr = nullptr;
				return *this;
			}
			cobject& operator= (cobject&& other) noexcept
			{
				if (this == &other)
					return *this;

				destroy();
				vm = other.vm;
				type = other.type;
				address = other.address;
				address_ptr = other.address_ptr;
				other.address = nullptr;
				other.address_ptr = nullptr;
				return *this;
			}
			inline void reset()
			{
				address = nullptr;
				address_ptr = nullptr;
			}
			inline void destroy()
			{
				if (vm != nullptr && type != nullptr && address != nullptr)
					vm->release_object(address, type);
				if (address_ptr != nullptr)
					*address_ptr = nullptr;
			}
		};

		struct string_repr
		{
			static constexpr uint32_t npos = std::numeric_limits<uint32_t>::max();
			static constexpr uint32_t stack_capacity = 66;

			union
			{
				struct
				{
					char data[stack_capacity + 1];
					uint32_t size;
				} stack;
				struct
				{
					char* data;
					uint32_t size;
					uint32_t capacity;
				} heap;
			};
			bool heap_buffer;

			string_repr();
			string_repr(const string_repr& other);
			string_repr(const std::string_view& other);
			string_repr(string_repr&& other);
			string_repr& operator=(const string_repr& other);
			string_repr& operator=(const std::string_view& other);
			string_repr& operator=(string_repr&& other);
			~string_repr();
			string_repr& operator+=(const string_repr& other);
			string_repr& operator+=(char c);
			string_repr operator+(const string_repr& other) const;
			string_repr operator+(char c) const;
			string_repr& assign(const string_repr& other);
			string_repr& assign_view(const std::string_view& other);
			string_repr& assign_append(const string_repr& other);
			string_repr& assign_append_char(char c);
			string_repr append(const string_repr& other);
			string_repr append_char_back(char c);
			string_repr append_char_front(char c);
			bool operator==(const string_repr& other) const;
			int compare(const string_repr& other) const;
			const char* at(uint32_t index) const;
			const char* front() const;
			const char* back() const;
			bool empty() const;
			uint32_t size() const;
			uint32_t capacity() const;
			void clear();
			void push_front(char c);
			void pop_front();
			void push_back(char c);
			void pop_back();
			bool starts_with(const string_repr& other, uint32_t offset) const;
			bool ends_with(const string_repr& other) const;
			string_repr substring(uint32_t offset) const;
			string_repr substring_sized(uint32_t offset, uint32_t len) const;
			string_repr& trim();
			string_repr& trim_start();
			string_repr& trim_end();
			string_repr& to_lower();
			string_repr& to_upper();
			string_repr& reverse();
			std::string_view view() const;
			uint32_t rfind(const string_repr& other) const;
			uint32_t rfind_char(uint8_t other) const;
			uint32_t rfind_offset(const string_repr& other, uint32_t offset) const;
			uint32_t rfind_char_offset(uint8_t other, uint32_t offset) const;
			uint32_t find(const string_repr& other, uint32_t offset) const;
			uint32_t find_char(uint8_t other, uint32_t offset) const;
			uint32_t find_first_of(const string_repr& other, uint32_t offset) const;
			uint32_t find_first_not_of(const string_repr& other, uint32_t offset) const;
			uint32_t find_last_of(const string_repr& other) const;
			uint32_t find_last_not_of(const string_repr& other) const;
			uint32_t find_last_of_offset(const string_repr& other, uint32_t offset) const;
			uint32_t find_last_not_of_offset(const string_repr& other, uint32_t offset) const;
			array_repr* split(const string_repr& delimiter) const;
			char* data();
			const char* data() const;
			void copy_buffer(const char* buffer, uint32_t buffer_size);
			void move_buffer(string_repr&& other);
			void resize_buffer(uint32_t required_size);
			void require_buffer_capacity(uint32_t required_capacity);
			uint128_t from_string_uint128(int base) const;
			uint256_t from_string_uint256(int base) const;
			decimal from_string_decimal(int base) const;
			template <typename t>
			t from_string(int base) const
			{
				auto value = vitex::core::from_string<t>(view(), base);
				return value ? *value : (t)0;
			}
			template <typename t>
			static string_repr to_string(t other, int base)
			{
				return string_repr(vitex::core::to_string<t>(other, base));
			}
			static string_repr to_string_uint128(const uint128_t& other, int base);
			static string_repr to_string_uint256(const uint256_t& other, int base);
			static string_repr to_string_decimal(const decimal& other);
			static string_repr to_string_address(const address_repr& other);
			static void construct(string_repr* base);
			static void construct_copy(string_repr* base, const string_repr& other);
			static void destroy(string_repr* base);
			static uint32_t buffer_capacity_of(size_t required_size);
		};

		struct exception_repr
		{
			struct category
			{
				static std::string_view generic();
				static std::string_view requirement();
				static std::string_view argument();
				static std::string_view memory();
				static std::string_view storage();
				static std::string_view execution();
			};

			string type;
			string text;
			string origin;
			vitex::scripting::immediate_context* context;

			exception_repr();
			exception_repr(vitex::scripting::immediate_context* context, size_t offset = 0);
			exception_repr(const std::string_view& data, size_t offset = 0);
			exception_repr(const std::string_view& type, const std::string_view& text, size_t offset = 0);
			exception_repr(const string_repr& type, const string_repr& text, size_t offset = 0);
			exception_repr(const exception_repr&) = default;
			exception_repr& operator=(const exception_repr&) = default;
			void load_exception_data(const std::string_view& data);
			string_repr get_type() const;
			string_repr get_text() const;
			string_repr get_what() const;
			string to_exception_string() const;
			string to_full_exception_string() const;
			string load_stack_here(size_t offset = 0) const;
			bool empty() const;
		};

		class array_repr : public reference<array_repr>
		{
		public:
			struct sbuffer
			{
				uint32_t max_elements;
				uint32_t num_elements;
				unsigned char data[1];
			};

		private:
			vitex::scripting::type_info obj_type;
			sbuffer* buffer;
			uint32_t element_size;
			int sub_type_id;

		public:
			array_repr(uint32_t length, asITypeInfo* t);
			array_repr(uint32_t length, void* def_val, asITypeInfo* t);
			array_repr(const array_repr& other);
			~array_repr();
			asITypeInfo* get_array_object_type() const;
			int get_array_type_id() const;
			int get_element_type_id() const;
			uint32_t size() const;
			uint32_t capacity() const;
			bool empty() const;
			void reserve(uint32_t max_elements);
			void resize(uint32_t num_elements);
			void* front();
			const void* front() const;
			void* back();
			const void* back() const;
			void* at(uint32_t index);
			const void* at(uint32_t index) const;
			void set_value(uint32_t index, void* value);
			array_repr& operator= (const array_repr&);
			void insert_at(uint32_t index, void* value);
			void insert_array_at(uint32_t index, const array_repr& other);
			void insert_first(void* value);
			void insert_last(void* value);
			void remove_at(uint32_t index);
			void remove_first();
			void remove_last();
			void remove_range(uint32_t start, uint32_t count);
			void swap(uint32_t index1, uint32_t index2);
			void reverse();
			void clear();
			void* get_buffer();
			void enum_references(asIScriptEngine* engine);
			void release_references(asIScriptEngine* engine);

		private:
			void* get_array_item_pointer(uint32_t index);
			void* get_data_pointer(void* buffer);
			void copy(void* dst, void* src);
			bool check_max_size(uint32_t num_elements);
			void resize_buffer(int32_t delta, uint32_t at);
			void create_buffer(sbuffer** buf, uint32_t num_elements);
			void delete_buffer(sbuffer* buf);
			void copy_buffer(sbuffer* dst, sbuffer* src);
			void create(sbuffer* buf, uint32_t start, uint32_t end);
			void destroy(sbuffer* buf, uint32_t start, uint32_t end);

		public:
			static array_repr* construct(asITypeInfo* t);
			static array_repr* construct(asITypeInfo* t, uint32_t length);
			static array_repr* construct(asITypeInfo* t, uint32_t length, void* default_value);
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);

		public:
			template <typename t>
			static array_repr* compose(const vitex::scripting::type_info& array_type, const vector<t>& objects)
			{
				array_repr* array = construct(array_type.get_type_info(), objects.size());
				for (size_t i = 0; i < objects.size(); i++)
					array->set_value((uint32_t)i, (void*)&objects[i]);

				return array;
			}
			template <typename t>
			static typename std::enable_if<std::is_pointer<t>::value, vector<t>>::type decompose(array_repr* array)
			{
				vector<t> result;
				if (!array)
					return result;

				uint32_t size = array->size();
				result.reserve((size_t)size);

				for (uint32_t i = 0; i < size; i++)
					result.push_back((t)array->at(i));

				return result;
			}
			template <typename t>
			static typename std::enable_if<!std::is_pointer<t>::value, vector<t>>::type decompose(array_repr* array)
			{
				vector<t> result;
				if (!array)
					return result;

				uint32_t size = array->size();
				result.reserve((size_t)size);

				for (uint32_t i = 0; i < size; i++)
					result.push_back(*((t*)array->at(i)));

				return result;
			}
		};

		struct real320_repr
		{
			static void custom_constructor_bool(decimal* base, bool value);
			static void custom_constructor_string(decimal* base, const string_repr& value);
			static void custom_constructor_uint128(decimal* base, const uint128_t& value);
			static void custom_constructor_uint256(decimal* base, const uint256_t& value);
			static void custom_constructor_copy(decimal* base, const decimal& value);
			static void custom_constructor(decimal* base);
			static bool is_not_zero_or_nan(decimal& base);
			static bool truncate_or_throw(decimal& base, bool require_decimal_precision);
			static uint128_t to_uint128(decimal& base);
			static uint256_t to_uint256(decimal& base);
			static string_repr to_string(decimal& base);
			static string_repr to_exponent(decimal& base);
			static decimal negate(decimal& base);
			static decimal& mul_eq(decimal& base, const decimal& v);
			static decimal& div_eq(decimal& base, const decimal& v);
			static decimal& add_eq(decimal& base, const decimal& v);
			static decimal& sub_eq(decimal& base, const decimal& v);
			static decimal& fpp(decimal& base);
			static decimal& fmm(decimal& base);
			static decimal& pp(decimal& base);
			static decimal& mm(decimal& base);
			static bool eq(decimal& base, const decimal& right);
			static int cmp(decimal& base, const decimal& right);
			static decimal add(const decimal& left, const decimal& right);
			static decimal sub(const decimal& left, const decimal& right);
			static decimal mul(const decimal& left, const decimal& right);
			static decimal div(const decimal& left, const decimal& right);
			static decimal from(const string_repr& data, uint8_t base);
			static decimal zero();
			static uint32_t estimate_bits(uint32_t digits);
			static uint32_t target_bits();
			template <typename t>
			static void custom_constructor_arithmetic(decimal* base, t value)
			{
				new(base) decimal(value);
				truncate_or_throw(*base, true);
			}
		};

		struct uint128_repr
		{
			static void default_construct(uint128_t* base);
			static void construct_string(uint128_t* base, const string_repr& other);
			static bool to_bool(uint128_t& value);
			static int8_t to_int8(uint128_t& value);
			static uint8_t to_uint8(uint128_t& value);
			static int16_t to_int16(uint128_t& value);
			static uint16_t to_uint16(uint128_t& value);
			static int32_t to_int32(uint128_t& value);
			static uint32_t to_uint32(uint128_t& value);
			static int64_t to_int64(uint128_t& value);
			static uint64_t to_uint64(uint128_t& value);
			static uint256_t to_uint256(uint128_t& value);
			static string_repr to_string(uint128_t& base);
			static uint128_t& mul_eq(uint128_t& base, const uint128_t& v);
			static uint128_t& div_eq(uint128_t& base, const uint128_t& v);
			static uint128_t& add_eq(uint128_t& base, const uint128_t& v);
			static uint128_t& sub_eq(uint128_t& base, const uint128_t& v);
			static uint128_t& fpp(uint128_t& base);
			static uint128_t& fmm(uint128_t& base);
			static uint128_t& pp(uint128_t& base);
			static uint128_t& mm(uint128_t& base);
			static bool eq(uint128_t& base, const uint128_t& right);
			static int cmp(uint128_t& base, const uint128_t& right);
			static uint128_t add(const uint128_t& left, const uint128_t& right);
			static uint128_t sub(const uint128_t& left, const uint128_t& right);
			static uint128_t mul(const uint128_t& left, const uint128_t& right);
			static uint128_t div(const uint128_t& left, const uint128_t& right);
			static uint128_t per(const uint128_t& left, const uint128_t& right);
		};

		struct uint256_repr
		{
			static void default_construct(uint256_t* base);
			static void construct_string(uint256_t* base, const string_repr& other);
			static bool to_bool(uint256_t& value);
			static int8_t to_int8(uint256_t& value);
			static uint8_t to_uint8(uint256_t& value);
			static int16_t to_int16(uint256_t& value);
			static uint16_t to_uint16(uint256_t& value);
			static int32_t to_int32(uint256_t& value);
			static uint32_t to_uint32(uint256_t& value);
			static int64_t to_int64(uint256_t& value);
			static uint64_t to_uint64(uint256_t& value);
			static uint128_t to_uint128(uint256_t& value);
			static string_repr to_string(uint256_t& base);
			static uint256_t& mul_eq(uint256_t& base, const uint256_t& v);
			static uint256_t& div_eq(uint256_t& base, const uint256_t& v);
			static uint256_t& add_eq(uint256_t& base, const uint256_t& v);
			static uint256_t& sub_eq(uint256_t& base, const uint256_t& v);
			static uint256_t& fpp(uint256_t& base);
			static uint256_t& fmm(uint256_t& base);
			static uint256_t& pp(uint256_t& base);
			static uint256_t& mm(uint256_t& base);
			static bool eq(uint256_t& base, const uint256_t& right);
			static int cmp(uint256_t& base, const uint256_t& right);
			static uint256_t add(const uint256_t& left, const uint256_t& right);
			static uint256_t sub(const uint256_t& left, const uint256_t& right);
			static uint256_t mul(const uint256_t& left, const uint256_t& right);
			static uint256_t div(const uint256_t& left, const uint256_t& right);
			static uint256_t per(const uint256_t& left, const uint256_t& right);
		};

		struct payable_repr
		{
			vector<std::pair<algorithm::asset_id, decimal>> payments;
			decimal total_value;

			payable_repr();
			payable_repr(vector<std::pair<algorithm::asset_id, decimal>>&& new_payments);
			payable_repr(const payable_repr&) = default;
			payable_repr& operator=(const payable_repr&) = default;
			void recalculate();
			bool plus(const algorithm::asset_id& new_asset, const decimal& new_value);
			bool minus(const algorithm::asset_id& new_asset, const decimal& new_value);
			bool minus_total(const decimal& new_value);
			bool has(const algorithm::asset_id& new_asset) const;
			decimal of(const algorithm::asset_id& new_asset) const;
			const decimal& total() const;
			algorithm::asset_id at(uint32_t index) const;
			uint32_t size() const;
			uint32_t empty() const;
		};

		struct address_repr
		{
			algorithm::pubkeyhash_t hash;

			address_repr() = default;
			address_repr(const algorithm::pubkeyhash_t& owner);
			address_repr(const string_repr& address_repr);
			address_repr(const uint256_t& owner_data);
			address_repr(const address_repr&) = default;
			address_repr& operator=(const address_repr&) = default;
			void pay(const uint256_t& asset, const decimal& value);
			void pay_all(const payable_repr& payable);
			void mint(const string_repr& token, const decimal& supply, const decimal& reserve);
			void burn(const string_repr& token, const decimal& supply, const decimal& reserve);
			bool callable(const string_repr& entrypoint) const;
			decimal token_balance_of(const string_repr& token) const;
			decimal token_reserve_of(const string_repr& token) const;
			decimal balance_of(const uint256_t& asset) const;
			decimal reserve_of(const uint256_t& asset) const;
			string_repr to_string() const;
			uint256_t to_public_key_hash() const;
			bool empty() const;
			static void call(asIScriptGeneric* generic);
			static void static_call(asIScriptGeneric* generic);
			static void execute_call(asIScriptGeneric* generic, const payable_repr& value, size_t args_offset);
			static bool equals(const address_repr& a, const address_repr& b);
		};

		struct batch_payout_repr
		{
			btree_map<algorithm::pubkeyhash_t, btree_map<algorithm::asset_id, decimal>> payouts;

			void to(const address_repr& new_to, const algorithm::asset_id& new_asset, const decimal& new_value);
			void pay();
		};

		struct abi_repr
		{
			format::ro_stream input;
			format::wo_stream output;

			abi_repr() = default;
			abi_repr(const string_repr& data);
			abi_repr(const abi_repr&) = default;
			abi_repr& operator=(const abi_repr&) = default;
			void merge(const string_repr& value);
			void seek(uint32_t offset);
			void clear();
			void wboolean(bool value);
			void wuint160(const address_repr& value);
			void wuint256(const uint256_t& value);
			void wreal320(const decimal& value);
			void wstr(const string_repr& value);
			bool rboolean(bool& value);
			bool ruint160(address_repr& value);
			bool ruint256(uint256_t& value);
			bool rreal320(decimal& value);
			bool rstr(string_repr& value);
			string_repr data();
		};

		struct storage_repr
		{
			char buffer[sizeof(uint64_t)] = { 0 };
			void* value = nullptr;
			bool hidden = true;

			void destroy(const vitex::scripting::type_info& type);
			bool copy(const void* input_value, int input_type_id, const vitex::scripting::type_info& input_type);
			const void* address();
			static bool template_callback(const vitex::scripting::type_info& type, int input_type_id);
		};

		struct container_repr
		{
			vitex::scripting::type_info type = vitex::scripting::type_info(nullptr);
			uint8_t slot = 0;

			container_repr(asITypeInfo* new_type);
			virtual ~container_repr();
			virtual void reset() = 0;
		};

		struct varying_repr : container_repr
		{
			storage_repr container;
			bool known;

			varying_repr(asITypeInfo* new_type);
			~varying_repr();
			void reset() override;
			void erase();
			void save();
			void store(const void* new_value);
			void store_if(bool condition, const void* new_value);
			const void* load();
			const void* try_load();
			bool empty();
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
		};

		struct mapping_repr : container_repr
		{
			btree_map<string, std::pair<storage_repr, storage_repr>> map;

			mapping_repr(asITypeInfo* new_type);
			~mapping_repr();
			void reset() override;
			void erase(const void* new_key);
			void store(const void* new_key, const void* new_value);
			void store_if(bool condition, const void* new_key, const void* new_value);
			const void* load(const void* new_key);
			const void* try_load(const void* new_key);
			bool has(const void* new_key);
			string to_key(const void* new_key);
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
		};

		struct listing_repr : container_repr
		{
			btree_map<uint32_t, storage_repr> list;
			option<uint32_t> length;

			listing_repr(asITypeInfo* new_type);
			~listing_repr();
			void reset() override;
			void clear();
			uint32_t size();
			bool empty();
			const void* load_first();
			const void* load_last();
			const void* load_at(uint32_t index);
			const void* try_load_at(uint32_t index);
			void store_at(uint32_t index, const void* value);
			void erase_at(uint32_t index);
			void insert_last(const void* value);
			void insert_first(const void* value);
			void remove_last();
			void remove_first();
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
		};

		struct ranging_slice_repr
		{
			format::wo_stream subject;
			ledger::filter_comparator comparator = ledger::filter_comparator::equal;
			ledger::filter_order order = ledger::filter_order::ascending;
			uint256_t value;
			uint32_t offset;
			uint32_t count;
			uint8_t slot;
			cquery mode;

			bool next(void* object_value, int object_type_id);
			bool next_index(void* object_value, int object_type_id, void* other_index_value, int other_index_type_id);
			bool next_index_ranked(void* object_value, int object_type_id, void* other_index_value, int other_index_type_id, uint256_t* filter_value);
			static void wrapped_next(asIScriptGeneric* generic);
			static void wrapped_next_object(asIScriptGeneric* generic);
			static void wrapped_next_object_index(asIScriptGeneric* generic);
			static void wrapped_next_object_index_ranked(asIScriptGeneric* generic);
			ranging_slice_repr& with_offset(uint32_t new_offset);
			ranging_slice_repr& with_count(uint32_t new_count);
			ranging_slice_repr& where_gt(const uint256_t& new_value);
			ranging_slice_repr& where_gte(const uint256_t& new_value);
			ranging_slice_repr& where_eq(const uint256_t& new_value);
			ranging_slice_repr& where_neq(const uint256_t& new_value);
			ranging_slice_repr& where_lt(const uint256_t& new_value);
			ranging_slice_repr& where_lte(const uint256_t& new_value);
			ranging_slice_repr& order_asc();
			ranging_slice_repr& order_desc();
			static ranging_slice_repr from(cquery new_mode, uint8_t new_slot, const void* index_value, int index_type_id);
		};

		struct ranging_repr : container_repr
		{
			struct range_item
			{
				storage_repr column;
				storage_repr row;
				storage_repr value;
			};
			btree_map<string, range_item> map;

			ranging_repr(asITypeInfo* new_type);
			~ranging_repr();
			void reset() override;
			ranging_slice_repr from_column(const void* new_column);
			ranging_slice_repr from_row(const void* new_row);
			void erase(const void* new_column, const void* new_row);
			void store(const void* new_column, const void* new_row, void* new_value);
			void store_if(bool condition, const void* new_column, const void* new_row, void* new_value);
			void store_positioned(const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position);
			void store_positioned_if(bool condition, const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position);
			static void wrapped_store_positioned_if(asIScriptGeneric* generic);
			const void* load(const void* new_column, const void* new_row);
			const void* try_load(const void* new_column, const void* new_row);
			bool has(const void* new_column, const void* new_row);
			bool has_column(const void* new_column);
			bool has_row(const void* new_row);
			string to_key(const void* new_column, const void* new_row);
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
		};

		struct contract
		{
			static void uniform_store(const void* index_value, int index_type_id, const void* object_value, int object_type_id);
			static void uniform_store_slot(uint8_t slot, const void* index_value, int index_type_id, const void* object_value, int object_type_id);
			static bool uniform_load(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error);
			static bool uniform_load_slot(uint8_t slot, const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error);
			static void uniform_set(const void* index_value, int index_type_id, void* object_value, int object_type_id);
			static void uniform_erase(const void* index_value, int index_type_id);
			static void uniform_set_if(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool condition);
			static bool uniform_has(const void* index_value, int index_type_id);
			static bool uniform_into(const void* index_value, int index_type_id, void* object_value, int object_type_id);
			static void uniform_get(asIScriptGeneric* generic);
			static void multiform_store(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value);
			static void multiform_store_slot(uint8_t slot, const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value);
			static bool multiform_load(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error);
			static bool multiform_load_slot(uint8_t slot, const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error);
			static void multiform_set_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value);
			static void multiform_set(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id);
			static void multiform_erase(const void* column_value, int column_type_id, const void* row_value, int row_type_id);
			static void multiform_set_if_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value, bool condition);
			static void multiform_set_if(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool condition);
			static bool multiform_into_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value);
			static bool multiform_into(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id);
			static bool multiform_has(const void* column_value, int column_type_id, const void* row_value, int row_type_id);
			static void multiform_get(asIScriptGeneric* generic);
			static void log_emit(asIScriptGeneric* generic);
			static void log_event(asIScriptGeneric* generic);
			static void log_into(asIScriptGeneric* generic);
			static void log_event_into(asIScriptGeneric* generic);
			static void log_get(asIScriptGeneric* generic);
			static void log_get_event(asIScriptGeneric* generic);
			static address_repr block_proposer();
			static uint256_t block_parent_hash();
			static uint256_t block_gas_use();
			static uint256_t block_gas_left();
			static uint256_t block_gas_limit();
			static uint128_t block_difficulty();
			static uint64_t block_time();
			static uint64_t block_time_between(uint64_t block_number_a, uint64_t block_number_b);
			static uint64_t block_priority();
			static uint64_t block_number();
			static payable_repr tx_value();
			static bool tx_paid();
			static address_repr tx_from();
			static address_repr tx_to();
			static string_repr tx_blockchain();
			static string_repr tx_token();
			static string_repr tx_contract();
			static decimal tx_gas_price();
			static uint256_t tx_gas_use();
			static uint256_t tx_gas_left();
			static uint256_t tx_gas_limit();
			static uint256_t tx_asset();
			static uint256_t coin_native();
			static uint256_t coin_token(const string_repr& token);
			static uint256_t coin_id_of(const string_repr& blockchain, const string_repr& token, const string_repr& contract_address);
			static string_repr coin_blockchain_of(const uint256_t& value);
			static string_repr coin_token_of(const uint256_t& value);
			static string_repr coin_checksum_of(const uint256_t& value);
			static string_repr coin_name_of(const uint256_t& value);
			static uint256_t alg_to_r256(const decimal& value);
			static decimal alg_from_r256(const uint256_t& value);
			static string_repr alg_from_u256(const uint256_t& value);
			static uint256_t alg_to_u256(const string_repr& value);
			static string_repr alg_from_e16(const string_repr& value);
			static string_repr alg_to_e16(const string_repr& value);
			static address_repr alg_erecover160(const uint256_t& hash, const string_repr& signature);
			static string_repr alg_erecover264(const uint256_t& hash, const string_repr& signature);
			static string_repr alg_crc32(const string_repr& data);
			static string_repr alg_ripemd160(const string_repr& data);
			static uint256_t alg_blake2b256(const string_repr& data);
			static string_repr alg_blake2b256s(const string_repr& data);
			static uint256_t alg_keccak256(const string_repr& data);
			static string_repr alg_keccak256s(const string_repr& data);
			static string_repr alg_keccak512(const string_repr& data);
			static uint256_t alg_sha256(const string_repr& data);
			static string_repr alg_sha256s(const string_repr& data);
			static string_repr alg_sha512(const string_repr& data);
			static uint256_t alg_prandom();
			static void math_min_value(asIScriptGeneric* generic);
			static void math_max_value(asIScriptGeneric* generic);
			static void math_abs(asIScriptGeneric* generic);
			static void math_min(asIScriptGeneric* generic);
			static void math_max(asIScriptGeneric* generic);
			static void math_clamp(asIScriptGeneric* generic);
			static void math_lerp(asIScriptGeneric* generic);
			static void math_pow(asIScriptGeneric* generic);
			static void math_sqrt(asIScriptGeneric* generic);
			static void require(bool condition, const string_repr& message);
			static void throw_ptr_at(vitex::scripting::immediate_context* context, const exception_repr& data);
			static void throw_ptr(const exception_repr& data);
			static void rethrow_at(vitex::scripting::immediate_context* context);
			static void rethrow();
			static bool has_exception_at(vitex::scripting::immediate_context* context);
			static bool has_exception();
			static exception_repr get_exception_at(vitex::scripting::immediate_context* context, size_t offset = 0);
			static exception_repr get_exception(size_t offset = 0);
		};

		class marshall
		{
		public:
			static expects_lr<void> index(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(format::tree& stream, const void* value, int value_type_id);
			static expects_lr<void> load(format::ro_stream& stream, void* value, int value_type_id, bool allow_partial = true);
			static expects_lr<void> load(format::tree& stream, void* value, int value_type_id, bool allow_partial = true);
		};

		struct cmodule
		{
			library ref;

			cmodule() noexcept;
			cmodule(library&& new_ref) noexcept;
			cmodule(const cmodule&) noexcept = delete;
			cmodule(cmodule&& other) noexcept;
			~cmodule();
			cmodule& operator= (const cmodule&) noexcept = delete;
			cmodule& operator= (cmodule&& other) noexcept;
			explicit operator bool() const;
			library* operator-> ();
			const library* operator-> () const;
			library& operator* ();
			const library& operator* () const;
			library reset();
			void destroy();
		};

		class factory : public singleton<factory>
		{
		private:
			struct module_ref
			{
				library ref = nullptr;
				size_t count = 0;
			};

		private:
			std::recursive_mutex mutex;
			hash_map<string, module_ref> modules;
			uptr<virtual_machine> vm;
			uptr<compiler> vmc;
			string vmc_log;
			bool vmc_tools;
			void* strings;

		public:
			std::mutex exclusive;

		public:
			factory() noexcept;
			virtual ~factory() noexcept override;
			void bind_debugger_tools(debugger_context* debugger);
			void return_module(cmodule&& value);
			string export_predefined_symbols();
			expects_lr<cmodule> compile_module(const std::string_view& hashcode, const std::function<expects_lr<string>()>& unpacked_code_callback);
			expects_lr<void> reset_module(library& module, immediate_context* context);
			virtual_machine* get_vm();

		private:
			static const void* to_string_constant(void* context, const char* buffer, size_t buffer_size);
			static int from_string_constant(void* context, const void* object, char* buffer, size_t* buffer_size);
			static int free_string_constant(void* context, const void* object);
		};

		struct program
		{
			struct cache_storage
			{
				hash_map<string, hash_map<string, uptr<states::account_multiform>>> index[2];
				option<algorithm::wesolowski::distribution> distribution = optional::none;
				option<payable_repr> payable = optional::none;
			} cache;
			ledger::executor_context* executor;
			library module;

			program(ledger::executor_context* new_executor, library&& new_module, program* new_parent = nullptr);
			virtual expects_lr<void> execute(const payable_repr& payable, ccall mutability, const std::string_view& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> execute(const payable_repr& payable, ccall mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const algorithm::pubkeyhash_t& target, const payable_repr& payable, ccall mutability, const std::string_view& entrypoint, format::variables&& args, void* output_value, int output_type_id);
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> dispatch_arguments(ccall* mutability, const function& entrypoint, const format::variables* args) const;
			virtual void dispatch_event(int event_type_id, const void* object_value, int object_type_id);
			virtual void dispatch_exception(immediate_context* coroutine);
			virtual void dispatch_coroutine(immediate_context* coroutine);
            virtual option<ccall> external_mutability_of(const algorithm::pubkeyhash_t& target, const std::string_view& entrypoint) const;
			virtual ccall mutability_of(const function& entrypoint) const;
			virtual algorithm::pubkeyhash_t callable() const;
			virtual payable_repr payable_value() const;
			virtual function deploy_function() const;
			virtual string function_declaration() const;
			virtual const format::variables* function_arguments() const;
			virtual uint64_t virtual_block_number() const;
			static program* fetch_mutable(immediate_context* coroutine = immediate_context::get());
			static const program* fetch_immutable(immediate_context* coroutine = immediate_context::get());
			static program* fetch_mutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static const program* fetch_immutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static bool request_gas_mop(size_t difficulty);
			static bool request_gas_vmemory(size_t size);
			static bool request_gas_vmemory_marshall(const format::ro_stream& stream, size_t prev_seek);
			template <typename t>
			static inline t* request_gas_memory(size_t size)
			{
				return request_gas_vmemory(size) ? memory::allocate<t>(size) : nullptr;
			}
		};
	}
}

namespace vitex
{
	namespace core
	{
		template <>
		struct key_hash<tangent::script::string_repr>
		{
			typedef int argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::script::string_repr& value) const noexcept
			{
				return key_hash<std::string_view>()(value.view());
			}
		};
	}
}
#endif
