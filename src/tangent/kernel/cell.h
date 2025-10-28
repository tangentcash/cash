#ifndef TAN_KERNEL_CELL_H
#define TAN_KERNEL_CELL_H
#include "block.h"

namespace tangent
{
	namespace cell
	{
		using namespace vitex::scripting;

		struct address_repr;

		class array_repr;

		enum class ccall
		{
			upgrade_call,
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

			cobject(virtual_machine* new_vm, asITypeInfo* new_type, void* new_address) noexcept : vm(new_vm), type(new_type), address(new_address)
			{
			}
			cobject(const cobject& other) noexcept : vm(other.vm), type(other.type), address(other.address)
			{
				((cobject*)&other)->address = nullptr;
			}
			cobject(cobject&& other) noexcept : vm(other.vm), type(other.type), address(other.address)
			{
				other.address = nullptr;
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
				((cobject*)&other)->address = nullptr;
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
				other.address = nullptr;
				return *this;
			}
			inline void destroy()
			{
				if (vm != nullptr && type != nullptr && address != nullptr)
					vm->release_object(address, type);
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
			string_repr(string_repr&& other) noexcept;
			string_repr& operator=(const string_repr& other);
			string_repr& operator=(const std::string_view& other);
			string_repr& operator=(string_repr&& other) noexcept;
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
			string_repr append_char(char c);
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
			static void create(string_repr* base);
			static void create_copy(string_repr* base, const string_repr& other);
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
			exception_repr(vitex::scripting::immediate_context* context);
			exception_repr(const std::string_view& data);
			exception_repr(const std::string_view& type, const std::string_view& text);
			exception_repr(const string_repr& type, const string_repr& text);
			exception_repr(const exception_repr&) = default;
			exception_repr& operator=(const exception_repr&) = default;
			void load_exception_data(const std::string_view& data);
			string_repr get_type() const;
			string_repr get_text() const;
			string_repr get_what() const;
			string to_exception_string() const;
			string to_full_exception_string() const;
			string load_stack_here() const;
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

			struct scache
			{
				asIScriptFunction* comparator;
				asIScriptFunction* equals;
				int comparator_return_code;
				int equals_return_code;
			};

		private:
			vitex::scripting::type_info obj_type;
			sbuffer* buffer;
			uint32_t element_size;
			int sub_type_id;

		public:
			array_repr(uint32_t length, asITypeInfo* t) noexcept;
			array_repr(uint32_t length, void* def_val, asITypeInfo* t) noexcept;
			array_repr(const array_repr& other) noexcept;
			~array_repr() noexcept;
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
			array_repr& operator= (const array_repr&) noexcept;
			bool operator== (const array_repr&) const;
			void insert_at(uint32_t index, void* value);
			void insert_at(uint32_t index, const array_repr& other);
			void insert_last(void* value);
			void remove_at(uint32_t index);
			void remove_last();
			void remove_range(uint32_t start, uint32_t count);
			void remove_if(void* value, uint32_t start_at);
			void swap(uint32_t index1, uint32_t index2);
			void sort(asIScriptFunction* callback);
			void reverse();
			void clear();
			uint32_t find(void* value, uint32_t start_at) const;
			uint32_t find_by_ref(void* value, uint32_t start_at) const;
			void* get_buffer();
			void enum_references(asIScriptEngine* engine);
			void release_references(asIScriptEngine* engine);

		private:
			void* get_array_item_pointer(uint32_t index);
			void* get_data_pointer(void* buffer);
			void copy(void* dst, void* src);
			void precache();
			bool check_max_size(uint32_t num_elements);
			void resize(int64_t delta, uint32_t at);
			void create_buffer(sbuffer** buf, uint32_t num_elements);
			void delete_buffer(sbuffer* buf);
			void copy_buffer(sbuffer* dst, sbuffer* src);
			void create(sbuffer* buf, uint32_t start, uint32_t end);
			void destroy(sbuffer* buf, uint32_t start, uint32_t end);
			bool less(const void* a, const void* b, immediate_context* ctx, scache* cache);
			bool equals(const void* a, const void* b, immediate_context* ctx, scache* cache) const;
			bool is_eligible_for_find(scache** output) const;
			bool is_eligible_for_sort(scache** output) const;

		public:
			static array_repr* create(asITypeInfo* t);
			static array_repr* create(asITypeInfo* t, uint32_t length);
			static array_repr* create(asITypeInfo* t, uint32_t length, void* default_value);
			static void cleanup_type_info_cache(asITypeInfo* type);
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
			static size_t get_id();

		public:
			template <typename t>
			static array_repr* compose(const vitex::scripting::type_info& array_type, const vector<t>& objects)
			{
				array_repr* array = create(array_type.get_type_info(), objects.size());
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
			static decimal per(const decimal& left, const decimal& right);
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
			decimal balance_of(const uint256_t& asset) const;
			string_repr to_string() const;
			uint256_t to_public_key_hash() const;
			bool empty() const;
			static void free_call(asIScriptGeneric* generic);
			static void paid_call(asIScriptGeneric* generic);
			static void call(asIScriptGeneric* generic, const decimal& value);
			static bool equals(const address_repr& a, const address_repr& b);
		};

		struct abi_repr
		{
			format::ro_stream input;
			format::wo_stream output;

			abi_repr() = default;
			abi_repr(const string_repr& data);
			abi_repr(const abi_repr&) = default;
			abi_repr& operator=(const abi_repr&) = default;
			void seek(uint32_t offset);
			void clear();
			void wboolean(bool value);
			void wuint160(const address_repr& value);
			void wuint256(const uint256_t& value);
			void wreal320(const decimal& value);
			void merge(const string_repr& value);
			void wstr(const string_repr& value);
			void wrstr(const string_repr& value);
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
			void store(const void* new_value);
			void store_if(bool condition, const void* new_value);
			const void* load();
			const void* try_load();
			bool empty();
			static bool template_callback(asITypeInfo* t, bool& dont_garbage_collect);
		};

		struct mapping_repr : container_repr
		{
			ordered_map<string, std::pair<storage_repr, storage_repr>> map;

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
			static ranging_slice_repr from_column(const void* index_value, int index_type_id);
			static ranging_slice_repr from_row(const void* index_value, int index_type_id);
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
			ordered_map<string, range_item> map;

			ranging_repr(asITypeInfo* new_type);
			~ranging_repr();
			void reset() override;
			const void* from(ranging_slice_repr& slice);
			ranging_slice_repr from_column(const void* new_column);
			ranging_slice_repr from_row(const void* new_row);
			void erase(const void* new_column, const void* new_row);
			void store(const void* new_column, const void* new_row, void* new_value);
			void store_if(bool condition, const void* new_column, const void* new_row, void* new_value);
			void store_positioned(const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position);
			void store_positioned_if(bool condition, const void* new_column, const void* new_row, void* new_value, const uint256_t& new_position);
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
			static void log_emit(const void* object_value, int object_type_id);
			static void log_event(const void* event_value, int event_type_id, const void* object_value, int object_type_id);
			static bool log_into(int32_t event_index, void* object_value, int object_type_id);
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
			static decimal tx_value();
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
			static uint256_t coin_from_decimal(const decimal& value);
			static decimal coin_to_decimal(const uint256_t& value);
			static uint256_t coin_id_of(const string_repr& blockchain, const string_repr& token, const string_repr& contract_address);
			static string_repr coin_blockchain_of(const uint256_t& value);
			static string_repr coin_token_of(const uint256_t& value);
			static string_repr coin_checksum_of(const uint256_t& value);
			static string_repr coin_name_of(const uint256_t& value);
			static string_repr alg_encode_bytes256(const uint256_t& value);
			static uint256_t alg_decode_bytes256(const string_repr& value);
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
			static exception_repr get_exception_at(vitex::scripting::immediate_context* context);
			static exception_repr get_exception();
		};

		class marshall
		{
		public:
			static expects_lr<void> index(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(schema* stream, const void* value, int value_type_id);
			static expects_lr<void> load(format::ro_stream& stream, void* value, int value_type_id);
			static expects_lr<void> load(schema* stream, void* value, int value_type_id);
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
			std::array<int8_t, std::numeric_limits<uint8_t>::max() + 1> opcodes;
			unordered_map<string, cmodule> modules;
			uptr<compiler> compiler;
			uptr<virtual_machine> vm;
			string compiler_log;
			std::recursive_mutex mutex;
			void* strings;

		public:
			std::mutex exclusive;

		public:
			factory() noexcept;
			virtual ~factory() noexcept override;
			void return_module(cmodule&& value);
			expects_lr<cmodule> compile_module(const std::string_view& hashcode, const std::function<expects_lr<string>()>& unpacked_code_callback);
			expects_lr<void> reset_properties(library& module, immediate_context* context);
			string hashcode(const std::string_view& unpacked_code);
			expects_lr<string> pack(const std::string_view& unpacked_code);
			expects_lr<string> unpack(const std::string_view& packed_code);
			virtual_machine* get_vm();
			int8_t opcode_cost(uint8_t opcode);

		private:
			void initialize_opcode_table();
			expects_lr<void> validate_bytecode(const function& compiled_function);
			static const void* to_string_constant(void* context, const char* buffer, size_t buffer_size);
			static int from_string_constant(void* context, const void* object, char* buffer, size_t* buffer_size);
			static int free_string_constant(void* context, const void* object);
		};

		struct stackframe
		{
			function call = nullptr;
			size_t byte_code_size = 0;
			uint32_t* byte_code = nullptr;
			uint32_t pointer = 0;
		};

		struct program
		{
			struct
			{
				unordered_map<string, unordered_map<size_t, uptr<states::account_multiform>>> index[2];
				option<algorithm::wesolowski::distribution> distribution = optional::none;
			} cache;
			ledger::transaction_context* context;
			library module;

			program(ledger::transaction_context* new_context, library&& new_module);
			virtual expects_lr<void> execute(ccall mutability, const std::string_view& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> execute(ccall mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const algorithm::pubkeyhash_t& target, const decimal& value, ccall mutability, const std::string_view& entrypoint, format::variables&& args, void* output_value, int output_type_id) const;
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> dispatch_arguments(ccall* mutability, const function& entrypoint, const format::variables& args) const;
			virtual void dispatch_event(int event_type_id, const void* object_value, int object_type_id);
			virtual void dispatch_exception(immediate_context* coroutine);
			virtual void dispatch_coroutine(immediate_context* coroutine, vector<stackframe>& frames);
			virtual bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode);
            virtual ccall mutability_of(const function& entrypoint) const;
			virtual algorithm::pubkeyhash_t callable() const;
			virtual decimal payable() const;
			virtual function upgrade_function() const;
			virtual string function_declaration() const;
			virtual const format::variables* function_arguments() const;
			static program* fetch_mutable(immediate_context* coroutine = immediate_context::get());
			static const program* fetch_immutable(immediate_context* coroutine = immediate_context::get());
			static program* fetch_mutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static const program* fetch_immutable_or_throw(immediate_context* coroutine = immediate_context::get());
			template <typename t>
			static inline t* gas_allocate(size_t size)
			{
				auto* program = program::fetch_immutable();
				if (program != nullptr)
				{
					size_t paid_blocks = std::max(size / sizeof(uint128_t), sizeof(uint128_t));
					size_t paid_gas = (size_t)ledger::gas_cost::memory_block * paid_blocks;
					if (paid_gas > 0 && !program->context->burn_gas(paid_gas))
					{
						contract::throw_ptr(exception_repr(exception_repr::category::memory(), std::string_view("ran out of gas")));
						return nullptr;
					}
				}
				return memory::allocate<t>(size);
			}
		};
	}
}

namespace vitex
{
	namespace core
	{
		template <>
		struct key_hasher<tangent::cell::string_repr>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::cell::string_repr& value) const noexcept
			{
				return key_hasher<std::string_view>()(value.view());
			}
		};
	}
}
#endif
