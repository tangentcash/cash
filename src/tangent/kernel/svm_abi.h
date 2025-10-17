#ifndef TAN_KERNEL_SVM_ABI_H
#define TAN_KERNEL_SVM_ABI_H
#include "svm.h"

namespace tangent
{
	namespace ledger
	{
		namespace svm_abi
		{
			struct address;

			class array_repr;

			struct uobject
			{
				virtual_machine* vm;
				asITypeInfo* type;
				void* address;

				uobject(virtual_machine* new_vm, asITypeInfo* new_type, void* new_address) noexcept : vm(new_vm), type(new_type), address(new_address)
				{
				}
				uobject(const uobject& other) noexcept : vm(other.vm), type(other.type), address(other.address)
				{
					((uobject*)&other)->address = nullptr;
				}
				uobject(uobject&& other) noexcept : vm(other.vm), type(other.type), address(other.address)
				{
					other.address = nullptr;
				}
				~uobject()
				{
					destroy();
				}
				uobject& operator= (const uobject& other) noexcept
				{
					if (this == &other)
						return *this;

					destroy();
					vm = other.vm;
					type = other.type;
					address = other.address;
					((uobject*)&other)->address = nullptr;
					return *this;
				}
				uobject& operator= (uobject&& other) noexcept
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
				static string_repr to_string_address(const address& other);
				static void create(string_repr* base);
				static void create_copy(string_repr* base, const string_repr& other);
				static void destroy(string_repr* base);
				static uint32_t buffer_capacity_of(size_t required_size);
			};

			class exception
			{
			public:
				struct pointer
				{
					string type;
					string text;
					string origin;
					vitex::scripting::immediate_context* context;

					pointer();
					pointer(vitex::scripting::immediate_context* context);
					pointer(const std::string_view& data);
					pointer(const std::string_view& type, const std::string_view& text);
					pointer(const string_repr& type, const string_repr& text);
					void load_exception_data(const std::string_view& data);
					string_repr get_type() const;
					string_repr get_text() const;
					string_repr get_what() const;
					string to_exception_string() const;
					string to_full_exception_string() const;
					string load_stack_here() const;
					bool empty() const;
				};

			public:
				static void throw_ptr_at(vitex::scripting::immediate_context* context, const pointer& data);
				static void throw_ptr(const pointer& data);
				static void rethrow_at(vitex::scripting::immediate_context* context);
				static void rethrow();
				static bool has_exception_at(vitex::scripting::immediate_context* context);
				static bool has_exception();
				static pointer get_exception_at(vitex::scripting::immediate_context* context);
				static pointer get_exception();
				static expects_vm<void> generator_callback(preprocessor* base, const std::string_view& path, string& code);

			public:
				struct category
				{
					static std::string_view generic();
					static std::string_view requirement();
					static std::string_view argument();
					static std::string_view memory();
					static std::string_view storage();
					static std::string_view execution();
				};
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

			struct decimal_repr
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

			struct address
			{
				algorithm::pubkeyhash_t hash;

				address() = default;
				address(const algorithm::pubkeyhash_t& owner);
				address(const string_repr& address);
				address(const uint256_t& owner_data);
				void pay(const uint256_t& asset, const decimal& value);
				decimal balance_of(const uint256_t& asset) const;
				string_repr to_string() const;
				uint256_t to_public_key_hash() const;
				bool empty() const;
				static void call(asIScriptGeneric* generic);
				static bool equals(const address& a, const address& b);
			};

			struct abi
			{
				format::ro_stream input;
				format::wo_stream output;

				abi() = default;
				abi(const string_repr& data);
				void seek(uint32_t offset);
				void clear();
				void merge(const string_repr& value);
				void wstr(const string_repr& value);
				void wrstr(const string_repr& value);
				void wdecimal(const decimal& value);
				void wboolean(bool value);
				void wuint160(const address& value);
				void wuint256(const uint256_t& value);
				bool rstr(string_repr& value);
				bool rdecimal(decimal& value);
				bool rboolean(bool& value);
				bool ruint160(address& value);
				bool ruint256(uint256_t& value);
				string_repr data();
			};

			struct filter
			{
				ledger::filter_comparator comparator;
				ledger::filter_order order;
				uint256_t value;

				filter();
				filter(ledger::filter_comparator new_condition, ledger::filter_order new_order, const uint256_t& new_value);
				static filter greater(const uint256_t& value, ledger::filter_order order);
				static filter greater_equal(const uint256_t& value, ledger::filter_order order);
				static filter equal(const uint256_t& value, ledger::filter_order order);
				static filter not_equal(const uint256_t& value, ledger::filter_order order);
				static filter less(const uint256_t& value, ledger::filter_order order);
				static filter less_equal(const uint256_t& value, ledger::filter_order order);
			};

			struct xc
			{
				format::wo_stream column;
				uint32_t offset;
				uint32_t count;

				void reset();
				bool next(void* object_value, int object_type_id);
				bool next_row(void* object_value, int object_type_id, void* row_value, int row_type_id);
				bool next_row_ranked(void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value);
				static xc from(const void* column_value, int column_type_id, uint32_t count);
			};

			struct xfc
			{
				filter query;
				format::wo_stream column;
				uint32_t offset;
				uint32_t count;

				void reset();
				bool next(void* object_value, int object_type_id);
				bool next_row(void* object_value, int object_type_id, void* row_value, int row_type_id);
				bool next_row_ranked(void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value);
				static xfc from(const void* column_value, int column_type_id, const filter& query, uint32_t count);
			};

			struct yc
			{
				format::wo_stream row;
				uint32_t offset;
				uint32_t count;

				void reset();
				bool next(void* object_value, int object_type_id);
				bool next_column(void* object_value, int object_type_id, void* column_value, int column_type_id);
				bool next_column_ranked(void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value);
				static yc from(const void* row_value, int row_type_id, uint32_t count);
			};

			struct yfc
			{
				filter query;
				format::wo_stream row;
				uint32_t offset;
				uint32_t count;

				void reset();
				bool next(void* object_value, int object_type_id);
				bool next_column(void* object_value, int object_type_id, void* column_value, int column_type_id);
				bool next_column_ranked(void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value);
				static yfc from(const void* row_value, int row_type_id, const filter& query, uint32_t count);
			};

			struct sv
			{
				static void store(const void* index_value, int index_type_id, const void* object_value, int object_type_id);
				static bool load(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error);
				static void set(const void* index_value, int index_type_id, void* object_value, int object_type_id);
				static void erase(const void* index_value, int index_type_id);
				static void set_if(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool condition);
				static bool has(const void* index_value, int index_type_id);
				static bool into(const void* index_value, int index_type_id, void* object_value, int object_type_id);
				static void get(asIScriptGeneric* generic);
			};

			struct qsv
			{
				static void store(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value);
				static bool load(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error);
				static void set_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value);
				static void set(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id);
				static void erase(const void* column_value, int column_type_id, const void* row_value, int row_type_id);
				static void set_if_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, const uint256_t& filter_value, bool condition);
				static void set_if(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool condition);
				static bool into_ranked(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value);
				static bool into(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id);
				static bool has(const void* column_value, int column_type_id, const void* row_value, int row_type_id);
				static void get(asIScriptGeneric* generic);
			};

			struct log
			{
				static bool emit(const void* object_value, int object_type_id);
				static bool into(int32_t event_index, void* object_value, int object_type_id);
				static void get(asIScriptGeneric* generic);
			};

			struct block
			{
				static address proposer();
				static uint256_t parent_hash();
				static uint256_t gas_use();
				static uint256_t gas_left();
				static uint256_t gas_limit();
				static uint128_t difficulty();
				static uint64_t time();
				static uint64_t time_between(uint64_t block_number_a, uint64_t block_number_b);
				static uint64_t priority();
				static uint64_t number();
			};

			struct tx
			{
				static decimal value();
				static bool paid();
				static address from();
				static address to();
				static string_repr blockchain();
				static string_repr token();
				static string_repr contract();
				static decimal gas_price();
				static uint256_t gas_use();
				static uint256_t gas_left();
				static uint256_t gas_limit();
				static uint256_t asset();
			};

			struct currency
			{
				static uint256_t from_decimal(const decimal& value);
				static decimal to_decimal(const uint256_t& value);
				static uint256_t id_of(const string_repr& blockchain, const string_repr& token, const string_repr& contract_address);
				static string_repr blockchain_of(const uint256_t& value);
				static string_repr token_of(const uint256_t& value);
				static string_repr checksum_of(const uint256_t& value);
				static string_repr name_of(const uint256_t& value);
			};

			struct repr
			{
				static string_repr encode_bytes256(const uint256_t& value);
				static uint256_t decode_bytes256(const string_repr& value);
			};

			struct dsa
			{
				static address erecover160(const uint256_t& hash, const string_repr& signature);
				static string_repr erecover264(const uint256_t& hash, const string_repr& signature);
			};

			struct alg
			{
				static string_repr crc32(const string_repr& data);
				static string_repr ripemd160(const string_repr& data);
				static uint256_t blake2b256(const string_repr& data);
				static string_repr blake2b256s(const string_repr& data);
				static uint256_t keccak256(const string_repr& data);
				static string_repr keccak256s(const string_repr& data);
				static string_repr keccak512(const string_repr& data);
				static uint256_t sha256(const string_repr& data);
				static string_repr sha256s(const string_repr& data);
				static string_repr sha512(const string_repr& data);
				static uint256_t random();
			};

			struct math
			{
				static void min_value(asIScriptGeneric* generic);
				static void max_value(asIScriptGeneric* generic);
				static void min(asIScriptGeneric* generic);
				static void max(asIScriptGeneric* generic);
				static void clamp(asIScriptGeneric* generic);
				static void lerp(asIScriptGeneric* generic);
				static void pow(asIScriptGeneric* generic);
				static void sqrt(asIScriptGeneric* generic);
			};

			struct assertion
			{
				static void require(bool condition, const string_repr& message);
			};

			template <typename t>
			inline t* gas_allocate(size_t size)
			{
				auto* program = svm_program::fetch_immutable();
				if (program != nullptr)
				{
					size_t paid_blocks = std::max(size / sizeof(uint128_t), sizeof(uint128_t));
					size_t paid_gas = (size_t)gas_cost::memory_block * paid_blocks;
					if (paid_gas > 0 && !program->context->burn_gas(paid_gas))
					{
						svm_abi::exception::throw_ptr(svm_abi::exception::pointer(svm_abi::exception::category::memory(), std::string_view("ran out of gas")));
						return nullptr;
					}
				}
				return memory::allocate<t>(size);
			}
		}
	}
}

namespace vitex
{
	namespace core
	{
		template <>
		struct key_hasher<tangent::ledger::svm_abi::string_repr>
		{
			typedef float argument_type;
			typedef size_t result_type;
			using is_transparent = void;

			inline result_type operator()(const tangent::ledger::svm_abi::string_repr& value) const noexcept
			{
				return key_hasher<std::string_view>()(value.view());
			}
		};
	}
}
#endif
