#ifndef TAN_KERNEL_SVM_H
#define TAN_KERNEL_SVM_H
#include "block.h"

using namespace vitex::scripting;

namespace tangent
{
	namespace ledger
	{
		enum class svm_call
		{
			default_call,
			mutable_call,
			immutable_call
		};

		class svm_marshalling
		{
		public:
			static expects_lr<void> store(format::wo_stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(schema* stream, const void* value, int value_type_id);
			static expects_lr<void> load(format::ro_stream& stream, void* value, int value_type_id);
			static expects_lr<void> load(schema* stream, void* value, int value_type_id);
		};

		class svm_host : public singleton<svm_host>
		{
		private:
			unordered_map<string, asIScriptModule*> modules;
			single_queue<uptr<compiler>> compilers;
			uptr<virtual_machine> vm;
			std::mutex mutex;

		public:
			svm_host() noexcept;
			virtual ~svm_host() noexcept override;
			uptr<compiler> allocate();
			void deallocate(uptr<compiler>&& compiler);
			expects_lr<void> compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& unpacked_program_code);
			bool precompile(compiler* compiler, const std::string_view& program_hashcode);
			string hashcode(const std::string_view& unpacked_program_code);
			expects_lr<string> pack(const std::string_view& unpacked_program_code);
			expects_lr<string> unpack(const std::string_view& packed_program_code);
			virtual_machine* get_vm();
		};

		struct svm_frame
		{
			function call = nullptr;
			size_t byte_code_size = 0;
			uint32_t* byte_code = nullptr;
			uint32_t pointer = 0;
		};

		struct svm_address
		{
			algorithm::subpubkeyhash_t hash;

			svm_address();
			svm_address(const algorithm::pubkeyhash_t& owner);
			svm_address(const algorithm::subpubkeyhash_t& owner);
			svm_address(const std::string_view& address);
			svm_address(const uint256_t& owner_data);
			svm_address(const uint256_t& owner_data, const uint256_t& derivation_data);
			svm_address to_address() const;
			svm_address to_subaddress_from_hash(const uint256_t& derivation_data) const;
			svm_address to_subaddress_from_data(const std::string_view& derivation_data) const;
			string to_string() const;
			uint256_t to_public_key_hash() const;
			uint256_t to_derivation_hash() const;
			bool empty() const;
			static bool equals(const svm_address& a, const svm_address& b);
		};

		struct svm_abi
		{
			format::ro_stream input;
			format::wo_stream output;

			svm_abi() = default;
			svm_abi(const std::string_view& data);
			void seek(size_t offset);
			void clear();
			void merge(const std::string_view& value);
			void wstr(const std::string_view& value);
			void wrstr(const std::string_view& value);
			void wdecimal(const decimal& value);
			void wboolean(bool value);
			void wuint160(const svm_address& value);
			void wuint256(const uint256_t& value);
			bool rstr(string& value);
			bool rdecimal(decimal& value);
			bool rboolean(bool& value);
			bool ruint160(svm_address& value);
			bool ruint256(uint256_t& value);
			string& data();
			const string& data_const() const;
		};

		struct svm_multiform_filter
		{
			ledger::filter_comparator comparator;
			ledger::filter_order order;
			uint256_t value;

			svm_multiform_filter();
			svm_multiform_filter(ledger::filter_comparator new_comparator, ledger::filter_order new_order, const uint256_t& new_value);
		};

		struct svm_multiform_column_cursor
		{
			format::wo_stream column;
			size_t count;

			bool at1(size_t offset, void* object_value, int object_type_id);
			bool at2(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id);
			bool at3(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value);
		};

		struct svm_multiform_column_filter_cursor
		{
			svm_multiform_filter filter;
			format::wo_stream column;
			size_t count;

			bool at1(size_t offset, void* object_value, int object_type_id);
			bool at2(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id);
			bool at3(size_t offset, void* object_value, int object_type_id, void* row_value, int row_type_id, uint256_t* filter_value);
		};

		struct svm_multiform_row_cursor
		{
			format::wo_stream row;
			size_t count;

			bool at1(size_t offset, void* object_value, int object_type_id);
			bool at2(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id);
			bool at3(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value);
		};

		struct svm_multiform_row_filter_cursor
		{
			svm_multiform_filter filter;
			format::wo_stream row;
			size_t count;

			bool at1(size_t offset, void* object_value, int object_type_id);
			bool at2(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id);
			bool at3(size_t offset, void* object_value, int object_type_id, void* column_value, int column_type_id, uint256_t* filter_value);
		};

		struct svm_program
		{
			struct
			{
				option<algorithm::wesolowski::distribution> distribution = optional::none;
				unordered_map<string, unordered_map<size_t, uptr<states::account_multiform>>> columns;
				unordered_map<string, unordered_map<size_t, uptr<states::account_multiform>>> rows;
			} cache;
			ledger::transaction_context* context;

			svm_program(ledger::transaction_context* new_context);
			virtual expects_lr<void> construct(compiler* compiler, const format::variables& args);
			virtual expects_lr<void> destruct(compiler* compiler);
			virtual expects_lr<void> destruct(const function& entrypoint);
			virtual expects_lr<void> mutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual expects_lr<void> immutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode);
			virtual void internal_call(const svm_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id);
			virtual void internal_call(const svm_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const;
			virtual void store_uniform(const void* index_value, int index_type_id, const void* object_value, int object_type_id);
			virtual bool load_uniform(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error) const;
			virtual bool has_uniform(const void* index_value, int index_type_id) const;
			virtual void store_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id, const uint256_t& filter_value);
			virtual bool load_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, uint256_t* filter_value, bool throw_on_error) const;
			virtual bool has_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id) const;
			virtual void emit_event(const void* object_value, int object_type_id);
			virtual void pay(const svm_address& target, const uint256_t& asset, const decimal& value);
			virtual void destroy();
			virtual svm_multiform_column_cursor multiform_column_cursor(const void* column_value, int column_type_id, size_t count) const;
			virtual svm_multiform_column_filter_cursor multiform_column_filter_cursor(const void* column_value, int column_type_id, const svm_multiform_filter& filter, size_t count) const;
			virtual svm_multiform_row_cursor multiform_row_cursor(const void* row_value, int row_type_id, size_t count) const;
			virtual svm_multiform_row_filter_cursor multiform_row_filter_cursor(const void* row_value, int row_type_id, const svm_multiform_filter& filter, size_t count) const;
			virtual uint256_t random();
			virtual svm_address from() const;
			virtual svm_address to() const;
			virtual decimal value() const;
			virtual string blockchain() const;
			virtual string token() const;
			virtual string contract() const;
			virtual string declaration() const;
			virtual decimal gas_price() const;
			virtual uint256_t gas_left() const;
			virtual uint256_t gas_use() const;
			virtual uint256_t gas_limit() const;
			virtual uint256_t asset() const;
			virtual svm_address block_proposer() const;
			virtual uint256_t parent_block_hash() const;
			virtual uint256_t block_gas_left() const;
			virtual uint256_t block_gas_use() const;
			virtual uint256_t block_gas_limit() const;
			virtual uint128_t block_difficulty() const;
			virtual uint64_t block_time() const;
			virtual uint64_t block_priority() const;
			virtual uint64_t block_number() const;
			virtual const format::variables* arguments() const;

		protected:
			virtual expects_lr<void> execute(svm_call mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const svm_address& target, svm_call mutability, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const;
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> load_arguments(svm_call* mutability, const function& entrypoint, const format::variables& args) const;
			virtual void load_coroutine(immediate_context* coroutine, vector<svm_frame>& frames);

		public:
			static svm_program* fetch_mutable(immediate_context* coroutine = immediate_context::get());
			static const svm_program* fetch_immutable(immediate_context* coroutine = immediate_context::get());
			static svm_program* fetch_mutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static const svm_program* fetch_immutable_or_throw(immediate_context* coroutine = immediate_context::get());
		};

		struct svm_program_trace : svm_program
		{
			uptr<schema> returning;
			vector<string> instructions;
			evaluation_context environment;
			ledger::block block;
			bool debugging;

			svm_program_trace(ledger::transaction* transaction, const algorithm::pubkeyhash from, bool tracing);
			expects_lr<void> trace_call(svm_call mutability, const std::string_view& function_decl, const format::variables& args);
			bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode) override;
			uptr<schema> as_schema() const;
		};
	}
}
#endif