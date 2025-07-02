#ifndef TAN_KERNEL_SCRIPT_H
#define TAN_KERNEL_SCRIPT_H
#include "block.h"

using namespace vitex::scripting;

namespace tangent
{
	namespace ledger
	{
		enum class script_call
		{
			default_call,
			mutable_call,
			immutable_call
		};

		class script_marshalling
		{
		public:
			static expects_lr<void> store(format::stream* stream, const void* value, int value_type_id);
			static expects_lr<void> store(schema* stream, const void* value, int value_type_id);
			static expects_lr<void> load(format::stream& stream, void* value, int value_type_id);
			static expects_lr<void> load(schema* stream, void* value, int value_type_id);
		};

		class script_host : public singleton<script_host>
		{
		private:
			unordered_map<string, asIScriptModule*> modules;
			single_queue<uptr<compiler>> compilers;
			uptr<virtual_machine> vm;
			std::mutex mutex;

		public:
			script_host() noexcept;
			virtual ~script_host() noexcept override;
			uptr<compiler> allocate();
			void deallocate(uptr<compiler>&& compiler);
			expects_lr<void> compile(compiler* compiler, const std::string_view& program_hashcode, const std::string_view& unpacked_program_code);
			bool precompile(compiler* compiler, const std::string_view& program_hashcode);
			string hashcode(const std::string_view& unpacked_program_code);
			expects_lr<string> pack(const std::string_view& unpacked_program_code);
			expects_lr<string> unpack(const std::string_view& packed_program_code);
			virtual_machine* get_vm();
		};

		struct script_frame
		{
			function call = nullptr;
			size_t byte_code_size = 0;
			uint32_t* byte_code = nullptr;
			uint32_t pointer = 0;
		};

		struct script_address
		{
			algorithm::subpubkeyhash_t hash;

			script_address();
			script_address(const algorithm::pubkeyhash owner);
			script_address(const std::string_view& address);
			script_address(const uint256_t& owner_data);
			script_address(const uint256_t& owner_data, const uint256_t& derivation_data);
			script_address to_address() const;
			script_address to_subaddress_from_hash(const uint256_t& derivation_data) const;
			script_address to_subaddress_from_data(const std::string_view& derivation_data) const;
			string to_string() const;
			uint256_t to_public_key_hash() const;
			uint256_t to_derivation_hash() const;
			bool empty() const;
			static bool equals(const script_address& a, const script_address& b);
		};

		struct script_program
		{
			option<algorithm::wesolowski::distribution> distribution;
			ledger::transaction_context* context;

			script_program(ledger::transaction_context* new_context);
			virtual expects_lr<void> construct(compiler* compiler, const format::variables& args);
			virtual expects_lr<void> destruct(compiler* compiler);
			virtual expects_lr<void> destruct(const function& entrypoint);
			virtual expects_lr<void> mutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual expects_lr<void> immutable_call(compiler* compiler, const std::string_view& function_decl, const format::variables& args);
			virtual bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode);
			virtual void internal_call(const script_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id);
			virtual void internal_call(const script_address& target, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const;
			virtual void store_uniform(const void* index_value, int index_type_id, const void* object_value, int object_type_id);
			virtual bool load_uniform(const void* index_value, int index_type_id, void* object_value, int object_type_id, bool throw_on_error) const;
			virtual void store_multiform(const void* column_value, int column_type_id, const void* row_value, int row_type_id, const void* object_value, int object_type_id);
			virtual bool load_multiform_by_composition(const void* column_value, int column_type_id, const void* row_value, int row_type_id, void* object_value, int object_type_id, bool throw_on_error) const;
			virtual bool load_multiform_by_column(const void* column_value, int column_type_id, void* row_value, int row_type_id, void* object_value, int object_type_id, size_t offset, bool throw_on_error) const;
			virtual void emit_event(const void* event_value, int event_type_id, const void* object_value, int object_type_id);
			virtual void pay(const script_address& target, const uint256_t& asset, const decimal& value);
			virtual void destroy();
			virtual uint256_t random();
			virtual decimal value() const;
			virtual script_address from() const;
			virtual script_address to() const;
			virtual string blockchain() const;
			virtual string token() const;
			virtual string contract() const;
			virtual decimal gas_price() const;
			virtual uint256_t gas_left() const;
			virtual uint256_t gas_use() const;
			virtual uint256_t gas_limit() const;
			virtual uint256_t asset() const;
			virtual uint256_t parent_block_hash() const;
			virtual uint256_t block_gas_left() const;
			virtual uint256_t block_gas_use() const;
			virtual uint256_t block_gas_limit() const;
			virtual uint128_t block_difficulty() const;
			virtual uint64_t block_time() const;
			virtual uint64_t block_priority() const;
			virtual uint64_t block_number() const;

		protected:
			virtual expects_lr<void> execute(script_call mutability, const function& entrypoint, const format::variables& args, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const script_address& target, script_call mutability, const std::string_view& function_decl, void* input_value, int input_type_id, void* output_value, int output_type_id) const;
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> load_arguments(script_call mutability, const function& entrypoint, const format::variables& args) const;
			virtual void load_coroutine(immediate_context* coroutine, vector<script_frame>& frames);

		public:
			static script_program* fetch_mutable(immediate_context* coroutine = immediate_context::get());
			static const script_program* fetch_immutable(immediate_context* coroutine = immediate_context::get());
			static script_program* fetch_mutable_or_throw(immediate_context* coroutine = immediate_context::get());
			static const script_program* fetch_immutable_or_throw(immediate_context* coroutine = immediate_context::get());
		};

		struct script_program_trace : script_program
		{
			uptr<schema> returning;
			vector<string> instructions;
			evaluation_context environment;
			ledger::block block;
			bool debugging;

			script_program_trace(ledger::transaction* transaction, const algorithm::pubkeyhash from, bool tracing);
			expects_lr<void> trace_call(script_call mutability, const std::string_view& function_decl, const format::variables& args);
			bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode) override;
			uptr<schema> as_schema() const;
		};
	}
}
#endif