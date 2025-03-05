#ifndef TAN_KERNEL_SCRIPT_H
#define TAN_KERNEL_SCRIPT_H
#include "block.h"

using namespace vitex::scripting;

namespace tangent
{
	namespace ledger
	{
		class script_marshalling
		{
		public:
			static expects_lr<void> store(format::stream* stream, void* value, int value_type_id);
			static expects_lr<void> store(schema* stream, void* value, int value_type_id);
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
			algorithm::pubkeyhash hash = { 0 };

			script_address();
			script_address(const algorithm::pubkeyhash owner);
			script_address(const std::string_view& address);
			script_address(const uint256_t& numeric);
			string to_string() const;
			uint256_t to_uint256() const;
			bool is_null() const;
			static bool equals(const script_address& a, const script_address& b);
		};

		struct script_program
		{
			option<algorithm::wesolowski::distribution> distribution;
			ledger::transaction_context* context;

			script_program(ledger::transaction_context* new_context);
			virtual expects_lr<void> initialize(compiler* compiler, const format::variables& args);
			virtual expects_lr<void> mutable_call(compiler* compiler, const std::string_view& function, const format::variables& args);
			virtual expects_lr<void> immutable_call(compiler* compiler, const std::string_view& function, const format::variables& args);
			virtual bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode);
			virtual bool call_mutable_function(const script_address& target, const std::string_view& function, void* input_value, int input_type_id, void* output_value, int output_type_id);
			virtual bool call_immutable_function(const script_address& target, const std::string_view& function, void* input_value, int input_type_id, void* output_value, int output_type_id) const;
			virtual bool store_by_address(const script_address& location, const void* object_value, int object_type_id);
			virtual bool store_by_location(const std::string_view& location, const void* object_value, int object_type_id);
			virtual bool load_by_address(const script_address& location, void* object_value, int object_type_id) const;
			virtual bool load_by_location(const std::string_view& location, void* object_value, int object_type_id) const;
			virtual bool load_from_by_address(const script_address& target, const script_address& location, void* object_value, int object_type_id) const;
			virtual bool load_from_by_location(const script_address& target, const std::string_view& location, void* object_value, int object_type_id) const;
			virtual bool emit_by_address(const script_address& location, const void* object_value, int object_type_id);
			virtual bool emit_by_location(const std::string_view& location, const void* object_value, int object_type_id);
			virtual bool transfer(const script_address& to, const uint256_t& asset, const decimal& value);
			virtual uint64_t account_sequence_of(const script_address& target) const;
			virtual uint256_t account_work_of(const script_address& target) const;
			virtual string account_program_of(const script_address& target) const;
			virtual decimal account_incoming_reward_of(const script_address& target, const algorithm::asset_id& asset, const decimal& value) const;
			virtual decimal account_outgoing_reward_of(const script_address& target, const algorithm::asset_id& asset, const decimal& value) const;
			virtual uint64_t account_derivation_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual decimal account_balance_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual decimal account_coverage_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual decimal account_contribution_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual decimal account_reservation_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual decimal account_custody_of(const script_address& target, const algorithm::asset_id& asset) const;
			virtual bool has_witness_program_of(const std::string_view& hashcode) const;
			virtual uint256_t witness_event_of(const uint256_t& transaction_hash) const;
			virtual script_address witness_address_of(const algorithm::asset_id& asset, const std::string_view& address, uint64_t address_index, size_t offset) const;
			virtual bool has_witness_transaction_of(const algorithm::asset_id& asset, const std::string_view& transaction_id) const;
			virtual bool is_account_honest(const script_address& target) const;
			virtual uint256_t random();
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
			virtual expects_lr<void> execute(compiler* compiler, const std::string_view& function, const format::variables& args, int8_t mutability, std::function<expects_lr<void>(void*, int)>&& return_callback);
			virtual expects_lr<void> subexecute(const script_address& target, const std::string_view& function, void* input_value, int input_type_id, void* output_value, int output_type_id, int8_t mutability) const;
			virtual expects_lr<vector<std::function<void(immediate_context*)>>> load_arguments(const function& entrypoint, const format::variables& args, int8_t mutability) const;
			virtual void load_coroutine(immediate_context* coroutine, vector<script_frame>& frames);
		};

		struct script_program_trace : script_program
		{
			uptr<schema> returning;
			vector<string> instructions;
			evaluation_context environment;
			ledger::block block;
			bool debugging;

			script_program_trace(ledger::transaction* transaction, const algorithm::pubkeyhash from, bool tracing);
			expects_lr<void> trace_call(const std::string_view& function, const format::variables& args, int8_t mutability);
			bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode) override;
			uptr<schema> as_schema() const;
		};
	}
}
#endif