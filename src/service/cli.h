#ifndef TAN_SERVICE_CLI_H
#define TAN_SERVICE_CLI_H
#include "../kernel/script.h"
#include <functional>

namespace tangent
{
	namespace cli
	{
		enum class script_asm
		{
			code,
			abi,
			tx_deploy,
			tx_call
		};

		enum class render
		{
			scalar,
			document,
			custom
		};

		struct outcome
		{
			bool ok = true;
			string code;
			string message;
			format::tree result;
		};

		using command_fn = std::function<outcome(struct interpreter&, vector<string>&, const std::string_view&)>;

		struct command_def
		{
			std::string_view name;
			std::string_view group;
			std::string_view usage;
			std::string_view summary;
			render mode = render::scalar;
			command_fn run;
		};

		struct session : script::program
		{
			struct
			{
				btree_map<algorithm::pubkeyhash_t, btree_map<algorithm::asset_id, decimal>> balances;
				script::payable_repr payable;
				algorithm::pubkeyhash_t from;
				algorithm::pubkeyhash_t to;
				uint64_t block_number = 1;
				uint8_t call_flags = 0;
				bool temporary_reverted = false;
				algorithm::asset_id call_asset = algorithm::asset::native();
			} env;
			struct
			{
				string path;
				string log;
				uint8_t trap = 0;
				bool instructions = false;
			} program;
			struct
			{
				hash_map<size_t, format::tree> events;
				uptr<ledger::transaction_message> transaction;
				ledger::solver_context solver;
				script::cmodule pmodule;
				format::tree returning;
				format::tree log;
				ledger::block_body block;
			} tracer;
			uptr<ledger::block_transaction> temporary_transaction;

			session();
			~session() = default;
			expects_lr<void> call_transaction(script::ccall mutability, const script::function& entrypoint, const format::variables& args);
			expects_lr<void> compile(const std::string_view& new_path);
			expects_lr<void> assemble(script_asm type, const std::string_view& new_path, format::variables&& function_args);
			expects_lr<void> call(const std::string_view& function_decl, format::variables&& args, bool attach_debugger_context);
			void dispatch_event(int event_type_id, const void* object_value, int object_type_id) override;
			void dispatch_exception(script::immediate_context* coroutine) override;
			void dispatch_coroutine(script::immediate_context* coroutine) override;
			void reset();
			bool bound() const;
			uint64_t virtual_block_number() const override;
			expects_lr<ledger::block_transaction> block_transaction_of(const uint256_t& transaction_hash) const override;
			uint256_t state_root_hash() const;
			format::tree serialize_event_args(const format::variables& value) const;
			static void interrupter(bool bind);
			static const uint256_t temporary_hash;
		};

		struct interpreter
		{
			session context;
			console* terminal = console::get();
			string directory;
			bool machine = false;
			bool quitting = false;
			vector<command_def> catalog;

			interpreter(bool machine_mode);
			bool respond(const command_def& def, uint64_t ms, outcome& result, bool force_machine = false);
			bool dispatch(vector<string>& args, const std::string_view& directory, bool force_machine = false);
			bool execute(const std::string_view& line);
			int launch(const inline_args& environment, size_t args_start_offset, size_t args_end_offset);
			void build_catalog();
		};

		class util
		{
		public:
			static outcome pass(format::tree&& value = format::tree());
			static outcome pass(const std::string_view& text);
			static outcome fail(const std::string_view& code, const std::string_view& message);
			static bool printable(const std::string_view& value);
			static string printable_arg(const std::string_view& value);
			static void echo(const std::string_view& line);
			static void echo_color(std_color color, const std::string_view& line);
			static void print_json(console* term, format::tree& item);
			static void echo_error(console* term, const std::string_view& code, const std::string_view& raw);
			static void echo_amount(console* term, const std::string_view& amount, const std::string_view& asset);
			static void echo_balance(console* term, const std::string_view& account, const std::string_view& amount, const std::string_view& asset);
			static vector<string> tokenize(const std::string_view& line);
			static expects_lr<void> encode_argument(format::wo_stream& message, schema& node, bool counted);
			static expects_lr<string> expand_argument(const std::string_view& token);
			static expects_lr<format::variables> expand_arguments(vector<string>& args, size_t offset);
			static format::tree error_detail(const std::string_view& code, const std::string_view& raw);
			static string address_of(const algorithm::pubkeyhash_t& value);
			static expects_lr<algorithm::asset_id> asset_of(vector<string>& args, size_t offset);
			static format::tree payments_of(const script::payable_repr& payable);
			static string revert_message(interpreter& self);
			static expects_lr<string> convert_plan_argument(schema* subargument);
			static bool run_plan_step(interpreter& self, vector<string>& subargs, const std::string_view& base, const string& note, schema* expected, size_t& steps, size_t& failures);
		};
	}
}
#endif
