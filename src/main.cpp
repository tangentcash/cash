#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"
#include "tangent/kernel/svm.h"
#include "tangent/policy/transactions.h"
#include "tangent/validator/storage/chainstate.h"
#include <vitex/bindings.h>
#include <sstream>
#include <regex>

using namespace tangent;

enum class svm_assembler
{
	abi_raw,
	abi_hex,
	code
};

struct svm_context : ledger::svm_program
{
	struct
	{
		ordered_map<algorithm::subpubkeyhash_t, ordered_map<algorithm::asset_id, decimal>> balances;
		algorithm::subpubkeyhash_t from;
		algorithm::subpubkeyhash_t to;
		algorithm::asset_id payable = 0;
		decimal pay = decimal::zero();
	} state;
	struct
	{
		string path;
		string log;
		uint8_t trap = 0;
	} program;
	struct
	{
		ledger::evaluation_context environment;
		uptr<transactions::call> contextual;
		uptr<compiler> compiler;
		uptr<schema> events;
		uptr<schema> returning;
		vector<string> instructions;
		ledger::block block;
	} svmc;

	svm_context() : svm_program(&svmc.environment.validation.context)
	{
		preprocessor::desc compiler_features;
		compiler_features.conditions = true;
		compiler_features.defines = true;
		compiler_features.includes = true;
		compiler_features.pragmas = false;

		auto* host = ledger::svm_host::get();
		auto* vm = host->get_vm();
		vm->set_ts_imports(true);
		vm->set_ts_imports_concat_mode(true);
		vm->set_preserve_source_code(true);
		vm->set_compiler_features(compiler_features);
		svmc.compiler = host->allocate();
	}
	~svm_context()
	{
		auto* host = ledger::svm_host::get();
		host->deallocate(std::move(svmc.compiler));
	}
	expects_lr<void> assign_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::subpubkeyhash_t& to, const decimal& value, const std::string_view& function_decl, const format::variables& args)
	{
		VI_ASSERT(from != nullptr, "from should be set");
		uptr<transactions::call> transaction = memory::init<transactions::call>();
		transaction->asset = asset;
		transaction->signature[0] = 0xFF;
		transaction->nonce = std::max<size_t>(1, svmc.environment.validation.context.get_account_nonce(from).or_else(states::account_nonce(nullptr, nullptr)).nonce);
		transaction->program_call(to, value, function_decl, format::variables(args));
		transaction->set_gas(decimal::zero(), ledger::block::get_gas_limit());

		auto chain = storages::chainstate(__func__);
		auto tip = chain.get_latest_block_header();
		if (tip)
			svmc.environment.tip = std::move(*tip);

		ledger::receipt receipt;
		svmc.block.set_parent_block(svmc.environment.tip.address());
		receipt.transaction_hash = transaction->as_hash();
		receipt.generation_time = protocol::now().time.now();
		receipt.block_number = svmc.block.number + 1;
		memcpy(receipt.from, from, sizeof(algorithm::pubkeyhash));

		svmc.contextual = std::move(transaction);
		svmc.environment.validation.context = ledger::transaction_context(&svmc.environment, &svmc.block, &svmc.environment.validation.changelog, *svmc.contextual, std::move(receipt));
		memset(svmc.environment.validator.public_key_hash, 0xFF, sizeof(algorithm::pubkeyhash));
		memset(svmc.environment.validator.secret_key, 0xFF, sizeof(algorithm::seckey));
		return expectation::met;
	}
	expects_lr<uptr<compiler>> compile_transaction()
	{
		VI_ASSERT(svmc.contextual, "transaction should be assigned");
		auto index = svmc.environment.validation.context.get_account_program(to().hash.data);
		if (!index)
			return layer_exception("program not assigned to address");

		auto* host = ledger::svm_host::get();
		auto& hashcode = index->hashcode;
		auto result = host->allocate();
		if (host->precompile(*result, hashcode))
			return expects_lr<uptr<compiler>>(std::move(result));

		auto program = svmc.environment.validation.context.get_witness_program(hashcode);
		if (!program)
		{
			host->deallocate(std::move(result));
			return layer_exception("program not stored to address");
		}

		auto code = program->as_code();
		if (!code)
		{
			host->deallocate(std::move(result));
			return code.error();
		}

		auto compilation = host->compile(*result, hashcode, format::util::encode_0xhex(hashcode), *code);
		if (!compilation)
		{
			host->deallocate(std::move(result));
			return compilation.error();
		}

		return expects_lr<uptr<compiler>>(std::move(result));
	}
	expects_lr<void> call_transaction(compiler* module, ledger::svm_call mutability, const std::string_view& function_decl, const format::variables& args)
	{
		VI_ASSERT(svmc.contextual, "transaction should be assigned");
		auto function = module->get_module().get_function_by_decl(function_decl);
		if (!function.is_valid())
			function = module->get_module().get_function_by_name(function_decl);
		if (!function.is_valid())
			return layer_exception("illegal call to function: null function");

		svmc.instructions.clear();
		auto execution = execute(mutability, function, args, [this](void* address, int type_id) -> expects_lr<void>
		{
			svmc.returning = var::set::object();
			auto serialization = ledger::svm_marshalling::store(*svmc.returning, address, type_id);
			if (!serialization)
			{
				svmc.returning.destroy();
				return layer_exception("return value error: " + serialization.error().message());
			}

			return expectation::met;
		});
		context->receipt.successful = !!execution;
		context->receipt.finalization_time = protocol::now().time.now();
		if (!context->receipt.successful)
			context->emit_event(0, { format::variable(execution.what()) }, false);

		uptr<schema> log = var::set::array();
		for (auto& [event, args] : context->receipt.events)
		{
			if (svmc.events)
			{
				bool replacement = false;
				for (size_t i = 0; i < svmc.events->size(); i++)
				{
					auto* target = svmc.events->get(i);
					auto* type = target->get("type");
					if (!type || (uint32_t)type->value.get_integer() != event)
						continue;

					target->pop("index");
					log->push(target);
					replacement = true;
				}
				if (replacement)
					continue;
			}

			uptr<ledger::state> temp = states::resolver::from_type(event);
			auto* next = svmc.events->push(var::set::object());
			next->set("type", var::integer(event));
			next->set("args", format::variables_util::serialize(args));
			next->set(temp ? temp->as_typename() : "__internal__", var::null());
		}

		if (!log->empty())
			svmc.events = std::move(log);
		return execution;
	}
	expects_lr<void> compile(const std::string_view& new_path)
	{
		auto file = os::file::read_as_string(new_path);
		if (!file)
			return layer_exception(file.what());

		auto* host = ledger::svm_host::get();
		auto* vm = host->get_vm();
		vm->set_compiler_error_callback([this](const std::string_view& message) { program.log.append(message).append("\r\n"); });
		vm->clear_cache();
		program.log.clear();

		auto hash = algorithm::hashing::hash512((uint8_t*)file->data(), file->size());
		auto result = host->compile(*svmc.compiler, hash, new_path, *file);
		vm->set_compiler_error_callback(nullptr);
		if (!program.log.empty())
			return layer_exception(string(program.log));
		else if (!result)
			return result.error();

		program.path = new_path;
		return expectation::met;
	}
	expects_lr<void> assemble(svm_assembler type, const std::string_view& new_path)
	{
		auto* host = ledger::svm_host::get();
		auto* vm = host->get_vm();
		if (vm->get_script_sections().empty())
			return layer_exception("source code not found");

		vector<string> codes;
		for (auto& [name, code] : vm->get_script_sections())
			codes.push_back(code);

		string listing;
		std::sort(codes.begin(), codes.end(), [](const string& a, const string& b) { return a.size() > b.size(); });
		for (auto& code : codes)
			listing.append(stringify::trim(code)).append("\n\n");
		if (!listing.empty())
			listing.erase(listing.size() - 2, 2);

		if (type == svm_assembler::abi_raw || type == svm_assembler::abi_hex)
		{
			auto result = host->pack(listing);
			if (!result)
				return result.error();

			if (type == svm_assembler::abi_hex)
				listing = format::util::encode_0xhex(*result);
			else
				listing = std::move(*result);
		}

		auto result = os::file::write(new_path, (uint8_t*)listing.data(), listing.size());
		if (!result)
			return layer_exception(result.what());

		return expectation::met;
	}
	expects_lr<void> call(const std::string_view& function, format::variables&& args, bool attach_debugger_context)
	{
		if (program.path.empty())
			return layer_exception("program not bound");

		if (state.from.empty())
			return layer_exception("caller address not valid");

		if (state.to.empty())
			return layer_exception("contract address not valid");

		if (!state.payable)
			return layer_exception("payable asset not valid");

		auto assignment = assign_transaction(state.payable, state.from.data, state.to, state.pay, function, args);
		if (!assignment)
			return assignment.error();

		for (auto& [account, balances] : state.balances)
		{
			for (auto& [asset, value] : balances)
			{
				auto prev_balance = context->get_account_balance(asset, account.data);
				if (prev_balance && prev_balance->get_balance() >= value)
					continue;

				auto balance = states::account_balance(account.data, asset, nullptr);
				balance.supply = value;

				auto status = context->store(&balance, false);
				if (!status)
					return status.error();
			}
		}

		if (state.pay.is_positive())
		{
			auto payment = context->apply_payment(state.payable, state.from.data, state.to.data, state.pay);
			if (!payment)
				return payment.error();
		}

		auto* vm = svmc.compiler->get_vm();
		if (attach_debugger_context)
		{
			debugger_context* debugger = new debugger_context();
			bindings::registry().bind_stringifiers(debugger);
			debugger->add_to_string_callback("address", [](string& indent, int depth, void* object, int type_id)
			{
				ledger::svm_address& source = *(ledger::svm_address*)object;
				return source.to_string() + " (address)";
			});
			debugger->add_to_string_callback("abi", [](string& indent, int depth, void* object, int type_id)
			{
				ledger::svm_abi& source = *(ledger::svm_abi*)object;
				return source.output.encode() + " (abi)";
			});
			debugger->add_to_string_callback("uint256", [](string& indent, int depth, void* object, int type_id)
			{
				uint256_t& source = *(uint256_t*)object;
				if (algorithm::asset::is_valid(source))
					return source.to_string() + " (uint256; " + algorithm::asset::name_of(source) + " as asset)";

				return source.to_string() + " (uint256)";
			});
			bindings::registry::import_any(vm);
			debugger->set_interrupt_callback([](bool is_interrupted) { console::get()->write_line(is_interrupted ? "program execution interrupted" : "resuming program execution"); });
			vm->set_debugger(debugger);
		}

		auto execution = call_transaction(*svmc.compiler, ledger::svm_call::system_call, function, args);
		if (attach_debugger_context)
			vm->set_debugger(nullptr);

		if (!execution)
			return execution.error();

		svmc.environment.validation.changelog.commit();
		state.balances.clear();
		return expectation::met;
	}
	void load_exception(immediate_context* coroutine)
	{
		auto* vm = coroutine->get_vm();
		if (vm->has_debugger())
			vm->get_debugger()->exception_callback(coroutine->get_context());
	}
	void load_coroutine(immediate_context* coroutine, vector<ledger::svm_frame>& frames)
	{
		auto* vm = coroutine->get_vm();
		if (vm->has_debugger())
			vm->get_debugger()->line_callback(coroutine->get_context());
		return svm_program::load_coroutine(coroutine, frames);
	}
	void reset()
	{
		auto* host = ledger::svm_host::get();
		host->deallocate(std::move(svmc.compiler));
		state.balances.clear();
		state.from = algorithm::subpubkeyhash_t();
		state.to = algorithm::subpubkeyhash_t();
		state.payable = 0;
		state.pay = decimal::zero();
		program.path.clear();
		program.log.clear();
		program.trap = 0;
		svmc.compiler = host->allocate();
		svmc.environment = ledger::evaluation_context();
		svmc.contextual = uptr<transactions::call>();
		svmc.events = uptr<schema>();
		svmc.returning = uptr<schema>();
		svmc.instructions.clear();
		svmc.block = ledger::block();
	}
	bool bound() const
	{
		return !program.path.empty();
	}
	bool emit_event(const void* object_value, int object_type_id)
	{
		if (!svm_program::emit_event(object_value, object_type_id))
			return false;

		if (!svmc.events)
			svmc.events = var::set::array();

		auto type = ledger::svm_host::get()->get_vm()->get_type_info_by_id(object_type_id).get_name();
		auto* event = svmc.events->push(var::set::object());
		event->set("type", var::integer(context->receipt.events.back().first));
		event->set("args", format::variables_util::serialize(context->receipt.events.back().second));
		ledger::svm_marshalling::store(event->set(type.empty() ? "__internal__" : type, var::null()), object_value, object_type_id);
		return true;
	}
	bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode)
	{
		string_stream stream;
		debugger_context::byte_code_label_to_text(stream, vm, program_data, program_counter, false, true);

		string instruction = stream.str();
		stringify::trim(instruction);
#if VI_64
		instruction.erase(2, 8);
#endif
		auto gas = ledger::svm_frame::gas_cost_of(opcode);
		instruction.append(instruction.find('%') != std::string::npos ? ", %gas:" : " %gas:");
		instruction.append(to_string(gas));
		svmc.instructions.push_back(std::move(instruction));
		return svm_program::dispatch_instruction(vm, coroutine, program_data, program_counter, opcode);
	}
};

int svm(const inline_args& environment)
{
	auto params = protocol(environment);
	auto context = svm_context();
	auto* terminal = console::get();
	auto directory = *os::directory::get_working();
	error_handling::set_flag(log_option::dated, false);

	auto ok = [&](const std::string_view& line) -> bool { terminal->colorize(std_color::light_gray, line); terminal->write_char('\n'); return true; };
	auto err = [&](const std::string_view& line) -> bool { terminal->colorize(std_color::light_gray, line); terminal->write_char('\n'); return false; };
	auto command_execute = [&](vector<string>& args, const std::string_view& directory) -> bool
	{
		if (args.empty())
			return true;

		auto& method = args[0];
		if (method == "from")
		{
			if (args.size() > 1)
			{
				if (args[1] != "?")
				{
					if (!algorithm::signing::decode_subaddress(args[1], context.state.from.data))
						return err("not a valid address");
				}
				else
				{
					memset(context.state.from.data, 0, sizeof(context.state.from.data));
					crypto::fill_random_bytes(context.state.from.data, sizeof(algorithm::pubkeyhash));
				}
			}

			if (context.state.from.empty())
				return ok("null");

			string address;
			algorithm::signing::encode_subaddress(context.state.from.data, address);
			return ok(address);
		}
		else if (method == "to")
		{
			if (args.size() > 1)
			{
				if (args[1] != "?")
				{
					if (!algorithm::signing::decode_subaddress(args[1], context.state.to.data))
						return err("not a valid address");
				}
				else
				{
					memset(context.state.to.data, 0, sizeof(context.state.to.data));
					crypto::fill_random_bytes(context.state.to.data, sizeof(algorithm::pubkeyhash));
				}
			}

			if (context.state.to.empty())
				return ok("null");

			string address;
			algorithm::signing::encode_subaddress(context.state.to.data, address);
			return ok(address);
		}
		else if (method == "payable")
		{
			if (args.size() > 1)
			{
				auto asset = algorithm::asset::id_of(stringify::to_upper(args[1]), args.size() > 2 ? stringify::to_upper(args[2]) : std::string_view(), args.size() > 3 ? args[3] : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
					return err("not a valid asset");
				context.state.payable = asset;
			}

			return ok(context.state.payable > 0 ? algorithm::asset::name_of(context.state.payable) : "null");
		}
		else if (method == "pay")
		{
			if (args.size() > 1)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
					return err("not a valid decimal value");
				context.state.pay = std::move(value);
			}

			return ok(context.state.pay.to_string());
		}
		else if (method == "fund")
		{
			if (args.size() >= 2 && context.state.payable > 0)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
					return err("not a valid decimal value");

				if (value.is_positive())
					context.state.balances[context.state.from][context.state.payable] = std::move(value);
				else
					context.state.balances[context.state.from].erase(context.state.payable);
			}

			for (auto& [account, balances] : context.state.balances)
			{
				for (auto& [asset, value] : balances)
				{
					string address = "null";
					if (!account.empty())
						algorithm::signing::encode_subaddress(account.data, address);
					ok(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
				}
			}
			return true;
		}
		else if (method == "compile")
		{
			if (args.size() < 2)
				return err("not a valid path");

			auto path = os::path::resolve(args[1], directory, true);
			if (!path)
				return err(path.what());

			auto result = context.compile(*path);
			if (!result)
				return err(result.what());

			return true;
		}
		else if (method == "assemble")
		{
			if (args.size() < 3)
				return err("not a valid type");

			if (!context.bound())
				return err("no program bound");

			auto type = args[1];
			if (type != "abi" && type != "0x/abi" && type != "code")
				return err("not a valid type");

			auto path = os::path::resolve(args[2], directory, true);
			if (!path)
				return err(path.what());

			svm_assembler svm_type;
			if (type == "abi")
				svm_type = svm_assembler::abi_raw;
			else if (type == "0x/abi")
				svm_type = svm_assembler::abi_hex;
			else if (true || type == "code")
				svm_type = svm_assembler::code;

			auto result = context.assemble(svm_type, *path);
			if (!result)
				return err(result.what());

			return true;
		}
		else if (method == "pack")
		{
			format::variables function_args;
			function_args.reserve(args.size() - 1);
			for (size_t i = 1; i < args.size(); i++)
				function_args.push_back(format::variable::from(args[i]));

			format::wo_stream message;
			return ok(format::variables_util::serialize_flat_into(function_args, &message) ? message.encode() : "null");
		}
		else if (method == "unpack")
		{
			auto input = format::util::decode_stream(args[1]);
			format::variables function_args;
			format::ro_stream message = format::ro_stream(input);
			if (!format::variables_util::deserialize_flat_from(message, &function_args))
				return ok("null");

			uptr<schema> data = format::variables_util::serialize(function_args);
			terminal->jwrite_line(*data);
			return true;
		}
		else if (method == "call")
		{
			if (args.size() < 2)
				return err("no function declaration");

			auto& function_decl = args[1];
			format::variables function_args;
			function_args.reserve(args.size() - 2);
			for (size_t i = 2; i < args.size(); i++)
				function_args.push_back(format::variable::from(args[i]));

			auto result = context.call(function_decl, std::move(function_args), false);
			if (!result)
				return err(result.what());

			if (context.svmc.returning)
			{
				terminal->jwrite_line(*context.svmc.returning);
				return true;
			}
			else if (context.svmc.environment.validation.context.receipt.successful)
				return ok("program execution finished");
			
			return err("program execution reverted");
		}
		else if (method == "debug")
		{
			if (args.size() < 2)
				return err("no function declaration");

			auto& function_decl = args[1];
			format::variables function_args;
			function_args.reserve(args.size() - 2);
			for (size_t i = 2; i < args.size(); i++)
				function_args.push_back(format::variable::from(args[i]));

			auto result = context.call(function_decl, std::move(function_args), true);
			if (!result)
				return err(result.what());

			if (context.svmc.returning)
			{
				terminal->jwrite_line(*context.svmc.returning);
				return true;
			}
			else if (context.svmc.environment.validation.context.receipt.successful)
				return ok("program execution finished");

			return err("program execution reverted");
		}
		else if (method == "result")
		{
			if (context.svmc.returning)
				terminal->jwrite_line(*context.svmc.returning);
			return true;
		}
		else if (method == "log")
		{
			if (context.svmc.events)
				terminal->jwrite_line(*context.svmc.events);
			return true;
		}
		else if (method == "changelog")
		{
			uptr<schema> changelog = var::set::object();
			auto* erase = changelog->set("erase", var::set::object());
			auto* upsert = changelog->set("upsert", var::set::object());
			for (auto& [index, change] : context.svmc.environment.validation.changelog.outgoing.finalized)
			{
				if (change.erase)
					erase->set(format::util::encode_0xhex(index), change.state->as_schema().reset());
				else
					upsert->set(format::util::encode_0xhex(index), change.state->as_schema().reset());
			}
			terminal->jwrite_line(*changelog);
			return true;
		}
		else if (method == "asm")
		{
			for (auto& instruction : context.svmc.instructions)
				ok(instruction);
			ok(stringify::text("%i instructions; %s gas units", (int)context.svmc.instructions.size(), context.svmc.environment.validation.context.receipt.relative_gas_use.to_string().c_str()));
			return true;
		}
		else if (method == "reset")
		{
			context.reset();
			return ok("state wiped");
		}
		else if (method == "trap")
		{
			if (args.size() > 1)
			{
				uint8_t trap = 255;
				if (args[1] == "off")
					trap = 0;
				else if (args[1] == "err")
					trap = 1;
				else if (args[1] == "all")
					trap = 2;
				if (trap == 255)
					return err("trap type not found");

				context.program.trap = trap;
			}

			if (context.program.trap == 0)
				return ok("execp trap disabled");

			return ok(context.program.trap == 1 ? "execp trap on error" : "execp trap on finish");
		}
		else if (method == "clear")
		{
			terminal->clear();
			return true;
		}
		return true;
	};
	auto command_assemble = [&](string& command) -> bool
	{
		if (stringify::trim(command).empty())
			return true;

		vector<string> args;
		static std::regex pattern("[^\\s\"\']+|\"([^\"]*)\"|\'([^\']*)'");
		for (auto it = std::sregex_iterator(command.begin(), command.end(), pattern); it != std::sregex_iterator(); ++it)
		{
			auto result = copy<string, std::string>(it->str());
			stringify::trim(result);
			if (result.size() >= 2 && result.front() == '\"' && result.back() == '\"')
				result = result.substr(1, result.size() - 2);
			if (!result.empty())
				args.push_back(std::move(result));
		}

		if (args.empty())
			return true;

		auto& method = args[0];
		if (method == "execp")
		{
			if (args.size() < 2)
				return err("not a valid path");

			auto path = os::path::resolve(args[1], directory, true);
			if (!path)
				return err(path.what());

			auto file = os::file::read_as_string(*path);
			if (!file)
				return err(file.what());

			auto possible_execp = schema::from_json(*file);
			if (!possible_execp)
				return err(possible_execp.what());

			auto execp = uptr<schema>(possible_execp);
			if (!execp->value.is(var_type::array))
				return err("not a valid array");

			auto path_directory = os::path::get_directory(*path);
			auto pack = [](const variant& value) -> string { return value.is(var_type::boolean) ? (value.get_boolean() ? "true" : "false") : value.get_blob(); };
			for (size_t i = 0; i < execp->size(); i++)
			{
				auto* subcommand = execp->get(i);
				auto method = subcommand->get_var(0).get_blob();
				if (method != "execp")
					continue;

				auto subpath = os::path::resolve(subcommand->get_var(1).get_blob(), path_directory, true);
				if (!subpath)
					return err("internal execp path error: " + subpath.what());

				auto subfile = os::file::read_as_string(*subpath);
				if (!subfile)
					return err("internal execp file error: " + subfile.what());

				auto possible_execp = schema::from_json(*subfile);
				if (!possible_execp)
					return err("internal execp data error: " + possible_execp.what());

				auto subexecp = uptr<schema>(possible_execp);
				if (!subexecp->value.is(var_type::array))
					return err("internal execp data error: not a valid array");

				auto& from_childs = subexecp->get_childs();
				auto& to_childs = execp->get_childs();
				execp->pop(i);
				while (!from_childs.empty())
				{
					auto* front = from_childs.front();
					front->attach(*execp);
					to_childs.insert(to_childs.begin() + i, front);
					++i;
				}
			}

			for (auto& subcommand : execp->get_childs())
			{
				vector<string> args;
				for (auto& subargument : subcommand->get_childs())
				{
					if (subargument->value.is_object())
					{
						if (subargument->has("$asset"))
						{
							auto blockchain = subargument->fetch_var("$asset.0").get_blob();
							auto token = subargument->fetch_var("$asset.1").get_blob();
							auto contract_address = subargument->fetch_var("$asset.2").get_blob();
							args.push_back(algorithm::asset::id_of(blockchain, token, contract_address).to_string());
						}
						else
						{
							format::variables function_args;
							function_args.reserve(subargument->size());
							for (auto& subsubargument : subargument->get_childs())
								function_args.push_back(format::variable::from(pack(subsubargument->value)));

							format::wo_stream message;
							if (format::variables_util::serialize_flat_into(function_args, &message))
								args.push_back(message.encode());
							else
								args.push_back(string());
						}			
					}
					else
						args.push_back(pack(subargument->value));
				}

				string compiled_command = "> ";
				for (auto& argument : args)
					compiled_command.append(argument).append(1, ' ');
				if (!compiled_command.empty())
					compiled_command.pop_back();

				ok(compiled_command);
				if (!command_execute(args, path_directory))
					return false;
			}
			return true;
		}
		else if (method == "help")
		{
			ok(
				"------------ state-tree virtual machine (svm) -------------\n"
				"This tool may be used to debug the smart contracts before\n"
				"deployment. SVM here does not require non-zero balance\n"
				"to send assets to smart contracts. Everything is virtual\n"
				"and will not be written to current chain state. However,\n"
				"SVM will use current chain state (if any) as a base to\n"
				"execute smart contracts on top of. You may fund one or\n"
				"more accounts before running smart contract code as well\n"
				"as pay to smart contract without funding before hand. The\n"
				"state will be incremental, each call to smart contract will\n"
				"use and update current virtual state. This can be leveraged\n"
				"while debugging more complex execution scenarious requiring\n"
				"more than one consecutive update to smart contract state.\n"
				"Standard debugger is also included and can be used to view\n"
				"the state of the smart contract  Highly verbose.\n"
				"This tool supports execution plans which are useful for\n"
				"creating the test cases using (execp) that are a chain of\n"
				"commands which will be executed until one of them fails or\n"
				"until all of them are successfully finalized. Because state\n"
				"is built upon current chain state, it is possible to test\n"
				"the smart contracts virtually on the mainnet blockchain\n"
				"--------- svm compiler and debugger functionality ---------\n"
				"from [address?|?]                                        -- get/set caller address (if ? then random)\n"
				"to [address?|?]                                          -- get/set contract address (if ? then random)\n"
				"payable [blockchain?] [token?] [contract_address?]       -- get/set caller address paying asset\n"
				"fund [value?]                                            -- get/set caller address balance\n"
				"pay [value?]                                             -- get/set caller address paying value\n"
				"compile [path]                                           -- compile and use program\n"
				"assemble [type:abi|0x/abi|code] [path]                   -- assemble and save used program\n"
				"pack [args?]...                                          -- pack many args into one (for non-trivial function args)\n"
				"unpack [stream]                                          -- unpack stream to many args\n"
				"call [declaration] [args?]...                            -- call a function in a used program\n"
				"debug [declaration] [args?]...                           -- call a function in a used program with debugger attached\n"
				"result                                                   -- get call result log\n"
				"log                                                      -- get call event log\n"
				"changelog                                                -- get call state changes log\n"
				"asm                                                      -- get call svm asm instruction listing\n"
				"reset                                                    -- reset contract state\n"
				"trap [off|err|all]                                       -- enable command interpreter if execp has finished (all) or failed (err)"
				"clear                                                    -- clear console output\n"
				"---------------- environment functionality ----------------\n"
				"execp [path]                                             -- run predefined execution plan (json file of format: [[\"method\", value_or_object_or_array_args?...], ...])\n"
				"help                                                     -- show this message\n"
				"\n"
				"********* node configuration arguments applicable *********\n");
			return true;
		}
		return command_execute(args, directory);
	};

	if (environment.params.size() <= 1 + (params.custom() ? 1 : 0))
	{
	interpreter:
		ok("type \"help\" for more information.");
		string command;
		while (true)
		{
			terminal->write("> ");
			if (!terminal->read_line(command, 1024))
				break;
			if (!command.empty())
				command_assemble(command);
		}
	}
	else
	{
		string command;
		for (size_t i = 1; i < environment.params.size() - (params.custom() ? 1 : 0); i++)
			command.append(environment.params[i]).append(1, ' ');

		bool result = command_assemble(command);
		if (context.program.trap > 1 || (!result && context.program.trap == 1))
			goto interpreter;

		if (!result)
			return 1;
	}
	return 0;
}
int node(const inline_args& environment)
{
	auto params = protocol(environment);
	nds::server_node discovery;
	p2p::server_node consensus;
	nss::server_node& synchronization = *nss::server_node::get();
	rpc::server_node interfaces = rpc::server_node(&consensus);
	
	service_control control;
	control.bind(discovery.get_entrypoint());
	control.bind(consensus.get_entrypoint());
	control.bind(synchronization.get_entrypoint());
	control.bind(interfaces.get_entrypoint());
	return control.launch();
}
int main(int argc, char* argv[])
{
	vitex::runtime scope;
	inline_args environment = os::process::parse_args(argc, argv, (size_t)args_format::key_value);
	return !environment.params.empty() && environment.params.front() == "svm" ? svm(environment) : node(environment);
}