#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"
#include "tangent/kernel/svm.h"
#include "tangent/policy/transactions.h"
#include <vitex/bindings.h>
#include <regex>

using namespace tangent;

struct svm_context
{
	enum class assembler
	{
		abi_raw,
		abi_hex,
		code
	};
	struct
	{
		uptr<compiler> compiler;
		string path;
		string log;
	} program;
	ordered_map<algorithm::subpubkeyhash_t, ordered_map<algorithm::asset_id, decimal>> balances;
	ledger::evaluation_context environment;
	algorithm::subpubkeyhash_t from;
	algorithm::subpubkeyhash_t to;
	algorithm::asset_id payable;
	decimal pay;

	svm_context() : payable(0), pay(decimal::zero())
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
		program.compiler = host->allocate();
	}
	~svm_context()
	{
		auto* host = ledger::svm_host::get();
		host->deallocate(std::move(program.compiler));
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
		auto result = host->compile(*program.compiler, hash, new_path, *file);
		vm->set_compiler_error_callback(nullptr);
		if (!result)
			return result.error();

		program.path = new_path;
		return expectation::met;
	}
	expects_lr<void> assemble(assembler type, const std::string_view& new_path)
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

		if (type == assembler::abi_raw || type == assembler::abi_hex)
		{
			auto result = host->pack(listing);
			if (!result)
				return result.error();

			if (type == assembler::abi_hex)
				listing = format::util::encode_0xhex(*result);
			else
				listing = std::move(*result);
		}

		auto result = os::file::write(new_path, (uint8_t*)listing.data(), listing.size());
		if (!result)
			return layer_exception(result.what());

		return expectation::met;
	}
	expects_lr<uptr<schema>> call(const std::string_view& function, format::variables&& args, bool attach_debugger_context)
	{
		if (program.path.empty())
			return layer_exception("program not bound");

		if (from.empty())
			return layer_exception("caller address not valid");

		if (to.empty())
			return layer_exception("contract address not valid");

		if (!payable)
			return layer_exception("payable asset not valid");

		auto script = ledger::svm_program_trace(&environment);
		auto assignment = script.assign_transaction(payable, from.data, to, pay, function, args);
		if (!assignment)
			return assignment.error();

		for (auto& [account, balances] : balances)
		{
			for (auto& [asset, value] : balances)
			{
				auto balance = states::account_balance(account.data, asset, nullptr);
				balance.supply = value;

				auto status = script.context->store(&balance, false);
				if (!status)
					return status.error();
			}
		}

		auto* vm = program.compiler->get_vm();
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

		auto execution = script.call_compiled(*program.compiler, ledger::svm_call::system_call, function, args);
		if (attach_debugger_context)
			vm->set_debugger(nullptr);

		if (!execution)
			return execution.error();

		auto result = script.as_schema();
		environment.validation.changelog.commit();
		return expects_lr<uptr<schema>>(std::move(result));
	}
	void reset()
	{
		auto* host = ledger::svm_host::get();
		host->deallocate(std::move(program.compiler));
		program.compiler = host->allocate();
		program.path.clear();
		program.log.clear();
		balances.clear();
		environment = ledger::evaluation_context();
		from = algorithm::subpubkeyhash_t();
		to = algorithm::subpubkeyhash_t();
		payable = 0;
		pay = decimal::zero();
	}
	bool bound() const
	{
		return !program.path.empty();
	}
};

int svm(const inline_args& environment)
{
	auto params = protocol(environment);
	auto context = svm_context();
	auto* terminal = console::get();
	auto results = uptr<schema>();
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
					if (!algorithm::signing::decode_subaddress(args[1], context.from.data))
						return err("not a valid address");
				}
				else
				{
					memset(context.from.data, 0, sizeof(context.from.data));
					crypto::fill_random_bytes(context.from.data, sizeof(algorithm::pubkeyhash));
				}
			}

			if (context.from.empty())
				return ok("null");

			string address;
			algorithm::signing::encode_subaddress(context.from.data, address);
			return ok(address);
		}
		else if (method == "to")
		{
			if (args.size() > 1)
			{
				if (args[1] != "?")
				{
					if (!algorithm::signing::decode_subaddress(args[1], context.to.data))
						return err("not a valid address");
				}
				else
				{
					memset(context.to.data, 0, sizeof(context.to.data));
					crypto::fill_random_bytes(context.to.data, sizeof(algorithm::pubkeyhash));
				}
			}

			if (context.to.empty())
				return ok("null");

			string address;
			algorithm::signing::encode_subaddress(context.to.data, address);
			return ok(address);
		}
		else if (method == "payable")
		{
			if (args.size() > 1)
			{
				auto asset = algorithm::asset::id_of(stringify::to_upper(args[1]), args.size() > 2 ? stringify::to_upper(args[2]) : std::string_view(), args.size() > 3 ? args[3] : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
					return err("not a valid asset");
				context.payable = asset;
			}

			return ok(context.payable > 0 ? algorithm::asset::name_of(context.payable) : "null");
		}
		else if (method == "pay")
		{
			if (args.size() > 1)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
					return err("not a valid decimal value");
				context.pay = std::move(value);
			}

			return ok(context.pay.to_string());
		}
		else if (method == "fund")
		{
			if (args.size() >= 3)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
					return err("not a valid decimal value");

				auto asset = algorithm::asset::id_of(stringify::to_upper(args[2]), args.size() > 3 ? stringify::to_upper(args[3]) : std::string_view(), args.size() > 4 ? stringify::to_upper(args[4]) : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
					return err("not a valid asset");

				if (value.is_positive())
					context.balances[context.to][asset] = std::move(value);
				else
					context.balances[context.to].erase(asset);
			}

			for (auto& [account, balances] : context.balances)
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

			svm_context::assembler svm_type;
			if (type == "abi")
				svm_type = svm_context::assembler::abi_raw;
			else if (type == "0x/abi")
				svm_type = svm_context::assembler::abi_hex;
			else if (true || type == "code")
				svm_type = svm_context::assembler::code;

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

			results = std::move(*result);
			if (results)
			{
				terminal->jwrite_line(results->get("returns"));
				return true;
			}
			else if (results->get_var("successful").get_boolean())
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

			results = std::move(*result);
			if (results)
			{
				terminal->jwrite_line(results->get("returns"));
				return true;
			}
			else if (results->get_var("successful").get_boolean())
				return ok("program execution finished");

			return err("program execution reverted");
		}
		else if (method == "result")
		{
			if (results)
				terminal->jwrite_line(results->get("returns"));
			return true;
		}
		else if (method == "log")
		{
			if (results)
			{
				auto events = results->get("events");
				if (events)
				{
					size_t index = 0;
					for (auto& event : events->get_childs())
					{
						auto hash = event->get_var("type").get_integer();
						auto name = event->get_var("name").get_blob();
						ok(stringify::text("%03d event 0x%x (%s):", (int)++index, (int)hash, name.c_str()));
						terminal->jwrite_line(event->get("data"));
					}
				}
			}
			return true;
		}
		else if (method == "changelog")
		{
			uptr<schema> changelog = var::set::object();
			auto* erase = changelog->set("erase", var::set::object());
			auto* upsert = changelog->set("upsert", var::set::object());
			for (auto& [index, change] : context.environment.validation.changelog.outgoing.finalized)
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
			if (results)
			{
				auto instructions = results->get("instructions");
				if (instructions)
				{
					for (auto& instruction : instructions->get_childs())
						ok(instruction->value.get_string());
					ok(stringify::text("%i instructions; %s gas units", (int)instructions->size(), results->get_var("gas").get_blob().c_str()));
				}
			}
			return true;
		}
		else if (method == "report")
		{
			if (results)
				terminal->jwrite_line(*results);
			return true;
		}
		else if (method == "reset")
		{
			context.reset();
			return ok("state wiped");
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
				"the state of the smart contract program. Highly verbose.\n"
				"This tool supports execution plans which are useful for\n"
				"creating the test cases using (execp) that are a chain of\n"
				"commands which will be executed until one of them fails or\n"
				"until all of them are successfully finalized. Because state\n"
				"is built upon current chain state, it is possible to test\n"
				"the smart contracts virtually on the mainnet blockchain\n"
				"--------- svm compiler and debugger functionality ---------\n"
				"from [address?|?]                                        -- get/set caller address (if ? then random)\n"
				"to [address?|?]                                          -- get/set contract address (if ? then random)\n"
				"payable [blockchain?] [token?] [contract_address?]       -- get/set paying asset\n"
				"pay [value?]                                             -- get/set paying value\n"
				"fund [value?] [blockchain?] [token?] [contract_address?] -- get/set test balance of address\n"
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
				"report                                                   -- get call full report\n"
				"reset                                                    -- reset contract state\n"
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
		return 0;
	}
	else
	{
		auto args = environment.params;
		args.erase(args.begin());
		if (params.custom())
			args.pop_back();
		return command_execute(args, directory) ? 0 : 1;
	}
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