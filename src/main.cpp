#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"
#include "tangent/kernel/svm.h"
#include "tangent/policy/transactions.h"
#include <regex>

using namespace tangent;

enum class svm_assemble
{
	abi_raw,
	abi_hex,
	code
};

struct svm_context
{
	struct
	{
		string path;
		string log;
	} program;
	ordered_map<algorithm::subpubkeyhash_t, ordered_map<algorithm::asset_id, decimal>> balances;
	ledger::evaluation_context environment;
	algorithm::subpubkeyhash_t from;
	algorithm::subpubkeyhash_t to;
	algorithm::asset_id payable;
	uptr<compiler> compiler;
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
		vm->set_preserve_source_code(true);
		vm->set_compiler_features(compiler_features);
		compiler = host->allocate();
	}
	~svm_context()
	{
		auto* host = ledger::svm_host::get();
		host->deallocate(std::move(compiler));
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
		auto result = host->compile(*compiler, hash, new_path, *file);
		vm->set_compiler_error_callback(nullptr);
		if (!result)
			return result.error();

		program.path = new_path;
		return expectation::met;
	}
	expects_lr<void> assemble(svm_assemble type, const std::string_view& new_path)
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

		if (type == svm_assemble::abi_raw || type == svm_assemble::abi_hex)
		{
			auto result = host->pack(listing);
			if (!result)
				return result.error();

			if (type == svm_assemble::abi_hex)
				listing = format::util::encode_0xhex(*result);
			else
				listing = std::move(*result);
		}

		auto result = os::file::write(new_path, (uint8_t*)listing.data(), listing.size());
		if (!result)
			return layer_exception(result.what());

		return expectation::met;
	}
	expects_lr<uptr<schema>> call(const std::string_view& function, format::variables&& args)
	{
		if (program.path.empty())
			return layer_exception("program not bound");

		if (from.empty())
			return layer_exception("caller address not valid");

		if (to.empty())
			return layer_exception("contract address not valid");

		if (!payable)
			return layer_exception("payable asset not valid");

		transactions::call transaction;
		transaction.asset = payable;
		transaction.signature[0] = 0xFF;
		transaction.nonce = std::max<size_t>(1, ledger::transaction_context().get_account_nonce(from.data).or_else(states::account_nonce(nullptr, nullptr)).nonce);
		transaction.program_call(to, pay, function, std::move(args));
		transaction.set_gas(decimal::zero(), ledger::block::get_gas_limit());

		auto script = ledger::svm_program_trace(&environment, &transaction, from.data, true);
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

		auto execution = script.trace_call(*compiler, ledger::svm_call::system_call, transaction.function, transaction.args);
		if (!execution)
			return execution.error();

		auto result = script.as_schema();
		environment.validation.changelog.commit();
		return expects_lr<uptr<schema>>(std::move(result));
	}
	void reset()
	{
		environment = ledger::evaluation_context();
		balances.clear();
	}
	bool bound() const
	{
		return !program.path.empty();
	}
};

int svm(const inline_args& environment)
{
	auto directory = *os::directory::get_working();
	auto params = protocol(environment);
	auto context = svm_context();
	auto* terminal = console::get();
	auto results = uptr<schema>();
	auto say = [&](const std::string_view& line) { terminal->colorize(std_color::light_gray, line); terminal->write_char('\n'); };
	error_handling::set_flag(log_option::dated, false);

	static bool active = true;
	os::process::bind_signal(signal_code::SIG_INT, [](int) { active = false; });
	os::process::bind_signal(signal_code::SIG_TERM, [](int) { active = false; });
	say("type \"help\" for more information.");
	while (active)
	{
		terminal->write("> ");
		auto command = terminal->read(1024);
		if (stringify::trim(command).empty())
			continue;

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

		auto& method = args[0];
		if (method == "from")
		{
			if (args.size() > 1)
			{
				if (args[1] != "?")
				{
					if (!algorithm::signing::decode_subaddress(args[1], context.from.data))
					{
						say("not a valid address");
						continue;
					}
				}
				else
					crypto::fill_random_bytes(context.from.data, sizeof(context.from.data));
			}
			
			if (!context.from.empty())
			{
				string address;
				algorithm::signing::encode_subaddress(context.from.data, address);
				say(address);
			}
			else
				say("null");
		}
		else if (method == "to")
		{
			if (args.size() > 1)
			{
				if (args[1] != "?")
				{
					if (!algorithm::signing::decode_subaddress(args[1], context.to.data))
					{
						say("not a valid address");
						continue;
					}
				}
				else
					crypto::fill_random_bytes(context.to.data, sizeof(context.to.data));
			}

			if (!context.to.empty())
			{
				string address;
				algorithm::signing::encode_subaddress(context.to.data, address);
				say(address);
			}
			else
				say("null");
		}
		else if (method == "payable")
		{
			if (args.size() > 1)
			{
				auto asset = algorithm::asset::id_of(stringify::to_upper(args[1]), args.size() > 2 ? stringify::to_upper(args[2]) : std::string_view(), args.size() > 3 ? stringify::to_upper(args[3]) : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
				{
					say("not a valid asset");
					continue;
				}
				context.payable = asset;
			}

			say(context.payable > 0 ? algorithm::asset::name_of(context.payable) : "null");
		}
		else if (method == "pay")
		{
			if (args.size() > 1)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
				{
					say("not a valid decimal value");
					continue;
				}
				context.pay = std::move(value);
			}

			say(context.pay.to_string());
		}
		else if (method == "fund")
		{
			if (args.size() >= 3)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
				{
					say("not a valid decimal value");
					continue;
				}

				auto asset = algorithm::asset::id_of(stringify::to_upper(args[2]), args.size() > 3 ? stringify::to_upper(args[3]) : std::string_view(), args.size() > 4 ? stringify::to_upper(args[4]) : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
				{
					say("not a valid asset");
					continue;
				}

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
					say(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
				}
			}
		}
		else if (method == "compile")
		{
			if (args.size() < 2)
			{
				say("not a valid path");
				continue;
			}

			auto path = os::path::resolve(args[1], directory, true);
			if (!path)
			{
				say(path.what());
				continue;
			}

			auto result = context.compile(*path);
			if (!result)
			{
				terminal->colorize(std_color::light_gray, result.what());
				continue;
			}
		}
		else if (method == "assemble")
		{
			if (args.size() < 3)
			{
				say("not a valid type");
				continue;
			}

			if (!context.bound())
			{
				say("no program bound");
				continue;
			}

			auto type = args[1];
			if (type != "abi" && type != "0x/abi" && type != "code")
			{
				say("not a valid type");
				continue;
			}

			auto path = os::path::resolve(args[2], directory, true);
			if (!path)
			{
				say(path.what());
				continue;
			}

			svm_assemble svm_type;
			if (type == "abi")
				svm_type = svm_assemble::abi_raw;
			else if (type == "0x/abi")
				svm_type = svm_assemble::abi_hex;
			else if (type == "code")
				svm_type = svm_assemble::code;

			auto result = context.assemble(svm_type, *path);
			if (!result)
				say(result.what());
		}
		else if (method == "pack")
		{
			format::variables function_args;
			function_args.reserve(args.size() - 1);
			for (size_t i = 1; i < args.size(); i++)
				function_args.push_back(format::variable::from(args[i]));

			format::wo_stream message;
			if (format::variables_util::serialize_flat_into(function_args, &message))
				say(message.encode());
			else
				say("null");
		}
		else if (method == "unpack")
		{
			auto input = format::util::decode_stream(args[1]);
			format::variables function_args;
			format::ro_stream message = format::ro_stream(input);
			if (format::variables_util::deserialize_flat_from(message, &function_args))
			{
				uptr<schema> data = format::variables_util::serialize(function_args);
				terminal->jwrite_line(*data);
			}
			else
				say("null");
		}
		else if (method == "call")
		{
			if (args.size() < 2)
			{
				say("no function declaration");
				continue;
			}

			auto& function_decl = args[1];
			format::variables function_args;
			function_args.reserve(args.size() - 2);
			for (size_t i = 2; i < args.size(); i++)
				function_args.push_back(format::variable::from(args[i]));

			auto result = context.call(function_decl, std::move(function_args));
			if (!result)
			{
				say(result.what());
				continue;
			}

			results = std::move(*result);
			say(results->get_var("successful").get_boolean() ? "OK" : "reverted");
		}
		else if (method == "result")
		{
			if (results)
				terminal->jwrite_line(results->get("returns"));
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
						auto hash = event->get_var("event").get_integer();
						say(stringify::text("%03d event 0x%x:", (int)++index, (int)hash));
						terminal->jwrite_line(event->get("args"));
					}
				}
			}
		}
		else if (method == "changelog")
		{
			if (results)
				terminal->jwrite_line(results->get("changelog"));
		}
		else if (method == "sasm")
		{
			if (results)
			{
				auto instructions = results->get("instructions");
				if (instructions)
				{
					for (auto& instruction : instructions->get_childs())
						say(instruction->value.get_string());
				}
			}
		}
		else if (method == "report")
		{
			if (results)
				terminal->jwrite_line(*results);
		}
		else if (method == "reset")
		{
			context.reset();
			say("state wiped");
		}
		else if (method == "clear")
		{
			terminal->clear();
			say("type \"help\" for more information.");
		}
		else if (method == "help")
		{
			say(
				"-------- svm compiler and debugger functionality --------\n"
				"from [address?|?]                                        -- get/set caller address (if ? then random)\n"
				"to [address?|?]                                          -- get/set contract address (if ? then random)\n"
				"payable [blockchain?] [token?] [contract_address?]       -- get/set paying asset\n"
				"pay [value?]                                             -- get/set paying value\n"
				"fund [value?] [blockchain?] [token?] [contract_address?] -- get/set test balance of contract address\n"
				"compile [path]                                           -- compile and use program\n"
				"assemble [type:abi|0x/abi|code] [path]                   -- assemble and save used program\n"
				"pack [args?]...                                          -- pack many args into one (for non-trivial function args)\n"
				"unpack [stream]                                          -- unpack stream to many args\n"
				"call [declaration] [args?]...                            -- call a function in a used program\n"
				"result                                                   -- get call result log\n"
				"log                                                      -- get call event log\n"
				"changelog                                                -- get call state changes log\n"
				"sasm                                                     -- get call svm asm instruction listing\n"
				"report                                                   -- get call full report\n"
				"reset                                                    -- reset contract state\n"
				"clear                                                    -- clear console output\n");
		}
	}

	return 0;
}
int server(const inline_args& environment)
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
	return !environment.params.empty() && environment.params.front() == "svm" ? svm(environment) : server(environment);
}