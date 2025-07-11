#include "tangent/validator/service/nss.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/rpc.h"
#include "tangent/kernel/svm.h"
#include "tangent/policy/transactions.h"

using namespace tangent;

int svm(const inline_args& environment)
{
	auto directory = *os::directory::get_working();
	auto params = protocol(environment);
	auto* terminal = console::get();
	auto* host = ledger::svm_host::get();
	auto compiler = host->allocate();
	error_handling::set_flag(log_option::dated, false);

	preprocessor::desc compiler_features;
	compiler_features.conditions = true;
	compiler_features.defines = true;
	compiler_features.includes = true;
	compiler_features.pragmas = false;

	auto* vm = host->get_vm();
	vm->set_ts_imports(true);
	vm->set_preserve_source_code(true);
	vm->set_compiler_features(compiler_features);

	auto program = string();
	ordered_map<algorithm::subpubkeyhash_t, ordered_map<algorithm::asset_id, decimal>> funding;
	algorithm::subpubkeyhash_t from;
	algorithm::subpubkeyhash_t to;
	algorithm::asset_id payable = 0;
	decimal pay = decimal::zero();

	static bool active = true;
	os::process::bind_signal(signal_code::SIG_INT, [](int) { active = false; });
	os::process::bind_signal(signal_code::SIG_TERM, [](int) { active = false; });
	terminal->write_line("type \"help\" for more information.");
	while (active)
	{
		terminal->write("> ");
		auto command = terminal->read(1024);
		if (command.empty())
			continue;

		auto args = stringify::split(command, ' ');
		auto& method = args[0];
		if (method == "from")
		{
			if (args.size() > 1)
			{
				if (!algorithm::signing::decode_subaddress(args[1], from.data))
				{
					terminal->write_line("not a valid address");
					continue;
				}
			}
			
			if (!from.empty())
			{
				string address;
				algorithm::signing::encode_subaddress(from.data, address);
				terminal->write_line(address);
			}
			else
				terminal->write_line("null");
		}
		else if (method == "to")
		{
			if (args.size() > 1)
			{
				if (!algorithm::signing::decode_subaddress(args[1], to.data))
				{
					terminal->write_line("not a valid address");
					continue;
				}
			}

			if (!to.empty())
			{
				string address;
				algorithm::signing::encode_subaddress(to.data, address);
				terminal->write_line(address);
			}
			else
				terminal->write_line("null");
		}
		else if (method == "payable")
		{
			if (args.size() > 1)
			{
				auto asset = algorithm::asset::id_of(args[1], args.size() > 2 ? args[2] : std::string_view(), args.size() > 3 ? args[3] : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
				{
					terminal->write_line("not a valid asset");
					continue;
				}
				payable = asset;
			}

			terminal->write_line(payable > 0 ? algorithm::asset::name_of(payable) : "null");
		}
		else if (method == "pay")
		{
			if (args.size() > 1)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
				{
					terminal->write_line("not a valid decimal value");
					continue;
				}
				pay = std::move(value);
			}

			terminal->write_line(pay.to_string());
		}
		else if (method == "fund")
		{
			if (args.size() >= 3)
			{
				decimal value = decimal(args[1]);
				if (value.is_nan() || value.is_negative())
				{
					terminal->write_line("not a valid decimal value");
					continue;
				}

				auto asset = algorithm::asset::id_of(args[2], args.size() > 3 ? args[3] : std::string_view(), args.size() > 4 ? args[4] : std::string_view());
				if (!asset || !algorithm::asset::is_valid(asset))
				{
					terminal->write_line("not a valid asset");
					continue;
				}

				if (value.is_positive())
					funding[to][asset] = std::move(value);
				else
					funding[to].erase(asset);
			}

			for (auto& [account, balances] : funding)
			{
				for (auto& [asset, value] : balances)
				{
					string address = "null";
					if (!account.empty())
						algorithm::signing::encode_subaddress(account.data, address);
					terminal->write_line(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
				}
			}
		}
		else if (method == "compile")
		{
			if (args.size() < 2)
			{
				terminal->write_line("not a valid path");
				continue;
			}

			auto path = os::path::resolve(args[1], directory, true);
			if (!path)
			{
				terminal->write_line(path.what());
				continue;
			}

			auto file = os::file::read_as_string(*path);
			if (!file)
			{
				terminal->write_line(file.what());
				continue;
			}

			vm->clear_cache();
			auto hash = algorithm::hashing::hash512((uint8_t*)file->data(), file->size());
			auto result = host->compile(*compiler, hash, *path, *file);
			if (!result)
			{
				terminal->colorize(std_color::light_gray, result.what());
				terminal->write_char('\n');
				continue;
			}

			program = std::move(*path);
		}
		else if (method == "assemble")
		{
			if (args.size() < 3)
			{
				terminal->write_line("not a valid type");
				continue;
			}

			if (program.empty())
			{
				terminal->write_line("no program in use");
				continue;
			}

			auto type = args[1];
			if (type != "abi" && type != "0x/abi" && type != "code")
			{
				terminal->write_line("not a valid type");
				continue;
			}

			auto path = os::path::resolve(args[2], directory, true);
			if (!path)
			{
				terminal->write_line(path.what());
				continue;
			}
			else if (vm->get_script_sections().empty())
			{
				terminal->write_line("no program attached");
				continue;
			}

			vector<string> codes;
			for (auto& [name, code] : vm->get_script_sections())
				codes.push_back(code);

			string listing;
			std::sort(codes.begin(), codes.end(), [](const string& a, const string& b) { return a.size() > b.size(); });
			for (auto& code : codes)
				listing.append(stringify::trim(code)).append("\n\n");
			if (!listing.empty())
				listing.erase(listing.size() - 2, 2);

			if (type == "abi" || type == "0x/abi")
			{
				auto result = host->pack(listing);
				if (!result)
				{
					terminal->write_line(result.what());
					continue;
				}

				if (type == "0x/abi")
					listing = format::util::encode_0xhex(*result);
				else
					listing = std::move(*result);
			}

			auto result = os::file::write(*path, (uint8_t*)listing.data(), listing.size());
			if (!result)
				terminal->write_line(result.what());
		}
		else if (method == "call")
		{
			if (args.size() < 2)
			{
				terminal->write_line("no function declaration");
				continue;
			}

			if (program.empty())
			{
				terminal->write_line("no program in use");
				continue;
			}

			if (from.empty())
			{
				terminal->write_line("no from address");
				continue;
			}

			if (to.empty())
			{
				terminal->write_line("no to address");
				continue;
			}

			if (!payable)
			{
				terminal->write_line("no payable asset");
				continue;
			}

			auto& function = args[1];
			format::variables calldata;
			calldata.reserve(args.size() - 2);
			for (size_t i = 2; i < args.size(); i++)
				calldata.push_back(format::variable::from(args[i]));

			transactions::call transaction;
			transaction.asset = payable;
			transaction.signature[0] = 0xFF;
			transaction.nonce = std::max<size_t>(1, ledger::transaction_context().get_account_nonce(from.data).or_else(states::account_nonce(nullptr, nullptr)).nonce);
			transaction.program_call(to, pay, function, std::move(calldata));
			transaction.set_gas(decimal::zero(), ledger::block::get_gas_limit());

			bool funded = true;
			auto script = ledger::svm_program_trace(&transaction, from.data, true);
			for (auto& [account, balances] : funding)
			{
				for (auto& [asset, value] : balances)
				{
					states::account_balance balance = states::account_balance(account.data, asset, nullptr);
					balance.supply = value;

					auto status = script.context->store(&balance, false);
					if (!status)
					{
						terminal->write_line(status.what());
						funded = false;
						break;
					}
				}
				if (!funded)
					break;
			}
			if (!funded)
				continue;

			auto execution = script.trace_call(ledger::svm_call::system_call, transaction.function, transaction.args);
			if (!execution)
			{
				terminal->write_line(execution.what());
				continue;
			}

			terminal->jwrite_line(*script.as_schema());
		}
		else if (method == "clear")
		{
			terminal->clear();
			terminal->write_line("type \"help\" for more information.");
		}
		else if (method == "help")
		{
			terminal->write(
				"-------- svm compiler and debugger functionality --------\n"
				"from [address?]                                          -- get/set caller address\n"
				"to [address?]                                            -- get/set contract address\n"
				"payable [blockchain?] [token?] [contract_address?]       -- get/set paying asset\n"
				"pay [value?]                                             -- get/set paying value\n"
				"fund [value?] [blockchain?] [token?] [contract_address?] -- get/set test balance of contract address\n"
				"compile [path]                                           -- compile and use program\n"
				"assemble [type:abi|x/abi|code] [path]                    -- assemble and save used program\n"
				"call [function_declaration]                              -- call a function in a used program\n"
				"clear                                                    -- clear console output\n");
		}
	}

	host->deallocate(std::move(compiler));
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