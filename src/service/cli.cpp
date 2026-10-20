#include "cli.h"
#include "../policy/transactions.h"
#include "../storage/chainstate.h"
#ifdef VI_MICROSOFT
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace tangent
{
	namespace cli
	{
		session::session() : script::program(nullptr, nullptr)
		{
			preprocessor::desc compiler_features;
			compiler_features.conditions = true;
			compiler_features.defines = true;
			compiler_features.includes = true;
			compiler_features.pragmas = false;

			auto* vm = script::factory::get()->get_vm();
			vm->set_ts_imports(true);
			vm->set_ts_imports_concat_mode(true);
			vm->set_preserve_source_code(true);
			vm->set_compiler_features(compiler_features);
			
			executor = &tracer.solver.state.executor;
			env.block_number = storages::chainstate().get_latest_block_number().or_else(1) + 1;
		}
		static void sanitize_binary_strings(format::tree& node)
		{
			if (node.is_flat())
			{
				if (node.value.is_string())
				{
					auto data = node.value.as_string();
					if (!format::variables_util::is_ascii_encoding(data))
						node.value = format::variable(format::util::encode_0xhex(data));
				}
				return;
			}
			for (auto& child : node.childs())
				sanitize_binary_strings(child);
		}
		expects_lr<void> session::call_transaction(script::ccall mutability, const script::function& entrypoint, const format::variables& args)
		{
			VI_ASSERT(tracer.transaction, "transaction should be assigned");
			tracer.returning = format::tree();
			tracer.events.clear();
			auto execution = execute(script::payable_repr(transactions::call::payable_array(env.payable.payments)), mutability, entrypoint, args, [this](void* address, int type_id) -> expects_lr<void>
			{
				auto serialization = script::marshall::store(tracer.returning, address, type_id);
				if (!serialization)
					return layer_exception("return value error: " + serialization.error().message());

				sanitize_binary_strings(tracer.returning);
				return expectation::met;
			});
			executor->receipt.successful = !!execution;
			executor->receipt.block_time = kernel::params().time.now();
			if (!executor->receipt.successful)
				executor->emit_event(0, { format::variable(execution.what()) }, ledger::executor_context::meter::unpaid);

			tracer.log = format::tree::list();
			for (auto& item : executor->receipt.events)
			{
				auto target = tracer.events.find(tracer.log.childs().size());
				auto* next = tracer.log.push(format::tree::map());
				next->set("type", format::variable(item.event));
				if (!item.emitter.empty())
					next->set("emitter", algorithm::signing::serialize_address(item.emitter));
				if (target == tracer.events.end())
				{
					uptr<ledger::transition_state> temp = states::resolver::from_type(item.event);
					next->set(temp ? temp->as_typename() : "__non_standard__", serialize_event_args(item.args));
				}
				else
					next->set(target->second.key, target->second);
			}
			if (execution && (mutability != script::ccall::standard_call || mutability_of(entrypoint) != script::ccall::constant_call) && (env.call_flags & ((uint8_t)transactions::call::feature::require_withdraw | (uint8_t)transactions::call::feature::require_route)))
			{
				ledger::transaction_message* staged = nullptr;
				if (env.call_flags & (uint8_t)transactions::call::feature::require_route)
				{
					auto routing = memory::init<transactions::imbind>();
					routing->asset = algorithm::asset::native();
					routing->gas_price = decimal::zero();
					routing->route_hash = executor->receipt.transaction_hash;
					staged = routing;
				}
				else
				{
					auto withdrawal = memory::init<transactions::broadcast>();
					withdrawal->asset = algorithm::asset::native();
					withdrawal->gas_price = decimal::zero();
					withdrawal->withdraw_hash = executor->receipt.transaction_hash;
					if (!env.temporary_reverted)
						withdrawal->set_proof(executor->receipt.transaction_hash, expects_lr<superchain::finalized_transaction>(superchain::finalized_transaction()));
					staged = withdrawal;
				}

				ledger::transaction_receipt broadcast;
				broadcast.transaction_hash = temporary_hash;
				broadcast.from = env.to;
				broadcast.block_number = virtual_block_number();
				broadcast.block_time = kernel::params().time.now();
				broadcast.successful = !env.temporary_reverted;
				broadcast.relative_gas_use = executor->receipt.relative_gas_use;
				broadcast.absolute_gas_use = executor->receipt.relative_gas_use;
				uptr<ledger::transaction_message> broadcast_message(staged);
				temporary_transaction = memory::init<ledger::block_transaction>(std::move(broadcast_message), std::move(broadcast));
			}
			return execution;
		}
		expects_lr<ledger::block_transaction> session::block_transaction_of(const uint256_t& transaction_hash) const
		{
			if (temporary_transaction && transaction_hash == temporary_hash)
				return ledger::block_transaction(**temporary_transaction);

			return script::program::block_transaction_of(transaction_hash);
		}
		expects_lr<void> session::compile(const std::string_view& new_path)
		{
			if (env.to.empty())
				return layer_exception("contract address not valid");

			auto file = os::file::read_as_string(new_path);
			if (!file)
				return layer_exception(file.what());

			auto* factory = script::factory::get();
			auto* vm = factory->get_vm();
			vm->set_compiler_error_callback([this](const std::string_view& message) { program.log.append(message).append("\r\n"); });
			vm->clear_cache();
			program.log.clear();

			auto result = factory->compile_module(new_path, [&]() { return expects_lr<string>(*file); });
			vm->set_compiler_error_callback(nullptr);
			if (!program.log.empty())
				return layer_exception(string(program.log));
			else if (!result)
				return result.error();

			transactions::call temporary;
			temporary.gas_limit = 1'000'000;
			tracer.solver.apply_temporary_state(&tracer.block, &temporary, { });

			auto storage = algorithm::encoding::pack_program(*file);
			if (!storage)
				return storage.error();

			auto storage_status = executor->apply_witness_program(*storage);
			if (!storage_status)
				return storage_status.error();

			auto hashcode_status = executor->apply_account_program(env.to, algorithm::hashing::ppc512(*file));
			if (!hashcode_status)
				return hashcode_status.error();

			program.path = new_path;
			tracer.pmodule = std::move(*result);
			module = tracer.pmodule->get_module();
			return expectation::met;
		}
		expects_lr<void> session::assemble(script_asm type, const std::string_view& new_path, format::variables&& function_args)
		{
			auto* vm = script::factory::get()->get_vm();
			if (vm->get_script_sections().empty())
				return layer_exception("source code not found");

			vector<string> codes;
			for (auto& [name, code] : vm->get_script_sections())
				codes.push_back(code);

			string data;
			std::sort(codes.begin(), codes.end(), [](const string& a, const string& b) { return a.size() > b.size(); });
			for (auto& code : codes)
				data.append(stringify::trim(code)).append("\n\n");
			if (!data.empty())
				data.erase(data.size() - 2, 2);

			if (type == script_asm::tx_deploy)
			{
				auto transaction = transactions::deploy();
				transaction.from_program(data, std::move(function_args));

				auto message = transaction.as_message();
				data = std::move(message.data);
			}
			else if (type == script_asm::tx_call)
			{
				if (function_args.empty())
					return layer_exception("first argument of argument pack must be a function decl/name");

				auto function_decl = function_args.front().as_blob();
				function_args.erase(function_args.begin());

				auto transaction = transactions::call();
				transaction.call_to(env.to, function_decl, std::move(function_args));
				transaction.pays = env.payable.payments;

				auto message = transaction.as_message();
				data = std::move(message.data);
			}
			else if (type == script_asm::abi)
			{
				auto result = algorithm::encoding::pack_program(data);
				if (!result)
					return result.error();

				data = std::move(*result);
			}

			auto result = os::file::write(new_path, (uint8_t*)data.data(), data.size());
			if (!result)
				return layer_exception(result.what());

			return expectation::met;
		}
		expects_lr<void> session::call(const std::string_view& function_decl, format::variables&& args, bool attach_debugger_context)
		{
			if (program.path.empty())
				return layer_exception("program not bound");

			if (env.from.empty())
				return layer_exception("caller address not valid");

			if (env.to.empty())
				return layer_exception("contract address not valid");

			auto* transaction = memory::init<transactions::call>();
			transaction->asset = env.call_asset;
			transaction->pays = env.payable.payments;
			transaction->signature.blob[0] = 0xFF;
			transaction->nonce = std::max<size_t>(1, tracer.solver.state.executor.get_account_nonce(env.from).or_else(states::account_nonce(algorithm::pubkeyhash_t(), nullptr)).nonce);
			transaction->call_to(env.to, function_decl, format::variables(args));
			transaction->set_gas(decimal::zero(), ledger::block_body::get_gas_limit());
			if (env.call_flags)
				transaction->set_flags(env.call_flags);
			tracer.transaction = std::move(transaction);

			auto function = transaction->get_function();
			ledger::transaction_receipt receipt;
			receipt.from = env.from;
			tracer.solver.apply_temporary_state(&tracer.block, *tracer.transaction, std::move(receipt));

			script::ccall call_type = script::ccall::standard_call;
			if (function == script::program::deploy_function_name())
				call_type = script::ccall::deploy_call;

			auto entrypoint = module.get_function_by_decl(function);
			if (!entrypoint.is_valid())
				entrypoint = module.get_function_by_name(function);
			if (call_type == script::ccall::standard_call && !entrypoint.is_valid())
				return layer_exception("illegal call to function: null function");

			auto read_only = call_type == script::ccall::standard_call ? mutability_of(entrypoint) == script::ccall::constant_call : false;
			if (!read_only)
			{
				for (auto& [account, balances] : env.balances)
				{
					for (auto& [asset, value] : balances)
					{
						auto prev_balance = executor->get_account_balance(asset, account);
						if (prev_balance && prev_balance->get_balance() >= value)
							continue;

						auto balance = states::account_balance(account, asset, nullptr);
						balance.supply = value;

						auto status = executor->store(&balance, ledger::executor_context::meter::unpaid);
						if (!status)
							return status.error();
					}
				}

				for (auto& [paying_asset, paying_value] : env.payable.payments)
				{
					auto payment = executor->apply_payment(paying_asset, env.from, env.to, paying_value);
					if (!payment)
						return payment.error();
				}
			}

			auto* vm = module.get_vm();
			if (attach_debugger_context)
			{
				auto* factory = script::factory::get();
				auto* debugger = new script::debugger_context();
				debugger->set_interrupt_callback([](bool is_interrupted) { console::get()->write_line(is_interrupted ? "program execution interrupted" : "resuming program execution"); });
				factory->bind_debugger_tools(debugger);
				vm->set_debugger(debugger);
				interrupter(true);
			}

			tracer.returning = format::tree();
			auto execution = call_transaction(call_type, entrypoint, args);
			executor->receipt.successful = !!execution;
			if (attach_debugger_context)
			{
				interrupter(false);
				vm->set_debugger(nullptr);
			}

			if (!execution)
				return execution.error();

			tracer.solver.state.changelog.commit();
			env.payable = script::payable_repr();
			env.balances.clear();
			return expectation::met;
		}
		void session::dispatch_event(int event_type_id, const void* object_value, int object_type_id)
		{
			script::program::dispatch_event(event_type_id, object_value, object_type_id);
			if (!executor->receipt.events.empty())
			{
				auto data = format::tree();
				if (script::marshall::store(data, object_value, object_type_id))
				{
					sanitize_binary_strings(data);
					auto type = script::factory::get()->get_vm()->get_type_info_by_id(event_type_id);
					data.key = type.is_valid() ? type.get_name() : std::string_view("__pod__");
					tracer.events[executor->receipt.events.size() - 1] = std::move(data);
				}
			}
		}
		void session::dispatch_exception(script::immediate_context* coroutine)
		{
			script::program::dispatch_exception(coroutine);
			auto* vm = coroutine->get_vm();
			if (vm->has_debugger())
				vm->get_debugger()->exception_callback(coroutine->get_context());
		}
		void session::dispatch_coroutine(script::immediate_context* coroutine)
		{
			script::program::dispatch_coroutine(coroutine);
			auto* vm = coroutine->get_vm();
			if (vm->has_debugger())
				vm->get_debugger()->line_callback(coroutine->get_context());
		}
		void session::reset()
		{
			env.balances.clear();
			env.from = algorithm::pubkeyhash_t();
			env.to = algorithm::pubkeyhash_t();
			env.payable = script::payable_repr();
			env.block_number = storages::chainstate().get_latest_block_number().or_else(1) + 1;
			env.call_flags = 0;
			env.call_asset = algorithm::asset::native();
			env.temporary_reverted = false;
			temporary_transaction.reset();
			module = nullptr;
			program.path.clear();
			program.log.clear();
			program.trap = 0;
			program.instructions = false;
			tracer.solver = ledger::solver_context();
			tracer.transaction.destroy();
			tracer.returning = format::tree();
			tracer.log = format::tree();
			tracer.events.clear();
			tracer.pmodule.destroy();
			tracer.block = ledger::block_body();
		}
		bool session::bound() const
		{
			return !program.path.empty();
		}
		uint64_t session::virtual_block_number() const
		{
			return env.block_number;
		}
		uint256_t session::state_root_hash() const
		{
			vector<uint256_t> state_tree;
			state_tree.reserve(tracer.solver.state.changelog.outgoing.finalized.size());
			for (auto& [index, change] : tracer.solver.state.changelog.outgoing.finalized)
			{
				auto copy = uptr(states::resolver::from_copy(*change.state));
				copy->block_number = std::numeric_limits<uint64_t>::max();
				state_tree.push_back(copy->as_hash());
			}
			return algorithm::merkle_tree::from(std::move(state_tree)).root();
		}
		format::tree session::serialize_event_args(const format::variables& value) const
		{
			auto readable = [](const format::variable& item, const std::string_view& data) -> format::variable
			{
				if (!item.is_string() || format::variables_util::is_ascii_encoding(data))
					return item;
				if (data.size() == sizeof(algorithm::pubkeyhash_t))
					return format::variable(algorithm::signing::encode_address((uint8_t*)data.data()));

				return format::variable(format::util::encode_0xhex(data));
			};
			if (value.size() != 1)
			{
				format::variables copy = value;
				for (auto& item : copy)
					item = readable(item, item.as_string());

				format::tree result = format::variables_util::serialize(copy);
				sanitize_binary_strings(result);
				return result;
			}
			else
			{
				format::tree result(readable(value.front(), value.front().as_string()));
				sanitize_binary_strings(result);
				return result;
			}
		}
		void session::interrupter(bool bind)
		{
			if (!bind)
			{
				os::process::bind_signal(signal_code::SIG_INT, nullptr);
				return;
			}

			os::process::bind_signal(signal_code::SIG_INT, [](int)
			{
				auto* vm = script::factory::get()->get_vm();
				if (vm->get_debugger() && vm->get_debugger()->interrupt())
					interrupter(true);
				else
					exit(1);
			});
		}
		const uint256_t session::temporary_hash = algorithm::hashing::hash256i("tangent.cli.temporary.transaction");

		interpreter::interpreter(bool machine_mode) : machine(machine_mode)
		{
			directory = *os::directory::get_working();
			build_catalog();
		}
		bool interpreter::respond(const command_def& def, uint64_t ms, outcome& result, bool force_machine)
		{
			if (machine || force_machine)
			{
				auto envelope = format::tree::map();
				envelope.set("ok", format::variable(result.ok));
				envelope.set("cmd", format::variable(def.name));
				envelope.set("ms", format::variable(ms));
				if (result.ok)
				{
					if (!result.result.is_none())
						envelope.set("result", result.result);
				}
				else
					envelope.set("error", util::error_detail(result.code, result.message));

				terminal->write_line(envelope.as_json());
				return result.ok;
			}

			if (!result.ok)
			{
				util::echo_error(terminal, result.code, result.message);
				return false;
			}

			if (def.mode == render::scalar)
			{
				if (!result.result.is_none())
				{
					terminal->colorize(std_color::light_gray, result.result.value.as_blob());
					terminal->write_char('\n');
				}
			}
			else if (def.mode == render::document)
			{
				util::print_json(terminal, result.result);
				terminal->write_char('\n');
			}

			return true;
		}
		bool interpreter::dispatch(vector<string>& args, const std::string_view& directory, bool force_machine)
		{
			if (args.empty())
				return true;

			const command_def* def = nullptr;
			for (auto& entry : catalog)
			{
				if (entry.name == args[0])
				{
					def = &entry;
					break;
				}
			}

			auto time = date_time().milliseconds();
			if (def == nullptr)
			{
				outcome result = util::fail("usage", "unknown command: " + args[0] + " (type help for the command list)");
				return respond(command_def { args[0], "internal", "", "", render::scalar, {} }, (uint64_t)(date_time().milliseconds() - time), result, force_machine);
			}

			auto result = def->run(*this, args, directory);
			return respond(*def, (uint64_t)(date_time().milliseconds() - time), result, force_machine);
		}
		bool interpreter::execute(const std::string_view& line)
		{
			auto args = util::tokenize(line);
			return dispatch(args, directory);
		}
		int interpreter::launch(const inline_args& environment, size_t args_start_offset, size_t args_end_offset)
		{
			error_handling::set_flag(log_option::dated, false);
			terminal->set_colorization(!machine);
#ifdef VI_MICROSOFT
			SetConsoleOutputCP(CP_UTF8);
			SetConsoleCP(CP_UTF8);
#endif

			if (environment.params.size() <= args_start_offset + args_end_offset)
			{
			interpreter:
				os::process::bind_signal(signal_code::SIG_INT, [](int) { });
				if (!machine)
				{
					terminal->write_char('\n');
					terminal->colorize(std_color::white, "  tangent virtual machine");
					terminal->write_char('\n');
					terminal->colorize(std_color::gray, "  smart-contract sandbox \xC2\xB7 type \"help\" for the command catalog");
					terminal->write_char('\n');
					terminal->write_char('\n');
				}

				string command;
				while (true)
				{
					if (!machine)
						terminal->colorize(std_color::cyan, "\xE2\x9D\xAF ");

					if (!terminal->read_line(command, 65536))
						break;
					if (!command.empty())
						execute(command);
					if (quitting)
						break;
				}
			}
			else
			{
				string command;
				for (size_t i = args_start_offset; i < environment.params.size() - args_end_offset; i++)
					command.append(environment.params[i]).append(1, ' ');

				bool result = execute(command);
				if (context.program.trap > 1 || (!result && context.program.trap == 1))
					goto interpreter;

				if (!result)
					return 1;
			}
			return 0;
		}
		void interpreter::build_catalog()
		{
			catalog = {
				{ "help", "session", "help [command]", "show command catalog or detailed usage for one command", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							for (auto& entry : self.catalog)
							{
								if (entry.name == args[1])
								{
									if (self.machine)
									{
										auto detail = format::tree::map();
										detail.set("name", format::variable(entry.name));
										detail.set("group", format::variable(entry.group));
										detail.set("usage", format::variable(entry.usage));
										detail.set("summary", format::variable(entry.summary));
										return util::pass(std::move(detail));
									}
									self.terminal->colorize(std_color::cyan, string(entry.usage));
									self.terminal->write(string(entry.usage.size() < 52 ? 52 - entry.usage.size() : 1, ' '));
									self.terminal->colorize(std_color::light_gray, string(entry.summary));
									self.terminal->write_char('\n');
									return util::pass();
								}
							}
							return util::fail("usage", "command not found: " + args[1]);
						}

						if (self.machine)
						{
							auto list = format::tree::list();
							for (auto& entry : self.catalog)
							{
								auto* item = list.push(format::tree::map());
								item->set("name", format::variable(entry.name));
								item->set("group", format::variable(entry.group));
								item->set("usage", format::variable(entry.usage));
								item->set("summary", format::variable(entry.summary));
							}
							return util::pass(std::move(list));
						}

						self.terminal->colorize(std_color::white, "tangent vm console \xC2\xB7 command catalog");
						self.terminal->write_char('\n');
						self.terminal->write_char('\n');
						std::string_view group = "";
						for (auto& entry : self.catalog)
						{
							if (entry.group != group)
							{
								if (!group.empty())
									self.terminal->write_char('\n');
								group = entry.group;
								self.terminal->colorize(std_color::orange, group);
								self.terminal->write_char('\n');
							}
							self.terminal->write("  ");
							self.terminal->colorize(std_color::cyan, string(entry.usage));
							self.terminal->write(string(entry.usage.size() < 52 ? 52 - entry.usage.size() : 1, ' '));
							self.terminal->colorize(std_color::light_gray, string(entry.summary));
							self.terminal->write_char('\n');
						}
						self.terminal->write_char('\n');
						self.terminal->colorize(std_color::gray, "special arguments: {\"$asset\":[chain,token?,contract?]} asset, {\"$blob\":\"0x..\"} raw bytes, json arrays/objects serialize as marshall blobs (interactive and plan modes, nestable)");
						self.terminal->write_char('\n');
						return util::pass();
					}
				},
				{ "machine", "session", "machine [json|human]", "get/set output mode (json prints one compact json envelope per command)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							if (args[1] == "json")
								self.machine = true;
							else if (args[1] == "human")
								self.machine = false;
							else
								return util::fail("usage", "machine mode must be json or human");
						}
						return util::pass(self.machine ? "json" : "human");
					}
				},
				{ "status", "session", "status", "snapshot of the current session environment", render::document,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						auto data = format::tree::map();
						data.set("mode", format::variable(self.machine ? "json" : "human"));
						data.set("bound", format::variable(self.context.bound()));
						data.set("program", format::variable(self.context.program.path));
						data.set("from", format::variable(util::address_of(self.context.env.from)));
						data.set("to", format::variable(util::address_of(self.context.env.to)));
						data.set("block", format::variable(to_string(self.context.env.block_number)));
						data.set("flags", format::variable(to_string((uint32_t)self.context.env.call_flags)));
						data.set("temporary", format::variable((bool)self.context.temporary_transaction));
						data.set("temporary_hash", format::variable(algorithm::encoding::encode_0xhex256(session::temporary_hash)));
						data.set("temporary_reverted", format::variable(self.context.env.temporary_reverted));
						data.set("pay", util::payments_of(self.context.env.payable));

						auto fund = format::tree::list();
						for (auto& [account, balances] : self.context.env.balances)
						{
							for (auto& [asset, value] : balances)
							{
								auto* item = fund.push(format::tree::map());
								item->set("account", format::variable(util::address_of(account)));
								item->set("asset", format::variable(algorithm::asset::name_of(asset)));
								item->set("value", format::variable(value.to_string()));
							}
						}
						data.set("fund", std::move(fund));
						return util::pass(std::move(data));
					}
				},
				{ "reset", "session", "reset", "wipe session state, program binding and balances", render::scalar,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						self.context.reset();
						return util::pass("state wiped");
					}
				},
				{ "trap", "session", "trap [off|err|all|now]", "drop to interpreter after plan completion (all) or failure (err); now drops immediately", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
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
							else if (args[1] == "now")
							{
								self.context.program.trap = 2;
								return util::fail("usage", "trap now");
							}

							if (trap == 255)
								return util::fail("usage", "trap type not found (off|err|all|now)");

							self.context.program.trap = trap;
						}

						if (self.context.program.trap == 0)
							return util::pass("execp trap disabled");
						return util::pass(self.context.program.trap == 1 ? "execp trap on error" : "execp trap on finish");
					}
				},
				{ "clear", "session", "clear", "clear console output", render::custom,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						if (!self.machine)
							self.terminal->clear();
						return util::pass();
					}
				},
				{ "exit", "session", "exit", "leave the interpreter", render::scalar,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						self.quitting = true;
						return util::pass("bye");
					}
				},
				{ "from", "environment", "from [address|?]", "get/set caller address (? generates a random one)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							if (args[1] != "?")
							{
								if (!algorithm::signing::decode_address(args[1], self.context.env.from))
									return util::fail("argument", "not a valid address");
							}
							else
								crypto::fill_random_bytes(self.context.env.from.blob, sizeof(algorithm::pubkeyhash_t));
						}
						return util::pass(util::address_of(self.context.env.from));
					}
				},
				{ "to", "environment", "to [address|?]", "get/set contract address (? generates a random one)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							if (args[1] != "?")
							{
								if (!algorithm::signing::decode_address(args[1], self.context.env.to))
									return util::fail("argument", "not a valid address");
							}
							else
								crypto::fill_random_bytes(self.context.env.to.blob, sizeof(algorithm::pubkeyhash_t));
						}
						return util::pass(util::address_of(self.context.env.to));
					}
				},
				{ "block", "environment", "block [number]", "get/set virtual block number (+/- prefix: relative to tip)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							int8_t relative = 0;
							if (!args[1].empty() && args[1].front() == '+')
								relative = 1;
							else if (!args[1].empty() && args[1].front() == '-')
								relative = -1;

							auto block_number = from_string<uint64_t>(relative ? std::string_view(args[1]).substr(1) : std::string_view(args[1]));
							if (!block_number)
								return util::fail("argument", block_number.what());

							if (relative != 0)
							{
								uint64_t tip_block_number = storages::chainstate().get_latest_block_number().or_else(1);
								if (relative > 0)
									self.context.env.block_number = std::max<uint64_t>(tip_block_number + *block_number, 1);
								else if (relative < 0)
									self.context.env.block_number = std::max<uint64_t>(tip_block_number >= *block_number ? tip_block_number - *block_number : 1, 1);
							}
							else 
								self.context.env.block_number = std::max<uint64_t>(*block_number, 1);
						}
						return util::pass(to_string(self.context.env.block_number));
					}
				},
				{ "pay", "environment", "pay [value] [blockchain] [token?] [contract?]", "get/add caller payment for the next call (non-positive value removes)", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 2)
						{
							decimal value = decimal(args[1]);
							if (value.is_nan())
								return util::fail("argument", "not a valid decimal value");

							auto asset = util::asset_of(args, 2);
							if (!asset)
								return util::fail("argument", asset.error().message());

							if (!self.context.env.payable.plus(*asset, value.is_positive() ? value : -self.context.env.payable.of(*asset)))
								return util::fail("argument", "failed to pay");
						}

						std::erase_if(self.context.env.payable.payments, [](const std::pair<algorithm::asset_id, decimal>& item) { return !item.second.is_positive(); });
						if (!self.machine)
						{
							for (auto& [asset, value] : self.context.env.payable.payments)
								util::echo_amount(self.terminal, value.to_string(), algorithm::asset::name_of(asset));
						}
						return util::pass(util::payments_of(self.context.env.payable));
					}
				},
				{ "fund", "environment", "fund [value] [blockchain] [token?] [contract?]", "get/set caller balance injected before the next call (non-positive value removes)", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 2)
						{
							decimal value = decimal(args[1]);
							if (value.is_nan())
								return util::fail("argument", "not a valid decimal value");

							auto asset = util::asset_of(args, 2);
							if (!asset)
								return util::fail("argument", asset.error().message());

							if (value.is_positive())
								self.context.env.balances[self.context.env.from][*asset] = std::move(value);
							else
								self.context.env.balances[self.context.env.from].erase(*asset);
						}

						auto list = format::tree::list();
						for (auto& [account, balances] : self.context.env.balances)
						{
							for (auto& [asset, value] : balances)
							{
								auto* item = list.push(format::tree::map());
								item->set("account", format::variable(util::address_of(account)));
								item->set("asset", format::variable(algorithm::asset::name_of(asset)));
								item->set("value", format::variable(value.to_string()));
							}
						}
						if (!self.machine)
						{
							for (auto& [account, balances] : self.context.env.balances)
							{
								for (auto& [asset, value] : balances)
									util::echo_balance(self.terminal, util::address_of(account), value.to_string(), algorithm::asset::name_of(asset));
							}
						}
						return util::pass(std::move(list));
					}
				},
				{ "pay_funded", "environment", "pay_funded [value] [blockchain] [token?] [contract?]", "combination of fund then pay", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view& directory) -> outcome
					{
						if (args.size() > 2)
						{
							decimal value = decimal(args[1]);
							if (value.is_nan() || value.is_negative())
								return util::fail("argument", "not a valid decimal value");

							auto asset = util::asset_of(args, 2);
							if (!asset)
								return util::fail("argument", asset.error().message());

							if (!self.context.env.payable.plus(*asset, value.is_positive() ? value : -self.context.env.payable.of(*asset)))
								return util::fail("argument", "failed to pay");

							if (value.is_positive())
								self.context.env.balances[self.context.env.from][*asset] = value;
							else
								self.context.env.balances[self.context.env.from].erase(*asset);
						}

						auto data = format::tree::map();
						auto fund = format::tree::list();
						for (auto& [account, balances] : self.context.env.balances)
						{
							for (auto& [asset, balance_value] : balances)
							{
								auto* item = fund.push(format::tree::map());
								item->set("account", format::variable(util::address_of(account)));
								item->set("asset", format::variable(algorithm::asset::name_of(asset)));
								item->set("value", format::variable(balance_value.to_string()));
							}
						}
						data.set("fund", std::move(fund));
						data.set("pay", util::payments_of(self.context.env.payable));

						std::erase_if(self.context.env.payable.payments, [](const std::pair<algorithm::asset_id, decimal>& item) { return !item.second.is_positive(); });
						if (!self.machine)
						{
							for (auto& [asset, balance_value] : self.context.env.payable.payments)
								util::echo_amount(self.terminal, balance_value.to_string(), algorithm::asset::name_of(asset));
						}
						return util::pass(std::move(data));
					}
				},
				{ "flags", "environment", "flags [withdraw|withdraw_with_revert|route|pipeline|off]", "get/set feature flags of the synthetic call transaction (withdraw/route stage a temporary broadcast transaction under a pinned hash after the next call)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							uint8_t call_flags = 0;
							bool temporary_reverted = false;
							if (args[1] != "off")
							{
								if (args[1] == "withdraw_with_revert")
								{
									call_flags = (uint8_t)transactions::call::feature::require_withdraw;
									temporary_reverted = true;
								}
								else if (args[1] == "withdraw")
									call_flags = (uint8_t)transactions::call::feature::require_withdraw;
								else if (args[1] == "route")
									call_flags = (uint8_t)transactions::call::feature::require_route;
								else if (args[1] == "pipeline")
									call_flags = (uint8_t)transactions::call::feature::pipeline_pay;
								else
									return util::fail("usage", "unsupported flags value (withdraw|withdraw_with_revert|route|pipeline|off)");
							}
							self.context.env.call_flags = call_flags;
							self.context.env.temporary_reverted = temporary_reverted;
						}
						return util::pass(stringify::text("call flags: %" PRIu8 "%s", self.context.env.call_flags, self.context.env.temporary_reverted ? " (temporary tx will revert)" : ""));
					}
				},
				{ "asset", "environment", "asset [blockchain] [token?] [contract?] | off", "get/set the synthetic call transaction asset (tx::asset())", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() > 1)
						{
							if (args[1] == "off")
								self.context.env.call_asset = algorithm::asset::native();
							else
							{
								auto asset = util::asset_of(args, 1);
								if (!asset)
									return util::fail("argument", asset.error().message());

								self.context.env.call_asset = *asset;
							}
						}
						return util::pass(algorithm::asset::name_of(self.context.env.call_asset));
					}
				},
				{ "compile", "program", "compile [path]", "compile a script and bind it to the contract address", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view& directory) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "not a valid path");

						auto path = os::path::resolve(args[1], directory, true);
						if (!path)
							return util::fail("io", path.what());

						auto result = self.context.compile(*path);
						if (!result)
							return util::fail("compile", result.what());

						return util::pass("compiled " + *path);
					}
				},
				{ "assemble", "program", "assemble [deploy|call|abi|code] [path] [args?]", "assemble current program to file (deploy/call produce transaction payload)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view& directory) -> outcome
					{
						if (args.size() < 3)
							return util::fail("usage", "not a valid type");

						if (!self.context.bound())
							return util::fail("usage", "no program bound");

						auto type = args[1];
						if (type != "deploy" && type != "call" && type != "abi" && type != "code")
							return util::fail("usage", "not a valid type");

						auto path = os::path::resolve(args[2], directory, true);
						if (!path)
							return util::fail("io", path.what());

						script_asm asm_type;
						if (type == "deploy")
							asm_type = script_asm::tx_deploy;
						else if (type == "call")
							asm_type = script_asm::tx_call;
						else if (type == "abi")
							asm_type = script_asm::abi;
						else
							asm_type = script_asm::code;

						auto function_args = util::expand_arguments(args, 3);
						if (!function_args)
							return util::fail("argument", function_args.error().message());

						auto result = self.context.assemble(asm_type, *path, std::move(*function_args));
						if (!result)
							return util::fail("compile", result.what());

						return util::pass("assembled " + *path);
					}
				},
				{ "abi", "program", "abi", "list callable function declarations of the bound program", render::custom,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						auto list = format::tree::list();
						if (self.context.module.is_valid())
						{
							for (size_t i = 0; i < self.context.module.get_function_count(); i++)
							{
								int type_id;
								auto function = self.context.module.get_function_by_index(i);
								if (function.get_arg(0, &type_id))
								{
									auto type = self.context.module.get_vm()->get_type_info_by_id(type_id);
									auto name = type.is_valid() ? type.get_name() : std::string_view();
									if (name == "pmut" || name == "pconst")
									{
										auto decl = function.get_decl();
										if (!decl.empty())
										{
											list.push(format::variable(string(decl) + ";"));
										}
									}
								}
							}
						}

						if (!self.machine)
						{
							for (auto& item : list.childs())
							{
								self.terminal->colorize(std_color::cyan, item.value.as_blob());
								self.terminal->write_char('\n');
							}
						}
						return util::pass(std::move(list));
					}
				},
				{ "predefined", "program", "predefined [path]", "export AngelScript language server symbols (as.predefined)", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view& directory) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "not a valid path");

						auto path = os::path::resolve(args[1], directory, true);
						if (!path)
							return util::fail("io", path.what());

						auto symbols = script::factory::get()->export_predefined_symbols();
						auto result = os::file::write(*path, (uint8_t*)symbols.data(), symbols.size());
						if (!result)
							return util::fail("io", result.what());

						return util::pass("exported " + *path);
					}
				},
				{ "call", "execution", "call [declaration] [args?]", "call a function of the bound program (json object/array arguments supported)", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "no function declaration");

						auto function_args = util::expand_arguments(args, 2);
						if (!function_args)
							return util::fail("argument", function_args.error().message());

						auto time = date_time().milliseconds();
						auto result = self.context.call(args[1], std::move(*function_args), false);
						uint64_t ms = (uint64_t)(date_time().milliseconds() - time);
						if (!result)
						{
							auto message = result.what();
							return util::fail("runtime", message.empty() ? util::revert_message(self) : message);
						}

						bool success = self.context.executor->receipt.successful;
						auto root = algorithm::encoding::encode_0xhex256(self.context.state_root_hash());
						if (!self.machine)
						{
							self.terminal->write(" ");
							self.terminal->colorize(success ? std_color::green : std_color::red, success ? "\xE2\x9C\x93 finalized" : "\xE2\x9C\x97 reverted");
							self.terminal->colorize(std_color::gray, stringify::text(" in %" PRIu64 " ms", ms));
							self.terminal->write_char('\n');
							self.terminal->write("   ");
							self.terminal->colorize(std_color::gray, "root");
							self.terminal->write_char(' ');
							self.terminal->colorize(std_color::magenta, root);
							self.terminal->write_char('\n');
							if (!self.context.tracer.returning.is_none())
							{
								self.terminal->write("   ");
								self.terminal->colorize(std_color::gray, "return");
								self.terminal->write_char(' ');
								util::print_json(self.terminal, self.context.tracer.returning);
								self.terminal->write_char('\n');
							}
						}

						auto data = format::tree::map();
						data.set("success", format::variable(success));
						data.set("root", format::variable(root));
						data.set("value", self.context.tracer.returning);
						data.set("ms", format::variable(ms));
						return success ? util::pass(std::move(data)) : util::fail("runtime", util::revert_message(self));
					}
				},
				{ "debug", "execution", "debug [declaration] [args?]", "call a function with the script debugger attached", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "no function declaration");

						auto function_args = util::expand_arguments(args, 2);
						if (!function_args)
							return util::fail("argument", function_args.error().message());

						auto time = date_time().milliseconds();
						auto result = self.context.call(args[1], std::move(*function_args), true);
						uint64_t ms = (uint64_t)(date_time().milliseconds() - time);
						if (!result)
						{
							auto message = result.what();
							return util::fail("runtime", message.empty() ? util::revert_message(self) : message);
						}

						bool success = self.context.executor->receipt.successful;
						if (!self.machine)
						{
							self.terminal->write(" ");
							self.terminal->colorize(success ? std_color::green : std_color::red, success ? "\xE2\x9C\x93 finalized" : "\xE2\x9C\x97 reverted");
							self.terminal->colorize(std_color::gray, stringify::text(" in %" PRIu64 " ms", ms));
							self.terminal->write_char('\n');
							if (!self.context.tracer.returning.is_none())
							{
								self.terminal->write("   ");
								self.terminal->colorize(std_color::gray, "return");
								self.terminal->write_char(' ');
								util::print_json(self.terminal, self.context.tracer.returning);
								self.terminal->write_char('\n');
							}
						}

						auto data = format::tree::map();
						data.set("success", format::variable(success));
						data.set("value", self.context.tracer.returning);
						data.set("ms", format::variable(ms));
						return success ? util::pass(std::move(data)) : util::fail("runtime", util::revert_message(self));
					}
				},
				{ "run", "execution", "run [path]", "execute a json plan file; steps are token arrays or objects {\"cmd\":[tokens],\"note\":?,\"expect\":{\"ok\"|\"error\"|\"root\"|\"contains\"}?,\"run\":path}", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view& directory) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "not a valid path");

						auto path = os::path::resolve(args[1], directory, true);
						if (!path)
							return util::fail("io", path.what());

						auto file = os::file::read_as_string(*path);
						if (!file)
							return util::fail("io", file.what());

						auto plan = schema::from_json(*file);
						if (!plan)
							return util::fail("argument", "invalid plan json: " + plan.error().message());

						if (!plan->value.is(var_type::array))
							return util::fail("argument", "plan is not a json array");

						auto path_directory = os::path::get_directory(*path);
						size_t steps = 0, failures = 0;
						auto summary = format::tree::map();

						std::function<bool(schema&, const std::string_view&, size_t)> walk = [&](schema& parent, const std::string_view& base, size_t depth) -> bool
						{
							if (depth > 16)
							{
								util::echo("plan nesting too deep");
								return false;
							}

							for (auto& subcommand : parent.get_childs())
							{
								if (subcommand->value.is(var_type::object))
								{
									if (subcommand->has("run"))
									{
										steps++;
										auto nested_path = os::path::resolve(subcommand->fetch_var("run").get_blob(), base, true);
										if (!nested_path)
										{
											util::echo("plan: invalid nested path: " + nested_path.what());
											return false;
										}

										auto nested_file = os::file::read_as_string(*nested_path);
										if (!nested_file)
										{
											util::echo("plan: cannot read nested plan: " + nested_file.what());
											return false;
										}

										auto nested = schema::from_json(*nested_file);
										if (!nested || !nested->value.is(var_type::array))
										{
											util::echo("plan: invalid nested plan data");
											return false;
										}

										if (!walk(**nested, os::path::get_directory(*nested_path), depth + 1))
											return false;
										continue;
									}

									if (!subcommand->has("cmd"))
									{
										util::echo("plan step is an object without cmd/run");
										return false;
									}

									vector<string> subargs;
									auto* cmd = subcommand->get("cmd");
									for (auto& subargument : cmd->get_childs())
									{
										auto converted = util::convert_plan_argument(subargument);
										if (!converted)
										{
											util::echo("plan: " + converted.error().message());
											return false;
										}
										subargs.push_back(*converted);
									}

									string note(subcommand->has("note") ? subcommand->fetch_var("note").get_blob() : std::string_view());
									auto expected = subcommand->get("expect");
									if (!util::run_plan_step(self, subargs, base, note, expected, steps, failures))
										return false;
									continue;
								}

								vector<string> subargs;
								for (auto& subargument : subcommand->get_childs())
								{
									auto converted = util::convert_plan_argument(subargument);
									if (!converted)
									{
										util::echo("plan: " + converted.error().message());
										return false;
									}
									subargs.push_back(*converted);
								}

								if (subargs.size() == 2 && subargs[0] == "execp")
								{
									steps++;
									auto nested_path = os::path::resolve(subargs[1], base, true);
									if (!nested_path)
									{
										util::echo("internal execp path error: " + nested_path.what());
										return false;
									}

									auto nested_file = os::file::read_as_string(*nested_path);
									if (!nested_file)
									{
										util::echo("internal execp file error: " + nested_file.what());
										return false;
									}

									auto nested = schema::from_json(*nested_file);
									if (!nested)
									{
										util::echo("internal execp data error: " + nested.what());
										return false;
									}

									if (!nested->value.is(var_type::array))
									{
										util::echo("internal execp data error: not a valid array");
										return false;
									}

									if (!walk(**nested, os::path::get_directory(*nested_path), depth + 1))
										return false;
									continue;
								}

								if (!util::run_plan_step(self, subargs, base, string(), nullptr, steps, failures))
									return false;
							}
							return true;
						};

						bool ok = walk(**plan, path_directory, 0);
						summary.set("steps", format::variable(to_string(steps)));
						summary.set("failures", format::variable(to_string(failures)));
						summary.set("path", format::variable(*path));
						if (!self.machine && ok)
						{
							self.terminal->write_char('\n');
							util::echo_color(std_color::green, " \xE2\x9C\x93 plan complete \xC2\xB7 " + to_string(steps) + " steps");
						}
						return ok ? util::pass(std::move(summary)) : util::fail("state", "plan failed at step " + to_string(steps));
					}
				},
				{ "result", "inspection", "result", "return value of the last call", render::document,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						return util::pass(format::tree(self.context.tracer.returning));
					}
				},
				{ "log", "inspection", "log", "event log of the last call", render::document,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						return util::pass(format::tree(self.context.tracer.log));
					}
				},
				{ "receipt", "inspection", "receipt", "receipt of the last call", render::document,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						auto data = self.context.executor->receipt.as_tree();
						sanitize_binary_strings(data);
						return util::pass(std::move(data));
					}
				},
				{ "changelog", "inspection", "changelog", "state changes committed by the last call", render::document,
					[](interpreter& self, vector<string>&, const std::string_view&) -> outcome
					{
						auto changelog = format::tree::map();
						changelog.childs().reserve(2);
						auto* erase = changelog.set("erase", format::tree::map());
						auto* upsert = changelog.set("upsert", format::tree::map());
						for (auto& [index, change] : self.context.tracer.solver.state.changelog.outgoing.finalized)
						{
							auto copy = uptr(states::resolver::from_copy(*change.state));
							copy->block_number = std::numeric_limits<uint64_t>::max();
							copy->checksum = 0;
							if (change.erase)
								erase->set(format::util::encode_0xhex(index), copy->as_tree());
							else
								upsert->set(format::util::encode_0xhex(index), copy->as_tree());
						}
						sanitize_binary_strings(changelog);
						return util::pass(std::move(changelog));
					}
				},
				{ "state_check", "inspection", "state_check [hash] [continue?]", "verify state hash derived from the committed changelog", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "not a valid state hash");

						auto state_hash = algorithm::encoding::decode_0xhex256(args[1]);
						vector<uint256_t> state_tree;
						state_tree.reserve(self.context.tracer.solver.state.changelog.outgoing.finalized.size() + 1);
						for (auto& [index, change] : self.context.tracer.solver.state.changelog.outgoing.finalized)
						{
							if (change.state->as_type() == states::witness_program::as_instance_type() || change.state->as_type() == states::account_program::as_instance_type())
								continue;

							auto copy = uptr(states::resolver::from_copy(*change.state));
							copy->block_number = std::numeric_limits<uint64_t>::max();
							copy->checksum = 0;
							state_tree.push_back(copy->as_hash(true));
						}

						auto state_root = algorithm::merkle_tree::from(std::move(state_tree)).root();
						if (state_root != state_hash)
						{
							bool continues = args.size() >= 3 && var::any(args[2]).get_boolean();
							auto message = "state hash mismatch (actual): " + algorithm::encoding::encode_0xhex256(state_root);
							if (!continues)
								return util::fail("state", message);

							util::echo(message);
						}
						return util::pass();
					}
				},
				{ "balance", "inspection", "balance [address] [blockchain] [token?] [contract?]", "query committed account balance from the session state", render::scalar,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						algorithm::pubkeyhash_t account = self.context.env.from;
						size_t offset = 1;
						if (args.size() > 1 && (args[1].size() >= 5 && args[1][0] == 't' && args[1][1] == 'c'))
						{
							if (!algorithm::signing::decode_address(args[1], account))
								return util::fail("argument", "not a valid address");
							offset = 2;
						}

						auto asset = algorithm::asset::native();
						if (args.size() > offset)
						{
							auto resolved = util::asset_of(args, offset);
							if (!resolved)
								return util::fail("argument", resolved.error().message());
							asset = *resolved;
						}

						if (account.empty())
							return util::fail("usage", "caller address not valid");

						auto balance = self.context.executor->get_account_balance(asset, account);
						if (!self.machine)
						{
							util::echo_balance(self.terminal, util::address_of(account), balance ? balance->get_balance().to_string() : "null", algorithm::asset::name_of(asset));
						}

						auto data = format::tree::map();
						data.set("account", format::variable(util::address_of(account)));
						data.set("asset", format::variable(algorithm::asset::name_of(asset)));
						data.set("balance", format::variable(balance ? balance->get_balance().to_string() : "null"));
						return util::pass(std::move(data));
					}
				},
				{ "state_get", "inspection", "state_get [index]", "look up a committed state entry by its changelog index", render::document,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "not a valid state index");

						auto needle = format::util::assign_0xhex(args[1]);
						for (auto& [entry_index, change] : self.context.tracer.solver.state.changelog.outgoing.finalized)
						{
							if (format::util::encode_0xhex(entry_index) == needle)
							{
								auto copy = uptr(states::resolver::from_copy(*change.state));
								copy->block_number = std::numeric_limits<uint64_t>::max();
								copy->checksum = 0;
								return util::pass(copy->as_tree());
							}
						}
						return util::pass();
					}
				},
				{ "pack", "codec", "pack [args?]", "pack plain arguments into one flat stream encoding", render::scalar,
					[](interpreter&, vector<string>& args, const std::string_view&) -> outcome
					{
						format::variables function_args;
						function_args.reserve(args.size() - 1);
						for (size_t i = 1; i < args.size(); i++)
							function_args.push_back(format::variable::from(args[i]));

						format::wo_stream message;
						return util::pass(format::variables_util::serialize_flat_into(function_args, &message) ? message.encode() : "null");
					}
				},
				{ "unpack", "codec", "unpack [stream]", "decode a flat stream encoding into json", render::custom,
					[](interpreter& self, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "no stream provided");

						auto input = format::util::decode_stream(args[1]);
						format::variables function_args;
						format::ro_stream message = format::ro_stream(input);
						if (!format::variables_util::deserialize_flat_from(message, &function_args))
							return util::pass();

						auto data = format::variables_util::serialize(function_args);
						if (!self.machine)
						{
							util::print_json(self.terminal, data);
							self.terminal->write_char('\n');
						}
						return util::pass(std::move(data));
					}
				},
				{ "pack256", "codec", "pack256 [integer]", "encode a decimal uint256 as a hex string", render::scalar,
					[](interpreter&, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "integer required (r10)");

						uint8_t data[32];
						auto value = uint256_t(args[1], 10);
						value.encode(data);

						size_t size = value.bytes();
						return util::pass(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
					}
				},
				{ "unpack256", "codec", "unpack256 [hex]", "decode a hex uint256 into a decimal number", render::scalar,
					[](interpreter&, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "integer required (r16)");
						return util::pass(uint256_t(args[1], 16).to_string());
					}
				},
				{ "pack3_256", "codec", "pack3_256 [blockchain] [token?] [contract?]", "encode an asset id as a hex string", render::scalar,
					[](interpreter&, vector<string>& args, const std::string_view&) -> outcome
					{
						if (args.size() < 2)
							return util::fail("usage", "blockchain required");

						auto asset = util::asset_of(args, 1);
						if (!asset)
							return util::fail("argument", asset.error().message());
						uint8_t data[32];
						asset->encode(data);

						size_t size = asset->bytes();
						return util::pass(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
					}
				}
			};
		}

		outcome util::pass(format::tree&& value)
		{
			outcome out;
			out.result = std::move(value);
			return out;
		}
		outcome util::pass(const std::string_view& text)
		{
			outcome out;
			out.result = format::tree(format::variable(text));
			return out;
		}
		outcome util::fail(const std::string_view& code, const std::string_view& message)
		{
			outcome out;
			out.ok = false;
			out.code = code;
			out.message = message;
			return out;
		}
		bool util::printable(const std::string_view& value)
		{
			static const std::string_view allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,:;/\\_-+=?!@#$%^&*()[]{}'\"<>~`|";
			return value.find_first_not_of(allowed) == std::string_view::npos;
		}
		string util::printable_arg(const std::string_view& value)
		{
			return printable(value) ? string(value) : ("0x" + format::util::encode_0xhex(value));
		}
		void util::echo(const std::string_view& line)
		{
			console::get()->write_line(line);
		}
		void util::echo_color(std_color color, const std::string_view& line)
		{
			console::get()->colorize(color, line);
			console::get()->write_char('\n');
		}
		static void write_json_node(format::tree& item, console* term, size_t depth)
		{
			if (item.is_map())
			{
				if (item.childs().empty())
				{
					term->write("{}");
					return;
				}
				term->write("{\n");
				for (size_t i = 0; i < item.childs().size(); i++)
				{
					term->write(string((depth + 1) * 2, ' '));
					term->colorize(std_color::cyan, string("\"") + string(item.childs()[i].key) + "\"");
					term->write(": ");
					write_json_node(item.childs()[i], term, depth + 1);
					term->write(i + 1 < item.childs().size() ? ",\n" : "\n");
				}
				term->write(string(depth * 2, ' '));
				term->write("}");
			}
			else if (item.is_list())
			{
				if (item.childs().empty())
				{
					term->write("[]");
					return;
				}
				term->write("[\n");
				for (size_t i = 0; i < item.childs().size(); i++)
				{
					term->write(string((depth + 1) * 2, ' '));
					write_json_node(item.childs()[i], term, depth + 1);
					term->write(i + 1 < item.childs().size() ? ",\n" : "\n");
				}
				term->write(string(depth * 2, ' '));
				term->write("]");
			}
			else if (item.is_none())
				term->colorize(std_color::gray, "null");
			else if (item.value.is_boolean())
				term->colorize(std_color::magenta, item.value.as_boolean() ? "true" : "false");
			else if (item.value.is_integer() || item.value.is_decimal())
				term->colorize(std_color::yellow, item.value.as_blob());
			else
			{
				string text = item.value.as_blob();
				stringify::replace(text, "\n", "\\n");
				stringify::replace(text, "\t", "\\t");
				term->colorize(std_color::green, string("\"") + text + "\"");
			}
		}
		void util::print_json(console* term, format::tree& item)
		{
			write_json_node(item, term, 0);
		}
		void util::echo_error(console* term, const std::string_view& code, const std::string_view& raw)
		{
			auto lines = stringify::split(raw, '\n');
			size_t first = 0;
			while (first < lines.size() && lines[first].empty())
				first++;

			string message = first < lines.size() ? lines[first] : string();
			string category(code);
			if (!message.empty() && message.front() == '(')
			{
				auto closing = message.find(')');
				if (closing != std::string::npos)
				{
					category = message.substr(1, closing - 1);
					message = message.substr(closing + 1);
					stringify::trim(message);
				}
			}

			term->write(" ");
			term->colorize(std_color::red, "\xE2\x9C\x97");
			term->write("  ");
			if (!category.empty())
			{
				term->colorize(std_color::orange, category);
				term->write(" \xC2\xB7 ");
			}
			term->colorize(std_color::light_gray, message);
			term->write_char('\n');

			for (size_t i = first + 1; i < lines.size(); i++)
			{
				stringify::trim(lines[i]);
				if (lines[i].empty())
					continue;
				term->write("     ");
				term->colorize(std_color::gray, lines[i]);
				term->write_char('\n');
			}
		}
		void util::echo_amount(console* term, const std::string_view& amount, const std::string_view& asset)
		{
			term->colorize(std_color::yellow, amount);
			term->write(" ");
			term->colorize(std_color::orange, asset);
			term->write_char('\n');
		}
		void util::echo_balance(console* term, const std::string_view& account, const std::string_view& amount, const std::string_view& asset)
		{
			term->colorize(std_color::cyan, account);
			term->write("  ");
			term->colorize(std_color::yellow, amount);
			term->write(" ");
			term->colorize(std_color::orange, asset);
			term->write_char('\n');
		}
		vector<string> util::tokenize(const std::string_view& line)
		{
			vector<string> args;
			string current;
			bool active = false, quoted = false;
			int depth = 0;
			for (size_t i = 0; i < line.size(); i++)
			{
				const char& ch = line[i];
				if (quoted)
				{
					if (ch == '\"')
						quoted = false;
					else
						current.append(1, ch);
					continue;
				}

				if (ch == '\"')
				{
					quoted = true;
					active = true;
					continue;
				}

				if (ch == '{' || ch == '[')
					depth++;
				else if (ch == '}' || ch == ']')
					depth = depth > 0 ? depth - 1 : 0;

				if (depth == 0 && (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n'))
				{
					if (active)
					{
						args.push_back(std::move(current));
						current = string();
						active = false;
					}
					continue;
				}

				current.append(1, ch);
				active = true;
			}

			if (active)
				args.push_back(std::move(current));
			return args;
		}
		expects_lr<void> util::encode_argument(format::wo_stream& message, schema& node, bool counted)
		{
			if (node.value.is(var_type::array))
			{
				if (counted)
					message.write_integer((uint32_t)node.size());
				for (auto& child : node.get_childs())
				{
					auto status = encode_argument(message, *child, !counted);
					if (!status)
						return status;
				}
				return expectation::met;
			}

			if (node.value.is(var_type::object))
			{
				if (node.has("$asset"))
				{
					message.write_integer(algorithm::asset::id_of(node.fetch_var("$asset.0").get_blob(), node.fetch_var("$asset.1").get_blob(), node.fetch_var("$asset.2").get_blob()));
					return expectation::met;
				}
				if (node.has("$blob"))
				{
					message.write_string(format::util::decode_0xhex(node.fetch_var("$blob").get_blob()));
					return expectation::met;
				}
				for (auto& child : node.get_childs())
				{
					auto status = encode_argument(message, *child, true);
					if (!status)
						return status;
				}
				return expectation::met;
			}

			auto text = node.value.is(var_type::boolean) ? (node.value.get_boolean() ? "true" : "false") : node.value.get_blob();
			if (text == "true" || text == "false")
			{
				message.write_boolean(text == "true");
				return expectation::met;
			}

			bool numeric = !text.empty(), fractional = false;
			for (size_t c = 0; c < text.size() && numeric; c++)
			{
				const char& ch = text[c];
				if ((ch >= '0' && ch <= '9') || ch == '-')
					continue;
				if (ch == '.' || ch == 'e' || ch == 'E')
				{
					fractional = true;
					continue;
				}
				numeric = false;
			}

			if (numeric && fractional)
				message.write_decimal(decimal(text));
			else if (numeric)
				message.write_integer(uint256_t(text, 10));
			else
				message.write_string(text);
			return expectation::met;
		}
		expects_lr<string> util::expand_argument(const std::string_view& token)
		{
			if (token.empty() || (token.front() != '{' && token.front() != '['))
				return string(token);

			auto json = schema::from_json(token);
			if (!json)
				return layer_exception("invalid json argument: " + json.error().message());

			format::wo_stream message;
			auto status = encode_argument(message, **json, true);
			if (!status)
				return layer_exception(status.error().message());

			return message.encode();
		}
		expects_lr<format::variables> util::expand_arguments(vector<string>& args, size_t offset)
		{
			format::variables expanded;
			expanded.reserve(args.size() - offset);
			for (size_t i = offset; i < args.size(); i++)
			{
				auto argument = expand_argument(args[i]);
				if (!argument)
					return argument.error();
				expanded.push_back(format::variable::from(*argument));
			}
			return expanded;
		}
		format::tree util::error_detail(const std::string_view& code, const std::string_view& raw)
		{
			auto detail = format::tree::map();
			detail.set("code", format::variable(code));

			auto lines = stringify::split(std::string(raw), '\n');
			size_t first = 0;
			while (first < lines.size() && lines[first].empty())
				first++;

			string message = first < lines.size() ? string(lines[first]) : string();
			string category;
			if (message.size() > 2 && message.front() == '(')
			{
				auto closing = message.find(')');
				if (closing != std::string_view::npos)
				{
					category = message.substr(1, closing - 1);
					auto remainder = message.substr(closing + 1);
					message = stringify::trim(remainder);
				}
			}

			detail.set("message", format::variable(message));
			if (!category.empty())
				detail.set("category", format::variable(category));

			auto trace = format::tree::list();
			for (size_t i = first + 1; i < lines.size(); i++)
			{
				auto line = stringify::trim(lines[i]);
				if (line.empty())
					continue;
				if (line.size() > 1 && line[0] == '#' && line[1] >= '0' && line[1] <= '9')
				{
					auto frame = format::tree::map();
					auto at = line.find(" at ");
					auto in = line.find(" in \"");
					frame.set("at", format::variable(at != std::string_view::npos && in > at ? line.substr(at + 4, in - at - 4) : std::string_view()));
					frame.set("function", format::variable(in != std::string_view::npos ? line.substr(in + 5) : std::string_view()));
					trace.push(std::move(frame));
					continue;
				}
				trace.push(format::variable(line));
			}

			if (!trace.childs().empty())
				detail.set("trace", std::move(trace));
			return detail;
		}
		string util::address_of(const algorithm::pubkeyhash_t& value)
		{
			return value.empty() ? string("null") : algorithm::signing::encode_address(value);
		}
		expects_lr<algorithm::asset_id> util::asset_of(vector<string>& args, size_t offset)
		{
			auto asset = algorithm::asset::id_of(args[offset], args.size() > offset + 1 ? args[offset + 1] : std::string_view(), args.size() > offset + 2 ? args[offset + 2] : std::string_view());
			if (!algorithm::asset::is_any(asset))
				return layer_exception("not a valid asset");
			return asset;
		}
		format::tree util::payments_of(const script::payable_repr& payable)
		{
			auto list = format::tree::list();
			for (auto& [asset, value] : payable.payments)
			{
				auto* item = list.push(format::tree::map());
				item->set("asset", format::variable(algorithm::asset::name_of(asset)));
				item->set("value", format::variable(value.to_string()));
			}
			return list;
		}
		string util::revert_message(interpreter& self)
		{
			for (auto& item : self.context.executor->receipt.events)
			{
				if (item.event == 0 && !item.args.empty())
					return string(item.args.front().as_string());
			}
			return "execution reverted";
		}
		expects_lr<string> util::convert_plan_argument(schema* subargument)
		{
			if (subargument->value.is(var_type::object))
			{
				if (subargument->has("$asset"))
				{
					auto blockchain = subargument->fetch_var("$asset.0").get_blob();
					auto token = subargument->fetch_var("$asset.1").get_blob();
					auto contract_address = subargument->fetch_var("$asset.2").get_blob();
					return algorithm::asset::id_of(blockchain, token, contract_address).to_string();
				}
				if (subargument->has("$blob"))
					return format::util::decode_0xhex(subargument->fetch_var("$blob").get_blob());

				format::wo_stream message;
				auto status = encode_argument(message, *subargument, true);
				if (!status)
					return layer_exception(status.error().message());
				return message.encode();
			}

			if (subargument->value.is(var_type::array))
			{
				format::wo_stream message;
				auto status = encode_argument(message, *subargument, true);
				if (!status)
					return layer_exception(status.error().message());
				return message.encode();
			}

			if (subargument->value.is(var_type::boolean))
				return string(subargument->value.get_boolean() ? "true" : "false");
			return string(subargument->value.get_blob());
		}
		bool util::run_plan_step(interpreter& self, vector<string>& subargs, const std::string_view& base, const string& note, schema* expected, size_t& steps, size_t& failures)
		{
			if (subargs.empty())
				return true;

			bool attempt = subargs.size() > 1 && subargs[0] == "try";
			vector<string> inner;
			if (attempt)
				inner.assign(subargs.begin() + 1, subargs.end());

			if (!self.machine)
			{
				string compiled_command = attempt ? "[try] " : "";
				for (auto& argument : (attempt ? inner : subargs))
					compiled_command.append(printable_arg(argument)).append(1, ' ');
				if (compiled_command.size() > 1)
					compiled_command.pop_back();

				self.terminal->write(" ");
				self.terminal->colorize(std_color::cyan, "\xE2\x9D\xAF ");
				self.terminal->colorize(std_color::light_gray, compiled_command);
				if (!note.empty())
					self.terminal->colorize(std_color::gray, "   ; " + note);
				self.terminal->write_char('\n');
			}

			steps++;
			uint64_t time = date_time().milliseconds();
			format::tree step_result;
			bool ok = false;

			const command_def* def = nullptr;
			for (auto& entry : self.catalog)
			{
				if (entry.name == (attempt ? inner : subargs).front())
				{
					def = &entry;
					break;
				}
			}

			string error_message, error_code;
			if (def == nullptr)
			{
				error_code = "usage";
				error_message = "unknown command: " + (attempt ? inner : subargs).front();
			}
			else
			{
				auto result = def->run(self, attempt ? inner : subargs, base);
				ok = result.ok;
				step_result = result.result;
				if (!result.ok)
				{
					error_code = result.code;
					error_message = result.message;
				}
			}

			uint64_t ms = (uint64_t)(date_time().milliseconds() - time);
			if (self.machine)
			{
				auto envelope = format::tree::map();
				envelope.set("event", format::variable("step"));
				envelope.set("step", format::variable(to_string(steps)));
				envelope.set("cmd", format::variable((attempt ? inner : subargs).front()));
				envelope.set("ms", format::variable(ms));
				if (!note.empty())
					envelope.set("note", format::variable(note));
				if (ok)
				{
					if (!step_result.is_none())
						envelope.set("result", step_result);
				}
				else
					envelope.set("error", error_detail(error_code, error_message));
				echo(envelope.as_json());
			}
			else if (def != nullptr)
			{
				outcome rendered;
				rendered.ok = ok;
				rendered.code = error_code;
				rendered.message = error_message;
				rendered.result = step_result;
				self.respond(*def, ms, rendered, false);
			}

			bool expect_fail = attempt;
			string expect_error, expect_root, expect_contains;
			bool has_expectation = expected != nullptr;
			if (has_expectation)
			{
				if (expected->has("ok"))
					expect_fail = !expected->fetch_var("ok").get_boolean();
				if (expected->has("error"))
				{
					expect_error = string(expected->fetch_var("error").get_blob());
					expect_fail = true;
				}
				if (expected->has("root"))
					expect_root = string(expected->fetch_var("root").get_blob());
				if (expected->has("contains"))
					expect_contains = string(expected->fetch_var("contains").get_blob());
			}

			if (expect_fail)
			{
				if (ok)
				{
					util::echo_color(std_color::red, "   \xE2\x9C\x97 expected failure but command succeeded");
					failures++;
					return false;
				}
				if (!expect_error.empty() && error_message.find(expect_error) == std::string_view::npos)
				{
					util::echo_color(std_color::red, "   \xE2\x9C\x97 expected error \"" + expect_error + "\" but got \"" + error_message + "\"");
					failures++;
					return false;
				}
				if (!self.machine)
					util::echo_color(std_color::green, "   \xE2\x9C\x93 expected failure observed");
			}
			else if (!ok)
			{
				failures++;
				return false;
			}

			if (!expect_root.empty() && algorithm::encoding::encode_0xhex256(self.context.state_root_hash()) != expect_root)
			{
				util::echo_color(std_color::red, "   \xE2\x9C\x97 expected root " + expect_root + " but got " + algorithm::encoding::encode_0xhex256(self.context.state_root_hash()));
				failures++;
				return false;
			}

			if (!expect_contains.empty() && step_result.as_json(false).find(expect_contains) == std::string_view::npos)
			{
				util::echo_color(std_color::red, "   \xE2\x9C\x97 expected result to contain \"" + expect_contains + "\"");
				failures++;
				return false;
			}

			return true;
		}
	}
}