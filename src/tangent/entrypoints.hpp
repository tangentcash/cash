#ifndef TAN_VALIDATOR_ENTRYPOINTS_HPP
#define TAN_VALIDATOR_ENTRYPOINTS_HPP
#include "service/consensus.h"
#include "service/discovery.h"
#include "service/rpc.h"
#include "storage/chainstate.h"
#include "kernel/script.h"
#include "policy/transactions.h"
#include <sstream>
#include <regex>

namespace tangent
{
	namespace entrypoints
	{
		enum class script_asm
		{
			code,
			abi,
			tx_deploy,
			tx_call
		};

		struct script_context : script::program
		{
			struct
			{
				btree_map<algorithm::pubkeyhash_t, btree_map<algorithm::asset_id, decimal>> balances;
				script::payable_repr payable;
				algorithm::pubkeyhash_t from;
				algorithm::pubkeyhash_t to;
			} state;
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
				uptr<transactions::call> contextual;
				ledger::solver_context solver;
				script::cmodule pmodule;
				format::tree returning;
				format::tree log;
				ledger::block_body block;
			} tracer;

			script_context() : script::program(nullptr, nullptr)
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
			}
			~script_context() = default;
			expects_lr<void> assign_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from, const algorithm::pubkeyhash_t& to, const vector<std::pair<algorithm::asset_id, decimal>>& pays, const std::string_view& function_decl, const format::variables& args)
			{
				ledger::transaction_receipt receipt;
				receipt.from = from;

				uptr<transactions::call> transaction = memory::init<transactions::call>();
				transaction->asset = asset;
				transaction->pays = pays;
				transaction->signature.blob[0] = 0xFF;
				transaction->nonce = std::max<size_t>(1, tracer.solver.state.executor.get_account_nonce(from).or_else(states::account_nonce(algorithm::pubkeyhash_t(), nullptr)).nonce);
				transaction->call_to(to, function_decl, format::variables(args));
				transaction->set_gas(decimal::zero(), ledger::block_body::get_transaction_gas_limit());
				tracer.contextual = std::move(transaction);
				tracer.solver.apply_temporary_state(&tracer.block, *tracer.contextual, std::move(receipt));
				return expectation::met;
			}
			expects_lr<void> call_transaction(script::ccall mutability, const script::function& entrypoint, const format::variables& args)
			{
				VI_ASSERT(tracer.contextual, "transaction should be assigned");
				tracer.returning = format::tree();
				tracer.events.clear();
				auto execution = execute(mutability, entrypoint, args, [this](void* address, int type_id) -> expects_lr<void>
				{
					tracer.returning = format::tree::map();
					auto serialization = script::marshall::store(tracer.returning, address, type_id);
					if (!serialization)
					{
						tracer.returning = format::tree();
						return layer_exception("return value error: " + serialization.error().message());
					}

					return expectation::met;
				});
				executor->receipt.successful = !!execution;
				executor->receipt.block_time = protocol::now().time.now();
				if (!executor->receipt.successful)
					executor->emit_event(0, { format::variable(execution.what()) }, false);

				tracer.log = format::tree::list();
				for (auto& [event, params] : executor->receipt.events)
				{
					auto target = tracer.events.find(tracer.log.childs().size());
					auto* next = tracer.log.push(format::tree::map());
					next->set("type", format::variable(event));
					if (target == tracer.events.end())
					{
						uptr<ledger::transition_state> temp = states::resolver::from_type(event);
						next->set(temp ? temp->as_typename() : "__internal__", serialize_event_args(params));
					}
					else
						next->set(target->second.key, target->second);
				}

				return execution;
			}
			expects_lr<void> compile(const std::string_view& new_path)
			{
				auto file = os::file::read_as_string(new_path);
				if (!file)
					return layer_exception(file.what());

				auto* factory = script::factory::get();
				auto* vm = factory->get_vm();
				vm->set_compiler_error_callback([this](const std::string_view& message) { program.log.append(message).append("\r\n"); });
				vm->clear_cache();
				program.log.clear();

				auto hash = algorithm::hashing::hash512((uint8_t*)file->data(), file->size());
				auto result = factory->compile_module(new_path, [&]() mutable { return expects_lr<string>(std::move(*file)); });
				vm->set_compiler_error_callback(nullptr);
				if (!program.log.empty())
					return layer_exception(string(program.log));
				else if (!result)
					return result.error();

				program.path = new_path;
				tracer.pmodule = std::move(*result);
				module = tracer.pmodule->get_module();
				return expectation::met;
			}
			expects_lr<void> assemble(script_asm type, const std::string_view& new_path, format::variables&& function_args)
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
					transaction.call_to(state.to, function_decl, std::move(function_args));
					transaction.pays = state.payable.payments;

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
			expects_lr<void> call(const std::string_view& function, format::variables&& args, bool attach_debugger_context)
			{
				if (program.path.empty())
					return layer_exception("program not bound");

				if (state.from.empty())
					return layer_exception("caller address not valid");

				if (state.to.empty())
					return layer_exception("contract address not valid");

				auto entrypoint = module.get_function_by_decl(function);
				if (!entrypoint.is_valid())
					entrypoint = module.get_function_by_name(function);
				if (!entrypoint.is_valid())
					return layer_exception("illegal call to function: null function");

				auto assignment = assign_transaction(algorithm::asset::native(), state.from, state.to, state.payable.payments, function, args);
				if (!assignment)
					return assignment.error();

				auto read_only = mutability_of(entrypoint) == script::ccall::const_call;
				if (!read_only)
				{
					for (auto& [account, balances] : state.balances)
					{
						for (auto& [asset, value] : balances)
						{
							auto prev_balance = executor->get_account_balance(asset, account);
							if (prev_balance && prev_balance->get_balance() >= value)
								continue;

							auto balance = states::account_balance(account, asset, nullptr);
							balance.supply = value;

							auto status = executor->store(&balance, false);
							if (!status)
								return status.error();
						}
					}

					for (auto& [paying_asset, paying_value] : state.payable.payments)
					{
						auto payment = executor->apply_payment(paying_asset, state.from, state.to, paying_value);
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

				auto execution = call_transaction(script::ccall::deploy_call, entrypoint, args);
				if (attach_debugger_context)
				{
					interrupter(false);
					vm->set_debugger(nullptr);
				}

				if (!execution)
					return execution.error();

				tracer.solver.state.changelog.commit();
				state.payable = script::payable_repr();
				state.balances.clear();
				return expectation::met;
			}
			void dispatch_event(int event_type_id, const void* object_value, int object_type_id) override
			{
				script::program::dispatch_event(event_type_id, object_value, object_type_id);
				if (!executor->receipt.events.empty())
				{
					auto data = format::tree();
					if (script::marshall::store(data, object_value, object_type_id))
					{
						auto type = script::factory::get()->get_vm()->get_type_info_by_id(event_type_id);
						data.key = type.is_valid() ? type.get_name() : std::string_view("__pod__");
						tracer.events[executor->receipt.events.size() - 1] = std::move(data);
					}
				}
			}
			void dispatch_exception(script::immediate_context* coroutine) override
			{
				script::program::dispatch_exception(coroutine);
				auto* vm = coroutine->get_vm();
				if (vm->has_debugger())
					vm->get_debugger()->exception_callback(coroutine->get_context());
			}
			void dispatch_coroutine(script::immediate_context* coroutine) override
			{
				script::program::dispatch_coroutine(coroutine);
				auto* vm = coroutine->get_vm();
				if (vm->has_debugger())
					vm->get_debugger()->line_callback(coroutine->get_context());
			}
			void reset()
			{
				state.balances.clear();
				state.from = algorithm::pubkeyhash_t();
				state.to = algorithm::pubkeyhash_t();
				state.payable = script::payable_repr();
				module = nullptr;
				program.path.clear();
				program.log.clear();
				program.trap = 0;
				program.instructions = false;
				tracer.solver = ledger::solver_context();
				tracer.contextual = uptr<transactions::call>();
				tracer.returning = format::tree();
				tracer.log = format::tree();
				tracer.events.clear();
				tracer.pmodule.destroy();
				tracer.block = ledger::block_body();
			}
			bool bound() const
			{
				return !program.path.empty();
			}
			uint256_t state_root_hash() const
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
			format::tree serialize_event_args(const format::variables& value) const
			{
				format::variables copy = value;
				for (auto& item : copy)
				{
					auto data = item.as_string();
					if (data.size() == sizeof(algorithm::pubkeyhash_t) && !format::variables_util::is_ascii_encoding(data))
						item = format::variable(algorithm::signing::encode_address((uint8_t*)data.data()));
				}
				return format::variables_util::serialize(copy);
			}
			static void interrupter(bool bind)
			{
				os::process::bind_signal(signal_code::SIG_INT, bind ? [](int)
				{
					auto* vm = script::factory::get()->get_vm();
					if (vm->get_debugger() && vm->get_debugger()->interrupt())
						interrupter(true);
					else
						exit(1);
				} : nullptr);
			}
		};

		int script(const inline_args& environment)
		{
			auto params = protocol(environment);
			auto context = script_context();
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
							if (!algorithm::signing::decode_address(args[1], context.state.from))
								return err("not a valid address");
						}
						else
							crypto::fill_random_bytes(context.state.from.blob, sizeof(algorithm::pubkeyhash_t));
					}

					if (context.state.from.empty())
						return ok("null");

					return ok(algorithm::signing::encode_address(context.state.from));
				}
				else if (method == "to")
				{
					if (args.size() > 1)
					{
						if (args[1] != "?")
						{
							if (!algorithm::signing::decode_address(args[1], context.state.to))
								return err("not a valid address");
						}
						else
							crypto::fill_random_bytes(context.state.to.blob, sizeof(algorithm::pubkeyhash_t));
					}

					if (context.state.to.empty())
						return ok("null");

					return ok(algorithm::signing::encode_address(context.state.to));
				}
				else if (method == "pay")
				{
					if (args.size() > 2)
					{
						decimal value = decimal(args[1]);
						if (value.is_nan())
							return err("not a valid decimal value");

						auto asset = algorithm::asset::id_of(args[2], args.size() > 3 ? args[3] : std::string_view(), args.size() > 4 ? args[4] : std::string_view());
						if (!algorithm::asset::is_any(asset))
							return err("not a valid asset");

						if (!context.state.payable.plus(asset, value.is_positive() ? value : -context.state.payable.of(asset)))
							return err("failed to pay");
					}

					std::erase_if(context.state.payable.payments, [](const std::pair<algorithm::asset_id, decimal>& item) { return !item.second.is_positive(); });
					for (auto& [asset, value] : context.state.payable.payments)
						ok(value.to_string() + " " + algorithm::asset::name_of(asset));
					return true;
				}
				else if (method == "fund")
				{
					if (args.size() > 2)
					{
						decimal value = decimal(args[1]);
						if (value.is_nan())
							return err("not a valid decimal value");

						auto asset = algorithm::asset::id_of(args[2], args.size() > 3 ? args[3] : std::string_view(), args.size() > 4 ? args[4] : std::string_view());
						if (!algorithm::asset::is_any(asset))
							return err("not a valid asset");

						if (value.is_positive())
							context.state.balances[context.state.from][asset] = std::move(value);
						else
							context.state.balances[context.state.from].erase(asset);
					}

					for (auto& [account, balances] : context.state.balances)
					{
						for (auto& [asset, value] : balances)
						{
							string address = "null";
							if (!account.empty())
								algorithm::signing::encode_address(account, address);
							ok(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
						}
					}
					return true;
				}
				else if (method == "pay_funded")
				{
					if (args.size() > 2)
					{
						decimal value = decimal(args[1]);
						if (value.is_nan() || value.is_negative())
							return err("not a valid decimal value");

						auto asset = algorithm::asset::id_of(args[2], args.size() > 3 ? args[3] : std::string_view(), args.size() > 4 ? args[4] : std::string_view());
						if (!algorithm::asset::is_any(asset))
							return err("not a valid asset");

						if (!context.state.payable.plus(asset, value.is_positive() ? value : -context.state.payable.of(asset)))
							return err("failed to pay");

						if (value.is_positive())
							context.state.balances[context.state.from][asset] = value;
						else
							context.state.balances[context.state.from].erase(asset);
					}

					for (auto& [account, balances] : context.state.balances)
					{
						for (auto& [asset, value] : balances)
						{
							string address = "null";
							if (!account.empty())
								algorithm::signing::encode_address(account, address);
							ok(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
						}
					}

					std::erase_if(context.state.payable.payments, [](const std::pair<algorithm::asset_id, decimal>& item) { return !item.second.is_positive(); });
					for (auto& [asset, value] : context.state.payable.payments)
						ok(value.to_string() + " " + algorithm::asset::name_of(asset));

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

					return ok("compiled " + *path);
				}
				else if (method == "assemble")
				{
					if (args.size() < 3)
						return err("not a valid type");

					if (!context.bound())
						return err("no program bound");

					auto type = args[1];
					if (type != "deploy" && type != "call" && type != "abi" && type != "code")
						return err("not a valid type");

					auto path = os::path::resolve(args[2], directory, true);
					if (!path)
						return err(path.what());

					script_asm asm_type;
					if (type == "deploy")
						asm_type = script_asm::tx_deploy;
					else if (type == "call")
						asm_type = script_asm::tx_call;
					else if (type == "abi")
						asm_type = script_asm::abi;
					else
						asm_type = script_asm::code;

					format::variables function_args;
					function_args.reserve(args.size() - 3);
					for (size_t i = 3; i < args.size(); i++)
						function_args.push_back(format::variable::from(args[i]));

					auto result = context.assemble(asm_type, *path, std::move(function_args));
					if (!result)
						return err(result.what());

					return ok("assembled " + *path);
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
				else if (method == "pack3_256")
				{
					if (args.size() < 2)
						return err("blockchain required");

					auto asset = algorithm::asset::id_of(args[1], args.size() > 2 ? args[2] : std::string_view(), args.size() > 3 ? args[3] : std::string_view());
					if (!algorithm::asset::is_any(asset))
						return err("not a valid asset");

					uint8_t data[32];
					asset.encode(data);

					size_t size = asset.bytes();
					return ok(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
				}
				else if (method == "pack256")
				{
					if (args.size() < 2)
						return err("integer required (r10)");

					uint8_t data[32];
					auto value = uint256_t(args[1], 10);
					value.encode(data);

					size_t size = value.bytes();
					return ok(format::util::encode_0xhex(std::string_view((char*)data + (sizeof(data) - size), size)));
				}
				else if (method == "unpack")
				{
					auto input = format::util::decode_stream(args[1]);
					format::variables function_args;
					format::ro_stream message = format::ro_stream(input);
					if (!format::variables_util::deserialize_flat_from(message, &function_args))
						return ok("null");

					format::tree data = format::variables_util::serialize(function_args);
					terminal->write_line(data.as_json(true));
					return true;
				}
				else if (method == "unpack256")
				{
					if (args.size() < 2)
						return err("integer required (r16)");

					return ok(uint256_t(args[1], 16).to_string());
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

					auto time = date_time().milliseconds();
					auto result = context.call(function_decl, std::move(function_args), false);
					if (!result)
						return err(result.what());

					bool success = context.tracer.solver.state.executor.receipt.successful;
					terminal->write_color(std_color::white, success ? std_color::dark_green : std_color::red);
					terminal->fwrite("%s in %" PRIu64 " ms", success ? "OK finalize transaction" : "ERR revert transaction", (uint64_t)(date_time().milliseconds() - time));
					terminal->clear_color();
					terminal->write("\n");
					terminal->fwrite("\"%s\": ", algorithm::encoding::encode_0xhex256(context.state_root_hash()).c_str());
					terminal->write_line(context.tracer.returning.as_json(true));
					return success;
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

					auto time = date_time().milliseconds();
					auto result = context.call(function_decl, std::move(function_args), true);
					if (!result)
						return err(result.what());

					bool success = context.tracer.solver.state.executor.receipt.successful;
					terminal->write_color(std_color::white, success ? std_color::dark_green : std_color::red);
					terminal->fwrite("%s in %" PRIu64 " ms", success ? "OK finalize transaction" : "ERR revert transaction", (uint64_t)(date_time().milliseconds() - time));
					terminal->clear_color();
					terminal->write("\n");
					terminal->write_line(context.tracer.returning.as_json(true));
					return success;
				}
				else if (method == "result")
				{
					terminal->write_line(context.tracer.returning.as_json(true));
					return true;
				}
				else if (method == "log")
				{
					terminal->write_line(context.tracer.log.as_json(true));
					return true;
				}
				else if (method == "changelog")
				{
					format::tree changelog;
					changelog.childs().reserve(2);
					auto* erase = changelog.set("erase", format::tree::map());
					auto* upsert = changelog.set("upsert", format::tree::map());
					for (auto& [index, change] : context.tracer.solver.state.changelog.outgoing.finalized)
					{
						if (change.erase)
							erase->set(format::util::encode_0xhex(index), change.state->as_tree());
						else
							upsert->set(format::util::encode_0xhex(index), change.state->as_tree());
					}
					terminal->write_line(changelog.as_json(true));
					return true;
				}
				else if (method == "state_check")
				{
					if (args.size() < 2)
						return err("not a valid state hash");

					auto state_hash = algorithm::encoding::decode_0xhex256(args[1]);
					vector<uint256_t> state_tree;
					state_tree.reserve(context.tracer.solver.state.changelog.outgoing.finalized.size() + 1);
					for (auto& [index, change] : context.tracer.solver.state.changelog.outgoing.finalized)
					{
						if (change.state->as_type() == states::witness_program::as_instance_type())
							continue;

						auto copy = uptr(states::resolver::from_copy(*change.state));
						copy->block_number = std::numeric_limits<uint64_t>::max();
						state_tree.push_back(copy->as_hash());
					}

					auto state_root = algorithm::merkle_tree::from(std::move(state_tree)).root();
					if (state_root != state_hash)
						return err("state hash mismatch (actual): " + algorithm::encoding::encode_0xhex256(state_root));

					return true;
				}
				else if (method == "receipt")
				{
					terminal->write_line(context.executor->receipt.as_tree().as_json(true));
					return true;
				}
				else if (method == "abi")
				{
					if (context.module.is_valid())
					{
						for (size_t i = 0; i < context.module.get_function_count(); i++)
						{
							int type_id;
							auto function = context.module.get_function_by_index(i);
							if (function.get_arg(0, &type_id))
							{
								auto type = context.module.get_vm()->get_type_info_by_id(type_id);
								auto name = type.is_valid() ? type.get_name() : std::string_view();
								if (name == "pmut" || name == "pconst")
								{
									auto decl = function.get_decl();
									if (!decl.empty())
										ok(stringify::text("%.*s;", (int)decl.size(), decl.data()));
								}
							}
						}
					}
					return true;
				}
				else if (method == "predefined")
				{
					if (args.size() < 2)
						return err("not a valid path");

					auto path = os::path::resolve(args[1], directory, true);
					if (!path)
						return err(path.what());

					auto symbols = script::factory::get()->export_predefined_symbols();
					auto result = os::file::write(*path, (uint8_t*)symbols.data(), symbols.size());
					if (!result)
						return err(result.what());

					return ok("assembled " + *path);
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
						else if (args[1] == "now")
							trap = 3;
						if (trap == 255)
							return err("trap type not found");
						else if (trap == 3)
							return false;

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
				auto command_copy = copy<std::string>(command);
				static std::regex pattern("[^\\s\"\']+|\"([^\"]*)\"|\'([^\']*)'");
				for (auto it = std::sregex_iterator(command_copy.begin(), command_copy.end(), pattern); it != std::sregex_iterator(); ++it)
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
						auto submethod = subcommand->get_var(0).get_blob();
						if (submethod != "execp")
							continue;

						auto subpath = os::path::resolve(subcommand->get_var(1).get_blob(), path_directory, true);
						if (!subpath)
							return err("internal execp path error: " + subpath.what());

						auto subfile = os::file::read_as_string(*subpath);
						if (!subfile)
							return err("internal execp file error: " + subfile.what());

						auto subpossible_execp = schema::from_json(*subfile);
						if (!subpossible_execp)
							return err("internal execp data error: " + subpossible_execp.what());

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
						vector<string> subargs;
						for (auto& subargument : subcommand->get_childs())
						{
							if (subargument->value.is_object())
							{
								if (subargument->has("$asset"))
								{
									auto blockchain = subargument->fetch_var("$asset.0").get_blob();
									auto token = subargument->fetch_var("$asset.1").get_blob();
									auto contract_address = subargument->fetch_var("$asset.2").get_blob();
									subargs.push_back(algorithm::asset::id_of(blockchain, token, contract_address).to_string());
								}
								else
								{
									format::variables function_args;
									function_args.reserve(subargument->size());
									for (auto& subsubargument : subargument->get_childs())
										function_args.push_back(format::variable::from(pack(subsubargument->value)));

									format::wo_stream message;
									if (format::variables_util::serialize_flat_into(function_args, &message))
										subargs.push_back(message.encode());
									else
										subargs.push_back(string());
								}
							}
							else
								subargs.push_back(pack(subargument->value));
						}

						string compiled_command = "> ";
						for (auto& argument : subargs)
							compiled_command.append(argument).append(1, ' ');
						if (!compiled_command.empty())
							compiled_command.pop_back();

						ok(compiled_command);
						if (!command_execute(subargs, path_directory))
							return false;
					}
					return true;
				}
				else if (method == "help")
				{
					ok(
						"------------- VM for smart contract scripts --------------\n"
						"trap [off|err|all|now]                                  -- enable command interpreter if execp has finished (all) or failed (err)\n"
						"execp [path]                                            -- run predefined execution plan (json file of format: [[\"method\", value_or_object_or_array_args?...], ...])\n"
						"from [address?|?]                                       -- get/set caller address (if ? then random)\n"
						"to [address?|?]                                         -- get/set contract address (if ? then random)\n"
						"fund [value?] [blockchain?] [token?] [contract?]        -- get/set caller address balance\n"
						"pay [value?] [blockchain?] [token?] [contract?]         -- get/set caller address paying value\n"
						"pay_funded [value?] [blockchain?] [token?] [contract?]  -- combination of fund then pay\n"
						"compile [path]                                          -- compile and use program\n"
						"assemble [type:deploy|call|abi|code] [path] [args?]     -- assemble current program (type=deploy/call: assemble deploy tx data with packed args)\n"
						"pack [args?]...                                         -- pack many args into one (for non-trivial function args)\n"
						"pack256 [integer]...                                    -- pack a decimal uint256 into a hex number\n"
						"pack3_256 [blockchain] [token?] [contract?]             -- pack an asset into uint256\n"
						"unpack [stream]                                         -- unpack stream to many args\n"
						"unpack256 [integer]...                                  -- unpack hex uint256 into a decimal number\n"
						"call [declaration] [args?]...                           -- call a function in a current program\n"
						"debug [declaration] [args?]...                          -- call a function in a current program with debugger attached\n"
						"result                                                  -- get call result log\n"
						"log                                                     -- get call event log\n"
						"changelog                                               -- get call state changes log\n"
						"state_check [hash]                                      -- verify state hash derived from current changelog\n"
						"receipt                                                 -- get call receipt\n"
						"abi                                                     -- get program abi listing\n"
						"predefined [path]                                       -- export symbols for AngelScript Language Server (as.predefined)\n"
						"reset                                                   -- reset contract state\n"
						"clear                                                   -- clear console output\n"
						"help                                                    -- show this message\n");
					return true;
				}
				return command_execute(args, directory);
			};

			if (environment.params.size() <= 1 + (params.custom() ? 1 : 0))
			{
			interpreter:
				os::process::bind_signal(signal_code::SIG_INT, [](int) { });
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
			consensus::server_node consensus_service;
			discovery::server_node discovery_service;
			rpc::server_node rpc_service = rpc::server_node(&consensus_service);

			service_control control;
			control.bind(consensus_service.get_entrypoint());
			control.bind(discovery_service.get_entrypoint());
			control.bind(rpc_service.get_entrypoint());
			return control.launch();
		}
	}
}
#endif