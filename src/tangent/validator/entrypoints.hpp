#ifndef TAN_VALIDATOR_ENTRYPOINTS_HPP
#define TAN_VALIDATOR_ENTRYPOINTS_HPP
#include "service/consensus.h"
#include "service/discovery.h"
#include "service/oracle.h"
#include "service/rpc.h"
#include "storage/chainstate.h"
#include "../kernel/svm_abi.h"
#include "../policy/transactions.h"
#include <vitex/bindings.h>
#include <sstream>
#include <regex>

namespace tangent
{
	namespace entrypoints
	{
		using namespace vitex::scripting;

		enum class svm_assembler
		{
			code,
			abi,
			tx_upgrade,
			tx_call
		};

		struct svm_context : ledger::svm_program
		{
			struct
			{
				ordered_map<algorithm::pubkeyhash_t, ordered_map<algorithm::asset_id, decimal>> balances;
				algorithm::pubkeyhash_t from;
				algorithm::pubkeyhash_t to;
				algorithm::asset_id payable = 0;
				decimal pay = decimal::zero();
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
				ledger::evaluation_context environment;
				ledger::svm_compiler compiler;
				uptr<transactions::call> contextual;
				uptr<schema> returning;
				uptr<schema> log;
				unordered_map<size_t, uptr<schema>> events;
				vector<string> instructions;
				ledger::block block;
			} svmc;

			svm_context() : svm_program(nullptr)
			{
				preprocessor::desc compiler_features;
				compiler_features.conditions = true;
				compiler_features.defines = true;
				compiler_features.includes = true;
				compiler_features.pragmas = false;

				auto* container = ledger::svm_container::get();
				auto* vm = container->get_vm();
				vm->set_ts_imports(true);
				vm->set_ts_imports_concat_mode(true);
				vm->set_preserve_source_code(true);
				vm->set_compiler_features(compiler_features);
				svmc.compiler = container->allocate();
				context = &svmc.environment.validation.context;
			}
			~svm_context() = default;
			expects_lr<void> assign_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from, const algorithm::pubkeyhash_t& to, const decimal& value, const std::string_view& function_decl, const format::variables& args)
			{
				uptr<transactions::call> transaction = memory::init<transactions::call>();
				transaction->asset = asset;
				transaction->signature.data[0] = 0xFF;
				transaction->nonce = std::max<size_t>(1, svmc.environment.validation.context.get_account_nonce(from).or_else(states::account_nonce(algorithm::pubkeyhash_t(), nullptr)).nonce);
				transaction->program_call(to, value, function_decl, format::variables(args));
				transaction->set_gas(decimal::zero(), ledger::block::get_gas_limit());

				auto chain = storages::chainstate();
				auto tip = chain.get_latest_block_header();
				if (tip)
					svmc.environment.tip = std::move(*tip);

				ledger::receipt receipt;
				svmc.block.set_parent_block(svmc.environment.tip.address());
				receipt.transaction_hash = transaction->as_hash();
				receipt.generation_time = protocol::now().time.now();
				receipt.block_number = svmc.block.number + 1;
				receipt.from = from;

				svmc.contextual = std::move(transaction);
				svmc.environment.validation.context = ledger::transaction_context(&svmc.environment, &svmc.block, &svmc.environment.validation.changelog, *svmc.contextual, std::move(receipt));
				memset(svmc.environment.validator.public_key_hash.data, 0xFF, sizeof(algorithm::pubkeyhash_t));
				memset(svmc.environment.validator.secret_key.data, 0xFF, sizeof(algorithm::seckey_t));
				return expectation::met;
			}
			expects_lr<ledger::svm_compiler> compile_transaction()
			{
				VI_ASSERT(svmc.contextual, "transaction should be assigned");
				auto index = svmc.environment.validation.context.get_account_program(callable());
				if (!index)
					return layer_exception("program not assigned to address");

				auto* container = ledger::svm_container::get();
				auto& hashcode = index->hashcode;
				auto result = container->allocate();
				if (container->precompile(*result, hashcode))
					return expects_lr<ledger::svm_compiler>(std::move(result));

				auto program = svmc.environment.validation.context.get_witness_program(hashcode);
				if (!program)
					return layer_exception("program not stored to address");

				auto code = program->as_code();
				if (!code)
					return code.error();

				auto compilation = container->compile(*result, hashcode, format::util::encode_0xhex(hashcode), *code);
				if (!compilation)
					return compilation.error();

				return expects_lr<ledger::svm_compiler>(std::move(result));
			}
			expects_lr<void> call_transaction(ledger::svm_call mutability, const function& entrypoint, const format::variables& args)
			{
				VI_ASSERT(svmc.contextual, "transaction should be assigned");
				svmc.returning.destroy();
				svmc.events.clear();
				svmc.instructions.clear();
				auto execution = execute(mutability, entrypoint, args, [this](void* address, int type_id) -> expects_lr<void>
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

				svmc.log = var::set::array();
				for (auto& [event, args] : context->receipt.events)
				{
					auto target = svmc.events.find(svmc.log->size());
					auto* next = svmc.log->push(var::set::object());
					next->set("type", var::integer(event));
					if (target == svmc.events.end())
					{
						uptr<ledger::state> temp = states::resolver::from_type(event);
						next->set(temp ? temp->as_typename() : "__internal__", serialize_event_args(args));
					}
					else
					{
						auto key = target->second->key;
						next->set(key, target->second.reset());
					}
				}

				return execution;
			}
			expects_lr<void> compile(const std::string_view& new_path)
			{
				auto file = os::file::read_as_string(new_path);
				if (!file)
					return layer_exception(file.what());

				auto* container = ledger::svm_container::get();
				auto* vm = container->get_vm();
				vm->set_compiler_error_callback([this](const std::string_view& message) { program.log.append(message).append("\r\n"); });
				vm->clear_cache();
				program.log.clear();

				auto hash = algorithm::hashing::hash512((uint8_t*)file->data(), file->size());
				auto result = container->compile(*svmc.compiler, hash, new_path, *file);
				vm->set_compiler_error_callback(nullptr);
				if (!program.log.empty())
					return layer_exception(string(program.log));
				else if (!result)
					return result.error();

				program.path = new_path;
				return expectation::met;
			}
			expects_lr<void> assemble(svm_assembler type, const std::string_view& new_path, format::variables&& function_args)
			{
				auto* container = ledger::svm_container::get();
				auto* vm = container->get_vm();
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

				if (type == svm_assembler::tx_upgrade)
				{
					auto transaction = transactions::upgrade();
					transaction.from_program(data, std::move(function_args));

					auto message = transaction.as_message();
					data = std::move(message.data);
				}
				else if (type == svm_assembler::tx_call)
				{
					if (function_args.empty())
						return layer_exception("first argument of argument pack must be a function decl/name");

					auto function_decl = function_args.front().as_blob();
					function_args.erase(function_args.begin());

					auto transaction = transactions::call();
					transaction.program_call(state.to, state.pay, function_decl, std::move(function_args));

					auto message = transaction.as_message();
					data = std::move(message.data);
				}
				else if (type == svm_assembler::abi)
				{
					auto result = container->pack(data);
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

				if (!state.payable)
					return layer_exception("payable asset not valid");

				auto entrypoint = svmc.compiler->get_module().get_function_by_decl(function);
				if (!entrypoint.is_valid())
					entrypoint = svmc.compiler->get_module().get_function_by_name(function);
				if (!entrypoint.is_valid())
					return layer_exception("illegal call to function: null function");

				auto assignment = assign_transaction(state.payable, state.from.data, state.to, state.pay, function, args);
				if (!assignment)
					return assignment.error();

				auto read_only = mutability_of(entrypoint) == ledger::svm_call::immutable_call;
				if (!read_only)
				{
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
				}

				auto* vm = svmc.compiler->get_vm();
				if (attach_debugger_context)
				{
					static bool has_any = false;
					debugger_context* debugger = new debugger_context();
					debugger->add_to_string_callback("string", [](string& indent, int depth, void* object, int type_id)
					{
						string& source = *(string*)object;
						string_stream stream;
						stream << "\"" << source << "\"";
						stream << " (string, " << source.size() << " chars)";
						return stream.str();
					});
					debugger->add_to_string_callback("uint128", [](string& indent, int depth, void* object, int type_id)
					{
						uint128& source = *(uint128*)object;
						return source.to_string() + " (uint128)";
					});
					debugger->add_to_string_callback("uint256", [](string& indent, int depth, void* object, int type_id)
					{
						uint256_t& source = *(uint256_t*)object;
						if (algorithm::asset::is_valid(source))
							return source.to_string() + " (uint256; " + algorithm::asset::name_of(source) + " as asset)";

						return source.to_string() + " (uint256)";
					});
					debugger->add_to_string_callback("real320", [](string& indent, int depth, void* object, int type_id)
					{
						decimal& source = *(decimal*)object;
						return source.to_string() + " (real320)";
					});
					debugger->add_to_string_callback("array", [debugger](string& indent, int depth, void* object, int type_id)
					{
						auto* source = (ledger::svm_abi::array_repr*)object;
						int base_type_id = source->get_element_type_id();
						uint32_t size = source->size();
						string_stream stream;
						stream << "0x" << (void*)source << " (array<t>, " << size << " elements)";

						if (!depth || !size)
							return stream.str();

						if (size > 128)
						{
							stream << "\n";
							indent.append("  ");
							for (uint32_t i = 0; i < size; i++)
							{
								stream << indent << "[" << i << "]: " << debugger->to_string(indent, depth - 1, source->at(i), base_type_id);
								if (i + 1 < size)
									stream << "\n";
							}
							indent.erase(indent.end() - 2, indent.end());
						}
						else
						{
							stream << " [";
							for (uint32_t i = 0; i < size; i++)
							{
								stream << debugger->to_string(indent, depth - 1, source->at(i), base_type_id);
								if (i + 1 < size)
									stream << ", ";
							}
							stream << "]";
						}

						return stream.str();
					});
					debugger->add_to_string_callback("address", [](string& indent, int depth, void* object, int type_id)
					{
						auto& source = *(ledger::svm_abi::address*)object;
						return string(source.to_string().view()) + " (address)";
					});
					debugger->add_to_string_callback("abi", [](string& indent, int depth, void* object, int type_id)
					{
						auto& source = *(ledger::svm_abi::abi*)object;
						return source.output.encode() + " (abi)";
					});
					debugger->add_to_string_callback("any", [debugger](string& indent, int depth, void* object, int type_id)
					{
						bindings::any* source = (bindings::any*)object;
						return debugger->to_string(indent, depth - 1, source->get_address_of_object(), source->get_type_id());
					});
					if (!has_any)
					{
						bindings::registry::import_any(vm);
						has_any = true;
					}
					debugger->set_interrupt_callback([](bool is_interrupted) { console::get()->write_line(is_interrupted ? "program execution interrupted" : "resuming program execution"); });
					vm->set_debugger(debugger);
					interrupter(true);
				}

				auto execution = call_transaction(ledger::svm_call::system_call, entrypoint, args);
				if (attach_debugger_context)
				{
					interrupter(false);
					vm->set_debugger(nullptr);
				}

				if (!execution)
					return execution.error();

				svmc.environment.validation.changelog.commit();
				state.balances.clear();
				return expectation::met;
			}
			void dispatch_exception(immediate_context* coroutine) override
			{
				auto* vm = coroutine->get_vm();
				if (vm->has_debugger())
					vm->get_debugger()->exception_callback(coroutine->get_context());
			}
			void dispatch_coroutine(immediate_context* coroutine, vector<ledger::svm_stackframe>& frames) override
			{
				auto* vm = coroutine->get_vm();
				if (vm->has_debugger())
					vm->get_debugger()->line_callback(coroutine->get_context());
				return svm_program::dispatch_coroutine(coroutine, frames);
			}
			bool dispatch_instruction(virtual_machine* vm, immediate_context* coroutine, uint32_t* program_data, size_t program_counter, byte_code_label& opcode) override
			{
				if (program.instructions)
				{
					string_stream stream;
					debugger_context::byte_code_label_to_text(stream, vm, program_data, program_counter, false, true);

					string instruction = stream.str();
					stringify::trim(instruction);

					auto gas = ledger::svm_stackframe::gas_cost_of(opcode);
					instruction.append(instruction.find('%') != std::string::npos ? ", %gas:" : " %gas:");
					instruction.append(to_string(gas));
					svmc.instructions.push_back(std::move(instruction));
				}
				return svm_program::dispatch_instruction(vm, coroutine, program_data, program_counter, opcode);
			}
			bool emit_event(const void* object_value, int object_type_id) override
			{
				if (!ledger::svm_program::emit_event(object_value, object_type_id) || context->receipt.events.empty())
					return false;

				auto data = uptr<schema>(var::set::object());
				data->key = ledger::svm_container::get()->get_vm()->get_type_info_by_id(object_type_id).get_name();
				if (ledger::svm_marshalling::store(*data, object_value, object_type_id))
					svmc.events[context->receipt.events.size() - 1] = std::move(data);

				return true;
			}
			void reset()
			{
				auto* container = ledger::svm_container::get();
				state.balances.clear();
				state.from = algorithm::pubkeyhash_t();
				state.to = algorithm::pubkeyhash_t();
				state.payable = 0;
				state.pay = decimal::zero();
				program.path.clear();
				program.log.clear();
				program.trap = 0;
				program.instructions = false;
				svmc.compiler = container->allocate();
				svmc.environment = ledger::evaluation_context();
				svmc.contextual = uptr<transactions::call>();
				svmc.returning = uptr<schema>();
				svmc.log = uptr<schema>();
				svmc.events.clear();
				svmc.instructions.clear();
				svmc.block = ledger::block();
			}
			bool bound() const
			{
				return !program.path.empty();
			}
			schema* serialize_event_args(const format::variables& value) const
			{
				format::variables copy = value;
				for (auto& item : copy)
				{
					auto data = item.as_string();
					if (data.size() == sizeof(algorithm::pubkeyhash_t) && !format::variables_util::is_ascii_encoding(data))
					{
						string address;
						algorithm::signing::encode_address((uint8_t*)data.data(), address);
						item = format::variable(address);
					}
				}
				return format::variables_util::serialize(copy);
			}
			static void interrupter(bool bind)
			{
				os::process::bind_signal(signal_code::SIG_INT, bind ? [](int)
				{
					auto* vm = ledger::svm_container::get()->get_vm();
					if (vm->get_debugger() && vm->get_debugger()->interrupt())
						interrupter(true);
					else
						exit(1);
				} : nullptr);
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
							if (!algorithm::signing::decode_address(args[1], context.state.from))
								return err("not a valid address");
						}
						else
							crypto::fill_random_bytes(context.state.from.data, sizeof(algorithm::pubkeyhash_t));
					}

					if (context.state.from.empty())
						return ok("null");

					string address;
					algorithm::signing::encode_address(context.state.from, address);
					return ok(address);
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
							crypto::fill_random_bytes(context.state.to.data, sizeof(algorithm::pubkeyhash_t));
					}

					if (context.state.to.empty())
						return ok("null");

					string address;
					algorithm::signing::encode_address(context.state.to, address);
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
								algorithm::signing::encode_address(account, address);
							ok(address + ": " + value.to_string() + " " + algorithm::asset::name_of(asset));
						}
					}
					return true;
				}
				else if (method == "pay_funded")
				{
					if (args.size() > 1)
					{
						decimal value = decimal(args[1]);
						if (value.is_nan() || value.is_negative())
							return err("not a valid decimal value");

						if (value.is_positive())
							context.state.balances[context.state.from][context.state.payable] = value;
						else
							context.state.balances[context.state.from].erase(context.state.payable);
						context.state.pay = std::move(value);
					}

					return ok(context.state.pay.to_string());
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
					if (type != "upgrade" && type != "call" && type != "abi" && type != "code")
						return err("not a valid type");

					auto path = os::path::resolve(args[2], directory, true);
					if (!path)
						return err(path.what());

					svm_assembler svm_type;
					if (type == "upgrade")
						svm_type = svm_assembler::tx_upgrade;
					else if (type == "call")
						svm_type = svm_assembler::tx_call;
					else if (type == "abi")
						svm_type = svm_assembler::abi;
					else if (true || type == "code")
						svm_type = svm_assembler::code;

					format::variables function_args;
					function_args.reserve(args.size() - 3);
					for (size_t i = 3; i < args.size(); i++)
						function_args.push_back(format::variable::from(args[i]));

					auto result = context.assemble(svm_type, *path, std::move(function_args));
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

					uptr<schema> data = format::variables_util::serialize(function_args);
					terminal->jwrite_line(*data);
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

					bool success = context.svmc.environment.validation.context.receipt.successful;
					terminal->write_color(std_color::white, success ? std_color::dark_green : std_color::red);
					terminal->fwrite("%s in %" PRIu64 " ms", success ? "OK finalize transaction" : "ERR revert transaction", (uint64_t)(date_time().milliseconds() - time));
					terminal->clear_color();
					terminal->write("\n");
					if (context.svmc.returning)
						terminal->jwrite_line(*context.svmc.returning);
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

					bool success = context.svmc.environment.validation.context.receipt.successful;
					terminal->write_color(std_color::white, success ? std_color::dark_green : std_color::red);
					terminal->fwrite("%s in %" PRIu64 " ms", success ? "OK finalize transaction" : "ERR revert transaction", (uint64_t)(date_time().milliseconds() - time));
					terminal->clear_color();
					terminal->write("\n");
					if (context.svmc.returning)
						terminal->jwrite_line(*context.svmc.returning);
					return success;
				}
				else if (method == "result")
				{
					if (context.svmc.returning)
						terminal->jwrite_line(*context.svmc.returning);
					return true;
				}
				else if (method == "log")
				{
					if (context.svmc.log)
						terminal->jwrite_line(*context.svmc.log);
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
					if (args.size() > 1)
					{
						context.program.instructions = args[1] == "on";
						return ok(context.program.instructions ? "enable asm tracer" : "disable asm tracer");
					}

					for (auto& instruction : context.svmc.instructions)
						ok(instruction);

					return ok(stringify::text("%i instructions; %s gas units", (int)context.svmc.instructions.size(), context.svmc.environment.validation.context.receipt.relative_gas_use.to_string().c_str()));
				}
				else if (method == "abi")
				{
					if (context.svmc.compiler)
					{
						auto program = context.svmc.compiler->get_module();
						if (program.is_valid())
						{
							for (size_t i = 0; i < program.get_function_count(); i++)
							{
								int type_id;
								auto function = program.get_function_by_index(i);
								if (function.get_arg(0, &type_id))
								{
									auto type = program.get_vm()->get_type_info_by_id(type_id);
									auto name = type.is_valid() ? type.get_name() : std::string_view();
									if (name == "rwptr" || name == "rptr")
									{
										auto decl = function.get_decl();
										if (!decl.empty())
											ok(stringify::text("%.*s;", (int)decl.size(), decl.data()));
									}
								}
							}
						}
					}
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
						"pay_funded [value?]                                      -- combination of fund then pay\n"
						"compile [path]                                           -- compile and use program\n"
						"assemble [type:upgrade|call|abi|code] [path] [args?]     -- assemble current program (type=upgrade_tx/call_tx: assemble upgrade tx data with packed args)\n"
						"pack [args?]...                                          -- pack many args into one (for non-trivial function args)\n"
						"pack256 [integer]...                                     -- pack a decimal uint256 into a hex number\n"
						"unpack [stream]                                          -- unpack stream to many args\n"
						"unpack256 [integer]...                                   -- unpack hex uint256 into a decimal number\n"
						"call [declaration] [args?]...                            -- call a function in a current program\n"
						"debug [declaration] [args?]...                           -- call a function in a current program with debugger attached\n"
						"result                                                   -- get call result log\n"
						"log                                                      -- get call event log\n"
						"changelog                                                -- get call state changes log\n"
						"asm [on|off?]                                            -- get/set svm asm instruction listing\n"
						"abi                                                      -- get program abi listing\n"
						"reset                                                    -- reset contract state\n"
						"trap [off|err|all]                                       -- enable command interpreter if execp has finished (all) or failed (err)\n"
						"clear                                                    -- clear console output\n"
						"---------------- environment functionality ----------------\n"
						"execp [path]                                             -- run predefined execution plan (json file of format: [[\"method\", value_or_object_or_array_args?...], ...])\n"
						"help                                                     -- show this message\n"
						"\n"
						"********* node configuration arguments applicable *********");
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
			consensus::server_node consensus_service;
			discovery::server_node discovery_service;
			oracle::server_node& oracle_service = *oracle::server_node::get();
			rpc::server_node rpc_service = rpc::server_node(&consensus_service);

			service_control control;
			control.bind(discovery_service.get_entrypoint());
			control.bind(consensus_service.get_entrypoint());
			control.bind(oracle_service.get_entrypoint());
			control.bind(rpc_service.get_entrypoint());
			return control.launch();
		}
	}
}
#endif