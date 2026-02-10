#include "transactions.h"
#include "../kernel/script.h"
#include "../kernel/superchain.h"
#define MOCKUP_FAIL "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
#define MOCKUP_LOST "0xbeefdeadbeefdeadbeefdeadbeefdeadbeefdead"

namespace tangent
{
	namespace transactions
	{
		expects_lr<void> transfer::validate(uint64_t block_number) const
		{
			if (to.empty())
				return layer_exception("no transfers");

			for (auto& [owner, value] : to)
			{
				if (!value.is_positive())
					return layer_exception("invalid value");
			}

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> transfer::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			for (auto& [owner, value] : to)
			{
				if (executor->receipt.from == owner)
					return layer_exception("invalid payment");

				auto payment = executor->apply_payment(asset, executor->receipt.from, owner, value);
				if (!payment)
					return payment.error();
			}

			return expectation::met;
		}
		bool transfer::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (to.size() > 1)
			{
				stream->write_integer((uint16_t)to.size());
				for (auto& [owner, value] : to)
				{
					stream->write_string(owner.optimized_view());
					stream->write_decimal(value);
				}
			}
			else if (!to.empty())
			{
				auto& [owner, value] = to.front();
				stream->write_string(owner.optimized_view());
				stream->write_decimal(value);
			}

			return true;
		}
		bool transfer::load_body(format::ro_stream& stream)
		{
			auto type = stream.read_type();
			if (format::util::is_string(type))
			{
				string owner_assembly;
				algorithm::pubkeyhash_t owner;
				if (!stream.read_string(type, &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
					return false;

				decimal value;
				if (!stream.read_decimal(stream.read_type(), &value))
					return false;

				to.clear();
				to.push_back(std::make_pair(owner, std::move(value)));
			}
			else if (type != format::viewable::invalid)
			{
				uint16_t transfers_size;
				if (!stream.read_integer(type, &transfers_size))
					return false;

				to.clear();
				to.reserve(transfers_size);
				for (uint16_t i = 0; i < transfers_size; i++)
				{
					string owner_assembly;
					algorithm::pubkeyhash_t owner;
					if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
						return false;

					decimal value;
					if (!stream.read_decimal(stream.read_type(), &value))
						return false;

					to.push_back(std::make_pair(owner, std::move(value)));
				}
			}

			return true;
		}
		bool transfer::recover_many(const ledger::executor_context*, const ledger::transaction_receipt&, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& [owner, value] : to)
				parties.insert(owner);
			return true;
		}
		void transfer::set_to(const algorithm::pubkeyhash_t& new_to, const decimal& new_value)
		{
			to.push_back(std::make_pair(new_to, new_value));
		}
		format::tree transfer::as_tree() const
		{
			format::tree data = ledger::transaction_message::as_tree();
			auto* transfers_data = data.set("to", format::tree::list());
			for (auto& [owner, value] : to)
			{
				auto* transfer_data = transfers_data->push(format::tree::map());
				transfer_data->set("to", algorithm::signing::serialize_address(owner));
				transfer_data->set("value", format::variable(value));
			}
			return data;
		}
		uint32_t transfer::as_type() const
		{
			return as_instance_type();
		}
		std::string_view transfer::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t transfer::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view transfer::as_instance_typename()
		{
			return "transfer";
		}

		expects_lr<void> deploy::validate(uint64_t block_number) const
		{
			auto type = get_data_type();
			if (!type)
				return layer_exception("invalid data type");
			else if (*type == data_type::hashcode && data.size() != 65)
				return layer_exception("invalid hashcode data");

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> deploy::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			auto account = get_account();
			auto storage = std::string_view(data).substr(1);
			auto type = get_data_type().or_else(data_type::hashcode);
			auto* factory = script::factory::get();
			auto pmodule = script::cmodule(nullptr);
			switch (type)
			{
				case data_type::program:
				{
					auto code = algorithm::encoding::unpack_program(storage);
					if (!code)
						return code.error();

					auto hashcode = algorithm::hashing::ppc512(*code);
					auto result = factory->compile_module(format::util::encode_0xhex(hashcode), [&]() mutable { return std::move(code); });
					if (!result)
						return result.error();

					auto collision = executor->get_witness_program(hashcode);
					if (!collision)
					{
						auto status = executor->apply_witness_program(storage);
						if (!status)
							return status.error();
					}
					else if (collision->storage != data)
						return layer_exception("program hashcode collision");

					auto status = executor->apply_account_program(account, hashcode);
					if (!status)
						return status.error();

					pmodule = std::move(*result);
					break;
				}
				case data_type::hashcode:
				{
					auto program = executor->get_witness_program(storage);
					if (!program)
						return layer_exception("program is not stored");

					auto result = factory->compile_module(format::util::encode_0xhex(storage), [&]() { return program->as_code(); });
					if (!result)
						return result.error();

					auto status = executor->apply_account_program(account, storage);
					if (!status)
						return status.error();

					pmodule = std::move(*result);
					break;
				}
				default:
					return layer_exception("invalid data type");
			}

			auto script = script::program(executor, pmodule->get_module());
			return script.execute(script::ccall::deploy_call, script.deploy_function(), args, nullptr);
		}
		bool deploy::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(data);
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool deploy::load_body(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &data))
				return false;

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool deploy::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			size_t offset = 0;
			parties.insert(get_account());

			const format::variables* event = receipt.find_event<states::account_balance>();
			while (event != nullptr)
			{
				auto from = event->size() > 1 ? event->at(1).as_string() : std::string_view();
				if (from.size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(from));

				auto to = event->size() > 2 ? event->at(2).as_string() : std::string_view();
				if (to.size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(to));

				event = receipt.find_event<states::account_balance>(++offset);
			}
			return true;
		}
		void deploy::from_program(const std::string_view& new_data, format::variables&& new_args)
		{
			args = std::move(new_args);
			data.clear();
			data.assign(1, (char)data_type::program);
			data.append(algorithm::encoding::pack_program(new_data).or_else(string()));
		}
		void deploy::from_hashcode(const std::string_view& new_data, format::variables&& new_args)
		{
			args = std::move(new_args);
			data.clear();
			data.assign(1, (char)data_type::hashcode);
			data.append(new_data.substr(0, 64));
		}
		algorithm::pubkeyhash_t deploy::get_account() const
		{
			auto message = as_message();
			message.write_integer(0xFFFFFFFF);

			algorithm::pubkeyhash_t account;
			algorithm::hashing::hash160((uint8_t*)message.data.data(), message.data.size(), account.blob);
			return account;
		}
		option<deploy::data_type> deploy::get_data_type() const
		{
			if (data.empty())
				return optional::none;

			data_type type = (data_type)(uint8_t)data.front();
			switch (type)
			{
				case data_type::program:
				case data_type::hashcode:
					return type;
				default:
					return optional::none;
			}
		}
		format::tree deploy::as_tree() const
		{
			std::string_view name;
			switch (get_data_type().or_else((data_type)(uint8_t)0))
			{
				case data_type::program:
					name = "program";
					break;
				case data_type::hashcode:
					name = "hashcode";
					break;
				default:
					break;
			}

			format::tree result = ledger::transaction_message::as_tree();
			result.set("callable", algorithm::signing::serialize_address(get_account()));
			result.set("from", name.empty() ? format::variable() : format::variable(name));
			result.set("data", format::variable(format::util::encode_0xhex(data)));
			result.set("args", format::variables_util::serialize(args));
			return result;
		}
		uint32_t deploy::as_type() const
		{
			return as_instance_type();
		}
		std::string_view deploy::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t deploy::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view deploy::as_instance_typename()
		{
			return "deploy";
		}

		expects_lr<void> call::validate(uint64_t block_number) const
		{
			if (function.empty())
				return layer_exception("invalid function call");

			hash_set<algorithm::asset_id> duplicates;
			for (auto& [paying_asset, paying_value] : pays)
			{
				if (!algorithm::asset::is_any(paying_asset) || !paying_value.is_positive())
					return layer_exception("invalid value");
				else if (duplicates.find(paying_asset) != duplicates.end())
					return layer_exception("duplicate payment asset");

				duplicates.insert(paying_asset);
			}

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> call::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			return subexecute(executor, [this, executor](void* module_ptr)
			{
				auto script = script::program(executor, (asIScriptModule*)module_ptr);
				return script.execute(script::ccall::paying_call, function, args, nullptr);
			});
		}
		expects_lr<void> call::subexecute(ledger::executor_context* executor, std::function<expects_lr<void>(void*)>&& callback) const
		{
			VI_ASSERT(executor, "executor should be set");
			auto index = executor->get_account_program(callable);
			if (!index)
				return layer_exception("program is not assigned");

			auto& hashcode = index->hashcode;
			auto program = executor->get_witness_program(hashcode);
			if (!program)
				return layer_exception("program is not stored");

			auto pmodule = script::factory::get()->compile_module(format::util::encode_0xhex(hashcode), [&]() { return program->as_code(); });
			if (!pmodule)
				return pmodule.error();

			for (auto& [paying_asset, paying_value] : pays)
			{
				if (executor->receipt.from == callable)
					return layer_exception("invalid payment");

				auto payment = executor->apply_payment(paying_asset, executor->receipt.from, callable, paying_value);
				if (!payment)
					return payment.error();
			}

			return callback(pmodule->ref.get_module());
		}
		bool call::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(callable.optimized_view());
			stream->write_string(function);
			stream->write_integer((uint8_t)pays.size());
			for (auto& [paying_asset, paying_value] : pays)
			{
				stream->write_integer(paying_asset);
				stream->write_decimal(paying_value);
			}
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool call::load_body(format::ro_stream& stream)
		{
			string callable_assembly;
			if (!stream.read_string(stream.read_type(), &callable_assembly) || !algorithm::encoding::decode_bytes(callable_assembly, callable.blob, sizeof(callable)))
				return false;

			if (!stream.read_string(stream.read_type(), &function))
				return false;

			uint8_t pays_size;
			if (!stream.read_integer(stream.read_type(), &pays_size))
				return false;

			pays.clear();
			pays.reserve((size_t)pays_size);
			for (uint8_t i = 0; i < pays_size; i++)
			{
				algorithm::asset_id paying_asset;
				if (!stream.read_integer(stream.read_type(), &paying_asset))
					return false;

				decimal paying_value;
				if (!stream.read_decimal(stream.read_type(), &paying_value))
					return false;

				pays.push_back(std::make_pair(std::move(paying_asset), std::move(paying_value)));
			}

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool call::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			size_t offset = 0;
			const format::variables* event = receipt.find_event<states::account_balance>();
			while (event != nullptr)
			{
				auto from = event->size() > 1 ? event->at(1).as_string() : std::string_view();
				if (from.size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(from));

				auto to = event->size() > 2 ? event->at(2).as_string() : std::string_view();
				if (to.size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(to));

				event = receipt.find_event<states::account_balance>(++offset);
			}

			parties.insert(algorithm::pubkeyhash_t(callable));
			return true;
		}
		void call::call_to(const algorithm::pubkeyhash_t& new_callable, const std::string_view& new_function, format::variables&& new_args)
		{
			args = std::move(new_args);
			function = new_function;
			callable = new_callable;
		}
		void call::pay_with(const algorithm::asset_id& new_asset, const decimal& new_value)
		{
			pays.push_back(std::make_pair(new_asset, new_value));
		}
		format::tree call::as_tree() const
		{
			format::tree data = ledger::transaction_message::as_tree();
			data.set("callable", algorithm::signing::serialize_address(callable));
			data.set("function", format::variable(function));
			data.set("args", format::variables_util::serialize(args));
			auto* pays_data = data.set("pays", format::tree::list());
			for (auto& [paying_asset, paying_value] : pays)
			{
				auto* pay_data = pays_data->push(format::tree::map());
				pay_data->set("asset", algorithm::asset::serialize(paying_asset));
				pay_data->set("value", format::variable(paying_value));
			}
			return data;
		}
		uint32_t call::as_type() const
		{
			return as_instance_type();
		}
		std::string_view call::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t call::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view call::as_instance_typename()
		{
			return "call";
		}

		rollup::rollup(const rollup& other)
		{
			ledger::transaction_message& base = *this;
			base = *(ledger::transaction_message*)&other;
			transactions.clear();
			for (auto& group : other.transactions)
			{
				auto& group_copy = transactions[group.first];
				group_copy.reserve(group.second.size());
				for (auto& transaction : group.second)
				{
					auto* copy = resolver::from_copy(*transaction);
					if (copy != nullptr)
						group_copy.push_back(copy);
				}
			}
		}
		rollup& rollup::operator= (const rollup& other)
		{
			if (this == &other)
				return *this;

			ledger::transaction_message& base = *this;
			base = *(ledger::transaction_message*)&other;
			transactions.clear();
			for (auto& group : other.transactions)
			{
				auto& group_copy = transactions[group.first];
				group_copy.reserve(group.second.size());
				for (auto& transaction : group.second)
				{
					auto* copy = resolver::from_copy(*transaction);
					if (copy != nullptr)
						group_copy.push_back(copy);
				}
			}
			return *this;
		}
		expects_lr<void> rollup::validate(uint64_t block_number) const
		{
			if (transactions.empty())
				return layer_exception("invalid transactions");

			for (auto& group : transactions)
			{
				if (group.second.empty())
					return layer_exception("invalid transactions");

				for (auto& transaction : group.second)
				{
					if (!transaction || transaction->as_type() == as_type() || transaction->is_commitment())
						return layer_exception("invalid sub-transaction");

					if (transaction->asset != group.first || !transaction->gas_price.is_nan() || transaction->gas_limit > 0)
						return layer_exception("invalid sub-transaction data");
				}
			}

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> rollup::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			vector<std::pair<ledger::transaction_message*, uint16_t>> queue;
			for (auto& group : transactions)
			{
				uint16_t index = 0;
				queue.reserve(queue.size() + group.second.size());
				for (auto& transaction : group.second)
					queue.push_back(std::make_pair(*transaction, index++));
			}

			algorithm::pubkeyhash_t owner;
			uint256_t absolute_gas_limit = executor->block->gas_limit;
			uint256_t absolute_gas_use = executor->block->gas_use;
			uint256_t relative_gas_use = executor->receipt.relative_gas_use;
			std::sort(queue.begin(), queue.end(), [](const std::pair<ledger::transaction_message*, uint16_t>& a, const std::pair<ledger::transaction_message*, uint16_t>& b)
			{
				return a.first->nonce > 0 && b.first->nonce > 0 && a.first->nonce != b.first->nonce ? a.first->nonce < b.first->nonce : a.second < b.second;
			});

			auto internal_receipt = ledger::transaction_receipt();
			for (auto& [transaction, index] : queue)
			{
				bool internal_transaction = transaction->signature.empty();
				uint256_t transaction_hash = transaction->as_hash();
				uint64_t transaction_nonce = transaction->nonce;
				uint8_t transaction_code = transaction->signature.blob[0];
				uint8_t execution_flags = (uint8_t)ledger::executor_context::flags::pedantic;
				if (internal_transaction)
				{
					transaction->nonce = nonce;
					transaction->signature.blob[0] = 0xFF;
					execution_flags |= (uint8_t)ledger::executor_context::flags::replayable;
					owner = executor->receipt.from;
				}
				else if (!transaction->recover_hash(owner) || owner.empty())
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " validation failed: invalid signature");

				transaction->gas_price = decimal::zero();
				transaction->gas_limit = gas_limit - executor->receipt.relative_gas_use;
				auto execution = ledger::executor_context::execute_tx(executor->solver, executor->block, executor->changelog, transaction, transaction_hash, owner, 0, execution_flags, internal_receipt);
				transaction->signature.blob[0] = transaction_code;
				transaction->nonce = transaction_nonce;
				transaction->gas_limit = 0;
				transaction->gas_price = decimal::nan();
				if (!execution)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " execution failed: " + execution.error().message());

				relative_gas_use += execution->receipt.relative_gas_use;
				auto report = executor->emit_event<rollup>({ format::variable(execution->receipt.transaction_hash), format::variable(index), format::variable(execution->receipt.relative_gas_use) });
				if (!report)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " merge failed: " + report.error().message());

				size_t prev_size = internal_receipt.events.size();
				internal_receipt.events = std::move(execution->receipt.events);
				if (internal_receipt.events.size() > prev_size)
					executor->receipt.events.insert(executor->receipt.events.end(), internal_receipt.events.begin() + prev_size, internal_receipt.events.end());
			}

			executor->block->gas_limit = absolute_gas_limit;
			executor->block->gas_use = absolute_gas_use;
			executor->receipt.relative_gas_use = relative_gas_use;
			return expectation::met;
		}
		expects_promise_rt<void> rollup::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			if (!is_dispatchable())
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, executor, dispatcher]() -> expects_promise_rt<void>
			{
				string error_message;
				for (auto& group : transactions)
				{
					for (auto& transaction : group.second)
					{
						auto resolved_transaction = resolve_block_transaction(executor->receipt, transaction->as_hash());
						if (!resolved_transaction)
							continue;

						auto& target_transaction = *resolved_transaction;
						auto status = coawait(ledger::executor_context::dispatch_tx(dispatcher, &target_transaction));
						if (!status && (status.error().is_retry() || status.error().is_shutdown()))
							coreturn status;
						else if (!status)
							error_message += "sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " dispatch failed: " + status.error().message() + "\n";
					}
				}
				if (error_message.empty())
					coreturn expectation::met;

				error_message.pop_back();
				coreturn remote_exception(std::move(error_message));
			});
		}
		bool rollup::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)transactions.size());
			for (auto& group : transactions)
			{
				stream->write_integer(group.first);
				stream->write_integer((uint32_t)group.second.size());
				for (auto& transaction : group.second)
				{
					bool internal_transaction = transaction->signature.empty();
					stream->write_boolean(internal_transaction);
					stream->write_integer(transaction->as_type());
					if (!internal_transaction)
					{
						stream->write_integer(transaction->nonce);
						stream->write_string(transaction->signature.view());
					}
					if (!transaction->store_body(stream))
						return false;
				}
			}

			return true;
		}
		bool rollup::load_body(format::ro_stream& stream)
		{
			transactions.clear();
			uint16_t groups_count;
			if (!stream.read_integer(stream.read_type(), &groups_count))
				return false;

			string signature_assembly;
			for (uint16_t i = 0; i < groups_count; i++)
			{
				algorithm::asset_id group_asset;
				if (!stream.read_integer(stream.read_type(), &group_asset))
					return false;

				uint32_t transactions_count;
				if (!stream.read_integer(stream.read_type(), &transactions_count))
					return false;

				auto& group = transactions[group_asset];
				group.reserve(transactions_count);
				for (uint32_t j = 0; j < transactions_count; j++)
				{
					bool internal_transaction;
					if (!stream.read_boolean(stream.read_type(), &internal_transaction))
						return false;

					uint32_t type;
					if (!stream.read_integer(stream.read_type(), &type))
						return false;

					uptr<ledger::transaction_message> next = resolver::from_type(type);
					if (!next)
						return false;

					if (!internal_transaction)
					{
						if (!stream.read_integer(stream.read_type(), &next->nonce))
							return false;

						if (!stream.read_string(stream.read_type(), &signature_assembly) || signature_assembly.size() != sizeof(algorithm::hashsig_t))
							return false;

						next->signature = algorithm::hashsig_t(signature_assembly);
					}
					else
					{
						next->signature.clear();
						next->nonce = 0;
					}

					next->asset = group_asset;
					if (!next->load_body(stream))
						return false;

					normalize_transaction(**next, asset);
					group.push_back(std::move(next));
				}
			}
			return true;
		}
		bool rollup::recover_many(const ledger::executor_context* executor, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			algorithm::pubkeyhash_t from;
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					bool internal_transaction = transaction->signature.empty();
					if (!internal_transaction && transaction->recover_hash(from))
						parties.insert(from);
					transaction->recover_many(executor, receipt, parties);
				}
			}
			return true;
		}
		bool rollup::recover_aliases(btree_set<uint256_t>& aliases) const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					aliases.insert(transaction->as_hash());
					if (!transaction->recover_aliases(aliases))
						return false;
				}
			}
			return true;
		}
		bool rollup::import_transaction(const ledger::transaction_message& transaction)
		{
			auto* next = resolver::from_copy(&transaction);
			if (!next)
				return false;

			transactions[next->asset].push_back(next);
			return true;
		}
		bool rollup::import_internal_transaction(ledger::transaction_message& transaction)
		{
			transaction.nonce = 0;
			transaction.signature.clear();
			normalize_transaction(transaction, asset);
			return import_transaction(transaction);
		}
		bool rollup::import_external_transaction(ledger::transaction_message& transaction, const algorithm::seckey_t& secret_key, uint64_t account_nonce)
		{
			transaction.nonce = account_nonce > 0 ? account_nonce : transaction.nonce;
			normalize_transaction(transaction, asset);
			if (!transaction.sign(secret_key))
				return false;

			return import_transaction(transaction);
		}
		bool rollup::is_dispatchable() const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					if (transaction->is_dispatchable())
						return true;
				}
			}
			return false;
		}
		expects_lr<ledger::block_transaction> rollup::resolve_block_transaction(const ledger::transaction_receipt& receipt, const uint256_t& transaction_hash) const
		{
			if (!transaction_hash)
				return layer_exception("sub-transaction not found");

			ledger::transaction_message* target = nullptr;
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					if (transaction->as_hash() == transaction_hash)
					{
						target = *transaction;
						break;
					}
					else if (transaction->as_type() != rollup::as_instance_type())
						continue;

					auto candidate = ((rollup*)*transaction)->resolve_block_transaction(receipt, transaction_hash);
					if (candidate)
						return candidate;
				}
			}

			if (!target)
				return layer_exception("sub-transaction not found");

			ledger::block_transaction transaction;
			transaction.transaction = resolver::from_copy(target);
			transaction.receipt = receipt;
			if (!transaction.transaction)
				return layer_exception("sub-transaction not valid");

			transaction.receipt.relative_gas_use = 0;
			transaction.receipt.transaction_hash = transaction.transaction->as_hash();
			if (!transaction.transaction->recover_hash(transaction.receipt.from))
				return layer_exception("sub-transaction not valid");

			size_t offset = 0;
			size_t begin = std::string::npos, end = std::string::npos;
			for (auto& event : receipt.events)
			{
				++offset;
				if (event.first != rollup::as_instance_type() || event.second.size() != 2)
					continue;

				uint256_t candidate_hash = event.second[0].as_uint256();
				if (candidate_hash == transaction_hash)
				{
					begin = offset - 1;
					transaction.receipt.relative_gas_use = event.second[1].as_uint256();
					continue;
				}
				else if (begin != std::string::npos)
				{
					end = offset - 1;
					break;
				}
			}

			if (begin == std::string::npos)
				return layer_exception("sub-transaction not valid");
			else if (end == std::string::npos)
				end = offset;

			transaction.receipt.events.resize(end - 1);
			transaction.receipt.events.erase(transaction.receipt.events.begin(), transaction.receipt.events.begin() + begin + 1);
			return transaction;
		}
		const ledger::transaction_message* rollup::resolve_transaction(const uint256_t& transaction_hash) const
		{
			if (!transaction_hash)
				return nullptr;

			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					if (transaction->as_hash() == transaction_hash)
						return *transaction;
					else if (transaction->as_type() != rollup::as_instance_type())
						continue;

					auto* candidate = ((rollup*)*transaction)->resolve_transaction(transaction_hash);
					if (candidate != nullptr)
						return candidate;
				}
			}

			return nullptr;
		}
		format::tree rollup::as_tree() const
		{
			algorithm::pubkeyhash_t from;
			format::tree data = ledger::transaction_message::as_tree();
			auto* transactions_data = data.set("transactions", format::tree::list());
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					bool internal_transaction = transaction->signature.empty();
					auto* item = transactions_data->push(format::tree::map());
					item->set("action", transaction->as_tree());
					item->set("signer", !internal_transaction && transaction->recover_hash(from) ? algorithm::signing::serialize_address(from) : format::variable());
				}
			}
			return data;
		}
		uint32_t rollup::as_type() const
		{
			return as_instance_type();
		}
		std::string_view rollup::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t rollup::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view rollup::as_instance_typename()
		{
			return "rollup";
		}
		void rollup::normalize_transaction(ledger::transaction_message& transaction, const algorithm::asset_id& asset)
		{
			transaction.gas_price = decimal::nan();
			transaction.gas_limit = 0;
			if (!transaction.asset)
				transaction.asset = asset;
		}

		expects_lr<void> setup::validate(uint64_t block_number) const
		{
			if (migrations.empty() && attestations.empty() && bridges.empty() && !participation && !production)
				return layer_exception("invalid validator change");

			for (auto& [broadcast_hash, participant] : migrations)
			{
				if (!broadcast_hash)
					return layer_exception("invalid broadcast hash");

				if (participant.empty())
					return layer_exception("invalid participant");
			}

			for (auto& [attestation_asset, setup] : attestations)
			{
				if (!algorithm::asset::is_aux(attestation_asset, true))
					return layer_exception("invalid attestation asset");

				if (setup.stake.is_negative())
					return layer_exception("attestation stake must not be negative");

				if (setup.min_fee && (setup.min_fee->is_nan() || setup.min_fee->is_negative()))
					return layer_exception("invalid min fee");
			}

			for (auto& [bridge_asset, setup] : bridges)
			{
				if (!algorithm::asset::is_aux(bridge_asset, true))
					return layer_exception("invalid bridge asset");

				if (!setup.fee_rate.is_positive())
					return layer_exception("invalid fee rate");

				if (setup.security_level < protocol::now().policy.participation.min_per_account || setup.security_level > protocol::now().policy.participation.max_per_account)
					return layer_exception("invalid security level");
			}

			if (participation && participation->is_negative())
				return layer_exception("participation stake must not be negative");

			if (production && production->is_negative())
				return layer_exception("production stake must not be negative");

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> setup::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			btree_set<uint256_t> accounts;
			btree_set<algorithm::pubkeyhash_t> exclusion;
			for (auto& [broadcast_hash, participant] : migrations)
			{
				auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
				if (!parent)
					return layer_exception("broadcast transaction not found");

				auto* parent_transaction = (broadcast*)*parent->transaction;
				if (parent_transaction->proof)
					return layer_exception("broadcast transaction not applicable");

				auto origin = executor->get_block_transaction<withdraw>(parent_transaction->withdraw_hash, true);
				if (!origin)
					return layer_exception("withdraw transaction not found");

				auto base_asset = algorithm::asset::base_id_of(parent_transaction->asset);
				auto requirement = executor->get_verified_validator_attestation(base_asset, executor->receipt.from);
				if (!requirement)
					return layer_exception("must be an active attester to request migration");

				auto time_lock = protocol::now().policy.attestation.withdrawal_time / protocol::now().policy.pow.time;
				auto time_delta = parent->receipt.block_number < executor->receipt.block_number ? executor->receipt.block_number - parent->receipt.block_number : 0;
				if (time_delta <= time_lock)
					return layer_exception("broadcast time lock active - retry after block number " + to_string(parent->receipt.block_number + time_lock));
				else if (time_delta > time_lock * 2)
					return layer_exception("permanent broadcast time lock - activated after block number " + to_string(parent->receipt.block_number + time_lock * 2));

				auto* origin_transaction = (withdraw*)*origin->transaction;
				auto bridge = executor->get_bridge_instance(base_asset, origin_transaction->bridge_hash);
				if (!bridge)
					return bridge.error();

				if (bridge->transaction_hash > 0 && bridge->transaction_hash != broadcast_hash)
				{
					parent = executor->get_block_transaction<broadcast>(bridge->transaction_hash, true);
					if (!parent)
						return layer_exception("last broadcast transaction not found");

					parent_transaction = (broadcast*)*parent->transaction;
					if (parent_transaction->proof)
						return layer_exception("bridge participant migration is not justified");
				}
				else if (!bridge->transaction_hash)
					return layer_exception("bridge does not have any past withdrawals");

				auto event = executor->apply_witness_event(parent->receipt.transaction_hash, parent->receipt.transaction_hash);
				if (!event)
					return event.error();

				bool has_any = false;
				size_t offset = 0, count = 32;
				while (true)
				{
					auto results = executor->get_validator_participation_refs(participant, offset, count);
					if (!results)
						break;

					offset += results->size();
					for (auto& ref_state : *results)
					{
						auto& ref = ref_state.ref;
						if (!ref_state.active || ref.asset != bridge->ref.asset || ref.hash != bridge->ref.hash)
							continue;

						auto account = executor->get_bridge_account(ref.owner, ref.asset, ref.hash);
						if (!account)
							return account.error();

						has_any = true;
						exclusion.insert(account->group.begin(), account->group.end());
						auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(ref.owner, ref.asset, ref.hash);
						if (accounts.find(ref_hash) != accounts.end())
							return layer_exception("migration requires migration to multiple new participants");

						accounts.insert(ref_hash);
					}

					if (results->size() != count)
						break;
				}
				if (!has_any)
					return layer_exception("migrations for a participant not found");
			}

			for (auto& [attestation_asset, setup] : attestations)
			{
				if (!algorithm::asset::token_of(attestation_asset).empty())
					continue;

				auto type = setup.stake.is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock;
				auto prev_attestation = executor->get_validator_attestation(attestation_asset, executor->receipt.from).or_else(states::validator_attestation(executor->receipt.from, attestation_asset, nullptr));
				auto next_attestation = executor->apply_validator_attestation(attestation_asset, executor->receipt.from, type, setup.stake, setup.min_fee.or_else(prev_attestation.min_fee));
				if (!next_attestation)
					return next_attestation.error();
			}

			for (auto& [bridge_asset, setup] : bridges)
			{
				if (!algorithm::asset::token_of(bridge_asset).empty())
					continue;

				auto distribution = executor->calculate_random(executor->receipt.transaction_hash);
				if (!distribution)
					return distribution.error();

				auto cost = (uint64_t)ledger::gas_cost::write_tx_byte;
				auto payment = executor->burn_gas(cost * cost * cost * (1 + (protocol::now().policy.participation.max_per_account - setup.security_level)));
				if (!payment)
					return payment.error();

				auto instance = executor->apply_bridge_instance(bridge_asset, distribution->derive(), setup.security_level, setup.fee_rate);
				if (!instance)
					return instance.error();
			}

			bool requires_self_migration = false;
			auto participation_type = participation ? (participation->is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock) : ledger::executor_context::staker::reward_or_penalty;
			if (participation_type != ledger::executor_context::staker::reward_or_penalty)
			{
				auto type = participation->is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock;
				if (type == ledger::executor_context::staker::unlock)
				{
					bool has_any = false;
					size_t offset = 0, count = 32;
					while (true)
					{
						auto results = executor->get_validator_participation_refs(executor->receipt.from, offset, count);
						if (!results)
							break;

						offset += results->size();
						for (auto& ref_state : *results)
						{
							auto& ref = ref_state.ref;
							if (!ref_state.active)
								continue;

							auto account = executor->get_bridge_account(ref.owner, ref.asset, ref.hash);
							if (!account)
								return account.error();

							requires_self_migration = true;
							exclusion.insert(account->group.begin(), account->group.end());
							auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(ref.owner, ref.asset, ref.hash);
							if (accounts.find(ref_hash) != accounts.end())
								return layer_exception("migration requires migration to multiple new participants");

							accounts.insert(ref_hash);
							has_any = true;
						}

						if (results->size() != count)
							break;
					}

					if (!has_any)
						goto modify_participation;
					else if (!requires_self_migration)
						return layer_exception("participant migration(s) required but not found");
				}
				else
				{
				modify_participation:
					auto status = executor->apply_validator_participation(executor->receipt.from, type, *participation);
					if (!status)
						return status.error();
				}
			}

			if (production)
			{
				auto status = executor->apply_validator_production(executor->receipt.from, production->is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock, *production);
				if (!status)
					return status.error();
			}

			if (exclusion.empty())
				return expectation::met;

			auto committee = executor->calculate_participants(1, exclusion);
			if (!committee)
				return committee.error();

			auto event = executor->emit_event<setup>({ format::variable(requires_self_migration), format::variable(committee->front().owner.view()) });
			if (!event)
				return event;

			return expectation::met;
		}
		expects_promise_rt<void> setup::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto* runner_wallet = dispatcher->get_runner_wallet(executor->receipt.from);
			if (!runner_wallet)
				return expects_promise_rt<void>(expectation::met);

			bool requires_new_participant = false;
			auto new_participant = get_new_participant(executor->receipt, &requires_new_participant);
			if (!requires_new_participant)
				return expects_promise_rt<void>(expectation::met);
			else if (new_participant.empty() || executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(remote_exception("invalid new participant"));

			return coasync<expects_rt<void>>([this, executor, dispatcher, runner_wallet, new_participant]() -> expects_promise_rt<void>
			{
				auto migrations = expects_lr<vector<migration_ref>>(layer_exception());
				auto cache = dispatcher->pull_cache(executor);
				auto aggregation_state = ledger::dispatcher_context::entropy_aggregation_state();
				if (!aggregation_state.load_message(cache))
				{
					migrations = get_migration_refs(executor, executor->receipt);
					if (!migrations)
						coreturn remote_exception(std::move(migrations.error().message()));
					else if (migrations->empty())
						coreturn remote_exception("must have participations to migrate");

					for (auto& migration : *migrations)
					{
						if (migration.must_have_locally)
							continue;

						auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
						migration.account.group.erase(migration.old_participant);
						aggregation_state.participants.insert(migration.account.group.begin(), migration.account.group.end());
						aggregation_state.encrypted_shares[ref_hash] = btree_map<algorithm::pubkeyhash_t, string>();
					}

					if (aggregation_state.participants.find(new_participant) != aggregation_state.participants.end())
						coreturn remote_exception("new participant must not be present in account groups that are being migrated");
				}

				auto required_participants = aggregation_state.participants;
				required_participants.insert(new_participant);

				auto session = coawait(dispatcher->aggregate_validators(required_participants));
				if (!session)
					coreturn session.error();

				aggregation_state.public_key = dispatcher->get_public_key(new_participant);
				if (aggregation_state.public_key.empty())
				{
				postpone:
					if (++aggregation_state.attempt >= protocol::now().user.consensus.coordination_attempts)
						coreturn remote_exception("failed to coordinate participants after several retries");

					dispatcher->push_cache(executor, aggregation_state.as_message());
					coreturn remote_exception::retry_later();
				}

				btree_set<algorithm::pubkeyhash_t> deferred_participants;
				while (!aggregation_state.participants.empty())
				{
					auto result = coawait(dispatcher->aggregate_entropy_shares(executor, aggregation_state, *aggregation_state.participants.begin()));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						deferred_participants.insert(*aggregation_state.participants.begin());
					else if (!result)
						coreturn result.error();

					aggregation_state.participants.erase(aggregation_state.participants.begin());
				}

				if (!deferred_participants.empty())
				{
					aggregation_state.participants = std::move(deferred_participants);
					goto postpone;
				}

				auto tweaked_public_key = aggregation_state.public_key;
				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					coreturn remote_exception("invalid tweaked public key");

				if (!migrations)
				{
					migrations = get_migration_refs(executor, executor->receipt);
					if (!migrations)
						coreturn remote_exception(std::move(migrations.error().message()));
				}

				auto recovery_state = ledger::dispatcher_context::entropy_recovery_state();
				recovery_state.encrypted_shares = aggregation_state.encrypted_shares;
				for (auto& migration : *migrations)
				{
					if (!migration.must_have_locally)
						continue;

					auto secret = dispatcher->recover_secret_entropy(runner_wallet, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
					if (!secret)
						coreturn remote_exception(std::move(secret.error().message()));

					uint256_t entropy = algorithm::hashing::hash256i(*crypto::random_bytes(64));
					auto encrypted_entropy = algorithm::signing::public_encrypt(tweaked_public_key, secret->as_message().data, entropy);
					if (!encrypted_entropy)
						coreturn remote_exception("participant entropy encryption failed");

					recovery_state.encrypted_entropies[secret->as_ref_hash()] = std::move(*encrypted_entropy);
				}

				auto result = coawait(dispatcher->recover_entropy(executor, recovery_state, new_participant));
				if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					goto postpone;
				else if (!result)
					coreturn result.error();

				auto* transaction = memory::init<migrate>();
				transaction->asset = asset;
				transaction->setup_hash = executor->receipt.transaction_hash;
				transaction->proof = recovery_state.proof;
				dispatcher->emit_transaction(runner_wallet, transaction);
				coreturn expects_promise_rt<void>(expectation::met);
			});
		}
		bool setup::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint8_t)migrations.size());
			for (auto& [broadcast_hash, participant] : migrations)
			{
				stream->write_integer(broadcast_hash);
				stream->write_string(participant.optimized_view());
			}
			stream->write_integer((uint8_t)attestations.size());
			for (auto& [attestation_asset, setup] : attestations)
			{
				stream->write_integer(attestation_asset);
				stream->write_decimal(setup.stake);
				stream->write_boolean(!!setup.min_fee);
				if (setup.min_fee)
					stream->write_decimal(*setup.min_fee);
			}
			stream->write_integer((uint8_t)bridges.size());
			for (auto& [bridge_asset, setup] : bridges)
			{
				stream->write_integer(bridge_asset);
				stream->write_integer(setup.security_level);
				stream->write_decimal(setup.fee_rate);
			}
			stream->write_boolean(!!participation);
			if (participation)
				stream->write_decimal(*participation);
			stream->write_boolean(!!production);
			if (production)
				stream->write_decimal(*production);
			return true;
		}
		bool setup::load_body(format::ro_stream& stream)
		{
			uint8_t migrations_size = 0;
			if (!stream.read_integer(stream.read_type(), &migrations_size))
				return false;

			migrations.clear();
			for (uint16_t i = 0; i < migrations_size; i++)
			{
				uint256_t broadcast_hash;
				if (!stream.read_integer(stream.read_type(), &broadcast_hash))
					return false;

				algorithm::pubkeyhash_t participant; string participant_assembly;
				if (!stream.read_string(stream.read_type(), &participant_assembly) || !algorithm::encoding::decode_bytes(participant_assembly, participant.blob, sizeof(participant)))
					return false;

				migrations[broadcast_hash] = participant;
			}

			uint8_t attestations_size = 0;
			if (!stream.read_integer(stream.read_type(), &attestations_size))
				return false;

			attestations.clear();
			for (uint16_t i = 0; i < attestations_size; i++)
			{
				algorithm::asset_id attestation_asset;
				if (!stream.read_integer(stream.read_type(), &attestation_asset))
					return false;

				attestation_setup setup;
				if (!stream.read_decimal(stream.read_type(), &setup.stake))
					return false;

				bool has_min_fee;
				if (!stream.read_boolean(stream.read_type(), &has_min_fee))
					return false;

				if (has_min_fee)
				{
					setup.min_fee = decimal::zero();
					if (!stream.read_decimal(stream.read_type(), setup.min_fee.address()))
						return false;
				}

				attestations[attestation_asset] = std::move(setup);
			}

			uint8_t bridges_size = 0;
			if (!stream.read_integer(stream.read_type(), &bridges_size))
				return false;

			bridges.clear();
			for (uint16_t i = 0; i < bridges_size; i++)
			{
				algorithm::asset_id bridge_asset;
				if (!stream.read_integer(stream.read_type(), &bridge_asset))
					return false;

				bridge_setup setup;
				if (!stream.read_integer(stream.read_type(), &setup.security_level))
					return false;

				if (!stream.read_decimal(stream.read_type(), &setup.fee_rate))
					return false;

				bridges[bridge_asset] = std::move(setup);
			}

			bool has_participation;
			if (!stream.read_boolean(stream.read_type(), &has_participation))
				return false;

			if (has_participation)
			{
				participation = decimal::nan();
				if (!stream.read_decimal(stream.read_type(), participation.address()))
					return false;
			}
			else
				participation = optional::none;

			bool has_production;
			if (!stream.read_boolean(stream.read_type(), &has_production))
				return false;

			if (has_production)
			{
				production = decimal::nan();
				if (!stream.read_decimal(stream.read_type(), production.address()))
					return false;
			}
			else
				production = optional::none;

			return true;
		}
		bool setup::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& [broadcast_hash, participant] : migrations)
				parties.insert(participant);

			auto participant = get_new_participant(receipt);
			if (!participant.empty())
				parties.insert(participant);

			return true;
		}
		void setup::allocate_production_stake(const decimal& value)
		{
			production = value;
		}
		void setup::disable_production()
		{
			production = decimal::nan();
		}
		void setup::standby_on_production()
		{
			production = optional::none;
		}
		void setup::allocate_participation_stake(const decimal& value)
		{
			participation = value;
		}
		void setup::disable_participation()
		{
			participation = decimal::nan();
		}
		void setup::standby_on_participation()
		{
			participation = optional::none;
		}
		void setup::allocate_attestation_stake(const algorithm::asset_id& new_asset, const decimal& new_value, const decimal& new_min_fee)
		{
			auto& attestation = attestations[new_asset];
			attestation.stake = new_value;
			if (!new_min_fee.is_nan())
				attestation.min_fee = new_min_fee;
			else
				attestation.min_fee = optional::none;
		}
		void setup::disable_attestation(const algorithm::asset_id& new_asset)
		{
			attestations[new_asset].stake = decimal::nan();
		}
		void setup::standby_on_attestation(const algorithm::asset_id& new_asset)
		{
			attestations.erase(new_asset);
		}
		void setup::allocate_bridge(const algorithm::asset_id& new_asset, uint8_t new_security_level, const decimal& new_fee_rate)
		{
			auto& bridge = bridges[new_asset];
			bridge.fee_rate = new_fee_rate;
			bridge.security_level = new_security_level;
		}
		void setup::unset_bridge(const algorithm::asset_id& new_asset)
		{
			bridges.erase(new_asset);
		}
		void setup::migrate_participant(const uint256_t& broadcast_hash, const algorithm::pubkeyhash_t& participant)
		{
			migrations[broadcast_hash] = participant;
		}
		void setup::clear_migration(const uint256_t& broadcast_hash)
		{
			migrations.erase(broadcast_hash);
		}
		bool setup::is_dispatchable() const
		{
			return true;
		}
		expects_lr<vector<setup::migration_ref>> setup::get_migration_refs(const ledger::executor_context* executor, const ledger::transaction_receipt& receipt) const
		{
			vector<migration_ref> results;
			auto* event = receipt.find_event<setup>();
			if (!event || event->size() != 2)
				return expects_lr<vector<migration_ref>>(std::move(results));

			bool requires_self_migration = event->front().as_boolean();
			if (!requires_self_migration && migrations.empty())
				return expects_lr<vector<migration_ref>>(std::move(results));

			if (requires_self_migration)
			{
				size_t offset = 0, count = 32;
				while (true)
				{
					auto subresults = executor->get_validator_participation_refs(executor->receipt.from, offset, count);
					if (!subresults)
						break;

					offset += subresults->size();
					for (auto& ref_state : *subresults)
					{
						auto& ref = ref_state.ref;
						if (!ref_state.active)
							continue;
						
						auto account = executor->get_bridge_account(ref.owner, ref.asset, ref.hash);
						if (!account)
							return account.error();

						migration_ref migration;
						migration.account = std::move(*account);
						migration.old_participant = receipt.from;
						migration.must_have_locally = true;
						results.push_back(std::move(migration));
					}

					if (subresults->size() != count)
						break;
				}
			}

			for (auto& [broadcast_hash, participant] : migrations)
			{
				auto event = executor->get_witness_event(broadcast_hash);
				if (!event || event->child_transaction_hash != broadcast_hash)
					continue;

				auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
				if (!parent)
					return layer_exception("broadcast transaction not found");

				auto origin = executor->get_block_transaction<withdraw>(((broadcast*)*parent->transaction)->withdraw_hash, true);
				if (!origin)
					return layer_exception("withdraw transaction not found");

				auto bridge = executor->get_bridge_instance(algorithm::asset::base_id_of(origin->transaction->asset), ((withdraw*)*origin->transaction)->bridge_hash);
				if (!bridge)
					return bridge.error();

				bool has_any = false;
				size_t offset = 0, count = 32;
				while (true)
				{
					auto subresults = executor->get_validator_participation_refs(participant, offset, count);
					if (!subresults)
						break;

					offset += subresults->size();
					for (auto& ref_state : *subresults)
					{
						auto& ref = ref_state.ref;
						if (!ref_state.active || ref.asset != bridge->ref.asset || ref.hash != bridge->ref.hash)
							continue;

						auto account = executor->get_bridge_account(ref.owner, ref.asset, ref.hash);
						if (!account)
							return account.error();

						migration_ref migration;
						migration.account = std::move(*account);
						migration.old_participant = participant;
						migration.must_have_locally = false;
						results.push_back(std::move(migration));
						has_any = true;
					}

					if (subresults->size() != count)
						break;
				}
				if (!has_any)
					return layer_exception("invalid migration participant");
			}

			return expects_lr<vector<migration_ref>>(std::move(results));
		}
		algorithm::pubkeyhash_t setup::get_new_participant(const ledger::transaction_receipt& receipt, bool* requires_new_participant) const
		{
			auto new_participant = algorithm::pubkeyhash_t();
			auto* event = receipt.find_event<setup>();
			if (event && event->size() == 2 && event->back().as_string().size() == sizeof(algorithm::pubkeyhash_t))
				new_participant = algorithm::pubkeyhash_t(event->back().as_blob());
			if (requires_new_participant != nullptr)
				*requires_new_participant = event != nullptr;
			return new_participant;
		}
		format::tree setup::as_tree() const
		{
			format::tree data = ledger::transaction_message::as_tree();
			if (!migrations.empty())
			{
				auto* migrations_data = data.set("bridge_migrations", format::tree::list());
				for (auto& [broadcast_hash, participant] : migrations)
				{
					auto* migration_data = migrations_data->push(format::tree::map());
					migration_data->set("broadcast_hash", format::variable(algorithm::encoding::encode_0xhex256(broadcast_hash)));
					migration_data->set("participant", algorithm::signing::serialize_address(participant));
				}
			}
			if (!attestations.empty())
			{
				auto* attestations_data = data.set("attestations", format::tree::list());
				for (auto& [attestation_asset, setup] : attestations)
				{
					auto* attestation_data = attestations_data->push(format::tree::map());
					attestation_data->set("asset", algorithm::asset::serialize(attestation_asset));
					attestation_data->set("stake", format::variable(setup.stake));
					attestation_data->set("min_fee", setup.min_fee ? format::variable(*setup.min_fee) : format::variable());
				}
			}
			if (!bridges.empty())
			{
				auto* bridges_data = data.set("bridges", format::tree::list());
				for (auto& [bridge_asset, setup] : bridges)
				{
					auto* bridge_data = bridges_data->push(format::tree::map());
					bridge_data->set("asset", algorithm::asset::serialize(bridge_asset));
					bridge_data->set("security_level", format::variable(setup.security_level));
					bridge_data->set("fee_rate", format::variable(setup.fee_rate));
				}
			}
			if (participation)
				data.set("bridge_participation", participation->is_zero() || participation->is_positive() ? format::variable(*participation) : format::variable(false));
			if (production)
				data.set("block_production", production->is_zero() || production->is_positive() ? format::variable(*production) : format::variable(false));
			return data;
		}
		uint32_t setup::as_type() const
		{
			return as_instance_type();
		}
		std::string_view setup::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t setup::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view setup::as_instance_typename()
		{
			return "setup";
		}

		expects_lr<void> migrate::validate(uint64_t block_number) const
		{
			if (!setup_hash)
				return layer_exception("invalid setup transaction");

			if (proof.empty())
				return layer_exception("invalid proof");

			return ledger::commitment_message::validate(block_number);
		}
		expects_lr<void> migrate::execute(ledger::executor_context* executor) const
		{
			auto validation = ledger::commitment_message::execute(executor);
			if (!validation)
				return validation.error();

			auto event = executor->apply_witness_event(setup_hash, executor->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto parent = executor->get_block_transaction<setup>(setup_hash);
			if (!parent)
				return layer_exception("setup transaction not found");

			auto* parent_transaction = (setup*)*parent->transaction;
			if (parent->receipt.from != executor->receipt.from)
				return layer_exception("setup transaction not applicable");

			uint8_t transaction_hash_data[32];
			parent->receipt.transaction_hash.encode(transaction_hash_data);

			auto proof_hash = algorithm::hashing::hash256i(transaction_hash_data, sizeof(transaction_hash_data));
			algorithm::pubkeyhash_t new_participant_check;
			algorithm::pubkeyhash_t new_participant = parent_transaction->get_new_participant(parent->receipt);
			if (!algorithm::signing::recover_hash(proof_hash, new_participant_check, proof) || new_participant != new_participant_check)
				return layer_exception("new participant proof not valid");

			auto migrations = parent_transaction->get_migration_refs(executor, parent->receipt);
			if (!migrations)
				return migrations.error();

			for (auto& migration : *migrations)
			{
				auto account = executor->get_bridge_account(migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
				if (!account)
					return account.error();

				size_t prev_size = account->group.size();
				account->group.erase(migration.old_participant);
				account->group.insert(new_participant);
				if (prev_size != account->group.size())
					return layer_exception("conflicting group migration (size changed)");

				account = executor->apply_bridge_account(account->ref.owner, account->ref.asset, account->ref.hash, account->public_key, std::move(account->group));
				if (!account)
					return account.error();

				auto status = executor->apply_validator_participation_ref(migration.old_participant, account->ref, false);
				if (!status)
					return status.error();

				status = executor->apply_validator_participation_ref(new_participant, account->ref, true);
				if (!status)
					return status.error();
			}

			return expectation::met;
		}
		bool migrate::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(setup_hash);
			stream->write_string(proof.optimized_view());
			return true;
		}
		bool migrate::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &setup_hash))
				return false;

			string proof_assembly;
			if (!stream.read_string(stream.read_type(), &proof_assembly) || !algorithm::encoding::decode_bytes(proof_assembly, proof.blob, sizeof(proof)))
				return false;

			return true;
		}
		format::tree migrate::as_tree() const
		{
			format::tree data = ledger::commitment_message::as_tree();
			data.set("setup_hash", format::variable(algorithm::encoding::encode_0xhex256(setup_hash)));
			data.set("proof", proof.empty() ? format::variable() : format::variable(format::util::encode_0xhex(proof.view())));
			return data;
		}
		uint32_t migrate::as_type() const
		{
			return as_instance_type();
		}
		std::string_view migrate::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t migrate::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view migrate::as_instance_typename()
		{
			return "migrate";
		}

		expects_lr<void> route::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!bridge_hash)
				return layer_exception("invalid bridge hash");

			return ledger::commitment_message::validate(block_number);
		}
		expects_lr<void> route::execute(ledger::executor_context* executor) const
		{
			auto validation = ledger::commitment_message::execute(executor);
			if (!validation)
				return validation.error();

			auto* params = superchain::bridge::get()->get_network_params(asset);
			if (!params)
				return layer_exception("invalid operation");

			bool routing_address_application = !routing_address.empty();
			if (routing_address_application)
			{
				auto collision = executor->get_witness_account_tagged(asset, routing_address, 0);
				if (collision)
					return layer_exception("routing account address " + routing_address + " taken");

				auto status = executor->apply_witness_routing_account(executor->receipt.from, asset, { { (uint8_t)1, string(routing_address) } });
				if (!status)
					return status.error();
			}

			auto bridge = executor->get_bridge_instance(asset, bridge_hash);
			if (!bridge)
				return bridge.error();

			switch (params->routing)
			{
				case superchain::routing_policy::account:
				{
					if (!bridge->account_nonce)
						break;
					
					return routing_address_application ? expects_lr<void>(expectation::met) : expects_lr<void>(layer_exception("only one initiator bridge account may exist"));
				}
				case superchain::routing_policy::memo:
				{
					if (!bridge->account_nonce)
						break;

					auto initiator_account = executor->get_bridge_account(bridge->ref.owner, asset, bridge->ref.hash);
					if (!initiator_account || initiator_account->public_key.empty() || initiator_account->group.empty() || initiator_account->ref.owner != bridge->ref.owner || initiator_account->ref.asset != bridge->ref.asset || initiator_account->ref.hash != bridge->ref.hash)
						return layer_exception("initiator bridge account required");

					size_t offset = 0, count = 32;
					while (true)
					{
						auto duplicates = executor->get_witness_accounts_by_purpose(executor->receipt.from, states::witness_account::account_type::bridge, 0, count);
						if (!duplicates)
							break;

						auto it = std::find_if(duplicates->begin(), duplicates->end(), [&](const states::witness_account& account) { return account.ref.owner == executor->receipt.from && account.ref.asset == asset && account.ref.hash == bridge_hash && account.active; });
						if (it != duplicates->end())
							return routing_address_application ? expects_lr<void>(expectation::met) : expects_lr<void>(layer_exception("bridge account already bound to this account"));

						offset += duplicates->size();
						if (duplicates->size() != count)
							break;
					}

					auto* chain = superchain::bridge::get()->get_network(asset);
					if (!chain)
						return layer_exception("invalid operation");

					auto encoded_public_key = chain->encode_public_key(std::string_view((char*)initiator_account->public_key.data(), initiator_account->public_key.size()));
					if (!encoded_public_key)
						return encoded_public_key.error();

					auto addresses = chain->to_addresses(*encoded_public_key);
					if (!addresses)
						return addresses.error();

					for (auto& address : *addresses)
						address.second = superchain::address_util::encode_tag_address(address.second, to_string(bridge->account_nonce));

					auto policy_status = executor->apply_bridge_instance_account(asset, bridge_hash, executor->receipt.from);
					if (!policy_status)
						return policy_status.error();

					auto witness_account_status = executor->apply_witness_bridge_account(executor->receipt.from, asset, bridge_hash, *addresses);
					if (!witness_account_status)
						return witness_account_status.error();

					return expectation::met;
				}
				case superchain::routing_policy::utxo:
				{
					auto duplicate = executor->get_bridge_account(executor->receipt.from, asset, bridge_hash);
					if (!duplicate)
						break;

					return routing_address_application ? expects_lr<void>(expectation::met) : expects_lr<void>(layer_exception("bridge account already bound to this account"));
				}
				default:
					return layer_exception("invalid operation");
			}

			btree_set<algorithm::pubkeyhash_t> exclusion;
			auto attesters = executor->calculate_attesters(asset, 1, decimal::nan(), exclusion);
			if (!attesters)
				return attesters.error();

			exclusion.insert(attesters->front().owner);
			auto event = executor->emit_event<route>({ format::variable(attesters->front().owner.view()) });
			if (!event)
				return event;

			auto participants = executor->calculate_participants(bridge->security_level, exclusion);
			if (!participants)
				return participants.error();

			for (auto& target : *participants)
			{
				auto event = executor->emit_event<route>({ format::variable(target.owner.view()) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> route::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto attester = get_attester(executor->receipt);
			auto* runner_wallet = attester.empty() ? nullptr : dispatcher->get_runner_wallet(attester);
			if (!runner_wallet)
				return expects_promise_rt<void>(expectation::met);
			else if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, executor, dispatcher, runner_wallet]() -> expects_promise_rt<void>
			{
				auto* chain = superchain::bridge::get()->get_network_params(asset);
				if (!chain)
					coreturn remote_exception("invalid operation");

				uint8_t message_hash[32];
				challenge(executor->receipt.transaction_hash, message_hash);

				size_t required_public_keys = 0;
				auto cache = dispatcher->pull_cache(executor);
				auto group = get_participants(executor->receipt);
				auto state = ledger::dispatcher_context::public_state();
				if (!state.load(cache))
				{
					auto compositor = algorithm::composition::make_public_key_compositor(chain->composition, message_hash, sizeof(message_hash), (uint16_t)group.size());
					if (!compositor)
						coreturn remote_exception(std::move(compositor.error().message()));

					state.compositor = std::move(*compositor);
					state.participants = group;
					state.alg = chain->composition;
					required_public_keys = state.participants.size();
				}

				auto session = coawait(dispatcher->aggregate_validators(state.participants));
				if (!session)
					coreturn session.error();

				if (required_public_keys > 0)
				{
					if (state.participants.size() != required_public_keys)
					{
					postpone:
						if (++state.attempt >= protocol::now().user.consensus.coordination_attempts)
							coreturn remote_exception("failed to coordinate participants after several retries");

						dispatcher->push_cache(executor, state.as_message());
						coreturn remote_exception::retry_later();
					}

					for (auto& participant : state.participants)
					{
						auto public_key = dispatcher->get_public_key(participant);
						if (public_key.empty())
							goto postpone;

						if (state.encrypted_shares.find(public_key) == state.encrypted_shares.end())
							state.encrypted_shares[public_key] = btree_map<algorithm::pubkeyhash_t, string>();
					}
				}

				bool reset = false;
				auto chosen = group.begin();
				auto unavailable = btree_set<algorithm::pubkeyhash_t>();
				std::advance(chosen, (size_t)(algorithm::hashing::hash256i(message_hash, sizeof(message_hash)) % uint256_t(group.size())));
				while (!state.distribution)
				{
					auto phase = state.compositor->next_phase();
					if (!reset && (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset))
					{
						state.participants = group;
						reset = true;
					}

					bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
					bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
					auto it = (uniform_input ? state.participants.begin() : (chosen_input ? state.participants.find(*chosen) : state.participants.end()));
					it = (!chosen_input && state.participants.size() > 1 && it != state.participants.end() && it->equals(*chosen) ? ++it : it);
					if (it == state.participants.end())
						break;

					auto result = coawait(dispatcher->aggregate_public_key(executor, state, *it));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					{
						unavailable.insert(*it);
						if (chosen_input)
							goto postpone;
					}
					else if (!result)
						coreturn result.error();
					else
						reset = false;

					state.participants.erase(it);
				}

				state.distribution = unavailable.empty();
				state.participants = std::move(group);
				if (!unavailable.empty())
				{
					state.participants = std::move(unavailable);
					goto postpone;
				}

				algorithm::composition::cpubkey_t aggregated_public_key;
				auto status = state.compositor->to_public_key(&aggregated_public_key);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				algorithm::composition::chashsig_t aggregated_signature;
				status = state.compositor->to_signature(&aggregated_signature);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				auto distribution_state = ledger::dispatcher_context::entropy_distribution_state();
				while (!state.participants.empty())
				{
					auto target = state.encrypted_shares.end();
					distribution_state.encrypted_shares.clear();
					for (auto it = state.encrypted_shares.begin(); it != state.encrypted_shares.end(); it++)
					{
						algorithm::pubkeyhash_t participant;
						algorithm::signing::derive_public_key_hash(it->first, participant);
						if (participant == *state.participants.begin())
						{
							distribution_state.encrypted_shares = it->second;
							target = it;
							break;
						}
					}
					if (target == state.encrypted_shares.end())
						coreturn remote_exception("participant requires group shares but none were shared");
					else if (distribution_state.encrypted_shares.empty())
						coreturn remote_exception("participant requires group shares but none were found");

					auto result = coawait(dispatcher->distribute_entropy_shares(executor, distribution_state, *state.participants.begin()));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						unavailable.insert(*state.participants.begin());
					else if (!result)
						coreturn result.error();

					state.participants.erase(state.participants.begin());
				}

				if (!unavailable.empty())
				{
					state.participants = std::move(unavailable);
					goto postpone;
				}

				auto* transaction = memory::init<bind>();
				transaction->asset = asset;
				transaction->set_witness(executor->receipt.transaction_hash, std::move(aggregated_public_key), std::move(aggregated_signature));
				dispatcher->emit_transaction(runner_wallet, transaction);
				coreturn expectation::met;
			});
		}
		bool route::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(bridge_hash);
			stream->write_string(routing_address);
			return true;
		}
		bool route::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &bridge_hash))
				return false;

			if (!stream.read_string(stream.read_type(), &routing_address))
				return false;

			return true;
		}
		bool route::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto attester = get_attester(receipt);
			if (!attester.empty())
				parties.insert(attester);

			auto participants = get_participants(receipt);
			parties.insert(participants.begin(), participants.end());
			return true;
		}
		bool route::is_dispatchable() const
		{
			return true;
		}
		void route::set_routing_address(const std::string_view& new_address)
		{
			routing_address = new_address;
		}
		void route::set_bridge_hash(const uint256_t& new_bridge_hash)
		{
			bridge_hash = new_bridge_hash;
		}
		algorithm::pubkeyhash_t route::get_attester(const ledger::transaction_receipt& receipt) const
		{
			auto* event = receipt.find_event<route>();
			if (event != nullptr && !event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
				return algorithm::pubkeyhash_t(event->front().as_blob());

			return algorithm::pubkeyhash_t();
		}
		btree_set<algorithm::pubkeyhash_t> route::get_participants(const ledger::transaction_receipt& receipt) const
		{
			btree_set<algorithm::pubkeyhash_t> result;
			auto events = receipt.find_events<route>();
			for (size_t i = 1; i < events.size(); i++)
			{
				auto& event = events[i];
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result.insert(algorithm::pubkeyhash_t(event->front().as_blob()));
			}
			return result;
		}
		format::tree route::as_tree() const
		{
			format::tree data = ledger::commitment_message::as_tree();
			data.set("bridge_hash", algorithm::encoding::serialize_uint256(bridge_hash));
			data.set("routing_address", format::variable(routing_address));
			return data;
		}
		uint32_t route::as_type() const
		{
			return as_instance_type();
		}
		std::string_view route::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t route::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view route::as_instance_typename()
		{
			return "route";
		}
		void route::challenge(const uint256_t& route_hash, uint8_t message_hash[32])
		{
			VI_ASSERT(message_hash != nullptr, "message hash should be set");
			uint8_t transaction_hash[32];
			route_hash.encode(transaction_hash);
			algorithm::hashing::hash256(transaction_hash, sizeof(transaction_hash), message_hash);
		}

		expects_lr<void> bind::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!route_hash)
				return layer_exception("invalid route hash");

			if (group_public_key.empty())
				return layer_exception("invalid group public key");

			if (group_signature.empty())
				return layer_exception("invalid group signature");

			auto* chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto compositor = algorithm::composition::make_compositor(chain->composition);
			if (!compositor)
				return compositor.error();

			uint8_t message_hash[32];
			route::challenge(route_hash, message_hash);

			auto& compositor_ptr = *compositor;
			auto status = compositor_ptr->verify_signature(message_hash, sizeof(message_hash), group_signature, group_public_key);
			if (!status)
				return status;

			return ledger::commitment_message::validate(block_number);
		}
		expects_lr<void> bind::execute(ledger::executor_context* executor) const
		{
			auto validation = ledger::commitment_message::execute(executor);
			if (!validation)
				return validation.error();

			auto event = executor->apply_witness_event(route_hash, executor->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto parent = executor->get_block_transaction<route>(route_hash);
			if (!parent)
				return parent.error();

			auto* parent_transaction = (route*)*parent->transaction;
			auto* offchain = superchain::bridge::get();
			auto* chain = offchain->get_network(asset);
			auto* params = offchain->get_network_params(asset);
			if (!chain || !params)
				return layer_exception("invalid operation");

			auto duplicate = executor->get_bridge_account(parent->receipt.from, asset, parent_transaction->bridge_hash);
			if (duplicate)
				return layer_exception("bridge account already exists");

			auto encoded_public_key = chain->encode_public_key(std::string_view((char*)group_public_key.data(), group_public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto addresses = chain->to_addresses(*encoded_public_key);
			if (!addresses)
				return addresses.error();

			auto bridge = executor->get_bridge_instance(asset, parent_transaction->bridge_hash);
			if (!bridge)
				return bridge.error();

			switch (params->routing)
			{
				case superchain::routing_policy::account:
				case superchain::routing_policy::memo:
				{
					if (bridge->account_nonce > 0)
						return layer_exception("too many accounts for a bridge");

					if (params->routing == superchain::routing_policy::account)
						break;

					for (auto& address : *addresses)
						address.second = superchain::address_util::encode_tag_address(address.second, to_string(bridge->account_nonce));
					break;
				}
				default:
					break;
			}

			auto ref = states::bridge_ref();
			ref.owner = parent->receipt.from;
			ref.asset = asset;
			ref.hash = parent_transaction->bridge_hash;

			auto policy_status = executor->apply_bridge_instance_account(ref.asset, ref.hash, ref.owner);
			if (!policy_status)
				return policy_status.error();

			auto participants = parent_transaction->get_participants(parent->receipt);
			for (auto& participant : participants)
			{
				auto status = executor->apply_validator_participation_ref(participant, ref, true);
				if (!status)
					return status.error();
			}

			auto bridge_account_status = executor->apply_bridge_account(ref.owner, ref.asset, ref.hash, group_public_key, std::move(participants));
			if (!bridge_account_status)
				return bridge_account_status.error();

			auto witness_account_status = executor->apply_witness_bridge_account(ref.owner, ref.asset, ref.hash, *addresses);
			if (!witness_account_status)
				return witness_account_status.error();

			auto link_asset = asset;
			auto link_base = superchain::wallet_link(parent_transaction->bridge_hash, *encoded_public_key, string());
			executor->defer_side_effect([link_asset, link_base = std::move(link_base), addresses = std::move(addresses)]() mutable
			{
				auto* offchain = superchain::bridge::get();
				for (auto& [type, address] : *addresses)
				{
					auto [base_address, tag] = superchain::address_util::decode_tag_address(address);
					if (base_address != address)
						offchain->enable_link(link_asset, superchain::wallet_link(link_base.hash, link_base.public_key, base_address)).report("failed to enable the off-chain link");

					offchain->enable_link(link_asset, superchain::wallet_link(link_base.hash, link_base.public_key, address)).report("failed to enable the off-chain link");
				}
			});
			return expectation::met;
		}
		void bind::set_witness(const uint256_t& new_route_hash, algorithm::composition::cpubkey_t&& new_group_public_key, algorithm::composition::chashsig_t&& new_group_signature)
		{
			route_hash = new_route_hash;
			group_public_key = std::move(new_group_public_key);
			group_signature = std::move(new_group_signature);
		}
		bool bind::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(std::string_view((char*)group_public_key.data(), group_public_key.size()));
			stream->write_string(std::string_view((char*)group_signature.data(), group_signature.size()));
			stream->write_integer(route_hash);
			return true;
		}
		bool bind::load_body(format::ro_stream& stream)
		{
			string group_public_key_assembly;
			if (!stream.read_string(stream.read_type(), &group_public_key_assembly))
				return false;

			string group_signature_assembly;
			if (!stream.read_string(stream.read_type(), &group_signature_assembly))
				return false;

			if (!stream.read_integer(stream.read_type(), &route_hash))
				return false;

			group_public_key.resize(group_public_key_assembly.size());
			group_signature.resize(group_signature_assembly.size());
			memcpy(group_public_key.data(), group_public_key_assembly.data(), group_public_key_assembly.size());
			memcpy(group_signature.data(), group_signature_assembly.data(), group_signature_assembly.size());
			return true;
		}
		bool bind::recover_many(const ledger::executor_context* executor, const ledger::transaction_receipt&, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = executor->get_block_transaction<route>(route_hash);
			if (parent)
				parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));

			return true;
		}
		format::tree bind::as_tree() const
		{
			format::tree data = ledger::commitment_message::as_tree();
			data.set("route_hash", route_hash > 0 ? format::variable(algorithm::encoding::encode_0xhex256(route_hash)) : format::variable());
			data.set("group_public_key", format::variable(format::util::encode_0xhex(std::string_view((char*)group_public_key.data(), group_public_key.size()))));
			data.set("group_signature", format::variable(format::util::encode_0xhex(std::string_view((char*)group_signature.data(), group_signature.size()))));
			return data;
		}
		uint32_t bind::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bind::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bind::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bind::as_instance_typename()
		{
			return "bind";
		}

		expects_lr<void> withdraw::validate(uint64_t block_number) const
		{
			if (!bridge_hash)
				return layer_exception("invalid bridge hash");

			auto* chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (!algorithm::asset::is_aux(asset))
				return layer_exception("not a valid withdrawal asset");

			if (address.empty())
				return layer_exception("invalid routing address");

			if (!value.is_positive())
				return layer_exception("invalid value");

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> withdraw::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			auto bridge = executor->get_bridge_instance(asset, bridge_hash);
			if (!bridge)
				return bridge.error();

			btree_set<algorithm::pubkeyhash_t> exclusion;
			auto fee_asset = algorithm::asset::base_id_of(asset);
			auto attesters = executor->calculate_attesters(fee_asset, 1, bridge->fee_rate, exclusion);
			if (!attesters)
				return attesters.error();

			auto event = executor->emit_event<withdraw>({ format::variable(attesters->front().owner.view()) });
			if (!event)
				return event;

			auto token_value = value;
			if (fee_asset != asset)
			{
				auto balance_requirement = executor->verify_transfer_balance(fee_asset, bridge->fee_rate);
				if (!balance_requirement)
					return balance_requirement.error();

				auto fee_balance = executor->get_bridge_balance(fee_asset, bridge_hash);
				if (!fee_balance || fee_balance->supply < bridge->fee_rate)
					return layer_exception(algorithm::asset::handle_of(fee_asset) + " balance is insufficient to cover base withdrawal value (value: " + bridge->fee_rate.to_string() + ")");
			}
			else
				token_value += bridge->fee_rate;

			auto balance_requirement = executor->verify_transfer_balance(asset, token_value);
			if (!balance_requirement)
				return balance_requirement;

			auto token_balance = executor->get_bridge_balance(asset, bridge_hash);
			if (!token_balance || token_balance->supply < token_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient to cover token withdrawal value (value: " + token_value.to_string() + ")");

			auto collision = executor->get_witness_account_tagged(fee_asset, address, 0);
			if (!collision)
				collision = executor->apply_witness_routing_account(executor->receipt.from, asset, { { (uint8_t)1, string(address) } });
			if (!collision)
				return collision.error();
			else if (!collision->is_routing_account() || collision->ref.owner != executor->receipt.from)
				return layer_exception("invalid routing address");

			if (fee_asset != asset)
			{
				auto fee_transfer = executor->apply_transfer(fee_asset, executor->receipt.from, decimal::zero(), bridge->fee_rate);
				if (!fee_transfer)
					return fee_transfer.error();
			}

			auto token_transfer = executor->apply_transfer(asset, executor->receipt.from, decimal::zero(), token_value);
			if (!token_transfer)
				return token_transfer.error();

			auto queue = executor->apply_bridge_queue(asset, bridge_hash, executor->receipt.transaction_hash, true);
			if (!queue)
				return queue.error();

			return expectation::met;
		}
		expects_promise_rt<void> withdraw::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto attester = get_attester(executor->receipt);
			auto* runner_wallet = attester.empty() ? nullptr : dispatcher->get_runner_wallet(attester);
			if (!runner_wallet)
				return expects_promise_rt<void>(expectation::met);

			if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto front = executor->get_bridge_queue(asset, bridge_hash);
			if (front && front->transaction_hash != executor->receipt.transaction_hash)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, dispatcher, runner_wallet]() mutable -> expects_promise_rt<void>
			{
				auto* chain = superchain::bridge::get()->get_network_params(asset);
				auto cancel = [this, executor, dispatcher, runner_wallet](remote_exception&& error) -> expects_rt<void>
				{
					auto* transaction = memory::init<broadcast>();
					transaction->asset = asset;
					transaction->set_proof(executor->receipt.transaction_hash, layer_exception(std::move(remote_exception(error).message())));
					dispatcher->emit_transaction(runner_wallet, transaction);
					return expects_rt<void>(std::move(error));
				};

				auto bridge = executor->get_bridge_instance(asset, bridge_hash);
				if (!bridge)
					coreturn cancel(remote_exception(std::move(bridge.error().message())));

				auto cache = dispatcher->pull_cache(executor);
				auto state = ledger::dispatcher_context::signature_state();
				if (chain->transaction_expires || !state.load(cache))
				{
					auto message = coawait(resolver::prepare_transaction(algorithm::asset::base_id_of(asset), superchain::wallet_link::from_hash(bridge_hash), superchain::value_transfer(asset, address, decimal(value)), bridge->fee_rate));
					if (!message)
						coreturn message.error().is_retry() || message.error().is_shutdown() ? expects_rt<void>(std::move(message.error())) : cancel(std::move(message.error()));
					else if (message->inputs.size() > std::numeric_limits<uint8_t>::max())
						coreturn cancel(remote_exception("too many prepared inputs"));

					state.message = memory::init<superchain::prepared_transaction>(std::move(*message));
				}

				auto finalization = expects_lr<superchain::finalized_transaction>(layer_exception());
				auto result = expects_rt<void>(remote_exception::shutdown());
				auto* input = state.message->next_input_for_aggregation();
				while (input != nullptr)
				{
					auto witness = executor->get_witness_account_tagged(asset, input->utxo.link.address, 0);
					if (!witness)
						coreturn cancel(remote_exception(std::move(witness.error().message())));

					auto account = executor->get_bridge_account(witness->ref.owner, witness->ref.asset, witness->ref.hash);
					if (!account)
						coreturn cancel(remote_exception(std::move(account.error().message())));

					auto session = coawait(dispatcher->aggregate_validators(account->group));
					if (!session)
						coreturn session.error().is_retry() || session.error().is_shutdown() ? expects_rt<void>(std::move(session.error())) : cancel(std::move(session.error()));

					auto chosen = account->group.begin();
					auto unavailable = btree_set<algorithm::pubkeyhash_t>();
					std::advance(chosen, (size_t)(algorithm::hashing::hash256i(input->message.data(), input->message.size()) % uint256_t(account->group.size())));
					if (!state.compositor)
					{
						auto compositor = algorithm::composition::make_signature_compositor(input->alg, input->public_key, input->message.data(), input->message.size(), (uint16_t)account->group.size());
						if (!compositor)
							coreturn cancel(remote_exception(std::move(compositor.error().message())));

						state.compositor = std::move(*compositor);
						state.alg = input->alg;
					}

					bool reset = false;
					while (true)
					{
						auto phase = state.compositor->next_phase();
						if (!reset && (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset))
						{
							state.participants = account->group;
							reset = true;
						}

						bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
						bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
						auto it = (uniform_input ? state.participants.begin() : (chosen_input ? state.participants.find(*chosen) : state.participants.end()));
						it = (!chosen_input && state.participants.size() > 1 && it != state.participants.end() && it->equals(*chosen) ? ++it : it);
						if (it == state.participants.end())
							break;

						auto subresult = coawait(dispatcher->aggregate_signature(executor, state, *it));
						if (!subresult && (subresult.error().is_retry() || subresult.error().is_shutdown()))
						{
							unavailable.insert(*it);
							if (chosen_input)
								goto postpone;
						}
						else if (!subresult)
							coreturn cancel(std::move(subresult.error()));
						else
							reset = false;

						state.participants.erase(it);
					}

					if (!unavailable.empty())
					{
						state.participants = std::move(unavailable);
						goto postpone;
					}

					auto subfinalization = state.compositor->to_signature(&input->signature);
					if (!subfinalization)
						coreturn cancel(remote_exception(std::move(subfinalization.error().message())));

					input = state.message->next_input_for_aggregation();
					state.compositor.destroy();
				}

				finalization = resolver::finalize_transaction(algorithm::asset::base_id_of(asset), std::move(**state.message));
				if (!finalization)
					coreturn cancel(remote_exception(std::move(finalization.error().message())));

				result = coawait(resolver::broadcast_transaction(algorithm::asset::base_id_of(asset), executor->receipt.transaction_hash, superchain::finalized_transaction(*finalization), dispatcher, runner_wallet));
				if (!result && (result.error().is_retry() || result.error().is_shutdown()))
				{
				postpone:
					if (++state.attempt >= protocol::now().user.consensus.coordination_attempts)
						coreturn remote_exception("failed to coordinate participants after several retries");

					dispatcher->push_cache(executor, state.as_message());
					coreturn remote_exception::retry_later();
				}
				else if (!result)
					coreturn cancel(std::move(result.error()));

				auto* transaction = memory::init<broadcast>();
				transaction->asset = asset;
				transaction->set_proof(executor->receipt.transaction_hash, std::move(*finalization));
				dispatcher->emit_transaction(runner_wallet, transaction);
				coreturn expectation::met;
			});
		}
		bool withdraw::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(bridge_hash);
			stream->write_string(address);
			stream->write_decimal(value);
			return true;
		}
		bool withdraw::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &bridge_hash))
				return false;

			if (!stream.read_string(stream.read_type(), &address))
				return false;

			if (!stream.read_decimal(stream.read_type(), &value))
				return false;

			return true;
		}
		bool withdraw::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto attester = get_attester(receipt);
			if (!attester.empty())
				parties.insert(algorithm::pubkeyhash_t(attester));
			return true;
		}
		void withdraw::set_routing_target(const std::string_view& new_address, const decimal& new_value)
		{
			address = new_address;
			value = new_value;
		}
		void withdraw::set_bridge_hash(const uint256_t& new_bridge_hash)
		{
			bridge_hash = new_bridge_hash;
		}
		bool withdraw::is_dispatchable() const
		{
			return true;
		}
		algorithm::pubkeyhash_t withdraw::get_attester(const ledger::transaction_receipt& receipt) const
		{
			auto* event = receipt.find_event<withdraw>();
			if (event != nullptr && !event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
				return algorithm::pubkeyhash_t(event->front().as_blob());

			return algorithm::pubkeyhash_t();
		}
		format::tree withdraw::as_tree() const
		{
			format::tree data = ledger::transaction_message::as_tree();
			data.set("bridge_hash", algorithm::encoding::serialize_uint256(bridge_hash));
			data.set("address", format::variable(address));
			data.set("value", format::variable(value));
			return data;
		}
		uint32_t withdraw::as_type() const
		{
			return as_instance_type();
		}
		std::string_view withdraw::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t withdraw::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view withdraw::as_instance_typename()
		{
			return "withdraw";
		}

		expects_lr<void> broadcast::validate(uint64_t block_number) const
		{
			if (!withdraw_hash)
				return layer_exception("withdraw hash not valid");

			return ledger::commitment_message::validate(block_number);
		}
		expects_lr<void> broadcast::execute(ledger::executor_context* executor) const
		{
			auto validation = ledger::commitment_message::execute(executor);
			if (!validation)
				return validation.error();

			auto parent = executor->get_block_transaction<withdraw>(withdraw_hash);
			if (!parent)
				return layer_exception("parent transaction not found");

			auto* parent_transaction = (withdraw*)*parent->transaction;
			auto event = executor->apply_witness_event(withdraw_hash, executor->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto confirmation = proof ? validate_finalized_proof(executor, parent_transaction, parent->receipt, *proof) : expects_lr<void>(expectation::met);
			if (!confirmation)
				return confirmation.error();

			auto fee_asset = algorithm::asset::base_id_of(parent_transaction->asset);
			auto bridge = executor->get_bridge_instance(fee_asset, parent_transaction->bridge_hash);
			if (!bridge)
				return bridge.error();

			if (proof)
			{
				auto fee_transfer = executor->apply_transfer(fee_asset, parent->receipt.from, -bridge->fee_rate, -bridge->fee_rate);
				if (!fee_transfer)
					return fee_transfer.error();

				auto attester = parent_transaction->get_attester(parent->receipt);
				auto attestation = executor->apply_validator_attestation_reward(fee_asset, attester, bridge->fee_rate * protocol::now().policy.attestation.fee_rate);
				if (!attestation)
					return attestation.error();

				auto proof_base = proof->as_computed();
				auto proof_asset = algorithm::asset::base_id_of(parent_transaction->asset);
				executor->defer_side_effect([proof_asset, proof_base = std::move(proof_base)]() mutable
				{
					superchain::bridge::get()->update_utxo_tree(proof_asset, proof_base).report("failed to update the pending off-chain utxo set");
				});
			}
			else
			{
				if (fee_asset != parent_transaction->asset)
				{
					auto fee_transfer = executor->apply_transfer(fee_asset, parent->receipt.from, decimal::zero(), -bridge->fee_rate);
					if (!fee_transfer)
						return fee_transfer.error();
				}

				auto token_value = parent_transaction->value + (fee_asset == parent_transaction->asset ? bridge->fee_rate : decimal::zero());
				auto token_transfer = executor->apply_transfer(parent_transaction->asset, parent->receipt.from, decimal::zero(), -token_value);
				if (!token_transfer)
					return token_transfer.error();
			}

			auto log = executor->apply_bridge_instance_log(fee_asset, parent_transaction->bridge_hash, executor->receipt.transaction_hash);
			if (!log)
				return log.error();

			auto queue = executor->apply_bridge_queue(asset, parent_transaction->bridge_hash, parent->receipt.transaction_hash, false);
			if (!queue)
				return queue.error();

			return expectation::met;
		}
		bool broadcast::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(withdraw_hash);
			stream->write_boolean(!!proof);
			if (proof)
				proof->store_payload(stream);
			else
				stream->write_string(proof.what());
			return true;
		}
		bool broadcast::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &withdraw_hash))
				return false;

			bool has_proof;
			if (!stream.read_boolean(stream.read_type(), &has_proof))
				return false;

			if (has_proof)
			{
				proof = expects_lr<superchain::finalized_transaction>(superchain::finalized_transaction());
				if (!proof->load_payload(stream))
					return false;
			}
			else
			{
				string error_message;
				if (!stream.read_string(stream.read_type(), &error_message))
					return false;

				proof = layer_exception(std::move(error_message));
			}

			return true;
		}
		bool broadcast::recover_many(const ledger::executor_context* executor, const ledger::transaction_receipt&, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = executor->get_block_transaction_instance(withdraw_hash);
			if (!parent)
				return false;

			parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));
			return true;
		}
		void broadcast::set_proof(const uint256_t& new_withdraw_hash, expects_lr<superchain::finalized_transaction>&& new_proof)
		{
			withdraw_hash = new_withdraw_hash;
			proof = std::move(new_proof);
		}
		format::tree broadcast::as_tree() const
		{
			format::tree data = ledger::commitment_message::as_tree();
			data.set("withdraw_hash", format::variable(algorithm::encoding::encode_0xhex256(withdraw_hash)));
			if (proof)
			{
				data.set("prepared", proof->prepared.as_tree());
				data.set("calldata", format::variable(proof->calldata));
				data.set("hashdata", format::variable(proof->hashdata));
				data.set("locktime", algorithm::encoding::serialize_uint256(proof->locktime));
			}
			else
				data.set("error", format::variable(proof.what()));
			return data;
		}
		uint32_t broadcast::as_type() const
		{
			return as_instance_type();
		}
		std::string_view broadcast::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t broadcast::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view broadcast::as_instance_typename()
		{
			return "broadcast";
		}
		expects_lr<void> broadcast::validate_possible_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::transaction_receipt& receipt, const superchain::prepared_transaction& prepared)
		{
			if (prepared.as_status() == superchain::prepared_transaction::status::invalid)
				return layer_exception("invalid prepared transaction");

			auto offchain = superchain::bridge::get();
			auto base_asset = algorithm::asset::base_id_of(transaction->asset);
			auto required_output_witness = btree_map<string, states::witness_account>();
			auto required_output_value = btree_map<algorithm::asset_id, decimal>();
			auto normalized_address = transaction->address;
			auto status = offchain->normalize_address(transaction->asset, &normalized_address);
			if (!status)
				return status.error();

			if (required_output_witness.find(normalized_address) == required_output_witness.end())
			{
				auto witness = executor->get_witness_account_tagged(base_asset, normalized_address, 0);
				if (!witness)
					return layer_exception("transaction requires paying to unknown address");

				required_output_witness.insert(std::make_pair(std::move(normalized_address), std::move(*witness)));
			}

			auto inout_witness = btree_map<string, states::witness_account>();
			auto input_value = btree_map<algorithm::asset_id, decimal>();
			auto output_value = btree_map<algorithm::asset_id, decimal>();
			auto change_value = btree_map<algorithm::asset_id, decimal>();
			auto& value = required_output_value[transaction->asset];
			value = value.is_nan() ? transaction->value : (value + transaction->value);
			for (auto& input : prepared.inputs)
			{
				auto normalized_address = input.utxo.link.address;
				auto status = offchain->normalize_address(base_asset, &normalized_address);
				if (!status)
					return status.error();

				auto it = inout_witness.find(normalized_address);
				if (it == inout_witness.end())
				{
					auto witness = executor->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("witness transaction input spends from unknown address");

					auto account = executor->get_bridge_account(witness->ref.owner, witness->ref.asset, witness->ref.hash);
					if (!account)
						return layer_exception("witness transaction input refers to a non-bridge account");

					inout_witness.insert(std::make_pair(normalized_address, std::move(*witness)));
					it = inout_witness.find(normalized_address);
				}

				if (!it->second.is_bridge_account() || it->second.ref.hash != transaction->bridge_hash)
					return layer_exception("witness transaction input spends from unrelated address");

				auto& value = input_value[input.utxo.get_asset(base_asset)];
				value = value.is_nan() ? input.utxo.value : (value + input.utxo.value);
				for (auto& [token_hash, token] : input.utxo.tokens)
				{
					auto& token_value = input_value[token.get_asset(base_asset)];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}
			for (auto& output : prepared.outputs)
			{
				auto normalized_address = output.link.address;
				auto status = offchain->normalize_address(base_asset, &normalized_address);
				if (!status)
					return status.error();

				auto it = inout_witness.find(normalized_address);
				if (it == inout_witness.end())
				{
					auto witness = executor->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("witness transaction output pays to unknown address");

					inout_witness.insert(std::make_pair(normalized_address, std::move(*witness)));
					it = inout_witness.find(normalized_address);
				}

				auto change_output = required_output_witness.find(normalized_address);
				if (change_output == required_output_witness.end())
				{
					if (!it->second.is_bridge_account())
						return layer_exception("witness transaction output receives change into unrelated address");

					auto account = executor->get_bridge_account(it->second.ref.owner, it->second.ref.asset, it->second.ref.hash);
					if (!account)
						return layer_exception("witness transaction output refers to a non-bridge account as change");
				}

				auto output_asset = output.get_asset(base_asset);
				auto& value = change_output == required_output_witness.end() ? change_value[output_asset] : output_value[output_asset];
				value = value.is_nan() ? output.value : (value + output.value);
				for (auto& [token_hash, token] : output.tokens)
				{
					auto token_asset = token.get_asset(base_asset);
					auto& token_value = change_output == required_output_witness.end() ? change_value[token_asset] : output_value[token_asset];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}

			if (output_value.size() < required_output_value.size())
				return layer_exception("witness transaction doesn't have required amount of outputs");

			auto bridge = executor->get_bridge_instance(base_asset, transaction->bridge_hash);
			if (!bridge)
				return bridge.error();

			for (auto& [input_token_asset, input_token_value_ref] : input_value)
			{
				decimal input_token_value = input_token_value_ref.is_nan() ? decimal::zero() : input_token_value_ref;
				decimal output_token_value = decimal::zero();
				decimal change_token_value = decimal::zero();
				auto it = output_value.find(input_token_asset);
				if (it != output_value.end())
					output_token_value = it->second.is_nan() ? decimal::zero() : it->second;
				it = change_value.find(input_token_asset);
				if (it != change_value.end())
					change_token_value = it->second.is_nan() ? decimal::zero() : it->second;

				auto delta_token_value = input_token_value - (output_token_value + change_token_value);
				if (delta_token_value.is_negative())
					return layer_exception("witness transaction output pays more that possible");
				else if (input_token_asset == base_asset && delta_token_value > bridge->fee_rate)
					return layer_exception("witness transaction fee overflow (max: " + bridge->fee_rate.to_string() + ")");
			}

			for (auto& [output_asset, actual_output_value] : output_value)
			{
				auto change_ref = change_value.find(output_asset);
				auto max_change_value = change_ref == change_value.end() || change_ref->second.is_nan() ? decimal::zero() : change_ref->second;
				auto it = required_output_value.find(output_asset);
				if (it != required_output_value.end())
				{
					if (it->second.is_nan())
						continue;
					else if (output_asset != base_asset && actual_output_value != it->second)
						return layer_exception("witness transaction output pays unexpected token value");
					else if (output_asset == base_asset && ((actual_output_value < it->second - bridge->fee_rate) || (actual_output_value > it->second + bridge->fee_rate)))
						return layer_exception("witness transaction output pays unexpected native value");
				}
				else if (output_asset == base_asset && actual_output_value > std::max(max_change_value, bridge->fee_rate))
					return layer_exception("witness transaction output pays unexpected native value");
				else if (output_asset != base_asset && actual_output_value != max_change_value)
					return layer_exception("witness transaction output pays unexpected token value");
			}

			return expectation::met;
		}
		expects_lr<void> broadcast::validate_finalized_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::transaction_receipt& receipt, const superchain::finalized_transaction& finalized)
		{
			auto validation = validate_possible_proof(executor, transaction, receipt, finalized.prepared);
			if (!validation)
				return validation;

			if (finalized.calldata.empty())
				return layer_exception("invalid finalized calldata");
			else if (finalized.hashdata.empty())
				return layer_exception("invalid finalized hashdata");

			auto finalization = resolver::finalize_transaction(transaction->asset, superchain::prepared_transaction(finalized.prepared));
			if (!finalization)
				return finalization.error();

			return expectation::met;
		}

		expects_lr<void> anticast::validate(uint64_t block_number) const
		{
			if (!broadcast_hash)
				return layer_exception("broadcast hash not valid");

			return ledger::transaction_message::validate(block_number);
		}
		expects_lr<void> anticast::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction_message::execute(executor);
			if (!validation)
				return validation.error();

			auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
			if (!parent)
				return layer_exception("parent transaction not found");

			auto* parent_transaction = (broadcast*)*parent->transaction;
			if (!parent_transaction->proof)
				return layer_exception("parent transaction not valid");

			auto origin = executor->get_block_transaction<withdraw>(parent_transaction->withdraw_hash, true);
			if (!origin)
				return layer_exception("origin transaction not found");

			if (executor->receipt.from != origin->receipt.from)
				return layer_exception("origin transaction not valid");

			auto* origin_transaction = (withdraw*)*origin->transaction;
			auto witness = executor->get_witness_transaction(origin_transaction->asset, parent_transaction->proof->hashdata);
			if (witness)
				return layer_exception("broadcast is considered final either by attestation or older protest");

			auto time_lock = protocol::now().policy.attestation.withdrawal_time / protocol::now().policy.pow.time;
			auto time_delta = parent->receipt.block_number < executor->receipt.block_number ? executor->receipt.block_number - parent->receipt.block_number : 0;
			if (time_delta <= time_lock)
				return layer_exception("broadcast time lock active - retry after block number " + to_string(parent->receipt.block_number + time_lock));

			auto base_asset = algorithm::asset::base_id_of(origin_transaction->asset);
			auto finalization = executor->apply_witness_transaction(base_asset, parent_transaction->proof->hashdata);
			if (!finalization)
				return finalization.error();

			auto token_transfer = executor->apply_transfer(origin_transaction->asset, origin->receipt.from, decimal::zero(), -origin_transaction->value);
			if (!token_transfer)
				return token_transfer.error();

			auto attester = origin_transaction->get_attester(origin->receipt);
			auto bridge = executor->get_bridge_instance(base_asset, origin_transaction->bridge_hash);
			if (!bridge)
				return bridge.error();

			auto queue = executor->apply_bridge_queue(asset, origin_transaction->bridge_hash, origin->receipt.transaction_hash, false);
			if (!queue)
				return queue.error();

			auto proof_base = parent_transaction->proof->as_computed();
			auto proof_asset = algorithm::asset::base_id_of(origin_transaction->asset);
			executor->defer_side_effect([proof_asset, proof_base = std::move(proof_base)]() mutable
			{
				superchain::bridge::get()->revive_utxo_tree(proof_asset, proof_base).report("failed to revive pending off-chain utxo set");
			});

			auto prev_attestation = executor->get_validator_attestation_reward(base_asset, attester);
			if (!prev_attestation)
				return expectation::met;

			auto next_attestation = executor->apply_validator_attestation_reward(base_asset, attester, -bridge->fee_rate);
			if (!next_attestation)
				return next_attestation.error();

			auto compensation = std::max(decimal::zero(), prev_attestation->reward - next_attestation->reward);
			if (!compensation.is_positive())
				return expectation::met;

			token_transfer = executor->apply_transfer(base_asset, origin->receipt.from, compensation, decimal::zero());
			if (!token_transfer)
				return token_transfer.error();

			return expectation::met;
		}
		bool anticast::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(broadcast_hash);
			return true;
		}
		bool anticast::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &broadcast_hash))
				return false;

			return true;
		}
		bool anticast::recover_many(const ledger::executor_context* executor, const ledger::transaction_receipt&, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = executor->get_block_transaction_instance(broadcast_hash);
			if (!parent)
				return false;

			parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));
			return true;
		}
		void anticast::set_protest(const uint256_t& new_broadcast_hash)
		{
			broadcast_hash = new_broadcast_hash;
		}
		format::tree anticast::as_tree() const
		{
			format::tree data = ledger::transaction_message::as_tree();
			data.set("broadcast_hash", format::variable(algorithm::encoding::encode_0xhex256(broadcast_hash)));
			return data;
		}
		uint32_t anticast::as_type() const
		{
			return as_instance_type();
		}
		std::string_view anticast::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t anticast::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view anticast::as_instance_typename()
		{
			return "anticast";
		}

		expects_lr<void> attestate::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!proof.block_id)
				return layer_exception("transaction has no block reference");

			if (!proof.is_valid_with(asset))
				return layer_exception("invalid proof");

			auto chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid operation");

			btree_set<algorithm::pubkeyhash_t> attesters;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				if (!commitment_hash)
					return layer_exception("invalid commitment hash");
				else if (signatures.size() > protocol::now().policy.attestation.max_per_transaction)
					return layer_exception("too many commitment attesters");

				for (auto& commitment_signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, commitment_signature))
						return layer_exception("invalid commitment signature");
					else if (attesters.find(attester) != attesters.end())
						return layer_exception("duplicate commitment attester");

					attesters.insert(attester);
				}
			}

			return ledger::commitment_message::validate(block_number);
		}
		expects_lr<void> attestate::execute(ledger::executor_context* executor) const
		{
			auto validation = ledger::commitment_message::execute(executor);
			if (!validation)
				return validation.error();

			auto* chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid chain");

			auto witness = executor->get_witness_transaction(asset, proof.transaction_id);
			if (witness)
				return layer_exception("transaction is considered final and immutable");

			uint256_t best_commitment_hash = 0;
			btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>> attesters;
			auto verification = verify_proof_commitment(executor, asset, commitments, best_commitment_hash, attesters);
			if (!verification)
				return verification;
			else if (best_commitment_hash != proof.as_hash())
				return layer_exception("provided proof is not the chosen one");

			decimal network_fee = decimal::zero();
			uint256_t withdrawer_hash = 0;
			algorithm::pubkeyhash_t depositor_account;
			for (auto& [hash, input] : proof.inputs)
			{
				auto baseline = states::witness_account(states::bridge_ref(), { }, nullptr);
				auto source = depositor_account.empty() || !withdrawer_hash ? executor->get_witness_account_tagged(asset, input.link.address, 0).or_else(baseline) : baseline;
				depositor_account = depositor_account.empty() && source.is_routing_account() && chain->routing == superchain::routing_policy::account ? source.ref.owner : depositor_account;
				withdrawer_hash = !withdrawer_hash && source.is_bridge_account() ? source.ref.hash : withdrawer_hash;
				network_fee += input.value;
			}
			for (auto& [hash, output] : proof.outputs)
				network_fee -= output.value;

			auto& succeeding_attesters = attesters[best_commitment_hash];
			btree_map<uint256_t, btree_map<algorithm::asset_id, decimal>> balances;
			btree_map<algorithm::pubkeyhash_t, btree_map<algorithm::asset_id, internal_transfer>> transfers;
			btree_map<algorithm::asset_id, decimal> penalties;
			btree_set<algorithm::pubkeyhash_t> participants;
			if (withdrawer_hash > 0)
			{
				for (auto& [hash, input] : proof.inputs)
				{
					auto source = executor->get_witness_account_tagged(asset, input.link.address, 0);
					if (source && source->is_bridge_account())
					{
						auto& supplies = balances[source->ref.hash];
						auto bridge_account = executor->get_bridge_account(source->ref.owner, source->ref.asset, source->ref.hash);
						if (bridge_account)
							participants.insert(bridge_account->group.begin(), bridge_account->group.end());

						if (input.value.is_positive())
						{
							auto token_asset = input.get_asset(asset);
							auto& supply = supplies[token_asset];
							auto& penalty = penalties[token_asset];
							supply = supply.is_nan() ? -input.value : (supply - input.value);
							penalty = penalty.is_nan() ? input.value : (penalty + input.value);
						}

						for (auto& [token_hash, token] : input.tokens)
						{
							auto token_asset = token.get_asset(asset);
							auto& supply = supplies[token_asset];
							auto& penalty = penalties[token_asset];
							supply = supply.is_nan() ? -token.value : (supply - token.value);
							penalty = penalty.is_nan() ? token.value : (penalty + token.value);
						}
					}
					else
					{
						if (input.value.is_positive())
						{
							auto& penalty = penalties[input.get_asset(asset)];
							penalty = penalty.is_nan() ? input.value : (penalty + input.value);
						}

						for (auto& [token_hash, token] : input.tokens)
						{
							if (token.value.is_positive())
							{
								auto& penalty = penalties[token.get_asset(asset)];
								penalty = penalty.is_nan() ? token.value : (penalty + token.value);
							}
						}
					}
				}

				for (auto& [hash, output] : proof.outputs)
				{
					auto source = executor->get_witness_account_tagged(asset, output.link.address, 0);
					if (source && source->is_bridge_account())
					{
						auto& supplies = balances[source->ref.hash];
						auto bridge_account = executor->get_bridge_account(source->ref.owner, source->ref.asset, source->ref.hash);
						if (bridge_account)
							participants.insert(bridge_account->group.begin(), bridge_account->group.end());

						if (output.value.is_positive())
						{
							auto token_asset = output.get_asset(asset);
							auto& supply = supplies[token_asset];
							auto& penalty = penalties[token_asset];
							supply = supply.is_nan() ? output.value : (supply + output.value);
							penalty = penalty.is_nan() ? -output.value : (penalty - output.value);
						}

						for (auto& [token_hash, token] : output.tokens)
						{
							if (!token.value.is_positive())
								continue;

							auto token_asset = token.get_asset(asset);
							auto& supply = supplies[token_asset];
							auto& penalty = penalties[token_asset];
							supply = supply.is_nan() ? token.value : (supply + token.value);
							penalty = penalty.is_nan() ? -token.value : (penalty - token.value);
						}
					}
					else if (source && source->is_routing_account())
					{
						auto& deltas = transfers[source->ref.owner];
						if (output.value.is_positive())
						{
							auto token_asset = output.get_asset(asset);
							auto& transfer = deltas[token_asset];
							auto& penalty = penalties[token_asset];
							transfer.output_supply += output.value;
							transfer.output_reserve += output.value;
							penalty = penalty.is_nan() ? -output.value : (penalty - output.value);
						}

						for (auto& [token_hash, token] : output.tokens)
						{
							if (!token.value.is_positive())
								continue;

							auto token_asset = token.get_asset(asset);
							auto& transfer = deltas[token_asset];
							auto& penalty = penalties[token_asset];
							transfer.output_supply += token.value;
							transfer.output_reserve += token.value;
							penalty = penalty.is_nan() ? -token.value : (penalty - token.value);
						}
					}
				}

				auto base_asset = algorithm::asset::base_id_of(asset);
				auto it = penalties.find(base_asset);
				if (it != penalties.end())
					it->second = std::max<decimal>(it->second - network_fee, decimal::zero());

				auto bridge = executor->get_bridge_instance(algorithm::asset::base_id_of(asset), withdrawer_hash);
				if (bridge)
				{
					auto reward = bridge->fee_rate * (1 - protocol::now().policy.attestation.fee_rate);
					if (it == penalties.end())
						penalties[base_asset] = -reward;
					else
						it->second -= reward;
				}
			}
			else
			{
				for (auto& [hash, output] : proof.outputs)
				{
					auto source = executor->get_witness_account(asset, output.link.address, 0);
					if (!source || !source->is_bridge_account())
						continue;

					auto& supplies = balances[source->ref.hash];
					auto& changes = transfers[depositor_account.empty() ? source->ref.owner : depositor_account];
					auto bridge_account = executor->get_bridge_account(source->ref.owner, source->ref.asset, source->ref.hash);
					if (bridge_account)
						participants.insert(bridge_account->group.begin(), bridge_account->group.end());

					if (output.value.is_positive())
					{
						auto token_asset = output.get_asset(asset);
						auto& supply = supplies[token_asset];
						auto& transfer = changes[token_asset];
						supply = supply.is_nan() ? output.value : (supply + output.value);
						transfer.input_supply += output.value;
					}

					for (auto& [token_hash, token] : output.tokens)
					{
						if (token.value.is_positive())
						{
							auto token_asset = token.get_asset(asset);
							auto& supply = supplies[token_asset];
							auto& transfer = changes[token_asset];
							supply = supply.is_nan() ? token.value : (supply + token.value);
							transfer.input_supply += token.value;
						}
					}
				}
			}

			if (transfers.empty() && balances.empty())
				return layer_exception("invalid transaction");

			auto failing_attesters = btree_set<algorithm::pubkeyhash_t>();
			for (auto& [commitment_hash, group] : attesters)
			{
				if (commitment_hash != best_commitment_hash)
					failing_attesters.insert(group.begin(), group.end());
			}

			for (auto& [transfer_account, changes] : transfers)
			{
				for (auto& [transfer_asset, transfer] : changes)
				{
					auto supply_delta = transfer.input_supply - transfer.output_supply;
					auto reserve_delta = transfer.input_reserve - transfer.output_reserve;
					if (supply_delta.is_negative() || reserve_delta.is_negative())
					{
						auto balance = executor->get_account_balance(transfer_asset, transfer_account).or_else(states::account_balance(algorithm::pubkeyhash_t(), 0, nullptr));
						auto supply_penalty = decimal::zero();
						auto reserve_penalty = decimal::zero();
						if (balance.supply < -supply_delta)
						{
							supply_penalty = -supply_delta - balance.supply;
							supply_delta = -balance.supply;
						}
						if (balance.reserve < -reserve_delta)
						{
							reserve_penalty = -reserve_delta - balance.reserve;
							reserve_delta = -balance.reserve;
						}
						if (supply_penalty.is_positive() || reserve_penalty.is_positive())
						{
							auto& penalty = penalties[transfer_asset];
							penalty = penalty.is_nan() ? std::max(supply_penalty, reserve_penalty) : (penalty - std::max(supply_penalty, reserve_penalty));
						}
					}

					if (!supply_delta.is_zero() || !reserve_delta.is_zero())
					{
						auto delta_transfer = executor->apply_transfer(transfer_asset, transfer_account, supply_delta, reserve_delta);
						if (!delta_transfer)
							return delta_transfer.error();
					}
				}
			}

			for (auto& [hash, supplies] : balances)
			{
				for (auto& [transfer_asset, transfer_value] : supplies)
				{
					if (transfer_value.is_negative())
					{
						auto balance = executor->get_bridge_balance(transfer_asset, hash);
						transfer_value = balance ? std::max(-balance->supply, transfer_value) : decimal::zero();
					}

					auto balance = executor->apply_bridge_balance(transfer_asset, hash, transfer_value);
					if (!balance)
						return balance.error();
				}
			}

			for (auto& [penalty_asset, penalty_value] : penalties)
			{
				if (penalty_value.is_zero_or_nan())
					continue;

				auto participation_cut = protocol::now().policy.participation.fee_rate;
				auto attestation_cut = 1 - participation_cut;
				if (!failing_attesters.empty() && penalty_value.is_negative())
				{
					auto individual_penalty = algorithm::arithmetic::divide(penalty_value * attestation_cut, failing_attesters.size());
					for (auto& failing_attester : failing_attesters)
					{
						auto prev_attestation = executor->get_validator_attestation_reward(penalty_asset, failing_attester);
						if (!prev_attestation)
							continue;

						auto next_attestation = executor->apply_validator_attestation_reward(penalty_asset, failing_attester, individual_penalty);
						if (!next_attestation)
							return next_attestation.error();

						penalty_value -= std::max(decimal::zero(), prev_attestation->reward - next_attestation->reward);
					}
				}

				auto individual_reward_or_penalty = algorithm::arithmetic::divide(-penalty_value * attestation_cut, succeeding_attesters.size());
				for (auto& succeeding_attester : succeeding_attesters)
				{
					auto attestation = executor->apply_validator_attestation_reward(penalty_asset, succeeding_attester, individual_reward_or_penalty);
					if (!attestation)
						return attestation.error();
				}	

				individual_reward_or_penalty = algorithm::arithmetic::divide(-penalty_value * participation_cut, participants.size());
				for (auto& participant : participants)
				{
					auto participation = executor->apply_validator_participation_reward(penalty_asset, participant, individual_reward_or_penalty);
					if (!participation)
						return participation.error();
				}
			}

			auto finalization = executor->apply_witness_transaction(asset, proof.transaction_id);
			if (!finalization)
				return finalization.error();

			auto proof_asset = asset;
			auto proof_base = proof;
			executor->defer_side_effect([proof_asset, proof_base = std::move(proof_base)]() mutable
			{
				superchain::bridge::get()->update_utxo_tree(proof_asset, proof_base).report("failed to update the off-chain utxo set");
			});
			return executor->emit_witness(asset, proof.block_id);
		}
		bool attestate::store_body(format::wo_stream* stream) const
		{
			if (!proof.store_payload(stream))
				return false;

			stream->write_integer((uint16_t)commitments.size());
			for (auto& [commitment_hash, signatures] : commitments)
			{
				stream->write_integer(commitment_hash);
				stream->write_integer((uint16_t)signatures.size());
				for (auto& commitment_signature : signatures)
					stream->write_string(commitment_signature.optimized_view());
			}
			return true;
		}
		bool attestate::load_body(format::ro_stream& stream)
		{
			if (!proof.load_payload(stream))
				return false;

			uint16_t commitments_size;
			if (!stream.read_integer(stream.read_type(), &commitments_size))
				return false;

			commitments.clear();
			for (uint16_t i = 0; i < commitments_size; i++)
			{
				uint256_t commitment_hash;
				if (!stream.read_integer(stream.read_type(), &commitment_hash))
					return false;

				uint16_t signatures_size;
				if (!stream.read_integer(stream.read_type(), &signatures_size))
					return false;

				auto& signatures = commitments[commitment_hash];
				for (uint16_t j = 0; j < signatures_size; j++)
				{
					algorithm::hashsig_t commitment; string signature_assembly;
					if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, commitment.blob, sizeof(commitment)))
						return false;

					signatures.insert(commitment);
				}
			}

			return true;
		}
		bool attestate::recover_many(const ledger::executor_context*, const ledger::transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& event : receipt.find_events<states::account_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			for (auto& event : receipt.find_events<states::bridge_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			return true;
		}
		void attestate::set_finalized_proof(uint64_t block_id, const std::string_view& transaction_id, const vector<superchain::value_transfer>& inputs, const vector<superchain::value_transfer>& outputs)
		{
			superchain::computed_transaction witness;
			witness.transaction_id = transaction_id;
			witness.block_id = block_id;
			for (auto& input : inputs)
			{
				auto utxo = superchain::coin_utxo(superchain::wallet_link::from_address(input.address), { { input.asset, input.value } });
				witness.inputs[utxo.as_hash()] = std::move(utxo);
			}
			for (auto& output : outputs)
			{
				auto utxo = superchain::coin_utxo(superchain::wallet_link::from_address(output.address), { { output.asset, output.value } });
				witness.outputs[utxo.as_hash()] = std::move(utxo);
			}
			set_computed_proof(std::move(witness), { });
		}
		void attestate::set_computed_proof(superchain::computed_transaction&& new_proof, btree_map<uint256_t, btree_set<algorithm::hashsig_t>>&& new_commitments)
		{
			proof = std::move(new_proof);
			commitments = std::move(new_commitments);
		}
		bool attestate::add_commitment(const algorithm::seckey_t& secret_key)
		{
			uint256_t commitment_hash;
			algorithm::hashsig_t commitment_signature;
			if (!commit_to_proof(proof, secret_key, commitment_hash, commitment_signature))
				return false;

			commitments[commitment_hash].insert(commitment_signature);
			return true;
		}
		format::tree attestate::as_tree() const
		{
			format::tree data = ledger::commitment_message::as_tree();
			auto* commitments_data = data.set("commitments", format::tree::map());
			for (auto& [commitment_hash, signatures] : commitments)
			{
				auto signatures_data = commitments_data->set(algorithm::encoding::encode_0xhex256(commitment_hash), format::tree::list());
				for (auto& commitment_signature : signatures)
					signatures_data->push(commitment_signature.empty() ? format::variable() : format::variable(format::util::encode_0xhex(commitment_signature.view())));
			}
			data.set("proof", proof.as_tree());
			return data;
		}
		uint32_t attestate::as_type() const
		{
			return as_instance_type();
		}
		std::string_view attestate::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t attestate::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view attestate::as_instance_typename()
		{
			return "attestate";
		}
		expects_lr<void> attestate::verify_proof_commitment(ledger::executor_context* executor, const algorithm::asset_id& asset, const btree_map<uint256_t, btree_set<algorithm::hashsig_t>>& commitments, uint256_t& best_commitment_hash, btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>>& attesters)
		{
			btree_set<algorithm::pubkeyhash_t> duplicates;
			best_commitment_hash = 0;
			attesters.clear();

			size_t best_commitment_size = 0;
			decimal best_commitment_stake = -1;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				if (!commitment_hash)
					return layer_exception("invalid commitment hash");

				for (auto& signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, signature))
						return layer_exception("commitment signature does not recover attester");
					else if (duplicates.find(attester) != duplicates.end())
						return layer_exception("multiple signatures from same attester");

					attesters[commitment_hash].insert(attester);
					duplicates.insert(attester);
				}

				size_t commitment_size = 0;
				decimal commitment_stake = decimal::zero();
				for (auto& attester : attesters[commitment_hash])
				{
					auto attestation = executor->get_verified_validator_attestation(asset, attester);
					if (!attestation)
						return layer_exception("commitment attester must be active");

					commitment_stake += attestation->stake;
					++commitment_size;
				}

				if (commitment_stake > best_commitment_stake)
				{
					best_commitment_hash = commitment_hash;
					best_commitment_stake = commitment_stake;
					best_commitment_size = commitment_size;
				}
			}

			if (!best_commitment_hash || !best_commitment_size || best_commitment_stake.is_negative())
				return layer_exception("proof requires more attestations");

			auto& params = protocol::now();
			auto best_attesters = executor->calculate_attesters(asset, params.policy.attestation.max_per_transaction);
			if (!best_attesters)
				return best_attesters.error();

			decimal min_commitment_stake = decimal::zero();
			for (auto& attester : *best_attesters)
				min_commitment_stake += attester.stake;

			min_commitment_stake *= params.policy.attestation.consensus_threshold;
			if (best_commitment_stake < min_commitment_stake)
				return layer_exception("proof requires better attestations");

			return expectation::met;
		}
		void attestate::optimize_proofs_and_commitments(const ledger::executor_context* executor, const algorithm::asset_id& asset, btree_map<uint256_t, superchain::computed_transaction>& proofs, btree_map<uint256_t, btree_set<algorithm::hashsig_t>>& commitments)
		{
			for (auto it = proofs.begin(); it != proofs.end();)
			{
				if (!it->second.is_valid_with(asset))
				{
					commitments.erase(it->first);
					it = proofs.erase(it);
				}
				else
					++it;
			}

			btree_set<algorithm::pubkeyhash_t> duplicates;
			btree_map<uint256_t, btree_set<algorithm::hashsig_t>> removals;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				vector<std::pair<algorithm::hashsig_t, decimal>> weights;
				for (auto& signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, signature))
					{
					strip_out:
						removals[commitment_hash].insert(signature);
						continue;
					}
					else if (duplicates.find(attester) != duplicates.end())
						goto strip_out;

					auto attestation = executor->get_verified_validator_attestation(asset, attester);
					if (!attestation)
						goto strip_out;

					weights.push_back(std::make_pair(signature, std::move(attestation->stake)));
					duplicates.insert(attester);
				}

				std::sort(weights.begin(), weights.end(), [](const std::pair<algorithm::hashsig_t, decimal>& a, const std::pair<algorithm::hashsig_t, decimal>& b) { return a.second > b.second; });
				for (size_t i = protocol::now().policy.attestation.max_per_transaction; i < weights.size(); i++)
					removals[commitment_hash].insert(weights[i].first);
			}

			for (auto& [commitment_hash, signatures] : removals)
			{
				for (auto& signature : signatures)
					commitments[commitment_hash].erase(signature);
			}

			for (auto it = commitments.begin(); it != commitments.end();)
			{
				if (it->second.empty())
					it = commitments.erase(it);
				else
					++it;
			}
		}
		bool attestate::commit_to_proof(const superchain::computed_transaction& new_proof, const algorithm::seckey_t& secret_key, uint256_t& commitment_hash, algorithm::hashsig_t& signature)
		{
			commitment_hash = new_proof.as_hash();
			return algorithm::signing::sign(commitment_hash, secret_key, signature);
		}

		ledger::transaction_message* resolver::from_stream(format::ro_stream& stream)
		{
			uint32_t type; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &type))
				return nullptr;

			stream.seek = seek;
			return from_type(type);
		}
		ledger::transaction_message* resolver::from_type(uint32_t hash)
		{
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>();
			else if (hash == deploy::as_instance_type())
				return memory::init<deploy>();
			else if (hash == call::as_instance_type())
				return memory::init<call>();
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>();
			else if (hash == setup::as_instance_type())
				return memory::init<setup>();
			else if (hash == migrate::as_instance_type())
				return memory::init<migrate>();
			else if (hash == route::as_instance_type())
				return memory::init<route>();
			else if (hash == bind::as_instance_type())
				return memory::init<bind>();
			else if (hash == withdraw::as_instance_type())
				return memory::init<withdraw>();
			else if (hash == broadcast::as_instance_type())
				return memory::init<broadcast>();
			else if (hash == anticast::as_instance_type())
				return memory::init<anticast>();
			else if (hash == attestate::as_instance_type())
				return memory::init<attestate>();
			return nullptr;
		}
		ledger::transaction_message* resolver::from_copy(const ledger::transaction_message* base)
		{
			uint32_t hash = base->as_type();
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>(*(const transfer*)base);
			else if (hash == deploy::as_instance_type())
				return memory::init<deploy>(*(const deploy*)base);
			else if (hash == call::as_instance_type())
				return memory::init<call>(*(const call*)base);
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>(*(const rollup*)base);
			else if (hash == setup::as_instance_type())
				return memory::init<setup>(*(const setup*)base);
			else if (hash == migrate::as_instance_type())
				return memory::init<migrate>(*(const migrate*)base);
			else if (hash == route::as_instance_type())
				return memory::init<route>(*(const route*)base);
			else if (hash == bind::as_instance_type())
				return memory::init<bind>(*(const bind*)base);
			else if (hash == withdraw::as_instance_type())
				return memory::init<withdraw>(*(const withdraw*)base);
			else if (hash == broadcast::as_instance_type())
				return memory::init<broadcast>(*(const broadcast*)base);
			else if (hash == anticast::as_instance_type())
				return memory::init<anticast>(*(const anticast*)base);
			else if (hash == attestate::as_instance_type())
				return memory::init<attestate>(*(const attestate*)base);
			return nullptr;
		}
		expects_promise_rt<superchain::prepared_transaction> resolver::prepare_transaction(const algorithm::asset_id& asset, const superchain::wallet_link& from_link, const superchain::value_transfer& to, const decimal& max_fee)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || offchain->has_network(asset, true))
				return offchain->prepare_transaction(asset, from_link, to, max_fee);

			auto chain = offchain->get_network_params(asset);
			if (!chain)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("invalid operation"));

			auto from = offchain->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::wo_stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = offchain->to_composite_public_key(asset, from->public_key);
			if (!public_key)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception(std::move(public_key.error().message())));

			auto transfers = hash_map<algorithm::asset_id, decimal>();
			transfers[algorithm::asset::base_id_of(asset)] = decimal("0.000001");
			if (to.address == MOCKUP_FAIL)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("synthetic mockup error"));

			uint8_t message_hash[32];
			auto& value = transfers[to.asset];
			value = value.is_nan() ? to.value : (value + to.value);
			message.write_integer(to.asset);
			message.write_string(to.address);
			message.write_decimal(to.value);
			message.hash().encode(message_hash);

			superchain::prepared_transaction regtest_prepared;
			regtest_prepared.requires_account_input(chain->composition, std::move(*from), *public_key, message_hash, sizeof(message_hash), std::move(transfers));
			regtest_prepared.requires_account_output(to.address, { { to.asset, to.value } });

			return expects_promise_rt<superchain::prepared_transaction>(std::move(regtest_prepared));
		}
		expects_lr<superchain::finalized_transaction> resolver::finalize_transaction(const algorithm::asset_id& asset, superchain::prepared_transaction&& prepared)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || offchain->has_network(asset, true))
				return offchain->finalize_transaction(asset, std::move(prepared));

			auto transaction_id = algorithm::encoding::encode_0xhex256(prepared.as_hash());
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint32_t>::max();
			auto regtest_finalized = superchain::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			regtest_finalized.calldata = regtest_finalized.as_message().encode();
			return expects_lr<superchain::finalized_transaction>(std::move(regtest_finalized));
		}
		expects_promise_rt<void> resolver::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, superchain::finalized_transaction&& finalized, ledger::dispatcher_context* dispatcher, const ledger::wallet* runner_wallet)
		{
			auto* offchain = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || offchain->has_network(asset, true))
			{
				auto preserved = memory::init<superchain::finalized_transaction>(std::move(finalized));
				return offchain->broadcast_transaction(asset, external_id, *preserved).then<expects_rt<void>>([preserved](expects_rt<void>&& status) mutable -> expects_rt<void>
				{
					memory::deinit(preserved);
					if (!status)
						return expects_rt<void>(std::move(status.error()));

					return expects_rt<void>(expectation::met);
				});
			}

			if (dispatcher != nullptr && !(finalized.prepared.outputs.size() == 1 && finalized.prepared.outputs.front().link.address == MOCKUP_LOST))
			{
				auto* transaction = memory::init<attestate>();
				transaction->asset = asset;
				transaction->set_gas(decimal::zero(), 0);
				transaction->set_computed_proof(finalized.as_computed(), { });
				dispatcher->emit_transaction(runner_wallet, transaction);
			}
			return expects_promise_rt<void>(expectation::met);
		}
	}
}