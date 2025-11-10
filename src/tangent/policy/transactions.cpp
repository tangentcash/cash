#include "transactions.h"
#include "../kernel/block.h"
#include "../kernel/cell.h"
#include "../validator/service/oracle.h"

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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> transfer::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			for (auto& [owner, value] : to)
			{
				if (context->receipt.from == algorithm::pubkeyhash_t(owner.data))
					return layer_exception("invalid payment");

				auto payment = context->apply_payment(asset, context->receipt.from, owner.data, value);
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
				if (!stream.read_string(type, &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.data, sizeof(owner.data)))
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
					if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.data, sizeof(owner.data)))
						return false;

					decimal value;
					if (!stream.read_decimal(stream.read_type(), &value))
						return false;

					to.push_back(std::make_pair(owner, std::move(value)));
				}
			}

			return true;
		}
		bool transfer::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& [owner, value] : to)
				parties.insert(algorithm::pubkeyhash_t(owner.data));
			return true;
		}
		void transfer::set_to(const algorithm::pubkeyhash_t& new_to, const decimal& new_value)
		{
			to.push_back(std::make_pair(new_to, new_value));
		}
		uptr<schema> transfer::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* transfers_data = data->set("to", var::set::array());
			for (auto& [owner, value] : to)
			{
				auto* transfer_data = transfers_data->push(var::set::object());
				transfer_data->set("to", algorithm::signing::serialize_address(owner.data));
				transfer_data->set("value", var::decimal(value));
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

		expects_lr<void> upgrade::validate(uint64_t block_number) const
		{
			auto type = get_data_type();
			if (!type)
				return layer_exception("invalid data type");
			else if (*type == data_type::hashcode && data.size() != 65)
				return layer_exception("invalid hashcode data");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> upgrade::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto account = get_account();
			auto storage = std::string_view(data).substr(1);
			auto type = get_data_type().or_else(data_type::hashcode);
			auto* factory = cell::factory::get();
			auto pmodule = cell::cmodule(nullptr);
			switch (type)
			{
				case data_type::program:
				{
					auto code = factory->unpack(storage);
					if (!code)
						return code.error();

					auto hashcode = factory->hashcode(*code);
					auto result = factory->compile_module(format::util::encode_0xhex(hashcode), [&]() mutable { return std::move(code); });
					if (!result)
						return result.error();

					auto collision = context->get_witness_program(hashcode);
					if (!collision)
					{
						auto status = context->apply_witness_program(storage);
						if (!status)
							return status.error();
					}
					else if (collision->storage != data)
						return layer_exception("program hashcode collision");

					auto status = context->apply_account_program(account.data, hashcode);
					if (!status)
						return status.error();

					pmodule = std::move(*result);
					break;
				}
				case data_type::hashcode:
				{
					auto program = context->get_witness_program(storage);
					if (!program)
						return layer_exception("program is not stored");

					auto result = factory->compile_module(format::util::encode_0xhex(storage), [&]() { return program->as_code(); });
					if (!result)
						return result.error();

					auto status = context->apply_account_program(account.data, storage);
					if (!status)
						return status.error();

					pmodule = std::move(*result);
					break;
				}
				default:
					return layer_exception("invalid data type");
			}

			auto script = cell::program(context, pmodule->get_module());
			return script.execute(cell::ccall::upgrade_call, script.upgrade_function(), args, nullptr);
		}
		bool upgrade::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(data);
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool upgrade::load_body(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &data))
				return false;

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool upgrade::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
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
		void upgrade::from_program(const std::string_view& new_data, format::variables&& new_args)
		{
			args = std::move(new_args);
			data.clear();
			data.assign(1, (char)data_type::program);
			data.append(cell::factory::get()->pack(new_data).or_else(string()));
		}
		void upgrade::from_hashcode(const std::string_view& new_data, format::variables&& new_args)
		{
			args = std::move(new_args);
			data.clear();
			data.assign(1, (char)data_type::hashcode);
			data.append(new_data.substr(0, 64));
		}
		algorithm::pubkeyhash_t upgrade::get_account() const
		{
			auto message = as_message();
			message.write_integer(0xFFFFFFFF);

			algorithm::pubkeyhash_t account;
			algorithm::hashing::hash160((uint8_t*)message.data.data(), message.data.size(), account.data);
			return account;
		}
		option<upgrade::data_type> upgrade::get_data_type() const
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
		uptr<schema> upgrade::as_schema() const
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

			schema* data = ledger::transaction::as_schema().reset();
			data->set("callable", algorithm::signing::serialize_address(get_account()));
			data->set("from", name.empty() ? var::null() : var::string(name));
			data->set("data", var::string(format::util::encode_0xhex(this->data)));
			data->set("args", format::variables_util::serialize(args));
			return data;
		}
		uint32_t upgrade::as_type() const
		{
			return as_instance_type();
		}
		std::string_view upgrade::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t upgrade::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view upgrade::as_instance_typename()
		{
			return "upgrade";
		}

		expects_lr<void> call::validate(uint64_t block_number) const
		{
			if (function.empty())
				return layer_exception("invalid function call");

			if (value.is_nan() || value.is_negative())
				return layer_exception("invalid value");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> call::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			return subexecute(context, [this, context](asIScriptModule* module_ptr)
			{
				auto script = cell::program(context, module_ptr);
				return script.execute(cell::ccall::paying_call, function, args, nullptr);
			});
		}
		expects_lr<void> call::subexecute(ledger::transaction_context* context, std::function<expects_lr<void>(asIScriptModule*)>&& executor) const
		{
			VI_ASSERT(executor, "executor should be set");
			auto index = context->get_account_program(callable);
			if (!index)
				return layer_exception("program is not assigned");

			auto& hashcode = index->hashcode;
			auto program = context->get_witness_program(hashcode);
			if (!program)
				return layer_exception("program is not stored");

			auto pmodule = cell::factory::get()->compile_module(format::util::encode_0xhex(hashcode), [&]() { return program->as_code(); });
			if (!pmodule)
				return pmodule.error();

			if (value.is_positive())
			{
				if (context->receipt.from == callable)
					return layer_exception("invalid payment");

				auto payment = context->apply_payment(asset, context->receipt.from, callable, value);
				if (!payment)
					return payment.error();
			}

			return executor(pmodule->ref.get_module());
		}
		bool call::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(callable.optimized_view());
			stream->write_string(function);
			stream->write_decimal(value);
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool call::load_body(format::ro_stream& stream)
		{
			string callable_assembly;
			if (!stream.read_string(stream.read_type(), &callable_assembly) || !algorithm::encoding::decode_bytes(callable_assembly, callable.data, sizeof(callable)))
				return false;

			if (!stream.read_string(stream.read_type(), &function))
				return false;

			if (!stream.read_decimal(stream.read_type(), &value))
				return false;

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool call::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
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
		void call::program_call(const algorithm::pubkeyhash_t& new_callable, const decimal& new_value, const std::string_view& new_function, format::variables&& new_args)
		{
			args = std::move(new_args);
			function = new_function;
			value = new_value;
			callable = new_callable;
		}
		uptr<schema> call::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("callable", algorithm::signing::serialize_address(callable));
			data->set("value", var::decimal(value));
			data->set("function", var::string(function));
			data->set("args", format::variables_util::serialize(args));
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
			ledger::transaction& base = *this;
			base = *(ledger::transaction*)&other;
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

			ledger::transaction& base = *this;
			base = *(ledger::transaction*)&other;
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

					auto* reference = (ledger::transaction*)*transaction;
					if (transaction->asset != group.first || !transaction->gas_price.is_nan() || transaction->gas_limit > 0)
						return layer_exception("invalid sub-transaction data");
				}
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> rollup::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			vector<std::pair<ledger::transaction*, uint16_t>> queue;
			for (auto& group : transactions)
			{
				uint16_t index = 0;
				queue.reserve(queue.size() + group.second.size());
				for (auto& transaction : group.second)
					queue.push_back(std::make_pair(*transaction, index++));
			}

			algorithm::pubkeyhash_t owner;
			uint256_t absolute_gas_limit = context->block->gas_limit;
			uint256_t absolute_gas_use = context->block->gas_use;
			uint256_t relative_gas_use = context->receipt.relative_gas_use;
			std::sort(queue.begin(), queue.end(), [](const std::pair<ledger::transaction*, uint16_t>& a, const std::pair<ledger::transaction*, uint16_t>& b)
			{
				return a.first->nonce > 0 && b.first->nonce > 0 && a.first->nonce != b.first->nonce ? a.first->nonce < b.first->nonce : a.second < b.second;
			});

			auto internal_receipt = ledger::receipt();
			for (auto& [transaction, index] : queue)
			{
				bool internal_transaction = transaction->signature.empty();
				uint256_t transaction_hash = transaction->as_hash();
				uint64_t transaction_nonce = transaction->nonce;
				uint8_t transaction_code = transaction->signature.data[0];
				uint8_t execution_flags = (uint8_t)ledger::transaction_context::execution_mode::pedantic;
				if (internal_transaction)
				{
					transaction->nonce = nonce;
					transaction->signature.data[0] = 0xFF;
					execution_flags |= (uint8_t)ledger::transaction_context::execution_mode::replayable;
					owner = context->receipt.from;
				}
				else if (!transaction->recover_hash(owner) || owner.empty())
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " validation failed: invalid signature");

				transaction->gas_price = decimal::zero();
				transaction->gas_limit = gas_limit - context->receipt.relative_gas_use;
				auto execution = ledger::transaction_context::execute_tx(context->environment, (ledger::block*)context->block, context->changelog, transaction, transaction_hash, owner, 0, execution_flags, internal_receipt);
				transaction->signature.data[0] = transaction_code;
				transaction->nonce = transaction_nonce;
				transaction->gas_limit = 0;
				transaction->gas_price = decimal::nan();
				if (!execution)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " execution failed: " + execution.error().message());

				relative_gas_use += execution->receipt.relative_gas_use;
				auto report = context->emit_event<rollup>({ format::variable(execution->receipt.transaction_hash), format::variable(index), format::variable(execution->receipt.relative_gas_use) });
				if (!report)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " merge failed: " + report.error().message());

				size_t prev_size = internal_receipt.events.size();
				internal_receipt.events = std::move(execution->receipt.events);
				if (internal_receipt.events.size() > prev_size)
					context->receipt.events.insert(context->receipt.events.end(), internal_receipt.events.begin() + prev_size, internal_receipt.events.end());
			}

			context->block->gas_limit = absolute_gas_limit;
			context->block->gas_use = absolute_gas_use;
			context->receipt.relative_gas_use = relative_gas_use;
			return expectation::met;
		}
		expects_promise_rt<void> rollup::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!is_dispatchable())
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, context, dispatcher]() -> expects_promise_rt<void>
			{
				string error_message;
				for (auto& group : transactions)
				{
					for (auto& transaction : group.second)
					{
						auto resolved_transaction = resolve_block_transaction(context->receipt, transaction->as_hash());
						if (!resolved_transaction)
							continue;

						auto& target_transaction = *resolved_transaction;
						auto status = coawait(ledger::transaction_context::dispatch_tx(dispatcher, &target_transaction));
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

					uptr<ledger::transaction> next = resolver::from_type(type);
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
		bool rollup::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			algorithm::pubkeyhash_t from;
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					bool internal_transaction = transaction->signature.empty();
					if (!internal_transaction && transaction->recover_hash(from))
						parties.insert(from);
					transaction->recover_many(context, receipt, parties);
				}
			}
			return true;
		}
		bool rollup::recover_aliases(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<uint256_t>& aliases) const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					aliases.insert(transaction->as_hash());
					transaction->recover_aliases(context, receipt, aliases);
				}
			}
			return true;
		}
		bool rollup::import_transaction(const ledger::transaction& transaction)
		{
			auto* next = resolver::from_copy(&transaction);
			if (!next)
				return false;

			transactions[next->asset].push_back(next);
			return true;
		}
		bool rollup::import_internal_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key)
		{
			transaction.nonce = 0;
			transaction.signature.clear();
			normalize_transaction(transaction, asset);
			return import_transaction(transaction);
		}
		bool rollup::import_external_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key, uint64_t nonce)
		{
			transaction.nonce = nonce > 0 ? nonce : transaction.nonce;
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
		expects_lr<ledger::block_transaction> rollup::resolve_block_transaction(const ledger::receipt& receipt, const uint256_t& transaction_hash) const
		{
			if (!transaction_hash)
				return layer_exception("sub-transaction not found");

			ledger::transaction* target = nullptr;
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
		const ledger::transaction* rollup::resolve_transaction(const uint256_t& transaction_hash) const
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
		uptr<schema> rollup::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			schema* transactions_data = data->set("transactions", var::array());
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
					transactions_data->push(transaction->as_schema().reset());
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
		void rollup::normalize_transaction(ledger::transaction& transaction, const algorithm::asset_id& asset)
		{
			transaction.gas_price = decimal::nan();
			transaction.gas_limit = 0;
			if (!transaction.asset)
				transaction.asset = asset;
		}

		expects_lr<void> validator_adjustment::validate(uint64_t block_number) const
		{
			if (!production && participation_stakes.empty() && attestation_stakes.empty())
				return layer_exception("invalid validator change");

			for (auto& [asset, stake] : participation_stakes)
			{
				uint64_t expiry_number = algorithm::asset::expiry_of(asset);
				if (!expiry_number || (block_number > expiry_number && !stake.is_nan() && !stake.is_negative()))
					return layer_exception("invalid participation asset");
			}

			for (auto& [asset, stake] : attestation_stakes)
			{
				uint64_t expiry_number = algorithm::asset::expiry_of(asset);
				if (!expiry_number || (block_number > expiry_number && !stake.is_nan() && !stake.is_negative()))
					return layer_exception("invalid attestation asset");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> validator_adjustment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			if (production)
			{
				auto type = *production ? ledger::transaction_context::production_type::mint_and_activate : ledger::transaction_context::production_type::burn_and_deactivate;
				auto status = context->apply_validator_production(context->receipt.from, type, { });
				if (!status)
					return status.error();
			}

			for (auto& [asset, stake] : participation_stakes)
			{
				if (!algorithm::asset::token_of(asset).empty())
					continue;

				auto type = stake.is_nan() || stake.is_negative() ? ledger::transaction_context::stake_type::unlock : ledger::transaction_context::stake_type::lock;
				auto blockchain = algorithm::asset::blockchain_of(asset);
				ordered_map<algorithm::asset_id, decimal> stakes;
				for (auto& [token_asset, token_stake] : participation_stakes)
				{
					if (algorithm::asset::blockchain_of(token_asset) != blockchain)
						continue;

					auto subtype = stake.is_nan() || stake.is_negative() ? ledger::transaction_context::stake_type::unlock : ledger::transaction_context::stake_type::lock;
					if (type != subtype)
						return layer_exception("token stake action mismatch");

					stakes[token_asset] = token_stake;
				}

				auto status = context->apply_validator_participation(asset, context->receipt.from, type, 0, stakes);
				if (!status)
					return status.error();
			}

			for (auto& [asset, stake] : attestation_stakes)
			{
				if (!algorithm::asset::token_of(asset).empty())
					continue;

				auto type = stake.is_nan() || stake.is_negative() ? ledger::transaction_context::stake_type::unlock : ledger::transaction_context::stake_type::lock;
				auto bridge = context->get_bridge_policy(asset, context->receipt.from);
				if (type == ledger::transaction_context::stake_type::unlock && bridge && (bridge->accepts_account_requests || bridge->accepts_withdrawal_requests))
					return layer_exception(algorithm::asset::handle_of(asset) + " bridge is still active");

				auto balance = context->get_bridge_balance(asset, context->receipt.from);
				auto blockchain = algorithm::asset::blockchain_of(asset);
				ordered_map<algorithm::asset_id, decimal> stakes;
				for (auto& [token_asset, token_stake] : attestation_stakes)
				{
					if (algorithm::asset::blockchain_of(token_asset) != blockchain)
						continue;

					auto subtype = stake.is_nan() || stake.is_negative() ? ledger::transaction_context::stake_type::unlock : ledger::transaction_context::stake_type::lock;
					if (type != subtype)
						return layer_exception("token stake action mismatch");

					stakes[token_asset] = token_stake;
					if (type == ledger::transaction_context::stake_type::lock || !bridge || !balance)
						continue;

					if (algorithm::asset::is_aux(token_asset, true))
					{
						auto reward = context->get_bridge_reward_median(token_asset).or_else(states::bridge_reward(context->receipt.from, token_asset, nullptr));
						if (balance->get_balance(token_asset) > reward.outgoing_fee)
							return layer_exception(algorithm::asset::handle_of(token_asset) + " bridge has non-dust custodial balance (max: " + reward.outgoing_fee.to_string() + ")");
					}
					else if (balance->get_balance(token_asset).is_positive())
						return layer_exception(algorithm::asset::handle_of(token_asset) + " bridge has custodial token balance");
				}

				auto status = context->apply_validator_attestation(asset, context->receipt.from, type, stakes);
				if (!status)
					return status.error();
			}

			return expectation::met;
		}
		bool validator_adjustment::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint8_t)(production ? (*production ? 1 : 0) : 2));
			stream->write_integer((uint8_t)participation_stakes.size());
			for (auto& [asset, stake] : participation_stakes)
			{
				stream->write_integer(asset);
				stream->write_decimal(stake);
			}
			stream->write_integer((uint8_t)attestation_stakes.size());
			for (auto& [asset, stake] : attestation_stakes)
			{
				stream->write_integer(asset);
				stream->write_decimal(stake);
			}
			return true;
		}
		bool validator_adjustment::load_body(format::ro_stream& stream)
		{
			uint8_t production_status;
			if (!stream.read_integer(stream.read_type(), &production_status))
				return false;

			if (production_status == 0)
				production = false;
			else if (production_status == 1)
				production = true;
			else
				production = optional::none;

			uint8_t participation_stakes_size = 0;
			if (!stream.read_integer(stream.read_type(), &participation_stakes_size))
				return false;

			participation_stakes.clear();
			for (uint16_t i = 0; i < participation_stakes_size; i++)
			{
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				decimal stake;
				if (!stream.read_decimal(stream.read_type(), &stake))
					return false;

				participation_stakes[asset] = stake;
			}

			uint8_t attestation_stakes_size = 0;
			if (!stream.read_integer(stream.read_type(), &attestation_stakes_size))
				return false;

			attestation_stakes.clear();
			for (uint16_t i = 0; i < attestation_stakes_size; i++)
			{
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				decimal stake;
				if (!stream.read_decimal(stream.read_type(), &stake))
					return false;

				attestation_stakes[asset] = stake;
			}

			return true;
		}
		void validator_adjustment::enable_block_production()
		{
			production = true;
		}
		void validator_adjustment::disable_block_production()
		{
			production = false;
		}
		void validator_adjustment::standby_on_block_production()
		{
			production = optional::none;
		}
		void validator_adjustment::allocate_participation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value >= 0.0)
				participation_stakes[asset] = value;
		}
		void validator_adjustment::deallocate_participation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value.is_positive())
				participation_stakes[asset] = -value;
		}
		void validator_adjustment::disable_participation(const algorithm::asset_id& asset)
		{
			participation_stakes[asset] = decimal::nan();
		}
		void validator_adjustment::standby_on_participation(const algorithm::asset_id& asset)
		{
			participation_stakes.erase(asset);
		}
		void validator_adjustment::allocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value >= 0.0)
				attestation_stakes[asset] = value;
		}
		void validator_adjustment::deallocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value.is_positive())
				attestation_stakes[asset] = -value;
		}
		void validator_adjustment::disable_attestation(const algorithm::asset_id& asset)
		{
			attestation_stakes[asset] = decimal::nan();
		}
		void validator_adjustment::standby_on_attestation(const algorithm::asset_id& asset)
		{
			attestation_stakes.erase(asset);
		}
		uptr<schema> validator_adjustment::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("block_production", var::integer(production ? (*production ? 1 : 0) : -1));

			auto* participation_stakes_data = data->set("participation_stakes", var::set::array());
			for (auto& [asset, stake] : participation_stakes)
			{
				auto* stake_data = participation_stakes_data->push(var::set::object());
				stake_data->set("asset", algorithm::asset::serialize(asset));
				stake_data->set("stake", var::decimal(stake));
			}

			auto* attestation_stakes_data = data->set("attestation_stakes", var::set::array());
			for (auto& [asset, stake] : attestation_stakes)
			{
				auto* stake_data = attestation_stakes_data->push(var::set::object());
				stake_data->set("asset", algorithm::asset::serialize(asset));
				stake_data->set("stake", var::decimal(stake));
			}
			return data;
		}
		uint32_t validator_adjustment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_adjustment::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t validator_adjustment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_adjustment::as_instance_typename()
		{
			return "validator_adjustment";
		}

		expects_lr<void> bridge_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (manager.empty())
				return layer_exception("invalid manager");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bridge_account::execute(ledger::transaction_context* context) const
		{
			auto validation = commitment::execute(context);
			if (!validation)
				return validation.error();

			auto delegation_requirement = context->verify_account_delegation(manager);
			if (!delegation_requirement)
				return delegation_requirement;

			auto delegation = context->apply_account_delegation(manager, 1);
			if (!delegation)
				return delegation.error();

			auto* params = oracle::server_node::get()->get_chainparams(asset);
			if (!params)
				return layer_exception("invalid operation");

			auto attestation_requirement = context->verify_validator_attestation(asset, manager);
			if (!attestation_requirement)
				return attestation_requirement.error();

			auto bridge_policy = context->get_bridge_policy(asset, manager);
			if (!bridge_policy)
				return bridge_policy.error();
			else if (!bridge_policy->accepts_account_requests)
				return layer_exception("bridge forbids account requests");

			bool routing_address_application = false;
			if (!routing_address.empty())
			{
				auto collision = context->get_witness_account(asset, routing_address, 0);
				if (collision && (!collision->is_routing_account() || collision->owner != context->receipt.from))
					return layer_exception("routing account address " + routing_address + " taken");

				if (!collision)
				{
					auto status = context->apply_witness_routing_account(asset, context->receipt.from, { { (uint8_t)1, string(routing_address) } });
					if (!status)
						return status.error();

					routing_address_application = true;
				}
			}

			auto duplicate = context->get_bridge_account(asset, manager, context->receipt.from);
			if (duplicate)
			{
				if (!routing_address_application)
					return layer_exception("bridge account already exists");

				return expectation::met;
			}

			switch (params->routing)
			{
				case oracle::routing_policy::account:
				{
					if (!bridge_policy->accounts_under_management)
					{
						if (context->receipt.from != manager)
							return layer_exception("bridge account for manager required");
						break;
					}
					else if (!routing_address_application)
						return layer_exception("routing address required");

					return expectation::met;
				}
				case oracle::routing_policy::memo:
				{
					if (!bridge_policy->accounts_under_management)
					{
						if (context->receipt.from != manager)
							return layer_exception("bridge account for manager required");
						break;
					}

					auto manager_account = context->get_bridge_account(asset, manager, manager);
					if (!manager_account || manager_account->public_key.empty() || manager_account->group.empty() || manager_account->owner != manager || manager_account->manager != manager)
						return layer_exception("bridge account for manager required");

					auto* chain = oracle::server_node::get()->get_chain(asset);
					if (!chain)
						return layer_exception("invalid operation");

					auto encoded_public_key = chain->encode_public_key(std::string_view((char*)manager_account->public_key.data(), manager_account->public_key.size()));
					if (!encoded_public_key)
						return encoded_public_key.error();

					auto addresses = chain->to_addresses(*encoded_public_key);
					if (!addresses)
						return addresses.error();

					for (auto& address : *addresses)
						address.second = oracle::address_util::encode_tag_address(address.second, to_string(bridge_policy->accounts_under_management));
					
					auto bridge_policy_status = context->apply_bridge_policy_account(asset, manager, 1);
					if (!bridge_policy_status)
						return bridge_policy_status.error();

					auto bridge_account_status = context->apply_bridge_account(asset, context->receipt.from, manager, algorithm::composition::cpubkey_t(), { });
					if (!bridge_account_status)
						return bridge_account_status.error();

					auto witness_account_status = context->apply_witness_bridge_account(asset, context->receipt.from, manager, *addresses);
					if (!witness_account_status)
						return witness_account_status.error();

					return expectation::met;
				}
				case oracle::routing_policy::utxo:
					break;
				default:
					return layer_exception("invalid operation");
			}

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto committee = context->calculate_participants(asset, exclusion, bridge_policy->security_level, bridge_policy->participation_threshold);
			if (!committee)
				return committee.error();

			for (auto& work : *committee)
			{
				auto event = context->emit_event<bridge_account>({ format::variable(work.owner.view()) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> bridge_account::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_running_on(manager))
				return expects_promise_rt<void>(expectation::met);

			auto* event = context->receipt.find_event<bridge_account>();
			if (!event || context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, context, dispatcher]() -> expects_promise_rt<void>
			{
				auto* chain = oracle::server_node::get()->get_chainparams(asset);
				if (!chain)
					coreturn remote_exception("invalid operation");

				auto cache = dispatcher->pull_cache(context);
				auto state = ledger::dispatch_context::public_state();
				if (!state.load_message(cache))
				{
					auto aggregator = algorithm::composition::make_public_state(chain->composition);
					if (!aggregator)
						coreturn remote_exception(std::move(aggregator.error().message()));

					state.aggregator = std::move(*aggregator);
					state.participants = get_group(context->receipt);
				}

				auto session = coawait(dispatcher->aggregate_validators(context->receipt.transaction_hash, state.participants));
				if (!session)
					coreturn session.error();

				ordered_set<algorithm::pubkeyhash_t> deferred_participants;
				while (!state.participants.empty())
				{
					auto result = coawait(dispatcher->aggregate_public_state(context, state, *state.participants.begin()));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						deferred_participants.insert(*state.participants.begin());
					else if (!result)
						coreturn result.error();

					state.participants.erase(state.participants.begin());
				}

				if (!deferred_participants.empty())
				{
					state.participants = std::move(deferred_participants);
					dispatcher->push_cache(context, state.as_message());
					coreturn remote_exception::retry();
				}

				algorithm::composition::cpubkey_t aggregated_public_key;
				auto status = state.aggregator->finalize(&aggregated_public_key);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				auto* transaction = memory::init<bridge_account_finalization>();
				transaction->asset = asset;
				transaction->set_witness(context->receipt.transaction_hash, aggregated_public_key);
				dispatcher->emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		bool bridge_account::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(manager.optimized_view());
			stream->write_string(routing_address);
			return true;
		}
		bool bridge_account::load_body(format::ro_stream& stream)
		{
			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_bytes(manager_assembly, manager.data, sizeof(manager.data)))
				return false;

			if (!stream.read_string(stream.read_type(), &routing_address))
				return false;

			return true;
		}
		bool bridge_account::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto group = get_group(receipt);
			parties.insert(algorithm::pubkeyhash_t(manager));
			parties.insert(group.begin(), group.end());
			return true;
		}
		bool bridge_account::is_dispatchable() const
		{
			return true;
		}
		void bridge_account::set_routing_address(const std::string_view& new_address)
		{
			routing_address = new_address;
		}
		void bridge_account::set_manager(const algorithm::pubkeyhash_t& new_manager)
		{
			manager = new_manager;
		}
		ordered_set<algorithm::pubkeyhash_t> bridge_account::get_group(const ledger::receipt& receipt) const
		{
			ordered_set<algorithm::pubkeyhash_t> result;
			for (auto& event : receipt.find_events<bridge_account>())
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result.insert(algorithm::pubkeyhash_t(event->front().as_blob()));
			}
			return result;
		}
		uptr<schema> bridge_account::as_schema() const
		{
			schema* data = ledger::commitment::as_schema().reset();
			data->set("manager", algorithm::signing::serialize_address(manager));
			data->set("routing_address", var::string(routing_address));
			return data;
		}
		uint32_t bridge_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_account::as_instance_typename()
		{
			return "bridge_account";
		}

		expects_lr<void> bridge_account_finalization::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!bridge_account_hash)
				return layer_exception("invalid bridge account hash");

			if (public_key.empty())
				return layer_exception("invalid public key");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bridge_account_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = commitment::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(bridge_account_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto setup = context->get_block_transaction<bridge_account>(bridge_account_hash);
			if (!setup)
				return setup.error();

			auto* setup_transaction = (bridge_account*)*setup->transaction;
			auto* server = oracle::server_node::get();
			auto* chain = server->get_chain(asset);
			auto* params = server->get_chainparams(asset);
			if (!chain || !params)
				return layer_exception("invalid operation");

			auto duplicate = context->get_bridge_account(asset, setup_transaction->manager, setup->receipt.from);
			if (duplicate)
				return layer_exception("bridge account already exists");

			auto encoded_public_key = chain->encode_public_key(std::string_view((char*)public_key.data(), public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto addresses = chain->to_addresses(*encoded_public_key);
			if (!addresses)
				return addresses.error();

			auto bridge_policy = context->get_bridge_policy(asset, setup_transaction->manager);
			if (!bridge_policy)
				return bridge_policy.error();

			switch (params->routing)
			{
				case oracle::routing_policy::account:
				case oracle::routing_policy::memo:
				{
					if (bridge_policy->accounts_under_management > 0)
						return layer_exception("too many accounts for a bridge");

					if (params->routing == oracle::routing_policy::account)
						break;

					for (auto& address : *addresses)
						address.second = oracle::address_util::encode_tag_address(address.second, to_string(bridge_policy->accounts_under_management));
					break;
				}
				default:
					break;
			}

			auto bridge_policy_status = context->apply_bridge_policy_account(asset, setup_transaction->manager, 1);
			if (!bridge_policy_status)
				return bridge_policy_status.error();

			auto group = setup_transaction->get_group(setup->receipt);
			for (auto& participant : group)
			{
				auto status = context->apply_validator_participation(asset, participant.data, ledger::transaction_context::stake_type::lock, 1, { });
				if (!status)
					return status.error();
			}

			auto bridge_account_status = context->apply_bridge_account(asset, setup->receipt.from, setup_transaction->manager, public_key, std::move(group));
			if (!bridge_account_status)
				return bridge_account_status.error();

			auto witness_account_status = context->apply_witness_bridge_account(asset, setup->receipt.from, setup_transaction->manager, *addresses);
			if (!witness_account_status)
				return witness_account_status.error();

			return expectation::met;
		}
		expects_promise_rt<void> bridge_account_finalization::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			auto setup = context->get_block_transaction<bridge_account>(bridge_account_hash);
			if (!setup)
				return expects_promise_rt<void>(remote_exception(std::move(setup.error().message())));

			ordered_set<string> addresses;
			for (auto& event : context->receipt.find_events<states::witness_account>())
			{
				for (size_t i = 2; i < event->size(); i++)
					addresses.insert(event->at(i).as_blob());
			}
			if (addresses.empty())
				return expects_promise_rt<void>(expectation::met);

			auto* server = oracle::server_node::get();
			auto* chain = server->get_chain(asset);
			auto* params = server->get_chainparams(asset);
			if (!chain || !params)
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto encoded_public_key = chain->encode_public_key(std::string_view((char*)public_key.data(), public_key.size()));
			if (!encoded_public_key)
				return expects_promise_rt<void>(remote_exception(std::move(encoded_public_key.error().message())));

			auto* setup_transaction = (bridge_account*)*setup->transaction;
			for (auto& address : addresses)
			{
				auto [base_address, tag] = oracle::address_util::decode_tag_address(address);
				if (base_address != address)
				{
					auto status = server->enable_link(asset, oracle::wallet_link(setup_transaction->manager, *encoded_public_key, base_address));
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}

				auto status = server->enable_link(asset, oracle::wallet_link(setup_transaction->manager, *encoded_public_key, address));
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
		void bridge_account_finalization::set_witness(const uint256_t& new_bridge_account_hash, const algorithm::composition::cpubkey_t& new_public_key)
		{
			bridge_account_hash = new_bridge_account_hash;
			public_key = new_public_key;
		}
		bool bridge_account_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(std::string_view((char*)public_key.data(), public_key.size()));
			stream->write_integer(bridge_account_hash);
			return true;
		}
		bool bridge_account_finalization::load_body(format::ro_stream& stream)
		{
			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			if (!stream.read_integer(stream.read_type(), &bridge_account_hash))
				return false;

			public_key.resize(public_key_assembly.size());
			memcpy(public_key.data(), public_key_assembly.data(), public_key_assembly.size());
			return true;
		}
		bool bridge_account_finalization::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto setup = context->get_block_transaction<bridge_account>(bridge_account_hash);
			if (!setup)
				return false;

			auto* setup_transaction = (bridge_account*)*setup->transaction;
			parties.insert(algorithm::pubkeyhash_t(setup_transaction->manager));
			parties.insert(algorithm::pubkeyhash_t(setup->receipt.from));
			return true;
		}
		bool bridge_account_finalization::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> bridge_account_finalization::as_schema() const
		{
			schema* data = ledger::commitment::as_schema().reset();
			data->set("bridge_account_hash", bridge_account_hash > 0 ? var::string(algorithm::encoding::encode_0xhex256(bridge_account_hash)) : var::null());
			data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)public_key.data(), public_key.size()))));
			return data;
		}
		uint32_t bridge_account_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_account_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_account_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_account_finalization::as_instance_typename()
		{
			return "bridge_account_finalization";
		}

		expects_lr<void> bridge_withdrawal::validate(uint64_t block_number) const
		{
			if (from_manager == to_manager)
				return layer_exception("invalid from/to manager");

			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (!algorithm::asset::is_aux(asset))
				return layer_exception("not a valid withdrawal asset");

			if (to_manager.empty())
			{
				if (to.empty())
					return layer_exception("invalid to");

				if (!chain->supports_bulk_transfer && to.size() > 1)
					return layer_exception("too many to addresses");

				unordered_set<string> addresses;
				for (auto& item : to)
				{
					if (addresses.find(item.first) != addresses.end())
						return layer_exception("duplicate to address");

					if (!item.second.is_positive())
						return layer_exception("invalid to value");

					addresses.insert(item.first);
				}
			}
			else if (!to.empty())
				return layer_exception("invalid to");		

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> bridge_withdrawal::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto attestation_requirement = context->verify_validator_attestation(asset, from_manager);
			if (!attestation_requirement)
				return attestation_requirement.error();

			auto bridge_policy = context->get_bridge_policy(asset, from_manager);
			if (!bridge_policy)
				return bridge_policy.error();
			else if (!bridge_policy->accepts_withdrawal_requests)
				return layer_exception("bridge forbids withdrawal requests");
			else if (only_if_not_in_queue && bridge_policy->queue_transaction_hash > 0)
				return layer_exception("bridge is in use - withdrawal will be queued");

			auto token_value = get_token_value(context);
			if (!token_value.is_positive())
				return layer_exception("zero value withdrawal not allowed");

			if (!to_manager.empty())
			{
				if (context->receipt.from != from_manager)
					return layer_exception("invalid transaction origin");

				attestation_requirement = context->verify_validator_attestation(asset, to_manager);
				if (!attestation_requirement)
					return attestation_requirement.error();

				auto account = find_receiving_account(context, asset, from_manager, to_manager);
				if (!account)
					return account.error();

				auto registration = context->apply_bridge_policy_queue(asset, from_manager, context->receipt.transaction_hash);
				if (!registration)
					return registration.error();

				return expectation::met;
			}

			auto fee_asset = algorithm::asset::base_id_of(asset);
			auto fee_value = get_fee_value(context);
			if (fee_asset != asset)
			{
				auto balance_requirement = context->verify_transfer_balance(fee_asset, fee_value);
				if (!balance_requirement)
					return balance_requirement.error();

				auto bridge = context->get_bridge_balance(fee_asset, from_manager);
				if (!bridge || bridge->get_balance(fee_asset) < fee_value)
					return layer_exception(algorithm::asset::handle_of(fee_asset) + " balance is insufficient to cover base withdrawal value (value: " + fee_value.to_string() + ")");
			}
			else
				token_value += fee_value;

			auto balance_requirement = context->verify_transfer_balance(asset, token_value);
			if (!balance_requirement)
				return balance_requirement;

			auto bridge = context->get_bridge_balance(asset, from_manager);
			if (!bridge || bridge->get_balance(asset) < token_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient to cover token withdrawal value (value: " + token_value.to_string() + ")");

			for (auto& item : to)
			{
				auto collision = context->get_witness_account(fee_asset, item.first, 0);
				if (collision && (!collision->is_routing_account() || collision->owner != context->receipt.from))
					return layer_exception("invalid to address (not owned by sender)");
				else if (!collision)
					collision = context->apply_witness_routing_account(asset, context->receipt.from, { { (uint8_t)1, string(item.first) } });
				if (!collision)
					return collision.error();
			}

			if (fee_asset != asset)
			{
				auto fee_transfer = context->apply_transfer(fee_asset, context->receipt.from, decimal::zero(), fee_value);
				if (!fee_transfer)
					return fee_transfer.error();
			}

			auto token_transfer = context->apply_transfer(asset, context->receipt.from, decimal::zero(), token_value);
			if (!token_transfer)
				return token_transfer.error();

			auto registration = context->apply_bridge_policy_queue(asset, from_manager, context->receipt.transaction_hash);
			if (!registration)
				return registration.error();

			return expectation::met;
		}
		expects_promise_rt<void> bridge_withdrawal::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_running_on(from_manager))
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto bridge_policy = context->get_bridge_policy(asset, from_manager);
			if (bridge_policy && bridge_policy->queue_transaction_hash != context->receipt.transaction_hash)
				return expects_promise_rt<void>(remote_exception::retry());

			return coasync<expects_rt<void>>([this, context, dispatcher]() mutable -> expects_promise_rt<void>
			{
				auto* server = oracle::server_node::get();
				auto* chain = server->get_chainparams(asset);
				auto cancel = [this, context, dispatcher](remote_exception&& error) -> expects_rt<void>
				{
					auto* transaction = memory::init<bridge_withdrawal_finalization>();
					transaction->asset = asset;
					transaction->set_proof(context->receipt.transaction_hash, layer_exception(std::move(remote_exception(error).message())));
					dispatcher->emit_transaction(transaction);
					return expects_rt<void>(std::move(error));
				};

				vector<oracle::value_transfer> transfers;
				if (!to_manager.empty())
				{
					auto account = find_receiving_account(context, asset, from_manager, to_manager);
					if (!account)
						coreturn cancel(remote_exception(std::move(account.error().message())));

					transfers.push_back(oracle::value_transfer(asset, account->addresses.begin()->second, get_token_value(context)));
				}
				else
				{
					for (auto& item : to)
						transfers.push_back(oracle::value_transfer(asset, item.first, decimal(item.second)));
				}

				auto cache = dispatcher->pull_cache(context);
				auto state = ledger::dispatch_context::signature_state();
				if (chain->requires_transaction_expiration || !state.load_message_if_preferred(cache))
				{
					auto message = coawait(resolver::prepare_transaction(algorithm::asset::base_id_of(asset), oracle::wallet_link::from_owner(from_manager), transfers, get_fee_value(context)));
					if (!message)
						coreturn message.error().is_retry() || message.error().is_shutdown() ? expects_rt<void>(std::move(message.error())) : cancel(std::move(message.error()));
					else if (message->inputs.size() > std::numeric_limits<uint8_t>::max())
						coreturn cancel(remote_exception("too many prepared inputs"));

					state.message = memory::init<oracle::prepared_transaction>(std::move(*message));
				}

				auto* input = state.message->next_input_for_aggregation();
				while (input != nullptr)
				{
					auto witness = context->get_witness_account_tagged(asset, input->utxo.link.address, 0);
					if (!witness)
						coreturn cancel(remote_exception(std::move(witness.error().message())));

					auto account = context->get_bridge_account(asset, witness->manager, witness->owner);
					if (!account)
						coreturn cancel(remote_exception(std::move(account.error().message())));

					auto session = coawait(dispatcher->aggregate_validators(context->receipt.transaction_hash, account->group));
					if (!session)
						coreturn session.error().is_retry() || session.error().is_shutdown() ? expects_rt<void>(std::move(session.error())) : cancel(std::move(session.error()));

					auto chosen = account->group.begin();
					auto unavailable = ordered_set<algorithm::pubkeyhash_t>();
					std::advance(chosen, (size_t)(algorithm::hashing::hash256i(input->message.data(), input->message.size()) % uint256_t(account->group.size())));
					if (!state.aggregator)
					{
						auto aggregator = algorithm::composition::make_signature_state(input->alg, input->public_key, input->message.data(), input->message.size(), (uint16_t)account->group.size());
						if (!aggregator)
							coreturn cancel(remote_exception(std::move(aggregator.error().message())));

						state.aggregator = std::move(*aggregator);
					}

					while (true)
					{
						auto phase = state.aggregator->next_phase();
						if (phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::chosen_input_after_reset)
							state.participants = account->group;

						bool uniform_input = phase == algorithm::composition::phase::any_input_after_reset || phase == algorithm::composition::phase::any_input;
						bool chosen_input = phase == algorithm::composition::phase::chosen_input_after_reset || phase == algorithm::composition::phase::chosen_input;
						auto it = (uniform_input ? state.participants.begin() : (chosen_input ? state.participants.find(*chosen) : state.participants.end()));
						it = (!chosen_input && state.participants.size() > 1 && it != state.participants.end() && it->equals(*chosen) ? ++it : it);
						if (it == state.participants.end())
							break;

						auto result = coawait(dispatcher->aggregate_signature_state(context, state, *it));
						if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						{
							unavailable.insert(*it);
							if (chosen_input)
							{
								dispatcher->push_cache(context, state.as_message());
								coreturn remote_exception::retry();
							}
						}
						else if (!result)
							coreturn cancel(std::move(result.error()));

						state.participants.erase(it);
					}

					if (!unavailable.empty())
					{
						state.participants = std::move(unavailable);
						dispatcher->push_cache(context, state.as_message());
						coreturn remote_exception::retry();
					}

					auto finalization = state.aggregator->finalize(&input->signature);
					if (!finalization)
						coreturn cancel(remote_exception(std::move(finalization.error().message())));

					input = state.message->next_input_for_aggregation();
					state.aggregator.destroy();
				}

				auto finalization = resolver::finalize_transaction(algorithm::asset::base_id_of(asset), std::move(**state.message));
				if (!finalization)
					coreturn cancel(remote_exception(std::move(finalization.error().message())));

				auto broadcast = coawait(resolver::broadcast_transaction(algorithm::asset::base_id_of(asset), context->receipt.transaction_hash, oracle::finalized_transaction(*finalization), dispatcher));
				if (!broadcast && (broadcast.error().is_retry() || broadcast.error().is_shutdown()))
					coreturn remote_exception::retry();
				else if (!broadcast)
					coreturn cancel(std::move(broadcast.error()));

				auto* transaction = memory::init<bridge_withdrawal_finalization>();
				transaction->asset = asset;
				transaction->set_proof(context->receipt.transaction_hash, std::move(*finalization));
				dispatcher->emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		bool bridge_withdrawal::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_boolean(only_if_not_in_queue);
			stream->write_string(from_manager.optimized_view());
			stream->write_string(to_manager.optimized_view());
			stream->write_integer((uint16_t)to.size());
			for (auto& item : to)
			{
				stream->write_string(item.first);
				stream->write_decimal(item.second);
			}
			return true;
		}
		bool bridge_withdrawal::load_body(format::ro_stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &only_if_not_in_queue))
				return false;

			string from_manager_assembly;
			if (!stream.read_string(stream.read_type(), &from_manager_assembly) || !algorithm::encoding::decode_bytes(from_manager_assembly, from_manager.data, sizeof(from_manager)))
				return false;

			string to_manager_assembly;
			if (!stream.read_string(stream.read_type(), &to_manager_assembly) || !algorithm::encoding::decode_bytes(to_manager_assembly, to_manager.data, sizeof(to_manager)))
				return false;

			uint16_t to_size;
			if (!stream.read_integer(stream.read_type(), &to_size))
				return false;

			for (uint16_t i = 0; i < to_size; i++)
			{
				string address;
				if (!stream.read_string(stream.read_type(), &address))
					return false;

				decimal value;
				if (!stream.read_decimal(stream.read_type(), &value))
					return false;

				to.push_back(std::make_pair(std::move(address), std::move(value)));
			}

			return true;
		}
		bool bridge_withdrawal::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			parties.insert(algorithm::pubkeyhash_t(from_manager));
			parties.insert(algorithm::pubkeyhash_t(to_manager));
			return true;
		}
		void bridge_withdrawal::set_to(const std::string_view& address, const decimal& value)
		{
			for (auto& item : to)
			{
				if (item.first == address)
				{
					item.second = value;
					return;
				}
			}
			to.push_back(std::make_pair(string(address), decimal(value)));
		}
		void bridge_withdrawal::set_manager(const algorithm::pubkeyhash_t& new_from_manager, const algorithm::pubkeyhash_t& new_to_manager)
		{
			from_manager = new_from_manager;
			to_manager = new_to_manager;
		}
		bool bridge_withdrawal::is_dispatchable() const
		{
			return true;
		}
		decimal bridge_withdrawal::get_token_value(const ledger::transaction_context* context) const
		{
			decimal value = 0.0;
			if (!to_manager.empty())
			{
				auto bridge = context->get_bridge_balance(asset, from_manager);
				if (bridge)
					value += bridge->get_balance(asset);
			}
			else
			{
				for (auto& item : to)
					value += item.second;
			}
			return value;
		}
		decimal bridge_withdrawal::get_fee_value(const ledger::transaction_context* context) const
		{
			auto reward = context->get_bridge_reward(algorithm::asset::base_id_of(asset), from_manager);
			if (!reward)
				return decimal::zero();

			return reward->outgoing_fee * to.size();
		}
		uptr<schema> bridge_withdrawal::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("from_manager", algorithm::signing::serialize_address(from_manager));
			data->set("to_manager", algorithm::signing::serialize_address(to_manager));
			data->set("only_if_not_in_queue", var::boolean(only_if_not_in_queue));
			if (!to.empty())
			{
				auto* to_data = data->set("to", var::set::array());
				for (auto& item : to)
				{
					auto* coin_data = to_data->push(var::set::object());
					coin_data->set("address", var::string(item.first));
					coin_data->set("value", var::decimal(item.second));
				}
			}
			return data;
		}
		uint32_t bridge_withdrawal::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_withdrawal::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_withdrawal::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_withdrawal::as_instance_typename()
		{
			return "bridge_withdrawal";
		}
		expects_lr<states::witness_account> bridge_withdrawal::find_receiving_account(const ledger::transaction_context* context, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from_manager, const algorithm::pubkeyhash_t& to_manager)
		{
			auto base_asset = algorithm::asset::base_id_of(asset);
			size_t offset = 0, count = 8;
			while (true)
			{
				auto candidates = context->get_witness_accounts_by_purpose(to_manager, states::witness_account::account_type::bridge, offset, count);
				if (!candidates)
					return candidates.error();

				auto candidate = std::find_if(candidates->begin(), candidates->end(), [&](const states::witness_account& v) { return v.asset == base_asset && v.manager == to_manager; });
				if (candidate != candidates->end())
					return *candidate;

				offset += candidates->size();
				if (candidates->size() < count)
					break;
			}

			offset = 0;
			while (true)
			{
				auto candidates = context->get_witness_accounts_by_purpose(from_manager, states::witness_account::account_type::bridge, offset, count);
				if (!candidates)
					return candidates.error();

				auto candidate = std::find_if(candidates->begin(), candidates->end(), [&](const states::witness_account& v) { return v.asset == base_asset && v.manager == to_manager; });
				if (candidate != candidates->end())
					return *candidate;

				offset += candidates->size();
				if (candidates->size() < count)
					break;
			}

			return layer_exception("receiving bridge account (to) not found");
		}

		expects_lr<void> bridge_withdrawal_finalization::validate(uint64_t block_number) const
		{
			if (!bridge_withdrawal_hash)
				return layer_exception("bridge withdrawal hash not valid");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bridge_withdrawal_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = commitment::execute(context);
			if (!validation)
				return validation.error();

			auto parent = context->get_block_transaction<bridge_withdrawal>(bridge_withdrawal_hash);
			if (!parent)
				return layer_exception("parent transaction not found");

			auto* parent_transaction = (bridge_withdrawal*)*parent->transaction;
			if (parent_transaction->from_manager != context->receipt.from)
				return layer_exception("parent transaction not valid");

			auto event = context->apply_witness_event(bridge_withdrawal_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto finalization = context->apply_bridge_policy_queue(parent_transaction->asset, parent_transaction->from_manager, 0);
			if (!finalization)
				return finalization.error();

			auto confirmation = proof ? validate_finalized_proof(context, parent_transaction, *proof) : proof.error();
			if (confirmation)
				return expectation::met;
			else if (proof)
				return confirmation.error();

			if (!parent_transaction->to_manager.empty())
				return expectation::met;

			auto fee_asset = algorithm::asset::base_id_of(parent_transaction->asset);
			auto fee_value = parent_transaction->get_fee_value(context);
			auto token_value = parent_transaction->get_token_value(context);
			if (fee_asset != parent_transaction->asset)
			{
				auto fee_transfer = context->apply_transfer(fee_asset, parent->receipt.from, decimal::zero(), -fee_value);
				if (!fee_transfer)
					return fee_transfer.error();
			}
			else
				token_value += fee_value;

			auto token_transfer = context->apply_transfer(parent_transaction->asset, parent->receipt.from, decimal::zero(), -token_value);
			if (!token_transfer)
				return token_transfer.error();

			return expectation::met;
		}
		bool bridge_withdrawal_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(bridge_withdrawal_hash);
			stream->write_boolean(!!proof);
			if (proof)
				proof->store_payload(stream);
			else
				stream->write_string(proof.what());
			return true;
		}
		bool bridge_withdrawal_finalization::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &bridge_withdrawal_hash))
				return false;

			bool has_proof;
			if (!stream.read_boolean(stream.read_type(), &has_proof))
				return false;

			if (has_proof)
			{
				proof = expects_lr<oracle::finalized_transaction>(oracle::finalized_transaction());
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
		bool bridge_withdrawal_finalization::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = context->get_block_transaction_instance(bridge_withdrawal_hash);
			if (!parent)
				return false;

			parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));
			return true;
		}
		void bridge_withdrawal_finalization::set_proof(const uint256_t& new_bridge_withdrawal_hash, expects_lr<oracle::finalized_transaction>&& new_proof)
		{
			bridge_withdrawal_hash = new_bridge_withdrawal_hash;
			proof = std::move(new_proof);
		}
		uptr<schema> bridge_withdrawal_finalization::as_schema() const
		{
			schema* data = ledger::commitment::as_schema().reset();
			data->set("bridge_withdrawal_hash", var::string(algorithm::encoding::encode_0xhex256(bridge_withdrawal_hash)));
			if (proof)
			{
				data->set("prepared", proof->prepared.as_schema().reset());
				data->set("calldata", var::string(proof->calldata));
				data->set("hashdata", var::string(proof->hashdata));
				data->set("locktime", algorithm::encoding::serialize_uint256(proof->locktime));
			}
			else
				data->set("error", var::string(proof.what()));
			return data;
		}
		uint32_t bridge_withdrawal_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_withdrawal_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_withdrawal_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_withdrawal_finalization::as_instance_typename()
		{
			return "bridge_withdrawal_finalization";
		}
		expects_lr<void> bridge_withdrawal_finalization::validate_possible_proof(const ledger::transaction_context* context, const bridge_withdrawal* transaction, const oracle::prepared_transaction& prepared)
		{
			if (prepared.as_status() == oracle::prepared_transaction::status::invalid)
				return layer_exception("invalid prepared transaction");

			auto server = oracle::server_node::get();
			auto base_asset = algorithm::asset::base_id_of(transaction->asset);
			auto required_output_witness = ordered_map<string, states::witness_account>();
			auto required_output_value = ordered_map<algorithm::asset_id, decimal>();
			for (auto& [output_address, output_value] : transaction->to)
			{
				auto normalized_address = output_address;
				auto status = server->normalize_address(transaction->asset, &normalized_address);
				if (!status)
					return status.error();

				if (required_output_witness.find(normalized_address) == required_output_witness.end())
				{
					auto witness = context->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("transaction requires paying to unknown address");

					required_output_witness.insert(std::make_pair(std::move(normalized_address), std::move(*witness)));
				}

				auto& value = required_output_value[transaction->asset];
				value = value.is_nan() ? output_value : (value + output_value);
			}
			if (!transaction->to_manager.empty())
			{
				if (!transaction->to.empty())
					return layer_exception("migration/withdrawal confusion");

				auto witness = bridge_withdrawal::find_receiving_account(context, transaction->asset, transaction->from_manager, transaction->to_manager);
				if (!witness)
					return layer_exception("prepared transaction not possible");

				auto account = context->get_bridge_account(base_asset, witness->manager, witness->owner);
				if (!account)
					return layer_exception("transaction output refers to a non-bridge account");

				required_output_value[transaction->asset] = decimal::nan();
				for (auto& [type, normalized_address] : witness->addresses)
				{
					auto status = server->normalize_address(base_asset, &normalized_address);
					if (!status)
						return status.error();

					required_output_witness.insert(std::make_pair(std::move(normalized_address), *witness));
				}
			}

			auto inout_witness = ordered_map<string, states::witness_account>();
			auto input_value = ordered_map<algorithm::asset_id, decimal>();
			auto output_value = ordered_map<algorithm::asset_id, decimal>();
			auto change_value = ordered_map<algorithm::asset_id, decimal>();
			for (auto& [hash, input] : prepared.inputs)
			{
				auto normalized_address = input.utxo.link.address;
				auto status = server->normalize_address(base_asset, &normalized_address);
				if (!status)
					return status.error();

				auto it = inout_witness.find(normalized_address);
				if (it == inout_witness.end())
				{
					auto witness = context->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("witness transaction input spends from unknown address");

					auto account = context->get_bridge_account(base_asset, witness->manager, witness->owner);
					if (!account)
						return layer_exception("witness transaction input refers to a non-bridge account");

					inout_witness.insert(std::make_pair(normalized_address, std::move(*witness)));
					it = inout_witness.find(normalized_address);
				}

				if (!it->second.is_bridge_account() || !it->second.manager.equals(transaction->from_manager))
					return layer_exception("witness transaction input spends from unrelated address");

				auto& value = input_value[input.utxo.get_asset(base_asset)];
				value = value.is_nan() ? input.utxo.value : (value + input.utxo.value);
				for (auto& [token_hash, token] : input.utxo.tokens)
				{
					auto& token_value = input_value[token.get_asset(base_asset)];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}
			for (auto& [hash, output] : prepared.outputs)
			{
				auto normalized_address = output.link.address;
				auto status = server->normalize_address(base_asset, &normalized_address);
				if (!status)
					return status.error();

				auto it = inout_witness.find(normalized_address);
				if (it == inout_witness.end())
				{
					auto witness = context->get_witness_account_tagged(base_asset, normalized_address, 0);
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

					auto account = context->get_bridge_account(base_asset, it->second.manager, it->second.owner);
					if (!account)
						return layer_exception("witness transaction output refers to a non-bridge account as change");
				}

				auto output_asset = output.get_asset(base_asset);
				auto& value = change_output == required_output_witness.end() ? change_value[output_asset] : output_value[output_asset];
				value = value.is_nan() ? output.value : (value + output.value);
				for (auto& [token_hash, token] : output.tokens)
				{
					auto& token_value = output_value[token.get_asset(base_asset)];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}

			if (output_value.size() < required_output_value.size())
				return layer_exception("witness transaction doesn't have required amount of outputs");

			auto& input_base_value = input_value[base_asset];
			auto& output_base_value = output_value[base_asset];
			auto& change_base_value = change_value[base_asset];
			auto fee_value = (input_base_value.is_nan() ? decimal::zero() : input_base_value) - ((output_base_value.is_nan() ? decimal::zero() : output_base_value) + (change_base_value.is_nan() ? decimal::zero() : change_base_value));
			auto max_fee_value = transaction->get_fee_value(context);
			if (fee_value.is_negative())
				return layer_exception("witness transaction output pays more that possible");
			else if (fee_value > max_fee_value)
				return layer_exception("witness transaction fee overflow (max: " + max_fee_value.to_string() + ")");

			for (auto& [output_asset, actual_output_value] : output_value)
			{
				auto it = required_output_value.find(output_asset);
				if (it != required_output_value.end())
				{
					if (!it->second.is_nan())
					{
						if (output_asset != base_asset && actual_output_value != it->second)
							return layer_exception("witness transaction output pays unexpected token value");
						else if (output_asset == base_asset && actual_output_value < it->second - max_fee_value || actual_output_value > it->second + max_fee_value)
							return layer_exception("witness transaction output pays unexpected native value");
					}
				}
				else if (output_asset == base_asset && actual_output_value > max_fee_value)
					return layer_exception("witness transaction output pays unexpected native value");
				else if (output_asset != base_asset)
					return layer_exception("witness transaction output pays unexpected token value");
			}

			return expectation::met;
		}
		expects_lr<void> bridge_withdrawal_finalization::validate_finalized_proof(const ledger::transaction_context* context, const bridge_withdrawal* transaction, const oracle::finalized_transaction& finalized)
		{
			auto validation = validate_possible_proof(context, transaction, finalized.prepared);
			if (!validation)
				return validation;

			if (finalized.calldata.empty())
				return layer_exception("invalid finalized calldata");
			else if (finalized.hashdata.empty())
				return layer_exception("invalid finalized hashdata");

			auto finalization = resolver::finalize_transaction(transaction->asset, oracle::prepared_transaction(finalized.prepared));
			if (!finalization)
				return finalization.error();

			return expectation::met;
		}

		expects_lr<void> bridge_attestation::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!proof.is_valid())
				return layer_exception("invalid proof");

			if (!proof.block_id)
				return layer_exception("transaction has no block reference");

			auto chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto blockchain = algorithm::asset::blockchain_of(asset);
			if (!proof.is_valid())
				return layer_exception("invalid proof data");

			for (auto& [hash, input] : proof.inputs)
			{
				if (input.is_account() && algorithm::asset::blockchain_of(input.get_asset(asset)) != blockchain)
					return layer_exception("proof input asset not valid");
			}

			for (auto& [hash, output] : proof.outputs)
			{
				if (output.is_account() && algorithm::asset::blockchain_of(output.get_asset(asset)) != blockchain)
					return layer_exception("proof output asset not valid");
			}

			ordered_set<algorithm::pubkeyhash_t> attesters;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				if (!commitment_hash)
					return layer_exception("invalid commitment hash");

				for (auto& signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, signature))
						return layer_exception("invalid commitment signature");
					else if (attesters.find(attester) != attesters.end())
						return layer_exception("duplicate commitment attester");

					attesters.insert(attester);
				}
			}

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bridge_attestation::execute(ledger::transaction_context* context) const
		{
			auto validation = commitment::execute(context);
			if (!validation)
				return validation.error();

			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid chain");

			auto collision = context->get_witness_transaction(asset, proof.transaction_id);
			if (collision)
				return layer_exception("proof " + proof.transaction_id + " finalized");

			uint256_t best_commitment_hash = 0;
			ordered_map<uint256_t, ordered_set<algorithm::pubkeyhash_t>> attesters;
			auto verification = verify_proof_commitment(context, asset, commitments, best_commitment_hash, attesters);
			if (!verification)
				return verification;
			else if (best_commitment_hash != proof.as_hash())
				return layer_exception("provided proof is not the chosen one");

			transition operations;
			ordered_set<algorithm::pubkeyhash_t> bridges, routers;
			auto rebalance_weights = [&](const oracle::coin_utxo& inout, bool accountable, int8_t sign)
			{
				if (inout.value.is_positive())
				{
					if (accountable)
						operations.weights[inout.get_asset(asset)].accountable += sign >= 0 ? inout.value : -inout.value;
					else
						operations.weights[inout.get_asset(asset)].unaccountable += sign >= 0 ? inout.value : -inout.value;
				}
				for (auto& [hash, token] : inout.tokens)
				{
					if (accountable)
						operations.weights[token.get_asset(asset)].accountable += sign >= 0 ? token.value : -token.value;
					else
						operations.weights[token.get_asset(asset)].unaccountable += sign >= 0 ? token.value : -token.value;
				}
			};
			for (auto& [hash, input] : proof.inputs)
			{
				auto source = context->get_witness_account(asset, input.link.address, 0);
				if (source && source->is_bridge_account())
				{
					auto from_bridge = algorithm::pubkeyhash_t(source->manager);
					auto& bridge = operations.bridges[from_bridge];
					rebalance_weights(input, true, -1);
					if (input.value.is_positive())
						bridge.transfers[input.get_asset(asset)].supply -= input.value;
					for (auto& [token_hash, token] : input.tokens)
						bridge.transfers[token.get_asset(asset)].supply -= token.value;

					auto account = context->get_bridge_account(asset, from_bridge.data, source->owner);
					if (account)
						bridge.participants.insert(account->group.begin(), account->group.end());
					bridges.insert(from_bridge);
				}
				else
				{
					rebalance_weights(input, !bridges.empty(), -1);
					if (source && source->is_routing_account())
						routers.insert(algorithm::pubkeyhash_t(source->owner));
				}
			}

			if (!bridges.empty())
			{
				for (auto& [asset, weight] : operations.weights)
				{
					weight.accountable += weight.unaccountable;
					weight.unaccountable = decimal::zero();
				}
			}

			for (auto& [hash, output] : proof.outputs)
			{
				auto source = context->get_witness_account(asset, output.link.address, 0);
				if (source && source->is_bridge_account())
				{
					auto to_bridge = algorithm::pubkeyhash_t(source->manager);
					auto& bridge = operations.bridges[to_bridge];
					auto amounts = ordered_map<algorithm::asset_id, decimal>();
					rebalance_weights(output, true, 1);
					if (output.value.is_positive())
						amounts[output.get_asset(asset)] = output.value;
					for (auto& [token_hash, token] : output.tokens)
						amounts[token.get_asset(asset)] = token.value;

					auto account = context->get_bridge_account(asset, to_bridge.data, source->owner);
					if (account)
						bridge.participants.insert(account->group.begin(), account->group.end());

					auto to_account = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
					for (auto& [token_asset, token_value] : amounts)
					{
						auto& transfer = bridge.transfers[token_asset];
						transfer.supply += token_value;
						if (token_value.is_positive() && bridges.empty())
						{
							auto& balance = operations.transfers[to_account][token_asset];
							balance.supply += token_value;
							if (!to_bridge.equals(to_account.data))
							{
								auto reward = context->get_bridge_reward(token_asset, to_bridge.data);
								if (reward && reward->incoming_fee.is_positive())
								{
									balance.supply -= reward->incoming_fee;
									transfer.incoming_fee += reward->incoming_fee;
								}
							}
						}
					}
				}
				else
				{
					rebalance_weights(output, !bridges.empty(), 1);
					if (!source || !source->is_routing_account())
						continue;

					auto from_account = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
					auto& from_transfers = operations.transfers[from_account];
					auto amounts = ordered_map<algorithm::asset_id, decimal>();
					if (output.value.is_positive())
						amounts[output.get_asset(asset)] = output.value;
					for (auto& [token_hash, token] : output.tokens)
						amounts[token.get_asset(asset)] = token.value;

					for (auto& [token_asset, token_value] : amounts)
					{
						auto& balance = from_transfers[token_asset];
						balance.supply -= token_value;
						balance.reserve -= token_value;
						if (token_value.is_positive())
						{
							for (auto from_bridge = bridges.begin(); from_bridge != bridges.end(); from_bridge++)
							{
								auto reward = context->get_bridge_reward(asset, from_bridge->data);
								auto outgoing_fee = reward ? algorithm::arithmetic::divide(reward->outgoing_fee, bridges.size()) : decimal::zero();
								if (outgoing_fee.is_positive())
								{
									auto& base_transfer = operations.bridges[*from_bridge].transfers[asset];
									auto& base_balance = from_transfers[asset];
									base_balance.supply -= outgoing_fee;
									base_balance.reserve -= outgoing_fee;
									base_transfer.outgoing_fee += outgoing_fee;
								}
							}
						}
					}
				}
			}

			if (operations.transfers.empty() && operations.bridges.empty())
				return layer_exception("invalid transaction");

			for (auto& [asset, weight] : operations.weights)
			{
				decimal fee = weight.accountable + weight.unaccountable;
				weight.accountable = math0::abs(std::min(decimal::zero(), weight.accountable - std::min(decimal::zero(), fee)));
			}

			auto& succeeding_attesters = attesters[best_commitment_hash];
			auto failing_attesters = ordered_set<algorithm::pubkeyhash_t>();
			for (auto& [commitment_hash, group] : attesters)
			{
				if (commitment_hash != best_commitment_hash)
					failing_attesters.insert(group.begin(), group.end());
			}

			for (auto& [owner, transfers] : operations.transfers)
			{
				for (auto& [transfer_asset, transfer] : transfers)
				{
					if (transfer.supply.is_zero_or_nan() && transfer.reserve.is_zero_or_nan())
						continue;

					auto supply_delta = transfer.supply.is_nan() ? decimal::zero() : transfer.supply;
					auto reserve_delta = transfer.reserve.is_nan() ? decimal::zero() : transfer.reserve;
					if (supply_delta.is_negative() || reserve_delta.is_negative())
					{
						auto balance = context->get_account_balance(transfer_asset, owner.data);
						auto supply = (balance ? balance->supply : decimal::zero()) + supply_delta;
						auto reserve = (balance ? balance->reserve : decimal::zero()) + reserve_delta;
						operations.weights[transfer_asset].accountable += std::min(decimal::zero(), std::min(supply, reserve));
						if (supply.is_negative())
							supply_delta = (balance ? -balance->supply : decimal::zero());
						if (reserve.is_negative())
							reserve_delta = (balance ? -balance->reserve : decimal::zero());
					}

					if (!supply_delta.is_zero() || !reserve_delta.is_zero())
					{
						auto delta_transfer = context->apply_transfer(transfer_asset, owner.data, supply_delta, reserve_delta);
						if (!delta_transfer)
							return delta_transfer.error();
					}
				}
			}

			for (auto& [owner, batch] : operations.bridges)
			{
				for (auto& [transfer_asset, transfer] : batch.transfers)
				{
					auto& penalty = operations.weights[transfer_asset].accountable;
					auto consume_penalty = [&penalty](const decimal& delta) -> decimal
					{
						auto adjustment = std::max(decimal::zero(), penalty - delta);
						auto result = std::max(decimal::zero(), delta - penalty);
						penalty = adjustment;
						return result;
					};
					penalty = math0::abs(penalty);
					if (transfer.supply.is_negative())
					{
						auto balance = context->get_bridge_balance(transfer_asset, owner.data);
						auto supply = balance ? -balance->get_balance(transfer_asset) : decimal::zero();
						if (supply > transfer.supply)
						{
							consume_penalty(transfer.supply - supply);
							transfer.supply = supply;
						}
					}

					if (!transfer.supply.is_zero())
					{
						auto bridge = context->apply_bridge_balance(transfer_asset, owner.data, { { transfer_asset, transfer.supply } });
						if (!bridge)
							return bridge.error();
					}

					auto total_fee = consume_penalty(transfer.incoming_fee + transfer.outgoing_fee);
					auto attestation_cut = succeeding_attesters.empty() ? decimal::zero() : decimal(protocol::now().policy.attestation_fee_rate);
					auto participation_cut = batch.participants.empty() ? decimal::zero() : decimal(protocol::now().policy.participation_fee_rate);
					auto bridge_fee = total_fee * (1 - attestation_cut - participation_cut);
					auto attestation_fee = !succeeding_attesters.empty() ? algorithm::arithmetic::divide(total_fee * attestation_cut, succeeding_attesters.size()) : decimal::zero();
					auto participation_fee = !batch.participants.empty() ? algorithm::arithmetic::divide(total_fee * participation_cut, batch.participants.size()) : decimal::zero();
					if (attestation_fee.is_positive())
					{
						for (auto& failing_attester : failing_attesters)
						{
							auto prev_attestation = context->get_validator_attestation(transfer_asset, failing_attester.data);
							if (!prev_attestation)
								continue;

							auto next_attestation = context->apply_validator_attestation(transfer_asset, failing_attester.data, ledger::transaction_context::stake_type::lock, { { transfer_asset, -attestation_fee } });
							if (!next_attestation)
								return next_attestation.error();

							auto& prev_value = prev_attestation->stakes[transfer_asset];
							auto& next_value = next_attestation->stakes[transfer_asset];
							prev_value = prev_value.is_nan() ? decimal::zero() : prev_value;
							next_value = next_value.is_nan() ? decimal::zero() : next_value;

							auto compensation_adjustment = std::max(decimal::zero(), prev_value - next_value);
							if (compensation_adjustment.is_positive())
								bridge_fee += consume_penalty(compensation_adjustment);
						}

						for (auto& succeeding_attester : succeeding_attesters)
						{
							auto attestation = context->apply_validator_attestation(transfer_asset, succeeding_attester, ledger::transaction_context::stake_type::reward_or_penalty, { { transfer_asset, attestation_fee } });
							if (!attestation)
								return attestation.error();
						}
					}

					if (penalty.is_positive() || participation_fee.is_positive())
					{
						auto individual_penalty = -algorithm::arithmetic::divide(penalty, batch.participants.size());
						for (auto& participant : batch.participants)
						{
							auto participation = context->apply_validator_participation(transfer_asset, participant.data, ledger::transaction_context::stake_type::reward_or_penalty, 0, { { transfer_asset, individual_penalty.is_negative() ? individual_penalty : participation_fee } });
							if (!participation)
								return participation.error();
						}
					}

					if (bridge_fee.is_positive())
					{
						auto attestation = context->apply_validator_attestation(transfer_asset, owner.data, ledger::transaction_context::stake_type::reward_or_penalty, { { transfer_asset, bridge_fee } });
						if (!attestation)
							return attestation.error();
					}
				}
			}

			auto finalization = context->apply_witness_transaction(asset, proof.transaction_id);
			if (!finalization)
				return finalization.error();

			return context->emit_witness(asset, proof.block_id);
		}
		bool bridge_attestation::store_body(format::wo_stream* stream) const
		{
			if (!proof.store_payload(stream))
				return false;

			stream->write_integer((uint16_t)commitments.size());
			for (auto& [commitment_hash, signatures] : commitments)
			{
				stream->write_integer(commitment_hash);
				stream->write_integer((uint16_t)signatures.size());
				for (auto& signature : signatures)
					stream->write_string(signature.optimized_view());
			}
			return true;
		}
		bool bridge_attestation::load_body(format::ro_stream& stream)
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
					if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, commitment.data, sizeof(commitment.data)))
						return false;

					signatures.insert(commitment);
				}
			}

			return true;
		}
		bool bridge_attestation::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
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
		void bridge_attestation::set_finalized_proof(uint64_t block_id, const std::string_view& transaction_id, const vector<oracle::value_transfer>& inputs, const vector<oracle::value_transfer>& outputs)
		{
			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			oracle::computed_transaction witness;
			witness.transaction_id = transaction_id;
			witness.block_id = block_id;
			for (auto& input : inputs)
			{
				auto utxo = oracle::coin_utxo(oracle::wallet_link::from_address(input.address), { { input.asset, input.value } });
				witness.inputs[utxo.as_hash()] = std::move(utxo);
			}
			for (auto& output : outputs)
			{
				auto utxo = oracle::coin_utxo(oracle::wallet_link::from_address(output.address), { { output.asset, output.value } });
				witness.outputs[utxo.as_hash()] = std::move(utxo);
			}
			set_computed_proof(std::move(witness), { });
		}
		void bridge_attestation::set_computed_proof(oracle::computed_transaction&& new_proof, ordered_map<uint256_t, ordered_set<algorithm::hashsig_t>>&& new_commitments)
		{
			proof = std::move(new_proof);
			commitments = std::move(new_commitments);
		}
		bool bridge_attestation::add_commitment(const algorithm::seckey_t& secret_key)
		{
			uint256_t commitment_hash;
			algorithm::hashsig_t commitment_signature;
			if (!commit_to_proof(proof, secret_key, commitment_hash, commitment_signature))
				return false;

			commitments[commitment_hash].insert(commitment_signature);
			return true;
		}
		uptr<schema> bridge_attestation::as_schema() const
		{
			schema* data = ledger::commitment::as_schema().reset();
			schema* commitments_data = data->set("commitments", var::set::object());
			for (auto& [commitment_hash, signatures] : commitments)
			{
				auto signatures_data = commitments_data->set(algorithm::encoding::encode_0xhex256(commitment_hash), var::set::array());
				for (auto& signature : signatures)
					signatures_data->push(signature.empty() ? var::null() : var::string(format::util::encode_0xhex(signature.view())));
			}
			data->set("proof", proof.as_schema().reset());
			return data;
		}
		uint32_t bridge_attestation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_attestation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_attestation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_attestation::as_instance_typename()
		{
			return "bridge_attestation";
		}
		expects_lr<void> bridge_attestation::verify_proof_commitment(const ledger::transaction_context* context, const algorithm::asset_id& asset, const ordered_map<uint256_t, ordered_set<algorithm::hashsig_t>>& commitments, uint256_t& best_commitment_hash, ordered_map<uint256_t, ordered_set<algorithm::pubkeyhash_t>>& attesters)
		{
			ordered_set<algorithm::pubkeyhash_t> duplicates;
			best_commitment_hash = 0;
			attesters.clear();

			for (auto& [commitment_hash, signatures] : commitments)
			{
				if (!commitment_hash)
					return layer_exception("invalid commitment hash");

				for (auto& signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, signature))
						return layer_exception("invalid commitment signature");
					else if (duplicates.find(attester) != duplicates.end())
						return layer_exception("duplicate commitment attester");

					attesters[commitment_hash].insert(attester);
					duplicates.insert(attester);
				}
			}

			auto& params = protocol::now();
			size_t required_commitments = context->calculate_attesters_size(asset).or_else(0);
			decimal best_commitment_stake = -1;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				size_t required_commitment_attestations = std::min<size_t>(required_commitments, params.policy.attestation_max_per_transaction);
				decimal current_commitment_threshold = required_commitment_attestations > 0 ? algorithm::arithmetic::divide(signatures.size(), required_commitment_attestations) : decimal::zero();
				if (current_commitment_threshold < params.policy.attestation_consensus_threshold || signatures.empty())
					continue;

				decimal commitment_stake = decimal::zero();
				for (auto& attester : attesters[commitment_hash])
				{
					auto attestation = context->get_validator_attestation(asset, attester);
					if (attestation)
						commitment_stake += attestation->get_ranked_stake();
				}

				if (commitment_stake > best_commitment_stake)
				{
					best_commitment_hash = commitment_hash;
					best_commitment_stake = commitment_stake;
				}
			}

			if (!best_commitment_hash)
				return layer_exception("proof requires more attestations");

			return expectation::met;
		}
		bool bridge_attestation::commit_to_proof(const oracle::computed_transaction& new_proof, const algorithm::seckey_t& secret_key, uint256_t& commitment_hash, algorithm::hashsig_t& signature)
		{
			commitment_hash = new_proof.as_hash();
			return algorithm::signing::sign(commitment_hash, secret_key, signature);
		}

		expects_lr<void> bridge_adjustment::validate(uint64_t block_number) const
		{
			if (incoming_fee.is_nan() || incoming_fee.is_negative())
				return layer_exception("invalid incoming fee");

			if (outgoing_fee.is_nan() || outgoing_fee.is_negative())
				return layer_exception("invalid outgoing fee");

			if (participation_threshold.is_nan() || participation_threshold.is_negative())
				return layer_exception("invalid participation threshold");

			if (security_level > 0 && security_level < protocol::now().policy.participation_min_per_account)
				return layer_exception("invalid security level");

			if (security_level > 0 && security_level > protocol::now().policy.participation_max_per_account)
				return layer_exception("invalid security level");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> bridge_adjustment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto attestation_requirement = context->verify_validator_attestation(asset, context->receipt.from);
			if (!attestation_requirement)
				return attestation_requirement;

			auto reward = context->apply_bridge_reward(algorithm::asset::base_id_of(asset), context->receipt.from, incoming_fee, outgoing_fee);
			if (!reward)
				return reward.error();

			auto bridge = context->get_bridge_policy(asset, context->receipt.from).or_else(states::bridge_policy(context->receipt.from, asset, nullptr));
			if (bridge.accepts_withdrawal_requests != accepts_withdrawal_requests && !accepts_withdrawal_requests)
			{
				auto balance = context->get_bridge_balance(asset, context->receipt.from);
				if (balance)
				{
					for (auto& [token_asset, token_value] : balance->balances)
					{
						if (algorithm::asset::is_aux(token_asset, true))
						{
							auto reward = context->get_bridge_reward_median(token_asset).or_else(states::bridge_reward(context->receipt.from, token_asset, nullptr));
							if (token_value > reward.outgoing_fee)
								return layer_exception(algorithm::asset::handle_of(token_asset) + " bridge has non-dust custodial balance (max: " + reward.outgoing_fee.to_string() + ")");
						}
						else if (token_value.is_positive())
							return layer_exception(algorithm::asset::handle_of(token_asset) + " bridge has custodial token balance");
					}
				}
			}

			if ((security_level > 0 && security_level != bridge.security_level) || bridge.participation_threshold != participation_threshold || bridge.accepts_account_requests != accepts_account_requests || bridge.accepts_withdrawal_requests != accepts_withdrawal_requests)
			{
				auto policy = context->apply_bridge_policy(asset, context->receipt.from, security_level, participation_threshold, accepts_account_requests, accepts_withdrawal_requests);
				if (!policy)
					return policy.error();
			}

			return expectation::met;
		}
		bool bridge_adjustment::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(incoming_fee);
			stream->write_decimal(outgoing_fee);
			stream->write_decimal(participation_threshold);
			stream->write_integer(security_level);
			stream->write_boolean(accepts_account_requests);
			stream->write_boolean(accepts_withdrawal_requests);
			return true;
		}
		bool bridge_adjustment::load_body(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &incoming_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &outgoing_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &participation_threshold))
				return false;

			if (!stream.read_integer(stream.read_type(), &security_level))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_account_requests))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_withdrawal_requests))
				return false;

			return true;
		}
		void bridge_adjustment::set_reward(const decimal& new_incoming_fee, const decimal& new_outgoing_fee)
		{
			incoming_fee = new_incoming_fee;
			outgoing_fee = new_outgoing_fee;
		}
		void bridge_adjustment::set_security(uint8_t new_security_level, const decimal& new_participation_threshold, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests)
		{
			participation_threshold = new_participation_threshold;
			security_level = new_security_level;
			accepts_account_requests = new_accepts_account_requests;
			accepts_withdrawal_requests = new_accepts_withdrawal_requests;
		}
		uptr<schema> bridge_adjustment::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("incoming_fee", var::decimal(incoming_fee));
			data->set("outgoing_fee", var::decimal(outgoing_fee));
			data->set("participation_threshold", var::decimal(participation_threshold));
			data->set("security_level", var::integer(security_level));
			data->set("accepts_account_requests", var::boolean(accepts_account_requests));
			data->set("accepts_withdrawal_requests", var::boolean(accepts_withdrawal_requests));
			return data;
		}
		uint32_t bridge_adjustment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_adjustment::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_adjustment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_adjustment::as_instance_typename()
		{
			return "bridge_adjustment";
		}

		expects_lr<void> bridge_migration::validate(uint64_t block_number) const
		{
			if (shares.empty())
				return layer_exception("no shares found");

			for (auto& [hash, share] : shares)
			{
				if (!algorithm::asset::is_aux(share.asset, true))
					return layer_exception("invalid share asset");

				if (share.manager.empty())
					return layer_exception("invalid share manager");

				if (share.owner.empty())
					return layer_exception("invalid share owner");

				if (hash != share.as_hash())
					return layer_exception("invalid share hash");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> bridge_migration::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto old_manager = algorithm::pubkeyhash_t(context->receipt.from);
			auto new_threshold = decimal::zero();
			for (auto& [hash, share] : shares)
			{
				auto target = context->get_bridge_account(share.asset, share.manager, share.owner);
				if (!target)
					return target.error();
				else if (target->group.find(old_manager) == target->group.end())
					return layer_exception("migration of other group member is forbidden");

				auto bridge_policy = context->get_bridge_policy(asset, share.manager);
				if (!bridge_policy)
					return bridge_policy.error();

				new_threshold = math0::max(new_threshold, bridge_policy->participation_threshold);
				exclusion.insert(target->group.begin(), target->group.end());
			}

			auto committee = context->calculate_participants(asset, exclusion, 1, new_threshold);
			if (!committee)
				return committee.error();

			auto& new_manager = committee->front();
			auto event = context->emit_event<bridge_migration>({ format::variable(new_manager.owner.view()) });
			if (!event)
				return event;

			return expectation::met;
		}
		expects_promise_rt<void> bridge_migration::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto old_manager = context->receipt.from;
			if (!dispatcher->is_running_on(old_manager.data))
				return expects_promise_rt<void>(expectation::met);

			auto new_manager = get_new_manager(context->receipt);
			if (new_manager.empty())
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, context, dispatcher, old_manager, new_manager]() -> expects_promise_rt<void>
			{
				auto* chain = oracle::server_node::get()->get_chainparams(asset);
				if (!chain)
					coreturn remote_exception("invalid operation");

				auto session = coawait(dispatcher->aggregate_validators(context->receipt.transaction_hash, { new_manager }));
				if (!session)
					coreturn session.error();

				auto tweaked_public_key = dispatcher->get_public_key(new_manager);
				if (tweaked_public_key.empty())
					coreturn remote_exception::retry();

				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(context->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					coreturn remote_exception("invalid tweaked public key");

				auto state = ledger::dispatch_context::secret_share_state();
				for (auto& [hash, share] : shares)
				{
					uint256_t scalar;
					auto status = dispatcher->recover_secret_share(share.asset, share.manager, share.owner, scalar);
					if (!status)
						coreturn remote_exception(std::move(status.error().message()));

					format::wo_stream entropy;
					entropy.write_integer(context->receipt.transaction_hash);
					entropy.write_integer(hash);

					uint8_t scalar_data[32];
					scalar.encode(scalar_data);

					auto encrypted_share = algorithm::signing::public_encrypt(tweaked_public_key, std::string_view((char*)scalar_data, sizeof(scalar_data)), entropy.hash());
					if (!encrypted_share)
						coreturn remote_exception("share encryption error");

					state.encrypted_shares[hash] = std::move(*encrypted_share);
				}

				auto result = coawait(dispatcher->aggregate_secret_share_state(context, state, new_manager));
				if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					coreturn remote_exception::retry();
				else if (!result)
					coreturn result.error();

				auto confirmation_public_key_hash = algorithm::pubkeyhash_t();
				auto confirmation_hash = state.as_confirmation_hash();
				if (!algorithm::signing::recover_hash(confirmation_hash, confirmation_public_key_hash, state.confirmation_signature) || !confirmation_public_key_hash.equals(new_manager))
					coreturn remote_exception("invalid confirmation signature");

				auto* transaction = memory::init<bridge_migration_finalization>();
				transaction->asset = asset;
				transaction->bridge_migration_hash = context->receipt.transaction_hash;
				transaction->confirmation_signature = state.confirmation_signature;
				dispatcher->emit_transaction(transaction);
				coreturn expects_promise_rt<void>(expectation::met);
			});
		}
		bool bridge_migration::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)shares.size());
			for (auto& [hash, share] : shares)
			{
				stream->write_integer(share.asset);
				stream->write_string(share.manager.optimized_view());
				stream->write_string(share.owner.optimized_view());
			}
			return true;
		}
		bool bridge_migration::load_body(format::ro_stream& stream)
		{
			uint16_t shares_size;
			if (!stream.read_integer(stream.read_type(), &shares_size))
				return false;

			string intermediate;
			for (uint16_t i = 0; i < shares_size; i++)
			{
				secret_share share;
				if (!stream.read_integer(stream.read_type(), &share.asset))
					return false;

				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, share.manager.data, sizeof(share.manager.data)))
					return false;

				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, share.owner.data, sizeof(share.owner.data)))
					return false;

				auto hash = share.as_hash();
				shares[hash] = std::move(share);
			}

			return true;
		}
		void bridge_migration::add_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner)
		{
			auto share = secret_share(asset, manager, owner);
			auto hash = share.as_hash();
			shares[hash] = std::move(share);
		}
		bool bridge_migration::is_dispatchable() const
		{
			return true;
		}
		algorithm::pubkeyhash_t bridge_migration::get_new_manager(const ledger::receipt& receipt) const
		{
			algorithm::pubkeyhash_t result;
			auto* event = receipt.find_event<bridge_migration>();
			if (event != nullptr)
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result = algorithm::pubkeyhash_t(event->front().as_blob());
			}
			return result;
		}
		uptr<schema> bridge_migration::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* shares_data = data->set("shares", var::set::array());
			for (auto& [hash, share] : shares)
			{
				auto* share_data = shares_data->push(var::set::object());
				share_data->set("asset", algorithm::asset::serialize(share.asset));
				share_data->set("manager", algorithm::signing::serialize_address(share.manager));
				share_data->set("owner", algorithm::signing::serialize_address(share.owner));
			}
			return data;
		}
		uint32_t bridge_migration::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_migration::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_migration::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_migration::as_instance_typename()
		{
			return "bridge_migration";
		}

		expects_lr<void> bridge_migration_finalization::validate(uint64_t block_number) const
		{
			if (!bridge_migration_hash)
				return layer_exception("invalid bridge migration transaction");

			if (confirmation_signature.empty())
				return layer_exception("invalid confirmation signature");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bridge_migration_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = commitment::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(bridge_migration_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto migration = context->get_block_transaction<bridge_migration>(bridge_migration_hash);
			if (!migration)
				return migration.error();

			auto* migration_transaction = (bridge_migration*)*migration->transaction;
			if (migration->receipt.from != context->receipt.from)
				return layer_exception("invalid migration transaction");

			auto state = ledger::dispatch_context::secret_share_state();
			state.confirmation_signature = confirmation_signature;
			for (auto& [hash, share] : migration_transaction->shares)
				state.encrypted_shares[hash] = string();

			auto new_manager = migration_transaction->get_new_manager(migration->receipt);
			auto confirmation_public_key_hash = algorithm::pubkeyhash_t();
			auto confirmation_hash = state.as_confirmation_hash();
			if (!algorithm::signing::recover_hash(confirmation_hash, confirmation_public_key_hash, state.confirmation_signature) || !confirmation_public_key_hash.equals(new_manager))
				return layer_exception("invalid confirmation signature");

			auto old_manager = algorithm::pubkeyhash_t(migration->receipt.from);
			for (auto& [hash, share] : migration_transaction->shares)
			{
				auto target = context->get_bridge_account(share.asset, share.manager, share.owner);
				if (!target)
					return target.error();

				auto status = context->apply_validator_participation(share.asset, old_manager.data, ledger::transaction_context::stake_type::lock, -1, { });
				if (!status)
					return status.error();

				status = context->apply_validator_participation(share.asset, new_manager.data, ledger::transaction_context::stake_type::lock, 1, { });
				if (!status)
					return status.error();

				target->group.erase(old_manager);
				target->group.insert(new_manager);
				target = context->apply_bridge_account(share.asset, share.manager, share.owner, target->public_key, std::move(target->group));
				if (!target)
					return target.error();
			}

			return expectation::met;
		}
		bool bridge_migration_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(bridge_migration_hash);
			stream->write_string(confirmation_signature.optimized_view());
			return true;
		}
		bool bridge_migration_finalization::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &bridge_migration_hash))
				return false;

			string intermediate;
			if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, confirmation_signature.data, sizeof(confirmation_signature.data)))
				return false;

			return true;
		}
		uptr<schema> bridge_migration_finalization::as_schema() const
		{
			schema* data = ledger::commitment::as_schema().reset();
			data->set("bridge_migration_hash", var::string(algorithm::encoding::encode_0xhex256(bridge_migration_hash)));
			data->set("confirmation_signature", confirmation_signature.empty() ? var::null() : var::string(format::util::encode_0xhex(confirmation_signature.view())));
			return data;
		}
		uint32_t bridge_migration_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_migration_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t bridge_migration_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_migration_finalization::as_instance_typename()
		{
			return "bridge_migration_finalization";
		}

		ledger::transaction* resolver::from_stream(format::ro_stream& stream)
		{
			uint32_t type; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &type))
				return nullptr;

			stream.seek = seek;
			return from_type(type);
		}
		ledger::transaction* resolver::from_type(uint32_t hash)
		{
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>();
			else if (hash == upgrade::as_instance_type())
				return memory::init<upgrade>();
			else if (hash == call::as_instance_type())
				return memory::init<call>();
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>();
			else if (hash == validator_adjustment::as_instance_type())
				return memory::init<validator_adjustment>();
			else if (hash == bridge_account::as_instance_type())
				return memory::init<bridge_account>();
			else if (hash == bridge_account_finalization::as_instance_type())
				return memory::init<bridge_account_finalization>();
			else if (hash == bridge_withdrawal::as_instance_type())
				return memory::init<bridge_withdrawal>();
			else if (hash == bridge_withdrawal_finalization::as_instance_type())
				return memory::init<bridge_withdrawal_finalization>();
			else if (hash == bridge_attestation::as_instance_type())
				return memory::init<bridge_attestation>();
			else if (hash == bridge_adjustment::as_instance_type())
				return memory::init<bridge_adjustment>();
			else if (hash == bridge_migration::as_instance_type())
				return memory::init<bridge_migration>();
			else if (hash == bridge_migration_finalization::as_instance_type())
				return memory::init<bridge_migration_finalization>();
			return nullptr;
		}
		ledger::transaction* resolver::from_copy(const ledger::transaction* base)
		{
			uint32_t hash = base->as_type();
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>(*(const transfer*)base);
			else if (hash == upgrade::as_instance_type())
				return memory::init<upgrade>(*(const upgrade*)base);
			else if (hash == call::as_instance_type())
				return memory::init<call>(*(const call*)base);
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>(*(const rollup*)base);
			else if (hash == validator_adjustment::as_instance_type())
				return memory::init<validator_adjustment>(*(const validator_adjustment*)base);
			else if (hash == bridge_account::as_instance_type())
				return memory::init<bridge_account>(*(const bridge_account*)base);
			else if (hash == bridge_account_finalization::as_instance_type())
				return memory::init<bridge_account_finalization>(*(const bridge_account_finalization*)base);
			else if (hash == bridge_withdrawal::as_instance_type())
				return memory::init<bridge_withdrawal>(*(const bridge_withdrawal*)base);
			else if (hash == bridge_withdrawal_finalization::as_instance_type())
				return memory::init<bridge_withdrawal_finalization>(*(const bridge_withdrawal_finalization*)base);
			else if (hash == bridge_attestation::as_instance_type())
				return memory::init<bridge_attestation>(*(const bridge_attestation*)base);
			else if (hash == bridge_adjustment::as_instance_type())
				return memory::init<bridge_adjustment>(*(const bridge_adjustment*)base);
			else if (hash == bridge_migration::as_instance_type())
				return memory::init<bridge_migration>(*(const bridge_migration*)base);
			else if (hash == bridge_migration_finalization::as_instance_type())
				return memory::init<bridge_migration_finalization>(*(const bridge_migration_finalization*)base);
			return nullptr;
		}
		expects_promise_rt<oracle::prepared_transaction> resolver::prepare_transaction(const algorithm::asset_id& asset, const oracle::wallet_link& from_link, const vector<oracle::value_transfer>& to, const decimal& max_fee)
		{
			auto* server = oracle::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
				return server->prepare_transaction(asset, from_link, to, max_fee);

			auto chain = server->get_chainparams(asset);
			if (!chain)
				return expects_promise_rt<oracle::prepared_transaction>(remote_exception("invalid operation"));

			auto from = server->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<oracle::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::wo_stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<oracle::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = server->to_composite_public_key(asset, from->public_key);
			if (!public_key)
				return expects_promise_rt<oracle::prepared_transaction>(remote_exception(std::move(public_key.error().message())));

			auto transfers = unordered_map<algorithm::asset_id, decimal>();
			for (auto& transfer : to)
			{
				auto& value = transfers[transfer.asset];
				value = value.is_nan() ? transfer.value : (value + transfer.value);
				message.write_integer(transfer.asset);
				message.write_string(transfer.address);
				message.write_decimal(transfer.value);
			}

			uint8_t message_hash[32];
			message.hash().encode(message_hash);

			oracle::prepared_transaction regtest_prepared;
			regtest_prepared.requires_account_input(chain->composition, std::move(*from), *public_key, message_hash, sizeof(message_hash), std::move(transfers));
			for (auto& transfer : to)
				regtest_prepared.requires_account_output(transfer.address, { { transfer.asset, transfer.value } });

			return expects_promise_rt<oracle::prepared_transaction>(std::move(regtest_prepared));
		}
		expects_lr<oracle::finalized_transaction> resolver::finalize_transaction(const algorithm::asset_id& asset, oracle::prepared_transaction&& prepared)
		{
			auto* server = oracle::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
				return server->finalize_transaction(asset, std::move(prepared));

			auto transaction_id = algorithm::encoding::encode_0xhex256(prepared.as_hash());
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint32_t>::max();
			auto regtest_finalized = oracle::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			regtest_finalized.calldata = regtest_finalized.as_message().encode();
			return expects_lr<oracle::finalized_transaction>(std::move(regtest_finalized));
		}
		expects_promise_rt<void> resolver::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, oracle::finalized_transaction&& finalized, ledger::dispatch_context* dispatcher)
		{
			auto* server = oracle::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
			{
				auto preserved = memory::init<oracle::finalized_transaction>(std::move(finalized));
				return server->broadcast_transaction(asset, external_id, *preserved).then<expects_rt<void>>([preserved](expects_rt<void>&& status) mutable -> expects_rt<void>
				{
					memory::deinit(preserved);
					if (!status)
						return expects_rt<void>(std::move(status.error()));

					return expects_rt<void>(expectation::met);
				});
			}

			if (dispatcher != nullptr)
			{
				auto* transaction = memory::init<bridge_attestation>();
				transaction->asset = asset;
				transaction->set_gas(decimal::zero(), 0);
				transaction->set_computed_proof(finalized.as_computed(), { });
				dispatcher->emit_transaction(transaction);
			}
			return expects_promise_rt<void>(expectation::met);
		}
	}
}
