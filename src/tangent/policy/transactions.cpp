#include "transactions.h"
#include "../kernel/block.h"
#include "../kernel/svm.h"
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
			auto* container = ledger::svm_container::get();
			auto compiler = container->allocate();
			switch (type)
			{
				case data_type::program:
				{
					auto code = container->unpack(storage);
					if (!code)
						return code.error();

					auto hashcode = container->hashcode(*code);
					if (!container->precompile(*compiler, hashcode))
					{
						auto compilation = container->compile(*compiler, hashcode, format::util::encode_0xhex(hashcode), *code);
						if (!compilation)
							return compilation.error();
					}

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
					break;
				}
				case data_type::hashcode:
				{
					if (!container->precompile(*compiler, storage))
					{
						auto program = context->get_witness_program(storage);
						if (!program)
							return layer_exception("program is not stored");

						auto code = program->as_code();
						if (!code)
							return code.error();

						auto compilation = container->compile(*compiler, storage, format::util::encode_0xhex(storage), *code);
						if (!compilation)
							return compilation.error();
					}

					auto status = context->apply_account_program(account.data, storage);
					if (!status)
						return status.error();
					break;
				}
				default:
					return layer_exception("invalid data type");
			}

			auto script = ledger::svm_program(context);
			return script.construct(*compiler, args);
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
			data.append(ledger::svm_container::get()->pack(new_data).or_else(string()));
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

			auto index = context->get_account_program(callable);
			if (!index)
				return layer_exception("program is not assigned");

			auto* container = ledger::svm_container::get();
			auto& hashcode = index->hashcode;
			auto compiler = container->allocate();
			if (!container->precompile(*compiler, hashcode))
			{
				auto program = context->get_witness_program(hashcode);
				if (!program)
					return layer_exception("program is not stored");

				auto code = program->as_code();
				if (!code)
					return code.error();

				auto compilation = container->compile(*compiler, hashcode, format::util::encode_0xhex(hashcode), *code);
				if (!compilation)
					return compilation.error();
			}

			if (value.is_positive())
			{
				if (context->receipt.from == callable)
					return layer_exception("invalid payment");

				auto payment = context->apply_payment(asset, context->receipt.from, callable, value);
				if (!payment)
					return payment.error();
			}

			auto script = ledger::svm_program(context);
			return script.mutable_call(*compiler, function, args);
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
					if (!transaction || transaction->as_type() == as_type())
						return layer_exception("invalid sub-transaction");

					auto* reference = (ledger::transaction*)*transaction;
					if (transaction->asset != group.first || transaction->conservative || !transaction->gas_price.is_nan() || !transaction->gas_limit)
						return layer_exception("invalid sub-transaction data");

					uint64_t transaction_nonce = transaction->nonce;
					uint8_t transaction_code = transaction->signature.data[0];
					uint256_t transaction_hash = transaction->as_hash();
					reference->gas_price = decimal::zero();
					reference->nonce = 1;
					reference->signature.data[0] = 0xFF;
					auto validation = transaction->validate(block_number);
					reference->signature.data[0] = transaction_code;
					reference->nonce = transaction_nonce;
					reference->gas_price = decimal::nan();
					if (!validation)
						return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction_hash) + " validation failed: " + validation.error().message());
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

			for (auto& [transaction, index] : queue)
			{
				bool internal_transaction = transaction->signature.empty();
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
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " validation failed: invalid signature");

				transaction->gas_price = decimal::zero();
				auto execution = ledger::transaction_context::execute_tx(context->environment, (ledger::block*)context->block, context->changelog, transaction, transaction->as_hash(), owner, transaction->as_message().data.size(), execution_flags);
				transaction->signature.data[0] = transaction_code;
				transaction->nonce = transaction_nonce;
				transaction->gas_price = decimal::nan();
				if (!execution)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " execution failed: " + execution.error().message());

				relative_gas_use += execution->receipt.relative_gas_use;
				auto report = context->emit_event<rollup>({ format::variable(execution->receipt.transaction_hash), format::variable(index), format::variable(execution->receipt.relative_gas_use), format::variable(execution->receipt.relative_gas_paid) });
				if (!report)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " event merge failed: " + report.error().message());

				context->receipt.events.reserve(context->receipt.events.size() + execution->receipt.events.size());
				for (auto& event : execution->receipt.events)
					context->receipt.events.push_back(std::move(event));
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
				stream->write_integer(group.first == asset ? uint256_t(0) : group.first);
				stream->write_integer((uint32_t)group.second.size());
				for (auto& transaction : group.second)
				{
					bool internal_transaction = transaction->signature.empty();
					stream->write_boolean(internal_transaction);
					stream->write_integer(transaction->as_type());
					stream->write_integer(transaction->gas_limit);
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

				group_asset = group_asset ? group_asset : asset;
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
					if (!next || !stream.read_integer(stream.read_type(), &next->gas_limit))
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
			normalize_transaction(transaction, asset);
			if (!transaction.gas_limit)
			{
				bool successful = transaction.sign(secret_key, transaction.nonce, decimal::zero());
				normalize_transaction(transaction, asset);
				if (!successful)
					return false;
			}

			transaction.signature.clear();
			return import_transaction(transaction);
		}
		bool rollup::import_external_transaction(ledger::transaction& transaction, const algorithm::seckey_t& secret_key, uint64_t nonce)
		{
			transaction.nonce = nonce > 0 ? nonce : transaction.nonce;
			normalize_transaction(transaction, asset);
			if (!transaction.gas_limit)
			{
				bool successful = transaction.sign(secret_key, transaction.nonce, decimal::zero());
				normalize_transaction(transaction, asset);
				if (!successful)
					return false;
			}
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
			transaction.receipt.relative_gas_paid = 0;
			transaction.receipt.transaction_hash = transaction.transaction->as_hash();
			if (!transaction.transaction->recover_hash(transaction.receipt.from))
				return layer_exception("sub-transaction not valid");

			size_t offset = 0;
			size_t begin = std::string::npos, end = std::string::npos;
			for (auto& event : receipt.events)
			{
				++offset;
				if (event.first != rollup::as_instance_type() || event.second.size() != 3)
					continue;

				uint256_t candidate_hash = event.second[0].as_uint256();
				if (candidate_hash == transaction_hash)
				{
					begin = offset - 1;
					transaction.receipt.relative_gas_use = event.second[1].as_uint256();
					transaction.receipt.relative_gas_paid = event.second[2].as_uint256();
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
			if (!transaction.asset)
				transaction.asset = asset;
			transaction.gas_price = decimal::nan();
			transaction.conservative = false;
		}

		expects_lr<void> certification::validate(uint64_t block_number) const
		{
			if (!production && participation_stakes.empty() && attestation_stakes.empty())
				return layer_exception("invalid certification");

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
		expects_lr<void> certification::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			if (production)
			{
				auto type = *production ? ledger::transaction_context::production_type::mint_gas_and_activate : ledger::transaction_context::production_type::burn_gas_and_deactivate;
				auto status = context->apply_validator_production(context->receipt.from, type, 0, { });
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
				if (type == ledger::transaction_context::stake_type::unlock)
				{
					auto depository = context->get_depository_policy(asset, context->receipt.from);
					if (depository && (depository->accepts_account_requests || depository->accepts_withdrawal_requests))
						return layer_exception(algorithm::asset::handle_of(asset) + " depository is still active");
				}

				auto balance = context->get_depository_balance(asset, context->receipt.from);
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
					if (type == ledger::transaction_context::stake_type::lock)
						continue;

					if (balance && balance->get_balance(token_asset).is_positive())
						return layer_exception(algorithm::asset::handle_of(token_asset) + " depository has custodial balance");
				}

				auto status = context->apply_validator_attestation(asset, context->receipt.from, type, stakes);
				if (!status)
					return status.error();
			}

			return expectation::met;
		}
		bool certification::store_body(format::wo_stream* stream) const
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
		bool certification::load_body(format::ro_stream& stream)
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
		void certification::enable_block_production()
		{
			production = true;
		}
		void certification::disable_block_production()
		{
			production = false;
		}
		void certification::standby_on_block_production()
		{
			production = optional::none;
		}
		void certification::allocate_participation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value >= 0.0)
				participation_stakes[asset] = value;
		}
		void certification::deallocate_participation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value.is_positive())
				participation_stakes[asset] = -value;
		}
		void certification::disable_participation(const algorithm::asset_id& asset)
		{
			participation_stakes[asset] = decimal::nan();
		}
		void certification::standby_on_participation(const algorithm::asset_id& asset)
		{
			participation_stakes.erase(asset);
		}
		void certification::allocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value >= 0.0)
				attestation_stakes[asset] = value;
		}
		void certification::deallocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			if (value.is_positive())
				attestation_stakes[asset] = -value;
		}
		void certification::disable_attestation(const algorithm::asset_id& asset)
		{
			attestation_stakes[asset] = decimal::nan();
		}
		void certification::standby_on_attestation(const algorithm::asset_id& asset)
		{
			attestation_stakes.erase(asset);
		}
		uptr<schema> certification::as_schema() const
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
		uint32_t certification::as_type() const
		{
			return as_instance_type();
		}
		std::string_view certification::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t certification::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view certification::as_instance_typename()
		{
			return "certification";
		}

		expects_lr<void> depository_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			return ledger::delegation_transaction::validate(block_number);
		}
		expects_lr<void> depository_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto attestation_requirement = context->verify_validator_attestation(asset, manager);
			if (!attestation_requirement)
				return attestation_requirement.error();

			auto depository_policy = context->get_depository_policy(asset, manager);
			if (!depository_policy)
				return depository_policy.error();
			else if (!depository_policy->accepts_account_requests)
				return layer_exception("depository forbids account requests");

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

			auto duplicate = context->get_depository_account(asset, manager, context->receipt.from);
			if (duplicate)
			{
				if (!routing_address_application)
					return layer_exception("depository account already exists");

				return expectation::met;
			}

			switch (chain->routing)
			{
				case warden::routing_policy::account:
				{
					if (!depository_policy->accounts_under_management)
						break;

					if (!routing_address_application)
						return layer_exception("too many accounts for a depository");

					return expectation::met;
				}
				case warden::routing_policy::memo:
				{
					size_t offset = 0, count = 64;
					while (depository_policy->accounts_under_management > 0)
					{
						auto candidates = context->get_witness_accounts_by_purpose(manager, states::witness_account::account_type::depository, offset, count);
						if (!candidates)
							return candidates.error();

						auto candidate = std::find_if(candidates->begin(), candidates->end(), [this](const states::witness_account& v) { return v.asset == asset && v.manager == manager; });
						if (candidate != candidates->end())
						{
							uint64_t address_index = depository_policy->accounts_under_management + 1;
							for (auto& address : candidate->addresses)
								address.second = warden::address_util::encode_tag_address(address.second, to_string(address_index));

							auto depository_policy_status = context->apply_depository_policy_account(asset, manager, 1);
							if (!depository_policy_status)
								return depository_policy_status.error();

							auto depository_account_status = context->apply_depository_account(asset, context->receipt.from, manager, algorithm::composition::cpubkey_t(), { });
							if (!depository_account_status)
								return depository_account_status.error();

							auto witness_account_status = context->apply_witness_depository_account(asset, context->receipt.from, manager, candidate->addresses);
							if (!witness_account_status)
								return witness_account_status.error();

							return expectation::met;
						}

						offset += candidates->size();
						if (candidates->size() < count)
							break;
					}
					break;
				}
				case warden::routing_policy::utxo:
				{
					auto duplicate = context->get_depository_account(asset, manager, context->receipt.from);
					if (duplicate)
						return layer_exception("depository account already exists");
					break;
				}
				default:
					return layer_exception("invalid operation");
			}

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto committee = context->calculate_participants(asset, exclusion, depository_policy->security_level);
			if (!committee)
				return committee.error();

			for (auto& work : *committee)
			{
				auto event = context->emit_event<depository_account>({ format::variable(work.owner.view()) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> depository_account::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_running_on(manager))
				return expects_promise_rt<void>(expectation::met);

			auto* event = context->receipt.find_event<depository_account>();
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

				auto* transaction = memory::init<depository_account_finalization>();
				transaction->asset = asset;
				transaction->set_witness(context->receipt.transaction_hash, aggregated_public_key);
				dispatcher->emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		bool depository_account::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(routing_address);
			return true;
		}
		bool depository_account::load_body(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &routing_address))
				return false;

			return true;
		}
		bool depository_account::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto group = get_group(receipt);
			parties.insert(algorithm::pubkeyhash_t(manager));
			parties.insert(group.begin(), group.end());
			return true;
		}
		bool depository_account::is_dispatchable() const
		{
			return true;
		}
		void depository_account::set_routing_address(const std::string_view& new_address)
		{
			routing_address = new_address;
		}
		ordered_set<algorithm::pubkeyhash_t> depository_account::get_group(const ledger::receipt& receipt) const
		{
			ordered_set<algorithm::pubkeyhash_t> result;
			for (auto& event : receipt.find_events<depository_account>())
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result.insert(algorithm::pubkeyhash_t(event->front().as_blob()));
			}
			return result;
		}
		uint32_t depository_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_account::as_instance_typename()
		{
			return "depository_account";
		}

		expects_lr<void> depository_account_finalization::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!depository_account_hash)
				return layer_exception("invalid depository account hash");

			if (public_key.empty())
				return layer_exception("invalid public key");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_account_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(depository_account_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto setup = context->get_block_transaction<depository_account>(depository_account_hash);
			if (!setup)
				return setup.error();

			auto* setup_transaction = (depository_account*)*setup->transaction;
			auto* server = oracle::server_node::get();
			auto* chain = server->get_chain(asset);
			auto* params = server->get_chainparams(asset);
			if (!chain || !params)
				return layer_exception("invalid operation");

			auto duplicate = context->get_depository_account(asset, setup_transaction->manager, setup->receipt.from);
			if (duplicate)
				return layer_exception("depository account already exists");

			auto encoded_public_key = chain->encode_public_key(std::string_view((char*)public_key.data(), public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto addresses = chain->to_addresses(*encoded_public_key);
			if (!addresses)
				return addresses.error();

			auto depository_policy = context->get_depository_policy(asset, setup_transaction->manager);
			if (!depository_policy)
				return depository_policy.error();

			switch (params->routing)
			{
				case warden::routing_policy::account:
				{
					if (depository_policy->accounts_under_management > 0)
						return layer_exception("too many accounts for a depository");
					break;
				}
				case warden::routing_policy::memo:
				{
					uint64_t address_index = depository_policy->accounts_under_management + 1;
					for (auto& address : *addresses)
						address.second = warden::address_util::encode_tag_address(address.second, to_string(address_index));
					break;
				}
				default:
					break;
			}

			auto depository_policy_status = context->apply_depository_policy_account(asset, setup_transaction->manager, 1);
			if (!depository_policy_status)
				return depository_policy_status.error();

			auto group = setup_transaction->get_group(setup->receipt);
			for (auto& participant : group)
			{
				auto status = context->apply_validator_participation(asset, participant.data, ledger::transaction_context::stake_type::lock, 1, { });
				if (!status)
					return status.error();
			}

			auto depository_account_status = context->apply_depository_account(asset, setup->receipt.from, setup_transaction->manager, public_key, std::move(group));
			if (!depository_account_status)
				return depository_account_status.error();

			auto witness_account_status = context->apply_witness_depository_account(asset, setup->receipt.from, setup_transaction->manager, *addresses);
			if (!witness_account_status)
				return witness_account_status.error();

			return expectation::met;
		}
		expects_promise_rt<void> depository_account_finalization::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			auto setup = context->get_block_transaction<depository_account>(depository_account_hash);
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

			auto* setup_transaction = (depository_account*)*setup->transaction;
			for (auto& address : addresses)
			{
				auto [base_address, tag] = warden::address_util::decode_tag_address(address);
				if (base_address != address)
				{
					auto status = server->enable_link(asset, warden::wallet_link(setup_transaction->manager, *encoded_public_key, base_address));
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}

				auto status = server->enable_link(asset, warden::wallet_link(setup_transaction->manager, *encoded_public_key, address));
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
		void depository_account_finalization::set_witness(const uint256_t& new_depository_account_hash, const algorithm::composition::cpubkey_t& new_public_key)
		{
			depository_account_hash = new_depository_account_hash;
			public_key = new_public_key;
		}
		bool depository_account_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(std::string_view((char*)public_key.data(), public_key.size()));
			stream->write_integer(depository_account_hash);
			return true;
		}
		bool depository_account_finalization::load_body(format::ro_stream& stream)
		{
			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			if (!stream.read_integer(stream.read_type(), &depository_account_hash))
				return false;

			public_key.resize(public_key_assembly.size());
			memcpy(public_key.data(), public_key_assembly.data(), public_key_assembly.size());
			return true;
		}
		bool depository_account_finalization::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto setup = context->get_block_transaction<depository_account>(depository_account_hash);
			if (!setup)
				return false;

			auto* setup_transaction = (depository_account*)*setup->transaction;
			parties.insert(algorithm::pubkeyhash_t(setup_transaction->manager));
			parties.insert(algorithm::pubkeyhash_t(setup->receipt.from));
			return true;
		}
		bool depository_account_finalization::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> depository_account_finalization::as_schema() const
		{
			size_t index = 0;
			auto params = oracle::server_node::get()->get_chainparams(asset);
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_account_hash", depository_account_hash > 0 ? var::string(algorithm::encoding::encode_0xhex256(depository_account_hash)) : var::null());
			data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)public_key.data(), public_key.size()))));
			return data;
		}
		uint32_t depository_account_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_account_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_account_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_account_finalization::as_instance_typename()
		{
			return "depository_account_finalization";
		}

		expects_lr<void> depository_withdrawal::validate(uint64_t block_number) const
		{
			if (from_manager == to_manager)
				return layer_exception("invalid from/to manager");

			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (!algorithm::asset::is_fully_valid(asset))
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
		expects_lr<void> depository_withdrawal::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto attestation_requirement = context->verify_validator_attestation(asset, from_manager);
			if (!attestation_requirement)
				return attestation_requirement.error();

			auto depository_policy = context->get_depository_policy(asset, from_manager);
			if (!depository_policy)
				return depository_policy.error();
			else if (!depository_policy->accepts_withdrawal_requests)
				return layer_exception("depository forbids withdrawal requests");
			else if (only_if_not_in_queue && depository_policy->queue_transaction_hash > 0)
				return layer_exception("depository is in use - withdrawal will be queued");

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

				auto registration = context->apply_depository_policy_queue(asset, from_manager, context->receipt.transaction_hash);
				if (!registration)
					return registration.error();

				return expectation::met;
			}

			auto fee_asset = algorithm::asset::base_id_of(asset);
			auto fee_value = get_fee_value(context, algorithm::pubkeyhash_t());
			if (fee_asset != asset && fee_value.is_positive())
			{
				auto balance_requirement = context->verify_transfer_balance(fee_asset, fee_value);
				if (!balance_requirement)
					return balance_requirement.error();

				auto depository = context->get_depository_balance(fee_asset, from_manager);
				if (!depository || depository->get_balance(fee_asset) < fee_value)
					return layer_exception(algorithm::asset::handle_of(fee_asset) + " balance is insufficient to cover base withdrawal value (value: " + fee_value.to_string() + ")");
			}

			auto balance_requirement = context->verify_transfer_balance(asset, token_value);
			if (!balance_requirement)
				return balance_requirement;

			auto depository = context->get_depository_balance(asset, from_manager);
			if (!depository || depository->get_balance(asset) < token_value)
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

			auto registration = context->apply_depository_policy_queue(asset, from_manager, context->receipt.transaction_hash);
			if (!registration)
				return registration.error();

			return expectation::met;
		}
		expects_promise_rt<void> depository_withdrawal::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_running_on(from_manager))
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto depository_policy = context->get_depository_policy(asset, from_manager);
			if (depository_policy && depository_policy->queue_transaction_hash != context->receipt.transaction_hash)
				return expects_promise_rt<void>(remote_exception::retry());

			vector<warden::value_transfer> transfers;
			if (!to_manager.empty())
			{
				auto account = find_receiving_account(context, asset, from_manager, to_manager);
				if (!account)
				{
					auto error = remote_exception(std::move(account.error().message()));
					auto* transaction = memory::init<depository_withdrawal_finalization>();
					transaction->asset = asset;
					transaction->set_failure_witness(error.what(), context->receipt.transaction_hash);
					dispatcher->emit_transaction(transaction);
					return expects_promise_rt<void>(std::move(error));
				}

				transfers.push_back(warden::value_transfer(asset, account->addresses.begin()->second, get_token_value(context)));
			}
			else
			{
				auto fee_asset = algorithm::asset::base_id_of(asset);
				auto fee_value = get_fee_value(context, algorithm::pubkeyhash_t());
				for (auto& item : to)
					transfers.push_back(warden::value_transfer(asset, item.first, decimal(fee_asset == asset ? item.second - fee_value : item.second)));
			}

			return coasync<expects_rt<void>>([this, context, dispatcher, transfers = std::move(transfers)]() mutable -> expects_promise_rt<void>
			{
				auto* server = oracle::server_node::get();
				auto* chain = server->get_chainparams(asset);
				auto cancel = [this, context, dispatcher](remote_exception&& error) -> expects_rt<void>
				{
					auto* transaction = memory::init<depository_withdrawal_finalization>();
					transaction->asset = asset;
					transaction->set_failure_witness(error.what(), context->receipt.transaction_hash);
					dispatcher->emit_transaction(transaction);
					return expects_rt<void>(std::move(error));
				};

				auto cache = dispatcher->pull_cache(context);
				auto state = ledger::dispatch_context::signature_state();
				if (chain->requires_transaction_expiration || !state.load_message_if_preferred(cache))
				{
					auto message = coawait(resolver::prepare_transaction(algorithm::asset::base_id_of(asset), warden::wallet_link::from_owner(from_manager), transfers));
					if (!message)
						coreturn message.error().is_retry() || message.error().is_shutdown() ? expects_rt<void>(std::move(message.error())) : cancel(std::move(message.error()));
					else if (message->inputs.size() > std::numeric_limits<uint8_t>::max())
						coreturn cancel(remote_exception("too many prepared inputs"));

					state.message = memory::init<warden::prepared_transaction>(std::move(*message));
				}

				auto* input = state.message->next_input_for_aggregation();
				while (input != nullptr)
				{
					auto witness = context->get_witness_account_tagged(asset, input->utxo.link.address, 0);
					if (!witness)
						coreturn cancel(remote_exception(std::move(witness.error().message())));

					auto account = context->get_depository_account(asset, witness->manager, witness->owner);
					if (!account)
						coreturn cancel(remote_exception(std::move(account.error().message())));

					auto session = coawait(dispatcher->aggregate_validators(context->receipt.transaction_hash, account->group));
					if (!session)
						coreturn session.error();

					auto chosen = account->group.begin();
					auto unavailable = ordered_set<algorithm::pubkeyhash_t>();
					std::advance(chosen, (size_t)(algorithm::hashing::hash256i(input->message.data(), input->message.size()) % uint256_t(account->group.size())));
					if (!state.aggregator)
					{
						auto aggregator = algorithm::composition::make_signature_state(chain->composition, input->public_key, input->message.data(), input->message.size(), (uint16_t)account->group.size());
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

				auto finalization = coawait(resolver::finalize_and_broadcast_transaction(algorithm::asset::base_id_of(asset), context->receipt.transaction_hash, std::move(**state.message), dispatcher));
				if (!finalization && (finalization.error().is_retry() || finalization.error().is_shutdown()))
				{
					dispatcher->push_cache(context, state.as_message());
					coreturn remote_exception::retry();
				}
				else if (!finalization)
					coreturn cancel(std::move(finalization.error()));

				auto* transaction = memory::init<depository_withdrawal_finalization>();
				transaction->asset = asset;
				transaction->set_success_witness(finalization->hashdata, finalization->calldata, context->receipt.transaction_hash);
				dispatcher->emit_transaction(transaction);
				coreturn expectation::met;
			});
		}
		bool depository_withdrawal::store_body(format::wo_stream* stream) const
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
		bool depository_withdrawal::load_body(format::ro_stream& stream)
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
		bool depository_withdrawal::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			parties.insert(algorithm::pubkeyhash_t(from_manager));
			parties.insert(algorithm::pubkeyhash_t(to_manager));
			return true;
		}
		void depository_withdrawal::set_to(const std::string_view& address, const decimal& value)
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
		void depository_withdrawal::set_manager(const algorithm::pubkeyhash_t& new_from_manager, const algorithm::pubkeyhash_t& new_to_manager)
		{
			from_manager = new_from_manager;
			to_manager = new_to_manager;
		}
		bool depository_withdrawal::is_dispatchable() const
		{
			return true;
		}
		decimal depository_withdrawal::get_token_value(const ledger::transaction_context* context) const
		{
			decimal value = 0.0;
			if (!to_manager.empty())
			{
				auto depository = context->get_depository_balance(asset, from_manager);
				if (depository)
					value += depository->get_balance(asset);
			}
			else
			{
				for (auto& item : to)
					value += item.second;
			}
			return value;
		}
		decimal depository_withdrawal::get_fee_value(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& from) const
		{
			auto& from_target = from.empty() ? context->receipt.from : from;
			if (!to_manager.empty() || from_target == from_manager)
				return decimal::zero();

			auto reward = context->get_depository_reward(algorithm::asset::base_id_of(asset), from_manager);
			if (!reward)
				return decimal::zero();

			return reward->outgoing_fee * to.size();
		}
		uptr<schema> depository_withdrawal::as_schema() const
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
		uint32_t depository_withdrawal::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_withdrawal::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_withdrawal::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_withdrawal::as_instance_typename()
		{
			return "depository_withdrawal";
		}
		expects_lr<void> depository_withdrawal::validate_prepared_transaction(const ledger::transaction_context* context, const depository_withdrawal* transaction, const warden::prepared_transaction& prepared)
		{
			if (prepared.as_status() == warden::prepared_transaction::status::invalid)
				return layer_exception("invalid prepared transaction");

			auto blockchain = algorithm::asset::blockchain_of(transaction->asset);
			auto base_asset = algorithm::asset::base_id_of(transaction->asset);
			for (auto& input : prepared.inputs)
			{
				if (input.utxo.is_account() && algorithm::asset::blockchain_of(input.utxo.get_asset(base_asset)) != blockchain)
					return layer_exception("prepared input asset not valid");
			}

			for (auto& output : prepared.outputs)
			{
				if (output.is_account() && algorithm::asset::blockchain_of(output.get_asset(base_asset)) != blockchain)
					return layer_exception("prepared output asset not valid");
			}

			auto input_value = unordered_map<algorithm::asset_id, decimal>();
			auto output_value = unordered_map<algorithm::asset_id, decimal>();
			for (auto& input : prepared.inputs)
			{
				auto& value = input_value[input.utxo.get_asset(base_asset)];
				value = value.is_nan() ? input.utxo.value : (value + input.utxo.value);
				for (auto& token : input.utxo.tokens)
				{
					auto& token_value = input_value[token.get_asset(base_asset)];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}
			for (auto& output : prepared.outputs)
			{
				auto& value = output_value[output.get_asset(base_asset)];
				value = value.is_nan() ? output.value : (value + output.value);
				for (auto& token : output.tokens)
				{
					auto& token_value = output_value[token.get_asset(base_asset)];
					token_value = token_value.is_nan() ? token.value : (token_value + token.value);
				}
			}
			for (auto& output : output_value)
			{
				auto input = input_value.find(output.first);
				if (input == input_value.end() || input->second < output.second)
					return layer_exception("prepared transaction inout not valid");
			}

			auto target_output = output_value.find(transaction->asset);
			if (target_output == output_value.end())
				return layer_exception("prepared transaction inout not valid");

			auto server = oracle::server_node::get();
			auto presented_output_addresses = unordered_set<string>();
			for (auto& output : prepared.outputs)
			{
				auto presented_address = output.link.address;
				auto status = server->normalize_address(base_asset, &presented_address);
				if (!status)
					return status.error();

				presented_output_addresses.insert(presented_address);
			}

			for (auto& transfer : transaction->to)
			{
				auto required_address = transfer.first;
				auto status = server->normalize_address(base_asset, &required_address);
				if (!status)
					return status.error();

				target_output->second -= transfer.second;
				if (presented_output_addresses.find(required_address) == presented_output_addresses.end())
					return layer_exception("prepared transaction inout not valid");
			}

			if (target_output->second.is_negative())
			{
				algorithm::pubkeyhash_t from;
				if (!transaction->recover_hash(from))
					return layer_exception("failed to recover withdrawal sender");

				auto base_fee_value = transaction->asset == base_asset ? transaction->get_fee_value(context, from) : decimal::zero();
				target_output->second += base_fee_value;
				if (target_output->second.is_negative())
					return layer_exception("prepared transaction inout not valid");
			}

			for (auto& input : prepared.inputs)
			{
				auto witness = context->get_witness_account_tagged(base_asset, input.utxo.link.address, 0);
				if (!witness || !witness->is_depository_account())
					return layer_exception("input refers to an address that does not exist or is not depository address");

				auto account = context->get_depository_account(base_asset, witness->manager, witness->owner);
				if (!account)
					return layer_exception("input refers to an account that does not have a linked depository");
			}

			return expectation::met;
		}
		expects_lr<states::witness_account> depository_withdrawal::find_receiving_account(const ledger::transaction_context* context, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from_manager, const algorithm::pubkeyhash_t& to_manager)
		{
			auto base_asset = algorithm::asset::base_id_of(asset);
			size_t offset = 0, count = 8;
			while (true)
			{
				auto candidates = context->get_witness_accounts_by_purpose(to_manager, states::witness_account::account_type::depository, offset, count);
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
				auto candidates = context->get_witness_accounts_by_purpose(from_manager, states::witness_account::account_type::depository, offset, count);
				if (!candidates)
					return candidates.error();

				auto candidate = std::find_if(candidates->begin(), candidates->end(), [&](const states::witness_account& v) { return v.asset == base_asset && v.manager == to_manager; });
				if (candidate != candidates->end())
					return *candidate;

				offset += candidates->size();
				if (candidates->size() < count)
					break;
			}

			return layer_exception("receiving depository account (to) not found");
		}

		expects_lr<void> depository_withdrawal_finalization::validate(uint64_t block_number) const
		{
			if (!depository_withdrawal_hash)
				return layer_exception("depository withdrawal hash not valid");

			if (error_message.empty() && (transaction_id.empty() || native_data.empty()))
				return layer_exception("invalid transaction success data");

			if (!error_message.empty() && (!transaction_id.empty() || !native_data.empty()))
				return layer_exception("invalid transaction error data");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_withdrawal_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto parent = context->get_block_transaction<depository_withdrawal>(depository_withdrawal_hash);
			if (!parent)
				return layer_exception("parent transaction not found");

			auto* parent_transaction = (depository_withdrawal*)*parent->transaction;
			if (parent_transaction->from_manager != context->receipt.from)
				return layer_exception("parent transaction not valid");

			auto event = context->apply_witness_event(depository_withdrawal_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto finalization = context->apply_depository_policy_queue(asset, parent_transaction->from_manager, 0);
			if (!finalization)
				return finalization.error();

			bool revert_withdrawal_side_effects = (transaction_id.empty() || !error_message.empty()) && parent_transaction->to_manager.empty();
			if (revert_withdrawal_side_effects)
			{
				auto fee_asset = algorithm::asset::base_id_of(asset);
				if (fee_asset != asset)
				{
					auto fee_value = parent_transaction->get_fee_value(context, algorithm::pubkeyhash_t());
					auto fee_transfer = context->apply_transfer(asset, parent->receipt.from, decimal::zero(), -fee_value);
					if (!fee_transfer)
						return fee_transfer.error();
				}

				auto token_value = parent_transaction->get_token_value(context);
				auto token_transfer = context->apply_transfer(asset, parent->receipt.from, decimal::zero(), -token_value);
				if (!token_transfer)
					return token_transfer.error();
			}

			return expectation::met;
		}
		bool depository_withdrawal_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_withdrawal_hash);
			stream->write_string(transaction_id);
			stream->write_string(native_data);
			stream->write_string(error_message);
			return true;
		}
		bool depository_withdrawal_finalization::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_withdrawal_hash))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			if (!stream.read_string(stream.read_type(), &native_data))
				return false;

			if (!stream.read_string(stream.read_type(), &error_message))
				return false;

			return true;
		}
		bool depository_withdrawal_finalization::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = context->get_block_transaction_instance(depository_withdrawal_hash);
			if (!parent)
				return false;

			parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));
			return true;
		}
		void depository_withdrawal_finalization::set_success_witness(const std::string_view& new_transaction_id, const std::string_view& new_native_data, const uint256_t& new_depository_withdrawal_hash)
		{
			depository_withdrawal_hash = new_depository_withdrawal_hash;
			transaction_id = new_transaction_id;
			native_data = new_native_data;
			error_message.clear();
		}
		void depository_withdrawal_finalization::set_failure_witness(const std::string_view& new_error_message, const uint256_t& new_depository_withdrawal_hash)
		{
			depository_withdrawal_hash = new_depository_withdrawal_hash;
			transaction_id.clear();
			native_data.clear();
			error_message = new_error_message;
		}
		uptr<schema> depository_withdrawal_finalization::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_withdrawal_hash", var::string(algorithm::encoding::encode_0xhex256(depository_withdrawal_hash)));
			if (!transaction_id.empty())
				data->set("transaction_id", var::string(transaction_id));
			if (!native_data.empty())
				data->set("native_data", var::string(native_data));
			if (!error_message.empty())
				data->set("error_message", var::string(error_message));
			return data;
		}
		uint32_t depository_withdrawal_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_withdrawal_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_withdrawal_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_withdrawal_finalization::as_instance_typename()
		{
			return "depository_withdrawal_finalization";
		}

		expects_lr<void> depository_transaction::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto assertion = get_assertion(nullptr);
			if (!assertion || !assertion->is_valid())
				return layer_exception("invalid assertion");

			if (!assertion->is_mature(asset))
				return layer_exception("transaction is not mature enough");

			auto chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto blockchain = algorithm::asset::blockchain_of(asset);
			if (!assertion->is_valid())
				return layer_exception("invalid assertion data");

			for (auto& input : assertion->inputs)
			{
				if (input.is_account() && algorithm::asset::blockchain_of(input.get_asset(asset)) != blockchain)
					return layer_exception("assertion input asset not valid");
			}

			for (auto& output : assertion->outputs)
			{
				if (output.is_account() && algorithm::asset::blockchain_of(output.get_asset(asset)) != blockchain)
					return layer_exception("assertion output asset not valid");
			}

			return ledger::attestation_transaction::validate(block_number);
		}
		expects_lr<void> depository_transaction::execute(ledger::transaction_context* context) const
		{
			auto validation = attestation_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto assertion = get_assertion(context);
			if (!assertion)
				return layer_exception("invalid assertion");

			auto collision = context->get_witness_transaction(asset, assertion->transaction_id);
			if (collision)
				return layer_exception("assertion " + assertion->transaction_id + " finalized");

			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid chain");

			transition operations;
			ordered_set<algorithm::pubkeyhash_t> depositories, routers;
			for (auto& input : assertion->inputs)
			{
				auto source = context->get_witness_account(asset, input.link.address, 0);
				if (!source)
					continue;

				if (source->is_depository_account())
				{
					auto from_depository = algorithm::pubkeyhash_t(source->manager);
					auto& depository = operations.depositories[from_depository];
					if (input.value.is_positive())
						depository.transfers[input.get_asset(asset)].balance -= input.value;
					for (auto& token : input.tokens)
						depository.transfers[token.get_asset(asset)].balance -= token.value;

					auto account = context->get_depository_account(asset, from_depository.data, source->owner);
					if (account)
						depository.participants.insert(account->group.begin(), account->group.end());
					depositories.insert(from_depository);
				}
				else if (source->is_routing_account())
					routers.insert(algorithm::pubkeyhash_t(source->owner));
			}

			for (auto& output : assertion->outputs)
			{
				auto source = context->get_witness_account(asset, output.link.address, 0);
				if (!source)
					continue;

				if (source->is_depository_account())
				{
					auto to_depository = algorithm::pubkeyhash_t(source->manager);
					auto& depository = operations.depositories[to_depository];
					auto amounts = ordered_map<algorithm::asset_id, decimal>();
					if (output.value.is_positive())
						amounts[output.get_asset(asset)] = output.value;
					for (auto& token : output.tokens)
						amounts[token.get_asset(asset)] = token.value;

					auto to_account = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
					for (auto& [token_asset, token_value] : amounts)
					{
						auto& target_depository = depository.transfers[token_asset];
						target_depository.balance += token_value;
						if (!token_value.is_positive() || !depositories.empty())
							continue;

						auto& balance = operations.transfers[to_account][token_asset];
						balance.supply += token_value;
						if (to_depository.equals(to_account.data))
							continue;

						auto reward = context->get_depository_reward(token_asset, to_depository.data);
						if (reward && reward->incoming_fee.is_positive())
						{
							balance.supply -= reward->incoming_fee;
							target_depository.incoming_fee += reward->incoming_fee;
						}
					}
				}
				else if (source->is_routing_account())
				{
					auto from_account = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
					auto& from_transfers = operations.transfers[from_account];
					auto amounts = ordered_map<algorithm::asset_id, decimal>();
					if (output.value.is_positive())
						amounts[output.get_asset(asset)] = output.value;
					for (auto& token : output.tokens)
						amounts[token.get_asset(asset)] = token.value;

					for (auto& [token_asset, token_value] : amounts)
					{
						auto& balance = from_transfers[token_asset];
						balance.supply -= token_value;
						balance.reserve -= token_value;
						if (!token_value.is_positive() || depositories.empty())
							continue;

						auto from_depository = *depositories.begin();
						auto reward = context->get_depository_reward(asset, from_depository.data);
						if (reward && reward->outgoing_fee.is_positive())
						{
							auto& base_balance = from_transfers[asset];
							base_balance.supply -= reward->outgoing_fee;
							base_balance.reserve -= reward->outgoing_fee;
							operations.depositories[from_depository].transfers[asset].outgoing_fee += reward->outgoing_fee;
						}
					}
				}
			}

			if (operations.transfers.empty() && operations.depositories.empty())
				return layer_exception("invalid transaction");

			ordered_set<algorithm::pubkeyhash_t> failing_attesters;
			const evaluation_branch* best_branch = get_best_branch(context, nullptr);
			for (auto& branch : output_hashes)
			{
				if (best_branch == &branch.second)
					continue;

				for (auto& signature : branch.second.signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(get_branch_image(branch.first), attester, signature))
						return layer_exception("invalid attestation signature");

					failing_attesters.insert(attester);
				}
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

			for (auto& [owner, batch] : operations.depositories)
			{
				for (auto& [transfer_asset, transfer] : batch.transfers)
				{
					if (transfer.balance.is_negative())
					{
						auto balance = context->get_depository_balance(transfer_asset, owner.data);
						auto supply = (balance ? balance->get_balance(transfer_asset) : decimal::zero()) + transfer.balance;
						if (supply.is_negative())
							transfer.balance = (balance ? -balance->get_balance(transfer_asset) : decimal::zero());
					}

					auto depository = context->apply_depository_balance(transfer_asset, owner.data, { { transfer_asset, transfer.balance } });
					if (!depository)
						return depository.error();

					if (transfer.incoming_fee.is_positive())
					{
						auto depository_fee = transfer.incoming_fee * (1.0 - protocol::now().policy.attestation_fee_rate);
						if (depository_fee.is_positive())
						{
							auto attestation = context->apply_validator_attestation(transfer_asset, owner.data, ledger::transaction_context::stake_type::reward, { { transfer_asset, depository_fee } });
							if (!attestation)
								return attestation.error();
						}

						if (!best_branch)
							best_branch = get_best_branch(context, nullptr);

						auto attestation_fee = transfer.incoming_fee * protocol::now().policy.attestation_fee_rate;
						if (attestation_fee.is_positive() && !best_branch->signatures.empty())
						{
							attestation_fee /= decimal(best_branch->signatures.size()).truncate(protocol::now().message.decimal_precision);
							if (attestation_fee.is_positive())
							{
								for (size_t i = 0; i < best_branch->signatures.size(); i++)
								{
									algorithm::pubkeyhash_t target;
									if (!recover_hash(target, best_branch->message.hash(), i))
										return layer_exception("invalid attestation signature");

									auto attestation = context->apply_validator_attestation(transfer_asset, target, ledger::transaction_context::stake_type::reward, { { transfer_asset, depository_fee } });
									if (!attestation)
										return attestation.error();
								}
							}
						}

						ordered_map<algorithm::asset_id, decimal> attestation_compensation;
						for (auto& attester : failing_attesters)
						{
							auto prev_attestation = context->get_validator_attestation(transfer_asset, attester.data);
							if (!prev_attestation)
								continue;

							auto next_attestation = context->apply_validator_attestation(transfer_asset, attester.data, ledger::transaction_context::stake_type::lock, { { transfer_asset, -transfer.incoming_fee } });
							if (!next_attestation)
								return next_attestation.error();

							auto& prev_value = prev_attestation->stakes[transfer_asset];
							auto& next_value = next_attestation->stakes[transfer_asset];
							prev_value = prev_value.is_nan() ? decimal::zero() : prev_value;
							next_value = next_value.is_nan() ? decimal::zero() : next_value;

							auto compensation_adjustment = std::max(decimal::zero(), prev_value - next_value);
							if (!compensation_adjustment.is_positive())
								continue;

							auto& compensation = attestation_compensation[transfer_asset];
							compensation = std::max(decimal::zero(), prev_value - next_value);
						}

						if (!attestation_compensation.empty())
						{
							auto attestation = context->apply_validator_attestation(transfer_asset, owner.data, ledger::transaction_context::stake_type::reward, attestation_compensation);
							if (!attestation)
								return attestation.error();
						}
					}

					if (transfer.outgoing_fee.is_positive())
					{
						auto depository_fee = transfer.outgoing_fee * (1.0 - protocol::now().policy.participation_fee_rate);
						if (depository_fee.is_positive())
						{
							auto attestation = context->apply_validator_attestation(transfer_asset, owner.data, ledger::transaction_context::stake_type::reward, { { transfer_asset, depository_fee } });
							if (!attestation)
								return attestation.error();
						}

						auto participation_fee = transfer.outgoing_fee * protocol::now().policy.attestation_fee_rate;
						if (participation_fee.is_positive() && !batch.participants.empty())
						{
							participation_fee /= decimal(batch.participants.size()).truncate(protocol::now().message.decimal_precision);
							if (participation_fee.is_positive())
							{
								for (auto& participant : batch.participants)
								{
									auto participation = context->apply_validator_participation(transfer_asset, participant.data, ledger::transaction_context::stake_type::reward, 0, { { transfer_asset, participation_fee } });
									if (!participation)
										return participation.error();
								}
							}
						}
					}
				}
			}

			auto witness = context->apply_witness_transaction(asset, assertion->transaction_id);
			if (!witness)
				return witness.error();

			return context->emit_witness(asset, std::max(assertion->block_id.execution, assertion->block_id.finalization));
		}
		bool depository_transaction::store_body(format::wo_stream* stream) const
		{
			return true;
		}
		bool depository_transaction::load_body(format::ro_stream& stream)
		{
			return true;
		}
		bool depository_transaction::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& event : receipt.find_events<states::account_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			for (auto& event : receipt.find_events<states::depository_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash_t))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			return true;
		}
		void depository_transaction::set_pending_witness(uint64_t block_id, const std::string_view& transaction_id, const vector<warden::value_transfer>& inputs, const vector<warden::value_transfer>& outputs)
		{
			warden::computed_transaction witness;
			witness.transaction_id = transaction_id;
			witness.block_id.execution = block_id;
			witness.inputs.reserve(inputs.size());
			witness.outputs.reserve(outputs.size());
			for (auto& input : inputs)
				witness.inputs.push_back(warden::coin_utxo(warden::wallet_link::from_address(input.address), { { input.asset, input.value } }));
			for (auto& output : outputs)
				witness.outputs.push_back(warden::coin_utxo(warden::wallet_link::from_address(output.address), { { output.asset, output.value } }));
			set_computed_witness(witness);
		}
		void depository_transaction::set_finalized_witness(uint64_t block_id, const std::string_view& transaction_id, const vector<warden::value_transfer>& inputs, const vector<warden::value_transfer>& outputs)
		{
			auto* chain = oracle::server_node::get()->get_chainparams(asset);
			warden::computed_transaction witness;
			witness.transaction_id = transaction_id;
			witness.block_id.execution = block_id;
			witness.block_id.finalization = block_id;
			witness.inputs.reserve(inputs.size());
			witness.outputs.reserve(outputs.size());
			for (auto& input : inputs)
				witness.inputs.push_back(warden::coin_utxo(warden::wallet_link::from_address(input.address), { { input.asset, input.value } }));
			for (auto& output : outputs)
				witness.outputs.push_back(warden::coin_utxo(warden::wallet_link::from_address(output.address), { { output.asset, output.value } }));
			set_computed_witness(witness);
		}
		void depository_transaction::set_computed_witness(const warden::computed_transaction& witness)
		{
			auto copy = witness;
			if (copy.block_id.finalization > 0)
			{
				auto* chain = oracle::server_node::get()->get_chainparams(asset);
				if (chain != nullptr)
					copy.block_id.finalization = copy.block_id.execution + chain->sync_latency;
			}
			set_statement(algorithm::hashing::hash256i(copy.transaction_id), copy.as_message());
		}
		option<warden::computed_transaction> depository_transaction::get_assertion(const ledger::transaction_context* context) const
		{
			auto* best_branch = get_best_branch(context, nullptr);
			if (!best_branch)
				return optional::none;

			auto message = best_branch->message.ro();
			warden::computed_transaction assertion;
			if (!assertion.load(message))
				return optional::none;

			return assertion;
		}
		uptr<schema> depository_transaction::as_schema() const
		{
			auto assertion = get_assertion(nullptr);
			schema* data = ledger::attestation_transaction::as_schema().reset();
			data->set("assertion", assertion ? assertion->as_schema().reset() : var::set::null());
			return data;
		}
		uint32_t depository_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_transaction::as_instance_typename()
		{
			return "depository_transaction";
		}

		expects_lr<void> depository_adjustment::validate(uint64_t block_number) const
		{
			if (incoming_fee.is_nan() || incoming_fee.is_negative())
				return layer_exception("invalid incoming fee");

			if (outgoing_fee.is_nan() || outgoing_fee.is_negative())
				return layer_exception("invalid outgoing fee");

			if (security_level > 0 && security_level < protocol::now().policy.participation_min_per_account)
				return layer_exception("invalid security level");

			if (security_level > 0 && security_level > protocol::now().policy.participation_max_per_account)
				return layer_exception("invalid security level");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_adjustment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto attestation_requirement = context->verify_validator_attestation(asset, context->receipt.from);
			if (!attestation_requirement)
				return attestation_requirement;

			auto reward = context->apply_depository_reward(algorithm::asset::base_id_of(asset), context->receipt.from, incoming_fee, outgoing_fee);
			if (!reward)
				return reward.error();

			auto depository = context->get_depository_policy(asset, context->receipt.from).or_else(states::depository_policy(context->receipt.from, asset, nullptr));
			if (depository.accepts_withdrawal_requests != accepts_withdrawal_requests && !accepts_withdrawal_requests && algorithm::asset::is_fully_valid(asset))
			{
				auto balance = context->get_depository_balance(asset, context->receipt.from);
				if (balance && balance->get_balance(asset).is_positive())
					return layer_exception("depository should not contain custodial funds before disabling withdrawals");
			}

			if ((security_level > 0 && security_level != depository.security_level) || depository.accepts_account_requests != accepts_account_requests || depository.accepts_withdrawal_requests != accepts_withdrawal_requests)
			{
				auto policy = context->apply_depository_policy(asset, context->receipt.from, security_level, accepts_account_requests, accepts_withdrawal_requests);
				if (!policy)
					return policy.error();
			}

			return expectation::met;
		}
		bool depository_adjustment::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(incoming_fee);
			stream->write_decimal(outgoing_fee);
			stream->write_integer(security_level);
			stream->write_boolean(accepts_account_requests);
			stream->write_boolean(accepts_withdrawal_requests);
			return true;
		}
		bool depository_adjustment::load_body(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &incoming_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &outgoing_fee))
				return false;

			if (!stream.read_integer(stream.read_type(), &security_level))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_account_requests))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_withdrawal_requests))
				return false;

			return true;
		}
		void depository_adjustment::set_reward(const decimal& new_incoming_fee, const decimal& new_outgoing_fee)
		{
			incoming_fee = new_incoming_fee;
			outgoing_fee = new_outgoing_fee;
		}
		void depository_adjustment::set_security(uint8_t new_security_level, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests)
		{
			security_level = new_security_level;
			accepts_account_requests = new_accepts_account_requests;
			accepts_withdrawal_requests = new_accepts_withdrawal_requests;
		}
		uptr<schema> depository_adjustment::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("incoming_fee", var::decimal(incoming_fee));
			data->set("outgoing_fee", var::decimal(outgoing_fee));
			data->set("security_level", var::integer(security_level));
			data->set("accepts_account_requests", var::boolean(accepts_account_requests));
			data->set("accepts_withdrawal_requests", var::boolean(accepts_withdrawal_requests));
			return data;
		}
		uint32_t depository_adjustment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_adjustment::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_adjustment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_adjustment::as_instance_typename()
		{
			return "depository_adjustment";
		}

		expects_lr<void> depository_regrouping::validate(uint64_t block_number) const
		{
			if (participants.empty())
				return layer_exception("no participants found");

			for (auto& [hash, account] : participants)
			{
				if (!algorithm::asset::is_fully_valid(account.asset, true))
					return layer_exception("invalid account asset");

				if (account.manager.empty())
					return layer_exception("invalid account manager");

				if (account.owner.empty())
					return layer_exception("invalid account owner");

				if (hash != account.hash())
					return layer_exception("invalid account hash");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_regrouping::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto migrating_manager = algorithm::pubkeyhash_t(context->receipt.from);
			for (auto& [hash, account] : participants)
			{
				auto target = context->get_depository_account(account.asset, account.manager, account.owner);
				if (!target)
					return target.error();
				else if (target->group.find(migrating_manager) == target->group.end())
					return layer_exception("regroup of other group member is forbidden");

				exclusion.insert(target->group.begin(), target->group.end());
			}

			auto committee = context->calculate_participants(asset, exclusion, 1);
			if (!committee)
				return committee.error();

			auto& work = committee->front();
			auto event = context->emit_event<depository_regrouping>({ format::variable(work.owner.view()) });
			if (!event)
				return event;

			return expectation::met;
		}
		expects_promise_rt<void> depository_regrouping::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto new_manager = get_new_manager(context->receipt);
			if (!dispatcher->is_running_on(new_manager.data))
				return expects_promise_rt<void>(expectation::met);

			auto* transaction = memory::init<depository_regrouping_preparation>();
			transaction->asset = asset;
			transaction->depository_regrouping_hash = context->receipt.transaction_hash;

			algorithm::seckey_t child_secret_key;
			algorithm::signing::derive_secret_key_from_parent(dispatcher->get_wallet()->secret_key, transaction->depository_regrouping_hash, child_secret_key);
			algorithm::signing::derive_public_key(child_secret_key, transaction->manager_public_key);
			dispatcher->emit_transaction(transaction);
			return expects_promise_rt<void>(expectation::met);
		}
		bool depository_regrouping::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)participants.size());
			for (auto& [hash, account] : participants)
			{
				stream->write_integer(account.asset);
				stream->write_string(algorithm::pubkeyhash_t(account.manager).optimized_view());
				stream->write_string(algorithm::pubkeyhash_t(account.owner).optimized_view());
			}
			return true;
		}
		bool depository_regrouping::load_body(format::ro_stream& stream)
		{
			uint16_t participants_size;
			if (!stream.read_integer(stream.read_type(), &participants_size))
				return false;

			for (uint16_t i = 0; i < participants_size; i++)
			{
				participant account;
				if (!stream.read_integer(stream.read_type(), &account.asset))
					return false;

				string manager_assembly;
				if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_bytes(manager_assembly, account.manager.data, sizeof(account.manager)))
					return false;

				string owner_assembly;
				if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, account.owner.data, sizeof(account.owner)))
					return false;

				participants[account.hash()] = std::move(account);
			}

			return true;
		}
		void depository_regrouping::migrate(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner)
		{
			participant account;
			account.asset = asset;
			account.manager = manager;
			account.owner = owner;
			participants[account.hash()] = std::move(account);
		}
		bool depository_regrouping::is_dispatchable() const
		{
			return true;
		}
		algorithm::pubkeyhash_t depository_regrouping::get_new_manager(const ledger::receipt& receipt) const
		{
			algorithm::pubkeyhash_t result;
			auto* event = receipt.find_event<depository_regrouping>();
			if (event != nullptr)
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result = algorithm::pubkeyhash_t(event->front().as_blob());
			}
			return result;
		}
		uptr<schema> depository_regrouping::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* participants_data = data->set("participants", var::set::array());
			for (auto& [hash, account] : participants)
			{
				auto* account_data = participants_data->push(var::set::object());
				account_data->set("asset", algorithm::asset::serialize(account.asset));
				account_data->set("manager", algorithm::signing::serialize_address(account.manager));
				account_data->set("owner", algorithm::signing::serialize_address(account.owner));
			}
			return data;
		}
		uint32_t depository_regrouping::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_regrouping::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_regrouping::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_regrouping::as_instance_typename()
		{
			return "depository_regrouping";
		}

		expects_lr<void> depository_regrouping_preparation::validate(uint64_t block_number) const
		{
			if (!depository_regrouping_hash)
				return layer_exception("invalid regroup transaction");

			if (manager_public_key.empty() || !algorithm::signing::verify_public_key(manager_public_key))
				return layer_exception("invalid manager public key");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_regrouping_preparation::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(depository_regrouping_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			return expectation::met;
		}
		expects_promise_rt<void> depository_regrouping_preparation::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto setup = context->get_block_transaction<depository_regrouping>(depository_regrouping_hash);
			if (!setup)
				return expects_promise_rt<void>(remote_exception(std::move(setup.error().message())));
			else if (!dispatcher->is_running_on(setup->receipt.from))
				return expects_promise_rt<void>(expectation::met);

			uptr<depository_regrouping_commitment> transaction = memory::init<depository_regrouping_commitment>();
			transaction->asset = asset;
			transaction->depository_regrouping_preparation_hash = context->receipt.transaction_hash;

			auto* setup_transaction = (depository_regrouping*)*setup->transaction;
			auto old_manager = dispatcher->get_wallet();
			for (auto& [hash, account] : setup_transaction->participants)
			{
				auto share = dispatcher->recover_group_share(account.asset, account.manager, account.owner);
				if (!share)
					return expects_promise_rt<void>(remote_exception(std::move(share.error().message())));

				auto status = transaction->transfer(hash, *share, manager_public_key, old_manager->secret_key);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			dispatcher->emit_transaction(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool depository_regrouping_preparation::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_regrouping_hash);
			stream->write_string(algorithm::pubkey_t(manager_public_key).optimized_view());
			return true;
		}
		bool depository_regrouping_preparation::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_regrouping_hash))
				return false;

			string manager_public_key_assembly;
			if (!stream.read_string(stream.read_type(), &manager_public_key_assembly) || !algorithm::encoding::decode_bytes(manager_public_key_assembly, manager_public_key.data, sizeof(manager_public_key)))
				return false;

			return true;
		}
		bool depository_regrouping_preparation::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> depository_regrouping_preparation::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_regrouping_hash", var::string(algorithm::encoding::encode_0xhex256(depository_regrouping_hash)));
			data->set("manager_public_key", var::string(format::util::encode_0xhex(manager_public_key.optimized_view())));
			return data;
		}
		uint32_t depository_regrouping_preparation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_regrouping_preparation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_regrouping_preparation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_regrouping_preparation::as_instance_typename()
		{
			return "depository_regrouping_preparation";
		}

		expects_lr<void> depository_regrouping_commitment::validate(uint64_t block_number) const
		{
			if (!depository_regrouping_preparation_hash)
				return layer_exception("invalid depository regroup transaction");

			if (encrypted_shares.empty())
				return layer_exception("no participants found");

			for (auto& [hash, encrypted_share] : encrypted_shares)
			{
				if (!hash || encrypted_share.empty())
					return layer_exception("invalid share");
			}

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_regrouping_commitment::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto preparation = context->get_block_transaction<depository_regrouping_preparation>(depository_regrouping_preparation_hash);
			if (!preparation)
				return preparation.error();

			auto* preparation_transaction = (depository_regrouping_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_regrouping>(preparation_transaction->depository_regrouping_hash);
			if (!setup)
				return setup.error();
			else if (setup->receipt.from != context->receipt.from)
				return layer_exception("invalid setup transaction");

			auto event = context->apply_witness_event(depository_regrouping_preparation_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto* setup_transaction = (depository_regrouping*)*setup->transaction;
			if (setup_transaction->participants.size() != encrypted_shares.size())
				return layer_exception("invalid participants size");

			auto new_manager = setup_transaction->get_new_manager(setup->receipt);
			if (!new_manager.equals(preparation->receipt.from))
				return layer_exception("invalid preparation transaction");

			return expectation::met;
		}
		expects_promise_rt<void> depository_regrouping_commitment::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto preparation = context->get_block_transaction<depository_regrouping_preparation>(depository_regrouping_preparation_hash);
			if (!preparation)
				return expects_promise_rt<void>(remote_exception(std::move(preparation.error().message())));

			if (!dispatcher->is_running_on(preparation->receipt.from))
				return expects_promise_rt<void>(expectation::met);

			auto* preparation_transaction = (depository_regrouping_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_regrouping>(preparation_transaction->depository_regrouping_hash);
			if (!setup)
				return expects_promise_rt<void>(remote_exception(std::move(setup.error().message())));

			algorithm::seckey_t child_secret_key;
			algorithm::signing::derive_secret_key_from_parent(dispatcher->get_wallet()->secret_key, preparation_transaction->depository_regrouping_hash, child_secret_key);

			bool exchange_successful = true;
			auto* setup_transaction = (depository_regrouping*)*setup->transaction;
			for (auto& [hash, encrypted_share] : encrypted_shares)
			{
				auto it = setup_transaction->participants.find(hash);
				if (it != setup_transaction->participants.end())
				{
					auto decrypted_share = algorithm::signing::private_decrypt(child_secret_key, encrypted_share);
					if (decrypted_share && decrypted_share->size() == sizeof(uint256_t))
					{
						uint256_t share;
						share.decode((uint8_t*)decrypted_share->data());

						auto& account = it->second;
						if (dispatcher->apply_group_share(account.asset, account.manager, account.owner, share))
							continue;
					}
				}
				exchange_successful = false;
			}

			auto* transaction = memory::init<depository_regrouping_finalization>();
			transaction->asset = asset;
			transaction->depository_regrouping_commitment_hash = context->receipt.transaction_hash;
			transaction->successful = exchange_successful;
			dispatcher->emit_transaction(transaction);
			return expects_promise_rt<void>(expectation::met);
		}
		expects_lr<void> depository_regrouping_commitment::transfer(const uint256_t& account_hash, const uint256_t& share, const algorithm::pubkey_t& new_manager_public_key, const algorithm::seckey_t& old_manager_secret_key)
		{
			format::wo_stream entropy;
			entropy.write_integer(depository_regrouping_preparation_hash);
			entropy.write_integer(algorithm::hashing::hash256i(old_manager_secret_key.view()));

			uint8_t share_data[32];
			share.encode(share_data);
			auto encrypted_share = algorithm::signing::public_encrypt(new_manager_public_key, std::string_view((char*)share_data, sizeof(share_data)), entropy.hash());
			if (!encrypted_share)
				return layer_exception("failed to encrypt a share");

			encrypted_shares[account_hash] = std::move(*encrypted_share);
			return expectation::met;
		}
		bool depository_regrouping_commitment::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_regrouping_preparation_hash);
			stream->write_integer((uint16_t)encrypted_shares.size());
			for (auto& [hash, encrypted_share] : encrypted_shares)
			{
				stream->write_integer(hash);
				stream->write_string(encrypted_share);
			}
			return true;
		}
		bool depository_regrouping_commitment::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_regrouping_preparation_hash))
				return false;

			uint16_t encrypted_shares_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_shares_size))
				return false;

			for (uint16_t i = 0; i < encrypted_shares_size; i++)
			{
				uint256_t hash;
				if (!stream.read_integer(stream.read_type(), &hash))
					return false;

				string encrypted_share;
				if (!stream.read_string(stream.read_type(), &encrypted_share))
					return false;

				encrypted_shares[hash] = std::move(encrypted_share);
			}

			return true;
		}
		bool depository_regrouping_commitment::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> depository_regrouping_commitment::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_regrouping_preparation_hash", var::string(algorithm::encoding::encode_0xhex256(depository_regrouping_preparation_hash)));
			auto* encrypted_shares_data = data->set("encrypted_shares", var::set::array());
			for (auto& [hash, encrypted_share] : encrypted_shares)
			{
				auto* encrypted_share_data = encrypted_shares_data->push(var::set::object());
				encrypted_share_data->set("account_hash", var::string(algorithm::encoding::encode_0xhex256(hash)));
				encrypted_share_data->set("encrypted_share", var::string(format::util::encode_0xhex(encrypted_share)));
			}
			return data;
		}
		uint32_t depository_regrouping_commitment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_regrouping_commitment::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_regrouping_commitment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_regrouping_commitment::as_instance_typename()
		{
			return "depository_regrouping_commitment";
		}

		expects_lr<void> depository_regrouping_finalization::validate(uint64_t block_number) const
		{
			if (!depository_regrouping_commitment_hash)
				return layer_exception("invalid depository regroup transaction");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_regrouping_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(depository_regrouping_commitment_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			if (!successful)
				return expectation::met;

			auto certification = context->get_block_transaction<depository_regrouping_commitment>(depository_regrouping_commitment_hash);
			if (!certification)
				return certification.error();

			auto* commitment_transaction = (depository_regrouping_commitment*)*certification->transaction;
			auto preparation = context->get_block_transaction<depository_regrouping_preparation>(commitment_transaction->depository_regrouping_preparation_hash);
			if (!preparation)
				return preparation.error();
			else if (preparation->receipt.from != context->receipt.from)
				return layer_exception("invalid preparation transaction");

			auto* preparation_transaction = (depository_regrouping_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_regrouping>(preparation_transaction->depository_regrouping_hash);
			if (!setup)
				return setup.error();

			auto* setup_transaction = (depository_regrouping*)*setup->transaction;
			if (setup_transaction->participants.size() != commitment_transaction->encrypted_shares.size())
				return layer_exception("invalid participants size");

			auto new_manager = setup_transaction->get_new_manager(setup->receipt);
			if (!new_manager.equals(preparation->receipt.from))
				return layer_exception("invalid preparation transaction");

			auto old_manager = algorithm::pubkeyhash_t(setup->receipt.from);
			for (auto& [hash, encrypted_share] : commitment_transaction->encrypted_shares)
			{
				auto it = setup_transaction->participants.find(hash);
				if (it == setup_transaction->participants.end())
					return layer_exception("invalid account hash");

				auto& account = it->second;
				auto target = context->get_depository_account(account.asset, account.manager, account.owner);
				if (!target)
					return target.error();

				auto status = context->apply_validator_participation(account.asset, old_manager.data, ledger::transaction_context::stake_type::lock, -1, { });
				if (!status)
					return status.error();

				status = context->apply_validator_participation(account.asset, new_manager.data, ledger::transaction_context::stake_type::lock, 1, { });
				if (!status)
					return status.error();

				target->group.erase(old_manager);
				target->group.insert(new_manager);
				target = context->apply_depository_account(account.asset, account.manager, account.owner, target->public_key, std::move(target->group));
				if (!target)
					return target.error();
			}

			return expectation::met;
		}
		bool depository_regrouping_finalization::store_body(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_regrouping_commitment_hash);
			stream->write_boolean(successful);
			return true;
		}
		bool depository_regrouping_finalization::load_body(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_regrouping_commitment_hash))
				return false;

			if (!stream.read_boolean(stream.read_type(), &successful))
				return false;

			return true;
		}
		uptr<schema> depository_regrouping_finalization::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_regrouping_commitment_hash", var::string(algorithm::encoding::encode_0xhex256(depository_regrouping_commitment_hash)));
			data->set("successful", var::boolean(successful));
			return data;
		}
		uint32_t depository_regrouping_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_regrouping_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t depository_regrouping_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_regrouping_finalization::as_instance_typename()
		{
			return "depository_regrouping_finalization";
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
			else if (hash == certification::as_instance_type())
				return memory::init<certification>();
			else if (hash == depository_account::as_instance_type())
				return memory::init<depository_account>();
			else if (hash == depository_account_finalization::as_instance_type())
				return memory::init<depository_account_finalization>();
			else if (hash == depository_withdrawal::as_instance_type())
				return memory::init<depository_withdrawal>();
			else if (hash == depository_withdrawal_finalization::as_instance_type())
				return memory::init<depository_withdrawal_finalization>();
			else if (hash == depository_transaction::as_instance_type())
				return memory::init<depository_transaction>();
			else if (hash == depository_adjustment::as_instance_type())
				return memory::init<depository_adjustment>();
			else if (hash == depository_regrouping::as_instance_type())
				return memory::init<depository_regrouping>();
			else if (hash == depository_regrouping_preparation::as_instance_type())
				return memory::init<depository_regrouping_preparation>();
			else if (hash == depository_regrouping_commitment::as_instance_type())
				return memory::init<depository_regrouping_commitment>();
			else if (hash == depository_regrouping_finalization::as_instance_type())
				return memory::init<depository_regrouping_finalization>();
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
			else if (hash == certification::as_instance_type())
				return memory::init<certification>(*(const certification*)base);
			else if (hash == depository_account::as_instance_type())
				return memory::init<depository_account>(*(const depository_account*)base);
			else if (hash == depository_account_finalization::as_instance_type())
				return memory::init<depository_account_finalization>(*(const depository_account_finalization*)base);
			else if (hash == depository_withdrawal::as_instance_type())
				return memory::init<depository_withdrawal>(*(const depository_withdrawal*)base);
			else if (hash == depository_withdrawal_finalization::as_instance_type())
				return memory::init<depository_withdrawal_finalization>(*(const depository_withdrawal_finalization*)base);
			else if (hash == depository_transaction::as_instance_type())
				return memory::init<depository_transaction>(*(const depository_transaction*)base);
			else if (hash == depository_adjustment::as_instance_type())
				return memory::init<depository_adjustment>(*(const depository_adjustment*)base);
			else if (hash == depository_regrouping::as_instance_type())
				return memory::init<depository_regrouping>(*(const depository_regrouping*)base);
			else if (hash == depository_regrouping_preparation::as_instance_type())
				return memory::init<depository_regrouping_preparation>(*(const depository_regrouping_preparation*)base);
			else if (hash == depository_regrouping_commitment::as_instance_type())
				return memory::init<depository_regrouping_commitment>(*(const depository_regrouping_commitment*)base);
			else if (hash == depository_regrouping_finalization::as_instance_type())
				return memory::init<depository_regrouping_finalization>(*(const depository_regrouping_finalization*)base);
			return nullptr;
		}
		expects_promise_rt<warden::prepared_transaction> resolver::prepare_transaction(const algorithm::asset_id& asset, const warden::wallet_link& from_link, const vector<warden::value_transfer>& to, option<warden::computed_fee>&& fee)
		{
			auto* server = oracle::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
				return server->prepare_transaction(asset, from_link, to, std::move(fee));

			auto chain = server->get_chainparams(asset);
			if (!chain)
				return expects_promise_rt<warden::prepared_transaction>(remote_exception("invalid operation"));

			auto from = server->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<warden::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::wo_stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<warden::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = server->to_composite_public_key(asset, from->public_key);
			if (!public_key)
				return expects_promise_rt<warden::prepared_transaction>(remote_exception(std::move(public_key.error().message())));

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

			warden::prepared_transaction regtest_prepared;
			regtest_prepared.requires_account_input(chain->composition, std::move(*from), *public_key, message_hash, sizeof(message_hash), std::move(transfers));
			for (auto& transfer : to)
				regtest_prepared.requires_account_output(transfer.address, { { transfer.asset, transfer.value } });

			return expects_promise_rt<warden::prepared_transaction>(std::move(regtest_prepared));
		}
		expects_promise_rt<warden::finalized_transaction> resolver::finalize_and_broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, warden::prepared_transaction&& prepared, ledger::dispatch_context* dispatcher)
		{
			auto* server = oracle::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
			{
				auto finalization = server->finalize_transaction(asset, std::move(prepared));
				if (!finalization)
					return expects_promise_rt<warden::finalized_transaction>(remote_exception(std::move(finalization.error().message())));

				auto finalized = std::move(*finalization);
				return server->broadcast_transaction(asset, external_id, finalized).then<expects_rt<warden::finalized_transaction>>([finalized](expects_rt<void>&& status) mutable -> expects_rt<warden::finalized_transaction>
				{
					if (!status)
						return expects_rt<warden::finalized_transaction>(status.error());

					return expects_rt<warden::finalized_transaction>(std::move(finalized));
				});
			}

			auto transaction_id = algorithm::encoding::encode_0xhex256(algorithm::hashing::hash256i(external_id.to_string()));
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint32_t>::max();
			auto regtest_finalized = warden::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			regtest_finalized.calldata = regtest_finalized.as_message().encode();
			if (dispatcher != nullptr)
			{
				auto regtest_computed = regtest_finalized.as_computed();
				regtest_computed.block_id.finalization = regtest_computed.block_id.execution;

				auto* transaction = memory::init<depository_transaction>();
				transaction->asset = asset;
				transaction->set_gas(decimal::zero(), 0);
				transaction->set_computed_witness(regtest_computed);
				dispatcher->emit_transaction(transaction);
			}
			return expects_promise_rt<warden::finalized_transaction>(std::move(regtest_finalized));
		}
	}
}
