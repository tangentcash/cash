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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> transfer::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
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
		bool transfer::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
			format::tree data = ledger::transaction::as_tree();
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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> deploy::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
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
		bool deploy::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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

			format::tree data = ledger::transaction::as_tree();
			data.set("callable", algorithm::signing::serialize_address(get_account()));
			data.set("from", name.empty() ? format::variable() : format::variable(name));
			data.set("data", format::variable(format::util::encode_0xhex(this->data)));
			data.set("args", format::variables_util::serialize(args));
			return data;
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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> call::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
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
		bool call::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
		void call::pay_with(const algorithm::asset_id& asset, const decimal& new_value)
		{
			pays.push_back(std::make_pair(asset, new_value));
		}
		format::tree call::as_tree() const
		{
			format::tree data = ledger::transaction::as_tree();
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
		expects_lr<void> rollup::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
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
			uint256_t absolute_gas_limit = executor->block->gas_limit;
			uint256_t absolute_gas_use = executor->block->gas_use;
			uint256_t relative_gas_use = executor->receipt.relative_gas_use;
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
		bool rollup::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
		format::tree rollup::as_tree() const
		{
			algorithm::pubkeyhash_t from;
			format::tree data = ledger::transaction::as_tree();
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
		void rollup::normalize_transaction(ledger::transaction& transaction, const algorithm::asset_id& asset)
		{
			transaction.gas_price = decimal::nan();
			transaction.gas_limit = 0;
			if (!transaction.asset)
				transaction.asset = asset;
		}

		expects_lr<void> setup::validate(uint64_t block_number) const
		{
			if (migrations.empty() && attestations.empty() && !participation && !production)
				return layer_exception("invalid validator change");

			for (auto& [broadcast_hash, participant] : migrations)
			{
				if (!broadcast_hash)
					return layer_exception("invalid broadcast hash");

				if (participant.empty())
					return layer_exception("invalid participant");
			}

			attestation_setup default_setup;
			for (auto& [asset, setup] : attestations)
			{
				if (!algorithm::asset::is_aux(asset, true))
					return layer_exception("invalid attestation asset");

				if (setup.stake.is_negative())
					return layer_exception("attestation stake must not be negative");

				if (setup.incoming_fee && (setup.incoming_fee->is_nan() || setup.incoming_fee->is_negative()))
					return layer_exception("invalid incoming fee");

				if (setup.outgoing_fee && (setup.outgoing_fee->is_nan() || setup.outgoing_fee->is_negative()))
					return layer_exception("invalid outgoing fee");

				if (setup.participation_threshold && (setup.participation_threshold->is_nan() || setup.participation_threshold->is_negative()))
					return layer_exception("invalid participation threshold");

				if (setup.security_level && (*setup.security_level < protocol::now().policy.participation.min_per_account || *setup.security_level > protocol::now().policy.participation.max_per_account))
					return layer_exception("invalid security level");
			}

			if (participation && participation->is_negative())
				return layer_exception("participation stake must not be negative");

			if (production && production->is_negative())
				return layer_exception("production stake must not be negative");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> setup::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
			if (!validation)
				return validation.error();

			size_t count = 32;
			vector<states::validator_participation_ref> refs;
			auto participation_type = participation ? (participation->is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock) : ledger::executor_context::staker::reward_or_penalty;
			while (!migrations.empty() || participation_type == ledger::executor_context::staker::unlock)
			{
				auto results = executor->get_validator_participation_refs(executor->receipt.from, refs.size(), count);
				if (results)
					refs.insert(refs.end(), results->begin(), results->end());
				if (!results || results->size() != count)
					break;
			}

			decimal threshold = decimal::zero();
			btree_set<uint256_t> accounts;
			btree_set<algorithm::pubkeyhash_t> exclusion;
			for (auto& [broadcast_hash, participant] : migrations)
			{
				auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
				if (!parent)
					return layer_exception("broadcast transaction not found");

				auto* parent_transaction = (broadcast*)*parent->transaction;
				if (parent_transaction->proof || parent->receipt.from != executor->receipt.from)
					return layer_exception("broadcast transaction not applicable");

				bool may_perform_migration = false;
				auto base_asset = algorithm::asset::base_id_of(parent_transaction->asset);
				for (auto& ref_state : refs)
				{
					auto& ref = ref_state.ref;
					if (!ref_state.active || ref.asset != base_asset || ref.manager != executor->receipt.from)
						continue;

					auto attestation = executor->get_verified_validator_attestation(ref.asset, ref.manager);
					if (!attestation)
						return attestation.error();

					auto account = executor->get_bridge_account(ref.asset, ref.manager, ref.owner);
					if (!account)
						return account.error();

					may_perform_migration = true;
					exclusion.insert(account->group.begin(), account->group.end());
					if (threshold < attestation->participation_threshold)
						threshold = attestation->participation_threshold;

					auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(ref.asset, ref.manager, ref.owner);
					if (accounts.find(ref_hash) != accounts.end())
						return layer_exception("migration requires migration to multiple new participants");

					accounts.insert(ref_hash);
				}
				if (!may_perform_migration)
					return layer_exception("migrations for a participant not found");
			}

			for (auto& [asset, setup] : attestations)
			{
				if (!algorithm::asset::token_of(asset).empty())
					continue;

				auto prev_policy = executor->get_validator_attestation(asset, executor->receipt.from).or_else(states::validator_attestation(executor->receipt.from, asset, nullptr));
				auto next_policy = executor->apply_validator_attestation_policy(algorithm::asset::base_id_of(asset), executor->receipt.from,
					setup.security_level.or_else(prev_policy.security_level),
					setup.participation_threshold.or_else(prev_policy.participation_threshold),
					setup.incoming_fee.or_else(prev_policy.incoming_fee),
					setup.outgoing_fee.or_else(prev_policy.outgoing_fee),
					setup.accepts_account_requests.or_else(prev_policy.accepts_account_requests),
					setup.accepts_withdrawal_requests.or_else(prev_policy.accepts_withdrawal_requests));
				if (!next_policy)
					return next_policy.error();

				auto type = setup.stake.is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock;
				if (type == ledger::executor_context::staker::unlock && (next_policy->accepts_account_requests || next_policy->accepts_withdrawal_requests))
					return layer_exception(algorithm::asset::handle_of(asset) + " bridge is still active");

				if (type == ledger::executor_context::staker::unlock || (prev_policy.is_active() && prev_policy.accepts_withdrawal_requests != next_policy->accepts_withdrawal_requests && !next_policy->accepts_withdrawal_requests))
				{
					size_t offset = 0, count = 32;
					while (true)
					{
						auto balances = executor->get_bridge_balances(executor->receipt.from, offset, count);
						if (!balances)
							break;

						for (auto& balance : *balances)
						{
							if (asset != algorithm::asset::base_id_of(balance.asset))
								continue;

							if (algorithm::asset::is_aux(asset, true))
							{
								auto dust = executor->calculate_amount_considered_dust(balance.asset).or_else(decimal::zero());
								if (balance.supply > dust)
									return layer_exception(algorithm::asset::handle_of(balance.asset) + " bridge has non-dust custodial balance (max_dust: " + dust.to_string() + ")");
							}
							else if (balance.supply.is_positive())
								return layer_exception(algorithm::asset::handle_of(balance.asset) + " bridge has custodial token balance");
						}

						offset += balances->size();
						if (balances->size() != count)
							break;
					}
				}

				auto status = executor->apply_validator_attestation(asset, executor->receipt.from, type, setup.stake);
				if (!status)
					return status.error();
			}

			bool requires_self_migration = false;
			if (participation_type != ledger::executor_context::staker::reward_or_penalty)
			{
				auto type = participation->is_nan() ? ledger::executor_context::staker::unlock : ledger::executor_context::staker::lock;
				if (type == ledger::executor_context::staker::unlock)
				{
					bool has_any = false;
					for (auto& ref_state : refs)
					{
						auto& ref = ref_state.ref;
						if (!ref_state.active)
							continue;

						auto attestation = executor->get_verified_validator_attestation(ref.asset, ref.manager);
						if (!attestation)
							return attestation.error();

						auto account = executor->get_bridge_account(ref.asset, ref.manager, ref.owner);
						if (!account)
							return account.error();

						requires_self_migration = true;
						exclusion.insert(account->group.begin(), account->group.end());
						if (threshold < attestation->participation_threshold)
							threshold = attestation->participation_threshold;

						auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(ref.asset, ref.manager, ref.owner);
						if (accounts.find(ref_hash) != accounts.end())
							return layer_exception("migration requires migration to multiple new participants");

						accounts.insert(ref_hash);
						has_any = true;
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

			auto committee = executor->calculate_participants(exclusion, 1, threshold);
			if (!committee)
				return committee.error();

			auto& new_manager = committee->front();
			auto event = executor->emit_event<setup>({ format::variable(requires_self_migration), format::variable(new_manager.owner.view()) });
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

						auto ref_hash = ledger::dispatcher_context::secret_entropy::ref_hash(migration.account.asset, migration.account.manager, migration.account.owner);
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

					auto secret = dispatcher->recover_secret_entropy(runner_wallet, migration.account.asset, migration.account.manager, migration.account.owner);
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
			for (auto& [asset, setup] : attestations)
			{
				stream->write_integer(asset);
				stream->write_decimal(setup.stake);
				stream->write_boolean(!!setup.accepts_account_requests);
				stream->write_boolean(!!setup.accepts_withdrawal_requests);
				stream->write_boolean(!!setup.security_level);
				stream->write_boolean(!!setup.incoming_fee);
				stream->write_boolean(!!setup.outgoing_fee);
				stream->write_boolean(!!setup.participation_threshold);
				if (setup.accepts_account_requests)
					stream->write_boolean(*setup.accepts_account_requests);
				if (setup.accepts_withdrawal_requests)
					stream->write_boolean(*setup.accepts_withdrawal_requests);
				if (setup.security_level)
					stream->write_integer(*setup.security_level);
				if (setup.incoming_fee)
					stream->write_decimal(*setup.incoming_fee);
				if (setup.outgoing_fee)
					stream->write_decimal(*setup.outgoing_fee);
				if (setup.participation_threshold)
					stream->write_decimal(*setup.participation_threshold);
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
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				attestation_setup setup;
				if (!stream.read_decimal(stream.read_type(), &setup.stake))
					return false;

				bool has_accepts_account_requests;
				if (!stream.read_boolean(stream.read_type(), &has_accepts_account_requests))
					return false;

				bool has_accepts_withdrawal_requests;
				if (!stream.read_boolean(stream.read_type(), &has_accepts_withdrawal_requests))
					return false;

				bool has_security_level;
				if (!stream.read_boolean(stream.read_type(), &has_security_level))
					return false;

				bool has_incoming_fee;
				if (!stream.read_boolean(stream.read_type(), &has_incoming_fee))
					return false;

				bool has_outgoing_fee;
				if (!stream.read_boolean(stream.read_type(), &has_outgoing_fee))
					return false;

				bool has_participation_threshold;
				if (!stream.read_boolean(stream.read_type(), &has_participation_threshold))
					return false;

				if (has_accepts_account_requests)
				{
					setup.accepts_account_requests = true;
					if (!stream.read_boolean(stream.read_type(), setup.accepts_account_requests.address()))
						return false;
				}

				if (has_accepts_withdrawal_requests)
				{
					setup.accepts_withdrawal_requests = true;
					if (!stream.read_boolean(stream.read_type(), setup.accepts_withdrawal_requests.address()))
						return false;
				}

				if (has_security_level)
				{
					setup.security_level = protocol::now().policy.participation.min_per_account;
					if (!stream.read_integer(stream.read_type(), setup.security_level.address()))
						return false;
				}

				if (has_incoming_fee)
				{
					setup.incoming_fee = decimal::zero();
					if (!stream.read_decimal(stream.read_type(), setup.incoming_fee.address()))
						return false;
				}

				if (has_outgoing_fee)
				{
					setup.outgoing_fee = decimal::zero();
					if (!stream.read_decimal(stream.read_type(), setup.outgoing_fee.address()))
						return false;
				}

				if (has_participation_threshold)
				{
					setup.participation_threshold = decimal::zero();
					if (!stream.read_decimal(stream.read_type(), setup.participation_threshold.address()))
						return false;
				}

				attestations[asset] = std::move(setup);
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
		bool setup::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
		void setup::allocate_attestation_stake(const algorithm::asset_id& asset, const decimal& value)
		{
			attestations[asset].stake = value;
		}
		void setup::configure_attestation_security(const algorithm::asset_id& asset, uint8_t new_security_level, const decimal& new_participation_threshold, bool new_accepts_account_requests, bool new_accepts_withdrawal_requests)
		{
			auto& setup = attestations[asset];
			setup.security_level = new_security_level;
			setup.participation_threshold = new_participation_threshold;
			setup.accepts_account_requests = new_accepts_account_requests;
			setup.accepts_withdrawal_requests = new_accepts_withdrawal_requests;
		}
		void setup::configure_attestation_reward(const algorithm::asset_id& asset, const decimal& new_incoming_fee, const decimal& new_outgoing_fee)
		{
			auto& setup = attestations[asset];
			setup.incoming_fee = new_incoming_fee;
			setup.outgoing_fee = new_outgoing_fee;
		}
		void setup::disable_attestation(const algorithm::asset_id& asset)
		{
			attestations[asset].stake = decimal::nan();
		}
		void setup::standby_on_attestation(const algorithm::asset_id& asset)
		{
			attestations.erase(asset);
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
		expects_lr<vector<setup::migration_ref>> setup::get_migration_refs(const ledger::executor_context* executor, const ledger::receipt& receipt) const
		{
			vector<migration_ref> results;
			auto* event = receipt.find_event<setup>();
			if (!event || event->size() != 2)
				return expects_lr<vector<migration_ref>>(std::move(results));
			
			bool requires_self_migration = event->front().as_boolean();
			if (!requires_self_migration && migrations.empty())
				return expects_lr<vector<migration_ref>>(std::move(results));

			size_t count = 32;
			vector<states::validator_participation_ref> refs;
			while (true)
			{
				auto results = executor->get_validator_participation_refs(executor->receipt.from, refs.size(), count);
				if (results)
					refs.insert(refs.end(), results->begin(), results->end());
				if (!results || results->size() != count)
					break;
			}

			if (requires_self_migration)
			{
				for (auto& ref_state : refs)
				{
					auto& ref = ref_state.ref;
					if (!ref_state.active)
						continue;

					auto account = executor->get_bridge_account(ref.asset, ref.manager, ref.owner);
					if (!account)
						return account.error();

					migration_ref migration;
					migration.account = std::move(*account);
					migration.old_participant = receipt.from;
					migration.must_have_locally = true;
					results.push_back(std::move(migration));
				}
			}

			for (auto& [broadcast_hash, participant] : migrations)
			{
				auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
				if (!parent)
					return layer_exception("invalid migration reasoning transaction");

				auto participation = executor->get_validator_participation(participant);
				if (!participation)
					return participation.error();

				bool has_any = false;
				auto ref_asset = algorithm::asset::base_id_of(parent->transaction->asset);
				for (auto& ref_state : refs)
				{
					auto& ref = ref_state.ref;
					if (!ref_state.active || ref.asset != ref_asset || ref.manager != receipt.from)
						continue;

					auto account = executor->get_bridge_account(ref.asset, ref.manager, ref.owner);
					if (!account)
						return account.error();

					migration_ref migration;
					migration.account = std::move(*account);
					migration.old_participant = participant;
					migration.must_have_locally = false;
					results.push_back(std::move(migration));
					has_any = true;
				}

				if (!has_any)
					return layer_exception("invalid migration participant");
			}

			return expects_lr<vector<migration_ref>>(std::move(results));
		}
		algorithm::pubkeyhash_t setup::get_new_participant(const ledger::receipt& receipt, bool* requires_new_participant) const
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
			format::tree data = ledger::transaction::as_tree();
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
				for (auto& [asset, setup] : attestations)
				{
					auto* attestation_data = attestations_data->push(format::tree::map());
					attestation_data->set("asset", algorithm::asset::serialize(asset));
					attestation_data->set("accepts_account_requests", setup.accepts_account_requests ? format::variable(*setup.accepts_account_requests) : format::variable());
					attestation_data->set("accepts_withdrawal_requests", setup.accepts_withdrawal_requests ? format::variable(*setup.accepts_withdrawal_requests) : format::variable());
					attestation_data->set("security_level", setup.security_level ? format::variable(*setup.security_level) : format::variable());
					attestation_data->set("incoming_fee", setup.incoming_fee ? format::variable(*setup.incoming_fee) : format::variable());
					attestation_data->set("outgoing_fee", setup.outgoing_fee ? format::variable(*setup.outgoing_fee) : format::variable());
					attestation_data->set("participation_threshold", setup.participation_threshold ? format::variable(*setup.participation_threshold) : format::variable());
					attestation_data->set("stake", format::variable(setup.stake));
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

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> migrate::execute(ledger::executor_context* executor) const
		{
			auto validation = commitment::execute(executor);
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
				auto account = executor->get_bridge_account(migration.account.asset, migration.account.manager, migration.account.owner);
				if (!account)
					return account.error();

				size_t prev_size = account->group.size();
				account->group.erase(migration.old_participant);
				account->group.insert(new_participant);
				if (prev_size != account->group.size())
					return layer_exception("conflicting group migration (size changed)");

				account = executor->apply_bridge_account(account->asset, account->manager, account->owner, account->public_key, std::move(account->group));
				if (!account)
					return account.error();

				auto ref = states::validator_participation_ref::ref_value();
				ref.asset = account->asset;
				ref.manager = account->manager;
				ref.owner = account->owner;
				
				auto status = executor->apply_validator_participation_ref(migration.old_participant, ref, false);
				if (!status)
					return status.error();

				status = executor->apply_validator_participation_ref(new_participant, ref, true);
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
			format::tree data = ledger::commitment::as_tree();
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

		expects_lr<void> attestate::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!proof.is_valid())
				return layer_exception("invalid proof");

			if (!proof.block_id)
				return layer_exception("transaction has no block reference");

			auto chain = superchain::bridge::get()->get_network_params(asset);
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

			btree_set<algorithm::pubkeyhash_t> attesters;
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
		expects_lr<void> attestate::execute(ledger::executor_context* executor) const
		{
			auto validation = commitment::execute(executor);
			if (!validation)
				return validation.error();

			auto* chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid chain");

			auto collision = executor->get_witness_transaction(asset, proof.transaction_id);
			if (collision)
				return layer_exception("proof " + proof.transaction_id + " finalized");

			uint256_t best_commitment_hash = 0;
			btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>> attesters;
			auto verification = verify_proof_commitment(executor, asset, commitments, best_commitment_hash, attesters);
			if (!verification)
				return verification;
			else if (best_commitment_hash != proof.as_hash())
				return layer_exception("provided proof is not the chosen one");

			decimal fee = decimal::zero();
			algorithm::pubkeyhash_t depositor, withdrawer;
			for (auto& [hash, input] : proof.inputs)
			{
				auto baseline = states::witness_account(algorithm::pubkeyhash_t(), 0, { }, nullptr);
				auto source = depositor.empty() || withdrawer.empty() ? executor->get_witness_account_tagged(asset, input.link.address, 0).or_else(baseline) : baseline;
				depositor = depositor.empty() && source.is_routing_account() && chain->routing == superchain::routing_policy::account ? source.owner : depositor;
				withdrawer = withdrawer.empty() && source.is_bridge_account() ? source.manager : withdrawer;
				fee += input.value;
			}
			for (auto& [hash, output] : proof.outputs)
				fee -= output.value;

			btree_map<algorithm::pubkeyhash_t, bridge_transfer_batch> bridges;
			btree_map<algorithm::pubkeyhash_t, btree_map<algorithm::asset_id, route_transfer>> routes;
			btree_map<algorithm::asset_id, decimal> penalties;
			if (!withdrawer.empty())
			{
				decimal rebate = fee;
				for (auto& [hash, input] : proof.inputs)
				{
					auto source = executor->get_witness_account_tagged(asset, input.link.address, 0);
					if (source && source->is_bridge_account())
					{
						auto& bridge = bridges[source->manager];
						auto bridge_account = executor->get_bridge_account(asset, source->manager, source->owner);
						if (!bridge_account)
							bridge_account = executor->get_bridge_account(asset, source->manager, source->manager);
						if (bridge_account)
							bridge.participants.insert(bridge_account->group.begin(), bridge_account->group.end());

						if (input.value.is_positive())
						{
							auto token_asset = input.get_asset(asset);
							auto& penalty = penalties[token_asset];
							penalty = penalty.is_nan() ? input.value : (penalty + input.value);
							bridge.transfers[token_asset].output_supply += input.value;
						}

						for (auto& [token_hash, token] : input.tokens)
						{
							auto token_asset = token.get_asset(asset);
							auto& penalty = penalties[token_asset];
							penalty = penalty.is_nan() ? token.value : (penalty + token.value);
							bridge.transfers[token_asset].output_supply += token.value;
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
								penalty = penalty.is_nan() ? token.value : (penalty - token.value);
							}
						}
					}
				}

				for (auto& [hash, output] : proof.outputs)
				{
					auto source = executor->get_witness_account_tagged(asset, output.link.address, 0);
					if (source && source->is_bridge_account())
					{
						auto& bridge = bridges[source->manager];
						auto bridge_account = executor->get_bridge_account(asset, source->manager, source->owner);
						if (!bridge_account)
							bridge_account = executor->get_bridge_account(asset, source->manager, source->manager);
						if (bridge_account)
							bridge.participants.insert(bridge_account->group.begin(), bridge_account->group.end());

						if (output.value.is_positive())
						{
							auto token_asset = output.get_asset(asset);
							auto& penalty = penalties[token_asset];
							penalty = penalty.is_nan() ? -output.value : (penalty - output.value);
							bridge.transfers[token_asset].input_supply += output.value;
						}

						for (auto& [token_hash, token] : output.tokens)
						{
							if (!token.value.is_positive())
								continue;

							auto token_asset = token.get_asset(asset);
							auto& penalty = penalties[token_asset];
							penalty = penalty.is_nan() ? -token.value : (penalty - token.value);
							bridge.transfers[token_asset].input_supply += token.value;
						}
					}
					else if (source && source->is_routing_account())
					{
						auto& route = routes[source->owner];
						auto token_asset = output.get_asset(asset);
						for (auto& [bridge_manager, bridge] : bridges)
						{
							auto transfer = bridge.transfers.find(token_asset);
							auto reward = transfer != bridge.transfers.end() && transfer->second.output_supply.is_positive() ? executor->get_verified_validator_attestation(asset, bridge_manager) : expects_lr<states::validator_attestation>(layer_exception());
							if (reward && reward->outgoing_fee.is_positive())
							{
								auto rebate_adjustment = std::min(rebate, reward->outgoing_fee);
								transfer->second.outgoing_fee += reward->outgoing_fee - rebate_adjustment;
								rebate -= rebate_adjustment;
								break;
							}
						}

						if (output.value.is_positive())
						{
							auto& penalty = penalties[token_asset];
							auto& route_transfer = route[token_asset];
							penalty = penalty.is_nan() ? -output.value : (penalty - output.value);
							route_transfer.output_supply += output.value;
							route_transfer.output_reserve += output.value;
						}

						for (auto& [token_hash, token] : output.tokens)
						{
							if (!token.value.is_positive())
								continue;

							token_asset = token.get_asset(asset);
							auto& route_transfer = route[token_asset];
							auto& penalty = penalties[token_asset];
							penalty = penalty.is_nan() ? token.value : (penalty - token.value);
							route_transfer.output_supply += token.value;
							route_transfer.output_reserve += token.value;
						}
					}
				}

				auto it = penalties.find(algorithm::asset::base_id_of(asset));
				if (it != penalties.end())
					it->second -= fee;

				for (auto& [penalty_asset, penalty_value] : penalties)
				{
					if (!penalty_value.is_positive())
						continue;

					size_t fee_payers = 0;
					for (auto& [route_account, transfers] : routes)
						fee_payers += transfers.find(penalty_asset) != transfers.end();

					auto amount = algorithm::arithmetic::divide(penalty_value, fee_payers > 0 ? fee_payers : bridges.size());
					if (!amount.is_positive())
						continue;

					penalty_value = decimal::zero();
					if (fee_payers > 0)
					{
						for (auto& [route_account, transfers] : routes)
						{
							auto it = transfers.find(penalty_asset);
							if (it != transfers.end())
							{
								it->second.output_supply += amount;
								it->second.output_reserve += amount;
							}
						}
					}
					else
					{
						for (auto& [bridge_account, batch] : bridges)
						{
							auto& route_transfer = routes[bridge_account][penalty_asset];
							route_transfer.output_supply += amount;
							route_transfer.output_reserve += amount;
						}
					}
				}
			}
			else
			{
				for (auto& [hash, output] : proof.outputs)
				{
					auto source = executor->get_witness_account(asset, output.link.address, 0);
					if (!source || !source->is_bridge_account())
						continue;

					auto& bridge = bridges[source->manager];
					auto& route = routes[depositor.empty() ? source->owner : depositor];
					auto bridge_account = executor->get_bridge_account(asset, source->manager, source->owner);
					if (!bridge_account)
						bridge_account = executor->get_bridge_account(asset, source->manager, source->manager);
					if (bridge_account)
						bridge.participants.insert(bridge_account->group.begin(), bridge_account->group.end());

					if (output.value.is_positive())
					{
						auto token_asset = output.get_asset(asset);
						auto& route_transfer = route[token_asset];
						auto& bridge_transfer = bridge.transfers[token_asset];
						auto reward = executor->get_verified_validator_attestation(token_asset, source->manager);
						auto reward_value = reward && reward->incoming_fee.is_positive() ? std::min(output.value, reward->incoming_fee) : decimal::zero();
						route_transfer.input_supply += output.value - reward_value;
						bridge_transfer.input_supply += output.value;
						bridge_transfer.incoming_fee += reward_value;
					}

					for (auto& [token_hash, token] : output.tokens)
					{
						if (token.value.is_positive())
						{
							auto token_asset = token.get_asset(asset);
							route[token_asset].input_supply += token.value;
							bridge.transfers[token_asset].input_supply += token.value;
						}
					}
				}
			}

			if (routes.empty() && bridges.empty())
				return layer_exception("invalid transaction");

			auto& succeeding_attesters = attesters[best_commitment_hash];
			auto failing_attesters = btree_set<algorithm::pubkeyhash_t>();
			for (auto& [commitment_hash, group] : attesters)
			{
				if (commitment_hash != best_commitment_hash)
					failing_attesters.insert(group.begin(), group.end());
			}

			for (auto& [route_account, transfers] : routes)
			{
				for (auto& [transfer_asset, transfer] : transfers)
				{
					auto supply_delta = transfer.input_supply - transfer.output_supply;
					auto reserve_delta = transfer.input_reserve - transfer.output_reserve;
					if (supply_delta.is_negative() || reserve_delta.is_negative())
					{
						auto balance = executor->get_account_balance(transfer_asset, route_account).or_else(states::account_balance(algorithm::pubkeyhash_t(), 0, nullptr));
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
							penalty = penalty.is_nan() ? std::max(supply_penalty, reserve_penalty)  : (penalty - std::max(supply_penalty, reserve_penalty));
						}
					}

					if (!supply_delta.is_zero() || !reserve_delta.is_zero())
					{
						auto delta_transfer = executor->apply_transfer(transfer_asset, route_account, supply_delta, reserve_delta);
						if (!delta_transfer)
							return delta_transfer.error();
					}
				}
			}

			for (auto& [bridge_manager, batch] : bridges)
			{
				for (auto& [transfer_asset, transfer] : batch.transfers)
				{
					auto& penalty = penalties[transfer_asset];
					penalty = penalty.is_positive() ? penalty : decimal::zero();
					auto consume_penalty = [&penalty](const decimal& delta) -> decimal
					{
						auto adjustment = std::max(decimal::zero(), penalty - delta);
						auto result = std::max(decimal::zero(), delta - penalty);
						penalty = adjustment;
						return result;
					};
					if (transfer.input_supply.is_positive() || transfer.output_supply.is_positive())
					{
						auto supply_delta = transfer.input_supply - transfer.output_supply;
						if (supply_delta.is_negative())
						{
							auto balance = executor->get_bridge_balance(transfer_asset, bridge_manager);
							supply_delta = balance ? std::max(-balance->supply, supply_delta) : decimal::zero();
						}

						if (!supply_delta.is_zero())
						{
							auto bridge = executor->apply_bridge_balance(transfer_asset, bridge_manager, supply_delta);
							if (!bridge)
								return bridge.error();
						}
					}

					auto total_fee = consume_penalty(transfer.incoming_fee + transfer.outgoing_fee);
					auto attestation_cut = succeeding_attesters.empty() ? decimal::zero() : decimal(protocol::now().policy.attestation.fee_rate);
					auto participation_cut = batch.participants.empty() ? decimal::zero() : decimal(protocol::now().policy.participation.fee_rate);
					auto bridge_fee = total_fee * (1 - attestation_cut - participation_cut);
					auto attestation_fee = !succeeding_attesters.empty() ? algorithm::arithmetic::divide(total_fee * attestation_cut, succeeding_attesters.size()) : decimal::zero();
					auto participation_fee = !batch.participants.empty() ? algorithm::arithmetic::divide(total_fee * participation_cut, batch.participants.size()) : decimal::zero();
					if (attestation_fee.is_positive())
					{
						for (auto& failing_attester : failing_attesters)
						{
							auto prev_attestation = executor->get_validator_attestation_reward(transfer_asset, failing_attester);
							if (!prev_attestation)
								continue;

							auto next_attestation = executor->apply_validator_attestation_reward(transfer_asset, failing_attester, -attestation_fee);
							if (!next_attestation)
								return next_attestation.error();

							auto compensation_adjustment = std::max(decimal::zero(), prev_attestation->reward - next_attestation->reward);
							if (compensation_adjustment.is_positive())
								bridge_fee += consume_penalty(compensation_adjustment);
						}

						for (auto& succeeding_attester : succeeding_attesters)
						{
							auto attestation = executor->apply_validator_attestation_reward(transfer_asset, succeeding_attester, attestation_fee);
							if (!attestation)
								return attestation.error();
						}
					}

					if (penalty.is_positive() || participation_fee.is_positive())
					{
						auto individual_penalty = -algorithm::arithmetic::divide(penalty, batch.participants.size());
						for (auto& participant : batch.participants)
						{
							auto participation = executor->apply_validator_participation_reward(transfer_asset, participant, individual_penalty.is_negative() ? individual_penalty : participation_fee);
							if (!participation)
								return participation.error();
						}
					}

					if (bridge_fee.is_positive())
					{
						auto attestation = executor->apply_validator_attestation_reward(transfer_asset, bridge_manager, bridge_fee);
						if (!attestation)
							return attestation.error();
					}
				}
			}

			auto finalization = executor->apply_witness_transaction(asset, proof.transaction_id);
			if (!finalization)
				return finalization.error();

			auto witness = executor->emit_witness(asset, proof.block_id);
			if (!witness)
				return witness;

			return expectation::met;
		}
		expects_promise_rt<void> attestate::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto status = superchain::bridge::get()->update_utxo_tree(asset, proof);
			return status ? expects_promise_rt<void>(expectation::met) : expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
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
				for (auto& signature : signatures)
					stream->write_string(signature.optimized_view());
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
		bool attestate::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
		bool attestate::is_dispatchable() const
		{
			return true;
		}
		void attestate::set_finalized_proof(uint64_t block_id, const std::string_view& transaction_id, const vector<superchain::value_transfer>& inputs, const vector<superchain::value_transfer>& outputs)
		{
			auto* chain = superchain::bridge::get()->get_network_params(asset);
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
			format::tree data = ledger::commitment::as_tree();
			auto* commitments_data = data.set("commitments", format::tree::map());
			for (auto& [commitment_hash, signatures] : commitments)
			{
				auto signatures_data = commitments_data->set(algorithm::encoding::encode_0xhex256(commitment_hash), format::tree::list());
				for (auto& signature : signatures)
					signatures_data->push(signature.empty() ? format::variable() : format::variable(format::util::encode_0xhex(signature.view())));
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

			size_t global_commitment_size = 0;
			decimal global_commitment_stake = decimal::zero();
			for (auto& attester : *best_attesters)
			{
				global_commitment_stake += attester.stake;
				++global_commitment_size;
			}

			global_commitment_size = std::min(global_commitment_size, params.policy.attestation.max_per_transaction);
			if (global_commitment_size > 0 && decimal(best_commitment_size) < decimal(global_commitment_size) * params.policy.attestation.consensus_threshold)
				return layer_exception("proof requires more attestations");

			if (best_commitment_stake < global_commitment_stake * params.policy.attestation.consensus_threshold)
				return layer_exception("proof requires better attestations");

			return expectation::met;
		}
		void attestate::strip_commitments(const ledger::executor_context* executor, const algorithm::asset_id& asset, btree_map<uint256_t, btree_set<algorithm::hashsig_t>>& commitments)
		{
			btree_set<algorithm::pubkeyhash_t> duplicates;
			btree_map<uint256_t, btree_set<algorithm::hashsig_t>> stripped_out;
			for (auto& [commitment_hash, signatures] : commitments)
			{
				for (auto& signature : signatures)
				{
					algorithm::pubkeyhash_t attester;
					if (!algorithm::signing::recover_hash(commitment_hash, attester, signature))
					{
					strip_out:
						stripped_out[commitment_hash].insert(signature);
						continue;
					}
					else if (duplicates.find(attester) != duplicates.end())
						goto strip_out;

					auto attestation = executor->get_verified_validator_attestation(asset, attester);
					if (!attestation)
						goto strip_out;

					duplicates.insert(attester);
				}
			}

			for (auto& [commitment_hash, signatures] : stripped_out)
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

		expects_lr<void> route::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (manager.empty())
				return layer_exception("invalid manager");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> route::execute(ledger::executor_context* executor) const
		{
			auto validation = commitment::execute(executor);
			if (!validation)
				return validation.error();

			auto may_delegate = executor->verify_account_delegation(manager);
			if (!may_delegate)
			{
				auto overdelegation_fee = executor->apply_fee_transfer(algorithm::asset::native(), executor->receipt.from, protocol::now().policy.emission.min_coinbase_value);
				if (!overdelegation_fee)
					return layer_exception("must pay for over-delegation but " + overdelegation_fee.error().message());
			}
			else
			{
				auto delegation = executor->apply_account_delegation(manager, 1);
				if (!delegation)
					return delegation.error();
			}

			auto* params = superchain::bridge::get()->get_network_params(asset);
			if (!params)
				return layer_exception("invalid operation");

			auto policy = executor->get_verified_validator_attestation(asset, manager);
			if (!policy)
				return policy.error();
			else if (!policy->accepts_account_requests)
				return layer_exception("bridge forbids account requests");

			bool routing_address_application = false;
			if (!routing_address.empty())
			{
				auto collision = executor->get_witness_account_tagged(asset, routing_address, 0);
				if (collision && (!collision->is_routing_account() || collision->owner != executor->receipt.from))
					return layer_exception("routing account address " + routing_address + " taken");

				if (!collision)
				{
					auto status = executor->apply_witness_routing_account(asset, executor->receipt.from, { { (uint8_t)1, string(routing_address) } });
					if (!status)
						return status.error();

					routing_address_application = true;
				}
			}

			switch (params->routing)
			{
				case superchain::routing_policy::account:
				{
					if (!policy->accounts_under_management)
					{
						if (executor->receipt.from != manager)
							return layer_exception("bridge account for manager required");
						break;
					}
					else if (!routing_address_application)
						return layer_exception("bridge account already exists (only one may exist)");

					return expectation::met;
				}
				case superchain::routing_policy::memo:
				{
					if (!policy->accounts_under_management)
					{
						if (executor->receipt.from != manager)
							return layer_exception("bridge account for manager required");
						break;
					}

					auto manager_account = executor->get_bridge_account(asset, manager, manager);
					if (!manager_account || manager_account->public_key.empty() || manager_account->group.empty() || manager_account->owner != manager || manager_account->manager != manager)
						return layer_exception("bridge account for manager required");

					size_t offset = 0, count = 32;
					bool duplicate = false;
					while (true)
					{
						auto duplicates = executor->get_witness_accounts_by_purpose(executor->receipt.from, states::witness_account::account_type::bridge, 0, count);
						if (!duplicates)
							break;

						auto it = std::find_if(duplicates->begin(), duplicates->end(), [&](const states::witness_account& account) { return account.asset == asset && account.manager == manager && account.active; });
						if (it != duplicates->end())
						{
							duplicate = true;
							break;
						}

						offset += duplicates->size();
						if (duplicates->size() != count)
							break;
					}

					if (duplicate)
						return routing_address_application ? expects_lr<void>(expectation::met) : expects_lr<void>(layer_exception("bridge account already exists"));

					auto* chain = superchain::bridge::get()->get_network(asset);
					if (!chain)
						return layer_exception("invalid operation");

					auto encoded_public_key = chain->encode_public_key(std::string_view((char*)manager_account->public_key.data(), manager_account->public_key.size()));
					if (!encoded_public_key)
						return encoded_public_key.error();

					auto addresses = chain->to_addresses(*encoded_public_key);
					if (!addresses)
						return addresses.error();

					for (auto& address : *addresses)
						address.second = superchain::address_util::encode_tag_address(address.second, to_string(policy->accounts_under_management));
					
					auto policy_status = executor->apply_validator_attestation_account(asset, manager, 1);
					if (!policy_status)
						return policy_status.error();

					auto witness_account_status = executor->apply_witness_bridge_account(asset, executor->receipt.from, manager, *addresses);
					if (!witness_account_status)
						return witness_account_status.error();

					return expectation::met;
				}
				case superchain::routing_policy::utxo:
				{
					auto duplicate = executor->get_bridge_account(asset, manager, executor->receipt.from);
					if (!duplicate)
						break;

					if (!routing_address_application)
						return layer_exception("bridge account already exists");

					return expectation::met;
				}
				default:
					return layer_exception("invalid operation");
			}

			btree_set<algorithm::pubkeyhash_t> exclusion;
			auto committee = executor->calculate_participants(exclusion, policy->security_level, policy->participation_threshold);
			if (!committee)
				return committee.error();

			for (auto& work : *committee)
			{
				auto event = executor->emit_event<route>({ format::variable(work.owner.view()) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> route::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto* runner_wallet = dispatcher->get_runner_wallet(manager);
			if (!runner_wallet)
				return expects_promise_rt<void>(expectation::met);

			auto* event = executor->receipt.find_event<route>();
			if (!event || executor->get_witness_event(executor->receipt.transaction_hash))
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
				auto group = get_group(executor->receipt);
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
			stream->write_string(manager.optimized_view());
			stream->write_string(routing_address);
			return true;
		}
		bool route::load_body(format::ro_stream& stream)
		{
			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_bytes(manager_assembly, manager.blob, sizeof(manager)))
				return false;

			if (!stream.read_string(stream.read_type(), &routing_address))
				return false;

			return true;
		}
		bool route::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto group = get_group(receipt);
			parties.insert(algorithm::pubkeyhash_t(manager));
			parties.insert(group.begin(), group.end());
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
		void route::set_manager(const algorithm::pubkeyhash_t& new_manager)
		{
			manager = new_manager;
		}
		btree_set<algorithm::pubkeyhash_t> route::get_group(const ledger::receipt& receipt) const
		{
			btree_set<algorithm::pubkeyhash_t> result;
			for (auto& event : receipt.find_events<route>())
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result.insert(algorithm::pubkeyhash_t(event->front().as_blob()));
			}
			return result;
		}
		format::tree route::as_tree() const
		{
			format::tree data = ledger::commitment::as_tree();
			data.set("manager", algorithm::signing::serialize_address(manager));
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

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> bind::execute(ledger::executor_context* executor) const
		{
			auto validation = commitment::execute(executor);
			if (!validation)
				return validation.error();

			auto event = executor->apply_witness_event(route_hash, executor->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto parent = executor->get_block_transaction<route>(route_hash);
			if (!parent)
				return parent.error();

			auto* parent_transaction = (route*)*parent->transaction;
			auto* server = superchain::bridge::get();
			auto* chain = server->get_network(asset);
			auto* params = server->get_network_params(asset);
			if (!chain || !params)
				return layer_exception("invalid operation");

			auto duplicate = executor->get_bridge_account(asset, parent_transaction->manager, parent->receipt.from);
			if (duplicate)
				return layer_exception("bridge account already exists");

			auto encoded_public_key = chain->encode_public_key(std::string_view((char*)group_public_key.data(), group_public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto addresses = chain->to_addresses(*encoded_public_key);
			if (!addresses)
				return addresses.error();

			auto policy = executor->get_verified_validator_attestation(asset, parent_transaction->manager);
			if (!policy)
				return policy.error();

			switch (params->routing)
			{
				case superchain::routing_policy::account:
				case superchain::routing_policy::memo:
				{
					if (policy->accounts_under_management > 0)
						return layer_exception("too many accounts for a bridge");

					if (params->routing == superchain::routing_policy::account)
						break;

					for (auto& address : *addresses)
						address.second = superchain::address_util::encode_tag_address(address.second, to_string(policy->accounts_under_management));
					break;
				}
				default:
					break;
			}

			auto policy_status = executor->apply_validator_attestation_account(asset, parent_transaction->manager, 1);
			if (!policy_status)
				return policy_status.error();

			auto ref = states::validator_participation_ref::ref_value();
			ref.asset = asset;
			ref.manager = parent_transaction->manager;
			ref.owner = parent->receipt.from;

			auto group = parent_transaction->get_group(parent->receipt);
			for (auto& participant : group)
			{
				auto status = executor->apply_validator_participation_ref(participant, ref, true);
				if (!status)
					return status.error();
			}

			auto bridge_account_status = executor->apply_bridge_account(asset, ref.owner, ref.manager, group_public_key, std::move(group));
			if (!bridge_account_status)
				return bridge_account_status.error();

			auto witness_account_status = executor->apply_witness_bridge_account(asset, ref.owner, ref.manager, *addresses);
			if (!witness_account_status)
				return witness_account_status.error();

			for (auto& [type, address] : *addresses)
			{
				auto [base_address, tag] = superchain::address_util::decode_tag_address(address);
				if (base_address != address)
				{
					auto status = server->enable_link(asset, superchain::wallet_link(parent_transaction->manager, *encoded_public_key, base_address));
					if (!status)
						return status.error();
				}

				auto status = server->enable_link(asset, superchain::wallet_link(parent_transaction->manager, *encoded_public_key, address));
				if (!status)
					return status.error();
			}

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
		bool bind::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto parent = executor->get_block_transaction<route>(route_hash);
			if (!parent)
				return false;

			auto* parent_transaction = (route*)*parent->transaction;
			parties.insert(algorithm::pubkeyhash_t(parent_transaction->manager));
			parties.insert(algorithm::pubkeyhash_t(parent->receipt.from));
			return true;
		}
		format::tree bind::as_tree() const
		{
			format::tree data = ledger::commitment::as_tree();
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
			if (manager.empty())
				return layer_exception("invalid manager");

			auto* chain = superchain::bridge::get()->get_network_params(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (!algorithm::asset::is_aux(asset))
				return layer_exception("not a valid withdrawal asset");

			if (!to_address.empty() && !to_value.is_positive())
				return layer_exception("invalid to value");
			else if (to_address.empty() && !to_value.is_nan())
				return layer_exception("invalid to address/value");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> withdraw::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
			if (!validation)
				return validation.error();

			bool migration = to_address.empty() && executor->receipt.from == manager;
			if (to_address.empty() && !migration)
				return layer_exception("must include at least one withdrawal destination");

			auto policy = executor->get_verified_validator_attestation(asset, manager);
			if (!policy)
				return policy.error();
			else if (!policy->accepts_withdrawal_requests && !migration)
				return layer_exception("bridge forbids withdrawal requests");
			else if (only_if_not_in_queue && policy->queue_transaction_hash > 0)
				return layer_exception("bridge is in use - withdrawal will be queued");

			auto token_value = get_token_value(executor, executor->receipt);
			if (!token_value.is_positive())
				return layer_exception("zero value withdrawal not allowed");

			auto fee_asset = algorithm::asset::base_id_of(asset);
			auto fee_value = get_fee_value(executor);
			if (!fee_value.is_positive())
				return layer_exception("bridge does not have a withdrawal fee - network fee cannot be paid");

			if (migration)
			{
				auto fee_balance = executor->get_bridge_balance(fee_asset, manager);
				if (!fee_balance || fee_balance->supply < fee_value)
					return layer_exception(algorithm::asset::handle_of(fee_asset) + " balance is insufficient perform migration");

				if (asset != fee_asset)
				{
					size_t offset = 0, count = 32;
					while (true)
					{
						auto balances = executor->get_bridge_balances(manager, offset, count);
						if (!balances)
							break;

						for (auto& balance : *balances)
						{
							if (fee_asset == balance.asset || fee_asset != algorithm::asset::base_id_of(balance.asset))
								continue;

							if (balance.supply.is_positive())
								return layer_exception(algorithm::asset::handle_of(balance.asset) + " balance must be migrated before " + algorithm::asset::handle_of(fee_asset));
						}

						offset += balances->size();
						if (balances->size() != count)
							break;
					}
				}

				auto next_policy = executor->calculate_attester_for_migration(asset, manager);
				if (!next_policy)
					return next_policy.error();

				auto account = find_receiving_account(executor, asset, manager, next_policy->owner);
				if (!account)
					return account.error();

				auto registration = executor->apply_validator_attestation_queue(asset, manager, executor->receipt.transaction_hash);
				if (!registration)
					return registration.error();

				auto event = executor->emit_event<withdraw>({ format::variable(next_policy->owner.view()) });
				if (!event)
					return event;

				return expectation::met;
			}

			if (fee_asset != asset)
			{
				auto balance_requirement = executor->verify_transfer_balance(fee_asset, fee_value);
				if (!balance_requirement)
					return balance_requirement.error();

				auto fee_balance = executor->get_bridge_balance(fee_asset, manager);
				if (!fee_balance || fee_balance->supply < fee_value)
					return layer_exception(algorithm::asset::handle_of(fee_asset) + " balance is insufficient to cover base withdrawal value (value: " + fee_value.to_string() + ")");
			}
			else
				token_value += fee_value;

			auto balance_requirement = executor->verify_transfer_balance(asset, token_value);
			if (!balance_requirement)
				return balance_requirement;

			auto token_balance = executor->get_bridge_balance(asset, manager);
			if (!token_balance || token_balance->supply < token_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient to cover token withdrawal value (value: " + token_value.to_string() + ")");

			auto collision = executor->get_witness_account_tagged(fee_asset, to_address, 0);
			if (collision && (!collision->is_routing_account() || collision->owner != executor->receipt.from))
				return layer_exception("invalid to address (not owned by sender)");
			else if (!collision)
				collision = executor->apply_witness_routing_account(asset, executor->receipt.from, { { (uint8_t)1, string(to_address) } });
			if (!collision)
				return collision.error();

			if (fee_asset != asset)
			{
				auto fee_transfer = executor->apply_transfer(fee_asset, executor->receipt.from, decimal::zero(), fee_value);
				if (!fee_transfer)
					return fee_transfer.error();
			}

			auto token_transfer = executor->apply_transfer(asset, executor->receipt.from, decimal::zero(), token_value);
			if (!token_transfer)
				return token_transfer.error();

			auto registration = executor->apply_validator_attestation_queue(asset, manager, executor->receipt.transaction_hash);
			if (!registration)
				return registration.error();

			return expectation::met;
		}
		expects_promise_rt<void> withdraw::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto* runner_wallet = dispatcher->get_runner_wallet(manager);
			if (!runner_wallet)
				return expects_promise_rt<void>(expectation::met);

			if (executor->get_witness_event(executor->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto policy = executor->get_verified_validator_attestation(asset, manager);
			if (policy && policy->queue_transaction_hash != executor->receipt.transaction_hash)
			{
				if (only_if_not_in_queue && policy->queue_transaction_hash > 0)
					return expects_promise_rt<void>(remote_exception::retry_later());
			}

			return coasync<expects_rt<void>>([this, executor, dispatcher, runner_wallet]() mutable -> expects_promise_rt<void>
			{
				auto* server = superchain::bridge::get();
				auto* chain = server->get_network_params(asset);
				auto cancel = [this, executor, dispatcher, runner_wallet](remote_exception&& error) -> expects_rt<void>
				{
					auto* transaction = memory::init<broadcast>();
					transaction->asset = asset;
					transaction->set_proof(executor->receipt.transaction_hash, layer_exception(std::move(remote_exception(error).message())));
					dispatcher->emit_transaction(runner_wallet, transaction);
					return expects_rt<void>(std::move(error));
				};

				auto transfer = superchain::value_transfer();
				auto new_manager = get_new_manager(executor->receipt);
				if (!new_manager.empty())
				{
					if (new_manager.empty() || new_manager == manager)
						coreturn cancel(remote_exception(remote_exception("invalid manager to migrate to")));

					auto account = find_receiving_account(executor, asset, manager, new_manager);
					if (!account)
						coreturn cancel(remote_exception(std::move(account.error().message())));

					transfer = superchain::value_transfer(asset, account->addresses.begin()->second, get_token_value(executor, executor->receipt));
				}
				else
					transfer = superchain::value_transfer(asset, to_address, decimal(to_value));

				auto cache = dispatcher->pull_cache(executor);
				auto state = ledger::dispatcher_context::signature_state();
				if (chain->transaction_expires || !state.load(cache))
				{
					auto message = coawait(resolver::prepare_transaction(algorithm::asset::base_id_of(asset), superchain::wallet_link::from_owner(manager), transfer, get_fee_value(executor)));
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

					auto account = executor->get_bridge_account(asset, witness->manager, witness->owner);
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

						auto result = coawait(dispatcher->aggregate_signature(executor, state, *it));
						if (!result && (result.error().is_retry() || result.error().is_shutdown()))
						{
							unavailable.insert(*it);
							if (chosen_input)
								goto postpone;
						}
						else if (!result)
							coreturn cancel(std::move(result.error()));
						else
							reset = false;

						state.participants.erase(it);
					}

					if (!unavailable.empty())
					{
						state.participants = std::move(unavailable);
						goto postpone;
					}

					auto finalization = state.compositor->to_signature(&input->signature);
					if (!finalization)
						coreturn cancel(remote_exception(std::move(finalization.error().message())));

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
			stream->write_boolean(only_if_not_in_queue);
			stream->write_string(manager.optimized_view());
			stream->write_string(to_address);
			stream->write_decimal(to_value);
			return true;
		}
		bool withdraw::load_body(format::ro_stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &only_if_not_in_queue))
				return false;

			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_bytes(manager_assembly, manager.blob, sizeof(manager)))
				return false;

			if (!stream.read_string(stream.read_type(), &to_address))
				return false;

			if (!stream.read_decimal(stream.read_type(), &to_value))
				return false;

			return true;
		}
		bool withdraw::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto new_manager = get_new_manager(receipt);
			parties.insert(algorithm::pubkeyhash_t(manager));
			if (!new_manager.empty())
				parties.insert(algorithm::pubkeyhash_t(new_manager));
			return true;
		}
		void withdraw::set_to(const std::string_view& address, const decimal& value)
		{
			to_address = address;
			to_value = value;
		}
		void withdraw::set_manager(const algorithm::pubkeyhash_t& new_manager)
		{
			manager = new_manager;
		}
		bool withdraw::is_dispatchable() const
		{
			return true;
		}
		algorithm::pubkeyhash_t withdraw::get_new_manager(const ledger::receipt& receipt) const
		{
			algorithm::pubkeyhash_t result;
			auto* event = receipt.find_event<withdraw>();
			if (event != nullptr)
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash_t))
					result = algorithm::pubkeyhash_t(event->front().as_blob());
			}
			if (result == manager)
				result = algorithm::pubkeyhash_t();
			return result;
		}
		decimal withdraw::get_token_value(const ledger::executor_context* executor, const ledger::receipt& receipt) const
		{
			decimal value = 0.0;
			if (to_address.empty() && receipt.from == manager)
			{
				auto bridge = executor->get_bridge_balance(asset, manager);
				if (bridge)
				{
					value += bridge->supply;
					if (algorithm::asset::is_aux(asset, true))
					{
						auto fee_value = get_fee_value(executor);
						if (fee_value <= value)
							value -= fee_value;
					}
				}
			}
			else
				value = to_value;
			return value;
		}
		decimal withdraw::get_fee_value(const ledger::executor_context* executor) const
		{
			auto reward = executor->get_verified_validator_attestation(algorithm::asset::base_id_of(asset), manager);
			return reward ? reward->outgoing_fee : decimal::zero();
		}
		format::tree withdraw::as_tree() const
		{
			format::tree data = ledger::transaction::as_tree();
			data.set("manager", algorithm::signing::serialize_address(manager));
			if (!to_address.empty() && !to_value.is_nan())
			{
				data.set("to_address", format::variable(to_address));
				data.set("to_value", format::variable(to_value));
			}
			data.set("only_if_not_in_queue", format::variable(only_if_not_in_queue));
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
		expects_lr<states::witness_account> withdraw::find_receiving_account(const ledger::executor_context* executor, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from_manager, const algorithm::pubkeyhash_t& to_manager)
		{
			auto base_asset = algorithm::asset::base_id_of(asset);
			size_t offset = 0, count = 8;
			while (true)
			{
				auto candidates = executor->get_witness_accounts_by_purpose(to_manager, states::witness_account::account_type::bridge, offset, count);
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
				auto candidates = executor->get_witness_accounts_by_purpose(from_manager, states::witness_account::account_type::bridge, offset, count);
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

		expects_lr<void> broadcast::validate(uint64_t block_number) const
		{
			if (!withdraw_hash)
				return layer_exception("withdraw hash not valid");

			return ledger::commitment::validate(block_number);
		}
		expects_lr<void> broadcast::execute(ledger::executor_context* executor) const
		{
			auto validation = commitment::execute(executor);
			if (!validation)
				return validation.error();

			auto parent = executor->get_block_transaction<withdraw>(withdraw_hash);
			if (!parent)
				return layer_exception("parent transaction not found");

			auto* parent_transaction = (withdraw*)*parent->transaction;
			if (parent_transaction->manager != executor->receipt.from)
				return layer_exception("parent transaction not valid");

			auto event = executor->apply_witness_event(withdraw_hash, executor->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto finalization = executor->apply_validator_attestation_queue(parent_transaction->asset, parent_transaction->manager, 0);
			if (!finalization)
				return finalization.error();

			auto confirmation = proof ? validate_finalized_proof(executor, parent_transaction, parent->receipt, *proof) : expects_lr<void>(expectation::met);
			if (!confirmation)
				return confirmation.error();

			bool pays_fee = parent_transaction->get_new_manager(parent->receipt).empty();
			auto fee_asset = algorithm::asset::base_id_of(parent_transaction->asset);
			auto fee_value = parent_transaction->get_fee_value(executor);
			if (!proof)
			{
				if (!pays_fee)
					return expectation::met;

				if (fee_asset != parent_transaction->asset)
				{
					auto fee_transfer = executor->apply_transfer(fee_asset, parent->receipt.from, decimal::zero(), -fee_value);
					if (!fee_transfer)
						return fee_transfer.error();
				}

				auto token_value = parent_transaction->get_token_value(executor, parent->receipt) + (fee_asset == parent_transaction->asset ? fee_value : decimal::zero());
				auto token_transfer = executor->apply_transfer(parent_transaction->asset, parent->receipt.from, decimal::zero(), -token_value);
				if (!token_transfer)
					return token_transfer.error();
			}
			else if (pays_fee)
			{
				auto fee_transfer = executor->apply_transfer(fee_asset, parent->receipt.from, -fee_value, -fee_value);
				if (!fee_transfer)
					return fee_transfer.error();
			}

			return expectation::met;
		}
		expects_promise_rt<void> broadcast::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto parent = proof ? executor->get_block_transaction<withdraw>(withdraw_hash) : expects_lr<ledger::block_transaction>(layer_exception("not applicable"));
			if (!parent)
				return expects_promise_rt<void>(expectation::met);

			auto* parent_transaction = (withdraw*)*parent->transaction;
			auto status = superchain::bridge::get()->update_utxo_tree(algorithm::asset::base_id_of(parent_transaction->asset), proof->as_computed());
			return status ? expects_promise_rt<void>(expectation::met) : expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
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
		bool broadcast::is_dispatchable() const
		{
			return true;
		}
		bool broadcast::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
			format::tree data = ledger::commitment::as_tree();
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
		expects_lr<void> broadcast::validate_possible_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::receipt& receipt, const superchain::prepared_transaction& prepared)
		{
			if (prepared.as_status() == superchain::prepared_transaction::status::invalid)
				return layer_exception("invalid prepared transaction");

			auto server = superchain::bridge::get();
			auto base_asset = algorithm::asset::base_id_of(transaction->asset);
			auto required_output_witness = btree_map<string, states::witness_account>();
			auto required_output_value = btree_map<algorithm::asset_id, decimal>();
			auto new_manager = transaction->get_new_manager(receipt);
			if (new_manager.empty())
			{
				auto normalized_address = transaction->to_address;
				auto status = server->normalize_address(transaction->asset, &normalized_address);
				if (!status)
					return status.error();

				if (required_output_witness.find(normalized_address) == required_output_witness.end())
				{
					auto witness = executor->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("transaction requires paying to unknown address");

					required_output_witness.insert(std::make_pair(std::move(normalized_address), std::move(*witness)));
				}

				auto& value = required_output_value[transaction->asset];
				value = value.is_nan() ? transaction->to_value : (value + transaction->to_value);
			}
			else
			{
				if (!transaction->to_address.empty() || !transaction->to_value.is_nan())
					return layer_exception("migration/withdrawal confusion");

				auto witness = withdraw::find_receiving_account(executor, transaction->asset, transaction->manager, new_manager);
				if (!witness)
					return layer_exception("prepared transaction not possible");

				auto account = executor->get_bridge_account(base_asset, witness->manager, witness->owner);
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

			auto inout_witness = btree_map<string, states::witness_account>();
			auto input_value = btree_map<algorithm::asset_id, decimal>();
			auto output_value = btree_map<algorithm::asset_id, decimal>();
			auto change_value = btree_map<algorithm::asset_id, decimal>();
			for (auto& input : prepared.inputs)
			{
				auto normalized_address = input.utxo.link.address;
				auto status = server->normalize_address(base_asset, &normalized_address);
				if (!status)
					return status.error();

				auto it = inout_witness.find(normalized_address);
				if (it == inout_witness.end())
				{
					auto witness = executor->get_witness_account_tagged(base_asset, normalized_address, 0);
					if (!witness)
						return layer_exception("witness transaction input spends from unknown address");

					auto account = executor->get_bridge_account(base_asset, witness->manager, witness->owner);
					if (!account)
						return layer_exception("witness transaction input refers to a non-bridge account");

					inout_witness.insert(std::make_pair(normalized_address, std::move(*witness)));
					it = inout_witness.find(normalized_address);
				}

				if (!it->second.is_bridge_account() || !it->second.manager.equals(transaction->manager))
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
				auto status = server->normalize_address(base_asset, &normalized_address);
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

					auto account = executor->get_bridge_account(base_asset, it->second.manager, it->second.owner);
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

			auto max_fee_value = transaction->get_fee_value(executor);
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
				else if (input_token_asset == base_asset && delta_token_value > max_fee_value)
					return layer_exception("witness transaction fee overflow (max: " + max_fee_value.to_string() + ")");
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
					else if (output_asset == base_asset && actual_output_value < it->second - max_fee_value || actual_output_value > it->second + max_fee_value)
						return layer_exception("witness transaction output pays unexpected native value");
				}
				else if (output_asset == base_asset && actual_output_value > std::max(max_change_value, max_fee_value))
					return layer_exception("witness transaction output pays unexpected native value");
				else if (output_asset != base_asset && actual_output_value != max_change_value)
					return layer_exception("witness transaction output pays unexpected token value");
			}

			return expectation::met;
		}
		expects_lr<void> broadcast::validate_finalized_proof(const ledger::executor_context* executor, const withdraw* transaction, const ledger::receipt& receipt, const superchain::finalized_transaction& finalized)
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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> anticast::execute(ledger::executor_context* executor) const
		{
			auto validation = transaction::execute(executor);
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
			if (executor->get_witness_transaction(origin_transaction->asset, parent_transaction->proof->hashdata))
				return layer_exception("broadcast is considered final either by attestation or older protest");

			auto time_lock = protocol::now().policy.attestation.withdrawal_time / protocol::now().policy.pow.time;
			auto time_delta = parent->receipt.block_number < executor->receipt.block_number ? executor->receipt.block_number - parent->receipt.block_number : 0;
			if (time_delta <= time_lock)
				return layer_exception("broadcast time lock active - retry after block number " + to_string(parent->receipt.block_number + time_lock));

			auto base_asset = algorithm::asset::base_id_of(origin_transaction->asset);
			auto finalization = executor->apply_witness_transaction(base_asset, parent_transaction->proof->hashdata);
			if (!finalization)
				return finalization.error();

			auto token_value = origin_transaction->get_token_value(executor, origin->receipt);
			auto token_transfer = executor->apply_transfer(origin_transaction->asset, origin->receipt.from, decimal::zero(), -token_value);
			if (!token_transfer)
				return token_transfer.error();

			auto attestation = executor->get_verified_validator_attestation(base_asset, origin_transaction->manager);
			if (!attestation)
				return expectation::met;

			auto prev_attestation = executor->get_validator_attestation_reward(base_asset, origin_transaction->manager);
			if (!prev_attestation)
				return expectation::met;

			auto next_attestation = executor->apply_validator_attestation_reward(base_asset, origin_transaction->manager, -attestation->outgoing_fee);
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
		expects_promise_rt<void> anticast::dispatch(const ledger::executor_context* executor, ledger::dispatcher_context* dispatcher) const
		{
			auto parent = executor->get_block_transaction<broadcast>(broadcast_hash, true);
			auto origin = parent ? executor->get_block_transaction<withdraw>(((broadcast*)*parent->transaction)->withdraw_hash, true) : expects_lr<ledger::block_transaction>(layer_exception("not applicable"));
			if (!origin)
				return expects_promise_rt<void>(expectation::met);

			auto* origin_transaction = (withdraw*)*origin->transaction;
			auto* parent_transaction = (broadcast*)*parent->transaction;
			auto status = superchain::bridge::get()->revive_utxo_tree(algorithm::asset::base_id_of(origin_transaction->asset), parent_transaction->proof->as_computed());
			return status ? expects_promise_rt<void>(expectation::met) : expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
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
		bool anticast::is_dispatchable() const
		{
			return true;
		}
		bool anticast::recover_many(const ledger::executor_context* executor, const ledger::receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
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
			format::tree data = ledger::transaction::as_tree();
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
			else if (hash == attestate::as_instance_type())
				return memory::init<attestate>();
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
			return nullptr;
		}
		ledger::transaction* resolver::from_copy(const ledger::transaction* base)
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
			else if (hash == attestate::as_instance_type())
				return memory::init<attestate>(*(const attestate*)base);
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
			return nullptr;
		}
		expects_promise_rt<superchain::prepared_transaction> resolver::prepare_transaction(const algorithm::asset_id& asset, const superchain::wallet_link& from_link, const superchain::value_transfer& to, const decimal& max_fee)
		{
			auto* server = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || server->has_network(asset, true))
				return server->prepare_transaction(asset, from_link, to, max_fee);

			auto chain = server->get_network_params(asset);
			if (!chain)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("invalid operation"));

			auto from = server->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::wo_stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<superchain::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = server->to_composite_public_key(asset, from->public_key);
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
			auto* server = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || server->has_network(asset, true))
				return server->finalize_transaction(asset, std::move(prepared));

			auto transaction_id = algorithm::encoding::encode_0xhex256(prepared.as_hash());
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint32_t>::max();
			auto regtest_finalized = superchain::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			regtest_finalized.calldata = regtest_finalized.as_message().encode();
			return expects_lr<superchain::finalized_transaction>(std::move(regtest_finalized));
		}
		expects_promise_rt<void> resolver::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, superchain::finalized_transaction&& finalized, ledger::dispatcher_context* dispatcher, const ledger::wallet* runner_wallet)
		{
			auto* server = superchain::bridge::get();
			bool may_mock_up = protocol::now().is(network_type::regtest);
			if (!may_mock_up || server->has_network(asset, true))
			{
				auto preserved = memory::init<superchain::finalized_transaction>(std::move(finalized));
				return server->broadcast_transaction(asset, external_id, *preserved).then<expects_rt<void>>([preserved](expects_rt<void>&& status) mutable -> expects_rt<void>
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
