#include "transactions.h"
#include "../kernel/block.h"
#include "../kernel/script.h"
#include "../validator/service/nss.h"

namespace tangent
{
	namespace transactions
	{
		expects_lr<void> transfer::validate(uint64_t block_number) const
		{
			if (transfers.empty())
				return layer_exception("no transfers");

			for (auto& transfer : transfers)
			{
				if (!transfer.value.is_positive())
					return layer_exception("invalid value");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> transfer::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			for (auto& transfer : transfers)
			{
				if (memcmp(context->receipt.from, transfer.to, sizeof(algorithm::pubkeyhash)) == 0)
					return layer_exception("invalid receiver");

				auto payment = context->apply_payment(asset, context->receipt.from, transfer.to, transfer.value);
				if (!payment)
					return payment.error();
			}

			return expectation::met;
		}
		bool transfer::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			if (transfers.size() > 1)
			{
				stream->write_integer((uint16_t)transfers.size());
				for (auto& transfer : transfers)
				{
					stream->write_string(transfer.memo);
					stream->write_decimal(transfer.value);
					stream->write_string(std::string_view((char*)transfer.to, memcmp(transfer.to, null, sizeof(null)) == 0 ? 0 : sizeof(transfer.to)));
				}
			}
			else if (!transfers.empty())
			{
				auto& transfer = transfers.front();
				stream->write_string(transfer.memo);
				stream->write_decimal(transfer.value);
				stream->write_string(std::string_view((char*)transfer.to, memcmp(transfer.to, null, sizeof(null)) == 0 ? 0 : sizeof(transfer.to)));	
			}

			return true;
		}
		bool transfer::load_body(format::stream& stream)
		{
			auto type = stream.read_type();
			if (format::util::is_string(type))
			{
				batch transfer;
				if (!stream.read_string(type, &transfer.memo))
					return false;

				if (!stream.read_decimal(stream.read_type(), &transfer.value))
					return false;

				string to_assembly;
				if (!stream.read_string(stream.read_type(), &to_assembly) || !algorithm::encoding::decode_uint_blob(to_assembly, transfer.to, sizeof(transfer.to)))
					return false;

				transfers.push_back(std::move(transfer));
			}
			else if (type != format::viewable::invalid)
			{
				uint16_t transfers_size;
				if (!stream.read_integer(type, &transfers_size))
					return false;

				transfers.clear();
				transfers.reserve(transfers_size);
				for (uint16_t i = 0; i < transfers_size; i++)
				{
					batch transfer;
					if (!stream.read_string(stream.read_type(), &transfer.memo))
						return false;

					if (!stream.read_decimal(stream.read_type(), &transfer.value))
						return false;

					string to_assembly;
					if (!stream.read_string(stream.read_type(), &to_assembly) || !algorithm::encoding::decode_uint_blob(to_assembly, transfer.to, sizeof(transfer.to)))
						return false;

					transfers.push_back(std::move(transfer));
				}
			}

			return true;
		}
		bool transfer::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& transfer : transfers)
				parties.insert(algorithm::pubkeyhash_t(transfer.to));
			return true;
		}
		void transfer::set_to(const algorithm::pubkeyhash new_to, const decimal& new_value, const std::string_view& new_memo)
		{
			batch transfer;
			transfer.value = new_value;
			transfer.memo = new_memo;
			if (!new_to)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(transfer.to, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(transfer.to, new_to, sizeof(algorithm::pubkeyhash));
			transfers.push_back(std::move(transfer));
		}
		bool transfer::is_to_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			for (auto& transfer : transfers)
			{
				if (memcmp(transfer.to, null, sizeof(null)) == 0)
					return true;
			}
			return transfers.empty();
		}
		uptr<schema> transfer::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* transfers_data = data->set("transfers", var::set::array());
			for (auto& transfer : transfers)
			{
				auto* transfer_data = transfers_data->push(var::set::object());
				transfer_data->set("to", algorithm::signing::serialize_address(transfer.to));
				transfer_data->set("value", var::decimal(transfer.value));
				transfer_data->set("memo", transfer.memo.empty() ? var::null() : var::string(transfer.memo));
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
		uint256_t transfer::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<transfer, 64>();
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

		expects_lr<void> deployment::validate(uint64_t block_number) const
		{
			if (is_location_null())
				return layer_exception("invalid location");

			auto type = get_calldata_type();
			if (!type)
				return layer_exception("invalid calldata type");
			else if (*type == calldata_type::hashcode && calldata.size() != 65)
				return layer_exception("invalid hashcode calldata");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> deployment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			algorithm::pubkeyhash owner;
			if (!recover_location(owner))
				return layer_exception("invalid location");

			auto data = std::string_view(calldata).substr(1);
			auto type = get_calldata_type().or_else(calldata_type::hashcode);
			auto* host = ledger::script_host::get();
			auto compiler = host->allocate();
			switch (type)
			{
				case calldata_type::program:
				{
					auto code = host->unpack(data);
					if (!code)
						return code.error();

					auto hashcode = host->hashcode(*code);
					if (!host->precompile(*compiler, hashcode))
					{
						auto compilation = host->compile(*compiler, hashcode, *code);
						if (!compilation)
						{
							host->deallocate(std::move(compiler));
							return compilation.error();
						}
					}

					auto collision = context->get_witness_program(hashcode);
					if (!collision)
					{
						auto status = context->apply_witness_program(data);
						if (!status)
						{
							host->deallocate(std::move(compiler));
							return status.error();
						}
					}
					else if (collision->storage != data)
					{
						host->deallocate(std::move(compiler));
						return layer_exception("program hashcode collision");
					}

					auto status = context->apply_account_program(owner, hashcode);
					if (!status)
					{
						host->deallocate(std::move(compiler));
						return status.error();
					}
					break;
				}
				case calldata_type::hashcode:
				{
					if (!host->precompile(*compiler, data))
					{
						auto program = context->get_witness_program(data);
						if (!program)
						{
							host->deallocate(std::move(compiler));
							return layer_exception("program is not stored");
						}

						auto code = program->as_code();
						if (!code)
						{
							host->deallocate(std::move(compiler));
							return code.error();
						}

						auto compilation = host->compile(*compiler, data, *code);
						if (!compilation)
						{
							host->deallocate(std::move(compiler));
							return compilation.error();
						}
					}

					auto status = context->apply_account_program(owner, data);
					if (!status)
					{
						host->deallocate(std::move(compiler));
						return status.error();
					}
					break;
				}
				default:
					host->deallocate(std::move(compiler));
					return layer_exception("invalid calldata type");
			}

			auto sequence = context->apply_account_sequence(owner, std::numeric_limits<uint64_t>::max());
			if (!sequence)
			{
				host->deallocate(std::move(compiler));
				return sequence.error();
			}

			auto script = ledger::script_program(context);
			auto execution = script.initialize(*compiler, args);
			host->deallocate(std::move(compiler));
			return execution;
		}
		bool deployment::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(calldata);
			stream->write_string(std::string_view((char*)location, sizeof(location)));
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool deployment::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &calldata))
				return false;

			string location_assembly;
			if (!stream.read_string(stream.read_type(), &location_assembly) || location_assembly.size() != sizeof(algorithm::recpubsig))
				return false;

			args.clear();
			memcpy(location, location_assembly.data(), location_assembly.size());
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool deployment::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			algorithm::pubkeyhash owner;
			if (recover_location(owner))
				parties.insert(algorithm::pubkeyhash_t(owner));
			return true;
		}
		bool deployment::sign_location(const algorithm::seckey secret_key)
		{
			format::stream message;
			format::variables_util::serialize_merge_into(args, &message);
			message.write_string(calldata);
			return algorithm::signing::sign(algorithm::signing::message_hash(message.data), secret_key, location);
		}
		bool deployment::verify_location(const algorithm::pubkey public_key) const
		{
			format::stream message;
			format::variables_util::serialize_merge_into(args, &message);
			message.write_string(calldata);
			return algorithm::signing::verify(algorithm::signing::message_hash(message.data), public_key, location);
		}
		bool deployment::recover_location(algorithm::pubkeyhash public_key_hash) const
		{
			format::stream message;
			format::variables_util::serialize_merge_into(args, &message);
			message.write_string(calldata);
			return algorithm::signing::recover_hash(algorithm::signing::message_hash(message.data), public_key_hash, location);
		}
		bool deployment::is_location_null() const
		{
			algorithm::recpubsig null = { 0 };
			return memcmp(location, null, sizeof(null)) == 0;
		}
		void deployment::set_location(const algorithm::recpubsig new_value)
		{
			VI_ASSERT(new_value != nullptr, "new value should be set");
			memcpy(location, new_value, sizeof(algorithm::recpubsig));
		}
		void deployment::set_program_calldata(const std::string_view& new_calldata, format::variables&& new_args)
		{
			args = std::move(new_args);
			calldata.clear();
			calldata.assign(1, (char)calldata_type::program);
			calldata.append(ledger::script_host::get()->pack(new_calldata).or_else(string()));
		}
		void deployment::set_hashcode_calldata(const std::string_view& new_calldata, format::variables&& new_args)
		{
			args = std::move(new_args);
			calldata.clear();
			calldata.assign(1, (char)calldata_type::hashcode);
			calldata.append(new_calldata.substr(0, 64));
		}
		option<deployment::calldata_type> deployment::get_calldata_type() const
		{
			if (calldata.empty())
				return optional::none;

			calldata_type type = (calldata_type)(uint8_t)calldata.front();
			switch (type)
			{
				case calldata_type::program:
				case calldata_type::hashcode:
					return type;
				default:
					return optional::none;
			}
		}
		uptr<schema> deployment::as_schema() const
		{
			algorithm::pubkeyhash owner;
			recover_location(owner);

			std::string_view name;
			switch (get_calldata_type().or_else((calldata_type)(uint8_t)0))
			{
				case calldata_type::program:
					name = "program";
					break;
				case calldata_type::hashcode:
					name = "hashcode";
					break;
				default:
					break;
			}

			schema* data = ledger::transaction::as_schema().reset();
			data->set("location_signature", var::string(format::util::encode_0xhex(std::string_view((char*)location, sizeof(location)))));
			data->set("location_address", algorithm::signing::serialize_address(owner));
			data->set("deployment", name.empty() ? var::null() : var::string(name));
			data->set("calldata", var::string(format::util::encode_0xhex(calldata)));
			data->set("args", format::variables_util::serialize(args));
			return data;
		}
		uint32_t deployment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view deployment::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t deployment::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<deployment, 128>();
		}
		uint32_t deployment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view deployment::as_instance_typename()
		{
			return "deployment";
		}

		expects_lr<void> invocation::validate(uint64_t block_number) const
		{
			if (function.empty())
				return layer_exception("invalid function invocation");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> invocation::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto index = context->get_account_program(to);
			if (!index)
				return layer_exception("program is not assigned");

			if (hashcode > 0)
			{
				uint32_t basecode = algorithm::hashing::hash32d(index->hashcode);
				if (hashcode != basecode)
					return layer_exception(stringify::text("program hashcode does not match (%i != %i)", hashcode, basecode));
			}

			auto* host = ledger::script_host::get();
			auto& hashcode = index->hashcode;
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, hashcode))
			{
				auto program = context->get_witness_program(hashcode);
				if (!program)
				{
					host->deallocate(std::move(compiler));
					return layer_exception("program is not stored");
				}

				auto code = program->as_code();
				if (!code)
				{
					host->deallocate(std::move(compiler));
					return code.error();
				}

				auto compilation = host->compile(*compiler, hashcode, *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return compilation.error();
				}
			}

			auto script = ledger::script_program(context);
			auto execution = script.mutable_call(*compiler, function, args);
			host->deallocate(std::move(compiler));
			return execution;
		}
		bool invocation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_integer(hashcode);
			stream->write_string(std::string_view((char*)to, memcmp(to, null, sizeof(null)) == 0 ? 0 : sizeof(to)));
			stream->write_string(function);
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool invocation::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &hashcode))
				return false;

			string to_assembly;
			if (!stream.read_string(stream.read_type(), &to_assembly) || !algorithm::encoding::decode_uint_blob(to_assembly, to, sizeof(to)))
				return false;

			if (!stream.read_string(stream.read_type(), &function))
				return false;

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool invocation::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			parties.insert(algorithm::pubkeyhash_t(to));
			return true;
		}
		void invocation::set_calldata(const algorithm::pubkeyhash new_to, const std::string_view& new_function, format::variables&& new_args)
		{
			set_calldata(new_to, 0, new_function, std::move(new_args));
		}
		void invocation::set_calldata(const algorithm::pubkeyhash new_to, uint32_t new_hashcode, const std::string_view& new_function, format::variables&& new_args)
		{
			args = std::move(new_args);
			function = new_function;
			hashcode = new_hashcode;
			if (!new_to)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(to, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(to, new_to, sizeof(algorithm::pubkeyhash));
		}
		bool invocation::is_to_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(to, null, sizeof(null)) == 0;
		}
		uptr<schema> invocation::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("to", algorithm::signing::serialize_address(to));
			data->set("hashcode", var::integer(hashcode));
			data->set("function", var::string(function));
			data->set("args", format::variables_util::serialize(args));
			return data;
		}
		uint32_t invocation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view invocation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t invocation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<invocation, 128>();
		}
		uint32_t invocation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view invocation::as_instance_typename()
		{
			return "invocation";
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

					uint256_t transaction_hash = transaction->as_hash();
					reference->gas_price = decimal::zero();
					auto validation = transaction->validate(block_number);
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

			uint256_t absolute_gas_limit = context->block->gas_limit;
			uint256_t absolute_gas_use = context->block->gas_use;
			uint256_t relative_gas_use = context->receipt.relative_gas_use;
			std::sort(queue.begin(), queue.end(), [](const std::pair<ledger::transaction*, uint16_t>& a, const std::pair<ledger::transaction*, uint16_t>& b)
			{
				return a.first->sequence < b.first->sequence;
			});

			algorithm::pubkeyhash null = { 0 };
			for (auto& [transaction, index] : queue)
			{
				format::stream message;
				message.write_integer(rollup::as_instance_type());
				message.write_integer(asset);
				message.write_integer(index);
				if (!transaction->store_payload(&message))
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " validation failed: invalid payload");

				algorithm::pubkeyhash owner;
				if (!algorithm::signing::recover_hash(message.hash(), owner, transaction->signature) || !memcmp(owner, null, sizeof(null)))
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " validation failed: invalid signature");

				transaction->gas_price = decimal::zero();
				auto execution = ledger::transaction_context::execute_tx((ledger::block*)context->block, context->environment, transaction, transaction->as_hash(), owner, *context->delta.incoming, transaction->as_message().data.size(), (uint8_t)ledger::transaction_context::execution_flags::only_successful);
				transaction->gas_price = decimal::nan();
				relative_gas_use += execution->receipt.relative_gas_use;
				if (!execution)
					return layer_exception("sub-transaction " + algorithm::encoding::encode_0xhex256(transaction->as_hash()) + " execution failed: " + execution.error().message());

				auto report = context->emit_event<rollup>({ format::variable(execution->receipt.transaction_hash), format::variable(execution->receipt.relative_gas_use), format::variable(execution->receipt.relative_gas_paid) });
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
						auto status = coawait(ledger::transaction_context::dispatch_tx(&target_transaction, dispatcher));
						if (!status && status.error().is_retry() || status.error().is_shutdown())
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
		bool rollup::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)transactions.size());
			for (auto& group : transactions)
			{
				stream->write_integer(group.first == asset ? uint256_t(0) : group.first);
				stream->write_integer((uint32_t)group.second.size());
				for (auto& transaction : group.second)
				{
					stream->write_integer(transaction->as_type());
					stream->write_integer(transaction->sequence);
					stream->write_integer(transaction->gas_limit);
					stream->write_string(std::string_view((char*)transaction->signature, sizeof(transaction->signature)));
					if (!transaction->store_body(stream))
						return false;
				}
			}

			return true;
		}
		bool rollup::load_body(format::stream& stream)
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
					uint32_t type;
					if (!stream.read_integer(stream.read_type(), &type))
						return false;

					uptr<ledger::transaction> next = resolver::from_type(type);
					if (!next || !stream.read_integer(stream.read_type(), &next->sequence))
						return false;

					if (!stream.read_integer(stream.read_type(), &next->gas_limit))
						return false;

					if (!stream.read_string(stream.read_type(), &signature_assembly) || signature_assembly.size() != sizeof(algorithm::recpubsig))
						return false;

					next->asset = group_asset;
					if (!next->load_body(stream))
						return false;

					setup_child(**next, asset);
					memcpy(next->signature, signature_assembly.data(), signature_assembly.size());
					group.push_back(std::move(next));
				}
			}
			return true;
		}
		bool rollup::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					algorithm::pubkeyhash from = { 0 };
					if (transaction->recover_hash(from))
					{
						parties.insert(algorithm::pubkeyhash_t(from));
						transaction->recover_many(context, receipt, parties);
					}
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
					algorithm::pubkeyhash from = { 0 };
					aliases.insert(transaction->as_hash());
					transaction->recover_aliases(context, receipt, aliases);
				}
			}
			return true;
		}
		bool rollup::merge(const ledger::transaction& transaction)
		{
			auto* next = resolver::from_copy(&transaction);
			if (!next)
				return false;

			transactions[next->asset].push_back(next);
			return true;
		}
		bool rollup::merge(ledger::transaction& transaction, const algorithm::seckey secret_key)
		{
			auto it = transactions.find(transaction.asset ? transaction.asset : asset);
			uint16_t index = it != transactions.end() ? it->second.size() : 0;
			return sign_child(transaction, secret_key, asset, index) && merge(transaction);
		}
		bool rollup::merge(ledger::transaction& transaction, const algorithm::seckey secret_key, uint64_t sequence)
		{
			transaction.sequence = sequence;
			return merge(transaction, secret_key);
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
		uint256_t rollup::get_gas_estimate() const
		{
			uint256_t gas_requirement = ledger::gas_util::get_gas_estimate<rollup, 8>();
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
					gas_requirement += transaction->gas_limit;
			}
			return gas_requirement;
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
		void rollup::setup_child(ledger::transaction& transaction, const algorithm::asset_id& asset)
		{
			if (!transaction.asset)
				transaction.asset = asset;
			transaction.conservative = false;
			transaction.gas_price = decimal::nan();
			if (!transaction.gas_limit)
				transaction.gas_limit = transaction.get_gas_estimate();
		}
		bool rollup::sign_child(ledger::transaction& transaction, const algorithm::seckey secret_key, const algorithm::asset_id& asset, uint16_t index)
		{
			format::stream message;
			message.write_integer(rollup::as_instance_type());
			message.write_integer(asset);
			message.write_integer(index);
			setup_child(transaction, asset);

			if (!transaction.store_payload(&message))
				return false;

			return algorithm::signing::sign(message.hash(), secret_key, transaction.signature);
		}

		expects_lr<void> certification::validate(uint64_t block_number) const
		{
			if (!online && observers.empty())
				return layer_exception("invalid status");

			for (auto& mediator : observers)
			{
				uint64_t expiry_number = algorithm::asset::expiry_of(mediator.first);
				if (!expiry_number || (block_number > expiry_number && mediator.second))
					return layer_exception("invalid observer asset");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> certification::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			bool goes_online = online.or_else(false);
			for (auto& mediator : observers)
				goes_online = mediator.second || goes_online;

			if (goes_online)
			{
				auto status = context->verify_account_work(context->receipt.from);
				if (!status)
					return status;
			}

			if (online)
			{
				auto work = context->apply_account_work(context->receipt.from, *online ? states::account_flags::online : states::account_flags::offline, 0, 0, 0);
				if (!work)
					return work.error();
			}

			for (auto& mediator : observers)
			{
				auto observer_work = context->apply_account_observer(mediator.first, context->receipt.from, mediator.second);
				if (!observer_work)
					return observer_work.error();
			}

			return expectation::met;
		}
		bool certification::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint8_t)(online ? (*online ? 1 : 0) : 2));
			stream->write_integer((uint16_t)observers.size());
			for (auto& mediator : observers)
			{
				stream->write_integer(mediator.first);
				stream->write_boolean(mediator.second);
			}
			return true;
		}
		bool certification::load_body(format::stream& stream)
		{
			uint8_t status;
			if (!stream.read_integer(stream.read_type(), &status))
				return false;

			if (status == 0)
				online = false;
			else if (status == 1)
				online = true;
			else
				online = optional::none;

			uint16_t observers_size = 0;
			if (!stream.read_integer(stream.read_type(), &observers_size))
				return false;

			observers.clear();
			for (uint16_t i = 0; i < observers_size; i++)
			{
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				bool observing;
				if (!stream.read_boolean(stream.read_type(), &observing))
					return false;

				observers[asset] = observing;
			}

			return true;
		}
		void certification::set_online()
		{
			online = true;
		}
		void certification::set_online(const algorithm::asset_id& asset)
		{
			observers[asset] = true;
		}
		void certification::set_offline()
		{
			online = false;
		}
		void certification::set_offline(const algorithm::asset_id& asset)
		{
			observers[asset] = false;
		}
		void certification::set_standby()
		{
			online = optional::none;
		}
		void certification::set_standby(const algorithm::asset_id& asset)
		{
			observers.erase(asset);
		}
		uptr<schema> certification::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("online", var::integer(online ? (*online ? 1 : 0) : -1));

			auto* observers_data = data->set("observers", var::set::array());
			for (auto& mediator : observers)
			{
				auto* observer_data = observers_data->push(var::set::object());
				observer_data->set("asset", algorithm::asset::serialize(mediator.first));
				observer_data->set("online", var::boolean(mediator.second));
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
		uint256_t certification::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<certification, 64>();
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

		expects_lr<void> routing_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (address.empty())
				return layer_exception("invalid address");

			return expectation::met;
		}
		expects_lr<void> routing_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto public_key_hash = chain->decode_address(address);
			if (!public_key_hash)
				return public_key_hash.error();

			auto collision = context->get_witness_account(asset, address, 0);
			if (collision)
				return layer_exception("account address " + address + " taken");

			auto status = context->apply_witness_routing_account(asset, context->receipt.from, { { (uint8_t)1, string(address) } });
			if (!status)
				return status.error();

			return expectation::met;
		}
		bool routing_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(address);
			return true;
		}
		bool routing_account::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &address))
				return false;

			return true;
		}
		void routing_account::set_address(const std::string_view& new_address)
		{
			address = new_address;
		}
		uptr<schema> routing_account::as_schema() const
		{
			schema* data = ledger::delegation_transaction::as_schema().reset();
			data->set("address", var::string(address));
			return data;
		}
		uint32_t routing_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view routing_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t routing_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<routing_account, 128>();
		}
		uint32_t routing_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view routing_account::as_instance_typename()
		{
			return "routing_account";
		}

		expects_lr<void> depository_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			algorithm::pubkeyhash null = { 0 };
			if (memcmp(proposer, null, sizeof(null)) == 0)
				return layer_exception("invalid account proposer");

			return ledger::delegation_transaction::validate(block_number);
		}
		expects_lr<void> depository_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto work_requirement = context->verify_account_work(proposer);
			if (!work_requirement)
				return work_requirement.error();

			auto depository_policy = context->get_depository_policy(asset, proposer);
			if (!depository_policy)
				return depository_policy.error();
			else if (!depository_policy->accepts_account_requests)
				return layer_exception("proposer's depository forbids account creations");

			auto duplicate = context->get_depository_account(asset, proposer, context->receipt.from);
			if (duplicate)
				return layer_exception("depository account already exists");

			switch (chain->routing)
			{
				case mediator::routing_policy::account:
				{
					if (depository_policy->accounts_under_management > 0)
						return layer_exception("too many accounts for a depository");
					break;
				}
				case mediator::routing_policy::memo:
				{
					size_t offset = 0, count = 64;
					while (depository_policy->accounts_under_management > 0)
					{
						auto candidates = context->get_witness_accounts_by_purpose(proposer, states::witness_account::account_type::depository, offset, count);
						if (!candidates)
							return candidates.error();

						auto candidate = std::find_if(candidates->begin(), candidates->end(), [this](const states::witness_account& v) { return v.asset == asset && !memcmp(v.proposer, proposer, sizeof(proposer)); });
						if (candidate != candidates->end())
						{
							uint64_t address_index = depository_policy->accounts_under_management + 1;
							for (auto& address : candidate->addresses)
								address.second = mediator::address_util::encode_tag_address(address.second, to_string(address_index));

							auto depository_policy_status = context->apply_depository_policy_account(asset, proposer, 1);
							if (!depository_policy_status)
								return depository_policy_status.error();

							auto depository_account_status = context->apply_depository_account(asset, context->receipt.from, proposer, nullptr, { });
							if (!depository_account_status)
								return depository_account_status.error();

							auto witness_account_status = context->apply_witness_depository_account(asset, context->receipt.from, candidate->addresses, proposer);
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
				case mediator::routing_policy::utxo:
					break;
				default:
					return layer_exception("invalid operation");
			}

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto committee = context->calculate_sharing_committee(exclusion, depository_policy->security_level);
			if (!committee)
				return committee.error();

			for (auto& work : *committee)
			{
				auto event = context->emit_event<depository_account>({ format::variable(std::string_view((char*)work.owner, sizeof(work.owner))) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> depository_account::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_on(proposer))
				return expects_promise_rt<void>(expectation::met);

			auto* event = context->receipt.find_event<depository_account>();
			if (!event || context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, context, dispatcher]() -> expects_promise_rt<void>
			{
				auto* chain = nss::server_node::get()->get_chainparams(asset);
				if (!chain)
					coreturn remote_exception("invalid operation");

				ordered_set<algorithm::pubkeyhash_t> mpc_signers;
				algorithm::composition::cpubkey_t mpc_public_key;
				auto cache = dispatcher->load_cache(context);
				if (cache)
				{
					mpc_public_key = algorithm::composition::cpubkey_t(codec::hex_decode(cache->get_var(0).get_blob()));
					for (size_t i = 1; i < cache->size(); i++)
						mpc_signers.insert(algorithm::pubkeyhash_t(codec::hex_decode(cache->get_var(i).get_blob())));
				}

				auto mpc = get_mpc(context->receipt);
				for (auto& share : mpc_signers)
					mpc.erase(share);

				bool mpc_fully_signed = true;
				for (auto& share : mpc)
				{
					auto result = coawait(dispatcher->calculate_mpc_public_key(context, share.data, mpc_public_key));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					{
						mpc_fully_signed = false;
						continue;
					}
					else if (!result)
						coreturn result.error();

					mpc_signers.insert(share);
				}

				if (mpc_fully_signed)
				{
					auto status = algorithm::composition::accumulate_public_key(chain->composition, nullptr, mpc_public_key.data);
					if (!status)
						coreturn remote_exception(std::move(status.error().message()));

					auto* transaction = memory::init<depository_account_finalization>();
					transaction->asset = asset;
					transaction->set_witness(context->receipt.transaction_hash, mpc_public_key.data);
					dispatcher->emit_transaction(transaction);
					dispatcher->store_cache(context, nullptr);
					coreturn expectation::met;
				}
				else
				{
					cache = var::set::array();
					cache->push(var::string(codec::hex_encode(mpc_public_key.optimized_view())));
					for (auto& share : mpc_signers)
						cache->push(var::string(codec::hex_encode(share.optimized_view())));
					dispatcher->store_cache(context, std::move(cache));
					coreturn remote_exception::retry();
				}
			});
		}
		bool depository_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			return true;
		}
		bool depository_account::load_body(format::stream& stream)
		{
			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			return true;
		}
		bool depository_account::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto mpc = get_mpc(receipt);
			parties.insert(algorithm::pubkeyhash_t(proposer));
			parties.insert(mpc.begin(), mpc.end());
			return true;
		}
		void depository_account::set_proposer(const algorithm::pubkeyhash new_proposer)
		{
			if (!new_proposer)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
		}
		bool depository_account::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(proposer, null, sizeof(null)) == 0;
		}
		bool depository_account::is_dispatchable() const
		{
			return true;
		}
		ordered_set<algorithm::pubkeyhash_t> depository_account::get_mpc(const ledger::receipt& receipt) const
		{
			ordered_set<algorithm::pubkeyhash_t> result;
			for (auto& event : receipt.find_events<depository_account>())
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash))
					result.insert(algorithm::pubkeyhash_t(event->front().as_blob()));
			}
			return result;
		}
		uptr<schema> depository_account::as_schema() const
		{
			schema* data = ledger::delegation_transaction::as_schema().reset();
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			return data;
		}
		uint32_t depository_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t depository_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_account, 16>();
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
			
			algorithm::composition::cpubkey null = { 0 };
			if (!memcmp(mpc_public_key, null, sizeof(null)))
				return layer_exception("invalid mpc public key");

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
			auto* server = nss::server_node::get();
			auto* chain = server->get_chain(asset);
			auto* params = server->get_chainparams(asset);
			if (!chain || !params)
				return layer_exception("invalid operation");

			auto duplicate = context->get_depository_account(asset, setup_transaction->proposer, context->receipt.from);
			if (duplicate)
				return layer_exception("depository account already exists");

			auto public_key = chain->encode_public_key(std::string_view((char*)mpc_public_key, algorithm::composition::size_of_public_key(params->composition)));
			if (!public_key)
				return public_key.error();

			auto addresses = chain->to_addresses(*public_key);
			if (!addresses)
				return addresses.error();

			auto work_requirement = context->verify_account_work(setup_transaction->proposer);
			if (!work_requirement)
				return work_requirement.error();

			auto depository_policy = context->get_depository_policy(asset, setup_transaction->proposer);
			if (!depository_policy)
				return depository_policy.error();
			else if (!depository_policy->accepts_account_requests)
				return layer_exception("proposer's depository forbids account creations");

			switch (params->routing)
			{
				case mediator::routing_policy::account:
				{
					if (depository_policy->accounts_under_management > 0)
						return layer_exception("too many accounts for a depository");
					break;
				}
				case mediator::routing_policy::memo:
				{
					uint64_t address_index = depository_policy->accounts_under_management + 1;
					for (auto& address : *addresses)
						address.second = mediator::address_util::encode_tag_address(address.second, to_string(address_index));
					break;
				}
				default:
					break;
			}

			auto depository_policy_status = context->apply_depository_policy_account(asset, setup_transaction->proposer, 1);
			if (!depository_policy_status)
				return depository_policy_status.error();

			auto depository_account_status = context->apply_depository_account(asset, setup->receipt.from, setup_transaction->proposer, mpc_public_key, setup_transaction->get_mpc(setup->receipt));
			if (!depository_account_status)
				return depository_account_status.error();

			auto witness_account_status = context->apply_witness_depository_account(asset, setup->receipt.from, *addresses, setup_transaction->proposer);
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

			auto* server = nss::server_node::get();
			auto* chain = server->get_chain(asset);
			auto* params = server->get_chainparams(asset);
			if (!chain || !params)
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto public_key = chain->encode_public_key(std::string_view((char*)mpc_public_key, algorithm::composition::size_of_public_key(params->composition)));
			if (!public_key)
				return expects_promise_rt<void>(remote_exception(std::move(public_key.error().message())));

			auto* setup_transaction = (depository_account*)*setup->transaction;
			for (auto& address : addresses)
			{
				auto [base_address, tag] = mediator::address_util::decode_tag_address(address);
				if (base_address != address)
				{
					auto status = server->enable_link(asset, mediator::wallet_link(setup_transaction->proposer, *public_key, base_address));
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}

				auto status = server->enable_link(asset, mediator::wallet_link(setup_transaction->proposer, *public_key, address));
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
		void depository_account_finalization::set_witness(const uint256_t& new_depository_account_hash, const algorithm::composition::cpubkey new_mpc_public_key)
		{
			VI_ASSERT(new_mpc_public_key, "mpc public key should be set");
			depository_account_hash = new_depository_account_hash;
			memcpy(mpc_public_key, new_mpc_public_key, sizeof(mpc_public_key));
		}
		bool depository_account_finalization::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::composition::cpubkey null = { 0 };
			auto params = nss::server_node::get()->get_chainparams(asset);
			size_t mpc_public_key_size = params ? algorithm::composition::size_of_public_key(params->composition) : sizeof(mpc_public_key);
			stream->write_string(std::string_view((char*)mpc_public_key, memcmp(mpc_public_key, null, mpc_public_key_size) == 0 ? 0 : mpc_public_key_size));
			stream->write_integer(depository_account_hash);
			return true;
		}
		bool depository_account_finalization::load_body(format::stream& stream)
		{
			string mpc_public_key_assembly;
			auto params = nss::server_node::get()->get_chainparams(asset);
			size_t mpc_public_key_size = params ? algorithm::composition::size_of_public_key(params->composition) : sizeof(mpc_public_key);
			if (!stream.read_string(stream.read_type(), &mpc_public_key_assembly) || !algorithm::encoding::decode_uint_blob(mpc_public_key_assembly, mpc_public_key, mpc_public_key_size))
				return false;

			if (!stream.read_integer(stream.read_type(), &depository_account_hash))
				return false;

			return true;
		}
		bool depository_account_finalization::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			auto setup = context->get_block_transaction<depository_account>(depository_account_hash);
			if (!setup)
				return false;

			auto* setup_transaction = (depository_account*)*setup->transaction;
			parties.insert(algorithm::pubkeyhash_t(setup_transaction->proposer));
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
			auto params = nss::server_node::get()->get_chainparams(asset);
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_account_hash", depository_account_hash > 0 ? var::string(algorithm::encoding::encode_0xhex256(depository_account_hash)) : var::null());
			data->set("mpc_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_public_key, params ? algorithm::composition::size_of_public_key(params->composition) : sizeof(mpc_public_key)))));
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
		uint256_t depository_account_finalization::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_account_finalization, 128>();
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
			if (is_proposer_null())
				return layer_exception("invalid proposer");

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (is_migration_proposer_null())
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
			else
			{
				if (!to.empty())
					return layer_exception("invalid to");

				if (!memcmp(proposer, migration_proposer, sizeof(migration_proposer)))
					return layer_exception("invalid migration proposer");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_withdrawal::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto depository_policy = context->get_depository_policy(asset, proposer);
			if (!depository_policy)
				return depository_policy.error();
			else if (!depository_policy->accepts_withdrawal_requests)
				return layer_exception("proposer's depository forbids withdrawals");
			else if (only_if_not_in_queue && depository_policy->queue_transaction_hash > 0)
				return layer_exception("proposer's depository is in use - withdrawal will be queued");

			if (!is_migration_proposer_null())
			{
				if (memcmp(context->receipt.from, proposer, sizeof(algorithm::pubkeyhash)) != 0)
					return layer_exception("invalid migration sender");

				auto to_depository = context->get_depository_policy(asset, migration_proposer);
				if (!to_depository)
					return depository_policy.error();
				else if (!depository_policy->accepts_account_requests || !depository_policy->accepts_withdrawal_requests)
					return layer_exception("invalid migration depository");

				auto account = find_migration_account(context, asset, proposer, migration_proposer);
				if (!account)
					return account.error();

				auto registration = context->apply_depository_policy_queue(asset, proposer, context->receipt.transaction_hash);
				if (!registration)
					return registration.error();

				return expectation::met;
			}

			auto token_value = get_total_value(context);
			auto base_asset = algorithm::asset::base_id_of(asset);
			auto base_fee_value = asset == base_asset ? get_fee_value(context, nullptr, token_value) : get_fee_value(context, nullptr, decimal::zero());
			auto& base_value = asset == base_asset ? std::max(base_fee_value, token_value) : base_fee_value;
			if (base_asset != asset && base_value.is_positive())
			{
				auto balance_requirement = context->verify_transfer_balance(base_asset, base_value);
				if (!balance_requirement)
					return balance_requirement.error();

				auto depository = context->get_depository_balance(base_asset, proposer);
				if (!depository || depository->supply < base_value)
					return layer_exception("proposer's " + algorithm::asset::handle_of(base_asset) + " balance is insufficient to cover base withdrawal value (value: " + base_value.to_string() + ")");
			}

			auto balance_requirement = context->verify_transfer_balance(asset, token_value);
			if (!balance_requirement)
				return balance_requirement;

			auto depository = context->get_depository_balance(asset, proposer);
			if (!depository || depository->supply < token_value)
				return layer_exception("proposer's " + algorithm::asset::handle_of(asset) + " balance is insufficient to cover token withdrawal value (value: " + token_value.to_string() + ")");

			for (auto& item : to)
			{
				auto collision = context->get_witness_account(base_asset, item.first, 0);
				if (collision && (!collision->is_routing_account() || memcmp(collision->owner, context->receipt.from, sizeof(collision->owner)) != 0))
					return layer_exception("invalid to address (not owned by sender)");
				else if (!collision)
					collision = context->apply_witness_routing_account(asset, context->receipt.from, { { (uint8_t)1, string(item.first) } });
				if (!collision)
					return collision.error();
			}

			if (base_value.is_positive() || base_fee_value.is_positive())
			{
				auto base_transfer = context->apply_transfer(base_asset, context->receipt.from, -base_fee_value, base_value - base_fee_value);
				if (!base_transfer)
					return base_transfer.error();

				base_transfer = context->apply_transfer(base_asset, proposer, base_fee_value, decimal::zero());
				if (!base_transfer)
					return base_transfer.error();
			}

			if (base_asset != asset && token_value.is_positive())
			{
				auto token_transfer = context->apply_transfer(asset, context->receipt.from, decimal::zero(), token_value);
				if (!token_transfer)
					return token_transfer.error();
			}

			auto registration = context->apply_depository_policy_queue(asset, proposer, context->receipt.transaction_hash);
			if (!registration)
				return registration.error();

			return expectation::met;
		}
		expects_promise_rt<void> depository_withdrawal::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (!dispatcher->is_on(proposer))
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto depository_policy = context->get_depository_policy(asset, proposer);
			if (depository_policy && depository_policy->queue_transaction_hash != context->receipt.transaction_hash)
				return expects_promise_rt<void>(remote_exception::retry());

			vector<mediator::value_transfer> transfers;
			if (!is_migration_proposer_null())
			{
				auto account = find_migration_account(context, asset, proposer, migration_proposer);
				if (!account)
					return expects_promise_rt<void>(remote_exception(std::move(account.error().message())));

				auto total_value = get_total_value(context);
				transfers.push_back(mediator::value_transfer(asset, account->addresses.begin()->second, decimal(total_value)));
			}
			else
			{
				auto base_asset = algorithm::asset::base_id_of(asset);
				auto base_fee_value = asset == base_asset ? get_fee_value(context, nullptr, get_total_value(context)) : get_fee_value(context, nullptr, decimal::zero());
				for (auto& item : to)
					transfers.push_back(mediator::value_transfer(asset, item.first, decimal(asset == base_asset ? item.second - base_fee_value : item.second)));
			}

			return coasync<expects_rt<void>>([this, context, dispatcher, transfers = std::move(transfers)]() mutable -> expects_promise_rt<void>
			{
				auto* server = nss::server_node::get();
				auto* chain = server->get_chainparams(asset);
				auto cache = dispatcher->load_cache(context);
				auto mpc_prepared = expects_rt<mediator::prepared_transaction>(mediator::prepared_transaction());
				auto mpc_signers = ordered_set<algorithm::pubkeyhash_t>();
				auto mpc_signature = ordered_map<uint8_t, algorithm::composition::cpubsig_t>();
				if (cache && !chain->requires_transaction_expiration)
				{
					format::stream mpc_prepared_message = format::stream::decode(cache->get_var(0).get_blob());
					if (!mpc_prepared->load_payload(mpc_prepared_message))
						mpc_prepared = expects_rt<mediator::prepared_transaction>(remote_exception::retry());

					uint8_t split = cache->get_var(1).get_integer();
					for (size_t i = 2; i < split; i++)
					{
						auto* item = cache->get(i);
						if (item != nullptr)
							mpc_signature[(uint8_t)item->get_var(0).get_integer()] = algorithm::composition::cpubsig_t(codec::hex_decode(item->get_var(1).get_blob()));
					}
					for (size_t i = split; i < cache->size(); i++)
						mpc_signers.insert(algorithm::pubkeyhash_t(codec::hex_decode(cache->get_var(i).get_blob())));
				}
				else
					mpc_prepared = expects_rt<mediator::prepared_transaction>(remote_exception::retry());

				if (!mpc_prepared)
					mpc_prepared = coawait(resolver::prepare_transaction(asset, mediator::wallet_link::from_owner(proposer), transfers));

				if (!mpc_prepared)
				{
					if (mpc_prepared.error().is_retry() || mpc_prepared.error().is_shutdown())
						coreturn expects_rt<void>(mpc_prepared.error());

					auto* transaction = memory::init<depository_withdrawal_finalization>();
					transaction->asset = asset;
					transaction->set_failure_witness(mpc_prepared.what(), context->receipt.transaction_hash);
					dispatcher->emit_transaction(transaction);
					coreturn expects_rt<void>(mpc_prepared.error());
				}
				else if (mpc_prepared->inputs.size() > std::numeric_limits<uint8_t>::max())
				{
					auto error = remote_exception("too many prepared inputs");
					auto* transaction = memory::init<depository_withdrawal_finalization>();
					transaction->asset = asset;
					transaction->set_failure_witness(error.what(), context->receipt.transaction_hash);
					dispatcher->emit_transaction(transaction);
					coreturn expects_rt<void>(std::move(error));
				}

				auto mpc = accumulate_prepared_mpc(context, this, *mpc_prepared);
				if (!mpc)
					coreturn remote_exception(std::move(mpc.error().message()));

				for (auto& share : mpc_signers)
					mpc->erase(share);

				bool mpc_fully_signed = true;
				for (auto& share : *mpc)
				{
					auto result = coawait(dispatcher->calculate_mpc_signature(context, share, *mpc_prepared, mpc_signature));
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					{
						mpc_fully_signed = false;
						continue;
					}
					else if (!result)
						coreturn result.error();

					mpc_signers.insert(share);
				}

				if (mpc_fully_signed)
				{
					for (auto& [input_index, input_signature] : mpc_signature)
					{
						auto& input = mpc_prepared->inputs[input_index];
						auto status = algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, nullptr, input_signature.data);
						if (!status)
							coreturn remote_exception(std::move(status.error().message()));

						memcpy(input.signature, input_signature.data, sizeof(input_signature.data));
					}

					auto mpc_finalized = coawait(resolver::finalize_and_broadcast_transaction(asset, context->receipt.transaction_hash, std::move(*mpc_prepared), dispatcher));
					if (!mpc_finalized)
					{
						if (!mpc_finalized.error().is_retry() && !mpc_finalized.error().is_shutdown())
						{
							auto* transaction = memory::init<depository_withdrawal_finalization>();
							transaction->asset = asset;
							transaction->set_failure_witness(mpc_finalized.what(), context->receipt.transaction_hash);
							dispatcher->emit_transaction(transaction);
							dispatcher->store_cache(context, nullptr);
						}
						coreturn mpc_finalized.error();
					}
					else
					{
						auto* transaction = memory::init<depository_withdrawal_finalization>();
						transaction->asset = asset;
						transaction->set_success_witness(mpc_finalized->hashdata, mpc_finalized->calldata, context->receipt.transaction_hash);
						dispatcher->emit_transaction(transaction);
						dispatcher->store_cache(context, nullptr);
						coreturn expectation::met;
					}
				}
				else
				{
					if (chain->requires_transaction_expiration)
						coreturn remote_exception::retry();

					format::stream mpc_prepared_message;
					mpc_prepared->store_payload(&mpc_prepared_message);

					cache = var::set::array();
					cache->push(var::string(mpc_prepared_message.encode()));
					for (auto& mpc_share : mpc_signature)
					{
						auto* item = cache->push(var::set::array());
						item->push(var::integer(mpc_share.first));
						item->push(var::string(codec::hex_encode(mpc_share.second.optimized_view())));
					}
					for (auto& share : mpc_signers)
						cache->push(var::string(codec::hex_encode(share.optimized_view())));
					dispatcher->store_cache(context, std::move(cache));
					coreturn remote_exception::retry();
				}
			});
		}
		bool depository_withdrawal::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_boolean(only_if_not_in_queue);
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			stream->write_string(std::string_view((char*)migration_proposer, memcmp(migration_proposer, null, sizeof(null)) == 0 ? 0 : sizeof(migration_proposer)));
			stream->write_integer((uint16_t)to.size());
			for (auto& item : to)
			{
				stream->write_string(item.first);
				stream->write_decimal(item.second);
			}
			return true;
		}
		bool depository_withdrawal::load_body(format::stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &only_if_not_in_queue))
				return false;

			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			string migration_proposer_assembly;
			if (!stream.read_string(stream.read_type(), &migration_proposer_assembly) || !algorithm::encoding::decode_uint_blob(migration_proposer_assembly, migration_proposer, sizeof(migration_proposer)))
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
			if (!is_proposer_null())
				parties.insert(algorithm::pubkeyhash_t(proposer));
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
		void depository_withdrawal::set_proposer(const algorithm::pubkeyhash new_proposer, const algorithm::pubkeyhash new_migration_proposer)
		{
			algorithm::pubkeyhash null = { 0 };
			if (!new_proposer)
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
			if (!new_migration_proposer)
				memcpy(migration_proposer, null, sizeof(algorithm::pubkeyhash));
			else
				memcpy(migration_proposer, new_migration_proposer, sizeof(algorithm::pubkeyhash));
		}
		bool depository_withdrawal::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(proposer, null, sizeof(null)) == 0;
		}
		bool depository_withdrawal::is_migration_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(migration_proposer, null, sizeof(null)) == 0;
		}
		bool depository_withdrawal::is_dispatchable() const
		{
			return true;
		}
		decimal depository_withdrawal::get_total_value(const ledger::transaction_context* context) const
		{
			decimal value = 0.0;
			if (!is_migration_proposer_null())
			{
				auto depository = context->get_depository_balance(asset, proposer);
				if (depository)
					value += depository->supply;
			}
			else
			{
				for (auto& item : to)
					value += item.second;
			}
			return value;
		}
		decimal depository_withdrawal::get_fee_value(const ledger::transaction_context* context, const algorithm::pubkeyhash from, const decimal& total_value) const
		{
			bool charges = is_migration_proposer_null() && memcmp(from ? from : context->receipt.from, proposer, sizeof(algorithm::pubkeyhash)) != 0;
			auto base_asset = algorithm::asset::base_id_of(asset);
			auto base_reward = charges ? context->get_depository_reward(base_asset, proposer) : expects_lr<states::depository_reward>(layer_exception());
			auto fee_value = (base_reward ? base_reward->calculate_outgoing_fee(total_value) : decimal::zero());
			return fee_value;
		}
		uptr<schema> depository_withdrawal::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			if (is_migration_proposer_null())
			{
				auto* to_data = data->set("to", var::set::array());
				for (auto& item : to)
				{
					auto* coin_data = to_data->push(var::set::object());
					coin_data->set("address", var::string(item.first));
					coin_data->set("value", var::decimal(item.second));
				}
				data->set("proposer", algorithm::signing::serialize_address(proposer));
			}
			else
			{
				data->set("from_proposer", algorithm::signing::serialize_address(proposer));
				data->set("to_proposer", algorithm::signing::serialize_address(migration_proposer));
			}
			data->set("only_if_not_in_queue", var::boolean(only_if_not_in_queue));
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
		uint256_t depository_withdrawal::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_withdrawal, 36>();
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
		expects_lr<void> depository_withdrawal::validate_prepared_transaction(const ledger::transaction_context* context, const depository_withdrawal* transaction, const mediator::prepared_transaction& prepared)
		{
			if (prepared.as_status() == mediator::prepared_transaction::status::invalid)
				return layer_exception("invalid prepared transaction");

			auto blockchain = algorithm::asset::blockchain_of(transaction->asset);
			auto base_asset = algorithm::asset::base_id_of(transaction->asset);
			for (auto& input : prepared.inputs)
			{
				if (input.utxo.is_account() && algorithm::asset::blockchain_of(input.utxo.get_asset(transaction->asset)) != blockchain)
					return layer_exception("prepared input asset not valid");
			}

			for (auto& output : prepared.outputs)
			{
				if (output.is_account() && algorithm::asset::blockchain_of(output.get_asset(transaction->asset)) != blockchain)
					return layer_exception("prepared output asset not valid");
			}

			auto input_value = unordered_map<algorithm::asset_id, decimal>();
			auto output_value = unordered_map<algorithm::asset_id, decimal>();
			for (auto& input : prepared.inputs)
			{
				auto& value = input_value[input.utxo.get_asset(transaction->asset)];
				value = value.is_nan() ? input.utxo.value : (value + input.utxo.value);
				for (auto& token : input.utxo.tokens)
				{
					auto& token_value = input_value[token.get_asset(transaction->asset)];
					token_value = token_value.is_nan() ? input.utxo.value : (token_value + input.utxo.value);
				}
			}
			for (auto& output : prepared.outputs)
			{
				auto& value = output_value[output.get_asset(transaction->asset)];
				value = value.is_nan() ? output.value : (value + output.value);
				for (auto& token : output.tokens)
				{
					auto& token_value = output_value[token.get_asset(transaction->asset)];
					token_value = token_value.is_nan() ? output.value : (token_value + output.value);
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

			auto server = nss::server_node::get();
			auto presented_output_addresses = unordered_set<string>();
			for (auto& output : prepared.outputs)
			{
				auto presented_address = output.link.address;
				auto status = server->normalize_address(transaction->asset, &presented_address);
				if (!status)
					return status.error();

				presented_output_addresses.insert(presented_address);
			}

			for (auto& transfer : transaction->to)
			{
				auto required_address = transfer.first;
				auto status = server->normalize_address(transaction->asset, &required_address);
				if (!status)
					return status.error();

				target_output->second -= transfer.second;
				if (presented_output_addresses.find(required_address) == presented_output_addresses.end())
					return layer_exception("prepared transaction inout not valid");
			}

			if (target_output->second.is_negative())
			{
				algorithm::pubkeyhash null = { 0 };
				auto token_value = transaction->get_total_value(context);
				auto base_asset = algorithm::asset::base_id_of(transaction->asset);
				auto base_fee_value = transaction->asset == base_asset ? transaction->get_fee_value(context, null, token_value) : transaction->get_fee_value(context, null, decimal::zero());
				target_output->second += base_fee_value;
				if (target_output->second.is_negative())
					return layer_exception("prepared transaction inout not valid");
			}

			for (auto& input : prepared.inputs)
			{
				auto witness = context->get_witness_account_tagged(transaction->asset, input.utxo.link.address, 0);
				if (!witness || !witness->is_depository_account())
					return layer_exception("input refers to an address that does not exist or is not depository address");

				auto account = context->get_depository_account(transaction->asset, witness->proposer, witness->owner);
				if (!account)
					return layer_exception("input refers to an account that does not have a linked depository");
			}

			return expectation::met;
		}
		expects_lr<ordered_set<algorithm::pubkeyhash_t>> depository_withdrawal::accumulate_prepared_mpc(const ledger::transaction_context* context, const depository_withdrawal* transaction, const mediator::prepared_transaction& prepared)
		{
			ordered_set<algorithm::pubkeyhash_t> mpc;
			for (auto& input : prepared.inputs)
			{
				auto witness = context->get_witness_account_tagged(transaction->asset, input.utxo.link.address, 0);
				if (!witness)
					return witness.error();

				auto account = context->get_depository_account(transaction->asset, witness->proposer, witness->owner);
				if (!account)
					return account.error();

				mpc.insert(account->mpc.begin(), account->mpc.end());
			}
			return expects_lr<ordered_set<algorithm::pubkeyhash_t>>(std::move(mpc));
		}
		expects_lr<states::witness_account> depository_withdrawal::find_migration_account(const ledger::transaction_context* context, const algorithm::asset_id& asset, const algorithm::pubkeyhash from_proposer, const algorithm::pubkeyhash to_proposer)
		{
			auto base_asset = algorithm::asset::base_id_of(asset);
			size_t offset = 0, count = 8;
			while (true)
			{
				auto candidates = context->get_witness_accounts_by_purpose(to_proposer, states::witness_account::account_type::depository, offset, count);
				if (!candidates)
					return candidates.error();

				auto candidate = std::find_if(candidates->begin(), candidates->end(), [&](const states::witness_account& v) { return v.asset == base_asset && !memcmp(to_proposer, v.proposer, sizeof(v.proposer)); });
				if (candidate != candidates->end())
					return *candidate;

				offset += candidates->size();
				if (candidates->size() < count)
					break;
			}

			offset = 0;
			while (true)
			{
				auto candidates = context->get_witness_accounts_by_purpose(from_proposer, states::witness_account::account_type::depository, offset, count);
				if (!candidates)
					return candidates.error();

				auto candidate = std::find_if(candidates->begin(), candidates->end(), [&](const states::witness_account& v) { return v.asset == base_asset && !memcmp(to_proposer, v.proposer, sizeof(v.proposer)); });
				if (candidate != candidates->end())
					return *candidate;

				offset += candidates->size();
				if (candidates->size() < count)
					break;
			}

			return layer_exception("depository migration account (to) not found");
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
			if (memcmp(parent_transaction->proposer, context->receipt.from, sizeof(algorithm::pubkeyhash)) != 0)
				return layer_exception("parent transaction not valid");

			auto event = context->apply_witness_event(depository_withdrawal_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto finalization = context->apply_depository_policy_queue(asset, parent_transaction->proposer, 0);
			if (!finalization)
				return finalization.error();

			if (!transaction_id.empty() || !parent_transaction->is_migration_proposer_null())
				return expectation::met;

			auto token_value = parent_transaction->get_total_value(context);
			auto base_asset = algorithm::asset::base_id_of(asset);
			auto base_fee_value = asset == base_asset ? parent_transaction->get_fee_value(context, parent->receipt.from, token_value) : parent_transaction->get_fee_value(context, parent->receipt.from, decimal::zero());
			auto& base_value = asset == base_asset ? std::max(base_fee_value, token_value) : base_fee_value;
			if (base_value.is_positive() || base_fee_value.is_positive())
			{
				auto base_transfer = context->apply_transfer(base_asset, parent->receipt.from, base_fee_value, base_fee_value - base_value);
				if (!base_transfer)
					return base_transfer.error();

				base_transfer = context->apply_transfer(base_asset, parent_transaction->proposer, -base_fee_value, decimal::zero());
				if (!base_transfer)
					return base_transfer.error();
			}

			if (base_asset != asset && token_value.is_positive())
			{
				auto token_transfer = context->apply_transfer(asset, parent->receipt.from, decimal::zero(), -token_value);
				if (!token_transfer)
					return token_transfer.error();
			}

			return expectation::met;
		}
		bool depository_withdrawal_finalization::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_withdrawal_hash);
			stream->write_string(transaction_id);
			stream->write_string(native_data);
			stream->write_string(error_message);
			return true;
		}
		bool depository_withdrawal_finalization::load_body(format::stream& stream)
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
		uint256_t depository_withdrawal_finalization::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_withdrawal_finalization, 32>();
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
				return layer_exception("invalid assertion status");

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

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid chain");

			decimal change = 0.0;
			transition operations;
			ordered_set<algorithm::pubkeyhash_t> routers;
			for (auto& input : assertion->inputs)
			{
				auto source = context->get_witness_account(asset, input.link.address, 0);
				if (source)
				{
					if (source->is_depository_account())
					{
						auto source_proposer = algorithm::pubkeyhash_t(source->proposer);
						operations.depositories[source_proposer][input.get_asset(asset)].balance -= input.value;
						for (auto& token : input.tokens)
							operations.depositories[source_proposer][token.get_asset(asset)].balance -= token.value;
					}
					else if (source->is_routing_account())
						routers.insert(algorithm::pubkeyhash_t(source->owner));
				}
				else
					change -= input.value;
			}

			bool depository_to_depository = !change.is_negative() && routers.empty();
			for (auto& output : assertion->outputs)
			{
				auto source = context->get_witness_account(asset, output.link.address, 0);
				if (source)
				{
					if (source->is_depository_account())
					{
						auto source_proposer = algorithm::pubkeyhash_t(source->proposer);
						operations.depositories[source_proposer][output.get_asset(asset)].balance += output.value;
						for (auto& token : output.tokens)
							operations.depositories[source_proposer][token.get_asset(asset)].balance += token.value;

						if (!depository_to_depository)
						{
							auto source_owner = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
							operations.transfers[source_owner][output.get_asset(asset)].supply += output.value;

							auto reward = context->get_depository_reward(asset, source->proposer);
							if (reward && reward->has_incoming_fee())
							{
								auto fee = reward->calculate_incoming_fee(output.value);
								operations.transfers[source_owner][output.get_asset(asset)].supply -= fee;
								operations.transfers[source_proposer][output.get_asset(asset)].supply += fee;
							}
						}
					}
					else if (source->is_routing_account())
					{
						auto source_owner = routers.empty() ? algorithm::pubkeyhash_t(source->owner) : *routers.begin();
						auto& source_owner_transfer = operations.transfers[source_owner];
						auto& balance = source_owner_transfer[output.get_asset(asset)];
						balance.supply -= output.value;
						balance.reserve -= output.value;
						for (auto& token : output.tokens)
						{
							balance = source_owner_transfer[token.get_asset(asset)];
							balance.supply -= token.value;
							balance.reserve -= token.value;
						}
					}
					else
						change += output.value;
				}
				else
					change += output.value;
			}

			if (operations.transfers.empty() && operations.depositories.empty())
				return layer_exception("invalid transaction");

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
							supply_delta = -(balance ? balance->supply : decimal::zero());
						if (reserve.is_negative())
							reserve_delta = -(balance ? balance->reserve : decimal::zero());
					}

					auto transfer = context->apply_transfer(transfer_asset, owner.data, supply_delta, reserve_delta);
					if (!transfer)
						return transfer.error();
				}
			}

			for (auto& [owner, transfers] : operations.depositories)
			{
				for (auto& [transfer_asset, transfer] : transfers)
				{
					if (transfer.balance.is_negative())
					{
						auto balance = context->get_depository_balance(transfer_asset, owner.data);
						auto supply = (balance ? balance->supply : decimal::zero()) + transfer.balance;
						if (supply.is_negative())
							transfer.balance = -(balance ? balance->supply : decimal::zero());
					}

					auto depository = context->apply_depository_balance(transfer_asset, owner.data, transfer.balance);
					if (!depository)
						return depository.error();
				}
			}

			auto witness = context->apply_witness_transaction(asset, assertion->transaction_id);
			if (!witness)
				return witness.error();

			return context->emit_witness(asset, assertion->block_id);
		}
		bool depository_transaction::store_body(format::stream* stream) const
		{
			return true;
		}
		bool depository_transaction::load_body(format::stream& stream)
		{
			return true;
		}
		bool depository_transaction::recover_many(const ledger::transaction_context* context, const ledger::receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			for (auto& event : receipt.find_events<states::account_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			for (auto& event : receipt.find_events<states::depository_balance>())
			{
				if (event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(algorithm::pubkeyhash_t(event->at(1).as_blob()));
			}
			return true;
		}
		void depository_transaction::set_witness(uint64_t block_id, const std::string_view& transaction_id, const vector<mediator::value_transfer>& inputs, const vector<mediator::value_transfer>& outputs)
		{
			mediator::computed_transaction witness;
			witness.transaction_id = transaction_id;
			witness.block_id = block_id;
			witness.inputs.reserve(inputs.size());
			witness.outputs.reserve(outputs.size());
			for (auto& input : inputs)
				witness.inputs.push_back(mediator::coin_utxo(mediator::wallet_link::from_address(input.address), { { input.asset, input.value } }));
			for (auto& output : outputs)
				witness.outputs.push_back(mediator::coin_utxo(mediator::wallet_link::from_address(output.address), { { output.asset, output.value } }));
			set_witness(witness);
		}
		void depository_transaction::set_witness(const mediator::computed_transaction& witness)
		{
			set_statement(algorithm::hashing::hash256i(witness.transaction_id), witness.as_message());
		}
		option<mediator::computed_transaction> depository_transaction::get_assertion(const ledger::transaction_context* context) const
		{
			auto* best_branch = get_best_branch(context);
			if (!best_branch)
				return optional::none;

			auto message = best_branch->message;
			message.seek = 0;

			mediator::computed_transaction assertion;
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
		uint256_t depository_transaction::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_transaction, 144>();
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
			if (incoming_absolute_fee.is_nan() || incoming_absolute_fee.is_negative())
				return layer_exception("invalid incoming absolute fee");

			if (incoming_relative_fee.is_nan() || incoming_relative_fee.is_negative() || incoming_relative_fee > 1.0)
				return layer_exception("invalid incoming relative fee");

			if (outgoing_absolute_fee.is_nan() || outgoing_absolute_fee.is_negative())
				return layer_exception("invalid outgoing absolute fee");

			if (outgoing_relative_fee.is_nan() || outgoing_relative_fee.is_negative() || outgoing_relative_fee > 1.0)
				return layer_exception("invalid outgoing relative fee");

			if (security_level > 0 && security_level < protocol::now().policy.depository_committee_min_size)
				return layer_exception("invalid security level");

			if (security_level > 0 && security_level > protocol::now().policy.depository_committee_max_size)
				return layer_exception("invalid security level");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_adjustment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto work_requirement = context->verify_account_work(context->receipt.from);
			if (!work_requirement)
				return work_requirement;

			auto reward = context->apply_depository_reward(algorithm::asset::base_id_of(asset), context->receipt.from, incoming_absolute_fee, incoming_relative_fee, outgoing_absolute_fee, outgoing_relative_fee);
			if (!reward)
				return reward.error();

			auto depository = context->get_depository_policy(asset, context->receipt.from).or_else(states::depository_policy(nullptr, nullptr));
			if (depository.accepts_withdrawal_requests != accepts_withdrawal_requests && !accepts_withdrawal_requests)
			{
				auto balance = context->get_depository_balance(asset, context->receipt.from);
				if (balance && balance->supply.is_positive())
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
		bool depository_adjustment::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(incoming_absolute_fee);
			stream->write_decimal(incoming_relative_fee);
			stream->write_decimal(outgoing_absolute_fee);
			stream->write_decimal(outgoing_relative_fee);
			stream->write_integer(security_level);
			stream->write_boolean(accepts_account_requests);
			stream->write_boolean(accepts_withdrawal_requests);
			return true;
		}
		bool depository_adjustment::load_body(format::stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &incoming_absolute_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &incoming_relative_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &outgoing_absolute_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &outgoing_relative_fee))
				return false;

			if (!stream.read_integer(stream.read_type(), &security_level))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_account_requests))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_withdrawal_requests))
				return false;

			return true;
		}
		void depository_adjustment::set_incoming_fee(const decimal& absolute_fee, const decimal& relative_fee)
		{
			incoming_absolute_fee = absolute_fee;
			incoming_relative_fee = relative_fee;
		}
		void depository_adjustment::set_outgoing_fee(const decimal& absolute_fee, const decimal& relative_fee)
		{
			outgoing_absolute_fee = absolute_fee;
			outgoing_relative_fee = relative_fee;
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
			data->set("incoming_absolute_fee", var::decimal(incoming_absolute_fee));
			data->set("incoming_relative_fee", var::decimal(incoming_relative_fee));
			data->set("outgoing_absolute_fee", var::decimal(outgoing_absolute_fee));
			data->set("outgoing_relative_fee", var::decimal(outgoing_relative_fee));
			data->set("security_level", var::integer(security_level));
			data->set("accepts_account_requests", var::number(accepts_account_requests));
			data->set("accepts_withdrawal_requests", var::number(accepts_withdrawal_requests));
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
		uint256_t depository_adjustment::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_adjustment, 20>();
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

		expects_lr<void> depository_migration::validate(uint64_t block_number) const
		{
			if (migrations.empty())
				return layer_exception("no migrations found");

			algorithm::pubkeyhash null = { 0 };
			for (auto& [hash, migration] : migrations)
			{
				if (!algorithm::asset::is_valid(migration.asset) || !algorithm::asset::token_of(migration.asset).empty())
					return layer_exception("invalid migration asset");

				if (!memcmp(migration.proposer, null, sizeof(null)))
					return layer_exception("invalid migration proposer");

				if (!memcmp(migration.owner, null, sizeof(null)))
					return layer_exception("invalid migration owner");

				if (hash != migration.hash())
					return layer_exception("invalid migration hash");
			}

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_migration::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			ordered_set<algorithm::pubkeyhash_t> exclusion;
			auto migrating_proposer = algorithm::pubkeyhash_t(context->receipt.from);
			for (auto& [hash, migration] : migrations)
			{
				auto account = context->get_depository_account(migration.asset, migration.proposer, migration.owner);
				if (!account)
					return account.error();
				else if (account->mpc.find(migrating_proposer) == account->mpc.end())
					return layer_exception("migration of other mpc member is forbidden");

				exclusion.insert(account->mpc.begin(), account->mpc.end());
			}

			auto committee = context->calculate_sharing_committee(exclusion, 1);
			if (!committee)
				return committee.error();

			auto& work = committee->front();
			auto event = context->emit_event<depository_migration>({ format::variable(std::string_view((char*)work.owner, sizeof(work.owner))) });
			if (!event)
				return event;

			return expectation::met;
		}
		expects_promise_rt<void> depository_migration::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto new_proposer = get_new_proposer(context->receipt);
			if (!dispatcher->is_on(new_proposer.data))
				return expects_promise_rt<void>(expectation::met);

			auto* transaction = memory::init<depository_migration_preparation>();
			transaction->asset = asset;
			transaction->depository_migration_hash = context->receipt.transaction_hash;

			algorithm::seckey cipher_secret_key;
			algorithm::signing::derive_cipher_keypair(dispatcher->get_wallet()->secret_key, transaction->depository_migration_hash, cipher_secret_key, transaction->cipher_public_key);
			dispatcher->emit_transaction(transaction);
			return expects_promise_rt<void>(expectation::met);
		}
		bool depository_migration::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)migrations.size());
			for (auto& [hash, migration] : migrations)
			{
				stream->write_integer(migration.asset);
				stream->write_string(algorithm::pubkeyhash_t(migration.proposer).optimized_view());
				stream->write_string(algorithm::pubkeyhash_t(migration.owner).optimized_view());
			}
			return true;
		}
		bool depository_migration::load_body(format::stream& stream)
		{
			uint16_t migrations_size;
			if (!stream.read_integer(stream.read_type(), &migrations_size))
				return false;

			for (uint16_t i = 0; i < migrations_size; i++)
			{
				mpc_migration migration;
				if (!stream.read_integer(stream.read_type(), &migration.asset))
					return false;

				string proposer_assembly;
				if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, migration.proposer, sizeof(migration.proposer)))
					return false;

				string owner_assembly;
				if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, migration.owner, sizeof(migration.owner)))
					return false;

				migrations[migration.hash()] = std::move(migration);
			}

			return true;
		}
		void depository_migration::migrate(const algorithm::asset_id& asset, const algorithm::pubkeyhash proposer, const algorithm::pubkeyhash owner)
		{
			VI_ASSERT(proposer != nullptr, "proposer should be set");
			VI_ASSERT(owner != nullptr, "owner should be set");
			mpc_migration migration;
			migration.asset = asset;
			memcpy(migration.proposer, proposer, sizeof(migration.proposer));
			memcpy(migration.owner, owner, sizeof(migration.owner));
			migrations[migration.hash()] = std::move(migration);
		}
		bool depository_migration::is_dispatchable() const
		{
			return true;
		}
		algorithm::pubkeyhash_t depository_migration::get_new_proposer(const ledger::receipt& receipt) const
		{
			algorithm::pubkeyhash_t result;
			auto* event = receipt.find_event<depository_migration>();
			if (event != nullptr)
			{
				if (!event->empty() && event->front().as_string().size() == sizeof(algorithm::pubkeyhash))
					result = algorithm::pubkeyhash_t(event->front().as_blob());
			}
			return result;
		}
		uptr<schema> depository_migration::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* migrations_data = data->set("migrations", var::set::array());
			for (auto& [hash, migration] : migrations)
			{
				auto* migration_data = migrations_data->push(var::set::object());
				migration_data->set("asset", algorithm::asset::serialize(migration.asset));
				migration_data->set("proposer", algorithm::signing::serialize_address(migration.proposer));
				migration_data->set("owner", algorithm::signing::serialize_address(migration.owner));
			}
			return data;
		}
		uint32_t depository_migration::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_migration::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t depository_migration::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_migration, 64>();
		}
		uint32_t depository_migration::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_migration::as_instance_typename()
		{
			return "depository_migration";
		}

		expects_lr<void> depository_migration_preparation::validate(uint64_t block_number) const
		{
			if (!depository_migration_hash)
				return layer_exception("invalid migration transaction");

			algorithm::pubkey null = { 0 };
			if (!memcmp(cipher_public_key, null, sizeof(null)))
				return layer_exception("invalid cipher public key");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_migration_preparation::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(depository_migration_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			return expectation::met;
		}
		expects_promise_rt<void> depository_migration_preparation::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto setup = context->get_block_transaction<depository_migration>(depository_migration_hash);
			if (!setup)
				return expects_promise_rt<void>(remote_exception(std::move(setup.error().message())));
			else if (!dispatcher->is_on(setup->receipt.from))
				return expects_promise_rt<void>(expectation::met);

			uptr<depository_migration_commitment> transaction = memory::init<depository_migration_commitment>();
			transaction->asset = asset;
			transaction->depository_migration_preparation_hash = context->receipt.transaction_hash;

			auto* setup_transaction = (depository_migration*)*setup->transaction;
			auto old_proposer = dispatcher->get_wallet();
			for (auto& [hash, migration] : setup_transaction->migrations)
			{
				auto mpc_seed = dispatcher->calculate_or_get_mpc_seed(migration.asset, migration.proposer, migration.owner);
				if (!mpc_seed)
					return expects_promise_rt<void>(remote_exception(std::move(mpc_seed.error().message())));

				auto status = transaction->transfer(hash, *mpc_seed, cipher_public_key, old_proposer->secret_key);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			dispatcher->emit_transaction(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool depository_migration_preparation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_migration_hash);
			stream->write_string(algorithm::pubkey_t(cipher_public_key).optimized_view());
			return true;
		}
		bool depository_migration_preparation::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_migration_hash))
				return false;

			string cipher_public_key_assembly;
			if (!stream.read_string(stream.read_type(), &cipher_public_key_assembly) || !algorithm::encoding::decode_uint_blob(cipher_public_key_assembly, cipher_public_key, sizeof(cipher_public_key)))
				return false;

			return true;
		}
		bool depository_migration_preparation::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> depository_migration_preparation::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_migration_hash", var::string(algorithm::encoding::encode_0xhex256(depository_migration_hash)));
			data->set("cipher_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key, sizeof(cipher_public_key)))));
			return data;
		}
		uint32_t depository_migration_preparation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_migration_preparation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t depository_migration_preparation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_migration_preparation, 64>();
		}
		uint32_t depository_migration_preparation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_migration_preparation::as_instance_typename()
		{
			return "depository_migration_preparation";
		}

		expects_lr<void> depository_migration_commitment::validate(uint64_t block_number) const
		{
			if (!depository_migration_preparation_hash)
				return layer_exception("invalid depository migration transaction");

			if (encrypted_migrations.empty())
				return layer_exception("no migrations found");

			algorithm::pubkeyhash null = { 0 };
			for (auto& [hash, encrypted_mpc_seed] : encrypted_migrations)
			{
				if (!hash || encrypted_mpc_seed.empty())
					return layer_exception("invalid migration");
			}

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_migration_commitment::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto preparation = context->get_block_transaction<depository_migration_preparation>(depository_migration_preparation_hash);
			if (!preparation)
				return preparation.error();

			auto* preparation_transaction = (depository_migration_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_migration>(preparation_transaction->depository_migration_hash);
			if (!setup)
				return setup.error();
			else if (memcmp(setup->receipt.from, context->receipt.from, sizeof(context->receipt.from)) != 0)
				return layer_exception("invalid setup transaction");

			auto event = context->apply_witness_event(depository_migration_preparation_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto* setup_transaction = (depository_migration*)*setup->transaction;
			if (setup_transaction->migrations.size() != encrypted_migrations.size())
				return layer_exception("invalid migration size");

			auto new_proposer = setup_transaction->get_new_proposer(setup->receipt);
			if (!new_proposer.equals(preparation->receipt.from))
				return layer_exception("invalid preparation transaction");

			return expectation::met;
		}
		expects_promise_rt<void> depository_migration_commitment::dispatch(const ledger::transaction_context* context, ledger::dispatch_context* dispatcher) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto preparation = context->get_block_transaction<depository_migration_preparation>(depository_migration_preparation_hash);
			if (!preparation)
				return expects_promise_rt<void>(remote_exception(std::move(preparation.error().message())));

			if (!dispatcher->is_on(preparation->receipt.from))
				return expects_promise_rt<void>(expectation::met);

			auto* preparation_transaction = (depository_migration_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_migration>(preparation_transaction->depository_migration_hash);
			if (!setup)
				return expects_promise_rt<void>(remote_exception(std::move(setup.error().message())));

			algorithm::seckey cipher_secret_key;
			algorithm::pubkey cipher_public_key;
			algorithm::signing::derive_cipher_keypair(dispatcher->get_wallet()->secret_key, preparation_transaction->depository_migration_hash, cipher_secret_key, cipher_public_key);

			bool exchange_successful = true;
			auto* setup_transaction = (depository_migration*)*setup->transaction;
			for (auto& [hash, encrypted_mpc_seed] : encrypted_migrations)
			{
				auto it = setup_transaction->migrations.find(hash);
				if (it != setup_transaction->migrations.end())
				{
					auto& migration = it->second;
					auto decrypted_mpc_seed = algorithm::signing::private_decrypt(cipher_secret_key, cipher_public_key, encrypted_mpc_seed);
					if (decrypted_mpc_seed && decrypted_mpc_seed->size() == sizeof(uint256_t))
					{
						uint256_t mpc_seed;
						algorithm::encoding::encode_uint256((uint8_t*)decrypted_mpc_seed->data(), mpc_seed);
						if (dispatcher->apply_mpc_seed(migration.asset, migration.proposer, migration.owner, mpc_seed))
							continue;
					}
				}
				exchange_successful = false;
			}

			auto* transaction = memory::init<depository_migration_finalization>();
			transaction->asset = asset;
			transaction->depository_migration_commitment_hash = context->receipt.transaction_hash;
			transaction->successful = exchange_successful;
			transaction->set_estimate_gas(decimal::zero());
			dispatcher->emit_transaction(transaction);
			return expects_promise_rt<void>(expectation::met);
		}
		expects_lr<void> depository_migration_commitment::transfer(const uint256_t& account_hash, const uint256_t& mpc_seed, const algorithm::pubkey new_proposer_cipher_public_key, const algorithm::seckey old_proposer_secret_key)
		{
			VI_ASSERT(new_proposer_cipher_public_key != nullptr, "new proposer cipher public key should be set");
			VI_ASSERT(old_proposer_secret_key != nullptr, "old proposer secret key should be set");
			format::stream entropy;
			entropy.write_integer(depository_migration_preparation_hash);
			entropy.write_integer(algorithm::hashing::hash256i(algorithm::seckey_t(old_proposer_secret_key).view()));

			uint8_t mpc_seed_data[32];
			algorithm::encoding::decode_uint256(mpc_seed, mpc_seed_data);
			auto encrypted_mpc_seed = algorithm::signing::public_encrypt(new_proposer_cipher_public_key, std::string_view((char*)mpc_seed_data, sizeof(mpc_seed_data)), entropy.data);
			if (!encrypted_mpc_seed)
				return layer_exception("failed to encrypt an mpc seed");

			encrypted_migrations[account_hash] = std::move(*encrypted_mpc_seed);
			return expectation::met;
		}
		bool depository_migration_commitment::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_migration_preparation_hash);
			stream->write_integer((uint16_t)encrypted_migrations.size());
			for (auto& [hash, encrypted_mpc_seed] : encrypted_migrations)
			{
				stream->write_integer(hash);
				stream->write_string(encrypted_mpc_seed);
			}
			return true;
		}
		bool depository_migration_commitment::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_migration_preparation_hash))
				return false;

			uint16_t encrypted_migrations_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_migrations_size))
				return false;

			for (uint16_t i = 0; i < encrypted_migrations_size; i++)
			{
				uint256_t hash;
				if (!stream.read_integer(stream.read_type(), &hash))
					return false;

				string encrypted_mpc_seed;
				if (!stream.read_string(stream.read_type(), &encrypted_mpc_seed))
					return false;

				encrypted_migrations[hash] = std::move(encrypted_mpc_seed);
			}

			return true;
		}
		bool depository_migration_commitment::is_dispatchable() const
		{
			return true;
		}
		uptr<schema> depository_migration_commitment::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_migration_preparation_hash", var::string(algorithm::encoding::encode_0xhex256(depository_migration_preparation_hash)));
			auto* migrations_data = data->set("encrypted_migrations", var::set::array());
			for (auto& [hash, encrypted_mpc_seed] : encrypted_migrations)
			{
				auto* migration_data = migrations_data->push(var::set::object());
				migration_data->set("account_hash", var::string(algorithm::encoding::encode_0xhex256(hash)));
				migration_data->set("encrypted_mpc_seed", var::string(format::util::encode_0xhex(encrypted_mpc_seed)));
			}
			return data;
		}
		uint32_t depository_migration_commitment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_migration_commitment::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t depository_migration_commitment::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_migration_commitment, 64>();
		}
		uint32_t depository_migration_commitment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_migration_commitment::as_instance_typename()
		{
			return "depository_migration_commitment";
		}

		expects_lr<void> depository_migration_finalization::validate(uint64_t block_number) const
		{
			if (!depository_migration_commitment_hash)
				return layer_exception("invalid depository migration transaction");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> depository_migration_finalization::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(depository_migration_commitment_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			if (!successful)
				return expectation::met;

			auto certification = context->get_block_transaction<depository_migration_commitment>(depository_migration_commitment_hash);
			if (!certification)
				return certification.error();

			auto* commitment_transaction = (depository_migration_commitment*)*certification->transaction;
			auto preparation = context->get_block_transaction<depository_migration_preparation>(commitment_transaction->depository_migration_preparation_hash);
			if (!preparation)
				return preparation.error();
			else if (memcmp(preparation->receipt.from, context->receipt.from, sizeof(context->receipt.from)) != 0)
				return layer_exception("invalid preparation transaction");

			auto* preparation_transaction = (depository_migration_preparation*)*preparation->transaction;
			auto setup = context->get_block_transaction<depository_migration>(preparation_transaction->depository_migration_hash);
			if (!setup)
				return setup.error();

			auto* setup_transaction = (depository_migration*)*setup->transaction;
			if (setup_transaction->migrations.size() != commitment_transaction->encrypted_migrations.size())
				return layer_exception("invalid migration size");

			auto new_proposer = setup_transaction->get_new_proposer(setup->receipt);
			if (!new_proposer.equals(preparation->receipt.from))
				return layer_exception("invalid preparation transaction");

			auto old_proposer = algorithm::pubkeyhash_t(setup->receipt.from);
			for (auto& [hash, encrypted_mpc_seed] : commitment_transaction->encrypted_migrations)
			{
				auto it = setup_transaction->migrations.find(hash);
				if (it == setup_transaction->migrations.end())
					return layer_exception("invalid migration");

				auto& migration = it->second;
				auto account = context->get_depository_account(migration.asset, migration.proposer, migration.owner);
				if (!account)
					return account.error();

				account->mpc.erase(old_proposer);
				account->mpc.insert(new_proposer);
				account = context->apply_depository_account(migration.asset, migration.proposer, migration.owner, account->mpc_public_key, std::move(account->mpc));
				if (!account)
					return account.error();
			}

			return expectation::met;
		}
		bool depository_migration_finalization::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(depository_migration_commitment_hash);
			stream->write_boolean(successful);
			return true;
		}
		bool depository_migration_finalization::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &depository_migration_commitment_hash))
				return false;

			if (!stream.read_boolean(stream.read_type(), &successful))
				return false;

			return true;
		}
		uptr<schema> depository_migration_finalization::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("depository_migration_commitment_hash", var::string(algorithm::encoding::encode_0xhex256(depository_migration_commitment_hash)));
			data->set("successful", var::boolean(successful));
			return data;
		}
		uint32_t depository_migration_finalization::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_migration_finalization::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t depository_migration_finalization::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<depository_migration_finalization, 64>();
		}
		uint32_t depository_migration_finalization::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_migration_finalization::as_instance_typename()
		{
			return "depository_migration_finalization";
		}

		ledger::transaction* resolver::from_stream(format::stream& stream)
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
			else if (hash == deployment::as_instance_type())
				return memory::init<deployment>();
			else if (hash == invocation::as_instance_type())
				return memory::init<invocation>();
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>();
			else if (hash == certification::as_instance_type())
				return memory::init<certification>();
			else if (hash == routing_account::as_instance_type())
				return memory::init<routing_account>();
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
			else if (hash == depository_migration::as_instance_type())
				return memory::init<depository_migration>();
			else if (hash == depository_migration_preparation::as_instance_type())
				return memory::init<depository_migration_preparation>();
			else if (hash == depository_migration_commitment::as_instance_type())
				return memory::init<depository_migration_commitment>();
			else if (hash == depository_migration_finalization::as_instance_type())
				return memory::init<depository_migration_finalization>();
			return nullptr;
		}
		ledger::transaction* resolver::from_copy(const ledger::transaction* base)
		{
			uint32_t hash = base->as_type();
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>(*(const transfer*)base);
			else if (hash == deployment::as_instance_type())
				return memory::init<deployment>(*(const deployment*)base);
			else if (hash == invocation::as_instance_type())
				return memory::init<invocation>(*(const invocation*)base);
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>(*(const rollup*)base);
			else if (hash == certification::as_instance_type())
				return memory::init<certification>(*(const certification*)base);
			else if (hash == routing_account::as_instance_type())
				return memory::init<routing_account>(*(const routing_account*)base);
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
			else if (hash == depository_migration::as_instance_type())
				return memory::init<depository_migration>(*(const depository_migration*)base);
			else if (hash == depository_migration_preparation::as_instance_type())
				return memory::init<depository_migration_preparation>(*(const depository_migration_preparation*)base);
			else if (hash == depository_migration_commitment::as_instance_type())
				return memory::init<depository_migration_commitment>(*(const depository_migration_commitment*)base);
			else if (hash == depository_migration_finalization::as_instance_type())
				return memory::init<depository_migration_finalization>(*(const depository_migration_finalization*)base);
			return nullptr;
		}
		expects_promise_rt<mediator::prepared_transaction> resolver::prepare_transaction(const algorithm::asset_id& asset, const mediator::wallet_link& from_link, const vector<mediator::value_transfer>& to, option<mediator::computed_fee>&& fee)
		{
			auto* server = nss::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
				return server->prepare_transaction(asset, from_link, to, std::move(fee));

			auto chain = server->get_chainparams(asset);
			if (!chain)
				return expects_promise_rt<mediator::prepared_transaction>(remote_exception("invalid operation"));

			auto from = server->normalize_link(asset, from_link);
			if (!from)
				return expects_promise_rt<mediator::prepared_transaction>(remote_exception(std::move(from.error().message())));

			auto message = format::stream();
			if (!from->store_payload(&message))
				return expects_promise_rt<mediator::prepared_transaction>(remote_exception("serialization error"));

			auto public_key = server->to_composite_public_key(asset, from->public_key);
			if (!public_key)
				return expects_promise_rt<mediator::prepared_transaction>(remote_exception(std::move(public_key.error().message())));

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
			algorithm::encoding::decode_uint256(message.hash(), message_hash);

			mediator::prepared_transaction fake_prepared;
			fake_prepared.requires_account_input(chain->composition, std::move(*from), public_key->data, message_hash, sizeof(message_hash), std::move(transfers));
			for (auto& transfer : to)
				fake_prepared.requires_account_output(transfer.address, { { transfer.asset, transfer.value } });
			
			return expects_promise_rt<mediator::prepared_transaction>(std::move(fake_prepared));
		}
		expects_promise_rt<mediator::finalized_transaction> resolver::finalize_and_broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, mediator::prepared_transaction&& prepared, ledger::dispatch_context* dispatcher)
		{
			auto* server = nss::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
			{
				auto finalization = server->finalize_transaction(asset, std::move(prepared));
				if (!finalization)
					return expects_promise_rt<mediator::finalized_transaction>(remote_exception(std::move(finalization.error().message())));

				auto finalized = std::move(*finalization);
				return server->broadcast_transaction(asset, external_id, finalized).then<expects_rt<mediator::finalized_transaction>>([finalized](expects_rt<void>&& status) mutable -> expects_rt<mediator::finalized_transaction>
				{
					if (!status)
						return expects_rt<mediator::finalized_transaction>(status.error());

					return expects_rt<mediator::finalized_transaction>(std::move(finalized));
				});
			}

			auto transaction_id = algorithm::encoding::encode_0xhex256(algorithm::hashing::hash256i(external_id.to_string()));
			auto block_id = algorithm::hashing::hash256i(transaction_id) % std::numeric_limits<uint64_t>::max();
			auto fake_finalized = mediator::finalized_transaction(std::move(prepared), string(), std::move(transaction_id), block_id);
			fake_finalized.calldata = fake_finalized.as_message().encode();
			if (dispatcher != nullptr)
			{
				auto* transaction = memory::init<depository_transaction>();
				transaction->asset = asset;
				transaction->set_estimate_gas(decimal::zero());
				transaction->set_witness(fake_finalized.as_computed());
				dispatcher->emit_transaction(transaction);
			}
			return expects_promise_rt<mediator::finalized_transaction>(std::move(fake_finalized));
		}
	}
}