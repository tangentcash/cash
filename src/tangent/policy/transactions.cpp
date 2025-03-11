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
			if (!value.is_positive())
				return layer_exception("invalid value");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> transfer::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();
			else if (memcmp(context->receipt.from, to, sizeof(algorithm::pubkeyhash)) == 0)
				return layer_exception("invalid receiver");

			auto payment = context->apply_payment(asset, context->receipt.from, to, value);
			if (!payment)
				return payment.error();

			return expectation::met;
		}
		bool transfer::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(memo);
			stream->write_decimal(value);
			stream->write_string(std::string_view((char*)to, memcmp(to, null, sizeof(null)) == 0 ? 0 : sizeof(to)));
			return true;
		}
		bool transfer::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &memo))
				return false;

			if (!stream.read_decimal(stream.read_type(), &value))
				return false;

			string to_assembly;
			if (!stream.read_string(stream.read_type(), &to_assembly) || !algorithm::encoding::decode_uint_blob(to_assembly, to, sizeof(to)))
				return false;

			return true;
		}
		bool transfer::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			parties.insert(string((char*)to, sizeof(to)));
			return true;
		}
		void transfer::set_to(const algorithm::pubkeyhash new_to, const decimal& new_value, const std::string_view& new_memo)
		{
			value = new_value;
			memo = new_memo;
			if (!new_to)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(to, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(to, new_to, sizeof(algorithm::pubkeyhash));
		}
		bool transfer::is_to_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(to, null, sizeof(null)) == 0;
		}
		uptr<schema> transfer::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("to", algorithm::signing::serialize_address(to));
			data->set("value", var::decimal(value));
			data->set("memo", memo.empty() ? var::null() : var::string(memo));
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
			return ledger::gas_util::get_gas_estimate<transfer, 20>();
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

		expects_lr<void> omnitransfer::validate(uint64_t block_number) const
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
		expects_lr<void> omnitransfer::execute(ledger::transaction_context* context) const
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
		bool omnitransfer::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_integer((uint16_t)transfers.size());
			for (auto& transfer : transfers)
			{
				stream->write_string(transfer.memo);
				stream->write_decimal(transfer.value);
				stream->write_string(std::string_view((char*)transfer.to, memcmp(transfer.to, null, sizeof(null)) == 0 ? 0 : sizeof(transfer.to)));
			}

			return true;
		}
		bool omnitransfer::load_body(format::stream& stream)
		{
			uint16_t transfers_size;
			if (!stream.read_integer(stream.read_type(), &transfers_size))
				return false;

			transfers.clear();
			transfers.reserve(transfers_size);
			for (uint16_t i = 0; i < transfers_size; i++)
			{
				subtransfer transfer;
				if (!stream.read_string(stream.read_type(), &transfer.memo))
					return false;

				if (!stream.read_decimal(stream.read_type(), &transfer.value))
					return false;

				string to_assembly;
				if (!stream.read_string(stream.read_type(), &to_assembly) || !algorithm::encoding::decode_uint_blob(to_assembly, transfer.to, sizeof(transfer.to)))
					return false;

				transfers.push_back(std::move(transfer));
			}

			return true;
		}
		bool omnitransfer::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			for (auto& transfer : transfers)
				parties.insert(string((char*)transfer.to, sizeof(transfer.to)));
			return true;
		}
		void omnitransfer::set_to(const algorithm::pubkeyhash new_to, const decimal& new_value, const std::string_view& new_memo)
		{
			subtransfer transfer;
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
		bool omnitransfer::is_to_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			for (auto& transfer : transfers)
			{
				if (memcmp(transfer.to, null, sizeof(null)) == 0)
					return true;
			}
			return transfers.empty();
		}
		uptr<schema> omnitransfer::as_schema() const
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
		uint32_t omnitransfer::as_type() const
		{
			return as_instance_type();
		}
		std::string_view omnitransfer::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t omnitransfer::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<omnitransfer, 64>();
		}
		uint32_t omnitransfer::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view omnitransfer::as_instance_typename()
		{
			return "omnitransfer";
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
			if (!stream.read_string(stream.read_type(), &location_assembly) || location_assembly.size() != sizeof(algorithm::recsighash))
				return false;

			args.clear();
			memcpy(location, location_assembly.data(), location_assembly.size());
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool deployment::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			algorithm::pubkeyhash owner;
			if (recover_location(owner))
				parties.insert(string((char*)owner, sizeof(owner)));
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
			algorithm::recsighash null = { 0 };
			return memcmp(location, null, sizeof(null)) == 0;
		}
		void deployment::set_location(const algorithm::recsighash new_value)
		{
			VI_ASSERT(new_value != nullptr, "new value should be set");
			memcpy(location, new_value, sizeof(algorithm::recsighash));
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
			data->set("calldata", var::string(format::util::encode_0xhex(calldata)));
			data->set("args", format::variables_util::serialize(args));
			data->set("type", name.empty() ? var::null() : var::string(name));
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
		bool invocation::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			parties.insert(string((char*)to, sizeof(to)));
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

		expects_lr<void> withdrawal::validate(uint64_t block_number) const
		{
			if (to.empty())
				return layer_exception("invalid to");

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> withdrawal::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			bool charges = memcmp(context->receipt.from, proposer, sizeof(algorithm::pubkeyhash)) != 0;
			auto value = get_total_value();
			auto base_asset = algorithm::asset::base_id_of(asset);
			auto base_reward = charges ? context->get_account_reward(base_asset, proposer) : expects_lr<states::account_reward>(layer_exception());
			auto base_fee = (base_reward ? base_reward->outgoing_absolute_fee : decimal::zero());
			if (base_reward && base_asset != asset)
			{
				auto balance_requirement = context->verify_transfer_balance(base_asset, base_reward->outgoing_absolute_fee);
				if (!balance_requirement)
					return balance_requirement.error();

				auto depository = context->get_account_depository(base_asset, proposer);
				if (!depository || depository->custody < base_reward->outgoing_absolute_fee)
					return layer_exception("proposer's " + algorithm::asset::handle_of(base_asset) + " balance is insufficient to cover withdrawal fee (value: " + base_reward->outgoing_absolute_fee.to_string() + ")");
			}

			auto token_reward = base_asset == asset || !charges ? base_reward : context->get_account_reward(asset, proposer);
			auto balance_requirement = context->verify_transfer_balance(asset, std::max(value, token_reward ? token_reward->calculate_outgoing_fee(value) : decimal::zero()));
			if (!balance_requirement)
				return balance_requirement;

			auto depository = context->get_account_depository(asset, proposer);
			if (!depository || depository->custody < value)
				return layer_exception("proposer's " + algorithm::asset::handle_of(asset) + " balance is insufficient to cover withdrawal value (value: " + value.to_string() + ")");

			uint64_t address_index = protocol::now().account.root_address_index;
			for (auto& item : to)
			{
				auto collision = context->get_witness_address(base_asset, item.first, protocol::now().account.root_address_index, 0);
				if (collision && memcmp(collision->owner, context->receipt.from, sizeof(collision->owner)) != 0)
					return layer_exception("invalid to address (not owned by sender)");
				else if (!collision)
					collision = context->apply_witness_address(asset, context->receipt.from, nullptr, { { (uint8_t)0, string(item.first) } }, address_index, states::address_type::router);
				if (!collision)
					return collision.error();
			}

			if (base_asset != asset && base_fee.is_positive())
			{
				auto base_transfer = context->apply_transfer(base_asset, context->receipt.from, -base_fee, decimal::zero());
				if (!base_transfer)
					return base_transfer.error();

				base_transfer = context->apply_transfer(base_asset, proposer, base_fee, decimal::zero());
				if (!base_transfer)
					return base_transfer.error();
			}

			auto token_fee = (token_reward ? token_reward->calculate_outgoing_fee(value) : decimal::zero());
			auto token_transfer = context->apply_transfer(asset, context->receipt.from, -token_fee, value - token_fee);
			if (!token_transfer)
				return token_transfer.error();

			if (token_fee.is_positive())
			{
				token_transfer = context->apply_transfer(asset, proposer, token_fee, decimal::zero());
				if (!token_transfer)
					return token_transfer.error();
			}

			auto registration = context->apply_account_depository_transaction(asset, proposer, context->receipt.transaction_hash, 1);
			if (!registration)
				return registration.error();

			return expectation::met;
		}
		expects_promise_rt<void> withdrawal::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (memcmp(proposer.public_key_hash, this->proposer, sizeof(this->proposer)) != 0)
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			bool charges = memcmp(context->receipt.from, proposer.public_key_hash, sizeof(algorithm::pubkeyhash)) != 0;
			auto base_asset = algorithm::asset::base_id_of(asset);
			auto base_reward = charges ? context->get_account_reward(base_asset, proposer.public_key_hash) : expects_lr<states::account_reward>(layer_exception());
			auto token_reward = base_asset == asset || !charges ? base_reward : context->get_account_reward(asset, proposer.public_key_hash);
			auto partition_fee = (token_reward ? token_reward->calculate_outgoing_fee(get_total_value()) : decimal::zero());
			if (to.size() > 1)
				partition_fee /= decimal(to.size()).truncate(protocol::now().message.precision);

			auto* transaction = memory::init<outgoing_claim>();
			transaction->asset = asset;
			pipeline->push_back(transaction);

			vector<mediator::transferer> destinations;
			destinations.reserve(to.size());
			for (auto& item : to)
				destinations.push_back(mediator::transferer(item.first, optional::none, item.second - partition_fee));

			auto parent = nss::server_node::get()->new_master_wallet(asset, proposer.secret_key);
			auto child = parent ? mediator::dynamic_wallet(*parent) : mediator::dynamic_wallet();
			return resolver::emit_transaction(pipeline, std::move(child), asset, context->receipt.transaction_hash, std::move(destinations)).then<expects_rt<void>>([this, context, pipeline, transaction](expects_rt<mediator::outgoing_transaction>&& result)
			{
				if (!result || result->transaction.transaction_id.empty())
				{
					transaction->set_failure_witness(result ? "transaction broadcast failed" : result.what(), context->receipt.transaction_hash);
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					{
						pipeline->pop_back();
						memory::deinit(transaction);
						return expects_rt<void>(result.error());
					}
				}
				else
					transaction->set_success_witness(result->transaction.transaction_id, result->data, context->receipt.transaction_hash);
				return expects_rt<void>(expectation::met);
			});
		}
		bool withdrawal::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			stream->write_integer((uint16_t)to.size());
			for (auto& item : to)
			{
				stream->write_string(item.first);
				stream->write_decimal(item.second);
			}
			return true;
		}
		bool withdrawal::load_body(format::stream& stream)
		{
			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
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
		bool withdrawal::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			if (!is_proposer_null())
				parties.insert(string((char*)proposer, sizeof(proposer)));
			return true;
		}
		void withdrawal::set_to(const std::string_view& address, const decimal& value)
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
		void withdrawal::set_proposer(const algorithm::pubkeyhash new_proposer)
		{
			if (!new_proposer)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
		}
		bool withdrawal::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(proposer, null, sizeof(null)) == 0;
		}
		decimal withdrawal::get_total_value() const
		{
			decimal value = 0.0;
			for (auto& item : to)
				value += item.second;
			return value;
		}
		uptr<schema> withdrawal::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			auto* to_data = data->set("to", var::set::array());
			for (auto& item : to)
			{
				auto* coin_data = to_data->push(var::set::object());
				coin_data->set("address", var::string(item.first));
				coin_data->set("value", var::decimal(item.second));
			}
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			return data;
		}
		uint32_t withdrawal::as_type() const
		{
			return as_instance_type();
		}
		std::string_view withdrawal::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t withdrawal::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<withdrawal, 36>();
		}
		uint64_t withdrawal::get_dispatch_offset() const
		{
			return protocol::now().user.nss.withdrawal_time / protocol::now().policy.consensus_proof_time;
		}
		uint32_t withdrawal::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view withdrawal::as_instance_typename()
		{
			return "withdrawal";
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
					auto* copy = resolver::copy(*transaction);
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
					auto* copy = resolver::copy(*transaction);
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
		expects_promise_rt<void> rollup::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			auto requirement = get_dispatch_offset();
			if (!requirement)
				return expects_promise_rt<void>(expectation::met);

			return coasync<expects_rt<void>>([this, proposer, context, pipeline]() -> expects_promise_rt<void>
			{
				string error_message;
				for (auto& group : transactions)
				{
					for (auto& transaction : group.second)
					{
						auto status = coawait(transaction->dispatch(proposer, context, pipeline));
						if (status)
							continue;
						else if (status.error().is_retry() || status.error().is_shutdown())
							coreturn status;

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

					uptr<ledger::transaction> next = resolver::init(type);
					if (!next || !stream.read_integer(stream.read_type(), &next->sequence))
						return false;

					if (!stream.read_integer(stream.read_type(), &next->gas_limit))
						return false;

					if (!stream.read_string(stream.read_type(), &signature_assembly) || signature_assembly.size() != sizeof(algorithm::recsighash))
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
		bool rollup::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					algorithm::pubkeyhash from = { 0 };
					if (transaction->recover_hash(from))
					{
						parties.insert(string((char*)from, sizeof(from)));
						transaction->recover_many(receipt, parties);
					}
				}
			}
			return true;
		}
		bool rollup::recover_aliases(const ledger::receipt& receipt, ordered_set<uint256_t>& aliases) const
		{
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					algorithm::pubkeyhash from = { 0 };
					aliases.insert(transaction->as_hash());
					transaction->recover_aliases(receipt, aliases);
				}
			}
			return true;
		}
		bool rollup::merge(const ledger::transaction& transaction)
		{
			auto* next = resolver::copy(&transaction);
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
			transaction.transaction = resolver::copy(target);
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
		uint64_t rollup::get_dispatch_offset() const
		{
			uint64_t max = 0;
			for (auto& group : transactions)
			{
				for (auto& transaction : group.second)
				{
					uint64_t value = transaction->get_dispatch_offset();
					if (value > max)
						max = value;
				}
			}
			return max;
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

		expects_lr<void> commitment::validate(uint64_t block_number) const
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
		expects_lr<void> commitment::execute(ledger::transaction_context* context) const
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
		bool commitment::store_body(format::stream* stream) const
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
		bool commitment::load_body(format::stream& stream)
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
		void commitment::set_online()
		{
			online = true;
		}
		void commitment::set_online(const algorithm::asset_id& asset)
		{
			observers[asset] = true;
		}
		void commitment::set_offline()
		{
			online = false;
		}
		void commitment::set_offline(const algorithm::asset_id& asset)
		{
			observers[asset] = false;
		}
		void commitment::set_standby()
		{
			online = optional::none;
		}
		void commitment::set_standby(const algorithm::asset_id& asset)
		{
			observers.erase(asset);
		}
		uptr<schema> commitment::as_schema() const
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
		uint32_t commitment::as_type() const
		{
			return as_instance_type();
		}
		std::string_view commitment::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t commitment::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<commitment, 64>();
		}
		uint32_t commitment::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view commitment::as_instance_typename()
		{
			return "commitment";
		}

		expects_lr<void> incoming_claim::validate(uint64_t block_number) const
		{
			auto assertion = get_assertion(nullptr);
			if (!assertion || !assertion->is_valid())
				return layer_exception("invalid assertion");

			if (assertion->asset != asset)
				return layer_exception("invalid assertion asset");

			if (!assertion->is_latency_approved())
				return layer_exception("invalid assertion status");

			return ledger::aggregation_transaction::validate(block_number);
		}
		expects_lr<void> incoming_claim::execute(ledger::transaction_context* context) const
		{
			auto validation = aggregation_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto assertion = get_assertion(context);
			if (!assertion)
				return layer_exception("invalid assertion");

			if (assertion->asset != asset)
				return layer_exception("invalid assertion asset");

			if (!assertion->is_latency_approved())
				return layer_exception("invalid assertion status");

			auto collision = context->get_witness_transaction(asset, assertion->transaction_id);
			if (collision)
				return layer_exception("assertion " + assertion->transaction_id + " finalized");

			auto base_derivation_index = protocol::now().account.root_address_index;
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid chain");

			transition operations;
			bool migration = true;
			algorithm::pubkeyhash null = { 0 };
			algorithm::pubkeyhash router = { 0 };
			unordered_map<string, decimal> inputs, outputs;
			decimal change = decimal::zero(), input = decimal::zero(), output = decimal::zero();
			std::for_each(assertion->from.begin(), assertion->from.end(), [&](auto& item) { auto& value = inputs[item.address]; value = value.is_nan() ? item.value : value + item.value; input += item.value; });
			std::for_each(assertion->to.begin(), assertion->to.end(), [&](auto& item) { auto& value = outputs[item.address]; value = value.is_nan() ? item.value : value + item.value; output += item.value; });
			std::for_each(inputs.begin(), inputs.end(), [&](auto& item) { auto value = outputs.find(item.first); if (value != outputs.end()) { auto delta = item.second; item.second -= value->second; value->second -= delta; } });
			assertion->from.erase(std::remove_if(assertion->from.begin(), assertion->from.end(), [&](auto& item) { return !inputs[item.address].is_positive(); }), assertion->from.end());
			assertion->to.erase(std::remove_if(assertion->to.begin(), assertion->to.end(), [&](auto& item) { return !outputs[item.address].is_positive(); }), assertion->to.end());

			if (input.is_nan() || input.is_negative())
				return layer_exception("invalid input value");

			if (input < output || output.is_nan() || output.is_negative())
				return layer_exception("invalid output value");

			switch (chain->routing)
			{
				case tangent::mediator::routing_policy::account:
				case tangent::mediator::routing_policy::memo:
					if (assertion->from.size() > 1)
						return layer_exception("too many inputs");

					if (assertion->to.size() > 1)
						return layer_exception("too many outputs");
					break;
				default:
					break;
			}

			for (auto& item : assertion->from)
			{
				uint64_t address_index = item.address_index && chain->routing == mediator::routing_policy::memo ? *item.address_index : base_derivation_index;
				auto source = context->get_witness_address(algorithm::asset::base_id_of(asset), item.address, address_index, 0);
				if (source)
				{
					if (source->is_custodian_address() || source->is_contribution_address())
					{
						auto& contribution = operations.contributions[string((char*)source->proposer, sizeof(source->proposer))];
						contribution.custody -= item.value;
					}
					else if (source->is_router_address())
					{
						memcpy(router, source->owner, sizeof(source->owner));
						migration = false;
					}
				}
				else
				{
					change -= item.value;
					migration = false;
				}
			}

			for (auto& item : assertion->to)
			{
				uint64_t address_index = item.address_index && chain->routing == mediator::routing_policy::memo ? *item.address_index : base_derivation_index;
				auto source = context->get_witness_address(algorithm::asset::base_id_of(asset), item.address, address_index, 0);
				if (source)
				{
					auto* owner = (chain->routing == mediator::routing_policy::account && memcmp(router, null, sizeof(null)) != 0 ? router : source->owner);
					if (!source->is_router_address())
					{
						auto& contribution = operations.contributions[string((char*)source->proposer, sizeof(source->proposer))];
						if (source->is_custodian_address())
						{
							contribution.custody += item.value;
							if (!migration)
							{
								auto& balance = operations.transfers[string((char*)owner, sizeof(source->owner))];
								balance.supply += item.value;

								auto reward = context->get_account_reward(asset, source->proposer);
								if (reward && reward->has_incoming_fee())
								{
									auto fee = reward->calculate_incoming_fee(item.value);
									balance.supply -= fee;

									auto& redeemer = operations.transfers[string((char*)source->proposer, sizeof(source->proposer))];
									redeemer.supply += fee;
								}
							}
						}
						else if (source->is_contribution_address())
						{
							auto& coverage = contribution.contributions[item.address];
							coverage = coverage.is_nan() ? item.value : coverage + item.value;
						}
					}
					else
					{
						auto& balance = operations.transfers[string((char*)owner, sizeof(source->owner))];
						balance.supply -= item.value;
						balance.reserve -= item.value;
					}
				}
				else
					change += item.value;
			}

			for (auto& item : operations.contributions)
			{
				if (change.is_negative() && item.second.custody.is_negative())
				{
					item.second.custody = decimal::nan();
					continue;
				}

				auto depository = context->get_account_depository(asset, (uint8_t*)item.first.data()).or_else(states::account_depository((uint8_t*)item.first.data(), context->block));
				depository.custody += item.second.custody;
				for (auto& coverage : item.second.contributions)
				{
					auto& merging = depository.contributions[coverage.first];
					merging = merging.is_nan() ? coverage.second : merging + coverage.second;
				}

				auto work = context->get_account_work((uint8_t*)item.first.data());
				decimal coverage = depository.get_coverage(work ? work->flags : 0);
				if (!coverage.is_negative())
					continue;

				coverage = -coverage;
				auto it = operations.transfers.begin();
				while (it != operations.transfers.end() && coverage.is_positive())
				{
					auto& reserve = std::min(it->second.supply, coverage);
					if (reserve.is_positive())
					{
						auto& reservation = item.second.reservations[it->first];
						reservation = reservation.is_nan() ? reserve : reservation + reserve;
						it->second.reserve += reserve;
						coverage -= reserve;
					}
					++it;
				}
			}

			if (operations.transfers.empty() && operations.contributions.empty())
				return layer_exception("invalid claim");

			for (auto& operation : operations.transfers)
			{
				if (operation.second.supply.is_zero_or_nan() && operation.second.reserve.is_zero_or_nan())
					continue;

				auto supply_delta = operation.second.supply.is_nan() ? decimal::zero() : operation.second.supply;
				auto reserve_delta = operation.second.reserve.is_nan() ? decimal::zero() : operation.second.reserve;
				if (supply_delta.is_negative() || reserve_delta.is_negative())
				{
					auto balance = context->get_account_balance(asset, (uint8_t*)operation.first.data());
					auto supply = (balance ? balance->supply : decimal::zero()) + supply_delta;
					auto reserve = (balance ? balance->reserve : decimal::zero()) + reserve_delta;
					if (supply < 0.0 || reserve < 0.0)
					{
						for (auto& item : operations.contributions)
							item.second.custody = decimal::nan();
						continue;
					}
				}

				auto transfer = context->apply_transfer(asset, (uint8_t*)operation.first.data(), supply_delta, reserve_delta);
				if (!transfer)
					return transfer.error();
			}

			for (auto& operation : operations.contributions)
			{
				auto depository = context->apply_account_depository_change(asset, (uint8_t*)operation.first.data(), operation.second.custody, std::move(operation.second.contributions), std::move(operation.second.reservations));
				if (!depository)
					return depository.error();
			}

			auto witness = context->apply_witness_transaction(asset, assertion->transaction_id);
			if (!witness)
				return witness.error();

			return context->emit_witness(asset, assertion->block_id);
		}
		bool incoming_claim::store_body(format::stream* stream) const
		{
			return true;
		}
		bool incoming_claim::load_body(format::stream& stream)
		{
			return true;
		}
		bool incoming_claim::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			const format::variables* event = nullptr;
			size_t offset = 0;
			do
			{
				event = receipt.find_event<states::account_balance>(offset++);
				if (event != nullptr && event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(event->at(1).as_blob());
			} while (event != nullptr);

			offset = 0;
			do
			{
				event = receipt.find_event<states::account_depository>(offset++);
				if (event != nullptr && event->size() >= 2 && event->at(1).as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(event->at(1).as_blob());
			} while (event != nullptr);
			return true;
		}
		void incoming_claim::set_witness(uint64_t block_height, const std::string_view& transaction_id, decimal&& fee, vector<mediator::transferer>&& senders, vector<mediator::transferer>&& receivers)
		{
			mediator::incoming_transaction target;
			target.set_transaction(asset, block_height, transaction_id, std::move(fee));
			target.set_operations(std::move(senders), std::move(receivers));
			set_witness(target);
		}
		void incoming_claim::set_witness(const mediator::incoming_transaction& witness)
		{
			asset = witness.asset;
			set_statement(algorithm::hashing::hash256i(witness.transaction_id), witness.as_message());
		}
		option<mediator::incoming_transaction> incoming_claim::get_assertion(const ledger::transaction_context* context) const
		{
			auto* best_branch = get_cumulative_branch(context);
			if (!best_branch)
				return optional::none;

			auto message = best_branch->message;
			message.seek = 0;

			mediator::incoming_transaction assertion;
			if (!assertion.load(message))
				return optional::none;

			return assertion;
		}
		uptr<schema> incoming_claim::as_schema() const
		{
			auto assertion = get_assertion(nullptr);
			schema* data = ledger::aggregation_transaction::as_schema().reset();
			data->set("assertion", assertion ? assertion->as_schema().reset() : var::set::null());
			return data;
		}
		uint32_t incoming_claim::as_type() const
		{
			return as_instance_type();
		}
		std::string_view incoming_claim::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t incoming_claim::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<incoming_claim, 144>();
		}
		uint32_t incoming_claim::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view incoming_claim::as_instance_typename()
		{
			return "incoming_claim";
		}

		expects_lr<void> outgoing_claim::validate(uint64_t block_number) const
		{
			if (!transaction_hash)
				return layer_exception("transaction hash not valid");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> outgoing_claim::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(transaction_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto parent = context->get_block_transaction_instance(transaction_hash);
			if (!parent)
				return layer_exception("parent transaction not found");

			uint32_t type = parent->transaction->as_type();
			if (type == withdrawal::as_instance_type())
			{
				auto* parent_transaction = (withdrawal*)*parent->transaction;
				if (memcmp(parent_transaction->proposer, context->receipt.from, sizeof(algorithm::pubkeyhash)) != 0)
					return layer_exception("parent transaction not valid");

				auto finalization = context->apply_account_depository_transaction(asset, parent_transaction->proposer, transaction_hash, -1);
				if (!finalization)
					return finalization.error();

				if (!transaction_id.empty())
					return expectation::met;

				bool honest = true;
				bool charges = memcmp(parent->receipt.from, parent_transaction->proposer, sizeof(algorithm::pubkeyhash)) != 0;
				auto base_asset = algorithm::asset::base_id_of(asset);
				auto base_reward = charges ? context->get_account_reward(base_asset, parent_transaction->proposer) : expects_lr<states::account_reward>(layer_exception());
				auto base_fee = (base_reward ? base_reward->outgoing_absolute_fee : decimal::zero());
				if (base_asset != asset && base_fee.is_positive())
				{
					auto base_transfer = context->apply_transfer(base_asset, parent->receipt.from, base_fee, decimal::zero());
					if (!base_transfer)
						return base_transfer.error();
					else if (!context->apply_transfer(base_asset, parent_transaction->proposer, -base_fee, decimal::zero()))
						honest = false;
				}

				auto value = parent_transaction->get_total_value();
				auto token_reward = base_asset == asset || !charges ? base_reward : context->get_account_reward(asset, parent_transaction->proposer);
				auto token_fee = (token_reward ? token_reward->calculate_outgoing_fee(value) : decimal::zero());
				auto token_transfer = context->apply_transfer(asset, parent->receipt.from, token_fee, token_fee - value);
				if (!token_transfer)
					return token_transfer.error();
				else if (token_fee.is_positive() && !context->apply_transfer(asset, parent_transaction->proposer, -token_fee, decimal::zero()))
					honest = false;

				if (!honest)
				{
					auto depository = context->apply_account_depository_custody(asset, parent_transaction->proposer, decimal::nan());
					if (!depository)
						return depository.error();
				}

				return expectation::met;
			}
			else if (type == contribution_deactivation::as_instance_type())
			{
				auto* parent_transaction = (contribution_deactivation*)*parent->transaction;
				auto deactivation = context->get_block_transaction<contribution_deselection>(parent_transaction->contribution_deselection_hash);
				if (!deactivation)
					return deactivation.error();

				auto deallocation = context->get_block_transaction<contribution_deallocation>(((contribution_deselection*)*deactivation->transaction)->contribution_deallocation_hash);
				if (!deallocation)
					return deallocation.error();

				if (memcmp(deallocation->receipt.from, context->receipt.from, sizeof(algorithm::pubkeyhash)) != 0)
					return layer_exception("parent transaction not valid");

				return expectation::met;
			}
			else if (type == depository_migration::as_instance_type())
			{
				auto* parent_transaction = (depository_migration*)*parent->transaction;
				if (memcmp(parent_transaction->proposer, context->receipt.from, sizeof(algorithm::pubkeyhash)) == 0)
					return layer_exception("depository migration transaction not valid");

				return expectation::met;
			}

			return layer_exception("parent transaction not valid");
		}
		bool outgoing_claim::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(transaction_id);
			stream->write_string(transaction_data);
			stream->write_string(transaction_message);
			stream->write_integer(transaction_hash);
			return true;
		}
		bool outgoing_claim::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_data))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_message))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_hash))
				return false;

			return true;
		}
		bool outgoing_claim::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto context = ledger::transaction_context();
			auto parent = context.get_block_transaction_instance(transaction_hash);
			if (!parent)
				return false;

			parties.insert(string((char*)parent->receipt.from, sizeof(parent->receipt.from)));
			return true;
		}
		void outgoing_claim::set_success_witness(const std::string_view& new_transaction_id, const std::string_view& new_transaction_data, const uint256_t& new_transaction_hash)
		{
			transaction_id = new_transaction_id;
			transaction_data = new_transaction_data;
			transaction_message.clear();
			transaction_hash = new_transaction_hash;
		}
		void outgoing_claim::set_failure_witness(const std::string_view& new_transaction_message, const uint256_t& new_transaction_hash)
		{
			transaction_id.clear();
			transaction_data.clear();
			transaction_message = new_transaction_message;
			transaction_hash = new_transaction_hash;
		}
		uptr<schema> outgoing_claim::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(transaction_hash)));
			data->set("transaction_id", transaction_id.empty() ? var::null() : var::string(transaction_id));
			data->set("transaction_data", transaction_data.empty() ? var::null() : var::string(transaction_data));
			data->set("transaction_message", transaction_message.empty() ? var::null() : var::string(transaction_message));
			return data;
		}
		uint32_t outgoing_claim::as_type() const
		{
			return as_instance_type();
		}
		std::string_view outgoing_claim::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t outgoing_claim::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<outgoing_claim, 32>();
		}
		uint32_t outgoing_claim::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view outgoing_claim::as_instance_typename()
		{
			return "outgoing_claim";
		}

		expects_lr<void> address_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (address.empty())
				return layer_exception("invalid address");

			return expectation::met;
		}
		expects_lr<void> address_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto public_key_hash = chain->new_public_key_hash(address);
			if (!public_key_hash)
				return public_key_hash.error();

			uint64_t address_index = protocol::now().account.root_address_index;
			auto collision = context->get_witness_address(asset, address, address_index, 0);
			if (collision)
				return layer_exception("account address " + address + " taken");

			auto status = context->apply_witness_address(asset, context->receipt.from, nullptr, { { (uint8_t)0, string(address) } }, address_index, states::address_type::router);
			if (!status)
				return status.error();

			return expectation::met;
		}
		bool address_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(address);
			return true;
		}
		bool address_account::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &address))
				return false;

			return true;
		}
		void address_account::set_address(const std::string_view& new_address)
		{
			address = new_address;
		}
		uptr<schema> address_account::as_schema() const
		{
			schema* data = ledger::delegation_transaction::as_schema().reset();
			data->set("address", var::string(address));
			return data;
		}
		uint32_t address_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view address_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t address_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<address_account, 128>();
		}
		uint32_t address_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view address_account::as_instance_typename()
		{
			return "address_account";
		}

		expects_lr<void> pubkey_account::sign_pubkey(const secret_box& signing_key)
		{
			uptr<pubkey_account> copy = (pubkey_account*)resolver::copy(this);
			copy->gas_price = decimal::nan();
			copy->gas_limit = 0;
			copy->sighash.clear();
			copy->sequence = 0;

			format::stream message;
			if (!copy->store_payload(&message))
				return layer_exception("serialization error");

			auto signature = nss::server_node::get()->sign_message(asset, message.data, signing_key);
			if (!signature)
				return signature.error();

			sighash = std::move(*signature);
			return expectation::met;
		}
		expects_lr<void> pubkey_account::verify_pubkey() const
		{
			uptr<pubkey_account> copy = (pubkey_account*)resolver::copy(this);
			copy->gas_price = decimal::nan();
			copy->gas_limit = 0;
			copy->sighash.clear();
			copy->sequence = 0;

			format::stream message;
			if (!copy->store_payload(&message))
				return layer_exception("serialization error");

			return nss::server_node::get()->verify_message(asset, message.data, pubkey, sighash);
		}
		expects_lr<void> pubkey_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (pubkey.empty())
				return layer_exception("invalid public key");

			if (sighash.empty())
				return layer_exception("invalid public key signature");

			return ledger::delegation_transaction::validate(block_number);
		}
		expects_lr<void> pubkey_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto verification = verify_pubkey();
			if (!verification)
				return verification.error();

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto verifying_wallet = chain->new_verifying_wallet(asset, pubkey);
			if (!verifying_wallet)
				return verifying_wallet.error();

			uint64_t address_index = protocol::now().account.root_address_index;
			auto status = context->apply_witness_address(asset, context->receipt.from, nullptr, verifying_wallet->addresses, address_index, states::address_type::router);
			if (!status)
				return status.error();

			return expectation::met;
		}
		bool pubkey_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(pubkey);
			stream->write_string(sighash);
			return true;
		}
		bool pubkey_account::load_body(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &pubkey))
				return false;

			if (!stream.read_string(stream.read_type(), &sighash))
				return false;

			return true;
		}
		void pubkey_account::set_pubkey(const std::string_view& verifying_key)
		{
			pubkey = verifying_key;
		}
		uptr<schema> pubkey_account::as_schema() const
		{
			schema* data = ledger::delegation_transaction::as_schema().reset();
			data->set("pubkey", var::set::string(pubkey));
			data->set("sighash", var::string(sighash));
			return data;
		}
		uint32_t pubkey_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view pubkey_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t pubkey_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<pubkey_account, 128>();
		}
		uint32_t pubkey_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view pubkey_account::as_instance_typename()
		{
			return "pubkey_account";
		}

		expects_lr<void> delegation_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			algorithm::pubkeyhash null = { 0 };
			if (memcmp(proposer, null, sizeof(null)) == 0)
				return layer_exception("invalid account proposer");

			return ledger::delegation_transaction::validate(block_number);
		}
		expects_lr<void> delegation_account::execute(ledger::transaction_context* context) const
		{
			auto validation = delegation_transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto work_requirement = context->verify_account_work(proposer);
			if (!work_requirement)
				return work_requirement.error();

			auto work = context->get_account_work(proposer);
			auto depository = context->get_account_depository(asset, proposer);
			auto coverage = depository ? depository->get_coverage(work ? work->flags : 0) : decimal::zero();
			if (coverage.is_negative())
				return layer_exception("depository contribution is too low for custodian account creation");

			switch (chain->routing)
			{
				case mediator::routing_policy::account:
				{
					if (memcmp(context->receipt.from, proposer, sizeof(proposer)) != 0)
						return layer_exception("invalid account proposer");

					return expectation::met;
				}
				case mediator::routing_policy::memo:
				case mediator::routing_policy::UTXO:
					return expectation::met;
				default:
					return layer_exception("invalid operation");
			}
		}
		expects_promise_rt<void> delegation_account::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (memcmp(this->proposer, proposer.public_key_hash, sizeof(algorithm::pubkeyhash)) != 0)
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			uptr<custodian_account> transaction = memory::init<custodian_account>();
			transaction->asset = asset;
			transaction->set_witness(context->receipt.transaction_hash);

			auto account = transaction->set_wallet(context, proposer, context->receipt.from);
			if (!account)
				return expects_promise_rt<void>(remote_exception(std::move(account.error().message())));

			pipeline->push_back(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool delegation_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			return true;
		}
		bool delegation_account::load_body(format::stream& stream)
		{
			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			return true;
		}
		bool delegation_account::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			parties.insert(string((char*)proposer, sizeof(proposer)));
			return true;
		}
		void delegation_account::set_proposer(const algorithm::pubkeyhash new_proposer)
		{
			if (!new_proposer)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
		}
		bool delegation_account::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(proposer, null, sizeof(null)) == 0;
		}
		uptr<schema> delegation_account::as_schema() const
		{
			schema* data = ledger::delegation_transaction::as_schema().reset();
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			return data;
		}
		uint32_t delegation_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view delegation_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t delegation_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<delegation_account, 16>();
		}
		uint64_t delegation_account::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t delegation_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view delegation_account::as_instance_typename()
		{
			return "delegation_account";
		}

		expects_lr<void> custodian_account::set_wallet(const ledger::transaction_context* context, const ledger::wallet& proposer, const algorithm::pubkeyhash new_owner)
		{
			auto* server = nss::server_node::get();
			auto* chain = server->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto derivation = context->get_account_derivation(asset, proposer.public_key_hash);
			uint64_t address_index = (derivation ? derivation->max_address_index + 1 : protocol::now().account.root_address_index);
			if (chain->routing == mediator::routing_policy::account)
			{
				address_index = protocol::now().account.root_address_index;
				if (derivation)
					return layer_exception("account exists");
				else if (memcmp(new_owner, proposer.public_key_hash, sizeof(algorithm::pubkeyhash)) != 0)
					return layer_exception("invalid account owner");
			}

			auto parent = server->new_master_wallet(asset, proposer.secret_key);
			if (!parent)
				return layer_exception("invalid master wallet");

			auto child = server->new_signing_wallet(asset, *parent, address_index);
			if (!child)
				return child.error();

			set_pubkey(child->verifying_key, address_index);
			set_owner(new_owner);
			return sign_pubkey(child->signing_key);
		}
		expects_lr<void> custodian_account::sign_pubkey(const secret_box& signing_key)
		{
			uptr<custodian_account> copy = (custodian_account*)resolver::copy(this);
			copy->gas_price = decimal::nan();
			copy->gas_limit = 0;
			copy->sighash.clear();
			copy->sequence = 0;

			format::stream message;
			if (!copy->store_payload(&message))
				return layer_exception("serialization error");

			auto signature = nss::server_node::get()->sign_message(asset, message.data, signing_key);
			if (!signature)
				return signature.error();

			sighash = std::move(*signature);
			return expectation::met;
		}
		expects_lr<void> custodian_account::verify_pubkey() const
		{
			uptr<custodian_account> copy = (custodian_account*)resolver::copy(this);
			copy->gas_price = decimal::nan();
			copy->gas_limit = 0;
			copy->sighash.clear();
			copy->sequence = 0;

			format::stream message;
			if (!copy->store_payload(&message))
				return layer_exception("serialization error");

			return nss::server_node::get()->verify_message(asset, message.data, pubkey, sighash);
		}
		expects_lr<void> custodian_account::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (pubkey.empty())
				return layer_exception("invalid public key");

			if (sighash.empty())
				return layer_exception("invalid public key signature");

			algorithm::pubkeyhash null = { 0 };
			if (!memcmp(owner, null, sizeof(null)))
				return layer_exception("invalid owner");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> custodian_account::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto verification = verify_pubkey();
			if (!verification)
				return verification.error();

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto verifying_wallet = chain->new_verifying_wallet(asset, pubkey);
			if (!verifying_wallet)
				return verifying_wallet.error();

			auto* params = nss::server_node::get()->get_chainparams(asset);
			if (!params)
				return layer_exception("invalid operation");

			if (delegation_account_hash > 0)
			{
				auto event = context->apply_witness_event(delegation_account_hash, context->receipt.transaction_hash);
				if (!event)
					return event.error();

				auto delegation = context->get_block_transaction<delegation_account>(delegation_account_hash);
				if (!delegation)
					return delegation.error();

				auto* delegation_transaction = (delegation_account*)*delegation->transaction;
				if (memcmp(delegation_transaction->proposer, context->receipt.from, sizeof(context->receipt.from)) != 0)
					return layer_exception("invalid origin");

				if (params->routing == mediator::routing_policy::account && memcmp(delegation->receipt.from, context->receipt.from, sizeof(context->receipt.from)) != 0)
					return layer_exception("invalid account owner");
			}

			auto work_requirement = context->verify_account_work(context->receipt.from);
			if (!work_requirement)
				return work_requirement.error();

			auto work = context->get_account_work(context->receipt.from);
			auto depository = context->get_account_depository(asset, context->receipt.from);
			auto coverage = depository ? depository->get_coverage(work ? work->flags : 0) : decimal::zero();
			if (coverage.is_negative())
				return layer_exception("depository contribution is too low for custodian account creation");

			uint64_t address_index = params->routing == mediator::routing_policy::memo ? pubkey_index : protocol::now().account.root_address_index;
			for (auto& address : verifying_wallet->addresses)
			{
				auto collision = context->get_witness_address(asset, address.second, address_index, 0);
				if (collision)
					return layer_exception("account address " + address.second + " taken");
			}

			auto derivation = context->get_account_derivation(asset, context->receipt.from);
			if (!derivation || derivation->max_address_index < address_index)
			{
				auto status = context->apply_account_derivation(asset, context->receipt.from, address_index);
				if (!status)
					return status.error();
			}

			auto status = context->apply_witness_address(asset, owner, context->receipt.from, verifying_wallet->addresses, address_index, states::address_type::custodian);
			if (!status)
				return status.error();

			return expectation::met;
		}
		expects_promise_rt<void> custodian_account::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto verifying_wallet = chain->new_verifying_wallet(asset, pubkey);
			if (!verifying_wallet)
				return expects_promise_rt<void>(remote_exception(std::move(verifying_wallet.error().message())));

			auto* params = nss::server_node::get()->get_chainparams(asset);
			if (!params)
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			uint64_t address_index = params->routing == mediator::routing_policy::memo ? pubkey_index : protocol::now().account.root_address_index;
			for (auto& address : verifying_wallet->addresses)
			{
				auto status = nss::server_node::get()->enable_wallet_address(asset, std::string_view((char*)context->receipt.from, sizeof(algorithm::pubkeyhash)), address.second, address_index);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
		bool custodian_account::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(delegation_account_hash);
			stream->write_integer(pubkey_index);
			stream->write_string(pubkey);
			stream->write_string(sighash);
			return true;
		}
		bool custodian_account::load_body(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &delegation_account_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &pubkey_index))
				return false;

			if (!stream.read_string(stream.read_type(), &pubkey))
				return false;

			if (!stream.read_string(stream.read_type(), &sighash))
				return false;

			return true;
		}
		bool custodian_account::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			parties.insert(string((char*)owner, sizeof(owner)));
			return true;
		}
		void custodian_account::set_witness(const uint256_t& new_delegation_account_hash)
		{
			delegation_account_hash = new_delegation_account_hash;
		}
		void custodian_account::set_pubkey(const std::string_view& verifying_key, uint64_t new_pubkey_index)
		{
			pubkey = verifying_key;
			pubkey_index = new_pubkey_index;
		}
		void custodian_account::set_owner(const algorithm::pubkeyhash new_owner)
		{
			if (!new_owner)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(owner, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(owner, new_owner, sizeof(algorithm::pubkeyhash));
		}
		bool custodian_account::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(owner, null, sizeof(null)) == 0;
		}
		uptr<schema> custodian_account::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("delegation_account_hash", delegation_account_hash > 0 ? var::string(algorithm::encoding::encode_0xhex256(delegation_account_hash)) : var::null());
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("pubkey_index", var::integer(pubkey_index));
			data->set("pubkey", var::string(pubkey));
			data->set("sighash", var::string(sighash));
			return data;
		}
		uint32_t custodian_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view custodian_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t custodian_account::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<custodian_account, 128>();
		}
		uint64_t custodian_account::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t custodian_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view custodian_account::as_instance_typename()
		{
			return "custodian_account";
		}

		expects_lr<void> contribution_allocation::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> contribution_allocation::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto work = context->verify_account_work(context->receipt.from);
			if (!work)
				return work;

			ordered_set<string> hashset = { string((char*)context->receipt.from, sizeof(algorithm::pubkeyhash)) };
			auto committee = context->calculate_sharing_committee(hashset, 2);
			if (!committee)
				return committee.error();

			for (auto& work : *committee)
			{
				auto event = context->emit_event<contribution_allocation>({ format::variable(std::string_view((char*)work.owner, sizeof(work.owner))) });
				if (!event)
					return event;
			}

			return expectation::met;
		}
		expects_promise_rt<void> contribution_allocation::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			ordered_set<string> parties;
			if (!recover_many(context->receipt, parties) || parties.size() != 2)
				return expects_promise_rt<void>(remote_exception("transaction receipt does not have a proposer"));

			algorithm::pubkeyhash chosen = { 0 };
			memcpy(chosen, parties.begin()->data(), sizeof(chosen));
			if (memcmp(chosen, proposer.public_key_hash, sizeof(chosen)) != 0)
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			uptr<contribution_selection> transaction = memory::init<contribution_selection>();
			transaction->asset = asset;

			auto status = transaction->set_share1(context->receipt.transaction_hash, proposer.secret_key);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			pipeline->push_back(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_allocation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			return true;
		}
		bool contribution_allocation::load_body(format::stream& stream)
		{
			return true;
		}
		bool contribution_allocation::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto* event1 = receipt.find_event<contribution_allocation>();
			if (!event1 || event1->size() != 1 || event1->front().as_string().size() != sizeof(algorithm::pubkeyhash))
				return false;

			auto* event2 = receipt.find_event<contribution_allocation>(1);
			if (!event2 || event2->size() != 1 || event2->front().as_string().size() != sizeof(algorithm::pubkeyhash))
				return false;

			parties.insert(event1->front().as_blob());
			parties.insert(event2->back().as_blob());
			return true;
		}
		uint32_t contribution_allocation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_allocation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_allocation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_allocation, 24>();
		}
		uint64_t contribution_allocation::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_allocation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_allocation::as_instance_typename()
		{
			return "contribution_allocation";
		}

		expects_lr<void> contribution_selection::set_share1(const uint256_t& new_contribution_allocation_hash, const algorithm::seckey secret_key)
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			algorithm::pubkey secret_key_hash;
			algorithm::signing::derive_public_key_hash(secret_key, secret_key_hash);

			format::stream entropy;
			entropy.write_typeless(contribution_allocation_hash = new_contribution_allocation_hash);
			entropy.write_typeless((char*)secret_key_hash, (uint32_t)sizeof(secret_key_hash));

			algorithm::composition::cseed seed1;
			algorithm::composition::cseckey secret_key1;
			algorithm::composition::convert_to_secret_seed(secret_key, entropy.data, seed1);
			return algorithm::composition::derive_keypair(chain->composition, seed1, secret_key1, public_key1);
		}
		expects_lr<void> contribution_selection::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			algorithm::composition::cpubkey null = { 0 };
			if (!memcmp(public_key1, null, sizeof(null)))
				return layer_exception("invalid public key 1");

			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			if (!contribution_allocation_hash)
				return layer_exception("invalid parent transaction");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> contribution_selection::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(contribution_allocation_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto allocation = context->get_block_transaction<contribution_allocation>(contribution_allocation_hash);
			if (!allocation)
				return allocation.error();
			else if (asset != allocation->transaction->asset)
				return layer_exception("invalid asset");

			ordered_set<string> parties;
			if (!allocation->transaction->recover_many(allocation->receipt, parties) || parties.size() != 2)
				return layer_exception("transaction receipt does not have a proposer");

			auto it = parties.begin();
			if (it->size() != sizeof(algorithm::pubkeyhash) || memcmp(it->data(), context->receipt.from, sizeof(context->receipt.from)) != 0)
				return layer_exception("invalid origin");

			auto work = context->verify_account_work(context->receipt.from);
			if (!work)
				return work;

			return context->emit_event<contribution_selection>({ format::variable(std::string_view((char*)allocation->receipt.from, sizeof(allocation->receipt.from))) });
		}
		expects_promise_rt<void> contribution_selection::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto allocation = context->get_block_transaction<contribution_allocation>(contribution_allocation_hash);
			if (!allocation)
				return expects_promise_rt<void>(remote_exception(std::move(allocation.error().message())));

			ordered_set<string> parties;
			if (!allocation->transaction->recover_many(allocation->receipt, parties) || parties.size() != 2)
				return expects_promise_rt<void>(remote_exception("transaction receipt does not have a proposer"));

			algorithm::pubkeyhash chosen = { 0 };
			memcpy(chosen, (++parties.begin())->data(), sizeof(chosen));
			if (memcmp(chosen, proposer.public_key_hash, sizeof(chosen)) != 0)
				return expects_promise_rt<void>(expectation::met);

			uptr<contribution_activation> transaction = memory::init<contribution_activation>();
			transaction->asset = asset;

			auto status = transaction->set_share2(context->receipt.transaction_hash, proposer.secret_key, public_key1);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			pipeline->push_back(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_selection::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::composition::cpubkey cpub_null = { 0 };
			stream->write_string(std::string_view((char*)public_key1, memcmp(public_key1, cpub_null, sizeof(cpub_null)) == 0 ? 0 : sizeof(public_key1)));
			stream->write_integer(contribution_allocation_hash);
			return true;
		}
		bool contribution_selection::load_body(format::stream& stream)
		{
			string public_key1_assembly;
			if (!stream.read_string(stream.read_type(), &public_key1_assembly) || !algorithm::encoding::decode_uint_blob(public_key1_assembly, public_key1, sizeof(public_key1)))
				return false;

			if (!stream.read_integer(stream.read_type(), &contribution_allocation_hash))
				return false;

			return true;
		}
		bool contribution_selection::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto* event = receipt.find_event<contribution_selection>();
			if (!event || event->size() != 1 || event->front().as_string().size() != sizeof(algorithm::pubkeyhash))
				return false;

			parties.insert(event->front().as_blob());
			return true;
		}
		uptr<schema> contribution_selection::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("contribution_allocation_hash", var::string(algorithm::encoding::encode_0xhex256(contribution_allocation_hash)));
			data->set("public_key_1", var::string(format::util::encode_0xhex(std::string_view((char*)public_key1, sizeof(public_key1)))));
			return data;
		}
		uint32_t contribution_selection::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_selection::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_selection::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_selection, 36>();
		}
		uint64_t contribution_selection::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_selection::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_selection::as_instance_typename()
		{
			return "contribution_selection";
		}

		expects_lr<void> contribution_activation::set_share2(const uint256_t& new_contribution_selection_hash, const algorithm::seckey secret_key, const algorithm::composition::cpubkey public_key1)
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			algorithm::pubkey secret_key_hash;
			algorithm::signing::derive_public_key_hash(secret_key, secret_key_hash);

			format::stream entropy;
			entropy.write_typeless(contribution_selection_hash = new_contribution_selection_hash);
			entropy.write_typeless((char*)secret_key_hash, (uint32_t)sizeof(secret_key_hash));
			entropy.write_typeless((char*)public_key1, (uint32_t)sizeof(algorithm::composition::cpubkey));

			algorithm::composition::cseed seed2;
			algorithm::composition::cseckey secret_key2;
			algorithm::composition::convert_to_secret_seed(secret_key, entropy.data, seed2);
			auto status = algorithm::composition::derive_keypair(chain->composition, seed2, secret_key2, public_key2);
			if (!status)
				return status;

			size_t public_key_size32 = 0;
			status = algorithm::composition::derive_public_key(chain->composition, public_key1, secret_key2, public_key, &public_key_size32);
			if (!status)
				return layer_exception("invalid message");

			public_key_size = (uint16_t)public_key_size32;
			auto verifying_wallet = get_verifying_wallet();
			if (!verifying_wallet)
				return verifying_wallet.error();

			return expectation::met;
		}
		expects_lr<void> contribution_activation::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			algorithm::composition::cpubkey pub_null = { 0 };
			if (!memcmp(public_key, pub_null, sizeof(pub_null)) || !public_key_size || public_key_size > sizeof(public_key))
				return layer_exception("invalid public key");

			algorithm::composition::cpubkey cpub_null = { 0 };
			if (!memcmp(public_key2, cpub_null, sizeof(cpub_null)))
				return layer_exception("invalid public key 2");

			if (!contribution_selection_hash)
				return layer_exception("invalid parent transaction");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> contribution_activation::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(contribution_selection_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto selection = context->get_block_transaction<contribution_selection>(contribution_selection_hash);
			if (!selection)
				return selection.error();

			auto allocation = context->get_block_transaction<contribution_allocation>(((contribution_selection*)*selection->transaction)->contribution_allocation_hash);
			if (!allocation)
				return allocation.error();
			else if (asset != allocation->transaction->asset)
				return layer_exception("invalid asset");

			auto verifying_wallet = get_verifying_wallet();
			if (!verifying_wallet)
				return verifying_wallet.error();

			ordered_set<string> parties;
			if (!allocation->transaction->recover_many(allocation->receipt, parties) || parties.size() != 2)
				return layer_exception("transaction receipt does not have a proposer");

			auto it = ++parties.begin();
			if (it->size() != sizeof(algorithm::pubkeyhash) || memcmp(it->data(), context->receipt.from, sizeof(context->receipt.from)) != 0)
				return layer_exception("invalid origin");

			auto address_index = protocol::now().account.root_address_index;
			for (auto& address : verifying_wallet->addresses)
			{
				auto collision = context->get_witness_address(asset, address.second, address_index, 0);
				if (collision)
					return layer_exception("address " + address.second + " taken");
			}

			auto status = context->apply_witness_address(asset, allocation->receipt.from, allocation->receipt.from, verifying_wallet->addresses, address_index, states::address_type::contribution);
			if (!status)
				return status.error();

			return context->emit_event<contribution_activation>({ format::variable(std::string_view((char*)allocation->receipt.from, sizeof(allocation->receipt.from))) });
		}
		expects_promise_rt<void> contribution_activation::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			auto selection = context->get_block_transaction<contribution_selection>(contribution_selection_hash);
			if (!selection)
				return expects_promise_rt<void>(remote_exception(std::move(selection.error().message())));

			auto allocation = context->get_block_transaction<contribution_allocation>(((contribution_selection*)*selection->transaction)->contribution_allocation_hash);
			if (!allocation)
				return expects_promise_rt<void>(remote_exception(std::move(allocation.error().message())));

			auto verifying_wallet = get_verifying_wallet();
			if (!verifying_wallet)
				return expects_promise_rt<void>(remote_exception(std::move(verifying_wallet.error().message())));

			auto address_index = protocol::now().account.root_address_index;
			for (auto& address : verifying_wallet->addresses)
			{
				auto status = nss::server_node::get()->enable_wallet_address(asset, std::string_view((char*)allocation->receipt.from, sizeof(allocation->receipt.from)), address.second, address_index);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_activation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::composition::cpubkey cpub_null = { 0 };
			stream->write_string(std::string_view((char*)public_key, std::min<size_t>(sizeof(public_key), public_key_size)));
			stream->write_string(std::string_view((char*)public_key2, memcmp(public_key2, cpub_null, sizeof(cpub_null)) == 0 ? 0 : sizeof(public_key2)));
			stream->write_integer(contribution_selection_hash);
			return true;
		}
		bool contribution_activation::load_body(format::stream& stream)
		{
			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly) || !algorithm::encoding::decode_uint_blob(public_key_assembly, public_key, std::min(public_key_assembly.size(), sizeof(public_key))))
				return false;

			string public_key2_assembly;
			if (!stream.read_string(stream.read_type(), &public_key2_assembly) || !algorithm::encoding::decode_uint_blob(public_key2_assembly, public_key2, sizeof(public_key2)))
				return false;

			if (!stream.read_integer(stream.read_type(), &contribution_selection_hash))
				return false;

			public_key_size = (uint16_t)std::min(public_key_assembly.size(), sizeof(public_key));
			return true;
		}
		bool contribution_activation::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto* event = receipt.find_event<contribution_activation>();
			if (!event || event->size() != 1 || event->front().as_string().size() != sizeof(algorithm::pubkeyhash))
				return false;

			parties.insert(event->front().as_blob());
			return true;
		}
		expects_lr<mediator::derived_verifying_wallet> contribution_activation::get_verifying_wallet() const
		{
			return nss::server_node::get()->new_verifying_wallet(asset, std::string_view((char*)public_key, public_key_size));
		}
		uptr<schema> contribution_activation::as_schema() const
		{
			auto verifying_wallet = get_verifying_wallet();
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("contribution_selection_hash", var::string(algorithm::encoding::encode_0xhex256(contribution_selection_hash)));
			data->set("public_key_2", var::string(format::util::encode_0xhex(std::string_view((char*)public_key2, sizeof(public_key2)))));
			data->set("verifying_wallet", verifying_wallet ? verifying_wallet->as_schema().reset() : var::set::null());
			return data;
		}
		uint32_t contribution_activation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_activation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_activation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_activation, 96>();
		}
		uint64_t contribution_activation::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_activation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_activation::as_instance_typename()
		{
			return "contribution_activation";
		}

		expects_lr<void> contribution_deallocation::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!contribution_activation_hash)
				return layer_exception("invalid parent transaction");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> contribution_deallocation::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto activation = context->get_block_transaction<contribution_activation>(contribution_activation_hash);
			if (!activation)
				return activation.error();

			auto* activation_transaction = (contribution_activation*)*activation->transaction;
			auto selection = context->get_block_transaction<contribution_selection>(activation_transaction->contribution_selection_hash);
			if (!selection)
				return selection.error();

			auto allocation = context->get_block_transaction<contribution_allocation>(((contribution_selection*)*selection->transaction)->contribution_allocation_hash);
			if (!allocation)
				return allocation.error();

			if (asset != allocation->transaction->asset)
				return layer_exception("invalid asset");

			auto work_requirement = context->verify_account_work(context->receipt.from);
			if (!work_requirement)
				return work_requirement;

			auto wallet = activation_transaction->get_verifying_wallet();
			if (!wallet)
				return wallet.error();

			bool migration = memcmp(allocation->receipt.from, context->receipt.from, sizeof(context->receipt.from)) != 0;
			auto from_depository = context->get_account_depository(asset, allocation->receipt.from);
			if (from_depository)
			{
				if (migration)
				{
					auto work = context->get_account_work(allocation->receipt.from);
					if (!work->is_matching(states::account_flags::outlaw))
						return layer_exception("contribution's proposer is honest");

					auto to_depository = context->get_account_depository(asset, allocation->receipt.from);
					if (!to_depository)
						return layer_exception("migration's proposer depository does not exist");

					for (auto& address : wallet->addresses)
					{
						auto it = from_depository->contributions.find(address.second);
						if (it != from_depository->contributions.end())
							to_depository->custody += it->second;
					}

					auto coverage = to_depository->get_coverage(work ? work->flags : 0);
					if (coverage.is_nan() || coverage.is_negative())
						return layer_exception("migration's proposer depository contribution change does not cover balance (contribution: " + to_depository->get_contribution().to_string() + ", custody: " + to_depository->custody.to_string() + ")");
				}
				else
				{
					for (auto& address : wallet->addresses)
						from_depository->contributions.erase(address.second);

					auto work = context->get_account_work(context->receipt.from);
					auto coverage = from_depository->get_coverage(work ? work->flags : 0);
					if (coverage.is_nan() || coverage.is_negative())
						return layer_exception("depository contribution change does not cover balance (contribution: " + from_depository->get_contribution().to_string() + ", custody: " + from_depository->custody.to_string() + ")");
				}
			}

			auto to_depository = migration ? context->get_account_depository(asset, context->receipt.from) : from_depository;
			if (migration && !to_depository)
				return layer_exception("migration's proposer depository does not exist");

			algorithm::pubkeyhash null = { 0 };
			auto address_index = protocol::now().account.root_address_index;
			auto status = context->apply_witness_address(asset, allocation->receipt.from, null, wallet->addresses, address_index, states::address_type::witness);
			if (!status)
				return status.error();

			for (auto& address : wallet->addresses)
			{
				auto value = from_depository->get_contribution(address.second);
				from_depository->contributions.erase(address.second);
				if (migration && value.is_positive())
					to_depository->custody += value;
			}

			auto work = context->get_account_work(allocation->receipt.from);
			auto coverage = from_depository->get_coverage(work ? work->flags : 0);
			if (coverage.is_nan() || coverage.is_negative())
				return layer_exception("depository contribution change does not cover balance (contribution: " + from_depository->get_contribution().to_string() + ", custody: " + from_depository->custody.to_string() + ")");

			auto resignation = context->store(from_depository.address());
			if (!resignation)
				return resignation.error();

			if (!migration)
				return expectation::met;

			work = context->get_account_work(context->receipt.from);
			coverage = from_depository->get_coverage(work ? work->flags : 0);
			if (coverage.is_nan() || coverage.is_negative())
				return layer_exception("migration's depository contribution change does not cover balance (contribution: " + from_depository->get_contribution().to_string() + ", custody: " + from_depository->custody.to_string() + ")");

			auto application = context->store(to_depository.address());
			if (!application)
				return application.error();

			auto derivation = context->get_account_derivation(asset, context->receipt.from);
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			address_index = (derivation && chain->routing != mediator::routing_policy::memo ? derivation->max_address_index + 1 : protocol::now().account.root_address_index);
			status = context->apply_witness_address(asset, allocation->receipt.from, context->receipt.from, wallet->addresses, address_index, states::address_type::custodian);
			if (!status)
				return status.error();

			if (!derivation || derivation->max_address_index < address_index)
			{
				auto substatus = context->apply_account_derivation(asset, derivation->owner, address_index);
				if (!substatus)
					return substatus.error();
			}

			return expectation::met;
		}
		expects_promise_rt<void> contribution_deallocation::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto activation = context->get_block_transaction<contribution_activation>(contribution_activation_hash);
			if (!activation)
				return expects_promise_rt<void>(remote_exception(std::move(activation.error().message())));

			auto* activation_transaction = (contribution_activation*)*activation->transaction;
			auto selection = context->get_block_transaction<contribution_selection>(activation_transaction->contribution_selection_hash);
			if (!selection)
				return expects_promise_rt<void>(remote_exception(std::move(selection.error().message())));

			if (memcmp(selection->receipt.from, proposer.public_key_hash, sizeof(selection->receipt.from)) != 0)
				return expects_promise_rt<void>(expectation::met);

			uptr<contribution_deselection> transaction = memory::init<contribution_deselection>();
			transaction->asset = asset;

			auto status = transaction->set_revealing_share1(context, context->receipt.transaction_hash, proposer.secret_key);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			pipeline->push_back(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_deallocation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkey null = { 0 };
			stream->write_string(std::string_view((char*)cipher_public_key1, memcmp(cipher_public_key1, null, sizeof(null)) == 0 ? 0 : sizeof(cipher_public_key1)));
			stream->write_string(std::string_view((char*)cipher_public_key2, memcmp(cipher_public_key2, null, sizeof(null)) == 0 ? 0 : sizeof(cipher_public_key2)));
			stream->write_integer(contribution_activation_hash);
			return true;
		}
		bool contribution_deallocation::load_body(format::stream& stream)
		{
			string cipher_public_key1_assembly;
			if (!stream.read_string(stream.read_type(), &cipher_public_key1_assembly) || !algorithm::encoding::decode_uint_blob(cipher_public_key1_assembly, cipher_public_key1, sizeof(cipher_public_key1)))
				return false;

			string cipher_public_key2_assembly;
			if (!stream.read_string(stream.read_type(), &cipher_public_key2_assembly) || !algorithm::encoding::decode_uint_blob(cipher_public_key2_assembly, cipher_public_key2, sizeof(cipher_public_key2)))
				return false;

			if (!stream.read_integer(stream.read_type(), &contribution_activation_hash))
				return false;

			return true;
		}
		void contribution_deallocation::set_witness(const algorithm::seckey secret_key, const uint256_t& new_contribution_activation_hash)
		{
			uint8_t seed[32];
			algorithm::encoding::decode_uint256(contribution_activation_hash = new_contribution_activation_hash, seed);

			algorithm::seckey cipher_secret_key;
			algorithm::signing::derive_cipher_keypair(secret_key, contribution_activation_hash, cipher_secret_key, cipher_public_key1);
			algorithm::signing::derive_cipher_keypair(secret_key, algorithm::hashing::hash256i(seed, sizeof(seed)), cipher_secret_key, cipher_public_key2);
		}
		uptr<schema> contribution_deallocation::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("contribution_activation_hash", var::string(algorithm::encoding::encode_0xhex256(contribution_activation_hash)));
			data->set("cipher_public_key_1", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key1, sizeof(cipher_public_key1)))));
			data->set("cipher_public_key_2", var::string(format::util::encode_0xhex(std::string_view((char*)cipher_public_key2, sizeof(cipher_public_key2)))));
			return data;
		}
		uint32_t contribution_deallocation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_deallocation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_deallocation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_deallocation, 64>();
		}
		uint64_t contribution_deallocation::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_deallocation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_deallocation::as_instance_typename()
		{
			return "contribution_deallocation";
		}

		expects_lr<void> contribution_deselection::set_revealing_share1(const ledger::transaction_context* context, const uint256_t& new_contribution_deallocation_hash, const algorithm::seckey secret_key)
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto deallocation = context->get_block_transaction<contribution_deallocation>(contribution_deallocation_hash = new_contribution_deallocation_hash);
			if (!deallocation)
				return deallocation.error();

			auto deallocation_transaction = (contribution_deallocation*)*deallocation->transaction;
			auto activation = context->get_block_transaction<contribution_activation>(deallocation_transaction->contribution_activation_hash);
			if (!activation)
				return activation.error();

			auto selection = context->get_block_transaction<contribution_selection>(((contribution_activation*)*activation->transaction)->contribution_selection_hash);
			if (!selection)
				return selection.error();

			algorithm::pubkey secret_key_hash;
			algorithm::signing::derive_public_key_hash(secret_key, secret_key_hash);

			auto selection_transaction = (contribution_selection*)*selection->transaction;
			format::stream entropy;
			entropy.write_typeless(selection_transaction->contribution_allocation_hash);
			entropy.write_typeless((char*)secret_key_hash, (uint32_t)sizeof(secret_key_hash));

			algorithm::composition::cseed seed1;
			algorithm::composition::cseckey secret_key1;
			algorithm::composition::cpubkey public_key1;
			algorithm::composition::convert_to_secret_seed(secret_key, entropy.data, seed1);
			auto status = algorithm::composition::derive_keypair(chain->composition, seed1, secret_key1, public_key1);
			if (!status)
				return status;

			entropy.write_typeless((char*)seed1, (uint32_t)sizeof(seed1));
			entropy.write_typeless(deallocation->receipt.transaction_hash);
			entropy.write_typeless(activation->receipt.transaction_hash);
			entropy.write_typeless(selection->receipt.transaction_hash);
			encrypted_secret_key1 = algorithm::signing::public_encrypt(deallocation_transaction->cipher_public_key1, std::string_view((char*)secret_key1, sizeof(secret_key1)), entropy.data).or_else(string());
			if (encrypted_secret_key1.empty())
				return layer_exception("secret key encryption error");

			return expectation::met;
		}
		expects_lr<void> contribution_deselection::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!contribution_deallocation_hash)
				return layer_exception("invalid parent transaction");

			if (encrypted_secret_key1.empty())
				return layer_exception("invalid encrypted secret key 1");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> contribution_deselection::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(contribution_deallocation_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto deallocation = context->get_block_transaction<contribution_deallocation>(contribution_deallocation_hash);
			if (!deallocation)
				return deallocation.error();

			auto activation = context->get_block_transaction<contribution_activation>(((contribution_deallocation*)*deallocation->transaction)->contribution_activation_hash);
			if (!activation)
				return activation.error();

			auto selection = context->get_block_transaction<contribution_selection>(((contribution_activation*)*activation->transaction)->contribution_selection_hash);
			if (!selection)
				return selection.error();

			if (asset != deallocation->transaction->asset)
				return layer_exception("invalid asset");

			if (memcmp(selection->receipt.from, context->receipt.from, sizeof(selection->receipt.from)) != 0)
				return layer_exception("invalid transaction owner");

			ordered_set<string> initiator;
			selection->transaction->recover_many(selection->receipt, initiator);

			format::variables parties = { format::variable(std::string_view((char*)deallocation->receipt.from, sizeof(deallocation->receipt.from))) };
			if (!initiator.empty() && *initiator.begin() != parties.begin()->as_string())
				parties.push_back(format::variable(*initiator.begin()));

			return context->emit_event<contribution_deselection>(std::move(parties));
		}
		expects_promise_rt<void> contribution_deselection::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto deallocation = context->get_block_transaction<contribution_deallocation>(contribution_deallocation_hash);
			if (!deallocation)
				return expects_promise_rt<void>(remote_exception(std::move(deallocation.error().message())));

			auto activation = context->get_block_transaction<contribution_activation>(((contribution_deallocation*)*deallocation->transaction)->contribution_activation_hash);
			if (!activation)
				return expects_promise_rt<void>(remote_exception(std::move(activation.error().message())));

			if (memcmp(activation->receipt.from, proposer.public_key_hash, sizeof(activation->receipt.from)) != 0)
				return expects_promise_rt<void>(expectation::met);

			uptr<contribution_deactivation> transaction = memory::init<contribution_deactivation>();
			transaction->asset = asset;

			auto status = transaction->set_revealing_share2(context, context->receipt.transaction_hash, proposer.secret_key);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			pipeline->push_back(transaction.reset());
			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_deselection::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(contribution_deallocation_hash);
			stream->write_string(encrypted_secret_key1);
			return true;
		}
		bool contribution_deselection::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &contribution_deallocation_hash))
				return false;

			if (!stream.read_string(stream.read_type(), &encrypted_secret_key1))
				return false;

			return true;
		}
		bool contribution_deselection::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto* event = receipt.find_event<contribution_deselection>();
			if (!event || event->empty())
				return false;

			for (auto& owner : *event)
			{
				if (owner.as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(owner.as_blob());
			}
			return true;
		}
		option<string> contribution_deselection::get_secret_key1(const ledger::transaction_context* context, const algorithm::seckey secret_key) const
		{
			auto deallocation = context->get_block_transaction<contribution_deallocation>(contribution_deallocation_hash);
			if (!deallocation)
				return optional::none;

			auto* deallocation_transaction = (contribution_deallocation*)*deallocation->transaction;
			algorithm::seckey cipher_secret_key; algorithm::pubkey cipher_public_key;
			algorithm::signing::derive_cipher_keypair(secret_key, deallocation_transaction->contribution_activation_hash, cipher_secret_key, cipher_public_key);
			return algorithm::signing::private_decrypt(cipher_secret_key, cipher_public_key, encrypted_secret_key1);
		}
		uptr<schema> contribution_deselection::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("contribution_deallocation_hash", var::string(algorithm::encoding::encode_0xhex256(contribution_deallocation_hash)));
			data->set("encrypted_secret_key_1", var::string(format::util::encode_0xhex(encrypted_secret_key1)));
			return data;
		}
		uint32_t contribution_deselection::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_deselection::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_deselection::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_deselection, 52>();
		}
		uint64_t contribution_deselection::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_deselection::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_deselection::as_instance_typename()
		{
			return "contribution_deselection";
		}

		expects_lr<void> contribution_deactivation::set_revealing_share2(const ledger::transaction_context* context, const uint256_t& new_contribution_deselection_hash, const algorithm::seckey secret_key)
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			contribution_deselection_hash = new_contribution_deselection_hash;
			auto deselection = context->get_block_transaction<contribution_deselection>(contribution_deselection_hash);
			if (!deselection)
				return deselection.error();

			auto deallocation = context->get_block_transaction<contribution_deallocation>(((contribution_deselection*)*deselection->transaction)->contribution_deallocation_hash);
			if (!deallocation)
				return deallocation.error();

			auto* deallocation_transaction = (contribution_deallocation*)*deallocation->transaction;
			auto activation = context->get_block_transaction<contribution_activation>(deallocation_transaction->contribution_activation_hash);
			if (!activation)
				return activation.error();

			auto* activation_transaction = ((contribution_activation*)*activation->transaction);
			auto selection = context->get_block_transaction<contribution_selection>(activation_transaction->contribution_selection_hash);
			if (!selection)
				return selection.error();

			algorithm::pubkey secret_key_hash;
			algorithm::signing::derive_public_key_hash(secret_key, secret_key_hash);

			auto selection_transaction = (contribution_selection*)*selection->transaction;
			format::stream entropy;
			entropy.write_typeless(activation_transaction->contribution_selection_hash);
			entropy.write_typeless((char*)secret_key_hash, (uint32_t)sizeof(secret_key_hash));
			entropy.write_typeless((char*)selection_transaction->public_key1, (uint32_t)sizeof(algorithm::composition::cpubkey));

			algorithm::composition::cseed seed2;
			algorithm::composition::cseckey secret_key2;
			algorithm::composition::cpubkey public_key2;
			algorithm::composition::convert_to_secret_seed(secret_key, entropy.data, seed2);
			auto status = algorithm::composition::derive_keypair(chain->composition, seed2, secret_key2, public_key2);
			if (!status)
				return status;

			size_t shared_public_key_size = 0;
			algorithm::composition::cpubkey shared_public_key;
			status = algorithm::composition::derive_public_key(chain->composition, selection_transaction->public_key1, secret_key2, shared_public_key, &shared_public_key_size);
			if (!status)
				return status;

			entropy.write_typeless((char*)seed2, (uint32_t)sizeof(seed2));
			entropy.write_typeless(deselection->receipt.transaction_hash);
			entropy.write_typeless(deallocation->receipt.transaction_hash);
			entropy.write_typeless(activation->receipt.transaction_hash);
			entropy.write_typeless(selection->receipt.transaction_hash);
			encrypted_secret_key2 = algorithm::signing::public_encrypt(deallocation_transaction->cipher_public_key2, std::string_view((char*)secret_key2, sizeof(secret_key2)), entropy.data).or_else(string());
			if (encrypted_secret_key2.empty())
				return layer_exception("secret key encryption error");

			return expectation::met;
		}
		expects_lr<void> contribution_deactivation::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (!contribution_deselection_hash)
				return layer_exception("invalid parent transaction");

			if (encrypted_secret_key2.empty())
				return layer_exception("invalid encrypted secret key 2");

			return ledger::consensus_transaction::validate(block_number);
		}
		expects_lr<void> contribution_deactivation::execute(ledger::transaction_context* context) const
		{
			auto validation = consensus_transaction::execute(context);
			if (!validation)
				return validation.error();

			auto event = context->apply_witness_event(contribution_deselection_hash, context->receipt.transaction_hash);
			if (!event)
				return event.error();

			auto deselection = context->get_block_transaction<contribution_deselection>(contribution_deselection_hash);
			if (!deselection)
				return deselection.error();

			auto deallocation = context->get_block_transaction<contribution_deallocation>(((contribution_deselection*)*deselection->transaction)->contribution_deallocation_hash);
			if (!deallocation)
				return deallocation.error();

			auto activation = context->get_block_transaction<contribution_activation>(((contribution_deallocation*)*deallocation->transaction)->contribution_activation_hash);
			if (!activation)
				return activation.error();

			if (asset != deallocation->transaction->asset)
				return layer_exception("invalid asset");

			if (memcmp(activation->receipt.from, context->receipt.from, sizeof(activation->receipt.from)) != 0)
				return layer_exception("invalid transaction owner");

			ordered_set<string> initiator;
			activation->transaction->recover_many(activation->receipt, initiator);

			format::variables parties = { format::variable(std::string_view((char*)deallocation->receipt.from, sizeof(deallocation->receipt.from))) };
			if (!initiator.empty() && *initiator.begin() != parties.begin()->as_string())
				parties.push_back(format::variable(*initiator.begin()));

			return context->emit_event<contribution_deactivation>(std::move(parties));
		}
		expects_promise_rt<void> contribution_deactivation::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			auto deselection = context->get_block_transaction<contribution_deselection>(contribution_deselection_hash);
			if (!deselection)
				return expects_promise_rt<void>(remote_exception(std::move(deselection.error().message())));

			auto deallocation = context->get_block_transaction<contribution_deallocation>(((contribution_deselection*)*deselection->transaction)->contribution_deallocation_hash);
			if (!deallocation)
				return expects_promise_rt<void>(remote_exception(std::move(deallocation.error().message())));

			auto activation = context->get_block_transaction<contribution_activation>(((contribution_deallocation*)*deallocation->transaction)->contribution_activation_hash);
			if (!activation)
				return expects_promise_rt<void>(remote_exception(std::move(activation.error().message())));

			auto* activation_transaction = ((contribution_activation*)*activation->transaction);
			auto verifying_wallet = activation_transaction->get_verifying_wallet();
			if (!verifying_wallet)
				return expects_promise_rt<void>(remote_exception(std::move(verifying_wallet.error().message())));

			auto* event = context->receipt.find_event<contribution_deactivation>();
			if (event != nullptr && event->size() == 2)
			{
				auto* server = nss::server_node::get();
				auto* event = deallocation->receipt.reverse_find_event<states::witness_address>();
				if (!event || event->size() < 3)
					return expects_promise_rt<void>(remote_exception("bad event type"));

				auto address_index = (*event)[2].as_uint64();
				if (!memcmp(proposer.public_key_hash, deallocation->receipt.from, sizeof(proposer.public_key_hash)))
				{
					auto parent = server->new_master_wallet(asset, proposer.secret_key);
					if (!parent)
						return expects_promise_rt<void>(remote_exception(std::move(parent.error().message())));

					auto child = get_signing_wallet(context, proposer.secret_key);
					if (!child)
						return expects_promise_rt<void>(remote_exception(std::move(child.error().message())));

					child->address_index = address_index;
					if (parent->max_address_index < address_index)
						parent->max_address_index = address_index;

					auto status = server->enable_signing_wallet(asset, *parent, *child);
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}

				for (auto& address : verifying_wallet->addresses)
				{
					auto status = server->enable_wallet_address(asset, std::string_view((char*)deallocation->receipt.from, sizeof(algorithm::pubkeyhash)), address.second, address_index);
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}
			}
			else
			{
				auto address_index = protocol::now().account.root_address_index;
				for (auto& address : verifying_wallet->addresses)
				{
					auto status = nss::server_node::get()->disable_wallet_address(asset, address.second);
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}
			}

			return expects_promise_rt<void>(expectation::met);
		}
		bool contribution_deactivation::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(contribution_deselection_hash);
			stream->write_string(encrypted_secret_key2);
			return true;
		}
		bool contribution_deactivation::load_body(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &contribution_deselection_hash))
				return false;

			if (!stream.read_string(stream.read_type(), &encrypted_secret_key2))
				return false;

			return true;
		}
		bool contribution_deactivation::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			auto* event = receipt.find_event<contribution_deactivation>();
			if (!event || event->empty())
				return false;

			for (auto& owner : *event)
			{
				if (owner.as_string().size() == sizeof(algorithm::pubkeyhash))
					parties.insert(owner.as_blob());
			}
			return true;
		}
		option<string> contribution_deactivation::get_secret_key1(const ledger::transaction_context* context, const algorithm::seckey secret_key) const
		{
			auto deselection = context->get_block_transaction<contribution_deselection>(contribution_deselection_hash);
			if (!deselection)
				return optional::none;

			return ((contribution_deselection*)*deselection->transaction)->get_secret_key1(context, secret_key);
		}
		option<string> contribution_deactivation::get_secret_key2(const ledger::transaction_context* context, const algorithm::seckey secret_key) const
		{
			auto deselection = context->get_block_transaction<contribution_deselection>(contribution_deselection_hash);
			if (!deselection)
				return optional::none;

			auto deallocation = context->get_block_transaction<contribution_deallocation>(((contribution_deselection*)*deselection->transaction)->contribution_deallocation_hash);
			if (!deallocation)
				return optional::none;

			uint8_t seed[32];
			auto* deallocation_transaction = (contribution_deallocation*)*deallocation->transaction;
			algorithm::seckey cipher_secret_key; algorithm::pubkey cipher_public_key;
			algorithm::encoding::decode_uint256(deallocation_transaction->contribution_activation_hash, seed);
			algorithm::signing::derive_cipher_keypair(secret_key, algorithm::hashing::hash256i(seed, sizeof(seed)), cipher_secret_key, cipher_public_key);
			return algorithm::signing::private_decrypt(cipher_secret_key, cipher_public_key, encrypted_secret_key2);
		}
		expects_lr<mediator::derived_signing_wallet> contribution_deactivation::get_signing_wallet(const ledger::transaction_context* context, const algorithm::seckey secret_key) const
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			if (!chain)
				return layer_exception("invalid operation");

			auto secret_key2 = get_secret_key2(context, secret_key);
			if (!secret_key2)
				return layer_exception("invalid secret key 2");

			auto secret_key1 = get_secret_key1(context, secret_key);
			if (!secret_key1)
				return layer_exception("invalid secret key 1");

			size_t shared_secret_key_size = 0;
			algorithm::composition::cseckey shared_secret_key;
			auto status = algorithm::composition::derive_secret_key(chain->composition, (uint8_t*)secret_key1->data(), (uint8_t*)secret_key2->data(), shared_secret_key, &shared_secret_key_size);
			if (!status)
				return layer_exception("invalid message");

			return nss::server_node::get()->new_signing_wallet(asset, secret_box::view(std::string_view((char*)shared_secret_key, shared_secret_key_size)));
		}
		expects_promise_rt<mediator::outgoing_transaction> contribution_deactivation::withdraw_to_address(const ledger::transaction_context* context, const algorithm::seckey secret_key, const std::string_view& address)
		{
			return coasync<expects_rt<mediator::outgoing_transaction>>([this, context, secret_key, address]() -> expects_promise_rt<mediator::outgoing_transaction>
			{
				auto signing_wallet = get_signing_wallet(context, secret_key);
				if (!signing_wallet)
					coreturn remote_exception(std::move(signing_wallet.error().message()));

				auto dynamic_wallet = mediator::dynamic_wallet(*signing_wallet);
				auto remaining_balance = coawait(nss::server_node::get()->calculate_balance(asset, dynamic_wallet, signing_wallet->addresses.begin()->second));
				if (!remaining_balance)
					coreturn remaining_balance.error();
				else if (!remaining_balance->is_positive())
					coreturn remote_exception("contribution wallet balance is zero");

				auto destinations = { mediator::transferer(address, optional::none, std::move(*remaining_balance)) };
				auto result = coawait(resolver::emit_transaction(nullptr, std::move(dynamic_wallet), asset, context->receipt.transaction_hash, std::move(destinations)));
				coreturn std::move(result);
			});
		}
		uptr<schema> contribution_deactivation::as_schema() const
		{
			schema* data = ledger::consensus_transaction::as_schema().reset();
			data->set("contribution_deselection_hash", var::string(algorithm::encoding::encode_0xhex256(contribution_deselection_hash)));
			data->set("encrypted_secret_key_2", var::string(format::util::encode_0xhex(encrypted_secret_key2)));
			return data;
		}
		uint32_t contribution_deactivation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view contribution_deactivation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t contribution_deactivation::get_gas_estimate() const
		{
			return ledger::gas_util::get_gas_estimate<contribution_deactivation, 52>();
		}
		uint64_t contribution_deactivation::get_dispatch_offset() const
		{
			return 1;
		}
		uint32_t contribution_deactivation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view contribution_deactivation::as_instance_typename()
		{
			return "contribution_deactivation";
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

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_adjustment::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			auto work = context->verify_account_work(context->receipt.from);
			if (!work)
				return work;

			auto reward = context->apply_account_reward(asset, context->receipt.from, incoming_absolute_fee, incoming_relative_fee, outgoing_absolute_fee, outgoing_relative_fee);
			if (!reward)
				return reward.error();

			return expectation::met;
		}
		bool depository_adjustment::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(incoming_absolute_fee);
			stream->write_decimal(incoming_relative_fee);
			stream->write_decimal(outgoing_absolute_fee);
			stream->write_decimal(outgoing_relative_fee);
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
		uptr<schema> depository_adjustment::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("incoming_absolute_fee", var::decimal(incoming_absolute_fee));
			data->set("incoming_relative_fee", var::decimal(incoming_relative_fee));
			data->set("outgoing_absolute_fee", var::decimal(outgoing_absolute_fee));
			data->set("outgoing_relative_fee", var::decimal(outgoing_relative_fee));
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
			if (is_proposer_null())
				return layer_exception("invalid proposer");

			if (!value.is_positive())
				return layer_exception("invalid value");

			return ledger::transaction::validate(block_number);
		}
		expects_lr<void> depository_migration::execute(ledger::transaction_context* context) const
		{
			auto validation = transaction::execute(context);
			if (!validation)
				return validation.error();

			if (!memcmp(context->receipt.from, proposer, sizeof(proposer)))
				return layer_exception("self migration not allowed");

			auto work_requirement = context->verify_account_depository_work(asset, context->receipt.from);
			if (!work_requirement)
				return work_requirement;

			auto depository = context->get_account_depository(asset, context->receipt.from);
			if (!depository)
				return layer_exception("proposer has no depository");

			auto work = context->get_account_work(context->receipt.from);
			auto coverage = depository->get_coverage(work ? work->flags : 0);
			if (coverage.is_nan() || coverage.is_negative())
				return layer_exception("proposer does not cover balance (contribution: " + depository->get_contribution().to_string() + ", custody: " + depository->custody.to_string() + ")");
			else if (depository->custody < value)
				return layer_exception("proposer does not have enough custody (value: " + value.to_string() + ", custody: " + depository->custody.to_string() + ")");

			work = context->get_account_work(proposer);
			depository = context->get_account_depository(asset, proposer);
			if (!depository)
				return layer_exception("migration proposer has no depository");

			depository->custody += value;
			coverage = depository->get_coverage(work ? work->flags : 0);
			if (coverage.is_nan() || coverage.is_negative())
				return layer_exception("migration proposer does not cover balance (contribution: " + depository->get_contribution().to_string() + ", custody: " + depository->custody.to_string() + ")");

			auto address = get_destination(context);
			if (!address)
				return layer_exception("migration proposer has no usable custodian address");

			return expectation::met;
		}
		expects_promise_rt<void> depository_migration::dispatch(const ledger::wallet& proposer, const ledger::transaction_context* context, vector<uptr<ledger::transaction>>* pipeline) const
		{
			if (memcmp(proposer.public_key_hash, context->receipt.from, sizeof(context->receipt.from)) != 0)
				return expects_promise_rt<void>(expectation::met);

			if (context->get_witness_event(context->receipt.transaction_hash))
				return expects_promise_rt<void>(expectation::met);

			auto address = get_destination(context);
			if (!address)
				return expects_promise_rt<void>(remote_exception("migration proposer has no usable custodian address"));

			auto* transaction = memory::init<outgoing_claim>();
			transaction->asset = asset;
			pipeline->push_back(transaction);

			auto destinations = { mediator::transferer(address->addresses.begin()->second, address->address_index, decimal(value)) };
			auto parent = nss::server_node::get()->new_master_wallet(asset, proposer.secret_key);
			auto child = parent ? mediator::dynamic_wallet(*parent) : mediator::dynamic_wallet();
			return resolver::emit_transaction(pipeline, std::move(child), asset, context->receipt.transaction_hash, std::move(destinations)).then<expects_rt<void>>([this, context, pipeline, transaction](expects_rt<mediator::outgoing_transaction>&& result)
			{
				if (!result || result->transaction.transaction_id.empty())
				{
					transaction->set_failure_witness(result ? "transaction broadcast failed" : result.what(), context->receipt.transaction_hash);
					if (!result && (result.error().is_retry() || result.error().is_shutdown()))
					{
						pipeline->pop_back();
						memory::deinit(transaction);
						return expects_rt<void>(result.error());
					}
				}
				else
					transaction->set_success_witness(result->transaction.transaction_id, result->data, context->receipt.transaction_hash);
				return expects_rt<void>(expectation::met);
			});
		}
		bool depository_migration::store_body(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			stream->write_decimal(value);
			return true;
		}
		bool depository_migration::load_body(format::stream& stream)
		{
			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			if (!stream.read_decimal(stream.read_type(), &value))
				return false;

			return true;
		}
		bool depository_migration::recover_many(const ledger::receipt& receipt, ordered_set<string>& parties) const
		{
			if (!is_proposer_null())
				parties.insert(string((char*)proposer, sizeof(proposer)));
			return true;
		}
		void depository_migration::set_proposer(const algorithm::pubkeyhash new_proposer, const decimal& new_value)
		{
			value = new_value;
			if (!new_proposer)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
		}
		bool depository_migration::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return memcmp(proposer, null, sizeof(null)) == 0;
		}
		expects_lr<states::witness_address> depository_migration::get_destination(const ledger::transaction_context* context) const
		{
			size_t offset = 0;
			auto address = expects_lr<states::witness_address>(layer_exception());
			while (true)
			{
				auto addresses = context->get_witness_addresses(proposer, offset, 16);
				if (!addresses)
					return addresses.error();
				else if (addresses->empty())
					return layer_exception("destination not found");

				offset += addresses->size();
				auto it = std::find_if(addresses->begin(), addresses->end(), [&](states::witness_address& item) { return item.is_custodian_address() && !memcmp(item.proposer, proposer, sizeof(proposer)) && item.asset == asset; });
				if (it != addresses->end())
				{
					address = std::move(*it);
					break;
				}
			}
			return address;
		}
		uptr<schema> depository_migration::as_schema() const
		{
			schema* data = ledger::transaction::as_schema().reset();
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			data->set("value", var::decimal(value));
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
		uint64_t depository_migration::get_dispatch_offset() const
		{
			return protocol::now().user.nss.withdrawal_time / protocol::now().policy.consensus_proof_time;
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

		ledger::transaction* resolver::init(uint32_t hash)
		{
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>();
			else if (hash == omnitransfer::as_instance_type())
				return memory::init<omnitransfer>();
			else if (hash == deployment::as_instance_type())
				return memory::init<deployment>();
			else if (hash == invocation::as_instance_type())
				return memory::init<invocation>();
			else if (hash == withdrawal::as_instance_type())
				return memory::init<withdrawal>();
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>();
			else if (hash == commitment::as_instance_type())
				return memory::init<commitment>();
			else if (hash == incoming_claim::as_instance_type())
				return memory::init<incoming_claim>();
			else if (hash == outgoing_claim::as_instance_type())
				return memory::init<outgoing_claim>();
			else if (hash == address_account::as_instance_type())
				return memory::init<address_account>();
			else if (hash == pubkey_account::as_instance_type())
				return memory::init<pubkey_account>();
			else if (hash == delegation_account::as_instance_type())
				return memory::init<delegation_account>();
			else if (hash == custodian_account::as_instance_type())
				return memory::init<custodian_account>();
			else if (hash == contribution_allocation::as_instance_type())
				return memory::init<contribution_allocation>();
			else if (hash == contribution_selection::as_instance_type())
				return memory::init<contribution_selection>();
			else if (hash == contribution_activation::as_instance_type())
				return memory::init<contribution_activation>();
			else if (hash == contribution_deallocation::as_instance_type())
				return memory::init<contribution_deallocation>();
			else if (hash == contribution_deselection::as_instance_type())
				return memory::init<contribution_deselection>();
			else if (hash == contribution_deactivation::as_instance_type())
				return memory::init<contribution_deactivation>();
			else if (hash == depository_adjustment::as_instance_type())
				return memory::init<depository_adjustment>();
			else if (hash == depository_migration::as_instance_type())
				return memory::init<depository_migration>();
			return nullptr;
		}
		ledger::transaction* resolver::copy(const ledger::transaction* base)
		{
			uint32_t hash = base->as_type();
			if (hash == transfer::as_instance_type())
				return memory::init<transfer>(*(const transfer*)base);
			else if (hash == omnitransfer::as_instance_type())
				return memory::init<omnitransfer>(*(const omnitransfer*)base);
			else if (hash == deployment::as_instance_type())
				return memory::init<deployment>(*(const deployment*)base);
			else if (hash == invocation::as_instance_type())
				return memory::init<invocation>(*(const invocation*)base);
			else if (hash == withdrawal::as_instance_type())
				return memory::init<withdrawal>(*(const withdrawal*)base);
			else if (hash == rollup::as_instance_type())
				return memory::init<rollup>(*(const rollup*)base);
			else if (hash == commitment::as_instance_type())
				return memory::init<commitment>(*(const commitment*)base);
			else if (hash == incoming_claim::as_instance_type())
				return memory::init<incoming_claim>(*(const incoming_claim*)base);
			else if (hash == outgoing_claim::as_instance_type())
				return memory::init<outgoing_claim>(*(const outgoing_claim*)base);
			else if (hash == address_account::as_instance_type())
				return memory::init<address_account>(*(const address_account*)base);
			else if (hash == pubkey_account::as_instance_type())
				return memory::init<pubkey_account>(*(const pubkey_account*)base);
			else if (hash == delegation_account::as_instance_type())
				return memory::init<delegation_account>(*(const delegation_account*)base);
			else if (hash == custodian_account::as_instance_type())
				return memory::init<custodian_account>(*(const custodian_account*)base);
			else if (hash == contribution_allocation::as_instance_type())
				return memory::init<contribution_allocation>(*(const contribution_allocation*)base);
			else if (hash == contribution_selection::as_instance_type())
				return memory::init<contribution_selection>(*(const contribution_selection*)base);
			else if (hash == contribution_activation::as_instance_type())
				return memory::init<contribution_activation>(*(const contribution_activation*)base);
			else if (hash == contribution_deallocation::as_instance_type())
				return memory::init<contribution_deallocation>(*(const contribution_deallocation*)base);
			else if (hash == contribution_deselection::as_instance_type())
				return memory::init<contribution_deselection>(*(const contribution_deselection*)base);
			else if (hash == contribution_deactivation::as_instance_type())
				return memory::init<contribution_deactivation>(*(const contribution_deactivation*)base);
			else if (hash == depository_adjustment::as_instance_type())
				return memory::init<depository_adjustment>(*(const depository_adjustment*)base);
			else if (hash == depository_migration::as_instance_type())
				return memory::init<depository_migration>(*(const depository_migration*)base);
			return nullptr;
		}
		expects_promise_rt<mediator::outgoing_transaction> resolver::emit_transaction(vector<uptr<ledger::transaction>>* pipeline, mediator::dynamic_wallet&& wallet, const algorithm::asset_id& asset, const uint256_t& transaction_hash, vector<mediator::transferer>&& to)
		{
			auto* server = nss::server_node::get();
			if (!protocol::now().is(network_type::regtest) || server->has_support(asset))
				return server->submit_transaction(transaction_hash, asset, std::move(wallet), std::move(to));

			expects_lr<mediator::derived_verifying_wallet> verifying_wallet = layer_exception();
			if (wallet.parent)
			{
				auto signing_wallet = server->new_signing_wallet(asset, *wallet.parent, protocol::now().account.root_address_index);
				if (!signing_wallet)
					return expects_promise_rt<mediator::outgoing_transaction>(remote_exception("wallet not found"));

				verifying_wallet = std::move(*signing_wallet);
			}
			else if (wallet.signing_child)
				verifying_wallet = std::move(*wallet.signing_child);
			else if (wallet.verifying_child)
				verifying_wallet = std::move(*wallet.verifying_child);
			if (!verifying_wallet)
				return expects_promise_rt<mediator::outgoing_transaction>(remote_exception("wallet not found"));

			mediator::outgoing_transaction ephimeric;
			ephimeric.transaction.to = to;
			ephimeric.transaction.from.push_back(mediator::transferer(verifying_wallet->addresses.begin()->second, option<uint64_t>(verifying_wallet->address_index), ephimeric.transaction.get_output_value()));
			ephimeric.transaction.asset = asset;
			ephimeric.transaction.transaction_id = algorithm::encoding::encode_0xhex256(algorithm::hashing::hash256i(transaction_hash.to_string()));
			ephimeric.transaction.block_id = algorithm::hashing::hash256i(ephimeric.transaction.transaction_id) % std::numeric_limits<uint64_t>::max();
			ephimeric.transaction.fee = decimal::zero();
			ephimeric.data = ephimeric.as_message().encode();

			if (pipeline != nullptr)
			{
				auto* transaction = memory::init<incoming_claim>();
				transaction->asset = asset;
				transaction->set_estimate_gas(decimal::zero());
				transaction->set_witness(ephimeric.transaction);
				pipeline->push_back(transaction);
			}

			return expects_promise_rt<mediator::outgoing_transaction>(std::move(ephimeric));
		}
	}
}