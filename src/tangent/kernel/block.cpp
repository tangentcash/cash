#include "block.h"
#include "../policy/transactions.h"
#include "../validator/service/nss.h"
#include "../validator/storage/mempoolstate.h"
#include "../validator/storage/chainstate.h"

namespace tangent
{
	namespace ledger
	{
		static size_t exponential_range_distribution(const uint256_t& entropy, size_t range)
		{
			const double lamda = 9.0;
			const double exponent = std::exp(-lamda);
			const double base = (double)(uint64_t)(entropy % std::numeric_limits<uint32_t>::max()) / (double)std::numeric_limits<uint32_t>::max();
			const double factor = std::min(1.0, std::max(0.0, -std::log(1.0 - (1.0 - exponent) * base) / lamda));
			const size_t index = (size_t)((uint64_t)(factor * (double)range) % (uint64_t)range);
			return index;
		}

		block_transaction::block_transaction(uptr<ledger::transaction>&& new_transaction, ledger::receipt&& new_receipt) : transaction(std::move(new_transaction)), receipt(std::move(new_receipt))
		{
			VI_ASSERT(transaction, "transaction should be set");
		}
		block_transaction::block_transaction(const block_transaction& other) : transaction(other.transaction ? transactions::resolver::copy(*other.transaction) : nullptr), receipt(other.receipt)
		{
		}
		block_transaction& block_transaction::operator= (const block_transaction& other)
		{
			if (this == &other)
				return *this;

			transaction = other.transaction ? transactions::resolver::copy(*other.transaction) : nullptr;
			receipt = other.receipt;
			return *this;
		}
		bool block_transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (transaction && !transaction->store(stream))
				return false;

			if (!receipt.store_payload(stream))
				return false;

			return true;
		}
		bool block_transaction::load_payload(format::stream& stream)
		{
			transaction = tangent::transactions::resolver::init(messages::authentic::resolve_type(stream).otherwise(0));
			if (transaction && !transaction->load(stream))
				return false;

			if (!receipt.load_payload(stream))
				return false;

			return true;
		}
		uptr<schema> block_transaction::as_schema() const
		{
			schema* data = var::set::object();
			data->set("transaction", transaction ? transaction->as_schema().reset() : var::set::null());
			data->set("receipt", receipt.as_schema().reset());
			return data;
		}
		uint32_t block_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view block_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t block_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view block_transaction::as_instance_typename()
		{
			return "block_transaction";
		}

		block_work::block_work(const block_work& other) : parent_work(other.parent_work)
		{
			for (size_t i = 0; i < (size_t)work_commitment::__Count__; i++)
			{
				auto& mapping = map[i];
				for (auto& item : other.map[i])
					mapping[item.first] = item.second ? states::resolver::copy(*item.second) : nullptr;
			}
		}
		block_work& block_work::operator= (const block_work& other)
		{
			if (&other == this)
				return *this;

			parent_work = other.parent_work;
			for (size_t i = 0; i < (size_t)work_commitment::__Count__; i++)
			{
				auto& mapping = map[i];
				mapping.clear();
				for (auto& item : other.map[i])
					mapping[item.first] = item.second ? states::resolver::copy(*item.second) : nullptr;
			}
			return *this;
		}
		option<uptr<state>> block_work::find_uniform(const std::string_view& index) const
		{
			auto composite = uniform::as_instance_composite(index);
			for (size_t i = 0; i < (size_t)work_commitment::__Count__; i++)
			{
				auto& mapping = map[i];
				auto it = mapping.find(composite);
				if (it != mapping.end())
					return it->second ? option<uptr<state>>(states::resolver::copy(*it->second)) : option<uptr<state>>(nullptr);
			}
			return parent_work ? parent_work->find_uniform(index) : option<uptr<state>>(optional::none);
		}
		option<uptr<state>> block_work::find_multiform(const std::string_view& column, const std::string_view& row) const
		{
			auto composite = multiform::as_instance_composite(column, row);
			for (size_t i = 0; i < (size_t)work_commitment::__Count__; i++)
			{
				auto& mapping = map[i];
				auto it = mapping.find(composite);
				if (it != mapping.end())
					return it->second ? option<uptr<state>>(states::resolver::copy(*it->second)) : option<uptr<state>>(nullptr);
			}
			return parent_work ? parent_work->find_multiform(column, row) : option<uptr<state>>(optional::none);
		}
		void block_work::clear_uniform(const std::string_view& index)
		{
			map[(size_t)work_commitment::pending][uniform::as_instance_composite(index)].destroy();
		}
		void block_work::clear_multiform(const std::string_view& column, const std::string_view& row)
		{
			map[(size_t)work_commitment::pending][multiform::as_instance_composite(column, row)].destroy();
		}
		void block_work::copy_any(state* value)
		{
			if (value)
			{
				auto copy = states::resolver::copy(value);
				if (copy)
					map[(size_t)work_commitment::pending][value->as_composite()] = copy;
			}
		}
		void block_work::move_any(uptr<state>&& value)
		{
			auto composite = value->as_composite();
			map[(size_t)work_commitment::pending][composite] = std::move(value);
		}
		const state_work& block_work::at(work_commitment level) const
		{
			switch (level)
			{
				case tangent::ledger::work_commitment::pending:
				case tangent::ledger::work_commitment::finalized:
					return map[(size_t)level];
				default:
					return map[(size_t)work_commitment::finalized];
			}
		}
		state_work& block_work::clear()
		{
			map[(size_t)work_commitment::pending].clear();
			map[(size_t)work_commitment::finalized].clear();
			return map[(size_t)work_commitment::finalized];
		}
		state_work& block_work::rollback()
		{
			map[(size_t)work_commitment::pending].clear();
			return map[(size_t)work_commitment::finalized];
		}
		state_work& block_work::commit()
		{
			for (auto& item : map[(size_t)work_commitment::pending])
			{
				if (item.second)
					map[(size_t)work_commitment::finalized][item.first] = std::move(item.second);
			}
			map[(size_t)work_commitment::pending].clear();
			return map[(size_t)work_commitment::finalized];
		}

		block_mutation::block_mutation() noexcept : outgoing(nullptr)
		{
			incoming = &cache;
		}
		block_mutation::block_mutation(const block_mutation& other) noexcept : cache(other.cache), outgoing(other.outgoing)
		{
			incoming = other.incoming == &other.cache ? &cache : other.incoming;
		}
		block_mutation::block_mutation(block_mutation&& other) noexcept : cache(std::move(other.cache)), outgoing(other.outgoing)
		{
			other.outgoing = nullptr;
			incoming = other.incoming == &other.cache ? &cache : other.incoming;
		}
		block_mutation& block_mutation::operator=(const block_mutation& other) noexcept
		{
			if (this == &other)
				return *this;

			cache = other.cache;
			outgoing = other.outgoing;
			incoming = other.incoming == &other.cache ? &cache : other.incoming;
			return *this;
		}
		block_mutation& block_mutation::operator=(block_mutation&& other) noexcept
		{
			if (this == &other)
				return *this;

			cache = std::move(other.cache);
			outgoing = other.outgoing;
			incoming = other.incoming == &other.cache ? &cache : other.incoming;
			other.outgoing = nullptr;
			return *this;
		}

		block_dispatch::block_dispatch(const block_dispatch& other) noexcept : inputs(other.inputs)
		{
			outputs.reserve(other.outputs.size());
			for (auto& output : other.outputs)
			{
				auto* copy = transactions::resolver::copy(*output);
				if (copy)
					outputs.push_back(copy);
			}
		}
		block_dispatch& block_dispatch::operator=(const block_dispatch& other) noexcept
		{
			if (this == &other)
				return *this;

			inputs = other.inputs;
			outputs.clear();
			outputs.reserve(other.outputs.size());
			for (auto& output : other.outputs)
			{
				auto* copy = transactions::resolver::copy(*output);
				if (copy)
					outputs.push_back(copy);
			}
			return *this;
		}
		expects_lr<void> block_dispatch::checkpoint() const
		{
			auto chain = storages::chainstate(__func__);
			return chain.dispatch(inputs, repeaters);
		}

		bool block_header::operator<(const block_header& other) const
		{
			return get_relative_order(other) < 0;
		}
		bool block_header::operator>(const block_header& other) const
		{
			return get_relative_order(other) > 0;
		}
		bool block_header::operator<=(const block_header& other) const
		{
			return get_relative_order(other) <= 0;
		}
		bool block_header::operator>=(const block_header& other) const
		{
			return get_relative_order(other) >= 0;
		}
		bool block_header::operator==(const block_header& other) const
		{
			return get_relative_order(other) == 0;
		}
		bool block_header::operator!=(const block_header& other) const
		{
			return get_relative_order(other) != 0;
		}
		expects_lr<block_dispatch> block_header::dispatch_sync(const wallet& proposer) const
		{
			size_t offset = 0, count = 512;
			block_dispatch pipeline;
			while (true)
			{
				auto chain = storages::chainstate(__func__);
				auto candidates = chain.get_pending_block_transactions(number, offset, count);
				if (!candidates || candidates->empty())
					break;

				offset += candidates->size();
				for (auto& input : *candidates)
				{
					auto execution = ledger::transaction_context::dispatch_tx(proposer, &input, &pipeline.outputs).get();
					if (!execution)
					{
						if (!execution.error().is_retry() && !execution.error().is_shutdown())
							pipeline.errors[input.receipt.transaction_hash].append(stringify::text("in transaction %s dispatch reverted: %s\n", algorithm::encoding::encode_0xhex256(input.receipt.transaction_hash).c_str(), execution.error().what()));
						else
							pipeline.repeaters.push_back(input.receipt.transaction_hash);
					}
					pipeline.inputs.push_back(input.receipt.transaction_hash);
				}
				if (candidates->size() < count)
					break;
			}

			for (auto& item : pipeline.errors)
				item.second.pop_back();

			return pipeline;
		}
		expects_promise_lr<block_dispatch> block_header::dispatch_async(const wallet& proposer) const
		{
			return coasync<expects_lr<block_dispatch>>([this, proposer]() -> expects_promise_lr<block_dispatch>
			{
				size_t offset = 0, count = 512;
				block_dispatch pipeline;
				while (true)
				{
					auto chain = storages::chainstate(__func__);
					auto candidates = chain.get_pending_block_transactions(number, offset, count);
					if (!candidates || candidates->empty())
						break;

					offset += candidates->size();
					for (auto& input : *candidates)
					{
						auto execution = coawait(ledger::transaction_context::dispatch_tx(proposer, &input, &pipeline.outputs));
						if (!execution)
							pipeline.errors[input.receipt.transaction_hash].append(stringify::text("in transaction %s dispatch reverted: %s\n", algorithm::encoding::encode_0xhex256(input.receipt.transaction_hash).c_str(), execution.error().what()));
						pipeline.inputs.push_back(input.receipt.transaction_hash);
					}
					if (candidates->size() < count)
						break;
				}

				for (auto& item : pipeline.errors)
					item.second.pop_back();

				coreturn pipeline;
			});
		}
		expects_lr<void> block_header::verify_validity(const block_header* parent_block) const
		{
			if (!number || (!parent_hash && number > 1) || (number == 1 && parent_hash > 0))
				return layer_exception("invalid number");

			uint128_t difficulty = target.difficulty();
			if (wesolowski.empty() || difficulty < algorithm::wesolowski::get_default().difficulty())
				return layer_exception("invalid wesolowski target");

			if (!transaction_root || !receipt_root || !state_root)
				return layer_exception("invalid transaction/receipt/state merkle tree root");

			uint256_t gas_work = gas_util::get_gas_work(difficulty, gas_use, gas_limit, priority);
			if (!gas_limit || gas_use > gas_limit || absolute_work < gas_work)
				return layer_exception("invalid gas work");

			if (!transaction_count)
				return layer_exception("invalid transaction count");

			algorithm::pubkeyhash public_key_hash = { 0 };
			if (!recover_hash(public_key_hash))
				return layer_exception("proposer proof verification failed");

			if (!verify_wesolowski())
				return layer_exception("wesolowski proof verification failed");

			if (!parent_block && number > 1)
				return expectation::met;

			if (absolute_work != (parent_block ? parent_block->absolute_work + gas_work : gas_work))
				return layer_exception("invalid absolute gas work");

			uint256_t cumulative = get_slot_length() > 1 ? uint256_t(1) : uint256_t(0);
			if (slot_gas_use != ((parent_block ? parent_block->slot_gas_use : uint256_t(0)) * cumulative + gas_use))
				return layer_exception("invalid slot gas use");

			if (slot_gas_target != ((parent_block ? parent_block->slot_gas_target : uint256_t(0)) * cumulative + (transaction_count > 0 ? gas_use / transaction_count : uint256_t(0))))
				return layer_exception("invalid slot gas target");

			if (slot_duration != ((parent_block ? parent_block->slot_duration + parent_block->get_duration() : uint256_t(0)) * cumulative))
				return layer_exception("invalid slot duration");

			for (auto& witness : witnesses)
			{
				uint64_t expiry_number = algorithm::asset::expiry_of(witness.first);
				if (!expiry_number || number > expiry_number)
					return layer_exception("invalid witness " + algorithm::asset::handle_of(witness.first));
			}

			return expectation::met;
		}
		bool block_header::store_payload_wesolowski(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(parent_hash);
			stream->write_integer(transaction_root);
			stream->write_integer(receipt_root);
			stream->write_integer(state_root);
			stream->write_integer(gas_use);
			stream->write_integer(gas_limit);
			stream->write_integer(absolute_work);
			stream->write_integer(slot_gas_use);
			stream->write_integer(slot_gas_target);
			stream->write_integer(slot_duration);
			stream->write_integer(target.length);
			stream->write_integer(target.bits);
			stream->write_integer(target.pow);
			stream->write_integer(recovery);
			stream->write_integer(time);
			stream->write_integer(priority);
			stream->write_integer(number);
			stream->write_integer(mutation_count);
			stream->write_integer(transaction_count);
			stream->write_integer(state_count);
			stream->write_integer((uint16_t)witnesses.size());
			for (auto& item : witnesses)
			{
				stream->write_integer(item.first);
				stream->write_integer(item.second);
			}
			return true;
		}
		bool block_header::load_payload_wesolowski(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &parent_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_root))
				return false;

			if (!stream.read_integer(stream.read_type(), &receipt_root))
				return false;

			if (!stream.read_integer(stream.read_type(), &state_root))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &absolute_work))
				return false;

			if (!stream.read_integer(stream.read_type(), &slot_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &slot_gas_target))
				return false;

			if (!stream.read_integer(stream.read_type(), &slot_duration))
				return false;

			if (!stream.read_integer(stream.read_type(), &target.length))
				return false;

			if (!stream.read_integer(stream.read_type(), &target.bits))
				return false;

			if (!stream.read_integer(stream.read_type(), &target.pow))
				return false;

			if (!stream.read_integer(stream.read_type(), &recovery))
				return false;

			if (!stream.read_integer(stream.read_type(), &time))
				return false;

			if (!stream.read_integer(stream.read_type(), &priority))
				return false;

			if (!stream.read_integer(stream.read_type(), &number))
				return false;

			if (!stream.read_integer(stream.read_type(), &mutation_count))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_count))
				return false;

			if (!stream.read_integer(stream.read_type(), &state_count))
				return false;

			uint16_t witnesses_size;
			if (!stream.read_integer(stream.read_type(), &witnesses_size))
				return false;

			witnesses.clear();
			for (size_t i = 0; i < witnesses_size; i++)
			{
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				uint64_t block_number;
				if (!stream.read_integer(stream.read_type(), &block_number))
					return false;

				set_witness_requirement(asset, block_number);
			}

			return true;
		}
		bool block_header::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!store_payload_wesolowski(stream))
				return false;

			stream->write_string(wesolowski);
			return true;
		}
		bool block_header::load_payload(format::stream& stream)
		{
			if (!load_payload_wesolowski(stream))
				return false;

			if (!stream.read_string(stream.read_type(), &wesolowski))
				return false;

			return true;
		}
		bool block_header::sign(const algorithm::seckey secret_key)
		{
			format::stream message;
			if (!block_header::store_payload(&message))
				return false;

			return algorithm::signing::sign(message.hash(), secret_key, signature);
		}
		bool block_header::solve(const algorithm::seckey secret_key)
		{
			format::stream message;
			if (!store_payload_wesolowski(&message))
				return false;

			wesolowski = algorithm::wesolowski::evaluate(target, message.data);
			return !wesolowski.empty();
		}
		bool block_header::verify(const algorithm::pubkey public_key) const
		{
			format::stream message;
			if (!block_header::store_payload(&message))
				return false;

			return algorithm::signing::verify(message.hash(), public_key, signature);
		}
		bool block_header::recover(algorithm::pubkey public_key) const
		{
			format::stream message;
			if (!block_header::store_payload(&message))
				return false;

			return algorithm::signing::recover(message.hash(), public_key, signature);
		}
		bool block_header::recover_hash(algorithm::pubkeyhash public_key_hash) const
		{
			format::stream message;
			if (!block_header::store_payload(&message))
				return false;

			return algorithm::signing::recover_hash(message.hash(), public_key_hash, signature);
		}
		bool block_header::verify_wesolowski() const
		{
			format::stream message;
			if (!store_payload_wesolowski(&message))
				return false;

			return algorithm::wesolowski::verify(target, message.data, wesolowski);
		}
		void block_header::set_parent_block(const block_header* parent_block)
		{
			parent_hash = (parent_block ? parent_block->as_hash() : uint256_t(0));
			number = (parent_block ? parent_block->number : 0) + 1;
			time = protocol::now().time.now();
		}
		void block_header::set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number)
		{
			auto& number = witnesses[algorithm::asset::base_id_of(asset)];
			if (number < block_number)
				number = block_number;
		}
		uint64_t block_header::get_witness_requirement(const algorithm::asset_id& asset) const
		{
			auto it = witnesses.find(algorithm::asset::base_id_of(asset));
			return it != witnesses.end() ? it->second : 0;
		}
		int8_t block_header::get_relative_order(const block_header& other) const
		{
			/*
				order priority:
				1. HIGHEST block number
				2. LOWEST  block priority
				3. HIGHEST block cumulative work
				4. HIGHEST block difficulty
				5. HIGHEST block wesolowski number
				6. HIGHEST block gas use
				7. HIGHEST block mutations
				8. LOWEST  block hash
				9. HIGHEST block data (lexicographical order)
			*/
			if (number != other.number)
				return number > other.number ? 1 : -1;

			if (priority != other.priority)
				return priority < other.priority ? 1 : -1;

			if (absolute_work != other.absolute_work)
				return absolute_work > other.absolute_work ? 1 : -1;

			if (recovery != other.recovery)
				return recovery < other.recovery ? 1 : -1;

			uint128_t difficulty_a = target.difficulty();
			uint128_t difficulty_b = other.target.difficulty();
			if (difficulty_a != difficulty_b)
				return difficulty_a > difficulty_b ? 1 : -1;

			int8_t security = algorithm::wesolowski::compare(wesolowski, other.wesolowski);
			if (security != 0)
				return security;

			if (gas_use != other.gas_use)
				return gas_use > other.gas_use ? 1 : -1;

			uint256_t mutations_a = uint256_t(transaction_count) * uint256_t(state_count);
			uint256_t mutations_b = uint256_t(other.transaction_count) * uint256_t(other.state_count);
			if (mutations_a != mutations_b)
				return mutations_a > mutations_b ? 1 : -1;

			uint256_t hash_a = as_hash();
			uint256_t hash_b = other.as_hash();
			if (hash_a == hash_b)
				return 0;

			return hash_a > hash_b ? -1 : 1;
		}
		uint256_t block_header::get_slot_gas_use() const
		{
			return slot_gas_use / get_slot_length();
		}
		uint256_t block_header::get_slot_gas_target() const
		{
			return slot_gas_target / get_slot_length();
		}
		uint64_t block_header::get_slot_duration() const
		{
			return (slot_duration + get_duration()) / get_slot_length();
		}
		uint64_t block_header::get_slot_length() const
		{
			auto interval = algorithm::wesolowski::adjustment_interval();
			return number < interval ? number : ((number % interval) + 1);
		}
		uint64_t block_header::get_duration() const
		{
			uint64_t proof_time = get_proof_time();
			return proof_time > time ? proof_time - time : 0;
		}
		uint64_t block_header::get_proof_time() const
		{
			return algorithm::wesolowski::locktime(wesolowski);
		}
		uptr<schema> block_header::as_schema() const
		{
			algorithm::pubkeyhash proposer = { 0 };
			bool has_proposer = recover_hash(proposer);
			schema* data = var::set::object();
			data->set("wesolowski", var::string(format::util::encode_0xhex(wesolowski)));
			data->set("signature", var::string(format::util::encode_0xhex(std::string_view((char*)signature, sizeof(signature)))));
			data->set("proposer", has_proposer ? algorithm::signing::serialize_address(proposer) : var::set::null());
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("parent_hash", var::string(algorithm::encoding::encode_0xhex256(parent_hash)));
			data->set("transaction_root", var::string(algorithm::encoding::encode_0xhex256(transaction_root)));
			data->set("receipt_root", var::string(algorithm::encoding::encode_0xhex256(receipt_root)));
			data->set("state_root", var::string(algorithm::encoding::encode_0xhex256(state_root)));
			data->set("absolute_work", algorithm::encoding::serialize_uint256(absolute_work));
			data->set("difficulty", algorithm::encoding::serialize_uint256(target.difficulty()));
			data->set("gas_use", algorithm::encoding::serialize_uint256(gas_use));
			data->set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			data->set("slot_gas_use", algorithm::encoding::serialize_uint256(get_slot_gas_use()));
			data->set("slot_gas_target", algorithm::encoding::serialize_uint256(get_slot_gas_target()));
			data->set("slot_duration", algorithm::encoding::serialize_uint256(get_slot_duration()));
			data->set("slot_length", algorithm::encoding::serialize_uint256(get_slot_length()));
			data->set("proposal_time", algorithm::encoding::serialize_uint256(time));
			data->set("approval_time", algorithm::encoding::serialize_uint256(get_proof_time()));
			data->set("wesolowski_time", algorithm::encoding::serialize_uint256(get_duration()));
			data->set("priority", algorithm::encoding::serialize_uint256(priority));
			data->set("number", algorithm::encoding::serialize_uint256(number));
			data->set("recovery", algorithm::encoding::serialize_uint256(recovery));
			data->set("mutation_count", algorithm::encoding::serialize_uint256(mutation_count));
			data->set("transaction_count", algorithm::encoding::serialize_uint256(transaction_count));
			data->set("state_count", algorithm::encoding::serialize_uint256(state_count));
			auto* witnesses_data = data->set("witnesses", var::set::array());
			for (auto& item : witnesses)
			{
				auto* witness_data = witnesses_data->push(var::set::object());
				witness_data->set("asset", algorithm::asset::serialize(item.first));
				witness_data->set("number", algorithm::encoding::serialize_uint256(item.second));
			}
			return data;
		}
		uint256_t block_header::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::stream message;
			((block_header*)this)->checksum = block_header::store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		uint32_t block_header::as_type() const
		{
			return as_instance_type();
		}
		std::string_view block_header::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t block_header::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view block_header::as_instance_typename()
		{
			return "block";
		}
		uint256_t block_header::get_gas_limit()
		{
			static uint256_t limit = transactions::transfer().get_gas_estimate() * (uint64_t)std::ceil((double)protocol::now().policy.consensus_proof_time * (double)protocol::now().policy.transaction_throughput / 1000.0);
			return limit;
		}

		block::block(const block_header& other) : block_header(other)
		{
		}
		expects_lr<void> block::evaluate(const block_header* parent_block, evaluation_context* environment, string* errors)
		{
			VI_ASSERT(environment != nullptr, "evaluation context should be set");
			if (environment->incoming.empty())
				return layer_exception("empty block is not valid");

			block_header::set_parent_block(parent_block);
			auto position = std::find_if(environment->proposers.begin(), environment->proposers.end(), [&environment](const states::account_work& a) { return !memcmp(a.owner, environment->proposer.public_key_hash, sizeof(environment->proposer.public_key_hash)); });
			auto prev_duration = parent_block ? parent_block->get_slot_duration() : (uint64_t)((double)protocol::now().policy.consensus_proof_time * protocol::now().policy.genesis_slot_time_bump);
			auto prev_target = parent_block ? parent_block->target : algorithm::wesolowski::get_default();
			if (parent_block && parent_block->recovery)
				prev_target = algorithm::wesolowski::bump(target, 1.0 / protocol::now().policy.consensus_recovery_bump);

			recovery = (position == environment->proposers.end() ? 1 : 0);
			priority = recovery ? 0 : (uint64_t)std::distance(environment->proposers.begin(), position);
			target = algorithm::wesolowski::adjust(prev_target, prev_duration, number);
			if (recovery)
				target = algorithm::wesolowski::bump(target, protocol::now().policy.consensus_recovery_bump);

			block_work cache;
			for (auto& item : environment->incoming)
			{
				auto execution = transaction_context::execute_tx(this, environment, *item.candidate, item.hash, item.owner, cache, item.size, item.candidate->conservative ? 0 : (uint8_t)transaction_context::execution_flags::only_successful);
				if (execution)
				{
					auto& blob = transactions.emplace_back();
					blob.transaction = std::move(item.candidate);
					blob.receipt = std::move(execution->receipt);
					states.commit();
				}
				else
				{
					if (errors != nullptr)
						errors->append(stringify::text("\n  in transaction %s execution error: %s", algorithm::encoding::encode_0xhex256(item.hash).c_str(), execution.error().what()));
					environment->outgoing.push_back(item.hash);
				}
			}

			if (transactions.empty())
			{
				if (!errors)
					return layer_exception("block does not have any valid transaction");
				else if (errors->empty())
					errors->assign("\n  block does not have any valid transactions");

				return layer_exception(string(*errors));
			}

			size_t participants = (size_t)(priority + 1);
			uint256_t gas_penalty = participants > 0 ? (gas_use / participants) : uint256_t(0);
			for (size_t i = 0; i < participants; i++)
			{
				bool winner = (i == priority);
				auto& participant = environment->proposers[i];
				auto work = winner ? environment->validation.context.apply_account_work(participant.owner, participant.is_matching(states::account_flags::online) ? states::account_flags::as_is : states::account_flags::online, 0, gas_use, 0) : environment->validation.context.apply_account_work(participant.owner, states::account_flags::offline, 1, 0, gas_penalty);
				if (!work)
					return work.error();
			}

			states.commit();
			recalculate(parent_block);
			return expectation::met;
		}
		expects_lr<void> block::validate(const block_header* parent_block, block* evaluated_block) const
		{
			if (parent_block && (parent_block->number != number - 1 || parent_block->as_hash() != parent_hash))
				return layer_exception("invalid parent block");

			algorithm::pubkeyhash proposer = { 0 };
			if (!recover_hash(proposer))
				return layer_exception("invalid proposer signature");

			evaluation_context environment;
			if (!environment.priority(proposer, nullptr, option<block_header*>((block_header*)parent_block)))
			{
				if (!recovery)
					return layer_exception("invalid proposer election");

				auto prev_duration = parent_block ? parent_block->get_slot_duration() : (uint64_t)((double)protocol::now().policy.consensus_proof_time * protocol::now().policy.genesis_slot_time_bump);
				auto prev_target = parent_block ? parent_block->target : algorithm::wesolowski::get_default();
				if (parent_block && parent_block->recovery)
					prev_target = algorithm::wesolowski::bump(target, 1.0 / protocol::now().policy.consensus_recovery_bump);

				auto candidate_target = algorithm::wesolowski::bump(algorithm::wesolowski::adjust(prev_target, prev_duration, number), protocol::now().policy.consensus_recovery_bump);
				if (target.difficulty() != candidate_target.difficulty())
					return layer_exception("invalid proposer election");
			}

			unordered_map<uint256_t, std::pair<const block_transaction*, const evaluation_context::transaction_info*>> childs;
			environment.incoming.reserve(transactions.size());
			for (auto& transaction : transactions)
			{
				if (!transaction.transaction)
					return layer_exception("invalid transaction included in a block");

				auto& info = environment.include(transactions::resolver::copy(*transaction.transaction));
				childs[transaction.receipt.transaction_hash] = std::make_pair(&transaction, (const evaluation_context::transaction_info*)&info);
			}

			auto evaluation = environment.evaluate();
			if (!evaluation)
				return evaluation.error();

			auto& result = *evaluation;
			for (auto& transaction : result.transactions)
			{
				auto it = childs.find(transaction.receipt.transaction_hash);
				if (it == childs.end())
					return layer_exception("transaction " + algorithm::encoding::encode_0xhex256(transaction.receipt.transaction_hash) + " not found in block");

				auto& child = it->second;
				if (memcmp(transaction.receipt.from, child.second->owner, sizeof(child.second->owner)) != 0)
					return layer_exception("transaction " + algorithm::encoding::encode_0xhex256(transaction.receipt.transaction_hash) + " public key recovery failed");

				transaction.receipt.generation_time = child.first->receipt.generation_time;
				transaction.receipt.finalization_time = child.first->receipt.finalization_time;
				transaction.receipt.checksum = 0;
			}

			memcpy(result.signature, signature, sizeof(signature));
			result.wesolowski = wesolowski;
			result.time = time;
			result.recalculate(parent_block);

			block_header input = *this, output = result;
			if (input.as_message().data != output.as_message().data)
				return layer_exception("resulting block deviates from pre-computed block");

			auto validity = result.verify_validity(parent_block);
			if (!validity)
				return validity;

			auto integrity = result.verify_integrity(parent_block);
			if (!integrity)
				return integrity;

			if (evaluated_block != nullptr)
				*evaluated_block = std::move(result);

			return expectation::met;
		}
		expects_lr<void> block::verify_integrity(const block_header* parent_block) const
		{
			if (transactions.empty() || transaction_count != (uint32_t)transactions.size())
				return layer_exception("invalid transactions count");
			else if (!state_count || state_count != (uint32_t)states.at(work_commitment::finalized).size())
				return layer_exception("invalid states count");

			if (!parent_block && number > 1)
				return expectation::met;

			algorithm::merkle_tree tree = (parent_block ? parent_block->transaction_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.transaction_hash);
			if (tree.calculate_root() != transaction_root)
				return layer_exception("invalid transactions merkle tree root");

			tree = (parent_block ? parent_block->receipt_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.as_hash());
			if (tree.calculate_root() != receipt_root)
				return layer_exception("invalid receipts merkle tree root");

			tree = (parent_block ? parent_block->state_root : uint256_t(0));
			for (auto& item : states.at(work_commitment::finalized))
				tree.push(item.second->as_hash());
			if (tree.calculate_root() != state_root)
				return layer_exception("invalid states merkle tree root");

			return expectation::met;
		}
		expects_lr<block_checkpoint> block::checkpoint(bool keep_reverted_transactions) const
		{
			auto chain = storages::chainstate(__func__);
			auto chain_session = chain.multi_tx_begin("chainwork", "apply", sqlite::isolation::placeholder);
			if (!chain_session)
				return layer_exception(std::move(chain_session.error().message()));

			unordered_set<uint256_t> finalized_transactions;
			finalized_transactions.reserve(transactions.size());
			for (auto& transaction : transactions)
				finalized_transactions.insert(transaction.receipt.transaction_hash);

			block_checkpoint mutation;
			mutation.old_tip_block_number = chain.get_latest_block_number().otherwise(0);
			mutation.new_tip_block_number = number;
			mutation.block_delta = 1;
			mutation.transaction_delta = transaction_count;
			mutation.state_delta = state_count;
			mutation.is_fork = mutation.old_tip_block_number > 0 && mutation.old_tip_block_number >= mutation.new_tip_block_number;
			if (mutation.is_fork)
			{
				if (keep_reverted_transactions)
				{
					auto mempool = storages::mempoolstate(__func__);
					auto mempool_session = mempool.tx_begin("mempoolwork", "apply", sqlite::isolation::placeholder);
					if (!mempool_session)
					{
						chain.multi_tx_rollback("chainwork", "apply");
						return layer_exception(std::move(mempool_session.error().message()));
					}

					uint64_t revert_number = mutation.old_tip_block_number;
					while (revert_number >= mutation.new_tip_block_number)
					{
						size_t offset = 0, count = 512;
						while (true)
						{
							auto transactions = chain.get_transactions_by_number(revert_number, offset, count);
							if (!transactions || transactions->empty())
								break;

							for (auto& item : *transactions)
							{
								if (finalized_transactions.find(item->as_hash()) == finalized_transactions.end())
								{
									auto status = mempool.add_transaction(**item, true);
									status.report("transaction resurrection failed");
									mutation.mempool_transactions += status ? 1 : 0;
								}
							}

							offset += transactions->size();
							if (transactions->size() < count)
								break;
						}
						--revert_number;
					}

					auto status = chain.revert(mutation.new_tip_block_number - 1, &mutation.block_delta, &mutation.transaction_delta, &mutation.state_delta);
					if (!status)
					{
						chain.multi_tx_rollback("chainwork", "apply");
						mempool.tx_rollback("mempoolwork", "apply");
						return status.error();
					}

					if (protocol::now().user.storage.logging)
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", mempool: +%" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(as_hash()).c_str(), mutation.new_tip_block_number, mutation.mempool_transactions, mutation.block_delta, mutation.transaction_delta, mutation.state_delta);

					status = chain.checkpoint(*this);
					if (!status)
					{
						chain.multi_tx_rollback("chainwork", "apply");
						mempool.tx_rollback("mempoolwork", "apply");
						return status.error();
					}

					auto result = chain.multi_tx_commit("chainwork", "apply");
					if (!result)
					{
						mempool.tx_rollback("mempoolwork", "apply");
						return layer_exception(std::move(result.error().message()));
					}

					mempool.remove_transactions(finalized_transactions).report("mempool cleanup failed");
					mempool.tx_commit("mempoolwork", "apply").report("mempool commit failed");
				}
				else
				{
					auto status = chain.revert(mutation.new_tip_block_number - 1, &mutation.block_delta, &mutation.transaction_delta, &mutation.state_delta);
					if (!status)
					{
						chain.multi_tx_rollback("chainwork", "apply");
						return status.error();
					}

					if (protocol::now().user.storage.logging)
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(as_hash()).c_str(), mutation.new_tip_block_number, mutation.block_delta, mutation.transaction_delta, mutation.state_delta);

					status = chain.checkpoint(*this);
					if (!status)
					{
						chain.multi_tx_rollback("chainwork", "apply");
						return status.error();
					}

					auto result = chain.multi_tx_commit("chainwork", "apply");
					if (!result)
						return layer_exception(std::move(result.error().message()));
				}
			}
			else
			{
				auto status = chain.checkpoint(*this);
				if (!status)
				{
					chain.multi_tx_rollback("chainwork", "apply");
					return status.error();
				}

				auto result = chain.multi_tx_commit("chainwork", "apply");
				if (!result)
					return layer_exception(std::move(result.error().message()));

				auto mempool = storages::mempoolstate(__func__);
				mempool.remove_transactions(finalized_transactions).report("mempool cleanup failed");
			}
			return mutation;
		}
		bool block::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!store_header_payload(stream))
				return false;

			if (!store_body_payload(stream))
				return false;

			return true;
		}
		bool block::load_payload(format::stream& stream)
		{
			if (!load_header_payload(stream))
				return false;

			if (!load_body_payload(stream))
				return false;

			return true;
		}
		bool block::store_header_payload(format::stream* stream) const
		{
			return block_header::store_payload(stream);
		}
		bool block::load_header_payload(format::stream& stream)
		{
			return block_header::load_payload(stream);
		}
		bool block::store_body_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint32_t)transactions.size());
			for (auto& item : transactions)
				item.store_payload(stream);

			stream->write_integer((uint32_t)states.at(work_commitment::finalized).size());
			for (auto& item : states.at(work_commitment::finalized))
				item.second->store(stream);
			return true;
		}
		bool block::load_body_payload(format::stream& stream)
		{
			uint32_t transactions_size;
			if (!stream.read_integer(stream.read_type(), &transactions_size))
				return false;

			transactions.clear();
			transactions.reserve(transactions_size);
			for (size_t i = 0; i < transactions_size; i++)
			{
				block_transaction value;
				if (!value.load_payload(stream))
					return false;

				transactions.emplace_back(std::move(value));
			}

			uint32_t states_size;
			if (!stream.read_integer(stream.read_type(), &states_size))
				return false;

			states.clear();
			for (size_t i = 0; i < states_size; i++)
			{
				uptr<ledger::state> value = states::resolver::init(messages::standard::resolve_type(stream).otherwise(0));
				if (!value || !value->load(stream))
					return false;

				states.move_any(std::move(value));
			}

			states.commit();
			return true;
		}
		void block::recalculate(const block_header* parent_block)
		{
			auto& state_tree = states.at(work_commitment::finalized);
			auto task_queue1 = parallel::for_each_sequential(state_tree.begin(), state_tree.end(), state_tree.size(), ELEMENTS_FEW, [](const std::pair<const string, uptr<ledger::state>>& item) { item.second->as_hash(); });
			auto task_queue2 = parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [](block_transaction& item) { item.receipt.as_hash(); });
			parallel::wail_all(std::move(task_queue1));
			parallel::wail_all(std::move(task_queue2));

			algorithm::merkle_tree tree = (parent_block ? parent_block->transaction_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.transaction_hash);
			transaction_root = tree.calculate_root();

			tree = (parent_block ? parent_block->receipt_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.as_hash());
			receipt_root = tree.calculate_root();

			tree = (parent_block ? parent_block->state_root : uint256_t(0));
			for (auto& item : state_tree)
				tree.push(item.second->as_hash());
			state_root = tree.calculate_root();

			uint256_t cumulative = get_slot_length() > 1 ? 1 : 0;
			absolute_work = (parent_block ? parent_block->absolute_work : uint256_t(0)) + gas_util::get_gas_work(target.difficulty(), gas_use, gas_limit, priority);
			slot_gas_use = (parent_block ? parent_block->slot_gas_use : uint256_t(0)) * cumulative + gas_use;
			slot_gas_target = (parent_block ? parent_block->slot_gas_target : uint256_t(0)) * cumulative + (transactions.size() > 0 ? gas_use / transactions.size() : uint256_t(0));
			slot_duration = (parent_block ? parent_block->slot_duration + parent_block->get_duration() : uint256_t(0)) * cumulative;
			transaction_count = (uint32_t)transactions.size();
			state_count = (uint32_t)state_tree.size();
		}
		void block::inherit_work(const block* parent_block)
		{
			states.parent_work = parent_block ? &parent_block->states : nullptr;
		}
		void block::inherit_work(const block_work* parent_work)
		{
			states.parent_work = parent_work;
		}
		uptr<schema> block::as_schema() const
		{
			schema* data = block_header::as_schema().reset();
			auto* transactions_data = data->set("transactions", var::set::array());
			for (auto& item : transactions)
				transactions_data->push(item.as_schema().reset());
			auto* states_data = data->set("states", var::set::array());
			for (auto& item : states.at(work_commitment::finalized))
				states_data->push(item.second->as_schema().reset());
			return data;
		}
		block_header block::as_header() const
		{
			return block_header(*this);
		}
		block_proof block::as_proof(const block_header* parent_block) const
		{
			auto proof = block_proof(*this, parent_block);
			proof.transactions.reserve(transactions.size());
			proof.receipts.reserve(transactions.size());
			for (auto& item : transactions)
			{
				proof.transactions.push_back(item.receipt.transaction_hash);
				proof.receipts.push_back(item.receipt.as_hash());
			}

			proof.states.reserve(states.at(work_commitment::finalized).size());
			for (auto& item : states.at(work_commitment::finalized))
				proof.states.push_back(item.second->as_hash());

			return proof;
		}
		uint256_t block::as_hash(bool renew) const
		{
			return as_header().as_hash(renew);
		}

		block_proof::block_proof(const block_header& from_block, const block_header* from_parent_block)
		{
			internal.transactions_tree = algorithm::merkle_tree(from_parent_block ? from_parent_block->transaction_root : uint256_t(0));
			internal.receipts_tree = algorithm::merkle_tree(from_parent_block ? from_parent_block->receipt_root : uint256_t(0));
			internal.states_tree = algorithm::merkle_tree(from_parent_block ? from_parent_block->state_root : uint256_t(0));
			transaction_root = from_block.transaction_root;
			receipt_root = from_block.receipt_root;
			state_root = from_block.state_root;
		}
		option<algorithm::merkle_tree::path> block_proof::find_transaction(const uint256_t& hash)
		{
			auto path = get_transactions_tree().calculate_path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		option<algorithm::merkle_tree::path> block_proof::find_receipt(const uint256_t& hash)
		{
			auto path = get_receipts_tree().calculate_path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		option<algorithm::merkle_tree::path> block_proof::find_state(const uint256_t& hash)
		{
			auto path = get_states_tree().calculate_path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		bool block_proof::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(transaction_root);
			stream->write_integer((uint32_t)transactions.size());
			for (auto& item : transactions)
				stream->write_integer(item);

			stream->write_integer(receipt_root);
			stream->write_integer((uint32_t)receipts.size());
			for (auto& item : receipts)
				stream->write_integer(item);

			stream->write_integer(state_root);
			stream->write_integer((uint32_t)states.size());
			for (auto& item : states)
				stream->write_integer(item);

			return true;
		}
		bool block_proof::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &transaction_root))
				return false;

			uint32_t transactions_size;
			if (!stream.read_integer(stream.read_type(), &transactions_size))
				return false;

			transactions.resize(transactions_size);
			for (size_t i = 0; i < transactions_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &transactions[i]))
					return false;
			}

			if (!stream.read_integer(stream.read_type(), &receipt_root))
				return false;

			uint32_t receipts_size;
			if (!stream.read_integer(stream.read_type(), &receipts_size))
				return false;

			receipts.resize(receipts_size);
			for (size_t i = 0; i < receipts_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &receipts[i]))
					return false;
			}

			if (!stream.read_integer(stream.read_type(), &state_root))
				return false;

			uint32_t states_size;
			if (!stream.read_integer(stream.read_type(), &states_size))
				return false;

			states.resize(states_size);
			for (size_t i = 0; i < states_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &states[i]))
					return false;
			}

			return true;
		}
		bool block_proof::has_transaction(const uint256_t& hash)
		{
			auto path = find_transaction(hash);
			return path && path->calculate_root(hash) == transaction_root;
		}
		bool block_proof::has_receipt(const uint256_t& hash)
		{
			auto path = find_receipt(hash);
			return path && path->calculate_root(hash) == receipt_root;
		}
		bool block_proof::has_state(const uint256_t& hash)
		{
			auto path = find_state(hash);
			return path && path->calculate_root(hash) == state_root;
		}
		algorithm::merkle_tree& block_proof::get_transactions_tree()
		{
			if (!internal.transactions_tree.is_calculated() || internal.transactions_tree.get_tree().size() < transactions.size())
			{
				for (auto& item : transactions)
					internal.transactions_tree.push(item);
			}
			return internal.transactions_tree.calculate();
		}
		algorithm::merkle_tree& block_proof::get_receipts_tree()
		{
			if (!internal.receipts_tree.is_calculated() || internal.receipts_tree.get_tree().size() < receipts.size())
			{
				for (auto& item : receipts)
					internal.receipts_tree.push(item);
			}
			return internal.receipts_tree.calculate();
		}
		algorithm::merkle_tree& block_proof::get_states_tree()
		{
			if (!internal.states_tree.is_calculated() || internal.states_tree.get_tree().size() < states.size())
			{
				for (auto& item : states)
					internal.states_tree.push(item);
			}
			return internal.states_tree.calculate();
		}
		uptr<schema> block_proof::as_schema() const
		{
			schema* data = var::set::object();
			auto* transactions_data = data->set("transactions", var::set::object());
			auto* transactions_hashes = transactions_data->set("hashes", var::set::array());
			auto* transactions_tree = transactions_data->set("tree", var::set::array());
			transactions_data->set("root", var::string(algorithm::encoding::encode_0xhex256(transaction_root)));
			if (internal.transactions_tree.get_tree().empty())
			{
				for (auto& item : transactions)
					transactions_hashes->push(var::string(algorithm::encoding::encode_0xhex256(item)));
			}
			else
				transactions_hashes->value = var::integer(transactions.size());
			for (auto& item : internal.transactions_tree.get_tree())
				transactions_tree->push(var::string(algorithm::encoding::encode_0xhex256(item)));

			auto* receipts_data = data->set("receipts", var::set::object());
			auto* receipts_hashes = receipts_data->set("hashes", var::set::array());
			auto* receipts_tree = receipts_data->set("tree", var::set::array());
			receipts_data->set("root", var::string(algorithm::encoding::encode_0xhex256(receipt_root)));
			if (internal.receipts_tree.get_tree().empty())
			{
				for (auto& item : receipts)
					receipts_hashes->push(var::string(algorithm::encoding::encode_0xhex256(item)));
			}
			else
				receipts_hashes->value = var::integer(receipts.size());
			for (auto& item : internal.receipts_tree.get_tree())
				receipts_tree->push(var::string(algorithm::encoding::encode_0xhex256(item)));

			auto* states_data = data->set("states", var::set::object());
			auto* states_hashes = states_data->set("hashes", var::set::array());
			auto* states_tree = states_data->set("tree", var::set::array());
			states_data->set("root", var::string(algorithm::encoding::encode_0xhex256(state_root)));
			if (internal.states_tree.get_tree().empty())
			{
				for (auto& item : states)
					states_hashes->push(var::string(algorithm::encoding::encode_0xhex256(item)));
			}
			else
				states_hashes->value = var::integer(states.size());
			for (auto& item : internal.states_tree.get_tree())
				states_tree->push(var::string(algorithm::encoding::encode_0xhex256(item)));
			return data;
		}
		uint32_t block_proof::as_type() const
		{
			return as_instance_type();
		}
		std::string_view block_proof::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t block_proof::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view block_proof::as_instance_typename()
		{
			return "block_proof";
		}

		transaction_context::transaction_context() : environment(nullptr), transaction(nullptr), block(nullptr)
		{
		}
		transaction_context::transaction_context(ledger::block* new_block) : environment(nullptr), transaction(nullptr), block(new_block)
		{
			if (new_block)
				delta.outgoing = &new_block->states;
		}
		transaction_context::transaction_context(ledger::block_header* new_block_header) : environment(nullptr), transaction(nullptr), block(new_block_header)
		{
		}
		transaction_context::transaction_context(ledger::block* new_block, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt) : environment(new_environment), transaction(new_transaction), block(new_block), receipt(std::move(new_receipt))
		{
			if (new_block)
				delta.outgoing = &new_block->states;
		}
		transaction_context::transaction_context(ledger::block_header* new_block_header, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt) : environment(new_environment), transaction(new_transaction), block(new_block_header), receipt(std::move(new_receipt))
		{
		}
		transaction_context::transaction_context(const transaction_context& other) : delta(other.delta), environment(other.environment), receipt(other.receipt), block(other.block)
		{
			transaction = other.transaction ? transactions::resolver::copy(other.transaction) : nullptr;
		}
		transaction_context& transaction_context::operator=(const transaction_context& other)
		{
			if (this == &other)
				return *this;

			delta = other.delta;
			environment = other.environment;
			transaction = other.transaction ? transactions::resolver::copy(other.transaction) : nullptr;
			receipt = other.receipt;
			block = other.block;
			return *this;
		}
		expects_lr<void> transaction_context::load(state* next, bool paid)
		{
			if (!next)
				return layer_exception("state not found");
			else if (!paid)
				return expectation::met;

			return burn_gas(next->as_message().data.size() * (size_t)gas_cost::read_byte);
		}
		expects_lr<void> transaction_context::store(state* next, bool paid)
		{
			if (!next)
				return layer_exception("invalid state");

			if (block != nullptr)
			{
				next->block_number = block->number;
				next->block_nonce = block->mutation_count++;
			}

			if (!next->block_number)
				return layer_exception("invalid state block number");
			else if (!delta.outgoing)
				return layer_exception("invalid state delta");

			auto chain = storages::chainstate(__func__);
			switch (next->as_level())
			{
				case state_level::uniform:
				{
					auto* state = (uniform*)next;
					auto prev = chain.get_uniform_by_index(&delta, state->as_index(), get_validation_nonce());
					auto status = state->transition(this, prev ? **prev : nullptr);
					if (!status)
						return status;
					break;
				}
				case state_level::multiform:
				{
					auto* state = (multiform*)next;
					auto prev = chain.get_multiform_by_composition(&delta, state->as_column(), state->as_row(), get_validation_nonce());
					auto status = state->transition(this, prev ? **prev : nullptr);
					if (!status)
						return status;
					break;
				}
				default:
					return layer_exception("invalid state level");
			}

			if (paid)
			{
				auto status = burn_gas(next->as_message().data.size() * (size_t)gas_cost::write_byte);
				if (!status)
					return status;
			}

			delta.outgoing->copy_any(next);
			return expectation::met;
		}
		expects_lr<void> transaction_context::emit_witness(const algorithm::asset_id& asset, uint64_t block_number)
		{
			if (!asset || !block_number)
				return layer_exception("invalid witness");

			auto& current_number = witnesses[algorithm::asset::base_id_of(asset)];
			if (current_number < block_number)
				current_number = block_number;

			return expectation::met;
		}
		expects_lr<void> transaction_context::emit_event(uint32_t event, format::variables&& values, bool paid)
		{
			if (paid)
			{
				format::stream stream;
				format::variables_util::serialize_merge_into(values, &stream);
				stream.write_integer(event);

				auto status = burn_gas(stream.data.size() * (size_t)gas_cost::write_byte);
				if (!status)
					return status;
			}
			receipt.emit_event(event, std::move(values));
			return expectation::met;
		}
		expects_lr<void> transaction_context::burn_gas()
		{
			if (!transaction)
				return expectation::met;

			return burn_gas(transaction->gas_limit - receipt.relative_gas_use);
		}
		expects_lr<void> transaction_context::burn_gas(const uint256_t& value)
		{
			if (!transaction)
				return expectation::met;

			receipt.relative_gas_use += value;
			if (receipt.relative_gas_use <= transaction->gas_limit)
				return expectation::met;

			receipt.relative_gas_use = transaction->gas_limit;
			return layer_exception("ran out of gas");
		}
		expects_lr<void> transaction_context::verify_account_sequence() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			auto current_sequence = get_account_sequence(receipt.from);
			if (current_sequence && current_sequence->sequence > transaction->sequence)
				return layer_exception("sequence is invalid (now: " + to_string(current_sequence->sequence) + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_gas_transfer_balance() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			if (!transaction->gas_price.is_positive())
				return expectation::met;

			auto asset = transaction->get_gas_asset();
			auto current_balance = get_account_balance(asset, receipt.from);
			decimal max_paid_value = transaction->gas_price * transaction->gas_limit.to_decimal();
			decimal max_payable_value = current_balance ? current_balance->get_balance() : decimal::zero();
			if (max_payable_value < max_paid_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient (balance: " + max_payable_value.to_string() + ", value: " + max_paid_value.to_string() + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_transfer_balance(const algorithm::asset_id& asset, const decimal& value) const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			decimal max_paid_value = value;
			if (!max_paid_value.is_positive())
				return expectation::met;

			auto current_balance = get_account_balance(asset, receipt.from);
			decimal max_payable_value = current_balance ? current_balance->get_balance() : decimal::zero();
			if (max_payable_value < max_paid_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient (balance: " + max_payable_value.to_string() + ", value: " + max_paid_value.to_string() + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_account_work(const algorithm::pubkeyhash owner) const
		{
			if (!environment)
				return layer_exception("invalid evaluation context");

			auto current_work = get_account_work(owner);
			uint256_t current_gas_work = current_work ? current_work->get_gas_use() : uint256_t(0);
			uint256_t current_gas_requirement = states::account_work::get_gas_work_required(block, current_gas_work);
			if (current_gas_requirement > 0)
				return layer_exception("account work is insufficient (work: " + current_gas_work.to_string() + ", value: " + current_gas_requirement.to_string() + ")");
			else if (current_work && current_work->is_matching(states::account_flags::outlaw))
				return layer_exception("account is outlaw");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_account_depository_work(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			if (!environment)
				return layer_exception("invalid evaluation context");

			auto current_work = get_account_work(owner);
			uint256_t current_gas_work = current_work ? current_work->get_gas_use() : uint256_t(0);
			uint256_t current_gas_requirement = states::account_work::get_gas_work_required(block, current_gas_work);
			if (current_gas_requirement > 0)
				return layer_exception("account work is insufficient (work: " + current_gas_work.to_string() + ", value: " + current_gas_requirement.to_string() + ")");
			else if (current_work && current_work->is_matching(states::account_flags::outlaw))
				return layer_exception("account is outlaw");

			auto current_depository = get_account_depository(asset, owner);
			auto current_coverage = current_depository ? current_depository->get_coverage(current_work ? current_work->flags : 0) : decimal::zero();
			if (current_coverage.is_negative())
				return layer_exception("account depository contribution is too low (coverage: " + current_coverage.to_string() + ")");

			return expectation::met;
		}
		expects_lr<algorithm::wesolowski::distribution> transaction_context::calculate_random(const uint256_t& seed)
		{
			if (!block)
				return layer_exception("block not found");

			format::stream message;
			message.write_typeless(block->parent_hash);
			message.write_typeless(block->recovery);
			message.write_typeless(block->priority);
			message.write_typeless(block->target.difficulty());
			message.write_typeless(block->mutation_count);
			message.write_typeless(receipt.relative_gas_use);
			message.write_typeless(seed);

			algorithm::wesolowski::distribution distribution;
			distribution.signature = message.data;
			distribution.value = algorithm::hashing::hash256i(*crypto::hash_raw(digests::SHA512(), distribution.signature));
			return distribution;
		}
		expects_lr<size_t> transaction_context::calculate_aggregation_committee_size(const algorithm::asset_id& asset)
		{
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::equal(1, 1);
			return chain.get_multiforms_count_by_row_filter(states::account_observer::as_instance_row(asset), filter, nonce);
		}
		expects_lr<vector<states::account_work>> transaction_context::calculate_proposal_committee(size_t target_size)
		{
			auto random = calculate_random(0);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto window = storages::factor_index_window();
			auto pool = chain.get_multiforms_count_by_row_filter(states::account_work::as_instance_row(), filter, nonce).otherwise(0);
			auto size = std::min(target_size, pool);
			auto indices = ordered_set<size_t>();
			while (indices.size() < size)
			{
				size_t index = exponential_range_distribution(random->derive(), size);
				if (indices.find(index) == indices.end())
				{
					window.indices.push_back(index);
					indices.insert(index);
				}
			}

			auto results = chain.get_multiforms_by_row_filter(&delta, states::account_work::as_instance_row(), filter, nonce, window);
			if (!results || results->empty())
				return layer_exception("committee threshold not met");

			vector<states::account_work> committee;
			committee.reserve(results->size());
			for (auto& result : *results)
			{
				auto& work = *(states::account_work*)*result;
				committee.emplace_back(std::move(work));
			}

			if (committee.size() >= target_size)
				std::sort(committee.begin(), committee.end(), [](const states::account_work& a, const states::account_work& b) { return a.get_gas_use() > b.get_gas_use(); });

			return committee;
		}
		expects_lr<vector<states::account_work>> transaction_context::calculate_sharing_committee(ordered_set<string>& hashset, size_t required_size)
		{
			auto random = calculate_random(1);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::account_work::as_instance_row(), filter, nonce).otherwise(0);
			if (pool < required_size)
				return layer_exception("committee threshold not met");

			vector<states::account_work> committee;
			auto indices = ordered_set<size_t>();
			while (indices.size() < pool)
			{
				auto window = storages::factor_index_window();
				auto prefetch = std::min<size_t>(std::max<size_t>(32, required_size), pool);
				while (window.indices.size() < prefetch)
				{
					size_t index = exponential_range_distribution(random->derive(), pool);
					if (indices.find(index) == indices.end())
					{
						window.indices.push_back(index);
						indices.insert(index);
					}
				}

				auto results = chain.get_multiforms_by_row_filter(&delta, states::account_work::as_instance_row(), filter, nonce, window);
				if (!results || results->empty())
					break;

				for (auto& result : *results)
				{
					auto& work = *(states::account_work*)*result;
					auto hash = string((char*)work.owner, sizeof(work.owner));
					if (hashset.find(hash) != hashset.end() || !verify_account_work(work.owner))
						continue;

					hashset.insert(std::move(hash));
					committee.push_back(std::move(work));
					if (committee.size() >= required_size)
						break;
				}

				if (committee.size() >= required_size)
					break;
			}

			if (committee.size() < required_size)
				return layer_exception("committee threshold not met");

			return committee;
		}
		expects_lr<states::account_sequence> transaction_context::apply_account_sequence(const algorithm::pubkeyhash owner, uint64_t sequence)
		{
			states::account_sequence new_state = states::account_sequence(owner, block);
			new_state.sequence = sequence;

			auto status = store(&new_state, false);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_work> transaction_context::apply_account_work(const algorithm::pubkeyhash owner, states::account_flags flags, uint64_t penalty, const uint256_t& gas_input, const uint256_t& gas_output)
		{
			states::account_work new_state = states::account_work(owner, block);
			new_state.gas_input = gas_input;
			new_state.gas_output = gas_output;
			new_state.flags = (uint8_t)flags;
			if (penalty > 0)
				new_state.penalty = (block ? block->number : 0) + penalty * (protocol::now().policy.consensus_penalty_point_time / protocol::now().policy.consensus_proof_time);

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_observer> transaction_context::apply_account_observer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, bool observing)
		{
			states::account_observer new_state = states::account_observer(owner, block);
			new_state.asset = asset;
			new_state.observing = observing;

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_program> transaction_context::apply_account_program(const algorithm::pubkeyhash owner, const std::string_view& program_hashcode)
		{
			states::account_program new_state = states::account_program(owner, block);
			new_state.hashcode = program_hashcode;

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_storage> transaction_context::apply_account_storage(const algorithm::pubkeyhash owner, const std::string_view& location, const std::string_view& storage)
		{
			states::account_storage new_state = states::account_storage(owner, block);
			new_state.location = location;
			new_state.storage = storage;

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_reward> transaction_context::apply_account_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& incoming_absolute_fee, const decimal& incoming_relative_fee, const decimal& outgoing_absolute_fee, const decimal& outgoing_relative_fee)
		{
			states::account_reward new_state = states::account_reward(owner, block);
			new_state.incoming_absolute_fee = incoming_absolute_fee;
			new_state.incoming_relative_fee = incoming_relative_fee;
			new_state.outgoing_absolute_fee = outgoing_absolute_fee;
			new_state.outgoing_relative_fee = outgoing_relative_fee;
			new_state.asset = asset;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_derivation> transaction_context::apply_account_derivation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, uint64_t max_address_index)
		{
			states::account_derivation new_state = states::account_derivation(owner, block);
			new_state.asset = asset;
			new_state.max_address_index = max_address_index;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_depository> transaction_context::apply_account_depository_custody(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& custody)
		{
			states::account_depository new_state = states::account_depository(owner, block);
			new_state.asset = asset;
			new_state.custody = custody.is_nan() ? decimal::zero() : custody;

			auto old_state = get_account_depository(asset, owner);
			if (old_state)
			{
				new_state.contributions = std::move(old_state->contributions);
				new_state.reservations = std::move(old_state->reservations);
				new_state.transactions = std::move(old_state->transactions);
				new_state.custody += old_state->custody;
			}

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::account_depository>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(custody) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_depository> transaction_context::apply_account_depository_change(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& custody, address_value_map&& contributions, account_value_map&& reservations)
		{
			states::account_depository new_state = states::account_depository(owner, block);
			new_state.asset = asset;
			new_state.custody = custody.is_nan() ? decimal::zero() : custody;
			new_state.contributions = std::move(contributions);
			new_state.reservations = std::move(reservations);

			auto old_state = get_account_depository(asset, owner);
			if (old_state)
			{
				new_state.transactions = std::move(old_state->transactions);
				new_state.custody += old_state->custody;

				for (auto& item : old_state->reservations)
				{
					auto& reservation = new_state.reservations[item.first];
					reservation = reservation.is_nan() ? item.second : reservation + item.second;
				}

				for (auto& item : old_state->contributions)
				{
					auto& contibution = new_state.contributions[item.first];
					contibution = contibution.is_nan() ? item.second : contibution + item.second;
				}
			}

			decimal old_contribution = (old_state ? old_state->get_contribution() : decimal::zero());
			decimal new_contribution = new_state.get_contribution();
			decimal coverage = new_contribution - old_contribution;
			while (coverage.is_positive() && !new_state.reservations.empty())
			{
				auto reservation = new_state.reservations.begin();
				auto reserve = std::min(coverage, reservation->second);
				auto transfer = apply_transfer(asset, (uint8_t*)reservation->first.data(), decimal::zero(), -reserve);
				if (!transfer)
					return transfer.error();

				reservation->second -= reserve;
				if (reservation->second.is_positive())
					break;

				coverage -= reserve;
				new_state.reservations.erase(reservation);
			}

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::account_depository>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(custody), format::variable(new_state.get_coverage(0)) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_depository> transaction_context::apply_account_depository_transaction(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const uint256_t& transaction_hash, int8_t direction)
		{
			states::account_depository new_state = states::account_depository(owner, block);
			new_state.asset = asset;
			if (direction > 0)
				new_state.transactions.insert(transaction_hash);

			auto old_state = get_account_depository(asset, owner);
			decimal old_contribution = (old_state ? old_state->get_contribution() : decimal::zero());
			if (old_state)
			{
				new_state.contributions = std::move(old_state->contributions);
				new_state.reservations = std::move(old_state->reservations);
				new_state.custody = std::move(old_state->custody);
				if (direction <= 0)
				{
					new_state.transactions = std::move(old_state->transactions);
					auto it = new_state.transactions.find(transaction_hash);
					if (it == new_state.transactions.end())
						return layer_exception("transaction hash not found");

					new_state.transactions.erase(it);
				}
				else
				{
					for (auto& item : old_state->transactions)
						new_state.transactions.insert(item);
				}
			}

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::account_depository>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(transaction_hash), format::variable(direction > 0) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_program> transaction_context::apply_witness_program(const std::string_view& packed_program_code)
		{
			states::witness_program new_state = states::witness_program(block);
			new_state.storage = packed_program_code;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_event> transaction_context::apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash)
		{
			states::witness_event new_state = states::witness_event(block);
			new_state.parent_transaction_hash = parent_transaction_hash;
			new_state.child_transaction_hash = child_transaction_hash;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_address> transaction_context::apply_witness_address(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const algorithm::pubkeyhash proposer, const address_map& addresses, uint64_t address_index, states::address_type purpose)
		{
			if (addresses.empty())
				return layer_exception("invalid operation");

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			ordered_map<string, address_map> segments;
			for (auto& address : addresses)
			{
				auto hash = chain->new_public_key_hash(address.second);
				if (hash)
					segments[*hash][address.first] = address.second;
				else
					segments[address.second][address.first] = address.second;
			}

			states::witness_address new_state = states::witness_address(nullptr, nullptr);
			for (auto& segment : segments)
			{
				new_state = states::witness_address(owner, block);
				new_state.set_proposer(proposer);
				new_state.address_index = address_index;
				new_state.addresses = std::move(segment.second);
				new_state.asset = asset;
				new_state.purpose = purpose;

				auto status = store(&new_state);
				if (!status)
					return status.error();

				format::variables event = { format::variable(asset), format::variable((uint8_t)purpose), format::variable(address_index) };
				for (auto& address : new_state.addresses)
					event.push_back(format::variable(address.second));

				status = emit_event<states::witness_address>(std::move(event));
				if (!status)
					return status.error();

			}
			return new_state;
		}
		expects_lr<states::witness_transaction> transaction_context::apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			states::witness_transaction new_state = states::witness_transaction(block);
			new_state.transaction_id = transaction_id;
			new_state.asset = asset;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::witness_transaction>({ format::variable(asset), format::variable(transaction_id) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> transaction_context::apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& supply, const decimal& reserve)
		{
			states::account_balance new_state = states::account_balance(owner, block);
			new_state.asset = asset;
			new_state.supply = supply;
			new_state.reserve = reserve;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(supply), format::variable(reserve) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> transaction_context::apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::pubkeyhash to, const decimal& value)
		{
			states::account_balance new_state1 = states::account_balance(from, block);
			new_state1.asset = asset;
			new_state1.supply = -value;
			if (!memcmp(from, to, sizeof(algorithm::pubkeyhash)))
				return new_state1;

			auto status = store(&new_state1);
			if (!status)
				return status.error();

			states::account_balance new_state2 = states::account_balance(to, block);
			new_state2.asset = asset;
			new_state2.supply = value;

			status = store(&new_state2);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(std::string_view((char*)from, sizeof(algorithm::pubkeyhash))), format::variable(std::string_view((char*)to, sizeof(algorithm::pubkeyhash))), format::variable(value) });
			if (!status)
				return status.error();

			return new_state1;
		}
		expects_lr<states::account_balance> transaction_context::apply_funding(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::pubkeyhash to, const decimal& value)
		{
			states::account_balance new_state1 = states::account_balance(from, block);
			new_state1.asset = asset;
			new_state1.supply = -value;
			if (!memcmp(from, to, sizeof(algorithm::pubkeyhash)))
				return new_state1;

			auto status = store(&new_state1, false);
			if (!status)
				return status.error();

			states::account_balance new_state2 = states::account_balance(to, block);
			new_state2.asset = asset;
			new_state2.supply = value;

			status = store(&new_state2, false);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(std::string_view((char*)from, sizeof(algorithm::pubkeyhash))), format::variable(std::string_view((char*)to, sizeof(algorithm::pubkeyhash))), format::variable(value) }, false);
			if (!status)
				return status.error();

			return new_state1;
		}
		expects_lr<states::account_sequence> transaction_context::get_account_sequence(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::account_sequence::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_sequence(std::move(*(states::account_sequence*)**state));
		}
		expects_lr<states::account_work> transaction_context::get_account_work(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			algorithm::pubkeyhash null = { 0 };
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::account_work::as_instance_column(owner), states::account_work::as_instance_row(), get_validation_nonce());
			if (!state)
			{
				if (memcmp(owner, environment ? environment->proposer.public_key_hash : null, sizeof(null)) != 0)
					return state.error();

				states::account_work result = states::account_work(owner, block);
				return result;
			}

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
			{
				if (memcmp(owner, environment ? environment->proposer.public_key_hash : null, sizeof(null)) != 0)
					return status.error();

				states::account_work result = states::account_work(owner, block);
				return result;
			}

			return states::account_work(std::move(*(states::account_work*)**state));
		}
		expects_lr<states::account_observer> transaction_context::get_account_observer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			algorithm::pubkeyhash null = { 0 };
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::account_observer::as_instance_column(owner), states::account_observer::as_instance_row(asset), get_validation_nonce());
			if (!state)
			{
				if (memcmp(owner, environment ? environment->proposer.public_key_hash : null, sizeof(null)) != 0)
					return state.error();

				states::account_observer result = states::account_observer(owner, block);
				return result;
			}

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
			{
				if (memcmp(owner, environment ? environment->proposer.public_key_hash : null, sizeof(null)) != 0)
					return status.error();

				states::account_observer result = states::account_observer(owner, block);
				return result;
			}

			return states::account_observer(std::move(*(states::account_observer*)**state));
		}
		expects_lr<vector<states::account_observer>> transaction_context::get_account_observers(const algorithm::pubkeyhash owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(&delta, states::account_observer::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::account_observer> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::account_observer*)*state));
			return addresses;
		}
		expects_lr<states::account_program> transaction_context::get_account_program(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::account_program::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_program(std::move(*(states::account_program*)**state));
		}
		expects_lr<states::account_storage> transaction_context::get_account_storage(const algorithm::pubkeyhash owner, const std::string_view& location) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::account_storage::as_instance_index(owner, location), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_storage(std::move(*(states::account_storage*)**state));
		}
		expects_lr<states::account_reward> transaction_context::get_account_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::account_reward::as_instance_column(owner), states::account_reward::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_reward(std::move(*(states::account_reward*)**state));
		}
		expects_lr<states::account_balance> transaction_context::get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_balance(std::move(*(states::account_balance*)**state));
		}
		expects_lr<states::account_depository> transaction_context::get_account_depository(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::account_depository::as_instance_column(owner), states::account_depository::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_depository(std::move(*(states::account_depository*)**state));
		}
		expects_lr<states::account_derivation> transaction_context::get_account_derivation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::account_derivation::as_instance_index(owner, asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_derivation(std::move(*(states::account_derivation*)**state));
		}
		expects_lr<states::witness_program> transaction_context::get_witness_program(const std::string_view& program_hashcode) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::witness_program::as_instance_index(program_hashcode), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_program(std::move(*(states::witness_program*)**state));
		}
		expects_lr<states::witness_event> transaction_context::get_witness_event(const uint256_t& parent_transaction_hash) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::witness_event::as_instance_index(parent_transaction_hash), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_event(std::move(*(states::witness_event*)**state));
		}
		expects_lr<vector<states::witness_address>> transaction_context::get_witness_addresses(const algorithm::pubkeyhash owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(&delta, states::witness_address::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::witness_address> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::witness_address*)*state));
			return addresses;
		}
		expects_lr<vector<states::witness_address>> transaction_context::get_witness_addresses_by_purpose(const algorithm::pubkeyhash owner, states::address_type purpose, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::equal((int64_t)purpose, 1);
			auto states = chain.get_multiforms_by_column_filter(&delta, states::witness_address::as_instance_column(owner), filter, get_validation_nonce(), storages::factor_range_window(offset, count));
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::witness_address> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::witness_address*)*state));
			return addresses;
		}
		expects_lr<states::witness_address> transaction_context::get_witness_address(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const std::string_view& address, uint64_t address_index) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(&delta, states::witness_address::as_instance_column(owner), states::witness_address::as_instance_row(asset, address, address_index), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_address(std::move(*(states::witness_address*)**state));
		}
		expects_lr<states::witness_address> transaction_context::get_witness_address(const algorithm::asset_id& asset, const std::string_view& address, uint64_t address_index, size_t offset) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_row(&delta, states::witness_address::as_instance_row(asset, address, address_index), get_validation_nonce(), offset);
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_address(std::move(*(states::witness_address*)**state));
		}
		expects_lr<states::witness_transaction> transaction_context::get_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(&delta, states::witness_transaction::as_instance_index(asset, transaction_id), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_transaction(std::move(*(states::witness_transaction*)**state));
		}
		expects_lr<ledger::block_transaction> transaction_context::get_block_transaction_instance(const uint256_t& transaction_hash) const
		{
			if (!transaction_hash)
				return layer_exception("block transaction not found");

			auto chain = storages::chainstate(__func__);
			auto candidate = chain.get_block_transaction_by_hash(transaction_hash);
			if (!candidate || !candidate->transaction || !candidate->receipt.successful)
				return layer_exception("block transaction not found");

			if (transaction && transaction->asset != candidate->transaction->asset)
				return layer_exception("block transaction asset is distinct");

			if (candidate->receipt.transaction_hash != transaction_hash && candidate->transaction->as_type() == transactions::rollup::as_instance_type())
				candidate = ((transactions::rollup*)*candidate->transaction)->resolve_block_transaction(candidate->receipt, transaction_hash);

			return candidate;
		}
		uint64_t transaction_context::get_validation_nonce() const
		{
			if (!environment)
				return block ? block->number : 0;
			else if (!environment->validation.tip)
				return block ? block->number : 1;
			return 0;
		}
		uint256_t transaction_context::get_gas_use() const
		{
			return receipt.relative_gas_use;
		}
		uint256_t transaction_context::get_gas_left() const
		{
			if (!transaction)
				return 0;

			return transaction->gas_limit > receipt.relative_gas_use ? transaction->gas_limit - receipt.relative_gas_use : uint256_t(0);
		}
		decimal transaction_context::get_gas_cost() const
		{
			if (!transaction || !transaction->gas_price.is_positive())
				return 0;

			return transaction->gas_price * get_gas_use().to_decimal();
		}
		expects_lr<void> transaction_context::validate_tx(const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash owner)
		{
			VI_ASSERT(new_transaction && owner, "transaction and owner should be set");
			algorithm::pubkeyhash null = { 0 };
			if (!algorithm::signing::recover_hash(new_transaction_hash, owner, new_transaction->signature) || !memcmp(owner, null, sizeof(null)))
				return layer_exception("invalid signature");

			auto chain = storages::chainstate(__func__);
			return new_transaction->validate(chain.get_latest_block_number().otherwise(1));
		}
		expects_lr<transaction_context> transaction_context::execute_tx(ledger::block* new_block, const ledger::evaluation_context* new_environment, const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash owner, block_work& cache, size_t transaction_size, uint8_t flags)
		{
			VI_ASSERT(new_block && new_environment && new_transaction && owner, "block, env, transaction and owner should be set");
			ledger::receipt new_receipt;
			new_receipt.transaction_hash = new_transaction_hash;
			new_receipt.generation_time = protocol::now().time.now();
			new_receipt.absolute_gas_use = new_block->gas_use;
			new_receipt.block_number = new_block->number;
			memcpy(new_receipt.from, owner, sizeof(new_receipt.from));

			auto validation = new_transaction->validate(new_receipt.block_number);
			if (!validation)
				return validation.error();

			transaction_context context = transaction_context(new_block, new_environment, new_transaction, std::move(new_receipt));
			context.delta.incoming = &cache;

			auto deployment = context.burn_gas(transaction_size * (size_t)gas_cost::write_byte);
			if (!deployment)
				return deployment.error();

			bool discard = (context.receipt.events.size() == 1 && context.receipt.events.front().first == 0 && context.receipt.events.front().second.size() == 1);
			auto execution = discard ? expects_lr<void>(layer_exception(context.receipt.events.front().second.front().as_blob())) : context.transaction->execute(&context);
			context.receipt.successful = !!execution;
			if (!context.receipt.successful)
				context.delta.outgoing->rollback();
			if (discard)
				context.receipt.events.clear();
			if ((flags & (uint8_t)execution_flags::only_successful) && !context.receipt.successful)
				return execution.error();

			if (!(flags & (uint8_t)execution_flags::skip_sequencing) && context.transaction->get_type() != transaction_level::aggregation)
			{
				auto info = context.apply_account_sequence(context.receipt.from, context.transaction->sequence + 1);
				if (!info)
					return info.error();
			}

			auto work = context.get_account_work(context.receipt.from);
			auto gas_use = work ? work->get_gas_use() : uint256_t(0);
			context.receipt.relative_gas_paid = states::account_work::get_adjusted_gas_paid(gas_use, context.receipt.relative_gas_use);
			context.receipt.finalization_time = protocol::now().time.now();
			if (memcmp(context.environment->proposer.public_key_hash, context.receipt.from, sizeof(context.receipt.from)) != 0)
			{
				if (context.receipt.relative_gas_paid > 0 && context.transaction->gas_price.is_positive())
				{
					auto funding = context.apply_funding(context.transaction->get_gas_asset(), context.receipt.from, context.environment->proposer.public_key_hash, context.transaction->gas_price * context.receipt.relative_gas_paid.to_decimal());
					if (!funding)
						return funding.error();
				}

				auto gas_output = states::account_work::get_adjusted_gas_output(gas_use, context.receipt.relative_gas_use);
				if (gas_output > 0)
				{
					work = context.apply_account_work(context.receipt.from, states::account_flags::as_is, 0, 0, gas_output);
					if (!work)
						return work.error();
				}
			}

			if (context.receipt.successful)
			{
				for (auto& item : context.witnesses)
					context.block->set_witness_requirement(item.first, item.second);
			}
			else
				context.emit_event(0, { format::variable(execution.what()) }, false);

			context.block->gas_use += context.receipt.relative_gas_use;
			context.block->gas_limit += context.transaction->gas_limit;
			return expects_lr<transaction_context>(std::move(context));
		}
		expects_lr<uint256_t> transaction_context::calculate_tx_gas(const ledger::transaction* transaction)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			algorithm::pubkeyhash owner;
			if (!transaction->recover_hash(owner))
				return layer_exception("invalid signature");

			auto* reference = (ledger::transaction*)transaction;
			auto initial_checksum = transaction->checksum;
			auto initial_gas_limit = transaction->gas_limit;
			auto initial_conservative = transaction->conservative;
			auto revert_transaction = [&]()
			{
				reference->checksum = initial_checksum;
				reference->gas_limit = initial_gas_limit;
				reference->conservative = initial_conservative;
			};
			reference->checksum = 0;
			reference->gas_limit = block::get_gas_limit();
			reference->conservative = false;

			ledger::block temp_block;
			temp_block.number = std::numeric_limits<int64_t>::max() - 1;

			algorithm::pubkeyhash public_key_hash = { 1 };
			ledger::evaluation_context temp_environment;
			memcpy(temp_environment.proposer.public_key_hash, public_key_hash, sizeof(algorithm::pubkeyhash));

			ledger::block_work cache;
			auto validation = transaction->validate(temp_block.number);
			if (!validation)
			{
				revert_transaction();
				return validation.error();
			}

			size_t transaction_size = transaction->as_message().data.size();
			auto execution = transaction_context::execute_tx(&temp_block, &temp_environment, transaction, transaction->as_hash(), owner, cache, transaction_size, (uint8_t)transaction_context::execution_flags::skip_sequencing);
			if (!execution)
			{
				revert_transaction();
				return execution.error();
			}

			revert_transaction();
			auto gas = execution->receipt.relative_gas_use;
			gas -= gas % 1000;
			return gas + 1000;
		}
		expects_promise_rt<void> transaction_context::dispatch_tx(const wallet& proposer, ledger::block_transaction* transaction, vector<uptr<ledger::transaction>>* pipeline)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			VI_ASSERT(pipeline != nullptr, "pipeline should be set");
			auto gas_limit = transaction->transaction->gas_limit;
			transaction->transaction->gas_limit = block::get_gas_limit();

			auto* context = memory::init<ledger::transaction_context>();
			context->transaction = *transaction->transaction;
			context->receipt = transaction->receipt;
			return transaction->transaction->dispatch(proposer, context, pipeline).then<expects_rt<void>>([transaction, context, gas_limit](expects_rt<void>&& result)
			{
				transaction->transaction->gas_limit = gas_limit;
				memory::deinit(context);
				return std::move(result);
			});
		}

		evaluation_context::transaction_info::transaction_info(const transaction_info& other) : hash(other.hash), size(other.size)
		{
			auto* reference = (transaction_info*)&other;
			candidate = reference->candidate.reset();
			memcpy(owner, other.owner, sizeof(other.owner));
		}
		evaluation_context::transaction_info& evaluation_context::transaction_info::operator= (const transaction_info& other)
		{
			if (this == &other)
				return *this;

			auto* reference = (transaction_info*)&other;
			hash = other.hash;
			size = other.size;
			candidate = reference->candidate.reset();
			memcpy(owner, other.owner, sizeof(other.owner));
			return *this;
		}

		option<uint64_t> evaluation_context::priority(const algorithm::pubkeyhash public_key_hash, const algorithm::seckey secret_key, option<block_header*>&& parent_block)
		{
			if (!parent_block)
			{
				auto chain = storages::chainstate(__func__);
				auto latest = chain.get_latest_block_header();
				tip = latest ? option<ledger::block_header>(std::move(*latest)) : option<ledger::block_header>(optional::none);
				validation.tip = true;
			}
			else if (*parent_block != nullptr)
			{
				auto chain = storages::chainstate(__func__);
				auto latest = chain.get_latest_block_number();
				tip = **parent_block;
				validation.tip = latest.otherwise(tip->number) < (tip->number + 1);
			}
			else
			{
				auto chain = storages::chainstate(__func__);
				auto latest = chain.get_latest_block_number();
				tip = option<ledger::block_header>(optional::none);
				validation.tip = !latest;
			}

			memcpy(proposer.public_key_hash, public_key_hash, sizeof(algorithm::pubkeyhash));
			if (secret_key != nullptr)
				memcpy(proposer.secret_key, secret_key, sizeof(algorithm::seckey));

			validation.cache = block_work();
			validation.context = ledger::transaction_context(tip.address());
			validation.context.environment = this;
			validation.context.delta.incoming = &validation.cache;
			validation.cumulative_gas = 0;
			precomputed = 0;
			proposers.clear();
			aggregators.clear();
			incoming.clear();
			outgoing.clear();

			if (validation.context.block && !validation.tip)
				++validation.context.block->number;

			auto& policy = protocol::now().policy;
			auto committee = validation.context.calculate_proposal_committee(policy.consensus_committee_size);
			if (committee)
				proposers = std::move(*committee);

			if (proposers.empty())
			{
				auto work = validation.context.get_account_work(proposer.public_key_hash);
				if (!work)
					proposers.push_back(states::account_work(proposer.public_key_hash, tip.address()));
				else
					proposers.push_back(std::move(*work));
			}

			if (validation.context.block && !validation.tip)
				--validation.context.block->number;

			auto position = std::find_if(proposers.begin(), proposers.end(), [this](const states::account_work& a) { return !memcmp(a.owner, proposer.public_key_hash, sizeof(proposer.public_key_hash)); });
			if (position == proposers.end())
				return optional::none;

			return std::distance(proposers.begin(), position);
		}
		size_t evaluation_context::apply(vector<uptr<transaction>>&& candidates)
		{
			vector<transaction_info> subqueue;
			subqueue.reserve(candidates.size());
			incoming.reserve(incoming.size() + candidates.size());
			for (auto& candidate : candidates)
			{
				auto& info = subqueue.emplace_back();
				info.candidate = std::move(candidate);
			}

			auto total_gas_limit = block_header::get_gas_limit();
			precompute(subqueue);

			algorithm::pubkeyhash null = { 0 };
			for (auto& item : subqueue)
			{
				if (!memcmp(item.owner, null, sizeof(null)))
				{
				erase:
					outgoing.push_back(item.hash);
					continue;
				}

				uint256_t new_cumulative_gas = validation.cumulative_gas + item.candidate->gas_limit;
				if (new_cumulative_gas > total_gas_limit)
					break;

				if (item.candidate->get_type() == transaction_level::aggregation)
				{
					auto* aggregation = ((aggregation_transaction*)*item.candidate);
					auto consensus = aggregation->calculate_cumulative_consensus(&aggregators, &validation.context);
					if (!consensus || !consensus->reached)
						continue;

					aggregation->set_consensus(consensus->branch->message.hash());
				}
				else
				{
					auto account_sequence = validation.context.get_account_sequence(item.owner);
					uint64_t sequence_target = (account_sequence ? account_sequence->sequence : 0);
					uint64_t sequence_delta = (sequence_target > item.candidate->sequence ? sequence_target - item.candidate->sequence : 0);
					if (sequence_delta > 1)
						goto erase;
					else if (sequence_delta > 0)
						continue;
				}

				validation.cumulative_gas = new_cumulative_gas;
				incoming.emplace_back(std::move(item));
				++precomputed;
			}
			return candidates.size();
		}
		evaluation_context::transaction_info& evaluation_context::include(uptr<transaction>&& candidate)
		{
			auto& info = incoming.emplace_back();
			info.candidate = std::move(candidate);
			return info;
		}
		expects_lr<block> evaluation_context::evaluate(string* errors)
		{
			ledger::block candidate;
			auto status = precompute(candidate);
			if (!status)
				return status.error();

			auto chain = storages::chainstate(__func__);
			auto evaluation = candidate.evaluate(tip.address(), this, errors);
			cleanup().report("mempool cleanup failed");
			if (!evaluation)
				return evaluation.error();

			return candidate;
		}
		expects_lr<void> evaluation_context::solve(block& candidate)
		{
			if (!candidate.solve(proposer.secret_key))
				return layer_exception("block proof evaluation failed");

			if (!candidate.sign(proposer.secret_key))
				return layer_exception("block signature evaluation failed");

			return expectation::met;
		}
		expects_lr<void> evaluation_context::verify(const block& candidate)
		{
			auto validity = candidate.verify_validity(tip.address());
			if (!validity)
				return validity;

			return candidate.verify_integrity(tip.address());
		}
		expects_lr<void> evaluation_context::precompute(block& candidate)
		{
			validation.context = transaction_context(&candidate);
			validation.context.environment = this;
			if (precomputed != incoming.size())
			{
				precomputed = incoming.size();
				precompute(incoming);
			}
			return expectation::met;
		}
		expects_lr<void> evaluation_context::cleanup()
		{
			if (outgoing.empty())
				return expectation::met;

			auto mempool = storages::mempoolstate(__func__);
			return mempool.remove_transactions(outgoing);
		}
		void evaluation_context::precompute(vector<transaction_info>& candidates)
		{
			algorithm::pubkeyhash null = { 0 };
			parallel::wail_all(parallel::for_each(candidates.begin(), candidates.end(), ELEMENTS_FEW, [&null](transaction_info& item)
			{
				item.hash = item.candidate->as_hash();
				if (memcmp(item.owner, null, sizeof(null)) != 0)
					return;

				item.size = item.candidate->as_message().data.size();
				if (item.candidate->get_type() != transaction_level::aggregation)
					algorithm::signing::recover_hash(item.candidate->as_payload().hash(), item.owner, item.candidate->signature);
				else
					item.candidate->recover_hash(item.owner);
			}));
		}
	}
}
