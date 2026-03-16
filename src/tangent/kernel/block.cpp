#include "block.h"
#include "superchain.h"
#include "../policy/transactions.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"

namespace tangent
{
	namespace ledger
	{
		static storages::position_condition to_position_condition(const filter_comparator comparator)
		{
			return (storages::position_condition)comparator;
		}
		static int8_t to_position_order(const filter_order order)
		{
			switch (order)
			{
				case filter_order::ascending:
					return 1;
				case filter_order::descending:
					return -1;
				default:
					return 0;
			}
		}

		block_transaction::block_transaction(uptr<transaction_message>&& new_transaction, transaction_receipt&& new_receipt) : transaction(std::move(new_transaction)), receipt(std::move(new_receipt))
		{
			VI_ASSERT(transaction, "transaction should be set");
		}
		block_transaction::block_transaction(const block_transaction& other) : transaction(other.transaction ? transactions::resolver::from_copy(*other.transaction) : nullptr), receipt(other.receipt)
		{
		}
		block_transaction& block_transaction::operator= (const block_transaction& other)
		{
			if (this == &other)
				return *this;

			transaction = other.transaction ? transactions::resolver::from_copy(*other.transaction) : nullptr;
			receipt = other.receipt;
			return *this;
		}
		bool block_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (transaction && !transaction->store(stream))
				return false;

			if (!receipt.store_payload(stream))
				return false;

			return true;
		}
		bool block_transaction::load_payload(format::ro_stream& stream)
		{
			transaction = tangent::transactions::resolver::from_stream(stream);
			if (transaction && !transaction->load(stream))
				return false;

			if (!receipt.load_payload(stream))
				return false;

			return true;
		}
		format::tree block_transaction::as_tree() const
		{
			format::tree data;
			data.set("transaction", transaction ? transaction->as_tree() : format::tree());
			data.set("receipt", receipt.as_tree());
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

		block_state::state_change::state_change() noexcept : erase(false)
		{
		}
		block_state::state_change::state_change(uptr<transition_state>&& new_state, bool new_erase) noexcept : state(std::move(new_state)), erase(new_erase)
		{
		}
		block_state::state_change::state_change(const state_change& other) noexcept : state(other.state ? states::resolver::from_copy(*other.state) : nullptr), erase(other.erase)
		{
		}
		block_state::state_change::state_change(state_change&& other) noexcept : state(std::move(other.state)), erase(other.erase)
		{
		}
		block_state::state_change& block_state::state_change::operator=(const state_change& other) noexcept
		{
			if (this == &other)
				return *this;

			state = other.state ? states::resolver::from_copy(*other.state) : nullptr;
			erase = other.erase;
			return *this;
		}
		block_state::state_change& block_state::state_change::operator=(state_change&& other) noexcept
		{
			if (this == &other)
				return *this;

			state = std::move(other.state);
			erase = other.erase;
			return *this;
		}
		format::tree block_state::state_change::as_tree() const
		{
			VI_ASSERT(state, "state should be set");
			auto data = state->as_tree();
			data.set("__erase__", format::variable(erase));
			return data;
		}
		bool block_state::state_change::empty() const
		{
			return !state || erase;
		}

		block_state::block_state(const block_state& other)
		{
			for (auto& [index, change] : other.finalized)
				finalized[index] = change;
			for (auto& [index, change] : other.pending)
				pending[index] = change;
		}
		block_state& block_state::operator= (const block_state& other)
		{
			if (&other == this)
				return *this;

			finalized.clear();
			pending.clear();
			for (auto& [index, change] : other.finalized)
				finalized[index] = change;
			for (auto& [index, change] : other.pending)
				pending[index] = change;
			return *this;
		}
		option<uptr<transition_state>> block_state::find(uint32_t type, const std::string_view& index) const
		{
			auto location = index_of(type, index);
			auto it = pending.find(location);
			if (it != pending.end())
				return it->second.empty() ? option<uptr<transition_state>>(nullptr) : option<uptr<transition_state>>(states::resolver::from_copy(*it->second.state));

			it = finalized.find(location);
			if (it != finalized.end())
				return it->second.empty() ? option<uptr<transition_state>>(nullptr) : option<uptr<transition_state>>(states::resolver::from_copy(*it->second.state));

			return option<uptr<transition_state>>(optional::none);
		}
		option<uptr<transition_state>> block_state::find(uint32_t type, const std::string_view& column, const std::string_view& row) const
		{
			auto location = index_of(type, column, row);
			auto it = pending.find(location);
			if (it != pending.end())
				return it->second.empty() ? option<uptr<transition_state>>(nullptr) : option<uptr<transition_state>>(states::resolver::from_copy(*it->second.state));

			it = finalized.find(location);
			if (it != finalized.end())
				return it->second.empty() ? option<uptr<transition_state>>(nullptr) : option<uptr<transition_state>>(states::resolver::from_copy(*it->second.state));

			return option<uptr<transition_state>>(optional::none);
		}
		void block_state::erase(uint32_t type, const std::string_view& index)
		{
			auto& change = pending[index_of(type, index)];
			change.state.destroy();
			change.erase = true;
		}
		void block_state::erase(uint32_t type, const std::string_view& column, const std::string_view& row)
		{
			auto& change = pending[index_of(type, column, row)];
			change.state.destroy();
			change.erase = true;
		}
		bool block_state::push(transition_state* value, bool will_delete)
		{
			VI_ASSERT(value != nullptr, "value should be set");
			auto copy = states::resolver::from_copy(value);
			if (!copy)
				return false;

			auto& change = pending[index_of(value)];
			change.state = copy;
			change.erase = will_delete;
			return true;
		}
		bool block_state::emplace(uptr<transition_state>&& value, bool will_delete)
		{
			VI_ASSERT(value, "value should be set");
			auto location = index_of(*value);
			auto& change = pending[location];
			change.state = std::move(value);
			change.erase = will_delete;
			return true;
		}
		string block_state::index_of(transition_state* value) const
		{
			VI_ASSERT(value != nullptr, "value should be set");
			switch (value->as_level())
			{
				case state_level::uniform:
				{
					auto* base = (uniform_state*)value;
					return index_of(value->as_type(), base->as_index());
				}
				case state_level::multiform:
				{
					auto* base = (multiform_state*)value;
					return index_of(value->as_type(), base->as_column(), base->as_row());
				}
				default:
					return string();
			}
		}
		string block_state::index_of(uint32_t type, const std::string_view& index) const
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(index.data(), index.size());
			return message.data;
		}
		string block_state::index_of(uint32_t type, const std::string_view& column, const std::string_view& row) const
		{
			format::wo_stream message;
			message.write_typeless(type);
			message.write_typeless(column.data(), column.size());
			message.write_typeless(row.data(), row.size());
			return message.data;
		}
		void block_state::revert(bool fully)
		{
			pending.clear();
			if (fully)
				finalized.clear();
		}
		void block_state::commit()
		{
			for (auto& [index, change] : pending)
				finalized[index] = std::move(change);
			pending.clear();
		}

		block_changelog::block_changelog() noexcept
		{
		}
		block_changelog::block_changelog(block_changelog&& other) noexcept : outgoing(std::move(other.outgoing)), incoming(std::move(other.incoming))
		{
		}
		block_changelog::~block_changelog() noexcept
		{
			clear_temporary_state();
		}
		block_changelog& block_changelog::operator=(block_changelog&& other) noexcept
		{
			if (this == &other)
				return *this;

			outgoing = std::move(other.outgoing);
			incoming = std::move(other.incoming);
			return *this;
		}
		void block_changelog::clear_temporary_state()
		{
			auto chain = storages::chainstate();
			chain.clear_temporary_state(this);
		}
		void block_changelog::clear()
		{
			effects.pending.clear();
			effects.finalized.clear();
			outgoing.revert(true);
			incoming.revert(true);
			clear_temporary_state();
		}
		void block_changelog::revert()
		{
			effects.pending.clear();
			outgoing.revert();
			incoming.revert();
		}
		void block_changelog::commit()
		{
			if (!effects.pending.empty())
			{
				effects.finalized.insert(effects.finalized.end(), std::make_move_iterator(effects.pending.begin()), std::make_move_iterator(effects.pending.end()));
				effects.pending.clear();
			}
			outgoing.commit();
			incoming.commit();
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
		expects_lr<void> block_header::verify_validity(const block_header* parent_block, const algorithm::pubkeyhash_t& recovered_producer) const
		{
			if (!number || (!parent_hash && number > 1) || (number == 1 && parent_hash > 0))
				return layer_exception("invalid number");

			if (!transaction_root || !receipt_root || !state_root)
				return layer_exception("invalid transaction/receipt/state merkle tree root");

			if (!generation_time || generation_time > evaluation_time)
				return layer_exception("invalid time");

			if (priority > protocol::now().policy.production.max_per_block)
				return layer_exception("invalid priority");

			auto target_difficulty = number <= 1 || parent_block ? algorithm::wesolowski::scale(get_proof_slot_target(parent_block), get_proof_difficulty_multiplier()) : difficulty;
			if (proof.empty() || difficulty != target_difficulty)
				return layer_exception("invalid wesolowski target");

			uint256_t gas_work = get_gas_work(gas_use, gas_limit, priority);
			if (!gas_limit || gas_use > gas_limit || absolute_work < gas_work)
				return layer_exception("invalid gas work");

			algorithm::pubkeyhash_t public_key_hash = recovered_producer;
			if (public_key_hash.empty() && !recover_hash(public_key_hash))
				return layer_exception("producer proof verification failed");

			if (!verify_proof(public_key_hash))
				return layer_exception("wesolowski proof verification failed");

			if (!parent_block && number > 1)
				return expectation::met;

			if (parent_block && parent_block->evaluation_time > generation_time + protocol::now().policy.pow.adjustment_time)
				return layer_exception("block is too far into the past");

			if (number > 1 && parent_block && parent_block->number != number - 1)
				return layer_exception("invalid parent block number");

			if (absolute_work != (parent_block ? parent_block->absolute_work + gas_work : gas_work))
				return layer_exception("invalid absolute gas work");

			bool cumulative = get_slot_length() > 1;
			if (slot_duration != (cumulative && parent_block ? parent_block->slot_duration + parent_block->get_proof_accounted_duration() : uint256_t(0)))
				return layer_exception("invalid slot duration");

			if (slot_gas_use != (cumulative && parent_block ? parent_block->slot_gas_use : uint256_t(0)) + gas_use)
				return layer_exception("invalid slot gas use");

			for (auto& witness : witnesses)
			{
				if (!algorithm::asset::is_aux(witness.first) || !witness.second)
					return layer_exception("invalid witness " + algorithm::asset::handle_of(witness.first));
			}

			if (parent_block != nullptr && parent_hash != parent_block->as_hash())
				return layer_exception("invalid parent hash");

			return expectation::met;
		}
		bool block_header::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(proof);
			stream->write_integer(parent_hash);
			stream->write_integer(transaction_root);
			stream->write_integer(receipt_root);
			stream->write_integer(state_root);
			stream->write_integer(gas_use);
			stream->write_integer(gas_limit);
			stream->write_integer(absolute_work);
			stream->write_integer(slot_duration);
			stream->write_integer(slot_gas_use);
			stream->write_integer(difficulty);
			stream->write_integer(generation_time);
			stream->write_integer(evaluation_time);
			stream->write_integer(priority);
			stream->write_integer(number);
			stream->write_integer(transaction_count);
			stream->write_integer(transition_count);
			stream->write_integer((uint16_t)witnesses.size());
			for (auto& item : witnesses)
			{
				stream->write_integer(item.first);
				stream->write_integer(item.second);
			}
			return true;
		}
		bool block_header::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &proof))
				return false;

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

			if (!stream.read_integer(stream.read_type(), &slot_duration))
				return false;

			if (!stream.read_integer(stream.read_type(), &slot_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &difficulty))
				return false;

			if (!stream.read_integer(stream.read_type(), &generation_time))
				return false;

			if (!stream.read_integer(stream.read_type(), &evaluation_time))
				return false;

			if (!stream.read_integer(stream.read_type(), &priority))
				return false;

			if (!stream.read_integer(stream.read_type(), &number))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_count))
				return false;

			if (!stream.read_integer(stream.read_type(), &transition_count))
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
		bool block_header::sign(const algorithm::seckey_t& secret_key)
		{
			return algorithm::signing::sign(block_header::as_signable().hash(), secret_key, signature);
		}
		bool block_header::solve(const algorithm::pubkeyhash_t& public_key_hash)
		{
			proof = algorithm::wesolowski::evaluate(difficulty, as_solution(public_key_hash).data);
			evaluation_time = protocol::now().time.now();
			return !proof.empty();
		}
		bool block_header::verify(const algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::verify(block_header::as_signable().hash(), public_key, signature);
		}
		bool block_header::recover(algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::recover(block_header::as_signable().hash(), public_key, signature);
		}
		bool block_header::recover_hash(algorithm::pubkeyhash_t& public_key_hash) const
		{
			return algorithm::signing::recover_hash(block_header::as_signable().hash(), public_key_hash, signature);
		}
		bool block_header::verify_proof(const algorithm::pubkeyhash_t& public_key_hash) const
		{
			return algorithm::wesolowski::verify(difficulty, as_solution(public_key_hash).data, proof);
		}
		void block_header::set_parent_block(const block_header* parent_block)
		{
			parent_hash = (parent_block ? parent_block->as_hash() : uint256_t(0));
			number = (parent_block ? parent_block->number : 0) + 1;
			generation_time = protocol::now().time.now();
		}
		void block_header::set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number)
		{
			auto& height = witnesses[algorithm::asset::base_id_of(asset)];
			if (height < block_number)
				height = block_number;
		}
		bool block_header::network_congestion() const
		{
			return network_congestion_threshold() > protocol::now().policy.production.network_congestion_threshold;
		}
		decimal block_header::network_congestion_threshold() const
		{
			return algorithm::arithmetic::divide(slot_gas_use.to_decimal(), get_slot_gas_limit().to_decimal());
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

			if (difficulty != other.difficulty)
				return difficulty > other.difficulty ? 1 : -1;

			int8_t security = algorithm::wesolowski::compare(proof, other.proof);
			if (security != 0)
				return security;

			if (gas_use != other.gas_use)
				return gas_use > other.gas_use ? 1 : -1;

			uint256_t mutations_a = uint256_t(transaction_count + 1) * uint256_t(transition_count + 1);
			uint256_t mutations_b = uint256_t(other.transaction_count + 1) * uint256_t(other.transition_count + 1);
			if (mutations_a != mutations_b)
				return mutations_a > mutations_b ? 1 : -1;

			uint256_t hash_a = as_hash();
			uint256_t hash_b = other.as_hash();
			if (hash_a == hash_b)
				return 0;

			return hash_a > hash_b ? -1 : 1;
		}
		uint64_t block_header::get_slot_proof_duration_average() const
		{
			return (slot_duration + get_proof_accounted_duration()) / get_slot_length();
		}
		uint64_t block_header::get_slot_length() const
		{
			auto interval = algorithm::wesolowski::adjustment_interval();
			return number < interval ? number : ((number % interval) + 1);
		}
		uint64_t block_header::get_proof_duration() const
		{
			return evaluation_time > generation_time ? evaluation_time - generation_time : 0;
		}
		uint64_t block_header::get_proof_accounted_duration() const
		{
			return priority > 0 ? (decimal(get_proof_duration()) / get_proof_difficulty_multiplier()).to_uint64() : get_proof_duration();
		}
		decimal block_header::get_proof_difficulty_multiplier() const
		{
			return algorithm::wesolowski::adjustment_scaling(priority);
		}
		uint64_t block_header::get_proof_slot_target(const block_header* parent_block) const
		{
			auto prev_duration = parent_block ? parent_block->get_slot_proof_duration_average() : 0;
			auto prev_target = parent_block ? parent_block->difficulty : protocol::now().policy.pow.difficulty;
			if (parent_block && parent_block->priority > 0)
				prev_target = algorithm::wesolowski::scale(prev_target, 1.0 / parent_block->get_proof_difficulty_multiplier());

			return algorithm::wesolowski::adjust(prev_target, prev_duration, number);
		}
		format::tree block_header::as_tree() const
		{
			algorithm::pubkeyhash_t producer;
			recover_hash(producer);

			format::tree data;
			data.set("signature", signature.empty() ? format::variable() : format::variable(format::util::encode_0xhex(signature.optimized_view())));
			data.set("producer", algorithm::signing::serialize_address(producer));
			data.set("hash", format::variable(algorithm::encoding::encode_0xhex256(as_hash())));
			data.set("parent_hash", format::variable(algorithm::encoding::encode_0xhex256(parent_hash)));
			data.set("transaction_root", format::variable(algorithm::encoding::encode_0xhex256(transaction_root)));
			data.set("receipt_root", format::variable(algorithm::encoding::encode_0xhex256(receipt_root)));
			data.set("state_root", format::variable(algorithm::encoding::encode_0xhex256(state_root)));
			data.set("absolute_work", algorithm::encoding::serialize_uint256(absolute_work));
			data.set("coinbase", format::variable(block_header::get_coinbase_value(number)));
			data.set("gas_use", algorithm::encoding::serialize_uint256(gas_use));
			data.set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			data.set("generation_time", algorithm::encoding::serialize_uint256(generation_time));
			data.set("evaluation_time", algorithm::encoding::serialize_uint256(evaluation_time));
			data.set("proof_duration", algorithm::encoding::serialize_uint256(get_proof_duration()));
			data.set("priority", algorithm::encoding::serialize_uint256(priority));
			data.set("number", algorithm::encoding::serialize_uint256(number));
			data.set("transaction_count", algorithm::encoding::serialize_uint256(transaction_count));
			data.set("transition_count", algorithm::encoding::serialize_uint256(transition_count));
			auto* pow_data = data.set("pow", format::tree::map());
			pow_data->set("proof", proof.empty() ? format::variable() : format::variable(format::util::encode_0xhex(proof)));
			pow_data->set("mdifficulty", format::variable(get_proof_difficulty_multiplier()));
			pow_data->set("kdifficulty", algorithm::encoding::serialize_uint256(algorithm::wesolowski::kdifficulty(difficulty)));
			pow_data->set("difficulty", format::variable(difficulty));
			pow_data->set("security", format::variable(protocol::now().policy.pow.security));
			pow_data->set("size", format::variable(proof.size()));
			auto* slot_data = data.set("slot", format::tree::map());
			slot_data->set("duration_total", algorithm::encoding::serialize_uint256(slot_duration));
			slot_data->set("duration_average", algorithm::encoding::serialize_uint256(get_slot_proof_duration_average()));
			slot_data->set("gas_use", algorithm::encoding::serialize_uint256(slot_gas_use));
			slot_data->set("gas_limit", algorithm::encoding::serialize_uint256(get_slot_gas_limit()));
			slot_data->set("congestion", format::variable(network_congestion()));
			slot_data->set("length", algorithm::encoding::serialize_uint256(get_slot_length()));
			auto* witnesses_data = data.set("witnesses", format::tree::list());
			for (auto& item : witnesses)
			{
				auto* witness_data = witnesses_data->push(format::tree::map());
				witness_data->set("asset", algorithm::asset::serialize(item.first));
				witness_data->set("number", algorithm::encoding::serialize_uint256(item.second));
			}
			return data;
		}
		format::wo_stream block_header::as_signable() const
		{
			format::wo_stream message;
			message.write_integer(as_type());
			if (!block_header::store_payload(&message))
				message.clear();
			return message;
		}
		format::wo_stream block_header::as_solution(const algorithm::pubkeyhash_t& public_key_hash) const
		{
			format::wo_stream message;
			message.write_string(public_key_hash.optimized_view());
			message.write_integer(parent_hash);
			message.write_integer(difficulty);
			message.write_integer(generation_time);
			message.write_integer(priority);
			message.write_integer(number);
			return message;
		}
		uint256_t block_header::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::wo_stream message;
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
			static uint256_t limit = protocol::now().policy.block_gas_limit;
			return limit;
		}
		uint256_t block_header::get_slot_gas_limit()
		{
			static uint256_t limit = algorithm::wesolowski::adjustment_interval() * get_gas_limit();
			return limit;
		}
		uint256_t block_header::get_gas_work(const uint256_t& gas_use, const uint256_t& gas_limit, uint64_t priority)
		{
			if (!gas_limit)
				return 0;

			auto& policy = protocol::now().policy;
			uint256_t alignment = 16;
			uint256_t committee = policy.production.max_per_block;
			uint256_t multiplier = priority >= committee ? 0 : math64u::pow3(committee - priority);
			uint256_t work = (multiplier * gas_use) / gas_limit;
			return work - (work % alignment) + alignment;
		}
		bool block_header::is_genesis_epoch(const uint64_t block_number)
		{
			uint64_t ending_block_number = protocol::now().policy.emission.genesis_epoch_length;
			return ending_block_number > 0 && block_number <= ending_block_number;
		}
		decimal block_header::get_coinbase_value(const uint64_t block_number)
		{
			auto& emission = protocol::now().policy.emission;
			if (is_genesis_epoch(block_number))
				return emission.genesis_coinbase_value;

			auto epoch = block_number / emission.epoch_length;
			auto decay = 1 - emission.decay_rate * epoch;
			auto coinbase = emission.coinbase_value * decay;
			return math0::max(coinbase, emission.min_coinbase_value);
		}

		block_body::block_body(const block_header& other) : block_header(other)
		{
		}
		expects_lr<void> block_body::verify_integrity(const block_header* parent_block, const block_state* state) const
		{
			if (transaction_count != (uint32_t)transactions.size())
				return layer_exception("invalid transactions count");
			else if (!transition_count && (state != nullptr && transition_count != (uint32_t)state->finalized.size()))
				return layer_exception("invalid states count");

			if (!parent_block && number > 1)
				return expectation::met;

			vector<uint256_t> transaction_tree;
			transaction_tree.reserve(transactions.size() + 1);
			if (parent_block != nullptr)
				transaction_tree.push_back(parent_block->transaction_root);
			for (auto& item : transactions)
				transaction_tree.push_back(item.receipt.transaction_hash);
			if (algorithm::merkle_tree::from(std::move(transaction_tree)).root() != transaction_root)
				return layer_exception("invalid transaction merkle tree root");

			vector<uint256_t> receipt_tree;
			receipt_tree.reserve(transactions.size() + 1);
			if (parent_block != nullptr)
				receipt_tree.push_back(parent_block->receipt_root);
			for (auto& item : transactions)
				receipt_tree.push_back(item.receipt.as_hash());
			if (algorithm::merkle_tree::from(std::move(receipt_tree)).root() != receipt_root)
				return layer_exception("invalid receipt merkle tree root");

			if (state != nullptr)
			{
				vector<uint256_t> state_tree;
				state_tree.reserve(state->finalized.size() + 1);
				if (parent_block != nullptr)
					state_tree.push_back(parent_block->state_root);
				for (auto& [index, change] : state->finalized)
					state_tree.push_back(change.state->as_hash());
				if (algorithm::merkle_tree::from(std::move(state_tree)).root() != state_root)
					return layer_exception("invalid state merkle tree root");
			}

			return expectation::met;
		}
		bool block_body::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!store_header_payload(stream))
				return false;

			if (!store_body_payload(stream))
				return false;

			return true;
		}
		bool block_body::load_payload(format::ro_stream& stream)
		{
			if (!load_header_payload(stream))
				return false;

			if (!load_body_payload(stream))
				return false;

			return true;
		}
		bool block_body::store_header_payload(format::wo_stream* stream) const
		{
			return block_header::store_payload(stream);
		}
		bool block_body::load_header_payload(format::ro_stream& stream)
		{
			return block_header::load_payload(stream);
		}
		bool block_body::store_body_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint32_t)transactions.size());
			for (auto& item : transactions)
				item.store_payload(stream);
			return true;
		}
		bool block_body::load_body_payload(format::ro_stream& stream)
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

			return true;
		}
		void block_body::recalculate(const block_header* parent_block, const block_state* state)
		{
			auto task_queue1 = parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [](block_transaction& item) { item.receipt.as_hash(); });
			if (state != nullptr)
			{
				auto task_queue2 = parallel::for_each_sequential(state->finalized.begin(), state->finalized.end(), state->finalized.size(), ELEMENTS_FEW, [](const std::pair<const string, block_state::state_change>& item) { item.second.state->as_hash(); });
				parallel::wail_all(std::move(task_queue2));
			}
			parallel::wail_all(std::move(task_queue1));

			vector<uint256_t> transaction_tree;
			transaction_tree.reserve(transactions.size() + 1);
			if (parent_block != nullptr)
				transaction_tree.push_back(parent_block->transaction_root);
			for (auto& item : transactions)
				transaction_tree.push_back(item.receipt.transaction_hash);
			transaction_root = algorithm::merkle_tree::from(std::move(transaction_tree)).root();

			vector<uint256_t> receipt_tree;
			receipt_tree.reserve(transactions.size() + 1);
			if (parent_block != nullptr)
				receipt_tree.push_back(parent_block->receipt_root);
			for (auto& item : transactions)
				receipt_tree.push_back(item.receipt.as_hash());
			receipt_root = algorithm::merkle_tree::from(std::move(receipt_tree)).root();

			if (state != nullptr)
			{
				vector<uint256_t> state_tree;
				state_tree.reserve(state->finalized.size() + 1);
				if (parent_block != nullptr)
					state_tree.push_back(parent_block->state_root);
				for (auto& [index, change] : state->finalized)
					state_tree.push_back(change.state->as_hash());
				state_root = algorithm::merkle_tree::from(std::move(state_tree)).root();
				transition_count = (uint32_t)state->finalized.size();
			}

			bool cumulative = get_slot_length() > 1;
			absolute_work = (parent_block ? parent_block->absolute_work : uint256_t(0)) + get_gas_work(gas_use, gas_limit, priority);
			slot_duration = (cumulative && parent_block ? parent_block->slot_duration + parent_block->get_proof_accounted_duration() : uint256_t(0));
			slot_gas_use = (cumulative && parent_block ? parent_block->slot_gas_use : uint256_t(0)) + gas_use;
			transaction_count = (uint32_t)transactions.size();
		}
		format::tree block_body::as_tree() const
		{
			auto data = block_header::as_tree();
			auto* transactions_data = data.set("transactions", format::tree::list());
			for (auto& item : transactions)
				transactions_data->push(item.as_tree());
			return data;
		}
		block_header block_body::as_header() const
		{
			return block_header(*this);
		}
		block_proof block_body::as_proof(const block_header* parent_block, const block_state* state) const
		{
			auto result = block_proof();
			result.transaction_root = transaction_root;
			result.receipt_root = receipt_root;
			result.state_root = state_root;
			result.transaction_tree.nodes.reserve(transactions.size() + 1);
			result.receipt_tree.nodes.reserve(transactions.size() + 1);
			result.state_tree.nodes.reserve(state ? state->finalized.size() + 1 : 0);
			if (parent_block != nullptr)
			{
				result.transaction_tree.nodes.push_back(parent_block->transaction_root);
				result.receipt_tree.nodes.push_back(parent_block->receipt_root);
			}
			for (auto& item : transactions)
			{
				result.transaction_tree.nodes.push_back(item.receipt.transaction_hash);
				result.receipt_tree.nodes.push_back(item.receipt.as_hash());
			}
			if (state != nullptr)
			{
				if (parent_block != nullptr)
					result.state_tree.nodes.push_back(parent_block->state_root);
				for (auto& [index, change] : state->finalized)
					result.state_tree.nodes.push_back(change.state->as_hash());
			}
			result.transaction_tree = algorithm::merkle_tree::from(std::move(result.transaction_tree.nodes));
			result.receipt_tree = algorithm::merkle_tree::from(std::move(result.receipt_tree.nodes));
			result.state_tree = algorithm::merkle_tree::from(std::move(result.state_tree.nodes));
			return result;
		}
		uint256_t block_body::as_hash(bool renew) const
		{
			return as_header().as_hash(renew);
		}

		option<algorithm::merkle_tree::branch_path> block_proof::find_transaction(const uint256_t& hash)
		{
			auto path = transaction_tree.path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		option<algorithm::merkle_tree::branch_path> block_proof::find_receipt(const uint256_t& hash)
		{
			auto path = receipt_tree.path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		option<algorithm::merkle_tree::branch_path> block_proof::find_state(const uint256_t& hash)
		{
			auto path = state_tree.path(hash);
			if (path.empty())
				return optional::none;

			return path;
		}
		bool block_proof::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(transaction_root);
			stream->write_integer((uint32_t)transaction_tree.size());
			for (size_t i = 0; i < transaction_tree.size(); i++)
				stream->write_integer(transaction_tree.nodes[i]);

			stream->write_integer(receipt_root);
			stream->write_integer((uint32_t)receipt_tree.size());
			for (size_t i = 0; i < receipt_tree.size(); i++)
				stream->write_integer(receipt_tree.nodes[i]);

			stream->write_integer(state_root);
			stream->write_integer((uint32_t)state_tree.size());
			for (size_t i = 0; i < state_tree.size(); i++)
				stream->write_integer(state_tree.nodes[i]);

			return true;
		}
		bool block_proof::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &transaction_root))
				return false;

			uint32_t transactions_size;
			if (!stream.read_integer(stream.read_type(), &transactions_size))
				return false;

			transaction_tree.nodes.resize(transactions_size);
			for (size_t i = 0; i < transactions_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &transaction_tree.nodes[i]))
					return false;
			}

			transaction_tree = algorithm::merkle_tree::from(std::move(transaction_tree.nodes));
			if (!stream.read_integer(stream.read_type(), &receipt_root))
				return false;

			uint32_t receipts_size;
			if (!stream.read_integer(stream.read_type(), &receipts_size))
				return false;

			receipt_tree.nodes.resize(receipts_size);
			for (size_t i = 0; i < receipts_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &receipt_tree.nodes[i]))
					return false;
			}

			receipt_tree = algorithm::merkle_tree::from(std::move(receipt_tree.nodes));
			if (!stream.read_integer(stream.read_type(), &state_root))
				return false;

			uint32_t states_size;
			if (!stream.read_integer(stream.read_type(), &states_size))
				return false;

			state_tree.nodes.resize(states_size);
			for (size_t i = 0; i < states_size; i++)
			{
				if (!stream.read_integer(stream.read_type(), &state_tree.nodes[i]))
					return false;
			}

			state_tree = algorithm::merkle_tree::from(std::move(state_tree.nodes));
			return true;
		}
		bool block_proof::has_transaction(const uint256_t& hash)
		{
			auto path = find_transaction(hash);
			return path && path->root(hash) == transaction_root;
		}
		bool block_proof::has_receipt(const uint256_t& hash)
		{
			auto path = find_receipt(hash);
			return path && path->root(hash) == receipt_root;
		}
		bool block_proof::has_state(const uint256_t& hash)
		{
			auto path = find_state(hash);
			return path && path->root(hash) == state_root;
		}
		format::tree block_proof::as_tree() const
		{
			format::tree data;
			data.childs().reserve(3);

			auto* transactions_data = data.set("transactions", format::tree::list());
			auto* receipts_data = data.set("receipts", format::tree::list());
			auto* states_data = data.set("states", format::tree::list());
			auto* transactions_tree_data = transactions_data->set("tree", format::tree::list());
			auto* receipts_tree_data = receipts_data->set("tree", format::tree::list());
			auto* states_tree_data = states_data->set("tree", format::tree::list());
			transactions_data->set("root", format::variable(algorithm::encoding::encode_0xhex256(transaction_root)));
			transactions_data->set("pivot", format::variable(transaction_tree.pivot));
			receipts_data->set("root", format::variable(algorithm::encoding::encode_0xhex256(receipt_root)));
			receipts_data->set("pivot", format::variable(receipt_tree.pivot));
			states_data->set("root", format::variable(algorithm::encoding::encode_0xhex256(state_root)));
			states_data->set("pivot", format::variable(state_tree.pivot));
			for (auto& item : transaction_tree.nodes)
				transactions_tree_data->push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			for (auto& item : receipt_tree.nodes)
				receipts_tree_data->push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			for (auto& item : state_tree.nodes)
				states_tree_data->push(format::variable(algorithm::encoding::encode_0xhex256(item)));
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

		format::tree block_evaluation::as_tree() const
		{
			auto data = block.as_tree();
			auto* states_data = data.set("changelog", format::tree::list());
			for (auto& [index, change] : state.finalized)
				states_data->push(change.state->as_tree());
			return data;
		}

		executor_context::executor_context(block_changelog* new_changelog) : solver(nullptr), transaction(nullptr), changelog(new_changelog), block(nullptr), options((uint8_t)flags::unrestricted)
		{
		}
		executor_context::executor_context(block_changelog* new_changelog, const solver_context* new_solver, block_header* new_block_header, const transaction_message* new_transaction, transaction_receipt&& new_receipt) : solver(new_solver), transaction(new_transaction), changelog(new_changelog), block(new_block_header), receipt(std::move(new_receipt)), options(0)
		{
		}
		executor_context::executor_context(const executor_context& other) : solver(other.solver), changelog(other.changelog), block(other.block), receipt(other.receipt), options(other.options)
		{
			transaction = other.transaction ? transactions::resolver::from_copy(other.transaction) : nullptr;
		}
		executor_context& executor_context::operator=(const executor_context& other)
		{
			if (this == &other)
				return *this;

			changelog = other.changelog;
			solver = other.solver;
			transaction = other.transaction ? transactions::resolver::from_copy(other.transaction) : nullptr;
			receipt = other.receipt;
			block = other.block;
			options = other.options;
			return *this;
		}
		void executor_context::defer_side_effect(task_callback&& callback)
		{
			VI_ASSERT(callback, "callback should be set");
			changelog->effects.pending.push_back(std::move(callback));
		}
		expects_lr<void> executor_context::query(transition_state* next, bool paid_in_full)
		{
			if (!next)
				return layer_exception("state not found");
			else if (!paid_in_full)
				return burn_gas((size_t)gas_cost::query_result);

			size_t bytes = next->as_message().data.size();
			return burn_gas(bytes * (size_t)gas_cost::read_byte + (size_t)gas_cost::query_result);
		}
		expects_lr<void> executor_context::load(transition_state* next, bool paid)
		{
			if (!next)
				return layer_exception("state not found");
			else if (!paid)
				return expectation::met;

			size_t bytes = next->as_message().data.size();
			return burn_gas(bytes * (size_t)gas_cost::read_byte);
		}
		expects_lr<void> executor_context::store(transition_state* next, bool paid)
		{
			if (!next)
				return layer_exception("invalid state");

			next->checksum = 0;
			if (block != nullptr)
				next->block_number = block->number;

			if (!next->block_number)
				return layer_exception("invalid state block number");
			else if (!changelog)
				return layer_exception("invalid state changelog");

			auto chain = storages::chainstate();
			auto prev = uptr<transition_state>();
			auto type = next->as_type();
			switch (next->as_level())
			{
				case state_level::uniform:
				{
					prev = chain.get_uniform(type, changelog, ((uniform_state*)next)->as_index(), get_validation_nonce()).or_else(storages::state_result()).value;
					auto status = next->transition(*prev);
					if (!status)
						return status;
					break;
				}
				case state_level::multiform:
				{
					prev = chain.get_multiform(type, changelog, ((multiform_state*)next)->as_column(), ((multiform_state*)next)->as_row(), get_validation_nonce()).or_else(storages::state_result()).value;
					auto status = next->transition(*prev);
					if (!status)
						return status;
					break;
				}
				default:
					return layer_exception("invalid state level");
			}

			bool prev_exists = !!prev;
			if (!prev)
				prev = states::resolver::from_type(type);

			bool will_delete = states::resolver::will_delete(next, prev);
			if (will_delete)
			{
				next->checksum = 0;
				if (!prev_exists)
					return expectation::met;
			}

			states::resolver::value_copy(type, next, *prev);
			changelog->outgoing.emplace(std::move(prev), will_delete);
			if (!paid)
				return expectation::met;

			size_t size = next->as_message().data.size();
			return burn_gas(size * (size_t)(will_delete ? gas_cost::erase_byte : gas_cost::write_byte));
		}
		expects_lr<void> executor_context::emit_witness(const algorithm::asset_id& asset, uint64_t block_number)
		{
			if (!algorithm::asset::is_aux(asset) || !block_number)
				return layer_exception("invalid witness");

			auto& current_number = witnesses[algorithm::asset::base_id_of(asset)];
			if (current_number < block_number)
				current_number = block_number;

			return expectation::met;
		}
		expects_lr<void> executor_context::emit_event(uint32_t event, format::variables&& values, bool paid)
		{
			if (paid)
			{
				format::wo_stream stream;
				format::variables_util::serialize_merge_into(values, &stream);
				stream.write_integer(event);

				auto status = burn_gas(stream.data.size() * (size_t)gas_cost::write_byte);
				if (!status)
					return status;
			}
			receipt.emit_event(event, std::move(values));
			return expectation::met;
		}
		expects_lr<void> executor_context::burn_gas()
		{
			if (!transaction)
				return expectation::met;

			return burn_gas(transaction->gas_limit - receipt.relative_gas_use);
		}
		expects_lr<void> executor_context::burn_gas(const uint256_t& value)
		{
			if (!transaction || (options & (uint8_t)flags::unrestricted))
				return expectation::met;

			uint256_t prev_relative_gas_use = receipt.relative_gas_use;
			receipt.relative_gas_use += value;
			if (value > transaction->gas_limit || prev_relative_gas_use > receipt.relative_gas_use)
				receipt.relative_gas_use = uint256_t::max();

			if (receipt.relative_gas_use <= transaction->gas_limit)
				return expectation::met;

			receipt.relative_gas_use = transaction->gas_limit;
			return layer_exception("ran out of gas");
		}
		expects_lr<void> executor_context::verify_account_nonce() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			bool replayable = (options & (uint8_t)flags::evaluation) || (options & (uint8_t)flags::replayable);
			auto state = get_account_nonce(receipt.from);
			if (state && state->nonce > transaction->nonce && !replayable)
				return layer_exception("nonce is invalid (now: " + to_string(state->nonce) + ")");
			else if (state && state->nonce == std::numeric_limits<uint64_t>::max())
				return layer_exception("account must stay passive");

			return expectation::met;
		}
		expects_lr<void> executor_context::verify_gas_transfer_balance() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			bool gas_calculation = block != nullptr && block->number == (uint64_t)(std::numeric_limits<int64_t>::max() - 1);
			if (gas_calculation)
				return expectation::met;

			if (!transaction->is_commitment() && (options & (uint8_t)flags::congestion) && !transaction->gas_price.is_positive())
				return layer_exception("must pay for gas - network congestion requirement");
			else if (!transaction->gas_price.is_positive() || (options & (uint8_t)flags::evaluation))
				return expectation::met;

			auto asset = transaction->gas_asset();
			auto state = get_account_balance(asset, receipt.from);
			decimal max_paid_value = transaction->gas_price * transaction->gas_limit.to_decimal();
			decimal max_payable_value = state ? state->get_balance() : decimal::zero();
			if (max_payable_value < max_paid_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient to cover gas fees (balance: " + max_payable_value.to_string() + ", value: " + max_paid_value.to_string() + ")");

			return expectation::met;
		}
		expects_lr<void> executor_context::verify_transfer_balance(const algorithm::asset_id& asset, const decimal& max_paid_value) const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			if (!max_paid_value.is_positive())
				return expectation::met;

			auto state = get_account_balance(asset, receipt.from);
			decimal max_payable_value = state ? state->get_balance() : decimal::zero();
			if (max_payable_value < max_paid_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient (balance: " + max_payable_value.to_string() + ", value: " + max_paid_value.to_string() + ")");

			return expectation::met;
		}
		expects_lr<algorithm::wesolowski::distribution> executor_context::calculate_random(const uint256_t& seed)
		{
			if (!block)
				return layer_exception("block not found");

			format::wo_stream message;
			message.write_typeless(block->number);
			message.write_typeless(block->priority);
			message.write_typeless(block->difficulty);
			message.write_typeless(receipt.transaction_hash);
			message.write_typeless(receipt.relative_gas_use);
			message.write_typeless(seed);

			algorithm::wesolowski::distribution distribution;
			distribution.signature = message.data;
			distribution.value = algorithm::hashing::hash256i(*crypto::hash(digests::sha512(), distribution.signature));
			return distribution;
		}
		expects_lr<size_t> executor_context::calculate_attesters_size(const algorithm::asset_id& asset) const
		{
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater(0, -1);
			return chain.get_multiforms_count_by_row_filter(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_row(asset), filter, nonce);
		}
		expects_lr<size_t> executor_context::calculate_producers_size() const
		{
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater(0, -1);
			auto window = storages::result_index_window();
			return chain.get_multiforms_count_by_row_filter(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_row(), filter, nonce).or_else(0);
		}
		expects_lr<vector<states::validator_production>> executor_context::calculate_producers(size_t target_size)
		{
			auto payment = burn_gas((uint64_t)gas_cost::query_result * 2048);
			if (!payment)
				return payment.error();

			auto random = calculate_random(0);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater(0, -1);
			auto window = storages::result_index_window();
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_row(), filter, nonce).or_else(0);
			auto size = std::min(target_size, pool);
			auto indices = btree_set<uint64_t>();
			auto distribution = algorithm::exponential_distribution();
			while (indices.size() < size)
			{
				uint64_t index = (uint64_t)distribution.next(random->derive(), (uint32_t)pool);
				if (indices.find(index) == indices.end())
				{
					window.indices.push_back(index);
					indices.insert(index);
				}
			}

			auto results = chain.get_multiforms_by_row_filter(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_row(), filter, nonce, window);
			if (!results || results->empty())
				return layer_exception("committee threshold not met");

			vector<states::validator_production> committee;
			committee.reserve(results->size());
			for (auto& result : *results)
			{
				auto& target = *(states::validator_production*)result.ptr();
				committee.emplace_back(std::move(target));

				auto status = query(result.ptr(), !result.cached);
				if (!status)
					return status.error();
			}

			return expects_lr<vector<states::validator_production>>(std::move(committee));
		}
		expects_lr<vector<states::validator_attestation>> executor_context::calculate_attesters(const algorithm::asset_id& asset, size_t target_size)
		{
			auto payment = burn_gas((uint64_t)gas_cost::query_result * 2048);
			if (!payment)
				return payment.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater(0, -1);
			auto window = storages::result_range_window(0, target_size);
			auto results = chain.get_multiforms_by_row_filter(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_row(asset), filter, nonce, window);
			if (!results)
				return layer_exception("committee threshold not met");

			vector<states::validator_attestation> committee;
			committee.reserve(results->size());
			for (auto& result : *results)
			{
				auto& target = *(states::validator_attestation*)result.ptr();
				committee.emplace_back(std::move(target));

				auto status = query(result.ptr(), !result.cached);
				if (!status)
					return status.error();
			}

			return expects_lr<vector<states::validator_attestation>>(std::move(committee));
		}
		expects_lr<vector<states::validator_attestation>> executor_context::calculate_attesters(const algorithm::asset_id& asset, size_t target_size, const decimal& fee_threshold, btree_set<algorithm::pubkeyhash_t>& exclusion)
		{
			auto payment = burn_gas((uint64_t)gas_cost::query_result * 2048);
			if (!payment)
				return payment.error();

			auto random = calculate_random(1);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater_equal(fee_threshold.is_zero_or_nan() ? uint256_t(1) : states::validator_attestation::to_rank(fee_threshold), -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_row(asset), filter, nonce).or_else(0);
			if (pool < target_size)
				return layer_exception("committee threshold not met");

			vector<states::validator_attestation> committee;
			auto distribution = algorithm::exponential_distribution();
			auto indices = btree_set<uint64_t>();
			while (indices.size() < pool)
			{
				auto window = storages::result_index_window();
				auto size = std::min<size_t>(target_size, pool - indices.size());
				while (window.indices.size() < size)
				{
					uint64_t index = (uint64_t)distribution.next(random->derive(), (uint32_t)pool);
					if (indices.find(index) == indices.end())
					{
						window.indices.push_back(index);
						indices.insert(index);
					}
				}

				auto results = chain.get_multiforms_by_row_filter(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_row(asset), filter, nonce, window);
				if (!results || results->empty())
					break;

				committee.reserve(results->size());
				for (auto& result : *results)
				{
					auto& target = *(states::validator_attestation*)result.ptr();
					auto hash = algorithm::pubkeyhash_t(target.owner);
					if (exclusion.find(hash) != exclusion.end())
						continue;

					auto status = load(result.ptr(), !result.cached);
					if (!status)
						return status.error();

					exclusion.insert(std::move(hash));
					committee.push_back(std::move(target));
					if (committee.size() >= target_size)
						break;
				}

				if (committee.size() >= target_size)
					break;
			}

			if (committee.size() < target_size)
				return layer_exception("committee threshold not met");

			return expects_lr<vector<states::validator_attestation>>(std::move(committee));
		}
		expects_lr<vector<states::validator_participation>> executor_context::calculate_participants(size_t target_size, btree_set<algorithm::pubkeyhash_t>& exclusion)
		{
			auto payment = burn_gas((uint64_t)gas_cost::query_result * 2048);
			if (!payment)
				return payment.error();

			auto random = calculate_random(2);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater_equal(uint256_t(1), -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_row(), filter, nonce).or_else(0);
			if (pool < target_size)
				return layer_exception("committee threshold not met");

			vector<states::validator_participation> committee;
			auto distribution = algorithm::exponential_distribution();
			auto indices = btree_set<uint64_t>();
			while (indices.size() < pool)
			{
				auto window = storages::result_index_window();
				auto size = std::min<size_t>(target_size, pool - indices.size());
				while (window.indices.size() < size)
				{
					uint64_t index = (uint64_t)distribution.next(random->derive(), (uint32_t)pool);
					if (indices.find(index) == indices.end())
					{
						window.indices.push_back(index);
						indices.insert(index);
					}
				}

				auto results = chain.get_multiforms_by_row_filter(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_row(), filter, nonce, window);
				if (!results || results->empty())
					break;

				committee.reserve(results->size());
				for (auto& result : *results)
				{
					auto& target = *(states::validator_participation*)result.ptr();
					auto hash = algorithm::pubkeyhash_t(target.owner);
					if (exclusion.find(hash) != exclusion.end())
						continue;

					auto status = load(result.ptr(), !result.cached);
					if (!status)
						return status.error();

					exclusion.insert(std::move(hash));
					committee.push_back(std::move(target));
					if (committee.size() >= target_size)
						break;
				}

				if (committee.size() >= target_size)
					break;
			}

			if (committee.size() < target_size)
				return layer_exception("committee threshold not met");

			return expects_lr<vector<states::validator_participation>>(std::move(committee));
		}
		expects_lr<states::account_nonce> executor_context::apply_account_nonce(const algorithm::pubkeyhash_t& owner, uint64_t nonce)
		{
			states::account_nonce new_state = states::account_nonce(owner, block);
			new_state.nonce = nonce;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();
			else if (receipt.from == owner)
				options |= (uint8_t)flags::replayable;

			return new_state;
		}
		expects_lr<states::account_program> executor_context::apply_account_program(const algorithm::pubkeyhash_t& owner, const std::string_view& program_hashcode)
		{
			states::account_program new_state = states::account_program(owner, block);
			new_state.hashcode = program_hashcode;

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_uniform> executor_context::apply_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index, const std::string_view& data)
		{
			states::account_uniform new_state = states::account_uniform(owner, index, block);
			new_state.data = data;

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_multiform> executor_context::apply_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row, const std::string_view& data, const uint256_t& filter)
		{
			states::account_multiform new_state = states::account_multiform(owner, column, row, block);
			new_state.data = data;
			new_state.filter = filter;

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_balance> executor_context::apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& supply, const decimal& reserve)
		{
			if (supply.is_zero() && reserve.is_zero())
				return get_account_balance(asset, owner).or_else(states::account_balance(owner, asset, block));

			states::account_balance new_state = states::account_balance(owner, asset, block);
			new_state.supply = supply;
			new_state.reserve = reserve;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(owner.view()), format::variable(supply), format::variable(reserve) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> executor_context::apply_fee_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& value)
		{
			if (value.is_zero())
				return get_account_balance(asset, owner).or_else(states::account_balance(owner, asset, block));

			states::account_balance new_state = states::account_balance(owner, asset, block);
			new_state.supply = -value;
			if (solver != nullptr && solver->state.public_key_hash == owner)
				return new_state;

			auto status = store(&new_state, false);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(owner.view()), format::variable(-value) }, false);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> executor_context::apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& from, const algorithm::pubkeyhash_t& to, const decimal& value)
		{
			if (from == to || value.is_zero())
				return get_account_balance(asset, from).or_else(states::account_balance(from, asset, block));

			states::account_balance new_state1 = states::account_balance(from, asset, block);
			new_state1.supply = -value;

			auto status = store(&new_state1, true);
			if (!status)
				return status.error();

			states::account_balance new_state2 = states::account_balance(to, asset, block);
			new_state2.supply = value;

			status = store(&new_state2, true);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(from.view()), format::variable(to.view()), format::variable(value) });
			if (!status)
				return status.error();

			return new_state1;
		}
		expects_lr<states::validator_production> executor_context::apply_validator_production(const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake)
		{
			states::validator_production new_state = get_validator_production(owner).or_else(states::validator_production(owner, block));
			switch (type)
			{
				case staker::lock:
				case staker::reward_or_penalty:
				{
					if (stake.is_nan())
						return layer_exception("invalid stake");

					if (new_state.stake.is_nan())
						new_state.stake = decimal::zero();

					auto stake_value = stake;
					if (stake_value.is_negative())
						stake_value = std::max(stake_value, -new_state.stake);

					new_state.stake += stake_value;
					auto transfer = apply_transfer(algorithm::asset::native(), owner, type == staker::reward_or_penalty ? stake_value : decimal::zero(), stake_value);
					if (!transfer)
						return transfer.error();
					break;
				}
				case staker::unlock:
				{
					if (!stake.is_zero_or_nan() && !stake.is_negative())
						return layer_exception("invalid stake");

					auto penalty = stake.is_nan() ? decimal::zero() : stake;
					auto transfer = apply_transfer(algorithm::asset::native(), owner, penalty, -new_state.stake);
					if (!transfer)
						return transfer.error();

					auto count = (size_t)32;
					auto rewards = vector<states::validator_production_reward>();
					while (true)
					{
						auto chunk = get_validator_production_rewards(owner, rewards.size(), count);
						if (chunk)
							rewards.insert(rewards.end(), chunk->begin(), chunk->end());
						if (!chunk || chunk->size() != count)
							break;
					}

					new_state.stake = decimal::nan();
					for (auto& reward : rewards)
					{
						transfer = apply_transfer(reward.asset, owner, decimal::zero(), -reward.reward);
						if (!transfer)
							return transfer.error();

						auto status = apply_validator_production_reward(reward.asset, reward.owner, decimal::zero());
						if (!status)
							return status.error();
					}
					break;
				}
				default:
					return layer_exception("invalid stake action");
			}

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::validator_production_reward> executor_context::apply_validator_production_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward)
		{
			states::validator_production_reward new_state = get_validator_production_reward(asset, owner).or_else(states::validator_production_reward(owner, asset, block));
			auto reward_value = reward.is_negative() ? std::max(reward, -new_state.reward) : reward;
			new_state.reward += reward_value;

			auto transfer = apply_transfer(asset, owner, reward_value, reward_value);
			if (!transfer)
				return transfer.error();

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::validator_participation> executor_context::apply_validator_participation(const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake)
		{
			states::validator_participation new_state = get_validator_participation(owner).or_else(states::validator_participation(owner, block));
			switch (type)
			{
				case staker::lock:
				case staker::reward_or_penalty:
				{
					if (stake.is_nan())
						return layer_exception("invalid stake");

					if (new_state.stake.is_nan())
						new_state.stake = decimal::zero();

					auto stake_value = stake;
					if (stake_value.is_negative())
						stake_value = std::max(stake_value, -new_state.stake);

					new_state.stake += stake_value;
					auto transfer = apply_transfer(algorithm::asset::native(), owner, type == staker::reward_or_penalty ? stake_value : decimal::zero(), stake_value);
					if (!transfer)
						return transfer.error();
					break;
				}
				case staker::unlock:
				{
					if (!stake.is_nan())
						return layer_exception("invalid stake");

					auto transfer = apply_transfer(algorithm::asset::native(), owner, decimal::zero(), -new_state.stake);
					if (!transfer)
						return transfer.error();

					auto count = (size_t)32;
					auto rewards = vector<states::validator_participation_reward>();
					while (true)
					{
						auto chunk = get_validator_participation_rewards(owner, rewards.size(), count);
						if (chunk)
							rewards.insert(rewards.end(), chunk->begin(), chunk->end());
						if (!chunk || chunk->size() != count)
							break;
					}

					new_state.stake = stake;
					for (auto& reward : rewards)
					{
						transfer = apply_transfer(reward.asset, owner, decimal::zero(), -reward.reward);
						if (!transfer)
							return transfer.error();

						auto status = apply_validator_participation_reward(reward.asset, reward.owner, decimal::zero());
						if (!status)
							return status.error();
					}
					break;
				}
				default:
					return layer_exception("invalid stake action");
			}

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::validator_participation_reward> executor_context::apply_validator_participation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward)
		{
			states::validator_participation_reward new_state = get_validator_participation_reward(asset, owner).or_else(states::validator_participation_reward(owner, asset, block));
			auto reward_value = reward.is_negative() ? std::max(reward, -new_state.reward) : reward;
			new_state.reward += reward_value;

			auto transfer = apply_transfer(asset, owner, reward_value, reward_value);
			if (!transfer)
				return transfer.error();

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::validator_participation_ref> executor_context::apply_validator_participation_ref(const algorithm::pubkeyhash_t& owner, const states::bridge_ref& ref, bool active)
		{
			states::validator_participation_ref new_state = states::validator_participation_ref(owner, ref, block);
			new_state.active = active;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::validator_attestation> executor_context::apply_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, staker type, const decimal& stake, const decimal& min_fee)
		{
			states::validator_attestation new_state = get_validator_attestation(asset, owner).or_else(states::validator_attestation(owner, asset, block));
			new_state.min_fee = min_fee;
			switch (type)
			{
				case staker::lock:
				case staker::reward_or_penalty:
				{
					if (stake.is_nan())
						return layer_exception("invalid stake");

					if (new_state.stake.is_nan())
						new_state.stake = decimal::zero();

					auto stake_value = stake;
					if (stake_value.is_negative())
						stake_value = std::max(stake_value, -new_state.stake);

					new_state.stake += stake_value;
					auto transfer = apply_transfer(algorithm::asset::native(), owner, type == staker::reward_or_penalty ? stake_value : decimal::zero(), stake_value);
					if (!transfer)
						return transfer.error();
					break;
				}
				case staker::unlock:
				{
					if (!stake.is_nan())
						return layer_exception("invalid stake");

					auto transfer = apply_transfer(algorithm::asset::native(), owner, decimal::zero(), -new_state.stake);
					if (!transfer)
						return transfer.error();

					auto count = (size_t)32;
					auto rewards = vector<states::validator_attestation_reward>();
					while (true)
					{
						auto chunk = get_validator_attestation_rewards(owner, rewards.size(), count);
						if (chunk)
							rewards.insert(rewards.end(), chunk->begin(), chunk->end());
						if (!chunk || chunk->size() != count)
							break;
					}

					new_state.stake = stake;
					for (auto& reward : rewards)
					{
						transfer = apply_transfer(reward.asset, owner, decimal::zero(), -reward.reward);
						if (!transfer)
							return transfer.error();

						auto status = apply_validator_attestation_reward(reward.asset, reward.owner, decimal::zero());
						if (!status)
							return status.error();
					}
					break;
				}
				default:
					return layer_exception("invalid stake action");
			}

			auto result = store(&new_state, true);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::validator_attestation_reward> executor_context::apply_validator_attestation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const decimal& reward)
		{
			states::validator_attestation_reward new_state = get_validator_attestation_reward(asset, owner).or_else(states::validator_attestation_reward(owner, asset, block));
			auto reward_value = reward.is_negative() ? std::max(reward, -new_state.reward) : reward;
			new_state.reward += reward_value;

			auto transfer = apply_transfer(asset, owner, reward_value, reward_value);
			if (!transfer)
				return transfer.error();

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::bridge_instance> executor_context::apply_bridge_instance(const algorithm::asset_id& asset, const uint256_t& bridge_hash, uint8_t security_level, const decimal& fee)
		{
			states::bridge_ref ref;
			ref.asset = asset;
			ref.hash = bridge_hash;

			auto new_state = get_bridge_instance(asset, bridge_hash).or_else(states::bridge_instance(ref, block));
			new_state.security_level = security_level;
			new_state.fee_rate = fee;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::bridge_instance>({ format::variable(asset), format::variable(bridge_hash) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::bridge_instance> executor_context::apply_bridge_instance_log(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const uint256_t& transaction_hash)
		{
			states::bridge_ref ref;
			ref.asset = asset;
			ref.hash = bridge_hash;

			auto new_state = get_bridge_instance(asset, bridge_hash).or_else(states::bridge_instance(ref, block));
			new_state.transaction_hash = transaction_hash;
			++new_state.transaction_nonce;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::bridge_instance>({ format::variable(asset), format::variable(bridge_hash), format::variable(new_state.transaction_nonce), format::variable(true) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::bridge_instance> executor_context::apply_bridge_instance_account(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const algorithm::pubkeyhash_t& owner)
		{
			states::bridge_ref ref;
			ref.asset = asset;
			ref.hash = bridge_hash;

			auto new_state = get_bridge_instance(asset, bridge_hash).or_else(states::bridge_instance(ref, block));
			++new_state.account_nonce;
			if (new_state.ref.owner.empty())
				new_state.ref.owner = owner;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::bridge_instance>({ format::variable(asset), format::variable(bridge_hash), format::variable(new_state.account_nonce), format::variable(false) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::bridge_queue> executor_context::apply_bridge_queue(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const uint256_t& transaction_hash, bool active)
		{
			states::bridge_queue new_state = states::bridge_queue(asset, bridge_hash, transaction_hash, block);
			if (active)
			{
				new_state.index = get_bridge_queue(asset, bridge_hash).or_else(states::bridge_queue(asset, bridge_hash, 0, nullptr)).index + 1;
				auto status = store(&new_state, true);
				if (!status)
					return status.error();

				status = emit_event<states::bridge_queue>({ format::variable(asset), format::variable(bridge_hash), format::variable(new_state.index) });
				if (!status)
					return status.error();
			}
			else
			{
				auto status = store(&new_state, true);
				if (!status)
					return status.error();
			}
			return new_state;
		}
		expects_lr<states::bridge_balance> executor_context::apply_bridge_balance(const algorithm::asset_id& asset, const uint256_t& bridge_hash, const decimal& balance)
		{
			if (balance.is_zero())
				return get_bridge_balance(asset, bridge_hash).or_else(states::bridge_balance(asset, bridge_hash, block));

			states::bridge_balance new_state = states::bridge_balance(asset, bridge_hash, block);
			new_state.supply = balance;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::bridge_balance>({ format::variable(asset), format::variable(bridge_hash), format::variable(balance) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::bridge_account> executor_context::apply_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash, const algorithm::composition::cpubkey_t& public_key, btree_set<algorithm::pubkeyhash_t>&& group)
		{
			auto ref = states::bridge_ref();
			ref.owner = owner;
			ref.asset = asset;
			ref.hash = bridge_hash;

			states::bridge_account new_state = states::bridge_account(ref, block);
			new_state.set_group(public_key, std::move(group));

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_program> executor_context::apply_witness_program(const std::string_view& packed_program_code)
		{
			states::witness_program new_state = states::witness_program(states::witness_program::as_instance_packed_hashcode(packed_program_code), block);
			new_state.storage = packed_program_code;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_event> executor_context::apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash)
		{
			states::witness_event new_state = states::witness_event(parent_transaction_hash, block);
			new_state.child_transaction_hash = child_transaction_hash;

			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_account> executor_context::apply_witness_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const address_map& addresses)
		{
			return apply_witness_bridge_account(owner, asset, 0, addresses, false);
		}
		expects_lr<states::witness_account> executor_context::apply_witness_routing_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const address_map& addresses)
		{
			return apply_witness_bridge_account(owner, asset, 0, addresses, true);
		}
		expects_lr<states::witness_account> executor_context::apply_witness_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash, const address_map& addresses, bool active)
		{
			if (addresses.empty())
				return layer_exception("invalid operation");

			auto* chain = superchain::bridge::get()->get_network(asset);
			if (!chain)
				return layer_exception("invalid operation");

			btree_map<string, address_map> segments;
			for (auto& address : addresses)
			{
				auto hash = chain->decode_address(address.second);
				if (!hash)
					return layer_exception(stringify::text("error applying \"%s\" address: %s", address.second.c_str(), hash.error().message().c_str()));

				segments[*hash][address.first] = address.second;
			}

			auto ref = states::bridge_ref();
			ref.owner = owner;
			ref.asset = asset;
			ref.hash = bridge_hash;

			states::witness_account new_state = states::witness_account(ref, { }, nullptr);
			for (auto& segment : segments)
			{
				new_state = states::witness_account(ref, segment.second, block);
				new_state.active = active;

				auto status = store(&new_state, true);
				if (!status)
					return status.error();

				format::variables event = { format::variable(asset), format::variable((uint8_t)new_state.get_type()) };
				for (auto& address : new_state.addresses)
					event.push_back(format::variable(address.second));

				status = emit_event<states::witness_account>(std::move(event));
				if (!status)
					return status.error();
			}
			return new_state;
		}
		expects_lr<states::witness_transaction> executor_context::apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			states::witness_transaction new_state = states::witness_transaction(asset, transaction_id, block);
			auto status = store(&new_state, true);
			if (!status)
				return status.error();

			status = emit_event<states::witness_transaction>({ format::variable(asset), format::variable(new_state.as_hash()) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_nonce> executor_context::get_account_nonce(const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), changelog, states::account_nonce::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return layer_exception("account nonce required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::account_nonce(std::move(*state->as<states::account_nonce>()));
		}
		expects_lr<states::account_program> executor_context::get_account_program(const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_program::as_instance_type(), changelog, states::account_program::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return layer_exception("account program required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			auto& result = *state->as<states::account_program>();
			if (result.hashcode.empty())
				return layer_exception("program is detached");

			return states::account_program(std::move(result));
		}
		expects_lr<states::account_uniform> executor_context::get_account_uniform(const algorithm::pubkeyhash_t& owner, const std::string_view& index) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_uniform::as_instance_type(), changelog, states::account_uniform::as_instance_index(owner, index), get_validation_nonce());
			if (!state)
				return layer_exception("account uniform required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::account_uniform(std::move(*state->as<states::account_uniform>()));
		}
		expects_lr<states::account_multiform> executor_context::get_account_multiform(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const std::string_view& row) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_column(owner, column), states::account_multiform::as_instance_row(owner, row), get_validation_nonce());
			if (!state)
				return layer_exception("account multiform required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::account_multiform(std::move(*state->as<states::account_multiform>()));
		}
		expects_lr<vector<uptr<states::account_multiform>>> executor_context::get_account_multiforms_by_column(const algorithm::pubkeyhash_t& owner, const std::string_view& column, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_column(owner, column), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("account multiform(s) required but not applicable (" + states.what() + ")");

			vector<uptr<states::account_multiform>> results;
			results.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				results.emplace_back((states::account_multiform*)state.value.reset());
			}
			return results;
		}
		expects_lr<vector<uptr<states::account_multiform>>> executor_context::get_account_multiforms_by_column_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& column, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const
		{
			auto filter = storages::result_filter();
			filter.condition = to_position_condition(comparator);
			filter.order = to_position_order(order);
			filter.value = filter_value;

			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column_filter(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_column(owner, column), filter, get_validation_nonce(), storages::result_range_window(offset, count));
			if (!states)
				return layer_exception("account multiform(s) required but not applicable (" + states.what() + ")");

			vector<uptr<states::account_multiform>> results;
			results.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				results.emplace_back((states::account_multiform*)state.value.reset());
			}
			return results;
		}
		expects_lr<vector<uptr<states::account_multiform>>> executor_context::get_account_multiforms_by_row(const algorithm::pubkeyhash_t& owner, const std::string_view& row, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_row(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_row(owner, row), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("account multiform(s) required but not applicable (" + states.what() + ")");

			vector<uptr<states::account_multiform>> results;
			results.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				results.emplace_back((states::account_multiform*)state.value.reset());
			}
			return results;
		}
		expects_lr<vector<uptr<states::account_multiform>>> executor_context::get_account_multiforms_by_row_filter(const algorithm::pubkeyhash_t& owner, const std::string_view& row, const filter_comparator& comparator, const uint256_t& filter_value, filter_order order, size_t offset, size_t count) const
		{
			auto filter = storages::result_filter();
			filter.condition = to_position_condition(comparator);
			filter.order = to_position_order(order);
			filter.value = filter_value;

			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_row_filter(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_row(owner, row), filter, get_validation_nonce(), storages::result_range_window(offset, count));
			if (!states)
				return layer_exception("account multiform(s) required but not applicable (" + states.what() + ")");

			vector<uptr<states::account_multiform>> results;
			results.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				results.emplace_back((states::account_multiform*)state.value.reset());
			}
			return results;
		}
		expects_lr<states::account_balance> executor_context::get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::account_balance::as_instance_type(), changelog, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return layer_exception("account balance required but not found (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::account_balance(std::move(*state->as<states::account_balance>()));
		}
		expects_lr<states::validator_production> executor_context::get_validator_production(const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_column(owner), states::validator_production::as_instance_row(), get_validation_nonce());
			if (!state)
				return layer_exception("validator production required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_production(std::move(*state->as<states::validator_production>()));
		}
		expects_lr<states::validator_production_reward> executor_context::get_validator_production_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_production_reward::as_instance_type(), changelog, states::validator_production_reward::as_instance_column(owner), states::validator_production_reward::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return layer_exception("validator production reward required but not found (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_production_reward(std::move(*state->as<states::validator_production_reward>()));
		}
		expects_lr<vector<states::validator_production_reward>> executor_context::get_validator_production_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::validator_production_reward::as_instance_type(), changelog, states::validator_production_reward::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("validator production reward(s) required but not applicable (" + states.what() + ")");

			vector<states::validator_production_reward> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::validator_production_reward>()));
			}
			return addresses;
		}
		expects_lr<states::validator_participation> executor_context::get_validator_participation(const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_column(owner), states::validator_participation::as_instance_row(), get_validation_nonce());
			if (!state)
				return layer_exception("validator participation required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_participation(std::move(*state->as<states::validator_participation>()));
		}
		expects_lr<states::validator_participation_reward> executor_context::get_validator_participation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_participation_reward::as_instance_type(), changelog, states::validator_participation_reward::as_instance_column(owner), states::validator_participation_reward::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return layer_exception("validator participation reward required but not found (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_participation_reward(std::move(*state->as<states::validator_participation_reward>()));
		}
		expects_lr<vector<states::validator_participation_reward>> executor_context::get_validator_participation_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::validator_participation_reward::as_instance_type(), changelog, states::validator_participation_reward::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("validator participation reward(s) required but not applicable (" + states.what() + ")");

			vector<states::validator_participation_reward> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::validator_participation_reward>()));
			}
			return addresses;
		}
		expects_lr<vector<states::validator_participation_ref>> executor_context::get_validator_participation_refs(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::validator_participation_ref::as_instance_type(), changelog, states::validator_participation_ref::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("validator participation ref(s) required but not applicable (" + states.what() + ")");

			vector<states::validator_participation_ref> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::validator_participation_ref>()));
			}
			return addresses;
		}
		expects_lr<states::validator_attestation> executor_context::get_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_column(owner), states::validator_attestation::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return layer_exception("validator attestation required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_attestation(std::move(*state->as<states::validator_attestation>()));
		}
		expects_lr<states::validator_attestation> executor_context::get_verified_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto attestation = get_validator_attestation(asset, owner);
			if (attestation && !attestation->is_active())
				return layer_exception("validator attestation is inactive");

			return attestation;
		}
		expects_lr<vector<states::validator_attestation>> executor_context::get_validator_attestations(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("validator attestation(s) required but not applicable (" + states.what() + ")");

			vector<states::validator_attestation> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::validator_attestation>()));
			}
			return addresses;
		}
		expects_lr<states::validator_attestation_reward> executor_context::get_validator_attestation_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_attestation_reward::as_instance_type(), changelog, states::validator_attestation_reward::as_instance_column(owner), states::validator_attestation_reward::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return layer_exception("validator attestation reward required but not found (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::validator_attestation_reward(std::move(*state->as<states::validator_attestation_reward>()));
		}
		expects_lr<vector<states::validator_attestation_reward>> executor_context::get_validator_attestation_rewards(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::validator_attestation_reward::as_instance_type(), changelog, states::validator_attestation_reward::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("validator attestation reward(s) required but not applicable (" + states.what() + ")");

			vector<states::validator_attestation_reward> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::validator_attestation_reward>()));
			}
			return addresses;
		}
		expects_lr<states::bridge_instance> executor_context::get_bridge_instance(const algorithm::asset_id& asset, const uint256_t& bridge_hash) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::bridge_instance::as_instance_type(), changelog, states::bridge_instance::as_instance_column(asset), states::bridge_instance::as_instance_row(bridge_hash), get_validation_nonce());
			if (!state)
				return layer_exception("bridge instance required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::bridge_instance(std::move(*state->as<states::bridge_instance>()));
		}
		expects_lr<vector<states::bridge_instance>> executor_context::get_bridge_instances(const uint256_t& asset, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::bridge_instance::as_instance_type(), changelog, states::bridge_instance::as_instance_column(asset), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("bridge instance(s) required but not applicable (" + states.what() + ")");

			vector<states::bridge_instance> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::bridge_instance>()));
			}
			return addresses;
		}
		expects_lr<states::bridge_queue> executor_context::get_bridge_queue(const algorithm::asset_id& asset, const uint256_t& bridge_hash, int8_t side) const
		{
			auto filter = storages::result_filter::greater(0, side);
			auto window = storages::result_range_window(0, 1);
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column_filter(states::bridge_queue::as_instance_type(), changelog, states::bridge_queue::as_instance_column(asset, bridge_hash), filter, get_validation_nonce(), window);
			if (!states)
				return layer_exception("bridge queue required but not applicable (" + states.what() + ")");
			else if (states->empty())
				return layer_exception("bridge queue required but not applicable (empty list)");

			auto& state = states->front();
			auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
			if (!status)
				return status.error();

			return states::bridge_queue(std::move(*state.as<states::bridge_queue>()));
		}
		expects_lr<states::bridge_balance> executor_context::get_bridge_balance(const algorithm::asset_id& asset, const uint256_t& bridge_hash) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::bridge_balance::as_instance_type(), changelog, states::bridge_balance::as_instance_column(asset), states::bridge_balance::as_instance_row(bridge_hash), get_validation_nonce());
			if (!state)
				return layer_exception("bridge balance required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::bridge_balance(std::move(*state->as<states::bridge_balance>()));
		}
		expects_lr<vector<states::bridge_balance>> executor_context::get_bridge_balances(const uint256_t& bridge_hash, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_row(states::bridge_balance::as_instance_type(), changelog, states::bridge_balance::as_instance_row(bridge_hash), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("bridge balance(s) required but not applicable (" + states.what() + ")");

			vector<states::bridge_balance> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::bridge_balance>()));
			}
			return addresses;
		}
		expects_lr<vector<states::bridge_account>> executor_context::get_bridge_accounts(const uint256_t& bridge_hash, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_row(states::bridge_account::as_instance_type(), changelog, states::bridge_account::as_instance_row(bridge_hash), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("bridge account(s) required but not applicable (" + states.what() + ")");

			vector<states::bridge_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::bridge_account>()));
			}
			return addresses;
		}
		expects_lr<states::bridge_account> executor_context::get_bridge_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& bridge_hash) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::bridge_account::as_instance_type(), changelog, states::bridge_account::as_instance_column(asset, owner), states::bridge_account::as_instance_row(bridge_hash), get_validation_nonce());
			if (!state)
				return layer_exception("bridge account required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::bridge_account(std::move(*state->as<states::bridge_account>()));
		}
		expects_lr<states::witness_program> executor_context::get_witness_program(const std::string_view& program_hashcode) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_program::as_instance_type(), changelog, states::witness_program::as_instance_index(program_hashcode), get_validation_nonce());
			if (!state)
				return layer_exception("witness program required but not applicable (" + state.what() + ")");

			if (!state->cached)
			{
				uint64_t optimized_program_size = algorithm::arithmetic::integer_sqrt<uint64_t>((uint64_t)state->ptr()->as_message().data.size());
				auto status = ((executor_context*)this)->burn_gas(optimized_program_size * (size_t)gas_cost::program_byte);
				if (!status)
					return status.error();
			}

			return states::witness_program(std::move(*state->as<states::witness_program>()));
		}
		expects_lr<states::witness_event> executor_context::get_witness_event(const uint256_t& parent_transaction_hash) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_event::as_instance_type(), changelog, states::witness_event::as_instance_index(parent_transaction_hash), get_validation_nonce());
			if (!state)
				return layer_exception("witness event required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::witness_event(std::move(*state->as<states::witness_event>()));
		}
		expects_lr<vector<states::witness_account>> executor_context::get_witness_accounts(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_column(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return layer_exception("witness account(s) required but not applicable (" + states.what() + ")");

			vector<states::witness_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::witness_account>()));
			}
			return addresses;
		}
		expects_lr<vector<states::witness_account>> executor_context::get_witness_accounts_by_purpose(const algorithm::pubkeyhash_t& owner, states::witness_account::account_type purpose, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::equal((uint64_t)purpose, 1);
			auto states = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), filter, get_validation_nonce(), storages::result_range_window(offset, count));
			if (!states)
				return layer_exception("witness account(s) required but not applicable (" + states.what() + ")");

			vector<states::witness_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
			{
				auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
				if (!status)
					return status.error();

				addresses.emplace_back(std::move(*state.as<states::witness_account>()));
			}
			return addresses;
		}
		expects_lr<states::witness_account> executor_context::get_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner, const std::string_view& address) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), states::witness_account::as_instance_row(asset, address), get_validation_nonce());
			if (!state)
				return layer_exception("witness account required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::witness_account(std::move(*state->as<states::witness_account>()));
		}
		expects_lr<states::witness_account> executor_context::get_witness_account(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const
		{
			auto chain = storages::chainstate();
			auto states = chain.get_multiforms_by_row(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_row(asset, address), get_validation_nonce(), offset, 1);
			if (!states)
				return layer_exception("witness account required but not applicable (" + states.what() + ")");
			else if (states->empty())
				return layer_exception("witness account required but not applicable (empty list)");

			auto& state = states->front();
			auto status = ((executor_context*)this)->query(state.ptr(), !state.cached);
			if (!status)
				return status.error();

			return states::witness_account(std::move(*state.as<states::witness_account>()));
		}
		expects_lr<states::witness_account> executor_context::get_witness_account_tagged(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const
		{
			auto result = get_witness_account(asset, address, offset);
			if (!result)
				result = get_witness_account(asset, superchain::address_util::encode_tag_address(address, "0"), offset);
			return result;
		}
		expects_lr<states::witness_transaction> executor_context::get_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id) const
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_transaction::as_instance_type(), changelog, states::witness_transaction::as_instance_index(asset, transaction_id), get_validation_nonce());
			if (!state)
				return layer_exception("witness transaction required but not applicable (" + state.what() + ")");

			auto status = ((executor_context*)this)->load(state->ptr(), !state->cached);
			if (!status)
				return status.error();

			return states::witness_transaction(std::move(*state->as<states::witness_transaction>()));
		}
		expects_lr<block_transaction> executor_context::get_block_transaction_instance(const uint256_t& transaction_hash, bool may_have_distinct_asset) const
		{
			if (!transaction_hash)
				return layer_exception("block transaction not found");

			auto chain = storages::chainstate();
			auto candidate = chain.get_block_transaction_by_hash(transaction_hash, false);
			if (!candidate || !candidate->transaction || !candidate->receipt.successful)
				return layer_exception("block transaction not found");

			auto& policy = protocol::now().policy;
			if (block != nullptr && candidate->receipt.block_number <= block->number && block->number - candidate->receipt.block_number > policy.participation.referencing_time / policy.pow.time)
				return layer_exception("block transaction reference is too far into the past");

			if (!may_have_distinct_asset && transaction && transaction->asset != candidate->transaction->asset)
				return layer_exception("block transaction asset is distinct");

			if (candidate->receipt.transaction_hash != transaction_hash && candidate->transaction->as_type() == transactions::rollup::as_instance_type())
				candidate = ((transactions::rollup*)*candidate->transaction)->resolve_block_transaction(candidate->receipt, transaction_hash);

			return candidate;
		}
		uint64_t executor_context::get_validation_nonce() const
		{
			if (!solver)
				return block ? block->number : 0;

			switch (solver->state.origin)
			{
				default:
				case solver_context::state_origin::chain:
					return 0;
				case solver_context::state_origin::chain_block:
					return block ? block->number + 1 : 0;
				case solver_context::state_origin::block:
					return block ? block->number : 1;
			}
		}
		uint256_t executor_context::get_gas_use() const
		{
			return receipt.relative_gas_use;
		}
		uint256_t executor_context::get_gas_left() const
		{
			if (!transaction)
				return 0;

			return transaction->gas_limit > receipt.relative_gas_use ? transaction->gas_limit - receipt.relative_gas_use : uint256_t(0);
		}
		decimal executor_context::get_gas_cost() const
		{
			if (!transaction || !transaction->gas_price.is_positive())
				return 0;

			return transaction->gas_price * get_gas_use().to_decimal();
		}
		expects_lr<uint256_t> executor_context::calculate_tx_gas(const transaction_message* transaction, transaction_receipt* out_receipt)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			algorithm::pubkeyhash_t owner;
			if (!transaction->recover_hash(owner))
				return layer_exception("invalid signature");

			auto* reference = (transaction_message*)transaction;
			auto initial_checksum = transaction->checksum;
			auto initial_gas_limit = transaction->gas_limit;
			auto revert_transaction = [&]()
			{
				reference->checksum = initial_checksum;
				reference->gas_limit = initial_gas_limit;
			};
			reference->checksum = 0;
			reference->gas_limit = block_header::get_gas_limit();

			ledger::block_body temp_block;
			solver_context temp_solver;
			temp_solver.apply_temporary_state(&temp_block, transaction, { });

			block_changelog temp_changelog;
			size_t transaction_size = transaction->as_message().data.size();
			auto execution = executor_context::execute_tx(&temp_solver, &temp_block, &temp_changelog, transaction, transaction->as_hash(), owner, transaction_size, (uint8_t)flags::pedantic | (uint8_t)flags::evaluation);
			if (!execution)
			{
				revert_transaction();
				return execution.error();
			}

			execution->receipt.relative_gas_use += 64 * (uint64_t)gas_cost::write_byte;
			auto gas = execution->receipt.relative_gas_use - (execution->receipt.relative_gas_use % 1000) + 1000;
			execution->receipt.relative_gas_use = gas;
			if (out_receipt != nullptr)
				*out_receipt = std::move(execution->receipt);
			revert_transaction();
			return gas;
		}
		expects_lr<void> executor_context::validate_tx(const transaction_message* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash_t& owner)
		{
			VI_ASSERT(new_transaction, "transaction should be set");
			owner.clear();
			if (!algorithm::signing::recover_hash(new_transaction_hash, owner, new_transaction->signature))
				return layer_exception("invalid signature");

			auto chain = storages::chainstate();
			return new_transaction->validate(chain.get_latest_block_number().or_else(1));
		}
		expects_lr<executor_context> executor_context::execute_tx(const solver_context* new_solver, block_header* new_block, block_changelog* changelog, const transaction_message* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash_t& owner, size_t transaction_size, uint8_t options, option<transaction_receipt>&& from_receipt)
		{
			VI_ASSERT(new_solver && new_block && new_transaction, "block, env, transaction should be set");
			auto new_receipt = from_receipt ? std::move(*from_receipt) : transaction_receipt();
			new_receipt.transaction_hash = new_transaction_hash;
			new_receipt.absolute_gas_use = new_block->gas_use;
			new_receipt.block_number = new_block->number;
			new_receipt.from = owner;

			auto validation = new_transaction->validate(new_receipt.block_number);
			if (!validation)
				return validation.error();

			auto executor = executor_context(changelog, new_solver, new_block, new_transaction, std::move(new_receipt));
			executor.options = options;

			auto storage = executor.burn_gas(transaction_size * (size_t)gas_cost::write_tx_byte);
			if (!storage)
				return storage.error();

			bool discard = (executor.receipt.events.size() == 1 && executor.receipt.events.front().first == 0 && executor.receipt.events.front().second.size() == 1);
			auto execution = discard ? expects_lr<void>(layer_exception(executor.receipt.events.front().second.front().as_blob())) : executor.transaction->execute(&executor);
			executor.receipt.successful = !!execution;
			if (!executor.receipt.successful && executor.changelog != nullptr)
				executor.changelog->outgoing.revert();
			if (discard)
				executor.receipt.events.clear();
			if ((executor.options & (uint8_t)flags::pedantic) && !executor.receipt.successful)
				return execution.error();

			if (!executor.receipt.from.empty() && !(executor.options & (uint8_t)flags::replayable))
			{
				auto nonce = (executor.options & (uint8_t)flags::evaluation ? executor.get_account_nonce(executor.receipt.from).or_else(states::account_nonce(algorithm::pubkeyhash_t(), nullptr)).nonce : executor.transaction->nonce);
				auto change = executor.apply_account_nonce(executor.receipt.from, nonce + 1);
				if (!change)
					return change.error();
			}

			if (executor.receipt.relative_gas_use > 0 && executor.transaction->gas_price.is_positive())
			{
				auto fee = executor.apply_fee_transfer(executor.transaction->gas_asset(), executor.receipt.from, executor.transaction->gas_price * executor.receipt.relative_gas_use.to_decimal());
				if (!fee)
					return fee.error();
			}

			if (executor.receipt.successful)
			{
				for (auto& item : executor.witnesses)
					executor.block->set_witness_requirement(item.first, item.second);
			}
			else
				executor.emit_event(0, { format::variable(execution.what()) }, false);

			executor.options = 0;
			executor.block->gas_use += executor.receipt.relative_gas_use;
			executor.block->gas_limit += executor.transaction->gas_limit;
			executor.receipt.block_time = protocol::now().time.now();
			return expects_lr<executor_context>(std::move(executor));
		}
		expects_promise_rt<void> executor_context::dispatch_tx(dispatcher_context* dispatcher, block_transaction* transaction)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			VI_ASSERT(dispatcher != nullptr, "dispatcher should be set");
			if (!transaction->receipt.successful)
				return expects_promise_rt<void>(expectation::met);

			auto* executor = memory::init<executor_context>(nullptr);
			executor->transaction = *transaction->transaction;
			executor->receipt = transaction->receipt;
			return transaction->transaction->dispatch(executor, dispatcher).then<expects_rt<void>>([transaction, executor](expects_rt<void>&& result)
			{
				memory::deinit(executor);
				return std::move(result);
			});
		}

		solver_context::queued_transaction::queued_transaction(const queued_transaction& other) : hash(other.hash), owner(other.owner), size(other.size)
		{
			auto* reference = (queued_transaction*)&other;
			candidate = reference->candidate.reset();
		}
		solver_context::queued_transaction& solver_context::queued_transaction::operator= (const queued_transaction& other)
		{
			if (this == &other)
				return *this;

			auto* reference = (queued_transaction*)&other;
			hash = other.hash;
			owner = other.owner;
			size = other.size;
			candidate = reference->candidate.reset();
			return *this;
		}

		bool dispatcher_context::secret_entropy::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(hash);
			stream->write_integer(asset);
			stream->write_string(owner.optimized_view());
			stream->write_string(entropy.optimized_view());
			stream->write_integer((uint8_t)shares.size());
			for (auto& [participant, share] : shares)
			{
				stream->write_string(participant.optimized_view());
				stream->write_string(share.input.optimized_view());
				stream->write_string(share.output.optimized_view());
			}
			return true;
		}
		bool dispatcher_context::secret_entropy::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			string entropy_assembly;
			if (!stream.read_string(stream.read_type(), &entropy_assembly) || !algorithm::encoding::decode_bytes(entropy_assembly, entropy.blob, sizeof(entropy)))
				return false;

			uint8_t shares_size;
			if (!stream.read_integer(stream.read_type(), &shares_size))
				return false;

			shares.clear();
			for (uint8_t i = 0; i < shares_size; i++)
			{
				string participant_assembly; algorithm::pubkeyhash_t participant;
				if (!stream.read_string(stream.read_type(), &participant_assembly) || !algorithm::encoding::decode_bytes(participant_assembly, participant.blob, sizeof(participant)))
					return false;

				auto& pair = shares[participant]; string share_assembly;
				if (!stream.read_string(stream.read_type(), &share_assembly) || !algorithm::encoding::decode_bytes(share_assembly, pair.input.blob, sizeof(pair.input)))
					return false;

				if (!stream.read_string(stream.read_type(), &share_assembly) || !algorithm::encoding::decode_bytes(share_assembly, pair.output.blob, sizeof(pair.output)))
					return false;
			}
			return true;
		}
		format::tree dispatcher_context::secret_entropy::as_tree() const
		{
			format::tree data;
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("hash", algorithm::encoding::serialize_uint256(hash));
			data.set("entropy", format::variable(algorithm::encoding::encode_0xhex256(entropy.view())));
			auto* shares_data = data.set("shares", format::tree::list());
			for (auto& [participant, share] : shares)
			{
				auto* share_data = shares_data->push(format::tree::map());
				share_data->set("participant", algorithm::signing::serialize_address(participant));
				share_data->set("input", format::variable(format::util::encode_0xhex(share.input.optimized_view())));
				share_data->set("output", format::variable(format::util::encode_0xhex(share.output.optimized_view())));
			}
			return data;
		}
		uint32_t dispatcher_context::secret_entropy::as_type() const
		{
			return as_instance_type();
		}
		std::string_view dispatcher_context::secret_entropy::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t dispatcher_context::secret_entropy::as_ref_hash() const
		{
			return ref_hash(owner, asset, hash);
		}
		uint32_t dispatcher_context::secret_entropy::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view dispatcher_context::secret_entropy::as_instance_typename()
		{
			return "secret_entropy";
		}
		uint256_t dispatcher_context::secret_entropy::ref_hash(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash)
		{
			format::wo_stream message;
			message.write_string(owner.view());
			message.write_integer(asset);
			message.write_integer(hash);
			return message.hash();
		}

		bool dispatcher_context::entropy_distribution_state::load_message(format::ro_stream& stream)
		{
			uint16_t encrypted_shares_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_shares_size))
				return false;

			encrypted_shares.clear();
			for (uint16_t i = 0; i < encrypted_shares_size; i++)
			{
				algorithm::pubkeyhash_t item; string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
					return false;

				string encrypted_share;
				if (!stream.read_string(stream.read_type(), &encrypted_share))
					return false;

				encrypted_shares[item] = std::move(encrypted_share);
			}

			return true;
		}
		format::wo_stream dispatcher_context::entropy_distribution_state::as_message() const
		{
			format::wo_stream message;
			message.write_integer((uint16_t)encrypted_shares.size());
			for (auto& [participant, encrypted_share] : encrypted_shares)
			{
				message.write_string(participant.optimized_view());
				message.write_string(encrypted_share);
			}
			return message;
		}

		bool dispatcher_context::entropy_aggregation_state::load_message(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &attempt))
				return false;

			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly) || !algorithm::encoding::decode_bytes(public_key_assembly, public_key.blob, sizeof(public_key)))
				return false;

			uint16_t encrypted_shares_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_shares_size))
				return false;

			encrypted_shares.clear();
			for (uint16_t i = 0; i < encrypted_shares_size; i++)
			{
				uint256_t hash;
				if (!stream.read_integer(stream.read_type(), &hash))
					return false;

				uint16_t encrypted_values_size;
				if (!stream.read_integer(stream.read_type(), &encrypted_values_size))
					return false;

				auto& encrypted_values = encrypted_shares[hash];
				for (uint16_t j = 0; j < encrypted_values_size; j++)
				{
					algorithm::pubkeyhash_t item; string intermediate;
					if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
						return false;

					string encrypted_value;
					if (!stream.read_string(stream.read_type(), &encrypted_value))
						return false;

					encrypted_values[item] = std::move(encrypted_value);
				}
			}

			uint8_t participants_size;
			if (!stream.read_integer(stream.read_type(), &participants_size))
				return false;

			participants.clear();
			for (uint16_t i = 0; i < participants_size; i++)
			{
				algorithm::pubkeyhash_t item; string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
					return false;

				participants.insert(item);
			}

			return true;
		}
		format::wo_stream dispatcher_context::entropy_aggregation_state::as_message() const
		{
			format::wo_stream message;
			message.write_integer(attempt);
			message.write_string(public_key.optimized_view());
			message.write_integer((uint16_t)encrypted_shares.size());
			for (auto& [hash, encrypted_values] : encrypted_shares)
			{
				message.write_integer(hash);
				message.write_integer((uint16_t)encrypted_values.size());
				for (auto& [participant, encrypted_value] : encrypted_values)
				{
					message.write_string(participant.optimized_view());
					message.write_string(encrypted_value);
				}
			}
			message.write_integer((uint8_t)participants.size());
			for (auto& participant : participants)
				message.write_string(participant.optimized_view());
			return message;
		}

		bool dispatcher_context::entropy_recovery_state::load_message(format::ro_stream& stream)
		{
			string proof_assembly;
			if (!stream.read_string(stream.read_type(), &proof_assembly) || !algorithm::encoding::decode_bytes(proof_assembly, proof.blob, sizeof(proof)))
				return false;

			uint16_t encrypted_shares_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_shares_size))
				return false;

			encrypted_shares.clear();
			for (uint16_t i = 0; i < encrypted_shares_size; i++)
			{
				uint256_t hash;
				if (!stream.read_integer(stream.read_type(), &hash))
					return false;

				uint16_t encrypted_values_size;
				if (!stream.read_integer(stream.read_type(), &encrypted_values_size))
					return false;

				auto& encrypted_values = encrypted_shares[hash];
				for (uint16_t j = 0; j < encrypted_values_size; j++)
				{
					algorithm::pubkeyhash_t item; string intermediate;
					if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
						return false;

					string encrypted_value;
					if (!stream.read_string(stream.read_type(), &encrypted_value))
						return false;

					encrypted_values[item] = std::move(encrypted_value);
				}
			}

			uint16_t encrypted_entropies_size;
			if (!stream.read_integer(stream.read_type(), &encrypted_entropies_size))
				return false;

			encrypted_entropies.clear();
			for (uint16_t i = 0; i < encrypted_entropies_size; i++)
			{
				uint256_t hash;
				if (!stream.read_integer(stream.read_type(), &hash))
					return false;

				string encrypted_secret;
				if (!stream.read_string(stream.read_type(), &encrypted_secret))
					return false;

				encrypted_entropies[hash] = std::move(encrypted_secret);
			}

			return true;
		}
		format::wo_stream dispatcher_context::entropy_recovery_state::as_message() const
		{
			format::wo_stream message;
			message.write_string(proof.optimized_view());
			message.write_integer((uint16_t)encrypted_shares.size());
			for (auto& [hash, encrypted_values] : encrypted_shares)
			{
				message.write_integer(hash);
				message.write_integer((uint16_t)encrypted_values.size());
				for (auto& [participant, encrypted_value] : encrypted_values)
				{
					message.write_string(participant.optimized_view());
					message.write_string(encrypted_value);
				}
			}
			message.write_integer((uint16_t)encrypted_entropies.size());
			for (auto& [hash, encrypted_entropy] : encrypted_entropies)
			{
				message.write_integer(hash);
				message.write_string(encrypted_entropy);
			}
			return message;
		}

		bool dispatcher_context::public_state::load_compositor_transition(format::ro_stream& stream)
		{
			auto state = algorithm::composition::make_compositor(alg);
			if (!state)
				return false;

			auto& state_ptr = *state;
			if (!state_ptr->load(stream))
				return false;

			if (compositor && !compositor->may_transition_to(**state_ptr))
				return false;

			compositor = std::move(state_ptr);
			return true;
		}
		bool dispatcher_context::public_state::load(format::ro_stream& stream)
		{
			bool has_compositor = false;
			if (!stream.read_boolean(stream.read_type(), &has_compositor))
				return false;

			auto state = has_compositor ? algorithm::composition::load_compositor(stream, &alg) : expects_lr<uptr<algorithm::composition::compositor>>(layer_exception());
			if (has_compositor && !state)
				return false;

			if (!stream.read_boolean(stream.read_type(), &distribution))
				return false;

			if (!stream.read_integer(stream.read_type(), &attempt))
				return false;

			uint8_t participants_size;
			if (!stream.read_integer(stream.read_type(), &participants_size))
				return false;

			btree_set<algorithm::pubkeyhash_t> possible_participants;
			for (uint16_t i = 0; i < participants_size; i++)
			{
				algorithm::pubkeyhash_t item; string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
					return false;

				possible_participants.insert(item);
			}

			uint8_t shares_size;
			if (!stream.read_integer(stream.read_type(), &shares_size))
				return false;

			btree_map<algorithm::pubkey_t, btree_map<algorithm::pubkeyhash_t, string>> possible_shares;
			for (uint16_t i = 0; i < shares_size; i++)
			{
				algorithm::pubkey_t public_key; string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, public_key.blob, sizeof(public_key)))
					return false;

				uint8_t values_size;
				if (!stream.read_integer(stream.read_type(), &values_size))
					return false;

				auto& values = possible_shares[public_key];
				for (uint16_t j = 0; j < values_size; j++)
				{
					algorithm::pubkeyhash_t participant;
					if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
						return false;

					string encrypted_share;
					if (!stream.read_string(stream.read_type(), &encrypted_share))
						return false;

					values[participant] = std::move(encrypted_share);
				}
			}

			if (has_compositor)
				compositor = std::move(*state);
			else
				compositor.destroy();
			participants = std::move(possible_participants);
			encrypted_shares = std::move(possible_shares);
			return true;
		}
		format::wo_stream dispatcher_context::public_state::as_message() const
		{
			format::wo_stream result;
			result.write_boolean(!!compositor);
			if (compositor)
				algorithm::composition::store_compositor(alg, *compositor, &result);
			result.write_boolean(distribution);
			result.write_integer(attempt);
			result.write_integer((uint8_t)encrypted_shares.size());
			for (auto& [public_key, values] : encrypted_shares)
			{
				result.write_string(public_key.optimized_view());
				result.write_integer((uint8_t)values.size());
				for (auto& [participant, value] : values)
				{
					result.write_string(participant.optimized_view());
					result.write_string(value);
				}
			}
			result.write_integer((uint8_t)participants.size());
			for (auto& participant : participants)
				result.write_string(participant.optimized_view());
			return result;
		}

		bool dispatcher_context::signature_state::load_compositor_transition(format::ro_stream& stream)
		{
			auto state = algorithm::composition::make_compositor(alg);
			if (!state)
				return false;

			auto& state_ptr = *state;
			if (!state_ptr->load(stream))
				return false;

			if (compositor && !compositor->may_transition_to(**state_ptr))
				return false;

			compositor = std::move(state_ptr);
			return true;
		}
		bool dispatcher_context::signature_state::load(format::ro_stream& stream)
		{
			bool has_compositor = false;
			if (!stream.read_boolean(stream.read_type(), &has_compositor))
				return false;

			auto state = has_compositor ? algorithm::composition::load_compositor(stream, &alg) : expects_lr<uptr<algorithm::composition::compositor>>(layer_exception());
			if (has_compositor && !state)
				return false;

			superchain::prepared_transaction possible_message;
			if (!possible_message.load(stream))
				return false;

			if (!stream.read_integer(stream.read_type(), &attempt))
				return false;

			uint16_t participants_size;
			if (!stream.read_integer(stream.read_type(), &participants_size))
				return false;

			btree_set<algorithm::pubkeyhash_t> possible_participants;
			for (uint16_t i = 0; i < participants_size; i++)
			{
				algorithm::pubkeyhash_t item; string intermediate;
				if (!stream.read_string(stream.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
					return false;

				possible_participants.insert(item);
			}

			if (has_compositor)
				compositor = std::move(*state);
			else
				compositor.destroy();
			participants = std::move(possible_participants);
			message = memory::init<superchain::prepared_transaction>(std::move(possible_message));
			return true;
		}
		format::wo_stream dispatcher_context::signature_state::as_message() const
		{
			VI_ASSERT(message, "message should be set");
			format::wo_stream result;
			result.write_boolean(!!compositor);
			if (compositor)
				algorithm::composition::store_compositor(alg, *compositor, &result);
			message->store(&result);
			result.write_integer(attempt);
			result.write_integer((uint16_t)participants.size());
			for (auto& participant : participants)
				result.write_string(participant.optimized_view());
			return result;
		}

		dispatcher_context::dispatcher_context(const dispatcher_context& other) noexcept : inputs(other.inputs)
		{
			outputs.reserve(other.outputs.size());
			for (auto& [wallet, output] : other.outputs)
			{
				auto* copy = transactions::resolver::from_copy(*output);
				if (copy)
					outputs.push_back(std::make_pair(wallet, copy));
			}
		}
		dispatcher_context& dispatcher_context::operator=(const dispatcher_context& other) noexcept
		{
			if (this == &other)
				return *this;

			inputs = other.inputs;
			outputs.clear();
			outputs.reserve(other.outputs.size());
			for (auto& [wallet, output] : other.outputs)
			{
				auto* copy = transactions::resolver::from_copy(*output);
				if (copy)
					outputs.push_back(std::make_pair(wallet, copy));
			}
			return *this;
		}
		expects_lr<dispatcher_context::secret_entropy> dispatcher_context::apply_secret_entropy(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash, const algorithm::storage_type<uint8_t, 64>& entropy, btree_map<algorithm::pubkeyhash_t, secret_entropy::share_pair>&& shares)
		{
			VI_ASSERT(runner_wallet != nullptr, "runner wallet should be set");
			secret_entropy result;
			result.owner = owner;
			result.asset = asset;
			result.hash = hash;
			result.entropy = entropy;
			result.shares = std::move(shares);

			auto mempool = storages::mempoolstate();
			auto status = mempool.apply_secret_entropy(runner_wallet->public_key_hash, result);
			if (!status)
				return status.error();

			return expects_lr<dispatcher_context::secret_entropy>(std::move(result));
		}
		expects_lr<dispatcher_context::secret_entropy> dispatcher_context::recover_secret_entropy(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash)
		{
			VI_ASSERT(runner_wallet != nullptr, "runner wallet should be set");
			auto mempool = storages::mempoolstate();
			auto result = mempool.get_secret_entropy(runner_wallet->public_key_hash, owner, asset, hash);
			if (result)
				return result;

			uint8_t entropy_source_1[sizeof(asset)], entropy_source_2[sizeof(hash)];
			auto entropy_source_3 = runner_wallet->secret_key.view();
			auto entropy_source_4 = format::util::decode_0xhex(protocol::now().policy.pow.base);
			asset.encode(entropy_source_1);
			hash.encode(entropy_source_2);

			format::wo_stream entropy_source;
			entropy_source.write_string(algorithm::hashing::hash512(entropy_source_1, sizeof(entropy_source_1)));
			entropy_source.write_string(algorithm::hashing::hash512(entropy_source_2, sizeof(entropy_source_2)));
			entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source_3.data(), entropy_source_3.size()));
			entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source_4.data(), entropy_source_4.size()));
			entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source.data.data(), entropy_source.data.size()));

			algorithm::storage_type<uint8_t, 64> entropy;
			if (!algorithm::signing::derive_seed_from_password((uint8_t*)entropy_source.data.data(), entropy_source.data.size(), entropy.blob, entropy.size()))
				return layer_exception("secret entropy source generation failed");

			return apply_secret_entropy(runner_wallet, owner, asset, hash, entropy, { });
		}
		expects_lr<void> dispatcher_context::checkpoint()
		{
			auto chain = storages::chainstate();
			return chain.dispatch(inputs, repeaters);
		}
		promise<void> dispatcher_context::dispatch_async(uint64_t block_number)
		{
			if (!block_number)
				return promise<void>::null();

			return coasync<void>([this, block_number]() -> promise<void>
			{
				size_t offset = 0, count = 512;
				while (true)
				{
					auto candidates = storages::chainstate().get_pending_block_transactions(block_number, offset, count);
					if (!candidates || candidates->empty())
						break;

					offset += candidates->size();
					for (auto& input : *candidates)
					{
						auto execution = coawait(executor_context::dispatch_tx(this, &input));
						if (!execution)
						{
							if (!execution.error().is_retry() && !execution.error().is_shutdown())
								report_error(input.receipt.transaction_hash, execution.error().what());
							else
								retry_later(input.receipt.transaction_hash);
						}
						report_trial(input.receipt.transaction_hash);
					}
					if (candidates->size() < count)
						break;
				}
				coreturn_void;
			});
		}
		void dispatcher_context::dispatch_sync(uint64_t block_number)
		{
			size_t offset = 0, count = 512;
			while (block_number > 0)
			{
				auto chain = storages::chainstate();
				auto candidates = chain.get_pending_block_transactions(block_number, offset, count);
				if (!candidates || candidates->empty())
					break;

				offset += candidates->size();
				for (auto& input : *candidates)
				{
					auto execution = executor_context::dispatch_tx(this, &input).get();
					if (!execution)
					{
						if (!execution.error().is_retry() && !execution.error().is_shutdown())
							report_error(input.receipt.transaction_hash, execution.error().what());
						else
							retry_later(input.receipt.transaction_hash);
					}
					report_trial(input.receipt.transaction_hash);
				}
				if (candidates->size() < count)
					break;
			}
		}
		void dispatcher_context::reset_for_checkpoint()
		{
			errors.clear();
			outputs.clear();
			inputs.clear();
			repeaters.clear();
		}
		void dispatcher_context::emit_transaction(const wallet* runner_wallet, uptr<transaction_message>&& value)
		{
			VI_ASSERT(runner_wallet, "runner wallet should be set");
			VI_ASSERT(value, "transaction should be set");
			outputs.push_back(std::make_pair(runner_wallet, std::move(value)));
		}
		void dispatcher_context::retry_later(const uint256_t& transaction_hash)
		{
			repeaters.push_back(transaction_hash);
		}
		void dispatcher_context::report_trial(const uint256_t& transaction_hash)
		{
			inputs.push_back(transaction_hash);
		}
		void dispatcher_context::report_error(const uint256_t& transaction_hash, const std::string_view& error_message)
		{
			auto& error = errors[transaction_hash];
			if (!error.empty())
				error.append(1, '\n');
			error.append(error_message);
		}
		vector<std::pair<const ledger::wallet*, uptr<transaction_message>>>& dispatcher_context::get_sendable_transactions()
		{
			return outputs;
		}
		format::ro_stream dispatcher_context::pull_cache(const executor_context* executor)
		{
			auto* offchain = superchain::bridge::get();
			auto location = stringify::text("dispatch_cache_%s", algorithm::encoding::encode_0xhex256(executor->receipt.transaction_hash).c_str());
			auto cache = offchain->load_cache(executor->transaction->asset, superchain::cache_policy::lifetime_cache, location);
			offchain->store_cache(executor->transaction->asset, superchain::cache_policy::lifetime_cache, location, format::tree());
			return format::ro_stream(cache ? cache->value.as_string() : std::string_view());
		}
		void dispatcher_context::push_cache(const executor_context* executor, const format::wo_stream& message) const
		{
			auto location = stringify::text("dispatch_cache_%s", algorithm::encoding::encode_0xhex256(executor->receipt.transaction_hash).c_str());
			superchain::bridge::get()->store_cache(executor->transaction->asset, superchain::cache_policy::lifetime_cache, location, format::variable(message.data));
		}

		void solver_context::apply_temporary_state(block_header* abstract_block, const transaction_message* abstract_transaction, transaction_receipt&& abstract_receipt)
		{
			VI_ASSERT(abstract_block != nullptr, "abstract block should be set");
			VI_ASSERT(abstract_transaction != nullptr, "abstract transaction should be set");
			auto chain = storages::chainstate();
			abstract_block->number = chain.get_latest_block_number().or_else(0) + 1;
			abstract_receipt.transaction_hash = abstract_transaction->as_hash();
			abstract_receipt.block_number = abstract_block->number;

			state.public_key_hash = algorithm::pubkeyhash_t();
			state.secret_key = algorithm::seckey_t();
			state.gas_usage = 0;
			state.commitments = 0;
			state.block_options = 0;
			state.validator_active = true;
			state.executor = executor_context(&state.changelog);
			state.origin = state_origin::chain;
			state.executor = executor_context(&state.changelog, this, abstract_block, abstract_transaction, std::move(abstract_receipt));
			transactions = transaction_queue();
			tip = optional::none;
			producers.clear();
			nonces.clear();
			memset(state.public_key_hash.blob, 0xFF, sizeof(algorithm::pubkeyhash_t));
			memset(state.secret_key.blob, 0xFF, sizeof(algorithm::seckey_t));
		}
		option<uint64_t> solver_context::apply_validator_state(const std::function<ledger::wallet* (size_t)>& try_producer, option<const block_header*>&& parent_block)
		{
			nonces.clear();
			state = state_variables();
			transactions = transaction_queue();
			if (!parent_block)
			{
				auto chain = storages::chainstate();
				auto parent = chain.get_latest_block_header();
				tip = parent ? option<block_header>(std::move(*parent)) : option<block_header>(optional::none);
				state.origin = state_origin::chain;
			}
			else if (*parent_block != nullptr)
			{
				auto chain = storages::chainstate();
				auto parent = chain.get_latest_block_number();
				tip = **parent_block;
				state.origin = parent.or_else(tip->number) < (tip->number + 1) ? state_origin::chain : state_origin::block;
			}
			else
			{
				auto chain = storages::chainstate();
				auto parent = chain.get_latest_block_number();
				tip = option<block_header>(optional::none);
				state.origin = parent ? state_origin::block : state_origin::chain;
			}

			auto origin = state.origin;
			state.executor = executor_context(&state.changelog, this, tip.address(), nullptr, { });
			state.executor.options = tip && tip->network_congestion() ? (uint8_t)executor_context::flags::congestion : 0;
			state.origin = state.origin == state_origin::block ? state_origin::chain_block : state_origin::chain;
			producers = state.executor.calculate_producers(protocol::now().policy.production.max_per_block).or_else(vector<states::validator_production>());
			if (producers.empty())
			{
				while (producers.size() < protocol::now().policy.production.max_per_block)
				{
					auto proposer = try_producer(producers.size());
					if (!proposer)
						break;

					auto work = state.executor.get_validator_production(proposer->public_key_hash);
					if (!work)
						producers.push_back(states::validator_production(proposer->public_key_hash, tip.address()));
					else
						producers.push_back(std::move(*work));
				}
			}

			size_t position = 0;
			state.origin = origin;
			state.executor.block = nullptr;
			for (auto& producer : producers)
			{
				size_t index = 0; ++position;
			next:
				auto target = try_producer(index++);
				if (!target)
					continue;
				else if (producer.owner != target->public_key_hash)
					goto next;

				state.public_key_hash = target->public_key_hash;
				state.secret_key = target->secret_key;
				return position - 1;
			}

			return optional::none;
		}
		size_t solver_context::try_include_transactions(vector<uptr<transaction_message>>&& candidates, hash_set<uint256_t>* hashes)
		{
			if (candidates.empty())
				return 0;

			vector<queued_transaction> subqueue;
			subqueue.reserve(candidates.size());
			transactions.pending.reserve(transactions.pending.size() + candidates.size());
			for (auto& candidate : candidates)
			{
				auto& info = subqueue.emplace_back();
				info.candidate = std::move(candidate);
			}
			precompute_transaction_list(subqueue);

			auto prev_pending_size = transactions.pending.size();
			auto gas_limit = block_header::get_gas_limit();
			for (auto& item : subqueue)
			{
				if (hashes != nullptr)
				{
					if (hashes->find(item.hash) != hashes->end())
						continue;

					hashes->insert(item.hash);
				}

				auto decision = decide_on_inclusion(item);
				if (decision == include_decision::include_in_block)
				{
					auto& nonce = nonces[algorithm::pubkeyhash_t(item.owner)];
					nonce = std::max(item.candidate->nonce, nonce);
					state.gas_usage += item.candidate->gas_limit;
					state.commitments += item.candidate->is_commitment() ? 1 : 0;
					transactions.pending.emplace_back(std::move(item));
					++transactions.queued;
				}
				else if (decision == include_decision::not_executable)
					transactions.failed.insert(item.hash);
			}
			if (state.gas_usage >= gas_limit - gas_limit / 100)
				state.gas_usage = gas_limit;
			return prev_pending_size - transactions.pending.size();
		}
		solver_context::queued_transaction& solver_context::force_include_transaction(uptr<transaction_message>&& candidate)
		{
			VI_ASSERT(candidate, "candidate should be set");
			auto& info = transactions.pending.emplace_back();
			info.candidate = std::move(candidate);
			return info;
		}
		solver_context::include_decision solver_context::decide_on_inclusion(const queued_transaction& item) const
		{
			if (!item.candidate || item.owner.empty())
				return include_decision::not_executable;

			uint256_t new_gas_limit = state.gas_usage + item.candidate->gas_limit;
			if (new_gas_limit < state.gas_usage || new_gas_limit > block_header::get_gas_limit())
				return include_decision::not_includable;

			if (!item.candidate->is_commitment() && (((uint8_t)state.executor.options & (uint8_t)executor_context::flags::congestion) && !item.candidate->gas_price.is_positive()))
				return include_decision::not_includable;
			else if (item.candidate->is_commitment() && state.commitments + 1 > protocol::now().policy.commitments_per_block)
				return include_decision::not_includable;

			auto map_nonce = nonces.find(algorithm::pubkeyhash_t(item.owner));
			if (map_nonce == nonces.end())
			{
				auto chain = storages::chainstate();
				auto nonce_state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(item.owner), 0);
				auto* nonce_value = (states::account_nonce*)(nonce_state ? nonce_state->ptr() : nullptr);
				auto nonce = (nonce_value ? nonce_value->nonce : 0);
				if (item.candidate->nonce < nonce)
					return include_decision::not_executable;
				else if (item.candidate->nonce >= nonce + protocol::now().policy.account_nonce_step_limit)
					return include_decision::not_includable;
			}
			else if (item.candidate->nonce != map_nonce->second + 1)
				return include_decision::not_includable;

			return include_decision::include_in_block;
		}
		expects_lr<void> solver_context::block_evalution_prepare(block_evaluation& solution)
		{
			auto* parent_block = tip.address();
			auto position = std::find_if(producers.begin(), producers.end(), [this](const states::validator_production& a) { return a.owner == state.public_key_hash; });
			solution.block = ledger::block_body();
			solution.block.set_parent_block(parent_block);
			solution.block.priority = (uint64_t)(position == producers.end() ? protocol::now().policy.production.max_per_block : std::distance(producers.begin(), position));
			solution.block.difficulty = algorithm::wesolowski::scale(solution.block.get_proof_slot_target(parent_block), solution.block.get_proof_difficulty_multiplier());
			state.executor = executor_context(&state.changelog, this, &solution.block, nullptr, { });
			state.validator_active = state.executor.get_validator_production(state.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active();
			state.block_options = parent_block && parent_block->network_congestion() ? (uint8_t)executor_context::flags::congestion : 0;
			state.changelog.clear();
			return expectation::met;
		}
		expects_lr<void> solver_context::block_evalution_update(block_evaluation& solution, block_rewards& rewards)
		{
			if (transactions.queued != transactions.pending.size())
			{
				precompute_transaction_list(transactions.pending);
				transactions.queued = transactions.pending.size();
			}

			for (auto& item : transactions.pending)
			{
				uint8_t tx_options = item.candidate->is_commitment() ? (uint8_t)executor_context::flags::pedantic : 0;
				auto execution = executor_context::execute_tx(this, &solution.block, &state.changelog, *item.candidate, item.hash, item.owner, item.size, state.block_options | tx_options);
				if (execution)
				{
					auto& blob = solution.block.transactions.emplace_back();
					blob.transaction = std::move(item.candidate);
					blob.receipt = std::move(execution->receipt);
					if (blob.receipt.relative_gas_use > 0 && blob.transaction->gas_price.is_positive())
					{
						auto& reward = rewards[blob.transaction->asset];
						reward = (reward.is_nan() ? decimal::zero() : reward) + blob.transaction->gas_price * blob.receipt.relative_gas_use.to_decimal();
					}
					state.changelog.commit();
				}
				else
				{
					transactions.failed.insert(item.hash);
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s execution error: %s", algorithm::encoding::encode_0xhex256(item.hash).c_str(), execution.error().what());
				}
				state.changelog.clear_temporary_state();
			}

			transactions.queued = 0;
			transactions.pending.clear();
			return expectation::met;
		}
		expects_lr<void> solver_context::block_evalution_finalize(block_evaluation& solution, block_rewards& rewards)
		{
			auto& coinbase = rewards[algorithm::asset::native()];
			coinbase = coinbase.is_nan() ? block_header::get_coinbase_value(solution.block.number) : (coinbase + block_header::get_coinbase_value(solution.block.number));

			auto penalty = -coinbase;
			auto penalty_queue = std::min((size_t)solution.block.priority, producers.size());
			for (size_t i = 0; i < penalty_queue; i++)
			{
				auto& target = producers[i].owner;
				auto production = state.executor.get_validator_production(target).or_else(states::validator_production(target, &solution.block));
				auto compensation = production.stake.is_positive() ? std::max(penalty, -production.stake) : decimal::zero();
				auto production_penalty = state.executor.apply_validator_production(target, executor_context::staker::unlock, compensation);
				if (!production_penalty)
					return production_penalty.error();

				coinbase -= compensation;
			}

			bool paying_rewards = state.executor.get_validator_production(state.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active();
			if (paying_rewards)
			{
				for (auto& [asset, reward] : rewards)
				{
					if (asset == algorithm::asset::native())
					{
						auto coinbase_reward = state.executor.apply_validator_production(state.public_key_hash, executor_context::staker::reward_or_penalty, reward);
						if (!coinbase_reward)
							return coinbase_reward.error();
					}
					else
					{
						auto coinbase_fee = state.executor.apply_validator_production_reward(asset, state.public_key_hash, reward);
						if (!coinbase_fee)
							return coinbase_fee.error();
					}
				}
			}
			else if (!state.validator_active)
				return layer_exception("block producer must be active");

			auto* parent_block = tip.address();
			size_t block_cost = (size_t)gas_cost::write_byte * 1024;
			state.changelog.commit();
			solution.block.gas_limit += block_cost;
			solution.block.gas_use += block_cost;
			solution.block.recalculate(parent_block, &state.changelog.outgoing);
			state.changelog.effects.finalized.swap(solution.effects);
			state.changelog.outgoing.pending.swap(solution.state.pending);
			state.changelog.outgoing.finalized.swap(solution.state.finalized);
			erase_failed_transactions().report("mempool cleanup failed");
			return expectation::met;
		}
		expects_lr<block_evaluation> solver_context::evaluate_block_inline()
		{
			block_evaluation solution;
			auto preparation = block_evalution_prepare(solution);
			if (!preparation)
				return preparation.error();

			auto rewards = block_rewards();
			auto execution = block_evalution_update(solution, rewards);
			if (!execution)
				return execution.error();

			auto finalization = block_evalution_finalize(solution, rewards);
			if (!finalization)
				return finalization.error();

			return expects_lr<block_evaluation>(std::move(solution));
		}
		expects_lr<void> solver_context::block_solution_solve(block_evaluation& evaluation)
		{
			if (!evaluation.block.solve(state.public_key_hash))
				return layer_exception("block proof evaluation failed");

			return expectation::met;
		}
		expects_lr<void> solver_context::block_solution_sign(block_evaluation& evaluation)
		{
			if (!evaluation.block.sign(state.secret_key))
				return layer_exception("block signature evaluation failed");

			return expectation::met;
		}
		expects_lr<void> solver_context::solve_block_inline(block_evaluation& evaluation)
		{
			auto solution = block_solution_solve(evaluation);
			if (!solution)
				return solution;

			return block_solution_sign(evaluation);
		}
		expects_lr<void> solver_context::verify_block(const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer)
		{
			return verify_solved_block(tip.address(), solution, recovered_producer);
		}
		expects_lr<block_checkpoint> solver_context::checkpoint_block(block_evaluation& solution, bool keep_reverted_transactions)
		{
			return checkpoint_solved_block(solution, keep_reverted_transactions);
		}
		expects_lr<void> solver_context::erase_failed_transactions()
		{
			if (transactions.failed.empty())
				return expectation::met;

			if (protocol::now().user.consensus.logging)
				VI_WARN("%" PRIu64 " failed mempool transaction%s dropped", (uint64_t)transactions.failed.size(), transactions.failed.size() > 1 ? " was" : "s were");

			auto mempool = storages::mempoolstate();
			return mempool.remove_transactions(transactions.failed);
		}
		bool solver_context::can_accept_more_transactions()
		{
			return state.gas_usage < block_header::get_gas_limit();
		}
		expects_lr<void> solver_context::solve_evaluated_block(block_evaluation& evaluation, const algorithm::pubkeyhash_t& public_key_hash, const algorithm::seckey_t& secret_key)
		{
			if (!evaluation.block.solve(public_key_hash))
				return layer_exception("block proof evaluation failed");

			if (!evaluation.block.sign(secret_key))
				return layer_exception("block signature evaluation failed");

			return expectation::met;
		}
		expects_lr<void> solver_context::verify_solved_block(const block_header* parent_block, const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer)
		{
			auto validity = solution.block.verify_validity(parent_block, recovered_producer);
			if (!validity)
				return validity;

			return solution.block.verify_integrity(parent_block, &solution.state);
		}
		expects_lr<void> solver_context::validate_solved_block(const block_header* parent_block, const block_body& child_block, block_evaluation* evaluated_result)
		{
			if (parent_block && (parent_block->number != child_block.number - 1 || parent_block->as_hash() != child_block.parent_hash))
				return layer_exception("invalid parent block");

			ledger::wallet producer;
			if (!child_block.recover_hash(producer.public_key_hash))
				return layer_exception("invalid producer signature");

			solver_context solver;
			if (!solver.apply_validator_state([&producer](size_t index) { return index > 0 ? nullptr : &producer; }, parent_block))
			{
				solver.state.public_key_hash = producer.public_key_hash;
				if (child_block.priority != protocol::now().policy.production.max_per_block)
					return layer_exception("invalid producer priority");
			}

			size_t commitments = 0;
			hash_map<uint256_t, std::pair<const block_transaction*, const solver_context::queued_transaction*>> childs;
			solver.transactions.pending.reserve(child_block.transactions.size());
			for (auto& transaction : child_block.transactions)
			{
				if (!transaction.transaction)
					return layer_exception("invalid transaction included in a block");

				auto& info = solver.force_include_transaction(transactions::resolver::from_copy(*transaction.transaction));
				childs[transaction.receipt.transaction_hash] = std::make_pair(&transaction, (const solver_context::queued_transaction*)&info);
				commitments += transaction.transaction->is_commitment() ? 1 : 0;
			}
			if (commitments > protocol::now().policy.commitments_per_block)
				return layer_exception("too many commitment transactions");

			auto evaluation = solver.evaluate_block_inline();
			if (!evaluation)
				return evaluation.error();

			auto& result = *evaluation;
			for (auto& transaction : result.block.transactions)
			{
				auto it = childs.find(transaction.receipt.transaction_hash);
				if (it == childs.end())
					return layer_exception("transaction " + algorithm::encoding::encode_0xhex256(transaction.receipt.transaction_hash) + " not found in block");

				auto& child = it->second;
				if (transaction.receipt.from != child.second->owner)
					return layer_exception("transaction " + algorithm::encoding::encode_0xhex256(transaction.receipt.transaction_hash) + " public key recovery failed");

				transaction.receipt.block_time = child.first->receipt.block_time;
				transaction.receipt.checksum = 0;
			}

			result.block.proof = child_block.proof;
			result.block.generation_time = child_block.generation_time;
			result.block.evaluation_time = child_block.evaluation_time;
			result.block.signature = child_block.signature;
			result.block.recalculate(parent_block, &result.state);

			auto verification = solver.verify_block(result, producer.public_key_hash);
			if (!verification)
				return verification;

			block_header input = child_block, output = result.block;
			if (input.as_message().data != output.as_message().data)
				return layer_exception("block data mismatch");

			if (evaluated_result != nullptr)
				*evaluated_result = std::move(result);

			return expectation::met;
		}
		expects_lr<block_checkpoint> solver_context::checkpoint_solved_block(block_evaluation& solution, bool keep_reverted_transactions)
		{
			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			hash_set<uint256_t> finalized_transactions;
			finalized_transactions.reserve(solution.block.transactions.size());
			for (auto& transaction : solution.block.transactions)
				finalized_transactions.insert(transaction.receipt.transaction_hash);

			block_checkpoint mutation;
			mutation.old_tip_block_number = chain.get_latest_block_number().or_else(0);
			mutation.new_tip_block_number = solution.block.number;
			mutation.block_delta = 1;
			mutation.transaction_delta = solution.block.transaction_count;
			mutation.state_delta = solution.block.transition_count;
			mutation.is_fork = mutation.old_tip_block_number > 0 && mutation.old_tip_block_number >= mutation.new_tip_block_number;
			if (mutation.is_fork)
			{
				uint64_t revert_number = mutation.old_tip_block_number;
				while (keep_reverted_transactions && revert_number >= mutation.new_tip_block_number)
				{
					size_t offset = 0, count = ELEMENTS_MANY;
					while (true)
					{
						auto transactions = chain.get_transactions_by_number(revert_number, offset, count);
						if (!transactions || transactions->empty())
							break;

						for (auto& item : *transactions)
						{
							if (finalized_transactions.find(item->as_hash()) == finalized_transactions.end())
							{
								auto status = mempool.add_transaction(**item);
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
					return status.error();

				if (protocol::now().user.storage.logging)
					VI_INFO("block %s rewinded (height: %" PRIu64 ", mempool: +%" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(solution.block.as_hash()).c_str(), mutation.new_tip_block_number, mutation.mempool_transactions, mutation.block_delta, mutation.transaction_delta, mutation.state_delta);

				if (solution.block.transition_count != solution.state.finalized.size())
				{
					auto parent_block = chain.get_block_by_number(solution.block.number - 1);
					auto validation = validate_solved_block(parent_block.address(), solution.block, &solution);
					if (!validation)
						return validation.error();
				}
			}

			auto status = chain.checkpoint(solution);
			if (!status)
				return status.error();

			mempool.remove_transactions(finalized_transactions).report("mempool cleanup failed");
			for (auto& side_effect : solution.effects)
			{
				VI_ASSERT(side_effect, "side effect callback should be set");
				side_effect();
			}

			return mutation;
		}
		solver_context::queued_transaction solver_context::precompute_transaction_element(uptr<transaction_message>&& candidate)
		{
			solver_context::queued_transaction result;
			result.candidate = std::move(candidate);
			if (result.candidate)
			{
				result.hash = result.candidate->as_hash();
				result.size = result.candidate->as_message().data.size();
				result.candidate->recover_hash(result.owner);
			}
			return result;
		}
		void solver_context::precompute_transaction_list(vector<queued_transaction>& candidates)
		{
			parallel::wail_all(parallel::for_each(candidates.begin(), candidates.end(), ELEMENTS_FEW, [](queued_transaction& item)
			{
				item.hash = item.candidate->as_hash();
				if (!item.owner.empty())
					return;

				item.size = item.candidate->as_message().data.size();
				item.candidate->recover_hash(item.owner);
			}));
		}
		void solver_context::sort_transaction_list(vector<uptr<transaction_message>>& candidates)
		{
			VI_SORT(candidates.begin(), candidates.end(), [](const uptr<transaction_message>& a, const uptr<transaction_message>& b) { return a->nonce < b->nonce; });
		}
		bool solver_context::requires_reorganization(const block_evaluation& solution)
		{
			auto chain = storages::chainstate();
			return chain.get_checkpoint_block_number().or_else(0) > solution.block.number - 1;
		}
	}
}