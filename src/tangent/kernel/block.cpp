#include "block.h"
#include "superchain.h"
#include "../policy/transactions.h"
#include "../policy/delegations.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"

namespace tangent
{
	namespace ledger
	{
		static bool may_use_as_witness_address(const std::string_view& hash)
		{
			return hash.size() >= 2 && !std::all_of(hash.begin() + 1, hash.end(), [](char c) { return c == '\0'; });
		}
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

			temporary_state.topics = std::move(temporary_state.topics);
			temporary_state.effects = std::move(temporary_state.effects);
			effects.pending = std::move(effects.pending);
			effects.finalized = std::move(effects.finalized);
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
		expects_lr<void> block_header::verify_validity(const block_header* parent_block, const algorithm::pubkeyhash_t& recovered_producer, bool verify_pow) const
		{
			if (!number || (!parent_hash && number > 1) || (number == 1 && parent_hash > 0))
				return layer_exception("invalid number");

			if (!transaction_root || !receipt_root || !state_root)
				return layer_exception("invalid transaction/receipt/state merkle tree root");

			if (!generation_time || generation_time > evaluation_time)
				return layer_exception("invalid time");

			if (priority > kernel::params().policy.production.max_per_block)
				return layer_exception("invalid priority");

			auto target_difficulty = number <= 1 || parent_block ? algorithm::wesolowski::scale(get_proof_slot_target(parent_block), get_proof_difficulty_multiplier()) : difficulty;
			if (proof.empty() || difficulty != target_difficulty)
				return layer_exception("invalid wesolowski target");

			uint256_t gas_work = get_gas_work(number, priority, difficulty, gas_use, gas_limit);
			if (!gas_limit || gas_use > gas_limit || absolute_work < gas_work)
				return layer_exception("invalid gas work");

			algorithm::pubkeyhash_t public_key_hash = recovered_producer;
			if (public_key_hash.empty() && !recover_hash(public_key_hash))
				return layer_exception("producer proof verification failed");

			if (verify_pow && !verify_proof(public_key_hash))
				return layer_exception("wesolowski proof verification failed");

			if (!parent_block && number > 1)
				return expectation::met;

			if (parent_block && parent_block->evaluation_time > generation_time + kernel::params().policy.pow.adjustment_time)
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
			proof = algorithm::wesolowski::evaluate(number, difficulty, as_solution(public_key_hash).data);
			evaluation_time = kernel::params().time.now();
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
			return algorithm::wesolowski::verify(number, difficulty, as_solution(public_key_hash).data, proof);
		}
		void block_header::set_parent_block(const block_header* parent_block)
		{
			parent_hash = (parent_block ? parent_block->as_hash() : uint256_t(0));
			number = (parent_block ? parent_block->number : 0) + 1;
			generation_time = kernel::params().time.now();
		}
		void block_header::set_witness_requirement(const algorithm::asset_id& asset, uint64_t block_number)
		{
			auto& height = witnesses[algorithm::asset::base_id_of(asset)];
			if (height < block_number)
				height = block_number;
		}
		bool block_header::network_congestion() const
		{
			uint256_t slot_gas_limit_band = get_slot_gas_limit() / 1'000'000;
			return slot_gas_use / slot_gas_limit_band > kernel::params().policy.production.min_network_congestion;
		}
		uint64_t block_header::get_witness_requirement(const algorithm::asset_id& asset) const
		{
			auto it = witnesses.find(algorithm::asset::base_id_of(asset));
			return it != witnesses.end() ? it->second : 0;
		}
		int8_t block_header::get_relative_order(const block_header& other) const
		{
			/* TRY HIGHEST: block number */
			if (number != other.number)
				return number > other.number ? 1 : -1;

			/* CHECK EQUAL: block hash */
			uint256_t hash_a = as_hash();
			uint256_t hash_b = other.as_hash();
			if (hash_a == hash_b)
				return 0;

			/* TRY LOWEST: block priority */
			if (priority != other.priority)
				return priority < other.priority ? 1 : -1;

			/* TRY HIGHEST: block wesolowski proof */
			int8_t security = algorithm::wesolowski::compare(proof, other.proof);
			if (security == 0)
			{
				/* RETURN LOWEST CHALLENGE: block hash challenge */
				uint256_t challenge = std::max(hash_a, hash_b) >> uint256_t(2);
				return hash_a < challenge ? 1 : -1;
			}
			
			/* TRY HIGHEST: block cumulative work */
			if (absolute_work != other.absolute_work)
				return absolute_work > other.absolute_work ? 1 : -1;

			return security;
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
			auto prev_target = parent_block ? parent_block->difficulty : kernel::params().policy.pow.difficulty;
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
			pow_data->set("security", format::variable(kernel::params().policy.pow.security));
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
		uint256_t block_header::get_block_gas_cost()
		{
			static uint256_t cost = ((size_t)gas_cost::write_byte * 1024);
			return cost;
		}
		uint256_t block_header::get_gas_limit()
		{
			static uint256_t limit = kernel::params().policy.block_gas_limit;
			return limit;
		}
		uint256_t block_header::get_slot_gas_limit()
		{
			static uint256_t limit = algorithm::wesolowski::adjustment_interval() * get_gas_limit();
			return limit;
		}
		uint256_t block_header::get_gas_work(uint64_t block_number, uint64_t priority, uint64_t difficulty, const uint256_t& gas_use, const uint256_t& gas_limit)
		{
			auto& policy = kernel::params().policy;
			uint256_t alignment = 16, work;
			uint256_t committee = policy.production.max_per_block;
			uint256_t multiplier = priority >= committee ? 0 : math64u::pow3(committee - priority);
			if (kernel::params().on(fork_id::difficulty_gas_work, block_number))
				work = (difficulty / policy.pow.difficulty) * multiplier * gas_use / get_gas_limit();
			else
				work = gas_limit > 0 ? (multiplier * gas_use) / gas_limit : uint256_t(0);
			uint256_t aligned_work = work - (work % alignment) + alignment;
			return aligned_work;
		}
		bool block_header::is_genesis_epoch(uint64_t block_number)
		{
			uint64_t ending_block_number = kernel::params().policy.emission.genesis_epoch_length;
			return ending_block_number > 0 && block_number <= ending_block_number;
		}
		decimal block_header::get_coinbase_value(uint64_t block_number)
		{
			auto& emission = kernel::params().policy.emission;
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
		expects_lr<void> block_body::verify_integrity(const block_header* parent_block, const block_state::log* state) const
		{
			if (transaction_count != (uint32_t)transactions.size())
				return layer_exception("invalid transactions count");
			else if (!transition_count && (state != nullptr && transition_count != (uint32_t)state->size()))
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
				state_tree.reserve(state->size() + 1);
				if (parent_block != nullptr)
					state_tree.push_back(parent_block->state_root);
				for (auto& [index, change] : *state)
					state_tree.push_back(change.state->as_hash());
				if (algorithm::merkle_tree::from(std::move(state_tree)).root() != state_root)
					return layer_exception("invalid state merkle tree root");
			}

			return expectation::met;
		}
		bool block_body::load_header(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_optimized_view(stream.read_type(), signature.blob, sizeof(signature)))
				return false;

			return load_header_payload(stream);
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
		void block_body::recalculate(const block_header* parent_block, const block_state::log* state)
		{
			auto task_queue1 = parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [](block_transaction& item) { item.receipt.as_hash(); });
			if (state != nullptr)
			{
				auto task_queue2 = parallel::for_each_sequential(state->begin(), state->end(), state->size(), ELEMENTS_FEW, [](const std::pair<const string, block_state::state_change>& item) { item.second.state->as_hash(); });
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
				state_tree.reserve(state->size() + 1);
				if (parent_block != nullptr)
					state_tree.push_back(parent_block->state_root);
				for (auto& [index, change] : *state)
					state_tree.push_back(change.state->as_hash());
				state_root = algorithm::merkle_tree::from(std::move(state_tree)).root();
				transition_count = (uint32_t)state->size();
			}

			bool cumulative = get_slot_length() > 1;
			absolute_work = (parent_block ? parent_block->absolute_work : uint256_t(0)) + get_gas_work(number, priority, difficulty, gas_use, gas_limit);
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
		block_proof block_body::as_proof(const block_header* parent_block, const block_state::log* state) const
		{
			auto result = block_proof();
			result.transaction_root = transaction_root;
			result.receipt_root = receipt_root;
			result.state_root = state_root;
			result.transaction_tree.nodes.reserve(transactions.size() + 1);
			result.receipt_tree.nodes.reserve(transactions.size() + 1);
			result.state_tree.nodes.reserve(state ? state->size() + 1 : 0);
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
				for (auto& [index, change] : *state)
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
			for (auto& [index, change] : state)
				states_data->push(change.state->as_tree());
			return data;
		}

		executor_context::executor_context(block_changelog* new_changelog) : solver(nullptr), transaction(nullptr), changelog(new_changelog), block(nullptr), options((uint8_t)flags::unrestricted)
		{
		}
		executor_context::executor_context(block_changelog* new_changelog, const solver_context* new_solver, block_header* new_block_header, const transaction_message* new_transaction) : solver(new_solver), transaction(new_transaction), changelog(new_changelog), block(new_block_header), options(0)
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
		expects_lr<void> executor_context::store(transition_state* next, bool paid, bool force_delete)
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
					if (force_delete && !prev)
						return expectation::met;

					auto status = next->transition(*prev);
					if (!status)
						return status;
					break;
				}
				case state_level::multiform:
				{
					prev = chain.get_multiform(type, changelog, ((multiform_state*)next)->as_column(), ((multiform_state*)next)->as_row(), get_validation_nonce()).or_else(storages::state_result()).value;
					if (force_delete && !prev)
						return expectation::met;

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

			bool will_delete = force_delete || states::resolver::will_delete(next, prev);
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
		expects_lr<void> executor_context::reset(transition_state* value, bool paid)
		{
			return store(value, paid, true);
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
				if (!event)
					return layer_exception("invalid event id");

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
		expects_lr<void> executor_context::emit_forwarded_event(uint32_t event, const algorithm::pubkeyhash_t& emitter, format::variables&& values, bool paid)
		{
			if (paid)
			{
				if (!event)
					return layer_exception("invalid event id");

				format::wo_stream stream;
				format::variables_util::serialize_merge_into(values, &stream);
				stream.write_integer(event);

				auto status = burn_gas(stream.data.size() * (size_t)gas_cost::write_byte);
				if (!status)
					return status;
			}
			receipt.emit_forwarded_event(event, emitter, std::move(values));
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

			bool pays_for_gas = transaction->gas_price.is_positive();
			if (pays_for_gas && transaction->gas_price < kernel::params().policy.production.min_gas_price)
				return layer_exception("gas price must be at least " + kernel::params().policy.production.min_gas_price.to_string());

			if (!transaction->commitment_priority(nullptr) && (options & (uint8_t)flags::congestion) && !pays_for_gas)
				return layer_exception("must pay for gas - network congestion requirement");
			else if (!pays_for_gas || (options & (uint8_t)flags::evaluation))
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

			auto random = get_random((uint8_t)seed_byte::proposer);
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater(0, -1);
			auto window = storages::result_index_window();
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_row(), filter, nonce).or_else(0);
			auto size = std::min(target_size, pool);
			auto distribution = algorithm::exponential_distribution();
			auto indices = vector<uint64_t>();
			indices.reserve(size);
			while (indices.size() < size)
			{
				uint64_t index = (uint64_t)distribution.next(random.derive(), (uint32_t)pool);
				auto it = std::find(indices.begin(), indices.end(), index);
				if (it == indices.end())
				{
					window.indices.push_back(index);
					indices.insert(it, index);
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

			auto random = get_random((uint8_t)seed_byte::attester);
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater_equal(fee_threshold.is_zero_or_nan() ? uint256_t(1) : states::validator_attestation::to_rank(fee_threshold), -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_row(asset), filter, nonce).or_else(0);
			if (pool < target_size)
				return layer_exception("committee threshold not met");

			vector<states::validator_attestation> committee;
			auto distribution = algorithm::exponential_distribution();
			auto indices = vector<uint64_t>();
			indices.reserve(pool);
			while (indices.size() < pool)
			{
				auto window = storages::result_index_window();
				auto size = std::min<size_t>(target_size, pool - indices.size());
				while (window.indices.size() < size)
				{
					uint64_t index = (uint64_t)distribution.next(random.derive(), (uint32_t)pool);
					auto it = std::lower_bound(indices.begin(), indices.end(), index);
					if (it == indices.end() || *it != index)
					{
						window.indices.push_back(index);
						indices.insert(it, index);
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

			auto random = get_random((uint8_t)seed_byte::participant);
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate();
			auto filter = storages::result_filter::greater_equal(uint256_t(1), -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_row(), filter, nonce).or_else(0);
			if (pool < target_size)
				return layer_exception("committee threshold not met");

			vector<states::validator_participation> committee;
			auto distribution = algorithm::exponential_distribution();
			auto indices = vector<uint64_t>();
			indices.reserve(pool);
			while (indices.size() < pool)
			{
				auto window = storages::result_index_window();
				auto size = std::min<size_t>(target_size, pool - indices.size());
				while (window.indices.size() < size)
				{
					uint64_t index = (uint64_t)distribution.next(random.derive(), (uint32_t)pool);
					auto it = std::lower_bound(indices.begin(), indices.end(), index);
					if (it == indices.end() || *it != index)
					{
						window.indices.push_back(index);
						indices.insert(it, index);
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
				new_state.index = get_bridge_queue(asset, bridge_hash, -1).or_else(states::bridge_queue(asset, bridge_hash, 0, nullptr)).index + 1;
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
				else if (!may_use_as_witness_address(*hash))
					return layer_exception(stringify::text("error applying \"%s\" address: invalid address", address.second.c_str()));

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
		expects_lr<states::witness_account> executor_context::reset_witness_account(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const address_map& addresses)
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
				else if (!may_use_as_witness_address(*hash))
					return layer_exception(stringify::text("error applying \"%s\" address: invalid address", address.second.c_str()));

				segments[*hash][address.first] = address.second;
			}

			auto ref = states::bridge_ref();
			ref.owner = owner;
			ref.asset = asset;
			ref.hash = 0;

			states::witness_account new_state = states::witness_account(ref, { }, nullptr);
			for (auto& segment : segments)
			{
				new_state = states::witness_account(ref, segment.second, block);
				new_state.active = false;

				auto status = reset(&new_state, true);
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

			auto& policy = kernel::params().policy;
			if (block != nullptr && candidate->receipt.block_number <= block->number && block->number - candidate->receipt.block_number > policy.participation.referencing_time / policy.pow.time)
				return layer_exception("block transaction not found");

			if (!may_have_distinct_asset && transaction && transaction->asset != candidate->transaction->asset)
				return layer_exception("block transaction asset is distinct");

			if (candidate->receipt.transaction_hash != transaction_hash && candidate->transaction->as_type() == transactions::rollup::as_instance_type())
				candidate = ((transactions::rollup*)*candidate->transaction)->resolve_block_transaction(candidate->receipt, transaction_hash);

			return candidate;
		}
		expects_lr<uint64_t> executor_context::get_block_number_by_hash(const uint256_t& block_hash) const
		{
			if (!block_hash)
				return expects_lr<uint64_t>(0);

			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(block_hash);
			if (!block_number)
				return block_number.error();

			auto& policy = kernel::params().policy;
			if (block != nullptr && *block_number <= block->number && block->number - *block_number > policy.participation.referencing_time / policy.pow.time)
				return layer_exception("block not found");

			return block_number;
		}
		algorithm::wesolowski::distribution executor_context::get_random(const uint256_t& seed, block_header* from_block, ledger::transaction_receipt* from_receipt)
		{
			auto* target_block = from_block ? from_block : block;
			auto* target_receipt = from_receipt ? from_receipt : &receipt;
			format::wo_stream message;
			message.write_typeless(target_block ? target_block->number : 0);
			message.write_typeless(target_block ? target_block->priority : 0);
			message.write_typeless(target_block ? target_block->difficulty : 0);
			message.write_typeless(target_receipt ? target_receipt->transaction_hash : uint256_t(0));
			message.write_typeless(target_receipt ? target_receipt->relative_gas_use : uint256_t(0));
			message.write_typeless(seed);

			algorithm::wesolowski::distribution distribution;
			distribution.signature = message.data;
			distribution.value = algorithm::hashing::hash256i(*crypto::hash(digests::sha512(), distribution.signature));
			return distribution;
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
			auto destructor = uscope([&]()
			{
				reference->checksum = initial_checksum;
				reference->gas_limit = initial_gas_limit;
			});
			reference->checksum = 0;
			reference->gas_limit = block_header::get_gas_limit();

			ledger::block_body temp_block;
			solver_context temp_solver;
			temp_solver.apply_temporary_state(&temp_block, transaction, { });

			block_changelog temp_changelog;
			size_t transaction_size = transaction->as_message().data.size();
			auto executor = ledger::executor_context(&temp_changelog, &temp_solver, &temp_block, transaction);
			auto execution = executor_context::execute_tx(&executor, owner, transaction, transaction->as_hash(), transaction_size, (uint8_t)flags::pedantic | (uint8_t)flags::evaluation);
			if (!execution)
				return execution.error();

			executor.receipt.relative_gas_use += 64 * (uint64_t)gas_cost::write_byte;
			auto gas = executor.receipt.relative_gas_use - (executor.receipt.relative_gas_use % 1000) + 1000;
			executor.receipt.relative_gas_use = gas;
			if (out_receipt != nullptr)
				*out_receipt = std::move(executor.receipt);
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
		expects_lr<void> executor_context::execute_tx(executor_context* executor, const algorithm::pubkeyhash_t& owner, const transaction_message* new_transaction, const uint256_t& new_transaction_hash, size_t transaction_size, uint8_t options)
		{
			VI_ASSERT(executor && executor->solver && executor->block && new_transaction, "executor and transaction should be set");
			if (owner.empty())
				return layer_exception("invalid transaction signature");

			executor->transaction = new_transaction;
			executor->options = options;
			executor->receipt.transaction_hash = new_transaction_hash;
			executor->receipt.absolute_gas_use = executor->block->gas_use;
			executor->receipt.relative_gas_use = 0;
			executor->receipt.block_number = executor->block->number;
			executor->receipt.block_time = kernel::params().time.now();
			executor->receipt.from = owner;
			executor->receipt.successful = false;
			if (!(executor->options & (uint8_t)flags::preserve_events))
				executor->receipt.events.clear();

			auto validation = new_transaction->validate(executor->receipt.block_number);
			if (!validation)
				return validation.error();

			auto storage = executor->burn_gas(transaction_size * (size_t)gas_cost::write_tx_byte);
			if (!storage)
				return storage.error();

			bool discard = (executor->receipt.events.size() == 1 && executor->receipt.events.front().event == 0 && executor->receipt.events.front().args.size() == 1);
			auto execution = discard ? expects_lr<void>(layer_exception(executor->receipt.events.front().args.front().as_blob())) : executor->transaction->execute(executor);
			executor->receipt.successful = !!execution;
			if (!executor->receipt.successful && executor->changelog != nullptr)
				executor->changelog->outgoing.revert();
			if (discard)
				executor->receipt.events.clear();
			if ((executor->options & (uint8_t)flags::pedantic) && !executor->receipt.successful)
				return execution.error();

			if (!executor->receipt.from.empty() && !(executor->options & (uint8_t)flags::replayable))
			{
				auto nonce = (executor->options & (uint8_t)flags::evaluation ? executor->get_account_nonce(executor->receipt.from).or_else(states::account_nonce(algorithm::pubkeyhash_t(), nullptr)).nonce : executor->transaction->nonce);
				auto change = executor->apply_account_nonce(executor->receipt.from, nonce + 1);
				if (!change)
					return change.error();
			}

			if (executor->receipt.relative_gas_use > 0 && executor->transaction->gas_price.is_positive())
			{
				auto fee = executor->apply_fee_transfer(executor->transaction->gas_asset(), executor->receipt.from, executor->transaction->gas_price * executor->receipt.relative_gas_use.to_decimal());
				if (!fee)
					return fee.error();
			}

			if (executor->receipt.successful)
			{
				for (auto& item : executor->witnesses)
					executor->block->set_witness_requirement(item.first, item.second);
			}
			else
				executor->emit_event(0, { format::variable(execution.what()) }, false);

			executor->options = 0;
			executor->block->gas_use += executor->receipt.relative_gas_use;
			executor->block->gas_limit += executor->transaction->gas_limit;
			return expectation::met;
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

		delegation_adapter::delegation_adapter(const delegation_adapter& other) noexcept
		{
			for (auto& [runner_wallet, transaction] : other.emissions)
				emissions.emplace_back(std::make_pair(runner_wallet, uptr(transactions::resolver::from_copy(*transaction))));
		}
		delegation_adapter& delegation_adapter::operator=(const delegation_adapter& other) noexcept
		{
			if (this == &other)
				return *this;

			emissions.clear();
			for (auto& [runner_wallet, transaction] : other.emissions)
				emissions.emplace_back(std::make_pair(runner_wallet, uptr(transactions::resolver::from_copy(*transaction))));
			return *this;
		}
		promise<delegation_adapter::dispatcher_result> delegation_adapter::execute_dispatcher_on(uint64_t block_number)
		{
			if (!block_number)
				return promise<dispatcher_result>(dispatcher_result());

			return coasync<dispatcher_result>([this, block_number]() -> promise<dispatcher_result>
			{
				auto* offchain = superchain::bridge::get();
				auto* runner = get_runner_wallet();
				uint64_t blocks_to_update = kernel::params().policy.attestation.confirmation_time / kernel::params().policy.pow.time;
				uint64_t blocks_to_unlock = kernel::params().policy.pow.adjustment_time / kernel::params().policy.pow.time;
				dispatcher_result result;
				while (runner != nullptr)
				{
					auto candidates = storages::chainstate().get_pending_block_transactions(block_number, result.dispatches, ELEMENTS_MANY);
					if (!candidates || candidates->empty())
						break;

					result.dispatches += candidates->size();
					for (auto& input : *candidates)
					{
						executor_context executor = executor_context(nullptr);
						executor.transaction = *input.transaction;
						executor.receipt = std::move(input.receipt);

						uint32_t delegation_type = executor.receipt.successful ? input.transaction->as_delegation_type() : 0;
						uptr<delegation_contract> delegation = delegation_type > 0 ? delegations::resolver::from_type(delegation_type, this, &executor, runner->public_key_hash) : nullptr;
						if (!delegation)
						{
							uint64_t next_block_number = block_number + blocks_to_update;
							storages::chainstate().dispatch(executor.receipt.transaction_hash, next_block_number);
							result.errors[executor.receipt.transaction_hash] = remote_exception::retry_after(next_block_number, "unrecognized delegation type");
							continue;
						}

						auto location = stringify::text("dispatch_cache_%s", algorithm::encoding::encode_0xhex256(executor.receipt.transaction_hash).c_str());
						auto cache = offchain->load_cache(input.transaction->asset, superchain::cache_policy::temporary_cache, location);
						if (cache && cache->value.is_string())
						{
							format::ro_stream message = format::ro_stream(cache->value.as_string());
							if (!delegation->load(message))
								delegation = delegations::resolver::from_type(delegation_type, this, &executor, executor.receipt.from);
						}

						auto status = coawait(delegation->execute_transition());
						if (!status)
						{
							uint64_t next_block_number = status.error().is_retry() || status.error().is_shutdown() ? block_number + (status.error().is_retry_after() ? status.error().retry_after_timestamp() : blocks_to_unlock) : 0;
							storages::chainstate().dispatch(executor.receipt.transaction_hash, next_block_number);
							result.errors[executor.receipt.transaction_hash] = next_block_number > 0 ? remote_exception::retry_after(next_block_number, status.what()) : std::move(status.error());
						}
						else
							storages::chainstate().dispatch(executor.receipt.transaction_hash, 0);
					}
					if (candidates->size() < ELEMENTS_MANY)
						break;
				}
				coreturn result;
			});
		}
		expects_lr<distribution_key> delegation_adapter::derive_key(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash, algorithm::composition::type alg, bool master)
		{
			VI_ASSERT(runner_wallet != nullptr, "runner wallet should be set");
			uint8_t entropy_source_1[sizeof(asset)], entropy_source_2[sizeof(hash)];
			auto entropy_source_3 = runner_wallet->secret_key.view();
			auto& entropy_source_4 = kernel::params().policy.participation.root;
			auto entropy_source_0 = owner.view();
			asset.encode(entropy_source_1);
			hash.encode(entropy_source_2);

			format::wo_stream entropy_source;
			if (!master)
				entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source_0.data(), entropy_source_0.size()));
			entropy_source.write_string(algorithm::hashing::hash512(entropy_source_1, sizeof(entropy_source_1)));
			entropy_source.write_string(algorithm::hashing::hash512(entropy_source_2, sizeof(entropy_source_2)));
			entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source_3.data(), entropy_source_3.size()));
			entropy_source.write_string(algorithm::hashing::hash512(entropy_source_4, sizeof(entropy_source_4)));
			entropy_source.write_string(algorithm::hashing::hash512((uint8_t*)entropy_source.data.data(), entropy_source.data.size()));

			uint8_t entropy[64];
			if (!algorithm::signing::derive_seed_from_high_entropy_password((uint8_t*)entropy_source.data.data(), entropy_source.data.size(), entropy, sizeof(entropy)))
				return layer_exception("secret entropy source generation failed");

			auto keypair = algorithm::composition::derive_keypair(alg, entropy, sizeof(entropy));
			if (!keypair)
				return keypair.error();

			distribution_key result;
			result.ref.owner = owner;
			result.ref.asset = asset;
			result.ref.hash = hash;
			result.key = std::move(keypair->secret_key);
			return expects_lr<distribution_key>(std::move(result));
		}
		expects_lr<distribution_key> delegation_adapter::store_key(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash, vector<uint8_t>&& key, btree_map<algorithm::pubkeyhash_t, distribution_key::share_pair>&& shares)
		{
			VI_ASSERT(runner_wallet != nullptr, "runner wallet should be set");
			distribution_key result;
			result.ref.owner = owner;
			result.ref.asset = asset;
			result.ref.hash = hash;
			result.key = std::move(key);
			result.shares = std::move(shares);

			auto mempool = storages::mempoolstate();
			auto status = mempool.apply_key(runner_wallet->public_key_hash, result);
			if (!status)
				return status.error();

			return expects_lr<distribution_key>(std::move(result));
		}
		expects_lr<distribution_key> delegation_adapter::load_key(const wallet* runner_wallet, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash)
		{
			VI_ASSERT(runner_wallet != nullptr, "runner wallet should be set");
			auto mempool = storages::mempoolstate();
			return mempool.get_key(runner_wallet->public_key_hash, owner, asset, hash);
		}

		delegation_contract::delegation_contract(delegation_adapter* new_adapter, const executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner) : adapter(new_adapter), executor(new_executor), runner(nullptr)
		{
			VI_ASSERT(adapter != nullptr, "adapter should be set");
			VI_ASSERT(executor != nullptr, "executor should be set");
			VI_PANIC(try_running_on(new_runner), "runner should be set");
		}
		bool delegation_contract::try_running_on(const algorithm::pubkeyhash_t& new_runner)
		{
			VI_ASSERT(adapter != nullptr, "adapter should be set");
			if (runner != nullptr && runner->public_key_hash == new_runner)
				return true;

			auto* target = adapter->get_runner_wallet(new_runner);
			if (!target)
				return false;

			runner = target;
			return true;
		}
		void delegation_contract::emit_transaction(ledger::transaction_message* transaction)
		{
			adapter->emissions.emplace_back(std::make_pair(runner, uptr(transaction)));
		}
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> delegation_contract::convene_delegates(const btree_set<algorithm::pubkeyhash_t>& targets)
		{
			VI_ASSERT(adapter != nullptr, "adapter should be set");
			return adapter->require_validators(this, targets);
		}
		expects_promise_rt<void> delegation_contract::yield_to_delegate(const algorithm::pubkeyhash_t& target, uint32_t delegate)
		{
			VI_ASSERT(adapter != nullptr, "adapter should be set");
			auto* runner_wallet = adapter->get_runner_wallet(target);
			if (!runner_wallet)
			{
				auto callback = as_delegate_ptr(delegate);
				if (!callback)
					return expects_promise_rt<void>(remote_exception("invalid contract delegate"));

				format::wo_stream message;
				message.write_integer(as_type());
				message.write_integer(delegate);
				if (!store_payload(&message))
					return expects_promise_rt<void>(remote_exception("failed to store delegation state"));

				return adapter->execute_on_validator(this, target, message).then<expects_rt<void>>([this, runner_wallet](expects_rt<format::wo_stream>&& wo_message) -> expects_rt<void>
				{
					if (!wo_message)
						return wo_message.error();

					auto message = wo_message->ro();
					auto delegation = uptr(delegations::resolver::from_copy(this));
					if (!delegation || !delegation->load_payload(message))
						return remote_exception("failed to load delegation state");

					auto validation = delegation->validate_transition(this, *runner_wallet);
					if (!validation)
						return remote_exception(std::move(validation.error().message()));

					message.seek = 0;
					if (!load_payload(message))
						return remote_exception("failed to re-load delegation state");

					return expectation::met;
				});
			}
			else
			{
				auto wo_message = yield_to_self(runner_wallet->public_key_hash, delegate, true);
				if (!wo_message)
					return expects_promise_rt<void>(remote_exception(std::move(wo_message.error().message())));

				auto message = wo_message->ro();
				if (!load_payload(message))
					return expects_promise_rt<void>(remote_exception("failed to re-load delegation state"));

				return expects_promise_rt<void>(expectation::met);
			}
		}
		expects_lr<format::wo_stream> delegation_contract::yield_to_self(const algorithm::pubkeyhash_t& target, uint32_t delegate, bool requires_validation)
		{
			auto callback = as_delegate_ptr(delegate);
			if (!callback)
				return layer_exception("invalid contract delegate");

			auto delegation = uptr(delegations::resolver::from_copy(this));
			if (!delegation->try_running_on(target))
				return layer_exception("invalid delegator selection");

			auto result = callback(*delegation);
			if (!result)
				return layer_exception(std::move(result.error().message()));

			if (requires_validation)
			{
				auto validation = delegation->validate_transition(this, *runner);
				if (!validation)
					return validation.error();
			}

			format::wo_stream wo_message;
			if (!delegation->store_payload(&wo_message))
				return layer_exception("failed to store delegation state");

			return expects_lr<format::wo_stream>(std::move(wo_message));
		}
		format::tree delegation_contract::as_tree() const
		{
			return format::tree(format::variable());
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
			state.validator_active = true;
			state.origin = state_origin::chain;
			state.executor = executor_context(&state.changelog, this, abstract_block, abstract_transaction);
			state.executor.receipt = std::move(abstract_receipt);
			transactions = transaction_queue();
			tip = optional::none;
			producers.clear();
			nonces.clear();
			memset(state.public_key_hash.blob, 0xFF, sizeof(algorithm::pubkeyhash_t));
			memset(state.secret_key.blob, 0xFF, sizeof(algorithm::seckey_t));
		}
		option<uint64_t> solver_context::apply_validator_state(const std::function<ledger::wallet* (size_t)>& try_producer, option<const block_header*>&& parent_block, tip_cache* cache)
		{
			nonces.clear();
			transactions.errors.clear();
			transactions.pending.clear();
			transactions.queued = 0;
			state.public_key_hash.clear();
			state.secret_key.clear();
			state.changelog.clear();
			state.gas_usage = 0;
			state.commitments = 0;
			state.validator_active = true;
			if (parent_block)
			{
				tip = *parent_block ? option<block_header>(**parent_block) : option<block_header>(optional::none);
				if (!cache || !cache->tip_block_number)
				{
					auto chain = storages::chainstate();
					auto parent = chain.get_latest_block_number();
					state.origin = (*parent_block ? parent.or_else(tip->number) < (tip->number + 1) : !parent) ? state_origin::chain : state_origin::block;
					if (cache != nullptr)
						cache->tip_block_number = parent.or_else(0);
				}
				else
					state.origin = state_origin::chain;
			}
			else
			{
				auto chain = storages::chainstate();
				auto parent = chain.get_latest_block_header();
				tip = parent ? option<block_header>(std::move(*parent)) : option<block_header>(optional::none);
				state.origin = state_origin::chain;
			}

			auto origin = state.origin;
			state.executor.solver = this;
			state.executor.changelog = &state.changelog;
			state.executor.block = tip.address();
			state.executor.transaction = nullptr;
			state.executor.receipt = transaction_receipt();
			state.executor.options = tip && tip->network_congestion() ? (uint8_t)executor_context::flags::congestion : 0;
			state.origin = state.origin == state_origin::block ? state_origin::chain_block : state_origin::chain;
			if (state.executor.block != nullptr)
				producers = state.executor.calculate_producers(kernel::params().policy.production.max_per_block).or_else(vector<states::validator_production>());
			else
				producers.clear();

			if (producers.empty())
			{
				while (producers.size() < kernel::params().policy.production.max_per_block)
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
					state.commitments += item.candidate->commitment_priority(nullptr) ? 1 : 0;
					transactions.pending.emplace_back(std::move(item));
					++transactions.queued;
				}
				else if (decision == include_decision::not_executable)
					transactions.errors[item.hash] = layer_exception("block inclusion denied");
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

			bool commitment = !!item.candidate->commitment_priority(nullptr);
			if (!commitment && ((uint8_t)state.executor.options & (uint8_t)executor_context::flags::congestion))
				return item.candidate->gas_price.is_positive() && item.candidate->gas_price < kernel::params().policy.production.min_gas_price ? include_decision::not_executable : include_decision::not_includable;
			else if (commitment && state.commitments + 1 > kernel::params().policy.commitments_per_block)
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
				else if (item.candidate->nonce >= nonce + kernel::params().policy.account_nonce_step_limit)
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
			solution.block.priority = (uint64_t)(position == producers.end() ? kernel::params().policy.production.max_per_block : std::distance(producers.begin(), position));
			solution.block.difficulty = algorithm::wesolowski::scale(solution.block.get_proof_slot_target(parent_block), solution.block.get_proof_difficulty_multiplier());
			solution.state.clear();
			solution.effects.clear();
			state.executor.witnesses.clear();
			state.executor.block = &solution.block;
			state.validator_active = state.executor.get_validator_production(state.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active();
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

			uint8_t state_options = state.executor.options;
			for (auto& item : transactions.pending)
			{
				uint8_t tx_options = item.candidate->commitment_priority(nullptr) ? (uint8_t)executor_context::flags::pedantic : 0;
				auto execution = executor_context::execute_tx(&state.executor, item.owner, *item.candidate, item.hash, item.size, state_options | tx_options);
				if (execution)
				{
					auto& blob = solution.block.transactions.emplace_back();
					blob.transaction = std::move(item.candidate);
					blob.receipt = state.executor.receipt;
					if (blob.receipt.relative_gas_use > 0 && blob.transaction->gas_price.is_positive())
					{
						auto& reward = rewards[blob.transaction->asset];
						reward = (reward.is_nan() ? decimal::zero() : reward) + blob.transaction->gas_price * blob.receipt.relative_gas_use.to_decimal();
					}
					state.changelog.commit();
				}
				else
				{
					transactions.errors[item.hash] = execution.error();
					state.changelog.revert();
				}
				state.changelog.clear_temporary_state();
			}

			state.executor.transaction = nullptr;
			state.executor.options = state_options;
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

			auto cost = block_header::get_block_gas_cost();
			auto* parent_block = tip.address();
			solution.block.gas_limit += cost;
			solution.block.gas_use += cost;
			state.changelog.commit();
			state.changelog.effects.finalized.swap(solution.effects);
			state.changelog.outgoing.finalized.swap(solution.state);
			solution.block.recalculate(parent_block, &solution.state);
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
		expects_lr<void> solver_context::verify_block(const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer, bool verify_pow)
		{
			return verify_solved_block(tip.address(), solution, recovered_producer, verify_pow);
		}
		expects_lr<block_checkpoint> solver_context::checkpoint_block(block_evaluation& solution, tip_cache* cache)
		{
			return checkpoint_solved_block(*this, solution, cache);
		}
		expects_lr<void> solver_context::erase_failed_transactions()
		{
			if (transactions.errors.empty())
				return expectation::met;

			auto hashes = hash_set<uint256_t>();
			hashes.reserve(transactions.errors.size());
			for (auto& [transaction_hash, error] : transactions.errors)
			{
				hashes.insert(transaction_hash);
				if (kernel::params().user.consensus.logging)
					VI_WARN("transaction %s dropped: %s", algorithm::encoding::encode_0xhex256(transaction_hash).c_str(), error.what());
			}

			auto mempool = storages::mempoolstate();
			return mempool.remove_transactions_by_hash(hashes);
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
		expects_lr<void> solver_context::verify_solved_block(const block_header* parent_block, const block_evaluation& solution, const algorithm::pubkeyhash_t& recovered_producer, bool verify_pow)
		{
			auto validity = solution.block.verify_validity(parent_block, recovered_producer, verify_pow);
			if (!validity)
				return validity;

			return solution.block.verify_integrity(parent_block, &solution.state);
		}
		expects_lr<void> solver_context::validate_solved_block(solver_context& solver, const block_header* parent_block, const block_body& child_block, block_evaluation* evaluated_result, bool verify_pow, tip_cache* cache)
		{
			if (parent_block && (parent_block->number != child_block.number - 1 || parent_block->as_hash() != child_block.parent_hash))
				return layer_exception("invalid parent block");

			ledger::wallet producer;
			if (!child_block.recover_hash(producer.public_key_hash))
				return layer_exception("invalid producer signature");

			if (!solver.apply_validator_state([&producer](size_t index) { return index > 0 ? nullptr : &producer; }, parent_block, cache))
			{
				solver.state.public_key_hash = producer.public_key_hash;
				if (child_block.priority != kernel::params().policy.production.max_per_block)
					return layer_exception("invalid producer priority");
			}

			if (parent_block != nullptr && (!child_block.transaction_count || child_block.transactions.empty()))
				return validate_solved_empty_block(solver, *parent_block, child_block, producer.public_key_hash, evaluated_result, verify_pow);

			size_t commitments = 0;
			hash_map<uint256_t, std::pair<const block_transaction*, const solver_context::queued_transaction*>> childs;
			solver.transactions.pending.reserve(child_block.transactions.size());
			for (auto& transaction : child_block.transactions)
			{
				if (!transaction.transaction)
					return layer_exception("invalid transaction included in a block");

				auto& info = solver.force_include_transaction(transactions::resolver::from_copy(*transaction.transaction));
				childs[transaction.receipt.transaction_hash] = std::make_pair(&transaction, (const solver_context::queued_transaction*)&info);
				commitments += transaction.transaction->commitment_priority(nullptr) ? 1 : 0;
			}
			if (commitments > kernel::params().policy.commitments_per_block)
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

			block_header input = child_block, output = result.block;
			if (input.as_message().data != output.as_message().data)
				return layer_exception("block data mismatch");

			auto verification = solver.verify_block(result, producer.public_key_hash, verify_pow);
			if (!verification)
				return verification;

			if (evaluated_result != nullptr)
				*evaluated_result = std::move(result);

			return expectation::met;
		}
		expects_lr<void> solver_context::validate_solved_empty_block(solver_context& solver, const block_header& parent_block, const block_body& child_block, const algorithm::pubkeyhash_t& recovered_producer, block_evaluation* evaluated_result, bool verify_pow)
		{
			if (child_block.transaction_count != 0 || !child_block.transactions.empty())
				return layer_exception("invalid transaction count");

			if (child_block.transaction_root != parent_block.transaction_root || child_block.receipt_root != parent_block.receipt_root)
				return layer_exception("invalid transaction/receipt merkle tree root");

			if (child_block.gas_use != child_block.gas_limit || child_block.gas_limit != block_header::get_block_gas_cost())
				return layer_exception("invalid gas use/limit");

			if (!child_block.witnesses.empty())
				return layer_exception("invalid witnesses count");

			auto validity = child_block.verify_validity(&parent_block, recovered_producer, verify_pow);
			if (!validity)
				return validity;

			auto position = std::find_if(solver.producers.begin(), solver.producers.end(), [&solver](const states::validator_production& a) { return a.owner == solver.state.public_key_hash; });
			uint64_t priority = (uint64_t)(position == solver.producers.end() ? kernel::params().policy.production.max_per_block : std::distance(solver.producers.begin(), position));
			solver.state.executor.block = (block_body*)&child_block;
			solver.state.validator_active = solver.state.executor.get_validator_production(solver.state.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active();
			if (priority != child_block.priority)
				return layer_exception("invalid producer priority");
			else if (!solver.state.validator_active)
				return layer_exception("block producer must be active");

			auto coinbase = block_header::get_coinbase_value(child_block.number);
			auto penalty = -coinbase;
			auto penalty_queue = std::min((size_t)child_block.priority, solver.producers.size());
			for (size_t i = 0; i < penalty_queue; i++)
			{
				auto& target = solver.producers[i].owner;
				auto production = solver.state.executor.get_validator_production(target).or_else(states::validator_production(target, &child_block));
				auto compensation = production.stake.is_positive() ? std::max(penalty, -production.stake) : decimal::zero();
				auto production_penalty = solver.state.executor.apply_validator_production(target, executor_context::staker::unlock, compensation);
				if (!production_penalty)
					return production_penalty.error();

				coinbase -= compensation;
			}

			auto coinbase_reward = solver.state.executor.apply_validator_production(recovered_producer, executor_context::staker::reward_or_penalty, coinbase);
			if (!coinbase_reward)
				return coinbase_reward.error();

			block_state::log state_log;
			solver.state.changelog.commit();
			solver.state.changelog.outgoing.finalized.swap(state_log);
			if (state_log.size() != child_block.transition_count)
				return layer_exception("invalid states count");

			vector<uint256_t> state_tree;
			state_tree.reserve(state_log.size() + 1);
			state_tree.push_back(parent_block.state_root);
			for (auto& [index, change] : state_log)
				state_tree.push_back(change.state->as_hash());
			if (algorithm::merkle_tree::from(std::move(state_tree)).root() != child_block.state_root)
				return layer_exception("invalid state merkle tree root");

			if (evaluated_result != nullptr)
			{
				evaluated_result->effects.clear();
				evaluated_result->state.swap(state_log);
				if (&evaluated_result->block != &child_block)
					evaluated_result->block = child_block;
			}

			return expectation::met;
		}
		expects_lr<block_checkpoint> solver_context::checkpoint_solved_block(solver_context& solver, block_evaluation& solution, tip_cache* cache)
		{
			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			hash_set<uint256_t> finalized_transactions, finalized_commitments;
			finalized_transactions.reserve(solution.block.transactions.size());
			for (auto& transaction : solution.block.transactions)
			{
				uint256_t commitment_hash;
				finalized_transactions.insert(transaction.receipt.transaction_hash);
				if (transaction.transaction->commitment_priority(&commitment_hash) && commitment_hash > 0)
					finalized_commitments.insert(commitment_hash);
			}

			block_checkpoint mutation;
			mutation.old_tip_block_number = cache && cache->tip_block_number > 0 ? cache->tip_block_number : chain.get_latest_block_number().or_else(0);
			mutation.new_tip_block_number = solution.block.number;
			mutation.block_delta = 1;
			mutation.transaction_delta = solution.block.transaction_count;
			mutation.state_delta = solution.block.transition_count;
			mutation.is_fork = mutation.old_tip_block_number > 0 && mutation.old_tip_block_number >= mutation.new_tip_block_number;
			if (mutation.is_fork)
			{
				auto status = chain.revert(mutation.new_tip_block_number - 1, &mutation.block_delta, &mutation.transaction_delta, &mutation.state_delta);
				if (!status)
					return status.error();

				if (solution.block.transition_count != solution.state.size())
				{
					auto parent_block = chain.get_block_by_number(solution.block.number - 1);
					auto validation = validate_solved_block(solver, parent_block.address(), solution.block, &solution, cache);
					if (!validation)
						return validation.error();
				}
			}

			auto status = chain.checkpoint(solution, false, cache ? &cache->checkpoint_block_number : nullptr);
			if (!status)
				return status.error();

			mempool.remove_transactions_by_hash(finalized_transactions).report("mempool cleanup failed");
			mempool.remove_transactions_by_commitment_hash(finalized_commitments).report("mempool cleanup failed");
			for (auto& side_effect : solution.effects)
			{
				VI_ASSERT(side_effect, "side effect callback should be set");
				side_effect();
			}

			if (cache != nullptr)
				cache->tip_block_number = mutation.new_tip_block_number;

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
		bool solver_context::requires_reorganization(const block_evaluation& solution, tip_cache* cache)
		{
			uint64_t checkpoint_block_number = cache ? cache->checkpoint_block_number : 0;
			if (!checkpoint_block_number)
			{
				auto chain = storages::chainstate();
				checkpoint_block_number = chain.get_checkpoint_block_number().or_else(0);
				if (cache != nullptr)
					cache->checkpoint_block_number = checkpoint_block_number;
			}
			return checkpoint_block_number > solution.block.number - 1;
		}
	}
}