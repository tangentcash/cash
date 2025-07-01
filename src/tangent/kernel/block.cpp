#include "block.h"
#include "../policy/transactions.h"
#include "../validator/service/nss.h"
#include "../validator/storage/mempoolstate.h"
#include "../validator/storage/chainstate.h"

namespace tangent
{
	namespace ledger
	{
		block_transaction::block_transaction(uptr<ledger::transaction>&& new_transaction, ledger::receipt&& new_receipt) : transaction(std::move(new_transaction)), receipt(std::move(new_receipt))
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
			transaction = tangent::transactions::resolver::from_stream(stream);
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

		block_state::block_state(const block_state& other) : parent_work(other.parent_work)
		{
			for (size_t i = 0; i < (size_t)work_state::__count__; i++)
			{
				auto& mapping = map[i];
				for (auto& item : other.map[i])
					mapping[item.first] = item.second ? states::resolver::from_copy(*item.second) : nullptr;
			}
		}
		block_state& block_state::operator= (const block_state& other)
		{
			if (&other == this)
				return *this;

			parent_work = other.parent_work;
			for (size_t i = 0; i < (size_t)work_state::__count__; i++)
			{
				auto& mapping = map[i];
				mapping.clear();
				for (auto& item : other.map[i])
					mapping[item.first] = item.second ? states::resolver::from_copy(*item.second) : nullptr;
			}
			return *this;
		}
		option<uptr<state>> block_state::find(uint32_t type, const std::string_view& index) const
		{
			auto location = index_of(type, index);
			for (size_t i = 0; i < (size_t)work_state::__count__; i++)
			{
				auto& mapping = map[i];
				auto it = mapping.find(location);
				if (it != mapping.end())
					return it->second ? option<uptr<state>>(states::resolver::from_copy(*it->second)) : option<uptr<state>>(nullptr);
			}
			return parent_work ? parent_work->find(type, index) : option<uptr<state>>(optional::none);
		}
		option<uptr<state>> block_state::find(uint32_t type, const std::string_view& column, const std::string_view& row) const
		{
			auto location = index_of(type, column, row);
			for (size_t i = 0; i < (size_t)work_state::__count__; i++)
			{
				auto& mapping = map[i];
				auto it = mapping.find(location);
				if (it != mapping.end())
					return it->second ? option<uptr<state>>(states::resolver::from_copy(*it->second)) : option<uptr<state>>(nullptr);
			}
			return parent_work ? parent_work->find(type, column, row) : option<uptr<state>>(optional::none);
		}
		void block_state::erase(uint32_t type, const std::string_view& index)
		{
			map[(size_t)work_state::pending][index_of(type, index)].destroy();
		}
		void block_state::erase(uint32_t type, const std::string_view& column, const std::string_view& row)
		{
			map[(size_t)work_state::pending][index_of(type, column, row)].destroy();
		}
		void block_state::copy(state* value)
		{
			if (value)
			{
				auto copy = states::resolver::from_copy(value);
				if (copy)
					map[(size_t)work_state::pending][index_of(value)] = copy;
			}
		}
		void block_state::move(uptr<state>&& value)
		{
			auto location = index_of(*value);
			map[(size_t)work_state::pending][location] = std::move(value);
		}
		string block_state::index_of(state* value) const
		{
			VI_ASSERT(value != nullptr, "value should be set");
			switch (value->as_level())
			{
				case state_level::uniform:
				{
					auto* base = (uniform*)value;
					return index_of(value->as_type(), base->as_index());
				}
				case state_level::multiform:
				{
					auto* base = (multiform*)value;
					return index_of(value->as_type(), base->as_column(), base->as_row());
				}
				default:
					return string();
			}
		}
		string block_state::index_of(uint32_t type, const std::string_view& index) const
		{
			format::stream message;
			message.write_typeless(type);
			message.write_typeless(index.data(), (uint32_t)index.size());
			return message.data;
		}
		string block_state::index_of(uint32_t type, const std::string_view& column, const std::string_view& row) const
		{
			format::stream message;
			message.write_typeless(type);
			message.write_typeless(column.data(), (uint32_t)column.size());
			message.write_typeless(row.data(), (uint32_t)row.size());
			return message.data;
		}
		const ordered_map<string, uptr<ledger::state>>& block_state::at(work_state level) const
		{
			switch (level)
			{
				case tangent::ledger::work_state::pending:
				case tangent::ledger::work_state::finalized:
					return map[(size_t)level];
				default:
					return map[(size_t)work_state::finalized];
			}
		}
		ordered_map<string, uptr<ledger::state>>& block_state::clear()
		{
			map[(size_t)work_state::pending].clear();
			map[(size_t)work_state::finalized].clear();
			return map[(size_t)work_state::finalized];
		}
		ordered_map<string, uptr<ledger::state>>& block_state::revert()
		{
			map[(size_t)work_state::pending].clear();
			return map[(size_t)work_state::finalized];
		}
		ordered_map<string, uptr<ledger::state>>& block_state::commit()
		{
			for (auto& item : map[(size_t)work_state::pending])
			{
				if (item.second)
					map[(size_t)work_state::finalized][item.first] = std::move(item.second);
			}
			map[(size_t)work_state::pending].clear();
			return map[(size_t)work_state::finalized];
		}

		block_changelog::block_changelog() noexcept
		{
		}
		block_changelog::block_changelog(const block_changelog& other) noexcept : outgoing(other.outgoing), incoming(other.incoming)
		{
		}
		block_changelog::block_changelog(block_changelog&& other) noexcept : outgoing(std::move(other.outgoing)), incoming(std::move(other.incoming))
		{
		}
		block_changelog& block_changelog::operator=(const block_changelog& other) noexcept
		{
			if (this == &other)
				return *this;

			outgoing = other.outgoing;
			incoming = other.incoming;
			return *this;
		}
		block_changelog& block_changelog::operator=(block_changelog&& other) noexcept
		{
			if (this == &other)
				return *this;

			outgoing = std::move(other.outgoing);
			incoming = std::move(other.incoming);
			return *this;
		}
		void block_changelog::clear()
		{
			outgoing.clear();
			incoming.clear();
		}
		void block_changelog::revert()
		{
			outgoing.revert();
			incoming.revert();
		}
		void block_changelog::commit()
		{
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
				return layer_exception("producer proof verification failed");

			if (!verify_wesolowski())
				return layer_exception("wesolowski proof verification failed");

			if (!parent_block && number > 1)
				return expectation::met;

			if (absolute_work != (parent_block ? parent_block->absolute_work + gas_work : gas_work))
				return layer_exception("invalid absolute gas work");

			uint256_t cumulative = get_slot_length() > 1 ? uint256_t(1) : uint256_t(0);
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
			return algorithm::signing::sign(block_header::as_signable().hash(), secret_key, signature);
		}
		bool block_header::solve(const algorithm::seckey secret_key)
		{
			wesolowski = algorithm::wesolowski::evaluate(target, as_solution().data);
			return !wesolowski.empty();
		}
		bool block_header::verify(const algorithm::pubkey public_key) const
		{
			return algorithm::signing::verify(block_header::as_signable().hash(), public_key, signature);
		}
		bool block_header::recover(algorithm::pubkey public_key) const
		{
			return algorithm::signing::recover(block_header::as_signable().hash(), public_key, signature);
		}
		bool block_header::recover_hash(algorithm::pubkeyhash public_key_hash) const
		{
			return algorithm::signing::recover_hash(block_header::as_signable().hash(), public_key_hash, signature);
		}
		bool block_header::verify_wesolowski() const
		{
			return algorithm::wesolowski::verify(target, as_solution().data, wesolowski);
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
		uint64_t block_header::get_slot_duration_target() const
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
			algorithm::pubkeyhash producer = { 0 };
			bool has_producer = recover_hash(producer);
			schema* data = var::set::object();
			data->set("wesolowski", var::string(format::util::encode_0xhex(wesolowski)));
			data->set("signature", var::string(format::util::encode_0xhex(std::string_view((char*)signature, sizeof(signature)))));
			data->set("producer", has_producer ? algorithm::signing::serialize_address(producer) : var::set::null());
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("parent_hash", var::string(algorithm::encoding::encode_0xhex256(parent_hash)));
			data->set("transaction_root", var::string(algorithm::encoding::encode_0xhex256(transaction_root)));
			data->set("receipt_root", var::string(algorithm::encoding::encode_0xhex256(receipt_root)));
			data->set("state_root", var::string(algorithm::encoding::encode_0xhex256(state_root)));
			data->set("absolute_work", algorithm::encoding::serialize_uint256(absolute_work));
			data->set("difficulty", algorithm::encoding::serialize_uint256(target.difficulty()));
			data->set("gas_use", algorithm::encoding::serialize_uint256(gas_use));
			data->set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));\
			data->set("slot_duration", algorithm::encoding::serialize_uint256(slot_duration));
			data->set("slot_duration_target", algorithm::encoding::serialize_uint256(get_slot_duration_target()));
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
		format::stream block_header::as_signable() const
		{
			format::stream message;
			message.write_integer(as_type());
			if (!block_header::store_payload(&message))
				message.clear();
			return message;
		}
		format::stream block_header::as_solution() const
		{
			format::stream message;
			message.write_integer(as_type());
			if (!block_header::store_payload_wesolowski(&message))
				message.clear();
			return message;
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
		uint64_t block_header::get_transaction_limit()
		{
			static uint64_t limit = (uint64_t)std::ceil((double)protocol::now().policy.consensus_proof_time * (double)protocol::now().policy.transaction_throughput / 1000.0);
			return limit;
		}
		uint256_t block_header::get_gas_limit()
		{
			static uint256_t limit = gas_util::get_gas_estimate<transactions::transfer, 64>() * get_transaction_limit();
			return limit;
		}

		block::block(const block_header& other) : block_header(other)
		{
		}
		expects_lr<block_state> block::evaluate(const block_header* parent_block, evaluation_context* environment, string* errors)
		{
			VI_ASSERT(environment != nullptr, "evaluation context should be set");
			if (environment->incoming.empty())
				return layer_exception("empty block is not valid");

			block_header::set_parent_block(parent_block);
			auto position = std::find_if(environment->producers.begin(), environment->producers.end(), [&environment](const states::validator_production& a) { return !memcmp(a.owner, environment->validator.public_key_hash, sizeof(environment->validator.public_key_hash)); });
			auto prev_duration = parent_block ? parent_block->get_slot_duration_target() : (uint64_t)((double)protocol::now().policy.consensus_proof_time * protocol::now().policy.genesis_slot_time_bump);
			auto prev_target = parent_block ? parent_block->target : algorithm::wesolowski::get_default();
			if (parent_block && parent_block->recovery)
				prev_target = algorithm::wesolowski::bump(target, 1.0 / protocol::now().policy.consensus_recovery_bump);

			recovery = (position == environment->producers.end() ? 1 : 0);
			priority = recovery ? 0 : (uint64_t)std::distance(environment->producers.begin(), position);
			target = algorithm::wesolowski::adjust(prev_target, prev_duration, number);
			if (recovery)
				target = algorithm::wesolowski::bump(target, protocol::now().policy.consensus_recovery_bump);

			block_changelog changelog;
			ordered_map<algorithm::asset_id, decimal> fees;
			for (auto& item : environment->incoming)
			{
				auto execution = transaction_context::execute_tx(environment, this, &changelog, *item.candidate, item.hash, item.owner, item.size, item.candidate->conservative ? 0 : (uint8_t)transaction_context::execution_flags::only_successful);
				if (execution)
				{
					auto& blob = transactions.emplace_back();
					blob.transaction = std::move(item.candidate);
					blob.receipt = std::move(execution->receipt);
					if (blob.receipt.relative_gas_paid > 0)
					{
						auto& fee = fees[blob.transaction->get_gas_asset()];
						fee = (fee.is_nan() ? decimal::zero() : fee) + blob.transaction->gas_price * blob.receipt.relative_gas_paid.to_decimal();
					}
					changelog.outgoing.commit();
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

				errors->append("\n  block does not have any valid transactions");
				return layer_exception(string(*errors));
			}

			size_t participants = (size_t)(priority + 1);
			for (size_t i = 0; i < participants; i++)
			{
				auto& participant = environment->producers[i];
				bool winner = (i == priority);
				if (winner)
				{
					auto work = environment->validation.context.apply_validator_production(participant.owner, transaction_context::production_type::mint_gas, gas_use, fees);
					if (!work)
						return work.error();
				}
				else
				{
					auto work = environment->validation.context.apply_validator_production(participant.owner, transaction_context::production_type::burn_gas_and_deactivate, gas_use * (protocol::now().policy.production_max_per_block - i), { });
					if (!work)
						return work.error();
				}
			}

			changelog.outgoing.commit();
			recalculate(parent_block, &changelog.outgoing);
			return expects_lr<block_state>(std::move(changelog.outgoing));
		}
		expects_lr<void> block::validate(const block_header* parent_block, block_evaluation* evaluated_result) const
		{
			if (parent_block && (parent_block->number != number - 1 || parent_block->as_hash() != parent_hash))
				return layer_exception("invalid parent block");

			algorithm::pubkeyhash producer = { 0 };
			if (!recover_hash(producer))
				return layer_exception("invalid producer signature");

			evaluation_context environment;
			if (!environment.priority(producer, nullptr, option<block_header*>((block_header*)parent_block)))
			{
				if (!recovery)
					return layer_exception("invalid producer election");

				auto prev_duration = parent_block ? parent_block->get_slot_duration_target() : (uint64_t)((double)protocol::now().policy.consensus_proof_time * protocol::now().policy.genesis_slot_time_bump);
				auto prev_target = parent_block ? parent_block->target : algorithm::wesolowski::get_default();
				if (parent_block && parent_block->recovery)
					prev_target = algorithm::wesolowski::bump(target, 1.0 / protocol::now().policy.consensus_recovery_bump);

				auto candidate_target = algorithm::wesolowski::bump(algorithm::wesolowski::adjust(prev_target, prev_duration, number), protocol::now().policy.consensus_recovery_bump);
				if (target.difficulty() != candidate_target.difficulty())
					return layer_exception("invalid producer election");
			}

			unordered_map<uint256_t, std::pair<const block_transaction*, const evaluation_context::transaction_info*>> childs;
			environment.incoming.reserve(transactions.size());
			for (auto& transaction : transactions)
			{
				if (!transaction.transaction)
					return layer_exception("invalid transaction included in a block");

				auto& info = environment.include(transactions::resolver::from_copy(*transaction.transaction));
				childs[transaction.receipt.transaction_hash] = std::make_pair(&transaction, (const evaluation_context::transaction_info*)&info);
			}

			auto evaluation = environment.evaluate();
			if (!evaluation)
				return evaluation.error();

			auto& result = *evaluation;
			for (auto& transaction : result.block.transactions)
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

			memcpy(result.block.signature, signature, sizeof(signature));
			result.block.wesolowski = wesolowski;
			result.block.time = time;
			result.block.recalculate(parent_block, &result.state);

			block_header input = *this, output = result.block;
			if (input.as_message().data != output.as_message().data)
				return layer_exception("resulting block deviates from pre-computed block");

			auto validity = result.block.verify_validity(parent_block);
			if (!validity)
				return validity;

			auto integrity = result.block.verify_integrity(parent_block, &result.state);
			if (!integrity)
				return integrity;

			if (evaluated_result != nullptr)
				*evaluated_result = std::move(result);

			return expectation::met;
		}
		expects_lr<void> block::verify_integrity(const block_header* parent_block, const block_state* state) const
		{
			if (transactions.empty() || transaction_count != (uint32_t)transactions.size())
				return layer_exception("invalid transactions count");
			else if (!state_count && (state != nullptr && state_count != (uint32_t)state->at(work_state::finalized).size()))
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

			if (state != nullptr)
			{
				tree = (parent_block ? parent_block->state_root : uint256_t(0));
				for (auto& item : state->at(work_state::finalized))
					tree.push(item.second->as_hash());
				if (tree.calculate_root() != state_root)
					return layer_exception("invalid states merkle tree root");
			}

			return expectation::met;
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

			return true;
		}
		void block::recalculate(const block_header* parent_block, const block_state* state)
		{
			auto task_queue1 = parallel::for_each(transactions.begin(), transactions.end(), ELEMENTS_FEW, [](block_transaction& item) { item.receipt.as_hash(); });
			if (state != nullptr)
			{
				auto& state_tree = state->at(work_state::finalized);
				auto task_queue2 = parallel::for_each_sequential(state_tree.begin(), state_tree.end(), state_tree.size(), ELEMENTS_FEW, [](const std::pair<const string, uptr<ledger::state>>& item) { item.second->as_hash(); });
				parallel::wail_all(std::move(task_queue2));
			}
			parallel::wail_all(std::move(task_queue1));

			algorithm::merkle_tree tree = (parent_block ? parent_block->transaction_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.transaction_hash);
			transaction_root = tree.calculate_root();

			tree = (parent_block ? parent_block->receipt_root : uint256_t(0));
			for (auto& item : transactions)
				tree.push(item.receipt.as_hash());
			receipt_root = tree.calculate_root();

			if (state)
			{
				auto& state_tree = state->at(work_state::finalized);
				tree = (parent_block ? parent_block->state_root : uint256_t(0));
				for (auto& item : state_tree)
					tree.push(item.second->as_hash());
				state_root = tree.calculate_root();
				state_count = (uint32_t)state_tree.size();
			}

			uint256_t cumulative = get_slot_length() > 1 ? 1 : 0;
			absolute_work = (parent_block ? parent_block->absolute_work : uint256_t(0)) + gas_util::get_gas_work(target.difficulty(), gas_use, gas_limit, priority);
			slot_duration = (parent_block ? parent_block->slot_duration + parent_block->get_duration() : uint256_t(0)) * cumulative;
			transaction_count = (uint32_t)transactions.size();
		}
		uptr<schema> block::as_schema() const
		{
			schema* data = block_header::as_schema().reset();
			auto* transactions_data = data->set("transactions", var::set::array());
			for (auto& item : transactions)
				transactions_data->push(item.as_schema().reset());
			return data;
		}
		block_header block::as_header() const
		{
			return block_header(*this);
		}
		block_proof block::as_proof(const block_header* parent_block, const block_state* state) const
		{
			auto proof = block_proof(*this, parent_block);
			proof.transactions.reserve(transactions.size());
			proof.receipts.reserve(transactions.size());
			for (auto& item : transactions)
			{
				proof.transactions.push_back(item.receipt.transaction_hash);
				proof.receipts.push_back(item.receipt.as_hash());
			}
			if (state != nullptr)
			{
				proof.states.reserve(state->at(work_state::finalized).size());
				for (auto& item : state->at(work_state::finalized))
					proof.states.push_back(item.second->as_hash());
			}
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

		expects_lr<block_checkpoint> block_evaluation::checkpoint(bool keep_reverted_transactions) const
		{
			auto chain = storages::chainstate(__func__);
			auto chain_session = chain.multi_tx_begin("chainwork", "apply", sqlite::isolation::placeholder);
			if (!chain_session)
				return layer_exception(std::move(chain_session.error().message()));

			unordered_set<uint256_t> finalized_transactions;
			finalized_transactions.reserve(block.transactions.size());
			for (auto& transaction : block.transactions)
				finalized_transactions.insert(transaction.receipt.transaction_hash);

			block_checkpoint mutation;
			mutation.old_tip_block_number = chain.get_latest_block_number().or_else(0);
			mutation.new_tip_block_number = block.number;
			mutation.block_delta = 1;
			mutation.transaction_delta = block.transaction_count;
			mutation.state_delta = block.state_count;
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
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", mempool: +%" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(block.as_hash()).c_str(), mutation.new_tip_block_number, mutation.mempool_transactions, mutation.block_delta, mutation.transaction_delta, mutation.state_delta);

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
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(block.as_hash()).c_str(), mutation.new_tip_block_number, mutation.block_delta, mutation.transaction_delta, mutation.state_delta);

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

		transaction_context::transaction_context() : environment(nullptr), transaction(nullptr), changelog(nullptr), block(nullptr)
		{
		}
		transaction_context::transaction_context(const ledger::evaluation_context* new_environment, ledger::block_header* new_block_header, block_changelog* new_changelog, const ledger::transaction* new_transaction, ledger::receipt&& new_receipt) : environment(new_environment), transaction(new_transaction), changelog(new_changelog), block(new_block_header), receipt(std::move(new_receipt))
		{
		}
		transaction_context::transaction_context(const transaction_context& other) : changelog(other.changelog), environment(other.environment), receipt(other.receipt), block(other.block)
		{
			transaction = other.transaction ? transactions::resolver::from_copy(other.transaction) : nullptr;
		}
		transaction_context& transaction_context::operator=(const transaction_context& other)
		{
			if (this == &other)
				return *this;

			changelog = other.changelog;
			environment = other.environment;
			transaction = other.transaction ? transactions::resolver::from_copy(other.transaction) : nullptr;
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
			else if (!changelog)
				return layer_exception("invalid state changelog");

			auto chain = storages::chainstate(__func__);
			switch (next->as_level())
			{
				case state_level::uniform:
				{
					auto* state = (uniform*)next;
					auto prev = chain.get_uniform_by_index(state->as_type(), changelog, state->as_index(), get_validation_nonce());
					auto status = state->transition(this, prev ? **prev : nullptr);
					if (!status)
						return status;
					break;
				}
				case state_level::multiform:
				{
					auto* state = (multiform*)next;
					auto prev = chain.get_multiform_by_composition(state->as_type(), changelog, state->as_column(), state->as_row(), get_validation_nonce());
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

			changelog->outgoing.copy(next);
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
		expects_lr<void> transaction_context::verify_account_nonce() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			auto state = get_account_nonce(receipt.from);
			if (state && state->nonce > transaction->nonce)
				return layer_exception("nonce is invalid (now: " + to_string(state->nonce) + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_account_delegation(const algorithm::pubkeyhash owner) const
		{
			if (!transaction || !block)
				return layer_exception("invalid transaction or block");

			auto state = get_account_delegation(owner);
			if (!state)
				return expectation::met;

			uint64_t target_block_number = state->get_delegation_zeroing_block(block->number);
			if (target_block_number > block->number)
				return layer_exception("account is over delegated (retry at block: " + to_string(target_block_number) + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_gas_transfer_balance() const
		{
			if (!transaction)
				return layer_exception("invalid transaction");

			bool gas_calculation = block != nullptr && block->number == std::numeric_limits<int64_t>::max() - 1;
			if (gas_calculation || !transaction->gas_price.is_positive())
				return expectation::met;

			auto asset = transaction->get_gas_asset();
			auto state = get_account_balance(asset, receipt.from);
			decimal max_paid_value = transaction->gas_price * transaction->gas_limit.to_decimal();
			decimal max_payable_value = state ? state->get_balance() : decimal::zero();
			if (max_payable_value < max_paid_value)
				return layer_exception(algorithm::asset::handle_of(asset) + " balance is insufficient (balance: " + max_payable_value.to_string() + ", value: " + max_paid_value.to_string() + ")");

			return expectation::met;
		}
		expects_lr<void> transaction_context::verify_transfer_balance(const algorithm::asset_id& asset, const decimal& max_paid_value) const
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
		expects_lr<void> transaction_context::verify_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			if (!environment)
				return layer_exception("invalid evaluation context");

			auto attestation = get_validator_attestation(asset, owner);
			if (!attestation || !attestation->is_active())
				return layer_exception("validator attestation is inactive");

			return expectation::met;
		}
		expects_lr<algorithm::wesolowski::distribution> transaction_context::calculate_random(const uint256_t& seed)
		{
			if (!block)
				return layer_exception("block not found");

			format::stream message;
			message.write_typeless(block->number);
			message.write_typeless(block->recovery);
			message.write_typeless(block->priority);
			message.write_typeless(block->target.difficulty());
			message.write_typeless(block->mutation_count);
			message.write_typeless(receipt.transaction_hash);
			message.write_typeless(receipt.relative_gas_use);
			message.write_typeless(seed);

			algorithm::wesolowski::distribution distribution;
			distribution.signature = message.data;
			distribution.value = algorithm::hashing::hash256i(*crypto::hash(digests::sha512(), distribution.signature));
			return distribution;
		}
		expects_lr<size_t> transaction_context::calculate_attesters_size(const algorithm::asset_id& asset) const
		{
			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::greater_equal(0, -1);
			return chain.get_multiforms_count_by_row_filter(states::validator_attestation::as_instance_type(), states::validator_attestation::as_instance_row(asset), filter, nonce);
		}
		expects_lr<vector<states::validator_production>> transaction_context::calculate_producers(size_t target_size)
		{
			auto random = calculate_random(0);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto window = storages::factor_index_window();
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_production::as_instance_type(), states::validator_production::as_instance_row(), filter, nonce).or_else(0);
			auto size = std::min(target_size, pool);
			auto indices = ordered_set<uint64_t>();
			while (indices.size() < size)
			{
				uint64_t index = algorithm::hashing::erd64(random->derive(), size);
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
				auto& work = *(states::validator_production*)*result;
				committee.emplace_back(std::move(work));
			}

			if (committee.size() >= target_size)
				std::sort(committee.begin(), committee.end(), [](const states::validator_production& a, const states::validator_production& b) { return a.gas > b.gas; });

			return committee;
		}
		expects_lr<vector<states::validator_participation>> transaction_context::calculate_participants(const algorithm::asset_id& asset, ordered_set<algorithm::pubkeyhash_t>& exclusion, size_t target_size)
		{
			auto random = calculate_random(1);
			if (!random)
				return random.error();

			auto nonce = get_validation_nonce();
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto pool = chain.get_multiforms_count_by_row_filter(states::validator_participation::as_instance_type(), states::validator_participation::as_instance_row(asset), filter, nonce).or_else(0);
			if (pool < target_size)
				return layer_exception("committee threshold not met");

			size_t median_pool = (size_t)std::ceil((double)pool * protocol::now().policy.participation_stake_threshold);
			if (median_pool <= target_size + exclusion.size())
				median_pool = pool;

			vector<states::validator_participation> committee;
			auto indices = ordered_set<uint64_t>();
			while (indices.size() < median_pool)
			{
				auto window = storages::factor_index_window();
				auto prefetch = std::min<size_t>(target_size, median_pool);
				while (window.indices.size() < prefetch)
				{
					uint64_t index = algorithm::hashing::erd64(random->derive(), median_pool);
					if (indices.find(index) == indices.end())
					{
						window.indices.push_back(index);
						indices.insert(index);
					}
				}

				auto results = chain.get_multiforms_by_row_filter(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_row(asset), filter, nonce, window);
				if (!results || results->empty())
					break;

				for (auto& result : *results)
				{
					auto& work = *(states::validator_participation*)*result;
					auto hash = algorithm::pubkeyhash_t(work.owner);
					if (exclusion.find(hash) == exclusion.end())
					{
						exclusion.insert(std::move(hash));
						committee.push_back(std::move(work));
						if (committee.size() >= target_size)
							break;
					}
				}

				if (committee.size() >= target_size)
					break;
			}

			if (committee.size() < target_size)
				return layer_exception("committee threshold not met");

			return committee;
		}
		expects_lr<states::account_nonce> transaction_context::apply_account_nonce(const algorithm::pubkeyhash owner, uint64_t nonce)
		{
			states::account_nonce new_state = states::account_nonce(owner, block);
			new_state.nonce = nonce;

			auto status = store(&new_state);
			if (!status)
				return status.error();

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
		expects_lr<states::account_uniform> transaction_context::apply_account_uniform(const algorithm::pubkeyhash owner, const std::string_view& index, const std::string_view& data)
		{
			states::account_uniform new_state = states::account_uniform(owner, index, block);
			new_state.data = data;

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_multiform> transaction_context::apply_account_multiform(const algorithm::pubkeyhash owner, const std::string_view& column, const std::string_view& row, const std::string_view& data)
		{
			states::account_multiform new_state = states::account_multiform(owner, column, row, block);
			new_state.data = data;

			auto result = store(&new_state);
			if (!result)
				return result.error();

			return new_state;
		}
		expects_lr<states::account_delegation> transaction_context::apply_account_delegation(const algorithm::pubkeyhash owner, uint32_t delegations)
		{
			states::account_delegation new_state = states::account_delegation(owner, block);
			new_state.delegations = delegations;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> transaction_context::apply_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& supply, const decimal& reserve)
		{
			states::account_balance new_state = states::account_balance(owner, asset, block);
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
		expects_lr<states::account_balance> transaction_context::apply_fee_transfer(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& value)
		{
			states::account_balance new_state = states::account_balance(owner, asset, block);
			new_state.supply = -value;
			if (environment != nullptr && !memcmp(environment->validator.public_key_hash, owner, sizeof(algorithm::pubkeyhash)))
				return new_state;

			auto status = store(&new_state, false);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(-value) }, false);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::account_balance> transaction_context::apply_payment(const algorithm::asset_id& asset, const algorithm::pubkeyhash from, const algorithm::pubkeyhash to, const decimal& value)
		{
			states::account_balance new_state1 = states::account_balance(from, asset, block);
			new_state1.supply = -value;
			if (!memcmp(from, to, sizeof(algorithm::pubkeyhash)))
				return new_state1;

			auto status = store(&new_state1);
			if (!status)
				return status.error();

			states::account_balance new_state2 = states::account_balance(to, asset, block);
			new_state2.supply = value;

			status = store(&new_state2);
			if (!status)
				return status.error();

			status = emit_event<states::account_balance>({ format::variable(asset), format::variable(std::string_view((char*)from, sizeof(algorithm::pubkeyhash))), format::variable(std::string_view((char*)to, sizeof(algorithm::pubkeyhash))), format::variable(value) });
			if (!status)
				return status.error();

			return new_state1;
		}
		expects_lr<states::validator_production> transaction_context::apply_validator_production(const algorithm::pubkeyhash owner, production_type action, const uint256_t& gas, const ordered_map<algorithm::asset_id, decimal>& stakes)
		{
			switch (action)
			{
				case production_type::burn_gas:
				case production_type::burn_gas_and_deactivate:
				{
					if (!stakes.empty())
						return layer_exception("unstaking is either all or none");

					auto new_state = get_validator_production(owner).or_else(states::validator_production(owner, block));
					auto new_gas = new_state.gas - gas;
					new_state.gas = new_gas > new_state.gas ? 0 : new_gas;
					new_state.active = action == production_type::burn_gas_and_deactivate ? false : new_state.active;
					if (action == production_type::burn_gas_and_deactivate && !new_state.stakes.empty())
					{
						new_state.gas /= 2;
						if (!new_state.gas)
							return layer_exception("not enough gas to perform unstaking");

						for (auto& [asset, stake] : new_state.stakes)
						{
							if (stake.is_positive())
							{
								auto transfer = apply_transfer(asset, owner, decimal::zero(), -stake);
								if (!transfer)
									return transfer.error();
							}
						}
						new_state.stakes.clear();
					}

					auto result = store(&new_state);
					if (!result)
						return result.error();

					return new_state;
				}
				case production_type::mint_gas:
				case production_type::mint_gas_and_activate:
				{
					auto new_state = get_validator_production(owner).or_else(states::validator_production(owner, block));
					auto new_gas = new_state.gas + gas;
					new_state.gas = new_gas < new_state.gas ? 0 : new_gas;
					new_state.active = (action == production_type::mint_gas_and_activate) || new_state.active;

					for (auto& [asset, stake] : stakes)
					{
						auto& prev_stake = new_state.stakes[asset];
						prev_stake = (prev_stake.is_nan() ? decimal::zero() : prev_stake) + stake;
						if (stake.is_positive())
						{
							auto transfer = apply_transfer(asset, owner, stake, stake);
							if (!transfer)
								return transfer.error();
						}
					}

					auto result = store(&new_state);
					if (!result)
						return result.error();

					return new_state;
				}
				default:
					return layer_exception("invalid production action");
			}
		}
		expects_lr<states::validator_participation> transaction_context::apply_validator_participation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& value, int64_t participations, bool is_reward)
		{
			states::validator_participation new_state = get_validator_participation(asset, owner).or_else(states::validator_participation(owner, asset, block));
			decimal prev_state_stake = new_state.stake;
			new_state.participations = participations >= 0 || new_state.participations >= (uint64_t)-participations ? (int64_t)new_state.participations + participations : 0;
			new_state.stake = value.is_nan() ? decimal::nan() : (new_state.stake.is_nan() ? value : (new_state.stake + value));
			if (new_state.stake.is_negative())
				new_state.stake = decimal::nan();

			auto result = store(&new_state);
			if (!result)
				return result.error();

			decimal changelog = (new_state.stake.is_nan() ? decimal::zero() : new_state.stake) - (prev_state_stake.is_nan() ? decimal::zero() : prev_state_stake);
			if (!changelog.is_zero_or_nan())
			{
				auto transfer = apply_transfer(asset, owner, is_reward ? changelog : decimal::zero(), changelog);
				if (!transfer)
					return transfer.error();
			}

			return new_state;
		}
		expects_lr<states::validator_attestation> transaction_context::apply_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& value, bool is_reward)
		{
			states::validator_attestation new_state = get_validator_attestation(asset, owner).or_else(states::validator_attestation(owner, asset, block));
			decimal prev_state_stake = new_state.stake;
			new_state.stake = value.is_nan() ? decimal::nan() : (new_state.stake.is_nan() ? value : (new_state.stake + value));
			if (new_state.stake.is_negative())
				new_state.stake = decimal::nan();

			auto result = store(&new_state);
			if (!result)
				return result.error();

			decimal changelog = (new_state.stake.is_nan() ? decimal::zero() : new_state.stake) - (prev_state_stake.is_nan() ? decimal::zero() : prev_state_stake);
			if (!changelog.is_zero_or_nan())
			{
				auto transfer = apply_transfer(asset, owner, is_reward ? changelog : decimal::zero(), changelog);
				if (!transfer)
					return transfer.error();
			}

			return new_state;
		}
		expects_lr<states::depository_reward> transaction_context::apply_depository_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& incoming_fee, const decimal& outgoing_fee)
		{
			states::depository_reward new_state = states::depository_reward(owner, asset, block);
			new_state.incoming_fee = incoming_fee;
			new_state.outgoing_fee = outgoing_fee;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::depository_balance> transaction_context::apply_depository_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const decimal& supply)
		{
			states::depository_balance new_state = states::depository_balance(owner, asset, block);
			new_state.supply = supply;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::depository_balance>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable(supply) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::depository_policy> transaction_context::apply_depository_policy_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, uint64_t new_accounts)
		{
			auto new_state = get_depository_policy(asset, owner).or_else(states::depository_policy(owner, asset, block));
			new_state.accounts_under_management += new_accounts;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::depository_policy>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable((uint8_t)0), format::variable(new_accounts) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::depository_policy> transaction_context::apply_depository_policy_queue(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const uint256_t& transaction_hash)
		{
			auto new_state = get_depository_policy(asset, owner).or_else(states::depository_policy(owner, asset, block));
			new_state.queue_transaction_hash = transaction_hash;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::depository_policy>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable((uint8_t)1), format::variable(transaction_hash) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::depository_policy> transaction_context::apply_depository_policy(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, uint8_t security_level, bool accepts_account_requests, bool accepts_withdrawal_requests)
		{
			auto new_state = get_depository_policy(asset, owner).or_else(states::depository_policy(owner, asset, block));
			new_state.security_level = security_level;
			new_state.accepts_account_requests = accepts_account_requests;
			new_state.accepts_withdrawal_requests = accepts_withdrawal_requests;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			status = emit_event<states::depository_policy>({ format::variable(asset), format::variable(std::string_view((char*)owner, sizeof(algorithm::pubkeyhash))), format::variable((uint8_t)2), format::variable(security_level), format::variable(accepts_account_requests), format::variable(accepts_withdrawal_requests) });
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::depository_account> transaction_context::apply_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const algorithm::pubkeyhash manager, const algorithm::composition::cpubkey public_key, ordered_set<algorithm::pubkeyhash_t>&& group)
		{
			states::depository_account new_state = states::depository_account(manager, asset, owner, block);
			new_state.set_group(public_key, std::move(group));
			new_state.asset = asset;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_program> transaction_context::apply_witness_program(const std::string_view& packed_program_code)
		{
			states::witness_program new_state = states::witness_program(states::witness_program::as_instance_packed_hashcode(packed_program_code), block);
			new_state.storage = packed_program_code;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_event> transaction_context::apply_witness_event(const uint256_t& parent_transaction_hash, const uint256_t& child_transaction_hash)
		{
			states::witness_event new_state = states::witness_event(parent_transaction_hash, block);
			new_state.child_transaction_hash = child_transaction_hash;

			auto status = store(&new_state);
			if (!status)
				return status.error();

			return new_state;
		}
		expects_lr<states::witness_account> transaction_context::apply_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const address_map& addresses)
		{
			return apply_witness_depository_account(asset, owner, nullptr, addresses, false);
		}
		expects_lr<states::witness_account> transaction_context::apply_witness_routing_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const address_map& addresses)
		{
			return apply_witness_depository_account(asset, owner, nullptr, addresses, true);
		}
		expects_lr<states::witness_account> transaction_context::apply_witness_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const algorithm::pubkeyhash manager, const address_map& addresses, bool active)
		{
			if (addresses.empty())
				return layer_exception("invalid operation");

			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return layer_exception("invalid operation");

			ordered_map<string, address_map> segments;
			for (auto& address : addresses)
			{
				auto hash = chain->decode_address(address.second);
				if (!hash)
					return layer_exception(stringify::text("error applying \"%s\" address: %s", address.second.c_str(), hash.error().message().c_str()));

				segments[*hash][address.first] = address.second;
			}

			states::witness_account new_state = states::witness_account(nullptr, 0, { }, nullptr);
			for (auto& segment : segments)
			{
				new_state = states::witness_account(owner, asset, segment.second, block);
				new_state.active = active;
				if (manager != nullptr)
					memcpy(new_state.manager, manager, sizeof(algorithm::pubkeyhash));

				auto status = store(&new_state);
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
		expects_lr<states::witness_transaction> transaction_context::apply_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			states::witness_transaction new_state = states::witness_transaction(asset, transaction_id, block);
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
		expects_lr<states::account_nonce> transaction_context::get_account_nonce(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::account_nonce::as_instance_type(), changelog, states::account_nonce::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_nonce(std::move(*(states::account_nonce*)**state));
		}
		expects_lr<states::account_program> transaction_context::get_account_program(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::account_program::as_instance_type(), changelog, states::account_program::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			auto& result = *(states::account_program*)**state;
			if (result.hashcode.empty())
				return layer_exception("program is detached");

			return states::account_program(std::move(result));
		}
		expects_lr<states::account_uniform> transaction_context::get_account_uniform(const algorithm::pubkeyhash owner, const std::string_view& index) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::account_uniform::as_instance_type(), changelog, states::account_uniform::as_instance_index(owner, index), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_uniform(std::move(*(states::account_uniform*)**state));
		}
		expects_lr<states::account_multiform> transaction_context::get_account_multiform(const algorithm::pubkeyhash owner, const std::string_view& column, const std::string_view& row) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_column(owner, column), states::account_multiform::as_instance_row(row), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_multiform(std::move(*(states::account_multiform*)**state));
		}
		expects_lr<states::account_multiform> transaction_context::get_account_multiform_by_column(const algorithm::pubkeyhash owner, const std::string_view& column, size_t offset) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_column(states::account_multiform::as_instance_type(), changelog, states::account_multiform::as_instance_column(owner, column), get_validation_nonce(), offset);
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_multiform(std::move(*(states::account_multiform*)**state));
		}
		expects_lr<states::account_delegation> transaction_context::get_account_delegation(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::account_delegation::as_instance_type(), changelog, states::account_delegation::as_instance_index(owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_delegation(std::move(*(states::account_delegation*)**state));
		}
		expects_lr<states::account_balance> transaction_context::get_account_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::account_balance::as_instance_type(), changelog, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::account_balance(std::move(*(states::account_balance*)**state));
		}
		expects_lr<states::validator_production> transaction_context::get_validator_production(const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			algorithm::pubkeyhash null = { 0 };
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::validator_production::as_instance_type(), changelog, states::validator_production::as_instance_column(owner), states::validator_production::as_instance_row(), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::validator_production(std::move(*(states::validator_production*)**state));
		}
		expects_lr<states::validator_participation> transaction_context::get_validator_participation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			algorithm::pubkeyhash null = { 0 };
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_column(owner), states::validator_participation::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::validator_participation(std::move(*(states::validator_participation*)**state));
		}
		expects_lr<vector<states::validator_participation>> transaction_context::get_validator_participations(const algorithm::pubkeyhash owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(states::validator_participation::as_instance_type(), changelog, states::validator_participation::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::validator_participation> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::validator_participation*)*state));
			return addresses;
		}
		expects_lr<states::validator_attestation> transaction_context::get_validator_attestation(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			algorithm::pubkeyhash null = { 0 };
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_column(owner), states::validator_attestation::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::validator_attestation(std::move(*(states::validator_attestation*)**state));
		}
		expects_lr<vector<states::validator_attestation>> transaction_context::get_validator_attestations(const algorithm::pubkeyhash owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(states::validator_attestation::as_instance_type(), changelog, states::validator_attestation::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::validator_attestation> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::validator_attestation*)*state));
			return addresses;
		}
		expects_lr<states::depository_reward> transaction_context::get_depository_reward(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::depository_reward::as_instance_type(), changelog, states::depository_reward::as_instance_column(owner), states::depository_reward::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::depository_reward(std::move(*(states::depository_reward*)**state));
		}
		expects_lr<states::depository_balance> transaction_context::get_depository_balance(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::depository_balance::as_instance_type(), changelog, states::depository_balance::as_instance_column(owner), states::depository_balance::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::depository_balance(std::move(*(states::depository_balance*)**state));
		}
		expects_lr<states::depository_policy> transaction_context::get_depository_policy(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner) const
		{
			VI_ASSERT(owner != nullptr, "owner should be set");
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::depository_policy::as_instance_type(), changelog, states::depository_policy::as_instance_column(owner), states::depository_policy::as_instance_row(asset), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::depository_policy(std::move(*(states::depository_policy*)**state));
		}
		expects_lr<vector<states::depository_account>> transaction_context::get_depository_accounts(const algorithm::pubkeyhash manager, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(states::depository_account::as_instance_type(), changelog, states::depository_account::as_instance_column(manager), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::depository_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::depository_account*)*state));
			return addresses;
		}
		expects_lr<states::depository_account> transaction_context::get_depository_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash manager, const algorithm::pubkeyhash owner) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::depository_account::as_instance_type(), changelog, states::depository_account::as_instance_column(manager), states::depository_account::as_instance_row(asset, owner), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::depository_account(std::move(*(states::depository_account*)**state));
		}
		expects_lr<states::witness_program> transaction_context::get_witness_program(const std::string_view& program_hashcode) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::witness_program::as_instance_type(), changelog, states::witness_program::as_instance_index(program_hashcode), get_validation_nonce());
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
			auto state = chain.get_uniform_by_index(states::witness_event::as_instance_type(), changelog, states::witness_event::as_instance_index(parent_transaction_hash), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_event(std::move(*(states::witness_event*)**state));
		}
		expects_lr<vector<states::witness_account>> transaction_context::get_witness_accounts(const algorithm::pubkeyhash owner, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto states = chain.get_multiforms_by_column(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), get_validation_nonce(), offset, count);
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::witness_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::witness_account*)*state));
			return addresses;
		}
		expects_lr<vector<states::witness_account>> transaction_context::get_witness_accounts_by_purpose(const algorithm::pubkeyhash owner, states::witness_account::account_type purpose, size_t offset, size_t count) const
		{
			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::equal((int64_t)purpose, 1);
			auto states = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), filter, get_validation_nonce(), storages::factor_range_window(offset, count));
			if (!states)
				return states.error();

			if (!states->empty())
			{
				auto status = ((transaction_context*)this)->load(*states->front(), chain.query_used());
				if (!status)
					return status.error();
			}

			vector<states::witness_account> addresses;
			addresses.reserve(states->size());
			for (auto& state : *states)
				addresses.emplace_back(std::move(*(states::witness_account*)*state));
			return addresses;
		}
		expects_lr<states::witness_account> transaction_context::get_witness_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, const std::string_view& address) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_column(owner), states::witness_account::as_instance_row(asset, address), get_validation_nonce());
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_account(std::move(*(states::witness_account*)**state));
		}
		expects_lr<states::witness_account> transaction_context::get_witness_account(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_row(states::witness_account::as_instance_type(), changelog, states::witness_account::as_instance_row(asset, address), get_validation_nonce(), offset);
			if (!state)
				return state.error();

			auto status = ((transaction_context*)this)->load(**state, chain.query_used());
			if (!status)
				return status.error();

			return states::witness_account(std::move(*(states::witness_account*)**state));
		}
		expects_lr<states::witness_account> transaction_context::get_witness_account_tagged(const algorithm::asset_id& asset, const std::string_view& address, size_t offset) const
		{
			auto result = get_witness_account(asset, address, offset);
			if (!result)
				result = get_witness_account(asset, warden::address_util::encode_tag_address(address, "0"), offset);
			return result;
		}
		expects_lr<states::witness_transaction> transaction_context::get_witness_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id) const
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(states::witness_transaction::as_instance_type(), changelog, states::witness_transaction::as_instance_index(asset, transaction_id), get_validation_nonce());
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
		expects_lr<uint256_t> transaction_context::calculate_tx_gas(const ledger::transaction* transaction)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			algorithm::pubkeyhash owner = { 0 };
			if (transaction->is_recoverable() && !transaction->recover_hash(owner))
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
			memcpy(temp_environment.validator.public_key_hash, public_key_hash, sizeof(algorithm::pubkeyhash));

			auto validation = transaction->validate(temp_block.number);
			if (!validation)
			{
				revert_transaction();
				return validation.error();
			}

			ledger::block_changelog temp_changelog;
			size_t transaction_size = transaction->as_message().data.size();
			auto execution = transaction_context::execute_tx(&temp_environment, &temp_block, &temp_changelog, transaction, transaction->as_hash(), owner, transaction_size, (transaction->conservative && false ? 0 : (uint8_t)execution_flags::only_successful) | (uint8_t)execution_flags::gas_calculation);
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
		expects_lr<void> transaction_context::validate_tx(const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, algorithm::pubkeyhash owner)
		{
			VI_ASSERT(new_transaction && owner, "transaction and owner should be set");
			memset(owner, 0, sizeof(algorithm::pubkeyhash));
			if (new_transaction->is_recoverable() && !algorithm::signing::recover_hash(new_transaction_hash, owner, new_transaction->signature))
				return layer_exception("invalid signature");

			auto chain = storages::chainstate(__func__);
			return new_transaction->validate(chain.get_latest_block_number().or_else(1));
		}
		expects_lr<transaction_context> transaction_context::execute_tx(const ledger::evaluation_context* new_environment, ledger::block* new_block, block_changelog* changelog, const ledger::transaction* new_transaction, const uint256_t& new_transaction_hash, const algorithm::pubkeyhash owner, size_t transaction_size, uint8_t flags)
		{
			VI_ASSERT(new_environment && new_block && new_transaction && owner, "block, env, transaction and owner should be set");
			ledger::receipt new_receipt;
			new_receipt.transaction_hash = new_transaction_hash;
			new_receipt.generation_time = protocol::now().time.now();
			new_receipt.absolute_gas_use = new_block->gas_use;
			new_receipt.block_number = new_block->number;
			memcpy(new_receipt.from, owner, sizeof(new_receipt.from));

			auto validation = new_transaction->validate(new_receipt.block_number);
			if (!validation)
				return validation.error();

			auto context = transaction_context(new_environment, new_block, changelog, new_transaction, std::move(new_receipt));
			auto deployment = context.burn_gas(transaction_size * (size_t)gas_cost::write_byte);
			if (!deployment)
				return deployment.error();

			bool discard = (context.receipt.events.size() == 1 && context.receipt.events.front().first == 0 && context.receipt.events.front().second.size() == 1);
			auto execution = discard ? expects_lr<void>(layer_exception(context.receipt.events.front().second.front().as_blob())) : context.transaction->execute(&context);
			context.receipt.successful = !!execution;
			if (!context.receipt.successful && context.changelog != nullptr)
				context.changelog->outgoing.revert();
			if (discard)
				context.receipt.events.clear();
			if ((flags & (uint8_t)execution_flags::only_successful) && !context.receipt.successful)
				return execution.error();

			algorithm::pubkeyhash null = { 0 };
			if (memcmp(context.receipt.from, null, sizeof(null)) != 0)
			{
				auto nonce = (flags & (uint8_t)execution_flags::gas_calculation ? context.get_account_nonce(context.receipt.from).or_else(states::account_nonce(nullptr, nullptr)).nonce : context.transaction->nonce);
				auto sequencing = context.apply_account_nonce(context.receipt.from, nonce + 1);
				if (!sequencing)
					return sequencing.error();
			}

			context.receipt.relative_gas_paid = memcmp(context.environment->validator.public_key_hash, context.receipt.from, sizeof(context.receipt.from)) != 0 && context.transaction->gas_price.is_positive() ? context.receipt.relative_gas_use : 0;
			if (context.receipt.relative_gas_paid > 0)
			{
				auto fee = context.apply_fee_transfer(context.transaction->get_gas_asset(), context.receipt.from, context.transaction->gas_price * context.receipt.relative_gas_paid.to_decimal());
				if (!fee)
					return fee.error();
			}

			if (context.receipt.successful)
			{
				for (auto& item : context.witnesses)
					context.block->set_witness_requirement(item.first, item.second);
			}
			else
				context.emit_event(0, { format::variable(execution.what()) }, false);

			context.receipt.finalization_time = protocol::now().time.now();
			context.block->gas_use += context.receipt.relative_gas_use;
			context.block->gas_limit += context.transaction->gas_limit;
			return expects_lr<transaction_context>(std::move(context));
		}
		expects_promise_rt<void> transaction_context::dispatch_tx(dispatch_context* dispatcher, ledger::block_transaction* transaction)
		{
			VI_ASSERT(transaction != nullptr, "transaction should be set");
			VI_ASSERT(dispatcher != nullptr, "dispatcher should be set");
			auto gas_limit = transaction->transaction->gas_limit;
			transaction->transaction->gas_limit = block::get_gas_limit();

			auto* context = memory::init<ledger::transaction_context>();
			context->transaction = *transaction->transaction;
			context->receipt = transaction->receipt;
			return transaction->transaction->dispatch(context, dispatcher).then<expects_rt<void>>([transaction, context, gas_limit](expects_rt<void>&& result)
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

		dispatch_context::dispatch_context(const dispatch_context& other) noexcept : inputs(other.inputs)
		{
			outputs.reserve(other.outputs.size());
			for (auto& output : other.outputs)
			{
				auto* copy = transactions::resolver::from_copy(*output);
				if (copy)
					outputs.push_back(copy);
			}
		}
		dispatch_context& dispatch_context::operator=(const dispatch_context& other) noexcept
		{
			if (this == &other)
				return *this;

			inputs = other.inputs;
			outputs.clear();
			outputs.reserve(other.outputs.size());
			for (auto& output : other.outputs)
			{
				auto* copy = transactions::resolver::from_copy(*output);
				if (copy)
					outputs.push_back(copy);
			}
			return *this;
		}
		expects_lr<uint256_t> dispatch_context::apply_group_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash validator, const algorithm::pubkeyhash owner, const uint256_t& share)
		{
			auto mempool = storages::mempoolstate(__func__);
			auto status = mempool.apply_group_account(asset, validator, owner, share);
			if (!status)
				return status.error();

			return share;
		}
		expects_lr<uint256_t> dispatch_context::recover_group_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash validator, const algorithm::pubkeyhash owner) const
		{
			auto* wallet = get_wallet();
			auto mempool = storages::mempoolstate(__func__);
			return mempool.get_or_apply_group_account_share(asset, validator, owner, algorithm::hashing::hash256i(std::string_view((char*)wallet->secret_key, sizeof(wallet->secret_key))));
		}
		expects_lr<void> dispatch_context::checkpoint()
		{
			auto chain = storages::chainstate(__func__);
			return chain.dispatch(inputs, repeaters);
		}
		promise<void> dispatch_context::dispatch_async(const block_header& target)
		{
			uint64_t block_number = target.number;
			return coasync<void>([this, block_number]() -> promise<void>
			{
				size_t offset = 0, count = 512;
				while (true)
				{
					auto chain = storages::chainstate(__func__);
					auto candidates = chain.get_pending_block_transactions(block_number, offset, count);
					if (!candidates || candidates->empty())
						break;

					offset += candidates->size();
					for (auto& input : *candidates)
					{
						auto execution = coawait(ledger::transaction_context::dispatch_tx(this, &input));
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
		void dispatch_context::dispatch_sync(const block_header& target)
		{
			size_t offset = 0, count = 512;
			while (true)
			{
				auto chain = storages::chainstate(__func__);
				auto candidates = chain.get_pending_block_transactions(target.number, offset, count);
				if (!candidates || candidates->empty())
					break;

				offset += candidates->size();
				for (auto& input : *candidates)
				{
					auto execution = ledger::transaction_context::dispatch_tx(this, &input).get();
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
		void dispatch_context::reset_for_checkpoint()
		{
			errors.clear();
			outputs.clear();
			inputs.clear();
			repeaters.clear();
		}
		void dispatch_context::emit_transaction(uptr<transaction>&& value)
		{
			VI_ASSERT(value, "transaction should be set");
			outputs.push_back(std::move(value));
		}
		void dispatch_context::retry_later(const uint256_t& transaction_hash)
		{
			repeaters.push_back(transaction_hash);
		}
		void dispatch_context::report_trial(const uint256_t& transaction_hash)
		{
			inputs.push_back(transaction_hash);
		}
		void dispatch_context::report_error(const uint256_t& transaction_hash, const std::string_view& error_message)
		{
			auto& error = errors[transaction_hash];
			if (!error.empty())
				error.append(1, '\n');
			error.append(stringify::text("in transaction %s dispatch reverted: %.*s", algorithm::encoding::encode_0xhex256(transaction_hash).c_str(), (int)error_message.size(), error_message.data()));
		}
		bool dispatch_context::is_running_on(const algorithm::pubkeyhash validator) const
		{
			VI_ASSERT(validator != nullptr, "validator should be set");
			return !memcmp(validator, get_wallet()->public_key_hash, sizeof(algorithm::pubkeyhash));
		}
		vector<uptr<transaction>>& dispatch_context::get_sendable_transactions()
		{
			return outputs;
		}
		uptr<schema> dispatch_context::load_cache(const transaction_context* context) const
		{
			auto* server = nss::server_node::get();
			auto location = stringify::text("dispatch_%s", algorithm::encoding::encode_0xhex256(context->receipt.transaction_hash).c_str());
			auto result = server->load_cache(context->transaction->asset, warden::cache_policy::lifetime_cache, location);
			if (result && *result)
				server->store_cache(context->transaction->asset, warden::cache_policy::lifetime_cache, location, nullptr);
			return uptr<schema>(result.or_else(nullptr));
		}
		void dispatch_context::store_cache(const transaction_context* context, uptr<schema>&& value) const
		{
			auto location = stringify::text("dispatch_%s", algorithm::encoding::encode_0xhex256(context->receipt.transaction_hash).c_str());
			nss::server_node::get()->store_cache(context->transaction->asset, warden::cache_policy::lifetime_cache, location, std::move(value));
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
				validation.tip = latest.or_else(tip->number) < (tip->number + 1);
			}
			else
			{
				auto chain = storages::chainstate(__func__);
				auto latest = chain.get_latest_block_number();
				tip = option<ledger::block_header>(optional::none);
				validation.tip = !latest;
			}

			memcpy(validator.public_key_hash, public_key_hash, sizeof(algorithm::pubkeyhash));
			if (secret_key != nullptr)
				memcpy(validator.secret_key, secret_key, sizeof(algorithm::seckey));

			validation.changelog.clear();
			validation.context = ledger::transaction_context(this, tip.address(), &validation.changelog, nullptr, receipt());
			validation.cumulative_gas = 0;
			precomputed = 0;
			producers.clear();
			attesters.clear();
			incoming.clear();
			outgoing.clear();

			if (validation.context.block && !validation.tip)
				++validation.context.block->number;

			auto& policy = protocol::now().policy;
			auto committee = validation.context.calculate_producers(policy.production_max_per_block);
			if (committee)
				producers = std::move(*committee);

			if (producers.empty())
			{
				auto work = validation.context.get_validator_production(validator.public_key_hash);
				if (!work)
					producers.push_back(states::validator_production(validator.public_key_hash, tip.address()));
				else
					producers.push_back(std::move(*work));
			}

			if (validation.context.block && !validation.tip)
				--validation.context.block->number;

			auto position = std::find_if(producers.begin(), producers.end(), [this](const states::validator_production& a) { return !memcmp(a.owner, validator.public_key_hash, sizeof(validator.public_key_hash)); });
			if (position == producers.end())
				return optional::none;

			return std::distance(producers.begin(), position);
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
				if (item.candidate->is_recoverable() && !memcmp(item.owner, null, sizeof(null)))
				{
					outgoing.push_back(item.hash);
					continue;
				}

				uint256_t new_cumulative_gas = validation.cumulative_gas + item.candidate->gas_limit;
				if (new_cumulative_gas > total_gas_limit)
					break;

				bool applicable = false;
				switch (item.candidate->get_type())
				{
					case transaction_level::attestation:
					{
						auto* candidate = ((attestation_transaction*)*item.candidate);
						auto* branch = candidate->get_best_branch(&validation.context, &attesters);
						if (!branch)
							break;

						candidate->set_best_branch(branch->message.hash());
						applicable = true;
						break;
					}
					default:
					{
						auto account_nonce = validation.context.get_account_nonce(item.owner);
						uint64_t nonce_target = (account_nonce ? account_nonce->nonce : 0);
						uint64_t nonce_delta = (nonce_target > item.candidate->nonce ? nonce_target - item.candidate->nonce : 0);
						if (nonce_delta > 1)
						{
							outgoing.push_back(item.hash);
							break;
						}
						else if (nonce_delta > 0)
							break;

						applicable = true;
						break;
					}
				}

				if (applicable)
				{
					validation.cumulative_gas = new_cumulative_gas;
					incoming.emplace_back(std::move(item));
					++precomputed;
				}
			}
			return candidates.size();
		}
		evaluation_context::transaction_info& evaluation_context::include(uptr<transaction>&& candidate)
		{
			auto& info = incoming.emplace_back();
			info.candidate = std::move(candidate);
			return info;
		}
		expects_lr<block_evaluation> evaluation_context::evaluate(string* errors)
		{
			block_evaluation result;
			auto status = precompute(result.block);
			if (!status)
				return status.error();

			auto chain = storages::chainstate(__func__);
			auto evaluation = result.block.evaluate(tip.address(), this, errors);
			cleanup().report("mempool cleanup failed");
			if (!evaluation)
				return evaluation.error();

			result.state = std::move(*evaluation);
			return expects_lr<block_evaluation>(std::move(result));
		}
		expects_lr<void> evaluation_context::solve(block& candidate)
		{
			if (!candidate.solve(validator.secret_key))
				return layer_exception("block proof evaluation failed");

			if (!candidate.sign(validator.secret_key))
				return layer_exception("block signature evaluation failed");

			return expectation::met;
		}
		expects_lr<void> evaluation_context::verify(const block& candidate, const block_state* state)
		{
			auto validity = candidate.verify_validity(tip.address());
			if (!validity)
				return validity;

			return candidate.verify_integrity(tip.address(), state);
		}
		expects_lr<void> evaluation_context::precompute(block& candidate)
		{
			validation.context = transaction_context(this, &candidate, &validation.changelog, nullptr, receipt());
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
				item.candidate->recover_hash(item.owner);
			}));
		}
	}
}
