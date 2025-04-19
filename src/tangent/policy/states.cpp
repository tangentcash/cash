#include "states.h"
#include "../kernel/block.h"
#include "../kernel/script.h"
#include "../validator/service/nss.h"

namespace tangent
{
	namespace states
	{
		account_sequence::account_sequence(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), sequence(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_sequence::account_sequence(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), sequence(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_sequence::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_sequence*)prev_state;
			if (!prev || sequence == std::numeric_limits<uint64_t>::max())
				return expectation::met;

			if (prev->sequence >= sequence)
				return layer_exception("sequence lower than " + to_string(prev->sequence));
			else if (sequence - prev->sequence > 1)
				return layer_exception("sequence skips " + to_string(sequence - prev->sequence) + " steps");

			return expectation::met;
		}
		bool account_sequence::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(sequence);
			return true;
		}
		bool account_sequence::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &sequence))
				return false;

			return true;
		}
		bool account_sequence::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_sequence::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("sequence", algorithm::encoding::serialize_uint256(sequence));
			return data;
		}
		uint32_t account_sequence::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_sequence::as_typename() const
		{
			return as_instance_typename();
		}
		string account_sequence::as_index() const
		{
			return as_instance_index(owner);
		}
		uint32_t account_sequence::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_sequence::as_instance_typename()
		{
			return "account_sequence";
		}
		string account_sequence::as_instance_index(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}

		account_work::account_work(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_work::account_work(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_work::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_work*)prev_state;
			if (prev != nullptr)
			{
				uint256_t gas_input_change = gas_input + prev->gas_input;
				uint256_t gas_output_change = gas_output + prev->gas_output;
				gas_input = (gas_input_change >= gas_input ? gas_input_change : uint256_t::max());
				gas_output = (gas_output_change >= gas_output ? gas_output_change : uint256_t::max());
				if (!flags || prev->is_matching(account_flags::outlaw))
					flags = prev->flags;
				if (prev->is_matching(account_flags::founder))
					flags |= (uint8_t)account_flags::founder;
				if (penalty < prev->penalty)
					penalty = prev->penalty;
			}
			else if (block_number == 1)
				flags |= (uint8_t)account_flags::founder;

			if (!flags || (is_matching(account_flags::online) && is_matching(account_flags::offline)) || (is_matching(account_flags::online) && is_matching(account_flags::outlaw)))
				return layer_exception("invalid status");

			if (gas_output > gas_input)
				gas_output = gas_input;

			if (penalty < block_number)
				penalty = 0;

			return expectation::met;
		}
		bool account_work::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(gas_input);
			stream->write_integer(gas_output);
			stream->write_integer(penalty);
			stream->write_integer(flags);
			return true;
		}
		bool account_work::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_input))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_output))
				return false;

			if (!stream.read_integer(stream.read_type(), &penalty))
				return false;

			if (!stream.read_integer(stream.read_type(), &flags))
				return false;

			return true;
		}
		bool account_work::is_eligible(const ledger::block_header* block_header) const
		{
			return !get_gas_work_required(block_header, get_gas_use());
		}
		bool account_work::is_matching(account_flags flag) const
		{
			return flags & (uint8_t)flag;
		}
		bool account_work::is_online() const
		{
			return block_number > penalty && is_matching(account_flags::online);
		}
		bool account_work::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uint256_t account_work::get_gas_use() const
		{
			return gas_input - gas_output;
		}
		uint64_t account_work::get_closest_proposal_block_number() const
		{
			return std::max(block_number, penalty) + 1;
		}
		uptr<schema> account_work::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("gas_input", algorithm::encoding::serialize_uint256(gas_input));
			data->set("gas_output", algorithm::encoding::serialize_uint256(gas_output));
			data->set("gas_use", algorithm::encoding::serialize_uint256(get_gas_use()));
			data->set("penalty", algorithm::encoding::serialize_uint256(penalty));
			data->set("online", var::boolean(is_online()));

			auto* flags_array = data->set("flags", var::set::array());
			if (is_matching(account_flags::offline))
				flags_array->push(var::string("offline"));
			if (is_matching(account_flags::online))
				flags_array->push(var::string("online"));
			if (is_matching(account_flags::founder))
				flags_array->push(var::string("founder"));
			if (is_matching(account_flags::outlaw))
				flags_array->push(var::string("outlaw"));
			return data;
		}
		uint32_t account_work::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_work::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_work::as_factor() const
		{
			if (!is_online())
				return -1;

			auto gas_use = get_gas_use() / 100;
			return gas_use > std::numeric_limits<int64_t>::max() ? std::numeric_limits<int64_t>::max() : (int64_t)(uint64_t)gas_use;
		}
		string account_work::as_column() const
		{
			return as_instance_column(owner);
		}
		string account_work::as_row() const
		{
			return as_instance_row();
		}
		uint32_t account_work::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_work::as_instance_typename()
		{
			return "account_work";
		}
		string account_work::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string account_work::as_instance_row()
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			return std::move(stream.data);
		}
		uint256_t account_work::get_gas_work_required(const ledger::block_header* block_header, const uint256_t& gas_use)
		{
			auto& config = protocol::now();
			auto total_gas_limit = ledger::block_header::get_gas_limit();
			auto requirement = block_header ? block_header->get_slot_gas_target() : uint256_t(0);
			auto utility = (block_header ? total_gas_limit.to_decimal() / block_header->get_slot_gas_use().to_decimal() : 1);
			if (utility.is_nan())
				utility = decimal::zero();

			auto multiplier = requirement.to_decimal() * utility * config.policy.account_gas_work_required;
			requirement = uint256_t(multiplier.truncate(0).to_string(), 10);
			return requirement > gas_use ? requirement - gas_use : uint256_t(0);
		}
		uint256_t account_work::get_adjusted_gas_paid(const uint256_t& gas_use, const uint256_t& gas_paid)
		{
			return gas_paid > gas_use ? gas_paid - gas_use : uint256_t(0);
		}
		uint256_t account_work::get_adjusted_gas_output(const uint256_t& gas_use, const uint256_t& gas_paid)
		{
			return gas_paid < gas_use ? gas_use - gas_paid : uint256_t(0);
		}

		account_observer::account_observer(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_observer::account_observer(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_observer::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_observer*)prev_state;
			if (!prev && !(algorithm::asset::is_valid(asset) && algorithm::asset::token_of(asset).empty()))
				return layer_exception("invalid asset");

			return expectation::met;
		}
		bool account_observer::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_boolean(observing);
			return true;
		}
		bool account_observer::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_boolean(stream.read_type(), &observing))
				return false;

			return true;
		}
		bool account_observer::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_observer::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("observing", var::boolean(observing));
			return data;
		}
		uint32_t account_observer::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_observer::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_observer::as_factor() const
		{
			return observing ? 1 : -1;
		}
		string account_observer::as_column() const
		{
			return as_instance_column(owner);
		}
		string account_observer::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t account_observer::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_observer::as_instance_typename()
		{
			return "account_observer";
		}
		string account_observer::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string account_observer::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		account_program::account_program(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_program::account_program(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_program::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			return expectation::met;
		}
		bool account_program::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(hashcode);
			return true;
		}
		bool account_program::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &hashcode))
				return false;

			return true;
		}
		bool account_program::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_program::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("hashcode", var::string(format::util::encode_0xhex(hashcode)));
			return data;
		}
		uint32_t account_program::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_program::as_typename() const
		{
			return as_instance_typename();
		}
		string account_program::as_index() const
		{
			return as_instance_index(owner);
		}
		uint32_t account_program::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_program::as_instance_typename()
		{
			return "account_program";
		}
		string account_program::as_instance_index(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}

		account_storage::account_storage(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_storage::account_storage(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_storage::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			if (location.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state location");

			return expectation::met;
		}
		bool account_storage::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(location);
			stream->write_string(storage);
			return true;
		}
		bool account_storage::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &location))
				return false;

			if (!stream.read_string(stream.read_type(), &storage))
				return false;

			return true;
		}
		bool account_storage::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_storage::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("location", var::string(format::util::encode_0xhex(location)));
			data->set("storage", var::string(format::util::encode_0xhex(storage)));
			return data;
		}
		uint32_t account_storage::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_storage::as_typename() const
		{
			return as_instance_typename();
		}
		string account_storage::as_index() const
		{
			return as_instance_index(owner, location);
		}
		uint32_t account_storage::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_storage::as_instance_typename()
		{
			return "account_storage";
		}
		string account_storage::as_instance_index(const algorithm::pubkeyhash owner, const std::string_view& location)
		{
			auto data = format::util::is_hex_encoding(location) ? codec::hex_decode(location) : string(location);
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			stream.write_typeless((char*)data.data(), (uint8_t)data.size());
			return std::move(stream.data);
		}

		account_balance::account_balance(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_balance::account_balance(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_balance::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_balance*)prev_state;
			if (prev)
			{
				supply += prev->supply;
				reserve += prev->reserve;
			}
			else if (!algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			if (supply.is_nan() || supply.is_negative())
				return layer_exception("ran out of supply balance");

			if (reserve.is_nan() || reserve.is_negative())
				return layer_exception("ran out of reserve balance");

			if (supply < reserve)
				return layer_exception("ran out of balance");

			return expectation::met;
		}
		bool account_balance::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_decimal(supply);
			stream->write_decimal(reserve);
			return true;
		}
		bool account_balance::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &supply))
				return false;

			if (!stream.read_decimal(stream.read_type(), &reserve))
				return false;

			return true;
		}
		bool account_balance::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		decimal account_balance::get_balance() const
		{
			if (supply.is_nan() || supply.is_negative() || reserve.is_nan() || reserve.is_negative())
				return decimal::nan();

			auto balance = supply - reserve;
			if (balance.is_negative())
				return decimal::nan();

			return balance;
		}
		uptr<schema> account_balance::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("supply", var::decimal(supply));
			data->set("reserve", var::decimal(reserve));
			data->set("balance", var::decimal(get_balance()));
			return data;
		}
		uint32_t account_balance::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_balance::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_balance::as_factor() const
		{
			auto balance = get_balance();
			balance *= protocol::now().policy.weight_multiplier;
			return balance.to_uint64();
		}
		string account_balance::as_column() const
		{
			return as_instance_column(owner);
		}
		string account_balance::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t account_balance::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_balance::as_instance_typename()
		{
			return "account_balance";
		}
		string account_balance::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string account_balance::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		depository_reward::depository_reward(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_reward::depository_reward(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_reward::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			if (incoming_absolute_fee.is_nan() || incoming_absolute_fee.is_negative())
				return layer_exception("invalid incoming absolute fee");

			if (incoming_relative_fee.is_nan() || incoming_relative_fee.is_negative() || incoming_relative_fee > 1.0)
				return layer_exception("invalid incoming relative fee");

			if (outgoing_absolute_fee.is_nan() || outgoing_absolute_fee.is_negative())
				return layer_exception("invalid outgoing absolute fee");

			if (outgoing_relative_fee.is_nan() || outgoing_relative_fee.is_negative() || outgoing_relative_fee > 1.0)
				return layer_exception("invalid outgoing relative fee");

			auto* prev = (depository_reward*)prev_state;
			if (!prev)
			{
				if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
					return layer_exception("invalid asset");

				return expectation::met;
			}

			decimal threshold = 1.0 - protocol::now().policy.depository_reward_max_increase;
			if (incoming_absolute_fee.is_positive() && prev->incoming_absolute_fee / decimal(incoming_absolute_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("incoming absolute fee increase overflows step threshold");

			if (incoming_relative_fee.is_positive() && prev->incoming_relative_fee / decimal(incoming_relative_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("incoming absolute fee relative overflows step threshold");

			if (outgoing_absolute_fee.is_positive() && prev->outgoing_absolute_fee / decimal(outgoing_absolute_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("outgoing absolute fee increase overflows step threshold");

			if (outgoing_relative_fee.is_positive() && prev->outgoing_relative_fee / decimal(outgoing_relative_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("outgoing absolute fee relative overflows step threshold");

			return expectation::met;
		}
		bool depository_reward::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_decimal(incoming_absolute_fee);
			stream->write_decimal(incoming_relative_fee);
			stream->write_decimal(outgoing_absolute_fee);
			stream->write_decimal(outgoing_relative_fee);
			return true;
		}
		bool depository_reward::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

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
		bool depository_reward::has_incoming_fee() const
		{
			return incoming_absolute_fee.is_positive() || incoming_relative_fee.is_positive();
		}
		bool depository_reward::has_outgoing_fee() const
		{
			return outgoing_absolute_fee.is_positive() || outgoing_relative_fee.is_positive();
		}
		bool depository_reward::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		decimal depository_reward::calculate_incoming_fee(const decimal& value) const
		{
			auto relative_fee = value * decimal(incoming_relative_fee).truncate(protocol::now().message.precision);
			auto leftover_value = value - relative_fee;
			auto absolute_fee = std::min(leftover_value, incoming_absolute_fee);
			return relative_fee + absolute_fee;
		}
		decimal depository_reward::calculate_outgoing_fee(const decimal& value) const
		{
			auto relative_fee = value * decimal(outgoing_relative_fee).truncate(protocol::now().message.precision);
			return relative_fee + outgoing_absolute_fee;
		}
		uptr<schema> depository_reward::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("incoming_absolute_fee", var::decimal(incoming_absolute_fee));
			data->set("incoming_relative_fee", var::decimal(incoming_relative_fee));
			data->set("outgoing_absolute_fee", var::decimal(outgoing_absolute_fee));
			data->set("outgoing_relative_fee", var::decimal(outgoing_relative_fee));
			return data;
		}
		uint32_t depository_reward::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_reward::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t depository_reward::as_factor() const
		{
			decimal absolute_fee = incoming_absolute_fee + outgoing_absolute_fee;
			decimal relative_fee = incoming_relative_fee + outgoing_relative_fee + 1.0;
			absolute_fee *= relative_fee;
			absolute_fee *= protocol::now().policy.weight_multiplier;
			return std::numeric_limits<int64_t>::max() - absolute_fee.to_int64();
		}
		string depository_reward::as_column() const
		{
			return as_instance_column(owner);
		}
		string depository_reward::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t depository_reward::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_reward::as_instance_typename()
		{
			return "depository_reward";
		}
		string depository_reward::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string depository_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		depository_balance::depository_balance(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_balance::depository_balance(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_balance::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (depository_balance*)prev_state;
			if (!prev)
			{
				if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
					return layer_exception("invalid asset");
			}
			else
				supply += prev->supply;

			if (supply.is_nan() || supply.is_negative())
				return layer_exception("invalid supply value");

			return expectation::met;
		}
		bool depository_balance::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_decimal(supply);
			return true;
		}
		bool depository_balance::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &supply))
				return false;

			return true;
		}
		bool depository_balance::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> depository_balance::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("supply", var::decimal(supply));
			return data;
		}
		uint32_t depository_balance::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_balance::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t depository_balance::as_factor() const
		{
			auto value = supply;
			value *= protocol::now().policy.weight_multiplier;
			return value.to_uint64();
		}
		string depository_balance::as_column() const
		{
			return as_instance_column(owner);
		}
		string depository_balance::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t depository_balance::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_balance::as_instance_typename()
		{
			return "depository_balance";
		}
		string depository_balance::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string depository_balance::as_instance_row(const algorithm::asset_id& asset)
		{ 
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		depository_policy::depository_policy(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_policy::depository_policy(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_policy::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (depository_policy*)prev_state;
			if (!prev)
			{
				if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
					return layer_exception("invalid asset");
			}
			else
			{
				if (accounts_under_management < prev->accounts_under_management)
					return layer_exception("invalid accounts count");

				if (prev->queue_transaction_hash > 0 && queue_transaction_hash > 0 && prev->queue_transaction_hash != queue_transaction_hash)
					return layer_exception("transaction queue head cannot be replaced with new transaction");
			}

			if (security_level > (uint8_t)protocol::now().policy.depository_committee_max_size)
				return layer_exception("security level too high");
			else if (security_level < (uint8_t)protocol::now().policy.depository_committee_min_size)
				return layer_exception("security level too low");

			if (accepts_account_requests && !accepts_withdrawal_requests)
				return layer_exception("withdrawal requests must be accepted if account creation requests are accepted");

			return expectation::met;
		}
		bool depository_policy::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_integer(queue_transaction_hash);
			stream->write_integer(accounts_under_management);
			stream->write_integer(security_level);
			stream->write_boolean(accepts_account_requests);
			stream->write_boolean(accepts_withdrawal_requests);
			return true;
		}
		bool depository_policy::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &queue_transaction_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &accounts_under_management))
				return false;

			if (!stream.read_integer(stream.read_type(), &security_level))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_account_requests))
				return false;

			if (!stream.read_boolean(stream.read_type(), &accepts_withdrawal_requests))
				return false;

			return true;
		}
		bool depository_policy::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> depository_policy::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("queue_transaction_hash", queue_transaction_hash > 0 ? var::string(algorithm::encoding::encode_0xhex256(queue_transaction_hash)) : var::null());
			data->set("accounts_under_management", var::integer(accounts_under_management));
			data->set("security_level", var::integer(security_level));
			data->set("accepts_account_requests", var::boolean(accepts_account_requests));
			data->set("accepts_withdrawal_requests", var::boolean(accepts_withdrawal_requests));
			return data;
		}
		uint32_t depository_policy::as_type() const
		{
			return as_instance_type();
		}
		std::string_view depository_policy::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t depository_policy::as_factor() const
		{
			return std::max<uint64_t>(1, accounts_under_management) * security_level;
		}
		string depository_policy::as_column() const
		{
			return as_instance_column(owner);
		}
		string depository_policy::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t depository_policy::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_policy::as_instance_typename()
		{
			return "depository_policy";
		}
		string depository_policy::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string depository_policy::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		depository_account::depository_account(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_account::depository_account(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_account::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (depository_account*)prev_state;
			if (!prev && !algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			algorithm::composition::cpubkey null = { 0 };
			if (!mpc.empty() && !memcmp(mpc_public_key, null, sizeof(null)))
				return layer_exception("invalid mpc public key");

			for (auto& item : mpc)
			{
				if (item.empty())
					return layer_exception("invalid mpc");
			}

			return expectation::met;
		}
		bool depository_account::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null_pkh = { 0 };
			algorithm::composition::cpubkey null_pk = { 0 };
			stream->write_integer(asset);
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null_pkh, sizeof(null_pkh)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null_pkh, sizeof(null_pkh)) == 0 ? 0 : sizeof(proposer)));
			stream->write_string(std::string_view((char*)mpc_public_key, memcmp(mpc_public_key, null_pk, sizeof(null_pk)) == 0 ? 0 : sizeof(mpc_public_key)));
			stream->write_integer((uint8_t)mpc.size());
			for (auto& item : mpc)
				stream->write_string(item.optimized_view());
			return true;
		}
		bool depository_account::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			string mpc_public_key_assembly;
			if (!stream.read_string(stream.read_type(), &mpc_public_key_assembly) || !algorithm::encoding::decode_uint_blob(mpc_public_key_assembly, mpc_public_key, sizeof(mpc_public_key)))
				return false;

			uint8_t mpc_size;
			if (!stream.read_integer(stream.read_type(), &mpc_size))
				return false;

			mpc.clear();
			for (uint8_t i = 0; i < mpc_size; i++)
			{
				string mpc_assembly;
				algorithm::pubkeyhash mpc_hash;
				if (!stream.read_string(stream.read_type(), &mpc_assembly) || !algorithm::encoding::decode_uint_blob(mpc_assembly, mpc_hash, sizeof(mpc_hash)))
					return false;

				mpc.insert(algorithm::pubkeyhash_t(mpc_hash));
			}

			return true;
		}
		void depository_account::set_mpc(const algorithm::pubkeyhash new_proposer, const algorithm::composition::cpubkey new_public_key, ordered_set<algorithm::pubkeyhash_t>&& new_mpc)
		{
			mpc = std::move(new_mpc);
			if (!new_proposer)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_proposer, sizeof(algorithm::pubkeyhash));
			if (!new_public_key)
			{
				algorithm::composition::cpubkey null = { 0 };
				memcpy(mpc_public_key, null, sizeof(algorithm::composition::cpubkey));
			}
			else
				memcpy(mpc_public_key, new_public_key, sizeof(algorithm::composition::cpubkey));
		}
		bool depository_account::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool depository_account::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(proposer, null, sizeof(null));
		}
		uptr<schema> depository_account::as_schema() const
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			auto mpc_public_key_size = chain ? algorithm::composition::size_of_public_key(chain->composition) : sizeof(mpc_public_key);
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			data->set("asset", algorithm::asset::serialize(asset));
			algorithm::composition::cpubkey null = { 0 };
			if (!memcmp(mpc_public_key, null, sizeof(null)))
				data->set("mpc_public_key", var::string(format::util::encode_0xhex(std::string_view((char*)mpc_public_key, mpc_public_key_size))));
			else
				data->set("mpc_public_key", var::null());
			auto* mpc_data = data->set("mpc", var::array());
			for (auto& item : mpc)
				mpc_data->push(item.empty() ? var::set::null() : algorithm::signing::serialize_address(item.data));
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
		int64_t depository_account::as_factor() const
		{
			return 0;
		}
		string depository_account::as_column() const
		{
			return as_instance_column(proposer);
		}
		string depository_account::as_row() const
		{
			return as_instance_row(asset, owner);
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
		string depository_account::as_instance_column(const algorithm::pubkeyhash proposer)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)proposer, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string depository_account::as_instance_row(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		witness_program::witness_program(uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
		}
		witness_program::witness_program(const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
		}
		expects_lr<void> witness_program::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (prev_state != nullptr)
				return layer_exception("program already exists");

			if (storage.empty())
				return layer_exception("program storage not valid");

			auto code = as_code();
			if (!code)
				return layer_exception("program storage not valid: " + code.error().message());

			hashcode = ledger::script_host::get()->hashcode(*code);
			return expectation::met;
		}
		bool witness_program::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(hashcode);
			stream->write_string(storage);
			return true;
		}
		bool witness_program::load_payload(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &hashcode))
				return false;

			if (!stream.read_string(stream.read_type(), &storage))
				return false;

			return true;
		}
		uptr<schema> witness_program::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("hashcode", var::string(format::util::encode_0xhex(hashcode)));
			data->set("storage", var::string(format::util::encode_0xhex(storage)));
			return data;
		}
		uint32_t witness_program::as_type() const
		{
			return as_instance_type();
		}
		std::string_view witness_program::as_typename() const
		{
			return as_instance_typename();
		}
		string witness_program::as_index() const
		{
			return as_instance_index(hashcode);
		}
		expects_lr<string> witness_program::as_code() const
		{
			return ledger::script_host::get()->unpack(storage);
		}
		uint32_t witness_program::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view witness_program::as_instance_typename()
		{
			return "witness_program";
		}
		string witness_program::as_instance_index(const std::string_view& hashcode)
		{
			auto data = format::util::is_hex_encoding(hashcode) ? codec::hex_decode(hashcode) : string(hashcode);
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(data.data(), (uint8_t)data.size());
			return std::move(stream.data);
		}

		witness_event::witness_event(uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
		}
		witness_event::witness_event(const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
		}
		expects_lr<void> witness_event::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (!parent_transaction_hash)
				return layer_exception("invalid parent transaction hash");

			if (!child_transaction_hash)
				return layer_exception("invalid child transaction hash");

			if (prev_state != nullptr)
				return layer_exception("event already finalized");

			return expectation::met;
		}
		bool witness_event::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(parent_transaction_hash);
			stream->write_integer(child_transaction_hash);
			return true;
		}
		bool witness_event::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &parent_transaction_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &child_transaction_hash))
				return false;

			return true;
		}
		uptr<schema> witness_event::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("parent_transaction_hash", var::string(algorithm::encoding::encode_0xhex256(parent_transaction_hash)));
			data->set("child_transaction_hash", var::string(algorithm::encoding::encode_0xhex256(child_transaction_hash)));
			return data;
		}
		uint32_t witness_event::as_type() const
		{
			return as_instance_type();
		}
		std::string_view witness_event::as_typename() const
		{
			return as_instance_typename();
		}
		string witness_event::as_index() const
		{
			return as_instance_index(parent_transaction_hash);
		}
		uint32_t witness_event::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view witness_event::as_instance_typename()
		{
			return "witness_event";
		}
		string witness_event::as_instance_index(const uint256_t& transaction_hash)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(transaction_hash);
			return std::move(stream.data);
		}

		witness_account::witness_account(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		witness_account::witness_account(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> witness_account::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (witness_account*)prev_state;
			if (!prev && !algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			if (addresses.empty())
				return layer_exception("invalid address");

			for (auto& address : addresses)
			{
				if (stringify::is_empty_or_whitespace(address.second))
					return layer_exception("invalid address");
			}

			return expectation::met;
		}
		bool witness_account::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null_pkh = { 0 };
			algorithm::composition::cpubkey null_pk = { 0 };
			stream->write_integer(asset);
			stream->write_boolean(active);
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null_pkh, sizeof(null_pkh)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null_pkh, sizeof(null_pkh)) == 0 ? 0 : sizeof(proposer)));
			stream->write_integer((uint8_t)addresses.size());
			for (auto& address : addresses)
			{
				stream->write_integer(address.first);
				stream->write_string(address.second);
			}
			return true;
		}
		bool witness_account::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_boolean(stream.read_type(), &active))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			uint8_t addresses_size;
			if (!stream.read_integer(stream.read_type(), &addresses_size))
				return false;

			addresses.clear();
			for (uint8_t i = 0; i < addresses_size; i++)
			{
				uint8_t version;
				if (!stream.read_integer(stream.read_type(), &version))
					return false;

				string address;
				if (!stream.read_string(stream.read_type(), &address))
					return false;

				addresses[version] = std::move(address);
			}

			return true;
		}
		bool witness_account::is_witness_account() const
		{
			return !active;
		}
		bool witness_account::is_routing_account() const
		{
			algorithm::pubkeyhash null_pkh = { 0 };
			algorithm::composition::cpubkey null_pk = { 0 };
			return memcmp(proposer, null_pkh, sizeof(null_pkh)) == 0 && memcmp(owner, null_pkh, sizeof(null_pkh)) != 0 && active;
		}
		bool witness_account::is_depository_account() const
		{
			algorithm::pubkeyhash null_pkh = { 0 };
			algorithm::composition::cpubkey null_pk = { 0 };
			return memcmp(proposer, null_pkh, sizeof(null_pkh)) != 0 && memcmp(owner, null_pkh, sizeof(null_pkh)) != 0 && active;
		}
		bool witness_account::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool witness_account::is_proposer_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(proposer, null, sizeof(null));
		}
		witness_account::account_type witness_account::get_type() const
		{
			account_type type;
			if (is_routing_account())
				type = account_type::routing;
			else if (is_depository_account())
				type = account_type::depository;
			else
				type = account_type::witness;
			return type;
		}
		uptr<schema> witness_account::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			data->set("asset", algorithm::asset::serialize(asset));
			auto* addresses_data = data->set("addresses", var::set::array());
			for (auto& address : addresses)
				addresses_data->push(var::string(address.second));
			switch (get_type())
			{
				case account_type::routing:
					data->set("purpose", var::string("routing"));
					break;
				case account_type::depository:
					data->set("purpose", var::string("depository"));
					break;
				default:
					data->set("purpose", var::string("witness"));
					break;
			}
			return data;
		}
		uint32_t witness_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view witness_account::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t witness_account::as_factor() const
		{
			return (int64_t)get_type();
		}
		string witness_account::as_column() const
		{
			return as_instance_column(owner);
		}
		string witness_account::as_row() const
		{
			return as_instance_row(asset, addresses.empty() ? std::string_view() : addresses.begin()->second);
		}
		uint32_t witness_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view witness_account::as_instance_typename()
		{
			return "witness_account";
		}
		string witness_account::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string witness_account::as_instance_row(const algorithm::asset_id& asset, const std::string_view& address)
		{
			auto location = nss::server_node::get()->decode_address(asset, address).or_else(string(address));
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(location.data(), (uint8_t)location.size());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		witness_transaction::witness_transaction(uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
		}
		witness_transaction::witness_transaction(const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
		}
		expects_lr<void> witness_transaction::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			auto* prev = (witness_account*)prev_state;
			if (!prev && !algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			if (transaction_id.empty())
				return layer_exception("invalid transaction id");

			return expectation::met;
		}
		bool witness_transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_string(transaction_id);
			return true;
		}
		bool witness_transaction::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			return true;
		}
		uptr<schema> witness_transaction::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("transaction_id", var::string(transaction_id));
			return data;
		}
		uint32_t witness_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view witness_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		string witness_transaction::as_index() const
		{
			return as_instance_index(asset, transaction_id);
		}
		uint32_t witness_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view witness_transaction::as_instance_typename()
		{
			return "witness_transaction";
		}
		string witness_transaction::as_instance_index(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			auto id = format::util::is_hex_encoding(transaction_id) ? codec::hex_decode(transaction_id) : string(transaction_id);
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			stream.write_typeless(id.data(), (uint8_t)id.size());
			return std::move(stream.data);
		}

		ledger::state* resolver::from_stream(format::stream& stream)
		{
			uint32_t type; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &type))
				return nullptr;

			stream.seek = seek;
			return from_type(type);
		}
		ledger::state* resolver::from_type(uint32_t hash)
		{
			if (hash == account_sequence::as_instance_type())
				return memory::init<account_sequence>(nullptr, nullptr);
			else if (hash == account_work::as_instance_type())
				return memory::init<account_work>(nullptr, nullptr);
			else if (hash == account_observer::as_instance_type())
				return memory::init<account_observer>(nullptr, nullptr);
			else if (hash == account_program::as_instance_type())
				return memory::init<account_program>(nullptr, nullptr);
			else if (hash == account_storage::as_instance_type())
				return memory::init<account_storage>(nullptr, nullptr);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(nullptr, nullptr);
			else if (hash == depository_reward::as_instance_type())
				return memory::init<depository_reward>(nullptr, nullptr);
			else if (hash == depository_balance::as_instance_type())
				return memory::init<depository_balance>(nullptr, nullptr);
			else if (hash == depository_policy::as_instance_type())
				return memory::init<depository_policy>(nullptr, nullptr);
			else if (hash == depository_account::as_instance_type())
				return memory::init<depository_account>(nullptr, nullptr);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(nullptr);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(nullptr);
			else if (hash == witness_account::as_instance_type())
				return memory::init<witness_account>(nullptr, nullptr);
			else if (hash == witness_transaction::as_instance_type())
				return memory::init<witness_transaction>(nullptr);
			return nullptr;
		}
		ledger::state* resolver::from_copy(const ledger::state* base)
		{
			uint32_t hash = base->as_type();
			if (hash == account_sequence::as_instance_type())
				return memory::init<account_sequence>(*(const account_sequence*)base);
			else if (hash == account_work::as_instance_type())
				return memory::init<account_work>(*(const account_work*)base);
			else if (hash == account_observer::as_instance_type())
				return memory::init<account_observer>(*(const account_observer*)base);
			else if (hash == account_program::as_instance_type())
				return memory::init<account_program>(*(const account_program*)base);
			else if (hash == account_storage::as_instance_type())
				return memory::init<account_storage>(*(const account_storage*)base);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(*(const account_balance*)base);
			else if (hash == depository_reward::as_instance_type())
				return memory::init<depository_reward>(*(const depository_reward*)base);
			else if (hash == depository_balance::as_instance_type())
				return memory::init<depository_balance>(*(const depository_balance*)base);
			else if (hash == depository_policy::as_instance_type())
				return memory::init<depository_policy>(*(const depository_policy*)base);
			else if (hash == depository_account::as_instance_type())
				return memory::init<depository_account>(*(const depository_account*)base);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(*(const witness_program*)base);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(*(const witness_event*)base);
			else if (hash == witness_account::as_instance_type())
				return memory::init<witness_account>(*(const witness_account*)base);
			else if (hash == witness_transaction::as_instance_type())
				return memory::init<witness_transaction>(*(const witness_transaction*)base);
			return nullptr;
		}
		unordered_set<uint32_t> resolver::get_hashes()
		{
			unordered_set<uint32_t> hashes;
			hashes.insert(account_sequence::as_instance_type());
			hashes.insert(account_work::as_instance_type());
			hashes.insert(account_observer::as_instance_type());
			hashes.insert(account_program::as_instance_type());
			hashes.insert(account_storage::as_instance_type());
			hashes.insert(account_balance::as_instance_type());
			hashes.insert(depository_reward::as_instance_type());
			hashes.insert(depository_balance::as_instance_type());
			hashes.insert(depository_policy::as_instance_type());
			hashes.insert(depository_account::as_instance_type());
			hashes.insert(witness_program::as_instance_type());
			hashes.insert(witness_event::as_instance_type());
			hashes.insert(witness_account::as_instance_type());
			hashes.insert(witness_transaction::as_instance_type());
			return hashes;
		}
	}
}
