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
			if (prev != nullptr && sequence != std::numeric_limits<uint64_t>::max())
			{
				if (!sequence)
					sequence = prev->sequence + 1;
				else if (prev->sequence > sequence)
					return layer_exception("sequence lower than " + to_string(prev->sequence));
				else if (sequence - prev->sequence > 1)
					return layer_exception("excessive sequence gap " + to_string(sequence - prev->sequence));
			}
			else if (!sequence)
				return layer_exception("zero sequence not allowed");

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

		account_reward::account_reward(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_reward::account_reward(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_reward::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
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

			auto* prev = (account_reward*)prev_state;
			if (!prev)
			{
				if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
					return layer_exception("invalid asset");

				return expectation::met;
			}

			decimal threshold = 1.0 - protocol::now().policy.account_reward_max_increase;
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
		bool account_reward::store_payload(format::stream* stream) const
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
		bool account_reward::load_payload(format::stream& stream)
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
		bool account_reward::has_incoming_fee() const
		{
			return incoming_absolute_fee.is_positive() || incoming_relative_fee.is_positive();
		}
		bool account_reward::has_outgoing_fee() const
		{
			return outgoing_absolute_fee.is_positive() || outgoing_relative_fee.is_positive();
		}
		bool account_reward::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		decimal account_reward::calculate_incoming_fee(const decimal& value) const
		{
			auto relative_fee = value * decimal(incoming_relative_fee).truncate(protocol::now().message.precision);
			auto leftover_value = value - relative_fee;
			auto absolute_fee = std::min(leftover_value, incoming_absolute_fee);
			return relative_fee + absolute_fee;
		}
		decimal account_reward::calculate_outgoing_fee(const decimal& value) const
		{
			auto relative_fee = value * decimal(outgoing_relative_fee).truncate(protocol::now().message.precision);
			auto leftover_value = value - relative_fee;
			auto absolute_fee = std::min(leftover_value, outgoing_absolute_fee);
			return relative_fee + absolute_fee;
		}
		uptr<schema> account_reward::as_schema() const
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
		uint32_t account_reward::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_reward::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_reward::as_factor() const
		{
			decimal absolute_fee = incoming_absolute_fee + outgoing_absolute_fee;
			decimal relative_fee = incoming_relative_fee + outgoing_relative_fee + 1.0;
			absolute_fee *= relative_fee;
			absolute_fee *= protocol::now().policy.weight_multiplier;
			return std::numeric_limits<int64_t>::max() - absolute_fee.to_int64();
		}
		string account_reward::as_column() const
		{
			return as_instance_column(owner);
		}
		string account_reward::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t account_reward::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_reward::as_instance_typename()
		{
			return "account_reward";
		}
		string account_reward::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string account_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(asset);
			return std::move(stream.data);
		}

		account_derivation::account_derivation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), asset(0), max_address_index(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_derivation::account_derivation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), asset(0), max_address_index(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_derivation::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_derivation*)prev_state;
			if (prev && prev->max_address_index >= max_address_index)
				return layer_exception("invalid max address index");
			else if (!prev && !algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			return expectation::met;
		}
		bool account_derivation::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_integer(max_address_index);
			return true;
		}
		bool account_derivation::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &max_address_index))
				return false;

			return true;
		}
		bool account_derivation::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_derivation::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("max_address_index", algorithm::encoding::serialize_uint256(max_address_index));
			return data;
		}
		uint32_t account_derivation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_derivation::as_typename() const
		{
			return as_instance_typename();
		}
		string account_derivation::as_index() const
		{
			return as_instance_index(owner, asset);
		}
		uint32_t account_derivation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_derivation::as_instance_typename()
		{
			return "account_derivation";
		}
		string account_derivation::as_instance_index(const algorithm::pubkeyhash owner, const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			stream.write_typeless(asset);
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

		account_depository::account_depository(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_depository::account_depository(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_depository::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_depository*)prev_state;
			if (!prev && !algorithm::asset::is_valid(asset))
				return layer_exception("invalid asset");

			for (auto it = contributions.cbegin(); it != contributions.cend();)
			{
				if (it->second.is_nan() || it->second.is_negative())
					return layer_exception("invalid contribution");

				if (it->second.is_zero())
					contributions.erase(it++);
				else
					++it;
			}

			for (auto it = reservations.cbegin(); it != reservations.cend();)
			{
				if (it->second.is_nan() || it->second.is_negative())
					return layer_exception("invalid reservation");

				if (it->second.is_zero())
					reservations.erase(it++);
				else
					++it;
			}

			for (auto& item : transactions)
			{
				if (!item)
					return layer_exception("invalid transaction hash");
			}

			if (custody.is_negative())
				return layer_exception("invalid custody value");

			return expectation::met;
		}
		bool account_depository::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_integer(asset);
			stream->write_decimal(custody);
			stream->write_integer((uint32_t)contributions.size());
			for (auto& item : contributions)
			{
				stream->write_string(item.first);
				stream->write_decimal(item.second);
			}
			stream->write_integer((uint32_t)reservations.size());
			for (auto& item : reservations)
			{
				stream->write_string(item.first);
				stream->write_decimal(item.second);
			}
			stream->write_integer((uint32_t)transactions.size());
			for (auto& item : transactions)
				stream->write_integer(item);
			return true;
		}
		bool account_depository::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &custody))
				return false;

			uint32_t contributions_size;
			if (!stream.read_integer(stream.read_type(), &contributions_size))
				return false;

			contributions.clear();
			for (uint32_t i = 0; i < contributions_size; i++)
			{
				string address;
				if (!stream.read_string(stream.read_type(), &address))
					return false;

				auto& contribution = contributions[address];
				if (!stream.read_decimal(stream.read_type(), &contribution))
					return false;
			}

			uint32_t reservations_size;
			if (!stream.read_integer(stream.read_type(), &reservations_size))
				return false;

			reservations.clear();
			for (uint32_t i = 0; i < reservations_size; i++)
			{
				string owner;
				if (!stream.read_string(stream.read_type(), &owner))
					return false;

				auto& reservation = reservations[owner];
				if (!stream.read_decimal(stream.read_type(), &reservation))
					return false;
			}

			uint32_t transactions_size;
			if (!stream.read_integer(stream.read_type(), &transactions_size))
				return false;

			transactions.clear();
			for (uint32_t i = 0; i < transactions_size; i++)
			{
				uint256_t transaction_hash;
				if (!stream.read_integer(stream.read_type(), &transaction_hash))
					return false;

				transactions.insert(transaction_hash);
			}

			return true;
		}
		bool account_depository::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		decimal account_depository::get_reservation() const
		{
			decimal value = decimal::zero();
			for (auto& item : reservations)
				value += item.second;
			return value;
		}
		decimal account_depository::get_contribution(const std::string_view& address) const
		{
			auto contribution = contributions.find(string(address));
			return contribution != contributions.end() ? contribution->second : decimal::zero();
		}
		decimal account_depository::get_contribution(const ordered_set<string>& addresses) const
		{
			decimal value = decimal::zero();
			for (auto& address : addresses)
				value += get_contribution(address);
			return value;
		}
		decimal account_depository::get_contribution() const
		{
			decimal value = decimal::zero();
			for (auto& item : contributions)
				value += item.second;
			return value;
		}
		decimal account_depository::get_coverage(uint8_t flags) const
		{
			if (!custody.is_positive())
				return decimal::zero();

			auto contribution = get_contribution();
			if (!(flags & (uint8_t)account_flags::founder))
				contribution -= custody * decimal(protocol::now().policy.account_contribution_required).truncate(protocol::now().message.precision);
			if (contribution.is_nan())
				contribution = decimal::zero();
			if (flags & (uint8_t)account_flags::outlaw)
			{
				if (contribution.is_positive())
					contribution = -contribution;
				else if (contribution.is_zero())
					contribution = decimal(-1);
			}

			return contribution;
		}
		uptr<schema> account_depository::as_schema() const
		{
			auto reservation = get_reservation();
			auto contribution = get_contribution();
			auto coverage = get_coverage(0);
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("custody", custody.is_nan() ? var::null() : var::decimal(custody));
			data->set("contribution", contribution.is_nan() ? var::null() : var::decimal(contribution));
			data->set("reservation", reservation.is_nan() ? var::null() : var::decimal(reservation));
			data->set("coverage", coverage.is_nan() ? var::null() : var::decimal(coverage));
			if (!contributions.empty())
			{
				auto* contributions_data = data->set("contributions", var::set::array());
				for (auto& item : contributions)
				{
					auto* contribution_data = contributions_data->push(var::set::object());
					contribution_data->set("address", var::string(item.first));
					contribution_data->set("value", var::decimal(item.second));
				}
			}
			if (!reservations.empty())
			{
				auto* reservations_data = data->set("reservations", var::set::array());
				for (auto& item : reservations)
				{
					algorithm::pubkeyhash owner; string address;
					memcpy(owner, item.first.data(), std::min(sizeof(owner), item.first.size()));
					algorithm::signing::encode_address(owner, address);

					auto* reservation_data = reservations_data->push(var::set::object());
					reservation_data->set("owner", var::string(address));
					reservation_data->set("value", var::decimal(item.second));
				}
			}
			if (!transactions.empty())
			{
				auto* transactions_data = data->set("transactions", var::set::array());
				for (auto& item : transactions)
					transactions_data->push(algorithm::encoding::serialize_uint256(item));
			}
			return data;
		}
		uint32_t account_depository::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_depository::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_depository::as_factor() const
		{
			decimal coverage = get_coverage(0) * protocol::now().policy.weight_multiplier;
			return coverage.to_int64();
		}
		string account_depository::as_column() const
		{
			return as_instance_column(owner);
		}
		string account_depository::as_row() const
		{
			return as_instance_row(asset);
		}
		uint32_t account_depository::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_depository::as_instance_typename()
		{
			return "account_depository";
		}
		string account_depository::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string account_depository::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
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

		witness_address::witness_address(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), address_index(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		witness_address::witness_address(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), address_index(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> witness_address::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (witness_address*)prev_state;
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
		bool witness_address::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(std::string_view((char*)proposer, memcmp(proposer, null, sizeof(null)) == 0 ? 0 : sizeof(proposer)));
			stream->write_integer((uint8_t)purpose);
			stream->write_integer(asset);
			stream->write_integer(address_index);
			stream->write_integer((uint8_t)addresses.size());
			for (auto& address : addresses)
			{
				stream->write_integer(address.first);
				stream->write_string(address.second);
			}
			return true;
		}
		bool witness_address::load_payload(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			string proposer_assembly;
			if (!stream.read_string(stream.read_type(), &proposer_assembly) || !algorithm::encoding::decode_uint_blob(proposer_assembly, proposer, sizeof(proposer)))
				return false;

			if (!stream.read_integer(stream.read_type(), (uint8_t*)&purpose))
				return false;

			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &address_index))
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
		void witness_address::set_proposer(const algorithm::pubkeyhash new_value)
		{
			if (!new_value)
			{
				algorithm::pubkeyhash null = { 0 };
				memcpy(proposer, null, sizeof(algorithm::pubkeyhash));
			}
			else
				memcpy(proposer, new_value, sizeof(algorithm::pubkeyhash));
		}
		bool witness_address::is_witness_address() const
		{
			return purpose == address_type::witness && memcmp(proposer, owner, sizeof(owner)) == 0;
		}
		bool witness_address::is_router_address() const
		{
			algorithm::pubkeyhash null = { 0 };
			return purpose == address_type::router && memcmp(proposer, null, sizeof(null)) == 0;
		}
		bool witness_address::is_custodian_address() const
		{
			algorithm::pubkeyhash null = { 0 };
			return purpose == address_type::custodian && memcmp(proposer, null, sizeof(null)) != 0;
		}
		bool witness_address::is_contribution_address() const
		{
			return purpose == address_type::contribution && memcmp(proposer, owner, sizeof(owner)) == 0;
		}
		bool witness_address::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> witness_address::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("proposer", algorithm::signing::serialize_address(proposer));
			data->set("asset", algorithm::asset::serialize(asset));
			auto* addresses_data = data->set("addresses", var::set::array());
			for (auto& address : addresses)
				addresses_data->push(var::string(address.second));
			data->set("address_index", algorithm::encoding::serialize_uint256(address_index));
			switch (purpose)
			{
				case address_type::witness:
					data->set("purpose", var::string("witness"));
					break;
				case address_type::router:
					data->set("purpose", var::string("router"));
					break;
				case address_type::custodian:
					data->set("purpose", var::string("custodian"));
					break;
				case address_type::contribution:
					data->set("purpose", var::string("contribution"));
					break;
				default:
					data->set("purpose", var::string("bad"));
					break;
			}
			return data;
		}
		uint32_t witness_address::as_type() const
		{
			return as_instance_type();
		}
		std::string_view witness_address::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t witness_address::as_factor() const
		{
			return (int64_t)purpose;
		}
		string witness_address::as_column() const
		{
			return as_instance_column(owner);
		}
		string witness_address::as_row() const
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			return as_instance_row(asset, addresses.empty() ? std::string_view() : addresses.begin()->second, chain && chain->routing == mediator::routing_policy::memo ? address_index : protocol::now().account.root_address_index);
		}
		uint32_t witness_address::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view witness_address::as_instance_typename()
		{
			return "witness_address";
		}
		string witness_address::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless((char*)owner, (uint8_t)sizeof(algorithm::pubkeyhash));
			return std::move(stream.data);
		}
		string witness_address::as_instance_row(const algorithm::asset_id& asset, const std::string_view& address, uint64_t max_address_index)
		{
			auto location = nss::server_node::get()->new_public_key_hash(asset, address).or_else(string(address));
			format::stream stream;
			stream.write_typeless(as_instance_type());
			stream.write_typeless(location.data(), (uint8_t)location.size());
			stream.write_typeless(asset);
			stream.write_typeless(max_address_index);
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
			auto* prev = (witness_address*)prev_state;
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

		ledger::state* resolver::init(uint32_t hash)
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
			else if (hash == account_reward::as_instance_type())
				return memory::init<account_reward>(nullptr, nullptr);
			else if (hash == account_derivation::as_instance_type())
				return memory::init<account_derivation>(nullptr, nullptr);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(nullptr, nullptr);
			else if (hash == account_depository::as_instance_type())
				return memory::init<account_depository>(nullptr, nullptr);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(nullptr);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(nullptr);
			else if (hash == witness_address::as_instance_type())
				return memory::init<witness_address>(nullptr, nullptr);
			else if (hash == witness_transaction::as_instance_type())
				return memory::init<witness_transaction>(nullptr);
			return nullptr;
		}
		ledger::state* resolver::copy(const ledger::state* base)
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
			else if (hash == account_reward::as_instance_type())
				return memory::init<account_reward>(*(const account_reward*)base);
			else if (hash == account_derivation::as_instance_type())
				return memory::init<account_derivation>(*(const account_derivation*)base);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(*(const account_balance*)base);
			else if (hash == account_depository::as_instance_type())
				return memory::init<account_depository>(*(const account_depository*)base);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(*(const witness_program*)base);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(*(const witness_event*)base);
			else if (hash == witness_address::as_instance_type())
				return memory::init<witness_address>(*(const witness_address*)base);
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
			hashes.insert(account_reward::as_instance_type());
			hashes.insert(account_derivation::as_instance_type());
			hashes.insert(account_balance::as_instance_type());
			hashes.insert(account_depository::as_instance_type());
			hashes.insert(witness_program::as_instance_type());
			hashes.insert(witness_event::as_instance_type());
			hashes.insert(witness_address::as_instance_type());
			hashes.insert(witness_transaction::as_instance_type());
			return hashes;
		}
	}
}
