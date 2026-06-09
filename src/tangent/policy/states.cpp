#include "states.h"
#include "../kernel/block.h"
#include "../kernel/superchain.h"

namespace tangent
{
	namespace states
	{
		account_nonce::account_nonce(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number) : uniform_state(new_block_number), owner(new_owner), nonce(0)
		{
		}
		account_nonce::account_nonce(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header) : uniform_state(new_block_header), owner(new_owner), nonce(0)
		{
		}
		expects_lr<void> account_nonce::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			auto* prev = (account_nonce*)prev_state;
			if (!prev)
			{
				if (nonce > protocol::now().policy.account_nonce_step_limit && nonce != std::numeric_limits<uint64_t>::max())
					return layer_exception("invalid starting nonce");
			}
			else if (prev->nonce == std::numeric_limits<uint64_t>::max() || nonce == std::numeric_limits<uint64_t>::max())
			{
				if (prev->nonce != nonce)
					return layer_exception("account nonce must stay frozen");
			}
			else if (prev->nonce >= nonce || nonce - prev->nonce > protocol::now().policy.account_nonce_step_limit)
				return layer_exception("invalid nonce (received: " + to_string(nonce) + ", expected: " + to_string(prev->nonce + 1) + "-" + to_string(prev->nonce + protocol::now().policy.account_nonce_step_limit) + ")");

			return expectation::met;
		}
		bool account_nonce::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool account_nonce::load_index(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool account_nonce::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(nonce);
			return true;
		}
		bool account_nonce::load_data(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return true;
		}
		format::tree account_nonce::as_tree() const
		{
			auto data = uniform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("nonce", algorithm::encoding::serialize_uint256(nonce));
			return data;
		}
		uint32_t account_nonce::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_nonce::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t account_nonce::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_nonce::as_instance_typename()
		{
			return "account_nonce";
		}
		string account_nonce::as_instance_index(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			account_nonce(owner, nullptr).store_index(&message);
			return message.data;
		}

		account_program::account_program(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number) : uniform_state(new_block_number), owner(new_owner)
		{
		}
		account_program::account_program(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header) : uniform_state(new_block_header), owner(new_owner)
		{
		}
		expects_lr<void> account_program::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			return expectation::met;
		}
		bool account_program::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool account_program::load_index(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool account_program::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(hashcode);
			return true;
		}
		bool account_program::load_data(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &hashcode))
				return false;

			return true;
		}
		format::tree account_program::as_tree() const
		{
			auto data = uniform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("hashcode", format::variable(format::util::encode_0xhex(hashcode)));
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
		uint32_t account_program::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_program::as_instance_typename()
		{
			return "account_program";
		}
		string account_program::as_instance_index(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			account_program(owner, nullptr).store_index(&message);
			return message.data;
		}

		account_uniform::account_uniform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_index, uint64_t new_block_number) : uniform_state(new_block_number), owner(new_owner), index(new_index)
		{
		}
		account_uniform::account_uniform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_index, const ledger::block_header* new_block_header) : uniform_state(new_block_header), owner(new_owner), index(new_index)
		{
		}
		expects_lr<void> account_uniform::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (index.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state index");

			if (data.size() > BLOB_SIZE * 4)
				return layer_exception("invalid state data");

			return expectation::met;
		}
		bool account_uniform::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			stream->write_string(index);
			return true;
		}
		bool account_uniform::load_index(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &index))
				return false;

			return true;
		}
		bool account_uniform::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(data);
			return true;
		}
		bool account_uniform::load_data(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &data))
				return false;

			return true;
		}
		format::tree account_uniform::as_tree() const
		{
			auto result = uniform_state::as_tree();
			result.set("owner", algorithm::signing::serialize_address(owner));
			result.set("index", format::variable(format::util::encode_0xhex(index)));
			result.set("data", format::variable(format::util::encode_0xhex(data)));
			return result;
		}
		uint32_t account_uniform::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_uniform::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t account_uniform::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_uniform::as_instance_typename()
		{
			return "account_uniform";
		}
		string account_uniform::as_instance_index(const algorithm::pubkeyhash_t& owner, const std::string_view& index)
		{
			format::wo_stream message;
			account_uniform(owner, index, nullptr).store_index(&message);
			return message.data;
		}

		account_multiform::account_multiform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_column, const std::string_view& new_row, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), column(new_column), row(new_row), filter(0)
		{
		}
		account_multiform::account_multiform(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_column, const std::string_view& new_row, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), column(new_column), row(new_row), filter(0)
		{
		}
		expects_lr<void> account_multiform::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (column.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state column");

			if (row.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state row");

			if (data.size() > BLOB_SIZE * 4)
				return layer_exception("invalid state data");

			return expectation::met;
		}
		bool account_multiform::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			stream->write_string(column);
			return true;
		}
		bool account_multiform::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &column))
				return false;

			return true;
		}
		bool account_multiform::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			stream->write_string(row);
			return true;
		}
		bool account_multiform::load_row(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &row))
				return false;

			return true;
		}
		bool account_multiform::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(filter);
			stream->write_string(data);
			return true;
		}
		bool account_multiform::load_data(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &filter))
				return false;

			if (!stream.read_string(stream.read_type(), &data))
				return false;

			return true;
		}
		format::tree account_multiform::as_tree() const
		{
			auto result = multiform_state::as_tree();
			result.set("owner", algorithm::signing::serialize_address(owner));
			result.set("column", format::variable(format::util::encode_0xhex(column)));
			result.set("row", format::variable(format::util::encode_0xhex(row)));
			result.set("data", format::variable(format::util::encode_0xhex(data)));
			return result;
		}
		uint32_t account_multiform::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_multiform::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t account_multiform::as_rank() const
		{
			return filter;
		}
		uint32_t account_multiform::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_multiform::as_instance_typename()
		{
			return "account_multiform";
		}
		string account_multiform::as_instance_column(const algorithm::pubkeyhash_t& owner, const std::string_view& column)
		{
			format::wo_stream message;
			account_multiform(owner, column, std::string_view(), nullptr).store_column(&message);
			return message.data;
		}
		string account_multiform::as_instance_row(const algorithm::pubkeyhash_t& owner, const std::string_view& row)
		{
			format::wo_stream message;
			account_multiform(owner, std::string_view(), row, nullptr).store_row(&message);
			return message.data;
		}

		account_balance::account_balance(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), asset(new_asset)
		{
		}
		account_balance::account_balance(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), asset(new_asset)
		{
		}
		expects_lr<void> account_balance::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			auto* prev = (account_balance*)prev_state;
			if (prev)
			{
				supply += prev->supply;
				reserve += prev->reserve;
			}
			else if (!algorithm::asset::is_any(asset))
				return layer_exception("invalid asset");

			if (supply.is_nan() || supply.is_negative())
				return layer_exception("ran out of supply value");

			if (reserve.is_nan() || reserve.is_negative())
				return layer_exception("ran out of reserve value");

			if (supply < reserve)
				return layer_exception("ran out of balance");

			return expectation::met;
		}
		bool account_balance::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool account_balance::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool account_balance::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool account_balance::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool account_balance::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(supply);
			stream->write_decimal(reserve);
			return true;
		}
		bool account_balance::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &supply))
				return false;

			if (!stream.read_decimal(stream.read_type(), &reserve))
				return false;

			return true;
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
		format::tree account_balance::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("supply", format::variable(supply));
			data.set("reserve", format::variable(reserve));
			data.set("balance", format::variable(get_balance()));
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
		uint256_t account_balance::as_rank() const
		{
			return algorithm::arithmetic::fixed256(get_balance());
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
		string account_balance::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			account_balance(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string account_balance::as_instance_row(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			account_balance(algorithm::pubkeyhash_t(), asset, nullptr).store_row(&message);
			return message.data;
		}

		validator_production::validator_production(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner)
		{
		}
		validator_production::validator_production(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner)
		{
		}
		expects_lr<void> validator_production::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (stake.is_negative())
				return layer_exception("invalid stake");
			else if (!stake.is_nan() && !ledger::block_header::is_genesis_epoch(block_number) && stake < protocol::now().policy.production.min_stake_value)
				return layer_exception(stringify::text("minimum stake requirement not met (%s %s)", protocol::now().policy.production.min_stake_value.to_string().c_str(), protocol::now().policy.token.c_str()));

			return expectation::met;
		}
		bool validator_production::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_production::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_production::store_row(format::wo_stream* stream) const
		{
			return true;
		}
		bool validator_production::load_row(format::ro_stream& stream)
		{
			return true;
		}
		bool validator_production::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(stake);
			return true;
		}
		bool validator_production::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &stake))
				return false;

			return true;
		}
		bool validator_production::is_active() const
		{
			return !stake.is_nan();
		}
		format::tree validator_production::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("stake", format::variable(stake));
			return data;
		}
		uint32_t validator_production::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_production::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_production::as_rank() const
		{
			if (!is_active())
				return 0;

			return to_rank(stake);
		}
		uint32_t validator_production::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_production::as_instance_typename()
		{
			return "validator_production";
		}
		string validator_production::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_production(owner, nullptr).store_column(&message);
			return message.data;
		}
		string validator_production::as_instance_row()
		{
			format::wo_stream message;
			validator_production(algorithm::pubkeyhash_t(), nullptr).store_row(&message);
			return message.data;
		}
		uint256_t validator_production::to_rank(const decimal& threshold)
		{
			return algorithm::arithmetic::fixed256(threshold) + 1;
		}

		validator_production_reward::validator_production_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), asset(new_asset)
		{
		}
		validator_production_reward::validator_production_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), asset(new_asset)
		{
		}
		expects_lr<void> validator_production_reward::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");
			
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");

			if (!reward.is_positive() && !reward.is_zero())
				return layer_exception("invalid reward");

			return expectation::met;
		}
		bool validator_production_reward::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_production_reward::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_production_reward::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_production_reward::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_production_reward::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(reward);
			return true;
		}
		bool validator_production_reward::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &reward))
				return false;

			return true;
		}
		format::tree validator_production_reward::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("reward", format::variable(reward));
			return data;
		}
		uint32_t validator_production_reward::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_production_reward::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_production_reward::as_rank() const
		{
			return algorithm::arithmetic::fixed256(reward);
		}
		uint32_t validator_production_reward::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_production_reward::as_instance_typename()
		{
			return "validator_production_reward";
		}
		string validator_production_reward::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_production_reward(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_production_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			validator_production_reward(algorithm::pubkeyhash_t(), asset, nullptr).store_row(&message);
			return message.data;
		}

		validator_participation::validator_participation(const algorithm::pubkeyhash_t& new_owner, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner)
		{
		}
		validator_participation::validator_participation(const algorithm::pubkeyhash_t& new_owner, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner)
		{
		}
		expects_lr<void> validator_participation::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (stake.is_negative())
				return layer_exception("invalid stake");
			else if (!stake.is_nan() && stake < protocol::now().policy.participation.min_stake_value)
				return layer_exception(stringify::text("minimum stake requirement not met (%s %s)", protocol::now().policy.participation.min_stake_value.to_string().c_str(), protocol::now().policy.token.c_str()));

			auto* prev = (validator_participation*)prev_state;
			if (prev != nullptr && !prev->stake.is_nan() && stake.is_nan())
			{
				auto time_lock = time_lock_blocks(prev_state, protocol::now().policy.participation.locking_time);
				if (time_lock > 0)
					return layer_exception("stake is time locked for the next " + to_string(time_lock) + " blocks");
			}

			return expectation::met;
		}
		bool validator_participation::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_participation::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_participation::store_row(format::wo_stream* stream) const
		{
			return true;
		}
		bool validator_participation::load_row(format::ro_stream& stream)
		{
			return true;
		}
		bool validator_participation::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(stake);
			return true;
		}
		bool validator_participation::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &stake))
				return false;

			return true;
		}
		bool validator_participation::is_active() const
		{
			return !stake.is_nan();
		}
		format::tree validator_participation::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("stake", format::variable(stake));
			return data;
		}
		uint32_t validator_participation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_participation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_participation::as_rank() const
		{
			if (!is_active())
				return 0;

			return validator_production::to_rank(stake);
		}
		uint32_t validator_participation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_participation::as_instance_typename()
		{
			return "validator_participation";
		}
		string validator_participation::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_participation(owner, nullptr).store_column(&message);
			return message.data;
		}
		string validator_participation::as_instance_row()
		{
			format::wo_stream message;
			validator_participation(algorithm::pubkeyhash_t(), nullptr).store_row(&message);
			return message.data;
		}

		validator_participation_reward::validator_participation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), asset(new_asset)
		{
		}
		validator_participation_reward::validator_participation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), asset(new_asset)
		{
		}
		expects_lr<void> validator_participation_reward::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");

			if (!reward.is_positive() && !reward.is_zero())
				return layer_exception("invalid reward");

			return expectation::met;
		}
		bool validator_participation_reward::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_participation_reward::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_participation_reward::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_participation_reward::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_participation_reward::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(reward);
			return true;
		}
		bool validator_participation_reward::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &reward))
				return false;

			return true;
		}
		format::tree validator_participation_reward::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("reward", format::variable(reward));
			return data;
		}
		uint32_t validator_participation_reward::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_participation_reward::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_participation_reward::as_rank() const
		{
			return algorithm::arithmetic::fixed256(reward);
		}
		uint32_t validator_participation_reward::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_participation_reward::as_instance_typename()
		{
			return "validator_participation_reward";
		}
		string validator_participation_reward::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_participation_reward(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_participation_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			validator_participation_reward(algorithm::pubkeyhash_t(), asset, nullptr).store_row(&message);
			return message.data;
		}

		validator_participation_ref::validator_participation_ref(const algorithm::pubkeyhash_t& new_owner, const bridge_ref& new_ref, uint64_t new_block_number) : multiform_state(new_block_number), ref(new_ref), owner(new_owner)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		validator_participation_ref::validator_participation_ref(const algorithm::pubkeyhash_t& new_owner, const bridge_ref& new_ref, const ledger::block_header* new_block_header) : multiform_state(new_block_header), ref(new_ref), owner(new_owner)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		expects_lr<void> validator_participation_ref::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (!algorithm::asset::is_aux(ref.asset, true))
				return layer_exception("invalid participation asset");

			if (!ref.hash)
				return layer_exception("invalid participation ref");

			return expectation::met;
		}
		bool validator_participation_ref::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_participation_ref::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_participation_ref::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.asset);
			stream->write_integer(ref.hash);
			stream->write_string(ref.owner.optimized_view());
			return true;
		}
		bool validator_participation_ref::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &ref.hash))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, ref.owner.blob, sizeof(ref.owner)))
				return false;

			return true;
		}
		bool validator_participation_ref::store_data(format::wo_stream* stream) const
		{
			stream->write_boolean(active);
			return true;
		}
		bool validator_participation_ref::load_data(format::ro_stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &active))
				return false;

			return true;
		}
		format::tree validator_participation_ref::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("active", format::variable(active));
			auto* ref_data = data.set("ref", format::variable());
			ref_data->set("owner", algorithm::signing::serialize_address(ref.owner));
			ref_data->set("asset", algorithm::asset::serialize(ref.asset));
			ref_data->set("hash", algorithm::encoding::serialize_uint256(ref.hash));
			return data;
		}
		uint32_t validator_participation_ref::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_participation_ref::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_participation_ref::as_rank() const
		{
			return 0;
		}
		uint32_t validator_participation_ref::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_participation_ref::as_instance_typename()
		{
			return "validator_participation_ref";
		}
		string validator_participation_ref::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_participation_ref(owner, bridge_ref(), nullptr).store_column(&message);
			return message.data;
		}
		string validator_participation_ref::as_instance_row(const bridge_ref& ref)
		{
			format::wo_stream message;
			validator_participation_ref(algorithm::pubkeyhash_t(), ref, nullptr).store_row(&message);
			return message.data;
		}

		validator_attestation::validator_attestation(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), asset(algorithm::asset::base_id_of(new_asset))
		{
		}
		validator_attestation::validator_attestation(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), asset(algorithm::asset::base_id_of(new_asset))
		{
		}
		expects_lr<void> validator_attestation::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (!algorithm::asset::is_aux(asset, true))
				return layer_exception("invalid asset");

			if (stake.is_negative())
				return layer_exception("invalid stake");
			else if (!stake.is_nan() && stake < protocol::now().policy.attestation.min_stake_value)
				return layer_exception(stringify::text("minimum stake requirement not met (%s %s)", protocol::now().policy.attestation.min_stake_value.to_string().c_str(), protocol::now().policy.token.c_str()));

			if (min_fee.is_nan() || min_fee.is_negative())
				return layer_exception("invalid min fee");

			auto* prev = (validator_attestation*)prev_state;
			if (prev != nullptr && !prev->stake.is_nan() && stake.is_nan())
			{
				auto time_lock = time_lock_blocks(prev_state, protocol::now().policy.attestation.confirmation_time);
				if (time_lock > 0)
					return layer_exception("stake is time locked for the next " + to_string(time_lock) + " blocks");
			}

			return expectation::met;
		}
		bool validator_attestation::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_attestation::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_attestation::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_attestation::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_attestation::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(stake);
			stream->write_decimal(min_fee);
			return true;
		}
		bool validator_attestation::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &stake))
				return false;

			if (!stream.read_decimal(stream.read_type(), &min_fee))
				return false;

			return true;
		}
		bool validator_attestation::is_active() const
		{
			return !stake.is_nan();
		}
		format::tree validator_attestation::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("stake", format::variable(stake));
			data.set("min_fee", format::variable(min_fee));
			return data;
		}
		uint32_t validator_attestation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_attestation::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_attestation::as_rank() const
		{
			if (!is_active())
				return 0;

			return to_rank(min_fee);
		}
		uint32_t validator_attestation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_attestation::as_instance_typename()
		{
			return "validator_attestation";
		}
		string validator_attestation::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_attestation(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_attestation::as_instance_row(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			validator_attestation(algorithm::pubkeyhash_t(), asset, nullptr).store_row(&message);
			return message.data;
		}
		uint256_t validator_attestation::to_rank(const decimal& threshold)
		{
			return std::max<uint256_t>(uint256_t(1), uint256_t::max() - algorithm::arithmetic::fixed256(threshold));
		}

		validator_attestation_reward::validator_attestation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number) : multiform_state(new_block_number), owner(new_owner), asset(new_asset)
		{
		}
		validator_attestation_reward::validator_attestation_reward(const algorithm::pubkeyhash_t& new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : multiform_state(new_block_header), owner(new_owner), asset(new_asset)
		{
		}
		expects_lr<void> validator_attestation_reward::transition(const transition_state* prev_state)
		{
			if (owner.empty())
				return layer_exception("invalid state owner");

			if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");

			if (!reward.is_positive() && !reward.is_zero())
				return layer_exception("invalid reward");

			return expectation::met;
		}
		bool validator_attestation_reward::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool validator_attestation_reward::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.blob, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_attestation_reward::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_attestation_reward::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_attestation_reward::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(reward);
			return true;
		}
		bool validator_attestation_reward::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &reward))
				return false;

			return true;
		}
		format::tree validator_attestation_reward::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(owner));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("reward", format::variable(reward));
			return data;
		}
		uint32_t validator_attestation_reward::as_type() const
		{
			return as_instance_type();
		}
		std::string_view validator_attestation_reward::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t validator_attestation_reward::as_rank() const
		{
			return algorithm::arithmetic::fixed256(reward);
		}
		uint32_t validator_attestation_reward::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view validator_attestation_reward::as_instance_typename()
		{
			return "validator_attestation_reward";
		}
		string validator_attestation_reward::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			format::wo_stream message;
			validator_attestation_reward(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_attestation_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			validator_attestation_reward(algorithm::pubkeyhash_t(), asset, nullptr).store_row(&message);
			return message.data;
		}

		bridge_instance::bridge_instance(const bridge_ref& new_ref, uint64_t new_block_number) : multiform_state(new_block_number), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		bridge_instance::bridge_instance(const bridge_ref& new_ref, const ledger::block_header* new_block_header) : multiform_state(new_block_header), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		expects_lr<void> bridge_instance::transition(const transition_state* prev_state)
		{
			if (!ref.hash)
				return layer_exception("invalid bridge hash");

			if (!algorithm::asset::is_aux(ref.asset, true))
				return layer_exception("invalid asset");

			auto* prev = (bridge_instance*)prev_state;
			if (prev != nullptr)
			{
				if (!prev->ref.owner.empty() && !ref.owner.empty() && prev->ref.owner != ref.owner)
					return layer_exception("invalid master account");

				if (prev->ref.hash != ref.hash)
					return layer_exception("invalid bridge hash");

				if (prev->security_level != security_level)
					return layer_exception("invalid security level");

				if (account_nonce < prev->account_nonce)
					return layer_exception("invalid accounts count");

				if (transaction_nonce < prev->transaction_nonce)
					return layer_exception("invalid transactions count");

				if (prev->transaction_hash > 0 && !transaction_hash)
					return layer_exception("transaction hash must not be reset");

				if (prev->fee_rate != fee_rate)
					return layer_exception("fee rate cannot be changed");
			}
			else
			{
				if (!algorithm::asset::is_aux(ref.asset, true))
					return layer_exception("invalid asset");

				if (security_level % 2 == 0)
					return layer_exception("security level value must be odd");
				else if (security_level > (uint8_t)protocol::now().policy.participation.max_per_account)
					return layer_exception("security level too high");
				else if (security_level < (uint8_t)protocol::now().policy.participation.min_per_account)
					return layer_exception("security level too low");
			}

			if (!fee_rate.is_positive())
				return layer_exception("invalid fee rate");

			return expectation::met;
		}
		bool bridge_instance::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.asset);
			return true;
		}
		bool bridge_instance::load_column(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.asset))
				return false;

			return true;
		}
		bool bridge_instance::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.hash);
			return true;
		}
		bool bridge_instance::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.hash))
				return false;

			return true;
		}
		bool bridge_instance::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(ref.owner.optimized_view());
			stream->write_decimal(fee_rate);
			stream->write_integer(transaction_hash);
			stream->write_integer(transaction_nonce);
			stream->write_integer(account_nonce);
			stream->write_integer(security_level);
			return true;
		}
		bool bridge_instance::load_data(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, ref.owner.blob, sizeof(ref.owner)))
				return false;

			if (!stream.read_decimal(stream.read_type(), &fee_rate))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &transaction_nonce))
				return false;

			if (!stream.read_integer(stream.read_type(), &account_nonce))
				return false;

			if (!stream.read_integer(stream.read_type(), &security_level))
				return false;

			return true;
		}
		bool bridge_instance::is_permanent() const
		{
			return true;
		}
		format::tree bridge_instance::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("master", algorithm::signing::serialize_address(ref.owner));
			data.set("asset", algorithm::asset::serialize(ref.asset));
			data.set("bridge_hash", ref.hash > 0 ? algorithm::encoding::serialize_uint256(ref.hash) : format::variable());
			data.set("transaction_hash", algorithm::encoding::serialize_uint256(transaction_hash));
			data.set("transaction_nonce", format::variable(transaction_nonce));
			data.set("account_nonce", format::variable(account_nonce));
			data.set("security_level", format::variable(security_level));
			data.set("fee_rate", format::variable(fee_rate));
			return data;
		}
		uint32_t bridge_instance::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_instance::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t bridge_instance::as_rank() const
		{
			return security_level;
		}
		uint32_t bridge_instance::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_instance::as_instance_typename()
		{
			return "bridge_instance";
		}
		string bridge_instance::as_instance_column(const algorithm::asset_id& asset)
		{
			bridge_ref ref;
			ref.asset = asset;

			format::wo_stream message;
			bridge_instance(ref, nullptr).store_column(&message);
			return message.data;
		}
		string bridge_instance::as_instance_row(const uint256_t& bridge_hash)
		{
			bridge_ref ref;
			ref.hash = bridge_hash;

			format::wo_stream message;
			bridge_instance(ref, nullptr).store_row(&message);
			return message.data;
		}

		bridge_queue::bridge_queue(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const uint256_t& new_transaction_hash, uint64_t new_block_number) : multiform_state(new_block_number), asset(new_asset), bridge_hash(new_bridge_hash), transaction_hash(new_transaction_hash)
		{
			asset = algorithm::asset::base_id_of(asset);
		}
		bridge_queue::bridge_queue(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const uint256_t& new_transaction_hash, const ledger::block_header* new_block_header) : multiform_state(new_block_header), asset(new_asset), bridge_hash(new_bridge_hash), transaction_hash(new_transaction_hash)
		{
			asset = algorithm::asset::base_id_of(asset);
		}
		expects_lr<void> bridge_queue::transition(const transition_state* prev_state)
		{
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");

			if (!bridge_hash)
				return layer_exception("invalid bridge hash");

			if (!transaction_hash)
				return layer_exception("invalid transaction hash");

			auto* prev = (bridge_queue*)prev_state;
			if (prev)
			{
				if (prev->bridge_hash != bridge_hash)
					return layer_exception("invalid bridge hash");

				if (prev->transaction_hash != transaction_hash)
					return layer_exception("invalid transaction hash");
			}
			else if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");

			return expectation::met;
		}
		bool bridge_queue::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_integer(bridge_hash);
			return true;
		}
		bool bridge_queue::load_column(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &bridge_hash))
				return false;

			return true;
		}
		bool bridge_queue::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(transaction_hash);
			return true;
		}
		bool bridge_queue::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &transaction_hash))
				return false;

			return true;
		}
		bool bridge_queue::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(index);
			return true;
		}
		bool bridge_queue::load_data(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &index))
				return false;

			return true;
		}
		format::tree bridge_queue::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("bridge_hash", bridge_hash > 0 ? algorithm::encoding::serialize_uint256(bridge_hash) : format::variable());
			data.set("transaction_hash", transaction_hash > 0 ? algorithm::encoding::serialize_uint256(transaction_hash) : format::variable());
			data.set("index", format::variable(index));
			return data;
		}
		uint32_t bridge_queue::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_queue::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t bridge_queue::as_rank() const
		{
			return index;
		}
		uint32_t bridge_queue::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_queue::as_instance_typename()
		{
			return "bridge_queue";
		}
		string bridge_queue::as_instance_column(const algorithm::asset_id& asset, const uint256_t& bridge_hash)
		{
			format::wo_stream message;
			bridge_queue(asset, bridge_hash, 0, nullptr).store_column(&message);
			return message.data;
		}
		string bridge_queue::as_instance_row(const uint256_t& transaction_hash)
		{
			format::wo_stream message;
			bridge_queue(0, 0, transaction_hash, nullptr).store_row(&message);
			return message.data;
		}

		bridge_balance::bridge_balance(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, uint64_t new_block_number) : multiform_state(new_block_number), asset(new_asset), bridge_hash(new_bridge_hash)
		{
		}
		bridge_balance::bridge_balance(const algorithm::asset_id& new_asset, const uint256_t& new_bridge_hash, const ledger::block_header* new_block_header) : multiform_state(new_block_header), asset(new_asset), bridge_hash(new_bridge_hash)
		{
		}
		expects_lr<void> bridge_balance::transition(const transition_state* prev_state)
		{
			if (!bridge_hash)
				return layer_exception("invalid bridge hash");

			auto* prev = (bridge_balance*)prev_state;
			if (prev)
			{
				if (prev->bridge_hash != bridge_hash)
					return layer_exception("invalid bridge hash");

				supply += prev->supply;
			}
			else if (!algorithm::asset::is_aux(asset))
				return layer_exception("invalid asset");
			
			if (supply.is_negative())
				return layer_exception("ran out of supply value");

			return expectation::met;
		}
		bool bridge_balance::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool bridge_balance::load_column(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool bridge_balance::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(bridge_hash);
			return true;
		}
		bool bridge_balance::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &bridge_hash))
				return false;

			return true;
		}
		bool bridge_balance::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(supply);
			return true;
		}
		bool bridge_balance::load_data(format::ro_stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &supply))
				return false;

			return true;
		}
		format::tree bridge_balance::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("bridge_hash", bridge_hash > 0 ? algorithm::encoding::serialize_uint256(bridge_hash) : format::variable());
			data.set("supply", format::variable(supply));
			return data;
		}
		uint32_t bridge_balance::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_balance::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t bridge_balance::as_rank() const
		{
			return algorithm::arithmetic::fixed256(supply);
		}
		uint32_t bridge_balance::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_balance::as_instance_typename()
		{
			return "bridge_balance";
		}
		string bridge_balance::as_instance_column(const algorithm::asset_id& asset)
		{
			format::wo_stream message;
			bridge_balance(asset, 0, nullptr).store_column(&message);
			return message.data;
		}
		string bridge_balance::as_instance_row(const uint256_t& bridge_hash)
		{
			format::wo_stream message;
			bridge_balance(0, bridge_hash, nullptr).store_row(&message);
			return message.data;
		}

		bridge_account::bridge_account(const bridge_ref& new_ref, uint64_t new_block_number) : multiform_state(new_block_number), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		bridge_account::bridge_account(const bridge_ref& new_ref, const ledger::block_header* new_block_header) : multiform_state(new_block_header), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		expects_lr<void> bridge_account::transition(const transition_state* prev_state)
		{
			if (ref.owner.empty())
				return layer_exception("invalid state owner");

			if (!ref.hash)
				return layer_exception("invalid bridge hash");

			auto* prev = (bridge_account*)prev_state;
			if (prev != nullptr)
			{
				if (prev->ref.hash != ref.hash)
					return layer_exception("invalid bridge hash");
			}
			else if (!algorithm::asset::is_aux(ref.asset, true))
				return layer_exception("invalid asset");

			if (!group.empty() && public_key.empty())
				return layer_exception("invalid public key");

			for (auto& item : group)
			{
				if (item.empty())
					return layer_exception("invalid group");
			}

			return expectation::met;
		}
		bool bridge_account::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.asset);
			stream->write_string(ref.owner.optimized_view());
			return true;
		}
		bool bridge_account::load_column(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.asset))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, ref.owner.blob, sizeof(ref.owner)))
				return false;

			return true;
		}
		bool bridge_account::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.hash);
			return true;
		}
		bool bridge_account::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.hash))
				return false;

			return true;
		}
		bool bridge_account::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(std::string_view((char*)public_key.data(), public_key.size()));
			stream->write_integer((uint8_t)group.size());
			for (auto& item : group)
				stream->write_string(item.optimized_view());
			return true;
		}
		bool bridge_account::load_data(format::ro_stream& stream)
		{
			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			uint8_t group_size;
			if (!stream.read_integer(stream.read_type(), &group_size))
				return false;

			group.clear();
			for (uint8_t i = 0; i < group_size; i++)
			{
				string group_assembly;
				algorithm::pubkeyhash_t group_hash;
				if (!stream.read_string(stream.read_type(), &group_assembly) || !algorithm::encoding::decode_bytes(group_assembly, group_hash.blob, sizeof(group_hash)))
					return false;

				group.insert(group_hash);
			}

			public_key.resize(public_key_assembly.size());
			memcpy(public_key.data(), public_key_assembly.data(), public_key_assembly.size());
			return true;
		}
		void bridge_account::set_group(const algorithm::composition::cpubkey_t& new_public_key, btree_set<algorithm::pubkeyhash_t>&& new_group)
		{
			group = std::move(new_group);
			public_key = new_public_key;
		}
		format::tree bridge_account::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(ref.owner));
			data.set("asset", algorithm::asset::serialize(ref.asset));
			data.set("bridge_hash", ref.hash > 0 ? algorithm::encoding::serialize_uint256(ref.hash) : format::variable());
			data.set("public_key", public_key.empty() ? format::variable() : format::variable(format::util::encode_0xhex(std::string_view((char*)public_key.data(), public_key.size()))));
			auto* group_data = data.set("group", format::tree::list());
			for (auto& item : group)
				group_data->push(item.empty() ? format::variable() : algorithm::signing::serialize_address(item));
			return data;
		}
		uint32_t bridge_account::as_type() const
		{
			return as_instance_type();
		}
		std::string_view bridge_account::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t bridge_account::as_rank() const
		{
			return 0;
		}
		uint32_t bridge_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view bridge_account::as_instance_typename()
		{
			return "bridge_account";
		}
		string bridge_account::as_instance_column(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& owner)
		{
			bridge_ref ref;
			ref.owner = owner;
			ref.asset = asset;

			format::wo_stream message;
			bridge_account(ref, nullptr).store_column(&message);
			return message.data;
		}
		string bridge_account::as_instance_row(const uint256_t& bridge_hash)
		{
			bridge_ref ref;
			ref.hash = bridge_hash;

			format::wo_stream message;
			bridge_account(ref, nullptr).store_row(&message);
			return message.data;
		}

		witness_program::witness_program(const std::string_view& new_hashcode, uint64_t new_block_number) : uniform_state(new_block_number), hashcode(new_hashcode)
		{
		}
		witness_program::witness_program(const std::string_view& new_hashcode, const ledger::block_header* new_block_header) : uniform_state(new_block_header), hashcode(new_hashcode)
		{
		}
		expects_lr<void> witness_program::transition(const transition_state* prev_state)
		{
			if (prev_state != nullptr)
				return layer_exception("program already exists");

			if (storage.empty())
				return layer_exception("program storage not valid");

			auto code = as_code();
			if (!code)
				return layer_exception("program storage not valid: " + code.error().message());

			if (hashcode != as_instance_unpacked_hashcode(*code))
				return layer_exception("program hashcode not valid");

			return expectation::met;
		}
		bool witness_program::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(hashcode);
			return true;
		}
		bool witness_program::load_index(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &hashcode))
				return false;

			return true;
		}
		bool witness_program::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(storage);
			return true;
		}
		bool witness_program::load_data(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &storage))
				return false;

			return true;
		}
		format::tree witness_program::as_tree() const
		{
			auto data = uniform_state::as_tree();
			data.set("hashcode", format::variable(format::util::encode_0xhex(hashcode)));
			data.set("storage", format::variable(format::util::encode_0xhex(storage)));
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
		expects_lr<string> witness_program::as_code() const
		{
			return algorithm::encoding::unpack_program(storage);
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
			format::wo_stream message;
			witness_program(hashcode, nullptr).store_index(&message);
			return message.data;
		}
		string witness_program::as_instance_packed_hashcode(const std::string_view& storage)
		{
			auto code = algorithm::encoding::unpack_program(storage);
			if (!code)
				return string();

			return as_instance_unpacked_hashcode(*code);
		}
		string witness_program::as_instance_unpacked_hashcode(const std::string_view& storage)
		{
			return algorithm::hashing::ppc512(storage);
		}

		witness_event::witness_event(const uint256_t& new_parent_transaction_hash, uint64_t new_block_number) : uniform_state(new_block_number), parent_transaction_hash(new_parent_transaction_hash)
		{
		}
		witness_event::witness_event(const uint256_t& new_parent_transaction_hash, const ledger::block_header* new_block_header) : uniform_state(new_block_header), parent_transaction_hash(new_parent_transaction_hash)
		{
		}
		expects_lr<void> witness_event::transition(const transition_state* prev_state)
		{
			if (!parent_transaction_hash)
				return layer_exception("invalid parent transaction hash");

			if (!child_transaction_hash)
				return layer_exception("invalid child transaction hash");

			if (prev_state != nullptr)
				return layer_exception("event already finalized");

			return expectation::met;
		}
		bool witness_event::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(parent_transaction_hash);
			return true;
		}
		bool witness_event::load_index(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &parent_transaction_hash))
				return false;

			return true;
		}
		bool witness_event::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(child_transaction_hash);
			return true;
		}
		bool witness_event::load_data(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &child_transaction_hash))
				return false;

			return true;
		}
		format::tree witness_event::as_tree() const
		{
			auto data = uniform_state::as_tree();
			data.set("parent_transaction_hash", format::variable(algorithm::encoding::encode_0xhex256(parent_transaction_hash)));
			data.set("child_transaction_hash", format::variable(algorithm::encoding::encode_0xhex256(child_transaction_hash)));
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
			format::wo_stream message;
			witness_event(transaction_hash, nullptr).store_index(&message);
			return message.data;
		}

		witness_account::witness_account(const bridge_ref& new_ref, const address_map& new_addresses, uint64_t new_block_number) : multiform_state(new_block_number), addresses(new_addresses), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		witness_account::witness_account(const bridge_ref& new_ref, const address_map& new_addresses, const ledger::block_header* new_block_header) : multiform_state(new_block_header), addresses(new_addresses), ref(new_ref)
		{
			ref.asset = algorithm::asset::base_id_of(ref.asset);
		}
		expects_lr<void> witness_account::transition(const transition_state* prev_state)
		{
			if (ref.owner.empty())
				return layer_exception("invalid state owner");

			auto* prev = (witness_account*)prev_state;
			if (!prev && !algorithm::asset::is_aux(ref.asset, true))
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
		bool witness_account::store_column(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(ref.owner.optimized_view());
			return true;
		}
		bool witness_account::load_column(format::ro_stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, ref.owner.blob, sizeof(ref.owner)))
				return false;

			return true;
		}
		bool witness_account::store_row(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			auto location = addresses.empty() ? string() : superchain::bridge::get()->decode_address(ref.asset, addresses.begin()->second).or_else(string(addresses.begin()->second));
			stream->write_integer(ref.asset);
			stream->write_string(location);
			return true;
		}
		bool witness_account::load_row(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.asset))
				return false;

			string location;
			if (!stream.read_string(stream.read_type(), &location))
				return false;

			return true;
		}
		bool witness_account::store_data(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			auto* offchain = superchain::bridge::get();
			stream->write_boolean(active);
			stream->write_integer(ref.hash);
			stream->write_integer((uint8_t)addresses.size());
			for (auto& address : addresses)
			{
				auto raw_address = offchain->decode_address(ref.asset, address.second);
				stream->write_integer(address.first);
				stream->write_string(raw_address ? *raw_address : address.second);
			}
			return true;
		}
		bool witness_account::load_data(format::ro_stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &active))
				return false;

			if (!stream.read_integer(stream.read_type(), &ref.hash))
				return false;

			uint8_t addresses_size;
			if (!stream.read_integer(stream.read_type(), &addresses_size))
				return false;

			addresses.clear();
			auto* offchain = superchain::bridge::get();
			for (uint8_t i = 0; i < addresses_size; i++)
			{
				uint8_t version;
				if (!stream.read_integer(stream.read_type(), &version))
					return false;

				string address;
				if (!stream.read_string(stream.read_type(), &address))
					return false;

				auto encoded_address = offchain->encode_address(ref.asset, address);
				if (encoded_address)
					addresses[version] = std::move(*encoded_address);
				else
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
			return !ref.hash && !ref.owner.empty() && active;
		}
		bool witness_account::is_bridge_account() const
		{
			return ref.hash > 0 && !ref.owner.empty() && active;
		}
		bool witness_account::is_permanent() const
		{
			return true;
		}
		witness_account::account_type witness_account::get_type() const
		{
			account_type type;
			if (is_routing_account())
				type = account_type::routing;
			else if (is_bridge_account())
				type = account_type::bridge;
			else
				type = account_type::witness;
			return type;
		}
		format::tree witness_account::as_tree() const
		{
			auto data = multiform_state::as_tree();
			data.set("owner", algorithm::signing::serialize_address(ref.owner));
			data.set("asset", algorithm::asset::serialize(ref.asset));
			data.set("bridge_hash", ref.hash > 0 ? algorithm::encoding::serialize_uint256(ref.hash) : format::variable());
			auto* addresses_data = data.set("addresses", format::tree::list());
			for (auto& address : addresses)
				addresses_data->push(format::variable(address.second));
			switch (get_type())
			{
				case account_type::routing:
					data.set("purpose", format::variable("routing"));
					break;
				case account_type::bridge:
					data.set("purpose", format::variable("bridge"));
					break;
				default:
					data.set("purpose", format::variable("witness"));
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
		uint256_t witness_account::as_rank() const
		{
			return (uint64_t)get_type();
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
		string witness_account::as_instance_column(const algorithm::pubkeyhash_t& owner)
		{
			bridge_ref ref;
			ref.owner = owner;

			format::wo_stream message;
			witness_account(ref, { }, nullptr).store_column(&message);
			return message.data;
		}
		string witness_account::as_instance_row(const algorithm::asset_id& asset, const std::string_view& address)
		{
			bridge_ref ref;
			ref.asset = asset;

			format::wo_stream message;
			witness_account(ref, { { (uint8_t)0, string(address) } }, nullptr).store_row(&message);
			return message.data;
		}

		witness_transaction::witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, uint64_t new_block_number) : uniform_state(new_block_number), asset(algorithm::asset::base_id_of(new_asset)), transaction_id(new_transaction_id)
		{
		}
		witness_transaction::witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, const ledger::block_header* new_block_header) : uniform_state(new_block_header), asset(algorithm::asset::base_id_of(new_asset)), transaction_id(new_transaction_id)
		{
		}
		expects_lr<void> witness_transaction::transition(const transition_state* prev_state)
		{
			auto* prev = (witness_transaction*)prev_state;
			if (!prev && !algorithm::asset::is_aux(asset, true))
				return layer_exception("invalid asset");

			if (transaction_id.empty())
				return layer_exception("invalid transaction id");

			return expectation::met;
		}
		bool witness_transaction::store_index(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_string(transaction_id);
			return true;
		}
		bool witness_transaction::load_index(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			return true;
		}
		bool witness_transaction::store_data(format::wo_stream* stream) const
		{
			return true;
		}
		bool witness_transaction::load_data(format::ro_stream& stream)
		{
			return true;
		}
		bool witness_transaction::is_permanent() const
		{
			return true;
		}
		format::tree witness_transaction::as_tree() const
		{
			auto data = uniform_state::as_tree();
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("transaction_id", format::variable(transaction_id));
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
			format::wo_stream message;
			witness_transaction(asset, transaction_id, nullptr).store_index(&message);
			return message.data;
		}

		ledger::transition_state* resolver::from_stream(format::ro_stream& stream)
		{
			uint32_t type; size_t seek = stream.seek;
			if (!stream.read_integer(stream.read_type(), &type))
				return nullptr;

			stream.seek = seek;
			return from_type(type);
		}
		ledger::transition_state* resolver::from_type(uint32_t hash)
		{
			if (hash == account_nonce::as_instance_type())
				return memory::init<account_nonce>(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == account_program::as_instance_type())
				return memory::init<account_program>(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == account_uniform::as_instance_type())
				return memory::init<account_uniform>(algorithm::pubkeyhash_t(), std::string_view(), nullptr);
			else if (hash == account_multiform::as_instance_type())
				return memory::init<account_multiform>(algorithm::pubkeyhash_t(), std::string_view(), std::string_view(), nullptr);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_production::as_instance_type())
				return memory::init<validator_production>(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == validator_production_reward::as_instance_type())
				return memory::init<validator_production_reward>(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_participation::as_instance_type())
				return memory::init<validator_participation>(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == validator_participation_reward::as_instance_type())
				return memory::init<validator_participation_reward>(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_participation_ref::as_instance_type())
				return memory::init<validator_participation_ref>(algorithm::pubkeyhash_t(), bridge_ref(), nullptr);
			else if (hash == validator_attestation::as_instance_type())
				return memory::init<validator_attestation>(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_attestation_reward::as_instance_type())
				return memory::init<validator_attestation_reward>(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == bridge_instance::as_instance_type())
				return memory::init<bridge_instance>(bridge_ref(), nullptr);
			else if (hash == bridge_queue::as_instance_type())
				return memory::init<bridge_queue>(0, 0, 0, nullptr);
			else if (hash == bridge_balance::as_instance_type())
				return memory::init<bridge_balance>(0, 0,nullptr);
			else if (hash == bridge_account::as_instance_type())
				return memory::init<bridge_account>(bridge_ref(), nullptr);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(std::string_view(), nullptr);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(0, nullptr);
			else if (hash == witness_account::as_instance_type())
				return memory::init<witness_account>(bridge_ref(), address_map(), nullptr);
			else if (hash == witness_transaction::as_instance_type())
				return memory::init<witness_transaction>(0, std::string_view(), nullptr);
			return nullptr;
		}
		ledger::transition_state* resolver::from_copy(const ledger::transition_state* base)
		{
			VI_ASSERT(base != nullptr, "base should be set");
			uint32_t hash = base->as_type();
			auto* result = from_type(hash);
			if (result)
				value_copy(hash, base, result);
			return result;
		}
		void resolver::value_copy(uint32_t hash, const ledger::transition_state* from, ledger::transition_state* to)
		{
			VI_ASSERT(to != nullptr, "to should be set");
			if (hash == account_nonce::as_instance_type())
				*(account_nonce*)to = from ? account_nonce(*(const account_nonce*)from) : account_nonce(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == account_program::as_instance_type())
				*(account_program*)to = from ? account_program(*(const account_program*)from) : account_program(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == account_uniform::as_instance_type())
				*(account_uniform*)to = from ? account_uniform(*(const account_uniform*)from) : account_uniform(algorithm::pubkeyhash_t(), std::string_view(), nullptr);
			else if (hash == account_multiform::as_instance_type())
				*(account_multiform*)to = from ? account_multiform(*(const account_multiform*)from) : account_multiform(algorithm::pubkeyhash_t(), std::string_view(), std::string_view(), nullptr);
			else if (hash == account_balance::as_instance_type())
				*(account_balance*)to = from ? account_balance(*(const account_balance*)from) : account_balance(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_production::as_instance_type())
				*(validator_production*)to = from ? validator_production(*(const validator_production*)from) : validator_production(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == validator_production_reward::as_instance_type())
				*(validator_production_reward*)to = from ? validator_production_reward(*(const validator_production_reward*)from) : validator_production_reward(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_participation::as_instance_type())
				*(validator_participation*)to = from ? validator_participation(*(const validator_participation*)from) : validator_participation(algorithm::pubkeyhash_t(), nullptr);
			else if (hash == validator_participation_reward::as_instance_type())
				*(validator_participation_reward*)to = from ? validator_participation_reward(*(const validator_participation_reward*)from) : validator_participation_reward(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_participation_ref::as_instance_type())
				*(validator_participation_ref*)to = from ? validator_participation_ref(*(const validator_participation_ref*)from) : validator_participation_ref(algorithm::pubkeyhash_t(), bridge_ref(), nullptr);
			else if (hash == validator_attestation::as_instance_type())
				*(validator_attestation*)to = from ? validator_attestation(*(const validator_attestation*)from) : validator_attestation(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == validator_attestation_reward::as_instance_type())
				*(validator_attestation_reward*)to = from ? validator_attestation_reward(*(const validator_attestation_reward*)from) : validator_attestation_reward(algorithm::pubkeyhash_t(), 0, nullptr);
			else if (hash == bridge_instance::as_instance_type())
				*(bridge_instance*)to = from ? bridge_instance(*(const bridge_instance*)from) : bridge_instance(bridge_ref(), nullptr);
			else if (hash == bridge_queue::as_instance_type())
				*(bridge_queue*)to = from ? bridge_queue(*(const bridge_queue*)from) : bridge_queue(0, 0, 0, nullptr);
			else if (hash == bridge_balance::as_instance_type())
				*(bridge_balance*)to = from ? bridge_balance(*(const bridge_balance*)from) : bridge_balance(0, 0, nullptr);
			else if (hash == bridge_account::as_instance_type())
				*(bridge_account*)to = from ? bridge_account(*(const bridge_account*)from) : bridge_account(bridge_ref(), nullptr);
			else if (hash == witness_program::as_instance_type())
				*(witness_program*)to = from ? witness_program(*(const witness_program*)from) : witness_program(std::string_view(), nullptr);
			else if (hash == witness_event::as_instance_type())
				*(witness_event*)to = from ? witness_event(*(const witness_event*)from) : witness_event(0, nullptr);
			else if (hash == witness_account::as_instance_type())
				*(witness_account*)to = from ? witness_account(*(const witness_account*)from) : witness_account(bridge_ref(), address_map(), nullptr);
			else if (hash == witness_transaction::as_instance_type())
				*(witness_transaction*)to = from ? witness_transaction(*(const witness_transaction*)from) : witness_transaction(0, std::string_view(), nullptr);
		}
		bool resolver::will_delete(const ledger::transition_state* base, uptr<ledger::transition_state>& cache)
		{
			VI_ASSERT(base != nullptr, "base should be set");
			if (base->is_permanent())
				return false;
			
			if (cache)
				value_copy(base->as_type(), nullptr, *cache);
			else
				cache = from_type(base->as_type());

			cache->block_number = base->block_number;
			switch (base->as_level())
			{
				case ledger::state_level::uniform:
				{
					auto maybe_unique = (ledger::uniform_state*)base;
					auto non_unique = (ledger::uniform_state*)*cache;
					if (!non_unique)
						return true;

					format::wo_stream writer;
					if (!maybe_unique->store_index(&writer))
						return true;

					auto reader = writer.ro();
					if (!non_unique->load_index(reader))
						return true;

					return maybe_unique->as_hash() == non_unique->as_hash(true);
				}
				case ledger::state_level::multiform:
				{
					auto maybe_unique = (ledger::multiform_state*)base;
					auto non_unique = (ledger::multiform_state*)*cache;
					if (!non_unique)
						return true;

					format::wo_stream writer;
					if (!maybe_unique->store_column(&writer))
						return true;

					auto reader = writer.ro();
					if (!non_unique->load_column(reader))
						return true;

					writer.clear();
					if (!maybe_unique->store_row(&writer))
						return true;

					reader = writer.ro();
					if (!non_unique->load_row(reader))
						return true;

					return maybe_unique->as_hash() == non_unique->as_hash(true);
				}
				default:
					return true;
			}
		}
		resolver::uniform_type_map& resolver::get_uniform_types()
		{
			static uniform_type_map result =
			{
				account_nonce::as_instance_type(),
				account_program::as_instance_type(),
				account_uniform::as_instance_type(),
				witness_program::as_instance_type(),
				witness_event::as_instance_type(),
				witness_transaction::as_instance_type()
			};
			return result;
		}
		resolver::multiform_type_map& resolver::get_multiform_types()
		{
			static multiform_type_map result =
			{
				account_multiform::as_instance_type(),
				account_balance::as_instance_type(),
				validator_production::as_instance_type(),
				validator_production_reward::as_instance_type(),
				validator_participation::as_instance_type(),
				validator_participation_reward::as_instance_type(),
				validator_participation_ref::as_instance_type(),
				validator_attestation::as_instance_type(),
				validator_attestation_reward::as_instance_type(),
				bridge_instance::as_instance_type(),
				bridge_queue::as_instance_type(),
				bridge_balance::as_instance_type(),
				bridge_account::as_instance_type(),
				witness_account::as_instance_type(),
			};
			return result;
		}
	}
}
