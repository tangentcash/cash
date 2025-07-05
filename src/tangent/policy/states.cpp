#include "states.h"
#include "../kernel/block.h"
#include "../kernel/script.h"
#include "../validator/service/nss.h"

namespace tangent
{
	namespace states
	{
		account_nonce::account_nonce(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), nonce(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_nonce::account_nonce(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), nonce(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_nonce::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_nonce*)prev_state;
			if (!prev || nonce == std::numeric_limits<uint64_t>::max())
				return expectation::met;

			if (prev->nonce >= nonce || nonce - prev->nonce > 1)
				return layer_exception("invalid nonce (received: " + to_string(nonce) + ", expected: " + to_string(prev->nonce + 1) + ")");

			return expectation::met;
		}
		bool account_nonce::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool account_nonce::load_index(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool account_nonce::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(nonce);
			return true;
		}
		bool account_nonce::load_data(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return true;
		}
		bool account_nonce::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_nonce::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("nonce", algorithm::encoding::serialize_uint256(nonce));
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
		string account_nonce::as_instance_index(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			account_nonce(owner, nullptr).store_index(&message);
			return message.data;
		}

		account_permit::account_permit(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_permit::account_permit(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_permit::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			for (auto& permit : permits)
			{
				if (permit.empty())
					return layer_exception("invalid permit");
			}

			return expectation::met;
		}
		bool account_permit::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool account_permit::load_index(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool account_permit::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)permits.size());
			for (auto& permit : permits)
				stream->write_string(permit.optimized_view());
			return true;
		}
		bool account_permit::load_data(format::stream& stream)
		{
			uint16_t permits_size;
			if (!stream.read_integer(stream.read_type(), &permits_size))
				return false;

			permits.clear();
			for (uint16_t i = 0; i < permits_size; i++)
			{
				string permit_assembly;
				algorithm::pubkeyhash_t permit;
				if (!stream.read_string(stream.read_type(), &permit_assembly) || !algorithm::encoding::decode_uint_blob(permit_assembly, permit.data, sizeof(permit.data)))
					return false;

				permits.insert(permit);
			}

			return true;
		}
		bool account_permit::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_permit::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			auto* permits_data = data->set("permits", var::set::array());
			for (auto& permit : permits)
				permits_data->push(algorithm::signing::serialize_address(permit.data));
			return data;
		}
		uint32_t account_permit::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_permit::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t account_permit::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_permit::as_instance_typename()
		{
			return "account_permit";
		}
		string account_permit::as_instance_index(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			account_permit(owner, nullptr).store_index(&message);
			return message.data;
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
		bool account_program::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool account_program::load_index(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool account_program::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(hashcode);
			return true;
		}
		bool account_program::load_data(format::stream& stream)
		{
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
			format::stream message;
			account_program(owner, nullptr).store_index(&message);
			return message.data;
		}

		account_uniform::account_uniform(const algorithm::pubkeyhash new_owner, const std::string_view& new_index, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), index(new_index)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_uniform::account_uniform(const algorithm::pubkeyhash new_owner, const std::string_view& new_index, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), index(new_index)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_uniform::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			if (index.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state index");

			if (data.empty())
				return layer_exception("invalid state data");

			return expectation::met;
		}
		bool account_uniform::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(index);
			return true;
		}
		bool account_uniform::load_index(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &index))
				return false;

			return true;
		}
		bool account_uniform::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(data);
			return true;
		}
		bool account_uniform::load_data(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &data))
				return false;

			return true;
		}
		bool account_uniform::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_uniform::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("index", var::string(format::util::encode_0xhex(index)));
			data->set("data", var::string(format::util::encode_0xhex(this->data)));
			return data;
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
		string account_uniform::as_instance_index(const algorithm::pubkeyhash owner, const std::string_view& index)
		{
			format::stream message;
			account_uniform(owner, index, nullptr).store_index(&message);
			return message.data;
		}

		account_multiform::account_multiform(const algorithm::pubkeyhash new_owner, const std::string_view& new_column, const std::string_view& new_row, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), column(new_column), row(new_row)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_multiform::account_multiform(const algorithm::pubkeyhash new_owner, const std::string_view& new_column, const std::string_view& new_row, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), column(new_column), row(new_row)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_multiform::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			if (column.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state column");

			if (row.size() > std::numeric_limits<uint8_t>::max())
				return layer_exception("invalid state row");

			if (data.empty())
				return layer_exception("invalid state data");

			return expectation::met;
		}
		bool account_multiform::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			stream->write_string(column);
			return true;
		}
		bool account_multiform::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			if (!stream.read_string(stream.read_type(), &column))
				return false;

			return true;
		}
		bool account_multiform::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(row);
			return true;
		}
		bool account_multiform::load_row(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &row))
				return false;

			return true;
		}
		bool account_multiform::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(data);
			return true;
		}
		bool account_multiform::load_data(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &data))
				return false;

			return true;
		}
		bool account_multiform::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> account_multiform::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("column", var::string(format::util::encode_0xhex(column)));
			data->set("row", var::string(format::util::encode_0xhex(row)));
			data->set("data", var::string(format::util::encode_0xhex(this->data)));
			return data;
		}
		uint32_t account_multiform::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_multiform::as_typename() const
		{
			return as_instance_typename();
		}
		int64_t account_multiform::as_factor() const
		{
			return 0;
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
		string account_multiform::as_instance_column(const algorithm::pubkeyhash owner, const std::string_view& column)
		{
			format::stream message;
			account_multiform(owner, column, std::string_view(), nullptr).store_column(&message);
			return message.data;
		}
		string account_multiform::as_instance_row(const std::string_view& row)
		{
			format::stream message;
			account_multiform(nullptr, std::string_view(), row, nullptr).store_row(&message);
			return message.data;
		}

		account_delegation::account_delegation(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), delegations(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_delegation::account_delegation(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), delegations(0)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> account_delegation::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (account_delegation*)prev_state;
			uint64_t prev_block_number = block_number;
			if (prev != nullptr)
			{
				delegations += prev->delegations;
				prev_block_number = prev->block_number;
			}

			if (delegations > protocol::now().policy.delegations_max_per_account)
			{
				uint64_t blocks_required = protocol::now().policy.delegations_zeroing_time / protocol::now().policy.consensus_proof_time;
				uint64_t blocks_passed = block_number - prev_block_number;
				if (blocks_passed < blocks_required)
					return layer_exception("account is over delegated");

				delegations = 0;
			}

			return expectation::met;
		}
		bool account_delegation::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool account_delegation::load_index(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool account_delegation::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(delegations);
			return true;
		}
		bool account_delegation::load_data(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &delegations))
				return false;

			return true;
		}
		bool account_delegation::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uint64_t account_delegation::get_delegation_zeroing_block(uint64_t current_block_number) const
		{
			if (delegations + 1 <= protocol::now().policy.delegations_max_per_account)
				return block_number;

			uint64_t blocks_required = protocol::now().policy.delegations_zeroing_time / protocol::now().policy.consensus_proof_time;
			uint64_t blocks_passed = current_block_number > block_number ? current_block_number - block_number : 0;
			return blocks_passed < blocks_required ? current_block_number + (blocks_required - blocks_passed) : current_block_number;
		}
		uptr<schema> account_delegation::as_schema() const
		{
			schema* data = ledger::uniform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("delegations", algorithm::encoding::serialize_uint256(delegations));
			return data;
		}
		uint32_t account_delegation::as_type() const
		{
			return as_instance_type();
		}
		std::string_view account_delegation::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t account_delegation::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view account_delegation::as_instance_typename()
		{
			return "account_delegation";
		}
		string account_delegation::as_instance_index(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			account_delegation(owner, nullptr).store_index(&message);
			return message.data;
		}

		account_balance::account_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		account_balance::account_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
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
				return layer_exception("ran out of supply value");

			if (reserve.is_nan() || reserve.is_negative())
				return layer_exception("ran out of reserve value");

			if (supply < reserve)
				return layer_exception("ran out of balance");

			return expectation::met;
		}
		bool account_balance::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool account_balance::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool account_balance::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool account_balance::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool account_balance::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(supply);
			stream->write_decimal(reserve);
			return true;
		}
		bool account_balance::load_data(format::stream& stream)
		{
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
			format::stream message;
			account_balance(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string account_balance::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			account_balance(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		validator_production::validator_production(const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		validator_production::validator_production(const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> validator_production::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (validator_production*)prev_state;
			active = active || (!prev && gas > 0);

			for (auto& [asset, stake] : stakes)
			{
				if (!algorithm::asset::is_valid(asset))
					return layer_exception("invalid asset");

				if (stake.is_nan() || stake.is_negative())
					return layer_exception("invalid stake");

				if (prev != nullptr)
				{
					auto prev_stake = prev->stakes.find(asset);
					if (prev_stake != prev->stakes.end() && prev_stake->second > stake)
						return layer_exception("next stake is lower than previous stake");
				}
			}

			return expectation::met;
		}
		bool validator_production::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool validator_production::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_production::store_row(format::stream* stream) const
		{
			return true;
		}
		bool validator_production::load_row(format::stream& stream)
		{
			return true;
		}
		bool validator_production::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_boolean(active);
			stream->write_integer(gas);
			stream->write_integer((uint16_t)stakes.size());
			for (auto& [asset, stake] : stakes)
			{
				stream->write_integer(asset);
				stream->write_decimal(stake);
			}
			return true;
		}
		bool validator_production::load_data(format::stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &active))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas))
				return false;

			uint16_t stakes_size;
			if (!stream.read_integer(stream.read_type(), &stakes_size))
				return false;

			for (uint16_t i = 0; i < stakes_size; i++)
			{
				algorithm::asset_id asset;
				if (!stream.read_integer(stream.read_type(), &asset))
					return false;

				decimal stake;
				if (!stream.read_decimal(stream.read_type(), &stake))
					return false;

				stakes[asset] = std::move(stake);
			}

			return true;
		}
		bool validator_production::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> validator_production::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("gas", algorithm::encoding::serialize_uint256(gas));
			data->set("active", var::boolean(active));
			schema* stakes_data = data->set("stakes", var::set::array());
			for (auto& [asset, stake] : stakes)
			{
				schema* stake_data = stakes_data->push(var::set::object());
				stake_data->set("asset", algorithm::asset::serialize(asset));
				stake_data->set("stake", var::decimal(stake));
			}
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
		int64_t validator_production::as_factor() const
		{
			if (!active)
				return -1;

			auto value = gas / 100;
			return value > std::numeric_limits<int64_t>::max() ? std::numeric_limits<int64_t>::max() : (int64_t)(uint64_t)value;
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
		string validator_production::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			validator_production(owner, nullptr).store_column(&message);
			return message.data;
		}
		string validator_production::as_instance_row()
		{
			format::stream message;
			validator_production(nullptr, nullptr).store_row(&message);
			return message.data;
		}

		validator_participation::validator_participation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		validator_participation::validator_participation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> validator_participation::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (validator_participation*)prev_state;
			if (prev)
				stake += prev->stake;
			else if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (stake.is_negative())
				return layer_exception("ran out of stake value");

			if (stake.is_nan() && participations > 0)
				return layer_exception("regroup is required");

			return expectation::met;
		}
		bool validator_participation::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool validator_participation::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_participation::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_participation::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_participation::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(participations);
			stream->write_decimal(stake);
			return true;
		}
		bool validator_participation::load_data(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &participations))
				return false;

			if (!stream.read_decimal(stream.read_type(), &stake))
				return false;

			return true;
		}
		bool validator_participation::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool validator_participation::is_active() const
		{
			return !stake.is_nan();
		}
		uptr<schema> validator_participation::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("stake", var::decimal(stake));
			data->set("participations", var::integer(participations));
			data->set("active", var::boolean(is_active()));
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
		int64_t validator_participation::as_factor() const
		{
			if (!is_active())
				return -1;

			auto value = stake;
			value *= protocol::now().policy.weight_multiplier;
			return value.to_uint64();
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
		string validator_participation::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			validator_participation(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_participation::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			validator_participation(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		validator_attestation::validator_attestation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		validator_attestation::validator_attestation(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> validator_attestation::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (validator_attestation*)prev_state;
			if (prev)
				stake += prev->stake;
			else if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (stake.is_negative())
				return layer_exception("ran out of stake value");

			return expectation::met;
		}
		bool validator_attestation::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool validator_attestation::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool validator_attestation::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool validator_attestation::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool validator_attestation::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(stake);
			return true;
		}
		bool validator_attestation::load_data(format::stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &stake))
				return false;

			return true;
		}
		bool validator_attestation::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool validator_attestation::is_active() const
		{
			return !stake.is_nan();
		}
		uptr<schema> validator_attestation::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("stake", var::decimal(stake));
			data->set("active", var::boolean(is_active()));
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
		int64_t validator_attestation::as_factor() const
		{
			if (!is_active())
				return -1;

			auto value = stake;
			value *= protocol::now().policy.weight_multiplier;
			return value.to_uint64();
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
		string validator_attestation::as_instance_column(const algorithm::pubkeyhash owner)
		{
			format::stream message;
			validator_attestation(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string validator_attestation::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			validator_attestation(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		depository_reward::depository_reward(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_reward::depository_reward(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_reward::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			if (incoming_fee.is_nan() || incoming_fee.is_negative())
				return layer_exception("invalid incoming fee");

			if (outgoing_fee.is_nan() || outgoing_fee.is_negative())
				return layer_exception("invalid outgoing fee");

			auto* prev = (depository_reward*)prev_state;
			if (!prev)
			{
				if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
					return layer_exception("invalid asset");

				return expectation::met;
			}

			decimal threshold = 1.0 - protocol::now().policy.depository_reward_max_increase;
			if (incoming_fee.is_positive() && prev->incoming_fee / decimal(incoming_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("incoming fee increase overflows step threshold");

			if (outgoing_fee.is_positive() && prev->outgoing_fee / decimal(outgoing_fee).truncate(protocol::now().message.precision) < threshold)
				return layer_exception("outgoing fee increase overflows step threshold");

			return expectation::met;
		}
		bool depository_reward::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool depository_reward::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool depository_reward::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool depository_reward::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool depository_reward::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(incoming_fee);
			stream->write_decimal(outgoing_fee);
			return true;
		}
		bool depository_reward::load_data(format::stream& stream)
		{
			if (!stream.read_decimal(stream.read_type(), &incoming_fee))
				return false;

			if (!stream.read_decimal(stream.read_type(), &outgoing_fee))
				return false;

			return true;
		}
		bool depository_reward::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		uptr<schema> depository_reward::as_schema() const
		{
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("incoming_fee", var::decimal(incoming_fee));
			data->set("outgoing_fee", var::decimal(outgoing_fee));
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
			decimal value = incoming_fee + outgoing_fee;
			value *= protocol::now().policy.weight_multiplier;
			return std::numeric_limits<int64_t>::max() - value.to_int64();
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
			format::stream message;
			depository_reward(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string depository_reward::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			depository_reward(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		depository_balance::depository_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_balance::depository_balance(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
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
		bool depository_balance::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool depository_balance::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool depository_balance::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool depository_balance::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool depository_balance::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_decimal(supply);
			return true;
		}
		bool depository_balance::load_data(format::stream& stream)
		{
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
			format::stream message;
			depository_balance(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string depository_balance::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			depository_balance(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		depository_policy::depository_policy(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_policy::depository_policy(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		expects_lr<void> depository_policy::transition(const ledger::transaction_context* context, const ledger::state* prev_state)
		{
			if (is_owner_null())
				return layer_exception("invalid state owner");

			auto* prev = (depository_policy*)prev_state;
			if (prev != nullptr)
			{
				if (accounts_under_management < prev->accounts_under_management)
					return layer_exception("invalid accounts count");

				if (prev->queue_transaction_hash > 0 && queue_transaction_hash > 0 && prev->queue_transaction_hash != queue_transaction_hash)
					return layer_exception("transaction queue head cannot be replaced with new transaction");
			}
			else if (!algorithm::asset::is_valid(asset) || !algorithm::asset::token_of(asset).empty())
				return layer_exception("invalid asset");

			if (security_level > (uint8_t)protocol::now().policy.participation_max_per_account)
				return layer_exception("security level too high");
			else if (security_level < (uint8_t)protocol::now().policy.participation_min_per_account)
				return layer_exception("security level too low");

			if (accepts_account_requests && !accepts_withdrawal_requests)
				return layer_exception("withdrawal requests must be accepted if account creation requests are accepted");

			return expectation::met;
		}
		bool depository_policy::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool depository_policy::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool depository_policy::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			return true;
		}
		bool depository_policy::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			return true;
		}
		bool depository_policy::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(queue_transaction_hash);
			stream->write_integer(accounts_under_management);
			stream->write_integer(security_level);
			stream->write_boolean(accepts_account_requests);
			stream->write_boolean(accepts_withdrawal_requests);
			return true;
		}
		bool depository_policy::load_data(format::stream& stream)
		{
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
			return std::max<uint64_t>(1, accounts_under_management) * (uint64_t)security_level * (uint64_t)accepts_account_requests * (uint64_t)accepts_withdrawal_requests;
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
			format::stream message;
			depository_policy(owner, 0, nullptr).store_column(&message);
			return message.data;
		}
		string depository_policy::as_instance_row(const algorithm::asset_id& asset)
		{
			format::stream message;
			depository_policy(nullptr, asset, nullptr).store_row(&message);
			return message.data;
		}

		depository_account::depository_account(const algorithm::pubkeyhash new_manager, const algorithm::asset_id& new_asset, const algorithm::pubkeyhash new_owner, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset)
		{
			if (new_manager)
				memcpy(manager, new_manager, sizeof(manager));
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		depository_account::depository_account(const algorithm::pubkeyhash new_manager, const algorithm::asset_id& new_asset, const algorithm::pubkeyhash new_owner, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset)
		{
			if (new_manager)
				memcpy(manager, new_manager, sizeof(manager));
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
			if (!group.empty() && !memcmp(public_key, null, sizeof(null)))
				return layer_exception("invalid public key");

			for (auto& item : group)
			{
				if (item.empty())
					return layer_exception("invalid group");
			}

			return expectation::met;
		}
		bool depository_account::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)manager, memcmp(manager, null, sizeof(null)) == 0 ? 0 : sizeof(manager)));
			return true;
		}
		bool depository_account::load_column(format::stream& stream)
		{
			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_uint_blob(manager_assembly, manager, sizeof(manager)))
				return false;

			return true;
		}
		bool depository_account::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_integer(asset);
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool depository_account::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool depository_account::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::composition::cpubkey null = { 0 };
			stream->write_string(std::string_view((char*)public_key, memcmp(public_key, null, sizeof(null)) == 0 ? 0 : sizeof(public_key)));
			stream->write_integer((uint8_t)group.size());
			for (auto& item : group)
				stream->write_string(item.optimized_view());
			return true;
		}
		bool depository_account::load_data(format::stream& stream)
		{
			string public_key_assembly;
			if (!stream.read_string(stream.read_type(), &public_key_assembly) || !algorithm::encoding::decode_uint_blob(public_key_assembly, public_key, sizeof(public_key)))
				return false;

			uint8_t group_size;
			if (!stream.read_integer(stream.read_type(), &group_size))
				return false;

			group.clear();
			for (uint8_t i = 0; i < group_size; i++)
			{
				string group_assembly;
				algorithm::pubkeyhash group_hash;
				if (!stream.read_string(stream.read_type(), &group_assembly) || !algorithm::encoding::decode_uint_blob(group_assembly, group_hash, sizeof(group_hash)))
					return false;

				group.insert(algorithm::pubkeyhash_t(group_hash));
			}

			return true;
		}
		void depository_account::set_group(const algorithm::composition::cpubkey new_public_key, ordered_set<algorithm::pubkeyhash_t>&& new_group)
		{
			group = std::move(new_group);
			if (!new_public_key)
			{
				algorithm::composition::cpubkey null = { 0 };
				memcpy(public_key, null, sizeof(algorithm::composition::cpubkey));
			}
			else
				memcpy(public_key, new_public_key, sizeof(algorithm::composition::cpubkey));
		}
		bool depository_account::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool depository_account::is_manager_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(manager, null, sizeof(null));
		}
		uptr<schema> depository_account::as_schema() const
		{
			auto* chain = nss::server_node::get()->get_chainparams(asset);
			auto public_key_size = chain ? algorithm::composition::size_of_public_key(chain->composition) : sizeof(public_key);
			schema* data = ledger::multiform::as_schema().reset();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("manager", algorithm::signing::serialize_address(manager));
			data->set("asset", algorithm::asset::serialize(asset));
			algorithm::composition::cpubkey null = { 0 };
			if (!memcmp(public_key, null, sizeof(null)))
				data->set("public_key", var::string(format::util::encode_0xhex(std::string_view((char*)public_key, public_key_size))));
			else
				data->set("public_key", var::null());
			auto* group_data = data->set("group", var::array());
			for (auto& item : group)
				group_data->push(item.empty() ? var::set::null() : algorithm::signing::serialize_address(item.data));
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
		uint32_t depository_account::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view depository_account::as_instance_typename()
		{
			return "depository_account";
		}
		string depository_account::as_instance_column(const algorithm::pubkeyhash manager)
		{
			format::stream message;
			depository_account(manager, 0, nullptr, nullptr).store_column(&message);
			return message.data;
		}
		string depository_account::as_instance_row(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner)
		{
			format::stream message;
			depository_account(nullptr, asset, owner, nullptr).store_row(&message);
			return message.data;
		}

		witness_program::witness_program(const std::string_view& new_hashcode, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), hashcode(new_hashcode)
		{
		}
		witness_program::witness_program(const std::string_view& new_hashcode, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), hashcode(new_hashcode)
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

			if (hashcode != as_instance_unpacked_hashcode(*code))
				return layer_exception("program hashcode not valid");

			return expectation::met;
		}
		bool witness_program::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(hashcode);
			return true;
		}
		bool witness_program::load_index(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &hashcode))
				return false;

			return true;
		}
		bool witness_program::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(storage);
			return true;
		}
		bool witness_program::load_data(format::stream& stream)
		{
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
			format::stream message;
			witness_program(hashcode, nullptr).store_index(&message);
			return message.data;
		}
		string witness_program::as_instance_packed_hashcode(const std::string_view& storage)
		{
			auto code = ledger::script_host::get()->unpack(storage);
			if (!code)
				return string();

			return as_instance_unpacked_hashcode(*code);
		}
		string witness_program::as_instance_unpacked_hashcode(const std::string_view& storage)
		{
			return ledger::script_host::get()->hashcode(storage);
		}

		witness_event::witness_event(const uint256_t& new_parent_transaction_hash, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), parent_transaction_hash(new_parent_transaction_hash)
		{
		}
		witness_event::witness_event(const uint256_t& new_parent_transaction_hash, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), parent_transaction_hash(new_parent_transaction_hash)
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
		bool witness_event::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(parent_transaction_hash);
			return true;
		}
		bool witness_event::load_index(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &parent_transaction_hash))
				return false;

			return true;
		}
		bool witness_event::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(child_transaction_hash);
			return true;
		}
		bool witness_event::load_data(format::stream& stream)
		{
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
			format::stream message;
			witness_event(transaction_hash, nullptr).store_index(&message);
			return message.data;
		}

		witness_account::witness_account(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const address_map& new_addresses, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::multiform(new_block_number, new_block_nonce), asset(new_asset), addresses(new_addresses)
		{
			if (new_owner)
				memcpy(owner, new_owner, sizeof(owner));
		}
		witness_account::witness_account(const algorithm::pubkeyhash new_owner, const algorithm::asset_id& new_asset, const address_map& new_addresses, const ledger::block_header* new_block_header) : ledger::multiform(new_block_header), asset(new_asset), addresses(new_addresses)
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
		bool witness_account::store_column(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_string(std::string_view((char*)owner, memcmp(owner, null, sizeof(null)) == 0 ? 0 : sizeof(owner)));
			return true;
		}
		bool witness_account::load_column(format::stream& stream)
		{
			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_uint_blob(owner_assembly, owner, sizeof(owner)))
				return false;

			return true;
		}
		bool witness_account::store_row(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			auto location = addresses.empty() ? string() : nss::server_node::get()->decode_address(asset, addresses.begin()->second).or_else(string(addresses.begin()->second));
			stream->write_integer(asset);
			stream->write_string(location);
			return true;
		}
		bool witness_account::load_row(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			string location;
			if (!stream.read_string(stream.read_type(), &location))
				return false;

			return true;
		}
		bool witness_account::store_data(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			algorithm::pubkeyhash null = { 0 };
			stream->write_boolean(active);
			stream->write_string(std::string_view((char*)manager, memcmp(manager, null, sizeof(null)) == 0 ? 0 : sizeof(manager)));
			stream->write_integer((uint8_t)addresses.size());
			for (auto& address : addresses)
			{
				stream->write_integer(address.first);
				stream->write_string(address.second);
			}
			return true;
		}
		bool witness_account::load_data(format::stream& stream)
		{
			if (!stream.read_boolean(stream.read_type(), &active))
				return false;

			string manager_assembly;
			if (!stream.read_string(stream.read_type(), &manager_assembly) || !algorithm::encoding::decode_uint_blob(manager_assembly, manager, sizeof(manager)))
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
			return memcmp(manager, null_pkh, sizeof(null_pkh)) == 0 && memcmp(owner, null_pkh, sizeof(null_pkh)) != 0 && active;
		}
		bool witness_account::is_depository_account() const
		{
			algorithm::pubkeyhash null_pkh = { 0 };
			algorithm::composition::cpubkey null_pk = { 0 };
			return memcmp(manager, null_pkh, sizeof(null_pkh)) != 0 && memcmp(owner, null_pkh, sizeof(null_pkh)) != 0 && active;
		}
		bool witness_account::is_owner_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(owner, null, sizeof(null));
		}
		bool witness_account::is_manager_null() const
		{
			algorithm::pubkeyhash null = { 0 };
			return !memcmp(manager, null, sizeof(null));
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
			data->set("manager", algorithm::signing::serialize_address(manager));
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
			format::stream message;
			witness_account(owner, 0, { }, nullptr).store_column(&message);
			return message.data;
		}
		string witness_account::as_instance_row(const algorithm::asset_id& asset, const std::string_view& address)
		{
			format::stream message;
			witness_account(nullptr, asset, { { (uint8_t)0, string(address) } }, nullptr).store_row(&message);
			return message.data;
		}

		witness_transaction::witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, uint64_t new_block_number, uint64_t new_block_nonce) : ledger::uniform(new_block_number, new_block_nonce), asset(new_asset), transaction_id(new_transaction_id)
		{
		}
		witness_transaction::witness_transaction(const algorithm::asset_id& new_asset, const std::string_view& new_transaction_id, const ledger::block_header* new_block_header) : ledger::uniform(new_block_header), asset(new_asset), transaction_id(new_transaction_id)
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
		bool witness_transaction::store_index(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_string(transaction_id);
			return true;
		}
		bool witness_transaction::load_index(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			return true;
		}
		bool witness_transaction::store_data(format::stream* stream) const
		{
			return true;
		}
		bool witness_transaction::load_data(format::stream& stream)
		{
			return true;
		}
		bool witness_transaction::is_permanent() const
		{
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
			format::stream message;
			witness_transaction(asset, transaction_id, nullptr).store_index(&message);
			return message.data;
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
			if (hash == account_nonce::as_instance_type())
				return memory::init<account_nonce>(nullptr, nullptr);
			else if (hash == account_permit::as_instance_type())
				return memory::init<account_permit>(nullptr, nullptr);
			else if (hash == account_program::as_instance_type())
				return memory::init<account_program>(nullptr, nullptr);
			else if (hash == account_uniform::as_instance_type())
				return memory::init<account_uniform>(nullptr, std::string_view(), nullptr);
			else if (hash == account_multiform::as_instance_type())
				return memory::init<account_multiform>(nullptr, std::string_view(), std::string_view(), nullptr);
			else if (hash == account_delegation::as_instance_type())
				return memory::init<account_delegation>(nullptr, nullptr);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(nullptr, 0, nullptr);
			else if (hash == validator_production::as_instance_type())
				return memory::init<validator_production>(nullptr, nullptr);
			else if (hash == validator_participation::as_instance_type())
				return memory::init<validator_participation>(nullptr, 0, nullptr);
			else if (hash == validator_attestation::as_instance_type())
				return memory::init<validator_attestation>(nullptr, 0, nullptr);
			else if (hash == depository_reward::as_instance_type())
				return memory::init<depository_reward>(nullptr, 0, nullptr);
			else if (hash == depository_balance::as_instance_type())
				return memory::init<depository_balance>(nullptr, 0, nullptr);
			else if (hash == depository_policy::as_instance_type())
				return memory::init<depository_policy>(nullptr, 0, nullptr);
			else if (hash == depository_account::as_instance_type())
				return memory::init<depository_account>(nullptr, 0, nullptr, nullptr);
			else if (hash == witness_program::as_instance_type())
				return memory::init<witness_program>(std::string_view(), nullptr);
			else if (hash == witness_event::as_instance_type())
				return memory::init<witness_event>(0, nullptr);
			else if (hash == witness_account::as_instance_type())
				return memory::init<witness_account>(nullptr, 0, address_map(), nullptr);
			else if (hash == witness_transaction::as_instance_type())
				return memory::init<witness_transaction>(0, std::string_view(), nullptr);
			return nullptr;
		}
		ledger::state* resolver::from_copy(const ledger::state* base)
		{
			uint32_t hash = base->as_type();
			if (hash == account_nonce::as_instance_type())
				return memory::init<account_nonce>(*(const account_nonce*)base);
			else if (hash == account_permit::as_instance_type())
				return memory::init<account_permit>(*(const account_permit*)base);
			else if (hash == account_program::as_instance_type())
				return memory::init<account_program>(*(const account_program*)base);
			else if (hash == account_uniform::as_instance_type())
				return memory::init<account_uniform>(*(const account_uniform*)base);
			else if (hash == account_multiform::as_instance_type())
				return memory::init<account_multiform>(*(const account_multiform*)base);
			else if (hash == account_delegation::as_instance_type())
				return memory::init<account_delegation>(*(const account_delegation*)base);
			else if (hash == account_balance::as_instance_type())
				return memory::init<account_balance>(*(const account_balance*)base);
			else if (hash == validator_production::as_instance_type())
				return memory::init<validator_production>(*(const validator_production*)base);
			else if (hash == validator_participation::as_instance_type())
				return memory::init<validator_participation>(*(const validator_participation*)base);
			else if (hash == validator_attestation::as_instance_type())
				return memory::init<validator_attestation>(*(const validator_attestation*)base);
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
		bool resolver::is_non_default(const ledger::state* base, uptr<ledger::state>& default_base)
		{
			if (!base)
				return false;
			else if (base->is_permanent())
				return true;
			else if (!default_base)
				default_base = from_type(base->as_type());

			default_base->block_number = base->block_number;
			default_base->block_nonce = base->block_nonce;
			switch (base->as_level())
			{
				case ledger::state_level::uniform:
				{
					auto maybe_unique = (ledger::uniform*)base;
					auto non_unique = (ledger::uniform*)*default_base;
					if (!non_unique)
						return false;

					format::stream index_message;
					if (!maybe_unique->store_index(&index_message) || !non_unique->load_index(index_message))
						return false;

					bool truly_unique = maybe_unique->as_hash() != non_unique->as_hash(true);
					return truly_unique;
				}
				case ledger::state_level::multiform:
				{
					auto maybe_unique = (ledger::multiform*)base;
					auto non_unique = (ledger::multiform*)*default_base;
					if (!non_unique)
						return false;

					format::stream column_message;
					if (!maybe_unique->store_column(&column_message) || !non_unique->load_column(column_message))
						return false;

					format::stream row_message;
					if (!maybe_unique->store_row(&row_message) || !non_unique->load_row(row_message))
						return false;

					bool truly_unique = maybe_unique->as_hash() != non_unique->as_hash(true);
					return truly_unique;
				}
				default:
					return false;
			}
		}
		unordered_set<uint32_t> resolver::get_uniform_types()
		{
			unordered_set<uint32_t> types;
			types.insert(account_nonce::as_instance_type());
			types.insert(account_permit::as_instance_type());
			types.insert(account_program::as_instance_type());
			types.insert(account_uniform::as_instance_type());
			types.insert(account_delegation::as_instance_type());
			types.insert(witness_program::as_instance_type());
			types.insert(witness_event::as_instance_type());
			types.insert(witness_transaction::as_instance_type());
			return types;
		}
		unordered_set<uint32_t> resolver::get_multiform_types()
		{
			unordered_set<uint32_t> types;
			types.insert(account_multiform::as_instance_type());
			types.insert(account_balance::as_instance_type());
			types.insert(validator_production::as_instance_type());
			types.insert(validator_participation::as_instance_type());
			types.insert(validator_attestation::as_instance_type());
			types.insert(depository_reward::as_instance_type());
			types.insert(depository_balance::as_instance_type());
			types.insert(depository_policy::as_instance_type());
			types.insert(depository_account::as_instance_type());
			types.insert(witness_account::as_instance_type());
			return types;
		}
	}
}
