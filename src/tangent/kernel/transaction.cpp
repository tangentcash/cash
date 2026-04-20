#include "transaction.h"
#include "block.h"
#include "../storage/chainstate.h"
#include "../storage/mempoolstate.h"

namespace tangent
{
	namespace ledger
	{
		uniform_serializer::uniform_serializer() : checksum(0)
		{
		}
		bool uniform_serializer::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			return store_payload(stream);
		}
		bool uniform_serializer::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		uint256_t uniform_serializer::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::wo_stream message;
			((uniform_serializer*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::wo_stream uniform_serializer::as_message() const
		{
			format::wo_stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::wo_stream uniform_serializer::as_signable() const
		{
			format::wo_stream message;
			message.write_integer(as_type());
			if (!store_payload(&message))
				message.clear();
			return message;
		}

		authentic_serializer::authentic_serializer() : checksum(0)
		{
		}
		bool authentic_serializer::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_string(signature.optimized_view());
			return store_payload(stream);
		}
		bool authentic_serializer::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			string signature_assembly;
			if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, signature.blob, sizeof(signature)))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool authentic_serializer::sign(const algorithm::seckey_t& secret_key)
		{
			return algorithm::signing::sign(as_signable().hash(), secret_key, signature);
		}
		bool authentic_serializer::verify(const algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::verify(as_signable().hash(), public_key, signature);
		}
		bool authentic_serializer::recover(algorithm::pubkey_t& public_key) const
		{
			return algorithm::signing::recover(as_signable().hash(), public_key, signature);
		}
		bool authentic_serializer::recover_hash(algorithm::pubkeyhash_t& public_key_hash) const
		{
			return algorithm::signing::recover_hash(as_signable().hash(), public_key_hash, signature);
		}
		uint256_t authentic_serializer::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::wo_stream message;
			((authentic_serializer*)this)->checksum = store(&message) ? message.hash() : uint256_t(0);
			return checksum;
		}
		format::wo_stream authentic_serializer::as_message() const
		{
			format::wo_stream message;
			if (!store(&message))
				message.clear();
			return message;
		}
		format::wo_stream authentic_serializer::as_signable() const
		{
			format::wo_stream message;
			message.write_integer(as_type());
			if (!store_payload(&message))
				message.clear();
			return message;
		}

		expects_lr<void> transaction_message::validate(uint64_t block_number) const
		{
			if (!algorithm::asset::is_any(asset))
				return layer_exception("invalid asset");

			if (nonce >= std::numeric_limits<uint64_t>::max() - 1)
				return layer_exception("invalid nonce");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			if (gas_limit > ledger::block_header::get_gas_limit())
				return layer_exception("gas limit requirement not met (max: " + ledger::block_header::get_gas_limit().to_string() + ")");

			if (!is_commitment())
			{
				if (gas_price.is_nan() || gas_price.is_negative())
					return layer_exception("invalid gas price");

				if (gas_price.is_positive() && algorithm::arithmetic::fixed256(gas_price) < 1)
					return layer_exception("invalid gas price");
			}
			else if (!gas_price.is_zero())
				return layer_exception("invalid gas price");

			if (signature.empty())
				return layer_exception("invalid signature");

			return expectation::met;
		}
		expects_lr<void> transaction_message::execute(executor_context* executor) const
		{
			auto nonce_requirement = executor->verify_account_nonce();
			if (!nonce_requirement)
				return nonce_requirement;

			return executor->verify_gas_transfer_balance();
		}
		bool transaction_message::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool transaction_message::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_decimal(stream.read_type(), &gas_price))
				return false;

			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return load_body(stream);
		}
		bool transaction_message::recover_many(const executor_context* executor, const transaction_receipt& receipt, btree_set<algorithm::pubkeyhash_t>& parties) const
		{
			return true;
		}
		bool transaction_message::recover_aliases(btree_set<uint256_t>& aliases) const
		{
			return true;
		}
		bool transaction_message::sign(const algorithm::seckey_t& secret_key)
		{
			return authentic_serializer::sign(secret_key);
		}
		bool transaction_message::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce)
		{
			nonce = new_nonce;
			return sign(secret_key);
		}
		expects_lr<void> transaction_message::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price)
		{
			set_gas(price, ledger::block_header::get_gas_limit());
			if (!sign(secret_key, new_nonce))
				return layer_exception("authentification failed");

			auto optimal_gas = ledger::executor_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();
			
			if (gas_limit == *optimal_gas)
				return expectation::met;

			gas_limit = *optimal_gas;
			if (!sign(secret_key))
				return layer_exception("re-authentification failed");

			return expectation::met;
		}
		expects_lr<void> transaction_message::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::executor_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();
			
			set_gas(price, *optimal_gas);
			return expectation::met;
		}
		void transaction_message::set_gas(const decimal& price, const uint256_t& limit)
		{
			gas_price = price;
			gas_limit = limit;
		}
		void transaction_message::set_asset(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			asset = algorithm::asset::id_of(blockchain, token, contract_address);
		}
		bool transaction_message::is_commitment() const
		{
			return false;
		}
		uint256_t transaction_message::gas_asset() const
		{
			return algorithm::asset::base_id_of(asset);
		}
		format::tree transaction_message::as_tree() const
		{
			format::tree data;
			data.set("hash", format::variable(algorithm::encoding::encode_0xhex256(as_hash())));
			data.set("signature", signature.empty() ? format::variable() : format::variable(format::util::encode_0xhex(signature.view())));
			data.set("type", format::variable(as_typename()));
			data.set("asset", algorithm::asset::serialize(asset));
			data.set("nonce", format::variable(nonce));
			data.set("gas_price", is_commitment() ? format::variable() : format::variable(gas_price));
			data.set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			return data;
		}
		uint32_t transaction_message::as_delegation_type() const
		{
			return 0;
		}

		commitment_message::commitment_message() : transaction_message()
		{
			gas_price = decimal::zero();
		}
		expects_lr<void> commitment_message::execute(executor_context* executor) const
		{
			return executor->verify_account_nonce();
		}
		bool commitment_message::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool commitment_message::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			gas_price = decimal::zero();
			if (!stream.read_integer(stream.read_type(), &gas_limit))
				return false;

			if (!stream.read_integer(stream.read_type(), &nonce))
				return false;

			return load_body(stream);
		}
		bool commitment_message::is_commitment() const
		{
			return true;
		}

		bool transaction_receipt::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(transaction_hash);
			stream->write_integer(absolute_gas_use);
			stream->write_integer(relative_gas_use);
			stream->write_integer(block_time);
			stream->write_integer(block_number);
			stream->write_boolean(successful);
			stream->write_string(from.optimized_view());
			stream->write_integer((uint16_t)events.size());
			for (auto& item : events)
			{
				stream->write_integer(item.first);
				if (!format::variables_util::serialize_merge_into(item.second, stream))
					return false;
			}
			return true;
		}
		bool transaction_receipt::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &transaction_hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &absolute_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &relative_gas_use))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_time))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_boolean(stream.read_type(), &successful))
				return false;

			string from_assembly;
			if (!stream.read_string(stream.read_type(), &from_assembly) || !algorithm::encoding::decode_bytes(from_assembly, from.blob, sizeof(from)))
				return false;

			uint16_t size;
			if (!stream.read_integer(stream.read_type(), &size))
				return false;

			events.clear();
			events.reserve((size_t)size);
			for (uint16_t i = 0; i < size; i++)
			{
				uint32_t type;
				if (!stream.read_integer(stream.read_type(), &type))
					return false;

				format::variables values;
				if (!format::variables_util::deserialize_merge_from(stream, &values))
					return false;

				events.emplace_back(std::make_pair(type, std::move(values)));
			}

			return true;
		}
		void transaction_receipt::emit_event(uint32_t type, format::variables&& values)
		{
			events.emplace_back(std::make_pair(type, std::move(values)));
		}
		const format::variables* transaction_receipt::find_event(uint32_t type, size_t offset) const
		{
			for (auto& item : events)
			{
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		const format::variables* transaction_receipt::reverse_find_event(uint32_t type, size_t offset) const
		{
			for (auto it = events.rbegin(); it != events.rend(); ++it)
			{
				auto& item = *it;
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		option<string> transaction_receipt::get_error_messages() const
		{
			string messages;
			size_t offset = 0;
			while (true)
			{
				auto* event = find_event(0, offset++);
				if (event && !event->empty())
					messages.append(event->front().as_blob()).push_back('\n');
				else if (!event)
					break;
			}

			if (messages.empty())
				return optional::none;

			messages.pop_back();
			return messages;
		}
		format::tree transaction_receipt::as_tree() const
		{
			format::tree data;
			data.set("hash", format::variable(algorithm::encoding::encode_0xhex256(as_hash())));
			data.set("transaction_hash", format::variable(algorithm::encoding::encode_0xhex256(transaction_hash)));
			data.set("from", algorithm::signing::serialize_address(from));
			data.set("absolute_gas_use", algorithm::encoding::serialize_uint256(absolute_gas_use));
			data.set("relative_gas_use", algorithm::encoding::serialize_uint256(relative_gas_use));
			data.set("block_time", algorithm::encoding::serialize_uint256(block_time));
			data.set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data.set("successful", format::variable(successful));
			auto* events_data = data.set("events", format::tree::list());
			for (auto& item : events)
			{
				auto* event_data = events_data->push(format::tree::map());
				event_data->set("event", format::variable(item.first));
				event_data->set("args", format::variables_util::serialize(item.second));
			}
			return data;
		}
		uint32_t transaction_receipt::as_type() const
		{
			return as_instance_type();
		}
		std::string_view transaction_receipt::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t transaction_receipt::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view transaction_receipt::as_instance_typename()
		{
			return "receipt";
		}

		transition_state::transition_state(uint64_t new_block_number) : block_number(new_block_number)
		{
		}
		transition_state::transition_state(const block_header* new_block_header) : block_number(new_block_header ? new_block_header->number : 0)
		{
		}
		bool transition_state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			return store_payload(stream);
		}
		bool transition_state::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool transition_state::store_optimized(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			return store_data(stream);
		}
		bool transition_state::load_optimized(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!load_data(stream))
				return false;

			return true;
		}
		bool transition_state::is_permanent() const
		{
			return false;
		}
		uint64_t transition_state::time_lock_blocks(const transition_state* prev, uint64_t milliseconds) const
		{
			if (!prev)
				return 0;

			auto current = prev->block_number < block_number ? prev->block_number - block_number : 0;
			auto target = milliseconds / protocol::now().policy.pow.time;
			return target < current ? target - current : 0;
		}

		uniform_state::uniform_state(uint64_t new_block_number) : transition_state(new_block_number)
		{
		}
		uniform_state::uniform_state(const block_header* new_block_header) : transition_state(new_block_header)
		{
		}
		bool uniform_state::store_payload(format::wo_stream* stream) const
		{
			if (!store_index(stream))
				return false;

			return store_data(stream);
		}
		bool uniform_state::load_payload(format::ro_stream& stream)
		{
			if (!load_index(stream))
				return false;

			return load_data(stream);
		}
		format::tree uniform_state::as_tree() const
		{
			format::tree data;
			data.set("hash", format::variable(algorithm::encoding::encode_0xhex256(as_hash())));
			data.set("type", format::variable(as_typename()));
			data.set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data.set("index", format::variable(format::util::encode_0xhex(as_index())));
			return data;
		}
		state_level uniform_state::as_level() const
		{
			return state_level::uniform;
		}
		string uniform_state::as_index() const
		{
			format::wo_stream message;
			store_index(&message);
			return message.data;
		}

		multiform_state::multiform_state(uint64_t new_block_number) : transition_state(new_block_number)
		{
		}
		multiform_state::multiform_state(const block_header* new_block_header) : transition_state(new_block_header)
		{
		}
		bool multiform_state::store_payload(format::wo_stream* stream) const
		{
			if (!store_column(stream))
				return false;

			if (!store_row(stream))
				return false;

			return store_data(stream);
		}
		bool multiform_state::load_payload(format::ro_stream& stream)
		{
			if (!load_column(stream))
				return false;

			if (!load_row(stream))
				return false;

			return load_data(stream);
		}
		format::tree multiform_state::as_tree() const
		{
			format::tree data;
			data.set("hash", format::variable(algorithm::encoding::encode_0xhex256(as_hash())));
			data.set("type", format::variable(as_typename()));
			data.set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data.set("column", format::variable(format::util::encode_0xhex(as_column())));
			data.set("row", format::variable(format::util::encode_0xhex(as_row())));
			data.set("rank", algorithm::encoding::serialize_uint256(as_rank()));
			return data;
		}
		state_level multiform_state::as_level() const
		{
			return state_level::multiform;
		}
		string multiform_state::as_column() const
		{
			format::wo_stream message;
			store_column(&message);
			return message.data;
		}
		string multiform_state::as_row() const
		{
			format::wo_stream message;
			store_row(&message);
			return message.data;
		}
		
		bool distribution_key::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(ref.hash);
			stream->write_integer(ref.asset);
			stream->write_string(ref.owner.optimized_view());
			stream->write_string(std::string_view((char*)key.data(), key.size()));
			stream->write_integer((uint8_t)shares.size());
			for (auto& [participant, share] : shares)
			{
				stream->write_string(participant.optimized_view());
				stream->write_string(share.recv.optimized_view());
				stream->write_string(share.sent.optimized_view());
			}
			return true;
		}
		bool distribution_key::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &ref.hash))
				return false;

			if (!stream.read_integer(stream.read_type(), &ref.asset))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, ref.owner.blob, sizeof(ref.owner)))
				return false;

			string key_assembly;
			if (!stream.read_string(stream.read_type(), &key_assembly))
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
				if (!stream.read_string(stream.read_type(), &share_assembly) || !algorithm::encoding::decode_bytes(share_assembly, pair.recv.blob, sizeof(pair.recv)))
					return false;

				if (!stream.read_string(stream.read_type(), &share_assembly) || !algorithm::encoding::decode_bytes(share_assembly, pair.sent.blob, sizeof(pair.sent)))
					return false;
			}

			key.resize(key_assembly.size());
			memcpy(key.data(), key_assembly.data(), key_assembly.size());
			return true;
		}
		format::tree distribution_key::as_tree() const
		{
			format::tree data;
			data.set("owner", algorithm::signing::serialize_address(ref.owner));
			data.set("asset", algorithm::asset::serialize(ref.asset));
			data.set("hash", algorithm::encoding::serialize_uint256(ref.hash));
			data.set("key", format::variable(format::util::encode_0xhex(std::string_view((char*)key.data(), key.size()))));
			auto* shares_data = data.set("shares", format::tree::list());
			for (auto& [participant, share] : shares)
			{
				auto* share_data = shares_data->push(format::tree::map());
				share_data->set("participant", algorithm::signing::serialize_address(participant));
				share_data->set("recv", format::variable(format::util::encode_0xhex(share.recv.optimized_view())));
				share_data->set("sent", format::variable(format::util::encode_0xhex(share.sent.optimized_view())));
			}
			return data;
		}
		uint32_t distribution_key::as_type() const
		{
			return as_instance_type();
		}
		std::string_view distribution_key::as_typename() const
		{
			return as_instance_typename();
		}
		uint256_t distribution_key::as_ref_hash() const
		{
			return ref_hash(ref.owner, ref.asset, ref.hash);
		}
		uint32_t distribution_key::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view distribution_key::as_instance_typename()
		{
			return "distribution_key";
		}
		uint256_t distribution_key::ref_hash(const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash)
		{
			format::wo_stream message;
			message.write_string(owner.view());
			message.write_integer(asset);
			message.write_integer(hash);
			return message.hash();
		}

		bool wallet::set_secret_key(const algorithm::seckey_t& value)
		{
			secret_key = value;
			public_key.clear();
			public_key_hash.clear();
			if (!has_secret_key())
				return false;

			if (!algorithm::signing::derive_public_key(secret_key, public_key))
				return false;

			algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
			return true;
		}
		void wallet::set_public_key(const algorithm::pubkey_t& value)
		{
			secret_key.clear();
			public_key = value;
			public_key_hash.clear();
			if (has_public_key())
				algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
		}
		void wallet::set_public_key_hash(const algorithm::pubkeyhash_t& value)
		{
			secret_key.clear();
			public_key.clear();
			public_key_hash = value;
		}
		bool wallet::verify_secret_key() const
		{
			return has_secret_key() && algorithm::signing::verify_secret_key(secret_key);
		}
		bool wallet::verify_public_key() const
		{
			if (!verify_secret_key())
				return false;

			algorithm::pubkey_t copy;
			algorithm::signing::derive_public_key(secret_key, copy);
			if (public_key != copy)
				return false;

			return has_public_key() && algorithm::signing::verify_public_key(public_key);
		}
		bool wallet::verify_address() const
		{
			if (!verify_public_key())
				return false;

			algorithm::pubkeyhash_t copy;
			algorithm::signing::derive_public_key_hash(public_key, copy);
			if (public_key_hash != copy)
				return false;

			return has_public_key_hash() && algorithm::signing::verify_address(get_address());
		}
		bool wallet::verify(const authentic_serializer& message) const
		{
			return has_public_key() && message.verify(public_key);
		}
		bool wallet::recovers(const authentic_serializer& message) const
		{
			algorithm::pubkeyhash_t recover_public_key_hash;
			return message.recover_hash(recover_public_key_hash) && recover_public_key_hash == public_key_hash;
		}
		bool wallet::sign(authentic_serializer& message) const
		{
			return has_secret_key() && message.sign(secret_key);
		}
		bool wallet::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(secret_key.optimized_view());
			stream->write_string(public_key.optimized_view());
			stream->write_string(public_key_hash.optimized_view());
			return true;
		}
		bool wallet::load_payload(format::ro_stream& stream)
		{
			string secret_key_assembly; secret_key.clear();
			if (!stream.read_string(stream.read_type(), &secret_key_assembly))
				return false;

			if (!secret_key_assembly.empty())
			{
				if (secret_key_assembly.size() != sizeof(secret_key))
					return false;

				memcpy(secret_key.blob, secret_key_assembly.data(), sizeof(secret_key));
			}

			string public_key_assembly; public_key.clear();
			if (!stream.read_string(stream.read_type(), &public_key_assembly))
				return false;

			if (!public_key_assembly.empty())
			{
				if (public_key_assembly.size() != sizeof(public_key))
					return false;

				memcpy(public_key.blob, public_key_assembly.data(), sizeof(public_key));
			}

			string public_key_hash_assembly; public_key_hash.clear();
			if (!stream.read_string(stream.read_type(), &public_key_hash_assembly))
				return false;

			if (!public_key_hash_assembly.empty())
			{
				if (public_key_hash_assembly.size() != sizeof(public_key_hash))
					return false;

				memcpy(public_key_hash.blob, public_key_hash_assembly.data(), sizeof(public_key_hash));
			}

			return true;
		}
		bool wallet::has_secret_key() const
		{
			return !secret_key.empty();
		}
		bool wallet::has_public_key() const
		{
			return !public_key.empty();
		}
		bool wallet::has_public_key_hash() const
		{
			return !public_key_hash.empty();
		}
		option<string> wallet::seal_message(const std::string_view& plaintext, const algorithm::pubkey_t& recipient_public_key, const uint256_t& entropy) const
		{
			return algorithm::signing::public_encrypt(recipient_public_key, plaintext, entropy);
		}
		option<string> wallet::open_message(const std::string_view& ciphertext) const
		{
			if (!has_secret_key())
				return optional::none;

			return algorithm::signing::private_decrypt(secret_key, ciphertext);
		}
		option<string> wallet::open_message(const std::string_view& ciphertext, const uint256_t& entropy) const
		{
			if (!has_secret_key())
				return optional::none;

			algorithm::seckey_t child_secret_key;
			algorithm::signing::derive_secret_key_from_parent(secret_key, entropy, child_secret_key);
			return algorithm::signing::private_decrypt(child_secret_key, ciphertext);
		}
		string wallet::get_secret_key() const
		{
			string value;
			if (!has_secret_key())
				return value;

			algorithm::signing::encode_secret_key(secret_key, value);
			return value;
		}
		string wallet::get_public_key() const
		{
			string value;
			if (!has_public_key())
				return value;

			algorithm::signing::encode_public_key(public_key, value);
			return value;
		}
		string wallet::get_address() const
		{
			string value;
			if (!has_public_key_hash())
				return value;

			algorithm::signing::encode_address(public_key_hash, value);
			return value;
		}
		expects_lr<uint64_t> wallet::get_latest_nonce() const
		{
			auto mempool = storages::mempoolstate();
			auto chain = storages::chainstate();
			auto next = mempool.get_highest_transaction_nonce(public_key_hash);
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(public_key_hash), 0);
			auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
			if (value != nullptr)
			{
				if (next && *next >= value->nonce)
				{
					auto prev = mempool.get_lowest_transaction_nonce(public_key_hash);
					next = !prev || *prev <= value->nonce ? *next + 1 : value->nonce;
				}
				else
					next = value->nonce;
			}
			else if (next)
				*next += 1;

			return next.or_else(0);
		}
		format::tree wallet::as_tree() const
		{
			format::tree data;
			data.set("secret_key", algorithm::signing::serialize_secret_key(secret_key));
			data.set("public_key", algorithm::signing::serialize_public_key(public_key));
			data.set("public_key_hash", format::variable(format::util::encode_0xhex(public_key_hash.optimized_view())));
			data.set("address", algorithm::signing::serialize_address(public_key_hash));
			return data;
		}
		format::tree wallet::as_public_tree() const
		{
			format::tree data;
			data.set("public_key", algorithm::signing::serialize_public_key(public_key));
			data.set("public_key_hash", format::variable(format::util::encode_0xhex(public_key_hash.optimized_view())));
			data.set("address", algorithm::signing::serialize_address(public_key_hash));
			return data;
		}
		uint32_t wallet::as_type() const
		{
			return as_instance_type();
		}
		std::string_view wallet::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t wallet::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view wallet::as_instance_typename()
		{
			return "wallet";
		}
		wallet wallet::from_mnemonic(const std::string_view& mnemonic)
		{
			algorithm::seckey_t key;
			algorithm::signing::derive_secret_key_from_mnemonic(mnemonic, key);
			return from_secret_key(key);
		}
		wallet wallet::from_seed(const std::string_view& seed)
		{
			return from_entropy(algorithm::hashing::hash256i(seed.empty() ? *crypto::random_bytes(64) : seed));
		}
		wallet wallet::from_entropy(const uint256_t& entropy)
		{
			algorithm::seckey_t key;
			algorithm::signing::derive_secret_key(entropy, key);
			return from_secret_key(key);
		}
		wallet wallet::from_secret_key(const algorithm::seckey_t& key)
		{
			wallet result;
			result.set_secret_key(key);
			return result;
		}
		wallet wallet::from_public_key(const algorithm::pubkey_t& key)
		{
			wallet result;
			result.set_public_key(key);
			return result;
		}
		wallet wallet::from_public_key_hash(const algorithm::pubkeyhash_t& key)
		{
			wallet result;
			result.set_public_key_hash(key);
			return result;
		}

		bool node::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint16_t)availability.neighbors.size());
			for (auto& neighbor : availability.neighbors)
				stream->write_string(neighbor.optimized_view());
			stream->write_string(address.get_ip_address().or_else(string()));
			stream->write_integer(address.get_ip_port().or_else(0));
			stream->write_integer(minor_version);
			stream->write_integer(major_version);
			stream->write_integer(availability.latency);
			stream->write_integer(availability.timestamp);
			stream->write_integer(availability.calls);
			stream->write_integer(availability.errors);
			stream->write_boolean(availability.reachable);
			stream->write_integer(ports.consensus);
			stream->write_integer(ports.discovery);
			stream->write_integer(ports.rpc);
			stream->write_boolean(services.has_consensus);
			stream->write_boolean(services.has_discovery);
			stream->write_boolean(services.has_superchain);
			stream->write_boolean(services.has_rpc);
			stream->write_boolean(services.has_production);
			stream->write_boolean(services.has_participation);
			stream->write_boolean(services.has_attestation);
			return true;
		}
		bool node::load_payload(format::ro_stream& stream)
		{
			uint16_t neighbors_size;
			if (!stream.read_integer(stream.read_type(), &neighbors_size))
				return false;

			availability.neighbors.clear();
			for (uint16_t i = 0; i < neighbors_size; i++)
			{
				string public_key_assembly; algorithm::pubkey_t public_key;
				if (!stream.read_string(stream.read_type(), &public_key_assembly) || !algorithm::encoding::decode_bytes(public_key_assembly, public_key.blob, sizeof(public_key)))
					return false;

				availability.neighbors.insert(public_key);
			}

			string ip_address;
			if (!stream.read_string(stream.read_type(), &ip_address))
				return false;

			uint16_t ip_port;
			if (!stream.read_integer(stream.read_type(), &ip_port))
				return false;

			if (!stream.read_integer(stream.read_type(), &minor_version))
				return false;

			if (!stream.read_integer(stream.read_type(), &major_version))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.latency))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.timestamp))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.calls))
				return false;

			if (!stream.read_integer(stream.read_type(), &availability.errors))
				return false;

			if (!stream.read_boolean(stream.read_type(), &availability.reachable))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.consensus))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.discovery))
				return false;

			if (!stream.read_integer(stream.read_type(), &ports.rpc))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_consensus))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_discovery))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_superchain))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_rpc))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_production))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_participation))
				return false;

			if (!stream.read_boolean(stream.read_type(), &services.has_attestation))
				return false;

			address = socket_address(ip_address, ip_port);
			return true;
		}
		bool node::is_valid() const
		{
			return address.is_valid();
		}
		uint64_t node::get_preference() const
		{
			const double min_step = 32.0, max_latency = 500.0;
			double responses = std::max((double)availability.calls, min_step);
			double errors = std::min(std::max((double)availability.errors, 0.0), responses);
			double latency = mathd::exp(-(double)availability.latency / max_latency);
			double reliability = availability.calls > 0 ? 1.0 - errors / responses : 1;
			double index = latency * 0.75 + reliability * 0.25;
			return (uint64_t)(1000000.0 * index);
		}
		format::tree node::as_tree() const
		{
			format::tree data;
			data.set("address", format::variable(address.get_ip_address().or_else("[bad_address]") + ":" + to_string(address.get_ip_port().or_else(0))));
			data.set("version", format::variable(as_version()));

			auto* availability_data = data.set("availability", format::tree::map());
			auto* neighbors_data = availability_data->set("neighbors", format::tree::list());
			for (auto& public_key : availability.neighbors)
				neighbors_data->push(algorithm::signing::serialize_public_key(public_key));
			availability_data->set("latency", algorithm::encoding::serialize_uint256(availability.latency));
			availability_data->set("timestamp", algorithm::encoding::serialize_uint256(availability.timestamp));
			availability_data->set("calls", algorithm::encoding::serialize_uint256(availability.calls));
			availability_data->set("errors", algorithm::encoding::serialize_uint256(availability.errors));
			availability_data->set("reachable", format::variable(availability.reachable));

			auto* ports_data = data.set("ports", format::tree::map());
			ports_data->set("consensus", format::variable(ports.consensus));
			ports_data->set("discovery", format::variable(ports.discovery));
			ports_data->set("rpc", format::variable(ports.rpc));

			auto* services_data = data.set("services", format::tree::map());
			services_data->set("consensus", format::variable(services.has_consensus));
			services_data->set("discovery", format::variable(services.has_discovery));
			services_data->set("superchain", format::variable(services.has_superchain));
			services_data->set("rpc", format::variable(services.has_rpc));
			services_data->set("production", format::variable(services.has_production));
			services_data->set("participation", format::variable(services.has_participation));
			services_data->set("attestation", format::variable(services.has_attestation));
			return data;
		}
		string node::as_version() const
		{
			uint8_t major_version_data[16], minor_version_data[16], data[32];
			size_t major_version_data_size = sizeof(major_version_data);
			size_t minor_version_data_size = sizeof(minor_version_data);
			uint128_t(major_version).encode_compact(major_version_data, &major_version_data_size);
			uint128_t(minor_version).encode_compact(minor_version_data, &minor_version_data_size);
			memcpy(data, major_version_data, major_version_data_size);
			memcpy(data + major_version_data_size, minor_version_data, minor_version_data_size);
			return "0x" + codec::hex_encode(std::string_view((char*)data, major_version_data_size + minor_version_data_size));
		}
		uint32_t node::as_type() const
		{
			return as_instance_type();
		}
		std::string_view node::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t node::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view node::as_instance_typename()
		{
			return "node";
		}
	}
}
