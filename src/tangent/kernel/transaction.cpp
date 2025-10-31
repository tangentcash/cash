#include "transaction.h"
#include "block.h"

namespace tangent
{
	namespace ledger
	{
		expects_lr<void> transaction::validate(uint64_t block_number) const
		{
			uint64_t expiry_number = algorithm::asset::expiry_of(asset);
			if (!expiry_number)
				return layer_exception("invalid asset");
			else if (block_number > expiry_number)
				return layer_exception("asset is no longer supported");

			if (nonce >= std::numeric_limits<uint64_t>::max() - 1)
				return layer_exception("invalid nonce");

			if (!gas_limit)
				return layer_exception("gas limit requirement not met (min: 1)");

			uint256_t max_gas_limit = is_commitment() ? block::get_commitment_gas_limit() : block::get_transaction_gas_limit();
			if (gas_limit > max_gas_limit)
				return layer_exception("gas limit requirement not met (max: " + max_gas_limit.to_string() + ")");

			if (is_commitment())
			{
				if (!gas_price.is_zero())
					return layer_exception("invalid gas price");
			}
			else if (gas_price.is_nan() || gas_price.is_negative())
				return layer_exception("invalid gas price");

			if (signature.empty())
				return layer_exception("invalid signature");

			return expectation::met;
		}
		expects_lr<void> transaction::execute(transaction_context* context) const
		{
			auto nonce_requirement = context->verify_account_nonce();
			if (!nonce_requirement)
				return nonce_requirement;

			return context->verify_gas_transfer_balance();
		}
		expects_promise_rt<void> transaction::dispatch(const transaction_context* context, dispatch_context* dispatcher) const
		{
			return expects_promise_rt<void>(remote_exception("invalid operation"));
		}
		bool transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_decimal(gas_price);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool transaction::load_payload(format::ro_stream& stream)
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
		bool transaction::recover_many(const transaction_context* context, const receipt& receipt, ordered_set<algorithm::pubkeyhash_t>& parties) const
		{
			return true;
		}
		bool transaction::recover_aliases(const transaction_context* context, const receipt& receipt, ordered_set<uint256_t>& aliases) const
		{
			return true;
		}
		bool transaction::sign(const algorithm::seckey_t& secret_key)
		{
			return authentic::sign(secret_key);
		}
		bool transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce)
		{
			nonce = new_nonce;
			return sign(secret_key);
		}
		expects_lr<void> transaction::sign(const algorithm::seckey_t& secret_key, uint64_t new_nonce, const decimal& price)
		{
			set_gas(price, is_commitment() ? block::get_commitment_gas_limit() : block::get_transaction_gas_limit());
			if (!sign(secret_key, new_nonce))
				return layer_exception("authentification failed");

			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();
			else if (gas_limit == *optimal_gas)
				return expectation::met;

			gas_limit = *optimal_gas;
			if (!sign(secret_key))
				return layer_exception("re-authentification failed");

			return expectation::met;
		}
		expects_lr<void> transaction::set_optimal_gas(const decimal& price)
		{
			auto optimal_gas = ledger::transaction_context::calculate_tx_gas(this);
			if (!optimal_gas)
				return optimal_gas.error();
			
			set_gas(price, *optimal_gas);
			return expectation::met;
		}
		void transaction::set_gas(const decimal& price, const uint256_t& limit)
		{
			gas_price = price;
			gas_limit = limit;
		}
		void transaction::set_asset(const std::string_view& blockchain, const std::string_view& token, const std::string_view& contract_address)
		{
			asset = algorithm::asset::id_of(blockchain, token, contract_address);
		}
		bool transaction::is_commitment() const
		{
			return false;
		}
		bool transaction::is_dispatchable() const
		{
			return false;
		}
		uptr<schema> transaction::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("signature", signature.empty() ? var::null() : var::string(format::util::encode_0xhex(signature.view())));
			data->set("type", var::string(as_typename()));
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("nonce", var::integer(nonce));
			data->set("gas_price", is_commitment() ? var::null() : var::decimal(gas_price));
			data->set("gas_limit", algorithm::encoding::serialize_uint256(gas_limit));
			return data;
		}

		commitment::commitment() : transaction()
		{
			gas_price = decimal::zero();
		}
		expects_lr<void> commitment::execute(transaction_context* context) const
		{
			return context->verify_account_nonce();
		}
		bool commitment::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_integer(gas_limit);
			stream->write_integer(nonce);
			return store_body(stream);
		}
		bool commitment::load_payload(format::ro_stream& stream)
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
		bool commitment::is_commitment() const
		{
			return true;
		}

		bool receipt::store_payload(format::wo_stream* stream) const
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
		bool receipt::load_payload(format::ro_stream& stream)
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
			if (!stream.read_string(stream.read_type(), &from_assembly) || !algorithm::encoding::decode_bytes(from_assembly, from.data, sizeof(from.data)))
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
		void receipt::emit_event(uint32_t type, format::variables&& values)
		{
			events.emplace_back(std::make_pair(type, std::move(values)));
		}
		const format::variables* receipt::find_event(uint32_t type, size_t offset) const
		{
			for (auto& item : events)
			{
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		const format::variables* receipt::reverse_find_event(uint32_t type, size_t offset) const
		{
			for (auto it = events.rbegin(); it != events.rend(); ++it)
			{
				auto& item = *it;
				if (item.first == type && !offset--)
					return &item.second;
			}
			return nullptr;
		}
		option<string> receipt::get_error_messages() const
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
		uptr<schema> receipt::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("transaction_hash", var::string(algorithm::encoding::encode_0xhex256(transaction_hash)));
			data->set("from", algorithm::signing::serialize_address(from));
			data->set("absolute_gas_use", algorithm::encoding::serialize_uint256(absolute_gas_use));
			data->set("relative_gas_use", algorithm::encoding::serialize_uint256(relative_gas_use));
			data->set("block_time", algorithm::encoding::serialize_uint256(block_time));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("successful", var::boolean(successful));
			auto* events_data = data->set("events", var::set::array());
			for (auto& item : events)
			{
				auto* event_data = events_data->push(var::set::object());
				event_data->set("event", var::integer(item.first));
				event_data->set("args", format::variables_util::serialize(item.second));
			}
			return data;
		}
		uint32_t receipt::as_type() const
		{
			return as_instance_type();
		}
		std::string_view receipt::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t receipt::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view receipt::as_instance_typename()
		{
			return "receipt";
		}

		state::state(uint64_t new_block_number, uint64_t new_block_nonce) : block_number(new_block_number), block_nonce(new_block_nonce)
		{
		}
		state::state(const block_header* new_block_header) : block_number(new_block_header ? new_block_header->number : 0), block_nonce(new_block_header ? new_block_header->mutation_count : 0)
		{
		}
		bool state::store(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			stream->write_integer(block_nonce);
			return store_payload(stream);
		}
		bool state::load(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_nonce))
				return false;

			if (!load_payload(stream))
				return false;

			return true;
		}
		bool state::store_optimized(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(as_type());
			stream->write_integer(block_number);
			stream->write_integer(block_nonce);
			return store_data(stream);
		}
		bool state::load_optimized(format::ro_stream& stream)
		{
			uint32_t type;
			if (!stream.read_integer(stream.read_type(), &type) || type != as_type())
				return false;

			if (!stream.read_integer(stream.read_type(), &block_number))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_nonce))
				return false;

			if (!load_data(stream))
				return false;

			return true;
		}
		bool state::is_permanent() const
		{
			return false;
		}

		uniform::uniform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		uniform::uniform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		bool uniform::store_payload(format::wo_stream* stream) const
		{
			if (!store_index(stream))
				return false;

			return store_data(stream);
		}
		bool uniform::load_payload(format::ro_stream& stream)
		{
			if (!load_index(stream))
				return false;

			return load_data(stream);
		}
		uptr<schema> uniform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", block_nonce > 0 ? algorithm::encoding::serialize_uint256(block_nonce) : var::set::null());
			data->set("index", var::string(format::util::encode_0xhex(as_index())));
			return data;
		}
		state_level uniform::as_level() const
		{
			return state_level::uniform;
		}
		string uniform::as_index() const
		{
			format::wo_stream message;
			store_index(&message);
			return message.data;
		}

		multiform::multiform(uint64_t new_block_number, uint64_t new_block_nonce) : state(new_block_number, new_block_nonce)
		{
		}
		multiform::multiform(const block_header* new_block_header) : state(new_block_header)
		{
		}
		bool multiform::store_payload(format::wo_stream* stream) const
		{
			if (!store_column(stream))
				return false;

			if (!store_row(stream))
				return false;

			return store_data(stream);
		}
		bool multiform::load_payload(format::ro_stream& stream)
		{
			if (!load_column(stream))
				return false;

			if (!load_row(stream))
				return false;

			return load_data(stream);
		}
		uptr<schema> multiform::as_schema() const
		{
			schema* data = var::set::object();
			data->set("hash", var::string(algorithm::encoding::encode_0xhex256(as_hash())));
			data->set("type", var::string(as_typename()));
			data->set("block_number", algorithm::encoding::serialize_uint256(block_number));
			data->set("block_nonce", block_nonce > 0 ? algorithm::encoding::serialize_uint256(block_nonce) : var::set::null());
			data->set("column", var::string(format::util::encode_0xhex(as_column())));
			data->set("row", var::string(format::util::encode_0xhex(as_row())));
			data->set("rank", algorithm::encoding::serialize_uint256(as_rank()));
			return data;
		}
		state_level multiform::as_level() const
		{
			return state_level::multiform;
		}
		string multiform::as_column() const
		{
			format::wo_stream message;
			store_column(&message);
			return message.data;
		}
		string multiform::as_row() const
		{
			format::wo_stream message;
			store_row(&message);
			return message.data;
		}
	}
}
