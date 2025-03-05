#include "mediator.h"
#include "../validator/service/nss.h"
#include <sstream>

namespace tangent
{
	namespace mediator
	{
		static bool is_secret_box_empty_or_whitespace(const secret_box& value)
		{
			if (!value.size())
				return true;

			auto data = value.expose<KEY_LIMIT>();
			for (char v : data.view)
			{
				if (v != ' ' && v != '\t' && v != '\r' && v != '\n')
					return false;
			}

			return true;
		}

		token_utxo::token_utxo() : decimals(0)
		{
		}
		token_utxo::token_utxo(const std::string_view& new_contract_address, const decimal& new_value) : contract_address(new_contract_address), value(new_value), decimals(0)
		{
		}
		token_utxo::token_utxo(const std::string_view& new_contract_address, const std::string_view& new_symbol, const decimal& new_value, uint8_t new_decimals) : contract_address(new_contract_address), symbol(new_symbol), value(new_value), decimals(new_decimals)
		{
		}
		decimal token_utxo::get_divisibility()
		{
			decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
			return divisibility.truncate(protocol::now().message.precision);
		}
		bool token_utxo::is_coin_valid() const
		{
			return !contract_address.empty() && !symbol.empty() && !value.is_negative() && !value.is_nan();
		}

		coin_utxo::coin_utxo(const std::string_view& new_transaction_id, const std::string_view& new_address, option<uint64_t>&& new_address_index, decimal&& new_value, uint32_t new_index) : transaction_id(new_transaction_id), address(new_address), value(std::move(new_value)), address_index(new_address_index), index(new_index)
		{
		}
		void coin_utxo::apply_token_value(const std::string_view& contract_address, const std::string_view& symbol, const decimal& new_value, uint8_t decimals)
		{
			if (!contract_address.empty())
			{
				for (auto& item : tokens)
				{
					if (item.contract_address == contract_address)
					{
						if (item.value.is_nan())
							item.value = new_value;
						else
							item.value += new_value;
						return;
					}
				}
				tokens.push_back(token_utxo(contract_address, symbol, new_value, decimals));
			}
			else if (value.is_nan())
				value = new_value;
			else
				value += new_value;
		}
		option<decimal> coin_utxo::get_token_value(const std::string_view& contract_address)
		{
			if (contract_address.empty())
				return value;

			for (auto& item : tokens)
			{
				if (item.contract_address == contract_address)
					return item.value;
			}

			return optional::none;
		}
		bool coin_utxo::is_valid() const
		{
			for (auto& token : tokens)
			{
				if (!token.is_coin_valid())
					return false;
			}

			return !transaction_id.empty() && !value.is_nan() && !value.is_negative() && !stringify::is_empty_or_whitespace(address);
		}

		transferer::transferer() : value(decimal::nan())
		{
		}
		transferer::transferer(const std::string_view& new_address, option<uint64_t>&& new_address_index, decimal&& new_value) : address(new_address), value(std::move(new_value)), address_index(new_address_index)
		{
		}
		bool transferer::is_valid() const
		{
			return !stringify::is_empty_or_whitespace(address) && (value.is_zero() || value.is_positive());
		}

		master_wallet::master_wallet(secret_box&& new_seeding_key, secret_box&& new_signing_key, string&& new_verifying_key) : seeding_key(std::move(new_seeding_key)), signing_key(std::move(new_signing_key)), verifying_key(std::move(new_verifying_key))
		{
		}
		bool master_wallet::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(max_address_index);
			stream->write_string(seeding_key.expose<KEY_LIMIT>().view);
			stream->write_string(signing_key.expose<KEY_LIMIT>().view);
			stream->write_string(verifying_key);
			return true;
		}
		bool master_wallet::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &max_address_index))
				return false;

			string seeding_key_data;
			if (!stream.read_string(stream.read_type(), &seeding_key_data))
				return false;

			string signing_key_data;
			if (!stream.read_string(stream.read_type(), &signing_key_data))
				return false;

			if (!stream.read_string(stream.read_type(), &verifying_key))
				return false;

			seeding_key = secret_box::secure(seeding_key_data);
			signing_key = secret_box::secure(signing_key_data);
			return true;
		}
		bool master_wallet::is_valid() const
		{
			return !is_secret_box_empty_or_whitespace(seeding_key) && !is_secret_box_empty_or_whitespace(signing_key) && !stringify::is_empty_or_whitespace(verifying_key);
		}
		uptr<schema> master_wallet::as_schema() const
		{
			schema* data = var::set::object();
			data->set("seeding_key", var::string(seeding_key.expose<KEY_LIMIT>().view));
			data->set("signing_key", var::string(signing_key.expose<KEY_LIMIT>().view));
			data->set("verifying_key", var::string(verifying_key));
			data->set("max_address_index", algorithm::encoding::serialize_uint256(max_address_index));
			return data;
		}
		uint256_t master_wallet::as_hash(bool renew) const
		{
			if (!renew && checksum != 0)
				return checksum;

			format::stream message;
			message.write_string(*crypto::hash_hex(digests::SHA512(), signing_key.expose<KEY_LIMIT>().view));
			((master_wallet*)this)->checksum = message.hash();
			return checksum;
		}
		uint32_t master_wallet::as_type() const
		{
			return as_instance_type();
		}
		std::string_view master_wallet::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t master_wallet::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view master_wallet::as_instance_typename()
		{
			return "observer_master_wallet";
		}

		derived_verifying_wallet::derived_verifying_wallet(address_map&& new_addresses, option<uint64_t>&& new_address_index, string&& new_verifying_key) : addresses(std::move(new_addresses)), address_index(std::move(new_address_index)), verifying_key(std::move(new_verifying_key))
		{
		}
		bool derived_verifying_wallet::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_boolean(!!address_index);
			if (address_index)
				stream->write_integer(*address_index);
			stream->write_integer((uint8_t)addresses.size());
			for (auto& address : addresses)
			{
				stream->write_integer(address.first);
				stream->write_string(address.second);
			}
			stream->write_string(verifying_key);
			return true;
		}
		bool derived_verifying_wallet::load_payload(format::stream& stream)
		{
			bool has_address_index;
			if (!stream.read_boolean(stream.read_type(), &has_address_index))
				return false;

			address_index = has_address_index ? option<uint64_t>(0) : option<uint64_t>(optional::none);
			if (address_index && !stream.read_integer(stream.read_type(), address_index.address()))
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

			if (!stream.read_string(stream.read_type(), &verifying_key))
				return false;

			return true;
		}
		bool derived_verifying_wallet::is_valid() const
		{
			if (addresses.empty())
				return false;

			if (stringify::is_empty_or_whitespace(verifying_key))
				return false;

			for (auto& address : addresses)
			{
				if (stringify::is_empty_or_whitespace(address.second))
					return false;
			}

			return true;
		}
		uptr<schema> derived_verifying_wallet::as_schema() const
		{
			schema* data = var::set::object();
			auto* addresses_data = data->set("addresses", var::set::array());
			for (auto& address : addresses)
				addresses_data->push(var::string(address.second));
			data->set("address_index", address_index ? algorithm::encoding::serialize_uint256(*address_index) : var::set::null());
			data->set("verifying_key", var::string(verifying_key));
			return data;
		}
		uint32_t derived_verifying_wallet::as_type() const
		{
			return as_instance_type();
		}
		std::string_view derived_verifying_wallet::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t derived_verifying_wallet::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view derived_verifying_wallet::as_instance_typename()
		{
			return "observer_derived_verifying_wallet";
		}

		derived_signing_wallet::derived_signing_wallet(derived_verifying_wallet&& new_wallet, secret_box&& new_signing_key) : derived_verifying_wallet(std::move(new_wallet)), signing_key(std::move(new_signing_key))
		{
		}
		bool derived_signing_wallet::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!derived_verifying_wallet::store_payload(stream))
				return false;

			stream->write_string(signing_key.expose<KEY_LIMIT>().view);
			return true;
		}
		bool derived_signing_wallet::load_payload(format::stream& stream)
		{
			if (!derived_verifying_wallet::load_payload(stream))
				return false;

			string raw_signing_key;
			if (!stream.read_string(stream.read_type(), &raw_signing_key))
				return false;

			signing_key = secret_box::secure(raw_signing_key);
			return true;
		}
		bool derived_signing_wallet::is_valid() const
		{
			return derived_verifying_wallet::is_valid() && !is_secret_box_empty_or_whitespace(signing_key);
		}
		uptr<schema> derived_signing_wallet::as_schema() const
		{
			schema* data = derived_verifying_wallet::as_schema().reset();
			data->set("signing_key", var::string(signing_key.expose<KEY_LIMIT>().view));
			return data;
		}
		uint32_t derived_signing_wallet::as_type() const
		{
			return as_instance_type();
		}
		std::string_view derived_signing_wallet::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t derived_signing_wallet::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view derived_signing_wallet::as_instance_typename()
		{
			return "observer_derived_signing_wallet";
		}

		dynamic_wallet::dynamic_wallet() : parent(optional::none), verifying_child(optional::none), signing_child(optional::none)
		{
		}
		dynamic_wallet::dynamic_wallet(const master_wallet& value) : parent(value), verifying_child(optional::none), signing_child(optional::none)
		{
			if (!parent->is_valid())
				parent = optional::none;
		}
		dynamic_wallet::dynamic_wallet(const derived_verifying_wallet& value) : parent(optional::none), verifying_child(value), signing_child(optional::none)
		{
			if (!verifying_child->is_valid())
				verifying_child = optional::none;
		}
		dynamic_wallet::dynamic_wallet(const derived_signing_wallet& value) : parent(optional::none), verifying_child(optional::none), signing_child(value)
		{
			if (!signing_child->is_valid())
				signing_child = optional::none;
		}
		option<string> dynamic_wallet::get_binding() const
		{
			const string* verifying_key = nullptr;
			if (parent)
				verifying_key = &parent->verifying_key;
			else if (verifying_child)
				verifying_key = &verifying_child->verifying_key;
			else if (signing_child)
				verifying_key = &signing_child->verifying_key;
			if (!verifying_key)
				return optional::none;

			return algorithm::hashing::hash256((uint8_t*)verifying_key->data(), verifying_key->size());
		}
		bool dynamic_wallet::is_valid() const
		{
			return (parent && parent->is_valid()) || (verifying_child && verifying_child->is_valid()) || (signing_child && signing_child->is_valid());
		}

		incoming_transaction::incoming_transaction() : asset(0), block_id(0)
		{
		}
		bool incoming_transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(asset);
			stream->write_integer(block_id);
			stream->write_string(transaction_id);
			stream->write_decimal(fee);
			stream->write_integer((uint32_t)from.size());
			for (auto& item : from)
			{
				stream->write_string(item.address);
				stream->write_boolean(!!item.address_index);
				if (item.address_index)
					stream->write_integer(*item.address_index);
				stream->write_decimal(item.value);
			}
			stream->write_integer((uint32_t)to.size());
			for (auto& item : to)
			{
				stream->write_string(item.address);
				stream->write_boolean(!!item.address_index);
				if (item.address_index)
					stream->write_integer(*item.address_index);
				stream->write_decimal(item.value);
			}
			return true;
		}
		bool incoming_transaction::load_payload(format::stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &asset))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_id))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			if (!stream.read_decimal(stream.read_type(), &fee))
				return false;

			uint32_t from_size;
			if (!stream.read_integer(stream.read_type(), &from_size))
				return false;

			from.reserve(from_size);
			for (size_t i = 0; i < from_size; i++)
			{
				transferer transferer;
				if (!stream.read_string(stream.read_type(), &transferer.address))
					return false;

				bool has_address_index;
				if (!stream.read_boolean(stream.read_type(), &has_address_index))
					return false;

				transferer.address_index = has_address_index ? option<uint64_t>(0) : option<uint64_t>(optional::none);
				if (transferer.address_index && !stream.read_integer(stream.read_type(), transferer.address_index.address()))
					return false;

				if (!stream.read_decimal(stream.read_type(), &transferer.value))
					return false;

				from.emplace_back(std::move(transferer));
			}

			uint32_t to_size;
			if (!stream.read_integer(stream.read_type(), &to_size))
				return false;

			to.reserve(to_size);
			for (size_t i = 0; i < to_size; i++)
			{
				transferer transferer;
				if (!stream.read_string(stream.read_type(), &transferer.address))
					return false;

				bool has_address_index;
				if (!stream.read_boolean(stream.read_type(), &has_address_index))
					return false;

				transferer.address_index = has_address_index ? option<uint64_t>(0) : option<uint64_t>(optional::none);
				if (transferer.address_index && !stream.read_integer(stream.read_type(), transferer.address_index.address()))
					return false;

				if (!stream.read_decimal(stream.read_type(), &transferer.value))
					return false;

				to.emplace_back(std::move(transferer));
			}

			return true;
		}
		bool incoming_transaction::is_valid() const
		{
			if (from.empty() || to.empty())
				return false;

			if (fee.is_negative() || fee.is_nan())
				return false;

			decimal input = 0.0;
			for (auto& address : from)
			{
				if (!address.value.is_positive() && !address.value.is_zero())
					return false;
				input += address.value;
			}

			if (input < fee)
				return false;

			decimal output = 0.0;
			for (auto& address : to)
			{
				if (!address.is_valid())
					return false;
				output += address.value;
			}

			return algorithm::asset::is_valid(asset) && !stringify::is_empty_or_whitespace(transaction_id) && output <= input;
		}
		void incoming_transaction::set_transaction(const algorithm::asset_id& new_asset, uint64_t new_block_id, const std::string_view& new_transaction_id, decimal&& new_fee)
		{
			block_id = new_block_id;
			transaction_id = new_transaction_id;
			asset = new_asset;
			fee = std::move(new_fee);
		}
		void incoming_transaction::set_operations(vector<transferer>&& new_from, vector<transferer>&& new_to)
		{
			from = std::move(new_from);
			to = std::move(new_to);
		}
		decimal incoming_transaction::get_input_value() const
		{
			decimal value = 0.0;
			for (auto& address : to)
				value += address.value;
			return value;
		}
		decimal incoming_transaction::get_output_value() const
		{
			decimal value = 0.0;
			for (auto& address : to)
				value += address.value;
			return value;
		}
		bool incoming_transaction::is_latency_approved() const
		{
			auto* chain = nss::server_node::get()->get_chain(asset);
			if (!chain)
				return false;

			return block_id >= chain->get_chainparams().sync_latency;
		}
		bool incoming_transaction::is_approved() const
		{
			auto* server = nss::server_node::get();
			auto* chain = server->get_chain(asset);
			if (!chain)
				return false;

			auto latest_block_id = server->get_latest_known_block_height(asset).otherwise(0);
			if (latest_block_id < block_id)
				return block_id >= chain->get_chainparams().sync_latency;

			return latest_block_id - block_id >= chain->get_chainparams().sync_latency;
		}
		uptr<schema> incoming_transaction::as_schema() const
		{
			schema* data = var::set::object();
			auto* from_data = data->set("from", var::set::array());
			for (auto& item : from)
			{
				auto* coin_data = from_data->push(var::set::object());
				coin_data->set("address", var::string(item.address));
				coin_data->set("address_index", item.address_index ? algorithm::encoding::serialize_uint256(*item.address_index) : var::set::null());
				coin_data->set("value", var::decimal(item.value));
			}
			auto* to_data = data->set("to", var::set::array());
			for (auto& item : to)
			{
				auto* coin_data = to_data->push(var::set::object());
				coin_data->set("address", var::string(item.address));
				coin_data->set("address_index", item.address_index ? algorithm::encoding::serialize_uint256(*item.address_index) : var::set::null());
				coin_data->set("value", var::decimal(item.value));
			}
			data->set("asset", algorithm::asset::serialize(asset));
			data->set("transaction_id", var::string(transaction_id));
			data->set("block_id", algorithm::encoding::serialize_uint256(block_id));
			data->set("fee", var::decimal(fee));
			return data;
		}
		uint32_t incoming_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view incoming_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t incoming_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view incoming_transaction::as_instance_typename()
		{
			return "observer_incoming_transaction";
		}

		outgoing_transaction::outgoing_transaction() : inputs(optional::none), outputs(optional::none)
		{
		}
		outgoing_transaction::outgoing_transaction(incoming_transaction&& new_transaction, const std::string_view& new_data, option<vector<coin_utxo>>&& new_inputs, option<vector<coin_utxo>>&& new_outputs) : inputs(std::move(new_inputs)), outputs(std::move(new_outputs)), transaction(std::move(new_transaction)), data(new_data)
		{
		}
		bool outgoing_transaction::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!transaction.store_payload(stream))
				return false;

			stream->write_string(data);
			stream->write_integer(inputs ? (uint32_t)inputs->size() : (uint32_t)0);
			if (inputs)
			{
				for (auto& item : *inputs)
				{
					index_utxo next;
					next.UTXO = item;
					if (!next.store_payload(stream))
						return false;
				}
			}

			stream->write_integer(outputs ? (uint32_t)outputs->size() : (uint32_t)0);
			if (outputs)
			{
				for (auto& item : *outputs)
				{
					index_utxo next;
					next.UTXO = item;
					if (!next.store_payload(stream))
						return false;
				}
			}
			return true;
		}
		bool outgoing_transaction::load_payload(format::stream& stream)
		{
			if (!transaction.load_payload(stream))
				return false;

			if (!stream.read_string(stream.read_type(), &data))
				return false;

			uint32_t inputs_size;
			if (!stream.read_integer(stream.read_type(), &inputs_size))
				return false;

			if (inputs_size > 0)
			{
				inputs = vector<coin_utxo>();
				inputs->reserve(inputs_size);
				for (size_t i = 0; i < inputs_size; i++)
				{
					index_utxo next;
					if (!next.load_payload(stream))
						return false;

					inputs->emplace_back(std::move(next.UTXO));
				}
			}

			uint32_t outputs_size;
			if (!stream.read_integer(stream.read_type(), &outputs_size))
				return false;

			if (outputs_size > 0)
			{
				outputs = vector<coin_utxo>();
				outputs->reserve(outputs_size);
				for (size_t i = 0; i < outputs_size; i++)
				{
					index_utxo next;
					if (!next.load_payload(stream))
						return false;

					outputs->emplace_back(std::move(next.UTXO));
				}
			}

			return true;
		}
		bool outgoing_transaction::is_valid() const
		{
			if (inputs)
			{
				for (auto& item : *inputs)
				{
					if (!item.is_valid())
						return false;
				}
			}

			if (outputs)
			{
				for (auto& item : *outputs)
				{
					if (!item.is_valid())
						return false;
				}
			}
			return transaction.is_valid() && !data.empty();
		}
		uptr<schema> outgoing_transaction::as_schema() const
		{
			schema* data = var::set::object();
			data->set("transaction_info", transaction.as_schema().reset());
			data->set("transaction_data", var::string(this->data));
			return data;
		}
		uint32_t outgoing_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view outgoing_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t outgoing_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view outgoing_transaction::as_instance_typename()
		{
			return "observer_outgoing_transaction";
		}

		bool index_address::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(binding);
			stream->write_string(address);
			stream->write_boolean(!!address_index);
			if (address_index)
				stream->write_integer(*address_index);
			return true;
		}
		bool index_address::load_payload(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &binding))
				return false;

			if (!stream.read_string(stream.read_type(), &address))
				return false;

			bool has_address_index;
			if (!stream.read_boolean(stream.read_type(), &has_address_index))
				return false;

			address_index = has_address_index ? option<uint64_t>(0) : option<uint64_t>(optional::none);
			if (address_index && !stream.read_integer(stream.read_type(), address_index.address()))
				return false;

			return true;
		}
		uptr<schema> index_address::as_schema() const
		{
			schema* data = var::set::object();
			data->set("address", var::string(address));
			data->set("address_index", address_index ? algorithm::encoding::serialize_uint256(*address_index) : var::set::null());
			data->set("binding", var::string(binding));
			return data;
		}
		uint32_t index_address::as_type() const
		{
			return as_instance_type();
		}
		std::string_view index_address::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t index_address::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view index_address::as_instance_typename()
		{
			return "observer_index_address";
		}

		bool index_utxo::store_payload(format::stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(UTXO.address);
			stream->write_boolean(!!UTXO.address_index);
			if (UTXO.address_index)
				stream->write_integer(*UTXO.address_index);
			stream->write_string(UTXO.transaction_id);
			stream->write_integer(UTXO.index);
			stream->write_decimal(UTXO.value);
			stream->write_integer((uint32_t)UTXO.tokens.size());
			for (auto& item : UTXO.tokens)
			{
				stream->write_string(item.contract_address);
				stream->write_string(item.symbol);
				stream->write_decimal(item.value);
				stream->write_integer(item.decimals);
			}
			return true;
		}
		bool index_utxo::load_payload(format::stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &UTXO.address))
				return false;

			bool has_address_index;
			if (!stream.read_boolean(stream.read_type(), &has_address_index))
				return false;

			UTXO.address_index = has_address_index ? option<uint64_t>(0) : option<uint64_t>(optional::none);
			if (UTXO.address_index && !stream.read_integer(stream.read_type(), UTXO.address_index.address()))
				return false;

			if (!stream.read_string(stream.read_type(), &UTXO.transaction_id))
				return false;

			if (!stream.read_integer(stream.read_type(), &UTXO.index))
				return false;

			if (!stream.read_decimal(stream.read_type(), &UTXO.value))
				return false;

			uint32_t size;
			if (!stream.read_integer(stream.read_type(), &size))
				return false;

			UTXO.tokens.reserve(size);
			for (uint32_t i = 0; i < size; i++)
			{
				token_utxo token;
				if (!stream.read_string(stream.read_type(), &token.contract_address))
					return false;

				if (!stream.read_string(stream.read_type(), &token.symbol))
					return false;

				if (!stream.read_decimal(stream.read_type(), &token.value))
					return false;

				if (!stream.read_integer(stream.read_type(), &token.decimals))
					return false;

				UTXO.tokens.emplace_back(std::move(token));
			}

			return true;
		}
		uptr<schema> index_utxo::as_schema() const
		{
			schema* data = var::set::object();
			auto* utxo_data = data->set("utxo", var::set::object());
			auto* tokens_data = utxo_data->set("tokens", var::set::array());
			for (auto& item : UTXO.tokens)
			{
				auto* token_data = tokens_data->push(var::set::object());
				token_data->set("contract_address", var::string(item.contract_address));
				token_data->set("symbol", var::string(item.symbol));
				token_data->set("value", var::decimal(item.value));
				token_data->set("Decimals", var::integer(item.decimals));
			}
			data->set("transaction_id", var::string(UTXO.transaction_id));
			data->set("address", var::string(UTXO.address));
			data->set("address_index", UTXO.address_index ? algorithm::encoding::serialize_uint256(*UTXO.address_index) : var::set::null());
			data->set("value", var::decimal(UTXO.value));
			data->set("index", var::integer(UTXO.index));
			data->set("binding", var::string(binding));
			return data;
		}
		uint32_t index_utxo::as_type() const
		{
			return as_instance_type();
		}
		std::string_view index_utxo::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t index_utxo::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view index_utxo::as_instance_typename()
		{
			return "observer_index_utxo";
		}

		base_fee::base_fee() : price(decimal::nan()), limit(decimal::nan())
		{
		}
		base_fee::base_fee(const decimal& new_price, const decimal& new_limit) : price(new_price), limit(new_limit)
		{
		}
		decimal base_fee::get_fee() const
		{
			return price * limit;
		}
		bool base_fee::is_valid() const
		{
			return price.is_positive() && !limit.is_nan() && limit >= 0.0;
		}

		void chain_supervisor_options::set_checkpoint_from_block(uint64_t block_height)
		{
			if (!state.starting_block_height)
				state.starting_block_height = block_height;
			state.latest_block_height = block_height;
		}
		void chain_supervisor_options::set_checkpoint_to_block(uint64_t block_height)
		{
			if (!state.current_block_height && !state.latest_block_height && !state.starting_block_height)
				set_checkpoint_from_block(block_height > 1 ? block_height - 1 : block_height);
			state.current_block_height = block_height;
		}
		uint64_t chain_supervisor_options::get_next_block_height()
		{
			return ++state.latest_block_height;
		}
		uint64_t chain_supervisor_options::get_time_awaited() const
		{
			return state.latest_time_awaited;
		}
		bool chain_supervisor_options::has_next_block_height() const
		{
			return state.current_block_height > state.latest_block_height + min_block_confirmations;
		}
		bool chain_supervisor_options::has_current_block_height() const
		{
			return state.current_block_height > 0;
		}
		bool chain_supervisor_options::has_latest_block_height() const
		{
			return state.latest_block_height > 0;
		}
		bool chain_supervisor_options::will_wait_for_transactions() const
		{
			return has_latest_block_height() && !has_next_block_height();
		}
		double chain_supervisor_options::get_checkpoint_percentage() const
		{
			if (!has_latest_block_height() || !has_current_block_height())
				return 0.0;

			double multiplier = 100.0;
			double current_value = (double)(state.latest_block_height - state.starting_block_height);
			double target_value = (double)(state.current_block_height - state.starting_block_height);
			double percentage = multiplier * current_value / target_value;
			return std::floor(percentage * multiplier) / multiplier;
		}
		const unordered_set<server_relay*>& chain_supervisor_options::get_interacted_nodes() const
		{
			return state.interactions;
		}
		bool chain_supervisor_options::is_cancelled(const algorithm::asset_id& asset)
		{
			auto* nodes = nss::server_node::get()->get_nodes(asset);
			if (!nodes || nodes->empty())
				return true;

			for (auto& node : *nodes)
			{
				if (!node->is_activity_allowed())
					return true;
			}

			return false;
		}

		chain_supervisor_options& multichain_supervisor_options::add_specific_options(const std::string_view& blockchain)
		{
			auto& options = specifics[string(blockchain)];
			auto* settings = (supervisor_options*)&options;
			*settings = *(supervisor_options*)this;
			return options;
		}

		server_relay::server_relay(const std::string_view& node_url, double node_throttling) noexcept : throttling(node_throttling), latest(0), allowed(true), user_data(nullptr)
		{
			for (auto& path : stringify::split(node_url, ';'))
			{
				if (stringify::starts_with(path, "jsonrpc="))
				{
					paths.json_rpc_path = path.substr(8);
					paths.json_rpc_distinct = true;
				}
				else if (stringify::starts_with(path, "rest="))
				{
					paths.rest_path = path.substr(5);
					paths.rest_distinct = true;
				}
				else if (stringify::starts_with(path, "http="))
				{
					paths.http_path = path.substr(5);
					paths.http_distinct = true;
				}
			}
			if (paths.http_path.empty())
			{
				size_t index = node_url.find('=');
				if (index != std::string::npos)
				{
					paths.http_path = node_url.substr(index + 1);
					paths.http_distinct = true;
				}
				else
				{
					paths.http_path = node_url;
					paths.http_distinct = false;
				}
			}
			if (paths.json_rpc_path.empty())
			{
				paths.json_rpc_path = paths.http_path;
				paths.json_rpc_distinct = false;
			}
			if (paths.rest_path.empty())
			{
				paths.rest_path = paths.http_path;
				paths.rest_distinct = false;
			}
			stringify::trim(paths.json_rpc_path);
			stringify::trim(paths.rest_path);
			stringify::trim(paths.http_path);
		}
		server_relay::~server_relay() noexcept
		{
			cancel_activities();
		}
		expects_promise_rt<schema*> server_relay::execute_rpc(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const schema_list& args, cache_policy cache, const std::string_view& path)
		{
			if (reporter.type == transmit_type::any)
				reporter.type = transmit_type::JSONRPC;
			if (reporter.method.empty())
				reporter.method = method;

			schema* params = var::set::array();
			params->reserve(args.size());
			for (auto& item : args)
				params->push(item->copy());

			uptr<schema> setup = var::set::object();
			setup->set("jsonrpc", var::string("2.0"));
			setup->set("id", var::string(get_cache_type(cache)));
			setup->set("method", var::string(method));
			setup->set("params", params);

			auto response_status = coawait(execute_rest(asset, reporter, "POST", path, *setup, cache));
			if (!response_status)
				coreturn expects_rt<schema*>(std::move(response_status.error()));

			uptr<schema> response = *response_status;
			if (response->has("error.code"))
			{
				string code = response->fetch_var("error.code").get_blob();
				string description = response->has("error.message") ? response->fetch_var("error.message").get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, code, description)));
			}
			else if (response->has("result.error_code"))
			{
				string code = response->fetch_var("result.error_code").get_blob();
				string description = response->has("result.error_message") ? response->fetch_var("result.error_message").get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, code, description)));
			}

			schema* result = response->get("result");
			if (!result)
			{
				string description = response->value.get_type() == var_type::string ? response->value.get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, "null", description)));
			}

			result->unlink();
			coreturn expects_rt<schema*>(result);
		}
		expects_promise_rt<schema*> server_relay::execute_rpc3(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const schema_args& args, cache_policy cache, const std::string_view& path)
		{
			if (reporter.type == transmit_type::any)
				reporter.type = transmit_type::JSONRPC;
			if (reporter.method.empty())
				reporter.method = method;

			schema* params = var::set::object();
			params->reserve(args.size());
			for (auto& item : args)
				params->set(item.first, item.second->copy());

			uptr<schema> setup = var::set::object();
			setup->set("jsonrpc", var::string("2.0"));
			setup->set("id", var::string(get_cache_type(cache)));
			setup->set("method", var::string(method));
			setup->set("params", params);

			auto response_status = coawait(execute_rest(asset, reporter, "POST", path, *setup, cache));
			if (!response_status)
				coreturn expects_rt<schema*>(std::move(response_status.error()));

			uptr<schema> response = *response_status;
			if (response->has("error.code"))
			{
				string code = response->fetch_var("error.code").get_blob();
				string description = response->has("error.message") ? response->fetch_var("error.message").get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, code, description)));
			}
			else if (response->has("result.error_code"))
			{
				string code = response->fetch_var("result.error_code").get_blob();
				string description = response->has("result.error_message") ? response->fetch_var("result.error_message").get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, code, description)));
			}

			schema* result = response->get("result");
			if (!result)
			{
				string description = response->value.get_type() == var_type::string ? response->value.get_blob() : "no error description";
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, "null", description)));
			}

			result->unlink();
			coreturn expects_rt<schema*>(result);
		}
		expects_promise_rt<schema*> server_relay::execute_rest(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache)
		{
			if (reporter.type == transmit_type::any)
				reporter.type = transmit_type::REST;
			if (reporter.method.empty())
				reporter.method = location(get_node_url(reporter.type, path)).path.substr(1);

			string body = (args ? schema::to_json(args) : string());
			coreturn coawait(execute_http(asset, reporter, method, path, "application/json", body, cache));
		}
		expects_promise_rt<schema*> server_relay::execute_http(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			if (reporter.type == transmit_type::any)
				reporter.type = transmit_type::HTTP;

			string target_url = get_node_url(reporter.type, path);
			if (reporter.method.empty())
				reporter.method = location(target_url).path.substr(1);

			if (!allowed)
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, "null", "system shutdown (cancelled)")));

			if (path.empty() && body.empty())
				cache = cache_policy::lazy;

			auto* server = nss::server_node::get();
			string message = string(path).append(body);
			string hash = codec::hex_encode(algorithm::hashing::hash256((uint8_t*)message.data(), message.size()));
			if (cache != cache_policy::lazy && cache != cache_policy::greedy)
			{
				auto data = server->load_cache(asset, cache, hash);
				if (data)
					coreturn expects_rt<schema*>(*data);
			}

			if (throttling > 0.0 && cache != cache_policy::greedy)
			{
				const int64_t time = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
				const double timeout = (double)(time - latest);
				const double limit = 1000.0 / throttling;
				const uint64_t cooldown = (uint64_t)(limit - timeout);
				uint64_t retry_timeout = cooldown;
				if (timeout < limit && !coawait(yield_for_cooldown(retry_timeout, protocol::now().user.nss.relaying_timeout)))
					coreturn expects_rt<schema*>(remote_exception::retry());
				else if (!allowed)
					coreturn expects_rt<schema*>(remote_exception::shutdown());
				latest = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			}

			http::fetch_frame setup;
			setup.max_size = 16 * 1024 * 1024;
			setup.verify_peers = (uint32_t)protocol::now().user.tcp.tls_trusted_peers;
			setup.timeout = protocol::now().user.nss.relaying_timeout;

			uint64_t retry_responses = 0;
			uint64_t retry_timeout = protocol::now().user.nss.relaying_retry_timeout;
			if (!body.empty())
			{
				setup.set_header("Content-Type", type);
				setup.content.assign(body);
			}
		retry:
			auto response = coawait(server->internal_call(target_url, method, setup));
			if (!response || response->status_code == 408 || response->status_code == 429 || response->status_code == 502 || response->status_code == 503 || response->status_code == 504)
			{
				++retry_responses;
				if (cache == cache_policy::greedy)
					coreturn  response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (retry_responses > 5)
					coreturn response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request too many times"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (!coawait(yield_for_cooldown(retry_timeout, setup.timeout)))
					coreturn response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request after cooldown"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (!allowed)
					coreturn expects_rt<schema*>(remote_exception::shutdown());
				goto retry;
			}

			auto text = response->content.get_text();
			auto data = response->content.get_json();
			if (!data)
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node's response is not JSON compliant")));

			if (cache != cache_policy::lazy && cache != cache_policy::greedy && (response->status_code < 400 || response->status_code == 404))
			{
				data->add_ref();
				server->store_cache(asset, cache, hash, uptr<schema>(data));
			}

			coreturn expects_rt<schema*>(*data);
		}
		promise<bool> server_relay::yield_for_cooldown(uint64_t& retry_timeout, uint64_t total_timeout_ms)
		{
			if (total_timeout_ms > 0 && retry_timeout >= total_timeout_ms)
				coreturn false;

			promise<bool> future;
			task_id timer_id = enqueue_activity(future, schedule::get()->set_timeout(retry_timeout, [future]() mutable
			{
				if (future.is_pending())
					future.set(true);
			}));
			if (!coawait(std::move(future)))
				coreturn false;

			dequeue_activity(timer_id);
			retry_timeout *= 2;
			coreturn true;
		}
		promise<bool> server_relay::yield_for_discovery(chain_supervisor_options* options)
		{
			if (!allowed)
				coreturn promise<bool>(false);

			promise<bool> future;
			options->state.latest_time_awaited += options->polling_frequency_ms;
			task_id timer_id = enqueue_activity(future, schedule::get()->set_timeout(options->polling_frequency_ms, [future]() mutable
			{
				if (future.is_pending())
					future.set(true);
			}));
			if (!coawait(std::move(future)))
				coreturn false;

			dequeue_activity(timer_id);
			coreturn true;
		}
		expects_lr<void> server_relay::verify_compatibility(const algorithm::asset_id& asset)
		{
			auto* implementation = nss::server_node::get()->get_chain(asset);
			if (!implementation)
				return expectation::met;

			return implementation->verify_node_compatibility(this);
		}
		task_id server_relay::enqueue_activity(const promise<bool>& future, task_id timer_id)
		{
			if (future.is_pending())
			{
				umutex<std::recursive_mutex> unique(mutex);
				tasks.push_back(std::make_pair(future, timer_id));
			}
			if (!allowed)
				cancel_activities();
			return timer_id;
		}
		void server_relay::dequeue_activity(task_id timer_id)
		{
			umutex<std::recursive_mutex> unique(mutex);
			for (auto it = tasks.begin(); it != tasks.end(); it++)
			{
				if (it->second == timer_id)
				{
					tasks.erase(it);
					break;
				}
			}
		}
		void server_relay::allow_activities()
		{
			allowed = true;
		}
		void server_relay::cancel_activities()
		{
			umutex<std::recursive_mutex> unique(mutex);
			allowed = false;
			for (auto& task : tasks)
			{
				schedule::get()->clear_timeout(task.second);
				if (task.first.is_pending())
					task.first.set(false);
			}
			tasks.clear();
		}
		bool server_relay::has_distinct_url(transmit_type type) const
		{
			switch (type)
			{
				case transmit_type::JSONRPC:
					return paths.json_rpc_distinct;
				case transmit_type::REST:
					return paths.rest_distinct;
				case transmit_type::HTTP:
					return paths.http_distinct;
				default:
					return paths.json_rpc_distinct || paths.rest_distinct || paths.http_distinct;
			}
		}
		bool server_relay::is_activity_allowed() const
		{
			return allowed;
		}
		const string& server_relay::get_node_url(transmit_type type) const
		{
			switch (type)
			{
				case server_relay::transmit_type::JSONRPC:
					return paths.json_rpc_path;
				case server_relay::transmit_type::REST:
					return paths.rest_path;
				case server_relay::transmit_type::HTTP:
				default:
					return paths.http_path;
			}
		}
		string server_relay::get_node_url(transmit_type type, const std::string_view& endpoint) const
		{
			if (stringify::starts_with(endpoint, "http"))
				return string(endpoint);

			string URL = get_node_url(type);
			if (URL.empty() || endpoint.empty())
				return URL;

			if (URL.back() == '/' && endpoint.front() == '/')
				URL.erase(URL.end() - 1);
			else if (URL.back() != '/' && endpoint.front() != '/')
				URL += '/';
			URL += endpoint;
			return URL;
		}
		std::string_view server_relay::get_cache_type(cache_policy cache)
		{
			switch (cache)
			{
				case cache_policy::greedy:
					return "greedy";
				case cache_policy::lazy:
					return "lazy";
				case cache_policy::shortened:
					return "scache";
				case cache_policy::extended:
					return "ecache";
				case cache_policy::persistent:
					return "pcache";
				default:
					return "any";
			}
		}
		string server_relay::generate_error_message(const expects_system<http::response_frame>& response, const error_reporter& reporter, const std::string_view& error_code, const std::string_view& error_message)
		{
			std::string_view domain;
			switch (reporter.type)
			{
				case server_relay::transmit_type::JSONRPC:
					domain = "jrpc";
					break;
				case server_relay::transmit_type::REST:
					domain = "rest";
					break;
				case server_relay::transmit_type::HTTP:
					domain = "http";
					break;
				default:
					domain = "call";
					break;
			}

			string_stream message;
			string method = reporter.method;
			message << "observer::" << domain << "::" << stringify::to_lower(method) << " error: ";
			if (error_message.empty())
				message << "no response";
			else
				message << error_message;
			message << " (netc: " << (response ? response->status_code : 500) << ", " << domain << "c: " << error_code << ")";
			return message.str();
		}

		relay_backend::relay_backend() noexcept : interact(nullptr)
		{
		}
		relay_backend::~relay_backend() noexcept
		{
		}
		expects_promise_rt<schema*> relay_backend::execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, cache_policy cache, const std::string_view& path)
		{
			auto* nodes = nss::server_node::get()->get_nodes(asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rpc(asset, reporter, method, args, cache, path));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_rpc3(const algorithm::asset_id& asset, const std::string_view& method, schema_args&& args, cache_policy cache, const std::string_view& path)
		{
			auto* nodes = nss::server_node::get()->get_nodes(asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rpc3(asset, reporter, method, args, cache, path));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_rest(const algorithm::asset_id& asset, const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache)
		{
			uptr<schema> body = args;
			auto* nodes = nss::server_node::get()->get_nodes(asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rest(asset, reporter, method, path, *body, cache));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_http(const algorithm::asset_id& asset, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			auto* nodes = nss::server_node::get()->get_nodes(asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_http(asset, reporter, method, path, type, body, cache));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_lr<ordered_map<string, uint64_t>> relay_backend::find_checkpoint_addresses(const algorithm::asset_id& asset, const unordered_set<string>& addresses)
		{
			if (addresses.empty())
				return expects_lr<ordered_map<string, uint64_t>>(layer_exception("no addresses supplied"));

			auto* server = nss::server_node::get();
			auto* implementation = server->get_chain(asset);
			if (!implementation)
				return expects_lr<ordered_map<string, uint64_t>>(layer_exception("chain not found"));

			auto results = server->get_address_indices(asset, addresses);
			if (!results || results->empty())
				return expects_lr<ordered_map<string, uint64_t>>(layer_exception("no addresses found"));

			ordered_map<string, uint64_t> info;
			for (auto& item : *results)
				info[item.first] = item.second.address_index.otherwise(protocol::now().account.root_address_index);

			return expects_lr<ordered_map<string, uint64_t>>(std::move(info));
		}
		expects_lr<vector<string>> relay_backend::get_checkpoint_addresses(const algorithm::asset_id& asset)
		{
			return nss::server_node::get()->get_address_indices(asset);
		}
		expects_lr<void> relay_backend::verify_node_compatibility(server_relay* node)
		{
			return expectation::met;
		}
		string relay_backend::get_checksum_hash(const std::string_view& value) const
		{
			return string(value);
		}
		uint256_t relay_backend::to_baseline_value(const decimal& value) const
		{
			decimal baseline = value * get_chainparams().divisibility;
			return uint256_t(baseline.truncate(0).to_string());
		}
		uint64_t relay_backend::get_retirement_block_number() const
		{
			return std::numeric_limits<uint64_t>::max();
		}

		relay_backend_utxo::relay_backend_utxo() noexcept : relay_backend()
		{
		}
		expects_promise_rt<decimal> relay_backend_utxo::calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address)
		{
			decimal balance = 0.0;
			auto outputs = calculate_coins(asset, wallet, optional::none, optional::none);
			if (!outputs)
				return expects_promise_rt<decimal>(std::move(balance));

			auto contract_address = nss::server_node::get()->get_contract_address(asset);
			if (contract_address)
			{
				for (auto& output : *outputs)
				{
					auto value = output.get_token_value(*contract_address);
					if (value)
						balance += *value;
				}
			}
			else
			{
				for (auto& output : *outputs)
					balance += output.value;
			}

			return expects_promise_rt<decimal>(std::move(balance));
		}
		expects_lr<vector<coin_utxo>> relay_backend_utxo::calculate_coins(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<decimal>&& min_value, option<token_utxo>&& min_token_value)
		{
			if (!wallet.is_valid())
				return expects_lr<vector<coin_utxo>>(layer_exception("wallet not found"));

			auto binding = wallet.get_binding();
			if (!binding)
				return expects_lr<vector<coin_utxo>>(layer_exception("binding not found"));

			vector<coin_utxo> values;
			decimal current_value = 0.0, current_token_value = 0.0;
			auto* server = nss::server_node::get();
			auto continue_accumulation = [&]() { return (!min_value || current_value < *min_value) && (!min_token_value || current_token_value < min_token_value->value); };
			while (continue_accumulation())
			{
				const size_t count = 64;
				auto outputs = server->get_utxos(asset, *binding, values.size(), count);
				if (!outputs || outputs->empty())
					break;

				bool eof_value = false;
				bool eof_utxo = outputs->size() < count;
				values.reserve(values.size() + outputs->size());
				for (auto& output : *outputs)
				{
					current_value += output.UTXO.value;
					eof_value = !continue_accumulation();
					values.emplace_back(std::move(output.UTXO));
					if (eof_value)
						break;
				}
				if (eof_utxo || eof_value)
					break;
			}

			if (continue_accumulation() && (min_value || min_token_value))
				return expects_lr<vector<coin_utxo>>(layer_exception("insufficient funds"));

			return expects_lr<vector<coin_utxo>>(std::move(values));
		}
		expects_lr<coin_utxo> relay_backend_utxo::get_coins(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
		{
			auto output = nss::server_node::get()->get_utxo(asset, transaction_id, index);
			if (!output)
				return expects_lr<coin_utxo>(layer_exception("transaction output was not found"));

			return expects_lr<coin_utxo>(std::move(output->UTXO));
		}
		expects_lr<void> relay_backend_utxo::update_coins(const algorithm::asset_id& asset, const outgoing_transaction& tx_data)
		{
			if (tx_data.inputs)
			{
				for (auto& output : *tx_data.inputs)
					remove_coins(asset, output.transaction_id, output.index);
			}
			if (tx_data.outputs)
			{
				for (auto& input : *tx_data.outputs)
					add_coins(asset, input);
			}
			return expects_lr<void>(expectation::met);
		}
		expects_lr<void> relay_backend_utxo::add_coins(const algorithm::asset_id& asset, const coin_utxo& output)
		{
			auto* server = nss::server_node::get();
			auto* implementation = server->get_chain(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			auto address_index = server->get_address_index(asset, implementation->get_checksum_hash(output.address));
			if (!address_index)
				return expects_lr<void>(layer_exception("transaction output is not being watched"));

			index_utxo new_output;
			new_output.binding = std::move(address_index->binding);
			new_output.UTXO = output;

			auto status = server->add_utxo(asset, new_output);
			if (status)
				return expects_lr<void>(expectation::met);

			remove_coins(asset, output.transaction_id, output.index);
			return expects_lr<void>(std::move(status.error()));
		}
		expects_lr<void> relay_backend_utxo::remove_coins(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index)
		{
			return nss::server_node::get()->remove_utxo(asset, transaction_id, index);
		}
		decimal relay_backend_utxo::get_coins_value(const vector<coin_utxo>& values, option<string>&& contract_address)
		{
			decimal value = 0.0;
			if (contract_address)
			{
				for (auto& item : values)
				{
					for (auto& token : item.tokens)
					{
						if (token.contract_address == *contract_address)
							value += token.value;
					}
				}
			}
			else
			{
				for (auto& item : values)
					value += item.value;
			}
			return value;
		}
	}
}
