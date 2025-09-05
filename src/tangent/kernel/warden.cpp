#include "warden.h"
#include "../validator/service/oracle.h"
#include <sstream>

namespace tangent
{
	namespace warden
	{
		wallet_link::wallet_link(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_public_key, const std::string_view& new_address) : owner(new_owner), address(new_address), public_key(new_public_key)
		{
		}
		bool wallet_link::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string_raw(public_key);
			stream->write_string_raw(address);
			stream->write_string(owner.optimized_view());
			return true;
		}
		bool wallet_link::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &public_key))
				return false;

			if (!stream.read_string(stream.read_type(), &address))
				return false;

			string owner_assembly;
			if (!stream.read_string(stream.read_type(), &owner_assembly) || !algorithm::encoding::decode_bytes(owner_assembly, owner.data, sizeof(owner)))
				return false;

			return true;
		}
		uptr<schema> wallet_link::as_schema() const
		{
			schema* data = var::set::object();
			data->set("owner", algorithm::signing::serialize_address(owner));
			data->set("public_key", public_key.empty() ? var::null() : var::string(public_key));
			data->set("address", address.empty() ? var::null() : var::string(address));
			return data;
		}
		uint32_t wallet_link::as_type() const
		{
			return as_instance_type();
		}
		std::string_view wallet_link::as_typename() const
		{
			return as_instance_typename();
		}
		wallet_link::search_term wallet_link::as_search_wide() const
		{
			if (has_owner())
				return search_term::owner;
			else if (has_public_key())
				return search_term::public_key;
			else if (has_address())
				return search_term::address;
			return search_term::none;
		}
		wallet_link::search_term wallet_link::as_search_narrow() const
		{
			if (has_address())
				return search_term::address;
			else if (has_public_key())
				return search_term::public_key;
			else if (has_owner())
				return search_term::owner;
			return search_term::none;
		}
		string wallet_link::as_tag_address(const std::string_view& tag) const
		{
			return address.empty() ? string() : address_util::encode_tag_address(address, tag);
		}
		string wallet_link::as_name() const
		{
			if (has_address())
				return address;

			if (has_public_key())
				return public_key;

			if (has_owner())
			{
				string owner_address;
				algorithm::signing::encode_address(owner, owner_address);
				return owner_address;
			}

			return "(confidential)";
		}
		bool wallet_link::has_owner() const
		{
			return !owner.empty();
		}
		bool wallet_link::has_public_key() const
		{
			return !stringify::is_empty_or_whitespace(public_key);
		}
		bool wallet_link::has_address() const
		{
			return !stringify::is_empty_or_whitespace(address);
		}
		bool wallet_link::has_all() const
		{
			return has_owner() && has_public_key() && has_address();
		}
		bool wallet_link::has_any() const
		{
			return has_owner() || has_public_key() || has_address();
		}
		uint32_t wallet_link::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view wallet_link::as_instance_typename()
		{
			return "warden_wallet_link";
		}
		wallet_link wallet_link::from_owner(const algorithm::pubkeyhash_t& new_owner)
		{
			return wallet_link(new_owner, std::string_view(), std::string_view());
		}
		wallet_link wallet_link::from_public_key(const std::string_view& new_public_key)
		{
			return wallet_link(algorithm::pubkeyhash_t(), new_public_key, std::string_view());
		}
		wallet_link wallet_link::from_address(const std::string_view& new_address)
		{
			return wallet_link(algorithm::pubkeyhash_t(), std::string_view(), new_address);
		}

		value_transfer::value_transfer() : asset(0), value(decimal::nan())
		{
		}
		value_transfer::value_transfer(const algorithm::asset_id& new_asset, const std::string_view& new_address, decimal&& new_value) : asset(new_asset), address(new_address), value(std::move(new_value))
		{
		}
		bool value_transfer::is_valid() const
		{
			return !stringify::is_empty_or_whitespace(address) && (value.is_zero() || value.is_positive());
		}

		coin_utxo::token_utxo::token_utxo() : decimals(0)
		{
		}
		coin_utxo::token_utxo::token_utxo(const algorithm::asset_id& new_asset, const decimal& new_value) : contract_address(algorithm::asset::handle_of(new_asset)), value(new_value), decimals(0)
		{
		}
		coin_utxo::token_utxo::token_utxo(const std::string_view& new_contract_address, const std::string_view& new_symbol, const decimal& new_value, uint8_t new_decimals) : contract_address(new_contract_address), symbol(new_symbol), value(new_value), decimals(new_decimals)
		{
		}
		decimal coin_utxo::token_utxo::get_divisibility() const
		{
			decimal divisibility = decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1);
			return divisibility.truncate(protocol::now().message.decimal_precision);
		}
		algorithm::asset_id coin_utxo::token_utxo::get_asset(const algorithm::asset_id& base_asset) const
		{
			return is_account() ? algorithm::asset::id_of_handle(contract_address) : algorithm::asset::id_of(algorithm::asset::blockchain_of(base_asset), symbol, contract_address);
		}
		bool coin_utxo::token_utxo::is_account() const
		{
			return symbol.empty() && decimals == 0;
		}
		bool coin_utxo::token_utxo::is_valid() const
		{
			if (is_account())
				return algorithm::asset::id_of_handle(contract_address) > 0 && !value.is_negative() && !value.is_nan();

			return !contract_address.empty() && !symbol.empty() && !value.is_negative() && !value.is_nan();
		}

		coin_utxo::coin_utxo(wallet_link&& new_link, unordered_map<algorithm::asset_id, decimal>&& new_values) : link(std::move(new_link)), index(std::numeric_limits<uint32_t>::max())
		{
			for (auto& [asset, asset_value] : new_values)
			{
				if (!algorithm::asset::token_of(asset).empty())
				{
					apply_token_value(algorithm::asset::handle_of(asset), std::string_view(), std::move(asset_value), 0);
					if (transaction_id.empty())
						transaction_id = algorithm::asset::base_handle_of(asset);
					if (value.is_nan())
						value = decimal::zero();
				}
				else
				{
					transaction_id = algorithm::asset::handle_of(asset);
					value = std::move(asset_value);
				}
			}
		}
		coin_utxo::coin_utxo(wallet_link&& new_link, const std::string_view& new_transaction_id, uint64_t new_index, decimal&& new_value) : link(std::move(new_link)), transaction_id(new_transaction_id), value(std::move(new_value)), index(new_index)
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
		bool coin_utxo::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!link.store_payload(stream))
				return false;

			stream->write_string_raw(transaction_id);
			stream->write_integer(index);
			stream->write_decimal(value);
			stream->write_integer((uint32_t)tokens.size());
			for (auto& item : tokens)
			{
				stream->write_string_raw(item.contract_address);
				stream->write_string(item.symbol);
				stream->write_decimal(item.value);
				stream->write_integer(item.decimals);
			}
			return true;
		}
		bool coin_utxo::load_payload(format::ro_stream& stream)
		{
			if (!link.load_payload(stream))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			if (!stream.read_integer(stream.read_type(), &index))
				return false;

			if (!stream.read_decimal(stream.read_type(), &value))
				return false;

			uint32_t size;
			if (!stream.read_integer(stream.read_type(), &size))
				return false;

			tokens.reserve(size);
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

				tokens.emplace_back(std::move(token));
			}

			return true;
		}
		bool coin_utxo::is_account() const
		{
			return index == std::numeric_limits<uint32_t>::max();
		}
		bool coin_utxo::is_valid_input() const
		{
			for (auto& token : tokens)
			{
				if (!token.is_valid())
					return false;
			}

			if (!is_account())
				return !transaction_id.empty() && !value.is_nan() && !value.is_negative() && link.has_all();

			if (!algorithm::asset::id_of_handle(transaction_id))
				return false;

			return !value.is_nan() && !value.is_negative() && link.has_all();
		}
		bool coin_utxo::is_valid_output() const
		{
			if (is_account() && !algorithm::asset::id_of_handle(transaction_id))
				return false;

			for (auto& token : tokens)
			{
				if (!token.is_valid())
					return false;
			}

			return !value.is_nan() && !value.is_negative() && (link.has_public_key() || link.has_address());
		}
		algorithm::asset_id coin_utxo::get_asset(const algorithm::asset_id& base_asset) const
		{
			return is_account() ? algorithm::asset::id_of_handle(transaction_id) : base_asset;
		}
		uptr<schema> coin_utxo::as_schema() const
		{
			bool account = is_account();
			schema* data = var::set::object();
			data->set("link", link.as_schema().reset());
			if (!account)
			{
				data->set("transaction_id", var::string(transaction_id));
				data->set("index", var::integer(index));
			}
			else
				data->set("asset", algorithm::asset::serialize(get_asset(0)));
			data->set("value", var::decimal(value));
			data->set("type", var::string(is_account() ? "account" : "utxo"));
			auto* tokens_data = data->set("tokens", var::set::array());
			for (auto& item : tokens)
			{
				auto* token_data = tokens_data->push(var::set::object());
				if (!item.is_account())
				{
					token_data->set("contract_address", var::string(item.contract_address));
					token_data->set("symbol", var::string(item.symbol));
					token_data->set("value", var::decimal(item.value));
					token_data->set("decimals", var::integer(item.decimals));
				}
				else
				{
					token_data->set("asset", algorithm::asset::serialize(item.get_asset(0)));
					token_data->set("value", var::decimal(item.value));
				}
			}
			return data;
		}
		uint32_t coin_utxo::as_type() const
		{
			return as_instance_type();
		}
		std::string_view coin_utxo::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t coin_utxo::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view coin_utxo::as_instance_typename()
		{
			return "warden_coin_utxo";
		}

		bool computed_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(block_id.execution);
			stream->write_integer(block_id.finalization);
			stream->write_string_raw(transaction_id);
			stream->write_integer((uint32_t)inputs.size());
			for (auto& item : inputs)
			{
				if (!item.store_payload(stream))
					return false;
			}

			stream->write_integer((uint32_t)outputs.size());
			for (auto& item : outputs)
			{
				if (!item.store_payload(stream))
					return false;
			}

			return true;
		}
		bool computed_transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &block_id.execution))
				return false;

			if (!stream.read_integer(stream.read_type(), &block_id.finalization))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			uint32_t inputs_size;
			if (!stream.read_integer(stream.read_type(), &inputs_size))
				return false;

			inputs.clear();
			inputs.reserve(inputs_size);
			for (size_t i = 0; i < inputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				inputs.emplace_back(std::move(next));
			}

			uint32_t outputs_size;
			if (!stream.read_integer(stream.read_type(), &outputs_size))
				return false;

			outputs.clear();
			outputs.reserve(outputs_size);
			for (size_t i = 0; i < outputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				outputs.emplace_back(std::move(next));
			}

			return true;
		}
		bool computed_transaction::is_valid() const
		{
			if (inputs.empty() || outputs.empty() || stringify::is_empty_or_whitespace(transaction_id))
				return false;

			unordered_map<algorithm::asset_id, decimal> balance;
			for (auto& input : inputs)
			{
				if (!input.is_valid_output())
					return false;

				auto& balance_value = balance[0];
				balance_value = balance_value.is_nan() ? -input.value : (balance_value - input.value);
				for (auto& token : input.tokens)
				{
					balance_value = balance[algorithm::asset::id_of("_", token.symbol, token.contract_address)];
					balance_value = balance_value.is_nan() ? -input.value : (balance_value - input.value);
				}
			}

			for (auto& output : outputs)
			{
				if (!output.is_valid_output())
					return false;

				auto& balance_value = balance[0];
				balance_value = balance_value.is_nan() ? output.value : (balance_value + output.value);
				for (auto& token : output.tokens)
				{
					balance_value = balance[algorithm::asset::id_of("_", token.symbol, token.contract_address)];
					balance_value = balance_value.is_nan() ? output.value : (balance_value + output.value);
				}
			}

			for (auto& balance_value : balance)
			{
				if (balance_value.second > 0.0)
					return false;
			}

			return true;
		}
		bool computed_transaction::is_mature(const algorithm::asset_id& asset) const
		{
			auto* server = oracle::server_node::get();
			auto* chain = server->get_chain(asset);
			if (!chain || block_id.finalization < block_id.execution)
				return false;

			return block_id.finalization - block_id.execution >= chain->get_chainparams().sync_latency;
		}
		uptr<schema> computed_transaction::as_schema() const
		{
			schema* data = var::set::object();
			schema* block_data = data->set("block_id", var::set::array());
			block_data->push(algorithm::encoding::serialize_uint256(block_id.execution));
			block_data->push(algorithm::encoding::serialize_uint256(block_id.finalization));
			data->set("transaction_id", var::string(transaction_id));
			schema* input_data = data->set("inputs", var::array());
			for (auto& input : inputs)
				input_data->push(input.as_schema().reset());
			schema* output_data = data->set("outputs", var::array());
			for (auto& output : outputs)
				output_data->push(output.as_schema().reset());
			return data;
		}
		uint32_t computed_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view computed_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t computed_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view computed_transaction::as_instance_typename()
		{
			return "warden_computed_transaction";
		}

		prepared_transaction& prepared_transaction::requires_input(algorithm::composition::type new_alg, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, coin_utxo&& input)
		{
			VI_ASSERT(new_message != nullptr, "message should be set");
			signable_coin_utxo item;
			item.utxo = std::move(input);
			item.alg = new_alg;
			item.public_key = new_public_key;
			item.message.resize(new_message_size);
			memcpy(item.message.data(), new_message, new_message_size);
			inputs.push_back(std::move(item));
			return *this;
		}
		prepared_transaction& prepared_transaction::requires_account_input(algorithm::composition::type new_alg, wallet_link&& signer, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, unordered_map<algorithm::asset_id, decimal>&& input)
		{
			coin_utxo item = coin_utxo(std::move(signer), std::move(input));
			return requires_input(new_alg, new_public_key, new_message, new_message_size, std::move(item));
		}
		prepared_transaction& prepared_transaction::requires_output(coin_utxo&& output)
		{
			outputs.push_back(std::move(output));
			for (size_t i = 0; i < outputs.size(); i++)
				outputs[i].index = (outputs[i].index == std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : (uint32_t)i);
			return *this;
		}
		prepared_transaction& prepared_transaction::requires_account_output(const std::string_view& to_address, unordered_map<algorithm::asset_id, decimal>&& output)
		{
			coin_utxo item = coin_utxo(wallet_link::from_address(to_address), std::move(output));
			outputs.push_back(std::move(item));
			return *this;
		}
		prepared_transaction& prepared_transaction::requires_abi(format::variable&& value)
		{
			abi.push_back(std::move(value));
			return *this;
		}
		format::variable* prepared_transaction::load_abi(size_t* ptr)
		{
			if (!ptr)
				return abi.empty() ? nullptr : &abi[0];

			return *ptr >= abi.size() ? nullptr : &abi[(*ptr)++];
		}
		bool prepared_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer((uint32_t)inputs.size());
			for (auto& item : inputs)
			{
				stream->write_integer((uint8_t)item.alg);
				stream->write_string(std::string_view((char*)item.public_key.data(), item.public_key.size()));
				stream->write_string(std::string_view((char*)item.signature.data(), item.signature.size()));
				stream->write_string(std::string_view((char*)item.message.data(), item.message.size()));
				if (!item.utxo.store_payload(stream))
					return false;
			}

			stream->write_integer((uint32_t)outputs.size());
			for (auto& item : outputs)
			{
				if (!item.store_payload(stream))
					return false;
			}

			return format::variables_util::serialize_merge_into(abi, stream);
		}
		bool prepared_transaction::load_payload(format::ro_stream& stream)
		{
			uint32_t inputs_size;
			if (!stream.read_integer(stream.read_type(), &inputs_size))
				return false;

			inputs.clear();
			inputs.reserve(inputs_size);
			for (size_t i = 0; i < inputs_size; i++)
			{
				signable_coin_utxo next;
				if (!stream.read_integer(stream.read_type(), (uint8_t*)&next.alg))
					return false;

				string public_key_assembly;
				if (!stream.read_string(stream.read_type(), &public_key_assembly) || !algorithm::encoding::decode_bytes(public_key_assembly, next.public_key.data(), next.public_key.size()))
					return false;

				string signature_assembly;
				if (!stream.read_string(stream.read_type(), &signature_assembly) || !algorithm::encoding::decode_bytes(signature_assembly, next.signature.data(), next.signature.size()))
					return false;

				string message_assembly;
				if (!stream.read_string(stream.read_type(), &message_assembly))
					return false;

				next.message.resize(message_assembly.size());
				memcpy(next.message.data(), message_assembly.data(), message_assembly.size());
				if (!next.utxo.load_payload(stream))
					return false;

				inputs.emplace_back(std::move(next));
			}

			uint32_t outputs_size;
			if (!stream.read_integer(stream.read_type(), &outputs_size))
				return false;

			outputs.clear();
			outputs.reserve(outputs_size);
			for (size_t i = 0; i < outputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				outputs.emplace_back(std::move(next));
			}

			abi.clear();
			return format::variables_util::deserialize_merge_from(stream, &abi);
		}
		prepared_transaction::signable_coin_utxo* prepared_transaction::next_input_for_aggregation()
		{
			for (auto& item : inputs)
			{
				if (item.signature.empty())
					return &item;
			}
			return nullptr;
		}
		prepared_transaction::status prepared_transaction::as_status() const
		{
			if (inputs.empty() || outputs.empty())
				return status::invalid;

			for (auto& item : inputs)
			{
				if (item.alg == algorithm::composition::type::unknown || item.public_key.empty() || item.message.empty() || !item.utxo.is_valid_input())
					return status::invalid;
			}

			for (auto& item : outputs)
			{
				if (!item.is_valid_output())
					return status::invalid;
			}

			for (auto& item : inputs)
			{
				if (item.signature.empty())
					return status::requires_signature;
			}

			return status::requires_finalization;
		}
		uptr<schema> prepared_transaction::as_schema() const
		{
			std::string_view status;
			switch (as_status())
			{
				case status::invalid:
					status = "invalid";
					break;
				case status::requires_signature:
					status = "requires_signature";
					break;
				case status::requires_finalization:
					status = "requires_finalization";
					break;
				default:
					status = "unknown";
					break;
			}

			schema* data = var::set::object();
			schema* input_data = data->set("inputs", var::array());
			for (auto& input : inputs)
			{
				auto* signer = input_data->push(var::set::object());
				signer->set("utxo", input.utxo.as_schema().reset());
				switch (input.alg)
				{
					case algorithm::composition::type::ed25519:
						signer->set("type", var::string("ed25519"));
						break;
					case algorithm::composition::type::ed25519_clsag:
						signer->set("type", var::string("ed25519_clsag"));
						break;
					case algorithm::composition::type::secp256k1:
						signer->set("type", var::string("secp256k1"));
						break;
					case algorithm::composition::type::secp256k1_schnorr:
						signer->set("type", var::string("secp256k1_schnorr"));
						break;
					default:
						signer->set("type", var::null());
						break;
				}
				signer->set("public_key", input.public_key.empty() ? var::null() : var::string(format::util::encode_0xhex(std::string_view((char*)input.public_key.data(), input.public_key.size()))));
				signer->set("signature", input.signature.empty() ? var::null() : var::string(format::util::encode_0xhex(std::string_view((char*)input.signature.data(), input.signature.size()))));
				signer->set("message", var::string(format::util::encode_0xhex(std::string_view((char*)input.message.data(), input.message.size()))));
				signer->set("finalized", var::boolean(!input.signature.empty()));
			}
			schema* output_data = data->set("outputs", var::array());
			for (auto& output : outputs)
				output_data->push(output.as_schema().reset());
			data->set("abi", format::variables_util::serialize(abi));
			data->set("status", var::string(status));
			return data;
		}
		uint32_t prepared_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view prepared_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t prepared_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view prepared_transaction::as_instance_typename()
		{
			return "warden_prepared_transaction";
		}

		finalized_transaction::finalized_transaction(prepared_transaction&& new_prepared, string&& new_calldata, string&& new_hashdata, uint64_t new_locktime) : prepared(std::move(new_prepared)), calldata(std::move(new_calldata)), hashdata(std::move(new_hashdata)), locktime(new_locktime)
		{
		}
		bool finalized_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			if (!prepared.store_payload(stream))
				return false;
			
			stream->write_string(calldata);
			stream->write_string(hashdata);
			stream->write_integer(locktime);
			return true;
		}
		bool finalized_transaction::load_payload(format::ro_stream& stream)
		{
			if (!prepared.load_payload(stream))
				return false;

			if (!stream.read_string(stream.read_type(), &calldata))
				return false;

			if (!stream.read_string(stream.read_type(), &hashdata))
				return false;

			if (!stream.read_integer(stream.read_type(), &locktime))
				return false;

			return true;
		}
		bool finalized_transaction::is_valid() const
		{
			return prepared.as_status() == prepared_transaction::status::requires_finalization && !calldata.empty() && !hashdata.empty();
		}
		computed_transaction finalized_transaction::as_computed() const
		{
			computed_transaction computed;
			computed.transaction_id = hashdata;
			computed.block_id.execution = locktime;
			computed.outputs = prepared.outputs;
			computed.inputs.reserve(prepared.inputs.size());
			for (auto& input : prepared.inputs)
				computed.inputs.push_back(input.utxo);
			return computed;
		}
		uptr<schema> finalized_transaction::as_schema() const
		{
			schema* data = var::set::object();
			data->set("prepared", prepared.as_schema().reset());
			data->set("computed", as_computed().as_schema().reset());
			data->set("calldata", var::string(calldata));
			data->set("hashdata", var::string(hashdata));
			data->set("locktime", algorithm::encoding::serialize_uint256(locktime));
			return data;
		}
		uint32_t finalized_transaction::as_type() const
		{
			return as_instance_type();
		}
		std::string_view finalized_transaction::as_typename() const
		{
			return as_instance_typename();
		}
		uint32_t finalized_transaction::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view finalized_transaction::as_instance_typename()
		{
			return "warden_finalized_transaction";
		}

		decimal computed_fee::get_max_fee() const
		{
			switch (type)
			{
				case fee_type::fee:
					return fee.fee_rate * decimal(fee.byte_rate);
				case fee_type::gas:
					return gas.gas_price * gas.gas_limit.to_decimal();
				default:
					return decimal::zero();
			}
		}
		bool computed_fee::is_flat_fee() const
		{
			return type == fee_type::fee && fee.byte_rate == 1;
		}
		bool computed_fee::is_valid() const
		{
			switch (type)
			{
				case fee_type::fee:
					return fee.fee_rate.is_positive() && fee.byte_rate > 0;
				case fee_type::gas:
					return !gas.gas_base_price.is_nan() && !gas.gas_base_price.is_negative() && gas.gas_price.is_positive() && gas.gas_base_price <= gas.gas_price && gas.gas_limit > 0;
				default:
					return false;
			}
		}
		computed_fee computed_fee::flat_fee(const decimal& fee)
		{
			return fee_per_byte(fee, 1);
		}
		computed_fee computed_fee::fee_per_byte(const decimal& rate, size_t bytes)
		{
			computed_fee result;
			result.type = fee_type::fee;
			result.fee.fee_rate = rate;
			result.fee.byte_rate = bytes;
			return result;
		}
		computed_fee computed_fee::fee_per_kilobyte(const decimal& rate)
		{
			return fee_per_byte(rate, 1024);
		}
		computed_fee computed_fee::fee_per_gas(const decimal& price, const uint256_t& limit)
		{
			return fee_per_gas_priority(decimal::zero(), price, limit);
		}
		computed_fee computed_fee::fee_per_gas_priority(const decimal& base_price, const decimal& priority_price, const uint256_t& limit)
		{
			computed_fee result;
			result.type = fee_type::gas;
			result.gas.gas_base_price = base_price;
			result.gas.gas_price = priority_price;
			result.gas.gas_limit = limit;
			return result;
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
			auto* nodes = oracle::server_node::get()->get_nodes(asset);
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

		server_relay::server_relay(unordered_map<string, string>&& node_urls, double node_rps) noexcept : urls(std::move(node_urls)), latest(0), rps(node_rps), allowed(true), user_data(nullptr)
		{
			for (auto& [type, path] : urls)
				stringify::trim(path);
		}
		server_relay::~server_relay() noexcept
		{
			cancel_activities();
		}
		expects_promise_rt<schema*> server_relay::execute_rpc(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const schema_list& args, cache_policy cache, const std::string_view& path)
		{
			if (reporter.type.empty())
				reporter.type = "jrpc";
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
			if (reporter.type.empty())
				reporter.type = "jrpc";
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
			if (reporter.type.empty())
				reporter.type = "rest";
			if (reporter.method.empty())
				reporter.method = location(get_node_url(reporter.type, path)).path.substr(1);

			string body = (args ? schema::to_json(args) : string());
			coreturn coawait(execute_http(asset, reporter, method, path, "application/json", body, cache));
		}
		expects_promise_rt<schema*> server_relay::execute_http(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			if (reporter.type.empty())
				reporter.type = "http";

			string target_url = get_node_url(reporter.type, path);
			if (reporter.method.empty())
				reporter.method = location(target_url).path.substr(1);

			if (!allowed)
				coreturn expects_rt<schema*>(remote_exception(generate_error_message(expects_system<http::response_frame>(system_exception()), reporter, "null", "system shutdown (cancelled)")));

			if (path.empty() && body.empty())
				cache = cache_policy::no_cache;

			auto* server = oracle::server_node::get();
			string message = string(path).append(body);
			string hash = codec::hex_encode(algorithm::hashing::hash256((uint8_t*)message.data(), message.size()));
			if (cache != cache_policy::no_cache && cache != cache_policy::no_cache_no_throttling)
			{
				auto data = server->load_cache(asset, cache, hash);
				if (data)
					coreturn expects_rt<schema*>(*data);
			}

			if (rps > 0.0 && cache != cache_policy::no_cache_no_throttling)
			{
				const int64_t time = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
				const double timeout = (double)(time - latest);
				const double limit = 1000.0 / rps;
				const uint64_t cooldown = (uint64_t)(limit - timeout);
				uint64_t retry_timeout = cooldown;
				if (timeout < limit && !coawait(yield_for_cooldown(retry_timeout, protocol::now().user.oracle.relaying_timeout)))
					coreturn expects_rt<schema*>(remote_exception::retry());
				else if (!allowed)
					coreturn expects_rt<schema*>(remote_exception::shutdown());
				latest = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			}

			http::fetch_frame setup;
			setup.max_size = 16 * 1024 * 1024;
			setup.verify_peers = (uint32_t)protocol::now().user.tcp.tls_trusted_peers;
			setup.timeout = protocol::now().user.oracle.relaying_timeout;

			uint64_t retry_responses = 0;
			uint64_t retry_timeout = protocol::now().user.oracle.relaying_retry_timeout;
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
				if (cache == cache_policy::no_cache_no_throttling)
					coreturn  response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (retry_responses > 5)
					coreturn response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request too many times"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (!coawait(yield_for_cooldown(retry_timeout, setup.timeout)))
					coreturn response ? expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node has rejected the request after cooldown"))) : expects_rt<schema*>(remote_exception::shutdown());
				else if (!allowed)
					coreturn expects_rt<schema*>(remote_exception::shutdown());
				goto retry;
			}

			uptr<schema> result;
			auto content_type = response->get_header("Content-Type");
			if (content_type == "application/json")
			{
				auto data = response->content.get_json();
				if (!data)
					coreturn expects_rt<schema*>(remote_exception(generate_error_message(response, reporter, "null", "node's response is not JSON compliant")));

				result = *data;
			}
			else if (content_type == "application/octet-stream")
				result = var::set::binary(response->content.get_text());
			else
				result = var::set::string(response->content.get_text());

			if (cache != cache_policy::no_cache && cache != cache_policy::no_cache_no_throttling && (response->status_code < 400 || response->status_code == 404))
			{
				result->add_ref();
				server->store_cache(asset, cache, hash, *result);
			}

			coreturn expects_rt<schema*>(result.reset());
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
			auto* implementation = oracle::server_node::get()->get_chain(asset);
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
		bool server_relay::has_distinct_url(const std::string_view& type) const
		{
			if (type.empty() || type == "auto")
				return !urls.empty();

			auto it = urls.find(key_lookup_cast(type));
			return it != urls.end();
		}
		bool server_relay::is_activity_allowed() const
		{
			return allowed;
		}
		const string& server_relay::get_node_url(const std::string_view& type) const
		{
			VI_ASSERT(!urls.empty(), "node does not have any urls");
			auto it = urls.find(key_lookup_cast(type));
			if (it != urls.end())
				return it->second;

			it = urls.find("auto");
			if (it != urls.end())
				return it->second;

			return urls.begin()->second;
		}
		string server_relay::get_node_url(const std::string_view& type, const std::string_view& endpoint) const
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
				case cache_policy::no_cache:
					return "no_cache";
				case cache_policy::no_cache_no_throttling:
					return "no_cache_no_throttling";
				case cache_policy::temporary_cache:
					return "temporary_cache";
				case cache_policy::blob_cache:
					return "blob_cache";
				case cache_policy::lifetime_cache:
					return "lifetime_cache";
				default:
					return "unset";
			}
		}
		string server_relay::generate_error_message(const expects_system<http::response_frame>& response, const error_reporter& reporter, const std::string_view& error_code, const std::string_view& error_message)
		{
			string_stream message;
			string method = reporter.method;
			message << "warden::" << reporter.type << "::" << stringify::to_lower(method) << " error: ";
			if (error_message.empty())
				message << "no response";
			else
				message << error_message;
			message << " (netc: " << (response ? response->status_code : 500) << ", " << reporter.type << "c: " << error_code << ")";
			return message.str();
		}

		relay_backend::relay_backend(const algorithm::asset_id& new_asset) noexcept : native_asset(algorithm::asset::base_id_of(new_asset)), interact(nullptr)
		{
		}
		relay_backend::~relay_backend() noexcept
		{
		}
		expects_promise_rt<schema*> relay_backend::execute_rpc(const std::string_view& method, schema_list&& args, cache_policy cache, const std::string_view& path)
		{
			auto* nodes = oracle::server_node::get()->get_nodes(native_asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rpc(native_asset, reporter, method, args, cache, path));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_rpc3(const std::string_view& method, schema_args&& args, cache_policy cache, const std::string_view& path)
		{
			auto* nodes = oracle::server_node::get()->get_nodes(native_asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rpc3(native_asset, reporter, method, args, cache, path));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_rest(const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache)
		{
			uptr<schema> body = args;
			auto* nodes = oracle::server_node::get()->get_nodes(native_asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_rest(native_asset, reporter, method, path, *body, cache));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_promise_rt<schema*> relay_backend::execute_http(const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			auto* nodes = oracle::server_node::get()->get_nodes(native_asset);
			if (!nodes || nodes->empty())
				coreturn expects_rt<schema*>(remote_exception("node not found"));

			size_t index = crypto::random();
			while (true)
			{
				server_relay::error_reporter reporter;
				index = (index + 1) % nodes->size();
				auto* node = *nodes->at(index);
				auto result = coawait(node->execute_http(native_asset, reporter, method, path, type, body, cache));
				if (interact) interact(node);
				if (result || !result.error().is_retry())
					coreturn result;
			}

			coreturn expects_rt<schema*>(remote_exception("node not found"));
		}
		expects_lr<algorithm::composition::cpubkey_t> relay_backend::to_composite_public_key(const std::string_view& public_key)
		{
			auto result = decode_public_key(public_key);
			if (!result)
				return result.error();

			return expects_lr<algorithm::composition::cpubkey_t>(algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*result));
		}
		expects_lr<ordered_map<string, wallet_link>> relay_backend::find_linked_addresses(const unordered_set<string>& addresses)
		{
			if (addresses.empty())
				return expects_lr<ordered_map<string, wallet_link>>(layer_exception("no addresses supplied"));

			auto* server = oracle::server_node::get();
			auto* implementation = server->get_chain(native_asset);
			if (!implementation)
				return expects_lr<ordered_map<string, wallet_link>>(layer_exception("chain not found"));

			auto results = server->get_links_by_addresses(native_asset, addresses);
			if (!results || results->empty())
				return expects_lr<ordered_map<string, wallet_link>>(layer_exception("no addresses found"));

			auto result = ordered_map<string, wallet_link>(results->begin(), results->end());
			return expects_lr<ordered_map<string, wallet_link>>(std::move(result));
		}
		expects_lr<ordered_map<string, wallet_link>> relay_backend::find_linked_addresses(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count)
		{
			auto* server = oracle::server_node::get();
			auto* implementation = server->get_chain(native_asset);
			if (!implementation)
				return expects_lr<ordered_map<string, wallet_link>>(layer_exception("chain not found"));

			auto results = server->get_links_by_owner(native_asset, owner, offset, count);
			if (!results || results->empty())
				return expects_lr<ordered_map<string, wallet_link>>(layer_exception("no addresses found"));

			auto result = ordered_map<string, wallet_link>(results->begin(), results->end());
			return expects_lr<ordered_map<string, wallet_link>>(std::move(result));
		}
		expects_lr<void> relay_backend::verify_node_compatibility(server_relay* node)
		{
			return expectation::met;
		}
		decimal relay_backend::to_value(const decimal& value) const
		{
			if (value.is_zero_or_nan())
				return value;

			decimal normalized = decimal(value);
			normalized.truncate((uint32_t)get_chainparams().divisibility.to_string().size() - 1);
			return normalized;
		}
		uint256_t relay_backend::to_baseline_value(const decimal& value) const
		{
			if (value.is_zero_or_nan())
				return uint256_t(0);

			decimal baseline = value * get_chainparams().divisibility;
			return uint256_t(baseline.truncate(0).to_string());
		}
		decimal relay_backend::from_baseline_value(const uint256_t& value) const
		{
			if (!value)
				return decimal::zero();

			return value.to_decimal() / get_chainparams().divisibility;
		}
		uint64_t relay_backend::get_retirement_block_number() const
		{
			return std::numeric_limits<uint64_t>::max();
		}
		bool relay_backend::has_token(const algorithm::asset_id& asset) const
		{
			return token_assets.contains(asset);
		}
		void relay_backend::apply_address_to_symbol_whitelist(const vector<std::pair<string, string>>& whitelist)
		{
			token_assets.clear();
			auto blockchain = algorithm::asset::blockchain_of(native_asset);
			for (auto& [contract_address, symbol] : whitelist)
				token_assets.insert(algorithm::asset::id_of(blockchain, symbol, contract_address));
		}

		relay_backend_utxo::balance_query::balance_query(const decimal& new_min_native_value, const unordered_map<algorithm::asset_id, decimal>& new_min_token_values) : min_native_value(new_min_native_value), min_token_values(new_min_token_values)
		{
		}

		relay_backend_utxo::relay_backend_utxo(const algorithm::asset_id& new_asset) noexcept : relay_backend(new_asset)
		{
		}
		expects_promise_rt<decimal> relay_backend_utxo::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
		{
			decimal balance = 0.0;
			auto outputs = calculate_utxo(link, optional::none);
			if (!outputs)
				return expects_promise_rt<decimal>(std::move(balance));

			auto contract_address = oracle::server_node::get()->get_contract_address(for_asset);
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
		expects_lr<vector<coin_utxo>> relay_backend_utxo::calculate_utxo(const wallet_link& link, option<balance_query>&& query)
		{
			vector<coin_utxo> values;
			decimal current_value = decimal::zero();
			auto* server = oracle::server_node::get();
			auto continue_accumulation = [&]()
			{
				if (!query)
					return true;

				for (auto& current_token_value : query->min_token_values)
				{
					if (current_token_value.second.is_positive())
						return true;
				}

				return current_value < query->min_native_value;
			};
			while (continue_accumulation())
			{
				const size_t count = 64;
				auto outputs = server->get_utxos(native_asset, link, values.size(), count);
				if (!outputs || outputs->empty())
					break;

				bool eof_value = false;
				bool eof_utxo = outputs->size() < count;
				values.reserve(values.size() + outputs->size());
				for (auto& output : *outputs)
				{
					if (query)
					{
						current_value += output.value;
						for (auto& token : output.tokens)
						{
							auto current_token_value = query->min_token_values.find(token.get_asset(native_asset));
							if (current_token_value != query->min_token_values.end())
								current_token_value->second -= token.value;
						}
					}

					eof_value = !continue_accumulation();
					values.emplace_back(std::move(output));
					if (eof_value)
						break;
				}
				if (eof_utxo || eof_value)
					break;
			}

			if (continue_accumulation() && query)
				return expects_lr<vector<coin_utxo>>(layer_exception("insufficient funds"));

			return expects_lr<vector<coin_utxo>>(std::move(values));
		}
		expects_lr<coin_utxo> relay_backend_utxo::get_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			return oracle::server_node::get()->get_utxo(native_asset, transaction_id, index);
		}
		expects_lr<void> relay_backend_utxo::update_utxo(const prepared_transaction& prepared)
		{
			for (auto& output : prepared.inputs)
			{
				if (!output.utxo.is_account())
					remove_utxo(output.utxo.transaction_id, output.utxo.index);
			}

			for (auto& input : prepared.outputs)
			{
				if (!input.is_account() && input.link.has_all())
					add_utxo(input);
			}

			return expects_lr<void>(expectation::met);
		}
		expects_lr<void> relay_backend_utxo::update_utxo(const computed_transaction& computed)
		{
			for (auto& output : computed.inputs)
			{
				if (!output.is_account())
					remove_utxo(output.transaction_id, output.index);
			}

			for (auto& input : computed.outputs)
			{
				if (!input.is_account() && input.link.has_all())
					add_utxo(input);
			}

			return expects_lr<void>(expectation::met);
		}
		expects_lr<void> relay_backend_utxo::add_utxo(const coin_utxo& output)
		{
			if (output.transaction_id.empty() || output.index == std::numeric_limits<uint64_t>::max())
				return expects_lr<void>(layer_exception("output must have a transaction id"));

			auto* server = oracle::server_node::get();
			auto* implementation = server->get_chain(native_asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			if (!output.link.has_address())
				return expects_lr<void>(layer_exception("output does not gave an address"));

			auto public_key_hash = implementation->decode_address(output.link.address);
			if (!public_key_hash)
				return expects_lr<void>(std::move(public_key_hash.error()));

			auto address = implementation->encode_address(*public_key_hash);
			if (!address)
				return expects_lr<void>(std::move(address.error()));

			auto link = server->get_link(native_asset, *address);
			if (!link)
				return expects_lr<void>(layer_exception("transaction output is not being watched"));

			coin_utxo copy = output;
			copy.link = std::move(*link);
			for (auto& item : copy.tokens)
			{
				public_key_hash = implementation->decode_address(item.contract_address);
				if (public_key_hash)
				{
					address = implementation->encode_address(*public_key_hash);
					if (address)
						item.contract_address = std::move(*address);
				}
			}

			auto status = server->add_utxo(native_asset, copy);
			if (status)
				return expects_lr<void>(expectation::met);

			remove_utxo(copy.transaction_id, copy.index);
			return expects_lr<void>(std::move(status.error()));
		}
		expects_lr<void> relay_backend_utxo::remove_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			if (transaction_id.empty() || index == std::numeric_limits<uint64_t>::max())
				return expects_lr<void>(layer_exception("output must have a transaction id"));

			return oracle::server_node::get()->remove_utxo(native_asset, transaction_id, index);
		}
		decimal relay_backend_utxo::get_utxo_value(const vector<coin_utxo>& values, option<string>&& contract_address)
		{
			decimal value = 0.0;
			if (contract_address)
			{
				auto* server = oracle::server_node::get();
				auto* implementation = server->get_chain(native_asset);
				if (!implementation)
					return value;

				auto public_key_hash = implementation->decode_address(*contract_address);
				if (!public_key_hash)
					return value;

				auto address = implementation->encode_address(*public_key_hash);
				if (!address)
					return value;

				for (auto& item : values)
				{
					auto* server = oracle::server_node::get();
					auto* implementation = server->get_chain(native_asset);
					for (auto& token : item.tokens)
					{
						if (token.contract_address == *address)
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
		relay_backend_utxo* relay_backend_utxo::from_relay(relay_backend* base)
		{
			return base->get_chainparams().routing == routing_policy::utxo ? (relay_backend_utxo*)base : nullptr;
		}

		string address_util::encode_tag_address(const std::string_view& address, const std::string_view& destination_tag)
		{
			auto split = address.find(':');
			size_t address_size = split == string::npos ? address.size() : split;
			if (destination_tag.empty())
				return string(address.substr(0, address_size));

			return stringify::text("%.*s:%.*s", (int)address_size, address.data(), (int)destination_tag.size(), destination_tag.data());
		}
		std::pair<string, string> address_util::decode_tag_address(const std::string_view& address_destination_tag)
		{
			auto split = address_destination_tag.find(':');
			if (split == string::npos || split + 1 >= address_destination_tag.size())
				return std::make_pair(string(address_destination_tag), string());

			return std::make_pair(string(address_destination_tag.substr(0, split)), string(address_destination_tag.substr(split + 1)));
		}
	}
}
