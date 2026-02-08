#include "superchain.h"
#include "../storage/superchainstate.h"
#include "../translation/bitcoin.h"
#include "../translation/cardano.h"
#include "../translation/ethereum.h"
#include "../translation/ripple.h"
#include "../translation/solana.h"
#include "../translation/stellar.h"
#include "../translation/tron.h"
#include "../translation/monero.h"
#include <sstream>

namespace tangent
{
	namespace superchain
	{
		template <typename t>
		static bridge::invocation_callback chain(bridge* server)
		{
			return [server](const std::string_view& blockchain) -> bool
			{
				algorithm::asset_id asset = algorithm::asset::id_of(blockchain);
				if (server->has_network(asset))
					return false;

				server->add_network<t>(asset);
				return true;
			};
		}
		static value_transfer normalize_value(translation_unit* implementation, const value_transfer& to)
		{
			auto result = to;
			result.value = implementation->to_value(result.value);
			return result;
		}
		static decimal normalize_value(translation_unit* implementation, const decimal& value)
		{
			return implementation->to_value(value);
		}
		static string normalize_error(const expects_system<http::response_frame>& response, const bridge::error_reporter& reporter, const std::string_view& error_code, const std::string_view& error_message)
		{
			string_stream message;
			string method = reporter.method;
			message << "" << reporter.type << "::" << stringify::to_lower(method) << " error: ";
			if (error_message.empty())
				message << "no response";
			else
				message << error_message;
			message << " (netc: " << (response ? response->status_code : 500) << ", " << reporter.type << "c: " << error_code << ")";
			return message.str();
		}
		static std::string_view random_user_agent()
		{
			std::string_view user_agents[] =
			{
				"Googlebot/2.1 (+http://www.google.com/bot.html)",
				"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
				"Mozilla/5.0 (compatible; adidxbot/2.0;  http://www.bing.com/bingbot.htm)",
				"LinkedInBot/1.0 (compatible; Mozilla/5.0; Jakarta Commons-HttpClient/4.3 +http://www.linkedin.com)",
				"Mozilla/5.0 (compatible; Yahoo! Slurp/3.0; http://help.yahoo.com/help/us/ysearch/slurp)",
				"librabot/2.0 (+http://search.msn.com/msnbot.htm)",
				"FAST-WebCrawler/3.7 (atw-crawler at fast dot no; http://fast.no/support/crawler.asp)",
				"DuckDuckBot/1.1; (+http://duckduckgo.com/duckduckbot.html)",
				"Wget/1.14 (linux-gnu)",
				"Python-urllib/3.7",
				"python-requests/2.9.2",
				"Python/3.9 aiohttp/3.7.3",
				"istellabot-nutch/Nutch-1.10",
				"2Bone_LinkChecker/1.0 libwww-perl/6.03",
				"okhttp/4.1.0",
				"PocketParser/2.0 (+https://getpocket.com/pocketparser_ua)"
			};
			size_t user_agents_size = sizeof(user_agents) / sizeof(user_agents[0]);
			return user_agents[(size_t)math64u::random() % user_agents_size];
		}
		static string join_url_path(const std::string_view& url, const std::string_view& path)
		{
			auto result = string(url);
			if (result.empty() || path.empty())
				return result;

			if (result.back() == '/' && path.front() == '/')
				result.pop_back();
			else if (result.back() != '/' && path.front() != '/')
				result.push_back('/');

			result += path;
			return result;
		}
		static expects_rt<format::tree> solve_rpc_response(format::tree& response, bridge::error_reporter* reporter)
		{
			if (response.has("error.code"))
			{
				string code = response.child_var("error.code").as_blob();
				string description = response.has("error.message") ? response.child_var("error.message").as_blob() : "no error description";
				return expects_rt<format::tree>(remote_exception(normalize_error(expects_system<http::response_frame>(system_exception()), reporter ? *reporter : bridge::error_reporter(), code, description)));
			}
			else if (response.has("result.error_code"))
			{
				string code = response.child_var("result.error_code").as_blob();
				string description = response.has("result.error_message") ? response.child_var("result.error_message").as_blob() : "no error description";
				return expects_rt<format::tree>(remote_exception(normalize_error(expects_system<http::response_frame>(system_exception()), reporter ? *reporter : bridge::error_reporter(), code, description)));
			}

			auto* result = (format::tree*)response.child("result");
			if (reporter != nullptr && !result)
			{
				string description = response.value.is_string() ? response.value.as_blob() : "no error description";
				return expects_rt<format::tree>(remote_exception(normalize_error(expects_system<http::response_frame>(system_exception()), reporter ? *reporter : bridge::error_reporter(), "null", description)));
			}
			else if (!reporter && !result)
				return expects_rt<format::tree>(std::move(response));

			return expects_rt<format::tree>(std::move(*result));
		};

		wallet_link::wallet_link(const uint256_t& new_hash, const std::string_view& new_public_key, const std::string_view& new_address) : hash(new_hash), public_key(new_public_key), address(new_address)
		{
		}
		bool wallet_link::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_string(public_key);
			stream->write_string(address);
			stream->write_integer(hash);
			return true;
		}
		bool wallet_link::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_string(stream.read_type(), &public_key))
				return false;

			if (!stream.read_string(stream.read_type(), &address))
				return false;

			if (!stream.read_integer(stream.read_type(), &hash))
				return false;

			return true;
		}
		format::tree wallet_link::as_tree() const
		{
			format::tree data;
			data.set("hash", algorithm::encoding::serialize_uint256(hash));
			data.set("public_key", public_key.empty() ? format::variable() : format::variable(public_key));
			data.set("address", address.empty() ? format::variable() : format::variable(address));
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
			if (has_hash())
				return search_term::hash;
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
			else if (has_hash())
				return search_term::hash;
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

			if (has_hash())
				return algorithm::encoding::encode_0xhex256(hash);

			return "(confidential)";
		}
		bool wallet_link::has_hash() const
		{
			return hash > 0;
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
			return has_hash() && has_public_key() && has_address();
		}
		bool wallet_link::has_any() const
		{
			return has_hash() || has_public_key() || has_address();
		}
		uint32_t wallet_link::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view wallet_link::as_instance_typename()
		{
			return "wallet_link";
		}
		wallet_link wallet_link::from_hash(const uint256_t& new_hash)
		{
			return wallet_link(new_hash, std::string_view(), std::string_view());
		}
		wallet_link wallet_link::from_public_key(const std::string_view& new_public_key)
		{
			return wallet_link(0, new_public_key, std::string_view());
		}
		wallet_link wallet_link::from_address(const std::string_view& new_address)
		{
			return wallet_link(0, std::string_view(), new_address);
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
			return algorithm::arithmetic::fixed(decimals > 0 ? decimal("1" + string(decimals, '0')) : decimal(1));
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
		uint256_t coin_utxo::token_utxo::as_hash() const
		{
			format::wo_stream message;
			message.write_string(contract_address);
			message.write_string(symbol);
			message.write_decimal(value);
			message.write_integer(decimals);
			return message.hash();
		}

		coin_utxo::coin_utxo(wallet_link&& new_link, hash_map<algorithm::asset_id, decimal>&& new_values) : link(std::move(new_link)), index(std::numeric_limits<uint32_t>::max())
		{
			for (auto& [asset, asset_value] : new_values)
			{
				if (!algorithm::asset::token_of(asset).empty())
				{
					apply_token_value(algorithm::asset::handle_of(asset), std::string_view(), std::move(asset_value), 0);
					if (transaction_id.empty())
						transaction_id = algorithm::asset::handle_of(algorithm::asset::base_id_of(asset));
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
				for (auto& [hash, item] : tokens)
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

				auto next = token_utxo(contract_address, symbol, new_value, decimals);
				tokens[next.as_hash()] = std::move(next);
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

			for (auto& [hash, item] : tokens)
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

			stream->write_string(transaction_id);
			stream->write_integer(index);
			stream->write_decimal(value);
			stream->write_integer((uint32_t)tokens.size());
			for (auto& [hash, item] : tokens)
			{
				stream->write_string(item.contract_address);
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

				tokens[token.as_hash()] = std::move(token);
			}

			return true;
		}
		bool coin_utxo::is_account() const
		{
			return index == std::numeric_limits<uint32_t>::max();
		}
		bool coin_utxo::is_valid_input() const
		{
			for (auto& [hash, token] : tokens)
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

			for (auto& [hash, token] : tokens)
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
		format::tree coin_utxo::as_tree() const
		{
			bool account = is_account();
			format::tree data;
			data.set("link", link.as_tree());
			if (!account)
			{
				data.set("transaction_id", transaction_id.empty() ? format::variable() : format::variable(transaction_id));
				data.set("index", format::variable(index));
			}
			else
				data.set("asset", algorithm::asset::serialize(get_asset(0)));
			data.set("value", format::variable(value));
			data.set("type", format::variable(is_account() ? "account" : "utxo"));
			auto* tokens_data = data.set("tokens", format::tree::list());
			for (auto& [hash, item] : tokens)
			{
				auto* token_data = tokens_data->push(format::tree::map());
				if (!item.is_account())
				{
					token_data->set("contract_address", format::variable(item.contract_address));
					token_data->set("symbol", format::variable(item.symbol));
					token_data->set("value", format::variable(item.value));
					token_data->set("decimals", format::variable(item.decimals));
				}
				else
				{
					token_data->set("asset", algorithm::asset::serialize(item.get_asset(0)));
					token_data->set("value", format::variable(item.value));
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
			return "coin_utxo";
		}

		void computed_transaction::add_input(coin_utxo&& input)
		{
			inputs[input.as_hash()] = std::move(input);
		}
		void computed_transaction::add_output(coin_utxo&& output)
		{
			outputs[output.as_hash()] = std::move(output);
		}
		bool computed_transaction::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "stream should be set");
			stream->write_integer(block_id);
			stream->write_string(transaction_id);
			stream->write_integer((uint32_t)inputs.size());
			for (auto& [hash, item] : inputs)
			{
				if (!item.store_payload(stream))
					return false;
			}

			stream->write_integer((uint32_t)outputs.size());
			for (auto& [hash, item] : outputs)
			{
				if (!item.store_payload(stream))
					return false;
			}

			return true;
		}
		bool computed_transaction::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &block_id))
				return false;

			if (!stream.read_string(stream.read_type(), &transaction_id))
				return false;

			uint32_t inputs_size;
			if (!stream.read_integer(stream.read_type(), &inputs_size))
				return false;

			inputs.clear();
			for (size_t i = 0; i < inputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				inputs[next.as_hash()] = std::move(next);
			}

			uint32_t outputs_size;
			if (!stream.read_integer(stream.read_type(), &outputs_size))
				return false;

			outputs.clear();
			for (size_t i = 0; i < outputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				outputs[next.as_hash()] = std::move(next);
			}

			return true;
		}
		bool computed_transaction::is_valid() const
		{
			if (inputs.empty() || outputs.empty() || stringify::is_empty_or_whitespace(transaction_id))
				return false;

			hash_map<algorithm::asset_id, decimal> balance;
			for (auto& [hash, input] : inputs)
			{
				if (!input.is_valid_output())
					return false;

				auto& balance_value = balance[0];
				balance_value = balance_value.is_nan() ? -input.value : (balance_value - input.value);
				for (auto& [token_hash, token] : input.tokens)
				{
					auto& token_balance_value = balance[algorithm::asset::id_of("_", token.symbol, token.contract_address)];
					token_balance_value = token_balance_value.is_nan() ? -token.value : (token_balance_value - token.value);
				}
			}

			for (auto& [hash, output] : outputs)
			{
				if (!output.is_valid_output())
					return false;

				auto& balance_value = balance[0];
				balance_value = balance_value.is_nan() ? output.value : (balance_value + output.value);
				for (auto& [token_hash, token] : output.tokens)
				{
					auto& token_balance_value = balance[algorithm::asset::id_of("_", token.symbol, token.contract_address)];
					token_balance_value = token_balance_value.is_nan() ? token.value : (token_balance_value + token.value);
				}
			}

			for (auto& balance_value : balance)
			{
				if (balance_value.second > 0.0)
					return false;
			}

			return true;
		}
		uint256_t computed_transaction::as_attestation_hash() const
		{
			return algorithm::hashing::hash256i(transaction_id);
		}
		format::tree computed_transaction::as_tree() const
		{
			format::tree data;
			data.set("transaction_id", format::variable(transaction_id));
			data.set("block_id", algorithm::encoding::serialize_uint256(block_id));
			auto* input_data = data.set("inputs", format::tree::list());
			for (auto& [hash, input] : inputs)
				input_data->push(input.as_tree());
			auto* output_data = data.set("outputs", format::tree::list());
			for (auto& [hash, output] : outputs)
				output_data->push(output.as_tree());
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
			return "computed_transaction";
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
		prepared_transaction& prepared_transaction::requires_account_input(algorithm::composition::type new_alg, wallet_link&& signer, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, hash_map<algorithm::asset_id, decimal>&& input)
		{
			coin_utxo item = coin_utxo(std::move(signer), std::move(input));
			return requires_input(new_alg, new_public_key, new_message, new_message_size, std::move(item));
		}
		prepared_transaction& prepared_transaction::requires_output(coin_utxo&& output)
		{
			outputs.push_back(std::move(output));
			return *this;
		}
		prepared_transaction& prepared_transaction::requires_account_output(const std::string_view& to_address, hash_map<algorithm::asset_id, decimal>&& output)
		{
			outputs.push_back(coin_utxo(wallet_link::from_address(to_address), std::move(output)));
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
			for (size_t i = 0; i < inputs_size; i++)
			{
				signable_coin_utxo next;
				if (!stream.read_integer(stream.read_type(), (uint8_t*)&next.alg))
					return false;

				string public_key_assembly;
				if (!stream.read_string(stream.read_type(), &public_key_assembly))
					return false;

				string signature_assembly;
				if (!stream.read_string(stream.read_type(), &signature_assembly))
					return false;

				string message_assembly;
				if (!stream.read_string(stream.read_type(), &message_assembly))
					return false;

				next.public_key.resize(public_key_assembly.size());
				next.message.resize(message_assembly.size());
				next.signature.resize(signature_assembly.size());
				memcpy(next.public_key.data(), public_key_assembly.data(), public_key_assembly.size());
				memcpy(next.signature.data(), signature_assembly.data(), signature_assembly.size());
				memcpy(next.message.data(), message_assembly.data(), message_assembly.size());
				if (!next.utxo.load_payload(stream))
					return false;

				inputs.push_back(std::move(next));
			}

			uint32_t outputs_size;
			if (!stream.read_integer(stream.read_type(), &outputs_size))
				return false;

			outputs.clear();
			for (size_t i = 0; i < outputs_size; i++)
			{
				coin_utxo next;
				if (!next.load_payload(stream))
					return false;

				outputs.push_back(std::move(next));
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
				else if (!item.is_account() && !item.transaction_id.empty())
					return status::invalid;
			}

			for (auto& item : inputs)
			{
				if (item.signature.empty())
					return status::signable;
			}

			return status::finalizeable;
		}
		format::tree prepared_transaction::as_tree() const
		{
			std::string_view status;
			switch (as_status())
			{
				case status::invalid:
					status = "invalid";
					break;
				case status::signable:
					status = "signable";
					break;
				case status::finalizeable:
					status = "finalizeable";
					break;
				default:
					status = "unknown";
					break;
			}

			format::tree data;
			auto* input_data = data.set("inputs", format::tree::list());
			for (auto& input : inputs)
			{
				auto* signer = input_data->push(format::tree::map());
				signer->set("utxo", input.utxo.as_tree());
				switch (input.alg)
				{
					case algorithm::composition::type::ed25519:
						signer->set("type", format::variable("ed25519"));
						break;
					case algorithm::composition::type::ed25519_clsag:
						signer->set("type", format::variable("ed25519_clsag"));
						break;
					case algorithm::composition::type::secp256k1:
						signer->set("type", format::variable("secp256k1"));
						break;
					case algorithm::composition::type::secp256k1_schnorr:
						signer->set("type", format::variable("secp256k1_schnorr"));
						break;
					default:
						signer->set("type", format::variable());
						break;
				}
				signer->set("public_key", input.public_key.empty() ? format::variable() : format::variable(format::util::encode_0xhex(std::string_view((char*)input.public_key.data(), input.public_key.size()))));
				signer->set("signature", input.signature.empty() ? format::variable() : format::variable(format::util::encode_0xhex(std::string_view((char*)input.signature.data(), input.signature.size()))));
				signer->set("message", format::variable(format::util::encode_0xhex(std::string_view((char*)input.message.data(), input.message.size()))));
			}
			auto* output_data = data.set("outputs", format::tree::list());
			for (auto& output : outputs)
				output_data->push(output.as_tree());
			data.set("abi", format::variables_util::serialize(abi));
			data.set("status", format::variable(status));
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
			return "prepared_transaction";
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
			return prepared.as_status() == prepared_transaction::status::finalizeable && !calldata.empty() && !hashdata.empty();
		}
		computed_transaction finalized_transaction::as_computed() const
		{
			computed_transaction computed;
			computed.transaction_id = hashdata;
			computed.block_id = locktime;
			for (auto& output : prepared.outputs)
				computed.outputs[output.as_hash()] = output;
			for (auto& input : prepared.inputs)
				computed.inputs[input.utxo.as_hash()] = input.utxo;
			return computed;
		}
		format::tree finalized_transaction::as_tree() const
		{
			format::tree data;
			data.set("prepared", prepared.as_tree());
			data.set("computed", as_computed().as_tree());
			data.set("calldata", format::variable(calldata));
			data.set("hashdata", format::variable(hashdata));
			data.set("locktime", algorithm::encoding::serialize_uint256(locktime));
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
			return "finalized_transaction";
		}

		void transaction_logs::report_logs(const algorithm::asset_id& asset, const network_options& options, size_t requests)
		{
			auto blockchain = algorithm::asset::blockchain_of(asset);
			VI_INFO("%s block %s found (height: %i, sync: %.2f%%, txns: %i, rpb: %i)",
				blockchain.c_str(),
				block_hash.c_str(),
				(int)block_height,
				options.get_checkpoint_percentage(),
				(int)receipts.size(),
				(int)requests);

			for (auto& tx : receipts)
			{
				string transfer_logs = stringify::text(
					"%s transaction %s found (block: %" PRIu64 ")\n",
					blockchain.c_str(),
					tx.transaction_id.c_str(), tx.block_id);
				for (auto& [hash, input] : tx.inputs)
				{
					transfer_logs += stringify::text("  %s spends %s %s\n", input.link.as_name().c_str(), input.value.to_string().c_str(), blockchain.c_str());
					for (auto& [token_hash, token] : input.tokens)
						transfer_logs += stringify::text("    with %s %s\n", token.value.to_string().c_str(), algorithm::asset::name_of(token.get_asset(asset)).c_str());
				}
				for (auto& [hash, output] : tx.outputs)
				{
					transfer_logs += stringify::text("  %s receives %s %s\n", output.link.as_name().c_str(), output.value.to_string().c_str(), blockchain.c_str());
					for (auto& [token_hash, token] : output.tokens)
						transfer_logs += stringify::text("    with %s %s\n", token.value.to_string().c_str(), algorithm::asset::name_of(token.get_asset(asset)).c_str());
				}
				if (transfer_logs.back() == '\n')
					transfer_logs.erase(transfer_logs.end() - 1);

				VI_INFO("%s", transfer_logs.c_str());
			}
		}

		decimal computed_fee::get_max_fee() const
		{
			switch (type)
			{
				case fee_type::fee:
					return fee.fee_rate * decimal(fee.byte_rate);
				case fee_type::gas:
					return (gas.gas_premium + gas.gas_price) * gas.gas_limit.to_decimal();
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
					return !gas.gas_premium.is_nan() && !gas.gas_premium.is_negative() && gas.gas_price.is_positive() && gas.gas_limit > 0;
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
		computed_fee computed_fee::fee_per_gas_priority(const decimal& premium, const decimal& priority_price, const uint256_t& limit)
		{
			computed_fee result;
			result.type = fee_type::gas;
			result.gas.gas_premium = premium;
			result.gas.gas_price = priority_price;
			result.gas.gas_limit = limit;
			return result;
		}

		format::tree computed_wallet::as_tree() const
		{
			auto data = format::tree::map();
			data.set("seed", format::variable(format::util::encode_0xhex(std::string_view((char*)seed.data(), seed.size()))));
			data.set("secret_key", format::variable(format::util::encode_0xhex(std::string_view((char*)secret_key.data(), secret_key.size()))));
			data.set("public_key", format::variable(format::util::encode_0xhex(std::string_view((char*)public_key.data(), public_key.size()))));
			data.set("encoded_secret_key", format::variable(encoded_secret_key.heap()));
			data.set("encoded_public_key", format::variable(encoded_public_key));
			auto* addresses_data = data.set("addresses", format::tree::list());
			for (auto encoded_address : encoded_addresses)
			{
				auto intemediate = addresses.find(encoded_address.first);
				auto* address = addresses_data->push(format::tree::map());
				address->set("version", format::variable(encoded_address.first));
				address->set("address", intemediate != addresses.end() ? format::variable(format::util::encode_0xhex(intemediate->second)) : format::variable());
				address->set("encoded_address", format::variable(encoded_address.second));
			}
			return data;
		}

		void network_options::set_checkpoint_from_block(uint64_t block_height)
		{
			state.inital_block_height = block_height;
			state.index_block_height = block_height;
			state.target_block_height = 0;
		}
		void network_options::set_checkpoint_to_block(uint64_t block_height)
		{
			if (!state.inital_block_height || !state.index_block_height)
				set_checkpoint_from_block(block_height > 1 ? block_height - 1 : block_height);
			state.target_block_height = block_height;
		}
		uint64_t network_options::get_next_block_height(uint64_t block_count)
		{
			block_count = std::max<uint64_t>(1, block_count);
			uint64_t result = (state.index_block_height / block_count) * block_count;
			state.index_block_height = result + block_count;
			return result;
		}
		bool network_options::has_next_block_height(uint64_t block_count) const
		{
			block_count = std::max<uint64_t>(1, block_count) - 1;
			return state.index_block_height + block_count <= state.target_block_height;
		}
		bool network_options::has_target_block_height() const
		{
			return state.target_block_height > 0;
		}
		double network_options::get_checkpoint_percentage() const
		{
			if (!state.inital_block_height || !state.index_block_height || !state.target_block_height)
				return 0.0;

			double multiplier = 100.0;
			double current_value = (double)((state.index_block_height - 1) - state.inital_block_height);
			double target_value = (double)(state.target_block_height - state.inital_block_height);
			if (current_value == target_value)
				return multiplier;

			double percentage = multiplier * current_value / target_value;
			return std::min(std::floor(percentage * multiplier) / multiplier, multiplier);
		}

		string address_util::encode_tag_address(const std::string_view& address, const std::string_view& destination_tag)
		{
			auto split = address.rfind('#');
			size_t address_size = split == string::npos ? address.size() : split;
			if (destination_tag.empty() || destination_tag == "0")
				return string(address.substr(0, address_size));

			return stringify::text("%.*s#%.*s", (int)address_size, address.data(), (int)destination_tag.size(), destination_tag.data());
		}
		std::pair<string, string> address_util::decode_tag_address(const std::string_view& address_destination_tag)
		{
			auto split = address_destination_tag.rfind('#');
			if (split == string::npos || split + 1 >= address_destination_tag.size())
				return std::make_pair(string(address_destination_tag), string());

			return std::make_pair(string(address_destination_tag.substr(0, split)), string(address_destination_tag.substr(split + 1)));
		}

		translation_unit::translation_unit(const algorithm::asset_id& new_asset) noexcept : native_asset(algorithm::asset::base_id_of(new_asset)), round_robin_index(crypto::random()), allow_any_token(true)
		{
		}
		translation_unit::~translation_unit() noexcept
		{
		}
		expects_promise_rt<format::tree> translation_unit::execute_rpc(const std::string_view& method, format::tree&& args, cache_policy cache, const std::string_view& path)
		{
			string ref_method = string(method), ref_path = string(path);
			return coasync<expects_rt<format::tree>>([this, cache, args = std::move(args), ref_method = std::move(ref_method), ref_path = std::move(ref_path)]() mutable -> expects_promise_rt<format::tree>
			{
				auto* instance = bridge::get()->get_network_instance(native_asset);
				auto exception = remote_exception::retry_later();
				auto reporter = bridge::error_reporter();
				for (size_t i = 0; instance != nullptr && i < instance->connections.size(); i++)
				{
					auto& connection = instance->connections[(++round_robin_index) % instance->connections.size()];
					auto result = coawait(bridge::get()->execute_rpc(native_asset, connection, reporter, ref_method, args, cache, ref_path, false));
					if (result || !result.error().is_retry())
						coreturn result;
					else if (!result)
						exception = std::move(result.error());
				}
				coreturn expects_rt<format::tree>(std::move(exception));
			});
		}
		expects_promise_rt<format::tree> translation_unit::execute_rpc_multi(const std::string_view& method, format::tree&& args, cache_policy cache, const std::string_view& path)
		{
			string ref_method = string(method), ref_path = string(path);
			return coasync<expects_rt<format::tree>>([this, cache, args = std::move(args), ref_method = std::move(ref_method), ref_path = std::move(ref_path)]() mutable -> expects_promise_rt<format::tree>
			{
				auto* instance = bridge::get()->get_network_instance(native_asset);
				auto exception = remote_exception::retry_later();
				auto reporter = bridge::error_reporter();
				for (size_t i = 0; instance != nullptr && i < instance->connections.size(); i++)
				{
					auto& connection = instance->connections[(++round_robin_index) % instance->connections.size()];
					auto result = coawait(bridge::get()->execute_rpc(native_asset, connection, reporter, ref_method, args, cache, ref_path, true));
					if (result || !result.error().is_retry())
						coreturn result;
					else if (!result)
						exception = std::move(result.error());
				}
				coreturn expects_rt<format::tree>(std::move(exception));
			});
		}
		expects_promise_rt<format::tree> translation_unit::execute_rest(const std::string_view& method, const std::string_view& path, format::tree&& args, cache_policy cache)
		{
			string ref_method = string(method), ref_path = string(path);
			return coasync<expects_rt<format::tree>>([this, cache, args = std::move(args), ref_method = std::move(ref_method), ref_path = std::move(ref_path)]() mutable -> expects_promise_rt<format::tree>
			{
				auto* instance = bridge::get()->get_network_instance(native_asset);
				auto exception = remote_exception::retry_later();
				auto reporter = bridge::error_reporter();
				for (size_t i = 0; instance != nullptr && i < instance->connections.size(); i++)
				{
					auto& connection = instance->connections[(++round_robin_index) % instance->connections.size()];
					auto result = coawait(bridge::get()->execute_rest(native_asset, connection, reporter, ref_method, ref_path, args, cache));
					if (result || !result.error().is_retry())
						coreturn result;
					else if (!result)
						exception = std::move(result.error());
				}
				coreturn expects_rt<format::tree>(std::move(exception));
			});
		}
		expects_promise_rt<format::tree> translation_unit::execute_http(const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			string ref_method = string(method), ref_path = string(path), ref_type = string(type), ref_body = string(body);
			return coasync<expects_rt<format::tree>>([this, cache, ref_method = std::move(ref_method), ref_path = std::move(ref_path), ref_type = std::move(ref_type), ref_body = std::move(ref_body)]() mutable -> expects_promise_rt<format::tree>
			{
				auto* instance = bridge::get()->get_network_instance(native_asset);
				auto exception = remote_exception::retry_later();
				auto reporter = bridge::error_reporter();
				for (size_t i = 0; instance != nullptr && i < instance->connections.size(); i++)
				{
					auto& connection = instance->connections[(++round_robin_index) % instance->connections.size()];
					auto result = coawait(bridge::get()->execute_http(native_asset, connection, reporter, ref_method, ref_path, ref_type, ref_body, cache));
					if (result || !result.error().is_retry())
						coreturn result;
					else if (!result)
						exception = std::move(result.error());
				}
				coreturn expects_rt<format::tree>(std::move(exception));
			});
		}
		expects_promise_rt<uint64_t> translation_unit::get_linked_block_height(uint64_t seen_block_height)
		{
			return expects_promise_rt<uint64_t>(remote_exception("not supported"));
		}
		expects_lr<algorithm::composition::cpubkey_t> translation_unit::to_composite_public_key(const std::string_view& public_key)
		{
			auto result = decode_public_key(public_key);
			if (!result)
				return result.error();

			return expects_lr<algorithm::composition::cpubkey_t>(algorithm::composition::to_cstorage<algorithm::composition::cpubkey_t>(*result));
		}
		expects_lr<btree_map<string, wallet_link>> translation_unit::find_linked_addresses(const hash_set<string>& addresses)
		{
			if (addresses.empty())
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("no addresses supplied"));

			auto* implementation = bridge::get()->get_network(native_asset);
			if (!implementation)
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("chain not found"));

			auto results = bridge::get()->get_links_by_addresses(native_asset, addresses);
			if (!results || results->empty())
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("no addresses found"));

			auto result = btree_map<string, wallet_link>(results->begin(), results->end());
			return expects_lr<btree_map<string, wallet_link>>(std::move(result));
		}
		expects_lr<btree_map<string, wallet_link>> translation_unit::find_linked_addresses(const uint256_t& hash, size_t offset, size_t count)
		{
			auto* implementation = bridge::get()->get_network(native_asset);
			if (!implementation)
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("chain not found"));

			auto results = bridge::get()->get_links_by_hash(native_asset, hash, offset, count);
			if (!results || results->empty())
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("no addresses found"));

			auto result = btree_map<string, wallet_link>(results->begin(), results->end());
			return expects_lr<btree_map<string, wallet_link>>(std::move(result));
		}
		expects_lr<btree_map<string, wallet_link>> translation_unit::find_linked_addresses(size_t offset, size_t count)
		{
			auto* implementation = bridge::get()->get_network(native_asset);
			if (!implementation)
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("chain not found"));

			auto results = bridge::get()->get_links_with_hash(native_asset, offset, count);
			if (!results || results->empty())
				return expects_lr<btree_map<string, wallet_link>>(layer_exception("no addresses found"));

			auto result = btree_map<string, wallet_link>(results->begin(), results->end());
			return expects_lr<btree_map<string, wallet_link>>(std::move(result));
		}
		decimal translation_unit::to_value(const decimal& value) const
		{
			if (value.is_zero_or_nan())
				return value;

			decimal normalized = decimal(value);
			normalized.truncate((uint32_t)get_chainparams().divisibility.to_string().size() - 1);
			return normalized;
		}
		uint256_t translation_unit::to_baseline_value(const decimal& value) const
		{
			if (value.is_zero_or_nan())
				return uint256_t(0);

			decimal baseline = value * get_chainparams().divisibility;
			return uint256_t(baseline.truncate(0).to_string());
		}
		decimal translation_unit::from_baseline_value(const uint256_t& value) const
		{
			if (!value)
				return decimal::zero();

			return value.to_decimal() / get_chainparams().divisibility;
		}

		utxo_translation_unit::balance_query::balance_query(const decimal& new_min_native_value, const hash_map<algorithm::asset_id, decimal>& new_min_token_values) : min_token_values(new_min_token_values), min_native_value(new_min_native_value)
		{
		}

		utxo_translation_unit::utxo_translation_unit(const algorithm::asset_id& new_asset) noexcept : translation_unit(new_asset)
		{
		}
		expects_promise_rt<decimal> utxo_translation_unit::calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link)
		{
			decimal balance = 0.0;
			auto outputs = calculate_utxo(link, optional::none);
			if (!outputs)
				return expects_promise_rt<decimal>(std::move(balance));

			auto contract_address = bridge::get()->get_contract_address(for_asset);
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
		expects_lr<vector<coin_utxo>> utxo_translation_unit::calculate_utxo(const wallet_link& link, option<balance_query>&& query)
		{
			vector<coin_utxo> values;
			decimal current_value = decimal::zero();
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
				auto outputs = bridge::get()->get_utxos(native_asset, link, values.size(), count);
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
						for (auto& [hash, token] : output.tokens)
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
		expects_lr<coin_utxo> utxo_translation_unit::get_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			return bridge::get()->get_utxo(native_asset, transaction_id, index);
		}
		expects_lr<void> utxo_translation_unit::update_utxo(const computed_transaction& computed)
		{
			for (auto& [hash, output] : computed.inputs)
			{
				if (output.is_account())
					continue;

				auto result = spend_utxo(output.transaction_id, output.index, computed.block_id);
				if (!result)
					return result;
			}

			for (auto& [hash, input] : computed.outputs)
			{
				if (input.is_account() || !input.link.has_all())
					continue;

				auto result = receive_utxo(computed.transaction_id, input.index, computed.block_id, input);
				if (!result)
					return result;
			}

			return expectation::met;
		}
		expects_lr<void> utxo_translation_unit::receive_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t receiver_block_id, const coin_utxo& output)
		{
			if (transaction_id.empty() || index == std::numeric_limits<uint64_t>::max())
				return expects_lr<void>(layer_exception("output must have a transaction id"));

			auto* implementation = bridge::get()->get_network(native_asset);
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

			auto link = bridge::get()->get_link(native_asset, *address);
			if (!link)
				return expects_lr<void>(layer_exception("transaction output is not being watched"));

			coin_utxo copy = output;
			copy.transaction_id = transaction_id;
			copy.index = index;
			copy.link = std::move(*link);
			for (auto& [hash, item] : copy.tokens)
			{
				public_key_hash = implementation->decode_address(item.contract_address);
				if (public_key_hash)
				{
					address = implementation->encode_address(*public_key_hash);
					if (address)
						item.contract_address = std::move(*address);
				}
			}

			return bridge::get()->receive_utxo(native_asset, transaction_id, index, receiver_block_id, copy);
		}
		expects_lr<void> utxo_translation_unit::spend_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t spender_block_id)
		{
			if (transaction_id.empty() || index == std::numeric_limits<uint64_t>::max())
				return expects_lr<void>(layer_exception("output must have a transaction id"));

			return bridge::get()->spend_utxo(native_asset, transaction_id, index, spender_block_id);
		}
		decimal utxo_translation_unit::get_utxo_value(const vector<coin_utxo>& values, option<string>&& contract_address)
		{
			decimal value = 0.0;
			if (contract_address)
			{
				auto* implementation = bridge::get()->get_network(native_asset);
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
					for (auto& [hash, token] : item.tokens)
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
		utxo_translation_unit* utxo_translation_unit::from(translation_unit* base)
		{
			return base->get_chainparams().routing == routing_policy::utxo ? (utxo_translation_unit*)base : nullptr;
		}

		bridge::bridge() noexcept
		{
			auto& chains = get_registrations();
			for (auto& chain : chains)
				chain.second(chain.first);

			auto& config = protocol::now().user.superchain.options;
			if (!config || !config->is_map())
				return;

			auto* protocols = config->child("protocols");
			if (protocols != nullptr)
			{
				for (auto& root : protocols->childs())
				{
					algorithm::asset_id asset = algorithm::asset::id_of(root.key);
					auto* instance = get_network_instance(asset);
					if (!instance)
					{
						VI_ERR("failed to configure %s server: asset not found", algorithm::asset::name_of(asset).c_str());
						continue;
					}

					auto* peers = root.child("peers");
					if (peers && !peers->childs().empty())
					{
						for (auto& child : peers->childs())
						{
							if (!child.is_map())
								continue;

							btree_map<string, string> headers;
							auto* headers_field = child.child("headers");
							if (headers_field != nullptr)
							{
								for (auto& header : headers_field->childs())
									headers[header.key] = header.value.as_blob();
							}

							size_t headers_size = headers.size();
							auto url = child.child_var("url").as_blob();
							auto rps = child.child_var("rps").as_double();
							if (add_network_connection(asset, url, std::move(headers), rps) && protocol::now().user.superchain.logging)
								VI_INFO("%s server add \"%s\" endpoint (rps: %.2f, headers: %i)", algorithm::asset::name_of(asset).c_str(), url.c_str(), rps, (int)headers_size);
							else if (protocol::now().user.superchain.logging)
								VI_ERR("failed to add %s server \"%s\" with %i headers", algorithm::asset::name_of(asset).c_str(), url.c_str(), (int)headers_size);
						}
					}

					auto* props = (format::tree*)root.child("strategy.props");
					if (props != nullptr && !props->is_none())
						instance->props = *props;

					auto* batching = root.child("strategy.batching");
					if (batching != nullptr && batching->value.is_integer())
						instance->options.blocks_batching = batching->value.as_uint64();

					auto* linker = root.child("strategy.linker");
					if (linker != nullptr && linker->value.is_boolean())
						instance->options.blocks_linker = linker->value.as_boolean();

					auto* tip = root.child("strategy.tip");
					if (tip != nullptr && tip->value.is_integer())
						scan_from_block_height(asset, tip->value.as_uint64());
					else if (tip != nullptr)
						scan_from_block_height(asset, optional::none);
				}
			}
		}
		bridge::~bridge() noexcept
		{
		}
		expects_promise_rt<format::tree> bridge::execute_rpc(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const format::tree& args, cache_policy cache, const std::string_view& path, bool multi)
		{
			if (reporter.type.empty())
				reporter.type = "jrpc";
			if (reporter.method.empty())
				reporter.method = method;

			auto category = cache_type_of(cache);
			auto setup = format::tree::map();
			setup.set("jsonrpc", format::variable("2.0"));
			setup.set("method", format::variable(method));
			if (multi && args.fields && args.fields->size() > 1)
			{
				auto multi_setup = format::tree::list();
				for (auto& request : *args.fields)
				{
					auto* sub_setup = multi_setup.push(setup);
					sub_setup->set("params", request);
					sub_setup->set("id", format::variable(string(category) + to_string(multi_setup.childs().size())));
				}
				setup = std::move(multi_setup);
			}
			else
			{
				setup.set("params", multi && args.fields ? args.fields->front() : args);
				setup.set("id", format::variable(category));
			}

			bool multi_confirmed = args.fields && args.fields->size() > 1;
			return execute_rest(asset, connection, reporter, "POST", path, setup, cache).then<expects_rt<format::tree>>([&reporter, multi, multi_confirmed](expects_rt<format::tree>&& response) -> expects_rt<format::tree>
			{
				if (!response)
					return response;

				if (!multi)
					return solve_rpc_response(*response, &reporter);

				format::tree results;
				if (multi_confirmed)
				{
					for (auto& subresponse : response->childs())
					{
						auto subresult = solve_rpc_response(subresponse, &reporter);
						if (!subresult)
							return subresult;

						results.push(std::move(*subresult));
					}
				}
				else
				{
					auto subresult = solve_rpc_response(*response, &reporter);
					if (!subresult)
						return subresult;

					results.push(std::move(*subresult));
				}
				return results;
			});
		}
		expects_promise_rt<format::tree> bridge::execute_rest(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const format::tree& args, cache_policy cache)
		{
			if (reporter.type.empty())
				reporter.type = "rest";

			string body = args.is_none() ? string() : args.as_json();
			return execute_http(asset, connection, reporter, method, path, "application/json", body, cache);
		}
		expects_promise_rt<format::tree> bridge::execute_http(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache)
		{
			if (reporter.type.empty())
				reporter.type = "http";

			string target_url = join_url_path(connection.connection_url, path);
			if (reporter.method.empty())
				reporter.method = location(target_url).path.substr(1);

			if (path.empty() && body.empty())
				cache = cache_policy::no_cache;

			string message = string(path).append(body);
			string hash = codec::hex_encode(algorithm::hashing::hash512((uint8_t*)message.data(), message.size()));
			if (cache != cache_policy::no_cache && cache != cache_policy::no_cache_no_throttling)
			{
				auto data = load_cache(asset, cache, hash);
				if (data)
					return expects_rt<format::tree>(std::move(*data));
			}

			if (protocol::now().time.now_cpu() < connection.state.error_retry_after_timestamp)
				return expects_rt<format::tree>(remote_exception::retry_after(connection.state.error_retry_after_timestamp));
			else
				message = string(body);

			string method_ref = string(method), type_ref = string(type);
			return coasync<expects_rt<format::tree>>([this, &connection, &reporter, asset, cache, method_ref = std::move(method_ref), type_ref = std::move(type_ref), target_url = std::move(target_url), message = std::move(message), hash = std::move(hash)]() mutable -> expects_promise_rt<format::tree>
			{
				if (connection.rps > 0.0 && cache != cache_policy::no_cache_no_throttling)
				{
					while (protocol::now().time.now_cpu() < connection.state.rps_retry_after_timestamp && (!network_active || network_active()))
					{
						promise<void> awaiter;
						schedule::get()->set_timeout(200, [awaiter]() mutable { awaiter.set(); });
						coawait(std::move(awaiter));
					}
					connection.state.rps_retry_after_timestamp = protocol::now().time.now_cpu() + (uint64_t)(1000000.0 / connection.rps) / 1000;
				}

				if (!network_fetch || (network_active && !network_active()))
					coreturn expects_rt<format::tree>(remote_exception::shutdown());

				http::fetch_frame setup;
				setup.max_size = 16 * 1024 * 1024;
				setup.verify_peers = (uint32_t)protocol::now().user.tcp.tls_trusted_peers;
				setup.timeout = protocol::now().user.tcp.timeout;
				setup.set_header("User-Agent", random_user_agent());
				if (!message.empty())
				{
					setup.set_header("Content-Type", type_ref);
					setup.content.assign(message);
				}

				for (auto& [key, value] : connection.headers)
					setup.set_header(key, value);

				auto response = coawait(network_fetch(asset, target_url, method_ref, setup));
				if (!response || response->status_code == 408 || response->status_code == 429 || response->status_code == 502 || response->status_code == 503 || response->status_code == 504)
					coreturn expects_rt<format::tree>(remote_exception::retry_after(protocol::now().time.now_cpu() + protocol::now().user.superchain.polling_frequency, response ? string(http::utils::status_message(response->status_code)) + string(" error") : std::move(response.error().message())));

				format::tree result;
				auto content_type = response->get_header("Content-Type");
				if (stringify::starts_with(content_type, "application/json") || stringify::starts_with(content_type, "application/hal+json"))
				{
					auto data = format::tree::from_json(std::string_view(response->content.data.data(), response->content.data.size()));
					if (!data)
						coreturn expects_rt<format::tree>(remote_exception(normalize_error(response, reporter, "null", "response decoding failed: " + data.error().message())));

					result = std::move(*data);
				}
				else
					result = format::variable::from(std::string_view(response->content.data.data(), response->content.data.size()));

				if (cache != cache_policy::no_cache && cache != cache_policy::no_cache_no_throttling && (response->status_code < 400 || response->status_code == 404))
					bridge::get()->store_cache(asset, cache, hash, result);

				coreturn expects_rt<format::tree>(std::move(result));
			});
		}
		expects_promise_rt<uint64_t> bridge::get_latest_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<uint64_t>(remote_exception("asset not found"));

			if (!has_network(asset))
				return expects_rt<uint64_t>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<uint64_t>(remote_exception("chain not found"));

			return implementation->get_latest_block_height();
		}
		expects_promise_rt<vector<block_log>> bridge::get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, uint64_t block_count)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<vector<block_log>>(remote_exception("asset not found"));

			if (!has_network(asset))
				return expects_rt<vector<block_log>>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<vector<block_log>>(remote_exception("chain not found"));

			return implementation->get_block_transactions(block_height, block_count);
		}
		expects_promise_rt<vector<transaction_logs>> bridge::link_transactions(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<vector<transaction_logs>>(remote_exception("asset not found"));

			if (!has_network(asset))
				return expects_rt<vector<transaction_logs>>(remote_exception("chain not active"));

			auto* instance = get_network_instance(asset);
			if (!instance)
				return expects_rt<vector<transaction_logs>>(remote_exception("chain not found"));

			uint64_t time = protocol::now().time.now_cpu();
			auto* implementation = *instance->translation;
			auto* options = &instance->options;
			if (network_active && !network_active())
				return expects_rt<vector<transaction_logs>>(remote_exception::shutdown());
			else if (time < options->state.retry_after_time)
				return expects_rt<vector<transaction_logs>>(remote_exception::retry_after(options->state.retry_after_time));

			return coasync<expects_rt<vector<transaction_logs>>>([this, asset, implementation, options]() -> expects_promise_rt<vector<transaction_logs>>
			{
				format::tree tip_now, tip_min, tip_max;
				auto to_delayed_block_height = [&](uint64_t block_height, bool zero_as_min)
				{
					auto latency = implementation->get_chainparams().sync_latency;
					return block_height > latency ? block_height - latency : (zero_as_min ? 0 : 1);
				};
				{
					storages::superchainstate state = storages::superchainstate(asset);
					auto tip_set = state.get_property("TIP:SET").or_else(format::tree());
					tip_min = state.get_property("TIP:MIN").or_else(format::tree());
					if (tip_set.value.is_integer())
					{
						uint64_t tip = to_delayed_block_height(tip_set.value.as_uint64(), !tip_set.value.as_uint64());
						options->set_checkpoint_from_block(tip);
						state.set_property("TIP:SET", format::variable());
						state.set_property("TIP:NOW", format::variable());
						state.set_property("TIP:MAX", format::variable());
					}
					else
					{
						tip_now = state.get_property("TIP:NOW").or_else(format::tree());
						tip_max = state.get_property("TIP:MAX").or_else(format::tree());
						if (tip_now.value.is_integer() && (!options->state.inital_block_height || !options->state.index_block_height))
							options->set_checkpoint_from_block(tip_now.value.as_uint64() + 1);
					}
				}

				uint64_t linked_block_height = 0;
				if (options->blocks_linker)
				{
					auto result = coawait(implementation->get_linked_block_height(options->state.index_block_height > 0 ? options->state.index_block_height - 1 : options->state.index_block_height));
					if (!result && result.error().is_retry())
					{
						if (result.error().is_retry_after())
						{
							options->state.retry_after_time = result.error().retry_after_timestamp();
							coreturn expects_rt<vector<transaction_logs>>(result.error());
						}

						options->state.retry_after_time = protocol::now().time.now_cpu() + protocol::now().user.superchain.polling_frequency;
						coreturn expects_rt<vector<transaction_logs>>(remote_exception::retry_after(options->state.retry_after_time));
					}
					else if (result)
						options->set_checkpoint_from_block(*result);
					linked_block_height = result.or_else(0);
				}

				options->state.retry_after_time = 0;
				if (!options->has_target_block_height())
				{
					auto latest_block_height = coawait(implementation->get_latest_block_height());
					if (!latest_block_height)
						coreturn expects_rt<vector<transaction_logs>>(std::move(latest_block_height.error()));

					*latest_block_height = to_delayed_block_height(*latest_block_height, true);
					if (linked_block_height > 0)
						*latest_block_height = std::min(*latest_block_height, linked_block_height + 1);

					options->set_checkpoint_to_block(*latest_block_height);
				}

				auto block_count = std::max<uint64_t>(1, options->blocks_batching);
				if (!options->has_next_block_height(block_count))
				{
					options->state.retry_after_time = protocol::now().time.now_cpu() + protocol::now().user.superchain.polling_frequency;
					options->set_checkpoint_from_block(options->state.target_block_height + 1);
					coreturn expects_rt<vector<transaction_logs>>(remote_exception::retry_after(options->state.retry_after_time));
				}

				auto logs = vector<transaction_logs>();
				auto block_height = options->get_next_block_height(block_count);
				auto block_batch = coawait(implementation->get_block_transactions(block_height, block_count));
				if (!block_batch || block_batch->empty())
					coreturn expects_rt<vector<transaction_logs>>(block_batch ? remote_exception("failed to find new block data") : block_batch.error());

				auto* utxo_implementation = utxo_translation_unit::from(implementation);
				for (auto& block : *block_batch)
				{
					transaction_logs log;
					log.block_height = block_height + (uint64_t)logs.size();
					log.block_hash = block.block_hash.empty() ? to_string(log.block_height) : block.block_hash;

					for (auto& item : block.transactions.childs())
					{
						auto computed = coawait(implementation->link_transaction(log.block_height, log.block_hash, item));
						if (computed)
						{
							computed->block_id = log.block_height;
							normalize_transaction_id(asset, &computed->transaction_id);
							log.receipts.push_back(std::move(*computed));
							item.key.clear();
						}
					}

					hash_set<string> transaction_ids;
					auto state = storages::superchainstate(asset);
					for (auto& new_transaction : log.receipts)
					{
						state.add_incoming_transaction(new_transaction);
						transaction_ids.insert(algorithm::asset::handle_of(asset) + ":" + new_transaction.transaction_id);
						if (utxo_implementation != nullptr)
							utxo_implementation->update_utxo(new_transaction).report("failed to update utxo set from " + new_transaction.transaction_id);
					}
					logs.push_back(std::move(log));
				}

				auto state = storages::superchainstate(asset);
				if (!tip_now.value.is_integer() || tip_now.value.as_uint64() != block_height)
					state.set_property("TIP:NOW", format::variable(block_height));
				if (!tip_min.value.is_integer() || (tip_min.value.as_uint64() > block_height && block_height > 0))
					state.set_property("TIP:MIN", format::variable(block_height));
				if (!tip_max.value.is_integer() || tip_max.value.as_uint64() < options->state.target_block_height)
					state.set_property("TIP:MAX", format::variable(options->state.target_block_height));

				coreturn expects_rt<vector<transaction_logs>>(std::move(logs));
			});
		}
		expects_promise_rt<computed_transaction> bridge::link_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<computed_transaction>(remote_exception("asset not found"));

			if (!block_height)
				return expects_rt<computed_transaction>(remote_exception("txs not found"));

			if (!has_network(asset))
				return expects_rt<computed_transaction>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<computed_transaction>(remote_exception("chain not found"));

			return implementation->link_transaction(block_height, block_hash, transaction_data);
		}
		expects_promise_rt<decimal> bridge::calculate_balance(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<decimal>(remote_exception("asset not found"));

			auto normalized_link = normalize_link(asset, link);
			if (!normalized_link)
				return expects_rt<decimal>(remote_exception(std::move(normalized_link.error().message())));

			if (!has_network(asset))
				return expects_rt<decimal>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<decimal>(remote_exception("chain not found"));

			return implementation->calculate_balance(asset, *normalized_link);
		}
		expects_promise_rt<void> bridge::broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const finalized_transaction& finalized)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<void>(remote_exception("asset not found"));

			if (!finalized.is_valid())
				return expects_rt<void>(remote_exception("transaction is not valid"));

			if (!has_network(asset))
				return expects_rt<void>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<void>(remote_exception("chain not found"));

			auto new_transaction = finalized.as_computed();
			normalize_transaction_id(asset, &new_transaction.transaction_id);
			new_transaction.block_id = 0;
			{
				storages::superchainstate state = storages::superchainstate(asset);
				auto duplicate_transaction = state.get_computed_transaction(new_transaction.transaction_id, external_id, algorithm::hashing::hash256i(new_transaction.transaction_id));
				if (duplicate_transaction)
					return expects_rt<void>(remote_exception("transaction is in dangling state (reverting due to double spending possibility)"));

				auto status = state.add_outgoing_transaction(new_transaction, external_id);
				if (!status)
					return expects_rt<void>(remote_exception(std::move(status.error().message())));
			}

			if (protocol::now().user.superchain.logging)
				VI_INFO("%s broadcast transaction: %s (ref: %s)", algorithm::asset::blockchain_of(asset).c_str(), finalized.as_tree().as_json().c_str(), algorithm::encoding::encode_0xhex256(external_id).c_str());

			return implementation->broadcast_transaction(finalized).then<expects_rt<void>>([implementation, new_transaction = std::move(new_transaction)](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				auto* utxo_implementation = result ? utxo_translation_unit::from(implementation) : nullptr;
				if (utxo_implementation != nullptr)
					utxo_implementation->update_utxo(new_transaction).report("failed to update utxo set from " + new_transaction.transaction_id);

				return result;
			});
		}
		expects_promise_rt<prepared_transaction> bridge::prepare_transaction(const algorithm::asset_id& asset, const wallet_link& from_link, const value_transfer& to, const decimal& max_fee)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<prepared_transaction>(remote_exception("asset not found"));

			if (!has_network(asset))
				return expects_rt<prepared_transaction>(remote_exception("chain not active"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_rt<prepared_transaction>(remote_exception("chain not found"));

			auto normalized_to = normalize_value(implementation, to);
			auto blockchain = algorithm::asset::blockchain_of(asset);
			if (!normalized_to.is_valid())
				return expects_rt<prepared_transaction>(remote_exception("receiver address not valid"));

			if (!algorithm::asset::is_aux(normalized_to.asset) || algorithm::asset::blockchain_of(normalized_to.asset) != blockchain)
				return expects_rt<prepared_transaction>(remote_exception("receiver asset not valid"));

			auto normalized_from_link = normalize_link(asset, from_link);
			if (!normalized_from_link)
				return expects_rt<prepared_transaction>(remote_exception(std::move(normalized_from_link.error().message())));

			auto normalized_max_fee = normalize_value(implementation, max_fee);
			if (protocol::now().user.superchain.logging)
			{
				VI_INFO(
					"%s build transaction: %s (fee: %s %s)\n"
					"  send from %s (%s)\n"
					"  send %s %s to %s",
					blockchain.c_str(),
					algorithm::encoding::encode_0xhex256(normalized_from_link->hash).c_str(),
					normalized_max_fee.to_string().c_str(),
					blockchain.c_str(),
					normalized_from_link->public_key.empty() ? "none" : normalized_from_link->public_key.c_str(),
					normalized_from_link->address.empty() ? "unaddressable" : normalized_from_link->address.c_str(),
					normalized_to.value.to_string().c_str(), algorithm::asset::name_of(normalized_to.asset).c_str(), normalized_to.address.c_str());
			}

			return implementation->prepare_transaction(*normalized_from_link, normalized_to, normalized_max_fee).then<expects_rt<prepared_transaction>>([blockchain = std::move(blockchain)](expects_rt<prepared_transaction>&& result) mutable -> expects_rt<prepared_transaction>
			{
				if (protocol::now().user.superchain.logging)
					VI_INFO("%s built transaction: %s", blockchain.c_str(), result ? result->as_tree().as_json().c_str() : result.error().what());

				return result;
			});
		}
		expects_lr<finalized_transaction> bridge::finalize_transaction(const algorithm::asset_id& asset, prepared_transaction&& prepared)
		{
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("asset not found");

			auto status = prepared.as_status();
			if (status != prepared_transaction::status::finalizeable)
				return layer_exception(status == prepared_transaction::status::invalid ? "transaction is not valid for finalization" : "transaction does not require finalization");

			auto* implementation = get_network(asset);
			if (!implementation)
				return layer_exception("chain not found");

			auto blockchain = algorithm::asset::blockchain_of(asset);
			auto base_asset = algorithm::asset::base_id_of(asset);
			for (auto& input : prepared.inputs)
			{
				auto input_asset = input.utxo.get_asset(base_asset);
				if (!algorithm::asset::is_aux(input_asset) || algorithm::asset::blockchain_of(input_asset) != blockchain)
					return layer_exception("input asset not valid");

				for (auto& [input_token_hash, input_token] : input.utxo.tokens)
				{
					if (!algorithm::asset::is_aux(input_token.get_asset(base_asset)))
						return layer_exception("invalid input token asset");
				}
			}

			for (auto& output : prepared.outputs)
			{
				auto output_asset = output.get_asset(base_asset);
				if (!algorithm::asset::is_aux(output_asset) || algorithm::asset::blockchain_of(output_asset) != blockchain)
					return layer_exception("invalid output asset");

				for (auto& [output_token_hash, output_token] : output.tokens)
				{
					if (!algorithm::asset::is_aux(output_token.get_asset(base_asset)))
						return layer_exception("invalid output token asset");
				}
			}

			auto finalized = implementation->finalize_transaction(std::move(prepared));
			if (!finalized)
				return finalized;
			else if (!finalized->is_valid())
				return layer_exception("transaction is not finalized properly");

			return finalized;
		}
		expects_lr<computed_transaction> bridge::get_computed_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id, const uint256_t& external_id, const uint256_t& optimized_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return layer_exception("asset not found");

			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_computed_transaction(transaction_id, external_id, optimized_id);
		}
		expects_lr<computed_wallet> bridge::compute_wallet(const algorithm::asset_id& asset, const uint8_t* seed, size_t seed_size)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<computed_wallet>(layer_exception("asset not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<computed_wallet>(layer_exception("chain not found"));

			auto& chain = implementation->get_chainparams();
			auto keypair = algorithm::composition::derive_keypair(chain.composition, seed, seed_size);
			if (!keypair)
				return keypair.error();

			computed_wallet wallet;
			wallet.seed.resize(seed_size);
			memcpy(wallet.seed.data(), seed, seed_size);
			wallet.secret_key = std::move(keypair->secret_key);
			wallet.public_key = std::move(keypair->public_key);
			wallet.encoded_seed = secret_box::secure(algorithm::encoding::encode_0xhex256(std::string_view((char*)wallet.seed.data(), wallet.seed.size())));

			auto encoded_secret_key = implementation->encode_secret_key(secret_box::view(std::string_view((char*)wallet.secret_key.data(), wallet.secret_key.size())));
			if (!encoded_secret_key)
				return encoded_secret_key.error();

			auto encoded_public_key = implementation->encode_public_key(std::string_view((char*)wallet.public_key.data(), wallet.public_key.size()));
			if (!encoded_public_key)
				return encoded_public_key.error();

			auto encoded_addresses = implementation->to_addresses(*encoded_public_key);
			if (!encoded_addresses)
				return encoded_addresses.error();

			wallet.encoded_secret_key = std::move(*encoded_secret_key);
			wallet.encoded_public_key = std::move(*encoded_public_key);
			wallet.encoded_addresses = std::move(*encoded_addresses);
			for (auto& [index, address] : wallet.encoded_addresses)
			{
				auto decoded_address = implementation->decode_address(address);
				if (!decoded_address)
					return decoded_address.error();

				wallet.addresses[index] = std::move(*decoded_address);
			}

			return expects_lr<computed_wallet>(std::move(wallet));
		}
		expects_lr<secret_box> bridge::encode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<secret_box>(layer_exception("asset not found"));

			if (secret_key.empty())
				return expects_lr<secret_box>(layer_exception("secret key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<secret_box>(layer_exception("chain not found"));

			return implementation->encode_secret_key(secret_key);
		}
		expects_lr<secret_box> bridge::decode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<secret_box>(layer_exception("asset not found"));

			if (secret_key.empty())
				return expects_lr<secret_box>(layer_exception("secret key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<secret_box>(layer_exception("chain not found"));

			return implementation->decode_secret_key(secret_key);
		}
		expects_lr<string> bridge::encode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<string>(layer_exception("public key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_public_key(public_key);
		}
		expects_lr<string> bridge::decode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(public_key))
				return expects_lr<string>(layer_exception("public key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_public_key(public_key);
		}
		expects_lr<string> bridge::encode_address(const algorithm::asset_id& asset, const std::string_view& public_key_hash)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (public_key_hash.empty())
				return expects_lr<string>(layer_exception("public key hash not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_address(public_key_hash);
		}
		expects_lr<string> bridge::decode_address(const algorithm::asset_id& asset, const std::string_view& address)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(address))
				return expects_lr<string>(layer_exception("address not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_address(address);
		}
		expects_lr<string> bridge::encode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (transaction_id.empty())
				return expects_lr<string>(layer_exception("transaction id not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->encode_transaction_id(transaction_id);
		}
		expects_lr<string> bridge::decode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<string>(layer_exception("asset not found"));

			if (stringify::is_empty_or_whitespace(transaction_id))
				return expects_lr<string>(layer_exception("transaction id not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<string>(layer_exception("chain not found"));

			return implementation->decode_transaction_id(transaction_id);
		}
		expects_lr<void> bridge::normalize_secret_key(const algorithm::asset_id& asset, secret_box* secret_key)
		{
			VI_ASSERT(secret_key != nullptr, "secret key should be set");
			auto decoded = decode_secret_key(asset, *secret_key);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_secret_key(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*secret_key = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> bridge::normalize_public_key(const algorithm::asset_id& asset, string* public_key)
		{
			VI_ASSERT(public_key != nullptr, "public key should be set");
			auto decoded = decode_public_key(asset, *public_key);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_public_key(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*public_key = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> bridge::normalize_address(const algorithm::asset_id& asset, string* address)
		{
			VI_ASSERT(address != nullptr, "address should be set");
			auto decoded = decode_address(asset, *address);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_address(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*address = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<void> bridge::normalize_transaction_id(const algorithm::asset_id& asset, string* transaction_id)
		{
			VI_ASSERT(transaction_id != nullptr, "transaction id should be set");
			auto decoded = decode_transaction_id(asset, *transaction_id);
			if (!decoded)
				return decoded.error();

			auto encoded = encode_transaction_id(asset, *decoded);
			if (!encoded)
				return encoded.error();

			*transaction_id = std::move(*encoded);
			return expectation::met;
		}
		expects_lr<algorithm::composition::cpubkey_t> bridge::to_composite_public_key(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("public key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<algorithm::composition::cpubkey_t>(layer_exception("chain not found"));

			return implementation->to_composite_public_key(public_key);
		}
		expects_lr<address_map> bridge::to_addresses(const algorithm::asset_id& asset, const std::string_view& public_key)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<address_map>(layer_exception("asset not found"));

			if (public_key.empty())
				return expects_lr<address_map>(layer_exception("public key not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<address_map>(layer_exception("chain not found"));

			return implementation->to_addresses(public_key);
		}
		expects_lr<void> bridge::scan_from_block_height(const algorithm::asset_id& asset, option<uint64_t>&& block_height)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			storages::superchainstate state = storages::superchainstate(asset);
			return state.set_property("TIP:SET", block_height ? format::variable(*block_height) : format::variable());
		}
		expects_lr<void> bridge::enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (contract_address.empty())
				return expects_lr<void>(layer_exception("contract address not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			storages::superchainstate state = storages::superchainstate(asset);
			auto key = algorithm::asset::token_of(asset);
			auto value = state.get_property(key);
			if (!value)
				value = format::tree::list();

			hash_set<string> addresses;
			for (auto& item : value->childs())
				addresses.insert(item.value.as_blob());

			auto address = string(contract_address);
			normalize_address(asset, &address);
			if (addresses.find(address) != addresses.end())
				return expectation::met;

			value->push(format::variable(address));
			return state.set_property(key, std::move(*value));
		}
		expects_lr<void> bridge::enable_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (!link.has_all())
				return expects_lr<void>(layer_exception("link not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			auto copy = link;
			auto status = normalize_public_key(asset, &copy.public_key);
			if (!status)
				return status;

			status = normalize_address(asset, &copy.address);
			if (!status)
				return status;

			storages::superchainstate state = storages::superchainstate(asset);
			auto candidate_link = state.get_link(copy.address);
			if (candidate_link && candidate_link->as_hash() == copy.as_hash())
				return expectation::met;

			return state.set_link(copy);
		}
		expects_lr<void> bridge::disable_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<void>(layer_exception("asset not found"));

			if (!link.has_all())
				return expects_lr<void>(layer_exception("address not found"));

			auto* implementation = get_network(asset);
			if (!implementation)
				return expects_lr<void>(layer_exception("chain not found"));

			auto copy = link;
			auto status = normalize_public_key(asset, &copy.public_key);
			if (!status)
				return status;

			status = normalize_address(asset, &copy.address);
			if (!status)
				return status;

			storages::superchainstate state = storages::superchainstate(asset);
			return state.clear_link(copy);
		}
		expects_lr<wallet_link> bridge::normalize_link(const algorithm::asset_id& asset, const wallet_link& link)
		{
			if (link.has_address())
			{
				auto result = get_links_by_addresses(asset, { link.address });
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			if (link.has_public_key())
			{
				auto result = get_links_by_public_keys(asset, { link.public_key });
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			if (link.has_hash())
			{
				auto result = get_links_by_hash(asset, link.hash, 0, 1);
				if (result && !result->empty())
					return expects_lr<wallet_link>(std::move(result->begin()->second));
			}

			return layer_exception("link not found");
		}
		expects_lr<uint64_t> bridge::get_earliest_scanned_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<uint64_t>(layer_exception("asset not found"));

			storages::superchainstate state = storages::superchainstate(asset);
			auto earliest_block_height = state.get_property("TIP:MIN");
			if (!earliest_block_height || !earliest_block_height->value.is_integer())
				return expects_lr<uint64_t>(layer_exception("block not found"));

			return expects_lr<uint64_t>(earliest_block_height->value.as_uint64());
		}
		expects_lr<uint64_t> bridge::get_latest_known_block_height(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return expects_lr<uint64_t>(layer_exception("asset not found"));

			uint64_t block_height = 0;
			storages::superchainstate state = storages::superchainstate(asset);
			auto latest_block_height = state.get_property("TIP:MAX");
			if (latest_block_height)
			{
				uint64_t possible_block_height = latest_block_height->value.as_uint64();
				if (possible_block_height > block_height)
					block_height = possible_block_height;
			}

			auto checkpoint_block_height = state.get_property("TIP:NOW");
			if (checkpoint_block_height)
			{
				uint64_t possible_block_height = checkpoint_block_height->value.as_uint64();
				if (possible_block_height > block_height)
					block_height = possible_block_height;
			}

			if (!block_height)
				return expects_lr<uint64_t>(layer_exception("block not found"));

			return expects_lr<uint64_t>(block_height);
		}
		expects_lr<wallet_link> bridge::get_link(const algorithm::asset_id& asset, const std::string_view& address)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_link(address);
		}
		expects_lr<hash_map<string, wallet_link>> bridge::get_links_by_hash(const algorithm::asset_id& asset, const uint256_t& hash, size_t offset, size_t count)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_links_by_hash(hash, offset, count);
		}
		expects_lr<hash_map<string, wallet_link>> bridge::get_links_with_hash(const algorithm::asset_id& asset, size_t offset, size_t count)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_links_with_hash(offset, count);
		}
		expects_lr<hash_map<string, wallet_link>> bridge::get_links_by_public_keys(const algorithm::asset_id& asset, const hash_set<string>& public_keys)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_links_by_public_keys(public_keys);
		}
		expects_lr<hash_map<string, wallet_link>> bridge::get_links_by_addresses(const algorithm::asset_id& asset, const hash_set<string>& addresses)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_links_by_addresses(addresses);
		}
		expects_lr<void> bridge::receive_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index, uint64_t block_id, const coin_utxo& value)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.receive_utxo(transaction_id, index, block_id, value);
		}
		expects_lr<void> bridge::spend_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index, uint64_t block_id)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.spend_utxo(transaction_id, index, block_id);
		}
		expects_lr<void> bridge::revive_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.revive_utxo(transaction_id, index);
		}
		expects_lr<void> bridge::revive_utxo_tree(const algorithm::asset_id& asset, const computed_transaction& computed)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			for (auto& [input_hash, input] : computed.inputs)
			{
				auto result = state.revive_utxo(input.transaction_id, input.index);
				if (!result)
					return result;
			}

			for (auto& [output_hash, output] : computed.outputs)
			{
				auto result = state.revive_utxo(output.transaction_id, output.index);
				if (!result)
					return result;

				auto child = state.get_computed_transaction(output.transaction_id, 0, 0);
				if (!child)
					continue;

				result = revive_utxo_tree(asset, *child);
				if (!result)
					return result;
			}

			return expectation::met;
		}
		expects_lr<void> bridge::update_utxo_tree(const algorithm::asset_id& asset, const computed_transaction& computed)
		{
			auto* implementation = get_network(asset);
			if (!implementation)
				return layer_exception("chain not found");

			auto* utxo_implementation = utxo_translation_unit::from(implementation);
			if (!utxo_implementation)
				return expectation::met;

			return utxo_implementation->update_utxo(computed);
		}
		expects_lr<coin_utxo> bridge::get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_utxo(transaction_id, index);
		}
		expects_lr<vector<coin_utxo>> bridge::get_utxos(const algorithm::asset_id& asset, const wallet_link& link, size_t offset, size_t count)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_utxos(link, offset, count);
		}
		expects_lr<format::tree> bridge::load_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.get_cache(policy, key);
		}
		expects_lr<void> bridge::store_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key, const format::tree& value)
		{
			storages::superchainstate state = storages::superchainstate(asset);
			return state.set_cache(policy, key, value);
		}
		option<string> bridge::get_contract_address(const algorithm::asset_id& asset)
		{
			if (!algorithm::asset::is_aux(asset))
				return optional::none;

			auto blockchain = algorithm::asset::blockchain_of(asset);
			auto token = algorithm::asset::token_of(asset);
			storages::superchainstate state = storages::superchainstate(asset);
			auto value = state.get_property(token);
			if (!value || value->childs().empty())
				return optional::none;

			auto target_checksum = algorithm::asset::checksum_of(asset);
			for (auto& item : value->childs())
			{
				auto candidate_address = item.value.as_blob();
				auto candidate_checksum = algorithm::asset::checksum_of(algorithm::asset::id_of(blockchain, token, candidate_address));
				if (candidate_checksum == target_checksum)
					return candidate_address;
			}

			return value->childs()[0].value.as_blob();
		}
		vector<algorithm::asset_id> bridge::get_assets(bool observing_only)
		{
			vector<algorithm::asset_id> assets;
			assets.reserve(networks.size());
			for (auto& node : networks)
			{
				if (!observing_only || !node.second.connections.empty())
					assets.push_back(algorithm::asset::id_of(node.first));
			}
			return assets;
		}
		hash_map<algorithm::asset_id, translation_unit::chainparams> bridge::get_assets_with_params()
		{
			hash_map<algorithm::asset_id, translation_unit::chainparams> result;
			result.reserve(networks.size());
			for (auto& next : networks)
				result[algorithm::asset::id_of(next.first)] = next.second.translation->get_chainparams();
			return result;
		}
		const hash_map<string, bridge::invocation_callback>& bridge::get_registrations()
		{
			if (!registrations.empty())
				return registrations;

			registrations =
			{
				{ "ADA", chain<translations::cardano>(this) },
				{ "BTC", chain<translations::bitcoin>(this) },
				{ "ETH", chain<translations::ethereum>(this) },
				{ "SOL", chain<translations::solana>(this) },
				{ "TRX", chain<translations::tron>(this) },
				{ "XRP", chain<translations::ripple>(this) },
				{ "XLM", chain<translations::stellar>(this) },
#ifdef TAN_TEST
				{ "BCH", chain<translations::bitcoin_cash>(this) },
				{ "BTG", chain<translations::bitcoin_gold>(this) },
				{ "BSV", chain<translations::bitcoin_sv>(this) },
				{ "DASH", chain<translations::dash>(this) },
				{ "DGB", chain<translations::digibyte>(this) },
				{ "DOGE", chain<translations::dogecoin>(this) },
				{ "LTC", chain<translations::litecoin>(this) },
				{ "XEC", chain<translations::ecash>(this) },
				{ "ZEC", chain<translations::zcash>(this) },
				{ "ARB", chain<translations::arbitrum>(this) },
				{ "AVAX", chain<translations::avalanche>(this) },
				{ "BASE", chain<translations::base>(this) },
				{ "BLAST", chain<translations::blast>(this) },
				{ "BNB", chain<translations::bnb>(this) },
				{ "CELO", chain<translations::celo>(this) },
				{ "ETC", chain<translations::ethereum_classic>(this) },
				{ "GNO", chain<translations::gnosis>(this) },
				{ "LINEA", chain<translations::linea>(this) },
				{ "MATIC", chain<translations::polygon>(this) },
				{ "OP", chain<translations::optimism>(this) },
				{ "S", chain<translations::sonic>(this) },
				{ "ZK", chain<translations::zksync>(this) },
				{ "XMR", chain<translations::monero>(this) },
#endif
			};
			return registrations;
		}
		hash_map<string, network_instance>& bridge::get_networks()
		{
			return networks;
		}
		translation_unit* bridge::get_network(const algorithm::asset_id& asset)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			return it != networks.end() ? *it->second.translation : nullptr;
		}
		network_instance* bridge::get_network_instance(const algorithm::asset_id& asset)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			return it != networks.end() ? &it->second : nullptr;
		}
		const translation_unit::chainparams* bridge::get_network_params(const algorithm::asset_id& asset)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			if (it != networks.end())
			{
				auto& params = it->second.translation->get_chainparams();
				return &params;
			}

			return nullptr;
		}
		connection_instance* bridge::add_network_connection(const algorithm::asset_id& asset, const std::string_view& url, btree_map<string, string>&& headers, double rps)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			VI_PANIC(it != networks.end(), "must add a network before adding a connection");
			it->second.connections.emplace_back();
			auto& next = it->second.connections.back();
			next.connection_url = url;
			next.headers = std::move(headers);
			next.rps = rps;

			stringify::trim(next.connection_url);
			for (auto& [key, value] : next.headers)
				stringify::trim(value);

			VI_PANIC(next.connection_url.size() > 1, "url must not be empty");
			if (next.connection_url.back() == '/')
				next.connection_url.pop_back();

			return &next;
		}
		format::tree* bridge::add_network_props(const algorithm::asset_id& asset, const format::tree& value)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			VI_PANIC(it != networks.end(), "must add a network before adding props");
			it->second.props = value;
			return &it->second.props;
		}
		format::tree* bridge::get_network_props(const algorithm::asset_id& asset)
		{
			auto it = networks.find(algorithm::asset::blockchain_of(asset));
			if (it != networks.end())
				return &it->second.props;

			return nullptr;
		}
		void bridge::add_network_instance(const algorithm::asset_id& asset, translation_unit* instance)
		{
			auto& network = networks[algorithm::asset::blockchain_of(asset)];
			network.asset = algorithm::asset::base_id_of(asset);
			network.translation = instance;
		}
		void bridge::remove_network(const algorithm::asset_id& asset)
		{
			networks.erase(algorithm::asset::blockchain_of(asset));
		}
		bool bridge::has_network(const algorithm::asset_id& asset, bool and_connections)
		{
			auto target = networks.find(algorithm::asset::blockchain_of(asset));
			return target != networks.end() && (!and_connections || !target->second.connections.empty());
		}
		std::string_view bridge::cache_type_of(cache_policy cache)
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
	}
}