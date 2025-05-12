#include "wardenstate.h"
#include "../service/nss.h"
#undef NULL

namespace tangent
{
	namespace storages
	{
		static string to_typeless(const std::string_view& data)
		{
			if (format::util::is_hex_encoding(data))
				return codec::hex_decode(data);
			else if (format::util::is_base64_encoding(data))
				return codec::base64_decode(data);
			else if (format::util::is_base64_url_encoding(data))
				return codec::base64_url_decode(data);
			return string(data);
		}
		static std::string_view load_link_field(warden::wallet_link::search_term term)
		{
			switch (term)
			{
				case warden::wallet_link::search_term::owner:
					return "owner";
				case warden::wallet_link::search_term::public_key:
					return "typeless_public_key";
				case warden::wallet_link::search_term::address:
					return "typeless_address";
				default:
					return "";
			}
		}
		static schema* load_link_value(warden::wallet_link::search_term term, const warden::wallet_link& link)
		{
			switch (term)
			{
				case warden::wallet_link::search_term::owner:
					return var::set::binary(link.owner, sizeof(link.owner));
				case warden::wallet_link::search_term::public_key:
					return var::set::binary(to_typeless(link.public_key));
				case warden::wallet_link::search_term::address:
					return var::set::binary(to_typeless(link.address));
				default:
					return nullptr;
			}
		}

		wardenstate::wardenstate(const std::string_view& new_label, const algorithm::asset_id& new_asset) noexcept : asset(new_asset), label(new_label)
		{
			string blockchain = algorithm::asset::blockchain_of(asset);
			storage_of("wardenstate." + stringify::to_lower(blockchain) + "data");
		}
		expects_lr<void> wardenstate::add_utxo(const warden::coin_utxo& value)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("utxo serialization error"));

			format::stream transaction_id_index;
			transaction_id_index.write_string(value.transaction_id);
			transaction_id_index.write_integer(value.index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));
			map.push_back(var::set::binary(std::string_view((char*)value.link.owner, sizeof(value.link.owner))));
			map.push_back(var::set::string(value.link.public_key));
			map.push_back(var::set::string(value.link.address));
			map.push_back(var::set::boolean(false));
			map.push_back(var::set::binary(message.data));
			
			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO coins (transaction_id_index, owner, public_key, address, spent, message) VALUES (?, ?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> wardenstate::remove_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = emplace_query(label, __func__, "UPDATE coins SET spent = TRUE WHERE transaction_id_index = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<warden::coin_utxo> wardenstate::get_stxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE transaction_id_index = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<warden::coin_utxo>(layer_exception(error_of(cursor)));

			warden::coin_utxo value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<warden::coin_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<warden::coin_utxo> wardenstate::get_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE transaction_id_index = ? AND spent = FALSE", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<warden::coin_utxo>(layer_exception(error_of(cursor)));

			warden::coin_utxo value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<warden::coin_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<vector<warden::coin_utxo>> wardenstate::get_utxos(const warden::wallet_link& link, size_t offset, size_t count)
		{
			if (!link.has_any())
				return expects_lr<vector<warden::coin_utxo>>(layer_exception("invalid link"));

			auto term = link.as_search_wide();
			schema_list map;
			map.push_back(var::set::string(load_link_field(term)));
			map.push_back(load_link_value(term, link));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE spent = FALSE AND $? = ? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<warden::coin_utxo>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<warden::coin_utxo> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				warden::coin_utxo value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (value.load(message))
					values.emplace_back(std::move(value));
			}

			return values;
		}
		expects_lr<void> wardenstate::add_computed_transaction(const warden::computed_transaction& value)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			schema_list map;
			map.push_back(var::set::string(value.transaction_id));
			map.push_back(var::set::integer(value.block_id.execution));
			map.push_back(var::set::boolean(value.is_mature(asset)));
			map.push_back(var::set::binary(message.data));

			auto cursor = emplace_query(label, __func__, "INSERT INTO transactions (transaction_id, block_id, finalized, message) VALUES (?, ?, ?, ?) ON CONFLICT (transaction_id) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, finalized = EXCLUDED.finalized, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> wardenstate::add_finalized_transaction(const warden::computed_transaction& value, const uint256_t& external_id)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			uint8_t hash[32];
			algorithm::encoding::decode_uint256(external_id, hash);

			schema_list map;
			map.push_back(external_id > 0 ? var::set::binary(hash, sizeof(hash)) : var::set::null());
			map.push_back(var::set::string(value.transaction_id));
			map.push_back(var::set::integer(value.block_id.execution));
			map.push_back(var::set::boolean(false));
			map.push_back(var::set::binary(message.data));

			auto cursor = emplace_query(label, __func__, "INSERT INTO transactions (external_id, transaction_id, block_id, finalized, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (transaction_id) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, finalized = EXCLUDED.finalized, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<warden::computed_transaction> wardenstate::get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(external_id, hash);

			schema_list map;
			map.push_back(var::set::string(transaction_id));
			map.push_back(external_id > 0 ? var::set::binary(hash, sizeof(hash)) : var::set::null());

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE transaction_id = ? OR external_id = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<warden::computed_transaction>(layer_exception(error_of(cursor)));

			warden::computed_transaction value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<warden::computed_transaction>(layer_exception("witness transaction deserialization error"));

			return value;
		}
		expects_lr<vector<warden::computed_transaction>> wardenstate::finalize_computed_transactions(uint64_t block_height, uint64_t block_latency)
		{
			if (!block_height || !block_latency)
				return expects_lr<vector<warden::computed_transaction>>(layer_exception("invalid block height or block latency"));
			else if (block_height <= block_latency)
				return expects_lr<vector<warden::computed_transaction>>(vector<warden::computed_transaction>());

			schema_list map;
			map.push_back(var::set::integer(block_height - block_latency));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE block_id <= ? AND finalized = FALSE", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<warden::computed_transaction>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<warden::computed_transaction> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				warden::computed_transaction value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (!value.load(message))
					continue;

				if (value.block_id.execution > 0)
				{
					if (block_height >= value.block_id.execution)
					{
						value.block_id.finalization = block_height;
						if (value.is_mature(asset) && add_computed_transaction(value))
							values.emplace_back(std::move(value));
					}
				}
				else
				{
					value.block_id.execution = block_height;
					value.block_id.finalization = 0;
					add_computed_transaction(value);
				}
			}

			return expects_lr<vector<warden::computed_transaction>>(std::move(values));
		}
		expects_lr<void> wardenstate::set_property(const std::string_view& key, uptr<schema>&& value)
		{
			schema_list map;
			map.push_back(var::set::string(algorithm::asset::blockchain_of(asset) + ":" + string(key)));

			if (value)
			{
				auto buffer = schema::to_jsonb(*value);
				format::stream message;
				message.write_string(std::string_view(buffer.begin(), buffer.end()));
				map.push_back(var::set::binary(message.compress()));

				auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO properties (key, message) VALUES (?, ?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}
			else
			{
				auto cursor = emplace_query(label, __func__, "DELETE FROM properties WHERE key = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<schema*> wardenstate::get_property(const std::string_view& key)
		{
			schema_list map;
			map.push_back(var::set::string(algorithm::asset::blockchain_of(asset) + ":" + string(key)));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM properties WHERE key = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<schema*>(layer_exception(error_of(cursor)));

			string buffer;
			format::stream message = format::stream::decompress((*cursor)["message"].get().get_string());
			if (!message.read_string(message.read_type(), &buffer))
				return expects_lr<schema*>(layer_exception("state value deserialization error"));
			
			auto value = schema::from_jsonb(buffer);
			if (!value)
				return expects_lr<schema*>(layer_exception(std::move(value.error().message())));

			return *value;
		}
		expects_lr<void> wardenstate::set_cache(warden::cache_policy policy, const std::string_view& key, uptr<schema>&& value)
		{
			schema_list map;
			map.push_back(var::set::binary(format::util::is_hex_encoding(key) ? codec::hex_decode(key) : string(key)));
			if (value)
			{
				auto buffer = schema::to_jsonb(*value);
				format::stream message;
				message.write_string(std::string_view(buffer.begin(), buffer.end()));
				map.push_back(var::set::binary(message.compress()));

				auto cursor = emplace_query(label, __func__, stringify::text("INSERT OR REPLACE INTO %s (key, message) VALUES (?, ?)", get_cache_location(policy).data()), &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}
			else
			{
				auto cursor = emplace_query(label, __func__, stringify::text("DELETE FROM %s WHERE key = ?", get_cache_location(policy).data()), &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<schema*> wardenstate::get_cache(warden::cache_policy policy, const std::string_view& key)
		{
			schema_list map;
			map.push_back(var::set::binary(format::util::is_hex_encoding(key) ? codec::hex_decode(key) : string(key)));

			auto cursor = emplace_query(label, __func__, stringify::text("SELECT message FROM %s WHERE key = ?", get_cache_location(policy).data()), &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<schema*>(layer_exception(error_of(cursor)));

			string buffer;
			format::stream message = format::stream::decompress((*cursor)["message"].get().get_string());
			if (!message.read_string(message.read_type(), &buffer))
				return expects_lr<schema*>(layer_exception("cache value deserialization error"));

			auto value = schema::from_jsonb(buffer);
			if (!value)
				return expects_lr<schema*>(layer_exception(std::move(value.error().message())));

			return *value;
		}
		expects_lr<void> wardenstate::set_link(const warden::wallet_link& value)
		{
			schema_list map;
			map.push_back(var::set::binary(value.owner, sizeof(value.owner)));
			map.push_back(var::set::string(value.public_key));
			map.push_back(var::set::string(value.address));
			map.push_back(var::set::binary(to_typeless(value.public_key)));
			map.push_back(var::set::binary(to_typeless(value.address)));

			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO links (owner, public_key, address, typeless_public_key, typeless_address) VALUES (?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> wardenstate::clear_link(const warden::wallet_link& value)
		{
			auto term = value.as_search_wide();
			schema_list map;
			map.push_back(var::set::string(load_link_field(term)));
			map.push_back(load_link_value(term, value));

			auto cursor = emplace_query(label, __func__, "DELETE FROM links WHERE $? = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<warden::wallet_link> wardenstate::get_link(const std::string_view& address)
		{
			schema_list map;
			map.push_back(var::set::binary(to_typeless(address)));

			auto cursor = emplace_query(label, __func__, "SELECT * FROM links WHERE typeless_address = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<warden::wallet_link>(layer_exception(error_of(cursor)));

			warden::wallet_link value;
			auto owner = (*cursor)["owner"].get().get_blob();
			memcpy(value.owner, owner.data(), std::min(sizeof(value.owner), owner.size()));
			value.public_key = (*cursor)["public_key"].get().get_blob();
			value.address = (*cursor)["address"].get().get_blob();
			return value;
		}
		expects_lr<unordered_map<string, warden::wallet_link>> wardenstate::get_links_by_public_keys(const unordered_set<string>& public_keys)
		{
			uptr<schema> public_key_list = var::set::array();
			public_key_list->reserve(public_keys.size());
			for (auto& item : public_keys)
			{
				if (!item.empty())
					public_key_list->push(var::binary(to_typeless(item)));
			}
			if (public_key_list->empty())
				return expects_lr<unordered_map<string, warden::wallet_link>>(layer_exception("no public keys"));

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(public_key_list))));

			auto cursor = emplace_query(label, __func__, "SELECT * FROM links WHERE typeless_public_key IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<unordered_map<string, warden::wallet_link>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			unordered_map<string, warden::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				warden::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				memcpy(value.owner, owner.data(), std::min(sizeof(value.owner), owner.size()));
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		expects_lr<unordered_map<string, warden::wallet_link>> wardenstate::get_links_by_addresses(const unordered_set<string>& addresses)
		{
			uptr<schema> address_list = var::set::array();
			address_list->reserve(addresses.size());
			for (auto& item : addresses)
			{
				if (!item.empty())
					address_list->push(var::binary(to_typeless(item)));
			}
			if (address_list->empty())
				return expects_lr<unordered_map<string, warden::wallet_link>>(layer_exception("no addresses"));

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(address_list))));

			auto cursor = emplace_query(label, __func__, "SELECT * FROM links WHERE typeless_address IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<unordered_map<string, warden::wallet_link>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			unordered_map<string, warden::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				warden::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				memcpy(value.owner, owner.data(), std::min(sizeof(value.owner), owner.size()));
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		expects_lr<unordered_map<string, warden::wallet_link>> wardenstate::get_links_by_owner(const algorithm::pubkeyhash owner, size_t offset, size_t count)
		{
			schema_list map;
			if (owner != nullptr)
				map.push_back(var::set::binary(owner, sizeof(algorithm::pubkeyhash)));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, owner ? "SELECT * FROM links WHERE owner = ? LIMIT ? OFFSET ?" : "SELECT * FROM links LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<unordered_map<string, warden::wallet_link>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			unordered_map<string, warden::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				warden::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				memcpy(value.owner, owner.data(), std::min(sizeof(value.owner), owner.size()));
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		std::string_view wardenstate::get_cache_location(warden::cache_policy policy)
		{
			switch (policy)
			{
				case warden::cache_policy::lifetime_cache:
					return "cache0";
				case warden::cache_policy::temporary_cache:
				default:
					return "cache1";
				case warden::cache_policy::blob_cache:
					return "cache2";
			}
		}
		bool wardenstate::reconstruct_storage()
		{
			const uint32_t max_cache1_capacity = protocol::now().user.nss.cache1_size;
			const uint32_t max_cache2_capacity = protocol::now().user.nss.cache2_size;
			string command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS coins
				(
					transaction_id_index BINARY NOT NULL,
					owner BINARY(20) NOT NULL,
					public_key TEXT NOT NULL,
					address TEXT NOT NULL,
					spent BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (transaction_id_index)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS coins_spent_owner ON coins (spent, owner);
				CREATE INDEX IF NOT EXISTS coins_spent_public_key ON coins (spent, public_key);
				CREATE INDEX IF NOT EXISTS coins_spent_address ON coins (spent, address);
				CREATE TABLE IF NOT EXISTS transactions
				(
					transaction_id TEXT NOT NULL,
					external_id BINARY DEFAULT NULL,
					block_id BIGINT NOT NULL,
					finalized BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (transaction_id)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS transactions_block_id_finalized ON transactions (block_id, finalized);
				CREATE TABLE IF NOT EXISTS links
				(
					owner BINARY(20) NOT NULL,
					public_key TEXT NOT NULL,
					address TEXT NOT NULL,
					typeless_public_key BINARY NOT NULL,
					typeless_address BINARY NOT NULL,
					PRIMARY KEY (owner, typeless_public_key, typeless_address)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS links_typeless_public_key ON links (typeless_public_key);
				CREATE INDEX IF NOT EXISTS links_typeless_address ON links (typeless_address);
				CREATE TABLE IF NOT EXISTS properties
				(
					key TEXT NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS cache0
				(
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS cache1
				(
					id INTEGER PRIMARY KEY,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
					UNIQUE (key)
				);
				CREATE TRIGGER IF NOT EXISTS cache1_capacity AFTER INSERT ON cache1 BEGIN
					DELETE FROM cache1 WHERE id = (SELECT id FROM cache1 ORDER BY id ASC) AND (SELECT COUNT(1) FROM cache1) > max_cache1_capacity;
				END;
				CREATE TABLE IF NOT EXISTS cache2
				(
					id INTEGER PRIMARY KEY,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
					UNIQUE (key)
				);
				CREATE TRIGGER IF NOT EXISTS cache2_capacity AFTER INSERT ON cache2 BEGIN
					DELETE FROM cache2 WHERE id = (SELECT id FROM cache2 ORDER BY id ASC) AND (SELECT COUNT(1) FROM cache2) > max_cache2_capacity;
				END;);
			stringify::replace(command, "max_cache1_capacity", to_string(max_cache1_capacity));
			stringify::replace(command, "max_cache2_capacity", to_string(max_cache2_capacity));

			auto cursor = query(label, __func__, command);
			return (cursor && !cursor->error());
		}
	}
}