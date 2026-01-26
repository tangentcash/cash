#include "superchainstate.h"
#undef NULL

namespace tangent
{
	namespace storages
	{
		struct superchainstate_schema_ptr
		{
			algorithm::asset_id asset = 0;
			sqlite::connection* connection = nullptr;
			repository* database = nullptr;
		};

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
		static std::string_view load_link_field(superchain::wallet_link::search_term term)
		{
			switch (term)
			{
				case superchain::wallet_link::search_term::owner:
					return "owner";
				case superchain::wallet_link::search_term::public_key:
					return "typeless_public_key";
				case superchain::wallet_link::search_term::address:
					return "typeless_address";
				default:
					return "";
			}
		}
		static schema* load_link_value(superchain::wallet_link::search_term term, const superchain::wallet_link& link)
		{
			switch (term)
			{
				case superchain::wallet_link::search_term::owner:
					return var::set::binary(link.owner.view());
				case superchain::wallet_link::search_term::public_key:
					return var::set::binary(to_typeless(link.public_key));
				case superchain::wallet_link::search_term::address:
					return var::set::binary(to_typeless(link.address));
				default:
					return nullptr;
			}
		}

		static thread_local superchainstate* parent_superchainstate = nullptr;
		superchainstate::superchainstate(const algorithm::asset_id& new_asset) noexcept : asset(new_asset)
		{
#ifndef NDEBUG
			local_id = std::this_thread::get_id();
#endif
			if (!parent_superchainstate)
				parent_superchainstate = this;
		}
		superchainstate::~superchainstate() noexcept
		{
#ifndef NDEBUG
			VI_ASSERT(local_id == std::this_thread::get_id(), "mempoolstate thread must not change");
#endif
			if (parent_superchainstate == this)
				parent_superchainstate = nullptr;
		}
		expects_lr<void> superchainstate::receive_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t block_id, const superchain::coin_utxo& value)
		{
			auto copy = value;
			copy.transaction_id = transaction_id;
			copy.index = index;

			format::wo_stream message;
			if (!copy.store(&message))
				return expects_lr<void>(layer_exception("utxo serialization error"));

			format::wo_stream transaction_id_index;
			transaction_id_index.write_string(copy.transaction_id);
			transaction_id_index.write_integer(copy.index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));
			map.push_back(block_id > 0 ? var::set::integer(block_id) : var::set::null());
			map.push_back(var::set::boolean(false));
			map.push_back(var::set::binary(copy.link.owner.view()));
			map.push_back(var::set::string(copy.link.public_key));
			map.push_back(var::set::string(copy.link.address));
			map.push_back(var::set::binary(message.data));
			
			auto cursor = get_storage().emplace_query(__func__, "INSERT OR REPLACE INTO coins (transaction_id_index, receiver_block_id, spent, owner, public_key, address, message) VALUES (?, ?, ?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> superchainstate::spend_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t block_id)
		{
			format::wo_stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(block_id > 0 ? var::set::integer(block_id) : var::set::null());
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = get_storage().emplace_query(__func__, "UPDATE coins SET spender_block_id = ?, spent = TRUE WHERE transaction_id_index = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> superchainstate::revive_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::wo_stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = get_storage().emplace_query(__func__,
				"UPDATE coins SET spent = FALSE WHERE transaction_id_index = ? AND receiver_block_id IS NOT NULL AND spender_block_id IS NULL;"
				"DELETE FROM coins WHERE transaction_id_index = ? AND receiver_block_id IS NULL AND spender_block_id IS NULL", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<superchain::coin_utxo> superchainstate::get_stxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::wo_stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM coins WHERE transaction_id_index = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<superchain::coin_utxo>(layer_exception(ledger::storage_util::error_of(cursor)));

			superchain::coin_utxo value;
			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			if (!value.load(message))
				return expects_lr<superchain::coin_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<superchain::coin_utxo> superchainstate::get_utxo(const std::string_view& transaction_id, uint64_t index)
		{
			format::wo_stream transaction_id_index;
			transaction_id_index.write_string(transaction_id);
			transaction_id_index.write_integer(index);

			schema_list map;
			map.push_back(var::set::binary(transaction_id_index.data));

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM coins WHERE transaction_id_index = ? AND spent = FALSE", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<superchain::coin_utxo>(layer_exception(ledger::storage_util::error_of(cursor)));

			superchain::coin_utxo value;
			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			if (!value.load(message))
				return expects_lr<superchain::coin_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<vector<superchain::coin_utxo>> superchainstate::get_utxos(const superchain::wallet_link& link, size_t offset, size_t count)
		{
			if (!link.has_any())
				return expects_lr<vector<superchain::coin_utxo>>(layer_exception("invalid link"));

			auto term = link.as_search_wide();
			schema_list map;
			map.push_back(var::set::string(load_link_field(term)));
			map.push_back(load_link_value(term, link));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM coins WHERE spent = FALSE AND $? = ? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<superchain::coin_utxo>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<superchain::coin_utxo> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				superchain::coin_utxo value;
				auto blob = response[i]["message"].get().get_blob();
				auto message = format::ro_stream(blob);
				if (value.load(message))
					values.emplace_back(std::move(value));
			}

			return values;
		}
		expects_lr<void> superchainstate::add_incoming_transaction(const superchain::computed_transaction& value)
		{
			format::wo_stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			uint8_t optimized_hash[32];
			algorithm::hashing::hash256i(value.transaction_id).encode(optimized_hash);

			schema_list map;
			map.push_back(var::set::binary(optimized_hash, sizeof(optimized_hash)));
			map.push_back(var::set::string(value.transaction_id));
			map.push_back(var::set::integer(value.block_id));
			map.push_back(var::set::binary(message.data));

			auto cursor = get_storage().emplace_query(__func__, "INSERT INTO transactions (optimized_id, transaction_id, block_id, message) VALUES (?, ?, ?, ?) ON CONFLICT (transaction_id) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> superchainstate::add_outgoing_transaction(const superchain::computed_transaction& value, const uint256_t& external_id)
		{
			format::wo_stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			uint8_t external_hash[32];
			external_id.encode(external_hash);

			uint8_t optimized_hash[32];
			algorithm::hashing::hash256i(value.transaction_id).encode(optimized_hash);

			schema_list map;
			map.push_back(external_id > 0 ? var::set::binary(external_hash, sizeof(external_hash)) : var::set::null());
			map.push_back(var::set::binary(optimized_hash, sizeof(optimized_hash)));
			map.push_back(var::set::string(value.transaction_id));
			map.push_back(var::set::integer(value.block_id));
			map.push_back(var::set::binary(message.data));

			auto cursor = get_storage().emplace_query(__func__, "INSERT INTO transactions (external_id, optimized_id, transaction_id, block_id, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (transaction_id) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<superchain::computed_transaction> superchainstate::get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id, const uint256_t& optimized_id)
		{
			uint8_t optimized_hash[32];
			optimized_id.encode(optimized_hash);

			uint8_t external_hash[32];
			external_id.encode(external_hash);

			schema_list map;
			map.push_back(transaction_id.empty() ? var::set::null() : var::set::string(transaction_id));
			map.push_back(external_id > 0 ? var::set::binary(external_hash, sizeof(external_hash)) : var::set::null());
			map.push_back(optimized_id > 0 ? var::set::binary(optimized_hash, sizeof(optimized_hash)) : var::set::null());

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM transactions WHERE transaction_id = ? OR external_id = ? OR optimized_id = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<superchain::computed_transaction>(layer_exception(ledger::storage_util::error_of(cursor)));

			superchain::computed_transaction value;
			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			if (!value.load(message))
				return expects_lr<superchain::computed_transaction>(layer_exception("witness transaction deserialization error"));

			return value;
		}
		expects_lr<void> superchainstate::set_property(const std::string_view& key, const format::tree& value)
		{
			schema_list map;
			map.push_back(var::set::string(algorithm::asset::blockchain_of(asset) + ":" + string(key)));

			if (!value.is_none())
			{
				map.push_back(var::set::binary(value.as_message().compress()));
				auto cursor = get_storage().emplace_query(__func__, "INSERT OR REPLACE INTO properties (key, message) VALUES (?, ?)", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}
			else
			{
				auto cursor = get_storage().emplace_query(__func__, "DELETE FROM properties WHERE key = ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<format::tree> superchainstate::get_property(const std::string_view& key)
		{
			schema_list map;
			map.push_back(var::set::string(algorithm::asset::blockchain_of(asset) + ":" + string(key)));

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM properties WHERE key = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<format::tree>(layer_exception(ledger::storage_util::error_of(cursor)));

			string buffer;
			auto blob = format::util::decompress_stream((*cursor)["message"].get().get_string());
			auto message = format::ro_stream(blob);
			auto value = format::tree::from_message(message);
			if (!value)
				return expects_lr<format::tree>(layer_exception("property deserialization error"));

			return expects_lr<format::tree>(std::move(*value));
		}
		expects_lr<void> superchainstate::set_cache(superchain::cache_policy policy, const std::string_view& key, const format::tree& value)
		{
			schema_list map;
			map.push_back(var::set::binary(format::util::is_hex_encoding(key) ? codec::hex_decode(key) : string(key)));
			if (!value.is_none())
			{
				map.push_back(var::set::binary(value.as_message().compress()));

				auto cursor = get_storage().emplace_query(__func__, stringify::text("INSERT OR REPLACE INTO %s (key, message) VALUES (?, ?)", get_cache_location(policy).data()), &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}
			else
			{
				auto cursor = get_storage().emplace_query(__func__, stringify::text("DELETE FROM %s WHERE key = ?", get_cache_location(policy).data()), &map);
				if (!cursor || cursor->error())
					return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			}

			return expectation::met;
		}
		expects_lr<format::tree> superchainstate::get_cache(superchain::cache_policy policy, const std::string_view& key)
		{
			schema_list map;
			map.push_back(var::set::binary(format::util::is_hex_encoding(key) ? codec::hex_decode(key) : string(key)));

			auto cursor = get_storage().emplace_query(__func__, stringify::text("SELECT message FROM %s WHERE key = ?", get_cache_location(policy).data()), &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<format::tree>(layer_exception(ledger::storage_util::error_of(cursor)));

			string buffer;
			auto blob = format::util::decompress_stream((*cursor)["message"].get().get_string());
			auto message = format::ro_stream(blob);
			auto value = format::tree::from_message(message);
			if (!value)
				return expects_lr<format::tree>(layer_exception("property deserialization error"));

			return expects_lr<format::tree>(std::move(*value));
		}
		expects_lr<void> superchainstate::set_link(const superchain::wallet_link& value)
		{
			schema_list map;
			map.push_back(var::set::binary(value.owner.view()));
			map.push_back(var::set::string(value.public_key));
			map.push_back(var::set::string(value.address));
			map.push_back(var::set::binary(to_typeless(value.public_key)));
			map.push_back(var::set::binary(to_typeless(value.address)));

			auto cursor = get_storage().emplace_query(__func__, "INSERT OR REPLACE INTO links (owner, public_key, address, typeless_public_key, typeless_address) VALUES (?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> superchainstate::clear_link(const superchain::wallet_link& value)
		{
			auto term = value.as_search_wide();
			schema_list map;
			map.push_back(var::set::string(load_link_field(term)));
			map.push_back(load_link_value(term, value));

			auto cursor = get_storage().emplace_query(__func__, "DELETE FROM links WHERE $? = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<superchain::wallet_link> superchainstate::get_link(const std::string_view& address)
		{
			schema_list map;
			map.push_back(var::set::binary(to_typeless(address)));

			auto cursor = get_storage().emplace_query(__func__, "SELECT * FROM links WHERE typeless_address = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<superchain::wallet_link>(layer_exception(ledger::storage_util::error_of(cursor)));

			superchain::wallet_link value;
			auto owner = (*cursor)["owner"].get().get_blob();
			value.owner = algorithm::pubkeyhash_t(owner);
			value.public_key = (*cursor)["public_key"].get().get_blob();
			value.address = (*cursor)["address"].get().get_blob();
			return value;
		}
		expects_lr<hash_map<string, superchain::wallet_link>> superchainstate::get_links_by_public_keys(const hash_set<string>& public_keys)
		{
			uptr<schema> public_key_list = var::set::array();
			public_key_list->reserve(public_keys.size());
			for (auto& item : public_keys)
			{
				if (!item.empty())
					public_key_list->push(var::binary(to_typeless(item)));
			}
			if (public_key_list->empty())
				return expects_lr<hash_map<string, superchain::wallet_link>>(layer_exception("no public keys"));

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(public_key_list))));

			auto cursor = get_storage().emplace_query(__func__, "SELECT * FROM links WHERE typeless_public_key IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<hash_map<string, superchain::wallet_link>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			hash_map<string, superchain::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				superchain::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				value.owner = algorithm::pubkeyhash_t(owner);
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		expects_lr<hash_map<string, superchain::wallet_link>> superchainstate::get_links_by_addresses(const hash_set<string>& addresses)
		{
			size_t address_count = 0;
			string query = "SELECT * FROM links WHERE typeless_address IN (";
			for (auto& item : addresses)
			{
				if (!item.empty())
				{
					query.append("x\'").append(codec::hex_encode(to_typeless(item))).append("\',");
					++address_count;
				}
			}
			if (addresses.empty() || !address_count)
				return expects_lr<hash_map<string, superchain::wallet_link>>(layer_exception("no addresses"));

			query.back() = ')';
			auto cursor = get_storage().query(__func__, query);
			if (!cursor || cursor->error())
				return expects_lr<hash_map<string, superchain::wallet_link>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			hash_map<string, superchain::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				superchain::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				value.owner = algorithm::pubkeyhash_t(owner);
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		expects_lr<hash_map<string, superchain::wallet_link>> superchainstate::get_links_by_owner(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count)
		{
			schema_list map;
			if (!owner.empty())
				map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, !owner.empty() ? "SELECT * FROM links WHERE owner = ? LIMIT ? OFFSET ?" : "SELECT * FROM links LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<hash_map<string, superchain::wallet_link>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			hash_map<string, superchain::wallet_link> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				superchain::wallet_link value;
				auto owner = row["owner"].get().get_blob();
				value.owner = algorithm::pubkeyhash_t(owner);
				value.public_key = row["public_key"].get().get_blob();
				value.address = row["address"].get().get_blob();
				values[string(value.address)] = std::move(value);
			}

			return values;
		}
		ledger::storage_index_ptr& superchainstate::get_storage()
		{
			if (!local_storage.may_use())
			{
				if (!parent_superchainstate->local_storage.may_use() || parent_superchainstate->asset != asset)
				{
					string blockchain = algorithm::asset::blockchain_of(asset);
					parent_superchainstate->local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_of("superchainstate." + stringify::to_lower(blockchain) + "data", &superchainstate::make_schema));
				}
				local_storage = parent_superchainstate->local_storage;
			}
			return local_storage;
		}
		std::string_view superchainstate::get_cache_location(superchain::cache_policy policy)
		{
			switch (policy)
			{
				case superchain::cache_policy::lifetime_cache:
					return "cache0";
				case superchain::cache_policy::temporary_cache:
				default:
					return "cache1";
				case superchain::cache_policy::blob_cache:
					return "cache2";
			}
		}
		uint32_t superchainstate::get_queries() const
		{
			return local_storage.uses();
		}
		bool superchainstate::make_schema(sqlite::connection* connection)
		{
			string command = VI_STRINGIFY(
			CREATE TABLE IF NOT EXISTS coins
			(
				transaction_id_index BLOB NOT NULL,
				receiver_block_id BIGINT DEFAULT NULL,
				spender_block_id BIGINT DEFAULT NULL,
				spent BOOLEAN NOT NULL,
				owner BLOB(20) NOT NULL,
				public_key TEXT NOT NULL,
				address TEXT NOT NULL,
				message BLOB NOT NULL,
  				PRIMARY KEY (transaction_id_index)
			) WITHOUT ROWID;
			CREATE INDEX IF NOT EXISTS coins_spent_owner ON coins (spent, owner);
			CREATE INDEX IF NOT EXISTS coins_spent_public_key ON coins (spent, public_key);
			CREATE INDEX IF NOT EXISTS coins_spent_address ON coins (spent, address);
			CREATE TABLE IF NOT EXISTS transactions
			(
				transaction_id TEXT NOT NULL,
				optimized_id BLOB DEFAULT NULL,
				external_id BLOB DEFAULT NULL,
				block_id BIGINT NOT NULL,
				message BLOB NOT NULL,
  				PRIMARY KEY (transaction_id)
			) WITHOUT ROWID;
			CREATE TABLE IF NOT EXISTS links
			(
				owner BLOB(20) NOT NULL,
				public_key TEXT NOT NULL,
				address TEXT NOT NULL,
				typeless_public_key BLOB NOT NULL,
				typeless_address BLOB NOT NULL,
				PRIMARY KEY (owner, typeless_public_key, typeless_address)
			) WITHOUT ROWID;
			CREATE INDEX IF NOT EXISTS links_typeless_public_key ON links (typeless_public_key);
			CREATE INDEX IF NOT EXISTS links_typeless_address ON links (typeless_address);
			CREATE TABLE IF NOT EXISTS properties
			(
				key TEXT NOT NULL,
				message BLOB NOT NULL,
  				PRIMARY KEY (key)
			) WITHOUT ROWID;
			CREATE TABLE IF NOT EXISTS cache0
			(
				key BLOB NOT NULL,
				message BLOB NOT NULL,
  				PRIMARY KEY (key)
			) WITHOUT ROWID;
			CREATE TABLE IF NOT EXISTS cache1
			(
				id INTEGER PRIMARY KEY,
				key BLOB NOT NULL,
				message BLOB NOT NULL,
				UNIQUE (key)
			);
			CREATE TRIGGER IF NOT EXISTS cache1_capacity AFTER INSERT ON cache1 BEGIN
				DELETE FROM cache1 WHERE id = (SELECT id FROM cache1 ORDER BY id ASC) AND (SELECT COUNT(1) FROM cache1) > max_cache1_capacity;
			END;
			CREATE TABLE IF NOT EXISTS cache2
			(
				id INTEGER PRIMARY KEY,
				key BLOB NOT NULL,
				message BLOB NOT NULL,
				UNIQUE (key)
			);
			CREATE TRIGGER IF NOT EXISTS cache2_capacity AFTER INSERT ON cache2 BEGIN
				DELETE FROM cache2 WHERE id = (SELECT id FROM cache2 ORDER BY id ASC) AND (SELECT COUNT(1) FROM cache2) > max_cache2_capacity;
			END;);
			stringify::replace(command, "max_cache1_capacity", to_string(protocol::now().user.superchain.cache1_size));
			stringify::replace(command, "max_cache2_capacity", to_string(protocol::now().user.superchain.cache2_size));

			auto cursor = connection->query(command);
			cursor.report("superchainstate configuration failed");
			return (cursor && !cursor->error());
		}
	}
}