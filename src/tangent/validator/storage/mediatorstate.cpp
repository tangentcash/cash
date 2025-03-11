#include "mediatorstate.h"
#include "../service/nss.h"
#undef NULL

namespace tangent
{
	namespace storages
	{
		mediatorstate::mediatorstate(const std::string_view& new_label, const algorithm::asset_id& new_asset) noexcept : asset(new_asset), label(new_label)
		{
			string blockchain = algorithm::asset::blockchain_of(asset);
			storage_of("mediatorstate." + stringify::to_lower(blockchain) + "data");
		}
		expects_lr<void> mediatorstate::add_master_wallet(const mediator::master_wallet& value)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("wallet serialization error"));

			auto blob = protocol::now().key.encrypt_blob(message.data);
			if (!blob)
				return blob.error();

			uint8_t hash[32];
			algorithm::encoding::decode_uint256(value.as_hash(), hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(date_time().milliseconds()));
			map.push_back(var::set::binary(*blob));

			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, -1, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<mediator::master_wallet> mediatorstate::get_master_wallet()
		{
			auto cursor = query(label, __func__, "SELECT message FROM wallets WHERE address_index = -1 ORDER BY nonce DESC LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::master_wallet>(layer_exception(error_of(cursor)));

			auto blob = protocol::now().key.decrypt_blob((*cursor)["message"].get().get_blob());
			if (!blob)
				return blob.error();

			mediator::master_wallet value;
			format::stream message = format::stream(std::move(*blob));
			if (!value.load(message))
				return expects_lr<mediator::master_wallet>(layer_exception("wallet deserialization error"));

			return value;
		}
		expects_lr<mediator::master_wallet> mediatorstate::get_master_wallet_by_hash(const uint256_t& master_wallet_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(master_wallet_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = -1", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::master_wallet>(layer_exception(error_of(cursor)));

			auto blob = protocol::now().key.decrypt_blob((*cursor)["message"].get().get_blob());
			if (!blob)
				return blob.error();

			mediator::master_wallet value;
			format::stream message = format::stream(std::move(*blob));
			if (!value.load(message))
				return expects_lr<mediator::master_wallet>(layer_exception("wallet deserialization error"));

			return value;
		}
		expects_lr<void> mediatorstate::add_derived_wallet(const mediator::master_wallet& parent, const mediator::derived_signing_wallet& value)
		{
			if (!value.is_valid())
				return expects_lr<void>(layer_exception("invalid wallet"));

			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("wallet serialization error"));

			auto blob = protocol::now().key.encrypt_blob(message.data);
			if (!blob)
				return blob.error();

			uint8_t hash[32];
			algorithm::encoding::decode_uint256(parent.as_hash(), hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(value.address_index.or_else(0)));
			map.push_back(var::set::integer(date_time().milliseconds()));
			map.push_back(var::set::binary(*blob));

			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return add_master_wallet(parent);
		}
		expects_lr<mediator::derived_signing_wallet> mediatorstate::get_derived_wallet(const uint256_t& master_wallet_hash, uint64_t address_index)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(master_wallet_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(address_index));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::derived_signing_wallet>(layer_exception(error_of(cursor)));

			auto blob = protocol::now().key.decrypt_blob((*cursor)["message"].get().get_blob());
			if (!blob)
				return blob.error();

			mediator::derived_signing_wallet value;
			format::stream message = format::stream(std::move(*blob));
			if (!value.load(message))
				return expects_lr<mediator::derived_signing_wallet>(layer_exception("wallet deserialization error"));

			return value;
		}
		expects_lr<void> mediatorstate::add_utxo(const mediator::index_utxo& value)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("utxo serialization error"));

			schema_list map;
			map.push_back(var::set::binary(get_coin_location(value.UTXO.transaction_id, value.UTXO.index)));
			map.push_back(var::set::binary(value.binding));
			map.push_back(var::set::boolean(false));
			map.push_back(var::set::binary(message.data));
			
			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO coins (location, binding, spent, message) VALUES (?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mediatorstate::remove_utxo(const std::string_view& transaction_id, uint32_t index)
		{
			schema_list map;
			map.push_back(var::set::binary(get_coin_location(transaction_id, index)));

			auto cursor = emplace_query(label, __func__, "UPDATE coins SET spent = TRUE WHERE location = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<mediator::index_utxo> mediatorstate::get_stxo(const std::string_view& transaction_id, uint32_t index)
		{
			schema_list map;
			map.push_back(var::set::string(string(transaction_id) + ":" + to_string(index)));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE location = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::index_utxo>(layer_exception(error_of(cursor)));

			mediator::index_utxo value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<mediator::index_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<mediator::index_utxo> mediatorstate::get_utxo(const std::string_view& transaction_id, uint32_t index)
		{
			schema_list map;
			map.push_back(var::set::binary(get_coin_location(transaction_id, index)));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE location = ? AND spent = FALSE", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::index_utxo>(layer_exception(error_of(cursor)));

			mediator::index_utxo value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<mediator::index_utxo>(layer_exception("utxo deserialization error"));

			return value;
		}
		expects_lr<vector<mediator::index_utxo>> mediatorstate::get_utxos(const std::string_view& binding, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::binary(binding));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM coins WHERE spent = FALSE AND binding = ? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<mediator::index_utxo>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<mediator::index_utxo> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				mediator::index_utxo value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (value.load(message))
					values.emplace_back(std::move(value));
			}

			return values;
		}
		expects_lr<void> mediatorstate::add_incoming_transaction(const mediator::incoming_transaction& value, uint64_t block_id)
		{
			auto* chain = nss::server_node::get()->get_chain(value.asset);
			if (!chain)
				return expects_lr<void>(layer_exception("invalid witness transaction asset"));

			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			schema_list map;
			map.push_back(var::set::binary(get_transaction_location(value.transaction_id)));
			map.push_back(var::set::null());
			map.push_back(var::set::integer(value.block_id));
			map.push_back(var::set::boolean(value.block_id <= block_id ? block_id - value.block_id >= chain->get_chainparams().sync_latency : false));
			map.push_back(var::set::binary(message.data));

			auto cursor = emplace_query(label, __func__, "INSERT INTO transactions (location, binding, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET binding = (CASE WHEN binding IS NOT NULL THEN binding ELSE EXCLUDED.binding END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mediatorstate::add_outgoing_transaction(const mediator::incoming_transaction& value, const uint256_t external_id)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("witness transaction serialization error"));

			uint8_t hash[32];
			algorithm::encoding::decode_uint256(external_id, hash);

			schema_list map;
			map.push_back(var::set::binary(get_transaction_location(value.transaction_id)));
			map.push_back(external_id > 0 ? var::set::binary(hash, sizeof(hash)) : var::set::null());
			map.push_back(var::set::integer(value.block_id));
			map.push_back(var::set::boolean(false));
			map.push_back(var::set::binary(message.data));

			auto cursor = emplace_query(label, __func__, "INSERT INTO transactions (location, external_id, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<mediator::incoming_transaction> mediatorstate::get_transaction(const std::string_view& transaction_id, const uint256_t& external_id)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(external_id, hash);

			schema_list map;
			map.push_back(var::set::binary(get_transaction_location(transaction_id)));
			map.push_back(external_id > 0 ? var::set::binary(hash, sizeof(hash)) : var::set::null());

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE location = ? OR binding = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::incoming_transaction>(layer_exception(error_of(cursor)));

			mediator::incoming_transaction value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<mediator::incoming_transaction>(layer_exception("witness transaction deserialization error"));

			return value;
		}
		expects_lr<vector<mediator::incoming_transaction>> mediatorstate::approve_transactions(uint64_t block_height, uint64_t block_latency)
		{
			if (!block_height || !block_latency)
				return expects_lr<vector<mediator::incoming_transaction>>(layer_exception("invalid block height or block latency"));
			else if (block_height <= block_latency)
				return expects_lr<vector<mediator::incoming_transaction>>(vector<mediator::incoming_transaction>());

			schema_list map;
			map.push_back(var::set::integer(block_height - block_latency));
			map.push_back(var::set::integer(block_height - block_latency));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE block_id <= ? AND approved = FALSE", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<mediator::incoming_transaction>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<mediator::incoming_transaction> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				mediator::incoming_transaction value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (!value.load(message))
					continue;

				if (value.block_id > 0)
				{
					if (add_incoming_transaction(value, block_height))
						values.emplace_back(std::move(value));
				}
				else
				{
					value.block_id = block_height;
					add_incoming_transaction(value, block_height);
				}
			}

			return expects_lr<vector<mediator::incoming_transaction>>(std::move(values));
		}
		expects_lr<void> mediatorstate::set_property(const std::string_view& key, uptr<schema>&& value)
		{
			auto buffer = schema::to_jsonb(*value);
			format::stream message;
			message.write_string(std::string_view(buffer.begin(), buffer.end()));

			schema_list map;
			map.push_back(var::set::string(algorithm::asset::blockchain_of(asset) + ":" + string(key)));
			map.push_back(var::set::binary(message.compress()));

			if (value)
			{
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
		expects_lr<schema*> mediatorstate::get_property(const std::string_view& key)
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
		expects_lr<void> mediatorstate::set_cache(mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value)
		{
			auto buffer = schema::to_jsonb(*value);
			format::stream message;
			message.write_string(std::string_view(buffer.begin(), buffer.end()));

			schema_list map;
			map.push_back(var::set::binary(format::util::is_hex_encoding(key) ? codec::hex_decode(key) : string(key)));
			map.push_back(var::set::binary(message.compress()));

			if (value)
			{
				auto cursor = emplace_query(label, __func__, stringify::text("INSERT INTO %s (key, message) VALUES (?, ?)", get_cache_location(policy).data()), &map);
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
		expects_lr<schema*> mediatorstate::get_cache(mediator::cache_policy policy, const std::string_view& key)
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
		expects_lr<void> mediatorstate::set_address_index(const std::string_view& address, const mediator::index_address& value)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("address index serialization error"));

			schema_list map;
			map.push_back(var::set::binary(get_address_location(address)));
			map.push_back(var::set::binary(message.data));

			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO addresses (location, message) VALUES (?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mediatorstate::clear_address_index(const std::string_view& address)
		{
			schema_list map;
			map.push_back(var::set::binary(get_address_location(address)));

			auto cursor = emplace_query(label, __func__, "DELETE FROM addresses WHERE location = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<mediator::index_address> mediatorstate::get_address_index(const std::string_view& address)
		{
			schema_list map;
			map.push_back(var::set::binary(get_address_location(address)));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM addresses WHERE location = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<mediator::index_address>(layer_exception(error_of(cursor)));

			mediator::index_address value;
			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<mediator::index_address>(layer_exception("address index deserialization error"));

			return value;
		}
		expects_lr<unordered_map<string, mediator::index_address>> mediatorstate::get_address_indices(const unordered_set<string>& addresses)
		{
			uptr<schema> address_list = var::set::array();
			address_list->reserve(addresses.size());
			for (auto& item : addresses)
			{
				if (!item.empty())
					address_list->push(var::binary(get_address_location(item)));
			}
			if (address_list->empty())
				return expects_lr<unordered_map<string, mediator::index_address>>(layer_exception("no locations"));

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(address_list))));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM addresses WHERE location IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<unordered_map<string, mediator::index_address>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			unordered_map<string, mediator::index_address> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				mediator::index_address value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (value.load(message))
					values[value.address] = std::move(value);
			}

			return values;
		}
		expects_lr<vector<string>> mediatorstate::get_address_indices()
		{
			auto cursor = query(label, __func__, "SELECT message FROM addresses");
			if (!cursor || cursor->error())
				return expects_lr<vector<string>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<string> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				mediator::index_address value;
				format::stream message = format::stream(response[i]["message"].get().get_blob());
				if (value.load(message))
					values.emplace_back(std::move(value.address));
			}

			return values;
		}
		std::string_view mediatorstate::get_cache_location(mediator::cache_policy policy)
		{
			switch (policy)
			{
				case mediator::cache_policy::persistent:
					return "persistent_caches";
				case mediator::cache_policy::extended:
					return "extended_caches";
				case mediator::cache_policy::greedy:
				case mediator::cache_policy::lazy:
				case mediator::cache_policy::shortened:
				default:
					return "shortened_caches";
			}
		}
		string mediatorstate::get_address_location(const std::string_view& address)
		{
			format::stream message;
			message.write_string(address);
			return message.data;
		}
		string mediatorstate::get_transaction_location(const std::string_view& transaction_id)
		{
			format::stream message;
			message.write_string(transaction_id);
			return message.data;
		}
		string mediatorstate::get_coin_location(const std::string_view& transaction_id, uint32_t index)
		{
			format::stream message;
			message.write_string(transaction_id);
			message.write_typeless(index);
			return message.data;
		}
		bool mediatorstate::reconstruct_storage()
		{
			const uint32_t max_ecache_capacity = protocol::now().user.nss.cache_extended_size;
			const uint32_t max_scache_capacity = protocol::now().user.nss.cache_short_size;
			string command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS wallets
				(
					hash BINARY(32) NOT NULL,
					address_index INTEGER NOT NULL,
					nonce INTEGER NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (hash, address_index)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS wallets_nonce_address_index ON wallets (nonce, address_index);
				CREATE TABLE IF NOT EXISTS coins
				(
					location BINARY NOT NULL,
					binding BINARY(32) NOT NULL,
					spent BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS coins_spent_binding ON coins (spent, binding);
				CREATE TABLE IF NOT EXISTS transactions
				(
					location BINARY NOT NULL,
					binding BINARY(32) DEFAULT NULL,
					block_id BIGINT NOT NULL,
					approved BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS transactions_binding ON transactions (binding);
				CREATE INDEX IF NOT EXISTS transactions_block_id_approved ON transactions (block_id, approved);
				CREATE TABLE IF NOT EXISTS addresses
				(
					location BINARY NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS properties
				(
					key TEXT NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS persistent_caches
				(
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS extended_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				) WITHOUT ROWID;
				CREATE TRIGGER IF NOT EXISTS extended_caches_capacity AFTER INSERT ON extended_caches BEGIN
					DELETE FROM extended_caches WHERE id = (SELECT id FROM extended_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM extended_caches) > max_extended_cache_capacity;
				END;
				CREATE TABLE IF NOT EXISTS shortened_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				) WITHOUT ROWID;
				CREATE TRIGGER IF NOT EXISTS shortened_caches_capacity AFTER INSERT ON shortened_caches BEGIN
					DELETE FROM shortened_caches WHERE id = (SELECT id FROM shortened_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM shortened_caches) > max_shortened_cache_capacity;
				END;);
			stringify::replace(command, "max_extended_cache_capacity", to_string(max_ecache_capacity));
			stringify::replace(command, "max_shortened_cache_capacity", to_string(max_scache_capacity));

			auto cursor = query(label, __func__, command);
			return (cursor && !cursor->error());
		}
	}
}