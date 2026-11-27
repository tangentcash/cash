#include "mempoolstate.h"
#include "../policy/transactions.h"
#define TRANSACTION_EXPIRATION (12 * 3600 * 1000)
#define OBSERVATION_EXPIRATION (36 * 3600 * 1000)
#define ATTESTATION_EXPIRATION (48 * 3600 * 1000)
#define KEY_SIZE 32
#define WRAP_SALT_SIZE 16
#define GCM_IV_SIZE 12
#undef NULL

namespace tangent
{
	namespace storages
	{
		static bool append_hash_literals(string& list, const std::function<bool(uint256_t&, size_t&)>& match)
		{
			static constexpr char digits[] = "0123456789abcdef";
			uint8_t hash[32], literal[64];
			uint256_t value = uint256_t(0);
			size_t offset = 0, count = 0;
			while (match(value, offset))
			{
				value.encode(hash); memset(&value, 0, sizeof(value));
				for (size_t i = 0; i < sizeof(hash); i++)
				{
					literal[0 + i * 2] = digits[hash[i] >> 4];
					literal[1 + i * 2] = digits[hash[i] & 0x0f];
				}
				list.append(offset > 0 ? ",x\'" : "x\'");
				list.append((char*)literal, sizeof(literal));
				list.append(1, '\'');
				++offset; ++count;
			}
			return !count;
		}
		static string derive_iv(const std::string_view& salt, mempoolstate::keystore::db_id db)
		{
			return string(*crypto::hash(digests::sha256(), string(salt).append(mempoolstate::keystore::name_of(db)).append("mempool-iv")), 0, GCM_IV_SIZE);
		}
		static string read_password_line(const std::string_view& prompt, bool allow_empty = false)
		{
			VI_INFO("keystate pwd prompt: awaiting input...");
			string password; auto* terminal = console::get();
			terminal->echo_off([&]() { password = terminal->read(1024); });
			stringify::trim(password);

			VI_PANIC(!password.empty() || allow_empty, "keystore password required but stdin delivered nothing (attach a terminal or pipe the password, e.g. 'printf \"$PASS\" | docker attach --sig-proxy=false <node>')");
			VI_INFO("keystate pwd prompt: input received");
			return password;
		}
		static void finalize_checksum(ledger::authentic_serializer& message, const variant& column)
		{
			if (column.size() == sizeof(uint256_t))
				message.checksum.decode(column.get_binary());
		}
		static string address_to_message(const socket_address& address)
		{
			format::wo_stream message;
			message.write_string(address.get_ip_address().or_else("[bad_address]"));
			message.write_integer(address.get_ip_port().or_else(0));
			return message.data;
		}
		static option<socket_address> message_to_address(const std::string_view& data)
		{
			format::ro_stream message(data);
			string ip_address;
			if (!message.read_string(message.read_type(), &ip_address))
				return optional::none;

			uint16_t ip_port;
			if (!message.read_integer(message.read_type(), &ip_port))
				return optional::none;

			socket_address address(ip_address, ip_port);
			if (!address.is_valid())
				return optional::none;

			return address;
		}

		bool routing_util::is_address_reserved(const socket_address& address)
		{
			auto value = address.get_ip_value();
			if (!value)
				return false;

			static std::array<socket_cidr, 20> reserved_ips =
			{
				*vitex::network::utils::parse_address_mask("0.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("100.64.0.0/10"),
				*vitex::network::utils::parse_address_mask("169.254.0.0/16"),
				*vitex::network::utils::parse_address_mask("192.0.0.0/24"),
				*vitex::network::utils::parse_address_mask("192.0.2.0/24"),
				*vitex::network::utils::parse_address_mask("198.18.0.0/15"),
				*vitex::network::utils::parse_address_mask("198.51.100.0/24"),
				*vitex::network::utils::parse_address_mask("233.252.0.0/24"),
				*vitex::network::utils::parse_address_mask("255.255.255.255/32"),
				*vitex::network::utils::parse_address_mask("::/128"),
				*vitex::network::utils::parse_address_mask("::ffff:0:0/96"),
				*vitex::network::utils::parse_address_mask("::ffff:0:0:0/96"),
				*vitex::network::utils::parse_address_mask("2001:20::/28"),
				*vitex::network::utils::parse_address_mask("2001:db8::/32"),
				*vitex::network::utils::parse_address_mask("5f00::/16")
			};

			for (auto& mask : reserved_ips)
			{
				if (mask.is_matching(*value))
					return true;
			}

			return false;
		}
		bool routing_util::is_address_loopback(const socket_address& address)
		{
			auto value = address.get_ip_value();
			if (!value)
				return false;

			static socket_cidr loopback_ip = *vitex::network::utils::parse_address_mask("127.0.0.0/8");
			return loopback_ip.is_matching(*value);
		}
		bool routing_util::is_address_private(const socket_address& address)
		{
			auto value = address.get_ip_value();
			if (!value)
				return false;

			static std::array<socket_cidr, 20> reserved_ips =
			{
				*vitex::network::utils::parse_address_mask("10.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("127.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("172.16.0.0/12"),
				*vitex::network::utils::parse_address_mask("192.168.0.0/16"),
				*vitex::network::utils::parse_address_mask("::1/128"),
				*vitex::network::utils::parse_address_mask("fc00::/7"),
				*vitex::network::utils::parse_address_mask("fe80::/10"),
				*vitex::network::utils::parse_address_mask("fd00::/8")
			};

			for (auto& mask : reserved_ips)
			{
				if (mask.is_matching(*value))
					return true;
			}

			return false;
		}
		bool routing_util::is_address_reserved_or_private(const socket_address& address)
		{
			return is_address_reserved(address) || is_address_private(address);
		}

		const std::string_view mempoolstate::keystore::name_of(db_id db)
		{
			switch (db)
			{
				case db_id::peers:
					return "peerdata";
				case db_id::secrets:
					return "secretdata";
				default:
					VI_PANIC(false, "invalid keystore db id");
					return "";
			}
		}
		std::unique_lock<std::recursive_mutex> mempoolstate::keystore::sync() const
		{
			return std::unique_lock<std::recursive_mutex>(mutex);
		}
		void mempoolstate::keystore::store(db_id db, const secret_box& key, const secret_box& wrap_key)
		{
			umutex<std::recursive_mutex> unique(mutex);
			auto& state = dbs[(uint8_t)db];
			state.key = key;
			state.wrap_key = wrap_key;
			state.ready = true;
		}
		bool mempoolstate::keystore::ready(db_id db) const
		{
			umutex<std::recursive_mutex> unique(mutex);
			return dbs[(uint8_t)db].ready;
		}
		bool mempoolstate::keystore::is_wrapped(db_id db) const
		{
			umutex<std::recursive_mutex> unique(mutex);
			return dbs[(uint8_t)db].ready && !dbs[(uint8_t)db].wrap_key.empty();
		}
		secret_box mempoolstate::keystore::key_of(db_id db) const
		{
			umutex<std::recursive_mutex> unique(mutex);
			return dbs[(uint8_t)db].key;
		}
		secret_box mempoolstate::keystore::wrap_key_of(db_id db) const
		{
			umutex<std::recursive_mutex> unique(mutex);
			return dbs[(uint8_t)db].wrap_key;
		}
		bool mempoolstate::keystore::current_key(db_id db, secret_box& key) const
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!dbs[(uint8_t)db].ready)
				return false;
			key = dbs[(uint8_t)db].key;
			return true;
		}
		expects_lr<string> mempoolstate::keystore::encrypt(db_id db, const std::string_view& data) const
		{
			secret_box key;
			if (!current_key(db, key))
				return expects_lr<string>(layer_exception("keystore is not initialized"));

			return row_encrypt(key, data);
		}
		expects_lr<string> mempoolstate::keystore::decrypt(db_id db, const std::string_view& data) const
		{
			secret_box key;
			if (!current_key(db, key))
				return expects_lr<string>(layer_exception("keystore is not initialized"));

			return row_decrypt(key, data);
		}
		secret_box mempoolstate::keystore::derive_wrap_key(const std::string_view& password)
		{
			uint8_t seed[KEY_SIZE] = { 0 };
			bool acquired = algorithm::signing::derive_seed_from_high_entropy_password((uint8_t*)password.data(), password.size(), seed, sizeof(seed));
			VI_PANIC(acquired, "keystore password derivation failed");
			return secret_box::secure(std::string_view((char*)seed, sizeof(seed)));
		}
		expects_lr<string> mempoolstate::keystore::wrap(const secret_box& key, const secret_box& wrap_key, db_id db, string& out_salt)
		{
			auto salt = *crypto::random_bytes(WRAP_SALT_SIZE);
			auto iv = derive_iv(salt, db);
			auto result = crypto::encrypt(ciphers::aes_256_gcm(), key.heap(), wrap_key, secret_box::view(iv));
			if (!result)
				return expects_lr<string>(layer_exception("keystore wrap failed"));

			out_salt = salt;
			return *result;
		}
		expects_lr<string> mempoolstate::keystore::unwrap(const std::string_view& wrapped, const std::string_view& salt, const secret_box& wrap_key, db_id db)
		{
			auto iv = derive_iv(salt, db);
			auto result = crypto::decrypt(ciphers::aes_256_gcm(), wrapped, wrap_key, secret_box::view(iv));
			if (!result || result->size() != KEY_SIZE)
				return expects_lr<string>(layer_exception("keystore unwrap failed"));

			return *result;
		}
		expects_lr<string> mempoolstate::keystore::row_encrypt(const secret_box& key, const std::string_view& data)
		{
			auto front = *crypto::random_bytes(KEY_SIZE), back = *crypto::random_bytes(KEY_SIZE);
			auto salt = crypto::hash(digests::sha256(), front + back);
			auto result = crypto::encrypt(ciphers::aes_256_cbc(), data, key, secret_box::view(*salt));
			if (!result)
				return expects_lr<string>(layer_exception("secret value encryption failed"));

			result->insert(result->begin(), front.begin(), front.end());
			result->append(back);
			return *result;
		}
		expects_lr<string> mempoolstate::keystore::row_decrypt(const secret_box& key, const std::string_view& data)
		{
			if (data.size() <= KEY_SIZE * 2)
				return expects_lr<string>(layer_exception("invalid blob"));

			auto front = data.substr(0, KEY_SIZE), back = data.substr(data.size() - KEY_SIZE);
			auto salt = crypto::hash(digests::sha256(), string(front) + string(back));
			auto result = crypto::decrypt(ciphers::aes_256_cbc(), data.substr(KEY_SIZE, data.size() - KEY_SIZE * 2), key, secret_box::view(*salt));
			if (!result)
				return expects_lr<string>(layer_exception("secret value decryption failed"));

			return *result;
		}

		static thread_local mempoolstate* parent_mempoolstate = nullptr;
		mempoolstate::mempoolstate() noexcept
		{
#ifndef NDEBUG
			local_id = std::this_thread::get_id();
#endif
			if (!parent_mempoolstate)
				parent_mempoolstate = this;
		}
		mempoolstate::~mempoolstate() noexcept
		{
#ifndef NDEBUG
			VI_ASSERT(local_id == std::this_thread::get_id(), "mempoolstate thread must not change");
#endif
			if (parent_mempoolstate == this)
				parent_mempoolstate = nullptr;
		}
		expects_lr<void> mempoolstate::setup_keys(option<string>&& password)
		{
			secret_box key, wrap_key;
			string salt, wrapped;
			string key_password = password.is_value() ? *password : string();
			auto* keys = keystore::get();
			for (uint8_t index = 0; index < 2; index++)
			{
				auto db = (keystore::db_id)index;
				auto tag = keystore::name_of(db);
				auto& storage = db == keystore::db_id::peers ? get_peer_storage() : get_secret_storage();
				auto cursor = storage.query(__func__, "SELECT salt, data FROM keystore WHERE id = 1");
				VI_PANIC(cursor && !cursor->error(), "cannot read keystore table in %.*s: %s", (int)tag.size(), tag.data(), ledger::storage_util::error_of(cursor).c_str());
				if (!cursor->empty())
				{
					salt = (*cursor)["salt"].get().get_blob();
					wrapped = (*cursor)["data"].get().get_blob();
					if (!salt.empty())
					{
						if (key_password.empty())
							key_password = read_password_line("keystore password: ");

						wrap_key = keystore::derive_wrap_key(key_password);
						auto plain = keystore::unwrap(wrapped, salt, wrap_key, db);
						VI_PANIC(plain, "wrong keystore password for %.*s", (int)tag.size(), tag.data());
						key = secret_box::secure(*plain);
						std::fill(plain->begin(), plain->end(), 0);
					}
					else
					{
						VI_PANIC(wrapped.size() == 32, "corrupted keystore row in %.*s", (int)tag.size(), tag.data());
						key = secret_box::secure(wrapped);
					}
				}
				else
				{
					auto fresh = *crypto::random_bytes(32);
					key = secret_box::secure(fresh);
					wrapped = fresh;

					schema_list map;
					map.push_back(var::set::null());
					map.push_back(var::set::binary(wrapped));
					cursor = storage.emplace_query(__func__, "INSERT INTO keystore (id, salt, data) VALUES (1, ?, ?)", &map);
					VI_PANIC(cursor && !cursor->error(), "cannot initialize keystore row in %.*s: %s", (int)tag.size(), tag.data(), ledger::storage_util::error_of(cursor).c_str());
				}
				keys->store(db, key, wrap_key);
			}
			std::fill(key_password.begin(), key_password.end(), 0);
			return expectation::met;
		}
		expects_lr<void> mempoolstate::rotate_keys()
		{
			auto multi = get_multi_storage();
			auto status = ledger::storage_util::multi_tx_begin(__func__, sqlite::isolation::exclusive, multi);
			if (!status)
				return layer_exception("cannot start keystore rotation transaction");

			bool revert = true;
			secret_box next_keys[2];
			auto* keys = keystore::get();
			auto sync = keys->sync();
			auto transaction_normalization = uscope([&]()
			{
				if (revert)
					ledger::storage_util::multi_tx_rollback(__func__, std::move(multi));
			});
			for (uint8_t index = 0; index < 2; index++)
			{
				auto db = (keystore::db_id)index;
				if (!keys->ready((keystore::db_id)index))
					return layer_exception("keystore is not initialized");

				auto tag = string(keystore::name_of(db));
				auto& storage = db == keystore::db_id::peers ? get_peer_storage() : get_secret_storage();
				auto sealed = keys->is_wrapped(db);
				auto fresh = *crypto::random_bytes(32);
				string wrapped = fresh, salt;
				secret_box next_key = secret_box::secure(fresh);
				next_keys[index] = next_key;
				if (sealed)
				{
					auto pack = keystore::wrap(next_key, keys->wrap_key_of(db), db, salt);
					if (!pack)
						return layer_exception("keystore rotation failed (rolled back, keys unchanged): cannot wrap rotated key for " + tag);
					wrapped = *pack;
				}

				vector<string> columns;
				if (db == keystore::db_id::peers)
					columns = { "address", "account" };
				else
					columns = { "owner", "asset", "hash", "participant" };

				auto cursor = storage.query(__func__, db == keystore::db_id::peers ? "SELECT address, account, wallet_message FROM nodes" : "SELECT owner, asset, hash, participant, entropy_message FROM secrets");
				if (!cursor || cursor->error())
					return layer_exception("keystore rotation failed (rolled back, keys unchanged): " + ledger::storage_util::error_of(cursor));

				vector<vector<string>> updates;
				if (!cursor->error_or_empty())
				{
					for (auto row : cursor->first())
					{
						auto plain = keys->decrypt(db, row[db == keystore::db_id::peers ? "wallet_message" : "entropy_message"].get().get_blob());
						if (!plain)
							return layer_exception("keystore rotation failed (rolled back, keys unchanged): cannot decrypt payload in " + tag);

						auto next = keystore::row_encrypt(next_key, *plain);
						std::fill(plain->begin(), plain->end(), 0);
						if (!next)
							return layer_exception("keystore rotation failed (rolled back, keys unchanged): cannot re-encrypt payload in " + tag);

						vector<string> values;
						values.reserve(columns.size() + 1);
						values.push_back(*next);
						for (auto& column : columns)
							values.push_back(row[column].get().get_blob());
						updates.push_back(std::move(values));
					}
				}

				for (auto& values : updates)
				{
					schema_list map;
					for (auto& value : values)
						map.push_back(var::set::binary(value));

					auto update = storage.emplace_query(__func__, db == keystore::db_id::peers ? "UPDATE nodes SET wallet_message = ? WHERE address = ? AND account = ?" : "UPDATE secrets SET entropy_message = ? WHERE owner = ? AND asset = ? AND hash = ? AND participant = ?", &map);
					if (!update || update->error())
						return layer_exception("keystore rotation failed (rolled back, keys unchanged): " + ledger::storage_util::error_of(update));
				}

				schema_list map;
				map.push_back(salt.empty() ? var::set::null() : var::set::binary(salt));
				map.push_back(var::set::binary(wrapped));
				auto update = storage.emplace_query(__func__, "UPDATE keystore SET salt = ?, data = ? WHERE id = 1", &map);
				if (!update || update->error())
					return layer_exception("keystore rotation failed (rolled back, keys unchanged): " + ledger::storage_util::error_of(update));
			}

			revert = false;
			auto commit = ledger::storage_util::multi_tx_commit(__func__, std::move(multi));
			if (!commit)
				return layer_exception("keystore rotation failed to commit (keys unchanged)");

			for (uint8_t index = 0; index < 2; index++)
			{
				auto db = (keystore::db_id)index;
				keys->store(db, next_keys[index], keys->wrap_key_of(db));
			}
			return expectation::met;
		}
		expects_lr<void> mempoolstate::seal_keys(option<string>&& password)
		{
			secret_box wrap_key;
			string key_password = password.is_value() ? *password : read_password_line("new keystore password (empty to remove): ", true);
			bool sealed = !key_password.empty();
			if (sealed)
			{
				wrap_key = keystore::derive_wrap_key(key_password);
				std::fill(key_password.begin(), key_password.end(), 0);
			}

			auto multi = get_multi_storage();
			auto status = ledger::storage_util::multi_tx_begin(__func__, sqlite::isolation::exclusive, multi);
			if (!status)
				return layer_exception("cannot start keystore sealing transaction");

			bool revert = true;
			auto* keys = keystore::get();
			auto sync = keys->sync();
			auto transaction_normalization = uscope([&]()
			{
				if (revert)
					ledger::storage_util::multi_tx_rollback(__func__, std::move(multi));
			});
			for (uint8_t index = 0; index < 2; index++)
			{
				auto db = (keystore::db_id)index;
				if (!keys->ready((keystore::db_id)index))
					return layer_exception("keystore is not initialized");
				else if (!sealed && !keys->is_wrapped((keystore::db_id)index))
					return layer_exception("database " + string(keystore::name_of((keystore::db_id)index)) + " has no password set");

				string salt, wrapped;
				secret_box key = keys->key_of(db);
				if (sealed)
				{
					auto pack = keystore::wrap(key, wrap_key, db, salt);
					if (!pack)
						return layer_exception("keystore sealing failed (rolled back, keys unchanged): cannot wrap keystore key for " + string(keystore::name_of(db)));

					wrapped = std::move(*pack);
				}
				else
					wrapped = key.heap();

				schema_list map;
				map.push_back(salt.empty() ? var::set::null() : var::set::binary(salt));
				map.push_back(var::set::binary(wrapped));

				auto& storage = db == keystore::db_id::peers ? get_peer_storage() : get_secret_storage();
				auto update = storage.emplace_query(__func__, "UPDATE keystore SET salt = ?, data = ? WHERE id = 1", &map);
				if (!update || update->error())
					return layer_exception("keystore sealing failed (rolled back, keys unchanged): " + ledger::storage_util::error_of(update));
			}

			revert = false;
			auto commit = ledger::storage_util::multi_tx_commit(__func__, std::move(multi));
			if (!commit)
				return layer_exception("keystore sealing failed to commit (keys unchanged)");

			for (uint8_t index = 0; index < 2; index++)
			{
				auto db = (keystore::db_id)index;
				keys->store(db, keys->key_of(db), sealed ? wrap_key : secret_box());
			}
			return expectation::met;
		}
		expects_lr<void> mempoolstate::apply_cooldown_node(const socket_address& node_address, bool cooldown, bool reset)
		{
			if (!node_address.is_valid())
				return expects_lr<void>(layer_exception("invalid ip address"));

			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + kernel::params().user.tcp.timeout));

			auto cursor = get_peer_storage().emplace_query(__func__, cooldown ? "INSERT INTO cooldowns (address, expiration, attempt) VALUES (?, ?, 0) ON CONFLICT DO UPDATE SET expiration = EXCLUDED.expiration, attempt = attempt + 1 RETURNING attempt" : "DELETE FROM cooldowns WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (!cooldown || reset)
				return expectation::met;

			uint64_t attempt = std::max<uint64_t>(1, (*cursor)["attempt"].get().get_integer());
			if (attempt > 9)
				return clear_node(node_address);
			else if (!attempt)
				return expectation::met;

			map[0] = var::set::integer(algorithm::arithmetic::integer_pow<uint64_t>(4, attempt) * 1000);
			map[1] = var::set::binary(address_to_message(node_address));
			cursor = get_peer_storage().emplace_query(__func__, "UPDATE cooldowns SET expiration = expiration + ? WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::apply_unknown_node(const socket_address& node_address, bool allow_reserved)
		{
			if (!node_address.is_valid())
				return expects_lr<void>(layer_exception("invalid ip address"));

			if (get_node(node_address))
				return expects_lr<void>(layer_exception("ip address and port is known"));

			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));
			map.push_back(var::set::boolean(!allow_reserved && routing_util::is_address_reserved_or_private(node_address)));

			auto cursor = get_peer_storage().emplace_query(__func__, "INSERT OR IGNORE INTO addresses (address, reserved) VALUES (?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::apply_node(const node_pair& value, node_peer type)
		{
			auto& [node, wallet] = value;
			int64_t quality = 0;
			switch (type)
			{
				case node_peer::runner:
					quality = -1;
					break;
				case node_peer::neighbor:
					quality = -2;
					break;
				case node_peer::inbound:
				{
					schema_list map;
					map.push_back(var::set::binary(address_to_message(node.address)));

					auto cursor = get_peer_storage().emplace_query(__func__, "SELECT quality FROM nodes WHERE address = ?", &map);
					quality = std::max<int64_t>(cursor && !cursor->error_or_empty() ? (*cursor)["quality"].get().get_integer() : 0, 0);
					break;
				}
				case node_peer::outbound:
					quality = node.get_preference();
					break;
				default:
					return layer_exception("invalid node type");
			}

			format::wo_stream node_message;
			if (!node.store(&node_message))
				return expects_lr<void>(layer_exception("node serialization error"));

			format::wo_stream wallet_message;
			if (!wallet.store(&wallet_message))
				return expects_lr<void>(layer_exception("wallet serialization error"));

			auto encrypted_wallet_message = keystore::get()->encrypt(keystore::db_id::peers, wallet_message.data);
			if (!encrypted_wallet_message)
				return encrypted_wallet_message.error();

			auto address_message = address_to_message(node.address);
			schema_list map;
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(wallet.public_key_hash.view()));
			map.push_back(var::set::boolean(quality >= 0));
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(wallet.public_key_hash.view()));
			map.push_back(var::set::integer(quality));
			map.push_back(var::set::integer(services_of(node)));
			map.push_back(var::set::binary(node_message.data));
			map.push_back(var::set::binary(*encrypted_wallet_message));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"DELETE FROM addresses WHERE address = ?;"
				"DELETE FROM nodes WHERE account = ? AND (quality >= 0) = ?;"
				"INSERT OR REPLACE INTO nodes (address, account, quality, services, node_message, wallet_message) VALUES (?, ?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return apply_cooldown_node(node.address, !wallet.has_secret_key() && !node.quality.reachable, false);
		}
		expects_lr<void> mempoolstate::apply_node_quality(const socket_address& node_address, int8_t call_result, uint64_t call_latency)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));

			auto& storage = get_peer_storage();
			auto cursor = storage.emplace_query(__func__, "SELECT node_message FROM nodes WHERE address = ? AND quality > 0", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<void>(layer_exception("node deserialization error"));

			node.quality.timestamp = kernel::params().time.now();
			node.quality.latency = call_latency > 0 ? call_latency : node.quality.latency;
			if (call_result != 0)
			{
				++node.quality.calls;
				if (call_result < 0)
					++node.quality.errors;
			}
			
			map.clear();
			map.push_back(var::set::integer(node.get_preference()));
			map.push_back(var::set::binary(node.as_message().data));
			map.push_back(var::set::binary(address_to_message(node.address)));

			cursor = storage.emplace_query(__func__, "UPDATE nodes SET quality = ?, node_message = ? WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			if (call_result < 0)
				return apply_cooldown_node(node.address, true, call_result == -2);

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_node(const algorithm::pubkeyhash_t& account)
		{
			schema_list map;
			map.push_back(var::set::binary(account.view()));

			auto cursor = get_peer_storage().emplace_query(__func__, "DELETE FROM nodes WHERE account = ? AND quality >= 0", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_node(const socket_address& node_address)
		{
			auto address_message = address_to_message(node_address);
			schema_list map;
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(address_message));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"DELETE FROM nodes WHERE address = ? AND quality >= 0;"
				"DELETE FROM cooldowns WHERE address = ?;"
				"DELETE FROM addresses WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_cooldowns()
		{
			auto cursor = get_peer_storage().query(__func__, "DELETE FROM cooldowns");
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<vector<node_pair>> mempoolstate::get_local_nodes()
		{
			auto cursor = get_peer_storage().query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality < 0 ORDER BY quality DESC");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<vector<node_pair>>(layer_exception(ledger::storage_util::error_of(cursor)));

			vector<node_pair> results;
			for (auto row : cursor->first())
			{
				auto decrypted_message = keystore::get()->decrypt(keystore::db_id::peers, row["wallet_message"].get().get_blob());
				if (decrypted_message)
				{
					ledger::node node;
					auto node_blob = row["node_message"].get().get_blob();
					auto node_message = format::ro_stream(node_blob);
					if (node.load(node_message))
					{
						ledger::wallet wallet;
						format::ro_stream wallet_message = format::ro_stream(*decrypted_message);
						if (wallet.load(wallet_message))
							results.push_back(std::make_pair(std::move(node), std::move(wallet)));
					}
				}
			}
			return expects_lr<vector<node_pair>>(std::move(results));
		}
		expects_lr<node_pair> mempoolstate::get_closest_node(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality >= 0 ORDER BY quality DESC LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = keystore::get()->decrypt(keystore::db_id::peers, (*cursor)["wallet_message"].get().get_blob());
			if (!decrypted_message)
				return decrypted_message.error();

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<node_pair>(layer_exception("node deserialization error"));

			ledger::wallet wallet;
			format::ro_stream wallet_message = format::ro_stream(*decrypted_message);
			if (!wallet.load(wallet_message))
				return expects_lr<node_pair>(layer_exception("wallet deserialization error"));

			return std::make_pair(std::move(node), std::move(wallet));
		}
		expects_lr<node_pair> mempoolstate::get_better_node(const algorithm::pubkeyhash_t& account)
		{
			schema_list map;
			map.push_back(var::set::binary(account.view()));

			auto& storage = get_peer_storage();
			auto cursor = storage.emplace_query(__func__, "SELECT quality FROM nodes WHERE account = ? AND quality >= 0", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			map.clear();
			map.push_back((*cursor)["quality"].get_inline());

			cursor = storage.emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality > ? ORDER BY random() LIMIT 1", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = keystore::get()->decrypt(keystore::db_id::peers, (*cursor)["wallet_message"].get().get_blob());
			if (!decrypted_message)
				return decrypted_message.error();

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<node_pair>(layer_exception("node deserialization error"));

			ledger::wallet wallet;
			format::ro_stream wallet_message = format::ro_stream(*decrypted_message);
			if (!wallet.load(wallet_message))
				return expects_lr<node_pair>(layer_exception("wallet deserialization error"));

			return std::make_pair(std::move(node), std::move(wallet));
		}
		expects_lr<node_pair> mempoolstate::get_node(const socket_address& node_address)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE address = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = keystore::get()->decrypt(keystore::db_id::peers, (*cursor)["wallet_message"].get().get_blob());
			if (!decrypted_message)
				return decrypted_message.error();

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<node_pair>(layer_exception("node deserialization error"));

			ledger::wallet wallet;
			format::ro_stream wallet_message = format::ro_stream(*decrypted_message);
			if (!wallet.load(wallet_message))
				return expects_lr<node_pair>(layer_exception("wallet deserialization error"));

			return std::make_pair(std::move(node), std::move(wallet));
		}
		expects_lr<node_pair> mempoolstate::get_node(const algorithm::pubkeyhash_t& account)
		{
			schema_list map;
			map.push_back(var::set::binary(account.view()));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE account = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = keystore::get()->decrypt(keystore::db_id::peers, (*cursor)["wallet_message"].get().get_blob());
			if (!decrypted_message)
				return decrypted_message.error();

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<node_pair>(layer_exception("node deserialization error"));

			ledger::wallet wallet;
			format::ro_stream wallet_message = format::ro_stream(*decrypted_message);
			if (!wallet.load(wallet_message))
				return expects_lr<node_pair>(layer_exception("wallet deserialization error"));

			return std::make_pair(std::move(node), std::move(wallet));
		}
		expects_lr<vector<node_location_pair>> mempoolstate::get_closest_nodes_with(size_t offset, size_t count, uint32_t services)
		{
			schema_list map;
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT account, address FROM nodes WHERE quality >= 0 AND (services & ?) == ? ORDER BY quality DESC LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<node_location_pair>>(layer_exception(ledger::storage_util::error_of(cursor)));

			vector<node_location_pair> results;
			for (auto row : cursor->first())
			{
				auto address = message_to_address(row["address"].get().get_blob());
				if (address)
				{
					auto account = algorithm::pubkeyhash_t(row["account"].get().get_blob());
					results.push_back(std::make_pair(account, *address));
				}
			}
			return expects_lr<vector<node_location_pair>>(std::move(results));
		}
		expects_lr<vector<node_location_pair>> mempoolstate::get_sample_nodes_with(size_t count, uint32_t services, node_ports port)
		{
			schema_list map;
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT account, node_message FROM nodes WHERE quality > 0 AND (services & ?) == ? ORDER BY random() LIMIT ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<node_location_pair>>(layer_exception(ledger::storage_util::error_of(cursor)));

			vector<node_location_pair> results;
			for (auto row : cursor->first())
			{
				ledger::node node;
				auto node_blob = row["node_message"].get().get_blob();
				auto node_message = format::ro_stream(node_blob);
				if (node.load(node_message))
				{
					auto account = algorithm::pubkeyhash_t(row["account"].get().get_blob());
					auto address = node.address.get_ip_address().or_else("[bad_address]");
					switch (port)
					{
						case node_ports::consensus:
							results.push_back(std::make_pair(account, socket_address(address, node.ports.consensus)));
							break;
						case node_ports::discovery:
							results.push_back(std::make_pair(account, socket_address(address, node.ports.discovery)));
							break;
						case node_ports::rpc:
							results.push_back(std::make_pair(account, socket_address(address, node.ports.rpc)));
							break;
					}
				}
			}
			return expects_lr<vector<node_location_pair>>(std::move(results));
		}
		expects_lr<socket_address> mempoolstate::sample_connectable_unknown_node()
		{
			schema_list map;
			map.push_back(var::set::integer(kernel::params().time.now_cpu()));

			auto& storage = get_peer_storage();
			auto cursor = storage.emplace_query(__func__, "SELECT addresses.address FROM addresses LEFT JOIN cooldowns ON cooldowns.address = addresses.address WHERE reserved = FALSE AND expiration IS NULL OR expiration < ? ORDER BY random() LIMIT 1", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<socket_address>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto message = (*cursor)["address"].get().get_blob();
			map.clear();
			map.push_back(var::set::binary(message));

			cursor = storage.emplace_query(__func__, "DELETE FROM addresses WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<socket_address>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto address = message_to_address(message);
			if (!address)
				return expects_lr<socket_address>(layer_exception("bad address"));

			return *address;
		}
		expects_lr<size_t> mempoolstate::get_connectable_unknown_nodes_count()
		{
			schema_list map;
			map.push_back(var::set::integer(kernel::params().time.now_cpu()));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT COUNT(1) AS counter FROM addresses LEFT JOIN cooldowns ON cooldowns.address = addresses.address WHERE reserved = FALSE AND expiration IS NULL OR expiration < ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<size_t> mempoolstate::get_nodes_count()
		{
			auto cursor = get_peer_storage().query(__func__, "SELECT COUNT(1) AS counter FROM nodes WHERE quality >= 0");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<bool> mempoolstate::has_cooldown_on_node(const socket_address& address)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(address)));
			map.push_back(var::set::integer(kernel::params().time.now_cpu()));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT TRUE AS cooldown FROM cooldowns WHERE address = ? AND expiration >= ? LIMIT 1", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (*cursor)["cooldown"].get().get_boolean();
		}
		expects_lr<decimal> mempoolstate::get_gas_price(const algorithm::asset_id& asset, double priority_percentile)
		{
			if (priority_percentile < 0.0 || priority_percentile > 1.0)
				return expects_lr<decimal>(layer_exception("invalid priority percentile"));

			uint8_t hash[32];
			asset.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::number(1.0 - priority_percentile));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT price FROM transactions WHERE asset = ? ORDER BY quality DESC NULLS FIRST LIMIT 1 OFFSET (SELECT CAST((COUNT(1) * ?) AS INT) FROM transactions)", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<decimal>(layer_exception(ledger::storage_util::error_of(cursor)));

			decimal price = (*cursor)["price"].get().get_decimal();
			return price;
		}
		expects_lr<decimal> mempoolstate::get_asset_price(const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double priority_percentile)
		{
			auto a = get_gas_price(price_of, priority_percentile);
			if (!a || a->is_zero())
				return decimal::zero();

			auto b = get_gas_price(relative_to, priority_percentile);
			if (!b)
				return decimal::zero();

			return algorithm::arithmetic::divide(*b, *a);
		}
		expects_lr<void> mempoolstate::add_attestation(const algorithm::asset_id& asset, const superchain::computed_transaction& value, const algorithm::hashsig_t& signature)
		{
			format::wo_stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("transaction serialization error"));

			uint8_t asset_hash[32], hash[32], commitment[32];
			asset.encode(asset_hash);
			value.as_attestation_hash().encode(hash);
			value.as_proof_hash(asset).encode(commitment);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(commitment, sizeof(commitment)));
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + ATTESTATION_EXPIRATION));
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(commitment, sizeof(commitment)));
			map.push_back(var::set::binary(signature.view()));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"INSERT INTO proofs (hash, commitment, asset, message, time) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET asset = EXCLUDED.asset, message = EXCLUDED.message;"
				"INSERT OR REPLACE INTO commitments (hash, commitment, signature) VALUES (?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<uint256_t> mempoolstate::pull_best_attestation_hash(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT DISTINCT hash FROM (SELECT hash, COUNT(*) OVER (PARTITION BY hash, commitment) AS signatures FROM commitments) counts ORDER BY signatures DESC LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<uint256_t>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<uint256_t>(layer_exception("attestation not found"));

			auto hash = (*cursor)["hash"].get().get_blob();
			uint256_t attestation_hash;
			attestation_hash.decode_compact((uint8_t*)hash.data(), hash.size());
			return expects_lr<uint256_t>(std::move(attestation_hash));
		}
		expects_lr<attestation_tree> mempoolstate::get_attestation(const uint256_t& attestation_hash)
		{
			uint8_t hash[32];
			attestation_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"SELECT commitment, signature FROM commitments WHERE hash = ?;"
				"SELECT commitment, asset, message FROM proofs WHERE hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<attestation_tree>(layer_exception(ledger::storage_util::error_of(cursor)));

			attestation_tree result;
			for (auto row : cursor->first())
			{
				auto commitment = row["commitment"].get().get_blob();
				uint256_t commitment_hash;
				commitment_hash.decode_compact((uint8_t*)commitment.data(), commitment.size());
				result.commitments[commitment_hash].insert(algorithm::hashsig_t(row["signature"].get().get_blob()));
			}

			for (auto row : cursor->last())
			{
				auto message = row["message"].get().get_blob();
				format::ro_stream proof_message = format::ro_stream(message);
				superchain::computed_transaction proof;
				if (proof.load(proof_message))
				{
					auto asset_hash = row["asset"].get().get_blob();
					auto commitment = row["commitment"].get().get_blob();
					uint256_t asset, commitment_hash;
					asset.decode_compact((uint8_t*)asset_hash.data(), asset_hash.size());
					commitment_hash.decode_compact((uint8_t*)commitment.data(), commitment.size());
					result.proofs[commitment_hash] = std::move(proof);
					result.asset = asset;
				}
			}

			return expects_lr<attestation_tree>(std::move(result));
		}
		expects_lr<void> mempoolstate::remove_attestation(const uint256_t& attestation_hash)
		{
			uint8_t hash[32];
			attestation_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"DELETE FROM proofs WHERE hash = ?;"
				"DELETE FROM commitments WHERE hash = ?;"
				"DELETE FROM preattestations WHERE hash = ?;"
				"DELETE FROM preattestation_keys WHERE NOT EXISTS (SELECT TRUE FROM preattestations WHERE preattestations.proof_hash = preattestation_keys.proof_hash);", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<size_t> mempoolstate::expire_attestations()
		{
			auto timestamp = kernel::params().time.now_cpu();
			schema_list map;
			map.push_back(var::set::integer(timestamp));
			map.push_back(var::set::integer(timestamp));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"DELETE FROM proofs WHERE time < ?;"
				"DELETE FROM commitments WHERE NOT EXISTS (SELECT TRUE FROM proofs WHERE proofs.hash = commitments.hash AND proofs.commitment = commitments.commitment);"
				"DELETE FROM preattestations WHERE time < ?;"
				"DELETE FROM preattestation_keys WHERE NOT EXISTS (SELECT TRUE FROM preattestations WHERE preattestations.proof_hash = preattestation_keys.proof_hash);", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return cursor->affected_rows();
		}
		expects_lr<void> mempoolstate::add_preattestation(const uint256_t& attestation_hash, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& attester, uint64_t tip_height, const uint256_t& proof_hash, const algorithm::hashsig_t& signature, const superchain::computed_transaction& body)
		{
			format::wo_stream message;
			if (!body.store(&message))
				return expects_lr<void>(layer_exception("preattestation body serialization error"));

			uint8_t hash[32], asset_hash[32], proof_bytes[32];
			attestation_hash.encode(hash);
			asset.encode(asset_hash);
			proof_hash.encode(proof_bytes);

			btree_set<string> lookup_keys;
			lookup_keys.insert(transaction_lookup_key(body.transaction_id));
			for (auto& [input_hash, input] : body.inputs)
				lookup_keys.insert(address_lookup_key(input.link.address));
			for (auto& [output_hash, output] : body.outputs)
				lookup_keys.insert(address_lookup_key(output.link.address));
			if (!body.memo.empty())
				lookup_keys.insert(memo_lookup_key(body.memo));

			string sql =
				"INSERT INTO preattestations (hash, asset, attester, proof_hash, tip_height, signature, message, time) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (hash, attester) DO UPDATE SET "
				" asset = CASE WHEN EXCLUDED.tip_height > preattestations.tip_height THEN EXCLUDED.asset ELSE preattestations.asset END, "
				" proof_hash = CASE WHEN EXCLUDED.tip_height > preattestations.tip_height THEN EXCLUDED.proof_hash ELSE preattestations.proof_hash END, "
				" tip_height = CASE WHEN EXCLUDED.tip_height > preattestations.tip_height THEN EXCLUDED.tip_height ELSE preattestations.tip_height END, "
				" signature = CASE WHEN EXCLUDED.tip_height > preattestations.tip_height THEN EXCLUDED.signature ELSE preattestations.signature END, "
				" message = CASE WHEN EXCLUDED.tip_height > preattestations.tip_height THEN EXCLUDED.message ELSE preattestations.message END; "
				"INSERT OR IGNORE INTO preattestation_keys (lookup_key, proof_hash) VALUES ";

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::binary(attester.view()));
			map.push_back(var::set::binary(proof_bytes, sizeof(proof_bytes)));
			map.push_back(var::set::integer(tip_height));
			map.push_back(var::set::binary(signature.view()));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + ATTESTATION_EXPIRATION));

			bool first = true;
			for (auto& lookup_key : lookup_keys)
			{
				sql += first ? "(?, ?)" : ",(?, ?)";
				first = false;
				map.push_back(var::set::binary(lookup_key));
				map.push_back(var::set::binary(proof_bytes, sizeof(proof_bytes)));
			}
			sql += ";";

			auto cursor = get_peer_storage().emplace_query(__func__, sql, &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<superchain::uncomputed_transaction> mempoolstate::get_preattestation_body(const uint256_t& attestation_hash, const uint256_t& proof_hash)
		{
			uint8_t hash[32], body[32];
			attestation_hash.encode(hash);
			proof_hash.encode(body);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(body, sizeof(body)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT message, tip_height FROM preattestations WHERE hash = ? AND proof_hash = ? AND message IS NOT NULL LIMIT 1", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<superchain::uncomputed_transaction>(layer_exception(ledger::storage_util::error_of(cursor)));

			superchain::computed_transaction value;
			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			if (!value.load(message))
				return expects_lr<superchain::uncomputed_transaction>(layer_exception("preattestation body deserialization error"));

			superchain::uncomputed_transaction uncomputed;
			*(superchain::computed_transaction*)(&uncomputed) = std::move(value);
			uncomputed.confirmed_block_id = (uint64_t)(*cursor)["tip_height"].get().get_integer();
			return uncomputed;
		}
		expects_lr<vector<superchain::uncomputed_transaction>> mempoolstate::get_preattestations(const hash_set<string>& lookup_keys, size_t offset, size_t count)
		{
			string command;
			schema_list map;
			if (!lookup_keys.empty())
			{
				command = "SELECT c.message, MAX(c.tip_height) AS tip_height FROM preattestations c INNER JOIN preattestation_keys k ON k.proof_hash = c.proof_hash WHERE k.lookup_key IN (";
				bool first = true;
				for (auto& lookup_key : lookup_keys)
				{
					command += first ? "?" : ", ?";
					first = false;
					map.push_back(var::set::binary(lookup_key));
				}
				command += ") AND c.message IS NOT NULL AND c.tip_height != ? GROUP BY c.proof_hash ORDER BY MIN(c.time) ASC LIMIT ? OFFSET ?";
			}
			else
				command = "SELECT message, MAX(tip_height) AS tip_height FROM preattestations WHERE message IS NOT NULL AND tip_height != ? GROUP BY proof_hash ORDER BY MIN(time) ASC LIMIT ? OFFSET ?";
			map.push_back(var::set::integer(superchain::uncomputed_transaction::erased_confirmed_block_id()));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, command, &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<superchain::uncomputed_transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<superchain::uncomputed_transaction> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				superchain::computed_transaction value;
				auto blob = response[i]["message"].get().get_blob();
				auto message = format::ro_stream(blob);
				if (!value.load(message))
					continue;

				superchain::uncomputed_transaction uncomputed;
				*(superchain::computed_transaction*)(&uncomputed) = std::move(value);
				uncomputed.confirmed_block_id = (uint64_t)response[i]["tip_height"].get().get_integer();
				values.emplace_back(std::move(uncomputed));
			}

			return values;
		}
		expects_lr<bool> mempoolstate::add_quote(const superchain::approved_fee& quote, const algorithm::pubkeyhash_t& attester, uint8_t level)
		{
			format::wo_stream message;
			if (!quote.store(&message))
				return expects_lr<bool>(layer_exception("quote serialization error"));

			uint8_t asset_hash[32];
			quote.asset.encode(asset_hash);

			schema_list map;
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::binary(attester.view()));
			map.push_back(var::set::integer(level));
			map.push_back(var::set::integer(quote.expiry_block_number));
			map.push_back(var::set::binary(message.data));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"INSERT INTO quotes (asset, attester, level, expiry_height, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (asset, attester, level) DO UPDATE SET "
				" expiry_height = EXCLUDED.expiry_height, message = EXCLUDED.message "
				" WHERE EXCLUDED.expiry_height > quotes.expiry_height;", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expects_lr<bool>(cursor->affected_rows() > 0);
		}
		expects_lr<vector<std::pair<superchain::approved_fee, uint8_t>>> mempoolstate::get_quotes(const algorithm::asset_id& asset, uint64_t block_number)
		{
			uint8_t asset_hash[32];
			asset.encode(asset_hash);

			schema_list map;
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::integer(block_number));
			map.push_back(var::set::integer(block_number));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"SELECT message, level FROM quotes WHERE asset = ? AND expiry_height > ?;"
				"DELETE FROM quotes WHERE expiry_height < ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<std::pair<superchain::approved_fee, uint8_t>>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<std::pair<superchain::approved_fee, uint8_t>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				superchain::approved_fee quote;
				auto quote_blob = response[i]["message"].get().get_blob();
				auto quote_message = format::ro_stream(quote_blob);
				if (quote.load(quote_message))
					values.push_back(std::make_pair(std::move(quote), (uint8_t)response[i]["level"].get().get_integer()));
			}

			return values;
		}
		expects_lr<size_t> mempoolstate::clear_observations()
		{
			auto cursor = get_peer_storage().query(__func__, "DELETE FROM observations");
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return cursor->affected_rows();
		}
		expects_lr<void> mempoolstate::add_transaction(const ledger::transaction_message& value, bool bypass_cooldown, const algorithm::pubkeyhash_t* known_owner)
		{
			format::wo_stream message;
			if (!value.store(&message))
				return layer_exception("transaction serialization error");

			algorithm::pubkeyhash_t owner;
			if (known_owner != nullptr)
				owner = *known_owner;
			else if (!value.recover_hash(owner))
				return layer_exception("transaction owner recovery error");

			uint256_t commitment_hash = 0;
			uint64_t as_commitment = value.as_commitment(&commitment_hash);
			decimal quality = decimal::nan();
			if (!as_commitment)
			{
				decimal median_gas_price = get_gas_price(value.asset, fee_percentile(fee_priority::medium)).or_else(decimal::nan());
				decimal delta_gas = median_gas_price.is_positive() ? value.gas_price / median_gas_price : 1.0;
				decimal max_gas = delta_gas.is_positive() ? algorithm::arithmetic::divide(value.gas_price * value.gas_limit.to_decimal(), delta_gas) : decimal::zero();
				decimal multiplier = 2 << 20;
				quality = max_gas * multiplier;
			}
			else
				quality = -((int64_t)as_commitment);

			uint8_t asset[32], hash[32], other_hash[32];
			value.asset.encode(asset);
			value.as_hash().encode(hash);
			commitment_hash.encode(other_hash);

			schema_list map;
			map.push_back(var::set::string(bypass_cooldown ? string() : string(" OR REPLACE")));
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + TRANSACTION_EXPIRATION + OBSERVATION_EXPIRATION));
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(commitment_hash > 0 ? var::set::binary(other_hash, sizeof(other_hash)) : var::set::null());
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::binary(asset, sizeof(asset)));
			map.push_back(var::set::integer(value.nonce));
			map.push_back(var::set::integer(quality.to_int64()));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + TRANSACTION_EXPIRATION));
			map.push_back(var::set::string(value.gas_price.to_string()));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::binary(owner.view()));

			auto cursor = get_peer_storage().emplace_query(__func__,
				"INSERT$? INTO observations (hash, time) VALUES (?, ?);"
				"INSERT OR REPLACE INTO transactions (hash, commitment_hash, owner, asset, nonce, quality, time, price, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);"
				"WITH epochs AS (SELECT rowid, ROW_NUMBER() OVER (ORDER BY nonce) AS epoch FROM transactions WHERE owner = ?) UPDATE transactions SET epoch = epochs.epoch FROM epochs WHERE transactions.rowid = epochs.rowid", &map);
			if (!cursor || cursor->error())
				return layer_exception(ledger::storage_util::error_of(cursor));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::add_transaction_observation(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(kernel::params().time.now_cpu() + TRANSACTION_EXPIRATION + OBSERVATION_EXPIRATION));

			auto cursor = get_peer_storage().emplace_query(__func__, "INSERT OR REPLACE INTO observations (hash, time) VALUES (?, ?)", &map);
			if (!cursor || cursor->error())
				return layer_exception(ledger::storage_util::error_of(cursor));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_transactions_by_hash(const std::function<bool(uint256_t&, size_t&)>& match)
		{
			string query = "WITH hashes AS MATERIALIZED (SELECT c.hash FROM transactions p JOIN transactions c ON c.owner = p.owner WHERE p.hash IN (";
			bool empty = append_hash_literals(query, match);
			query.append(") AND c.nonce <= p.nonce) DELETE FROM transactions WHERE hash IN (SELECT hash FROM hashes)");
			if (empty)
				return expectation::met;

			auto cursor = get_peer_storage().emplace_query(__func__, query, nullptr);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_transactions_by_commitment_hash(const std::function<bool(uint256_t&, size_t&)>& match)
		{
			string query = "DELETE FROM transactions WHERE commitment_hash IN (";
			bool empty = append_hash_literals(query, match);
			query.append(")");
			if (empty)
				return expectation::met;

			auto cursor = get_peer_storage().emplace_query(__func__, query, nullptr);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_attestations_by_hash(const std::function<bool(uint256_t&, size_t&)>& match)
		{
			string list;
			if (append_hash_literals(list, match))
				return expectation::met;

			string query;
			query.reserve(352 + list.size() * 3);
			query.append("DELETE FROM proofs WHERE hash IN (").append(list).append(");");
			query.append("DELETE FROM commitments WHERE hash IN (").append(list).append(");");
			query.append("DELETE FROM preattestations WHERE hash IN (").append(list).append(");");
			query.append("DELETE FROM preattestation_keys WHERE NOT EXISTS (SELECT TRUE FROM preattestations WHERE preattestations.proof_hash = preattestation_keys.proof_hash);");

			auto cursor = get_peer_storage().emplace_query(__func__, query, nullptr);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<bool> mempoolstate::has_transaction_commitment_hash(const uint256_t& commitment_hash)
		{
			uint8_t hash[32];
			commitment_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT TRUE FROM transactions WHERE commitment_hash = ? LIMIT 1", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expects_lr<bool>(!cursor->empty());
		}
		expects_lr<uptr<ledger::transaction_message>> mempoolstate::get_transaction_by_commitment_hash(const uint256_t& commitment_hash)
		{
			uint8_t hash[32];
			commitment_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT message, hash FROM transactions WHERE commitment_hash = ? LIMIT 1", &map);
			if (!cursor || cursor->error())
				return expects_lr<uptr<ledger::transaction_message>>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return expects_lr<uptr<ledger::transaction_message>>(layer_exception("transaction not found"));

			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			uptr<ledger::transaction_message> value = transactions::resolver::from_stream(message);
			if (!value || !value->load(message))
				return expects_lr<uptr<ledger::transaction_message>>(layer_exception("transaction deserialization error"));

			finalize_checksum(**value, (*cursor)["hash"].get());
			return expects_lr<uptr<ledger::transaction_message>>(std::move(value));
		}
		expects_lr<size_t> mempoolstate::expire_transactions(const std::function<uint64_t(const algorithm::pubkeyhash_t&)>& nonce_callback)
		{
			auto timestamp = kernel::params().time.now_cpu();
			schema_list map;
			map.push_back(var::set::integer(timestamp));
			map.push_back(var::set::integer(timestamp));

			auto& storage = get_peer_storage();
			auto cursor = storage.emplace_query(__func__,
				"DELETE FROM transactions WHERE time < ?;"
				"DELETE FROM observations WHERE time < ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			size_t offset = 0, count = cursor->affected_rows();
			while (nonce_callback)
			{
				map.clear();
				map.push_back(var::set::integer(ELEMENTS_MANY));
				map.push_back(var::set::integer(offset));
				
				cursor = storage.emplace_query(__func__, "SELECT DISTINCT owner FROM transactions LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error_or_empty())
					break;

				offset += cursor->size();
				for (auto row : cursor->first())
				{
					auto owner = algorithm::pubkeyhash_t(row["owner"].get().get_blob());
					map.clear();
					map.push_back(var::set::binary(owner.view()));
					map.push_back(var::set::integer(nonce_callback(owner)));
					cursor = storage.emplace_query(__func__, "DELETE FROM transactions WHERE owner = ? AND nonce < ?", &map);
					offset = cursor && cursor->affected_rows() > 0 ? 0 : offset;
					count += cursor ? cursor->affected_rows() : 0;
				}
			}

			return count;
		}
		expects_lr<size_t> mempoolstate::get_transactions_count()
		{
			auto cursor = get_peer_storage().query(__func__, "SELECT COUNT(1) AS counter FROM transactions");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<void> mempoolstate::apply_key(const algorithm::pubkeyhash_t& participant, const ledger::distribution_key& entropy)
		{
			format::wo_stream entropy_message;
			if (!entropy.store(&entropy_message))
				return expects_lr<void>(layer_exception("entropy serialization error"));

			auto encrypted_entropy_message = keystore::get()->encrypt(keystore::db_id::secrets, entropy_message.data);
			if (!encrypted_entropy_message)
				return encrypted_entropy_message.error();

			uint8_t hash_data[32], asset_data[32];
			entropy.ref.hash.encode(hash_data);
			entropy.ref.asset.encode(asset_data);

			schema_list map;
			map.push_back(var::set::binary(entropy.ref.owner.view()));
			map.push_back(var::set::binary(asset_data, sizeof(asset_data)));
			map.push_back(var::set::binary(hash_data, sizeof(hash_data)));
			map.push_back(var::set::binary(participant.view()));
			map.push_back(var::set::binary(*encrypted_entropy_message));

			auto cursor = get_secret_storage().emplace_query(__func__, "INSERT OR REPLACE INTO secrets (owner, asset, hash, participant, entropy_message) VALUES (?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			
			return expectation::met;
		}
		expects_lr<ledger::distribution_key> mempoolstate::get_key(const algorithm::pubkeyhash_t& participant, const algorithm::pubkeyhash_t& owner, const algorithm::asset_id& asset, const uint256_t& hash)
		{
			uint8_t hash_data[32], asset_data[32];
			hash.encode(hash_data);
			asset.encode(asset_data);

			schema_list map;
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::binary(asset_data, sizeof(asset_data)));
			map.push_back(var::set::binary(hash_data, sizeof(hash_data)));
			map.push_back(var::set::binary(participant.view()));

			auto cursor = get_secret_storage().emplace_query(__func__, "SELECT entropy_message FROM secrets WHERE owner = ? AND asset = ? AND hash = ? AND participant = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::distribution_key>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return layer_exception("failed to find secret key with used ref");

			auto decrypted_entropy_message = keystore::get()->decrypt(keystore::db_id::secrets, (*cursor)["entropy_message"].get().get_blob());
			if (!decrypted_entropy_message)
				return decrypted_entropy_message.error();

			ledger::distribution_key entropy;
			format::ro_stream entropy_message = format::ro_stream(*decrypted_entropy_message);
			bool success = entropy.load(entropy_message);
			std::fill(decrypted_entropy_message->begin(), decrypted_entropy_message->end(), 0);
			if (!success)
				return expects_lr<ledger::distribution_key>(layer_exception("secret entropy deserialization error"));

			return expects_lr<ledger::distribution_key>(std::move(entropy));
		}
		expects_lr<ledger::distribution_key> mempoolstate::get_key(const algorithm::pubkeyhash_t& participant, size_t index)
		{
			schema_list map;
			map.push_back(var::set::binary(participant.view()));
			map.push_back(var::set::integer(index));

			auto cursor = get_secret_storage().emplace_query(__func__, "SELECT entropy_message FROM secrets WHERE participant = ? LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::distribution_key>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return layer_exception("entropy not found");

			auto decrypted_entropy_message = keystore::get()->decrypt(keystore::db_id::secrets, (*cursor)["entropy_message"].get().get_blob());
			if (!decrypted_entropy_message)
				return decrypted_entropy_message.error();

			ledger::distribution_key entropy;
			format::ro_stream entropy_message = format::ro_stream(*decrypted_entropy_message);
			bool success = entropy.load(entropy_message);
			std::fill(decrypted_entropy_message->begin(), decrypted_entropy_message->end(), 0);
			if (!success)
				return expects_lr<ledger::distribution_key>(layer_exception("entropy deserialization error"));

			return expects_lr<ledger::distribution_key>(std::move(entropy));
		}
		expects_lr<bool> mempoolstate::has_transaction(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT TRUE FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expects_lr<bool>(!cursor->empty());
		}
		expects_lr<bool> mempoolstate::has_quote(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& attester, uint64_t block_number)
		{
			uint8_t asset_hash[32];
			asset.encode(asset_hash);

			schema_list map;
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::binary(attester.view()));
			map.push_back(var::set::integer(block_number));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT TRUE FROM quotes WHERE asset = ? AND attester = ? AND expiry_height > ?;", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expects_lr<bool>(!cursor->empty());
		}
		expects_lr<void> mempoolstate::verify_transaction_uniqueness(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT TRUE FROM observations WHERE hash = ?", &map);
			if (cursor && !cursor->error_or_empty())
				return layer_exception("finality conflict");

			return expectation::met;
		}
		expects_lr<uint64_t> mempoolstate::get_lowest_transaction_nonce(const algorithm::pubkeyhash_t& owner)
		{
			schema_list map;
			map.push_back(var::set::binary(owner.view()));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT MIN(nonce) AS nonce FROM transactions WHERE owner = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto nonce = (*cursor)["nonce"].get();
			if (!nonce.is(var_type::integer))
				return expects_lr<uint64_t>(layer_exception("lowest nonce not found"));

			return nonce.get_integer();
		}
		expects_lr<uint64_t> mempoolstate::get_highest_transaction_nonce(const algorithm::pubkeyhash_t& owner)
		{
			schema_list map;
			map.push_back(var::set::binary(owner.view()));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT max(nonce) AS nonce FROM transactions WHERE owner = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto nonce = (*cursor)["nonce"].get();
			if (!nonce.is(var_type::integer))
				return expects_lr<uint64_t>(layer_exception("highest nonce not found"));

			return nonce.get_integer();
		}
		expects_lr<uptr<ledger::transaction_message>> mempoolstate::get_transaction_by_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uptr<ledger::transaction_message>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			uptr<ledger::transaction_message> value = transactions::resolver::from_stream(message);
			if (!value || !value->load(message))
				return expects_lr<uptr<ledger::transaction_message>>(layer_exception("transaction deserialization error"));

			finalize_checksum(**value, (*cursor)["hash"].get());
			return value;
		}
		expects_lr<vector<uptr<ledger::transaction_message>>> mempoolstate::get_transactions_by_quality(uint8_t flags, size_t offsets[2], size_t count, hash_set<uint256_t>* hashes)
		{
			VI_ASSERT(offsets != nullptr, "offsets should be set");
			if (offsets[0] == std::numeric_limits<size_t>::max() && offsets[1] == std::numeric_limits<size_t>::max())
				return layer_exception("end of stream");

			schema_list map;
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offsets[0]));

			std::array<option<sqlite::response>, 2> responses = { option<sqlite::response>(optional::none), option<sqlite::response>(optional::none) };
			if (offsets[0] != std::numeric_limits<size_t>::max() && (flags & (uint8_t)transaction_queue::standard_paid))
			{
				auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE quality > 0 ORDER BY epoch ASC, quality DESC NULLS LAST LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uptr<ledger::transaction_message>>>(layer_exception(ledger::storage_util::error_of(cursor)));
				else if (!cursor->base.empty())
					responses[0] = std::move(cursor->base.front());
			}
			else if (offsets[0] != std::numeric_limits<size_t>::max() && (flags & (uint8_t)transaction_queue::standard_all))
			{
				auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE quality >= 0 ORDER BY epoch ASC, quality DESC NULLS LAST LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uptr<ledger::transaction_message>>>(layer_exception(ledger::storage_util::error_of(cursor)));
				else if (!cursor->base.empty())
					responses[0] = std::move(cursor->base.front());
			}
			if (offsets[1] != std::numeric_limits<size_t>::max() && (flags & (uint8_t)transaction_queue::commitment))
			{
				map.back() = var::set::integer(offsets[1]);
				auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE quality < 0 ORDER BY epoch ASC, quality ASC NULLS LAST LIMIT ? OFFSET ?", &map);
				if (!cursor || cursor->error())
					return expects_lr<vector<uptr<ledger::transaction_message>>>(layer_exception(ledger::storage_util::error_of(cursor)));
				else if (!cursor->base.empty())
					responses[1] = std::move(cursor->base.front());
			}

			size_t results = 0, split = 0;
			for (size_t i = 0; i < responses.size(); i++)
			{
				auto& response = responses[i];
				if (response)
				{
					size_t size = response->size();
					offsets[i] = (size == count ? offsets[i] + size : std::numeric_limits<size_t>::max());
					split = i > 0 ? split : size;
					results += size;
				}
				else
					offsets[i] = std::numeric_limits<size_t>::max();
			}
			if (!results)
				return expects_lr<vector<uptr<ledger::transaction_message>>>(vector<uptr<ledger::transaction_message>>());

			vector<uptr<ledger::transaction_message>> queue; queue.resize(results);
			parallel::wait_all(parallel::for_loop(queue.size(), ELEMENTS_FEW, [&](size_t j)
			{
				auto row = j < split ? (*responses[0])[j] : (*responses[1])[j - split];
				auto hash = row["hash"].get();
				auto transaction_hash = uint256_t(0);
				if (hash.size() == sizeof(uint256_t))
				{
					transaction_hash.decode(hash.get_binary());
					if (!hashes || hashes->find(transaction_hash) == hashes->end())
					{
						auto blob = row["message"].get().get_blob();
						auto message = format::ro_stream(blob);
						uptr<ledger::transaction_message> value = transactions::resolver::from_stream(message);
						if (value && value->load(message))
						{
							value->checksum = transaction_hash;
							queue[j] = std::move(value);
						}
					}
				}
			}));
			
			queue.erase(std::remove_if(queue.begin(), queue.end(), [](const uptr<ledger::transaction_message>& a) { return !a; }), queue.end());
			if (hashes != nullptr)
			{
				for (auto& item : queue)
					hashes->insert(item->checksum);
			}
			return expects_lr<vector<uptr<ledger::transaction_message>>>(std::move(queue));
		}
		expects_lr<vector<uptr<ledger::transaction_message>>> mempoolstate::get_transactions_by_owner(const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::string(direction < 0 ? "DESC" : "ASC"));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE owner = ? ORDER BY nonce $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction_message>>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction_message>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				auto blob = row["message"].get().get_blob();
				auto message = format::ro_stream(blob);
				uptr<ledger::transaction_message> value = transactions::resolver::from_stream(message);
				if (value && value->load(message))
				{
					finalize_checksum(**value, row["hash"].get());
					values.emplace_back(std::move(value));
				}
			}

			return values;
		}
		expects_lr<vector<uint256_t>> mempoolstate::get_transaction_hashset(size_t offset, size_t count)
		{
			if (!count)
				return layer_exception("invalid count");

			schema_list map;
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_peer_storage().emplace_query(__func__, "SELECT hash FROM transactions ORDER BY hash ASC LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uint256_t> result;
			result.reserve(result.size() + size);
			for (size_t i = 0; i < size; i++)
			{
				auto in_hash = response[i]["hash"].get().get_blob();
				if (in_hash.size() != sizeof(uint256_t))
					continue;

				uint256_t out_hash;
				out_hash.decode((uint8_t*)in_hash.data());
				result.push_back(out_hash);
			}

			return result;
		}
		ledger::storage_index_ptr& mempoolstate::get_peer_storage()
		{
			if (!peer_local_storage.may_use())
			{
				if (!parent_mempoolstate->peer_local_storage.may_use())
					parent_mempoolstate->peer_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("mempoolindex", "peerdata", &mempoolstate::make_schema));
				peer_local_storage = parent_mempoolstate->peer_local_storage;
			}
			return peer_local_storage;
		}
		ledger::storage_index_ptr& mempoolstate::get_secret_storage()
		{
			if (!secret_local_storage.may_use())
			{
				if (!parent_mempoolstate->secret_local_storage.may_use())
					parent_mempoolstate->secret_local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_named_of("mempoolindex", "secretdata", &mempoolstate::make_schema));
				secret_local_storage = parent_mempoolstate->secret_local_storage;
			}
			return secret_local_storage;
		}
		ledger::storage_util::multi_storage_index_ptr mempoolstate::get_multi_storage()
		{
			auto& peer_storage = get_peer_storage();
			auto& secret_storage = get_secret_storage();
			auto result = ledger::storage_util::multi_storage_index_ptr();
			result.reserve(2);
			result.insert(&peer_storage);
			result.insert(&secret_storage);
			return result;
		}
		uint32_t mempoolstate::get_queries() const
		{
			return peer_local_storage.uses() + secret_local_storage.uses();
		}
		double mempoolstate::fee_percentile(fee_priority priority)
		{
			switch (priority)
			{
				case tangent::storages::fee_priority::fastest:
					return 0.90;
				case tangent::storages::fee_priority::fast:
					return 0.75;
				case tangent::storages::fee_priority::medium:
					return 0.50;
				case tangent::storages::fee_priority::slow:
					return 0.25;
				default:
					return 1.00;
			}
		}
		uint32_t mempoolstate::services_of(const ledger::node& node)
		{
			uint32_t services = 0;
			if (node.services.has_consensus)
				services |= (uint32_t)node_services::consensus;
			if (node.services.has_discovery)
				services |= (uint32_t)node_services::discovery;
			if (node.services.has_superchain)
				services |= (uint32_t)node_services::superchain;
			if (node.services.has_rpc)
				services |= (uint32_t)node_services::rpc;
			if (node.services.has_production)
				services |= (uint32_t)node_services::production;
			if (node.services.has_participation)
				services |= (uint32_t)node_services::participation;
			if (node.services.has_attestation)
				services |= (uint32_t)node_services::attestation;
			return services;
		}
		uint64_t mempoolstate::transaction_limit()
		{
			return 1024 * 1024;
		}
		string mempoolstate::transaction_lookup_key(const std::string_view& transaction_id)
		{
			format::wo_stream message;
			message.write_typeless(uint256_t((uint8_t)'t'));
			if (format::util::is_hex_encoding(transaction_id))
			{
				string key = format::util::decode_0xhex(transaction_id);
				message.write_typeless(key.data(), key.size());
			}
			else
				message.write_typeless(transaction_id.data(), transaction_id.size());
			return message.data;
		}
		string mempoolstate::address_lookup_key(const std::string_view& address)
		{
			format::wo_stream message;
			message.write_typeless(uint256_t((uint8_t)'a'));
			if (format::util::is_hex_encoding(address))
			{
				string key = format::util::decode_0xhex(address);
				message.write_typeless(key.data(), key.size());
			}
			else
				message.write_typeless(address.data(), address.size());
			return message.data;
		}
		string mempoolstate::memo_lookup_key(const algorithm::pubkeyhash_t& memo)
		{
			format::wo_stream message;
			message.write_typeless(uint256_t((uint8_t)'m'));
			message.write_typeless(memo.blob, sizeof(memo.blob));
			return message.data;
		}
		bool mempoolstate::make_schema(sqlite::connection* connection, const std::string_view& name)
		{
			string command;
			if (name == "peerdata")
			{
				auto info = connection->query("PRAGMA table_info(quotes)");
				bool level_present = false;
				bool time_present = false;
				if (info && !info->error_or_empty())
				{
					for (auto row : info->first())
					{
						auto column = row["name"].get().get_string();
						if (column == "level")
							level_present = true;
						else if (column == "time")
							time_present = true;
					}
				}
				if (!level_present || time_present)
					connection->query("DROP TABLE IF EXISTS quotes");

				command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS nodes
				(
					address BLOB NOT NULL,
					account BLOB(20) NOT NULL,
					quality INTEGER DEFAULT NULL,
					services INTEGER NOT NULL,
					node_message BLOB NOT NULL,
					wallet_message BLOB NOT NULL,
					PRIMARY KEY (address, account)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS nodes_account ON nodes (account);
				CREATE TABLE IF NOT EXISTS addresses
				(
					address BLOB NOT NULL,
					reserved BOOLEAN NOT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS cooldowns
				(
					address BLOB NOT NULL,
					expiration INTEGER NOT NULL,
					attempt INTEGER NOT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS proofs
				(
					hash BLOB(32) NOT NULL,
					commitment BLOB(32) NOT NULL,
					asset BLOB(32) NOT NULL,
					message BLOB NOT NULL,
					time INTEGER NOT NULL,
					PRIMARY KEY (hash, commitment)
				);
				CREATE TABLE IF NOT EXISTS commitments
				(
					hash BLOB(32) NOT NULL,
					commitment BLOB(32) NOT NULL,
					signature BLOB(65) NOT NULL,
					PRIMARY KEY (hash, commitment, signature)
				);
				CREATE TABLE IF NOT EXISTS preattestations
				(
					hash BLOB(32) NOT NULL,
					asset BLOB(32) NOT NULL,
					attester BLOB(20) NOT NULL,
					proof_hash BLOB(32) NOT NULL,
					tip_height BIGINT NOT NULL,
					signature BLOB(65) NOT NULL,
					message BLOB DEFAULT NULL,
					time INTEGER NOT NULL,
					PRIMARY KEY (hash, attester)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS preattestations_body ON preattestations (hash, proof_hash);
				CREATE INDEX IF NOT EXISTS preattestations_time ON preattestations (time ASC);
				CREATE INDEX IF NOT EXISTS preattestations_proof ON preattestations (proof_hash);
				CREATE TABLE IF NOT EXISTS preattestation_keys
				(
					lookup_key BLOB NOT NULL,
					proof_hash BLOB(32) NOT NULL,
					PRIMARY KEY (lookup_key, proof_hash)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS quotes
				(
					asset BLOB(32) NOT NULL,
					attester BLOB(20) NOT NULL,
					level TINYINT NOT NULL DEFAULT 0,
					expiry_height BIGINT NOT NULL,
					message BLOB NOT NULL,
					PRIMARY KEY (asset, attester, level)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS quotes_asset ON quotes (asset, expiry_height DESC);
				CREATE TABLE IF NOT EXISTS observations
				(
					hash BLOB(32) NOT NULL,
					time INTEGER NOT NULL,
					PRIMARY KEY (hash)
				);
				CREATE INDEX IF NOT EXISTS observations_time ON observations (time ASC);
				CREATE TABLE IF NOT EXISTS transactions
				(
					hash BLOB(32) NOT NULL,
					commitment_hash BLOB(32) DEFAULT NULL,
					owner BLOB(20) NOT NULL,
					asset BLOB(32) NOT NULL,
					nonce BIGINT NOT NULL,
					epoch INTEGER DEFAULT 0,
					quality INTEGER DEFAULT NULL,
					time INTEGER NOT NULL,
					price TEXT NOT NULL,
					message BLOB NOT NULL,
					PRIMARY KEY (hash)
				);
				CREATE INDEX IF NOT EXISTS transactions_commitment_hash ON transactions (commitment_hash);
				CREATE INDEX IF NOT EXISTS transactions_owner_nonce ON transactions (owner, nonce);
				CREATE INDEX IF NOT EXISTS transactions_asset_quality ON transactions (asset ASC, quality DESC);
				CREATE INDEX IF NOT EXISTS transactions_epoch_quality ON transactions (epoch ASC, quality DESC);
				CREATE INDEX IF NOT EXISTS transactions_epoch_time ON transactions (epoch ASC, time ASC);
				CREATE TRIGGER IF NOT EXISTS transactions_capacity BEFORE INSERT ON transactions BEGIN
					DELETE FROM transactions WHERE hash = (SELECT hash FROM transactions ORDER BY epoch DESC, quality ASC NULLS FIRST) AND (SELECT COUNT(1) FROM transactions) >= max_mempool_size;
				END;
				CREATE TABLE IF NOT EXISTS keystore
				(
					id INTEGER PRIMARY KEY CHECK (id=1),
					salt BLOB,
					data BLOB NOT NULL
				););
				stringify::replace(command, "max_mempool_size", to_string(transaction_limit()));
			}
			else if (name == "secretdata")
			{
				command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS secrets
				(
					owner BLOB(20) NOT NULL,
					asset BLOB(32) NOT NULL,
					hash BLOB(32) NOT NULL,
					participant BLOB(20) NOT NULL,
					entropy_message BLOB NOT NULL,
					PRIMARY KEY (owner, asset, hash, participant)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS keystore
				(
					id INTEGER PRIMARY KEY CHECK (id=1),
					salt BLOB,
					data BLOB NOT NULL
				););
			}
			
			auto cursor = connection->query(command);
			cursor.report("mempoolstate configuration failed");
			return (cursor && !cursor->error());
		}
	}
}