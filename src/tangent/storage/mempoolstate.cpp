#include "mempoolstate.h"
#include "../policy/transactions.h"
#undef NULL

namespace tangent
{
	namespace storages
	{
		static void finalize_checksum(messages::authentic& message, const variant& column)
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
		expects_lr<void> mempoolstate::apply_cooldown_node(const socket_address& node_address, bool cooldown)
		{
			if (!node_address.is_valid())
				return expects_lr<void>(layer_exception("invalid ip address"));

			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));
			map.push_back(var::set::integer(protocol::now().time.now_cpu() + protocol::now().user.tcp.timeout));

			auto cursor = get_storage().emplace_query(__func__, cooldown ? "INSERT INTO cooldowns (address, expiration, attempt) VALUES (?, ?, 0) ON CONFLICT DO UPDATE SET expiration = EXCLUDED.expiration, attempt = attempt + 1 RETURNING attempt" : "DELETE FROM cooldowns WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (!cooldown)
				return expectation::met;

			uint64_t attempt = (*cursor)["attempt"].get().get_integer();
			if (attempt > 9)
				return clear_node(node_address);
			else if (!attempt)
				return expectation::met;

			map[1] = var::set::integer(std::pow(4, attempt));
			cursor = get_storage().emplace_query(__func__, "UPDATE cooldowns SET expiration = expiration + ? WHERE address = ?", &map);
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

			auto cursor = get_storage().emplace_query(__func__, "INSERT OR IGNORE INTO addresses (address, reserved) VALUES (?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::apply_node(const node_pair& value)
		{
			auto& [node, wallet] = value;
			format::wo_stream node_message;
			if (!node.store(&node_message))
				return expects_lr<void>(layer_exception("node serialization error"));

			format::wo_stream wallet_message;
			if (!wallet.store(&wallet_message))
				return expects_lr<void>(layer_exception("wallet serialization error"));

			auto encrypted_wallet_message = protocol::now().box.encrypt(wallet_message.data);
			if (!encrypted_wallet_message)
				return encrypted_wallet_message.error();

			auto address_message = address_to_message(node.address);
			schema_list map;
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(wallet.public_key_hash.view()));
			map.push_back(var::set::binary(address_message));
			map.push_back(var::set::binary(wallet.public_key_hash.view()));
			map.push_back(wallet.has_secret_key() ? var::set::null() : var::set::integer(node.get_preference()));
			map.push_back(var::set::integer(services_of(node)));
			map.push_back(var::set::binary(node_message.data));
			map.push_back(var::set::binary(*encrypted_wallet_message));

			auto cursor = get_storage().emplace_query(__func__,
				"DELETE FROM nodes WHERE address = ? OR account = ?;"
				"INSERT OR REPLACE INTO nodes (address, account, quality, services, node_message, wallet_message) VALUES (?, ?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return apply_cooldown_node(node.address, !wallet.has_secret_key() && !node.availability.reachable);
		}
		expects_lr<void> mempoolstate::apply_node_quality(const socket_address& node_address, int8_t call_result, uint64_t call_latency)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(node_address)));

			auto& storage = get_storage();
			auto cursor = storage.emplace_query(__func__, "SELECT node_message FROM nodes WHERE address = ? AND quality IS NOT NULL", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			ledger::node node;
			auto node_blob = (*cursor)["node_message"].get().get_blob();
			auto node_message = format::ro_stream(node_blob);
			if (!node.load(node_message))
				return expects_lr<void>(layer_exception("node deserialization error"));

			node.availability.timestamp = protocol::now().time.now();
			if (call_latency > 0)
				node.availability.latency = call_latency;
			if (call_result != 0)
			{
				++node.availability.calls;
				if (call_result < 0)
					++node.availability.errors;
			}

			map.clear();
			map.push_back(var::set::integer(node.get_preference()));
			map.push_back(var::set::binary(node.as_message().data));
			map.push_back(var::set::binary(address_to_message(node.address)));

			cursor = storage.emplace_query(__func__, "UPDATE nodes SET quality = ?, node_message = ? WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_node(const algorithm::pubkeyhash_t& account)
		{
			schema_list map;
			map.push_back(var::set::binary(account.view()));

			auto cursor = get_storage().emplace_query(__func__, "DELETE FROM nodes WHERE account = ?", &map);
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

			auto cursor = get_storage().emplace_query(__func__,
				"DELETE FROM nodes WHERE address = ?;"
				"DELETE FROM cooldowns WHERE address = ?;"
				"DELETE FROM addresses WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_cooldowns()
		{
			auto cursor = get_storage().query(__func__, "DELETE FROM cooldowns");
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<node_pair> mempoolstate::get_local_node()
		{
			auto cursor = get_storage().query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality IS NULL LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = protocol::now().box.decrypt((*cursor)["wallet_message"].get().get_blob());
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
		expects_lr<node_pair> mempoolstate::get_neighbor_node(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality IS NOT NULL ORDER BY quality DESC LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = protocol::now().box.decrypt((*cursor)["wallet_message"].get().get_blob());
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

			auto& storage = get_storage();
			auto cursor = storage.emplace_query(__func__, "SELECT quality FROM nodes WHERE account = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			map.clear();
			map.push_back((*cursor)["quality"].get_inline());

			cursor = storage.emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE quality > ? ORDER BY random() LIMIT 1", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = protocol::now().box.decrypt((*cursor)["wallet_message"].get().get_blob());
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

			auto cursor = get_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE address = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = protocol::now().box.decrypt((*cursor)["wallet_message"].get().get_blob());
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

			auto cursor = get_storage().emplace_query(__func__, "SELECT node_message, wallet_message FROM nodes WHERE account = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<node_pair>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto decrypted_message = protocol::now().box.decrypt((*cursor)["wallet_message"].get().get_blob());
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
		expects_lr<vector<node_location_pair>> mempoolstate::get_neighbor_nodes_with(size_t offset, size_t count, uint32_t services)
		{
			schema_list map;
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, "SELECT account, address FROM nodes WHERE quality IS NOT NULL AND (services & ?) == ? ORDER BY quality DESC LIMIT ? OFFSET ?", &map);
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
		expects_lr<vector<node_location_pair>> mempoolstate::get_random_nodes_with(size_t count, uint32_t services, node_ports port)
		{
			schema_list map;
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));

			auto cursor = get_storage().emplace_query(__func__, "SELECT account, address FROM nodes WHERE quality IS NOT NULL AND (services & ?) == ? ORDER BY random() LIMIT ?", &map);
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
			map.push_back(var::set::integer(protocol::now().time.now_cpu()));

			auto& storage = get_storage();
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
			map.push_back(var::set::integer(protocol::now().time.now_cpu()));

			auto cursor = get_storage().emplace_query(__func__, "SELECT COUNT(1) AS counter FROM addresses LEFT JOIN cooldowns ON cooldowns.address = addresses.address WHERE reserved = FALSE AND expiration IS NULL OR expiration < ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<size_t> mempoolstate::get_nodes_count()
		{
			auto cursor = get_storage().query(__func__, "SELECT COUNT(1) AS counter FROM nodes WHERE quality IS NOT NULL");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<bool> mempoolstate::has_cooldown_on_node(const socket_address& address)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(address)));
			map.push_back(var::set::integer(protocol::now().time.now_cpu()));

			auto cursor = get_storage().emplace_query(__func__, "SELECT TRUE AS cooldown FROM cooldowns WHERE address = ? AND expiration >= ? LIMIT 1", &map);
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

			auto cursor = get_storage().emplace_query(__func__, "SELECT price FROM transactions WHERE asset = ? ORDER BY quality DESC NULLS FIRST LIMIT 1 OFFSET (SELECT CAST((COUNT(1) * ?) AS INT) FROM transactions)", &map);
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
			value.as_hash().encode(commitment);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(commitment, sizeof(commitment)));
			map.push_back(var::set::binary(asset_hash, sizeof(asset_hash)));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(commitment, sizeof(commitment)));
			map.push_back(var::set::binary(signature.view()));

			auto cursor = get_storage().emplace_query(__func__,
				"INSERT OR REPLACE INTO proofs (hash, commitment, asset, message) VALUES (?, ?, ?, ?);"
				"INSERT OR REPLACE INTO commitments (hash, commitment, signature) VALUES (?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<uint256_t> mempoolstate::pull_best_attestation_hash(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, "SELECT hash FROM (SELECT hash, COUNT(*) OVER (PARTITION BY hash, commitment) AS signatures FROM commitments) counts ORDER BY signatures DESC LIMIT 1 OFFSET ?", &map);
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

			auto cursor = get_storage().emplace_query(__func__,
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

			auto cursor = get_storage().emplace_query(__func__,
				"DELETE FROM proofs WHERE hash = ?;"
				"DELETE FROM commitments WHERE hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::add_transaction(const ledger::transaction& value, bool resurrection)
		{
			format::wo_stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("transaction serialization error"));

			algorithm::pubkeyhash_t owner;
			if (!value.recover_hash(owner))
				return expects_lr<void>(layer_exception("transaction owner recovery error"));

			decimal quality = decimal::nan();
			if (!value.is_commitment())
			{
				auto median_gas_price = get_gas_price(value.asset, fee_percentile(fee_priority::medium));
				decimal delta_gas = median_gas_price && median_gas_price->is_positive() ? value.gas_price / *median_gas_price : 1.0;
				decimal max_gas = delta_gas.is_positive() ? algorithm::arithmetic::divide(value.gas_price * value.gas_limit.to_decimal(), delta_gas) : decimal::zero();
				decimal multiplier = 2 << 20;
				quality = max_gas * multiplier;
			}

			uint8_t hash[32];
			value.as_hash().encode(hash);

			uint8_t asset[32];
			value.asset.encode(asset);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::binary(asset, sizeof(asset)));
			map.push_back(var::set::integer(value.nonce));
			map.push_back(quality.is_nan() ? var::set::null() : var::set::integer(quality.to_uint64()));
			map.push_back(var::set::integer(time(nullptr) + (value.is_commitment() ? protocol::now().user.consensus.commitment_timeout : protocol::now().user.consensus.transaction_timeout)));
			map.push_back(var::set::string(value.gas_price.to_string()));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::binary(owner.view()));

			auto cursor = get_storage().emplace_query(__func__,
				"INSERT OR REPLACE INTO transactions (hash, owner, asset, nonce, quality, time, price, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
				"WITH epochs AS (SELECT rowid, ROW_NUMBER() OVER (ORDER BY nonce) AS epoch FROM transactions WHERE owner = ?) UPDATE transactions SET epoch = epochs.epoch FROM epochs WHERE transactions.rowid = epochs.rowid", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_transactions(const hash_set<uint256_t>& transaction_hashes)
		{
			if (transaction_hashes.empty())
				return expectation::met;

			uptr<schema> hash_list = var::set::array();
			hash_list->reserve(transaction_hashes.size());
			for (auto& item : transaction_hashes)
			{
				uint8_t hash[32];
				item.encode(hash);
				hash_list->push(var::binary(hash, sizeof(hash)));
			}

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(hash_list))));

			auto cursor = get_storage().emplace_query(__func__,
				"WITH hashes AS (SELECT c.hash FROM transactions p INNER JOIN transactions c ON c.owner = p.owner WHERE p.hash IN ($?) AND c.nonce <= p.nonce) "
				"DELETE FROM transactions WHERE hash IN (SELECT hash FROM hashes)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));

			return expectation::met;
		}
		expects_lr<size_t> mempoolstate::expire_transactions()
		{
			schema_list map;
			map.push_back(var::set::integer(time(nullptr)));

			auto cursor = get_storage().emplace_query(__func__, "DELETE FROM transactions WHERE time < ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return cursor->affected_rows();
		}
		expects_lr<size_t> mempoolstate::get_transactions_count()
		{
			auto cursor = get_storage().query(__func__, "SELECT COUNT(1) AS counter FROM transactions");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<void> mempoolstate::apply_secret_entropy(const algorithm::pubkeyhash_t& participant, const ledger::dispatch_context::secret_entropy& entropy)
		{
			format::wo_stream entropy_message;
			if (!entropy.store(&entropy_message))
				return expects_lr<void>(layer_exception("entropy serialization error"));

			auto encrypted_entropy_message = protocol::now().box.encrypt(entropy_message.data);
			if (!encrypted_entropy_message)
				return encrypted_entropy_message.error();

			uint8_t asset_data[32];
			entropy.asset.encode(asset_data);

			schema_list map;
			map.push_back(var::set::binary(asset_data, sizeof(asset_data)));
			map.push_back(var::set::binary(entropy.owner.view()));
			map.push_back(var::set::binary(entropy.manager.view()));
			map.push_back(var::set::binary(participant.view()));
			map.push_back(var::set::binary(*encrypted_entropy_message));

			auto cursor = get_storage().emplace_query(__func__, "INSERT OR REPLACE INTO secrets (asset, owner, manager, participant, entropy_message) VALUES (?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(ledger::storage_util::error_of(cursor)));
			
			return expectation::met;
		}
		expects_lr<ledger::dispatch_context::secret_entropy> mempoolstate::get_secret_entropy(const algorithm::pubkeyhash_t& participant, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner)
		{
			uint8_t asset_data[32];
			asset.encode(asset_data);

			schema_list map;
			map.push_back(var::set::binary(asset_data, sizeof(asset_data)));
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::binary(manager.view()));
			map.push_back(var::set::binary(participant.view()));

			auto cursor = get_storage().emplace_query(__func__, "SELECT entropy_message FROM secrets WHERE asset = ? AND owner = ? AND manager = ? AND participant = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<ledger::dispatch_context::secret_entropy>(layer_exception(ledger::storage_util::error_of(cursor)));
			else if (cursor->empty())
				return layer_exception("entropy not found");

			auto decrypted_entropy_message = protocol::now().box.decrypt((*cursor)["entropy_message"].get().get_blob());
			if (!decrypted_entropy_message)
				return decrypted_entropy_message.error();

			ledger::dispatch_context::secret_entropy entropy;
			format::ro_stream entropy_message = format::ro_stream(*decrypted_entropy_message);
			if (!entropy.load(entropy_message))
				return expects_lr<ledger::dispatch_context::secret_entropy>(layer_exception("entropy deserialization error"));

			return expects_lr<ledger::dispatch_context::secret_entropy>(std::move(entropy));
		}
		expects_lr<vector<states::bridge_account>> mempoolstate::get_secret_entropies_by_manager(const algorithm::pubkeyhash_t& manager, size_t offset, size_t count)
		{
			schema_list map;
			if (!manager.empty())
				map.push_back(var::set::binary(manager.view()));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, !manager.empty() ? "SELECT asset, owner FROM secrets WHERE manager = ? LIMIT ? OFFSET ?" : "SELECT asset, manager, owner FROM secrets LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<states::bridge_account>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto context = ledger::transaction_context();
			vector<states::bridge_account> result;
			for (auto row : cursor->first())
			{
				auto asset_data = row["asset"].get().get_blob();
				if (asset_data.size() != sizeof(algorithm::asset_id))
					continue;

				algorithm::asset_id asset;
				asset.decode((uint8_t*)asset_data.data());

				auto owner = algorithm::pubkeyhash_t(row["owner"].get().get_blob());
				auto submanager = algorithm::pubkeyhash_t(row["manager"].get().get_blob());
				auto account = context.get_bridge_account(asset, !manager.empty() ? manager : submanager.data, owner.data);
				if (account)
					result.push_back(std::move(*account));
			}
			return result;
		}
		expects_lr<bool> mempoolstate::has_transaction(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_storage().emplace_query(__func__, "SELECT TRUE FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(ledger::storage_util::error_of(cursor)));

			return !cursor->empty();
		}
		expects_lr<uint64_t> mempoolstate::get_lowest_transaction_nonce(const algorithm::pubkeyhash_t& owner)
		{
			schema_list map;
			map.push_back(var::set::binary(owner.view()));

			auto cursor = get_storage().emplace_query(__func__, "SELECT MIN(nonce) AS nonce FROM transactions WHERE owner = ?", &map);
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

			auto cursor = get_storage().emplace_query(__func__, "SELECT max(nonce) AS nonce FROM transactions WHERE owner = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto nonce = (*cursor)["nonce"].get();
			if (!nonce.is(var_type::integer))
				return expects_lr<uint64_t>(layer_exception("highest nonce not found"));

			return nonce.get_integer();
		}
		expects_lr<uptr<ledger::transaction>> mempoolstate::get_transaction_by_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			transaction_hash.encode(hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = get_storage().emplace_query(__func__, "SELECT hash, message FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uptr<ledger::transaction>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto blob = (*cursor)["message"].get().get_blob();
			auto message = format::ro_stream(blob);
			uptr<ledger::transaction> value = transactions::resolver::from_stream(message);
			if (!value || !value->load(message))
				return expects_lr<uptr<ledger::transaction>>(layer_exception("transaction deserialization error"));

			finalize_checksum(**value, (*cursor)["hash"].get());
			return value;
		}
		expects_lr<vector<uptr<ledger::transaction>>> mempoolstate::get_transactions(bool commitment, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, commitment ?
				"SELECT message FROM transactions WHERE quality IS NULL ORDER BY epoch ASC, time ASC NULLS LAST LIMIT ? OFFSET ?" :
				"SELECT message FROM transactions WHERE quality IS NOT NULL ORDER BY epoch ASC, quality DESC NULLS LAST LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				auto blob = row["message"].get().get_blob();
				auto message = format::ro_stream(blob);
				uptr<ledger::transaction> value = transactions::resolver::from_stream(message);
				if (value && value->load(message))
				{
					finalize_checksum(**value, row["hash"].get());
					values.emplace_back(std::move(value));
				}
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::transaction>>> mempoolstate::get_transactions_by_owner(const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::binary(owner.view()));
			map.push_back(var::set::string(direction < 0 ? "DESC" : "ASC"));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = get_storage().emplace_query(__func__, "SELECT message FROM transactions WHERE owner = ? ORDER BY nonce $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(ledger::storage_util::error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				auto blob = row["message"].get().get_blob();
				auto message = format::ro_stream(blob);
				uptr<ledger::transaction> value = transactions::resolver::from_stream(message);
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

			auto cursor = get_storage().emplace_query(__func__, "SELECT hash FROM transactions ORDER BY hash ASC LIMIT ? OFFSET ?", &map);
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
		ledger::storage_index_ptr& mempoolstate::get_storage()
		{
			if (!local_storage.may_use())
			{
				if (!parent_mempoolstate->local_storage.may_use())
					parent_mempoolstate->local_storage = ledger::storage_index_ptr(ledger::storage_util::index_storage_of("mempoolstate", &mempoolstate::make_schema));
				local_storage = parent_mempoolstate->local_storage;
			}
			return local_storage;
		}
		uint32_t mempoolstate::get_queries() const
		{
			return local_storage.uses();
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
			if (node.services.has_rpc_web_sockets)
				services |= (uint32_t)node_services::rpc_web_sockets;
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
			auto& params = protocol::now();
			auto transactions = ledger::block_header::get_transaction_limit() * (params.user.consensus.transaction_timeout / params.policy.pow.time);
			auto commitments = ledger::block_header::get_commitment_limit() * (params.user.consensus.commitment_timeout / params.policy.pow.time);
			return transactions + commitments;
		}
		bool mempoolstate::make_schema(sqlite::connection* connection)
		{
			string command = VI_STRINGIFY(
			CREATE TABLE IF NOT EXISTS nodes
			(
				address BLOB NOT NULL,
				account BLOB(20) NOT NULL,
				quality INTEGER DEFAULT NULL,
				services INTEGER NOT NULL,
				node_message BLOB NOT NULL,
				wallet_message BLOB NOT NULL,
				PRIMARY KEY (address)
				UNIQUE (account)
			) WITHOUT ROWID;
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
			CREATE TABLE IF NOT EXISTS secrets
			(
				asset BLOB(32) NOT NULL,
				owner BLOB(20) NOT NULL,
				manager BLOB(20) NOT NULL,
				participant BLOB(20) NOT NULL,
				entropy_message BLOB NOT NULL,
				PRIMARY KEY (asset, owner, manager, participant)
			) WITHOUT ROWID;
			CREATE INDEX IF NOT EXISTS secrets_manager ON secrets (manager);
			CREATE TABLE IF NOT EXISTS proofs
			(
				hash BLOB(32) NOT NULL,
				commitment BLOB(32) NOT NULL,
				asset BLOB(32) NOT NULL,
				message BLOB NOT NULL,
				PRIMARY KEY (hash, commitment)
			);
			CREATE TABLE IF NOT EXISTS commitments
			(
				hash BLOB(32) NOT NULL,
				commitment BLOB(32) NOT NULL,
				signature BLOB(65) NOT NULL,
				PRIMARY KEY (hash, commitment, signature)
			);
			CREATE TABLE IF NOT EXISTS transactions
			(
				hash BLOB(32) NOT NULL,
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
			CREATE TABLE IF NOT EXISTS transactions
			(
				hash BLOB(32) NOT NULL,
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
			CREATE INDEX IF NOT EXISTS transactions_owner_nonce ON transactions (owner, nonce);
			CREATE INDEX IF NOT EXISTS transactions_asset_quality ON transactions (asset ASC, quality DESC);
			CREATE INDEX IF NOT EXISTS transactions_epoch_quality ON transactions (epoch ASC, quality DESC);
			CREATE INDEX IF NOT EXISTS transactions_epoch_time ON transactions(epoch ASC, time ASC);
			CREATE TRIGGER IF NOT EXISTS transactions_capacity BEFORE INSERT ON transactions BEGIN
				DELETE FROM transactions WHERE hash = (SELECT hash FROM transactions ORDER BY epoch DESC, quality ASC NULLS FIRST) AND (SELECT COUNT(1) FROM transactions) >= max_mempool_size;
			END;);
			stringify::replace(command, "max_mempool_size", to_string(transaction_limit()));

			auto cursor = connection->query(command);
			cursor.report("mempoolstate configuration failed");
			return (cursor && !cursor->error());
		}
	}
}