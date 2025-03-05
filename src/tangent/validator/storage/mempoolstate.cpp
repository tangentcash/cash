#include "mempoolstate.h"
#include "../../policy/transactions.h"
#undef NULL

namespace tangent
{
	namespace storages
	{
		static void finalize_checksum(messages::authentic& message, const variant& column)
		{
			if (column.size() == sizeof(uint256_t))
				algorithm::encoding::encode_uint256(column.get_binary(), message.checksum);
		}
		static string address_to_message(const socket_address& address)
		{
			format::stream message;
			message.write_string(address.get_ip_address().otherwise("[bad_address]"));
			message.write_integer(address.get_ip_port().otherwise(0));
			return message.data;
		}
		static option<socket_address> message_to_address(const std::string_view& data)
		{
			format::stream message(data);
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

		static thread_local mempoolstate* latest_mempoolstate = nullptr;
		mempoolstate::mempoolstate(const std::string_view& new_label) noexcept : label(new_label), borrows(latest_mempoolstate != nullptr)
		{
			if (!borrows)
			{
				storage_of("mempoolstate");
				latest_mempoolstate = this;
			}
			else
				storage = *latest_mempoolstate->storage;
		}
		mempoolstate::~mempoolstate() noexcept
		{
			if (borrows)
				storage.reset();
			if (latest_mempoolstate == this)
				latest_mempoolstate = nullptr;
		}
		expects_lr<void> mempoolstate::apply_trial_address(const socket_address& address)
		{
			if (!address.is_valid())
				return expects_lr<void>(layer_exception("invalid ip address"));

			if (get_validator_by_address(address))
				return expects_lr<void>(layer_exception("ip address and port found"));

			schema_list map;
			map.push_back(var::set::binary(address_to_message(address)));

			auto cursor = emplace_query(label, __func__, "INSERT OR IGNORE INTO seeds (address) VALUES (?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::apply_validator(const ledger::validator& value, option<ledger::wallet>&& wallet)
		{
			format::stream edge_message;
			if (!value.store(&edge_message))
				return expects_lr<void>(layer_exception("validator serialization error"));

			format::stream wallet_message;
			if (wallet && !wallet->store(&wallet_message))
				return expects_lr<void>(layer_exception("wallet serialization error"));

			if (!wallet)
			{
				schema_list map;
				map.push_back(var::set::binary(address_to_message(value.address)));

				auto cursor = emplace_query(label, __func__, "SELECT wallet_message FROM validators WHERE address = ? AND wallet_message IS NOT NULL", &map);
				if (cursor && !cursor->error_or_empty())
				{
					wallet_message.data = (*cursor)["wallet_message"].get().get_blob();
					wallet = ledger::wallet();
				}
			}
			else
			{
				auto blob = protocol::now().key.encrypt_blob(wallet_message.data);
				if (!blob)
					return blob.error();

				wallet_message.data = std::move(*blob);
			}

			uint32_t services = 0;
			if (value.services.has_consensus)
				services |= (uint32_t)node_services::consensus;
			if (value.services.has_discovery)
				services |= (uint32_t)node_services::discovery;
			if (value.services.has_interfaces)
				services |= (uint32_t)node_services::interfaces;
			if (value.services.has_synchronization)
				services |= (uint32_t)node_services::synchronization;
			if (value.services.has_proposer)
				services |= (uint32_t)node_services::proposer;
			if (value.services.has_publicity)
				services |= (uint32_t)node_services::publicity;
			if (value.services.has_streaming)
				services |= (uint32_t)node_services::streaming;

			schema_list map;
			map.push_back(var::set::binary(address_to_message(value.address)));
			map.push_back(var::set::integer(value.get_preference()));
			map.push_back(var::set::integer(services));
			map.push_back(var::set::binary(edge_message.data));
			map.push_back(wallet ? var::set::binary(wallet_message.data) : var::set::null());

			auto cursor = emplace_query(label, __func__, "INSERT OR REPLACE INTO validators (address, preference, services, validator_message, wallet_message) VALUES (?, ?, ?, ?, ?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::clear_validator(const socket_address& validator_address)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(validator_address)));

			auto cursor = emplace_query(label, __func__, "DELETE FROM validators WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<std::pair<ledger::validator, ledger::wallet>> mempoolstate::get_validator_by_ownership(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT validator_message, wallet_message FROM validators WHERE NOT (wallet_message IS NULL) LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<std::pair<ledger::validator, ledger::wallet>>(layer_exception(error_of(cursor)));

			auto blob = protocol::now().key.decrypt_blob((*cursor)["wallet_message"].get().get_blob());
			if (!blob)
				return blob.error();

			ledger::validator node;
			format::stream edge_message = format::stream((*cursor)["validator_message"].get().get_blob());
			if (!node.load(edge_message))
				return expects_lr<std::pair<ledger::validator, ledger::wallet>>(layer_exception("validator deserialization error"));

			ledger::wallet wallet;
			format::stream wallet_message = format::stream(std::move(*blob));
			if (!wallet.load(wallet_message))
				return expects_lr<std::pair<ledger::validator, ledger::wallet>>(layer_exception("wallet deserialization error"));

			return std::make_pair(std::move(node), std::move(wallet));
		}
		expects_lr<ledger::validator> mempoolstate::get_validator_by_address(const socket_address& validator_address)
		{
			schema_list map;
			map.push_back(var::set::binary(address_to_message(validator_address)));

			auto cursor = emplace_query(label, __func__, "SELECT validator_message FROM validators WHERE address = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::validator>(layer_exception(error_of(cursor)));

			ledger::validator value;
			format::stream message = format::stream((*cursor)["validator_message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<ledger::validator>(layer_exception("validator deserialization error"));

			return value;
		}
		expects_lr<ledger::validator> mempoolstate::get_validator_by_preference(size_t offset)
		{
			schema_list map;
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT validator_message FROM validators WHERE wallet_message IS NULL ORDER BY preference DESC NULLS FIRST LIMIT 1 OFFSET ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<ledger::validator>(layer_exception(error_of(cursor)));

			ledger::validator value;
			format::stream message = format::stream((*cursor)["validator_message"].get().get_blob());
			if (!value.load(message))
				return expects_lr<ledger::validator>(layer_exception("validator deserialization error"));

			return value;
		}
		expects_lr<vector<socket_address>> mempoolstate::get_validator_addresses(size_t offset, size_t count, uint32_t services)
		{
			schema_list map;
			if (services > 0)
				map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, stringify::text("SELECT validator_message FROM validators WHERE wallet_message IS NULL %s ORDER BY preference DESC NULLS FIRST LIMIT ? OFFSET ?", services > 0 ? "AND services & ? > 0" : ""), &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<socket_address>>(layer_exception(error_of(cursor)));

			vector<socket_address> result;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				ledger::validator value;
				format::stream message = format::stream(response[i]["validator_message"].get().get_blob());
				if (value.load(message))
					result.push_back(std::move(value.address));
			}

			return result;
		}
		expects_lr<vector<socket_address>> mempoolstate::get_randomized_validator_addresses(size_t count, uint32_t services)
		{
			schema_list map;
			if (services > 0)
				map.push_back(var::set::integer(services));
			map.push_back(var::set::integer(count));

			auto cursor = emplace_query(label, __func__, stringify::text("SELECT validator_message FROM validators WHERE wallet_message IS NULL %s ORDER BY random() LIMIT ?", services > 0 ? "AND services & ? > 0" : ""), &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<socket_address>>(layer_exception(error_of(cursor)));

			vector<socket_address> result;
			auto& response = cursor->first();
			size_t size = response.size();
			for (size_t i = 0; i < size; i++)
			{
				ledger::validator value;
				format::stream message = format::stream(response[i]["validator_message"].get().get_blob());
				if (value.load(message))
					result.push_back(std::move(value.address));
			}

			return result;
		}
		expects_lr<socket_address> mempoolstate::next_trial_address()
		{
			auto cursor = query(label, __func__, "SELECT address FROM seeds ORDER BY random() LIMIT 1");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<socket_address>(layer_exception(error_of(cursor)));

			auto message = (*cursor)["address"].get().get_blob();
			schema_list map;
			map.push_back(var::set::binary(message));

			cursor = emplace_query(label, __func__, "DELETE FROM seeds WHERE address = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<socket_address>(layer_exception(error_of(cursor)));

			auto address = message_to_address(message);
			if (!address)
				return expects_lr<socket_address>(layer_exception("bad address"));

			return *address;
		}
		expects_lr<size_t> mempoolstate::get_validators_count()
		{
			auto cursor = query(label, __func__, "SELECT COUNT(1) AS counter FROM validators WHERE wallet_message IS NULL");
			if (!cursor || cursor->error_or_empty())
				return expects_lr<size_t>(layer_exception(error_of(cursor)));

			return (size_t)(*cursor)["counter"].get().get_integer();
		}
		expects_lr<decimal> mempoolstate::get_gas_price(const algorithm::asset_id& asset, double priority_percentile)
		{
			if (priority_percentile < 0.0 || priority_percentile > 1.0)
				return expects_lr<decimal>(layer_exception("invalid priority percentile"));

			uint8_t hash[16];
			algorithm::encoding::decode_uint128(asset, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::number(1.0 - priority_percentile));

			auto cursor = emplace_query(label, __func__, "SELECT price FROM transactions WHERE asset = ? ORDER BY preference DESC NULLS FIRST LIMIT 1 OFFSET (SELECT CAST((COUNT(1) * ?) AS INT) FROM transactions)", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<decimal>(layer_exception(error_of(cursor)));

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

			return *b / a->truncate(protocol::now().message.precision);
		}
		expects_lr<void> mempoolstate::add_transaction(ledger::transaction& value, bool bypass_congestion)
		{
			format::stream message;
			if (!value.store(&message))
				return expects_lr<void>(layer_exception("transaction serialization error"));

			algorithm::pubkeyhash owner;
			if (!value.recover_hash(owner))
				return expects_lr<void>(layer_exception("transaction owner recovery error"));

			uint256_t group = 0;
			decimal preference = decimal::nan();
			auto type = value.get_type();
			auto queue = [this, &value]() -> decimal
			{
				auto median_gas_price = get_gas_price(value.asset, fee_percentile(fee_priority::medium));
				decimal delta_gas = median_gas_price && median_gas_price->is_positive() ? value.gas_price / *median_gas_price : 1.0;
				decimal max_gas = delta_gas.is_positive() ? value.gas_price * value.gas_limit.to_decimal() / delta_gas.truncate(protocol::now().message.precision) : decimal::zero();
				decimal multiplier = 2 << 20;
				return max_gas * multiplier;
			};
			switch (type)
			{
				case ledger::transaction_level::functional:
				{
					preference = queue();
					break;
				}
				case ledger::transaction_level::delegation:
				{
					auto bandwidth = get_bandwidth_by_owner(owner, type);
					if (!bandwidth->congested || bandwidth->sequence >= value.sequence)
						break;

					if (!bypass_congestion && !value.gas_price.is_positive())
						return expects_lr<void>(layer_exception(stringify::text("wait for finalization of or replace previous delegation transaction (queue: %" PRIu64 ", sequence: %" PRIu64 ")", (uint64_t)bandwidth->count, bandwidth->sequence)));

					preference = queue();
					break;
				}
				case ledger::transaction_level::consensus:
				{
					auto bandwidth = get_bandwidth_by_owner(owner, type);
					if (!bandwidth->congested || bandwidth->sequence >= value.sequence)
						break;

					if (!bypass_congestion && !value.gas_price.is_positive())
						return expects_lr<void>(layer_exception(stringify::text("wait for finalization of or replace previous consensus transaction (queue: %" PRIu64 ", sequence: %" PRIu64 ")", (uint64_t)bandwidth->count, bandwidth->sequence)));

					preference = queue();
					break;
				}
				case ledger::transaction_level::aggregation:
				{
					vector<uint256_t> merges;
					size_t offset = 0, count = 64;
					auto context = ledger::transaction_context();
					auto* aggregation = ((ledger::aggregation_transaction*)&value);
					group = aggregation->get_cumulative_hash();
					while (true)
					{
						auto transactions = get_cumulative_event_transactions(group, offset, count);
						if (!transactions || transactions->empty())
							break;

						for (auto& item : *transactions)
						{
							merges.push_back(item->as_hash());
							if (item->get_type() != ledger::transaction_level::aggregation)
								continue;

							auto& candidate = *(ledger::aggregation_transaction*)*item;
							aggregation->merge(&context, candidate);
						}

						offset += transactions->size();
						if (transactions->size() != count)
							break;
					}

					auto status = remove_transactions(merges);
					if (!status)
						return status;
					else if (!merges.empty())
						break;

					auto optimal_gas_limit = ledger::transaction_context::calculate_tx_gas(aggregation);
					if (optimal_gas_limit && *optimal_gas_limit > aggregation->gas_limit)
						aggregation->gas_limit = *optimal_gas_limit;

					preference = queue();
					break;
				}
				default:
					break;
			}

			uint8_t hash[32];
			algorithm::encoding::decode_uint256(value.as_hash(), hash);

			uint8_t group_hash[32];
			algorithm::encoding::decode_uint256(group, group_hash);

			uint8_t asset[16];
			algorithm::encoding::decode_uint128(value.asset, asset);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::binary(group_hash, sizeof(group_hash)));
			map.push_back(var::set::binary(owner, sizeof(owner)));
			map.push_back(var::set::binary(asset, sizeof(asset)));
			map.push_back(var::set::integer(value.sequence));
			map.push_back(preference.is_nan() ? var::set::null() : var::set::integer(preference.to_uint64()));
			map.push_back(var::set::integer((int64_t)type));
			map.push_back(var::set::integer(time(nullptr)));
			map.push_back(var::set::string(value.gas_price.to_string()));
			map.push_back(var::set::binary(message.data));
			map.push_back(var::set::binary(owner, sizeof(owner)));

			auto cursor = emplace_query(label, __func__,
				"INSERT OR REPLACE INTO transactions (hash, attestation, owner, asset, sequence, preference, type, time, price, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
				"WITH epochs AS (SELECT rowid, ROW_NUMBER() OVER (ORDER BY sequence) AS epoch FROM transactions WHERE owner = ?) UPDATE transactions SET epoch = epochs.epoch FROM epochs WHERE transactions.rowid = epochs.rowid", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_transactions(const vector<uint256_t>& transaction_hashes)
		{
			if (transaction_hashes.empty())
				return expectation::met;

			uptr<schema> hash_list = var::set::array();
			hash_list->reserve(transaction_hashes.size());
			for (auto& item : transaction_hashes)
			{
				uint8_t hash[32];
				algorithm::encoding::decode_uint256(item, hash);
				hash_list->push(var::binary(hash, sizeof(hash)));
			}

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(hash_list))));

			auto cursor = emplace_query(label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::remove_transactions(const unordered_set<uint256_t>& transaction_hashes)
		{
			if (transaction_hashes.empty())
				return expectation::met;

			uptr<schema> hash_list = var::set::array();
			hash_list->reserve(transaction_hashes.size());
			for (auto& item : transaction_hashes)
			{
				uint8_t hash[32];
				algorithm::encoding::decode_uint256(item, hash);
				hash_list->push(var::binary(hash, sizeof(hash)));
			}

			schema_list map;
			map.push_back(var::set::string(*sqlite::utils::inline_array(std::move(hash_list))));

			auto cursor = emplace_query(label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<void> mempoolstate::expire_transactions()
		{
			schema_list map;
			map.push_back(var::set::integer(time(nullptr) - protocol::now().user.storage.transaction_timeout));

			auto cursor = emplace_query(label, __func__, "DELETE FROM transactions WHERE time < ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<void>(layer_exception(error_of(cursor)));

			return expectation::met;
		}
		expects_lr<account_bandwidth> mempoolstate::get_bandwidth_by_owner(const algorithm::pubkeyhash owner, ledger::transaction_level type)
		{
			schema_list map;
			map.push_back(var::set::binary(owner, sizeof(algorithm::pubkeyhash)));
			map.push_back(var::set::integer((int64_t)type));

			auto cursor = emplace_query(label, __func__, "SELECT COUNT(1) AS counter, max(sequence) AS sequence FROM transactions WHERE owner = ? AND type = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<account_bandwidth>(layer_exception(error_of(cursor)));

			account_bandwidth result;
			result.count = cursor->empty() ? 0 : (size_t)(*cursor)["counter"].get().get_integer();
			result.sequence = cursor->empty() ? 1 : (size_t)(*cursor)["sequence"].get().get_integer();
			switch (type)
			{
				case tangent::ledger::transaction_level::functional:
					result.congested = false;
					break;
				case tangent::ledger::transaction_level::delegation:
					result.congested = protocol::now().policy.parallel_delegation_limit > 0 && result.count >= protocol::now().policy.parallel_delegation_limit;
					break;
				case tangent::ledger::transaction_level::consensus:
					result.congested = protocol::now().policy.parallel_consensus_limit > 0 && result.count >= protocol::now().policy.parallel_consensus_limit;
					break;
				case tangent::ledger::transaction_level::aggregation:
					result.congested = protocol::now().policy.parallel_aggregation_limit > 0 && result.count >= protocol::now().policy.parallel_aggregation_limit;
					break;
				default:
					result.congested = true;
					break;
			}
			return result;
		}
		expects_lr<bool> mempoolstate::has_transaction(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(transaction_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(label, __func__, "SELECT TRUE FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<bool>(layer_exception(error_of(cursor)));

			return !cursor->empty();
		}
		expects_lr<uint64_t> mempoolstate::get_lowest_transaction_sequence(const algorithm::pubkeyhash owner)
		{
			schema_list map;
			map.push_back(var::set::binary(owner, sizeof(algorithm::pubkeyhash)));

			auto cursor = emplace_query(label, __func__, "SELECT MIN(sequence) AS sequence FROM transactions WHERE owner = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			uint64_t sequence = (*cursor)["sequence"].get().get_integer();
			return sequence;
		}
		expects_lr<uint64_t> mempoolstate::get_highest_transaction_sequence(const algorithm::pubkeyhash owner)
		{
			schema_list map;
			map.push_back(var::set::binary(owner, sizeof(algorithm::pubkeyhash)));

			auto cursor = emplace_query(label, __func__, "SELECT max(sequence) AS sequence FROM transactions WHERE owner = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uint64_t>(layer_exception(error_of(cursor)));

			uint64_t sequence = (*cursor)["sequence"].get().get_integer();
			return sequence;
		}
		expects_lr<uptr<ledger::transaction>> mempoolstate::get_transaction_by_hash(const uint256_t& transaction_hash)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(transaction_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));

			auto cursor = emplace_query(label, __func__, "SELECT hash, message FROM transactions WHERE hash = ?", &map);
			if (!cursor || cursor->error_or_empty())
				return expects_lr<uptr<ledger::transaction>>(layer_exception(error_of(cursor)));

			format::stream message = format::stream((*cursor)["message"].get().get_blob());
			uptr<ledger::transaction> value = transactions::resolver::init(messages::authentic::resolve_type(message).otherwise(0));
			if (!value || !value->load(message))
				return expects_lr<uptr<ledger::transaction>>(layer_exception("transaction deserialization error"));

			finalize_checksum(**value, (*cursor)["hash"].get());
			return value;
		}
		expects_lr<vector<uptr<ledger::transaction>>> mempoolstate::get_transactions(size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions ORDER BY epoch ASC, preference DESC NULLS FIRST LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				format::stream message = format::stream(row["message"].get().get_blob());
				uptr<ledger::transaction> value = transactions::resolver::init(messages::authentic::resolve_type(message).otherwise(0));
				if (value && value->load(message))
				{
					finalize_checksum(**value, row["hash"].get());
					values.emplace_back(std::move(value));
				}
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::transaction>>> mempoolstate::get_transactions_by_owner(const algorithm::pubkeyhash owner, int8_t direction, size_t offset, size_t count)
		{
			schema_list map;
			map.push_back(var::set::binary(owner, sizeof(algorithm::pubkeyhash)));
			map.push_back(var::set::string(direction < 0 ? "DESC" : "ASC"));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE owner = ? ORDER BY sequence $? LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				format::stream message = format::stream(row["message"].get().get_blob());
				uptr<ledger::transaction> value = transactions::resolver::init(messages::authentic::resolve_type(message).otherwise(0));
				if (value && value->load(message))
				{
					finalize_checksum(**value, row["hash"].get());
					values.emplace_back(std::move(value));
				}
			}

			return values;
		}
		expects_lr<vector<uptr<ledger::transaction>>> mempoolstate::get_cumulative_event_transactions(const uint256_t& cumulative_hash, size_t offset, size_t count)
		{
			uint8_t hash[32];
			algorithm::encoding::decode_uint256(cumulative_hash, hash);

			schema_list map;
			map.push_back(var::set::binary(hash, sizeof(hash)));
			map.push_back(var::set::integer(count));
			map.push_back(var::set::integer(offset));

			auto cursor = emplace_query(label, __func__, "SELECT message FROM transactions WHERE attestation = ? ORDER BY attestation ASC LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uptr<ledger::transaction>>>(layer_exception(error_of(cursor)));

			auto& response = cursor->first();
			size_t size = response.size();
			vector<uptr<ledger::transaction>> values;
			values.reserve(size);

			for (size_t i = 0; i < size; i++)
			{
				auto row = response[i];
				format::stream message = format::stream(row["message"].get().get_blob());
				uptr<ledger::transaction> value = transactions::resolver::init(messages::authentic::resolve_type(message).otherwise(0));
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

			auto cursor = emplace_query(label, __func__, "SELECT hash FROM transactions ORDER BY hash ASC LIMIT ? OFFSET ?", &map);
			if (!cursor || cursor->error())
				return expects_lr<vector<uint256_t>>(layer_exception(error_of(cursor)));

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
				algorithm::encoding::encode_uint256((uint8_t*)in_hash.data(), out_hash);
				result.push_back(out_hash);
			}

			return result;
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
		bool mempoolstate::reconstruct_storage()
		{
			string command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS validators
				(
					address BINARY NOT NULL,
					preference INTEGER NOT NULL,
					services INTEGER NOT NULL,
					validator_message BINARY NOT NULL,
					wallet_message BINARY DEFAULT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS validators_wallet_message_preference ON validators (wallet_message IS NULL, preference);
				CREATE TABLE IF NOT EXISTS seeds
				(
					address BINARY NOT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS transactions
				(
					hash BINARY(32) NOT NULL,
					attestation BINARY(32) DEFAULT NULL,
					owner BINARY(20) NOT NULL,
					asset BINARY(16) NOT NULL,
					sequence BIGINT NOT NULL,
					epoch INTEGER DEFAULT 0,
					preference INTEGER DEFAULT NULL,
					type INTEGER NOT NULL,
					time INTEGER NOT NULL,
					price TEXT NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (hash)
				);
				CREATE INDEX IF NOT EXISTS transactions_attestation ON transactions (attestation);
				CREATE INDEX IF NOT EXISTS transactions_owner_sequence ON transactions (owner, sequence);
				CREATE INDEX IF NOT EXISTS transactions_asset_preference ON transactions (asset ASC, preference DESC);
				CREATE INDEX IF NOT EXISTS transactions_epoch_preference ON transactions (epoch ASC, preference DESC););

			auto cursor = query(label, __func__, command);
			return (cursor && !cursor->error());
		}
	}
}