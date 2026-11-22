#include "consensus.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../policy/transactions.h"
#include "../policy/delegations.h"
#include <random>
#define TASK_TOPOLOGY_OPTIMIZATION "topology_optimization"
#define TASK_MEMPOOL_VACUUM "mempool_vacuum"
#define TASK_MEMPOOL_SYNC "mempool_sync"
#define TASK_FORK_RESOLUTION "fork_resolution"
#define TASK_SUPERCHAIN_SYNC "superchain_sync"
#define TASK_ATTESTATION_RESOLUTION "attestation_resolution"
#define TASK_BLOCK_PRODUCTION "block_production"
#define TASK_BLOCK_DISPATCHER "block_dispatcher"
#define TASK_BLOCK_DISPATCHER_LATE "block_dispatcher_late"
#define OUTGOING_QUEUE_SIZE 8192
#define MEMPOOL_RETRY_SIZE 64

namespace tangent
{
	namespace consensus
	{
		struct message_header
		{
			uint32_t magic;
			uint32_t checksum;
			uint32_t length;
		};

		static const uint8_t MAX_BOUND_ACCOUNTS = 64;
		static const uint8_t MAX_FORWARD_HOPS = 16;
		static const size_t MAX_DELEGATION_PATHS = 4096;
		static const uint64_t DELEGATION_PATH_TTL_MS = 5 * 60 * 1000;
		static void mask_set(string& mask, slot_t bit)
		{
			size_t byte = bit >> 3;
			if (mask.size() <= byte)
				mask.resize(byte + 1);
			mask[byte] = (char)(mask[byte] | (1 << (bit & 7)));
		}
		static bool mask_test(const string& mask, slot_t bit)
		{
			size_t byte = bit >> 3;
			return byte < mask.size() && (((unsigned char)mask[byte] >> (bit & 7)) & 1) != 0;
		}
		static void mask_clear(string& mask, slot_t bit)
		{
			size_t byte = bit >> 3;
			if (byte < mask.size())
				mask[byte] = (char)(mask[byte] & ~(char)(1 << (bit & 7)));
		}
		static string uint256_to_label(const uint256_t& hash, size_t margin = 11)
		{
			string result = algorithm::encoding::encode_0xhex256(hash);
			if (result.size() > margin * 2 + 3)
				result.replace(margin, result.size() - 2 * margin, "...");
			return result;
		}
		static string seconds_to_duration(uint64_t base_seconds)
		{
			if (!base_seconds)
				return "0 seconds";

			constexpr double SEC_PER_MIN = 60.0;
			constexpr double SEC_PER_HOUR = 60.0 * SEC_PER_MIN;
			constexpr double SEC_PER_DAY = 24.0 * SEC_PER_HOUR;
			constexpr double SEC_PER_WEEK = 7.0 * SEC_PER_DAY;
			constexpr double SEC_PER_MONTH = (365.2425 / 12.0) * SEC_PER_DAY;
			constexpr double SEC_PER_YEAR = 365.2425 * SEC_PER_DAY;
			auto to_duration = [](double value, const std::string_view& duration)
			{
				if (std::abs(value - std::round(value)) < 1e-3)
					return stringify::text("%" PRIi64 " %.*s%s", (int64_t)value, (int)duration.size(), duration.data(), value > 1 ? "s" : "");

				char buffer[64];
				auto text = to_string_view(buffer, sizeof(buffer), value);
				auto index = text.find('.');
				text = index != std::string_view::npos ? text.substr(0, index + 2) : text;
				return stringify::text("%.*s %.*s%s", (int)text.size(), text.data(), (int)duration.size(), duration.data(), value > 1 ? "s" : "");
			};
			double seconds = (double)base_seconds;
			if (seconds >= SEC_PER_YEAR)
				return to_duration(seconds / SEC_PER_YEAR, "year");
			else if (seconds >= SEC_PER_MONTH)
				return to_duration(seconds / SEC_PER_MONTH, "month");
			else if (seconds >= SEC_PER_WEEK)
				return to_duration(seconds / SEC_PER_WEEK, "week");
			else if (seconds >= SEC_PER_DAY)
				return to_duration(seconds / SEC_PER_DAY, "day");
			else if (seconds >= SEC_PER_HOUR)
				return to_duration(seconds / SEC_PER_HOUR, "hour");
			else if (seconds >= SEC_PER_MIN)
				return to_duration(seconds / SEC_PER_MIN, "minute");
			return to_duration(seconds, "second");
		}
		static option<socket_address> text_address_to_socket_address(const std::string_view& value, bool allow_private_network)
		{
			auto ip_address = value.substr(0, value.find(':'));
			auto ip_port = ip_address.size() + 1 <= value.size() ? value.substr(ip_address.size() + 1) : std::string_view();
			auto address = socket_address(ip_address, from_string<uint16_t>(ip_port).or_else(0));
			if (!address.is_valid())
				return option<socket_address>(optional::none);

			allow_private_network = allow_private_network || kernel::params().is(network_type::regtest);
			if (!allow_private_network && (storages::routing_util::is_address_reserved(address) || storages::routing_util::is_address_private(address)))
				return option<socket_address>(optional::none);

			return option<socket_address>(std::move(address));
		}
		static option<string> socket_address_to_text_address(const socket_address& value)
		{
			auto ip_address = value.get_ip_address();
			auto ip_port = value.get_ip_port();
			return ip_address && ip_port ? option<string>(*ip_address + ":" + to_string(*ip_port)) : option<string>(optional::none);
		}
		static uint256_t handshake_proof(const ledger::node& node, uint64_t time, string* node_message_out)
		{
			format::wo_stream message;
			node.store(&message);
			if (node_message_out != nullptr)
				node_message_out->assign(message.data);
			message.write_integer(time);
			return message.hash();
		}
		static uint256_t account_binding_proof(const algorithm::pubkey_t& account_key, const algorithm::pubkey_t& node_key, const socket_address& address)
		{
			format::wo_stream message;
			message.write_string(account_key.optimized_view());
			message.write_string(node_key.optimized_view());
			message.write_string(address.get_ip_address().or_else(string()));
			message.write_integer(address.get_ip_port().or_else(0));
			return message.hash();
		}
		static uint256_t preattestation_proof(const algorithm::asset_id& asset, const uint256_t& attestation_hash, uint64_t tip_height, const uint256_t& proof_hash)
		{
			format::wo_stream message;
			message.write_integer(algorithm::asset::base_id_of(asset));
			message.write_integer(attestation_hash);
			message.write_integer(tip_height);
			message.write_integer(proof_hash);
			return message.hash();
		}
		static uint256_t delegation_input_proof(const socket_address& address, uint64_t block_number, uint32_t contract_type, const format::variables& args, const btree_set<algorithm::pubkeyhash_t>& accounts)
		{
			format::wo_stream message;
			message.write_string(address.get_ip_address().or_else(string()));
			message.write_integer(address.get_ip_port().or_else(0));
			message.write_integer(contract_type);
			message.write_integer(block_number);
			for (auto& account : accounts)
				message.write_typeless(account.view());
			format::variables_util::serialize_flat_into(args, &message);
			return message.hash();
		}
		static uint256_t delegation_output_proof(const uint256_t& delegation_id, const algorithm::pubkey_t& account_key)
		{
			format::wo_stream message;
			message.write_typeless(delegation_id);
			message.write_string(account_key.optimized_view());
			return message.hash();
		}
		static format::variables pack_query_result(const expects_rt<format::variables>& result)
		{
			if (!result)
			{
				if (result.error().is_retry())
					return format::variables({ format::variable((uint8_t)0x1F) });
				else if (result.error().is_shutdown())
					return format::variables({ format::variable((uint8_t)0x2F) });

				return format::variables({ format::variable(true), format::variable(result.what()) });
			}

			format::wo_stream message;
			format::variables_util::serialize_flat_into(*result, &message);
			return format::variables({ format::variable(false), format::variable(message.data) });
		}
		static expects_rt<format::variables> unpack_query_result(const format::variables& packed_result)
		{
			if (packed_result.empty())
				return remote_exception("invalid response type");

			auto& type = packed_result.front();
			if (type.is_integer())
			{
				auto type_id = packed_result.size() == 1 ? type.as_uint8() : 0;
				if (type_id == 0x1F)
					return remote_exception::retry_later();
				else if (type_id == 0x2F)
					return remote_exception::shutdown();

				return remote_exception("invalid response type");
			}
			else if (packed_result.size() != 2)
				return remote_exception("invalid response type");
			else if (type.as_boolean())
				return remote_exception(packed_result.back().as_blob());

			format::variables result;
			format::ro_stream message = format::ro_stream(packed_result.back().as_string());
			if (!format::variables_util::deserialize_flat_from(message, &result))
				return remote_exception("invalid response body");

			return expects_rt<format::variables>(std::move(result));
		}
		static expects_rt<format::variables> pack_private_result(const format::variables& result, const algorithm::pubkey_t& to_public_key, const algorithm::seckey_t& from_secret_key)
		{
			format::wo_stream message;
			format::variables_util::serialize_flat_into(result, &message);

			uint256_t entropy;
			memcpy(&entropy, crypto::random_bytes(sizeof(entropy))->data(), sizeof(entropy));

			auto encrypted_message = algorithm::signing::public_encrypt(to_public_key, message.data, entropy);
			if (!encrypted_message)
				return remote_exception("private result encryption failed");

			algorithm::hashsig_t signature;
			if (!algorithm::signing::sign(algorithm::hashing::hash256i(*encrypted_message), from_secret_key, signature))
				return remote_exception("private result signing failed");

			return format::variables({ format::variable(*encrypted_message), format::variable(signature.view()) });
		}
		static expects_rt<format::variables> unpack_private_result(const format::variables& packed_result, const algorithm::seckey_t& to_secret_key, algorithm::pubkeyhash_t& from_public_key_hash)
		{
			if (packed_result.size() != 2)
				return remote_exception("private result decryption failed");

			auto encrypted_message = packed_result.front().as_string();
			auto signature = algorithm::hashsig_t(packed_result.back().as_string());
			if (!algorithm::signing::recover_hash(algorithm::hashing::hash256i(encrypted_message), from_public_key_hash, signature))
				return remote_exception("private result verification failed");

			auto decrypted_message = algorithm::signing::private_decrypt(to_secret_key, encrypted_message);
			if (!decrypted_message)
				return remote_exception("private result decryption failed");

			format::variables result;
			format::ro_stream message = format::ro_stream(*decrypted_message);
			if (!format::variables_util::deserialize_flat_from(message, &result))
				return remote_exception("private result decryption failed");

			return expects_rt<format::variables>(std::move(result));
		}
		static expects_rt<format::variables> unpack_private_result(const format::variables& packed_result, relay_descriptor* descriptor, algorithm::pubkeyhash_t& from_public_key_hash)
		{
			if (!descriptor)
				return remote_exception("invalid descriptor secret key");

			return unpack_private_result(packed_result, descriptor->second.secret_key, from_public_key_hash);
		}
		static promise<bool> aggregative_sleep(uint64_t& attempt)
		{
			if (++attempt > kernel::params().user.consensus.aggregation_attempts)
				return promise<bool>(false);

			promise<bool> sleep;
			schedule::get()->set_timeout(attempt * kernel::params().user.consensus.aggregation_cooldown, [sleep]() mutable { sleep.set(true); });
			return sleep;
		}

		bool exchange::store_payload(format::wo_stream* stream) const
		{
			VI_ASSERT(stream != nullptr, "result should be set");
			stream->write_integer(time);
			stream->write_integer(session);
			stream->write_integer(descriptor);
			stream->write_integer((uint8_t)type);
			return format::variables_util::serialize_merge_into(args, stream);
		}
		bool exchange::load_payload(format::ro_stream& stream)
		{
			if (!stream.read_integer(stream.read_type(), &time))
				return false;

			if (!stream.read_integer(stream.read_type(), &session))
				return false;

			if (!stream.read_integer(stream.read_type(), &descriptor))
				return false;

			uint8_t raw_type = 0;
			if (!stream.read_integer(stream.read_type(), &raw_type) || raw_type > (uint8_t)side::forward)
				return false;

			type = (side)raw_type;
			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		uint64_t exchange::calculate_latency()
		{
			auto time_now = kernel::params().time.now_cpu();
			return time > 0 && time_now > time ? time_now - time : 0;
		}
		uint32_t exchange::as_type() const
		{
			return as_instance_type();
		}
		uint256_t exchange::as_inventory_hash(bool renew) const
		{
			if (renew || !inventory_checksum)
			{
				format::wo_stream stream;
				stream.write_integer(descriptor);
				format::variables_util::serialize_merge_into(args, &stream);
				((exchange*)this)->inventory_checksum = stream.hash();
			}
			return inventory_checksum;
		}
		std::string_view exchange::as_typename() const
		{
			return as_instance_typename();
		}
		format::tree exchange::as_tree() const
		{
			format::tree data;
			data.set("descriptor", format::variable(descriptor));
			data.set("session", session > 0 ? format::variable(session) : format::variable());
			data.set("time", format::variable(time));
			data.set("type", format::variable(type == side::query ? "query" : (type == side::forward ? "forwarded_query" : "event")));
			data.set("args", format::variables_util::serialize(args));
			return data;
		}
		uint32_t exchange::as_instance_type()
		{
			static uint32_t hash = algorithm::encoding::type_of(as_instance_typename());
			return hash;
		}
		std::string_view exchange::as_instance_typename()
		{
			return "exchange";
		}

		forwarder::forwarder() : capacity((size_t)kernel::params().user.consensus.inventory_size)
		{		
			if (capacity > 0)
			{
				entries.resize(capacity + capacity / 4);
				queue.resize(capacity);
			}
		}
		bool forwarder::insert(const uint256_t& message_hash, slot_t peer)
		{
			if (peer == NULL_SLOT || !capacity)
				return true;

			auto& config = kernel::params();
			auto time = config.time.now_cpu();
			umutex<std::mutex> unique(guard);
			if (count >= capacity)
			{
				size_t limit = capacity;
				while (limit-- > 0 && queue_head != queue_tail)
				{
					auto& victim = entries[queue[queue_head]];
					queue_head = (queue_head + 1) % (uint32_t)capacity;
					if (victim.expiry != 0)
					{
						victim.expiry = 0;
						--count;
						break;
					}
				}
			}

			for (size_t probe = (uint64_t)message_hash % entries.size();; probe = (probe + 1) % entries.size())
			{
				auto& target = entries[probe];
				if (target.expiry <= time)
				{
					if (target.expiry == 0)
					{
						++count;
						queue[queue_tail] = (uint32_t)probe;
						queue_tail = (queue_tail + 1) % (uint32_t)capacity;
					}

					target.hash = message_hash;
					target.expiry = time + config.user.consensus.inventory_timeout;
					target.peers.clear();
					mask_set(target.peers, peer);
					return true;
				}
				else if (target.hash == message_hash)
				{
					target.expiry = time + config.user.consensus.inventory_timeout;
					mask_set(target.peers, peer);
					break;
				}
			}
			return false;
		}
		bool forwarder::mark(const uint256_t& message_hash, slot_t peer)
		{
			if (peer == NULL_SLOT || !capacity)
				return true;

			auto& config = kernel::params();
			auto time = config.time.now_cpu();
			umutex<std::mutex> unique(guard);
			if (count >= capacity)
			{
				size_t limit = capacity;
				while (limit-- > 0 && queue_head != queue_tail)
				{
					auto& victim = entries[queue[queue_head]];
					queue_head = (queue_head + 1) % (uint32_t)capacity;
					if (victim.expiry != 0)
					{
						victim.expiry = 0;
						--count;
						break;
					}
				}
			}

			for (size_t probe = (uint64_t)message_hash % entries.size();; probe = (probe + 1) % entries.size())
			{
				auto& target = entries[probe];
				if (target.expiry <= time)
				{
					if (target.expiry == 0)
					{
						++count;
						queue[queue_tail] = (uint32_t)probe;
						queue_tail = (queue_tail + 1) % (uint32_t)capacity;
					}

					target.hash = message_hash;
					target.expiry = time + config.user.consensus.inventory_timeout;
					target.peers.clear();
					mask_set(target.peers, peer);
					return true;
				}
				else if (target.hash == message_hash)
				{
					if (mask_test(target.peers, peer))
						break;

					mask_set(target.peers, peer);
					target.expiry = time + config.user.consensus.inventory_timeout;
					return true;
				}
			}
			return false;
		}
		void forwarder::forget(slot_t peer)
		{
			if (peer == NULL_SLOT)
				return;

			umutex<std::mutex> unique(guard);
			for (auto& target : entries)
			{
				if (target.expiry != 0)
					mask_clear(target.peers, peer);
			}
		}

		pacemaker::pacemaker(size_t bits_per_window, uint64_t window_ms) : max_bytes_per_window(bits_per_window / 8), window_size(window_ms), bytes_used_in_window(0), window_start_time(0)
		{
			if (!max_bytes_per_window)
				max_bytes_per_window = std::numeric_limits<size_t>::max();
		}
		bool pacemaker::check(size_t& bytes_available, uint64_t& timeout_ms)
		{
			auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			if (current_time - window_start_time >= window_size)
			{
				bytes_used_in_window = 0;
				window_start_time = current_time;
			}

			size_t remaining_bytes = max_bytes_per_window > bytes_used_in_window ? max_bytes_per_window - bytes_used_in_window : 0;
			uint64_t window_delta = current_time - window_start_time;
			bool should_wait = !remaining_bytes;
			timeout_ms = should_wait ? (window_delta < window_size ? window_size - window_delta : 0) : 0;
			bytes_available = remaining_bytes;
			return bytes_available > 0 && timeout_ms == 0;
		}
		void pacemaker::spend(size_t bytes)
		{
			auto current_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			if (current_time - window_start_time >= window_size)
			{
				bytes_used_in_window = 0;
				window_start_time = current_time;
			}
			bytes_used_in_window += bytes;
		}

		relay::relay(node_type new_type, void* new_instance, forwarder* new_inventory, slot_t new_slot) : aborted(false), inventory(new_inventory), inventory_slot(new_slot), type(new_type), instance(new_instance), counter(0), bandwidth(1000 * 1000 * kernel::params().user.tcp.mbps_per_socket), handshake_time(kernel::params().time.now()), deferred_pull(INVALID_TASK_ID)
		{
			VI_ASSERT(instance != nullptr, "instance should be set");
			switch (type)
			{
				case node_type::inbound:
					as_inbound_node()->add_ref();
					break;
				case node_type::outbound:
					as_outbound_node()->add_ref();
					break;
				default:
					VI_ASSERT(false, "invalid node state");
					break;
			}
		}
		relay::~relay()
		{
			close_channel("deferred shutdown", nullptr);
		}
		expects_promise_rt<exchange> relay::push_query(const callable::descriptor& subject, format::variables&& args, uint64_t timeout_ms, bool forwarded)
		{
			if (queued_overflow())
				return expects_promise_rt<exchange>(remote_exception::retry_later());

			exchange message;
			message.descriptor = subject.id;
			message.type = forwarded ? exchange::side::forward : exchange::side::query;
			message.args = std::move(args);

			umutex<std::recursive_mutex> unique(mutex);
			do { message.session = ++counter; } while (!message.session || queries.find(message.session) != queries.end());

			auto session = message.session;
			auto* queue = schedule::get();
			auto& query = queries[session];
			auto& result = query.result;
			if (timeout_ms > 0)
			{
				query.timeout = queue->set_timeout(timeout_ms, [this, session, result]() mutable
				{
					umutex<std::recursive_mutex> unique(mutex);
					queries.erase(session);
					if (result.is_pending())
						result.set(remote_exception::retry_later());
				});
			}
			push_outgoing(std::move(message));
			return result;
		}
		bool relay::push_event(const callable::descriptor& subject, format::variables&& args)
		{
			if (queued_overflow())
				return false;

			exchange message;
			message.descriptor = subject.id;
			message.type = exchange::side::event;
			message.args = std::move(args);
			if (inventory != nullptr && !inventory->mark(message.as_inventory_hash(), inventory_slot))
				return false;

			push_outgoing(std::move(message));
			return true;
		}
		void relay::push_query_response(uint32_t session, format::variables&& args)
		{
			exchange message;
			message.descriptor = 0;
			message.type = exchange::side::event;
			message.session = session;
			message.args = std::move(args);
			push_outgoing(std::move(message));
		}
		void relay::push_incoming(const uint8_t* buffer, size_t size)
		{
			if (!buffer || !size)
				return;

			umutex<std::recursive_mutex> unique(mutex);
			size_t offset = incoming_data.size();
			incoming_data.resize(std::min(offset + size, sizeof(message_header) + kernel::params().message.max_body_size));
			memcpy(incoming_data.data() + offset, buffer, std::min(incoming_data.size() - offset, size));
		}
		void relay::push_outgoing(exchange&& message)
		{
			if (kernel::params().user.consensus.logging)
				VI_DEBUG("node %s message out: %s", peer_address().c_str(), message.as_tree().as_json().substr(0, 2048).c_str());

			umutex<std::recursive_mutex> unique(mutex);
			if (outgoing_count >= OUTGOING_QUEUE_SIZE)
			{
				aborted = true;
				return;
			}

			++outgoing_count;
			outgoing_messages.push(std::move(message));
		}
		bool relay::queued_overflow()
		{
			umutex<std::recursive_mutex> unique(mutex);
			return outgoing_count >= OUTGOING_QUEUE_SIZE;
		}
		void relay::erase_incoming(size_t starting_bytes_to_erase)
		{
			umutex<std::recursive_mutex> unique(mutex);
			incoming_data.erase(0, std::min(incoming_data.size(), starting_bytes_to_erase));
		}
		bool relay::prepare_outgoing()
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!outgoing_data.empty() || outgoing_messages.empty())
				return false;

			size_t max_size = kernel::params().message.max_body_size;
			while (!outgoing_messages.empty())
			{
				auto& message = outgoing_messages.front();
				auto body = format::wo_stream();
				message.store_payload(&body);
				outgoing_messages.pop();
				--outgoing_count;

				size_t size = std::min(body.data.size(), max_size);
				message_header header;
				header.magic = os::hw::to_endianness(os::hw::endian::little, (uint32_t)kernel::params().message.packet_magic);
				header.length = os::hw::to_endianness(os::hw::endian::little, (uint32_t)size);
				header.checksum = os::hw::to_endianness(os::hw::endian::little, algorithm::hashing::hash32d(std::string_view(body.data).substr(0, max_size)));

				size_t offset = outgoing_data.size();
				outgoing_data.resize(offset + sizeof(header) + size);
				memcpy(outgoing_data.data() + offset, &header, sizeof(header));
				memcpy(outgoing_data.data() + offset + sizeof(header), body.data.data(), size);
			}
			return true;
		}
		void relay::clear_outgoing()
		{
			umutex<std::recursive_mutex> unique(mutex);
			outgoing_data.clear();
		}
		void relay::report_call(int8_t call_result, uint64_t call_latency, bool cooldown)
		{
			if (descriptor)
			{
				auto mempool = storages::mempoolstate();
				mempool.apply_node_quality(descriptor->first.address, call_result, call_latency);
				if (cooldown)
					mempool.apply_cooldown_node(descriptor->first.address, true, true);
			}
		}
		void relay::resolve_query(exchange&& packed_result)
		{
			auto unpacked_result = unpack_query_result(packed_result.args);
			report_call(unpacked_result ? 1 : (unpacked_result.error().is_retry() ? 0 : -1), packed_result.calculate_latency());

			umutex<std::recursive_mutex> unique(mutex);
			auto it = queries.find(packed_result.session);
			if (it != queries.end())
			{
				schedule::get()->clear_timeout(it->second.timeout);
				if (it->second.result.is_pending())
				{
					if (unpacked_result)
					{
						packed_result.args = std::move(*unpacked_result);
						it->second.result.set(std::move(packed_result));
					}
					else
						it->second.result.set(std::move(unpacked_result.error()));
				}
				queries.erase(it);
			}
		}
		void relay::cancel_queries()
		{
			auto* queue = schedule::get();
			umutex<std::recursive_mutex> unique(mutex);
			for (auto& query : queries)
			{
				queue->clear_timeout(query.second.timeout);
				if (query.second.result.is_pending())
					query.second.result.set(remote_exception::shutdown());
			}
			queries.clear();
		}
		void relay::open_channel(relay_descriptor&& new_descriptor)
		{
			descriptor = memory::init<relay_descriptor>(std::move(new_descriptor));
			if (kernel::params().user.consensus.logging)
				VI_INFO("node %s channel open %s (port: %s, version: v%i.%i, account: %s)", peer_address().c_str(), connection_type().data(), peer_service().c_str(), descriptor->first.fork_version, descriptor->first.patch_version, descriptor->second.get_address().c_str());

			auto* socket = as_socket();
			if (socket != nullptr)
			{
				socket->set_io_timeout(0);
				socket->set_keep_alive(true);
				socket->set_keep_alive_params((int)kernel::params().user.tcp.keep_alive, (int)kernel::params().user.tcp.keep_alive, 5);
			}
		}
		void relay::close_channel(const std::string_view& message, server_node* server)
		{
			auto* socket = as_socket();
			if (!aborted && kernel::params().user.consensus.logging)
			{
				std::string_view shutdown_message = message.empty() ? std::string_view("abnormal shutdown") : message;
				VI_INFO("node %s channel close (%.*s)", peer_address().c_str(), (int)shutdown_message.size(), shutdown_message.data());
			}

			if (descriptor && instance != nullptr && server != nullptr && server->is_active())
				report_call(0, 0, true);

			aborted = true;
			cancel_queries();
			if (deferred_pull != INVALID_TASK_ID)
			{
				schedule::get()->clear_timeout(deferred_pull);
				deferred_pull = INVALID_TASK_ID;
			}
			if (socket != nullptr)
				socket->shutdown(true);

			umutex<std::recursive_mutex> unique(mutex);
			auto* inbound = type == node_type::inbound ? (inbound_node*)instance : nullptr;
			auto* outbound = type == node_type::outbound ? (outbound_node*)instance : nullptr;
			memory::release(inbound);
			memory::release(outbound);
			instance = nullptr;
		}
		bool relay::private_network() const
		{
			return descriptor ? storages::routing_util::is_address_reserved_or_private(descriptor->first.address) : false;
		}
		bool relay::partially_valid() const
		{
			if (aborted)
				return false;

			switch (type)
			{
				case node_type::inbound:
				{
					auto* node = (inbound_node*)instance;
					return node && node->stream ? node->stream->is_valid() : false;
				}
				case node_type::outbound:
				{
					auto* node = (outbound_node*)instance;
					return node && node->get_stream() ? node->get_stream()->is_valid() : false;
				}
				default:
					return false;
			}
		}
		bool relay::fully_valid() const
		{
			return descriptor && partially_valid();
		}
		const string& relay::peer_address()
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!address.empty())
				return address;

			auto* stream = as_socket();
			if (!stream)
			{
			no_address:
				address = "[bad_address]";
				return address;
			}

			auto target = stream->get_peer_address();
			if (!target)
				goto no_address;

			auto result = target->get_ip_address();
			if (!result)
				goto no_address;

			address = std::move(*result);
			return address;
		}
		const string& relay::peer_service()
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!service.empty())
				return service;

			auto* stream = as_socket();
			if (!stream)
			{
			no_service:
				service = to_string(kernel::params().user.consensus.port);
				return service;
			}

			auto target = stream->get_peer_address();
			if (!target)
				goto no_service;

			auto result = target->get_ip_port();
			if (!result)
				goto no_service;

			service = to_string(*result);
			return service;
		}
		const uint8_t* relay::incoming_buffer()
		{
			return (const uint8_t*)incoming_data.data();
		}
		const uint8_t* relay::outgoing_buffer()
		{
			return (const uint8_t*)outgoing_data.data();
		}
		slot_t relay::inventory_slot_id() const
		{
			return inventory_slot;
		}
		size_t relay::incoming_size()
		{
			return incoming_data.size();
		}
		size_t relay::outgoing_size()
		{
			return outgoing_data.size();
		}
		node_type relay::type_of()
		{
			return type;
		}
		inbound_node* relay::as_inbound_node()
		{
			if (aborted)
				return nullptr;

			return type == node_type::inbound ? (inbound_node*)instance : nullptr;
		}
		outbound_node* relay::as_outbound_node()
		{
			if (aborted)
				return nullptr;

			return type == node_type::outbound ? (outbound_node*)instance : nullptr;
		}
		vitex::network::socket* relay::as_socket()
		{
			if (aborted)
				return nullptr;

			switch (type)
			{
				case node_type::inbound:
				{
					auto* node = as_inbound_node();
					return node ? node->stream : nullptr;
				}
				case node_type::outbound:
				{
					auto* node = as_outbound_node();
					return node ? node->get_stream() : nullptr;
				}
				default:
					return nullptr;
			}
		}
		void* relay::as_instance()
		{
			return instance;
		}
		format::tree relay::as_tree() const
		{
			format::tree data;
			switch (type)
			{
				case node_type::inbound:
					data.set("type", format::variable("inbound"));
					break;
				case node_type::outbound:
					data.set("type", format::variable("outbound"));
					break;
				default:
					data.set("type", format::variable("unknown"));
					break;
			}
			data.set("incoming_bytes", algorithm::encoding::serialize_uint256(incoming_data.size()));
			data.set("outgoing_bytes", algorithm::encoding::serialize_uint256(outgoing_data.size()));
			return data;
		}
		relay_descriptor* relay::as_descriptor() const
		{
			return *descriptor;
		}
		std::string_view relay::connection_type() const
		{
			switch (type)
			{
				case node_type::inbound:
					return "inbound";
				case node_type::outbound:
					return "outbound";
				default:
					return "unknown";
			}
		}

		outbound_node::outbound_node() noexcept : socket_client(kernel::params().user.tcp.timeout)
		{
		}
		void outbound_node::configure_stream()
		{
			socket_client::configure_stream();
			if (kernel::params().is(network_type::regtest))
				net.stream->bind(socket_address(kernel::params().user.consensus.address, 0));
		}

		callable::descriptor descriptors::broadcast_block_hash()
		{
			return callable::descriptor(__func__, 1);
		}
		callable::descriptor descriptors::broadcast_transaction_hash()
		{
			return callable::descriptor(__func__, 2);
		}
		callable::descriptor descriptors::broadcast_attestation()
		{
			return callable::descriptor(__func__, 3);
		}
		callable::descriptor descriptors::broadcast_delegation()
		{
			return callable::descriptor(__func__, 4);
		}
		callable::descriptor descriptors::perform_delegation()
		{
			return callable::descriptor(__func__, 5);
		}
		callable::descriptor descriptors::perform_handshake()
		{
			return callable::descriptor(__func__, 6);
		}
		callable::descriptor descriptors::perform_discovery()
		{
			return callable::descriptor(__func__, 7);
		}
		callable::descriptor descriptors::fetch_headers()
		{
			return callable::descriptor(__func__, 8);
		}
		callable::descriptor descriptors::fetch_block()
		{
			return callable::descriptor(__func__, 9);
		}
		callable::descriptor descriptors::fetch_blocks()
		{
			return callable::descriptor(__func__, 10);
		}
		callable::descriptor descriptors::fetch_mempool()
		{
			return callable::descriptor(__func__, 11);
		}
		callable::descriptor descriptors::fetch_transaction()
		{
			return callable::descriptor(__func__, 12);
		}
		callable::descriptor descriptors::fetch_transactions()
		{
			return callable::descriptor(__func__, 13);
		}
		callable::descriptor descriptors::delegate_execution()
		{
			return callable::descriptor(__func__, 14);
		}
		callable::descriptor descriptors::broadcast_preattestation()
		{
			return callable::descriptor(__func__, 15);
		}
		callable::descriptor descriptors::fetch_preattestation_body()
		{
			return callable::descriptor(__func__, 16);
		}
		callable::descriptor descriptors::broadcast_quote_ask()
		{
			return callable::descriptor(__func__, 17);
		}
		callable::descriptor descriptors::broadcast_quote()
		{
			return callable::descriptor(__func__, 18);
		}

		server_node::server_node() noexcept : socket_server(), control_sys("consensus-node"), runner_descriptor(nullptr)
		{
			VI_PANIC(kernel::params().user.consensus.max_inbound_connections + kernel::params().user.consensus.max_outbound_connections < NULL_SLOT, "reserving too many connections");
			verifier.regress_callback = [this](const ledger::block_body& block, uint64_t tip_number)
			{
				if (kernel::params().user.consensus.logging)
				{
					int64_t precision = 5000;
					int64_t progress = (int64_t)((double)precision * (double)block.number / (double)tip_number);
					verifier.size += (uint64_t)((double)(uint64_t)block.gas_limit / (double)ledger::gas_cost::write_byte);
					if (progress >= precision || verifier.progress < progress)
					{
						uint64_t time = kernel::params().time.now_cpu();
						double bps = verifier.progress_time > 0 ? 1000.0 * (double)(block.number - verifier.progress_block_number) / (double)std::max<uint64_t>(1, time - verifier.progress_time) : 0.0;
						VI_INFO("block %s (number: %" PRIu64 ", regress: %.2f%%, size: %.2f kb, bps: %.1f)", uint256_to_label(block.as_hash()).c_str(), block.number, (double)progress / ((double)precision / 100), (double)verifier.size.load() / 1000.0, bps);
						verifier.progress_bps = verifier.progress_bps > 1.0 ? verifier.progress_bps * 0.75 + bps * 0.25 : bps;
						verifier.progress_block_number = block.number;
						verifier.progress_time = time;
						verifier.progress = progress;
						verifier.size = 0;
					}
				}
				return is_active();
			};
		}
		server_node::~server_node() noexcept
		{
			if (superchain::bridge::has_instance())
			{
				auto* offchain = superchain::bridge::get();
				offchain->network_active = nullptr;
				offchain->network_fetch = nullptr;
			}
			clear_tip(nullptr, nullptr);
		}
		expects_promise_system<http::response_frame> server_node::queued_fetch_external(const algorithm::asset_id& asset, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options)
		{
			if (!is_active())
				return expects_promise_system<http::response_frame>(system_exception("cancelled due to shutdown", std::make_error_condition(std::errc::owner_dead)));

			umutex<std::recursive_mutex> unique(sync.fetcher);
			auto& fetcher = fetchers[asset];
			++fetcher.requests;
			if (fetcher.busy)
			{
				auto& target = fetcher.queue.emplace();
				target.location = location;
				target.method = method;
				target.options = options;
				return target.result;
			}

			fetcher.busy = true;
			unique.unlock();
			return queued_fetch_internal(asset, location, method, options);
		}
		expects_promise_system<http::response_frame> server_node::queued_fetch_internal(const algorithm::asset_id& asset, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options)
		{
			if (is_active())
			{
				return http::fetch(location, method, options).then<expects_system<http::response_frame>>([this, asset](expects_system<http::response_frame>&& response) -> expects_system<http::response_frame>&&
				{
					umutex<std::recursive_mutex> unique(sync.fetcher);
					auto& fetcher = fetchers[asset];
					fetcher.busy = !fetcher.queue.empty();
					if (!fetcher.busy)
						return std::move(response);

					auto target = std::move(fetcher.queue.front());
					fetcher.queue.pop();
					unique.unlock();
					cospawn([this, asset, target = std::move(target)]() mutable
					{
						auto result = std::move(target.result);
						queued_fetch_internal(asset, target.location, target.method, target.options).when([result](expects_system<http::response_frame>&& response) mutable { result.set(std::move(response)); });
					});
					return std::move(response);
				});
			}
			else
			{
				single_queue<fetch_target> cancellations;
				umutex<std::recursive_mutex> unique(sync.fetcher);
				auto& fetcher = fetchers[asset];
				cancellations.swap(fetcher.queue);
				unique.unlock();

				auto exception = system_exception("cancelled due to shutdown", std::make_error_condition(std::errc::owner_dead));
				while (!cancellations.empty())
				{
					auto& target = cancellations.front();
					target.result.set(exception);
					cancellations.pop();
				}
				return expects_promise_system<http::response_frame>(exception);
			}
		}
		expects_system<void> server_node::on_unlisten()
		{
			control_sys.deactivate(false);
			clear_tip(nullptr, nullptr);
			{
				single_queue<fetch_target> cancellations;
				umutex<std::recursive_mutex> unique(sync.fetcher);
				for (auto& [asset, fetcher] : fetchers)
				{
					while (!fetcher.queue.empty())
					{
						cancellations.emplace(std::move(fetcher.queue.front()));
						fetcher.queue.pop();
					}
				}

				fetchers.clear();
				unique.unlock();
				auto exception = system_exception("cancelled due to shutdown", std::make_error_condition(std::errc::owner_dead));
				while (!cancellations.empty())
				{
					auto& target = cancellations.front();
					target.result.set(exception);
					cancellations.pop();
				}
			}

			umutex<std::recursive_mutex> unique(exclusive);
		retry:
			{
				vector<uptr<vitex::network::socket>> current_sockets;
				current_sockets.reserve(pending_nodes.size());
				for (auto& node : pending_nodes)
				{
					auto* stream = node->get_stream();
					if (stream != nullptr)
					{
						current_sockets.push_back(stream);
						stream->add_ref();
					}
				}
				unique.unlock();
				for (auto& socket : current_sockets)
					socket->clear_events(true);
			}
			unique.lock();
			if (!pending_nodes.empty())
				goto retry;

			for (auto& node : nodes)
				node.second->cancel_queries();

			unique.unlock();
			control_sys.deactivate();
			return expectation::met;
		}
		expects_system<void> server_node::on_after_unlisten()
		{
			umutex<std::recursive_mutex> unique(exclusive);
		retry:
			{
				hash_map<void*, uref<relay>> current_nodes;
				current_nodes.swap(nodes);
				unique.unlock();
				for (auto& node : current_nodes)
					node.second->close_channel("server shutdown", this);
			}
			unique.lock();
			if (!nodes.empty())
				goto retry;

			return expectation::met;
		}
		expects_lr<void> server_node::accept_node(storages::mempoolstate& mempool, relay_descriptor& descriptor, node_category category)
		{
			auto& [node, wallet] = descriptor;
			auto ip_address = node.address.get_ip_address();
			auto ip_port = node.address.get_ip_port();
			if (!node.address.is_valid() || !ip_address || !ip_port)
				return layer_exception("bad node address");
			else if (*ip_address == "0.0.0.0")
				node.address = socket_address("127.0.0.1", *ip_port);

			switch (category)
			{
				case node_category::runner:
					return mempool.apply_node(descriptor, storages::node_peer::runner);
				case node_category::neighbor:
					return mempool.apply_node(descriptor, storages::node_peer::neighbor);
				case node_category::inbound:
				case node_category::outbound:
				{
					if (find_descriptor(wallet.public_key_hash))
						return layer_exception("must not modify internal node");

					auto prev = mempool.get_node(node.address);
					if (prev && find_descriptor(prev->second.public_key_hash))
						return layer_exception("must not modify internal node");

					return mempool.apply_node(descriptor, category == node_category::inbound ? storages::node_peer::inbound : storages::node_peer::outbound);
				}
				default:
					return layer_exception("invalid node category");
			}
		}
		expects_lr<void> server_node::accept_local_accounts(const vector<ledger::wallet>& accounts)
		{
			umutex<std::recursive_mutex> unique(sync.account);
			auto mempool = storages::mempoolstate();
			auto nodes = mempool.get_local_nodes().or_else(vector<relay_descriptor>());
			auto runner_account = accounts.empty() ? (nodes.empty() ? algorithm::pubkeyhash_t() : nodes.front().second.public_key_hash) : accounts.front().public_key_hash;
			for (auto& node : nodes)
				descriptors[node.second.public_key_hash] = std::move(node);

			for (auto& wallet : accounts)
			{
				auto it = descriptors.find(wallet.public_key_hash);
				if (it != descriptors.end())
					continue;

				ledger::node node;
				node.address = socket_address(kernel::params().user.consensus.address, kernel::params().user.consensus.port);
				descriptors[wallet.public_key_hash] = std::make_pair(std::move(node), wallet);
			}

			if (descriptors.empty())
			{
				ledger::node node; ledger::wallet wallet = ledger::wallet::from_seed(*crypto::random_bytes(512));
				node.address = socket_address(kernel::params().user.consensus.address, kernel::params().user.consensus.port);
				runner_account = wallet.public_key_hash;
				descriptors[runner_account] = std::make_pair(std::move(node), std::move(wallet));
			}

			for (auto& [account, descriptor] : descriptors)
			{
				auto& [node, wallet] = descriptor;
				fill_node_services(descriptor);
				node.patch_version = PATCH_VERSION;
				node.fork_version = FORK_VERSION;
				node.ports.consensus = kernel::params().user.consensus.port;
				node.ports.discovery = kernel::params().user.discovery.port;
				node.ports.rpc = kernel::params().user.rpc.port;
				node.services.has_consensus = kernel::params().user.consensus.server;
				node.services.has_discovery = kernel::params().user.discovery.server;
				node.services.has_superchain = kernel::params().user.superchain.listener;
				node.services.has_rpc = kernel::params().user.rpc.server && kernel::params().user.rpc.username.empty();
				VI_PANIC(wallet.has_secret_key(), "server descriptor %s wallet must have a secret key", wallet.get_address().c_str());

				bool runner = account == runner_account;
				auto result = accept_node(mempool, descriptor, runner ? node_category::runner : node_category::neighbor);
				if (result)
					VI_INFO("%s account %s accepted", runner ? "runner" : "neighbor", wallet.get_address().c_str());
			}

			auto it = descriptors.find(runner_account);
			if (it == descriptors.end())
				return layer_exception("failed to bind runner account");

			auto chain = storages::chainstate();
			auto tip = chain.get_latest_block_header();
			VI_INFO("tip block %s confirmed (number: %" PRIu64 ", work: 0x%s)", uint256_to_label(tip ? tip->as_hash() : uint256_t(0)).c_str(), tip ? tip->number : (uint64_t)0, tip ? tip->absolute_work.to_string(16).c_str() : "0");
			runner_descriptor = &it->second;
			return expectation::met;
		}
		expects_lr<void> server_node::accept_local_transaction(const ledger::wallet* signer_wallet, uptr<ledger::transaction_message>&& candidate_tx, uint256_t* output_hash)
		{
			VI_ASSERT(signer_wallet != nullptr, "signer wallet should be set");
			umutex<std::recursive_mutex> unique(sync.account);
			auto nonce = signer_wallet->get_latest_nonce().or_else(0);
			auto& watermark = nonces[signer_wallet->public_key_hash];
			nonce = nonce <= watermark ? watermark + 1 : nonce;

			auto status = candidate_tx->sign(signer_wallet->secret_key, nonce, decimal::zero());
			if (status)
			{
				status = accept_transaction(nullptr, std::move(candidate_tx), &signer_wallet->public_key_hash, output_hash);
				watermark = status ? nonce : watermark;
			}
			else if (kernel::params().user.consensus.logging)
			{
				auto purpose = candidate_tx->as_typename();
				VI_ERR("transaction %s %.*s error: %s", uint256_to_label(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data(), status.what().c_str());
			}
			return status;
		}
		expects_lr<void> server_node::accept_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx, const algorithm::pubkeyhash_t* local_signer, uint256_t* output_hash)
		{
			algorithm::pubkeyhash_t owner = local_signer ? *local_signer : algorithm::pubkeyhash_t();
			auto purpose = candidate_tx->as_typename();
			auto candidate_message = candidate_tx->as_message();
			auto candidate_hash = candidate_message.hash();
			candidate_tx->checksum = candidate_hash;
			if (!local_signer && !candidate_tx->recover_hash(owner))
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation rejection: invalid signature", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("signature key recovery failed");
			}
			else if (output_hash != nullptr)
				*output_hash = candidate_hash;

			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			if (!local_signer && (mempool.has_transaction(candidate_hash).or_else(false) || chain.has_block_transaction(candidate_hash).or_else(false)))
				return expectation::met;

			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(owner), 0);
			auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
			auto nonce = value ? value->nonce : 0;
			if (candidate_tx->nonce < nonce)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation rejection: invalid nonce (expired)", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("nonce is too old");
			}

			bool high_priority = candidate_tx->as_commitment(nullptr) > 0;
			if (!high_priority && !candidate_tx->gas_price.is_positive())
			{
				if (candidate_message.data.size() > kernel::params().policy.zero_gas_price_size_limit)
				{
					if (kernel::params().user.consensus.logging)
						VI_WARN("transaction %s %.*s validation rejection: must pay for gas (anti-spam, large transaction)", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
					return layer_exception("must pay for gas (anti-spam, large transaction)");
				}

				auto tip = chain.get_latest_block_header();
				if (tip && tip->network_congestion())
				{
					if (kernel::params().user.consensus.logging)
						VI_WARN("transaction %s %.*s validation rejection: must pay for gas (anti-spam, network congestion)", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
					return layer_exception("must pay for gas (anti-spam, network congestion)");
				}
			}

			auto validation = local_signer ? expects_lr<void>(expectation::met) : (high_priority ? ledger::executor_context::simulate_tx(*candidate_tx) : candidate_tx->validate(chain.get_latest_block_number().or_else(1)));
			if (!validation)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation rejection: %s", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
				if (high_priority)
					mempool.add_transaction_observation(candidate_hash);
				return validation.error();
			}
			return broadcast_transaction(uref(from), std::move(candidate_tx), owner, high_priority);
		}
		expects_rt<bool> server_node::accept_attestation(const storages::attestation_tree& attestation, bool save_to_storage)
		{
			option<uint256_t> reannounce_hash = optional::none;
			transactions::attestate* attestate_tx = nullptr;
			umutex<std::recursive_mutex> unique(sync.attestation);
			auto executor = ledger::executor_context(nullptr);
			for (auto& [commitment_hash, proof] : attestation.proofs)
			{
				auto collision = executor.get_witness_transaction(attestation.asset, proof.transaction_id);
				if (collision)
					return true;
			}

			auto mempool = storages::mempoolstate();
			if (save_to_storage)
			{
				for (auto& [commitment_hash, signatures] : attestation.commitments)
				{
					auto proof = attestation.proofs.find(commitment_hash);
					if (proof == attestation.proofs.end())
						continue;

					for (auto& signature : signatures)
					{
						auto status = mempool.add_attestation(attestation.asset, proof->second, signature);
						if (!status)
							return remote_exception(std::move(status.error().message()));
					}
				}
			}

			auto batch = attestation; auto errors = vector<string>();
			transactions::attestate::optimize_proofs_and_commitments(&executor, batch.asset, batch.proofs, batch.commitments, &errors);
			if (batch.proofs.empty())
			{
				string error = errors.empty() ? string("proofs are either not valid or not provided") : string();
				for (size_t i = 0; i < errors.size(); i++)
					error.append(errors[i]).append(", ", i < errors.size() - 1 ? 2 : 0);
				return remote_exception(std::move(error));
			}

			uint256_t best_commitment_hash = 0;
			btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>> attesters;
			auto evaluation = transactions::attestate::evaluate_proof_commitments(&executor, batch.asset, batch.commitments, best_commitment_hash, attesters);
			if (!evaluation)
				return remote_exception::retry_later();

			auto proof = batch.proofs.find(best_commitment_hash);
			if (proof == batch.proofs.end())
				return remote_exception::retry_later();

			auto signatures = batch.commitments.find(best_commitment_hash);
			if (signatures == batch.commitments.end())
				return remote_exception::retry_later();

			auto existing = mempool.get_transaction_by_commitment_hash(best_commitment_hash);
			if (existing)
			{
				auto simulation = ledger::executor_context::calculate_tx_gas(**existing);
				auto existing_hash = (*existing)->as_hash();
				if (simulation)
					reannounce_hash = existing_hash;
				else
					mempool.remove_transactions_by_hash({ existing_hash }).report("failed to remove stale attestate");
			}

			if (!reannounce_hash)
			{
				auto* transaction = memory::init<transactions::attestate>();
				transaction->asset = algorithm::asset::base_id_of(batch.asset);
				transaction->set_real_proof(best_commitment_hash, std::move(proof->second), std::move(signatures->second));
				attestate_tx = transaction;
			}
			
			unique.unlock();
			if (reannounce_hash)
			{
				size_t notifications = notify_all(descriptors::broadcast_transaction_hash(), { format::variable((uint256_t)*reannounce_hash) });
				if (notifications > 0 && kernel::params().user.consensus.logging)
					VI_DEBUG("transaction %s re-announced to %i nodes (attestate for commitment %s)", uint256_to_label(*reannounce_hash).c_str(), (int)notifications, uint256_to_label(best_commitment_hash).c_str());
				return false;
			}

			if (attestate_tx)
			{
				auto status = accept_local_transaction(&runner_descriptor->second, attestate_tx);
				if (!status)
					return status.error().message().find("attestate later") != std::string::npos ? remote_exception::retry_later() : remote_exception(status.what());
			}

			return false;
		}
		expects_lr<void> server_node::accept_block(uref<relay>&& from, ledger::block_evaluation& candidate, const ledger::block_header* fork_tip, bool verify_pow)
		{
			uint256_t candidate_hash = candidate.block.as_hash();
			auto chain = storages::chainstate();
			if (!fork_tip && chain.get_block_header_by_hash(candidate_hash))
				return expectation::met;

			option<ledger::block_header> cached_header = optional::none;
			{
				umutex<std::recursive_mutex> tip_unique(sync.tip);
				if (verifier.tip_cache && verifier.tip_cache->as_hash() == candidate_hash)
					cached_header = *verifier.tip_cache;
			}

			bool fork_branch = fork_tip != nullptr;
			auto tip_block = fork_branch ? expects_lr<ledger::block_header>(*fork_tip) : chain.get_latest_block_header();
			auto tip_hash = tip_block ? tip_block->as_hash() : (uint256_t)0;
			auto best_tip_work = tip_block ? tip_block->absolute_work : (uint256_t)0;
			auto parent_block = tip_hash == candidate.block.parent_hash ? tip_block : (cached_header ? ledger::block_header(std::move(*cached_header)) : chain.get_block_header_by_hash(candidate.block.parent_hash));
			int64_t branch_length = (int64_t)candidate.block.number - (int64_t)(tip_block ? tip_block->number : 0);
			branch_length = fork_branch ? std::abs(branch_length) : branch_length;
			if (branch_length < 0 || (!fork_branch && candidate.block.absolute_work < best_tip_work))
			{
				/*
													  <+> - <+> - <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
											   \
												<+> = ignore (smaller branch)
				*/
				return layer_exception(stringify::text("block %s rejected: inferior fork %s (length: %" PRIi64 ")", uint256_to_label(candidate_hash).c_str(), branch_length < 0 ? "branch" : "work", branch_length));
			}
			else if (branch_length == 0 && tip_block && tip_hash != candidate_hash && candidate.block < *tip_block)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				return layer_exception(stringify::text("block %s rejected: inferior fork", uint256_to_label(candidate_hash).c_str()));
			}
			else if (!parent_block && candidate.block.number > 1)
			{
				auto verification = from ? candidate.block.verify_validity(parent_block.address()) : expects_lr<void>(layer_exception("unexpected orphan"));
				if (!verification)
					return layer_exception(stringify::text("block %s rejected: %s", uint256_to_label(candidate_hash).c_str(), verification.error().what()));

				umutex<std::recursive_mutex> unique(sync.tip);
				if (tips.find(candidate_hash) != tips.end())
					return expectation::met;

				/*
															   <+> = better orphan (possibly)
															  /
					<+> - <+> - <+> - <+> - <+> - <+> ------------
														  \
														   <+> = weaker orphan
				*/
				bool better_than_prev_fork = tips.empty();
				for (auto& fork_candidate_tip : tips)
				{
					if (fork_candidate_tip.second.header < candidate.block)
					{
						better_than_prev_fork = true;
						break;
					}
				}
				if (!better_than_prev_fork)
					return layer_exception(stringify::text("block %s rejected: inferior fork orphan", uint256_to_label(candidate_hash).c_str()));

				/*
					<+> - <+> - <+> - <+> - <+> - <+> ----
														  \
														   <+> = better orphan (possibly)
				*/
				accept_tip(uref(from), candidate_hash, ledger::block_header(candidate.block));
				run_fork_resolution();
				if (kernel::params().user.consensus.logging)
				{
					auto distance = (uint64_t)std::abs((int64_t)(tip_block ? tip_block->number : 0) - (int64_t)candidate.block.number);
					VI_INFO("block %s %s ahead (number: %" PRIu64 ", eta: %s)",
						uint256_to_label(candidate_hash).c_str(), seconds_to_duration(distance * kernel::params().policy.pow.time / 1000).c_str(),
						candidate.block.number, verifier.progress_bps > 0.1 ? seconds_to_duration(std::max<uint64_t>((uint64_t)((double)distance / verifier.progress_bps), 1)).c_str() : "N/A");
				}
				return expectation::met;
			}

			/*
				<+> - <+> - <+> - <+> - <+> - <+> = possible extension
											\
											<+> - <+> = possible reorganization
			*/
			if (!try_acquire_checkpointer())
				return layer_exception(stringify::text("block %s checkpoint skipped: checkpointer busy", uint256_to_label(candidate_hash).c_str()));

			bool may_broadcast_early = from && !fork_tip;
			bool may_broadcast_lately = !from && !fork_tip;
			if (may_broadcast_early)
				append_pending_tip(uref(from), candidate_hash, &candidate.block);

			auto reorganization = ledger::solver_context::requires_reorganization(candidate, &verifier.cache);
			auto validation = fork_branch && reorganization ? expects_lr<void>(expectation::met) : ledger::solver_context::validate_solved_block(verifier.solver, parent_block.address(), candidate.block, &candidate, verify_pow, &verifier.cache);
			if (!validation)
			{
				release_checkpointer();
				return layer_exception(stringify::text("block %s rejected: %s", uint256_to_label(candidate_hash).c_str(), validation.error().what()));
			}
			else if (reorganization && !kernel::params().user.consensus.reorganizable)
			{
				release_checkpointer();
				return layer_exception(stringify::text("block %s rejected: requires deep chain reorganization (disabled)", uint256_to_label(candidate_hash).c_str()));
			}

			if (reorganization && kernel::params().user.consensus.logging)
				VI_WARN("block %s: running chain reorganization now (number: %" PRIu64 ")", uint256_to_label(candidate_hash).c_str(), candidate.block.number);

			auto mutation = ledger::solver_context::checkpoint_solved_block(verifier.solver, candidate, &verifier.cache, verifier.regress_callback);
			if (mutation)
			{
				umutex<std::recursive_mutex> tip_unique(sync.tip);
				verifier.tip_cache = ledger::block_header(candidate.block);
				verifier.tip_cache->checksum = candidate_hash;
			}

			release_checkpointer();
			if (may_broadcast_early)
				erase_pending_tip(candidate_hash);

			if (!mutation)
				return layer_exception(stringify::text("block %s checkpoint failed: %s", uint256_to_label(candidate_hash).c_str(), mutation.error().what()));

			if (kernel::params().user.consensus.logging)
			{
				int64_t precision = 5000;
				int64_t progress = (int64_t)((double)precision * get_sync_progress(candidate.block.number, *from));
				verifier.size += (uint64_t)((double)(uint64_t)candidate.block.gas_limit / (double)ledger::gas_cost::write_byte);
				if (progress >= precision || verifier.progress < progress || mutation->is_fork)
				{
					if (mutation->is_fork)
					{
						VI_INFO("block %s (number: %" PRIu64 ", sync: %.2f%%, size: %.2f kb, depth: %" PRIi64 ", txns: %" PRIi64 ", state: %" PRIi64 ")\n",
							uint256_to_label(candidate_hash).c_str(), candidate.block.number, (double)progress / ((double)precision / 100), (double)verifier.size.load() / 1000.0,
							mutation->block_delta, mutation->transaction_delta, mutation->state_delta);
					}
					else if (progress < precision)
					{
						uint64_t time = kernel::params().time.now_cpu();
						double bps = verifier.progress_time > 0 ? 1000.0 * (double)(candidate.block.number - verifier.progress_block_number) / (double)std::max<uint64_t>(1, time - verifier.progress_time) : 0.0;
						VI_INFO("block %s (number: %" PRIu64 ", sync: %.2f%%, size: %.2f kb, bps: %.1f)",
							uint256_to_label(candidate_hash).c_str(), candidate.block.number, (double)progress / ((double)precision / 100), (double)verifier.size.load() / 1000.0, bps);
						verifier.progress_bps = verifier.progress_bps > 1.0 ? verifier.progress_bps * 0.75 + bps * 0.25 : bps;
						verifier.progress_block_number = candidate.block.number;
						verifier.progress_time = time;
					}
					else
					{
						VI_INFO("block %s (number: %" PRIu64 ", sync: %.2f%%, size: %.2f kb)",
							uint256_to_label(candidate_hash).c_str(), candidate.block.number, (double)progress / ((double)precision / 100), (double)verifier.size.load() / 1000.0);
					}
					verifier.progress = progress;
					verifier.size = 0;
				}
			}

			if (events.accept_block)
				events.accept_block(candidate_hash, candidate.block, *mutation);

			for (auto& transaction : candidate.block.transactions)
			{
				if (transaction.receipt.successful && transaction.transaction->as_type() == transactions::attestate::as_instance_type())
					storages::mempoolstate().remove_attestation(((transactions::attestate*)*transaction.transaction)->proof.as_attestation_hash());
				if (find_descriptor(transaction.receipt.from))
					accept_proposal_transaction(transaction);
			}

			if (!candidate.block.witnesses.empty())
			{
				umutex<std::recursive_mutex> unique(sync.tip);
				for (auto& [asset, block_height] : candidate.block.witnesses)
				{
					auto it = witnesses.find(asset);
					if (it != witnesses.end())
						it->second = std::min(it->second, block_height);
					else
						witnesses[asset] = block_height;
				}
			}

			if (may_broadcast_early || may_broadcast_lately)
				finalize_pending_tip(std::move(from), may_broadcast_lately ? candidate_hash : uint256_t((uint8_t)0), may_broadcast_lately ? candidate.block.number : 0);
			return expectation::met;
		}
		expects_lr<void> server_node::broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx, const algorithm::pubkeyhash_t& owner, bool bypass_cooldown)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto mempool = storages::mempoolstate();
			auto action = mempool.add_transaction(**candidate_tx, bypass_cooldown, &owner);
			if (!action)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("transaction %s %.*s mempool rejection: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), action.error().what());
				return action.error();
			}
			else if (kernel::params().user.consensus.logging)
				VI_INFO("transaction %s queued (type: %.*s, nonce: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), candidate_tx->nonce);

			if (events.accept_transaction)
				events.accept_transaction(candidate_hash, *candidate_tx, owner);

			size_t notifications = notify_all_except(uref(from), descriptors::broadcast_transaction_hash(), { format::variable(candidate_hash) });
			if (notifications > 0 && kernel::params().user.consensus.logging)
				VI_DEBUG("transaction %s broadcasted to %i nodes (type: %.*s)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)notifications, (int)purpose.size(), purpose.data());
				
			if (!has_production())
				return expectation::met;

			sync.pool.lock();
			prover.pooled = true;
			sync.pool.unlock();
			sync.pool_cv.notify_all();
			run_block_production();
			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_block_hash(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			if (!block_hash)
				return expectation::met;

			auto chain = storages::chainstate();
			auto target = chain.get_block_header_by_hash(block_hash);
			if (target && block_hash == target->as_hash())
				return expectation::met;

			query(uref(from), descriptors::fetch_block(), { format::variable(block_hash) }, kernel::params().user.tcp.timeout).when([this, from](expects_rt<exchange>&& event) mutable
			{
				if (event && !event->args.empty())
				{
					ledger::block_evaluation candidate;
					format::ro_stream block_message = format::ro_stream(event->args.front().as_string());
					if (candidate.block.load(block_message))
					{
						auto status = accept_block(std::move(from), candidate, nullptr);
						if (!status && kernel::params().user.consensus.logging)
							VI_WARN("%s", status.error().what());
					}
				}
			});
			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_transaction_hash(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint256_t transaction_hash = event.args.front().as_uint256();
			if (!transaction_hash)
				return remote_exception("invalid hash");

			auto mempool = storages::mempoolstate();
			if (mempool.has_transaction(transaction_hash).or_else(false))
				return expectation::met;

			auto chain = storages::chainstate();
			if (chain.has_block_transaction(transaction_hash).or_else(false))
				return expectation::met;

			query(uref(from), descriptors::fetch_transaction(), { format::variable(transaction_hash) }, kernel::params().user.tcp.timeout).when([this, from](expects_rt<exchange>&& event) mutable
			{
				if (event && !event->args.empty())
				{
					format::ro_stream transaction_message = format::ro_stream(event->args.front().as_string());
					uptr<ledger::transaction_message> candidate = tangent::transactions::resolver::from_stream(transaction_message);
					if (candidate && candidate->load(transaction_message))
						accept_transaction(std::move(from), std::move(candidate));
				}
			});
			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_attestation(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() < 3)
				return remote_exception("invalid arguments");

			algorithm::asset_id asset = event.args[0].as_uint256();
			format::ro_stream proof_message = format::ro_stream(event.args[1].as_string());
			superchain::computed_transaction proof;
			if (!proof.load(proof_message))
				return remote_exception("invalid proof");

			auto attestation = storages::attestation_tree();
			auto executor = ledger::executor_context(nullptr);
			uint256_t commitment_hash = proof.as_proof_hash(asset);
			attestation.asset = asset;
			attestation.proofs[commitment_hash] = proof;
			for (size_t i = 2; i < event.args.size(); i++)
			{
				algorithm::pubkeyhash_t attester;
				algorithm::hashsig_t commitment_signature = algorithm::hashsig_t(event.args[i].as_string());
				if (!algorithm::signing::recover_hash(commitment_hash, attester, commitment_signature))
					return remote_exception("invalid commitment");

				auto validation = executor.get_verified_validator_attestation(asset, attester);
				if (!validation)
					return remote_exception(std::move(validation.error().message()));

				attestation.commitments[commitment_hash].insert(commitment_signature);
			}

			auto finalization = accept_attestation(attestation, true);
			if (finalization)
				return expectation::met;

			if (!finalization.error().is_retry() && !finalization.error().is_shutdown())
			{
				if (kernel::params().user.consensus.logging)
					VI_ERR("attestation %s verification failed: %s", uint256_to_label(commitment_hash).c_str(), finalization.what().c_str());
				return expects_rt<void>(finalization.error());
			}

			size_t notifications = notify_all_except(std::move(from), descriptors::broadcast_attestation(), format::variables(event.args));
			if (notifications > 0 && kernel::params().user.consensus.logging)
				VI_DEBUG("attestation %s broadcasted to %i nodes", uint256_to_label(commitment_hash).c_str(), (int)notifications);

			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_preattestation(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 5)
				return remote_exception("invalid arguments");

			algorithm::asset_id asset = event.args[0].as_uint256();
			uint256_t attestation_hash = event.args[1].as_uint256();
			uint64_t tip_height = event.args[2].as_uint64();
			uint256_t proof_hash = event.args[3].as_uint256();
			algorithm::hashsig_t signature = algorithm::hashsig_t(event.args[4].as_string());
			if (!attestation_hash || !proof_hash || signature.empty())
				return remote_exception("invalid preattestation");

			algorithm::pubkeyhash_t attester;
			if (!algorithm::signing::recover_hash(preattestation_proof(asset, attestation_hash, tip_height, proof_hash), attester, signature))
				return remote_exception("invalid preattestation signature");

			auto executor = ledger::executor_context(nullptr);
			auto validation = executor.get_verified_validator_attestation(asset, attester);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto mempool = storages::mempoolstate();
			auto cached = mempool.get_preattestation_body(attestation_hash, proof_hash);
			if (cached)
			{
				auto collision = executor.get_witness_transaction(asset, cached->transaction_id);
				if (collision)
					return expectation::met;

				auto status = mempool.add_preattestation(attestation_hash, asset, attester, tip_height, proof_hash, signature, *cached);
				if (!status)
					return remote_exception(std::move(status.error().message()));

				size_t notifications = notify_all_except(std::move(from), descriptors::broadcast_preattestation(), format::variables(event.args));
				if (notifications > 0 && kernel::params().user.consensus.logging)
					VI_DEBUG("preattestation %" PRIu64 " for %s broadcasted to %i nodes", tip_height, uint256_to_label(attestation_hash).c_str(), (int)notifications);

				return expectation::met;
			}

			auto args = format::variables(event.args);
			query(uref(from), descriptors::fetch_preattestation_body(), { format::variable(asset), format::variable(attestation_hash), format::variable(proof_hash) }, kernel::params().user.tcp.timeout).when([this, asset, attestation_hash, attester, tip_height, proof_hash, signature, args, from](expects_rt<exchange>&& event) mutable
			{
				if (!event || event->args.empty())
					return;

				superchain::computed_transaction body;
				format::ro_stream proof_message = format::ro_stream(event->args.front().as_string());
				if (!body.load(proof_message) || body.as_proof_hash(asset) != proof_hash)
					return;

				auto executor = ledger::executor_context(nullptr);
				auto collision = executor.get_witness_transaction(asset, body.transaction_id);
				if (collision)
					return;

				auto mempool = storages::mempoolstate();
				if (!mempool.add_preattestation(attestation_hash, asset, attester, tip_height, proof_hash, signature, body))
					return;

				size_t notifications = notify_all_except(std::move(from), descriptors::broadcast_preattestation(), std::move(args));
				if (notifications > 0 && kernel::params().user.consensus.logging)
					VI_DEBUG("preattestation %" PRIu64 " for %s broadcasted to %i nodes", tip_height, uint256_to_label(attestation_hash).c_str(), (int)notifications);
			});
			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_delegation(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() < 7 || event.args.size() > 11 + kernel::params().policy.participation.max_per_account)
				return remote_exception("invalid arguments");

			uint256_t delegation_id = event.args[0].as_uint256();
			auto signature = algorithm::hashsig_t(event.args[1].as_string());
			if (signature.empty())
				return remote_exception("invalid signature");

			auto address = text_address_to_socket_address(event.args[2].as_string(), false);
			if (!address)
				return remote_exception("invalid address");

			auto block_number = event.args[3].as_uint64();
			auto delegation_type = event.args[4].as_uint32();
			auto accounts_size = event.args[5].as_uint8();
			auto args_offset = 6;
			if (event.args.size() - args_offset < accounts_size)
				return remote_exception("invalid arguments");

			auto accounts = btree_set<algorithm::pubkeyhash_t>();
			for (uint8_t i = 0; i < accounts_size; i++)
			{
				auto account = algorithm::pubkeyhash_t(event.args[args_offset + i].as_string());
				accounts.insert(account);
				if (account.empty())
					return remote_exception("invalid account");
			}
			if (accounts.size() != accounts_size || accounts.empty())
				return remote_exception("invalid accounts size");

			auto delegator = algorithm::pubkeyhash_t();
			auto args = format::variables();
			args.insert(args.begin(), event.args.begin() + (args_offset + accounts.size()), event.args.end());
			if (!algorithm::signing::recover_hash(delegation_input_proof(*address, block_number, delegation_type, args, accounts), delegator, signature))
				return remote_exception("invalid signature");

			auto chain = storages::chainstate();
			if (chain.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto adapter = server_delegation_adapter(this);
			auto delegation = uptr(delegations::resolver::from_type(delegation_type, &adapter, &executor, runner_descriptor->second.public_key_hash));
			if (!delegation)
				return remote_exception("invalid delegation type");

			auto validation = delegation->validate_delegation(delegator, accounts, args);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));
			else if (!from)
				return expectation::met;

			{
				umutex<std::recursive_mutex> unique(sync.neighbor);
				if (delegation_paths.find(delegation_id) != delegation_paths.end())
					return expectation::met;

				if (delegation_paths.size() > MAX_DELEGATION_PATHS)
				{
					uint64_t now = kernel::params().time.now_cpu();
					for (auto it = delegation_paths.begin(); it != delegation_paths.end();)
						it = now > it->second.timestamp + MAX_DELEGATION_PATHS ? delegation_paths.erase(it) : std::next(it);

					if (delegation_paths.size() > MAX_DELEGATION_PATHS)
						return expectation::met;
				}
				delegation_paths[delegation_id] = delegation_path { uref(from), kernel::params().time.now_cpu() };
			}

			size_t notifications = 0;
			auto type = delegation->as_typename();
			for (auto& target : accounts)
			{
				algorithm::hashsig_t accept_signature; auto* hosted = find_descriptor(target);
				if (hosted && algorithm::signing::sign(delegation_output_proof(delegation_id, hosted->second.public_key), hosted->second.secret_key, accept_signature))
				{
					bool sent = !!notify(uref(from), descriptors::perform_delegation(), { format::variable(delegation_id), format::variable(hosted->second.public_key.optimized_view()), format::variable(accept_signature.optimized_view()) });
					if (sent && kernel::params().user.consensus.logging)
						VI_INFO("delegation %s path: accept to %s (type: %.*s, delegate: %s)", uint256_to_label(delegation_id).c_str(), from->peer_address().c_str(), (int)type.size(), type.data(), algorithm::signing::encode_address(hosted->second.public_key_hash).c_str());
					notifications += sent ? 1 : 0;
				}
			}

			notifications += notify_all_except(uref(from), descriptors::broadcast_delegation(), format::variables(event.args));
			if (kernel::params().user.consensus.logging && notifications > 0)
				VI_DEBUG("delegation %s path: broadcasted to %i nodes (type: %.*s, delegate: %s)", uint256_to_label(delegation_id).c_str(), (int)notifications, (int)type.size(), type.data(), algorithm::signing::encode_address(hosted->second.public_key_hash).c_str());
			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_quote_ask(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 2)
				return expects_rt<void>(remote_exception("invalid arguments"));

			algorithm::asset_id asset = event.args[0].as_uint256();
			if (!algorithm::asset::is_aux(asset))
				return expects_rt<void>(remote_exception("invalid fee query"));

			uint64_t interval = kernel::params().policy.attestation.quote_validity_time / kernel::params().policy.pow.time;
			uint64_t known_block_number = event.args[1].as_uint64();
			if (interval == 0 || known_block_number % interval != 0)
				return expects_rt<void>(remote_exception("misaligned quote ask"));

			auto chain = storages::chainstate();
			uint64_t tip_number = chain.get_latest_block_number().or_else(0);
			uint64_t aligned_tip = tip_number / interval * interval;
			if (known_block_number + interval < aligned_tip || known_block_number > aligned_tip + interval)
				return expects_rt<void>(remote_exception("stale quote ask"));

			size_t notifications = notify_all_except(uref(from), descriptors::broadcast_quote_ask(), format::variables(event.args));
			if (notifications > 0 && kernel::params().user.consensus.logging)
				VI_DEBUG("%s quote ask broadcasted to %i nodes", algorithm::asset::blockchain_of(asset).c_str(), (int)notifications);

			auto attester = std::pair<ledger::wallet*, decimal>(nullptr, decimal::zero());
			auto executor = ledger::executor_context(nullptr);
			for (auto& [account, descriptor] : descriptors)
			{
				if (descriptor.first.services.has_attestation)
				{
					auto attestation = executor.get_verified_validator_attestation(asset, account);
					if (attestation)
					{
						attester.first = &descriptor.second;
						if (attestation->min_fee.is_positive())
							attester.second = std::move(attestation->min_fee);
						break;
					}
				}
			}

			auto* offchain = superchain::bridge::get();
			if (!attester.first || !offchain->has_network(asset, true))
				return expects_rt<void>(expectation::met);

			auto mempool = storages::mempoolstate();
			if (mempool.has_quote(asset, attester.first->public_key_hash, chain.get_latest_block_number().or_else(0)).or_else(false))
				return expects_rt<void>(expectation::met);

			auto filter = storages::result_filter::greater(0, -1);
			auto candidates = chain.get_multiforms_by_column_filter(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_column(asset), filter, 0, storages::result_range_window(0, 1));
			if (!candidates || candidates->empty())
				return expects_rt<void>(expectation::met);

			auto* from_bridge = (states::bridge_balance*)candidates->front().ptr();
			auto to_wallet = offchain->compute_wallet(asset, (uint8_t*)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
			if (!from_bridge || !to_wallet || to_wallet->encoded_addresses.empty() || !from_bridge->supply.is_positive())
				return expects_rt<void>(expectation::met);

			auto supply = std::move(from_bridge->supply);
			auto from_link = superchain::wallet_link::from_hash(from_bridge->bridge_hash);
			auto address = to_wallet->encoded_addresses.begin()->second;
			auto expiry_block_number = chain.get_latest_block_number().or_else(0) + kernel::params().policy.attestation.quote_validity_time / kernel::params().policy.pow.time;
			coasync<void>([this, offchain, asset, expiry_block_number, from_link = std::move(from_link), address = std::move(address), supply = std::move(supply), attester = std::move(attester)]() mutable -> promise<void>
			{
				auto& [signer, min_fee] = attester;
				auto cascade = superchain::utxo_translation_unit::from(offchain->get_network(asset)) != nullptr;
				uint8_t level = cascade ? superchain::approved_fee::level_of_amount(supply) : 0;
				do
				{
					auto estimate = coawait(offchain->estimate_transaction_fee(asset, from_link, superchain::value_transfer(asset, address, decimal(cascade ? std::min(superchain::approved_fee::cap_of_level(level), supply) : supply))));
					auto network_fee = estimate ? estimate->get_max_fee() * kernel::params().policy.attestation.quote_headroom : decimal::nan();
					auto quote = superchain::approved_fee(asset, decimal(network_fee.is_positive() ? std::move(std::max(network_fee, min_fee)) : decimal::nan()), expiry_block_number);
					bool floored = estimate && network_fee.is_positive() && min_fee >= network_fee;
					if (quote.fee.is_positive() && quote.sign(signer->secret_key))
					{
						auto mempool = storages::mempoolstate();
						uint8_t min_level = cascade && floored ? 1 : level;
						for (uint16_t i = min_level; i <= level; i++)
							mempool.add_quote(quote, signer->public_key_hash, (uint8_t)i).report("failed to add a fee quote");

						size_t notifications = notify_all(descriptors::broadcast_quote(), { format::variable(quote.as_message().data), format::variable(min_level), format::variable(level) });
						if (notifications > 0 && kernel::params().user.consensus.logging)
							VI_DEBUG("%s quote broadcasted to %i nodes (levels: %i-%i)", algorithm::asset::blockchain_of(asset).c_str(), (int)notifications, (int)min_level, (int)level);
					}
					else if (estimate)
						estimate = remote_exception("failed to attest");

					if (kernel::params().user.consensus.logging)
					{
						auto symbol = algorithm::asset::blockchain_of(asset);
						if (estimate)
							VI_INFO("%s bridge fee attestation: %s %s (block: %" PRIu64 ", level: %i, network: %s)", symbol.c_str(), quote.fee.to_string().c_str(), symbol.c_str(), quote.expiry_block_number, (int)level, network_fee.to_string().c_str());
						else
							VI_WARN("%s bridge fee attestation failed: %s (level: %i)", symbol.c_str(), estimate.what().c_str(), (int)level);
					}

					level = floored || !cascade ? 0 : (level - 1);
				} while (level > 0);
				coreturn_void;
			});
			return expects_rt<void>(expectation::met);
		}
		expects_rt<void> server_node::broadcast_quote(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 3)
				return expects_rt<void>(remote_exception("invalid arguments"));

			uint8_t min_level = event.args[1].as_uint8(), max_level = event.args[2].as_uint8();
			if (min_level > max_level)
				return expects_rt<void>(remote_exception("invalid quote levels"));

			superchain::approved_fee quote;
			format::ro_stream message = format::ro_stream(event.args[0].as_string());
			if (!quote.load(message))
				return expects_rt<void>(remote_exception("invalid message"));

			algorithm::pubkeyhash_t attester;
			if (!quote.recover_hash(attester))
				return expects_rt<void>(remote_exception("invalid publisher"));

			auto executor = ledger::executor_context(nullptr);
			if (!executor.get_verified_validator_attestation(quote.asset, attester))
				return expects_rt<void>(remote_exception("invalid attester"));

			auto mempool = storages::mempoolstate(); bool propagate = false;
			for (uint16_t i = min_level; i <= max_level; i++)
				propagate = mempool.add_quote(quote, attester, (uint8_t)i) || propagate;

			size_t notifications = propagate ? notify_all_except(std::move(from), descriptors::broadcast_quote(), format::variables(event.args)) : 0;
			if (notifications > 0 && kernel::params().user.consensus.logging)
				VI_DEBUG("%s quote broadcasted to %i nodes", algorithm::asset::blockchain_of(quote.asset).c_str(), (int)notifications);
			return expects_rt<void>(expectation::met);
		}
		expects_rt<void> server_node::perform_delegation(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 3)
				return remote_exception("invalid arguments");

			uint256_t delegation_id = event.args[0].as_uint256();
			auto account_key = algorithm::pubkey_t(event.args[1].as_string());
			auto accept_signature = algorithm::hashsig_t(event.args[2].as_string());
			if (account_key.empty() || accept_signature.empty())
				return remote_exception("invalid accept");

			algorithm::pubkey_t recovered;
			if (!algorithm::signing::recover(delegation_output_proof(delegation_id, account_key), recovered, accept_signature) || !recovered.equals(account_key))
				return remote_exception("invalid accept signature");

			algorithm::pubkeyhash_t account;
			algorithm::signing::derive_public_key_hash(account_key, account);
			if (find_descriptor(account) != nullptr)
				return expectation::met;

			uref<relay> parent = nullptr;
			{
				umutex<std::recursive_mutex> unique(sync.neighbor);
				auto waiter = delegation_nodes.find(delegation_id);
				if (waiter != delegation_nodes.end())
				{
					waiter->second(account_key, uref(from));
					return expectation::met;
				}

				auto path = delegation_paths.find(delegation_id);
				if (path == delegation_paths.end() || !path->second.parent)
					return expectation::met;

				parent = uref(path->second.parent);
			}

			register_account_route(account, account_key, uref(from));
			if (!notify(uref(parent), descriptors::perform_delegation(), format::variables(event.args)))
				return expectation::met;
			else if (kernel::params().user.consensus.logging)
				VI_INFO("delegation %s path: hop to %s (delegate: %s)", uint256_to_label(delegation_id).c_str(), parent ? parent->peer_address().c_str() : "null", algorithm::signing::encode_address(account).c_str());
			return expectation::met;
		}
		expects_rt<void> server_node::check_socket(uref<relay>&&, const exchange& event)
		{
			if (!event.args.empty())
				return remote_exception("invalid args");

			return expectation::met;
		}
		expects_rt<format::variables> server_node::perform_handshake(uref<relay>&& from, const exchange& event, bool is_acknowledgement)
		{
			if (event.args.size() != (is_acknowledgement ? 5 : 4))
				return remote_exception("invalid arguments");

			uint64_t system_time = kernel::params().time.now_cpu();
			uint64_t peer_time = event.args[1].as_uint64();
			uint64_t peer_latency = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
			if (peer_latency > kernel::params().user.tcp.timeout)
				return remote_exception("bad latency or stale proof");

			relay_descriptor peer_descriptor;
			auto& [peer_node, peer_wallet] = peer_descriptor;
			format::ro_stream peer_message = format::ro_stream(event.args[0].as_string());
			algorithm::hashsig_t peer_signature = algorithm::hashsig_t(event.args[2].as_string());
			if (!peer_node.load(peer_message))
				return remote_exception("invalid message");
			else if (peer_node.fork_version != FORK_VERSION)
				return remote_exception(stringify::text("node v%i.%i not supported", peer_node.fork_version, peer_node.patch_version));
			else if (!algorithm::signing::recover(handshake_proof(peer_node, peer_time, nullptr), peer_wallet.public_key, peer_signature))
				return remote_exception("invalid signature");

			auto mempool = storages::mempoolstate();
			peer_node.quality.latency = peer_latency;
			peer_node.quality.reachable = is_acknowledgement;
			if (!from->private_network())
				peer_node.address = socket_address(from->peer_address(), peer_node.address.get_ip_port().or_else(kernel::params().user.consensus.port));

			algorithm::signing::derive_public_key_hash(peer_wallet.public_key, peer_wallet.public_key_hash);
			auto advertised_address = peer_node.address;
			bool identity_check = !peer_node.is_valid() || peer_wallet.public_key_hash.empty();
			bool uniqueness_check = identity_check || find_descriptor(peer_wallet.public_key_hash) || find_by_account(peer_wallet.public_key_hash);
			if (identity_check || uniqueness_check)
			{
				auto prev = mempool.get_node(peer_descriptor.first.address);
				if (prev)
				{
					if (!find_descriptor(prev->second.public_key_hash))
						mempool.clear_node(peer_descriptor.first.address);
				}
				return remote_exception(!identity_check && uniqueness_check ? "node identity is not unique" : "node identity is not accepted");
			}

			auto prev_descriptor = mempool.get_node(peer_node.address);
			if (prev_descriptor)
				peer_node.quality.reachable = peer_node.quality.reachable || prev_descriptor->first.quality.reachable;

			auto status = accept_node(mempool, peer_descriptor, from->type_of() == node_type::inbound ? node_category::inbound : node_category::outbound);
			if (!status)
				return remote_exception(std::move(status.error().message()));

			from->open_channel(std::move(peer_descriptor));
			auto bindings = apply_account_bindings(string(event.args[is_acknowledgement ? 4 : 3].as_string()), uref(from), advertised_address);
			if (!bindings)
				return remote_exception(std::move(bindings.error().message()));

			if (is_acknowledgement)
				return format::variables();

			auto node_message = string();
			if (!event.callee || !algorithm::signing::sign(handshake_proof(event.callee->first, system_time, &node_message), event.callee->second.secret_key, peer_signature))
				return remote_exception("proof generation error");

			return format::variables({ format::variable(node_message), format::variable(system_time), format::variable(peer_signature.optimized_view()), format::variable(peer_latency), format::variable(build_account_bindings()) });
		}
		expects_rt<format::variables> server_node::perform_discovery(uref<relay>&& from, const exchange& event, bool is_acknowledgement)
		{
			if (event.args.size() < 3 || event.args.size() > 3 + kernel::params().message.hashes_per_query)
				return remote_exception("invalid arguments");

			auto block_handle = exchange();
			block_handle.args.reserve(1);
			block_handle.args.push_back(event.args[1]);

			auto status = broadcast_block_hash(uref(from), std::move(block_handle));
			if (!status)
				return status.error();

			auto mempool = storages::mempoolstate();
			auto address = text_address_to_socket_address(event.args[0].as_string(), false);
			if (address && from->type_of() == node_type::inbound)
			{
				auto observed = text_address_to_socket_address(from->peer_address(), false);
				auto claimed_ip = address->get_ip_address().or_else(string());
				if (observed && !claimed_ip.empty() && claimed_ip == observed->get_ip_address().or_else(string()))
				{
					for (auto& [account, descriptor] : descriptors)
					{
						bool runner = runner_descriptor == &descriptor;
						descriptor.first.address = *address;
						accept_node(mempool, descriptor, runner ? node_category::runner : node_category::neighbor).report("mempool local node save failed");
					}
				}
			}

			size_t new_nodes = 0;
			bool private_network = from->private_network();
			for (size_t i = 3; i < event.args.size(); i++)
			{
				address = text_address_to_socket_address(event.args[i].as_string(), false);
				new_nodes += address && !connected_to_ip_address(*address) && mempool.apply_unknown_node(*address, private_network) ? 1 : 0;
			}

			size_t self_transactions = mempool.get_transactions_count().or_else(0);
			size_t other_transactions = (size_t)event.args[2].as_uint32();
			if (self_transactions < other_transactions)
				synchronize_mempool_with(uref(from));
			if (new_nodes > 0)
				run_topology_optimization();

			if (is_acknowledgement)
				return format::variables();

			return build_state_exchange(std::move(from));
		}
		expects_rt<format::variables> server_node::fetch_headers(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 2)
				return remote_exception("invalid arguments");

			uint64_t branch_number = event.args.front().as_uint64();
			uint64_t branch_length = event.args.back().as_uint64();
			if (!branch_number || !branch_length)
				return remote_exception("invalid branch");

			auto chain = storages::chainstate();
			auto headers = chain.get_block_headers(branch_number, std::min(kernel::params().message.headers_per_query, branch_length));
			if (!headers || headers->empty())
				return format::variables({ });

			format::variables result;
			result.resize(headers->size() + 1);
			result[0] = format::variable(branch_number + headers->size() - 1);
			parallel::wait_all(parallel::for_loop(result.size() - 1, ELEMENTS_BULK, [&](size_t i)
			{
				result[i + 1] = format::variable(headers->at(i).as_message().data);
			}));
			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::fetch_block(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() < 1 || event.args.size() > 2)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			uint64_t block_number = event.args.size() > 1 ? event.args[1].as_uint64() : 0;
			if (!block_hash && !block_number)
				return remote_exception("invalid arguments");

			auto chain = storages::chainstate();
			auto block = !block_number && block_hash > 0 ? chain.get_block_by_hash(block_hash) : chain.get_block_by_number(block_number);
			if (block)
				return format::variables({ format::variable(block->as_message().data) });

			umutex<std::recursive_mutex> unique(sync.tip);
			auto it = maybe_tips.find(block_hash);
			if (it != maybe_tips.end())
				return format::variables({ format::variable(it->second.data) });

			return format::variables();
		}
		expects_rt<format::variables> server_node::fetch_blocks(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 2)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			uint256_t block_number = event.args[1].as_uint64();
			if (!block_hash && !block_number)
				return remote_exception("invalid arguments");

			auto chain = storages::chainstate();
			if (!block_number && block_hash > 0)
			{
				auto result = chain.get_block_number_by_hash(block_hash);
				if (result)
					block_number = *result;
			}

			uint256_t gas_limit = kernel::params().message.blocks_size_per_query * (uint64_t)ledger::gas_cost::reserved_byte;
			size_t block_count = (size_t)(uint64_t)(gas_limit / ledger::block_header::get_block_gas_cost());
			auto blocks = chain.get_blocks(block_number, block_count, gas_limit);
			if (!blocks || blocks->empty())
				return format::variables({ });

			format::variables result;
			result.resize(blocks->size());
			parallel::wait_all(parallel::for_loop(result.size(), ELEMENTS_BULK, [&](size_t i)
			{
				result[i] = format::variable(blocks->at(i).as_message().data);
			}));
			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::fetch_mempool(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint64_t cursor = event.args.front().as_uint64();
			const uint64_t transactions_count = kernel::params().message.hashes_per_query;
			auto mempool = storages::mempoolstate();
			auto hashes = mempool.get_transaction_hashset(cursor, transactions_count);
			if (!hashes || hashes->empty())
				return format::variables();

			format::variables result;
			result.reserve(hashes->size());
			result.push_back(format::variable(cursor + hashes->size()));
			for (auto& item : *hashes)
				result.push_back(format::variable(item));

			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::fetch_transaction(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint256_t transaction_hash = event.args.front().as_uint256();
			if (!transaction_hash)
				return remote_exception("invalid hash");

			auto mempool = storages::mempoolstate();
			auto transaction = mempool.get_transaction_by_hash(transaction_hash);
			if (transaction)
				return format::variables({ format::variable((*transaction)->as_message().data) });

			auto chain = storages::chainstate();
			auto block_transaction = chain.get_block_transaction_by_hash(transaction_hash);
			if (block_transaction)
				return format::variables({ format::variable(block_transaction->transaction->as_message().data) });

			return format::variables();
		}
		expects_rt<format::variables> server_node::fetch_transactions(uref<relay>&&, const exchange& event)
		{
			if (event.args.empty() || event.args.size() > kernel::params().message.transactions_per_query)
				return remote_exception("invalid arguments");

			format::variables result;
			result.reserve(event.args.size());

			auto mempool = storages::mempoolstate();
			auto chain = storages::chainstate();
			for (auto& target : event.args)
			{
				uint256_t transaction_hash = target.as_uint256();
				if (!transaction_hash)
					return remote_exception("invalid hash");

				auto transaction = mempool.get_transaction_by_hash(transaction_hash);
				if (!transaction)
				{
					auto block_transaction = chain.get_block_transaction_by_hash(transaction_hash);
					if (block_transaction)
						result.push_back(format::variable(block_transaction->transaction->as_message().data));
				}
				else
					result.push_back(format::variable((*transaction)->as_message().data));
			}
			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::fetch_preattestation_body(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 3)
				return remote_exception("invalid arguments");

			algorithm::asset_id asset = event.args[0].as_uint256();
			uint256_t attestation_hash = event.args[1].as_uint256();
			uint256_t proof_hash = event.args[2].as_uint256();
			if (!attestation_hash || !proof_hash)
				return remote_exception("invalid hash");

			auto mempool = storages::mempoolstate();
			auto body = mempool.get_preattestation_body(attestation_hash, proof_hash);
			if (body && body->as_proof_hash(asset) == proof_hash)
				return format::variables({ format::variable(body->as_message().data) });

			auto batch = mempool.get_attestation(attestation_hash);
			if (!batch)
				return remote_exception("preattestation body not found");

			for (auto& item : batch->proofs)
			{
				if (item.second.as_proof_hash(asset) == proof_hash)
					return format::variables({ format::variable(item.second.as_message().data) });
			}

			return format::variables();
		}
		expects_rt<format::variables> server_node::delegate_execution(uref<relay>&&, const exchange& event)
		{
			auto sender = algorithm::pubkeyhash_t();
			auto packed = unpack_private_result(event.args, event.callee, sender);
			if (!packed)
				return packed;
			else if (packed->size() != 4)
				return remote_exception("invalid arguments");

			auto yielding_delegator = ledger::wallet::from_public_key(algorithm::pubkey_t(packed->at(0).as_string()));
			if (yielding_delegator.public_key_hash.empty() || yielding_delegator.public_key_hash != sender)
				return remote_exception("invalid delegator");

			auto chain = storages::chainstate();
			auto block_number = packed->at(1).as_uint64();
			if (chain.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			uint32_t delegation_type;
			auto reader = format::ro_stream(packed->at(3).as_string());
			if (!reader.read_integer(reader.read_type(), &delegation_type))
				return remote_exception("invalid delegation type");

			auto executor = ledger::executor_context(nullptr);
			auto adapter = server_delegation_adapter(this);
			auto contract = uptr(delegations::resolver::from_type(delegation_type, &adapter, &executor, event.callee->second.public_key_hash));
			if (!contract)
				return remote_exception("invalid delegation type");

			auto transaction_hash = packed->at(2).as_uint256();
			auto context = executor.get_applied_block_transaction(contract->as_transaction_type(), transaction_hash);
			if (!context)
				return remote_exception("transaction not found");

			executor.transaction = *context->transaction;
			executor.receipt = std::move(context->receipt);
			if (!reader.read_integer(reader.read_type(), &delegation_type))
				return remote_exception("invalid delegate");

			if (!contract->load_payload(reader))
				return remote_exception("delegation deserialization failed");

			auto validation = contract->validate_transition(nullptr, yielding_delegator);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto execution = contract->yield_to_self(contract->runner->public_key_hash, delegation_type, false);
			if (!execution)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("%s hop-execute failed: %s (from: %s, hash: %s)", contract->as_typename().data(), execution.what().c_str(), algorithm::signing::encode_address(yielding_delegator.public_key_hash).c_str(), algorithm::encoding::encode_0xhex256(reader.hash()).c_str());
				return remote_exception(std::move(execution.error().message()));
			}
			else if (kernel::params().user.consensus.logging)
				VI_INFO("%s execute: %s (from: %s)", contract->as_typename().data(), uint256_to_label(reader.hash()).c_str(), algorithm::signing::encode_address(yielding_delegator.public_key_hash).c_str());

			return pack_private_result({ format::variable(execution->data) }, yielding_delegator.public_key, event.callee->second.secret_key);
		}
		expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>> server_node::query_bridge_fee_estimates(const algorithm::asset_id& asset, const option<decimal>& amount)
		{
			auto chain = storages::chainstate();
			auto quotes = storages::mempoolstate().get_quotes(asset, chain.get_latest_block_number().or_else(0));
			if (!quotes)
				return expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>>(remote_exception(std::move(quotes.error().message())));

			if (amount && amount->is_positive())
			{
				auto level = superchain::approved_fee::level_of_amount(*amount);
				quotes->erase(std::remove_if(quotes->begin(), quotes->end(), [&](const std::pair<superchain::approved_fee, uint8_t>& x) { return x.second != level && x.second != 0; }), quotes->end());
				if (quotes->empty())
				{
					auto filter = storages::result_filter::greater(0, -1);
					auto candidates = chain.get_multiforms_by_column_filter(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_column(asset), filter, 0, storages::result_range_window(0, 1));
					auto* bridge = candidates && !candidates->empty() ? (states::bridge_balance*)candidates->front().ptr() : nullptr;
					if (!bridge || level > superchain::approved_fee::level_of_amount(bridge->supply))
						return expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>>(remote_exception("excessive estimation amount"));
				}
			}
			if (!quotes->empty())
				return expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>>(std::move(*quotes));

			uint64_t interval = kernel::params().policy.attestation.quote_validity_time / kernel::params().policy.pow.time;
			uint64_t block_number = chain.get_latest_block_number().or_else(0);
			exchange message;
			message.args.push_back(format::variable(asset));
			message.args.push_back(format::variable(interval > 0 ? (block_number / interval) * interval : block_number));
			
			auto status = broadcast_quote_ask(nullptr, message);
			if (!status)
				return expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>>(std::move(status.error()));

			return expects_rt<vector<std::pair<superchain::approved_fee, uint8_t>>>(remote_exception::retry_later());
		}
		expects_rt<ledger::block_body> server_node::produce_block()
		{
			if (!has_production())
				return remote_exception("no active block producer account; send a setup transaction to enable block production");
			else if (is_syncing() || !sync.producer.try_lock())
				return remote_exception::retry_later();

			std::lock_guard<std::mutex> guard(sync.producer, std::adopt_lock);
			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			auto accounts = [this](size_t index)
			{
				if (index == 0)
					return &runner_descriptor->second;

				auto it = descriptors.begin();
				std::advance(it, std::min(descriptors.size(), index - 1));
				if (it != descriptors.end() && it->second.second.public_key_hash == runner_descriptor->second.public_key_hash)
					++it;

				return it != descriptors.end() ? &it->second.second : nullptr;
			};
			auto tip = chain.get_latest_block_header();
			prover.solver = ledger::solver_context();
			prover.rewards.clear();
			prover.hashes.clear();

			auto priority = prover.solver.apply_validator_state(accounts, tip.address());
			auto position = priority.or_else(kernel::params().policy.production.max_per_block);
			if (tip && position > 0)
			{
				auto current_solution_time = std::max<int64_t>(((int64_t)kernel::params().time.now() - (int64_t)tip->evaluation_time) - (int64_t)kernel::params().policy.pow.time * 2, 0);
				for (uint64_t i = 0; i <= position; i++)
				{
					auto other_node_solution_time = (int64_t)((double)kernel::params().policy.pow.time * algorithm::wesolowski::adjustment_scaling(i).to_double());
					if (current_solution_time < other_node_solution_time)
						return remote_exception::retry_after((uint64_t)(other_node_solution_time - current_solution_time));
				}
			}

			auto span = (double)(tip ? tip->get_slot_proof_duration_average() : 0) * algorithm::wesolowski::adjustment_scaling(position).to_double();
			if (kernel::params().user.consensus.logging && position > 0)
				VI_WARN("block solver: performing %s (number: %" PRIu64 ", leader: %" PRIu64 ", work: <%.2f sec.)", position < kernel::params().policy.production.max_per_block ? "leader fallback" : "network recovery", tip ? tip->number + 1 : 1, position + 1, span / 1000.0);

			auto evaluation = prover.solver.block_evalution_prepare(prover.solution);
			if (!evaluation)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("block %s dropped: %s (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: <%.2f sec.)", uint256_to_label(prover.solution.block.as_hash()).c_str(), evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
				return remote_exception(std::move(evaluation.error().message()));
			}

			bool queue_wait = false;
			auto queue_paid = prover.solver.state.executor.options & (uint8_t)ledger::executor_context::flags::congestion;
			auto queue_flags = (uint8_t)storages::transaction_queue::commitment | (uint8_t)(queue_paid ? storages::transaction_queue::standard_paid : storages::transaction_queue::standard_all);
			auto solution_account = prover.solver.state.public_key_hash;
			auto solution_challenge = ledger::block_header(prover.solution.block);
			auto solution_task = expects_promise_lr<ledger::block_header>();
			schedule::get()->set_task([this, solution_task, solution_account, solution_challenge = std::move(solution_challenge)]() mutable
			{
				{
					auto result = solution_challenge.solve(solution_account) ? expects_lr<ledger::block_header>(std::move(solution_challenge)) : expects_lr<ledger::block_header>(layer_exception("failed to solve a block"));
					std::lock_guard<std::mutex> barrier(sync.pool);
					solution_task.set(std::move(result));
				}
				sync.pool_cv.notify_all();
			}, false);
			while (evaluation && is_active() && solution_task.is_pending())
			{
				std::unique_lock<std::mutex> unique(sync.pool);
				if (queue_wait)
					sync.pool_cv.wait_for(unique, std::chrono::milliseconds(100), [this, &solution_task]() { return !is_active() || !solution_task.is_pending() || prover.pooled; });
				else
					queue_wait = true;
				prover.pooled = false;
				unique.unlock();

				size_t offsets[2] = { 0, 0 };
				while (prover.solver.can_accept_more_transactions())
				{
					auto queue = mempool.get_transactions_by_quality(queue_flags, offsets, ELEMENTS_BULK, &prover.hashes);
					if (!queue)
						break;

					prover.solver.try_include_transactions(std::move(*queue));
				}

				evaluation = prover.solver.block_evalution_update(prover.solution, prover.rewards);
				if (evaluation && position > 0 && ledger::solver_context().apply_validator_state(accounts, (tip = chain.get_latest_block_header()).address()).or_else(kernel::params().policy.production.max_per_block) == 0)
				{
					evaluation = layer_exception("orphaned");
					break;
				}
			}

			auto solution = !evaluation || solution_task.is_pending() ? expects_lr<ledger::block_header>(layer_exception("orphaned")) : solution_task.get();
			if (solution)
			{
				prover.solution.block.proof = std::move(solution->proof);
				prover.solution.block.evaluation_time = solution->evaluation_time;
			}

			tip = chain.get_latest_block_header();
			bool outpaced = !is_active() || (tip && prover.solution.block.number <= tip->number && (prover.solution.block.number != tip->number || prover.solution.block.priority > tip->priority));
			if (outpaced || !solution || !evaluation)
			{
				auto error = outpaced ? remote_exception::retry_later() : remote_exception(evaluation ? std::move(solution.error().message()) : std::move(evaluation.error().message()));
				if (kernel::params().user.consensus.logging)
					VI_WARN("block %s dropped: %s (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: <%.2f sec.)", uint256_to_label(prover.solution.block.as_hash()).c_str(), error.what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
				return error;
			}

			evaluation = prover.solver.block_evalution_finalize(prover.solution, prover.rewards);
			evaluation = evaluation ? prover.solver.block_solution_sign(prover.solution) : evaluation;
			if (!evaluation)
			{
				if (kernel::params().user.consensus.logging && evaluation.error().message() != "block producer must be active")
					VI_WARN("block %s dropped: %s (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: <%.2f sec.)", uint256_to_label(prover.solution.block.as_hash()).c_str(), evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
				return remote_exception(std::move(evaluation.error().message()));
			}

			auto verification = accept_block(nullptr, prover.solution, 0);
			if (!verification)
			{
				if (kernel::params().user.consensus.logging)
					VI_WARN("%s", verification.error().what());
				return remote_exception(std::move(verification.error().message()));
			}
			else if (kernel::params().user.consensus.logging)
				VI_INFO("block %s solved (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: <%.2f sec.)", uint256_to_label(prover.solution.block.as_hash()).c_str(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);

			prover.solver.erase_failed_transactions();
			return expects_rt<ledger::block_body>(std::move(prover.solution.block));
		}
		expects_lr<void> server_node::dispatch_transaction_logs(const algorithm::asset_id& asset, superchain::transaction_logs&& logs)
		{
			if (logs.receipts.empty())
				return expectation::met;

			auto mempool = storages::mempoolstate();
			auto attestation = storages::attestation_tree();
			auto executor = ledger::executor_context(nullptr);
			for (auto& receipt : logs.receipts)
			{
				auto collision = executor.get_witness_transaction(asset, receipt.transaction_id);
				if (collision)
					continue;

				if (receipt.finalized(asset))
				{
					size_t signatures = 0;
					attestation.asset = asset;
					attestation.proofs.clear();
					attestation.commitments.clear();
					for (auto& [account, descriptor] : descriptors)
					{
						algorithm::hashsig_t commitment_signature; uint256_t commitment_hash;
						if (descriptor.first.services.has_attestation && transactions::attestate::commit_to_proof(asset, receipt, descriptor.second.secret_key, commitment_hash, commitment_signature))
						{
							attestation.commitments[commitment_hash].insert(commitment_signature);
							attestation.proofs[commitment_hash] = receipt;
							++signatures;
						}
					}

					auto finalization = accept_attestation(attestation, true);
					if (!finalization && (finalization.error().is_retry() || finalization.error().is_shutdown()))
					{
						auto args = format::variables({ format::variable(asset), format::variable(receipt.as_message().data) });
						if (!attestation.commitments.empty())
						{
							for (auto& signature : attestation.commitments.begin()->second)
								args.push_back(format::variable(signature.view()));
						}

						size_t notifications = args.size() > 2 ? notify_all(descriptors::broadcast_attestation(), std::move(args)) : 0;
						if (notifications > 0 && kernel::params().user.consensus.logging)
							VI_DEBUG("attestation %s broadcasted to %i nodes (signatures: %i)", uint256_to_label(receipt.as_attestation_hash()).c_str(), (int)notifications, (int)signatures);
					}
					else if (!finalization && kernel::params().user.consensus.logging)
						VI_ERR("attestation %s verification failed: %s", uint256_to_label(receipt.as_attestation_hash()).c_str(), finalization.what().c_str());
				}
				else
				{
					auto attestation_hash = receipt.as_attestation_hash();
					auto proof_hash = receipt.as_proof_hash(asset);
					auto preattestation_hash = preattestation_proof(asset, attestation_hash, receipt.confirmed_block_id, proof_hash);
					for (auto& [account, descriptor] : descriptors)
					{
						algorithm::hashsig_t signature;
						if (!descriptor.first.services.has_attestation || !algorithm::signing::sign(preattestation_hash, descriptor.second.secret_key, signature))
							continue;

						auto mempool = storages::mempoolstate();
						mempool.add_preattestation(attestation_hash, asset, descriptor.second.public_key_hash, receipt.confirmed_block_id, proof_hash, signature, receipt).report("preattestation seed failure");

						auto args = format::variables({ format::variable(asset), format::variable(attestation_hash), format::variable(receipt.confirmed_block_id), format::variable(proof_hash), format::variable(signature.view()) });
						size_t notifications = notify_all(descriptors::broadcast_preattestation(), std::move(args));
						if (notifications > 0 && kernel::params().user.consensus.logging)
							VI_DEBUG("preattestation %" PRIu64 " for %s broadcasted to %i nodes", receipt.confirmed_block_id, uint256_to_label(attestation_hash).c_str(), (int)notifications);
					}
				}
			}
			return expectation::met;
		}
		expects_lr<socket_address> server_node::find_node_from_mempool()
		{
			size_t offset = 0, unknown_misses = 0;
			auto mempool = storages::mempoolstate();
		retry_known_node:
			auto known_node = mempool.get_closest_node(offset);
			if (!known_node)
			{
			retry_unknown_node:
				auto unknown_node = mempool.sample_connectable_unknown_node();
				if (!unknown_node)
					return layer_exception("no candidate found in mempool");
				
				if (connected_to_ip_address(*unknown_node))
				{
					if (++unknown_misses >= MEMPOOL_RETRY_SIZE)
						return layer_exception("no candidate found in mempool");
					goto retry_unknown_node;
				}

				unknown_misses = 0;
				if (kernel::params().user.consensus.logging)
					VI_INFO("node %s:%i channel: try unknown", unknown_node->get_ip_address().or_else(string("[bad_address]")).c_str(), (int)unknown_node->get_ip_port().or_else(0));

				return expects_lr<socket_address>(std::move(*unknown_node));
			}
			else if (connected_to_ip_address(known_node->first.address) || mempool.has_cooldown_on_node(known_node->first.address).or_else(false))
			{
				++offset;
				goto retry_known_node;
			}

			if (kernel::params().user.consensus.logging)
				VI_INFO("node %s:%i channel: try known", known_node->first.address.get_ip_address().or_else(string("[bad_address]")).c_str(), (int)known_node->first.address.get_ip_port().or_else(0));

			return expects_lr<socket_address>(std::move(known_node->first.address));
		}
		expects_promise_rt<socket_address> server_node::find_node_from_discovery()
		{
			if (!is_active())
				return expects_promise_rt<socket_address>(remote_exception::shutdown());

			auto early_test = find_node_from_mempool();
			if (early_test)
				return expects_promise_rt<socket_address>(std::move(*early_test));

			if (kernel::params().user.bootstrap_nodes.empty())
				return expects_promise_rt<socket_address>(remote_exception("no bootstrap nodes"));

			return coasync<expects_rt<socket_address>>([this]() -> expects_promise_rt<socket_address>
			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto lists = vector<string>(kernel::params().user.bootstrap_nodes.begin(), kernel::params().user.bootstrap_nodes.end());
				unique.unlock();

				auto device = std::random_device();
				auto random = std::mt19937(device());
				std::shuffle(std::begin(lists), std::end(lists), random);
				for (auto& bootstrap_url : lists)
				{
					size_t results = std::numeric_limits<size_t>::max();
					auto response = coawait(http::fetch(bootstrap_url));
					if (response)
					{
						auto addresses = format::tree::from_json(std::string_view(response->content.data.data(), response->content.data.size()));
						if (addresses)
						{
							auto mempool = storages::mempoolstate(); results = 0;
							for (auto& address : addresses->childs())
							{
								auto endpoint = system_endpoint(address.value.as_blob(), bootstrap_url);
								if (!endpoint.is_valid())
									continue;

								if (!kernel::params().is(network_type::regtest) && (storages::routing_util::is_address_reserved(endpoint.address) || storages::routing_util::is_address_private(endpoint.address)))
									continue;

								if (!connected_to_ip_address(endpoint.address) && mempool.apply_unknown_node(endpoint.address, false))
									++results;
							}
						}
					}

					if (kernel::params().user.consensus.logging && results != std::numeric_limits<size_t>::max())
						VI_INFO("bootstrap node %s %sresults found (addresses: %" PRIu64 ")", bootstrap_url.c_str(), results > 0 ? "" : "no ", (uint64_t)results);
				}

				auto late_test = find_node_from_mempool();
				if (!late_test)
					coreturn remote_exception(std::move(late_test.error().message()));

				coreturn expects_rt<socket_address>(std::move(*late_test));
			});
		}
		expects_promise_rt<uref<relay>> server_node::connect_to_physical_node(const socket_address& address)
		{
			if (!is_active())
				return expects_promise_rt<uref<relay>>(remote_exception::shutdown());

			auto duplicate = find_by_ip_address(address);
			if (duplicate)
				return expects_promise_rt<uref<relay>>(std::move(duplicate));
			else if (connected_to_ip_address(address))
				return expects_promise_rt<uref<relay>>(remote_exception("possible loopback"));

			return coasync<expects_rt<uref<relay>>>([this, address]() mutable -> expects_promise_rt<uref<relay>>
			{
				uptr<outbound_node> candidate = new outbound_node();
				append_pending_node(*candidate);
				auto status = coawait(candidate->connect_async(address, PEER_NOT_SECURE));
				erase_pending_node(*candidate);
				if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				auto& [node, wallet] = *runner_descriptor;
				auto node_message = string();
				algorithm::hashsig_t signature;
				uint64_t system_time = kernel::params().time.now_cpu();
				if (!algorithm::signing::sign(handshake_proof(node, system_time, &node_message), wallet.secret_key, signature))
					coreturn remote_exception("proof generation error");

				umutex<std::recursive_mutex> unique(exclusive);
				uref<relay> next = new relay(node_type::outbound, candidate.reset(), &inventory, claim_peer_index());
				append_node(uref(next));
				unique.unlock();
				cospawn([this, next]() mutable { pull_messages(std::move(next)); });

				auto abort = [&](remote_exception&& exception) -> remote_exception&&
				{
					next->close_channel(exception.message(), this);
					return std::move(exception);
				};
				auto result = coawait(query(uref(next), descriptors::perform_handshake(), { format::variable(node_message), format::variable(system_time), format::variable(signature.optimized_view()), format::variable(build_account_bindings()) }, kernel::params().user.tcp.timeout, true));
				if (!result)
					coreturn abort(std::move(result.error()));

				auto acknowledgement = perform_handshake(uref(next), *result, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto* peer_descriptor = next->as_descriptor();
				if (!peer_descriptor)
					coreturn abort(remote_exception("invalid descriptor"));

				auto subresult = coawait(query(uref(next), descriptors::perform_discovery(), build_state_exchange(uref(next)), kernel::params().user.tcp.timeout));
				if (!subresult)
					coreturn abort(remote_exception(std::move(subresult.error().message())));

				acknowledgement = perform_discovery(uref(next), *subresult, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto& params = kernel::mparams();
				uint64_t peer_time = result->args[1].as_uint64();
				uint64_t peer_latency = result->args[3].as_uint64();
				uint64_t latency_time = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
				uint64_t varying_peer_time = peer_time + (peer_latency + latency_time) / 2;
				params.time.adjust(peer_descriptor->first.address, (int64_t)system_time - (int64_t)varying_peer_time);
				synchronize_mempool_with(uref(next));
				coreturn expects_rt<uref<relay>>(std::move(next));
			}).then<expects_rt<uref<relay>>>([address](expects_rt<uref<relay>>&& result) -> expects_rt<uref<relay>>
			{
				if (!result)
				{
					auto mempool = storages::mempoolstate();
					mempool.apply_node_quality(address, -1, kernel::params().user.tcp.timeout);
					if (kernel::params().user.consensus.logging)
					{
						auto error_message = result.error().is_retry() ? string("timed out") : (result.error().is_shutdown() ? "host unreachable" : result.what());
						VI_WARN("node %s:%i channel open failed: %s", address.get_ip_address().or_else("[bad_address]").c_str(), (int)address.get_ip_port().or_else(0), error_message.c_str());
					}
				}
				return result;
			});
		}
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> server_node::connect_to_delegation_nodes(ledger::delegation_contract* contract, btree_set<algorithm::pubkeyhash_t>&& accounts, format::variables&& permit_args)
		{
			if (accounts.empty() || !contract || !contract->runner)
				return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(remote_exception("invalid arguments"));

			auto contract_runner_descriptor = find_descriptor(contract->runner->public_key_hash);
			if (!contract_runner_descriptor)
				return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(remote_exception("invalid runner"));

			btree_set<algorithm::pubkeyhash_t> early_results;
			for (auto& account : accounts)
			{
				if (find_descriptor(account) || find_by_account(account) || find_account_route(account))
					early_results.insert(account);
			}
			if (early_results.size() == accounts.size())
				return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(early_results));

			uint32_t delegation_type = contract->as_type();
			return coasync<expects_rt<btree_set<algorithm::pubkeyhash_t>>>([this, delegation_type, contract_runner_descriptor, accounts = std::move(accounts), early_results = std::move(early_results), permit_args = std::move(permit_args)]() mutable -> expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>
			{
				hash_map<algorithm::pubkeyhash_t, expects_promise_rt<void>> directly_connected_accounts;
				btree_set<algorithm::pubkeyhash_t> indirectly_connected_accounts;
				{
					auto mempool = storages::mempoolstate();
					for (auto& account : accounts)
					{
						auto it = early_results.find(account);
						if (it == early_results.end())
						{
							auto target = mempool.get_node(account);
							if (target && target->first.quality.reachable)
							{
								directly_connected_accounts[account] = connect_to_physical_node(target->first.address).then<expects_rt<void>>([this, account](expects_rt<uref<relay>>&& result) -> expects_rt<void>
								{
									if (!result)
										return result.error();

									if (!find_descriptor(account) && !find_by_account(account) && !find_account_route(account))
										return remote_exception("account not hosted");

									return expectation::met;
								});
							}
							else
								indirectly_connected_accounts.insert(account);
						}
						else
							directly_connected_accounts[account] = expects_promise_rt<void>(expectation::met);
					}
				}

				btree_set<algorithm::pubkeyhash_t> results;
				for (auto& [account, directly_connected_account] : directly_connected_accounts)
				{
					auto result = coawait(std::move(directly_connected_account));
					if (result)
						results.insert(account);
					else
						indirectly_connected_accounts.insert(account);
				}

				if (indirectly_connected_accounts.empty())
				{
				exit:
					coreturn is_active() ? expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(results)) : expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(remote_exception::shutdown());
				}

				socket_address best_address = runner_descriptor->first.address;
				bool has_inbound = false, has_outbound = false;
				{
					uint64_t best_preference = 0;
					umutex<std::recursive_mutex> unique(exclusive);
					for (auto& node : nodes)
					{
						auto* descriptor = node.second->as_descriptor();
						if (descriptor != nullptr && node.second->as_outbound_node() != nullptr)
						{
							uint64_t preference = descriptor->first.get_preference();
							if (best_preference < preference)
							{
								best_address = descriptor->first.address;
								best_preference = preference;
							}
							has_outbound = true;
						}
						else if (descriptor != nullptr && node.second->as_inbound_node() != nullptr)
							has_inbound = true;
					}
				}
				if (!has_outbound && !has_inbound)
					goto exit;

				algorithm::hashsig_t signature;
				auto address = socket_address_to_text_address(best_address);
				auto block_number = storages::chainstate().get_latest_block_number().or_else(1);
				if (!address || !algorithm::signing::sign(delegation_input_proof(best_address, block_number, delegation_type, permit_args, indirectly_connected_accounts), contract_runner_descriptor->second.secret_key, signature))
					goto exit;

				std::mutex mutex; promise<void> task;
				uint256_t id = algorithm::hashing::hash256i(*crypto::random_bytes(32));
				umutex<std::recursive_mutex> unique(sync.neighbor);
				delegation_nodes[id] = [this, &mutex, &task, &results, &indirectly_connected_accounts](const algorithm::pubkey_t& public_key, uref<relay>&& channel)
				{
					algorithm::pubkeyhash_t account;
					algorithm::signing::derive_public_key_hash(public_key, account);
					{
						umutex<std::mutex> unique(mutex);
						if (indirectly_connected_accounts.find(account) == indirectly_connected_accounts.end())
							return;

						indirectly_connected_accounts.erase(account);
						results.insert(account);
					}

					register_account_route(account, public_key, std::move(channel));
					umutex<std::mutex> unique(mutex);
					if (task.is_pending() && (indirectly_connected_accounts.empty() || !is_active()))
						task.set();
				};
				unique.unlock();

				format::variables args;
				args.reserve(indirectly_connected_accounts.size() + permit_args.size() + 6);
				args.push_back(format::variable(id));
				args.push_back(format::variable(signature.optimized_view()));
				args.push_back(format::variable(*address));
				args.push_back(format::variable(block_number));
				args.push_back(format::variable(delegation_type));
				args.push_back(format::variable((uint8_t)indirectly_connected_accounts.size()));
				for (auto& account : indirectly_connected_accounts)
					args.push_back(format::variable(account.optimized_view()));
				args.insert(args.end(), permit_args.begin(), permit_args.end());

				size_t notifications = notify_all(descriptors::broadcast_delegation(), std::move(args));
				if (notifications > 0 && kernel::params().user.consensus.logging)
					VI_DEBUG("awaiting delegation for %s broadcasted to %i nodes (type: %i, accounts: %i)", algorithm::signing::encode_address(contract_runner_descriptor->second.public_key_hash).c_str(), (int)delegation_type, (int)accounts.size(), (int)notifications);

				auto* queue = schedule::get();
				task_id timeout = queue->set_timeout(kernel::params().user.tcp.timeout, [&mutex, &task, &results, &indirectly_connected_accounts]()
				{
					umutex<std::mutex> unique(mutex);
					for (auto& account : indirectly_connected_accounts)
						results.erase(account);
					if (task.is_pending())
						task.set();
				});
				if (notifications > 0)
					coawait(std::move(task));

				queue->clear_timeout(timeout);
				unique.lock();
				delegation_nodes.erase(id);
				goto exit;
			});
		}
		expects_promise_rt<uint64_t> server_node::synchronize_mempool_with(uref<relay>&& from)
		{
			return coasync<expects_rt<uint64_t>>([this, from]() -> expects_promise_rt<uint64_t>
			{
				uint64_t cursor = 0, count = 0;
				btree_set<uint256_t> all_transaction_hashes;
				btree_set<uint256_t> transaction_hashes;
				while (is_active())
				{
					auto result = coawait(query(uref(from), descriptors::fetch_mempool(), { format::variable(cursor) }, kernel::params().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.size() < 2)
						break;

					size_t prev_transaction_hashes_size = transaction_hashes.size();
					size_t prev_all_transaction_hashes_size = all_transaction_hashes.size();
					{
						auto mempool = storages::mempoolstate();
						auto chain = storages::chainstate();
						for (size_t i = 1; i < result->args.size(); i++)
						{
							auto transaction_hash = result->args[i].as_uint256();
							if (!mempool.has_transaction(transaction_hash).or_else(false) && !chain.has_block_transaction(transaction_hash).or_else(false))
							{
								transaction_hashes.insert(transaction_hash);
								all_transaction_hashes.insert(transaction_hash);
							}
						}
					}
					if (prev_transaction_hashes_size != transaction_hashes.size() && prev_all_transaction_hashes_size >= all_transaction_hashes.size())
						break;

					while (!transaction_hashes.empty())
					{
						format::variables messages;
						for (size_t i = 0; i < kernel::params().message.transactions_per_query; i++)
						{
							messages.push_back(format::variable(*transaction_hashes.begin()));
							transaction_hashes.erase(transaction_hashes.begin());
							if (transaction_hashes.empty())
								break;
						}

						auto subresult = coawait(query(uref(from), descriptors::fetch_transactions(), std::move(messages), kernel::params().user.tcp.timeout));
						if (subresult && !subresult->args.empty())
						{
							for (auto& transaction : subresult->args)
							{
								format::ro_stream transaction_message = format::ro_stream(transaction.as_string());
								uptr<ledger::transaction_message> candidate = tangent::transactions::resolver::from_stream(transaction_message);
								if (!candidate || !candidate->load(transaction_message) || all_transaction_hashes.find(candidate->as_hash()) == all_transaction_hashes.end())
								{
									disconnect_node(uref(from), "mempool sync failed");
									coreturn remote_exception("invalid mempool transaction received");
								}

								accept_transaction(uref(from), std::move(candidate));
								++count;
							}
						}
					}

					const uint64_t transactions_count = kernel::params().message.hashes_per_query;
					cursor = result->args.front().as_uint64();
					if (result->args.size() < transactions_count)
						break;
				}
				coreturn count;
			}, true);
		}
		expects_promise_rt<void> server_node::resolve_and_verify_fork(const std::pair<uint256_t, tip_header>* fork)
		{
			return coasync<expects_rt<void>>([this, fork]() mutable -> expects_promise_rt<void>
			{
				if (!try_acquire_checkpointer())
					coreturn remote_exception("checkpointer busy");
				else
					release_checkpointer();

			parallel_resolution:
				std::mutex batch_mutex;
				auto& [new_tip_fork_hash, new_tip] = *fork;
				auto tip_label = uint256_to_label(new_tip_fork_hash);
				auto new_tip_number = new_tip.header.number;
				auto new_tip_hash = uint256_t(0);
				auto old_tip = storages::chainstate().get_latest_block_header();
				auto old_tip_number = old_tip ? old_tip->number : 0;
				if (old_tip_number > 0 && new_tip_number > old_tip_number)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_headers(), { format::variable(old_tip_number + 1), format::variable((uint8_t)1) }, kernel::params().user.tcp.timeout));
					if (result && result->args.size() >= 2)
					{
						auto collision_tip = ledger::block_header();
						auto message = format::ro_stream(result->args[1].as_string());
						if (collision_tip.load(message) && collision_tip.parent_hash == old_tip->as_hash())
						{
							new_tip_number = collision_tip.number;
							new_tip_hash = collision_tip.as_hash();
							old_tip_number = 0;
						}
					}
				}
				else if (old_tip_number > 0 && old_tip_number == new_tip_number && old_tip->as_hash() == new_tip.header.as_hash())
					coreturn expectation::met;

				while (is_active() && !verifier.slow && old_tip_number > 0 && new_tip_number > 0)
				{
					if (kernel::params().user.consensus.logging)
						VI_INFO("tip %s fetch: headers (range: [%" PRIu64 "; %" PRIu64 "])", tip_label.c_str(), new_tip_number - (kernel::params().message.headers_per_query > new_tip_number ? 1 : kernel::params().message.headers_per_query), new_tip_number);

					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_headers(), { format::variable(new_tip_number), format::variable(new_tip_number > old_tip_number ? new_tip_number - old_tip_number : kernel::params().message.headers_per_query) }, kernel::params().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.empty())
						break;

					new_tip_number = result->args.front().as_uint64();
					if (!new_tip_number || result->args.size() < 2)
						coreturn remote_exception("invalid branch");

					if (kernel::params().user.consensus.logging)
					{
						uint64_t blocks_count = (uint64_t)(result->args.size() - 1);
						VI_INFO("tip %s verify: headers (range: [%" PRIu64 "; %" PRIu64 "])", tip_label.c_str(), new_tip_number - (blocks_count > new_tip_number ? 1 : blocks_count), new_tip_number);
					}

					option<remote_exception> error = optional::none;
					uint256_t best_new_tip_hash = 0;
					uint64_t best_new_tip_number = 0;
					size_t batch_size = 64, block_count = result->args.size() - 1;
					size_t batch_count = block_count / batch_size + (block_count % batch_size == 0 ? 0 : 1);
					for (auto& task : parallel::for_loop(batch_count, 2 * batch_size, [&](size_t batch_index)
					{
						auto chain = storages::chainstate();
						auto parent_header = ledger::block_header();
						auto child_header = ledger::block_header();
						size_t begin = std::min(batch_index * batch_size, block_count);
						size_t end = std::min(begin + batch_size, block_count);
						for (size_t i = begin; i < end; i++)
						{
							auto message = format::ro_stream(result->args[i + 1].as_string());
							auto verification = child_header.load(message) ? child_header.verify_validity(parent_header.number > 0 ? &parent_header : nullptr) : expects_lr<void>(layer_exception("bad message"));
							if (!verification)
							{
								umutex<std::mutex> unique(batch_mutex);
								error = remote_exception(stringify::text("invalid block header (number: %" PRIu64 "): %s", child_header.number, verification.error().what()));
								break;
							}

							uint256_t branch_hash = child_header.as_hash(true);
							auto collision = chain.get_block_header_by_hash(branch_hash);
							if (collision || child_header.number <= 1)
							{
								umutex<std::mutex> unique(batch_mutex);
								if (!best_new_tip_number || best_new_tip_number < child_header.number)
								{
									best_new_tip_number = child_header.number;
									best_new_tip_hash = branch_hash;
								}
							}

							parent_header = child_header;
							parent_header.checksum = 0;
						}
					}))
						coawait(std::move(task));

					if (error)
						coreturn remote_exception(std::move(*error));

					new_tip_number = new_tip_number > block_count ? new_tip_number - block_count : 0;
					if (best_new_tip_number > 0 && best_new_tip_hash > 0)
					{
						new_tip_hash = best_new_tip_hash;
						new_tip_number = best_new_tip_number;
						old_tip_number = 0;
					}
				}

				if (new_tip_hash > 0 && kernel::params().user.consensus.logging)
					VI_INFO("tip %s collision (number: %" PRIu64 ")", tip_label.c_str(), new_tip_number);

				new_tip_number = new_tip_hash > 0 ? 0 : 1;
				if (verifier.slow)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_block(), { format::variable(new_tip_number > 0 ? uint256_t(0) : new_tip_hash), format::variable(new_tip_number) }, kernel::params().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.size() != 1)
						coreturn remote_exception("failed to receive the block");

					ledger::block_evaluation tip;
					format::ro_stream block_message = format::ro_stream(result->args.front().as_string());
					if (!tip.block.load(block_message))
						coreturn remote_exception("invalid block message");

					auto status = accept_block(uref(new_tip.state), tip, &new_tip.header);
					if (!status)
						coreturn remote_exception(std::move(status.error().message()));

					if (kernel::params().user.consensus.logging)
						VI_INFO("tip %s approved (fast sync reactivated)", tip_label.c_str());

					verifier.slow = false;
					goto parallel_resolution;
				}

				ledger::block_evaluation tip;
				option<expects_rt<exchange>> cached_result = optional::none;
				expects_rt<exchange> result = expects_rt<exchange>(remote_exception());
				btree_map<uint64_t, ledger::block_body> candidate_blocks;
				vector<hash_map<uint64_t, ledger::block_body>> split_candidate_blocks;
				while (is_active() && (new_tip_number > 0 || new_tip_hash > 0))
				{
					if (!cached_result)
					{
						if (kernel::params().user.consensus.logging)
							VI_INFO("tip %s fetch: blocks (size: <%.2f kb)", tip_label.c_str(), (double)kernel::params().message.blocks_size_per_query / 1000.0);

						result = coawait(query(uref(new_tip.state), descriptors::fetch_blocks(), { format::variable(new_tip_number > 0 ? uint256_t(0) : new_tip_hash), format::variable(new_tip_number) }, kernel::params().user.tcp.timeout));
					}
					else
						result = std::move(*cached_result);
					if (!result)
						coreturn result.error();
					else if (result->args.empty())
						break;

					size_t batch_size = 64, block_count = result->args.size();
					size_t batch_count = block_count / batch_size + (block_count % batch_size == 0 ? 0 : 1);
					if (block_count > batch_size && kernel::params().user.consensus.logging)
						VI_INFO("tip %s verify: proofs (size: %" PRIu64 ")", tip_label.c_str(), (uint64_t)block_count);

					split_candidate_blocks.resize(batch_count);
					for (auto& task : parallel::for_loop(batch_count, 2 * batch_size, [&](size_t batch_index)
					{
						size_t begin = std::min(batch_index * batch_size, block_count);
						size_t end = std::min(begin + batch_size, block_count);
						auto& queue = split_candidate_blocks[batch_index];
						queue.reserve(end - begin);
						queue.clear();

						algorithm::pubkeyhash_t producer;
						for (size_t i = begin; i < end; i++)
						{
							ledger::block_body block;
							format::ro_stream block_message = format::ro_stream(result->args[i].as_string());
							if (!block.load(block_message) || !block.recover_hash(producer) || !block.verify_proof(producer))
								break;

							queue[block.number] = std::move(block);
						}
					}))
						coawait(std::move(task));

					candidate_blocks.clear();
					for (auto& queue : split_candidate_blocks)
					{
						for (auto& [key, value] : queue)
							candidate_blocks.emplace(key, std::move(value));
					}

					auto next_tip_number = candidate_blocks.empty() ? 0 : (candidate_blocks.rbegin()->first + 1);
					if (kernel::params().user.consensus.logging)
						VI_INFO("tip %s prefetch: blocks (size: <%.2f kb)", tip_label.c_str(), (double)kernel::params().message.blocks_size_per_query / 1000.0);

					auto pending_cached_result = next_tip_number > 0 ? query(uref(new_tip.state), descriptors::fetch_blocks(), { format::variable(uint8_t(0)), format::variable(next_tip_number) }, kernel::params().user.tcp.timeout) : expects_promise_rt<exchange>(remote_exception::shutdown());
					for (auto& [block_number, block] : candidate_blocks)
					{
						tip.block = std::move(block);
						new_tip_hash = tip.block.as_hash();
						new_tip_number = tip.block.number + 1;
						auto status = accept_block(uref(new_tip.state), tip, &new_tip.header, false);
						if (!status)
							coreturn remote_exception(std::move(status.error().message()));
						else if (!is_active())
							coreturn remote_exception::shutdown();
					}

					if (candidate_blocks.size() < result->args.size())
						coreturn remote_exception("stopping due to " + to_string(result->args.size() - candidate_blocks.size()) + " blocks with invalid proofs");

					if (next_tip_number > 0 && next_tip_number == new_tip_number)
					{
						if (kernel::params().user.consensus.logging && pending_cached_result.is_pending())
							VI_INFO("tip %s prefetch: awaiting completion", tip_label.c_str());

						cached_result = std::move(coawait(std::move(pending_cached_result)));
					}
					else
						cached_result = optional::none;
				}
				if (new_tip_hash > 0)
					finalize_pending_tip(uref(new_tip.state), new_tip_hash, new_tip_number - 1);

				coreturn expectation::met;
			});
		}
		expects_promise_rt<exchange> server_node::query(uref<relay>&& from, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call)
		{
			if (!force_call && !from->fully_valid())
				return expects_promise_rt<exchange>(remote_exception("node is not in valid state (offline/unauthorized)"));
			else if (!is_active())
				return expects_promise_rt<exchange>(remote_exception::shutdown());

			if (kernel::params().user.consensus.logging)
				VI_DEBUG("node %s query \"%.*s\" out: %s", from->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str());

			auto result = from->push_query(descriptor, std::move(args), timeout_ms, false);
			push_messages(std::move(from));
			return result;
		}
		expects_promise_rt<exchange> server_node::indirect_query(const algorithm::pubkeyhash_t& account, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call)
		{
			if (!is_active())
				return expects_promise_rt<exchange>(remote_exception::shutdown());

			auto direct_node = find_by_account(account);
			if (direct_node)
				return query(std::move(direct_node), descriptor, std::move(args), timeout_ms, force_call);

			auto indirect_node = find_account_route(account);
			if (!indirect_node)
				return expects_promise_rt<exchange>(remote_exception::retry_later());

			if (kernel::params().user.consensus.logging)
				VI_DEBUG("node %s forward query \"%.*s\" out: %s", indirect_node->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str());

			args.insert(args.begin(), format::variable((uint8_t)0));
			args.insert(args.begin(), format::variable(account.view()));
			auto result = indirect_node->push_query(descriptor, std::move(args), timeout_ms, true);
			push_messages(std::move(indirect_node));
			return result;
		}
		expects_lr<void> server_node::notify(uref<relay>&& from, const callable::descriptor& descriptor, format::variables&& args)
		{
			if (!from->fully_valid())
				return layer_exception("node is not in valid state (offline/unauthorized)");
			else if (!is_active())
				return layer_exception("relay is shutting down");

			if (kernel::params().user.consensus.logging)
				VI_DEBUG("node %s notify \"%.*s\" out: %s", from->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str());

			if (!from->push_event(descriptor, std::move(args)))
				return layer_exception("duplicate notification");

			push_messages(std::move(from));
			return expectation::met;
		}
		size_t server_node::notify_all(const callable::descriptor& descriptor, format::variables&& args)
		{
			return notify_all_except(nullptr, descriptor, std::move(args));
		}
		size_t server_node::notify_all_except(uref<relay>&& exception, const callable::descriptor& descriptor, format::variables&& args)
		{
			auto receivers = vector<uref<relay>>();
			{
				umutex<std::recursive_mutex> unique(exclusive);
				receivers.reserve(nodes.size());
				for (auto& node : nodes)
					receivers.push_back(node.second);
			}

			size_t responses = 0;
			for (auto& node : receivers)
				responses += *exception != *node ? notify(uref(node), descriptor, format::variables(args)) ? 1 : 0 : 0;
			return responses;
		}
		format::variables server_node::build_state_exchange(uref<relay>&& from)
		{
			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			auto tip = chain.get_latest_block_header();
			auto* descriptor = from->as_descriptor();
			auto address = descriptor ? socket_address_to_text_address(descriptor->first.address).or_else(string()) : string();
			format::variables args =
			{
				format::variable(address),
				format::variable(tip ? tip->as_hash() : uint256_t(0)),
				format::variable(mempool.get_transactions_count().or_else(0))
			};

			auto random_nodes = mempool.get_sample_nodes_with(kernel::params().message.hashes_per_query).or_else(vector<storages::node_location_pair>());
			args.reserve(args.size() + random_nodes.size());
			for (auto& [node_account, node_address] : random_nodes)
			{
				auto text_address = socket_address_to_text_address(node_address);
				if (text_address)
					args.push_back(format::variable(*text_address));
			}
			return args;
		}
		void server_node::bind_event(const callable::descriptor& descriptor, event_callback&& on_event_callback, bool guarded)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.event = std::move(on_event_callback);
			callable.guarded = guarded;
		}
		void server_node::bind_query(const callable::descriptor& descriptor, query_callback&& on_query_callback, bool guarded)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.query = std::move(on_query_callback);
			callable.guarded = guarded;
		}
		void server_node::bind_async_query(const callable::descriptor& descriptor, async_query_callback&& on_query_callback, bool guarded)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.async_query = std::move(on_query_callback);
			callable.guarded = guarded;
		}
		void server_node::pull_messages(uref<relay>&& from)
		{
			VI_ASSERT(from, "state should be set");
			auto* stream = from->as_socket();
			if (!stream)
				return disconnect_node(std::move(from), "connection lost");

			uint8_t buffer[CHUNK_SIZE];
			size_t max_buffer_size = sizeof(buffer);
			uint64_t next_pull_time = 0, message_latency = 100;
			while (from->bandwidth.check(max_buffer_size, next_pull_time))
			{
				auto size = stream->read(buffer, std::min(max_buffer_size, sizeof(buffer)));
				if (!size)
				{
					if (size.error() != std::errc::operation_would_block)
						return disconnect_node(std::move(from), "connection reset");

					multiplexer::get()->when_readable(stream, [this, from](socket_poll event) mutable
					{
						if (packet::is_done(event))
							pull_messages(std::move(from));
						else if (packet::is_error(event))
							disconnect_node(std::move(from), "connection reset");
					});
					return;
				}

				from->push_incoming(buffer, *size);
				from->bandwidth.spend(*size);
				while (from->incoming_size() >= sizeof(message_header))
				{
					umutex<std::recursive_mutex> unique(from->mutex);
					message_header header;
					memcpy(&header, from->incoming_buffer(), sizeof(message_header));
					header.magic = os::hw::to_endianness(os::hw::endian::little, header.magic);
					header.length = os::hw::to_endianness(os::hw::endian::little, header.length);
					header.checksum = os::hw::to_endianness(os::hw::endian::little, header.checksum);
					if (header.magic != kernel::params().message.packet_magic || header.length > kernel::params().message.max_body_size)
					{
						unique.unlock();
					abort:
						from->report_call(-1, message_latency);
						disconnect_node(std::move(from), "invalid message header");
						return;
					}
					else if (from->incoming_size() < sizeof(message_header) + header.length)
						break;

					exchange message;
					auto body = format::ro_stream(std::string_view((char*)from->incoming_buffer() + sizeof(message_header), header.length));
					bool valid = header.checksum == algorithm::hashing::hash32d(body.data) && message.load_payload(body);
					from->erase_incoming(sizeof(message_header) + body.data.size());
					unique.unlock();
					if (!valid)
						goto abort;

					message_latency = message.calculate_latency();
					if (kernel::params().user.consensus.logging)
						VI_DEBUG("node %s message in: %s", from->peer_address().c_str(), message.as_tree().as_json().substr(0, 2048).c_str());

					message.callee = runner_descriptor;
					switch (message.type)
					{
						case exchange::side::event:
						{
							if (message.descriptor == 0 && message.session > 0)
							{
								from->resolve_query(std::move(message));
								break;
							}
							else if (message.session > 0)
								goto abort;

							auto it = callables.find(message.descriptor);
							if (it == callables.end() || !it->second.event || (it->second.guarded && !from->as_descriptor()))
								goto abort;

							auto slot = from->inventory_slot_id();
							if (slot != NULL_SLOT && !inventory.insert(message.as_inventory_hash(true), slot))
								break;

							auto result = it->second.event(this, uref(from), message);
							if (!result && kernel::params().user.consensus.logging)
								VI_WARN("node %s event \"%.*s\" error: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
							else if (result && kernel::params().user.consensus.logging)
								VI_DEBUG("node %s event \"%.*s\" result: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? "OK" : "RETRY");
							break;
						}
						case exchange::side::query:
						{
							auto it = callables.find(message.descriptor);
							if (it == callables.end() || (!it->second.query && !it->second.async_query) || !message.session || (it->second.guarded && !from->as_descriptor()))
								goto abort;

							if (it->second.query)
							{
								auto result = it->second.query(this, uref(from), message);
								if (!result && kernel::params().user.consensus.logging)
									VI_WARN("node %s query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
								else if (result && kernel::params().user.consensus.logging)
									VI_DEBUG("node %s query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

								from->push_query_response(message.session, pack_query_result(result));
								push_messages(uref(from));
							}
							else if (it->second.async_query)
							{
								auto name = it->second.name;
								it->second.async_query(this, uref(from), message).when([this, name, message_latency, next_pull_time, from = std::move(from), message = std::move(message)](expects_rt<format::variables>&& result) mutable
								{
									if (!result && kernel::params().user.consensus.logging)
										VI_WARN("node %s async-query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)name.size(), name.data(), result.what().c_str());
									else if (result && kernel::params().user.consensus.logging)
										VI_DEBUG("node %s async-query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)name.size(), name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

									from->push_query_response(message.session, pack_query_result(result));
									push_messages(uref(from));
									from->report_call(1, message_latency);
									from->deferred_pull = schedule::get()->set_timeout(next_pull_time, [this, from]() mutable
									{
										from->deferred_pull = INVALID_TASK_ID;
										pull_messages(std::move(from));
									});
								});
								return;
							}
							break;
						}
						case exchange::side::forward:
						{
							auto it = callables.find(message.descriptor);
							if (it == callables.end() || (!it->second.query && !it->second.async_query) || !message.session || (it->second.guarded && !from->as_descriptor()))
								goto abort;

							auto account = message.args.size() < 2 ? algorithm::pubkeyhash_t() : algorithm::pubkeyhash_t(message.args[0].as_string());
							auto hops = message.args.size() < 2 ? (uint8_t)MAX_FORWARD_HOPS : (uint8_t)message.args[1].as_uint8();
							if (account.empty())
								goto abort;

							auto session = message.session;
							auto forward_descriptor = find_descriptor(account);
							message.args.erase(message.args.begin(), message.args.begin() + 2);
							if (forward_descriptor)
							{
								message.callee = forward_descriptor;
								if (it->second.query)
								{
									auto result = it->second.query(this, uref(from), message);
									if (!result && kernel::params().user.consensus.logging)
										VI_WARN("node %s forward query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
									else if (result && kernel::params().user.consensus.logging)
										VI_DEBUG("node %s forward query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

									from->push_query_response(message.session, pack_query_result(result));
									push_messages(uref(from));
								}
								else if (it->second.async_query)
								{
									auto name = it->second.name;
									it->second.async_query(this, uref(from), message).when([this, message_latency, next_pull_time, name, from = std::move(from), message = std::move(message)](expects_rt<format::variables>&& result) mutable
									{
										if (!result && kernel::params().user.consensus.logging)
											VI_WARN("node %s forward async-query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)name.size(), name.data(), result.what().c_str());
										else if (result && kernel::params().user.consensus.logging)
											VI_DEBUG("node %s forward async-query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)name.size(), name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

										from->push_query_response(message.session, pack_query_result(result));
										push_messages(uref(from));
										from->report_call(1, message_latency);
										from->deferred_pull = schedule::get()->set_timeout(next_pull_time, [this, from]() mutable
										{
											from->deferred_pull = INVALID_TASK_ID;
											pull_messages(std::move(from));
										});
									});
									return;
								}
							}
							else
							{
								auto route = hops >= MAX_FORWARD_HOPS ? uref<relay>(nullptr) : find_account_route(account);
								if (route && route->fully_valid())
								{
									auto method = callable::descriptor(it->second.name, it->first);
									message.args.insert(message.args.begin(), format::variable((uint8_t)(hops + 1)));
									message.args.insert(message.args.begin(), format::variable(account.view()));
									route->push_query(method, std::move(message.args), kernel::params().user.tcp.timeout, true).when([this, from, method, session](expects_rt<exchange>&& result) mutable
									{
										if (!result && kernel::params().user.consensus.logging)
											VI_WARN("node %s transit query \"%.*s\" error in: %s", from->peer_address().c_str(), (int)method.name.size(), method.name.data(), result.what().c_str());
										else if (result && kernel::params().user.consensus.logging)
											VI_DEBUG("node %s transit query \"%.*s\" result in: %s", from->peer_address().c_str(), (int)method.name.size(), method.name.data(), result ? result->args.empty() ? "OK" : stringify::text("[%i values]", (int)result->args.size()).c_str() : "RETRY");

										from->push_query_response(session, pack_query_result(result ? expects_rt<format::variables>(std::move(result->args)) : expects_rt<format::variables>(result.error())));
										push_messages(std::move(from));
									});
									push_messages(uref(route));
								}
								else
								{
									from->push_query_response(session, pack_query_result(remote_exception("route unavailable")));
									push_messages(std::move(from));
								}
							}
							break;
						}
						default:
							goto abort;
					}
					from->report_call(1, message_latency);
				}
			}

			from->deferred_pull = schedule::get()->set_timeout(next_pull_time, [this, from]() mutable
			{
				from->deferred_pull = INVALID_TASK_ID;
				pull_messages(std::move(from));
			});
		}
		void server_node::push_messages(uref<relay>&& from)
		{
			VI_ASSERT(from, "state and abort callback should be set");
			auto* stream = from->as_socket();
			if (!stream)
				return disconnect_node(std::move(from), "connection lost");
			else if (!from->prepare_outgoing())
				return;

			stream->write_queued(from->outgoing_buffer(), from->outgoing_size(), [this, stream, from](socket_poll event) mutable
			{
				from->clear_outgoing();
				if (packet::is_done(event))
					cospawn([this, from = std::move(from)]() mutable { push_messages(std::move(from)); });
				else if (packet::is_error(event))
					disconnect_node(std::move(from), "connection reset");
			}, false);
		}
		void server_node::disconnect_node(uref<relay>&& from, const std::string_view& message)
		{
			VI_ASSERT(from, "state should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto* inbound_node = from->as_inbound_node();
			auto* outbound_node = from->as_outbound_node();
			from->close_channel(message, this);
			if (inbound_node != nullptr)
			{
				inbound_node->abort();
				finalize(inbound_node);
			}
			if (outbound_node != nullptr)
				outbound_node->release();
			erase_node(std::move(from));
		}
		void server_node::disconnect_node_by_account(const algorithm::pubkeyhash_t& account, const std::string_view& message)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* descriptor = node.second->as_descriptor();
				if (descriptor != nullptr && descriptor->second.public_key_hash.equals(account))
				{
					unique.unlock();
					return disconnect_node(uref(node.second), message);
				}
			}
		}
		void server_node::append_node(uref<relay>&& from)
		{
			VI_ASSERT(from, "node should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(from->as_instance());
			if (it != nodes.end() && *it->second == *from)
				return;

			auto& node = nodes[from->as_instance()];
			VI_ASSERT(!node || *node == *from, "invalid state");
			node = std::move(from);
		}
		void server_node::erase_node(uref<relay>&& from)
		{
			VI_ASSERT(from, "node should be set");
			auto* instance = from->as_instance();
			if (instance != nullptr)
				return erase_node_by_instance(instance);

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto it = nodes.begin(); it != nodes.end(); it++)
			{
				if (*it->second == *from)
					return erase_node_by_iterator(it);
			}
		}
		void server_node::erase_node_by_instance(void* instance)
		{
			VI_ASSERT(instance != nullptr, "instance should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			erase_node_by_iterator(it);
		}
		void server_node::erase_node_by_iterator(hash_map<void*, uref<relay>>::iterator& it)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			if (it == nodes.end())
				return;

			uref<relay> from = std::move(it->second);
			inventory.forget(from->inventory_slot_id());
			nodes.erase(it);
			unique.unlock();
			erase_account_routes_for(from->as_instance());
			clear_tip(*from, nullptr);
			run_topology_optimization();
		}
		void server_node::append_pending_node(outbound_node* base)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			pending_nodes.insert(base);
		}
		void server_node::erase_pending_node(outbound_node* base)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			pending_nodes.erase(base);
		}
		void server_node::on_request_open(inbound_node* node)
		{
			VI_ASSERT(node != nullptr, "node should be set");
			if (!is_active())
				return;

			auto from = find_node_by_instance(node);
			if (from)
				return pull_messages(std::move(from));

			node->stream->set_io_timeout(kernel::params().user.tcp.timeout);
			umutex<std::recursive_mutex> unique(exclusive);
			from = new relay(node_type::inbound, node, &inventory, claim_peer_index());
			append_node(uref(from));
			unique.unlock();
			pull_messages(std::move(from));
		}
		bool server_node::try_acquire_checkpointer()
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			if (verifier.busy.load())
				return false;

			verifier.busy = true;
			return true;
		}
		void server_node::release_checkpointer()
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			verifier.busy = false;
		}
		bool server_node::run_superchain_sync(const algorithm::asset_id& asset)
		{
			if (!kernel::params().user.superchain.listener)
				return false;

			auto* offchain = superchain::bridge::get();
			auto* listener = offchain->get_network_instance(asset);
			if (!listener || listener->connections.empty())
				return false;

			string blockchain = algorithm::asset::blockchain_of(listener->asset);
			string task = stringify::text(TASK_SUPERCHAIN_SYNC "_%s", blockchain.c_str());
			stringify::to_lower(task);
			return control_sys.async_task_if_none(task, [this, task, blockchain, offchain, listener]() -> promise<void>
			{
				uint64_t start_time = kernel::params().time.now_cpu();
				uint64_t frequency = kernel::params().user.superchain.polling_frequency;
				uint64_t retry_after_timestamp = std::numeric_limits<uint64_t>::max();
				VI_INFO("%s block pulling: resuming now", blockchain.c_str());
			retry:
				while (is_active())
				{
					auto result = coawait(offchain->link_transactions(listener->asset));
					if (!result)
					{
						if (kernel::params().user.superchain.logging && !listener->options.state.retry_after_time && !result.error().is_retry())
							VI_WARN("%s block rejection: %s", blockchain.c_str(), result.error().what());

						if (!is_active())
							coreturn_void;
						else if (result.error().is_retry_after())
							retry_after_timestamp = std::min(retry_after_timestamp, result.error().retry_after_timestamp());
						break;
					}

					umutex<std::recursive_mutex> unique(sync.fetcher);
					auto it = fetchers.find(listener->asset);
					size_t requests = it != fetchers.end() ? it->second.requests : 0;
					if (it != fetchers.end())
						it->second.requests = 0;

					unique.unlock();
					for (auto& log : *result)
					{
						if (kernel::params().user.superchain.logging)
							log.report_logs(listener->asset, listener->options, requests);
						if (!log.receipts.empty())
							dispatch_transaction_logs(listener->asset, std::move(log)).report("failed to dispatch transaction logs");
					}
				}

				if (!is_active())
					coreturn_void;

				uint64_t end_time = kernel::params().time.now_cpu();
				uint64_t delta_time = end_time - start_time;
				uint64_t timeout = std::max<uint64_t>(retry_after_timestamp != std::numeric_limits<uint64_t>::max() ? (retry_after_timestamp - std::min(end_time, retry_after_timestamp)) : (frequency - std::min(delta_time, frequency)), 2000);
				if (!timeout)
					goto retry;

				VI_INFO("%s block pulling: resumes in %" PRIu64 " ms", blockchain.c_str(), timeout);
				control_sys.upsert_timeout(task + "_runner", timeout, [this, listener]() { run_superchain_sync(listener->asset); });
				coreturn_void;
			});
		}
		bool server_node::run_topology_optimization()
		{
			return control_sys.async_task_if_none(TASK_TOPOLOGY_OPTIMIZATION, [this]() -> promise<void>
			{
				bool has_dropped_nodes = false, has_disabled_outbounds = !kernel::params().user.consensus.max_outbound_connections;
				auto too_many_outbound_nodes = [this]() { return size_of(node_type::outbound) >= kernel::params().user.consensus.max_outbound_connections; };
				hash_set<uint256_t> passed_candidates;
				expects_rt<socket_address> candidate_address = socket_address();
				while (is_active() && !has_disabled_outbounds && candidate_address)
				{
					candidate_address = coawait(find_node_from_discovery());
					if (!candidate_address || find_by_ip_address(*candidate_address))
						break;

					if (too_many_outbound_nodes())
					{
						if (has_dropped_nodes)
							break;

						bool no_droppable_nodes = !is_active(); has_dropped_nodes = true;
						while (!no_droppable_nodes && too_many_outbound_nodes() && !find_by_ip_address(*candidate_address))
						{
							algorithm::pubkeyhash_t worst_account;
							uint64_t worst_preference = std::numeric_limits<uint64_t>::max();
							umutex<std::recursive_mutex> unique(exclusive);
							for (auto& node : nodes)
							{
								auto* descriptor = node.second->as_descriptor();
								uint64_t preference = descriptor && node.second->as_outbound_node() ? descriptor->first.get_preference() : std::numeric_limits<uint64_t>::max();
								if (worst_preference > preference)
								{
									worst_account = descriptor->second.public_key_hash;
									worst_preference = preference;
								}
							}

							no_droppable_nodes = is_active() ? worst_account.empty() : true;
							if (!no_droppable_nodes)
								disconnect_node_by_account(worst_account, "trying another node");
						}
						if (no_droppable_nodes || find_by_ip_address(*candidate_address))
							break;
					}

					auto ip_value = candidate_address->get_ip_value().or_else(0);
					auto ip_port = candidate_address->get_ip_port().or_else(0);
					auto ip_address = uint256_t(ip_value, ip_port);
					bool duplicate = passed_candidates.find(ip_address) != passed_candidates.end();
					if (duplicate || !coawait(connect_to_physical_node(*candidate_address)))
						storages::mempoolstate().apply_cooldown_node(*candidate_address, true, false);
					passed_candidates.insert(ip_address);
				}

				finalize_pending_tip(nullptr, uint256_t(0), 0);
				coreturn_void;
			});
		}
		bool server_node::run_mempool_vacuum()
		{
			return control_sys.task_if_none(TASK_MEMPOOL_VACUUM, [this](system_task&&)
			{
				if (is_syncing())
					return;

				auto mempool = storages::mempoolstate();
				auto hashset = hash_set<uint256_t>();
				size_t offsets[2] = { 0, 0 };
				size_t deletions = 0;
				while (true)
				{
					auto queue = mempool.get_transactions_by_quality((uint8_t)storages::transaction_queue::commitment, offsets, ELEMENTS_BULK);
					if (!queue || queue->empty())
						break;

					for (auto& candidate_tx : *queue)
					{
						auto candidate_hash = candidate_tx->as_hash();
						auto simulation = ledger::executor_context::calculate_tx_gas(*candidate_tx);
						if (!simulation)
						{
							hashset.insert(candidate_hash);
							if (kernel::params().user.consensus.logging)
							{
								auto purpose = candidate_tx->as_typename();
								VI_WARN("transaction %s %.*s vacuum reason: %s", uint256_to_label(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), simulation.error().what());
							}
						}
					}
				}

				if (!hashset.empty())
				{
					mempool.remove_transactions_by_hash(hashset).report("mempool tx vacuum failure");
					deletions += hashset.size();
				}

				auto chain = storages::chainstate();
				auto expirations = mempool.expire_transactions([&](const algorithm::pubkeyhash_t& target) -> uint64_t
				{
					auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(target), 0);
					auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
					return value ? value->nonce : 0;
				});

				deletions += expirations.or_else(0);
				expirations.report("mempool tx vacuum failure");
				if (deletions > 0 && kernel::params().user.consensus.logging)
					VI_INFO("mempool transaction vacuum: OK (transactions: %i)", (int)deletions);
			});
		}
		bool server_node::run_mempool_sync()
		{
			return control_sys.async_task_if_none(TASK_MEMPOOL_SYNC, [this]() -> promise<void>
			{
				if (is_syncing())
					coreturn_void;

				umutex<std::recursive_mutex> unique(exclusive);
				if (nodes.empty())
					coreturn_void;

				auto it = nodes.begin();
				std::advance(it, math<size_t>::random() % nodes.size());
				auto descriptor = it->second->as_descriptor();
				if (!descriptor)
					coreturn_void;

				auto random = find_by_account(descriptor->second.public_key_hash);
				unique.unlock();
				if (!random)
					coreturn_void;

				auto transactions_count = coawait(synchronize_mempool_with(std::move(random)));
				if (transactions_count.or_else(1) > 0 && kernel::params().user.consensus.logging)
				{
					if (transactions_count)
						VI_INFO("mempool sync: OK (transactions: +%" PRIu64 ")", *transactions_count);
					else
						VI_ERR("mempool sync failed: %s", transactions_count.what().c_str());
				}
				coreturn_void;
			});
		}
		bool server_node::run_fork_resolution()
		{
			return control_sys.async_task_if_none(TASK_FORK_RESOLUTION, [this]() -> promise<void>
			{
				auto best_fork = get_best_tip_header();
				if (!best_fork)
					coreturn_void;
			retry:
				auto candidate_hash = best_fork->first;
				auto from = uref(best_fork->second.state);
				auto status = coawait(resolve_and_verify_fork(best_fork.address()));
				verifier.slow = status ? false : (!status.error().is_retry() && !status.error().is_shutdown());
				if (!status && kernel::params().user.consensus.logging)
					VI_WARN("%s (tip %.8s.. dropped)", status.what().c_str(), uint256_to_label(candidate_hash).c_str());

				auto new_best_fork = get_best_tip_header();
				clear_tip(*from, status ? &best_fork->second.header : nullptr);
				if (new_best_fork && new_best_fork->first != candidate_hash && best_fork->second.header < new_best_fork->second.header)
				{
					best_fork = std::move(new_best_fork);
					goto retry;
				}

				for (auto& [account, descriptor] : descriptors)
					fill_node_services(descriptor);

				coreturn_void;
			});
		}
		bool server_node::run_attestation_resolution()
		{
			bool has_attestation = false;
			for (auto& [account, descriptor] : descriptors)
				has_attestation = has_attestation || descriptor.first.services.has_attestation;
			if (!has_attestation || is_syncing())
				return false;

			return control_sys.task_if_none(TASK_ATTESTATION_RESOLUTION, [this](system_task&&)
			{
				size_t offset = 0;
				auto mempool = storages::mempoolstate();
				auto expirations = mempool.expire_attestations();
				if (expirations)
				{
					if (*expirations > 0 && kernel::params().user.consensus.logging)
						VI_INFO("mempool attestation vacuum: OK (attestations: %i)", (int)*expirations);
				}
				else if (kernel::params().user.consensus.logging)
					VI_ERR("mempool attestation vacuum failed: %s", expirations.what().c_str());

			next_attestation:
				auto attestation_hash = mempool.pull_best_attestation_hash(offset);
				if (!attestation_hash)
					return;

				auto attestation = mempool.get_attestation(*attestation_hash);
				auto status = attestation ? accept_attestation(*attestation, false) : expects_rt<bool>(remote_exception(std::move(attestation.error().message())));
				if (!status)
				{
					if (attestation && (status.error().is_retry() || status.error().is_shutdown()))
					{
						for (auto& [commitment_hash, commitments] : attestation->commitments)
						{
							auto proof = attestation->proofs.find(commitment_hash);
							if (proof == attestation->proofs.end())
								continue;

							auto args = format::variables({ format::variable(attestation->asset), format::variable(proof->second.as_message().data) });
							for (auto& commitment_signature : commitments)
							{
								algorithm::pubkeyhash_t attester;
								if (algorithm::signing::recover_hash(commitment_hash, attester, commitment_signature) && find_descriptor(attester) != nullptr)
									args.push_back(format::variable(commitment_signature.view()));
							}

							size_t notifications = args.size() > 2 ? notify_all(descriptors::broadcast_attestation(), std::move(args)) : 0;
							if (notifications > 0 && kernel::params().user.consensus.logging)
								VI_DEBUG("attestation %s re-broadcasted to %i nodes", uint256_to_label(commitment_hash).c_str(), (int)notifications);
						}
						if (kernel::params().user.consensus.logging)
							VI_INFO("attestation %s pending (proofs: %i, commitments: %i)", uint256_to_label(*attestation_hash).c_str(), (int)attestation->proofs.size(), (int)attestation->commitments.size());
					}
					else if (kernel::params().user.consensus.logging)
						VI_INFO("attestation %s verification failed: %s", uint256_to_label(*attestation_hash).c_str(), status.what().c_str());
					++offset;
				}
				else if (*status)
					mempool.remove_attestation(*attestation_hash).report("failed to remove attestation");
				else
					++offset;
				goto next_attestation;
			});
		}
		bool server_node::run_block_production()
		{
			if (!has_production() || is_syncing())
				return false;

			if (prover.queued)
			{
				control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
				prover.queued = false;
			}

			return control_sys.task_if_none(TASK_BLOCK_PRODUCTION, [this](system_task&&)
			{
			next_block:
				if (!is_active() || (kernel::params().is(network_type::regtest) && !storages::mempoolstate().get_transactions_count().or_else(0)))
					return;

				auto produced_block = produce_block();
				if (produced_block)
					goto next_block;

				auto& action = produced_block.error();
				if (!action.is_retry_after())
					return;

				prover.queued = control_sys.upsert_timeout(TASK_BLOCK_PRODUCTION, action.retry_after_timestamp(), [this]()
				{
					control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
					run_block_production();
				});
			});
		}
		bool server_node::run_block_dispatcher()
		{
			if (is_syncing())
				return false;

			auto chain = storages::chainstate();
			auto stride = kernel::params().is(network_type::regtest) ? 0 : 1;
			auto tip_number = chain.get_latest_block_number().or_else(0);
			if (tip_number <= stride)
				return false;

			auto tip_header = chain.get_block_header_by_number(tip_number);
			if (!tip_header || tip_header->priority != 0)
				return false;

			auto dispatch_number = tip_number - stride;
			auto dispatch_header = tip_number == dispatch_number ? tip_header : chain.get_block_header_by_number(dispatch_number);
			if (!dispatch_header || dispatch_header->priority != 0)
				return false;

			return control_sys.async_task_if_none(TASK_BLOCK_DISPATCHER, [this, dispatch_number]() -> promise<void>
			{
				auto adapter = server_delegation_adapter(this);
				auto execution = coawait(adapter.execute_dispatcher_on(dispatch_number));
				for (auto& [runner_wallet, transaction] : adapter.emissions)
				{
					if (runner_wallet && transaction)
						accept_local_transaction(runner_wallet, std::move(transaction));
				}

				if (kernel::params().user.consensus.logging)
				{
					for (auto& [transaction_hash, error] : execution.errors)
					{
						if (!error.is_retry())
							VI_WARN("transaction %s dispatch: %s", algorithm::encoding::encode_0xhex256(transaction_hash).c_str(), error.what());
					}
					if (execution.dispatches > 0 || !adapter.emissions.empty() || !execution.errors.empty())
						VI_INFO("block dispatch (number: %" PRIu64", txns: -%" PRIu64 " / +%" PRIu64 ", reverted: %" PRIu64 ")", dispatch_number, (uint64_t)execution.dispatches, (uint64_t)adapter.emissions.size(), (uint64_t)execution.errors.size());
				}

				umutex<std::recursive_mutex> unique(sync.tip);
				if (!witnesses.empty())
				{
					auto* offchain = superchain::bridge::get();
					for (auto& [asset, block_height] : witnesses)
					{
						auto earlist_block_height = offchain->get_earliest_scanned_block_height(asset);
						if (!earlist_block_height)
							offchain->scan_from_block_height(asset, block_height);
					}
					witnesses.clear();
				}
				unique.unlock();
			});
		}
		void server_node::startup()
		{
			bool uses_server = kernel::params().user.consensus.server && kernel::params().user.consensus.max_inbound_connections > 0;
			if (!uses_server && !kernel::params().user.consensus.max_outbound_connections)
				return;

			control_sys.activate();
			if (uses_server)
			{
				socket_router* config = new socket_router();
				config->socket_timeout = (size_t)kernel::params().user.tcp.timeout;
				config->max_connections = kernel::params().user.consensus.max_inbound_connections;

				auto listener_status = config->listen(kernel::params().user.consensus.address, to_string(kernel::params().user.consensus.port));
				VI_PANIC(listener_status, "server listener error: %s", listener_status.error().what());

				auto configure_status = configure(config);
				VI_PANIC(configure_status, "server configuration error: %s", configure_status.error().what());

				auto binding_status = listen();
				VI_PANIC(binding_status, "server binding error: %s", binding_status.error().what());

				if (kernel::params().user.consensus.logging)
					VI_INFO("OK consensus node listen (location: %s:%i, type: %s)", kernel::params().user.consensus.address.c_str(), (int)kernel::params().user.consensus.port, kernel::params().user.consensus.max_outbound_connections > 0 ? "in-out" : "in");
			}
			else if (kernel::params().user.consensus.max_outbound_connections > 0 && kernel::params().user.consensus.logging)
				VI_INFO("OK consensus node listen (type: out)");

			auto wallets = vector<ledger::wallet>();
			for (auto& seed : kernel::mparams().user.consensus.accounts)
			{
				algorithm::seckey_t secret_key;
				if (algorithm::signing::decode_secret_key(seed, secret_key) && algorithm::signing::verify_secret_key(secret_key))
					wallets.push_back(ledger::wallet::from_secret_key(secret_key));
				else if (algorithm::signing::verify_mnemonic(seed))
					wallets.push_back(ledger::wallet::from_mnemonic(seed));
				else if (format::util::is_hex_encoding(seed))
					wallets.push_back(ledger::wallet::from_seed(codec::hex_decode(seed)));
				else
					VI_PANIC(false, "consensus account must be either a word mnemonic, hex seed or an encoded secret key");
				memset(seed.data(), 0, seed.size());
				seed.clear();
			}

			accept_local_accounts(wallets).expect("failed to create a local account");
			if (!kernel::params().user.known_nodes.empty())
			{
				auto mempool = storages::mempoolstate();
				for (auto& node : kernel::params().user.known_nodes)
				{
					auto endpoint = system_endpoint(node);
					if (endpoint.is_valid())
					{
						if (!connected_to_ip_address(endpoint.address))
						{
							mempool.clear_node(endpoint.address);
							mempool.apply_unknown_node(endpoint.address, true);
						}
					}
					else if (kernel::params().user.consensus.logging)
						VI_ERR("pre-configured node \"%s\" error: url not valid", node.c_str());
				}
			}

			bind_event(descriptors::broadcast_block_hash(), std::bind(&server_node::broadcast_block_hash, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_transaction_hash(), std::bind(&server_node::broadcast_transaction_hash, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_attestation(), std::bind(&server_node::broadcast_attestation, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_preattestation(), std::bind(&server_node::broadcast_preattestation, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_delegation(), std::bind(&server_node::broadcast_delegation, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_quote_ask(), std::bind(&server_node::broadcast_quote_ask, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::broadcast_quote(), std::bind(&server_node::broadcast_quote, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::perform_delegation(), std::bind(&server_node::perform_delegation, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::perform_handshake(), std::bind(&server_node::perform_handshake, this, std::placeholders::_2, std::placeholders::_3, false), false);
			bind_query(descriptors::perform_discovery(), std::bind(&server_node::perform_discovery, this, std::placeholders::_2, std::placeholders::_3, false));
			bind_query(descriptors::fetch_headers(), std::bind(&server_node::fetch_headers, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_block(), std::bind(&server_node::fetch_block, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_blocks(), std::bind(&server_node::fetch_blocks, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_mempool(), std::bind(&server_node::fetch_mempool, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_transaction(), std::bind(&server_node::fetch_transaction, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_transactions(), std::bind(&server_node::fetch_transactions, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_preattestation_body(), std::bind(&server_node::fetch_preattestation_body, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::delegate_execution(), std::bind(&server_node::delegate_execution, this, std::placeholders::_2, std::placeholders::_3));
			control_sys.interval_if_none(TASK_TOPOLOGY_OPTIMIZATION "_runner", 180000, std::bind(&server_node::run_topology_optimization, this));
			control_sys.interval_if_none(TASK_BLOCK_PRODUCTION "_runner", std::max<uint64_t>(kernel::params().policy.pow.time / 2, 3000), std::bind(&server_node::run_block_production, this));
			control_sys.interval_if_none(TASK_BLOCK_DISPATCHER_LATE "_runner", std::max<uint64_t>(kernel::params().policy.pow.time * 3, 9000), std::bind(&server_node::run_block_dispatcher, this));
			control_sys.interval_if_none(TASK_ATTESTATION_RESOLUTION "_runner", 300000, std::bind(&server_node::run_attestation_resolution, this));
			control_sys.interval_if_none(TASK_MEMPOOL_VACUUM "_runner", 240000, std::bind(&server_node::run_mempool_vacuum, this));
			control_sys.interval_if_none(TASK_MEMPOOL_SYNC "_runner", 240000, std::bind(&server_node::run_mempool_sync, this));
			run_topology_optimization();
			run_mempool_vacuum();
			run_attestation_resolution();
			if (!kernel::params().user.superchain.listener)
				return;

			auto* offchain = superchain::bridge::get();
			offchain->network_active = [this]() -> bool { return is_active(); };
			offchain->network_fetch = std::bind(&server_node::queued_fetch_external, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
			transport_layer::link_instance();
			for (auto& [blockchain, listener] : offchain->get_networks())
				run_superchain_sync(listener.asset);
		}
		void server_node::shutdown()
		{
			if (is_active() || kernel::params().user.consensus.server || kernel::params().user.consensus.max_outbound_connections)
			{
				if (kernel::params().user.consensus.logging)
					VI_INFO("OK consensus node shutdown");
			}

			if (!is_active())
				return;

			if (state != server_state::working)
			{
				on_unlisten();
				on_after_unlisten();
			}
			else
				unlisten(false);
		}
		void server_node::clear_tip(relay* from, ledger::block_header* prev_best)
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			if (from)
			{
				for (auto it = tips.cbegin(); it != tips.cend();)
				{
					if (from == *it->second.state || (prev_best && it->second.header < *prev_best))
					{
						if (kernel::params().user.consensus.logging)
							VI_INFO("tip %s dropped (number: %" PRIu64 ")", uint256_to_label(it->first).c_str(), it->second.header.number);
						it = tips.erase(it);
					}
					else
						++it;
				}
			}
			else if (!tips.empty())
			{
				if (kernel::params().user.consensus.logging)
					VI_INFO("tip%s %" PRIu64 " dropped", tips.size() > 1 ? "s" : "", (uint64_t)tips.size());
				tips.clear();
			}
		}
		void server_node::accept_tip(uref<relay>&& from, const uint256_t& candidate_hash, ledger::block_header&& candidate_block)
		{
			if (!from || !candidate_hash || !is_active())
				return;

			size_t replacements = 0;
			umutex<std::recursive_mutex> unique(sync.tip);
		retry:
			for (auto& fork_candidate_tip : tips)
			{
				if (*fork_candidate_tip.second.state == *from)
				{
					++replacements;
					tips.erase(fork_candidate_tip.first);
					goto retry;
				}
			}

			if (kernel::params().user.consensus.logging)
				VI_INFO("tip %s added (number: %" PRIu64 ", dropped: %" PRIu64 ")", uint256_to_label(candidate_hash).c_str(), candidate_block.number, (uint64_t)replacements);

			auto& fork = tips[candidate_hash];
			fork.header = candidate_block;
			fork.state = from;
			verifier.stale = true;
		}
		void server_node::append_pending_tip(uref<relay>&& from, const uint256_t& block_hash, ledger::block_body* tip)
		{
			VI_ASSERT(tip != nullptr, "tip should be set");
			uint64_t block_number = tip->number;
			umutex<std::recursive_mutex> unique(sync.tip);
			maybe_tips[block_hash] = tip->as_message();
			unique.unlock();
			broadcast_pending_tip(std::move(from), block_hash, block_number);
		}
		void server_node::erase_pending_tip(const uint256_t& block_hash)
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			maybe_tips.erase(block_hash);
		}
		void server_node::broadcast_pending_tip(uref<relay>&& from, const uint256_t& block_hash, uint64_t block_number)
		{
			if (!block_hash || !block_number)
				return;

			size_t notifications = notify_all_except(uref(from), descriptors::broadcast_block_hash(), { format::variable(block_hash) });
			if (notifications > 0 && kernel::params().user.consensus.logging)
				VI_DEBUG("block %s broadcasted to %i nodes (number: %" PRIu64 ")", uint256_to_label(block_hash).c_str(), (int)notifications, block_number);
		}
		void server_node::finalize_pending_tip(uref<relay>&& from, const uint256_t& block_hash, uint64_t block_number)
		{
			if (from && verifier.stale)
			{
				verifier.stale = false;
				synchronize_mempool_with(std::move(from));
			}
			if (block_hash > 0 && block_number > 0)
				broadcast_pending_tip(uref(from), block_hash, block_number);
			control_sys.upsert_timeout(TASK_BLOCK_DISPATCHER "_runner", std::max<uint64_t>(kernel::params().policy.pow.time, 3000), [this]() { run_block_dispatcher(); });
		}
		bool server_node::accept_proposal_transaction(const ledger::block_transaction& transaction)
		{
			uint32_t type = transaction.transaction->as_type();
			auto purpose = transaction.transaction->as_typename();
			if (type == transactions::setup::as_instance_type())
			{
				if (transaction.receipt.successful)
				{
					if (kernel::params().user.consensus.logging)
						VI_DEBUG("transaction %s finalized (type: %.*s)", uint256_to_label(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
					for (auto& [account, descriptor] : descriptors)
						fill_node_services(descriptor);
					run_block_production();
				}
				else if (kernel::params().user.consensus.logging)
					VI_ERR("transaction %s %.*s error: %s", uint256_to_label(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_message().or_else(string("execution error")).c_str());
			}
			else if (kernel::params().user.consensus.logging)
			{
				if (transaction.receipt.successful)
					VI_DEBUG("transaction %s finalized (type: %.*s)", uint256_to_label(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				else
					VI_ERR("transaction %s %.*s error: %s", uint256_to_label(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_message().or_else(string("execution error")).c_str());
			}
			return true;
		}
		void server_node::fill_node_services(relay_descriptor& descriptor)
		{
			auto& [node, wallet] = descriptor;
			auto executor = ledger::executor_context(nullptr);
			node.services.has_production = kernel::params().user.consensus.miner ? executor.get_validator_production(wallet.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active() : false;
			node.services.has_participation = executor.get_validator_participation(wallet.public_key_hash).or_else(states::validator_participation(algorithm::pubkeyhash_t(), nullptr)).is_active();
			node.services.has_attestation = false;
			if (kernel::params().user.consensus.miner && !node.services.has_production)
				node.services.has_production = executor.calculate_producers_size().or_else(0) == 0;

			size_t count = 64, offset = 0;
			while (true)
			{
				auto attestations = executor.get_validator_attestations(wallet.public_key_hash, offset, count);
				if (!attestations || attestations->empty())
					break;

				for (auto& attestation : *attestations)
				{
					node.services.has_attestation = attestation.is_active();
					if (node.services.has_attestation)
						break;
				}

				offset += attestations->size();
				if (attestations->size() < count)
					break;
			}
		}
		bool server_node::is_active()
		{
			return control_sys.is_active();
		}
		bool server_node::is_syncing()
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			return !tips.empty();
		}
		bool server_node::has_production()
		{
			for (auto& [account, descriptor] : descriptors)
			{
				if (descriptor.first.services.has_production)
					return true;
			}
			return false;
		}
		slot_t server_node::claim_peer_index()
		{
			umutex<std::recursive_mutex> unique(exclusive);
			uint8_t slots[(NULL_SLOT + 7) / 8] = {0};
			for (auto& node : nodes)
			{
				slot_t slot = node.second->inventory_slot_id();
				if (slot != NULL_SLOT)
					slots[slot >> 3] = slots[slot >> 3] | (uint8_t)(1 << (slot & 7));
			}
			for (size_t byte = 0; byte < sizeof(slots); byte++)
			{
				if (slots[byte] != 0xFF)
				{
					for (uint8_t bit = 0; bit < 8; bit++)
					{
						slot_t slot = (slot_t)((byte << 3) | bit);
						if (!(slots[byte] & (1 << bit)) && slot != NULL_SLOT)
							return slot;
					}
				}
			}
			return NULL_SLOT;
		}
		double server_node::get_sync_progress(uint64_t current_number)
		{
			auto best = get_best_tip_header();
			if (best && best->second.header.number)
				return (current_number <= best->second.header.number ? (double)current_number / (double)best->second.header.number : 1.0);

			return 1.0;
		}
		double server_node::get_sync_progress(uint64_t current_number, relay* from)
		{
			if (!from || !current_number)
				return 1.0;

			umutex<std::recursive_mutex> unique(sync.tip);
			for (auto& fork_candidate_tip : tips)
			{
				if (*fork_candidate_tip.second.state == from && fork_candidate_tip.second.header.number)
					return (current_number <= fork_candidate_tip.second.header.number ? (double)current_number / (double)fork_candidate_tip.second.header.number : 1.0);
			}

			return 1.0;
		}
		const hash_map<void*, uref<relay>>& server_node::get_nodes() const
		{
			return nodes;
		}
		option<std::pair<uint256_t, server_node::tip_header>> server_node::get_best_tip_header()
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			option<std::pair<uint256_t, server_node::tip_header>> best_fork = optional::none;
			if (!is_active())
				return best_fork;

			for (auto& fork_candidate_tip : tips)
			{
				if (!best_fork || best_fork->second.header < fork_candidate_tip.second.header)
					best_fork = std::make_pair(fork_candidate_tip.first, fork_candidate_tip.second);
			}
			return best_fork;
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!kernel::params().user.consensus.server && !kernel::params().user.consensus.max_outbound_connections)
				return service_control::service_node();

			service_control::service_node entrypoint;
			entrypoint.startup = std::bind(&server_node::startup, this);
			entrypoint.shutdown = std::bind(&server_node::shutdown, this);
			return entrypoint;
		}
		std::recursive_mutex& server_node::get_mutex()
		{
			return exclusive;
		}
		bool server_node::connected_to_ip_address(const socket_address& address)
		{
			auto ip_address = address.get_ip_address();
			if (!ip_address)
				return false;

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto& peer_address = node.second->peer_address();
				if (peer_address == *ip_address)
					return true;
			}

			for (auto& listener : listeners)
			{
				auto listener_ip = listener->address.get_ip_address();
				if (listener_ip && *listener_ip == *ip_address)
					return true;
			}

			for (auto& [account, descriptor] : descriptors)
			{
				auto& [node, wallet] = descriptor;
				auto node_ip = node.address.get_ip_address();
				if (node_ip && *node_ip == *ip_address)
					return true;
			}

			return false;
		}
		relay_descriptor* server_node::find_descriptor(const algorithm::pubkeyhash_t& account)
		{
			umutex<std::recursive_mutex> unique(sync.account);
			auto it = descriptors.find(account);
			return it != descriptors.end() ? &it->second : nullptr;
		}
		uref<relay> server_node::find_by_ip_address(const socket_address& address)
		{
			auto ip_address = address.get_ip_address();
			if (!ip_address)
				return nullptr;

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto& peer_address = node.second->peer_address();
				if (peer_address == *ip_address)
					return node.second;
			}

			return nullptr;
		}
		uref<relay> server_node::find_by_account(const algorithm::pubkeyhash_t& account)
		{
			if (account.empty())
				return nullptr;

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr && peer_descriptor->second.public_key_hash.equals(account))
					return node.second;
			}

			return nullptr;
		}
		uref<relay> server_node::find_account_route(const algorithm::pubkeyhash_t& account)
		{
			void* instance = nullptr;
			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto it = account_routes.find(account);
				if (it == account_routes.end())
					return nullptr;

				instance = it->second.channel_instance;
			}
			return find_node_by_instance(instance);
		}
		void server_node::register_account_route(const algorithm::pubkeyhash_t& account, const algorithm::pubkey_t& public_key, uref<relay>&& channel)
		{
			if (!channel || find_descriptor(account) != nullptr)
				return;

			umutex<std::recursive_mutex> unique(exclusive);
			auto it = account_routes.find(account);
			if (it != account_routes.end())
			{
				if (it->second.channel_instance == channel->as_instance())
					it->second.public_key = public_key;
				else if (find_node_by_instance(it->second.channel_instance))
					return;
			}
			account_routes[account] = account_route{ public_key, channel->as_instance() };
		}
		void server_node::erase_account_routes_for(void* channel_instance)
		{
			if (channel_instance == nullptr)
				return;

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto it = account_routes.begin(); it != account_routes.end();)
			{
				if (it->second.channel_instance == channel_instance)
					it = account_routes.erase(it);
				else
					++it;
			}
		}
		string server_node::build_account_bindings() const
		{
			if (runner_descriptor == nullptr)
				return string();

			auto bound = vector<std::tuple<algorithm::pubkey_t, algorithm::hashsig_t, algorithm::hashsig_t>>();
			for (auto& entry : descriptors)
			{
				auto& wallet = entry.second.second;
				if (wallet.public_key == runner_descriptor->second.public_key)
					continue;

				if (bound.size() == MAX_BOUND_ACCOUNTS)
					break;

				auto proof = account_binding_proof(wallet.public_key, runner_descriptor->second.public_key, runner_descriptor->first.address);
				algorithm::hashsig_t account_signature;
				algorithm::hashsig_t node_signature;
				if (!algorithm::signing::sign(proof, wallet.secret_key, account_signature) ||
					!algorithm::signing::sign(proof, runner_descriptor->second.secret_key, node_signature))
					continue;

				bound.emplace_back(wallet.public_key, account_signature, node_signature);
			}
			if (bound.empty())
				return string();

			format::wo_stream message;
			message.write_integer((uint8_t)bound.size());
			for (auto& [account_key, account_signature, node_signature] : bound)
			{
				message.write_string(account_key.optimized_view());
				message.write_string(account_signature.optimized_view());
				message.write_string(node_signature.optimized_view());
			}
			return string(message.data.data(), message.data.size());
		}
		expects_lr<size_t> server_node::apply_account_bindings(const string& blob, uref<relay>&& channel, const socket_address& advertised_address)
		{
			if (blob.empty() || !channel)
				return (size_t)0;

			auto* peer_descriptor = channel->as_descriptor();
			if (peer_descriptor == nullptr)
				return layer_exception("peer descriptor unavailable");

			format::ro_stream stream(blob);
			uint8_t count;
			if (!stream.read_integer(stream.read_type(), &count))
				return layer_exception("malformed account bindings");

			if (count > MAX_BOUND_ACCOUNTS)
				return layer_exception("too many account bindings");

			size_t applied = 0;
			for (uint8_t i = 0; i < count; i++)
			{
				string account_blob, account_signature_blob, node_signature_blob;
				if (!stream.read_string(stream.read_type(), &account_blob) ||
					!stream.read_string(stream.read_type(), &account_signature_blob) ||
					!stream.read_string(stream.read_type(), &node_signature_blob))
					return layer_exception("malformed account bindings");

				algorithm::pubkey_t account_key(account_blob);
				algorithm::hashsig_t account_signature(account_signature_blob);
				algorithm::hashsig_t node_signature(node_signature_blob);
				if (account_key.empty() || account_key == peer_descriptor->second.public_key)
					return layer_exception("invalid account binding");

				auto proof = account_binding_proof(account_key, peer_descriptor->second.public_key, advertised_address);
				algorithm::pubkey_t recovered;
				if (!algorithm::signing::recover(proof, recovered, account_signature) || !recovered.equals(account_key))
					return layer_exception("invalid account binding signature");

				if (!algorithm::signing::recover(proof, recovered, node_signature) || !recovered.equals(peer_descriptor->second.public_key))
					return layer_exception("invalid node binding signature");

				algorithm::pubkeyhash_t account;
				algorithm::signing::derive_public_key_hash(account_key, account);
				register_account_route(account, account_key, uref(channel));
				++applied;
			}
			return applied;
		}
		option<algorithm::pubkey_t> server_node::find_public_key(const algorithm::pubkeyhash_t& account)
		{
			auto* descriptor = find_descriptor(account);
			if (descriptor != nullptr)
				return descriptor->second.public_key;

			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto it = account_routes.find(account);
				if (it != account_routes.end())
					return it->second.public_key;
			}

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr && peer_descriptor->second.public_key_hash == account)
					return peer_descriptor->second.public_key;
			}

			return optional::none;
		}
		size_t server_node::size_of(node_type type)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			size_t size = 0;
			for (auto& node : nodes)
				size += node.second->type_of() == type ? 1 : 0;
			return size;
		}
		size_t server_node::get_connections()
		{
			umutex<std::recursive_mutex> unique(exclusive);
			return nodes.size();
		}
		uref<relay> server_node::find_node_by_instance(void* instance)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			return it != nodes.end() ? it->second : nullptr;
		}

		server_delegation_adapter::server_delegation_adapter(server_node* new_server) : server(new_server)
		{
			VI_ASSERT(server != nullptr, "server should be set");
		}
		server_delegation_adapter::server_delegation_adapter(const server_delegation_adapter& other) noexcept : ledger::delegation_adapter(other), server(other.server)
		{
		}
		server_delegation_adapter& server_delegation_adapter::operator=(const server_delegation_adapter& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::delegation_adapter*)this;
			auto& base_other = *(const ledger::delegation_adapter*)&other;
			base_this = base_other;
			server = other.server;
			return *this;
		}
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> server_delegation_adapter::require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& validators, format::variables&& args, size_t steps_left)
		{
			if (kernel::params().user.consensus.logging)
				VI_INFO("%s assemble: %i validators (stack: %i)", contract->as_typename().data(), (int)validators.size(), (int)steps_left);

			return server->connect_to_delegation_nodes(contract, btree_set<algorithm::pubkeyhash_t>(validators), std::move(args)).then<expects_rt<btree_set<algorithm::pubkeyhash_t>>>([contract, steps_left](expects_rt<btree_set<algorithm::pubkeyhash_t>>&& result) mutable -> expects_rt<btree_set<algorithm::pubkeyhash_t>>
			{
				if (result && kernel::params().user.consensus.logging)
					VI_INFO("%s assemble: acquired %i validators (stack: %i)", contract->as_typename().data(), (int)result->size(), (int)steps_left);
				else if (!result && kernel::params().user.consensus.logging)
					VI_WARN("%s assemble failed: %s (stack: %i)", contract->as_typename().data(), result.what().c_str(), (int)steps_left);
				return expects_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(result));
			});
		}
		expects_promise_rt<format::wo_stream> server_delegation_adapter::execute_on_validator(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message)
		{
			uint256_t message_hash = kernel::params().user.consensus.logging ? message.hash() : uint256_t(0);
			if (kernel::params().user.consensus.logging)
				VI_DEBUG("%s hop-execute: %s (message: %s)", contract->as_typename().data(), algorithm::signing::encode_address(target).c_str(), message.encode().c_str());

			return execute_on_validator_internal(contract, target, message).then<expects_rt<format::wo_stream>>([message_hash, contract, target](expects_rt<format::wo_stream>&& result) mutable -> expects_rt<format::wo_stream>
			{
				if (result && kernel::params().user.consensus.logging)
					VI_INFO("%s hop-execute: %s (to: %s)", contract->as_typename().data(), uint256_to_label(message_hash).c_str(), algorithm::signing::encode_address(target).c_str());
				else if (!result && kernel::params().user.consensus.logging)
					VI_WARN("%s hop-execute failed: %s (to: %s, hash: %s)", contract->as_typename().data(), result.what().c_str(), algorithm::signing::encode_address(target).c_str(), algorithm::encoding::encode_0xhex256(message_hash).c_str());
				return expects_rt<format::wo_stream>(std::move(result));
			});
		}
		expects_promise_rt<format::wo_stream> server_delegation_adapter::execute_on_validator_internal(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message)
		{
			auto target_public_key = server->find_public_key(target);
			if (!target_public_key)
				return expects_promise_rt<format::wo_stream>(remote_exception::retry_later());

			format::variables args;
			args.push_back(format::variable(contract->runner->public_key.optimized_view()));
			args.push_back(format::variable(contract->executor->receipt.block_number));
			args.push_back(format::variable(contract->executor->receipt.transaction_hash));
			args.push_back(format::variable(message.data));

			auto private_args = pack_private_result(args, *target_public_key, contract->runner->secret_key);
			if (!private_args)
				return expects_promise_rt<format::wo_stream>(std::move(private_args.error()));

			return coasync<expects_rt<format::wo_stream>>([this, contract, target, target_public_key = std::move(target_public_key), private_args = std::move(private_args)]() mutable -> expects_promise_rt<format::wo_stream>
			{
				uint64_t attempt = 0;
			retry:
				auto event = coawait(server->indirect_query(target, descriptors::delegate_execution(), format::variables(*private_args), kernel::params().user.tcp.timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				algorithm::pubkeyhash_t from_public_key_hash;
				private_args = unpack_private_result(event->args, contract->runner->secret_key, from_public_key_hash);
				if (!private_args)
					coreturn private_args.error();

				algorithm::pubkeyhash_t target_public_key_hash;
				algorithm::signing::derive_public_key_hash(*target_public_key, target_public_key_hash);
				if (private_args->size() != 1 || !private_args->at(0).is_string() || from_public_key_hash != target_public_key_hash)
					coreturn remote_exception("delegation result verification failed (possible attack)");

				format::wo_stream message = format::wo_stream(private_args->at(0).as_blob());
				coreturn expects_rt<format::wo_stream>(std::move(message));
			});
		}
		algorithm::pubkey_t server_delegation_adapter::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto target = server->find_public_key(validator);
			if (!target)
				return algorithm::pubkey_t();

			return *target;
		}
		const ledger::wallet* server_delegation_adapter::get_runner_wallet(const algorithm::pubkeyhash_t& validator) const
		{
			auto* result = server->find_descriptor(validator);
			return result ? &result->second : nullptr;
		}
		const ledger::wallet* server_delegation_adapter::get_runner_wallet() const
		{
			return server->runner_descriptor ? &server->runner_descriptor->second : nullptr;
		}

		local_delegation_adapter::local_delegation_adapter(const vector<ledger::wallet>& new_validators)
		{
			for (auto& target : new_validators)
				validators[algorithm::pubkeyhash_t(target.public_key_hash)] = target;
		}
		local_delegation_adapter::local_delegation_adapter(const local_delegation_adapter& other) noexcept : ledger::delegation_adapter(other), validators(other.validators)
		{
		}
		local_delegation_adapter& local_delegation_adapter::operator=(const local_delegation_adapter& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::delegation_adapter*)this;
			auto& base_other = *(const ledger::delegation_adapter*)&other;
			base_this = base_other;
			validators = other.validators;
			return *this;
		}
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> local_delegation_adapter::require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& targets, format::variables&& args, size_t steps_left)
		{
			btree_set<algorithm::pubkeyhash_t> results;
			for (auto& [validator, wallet] : validators)
			{
				if (targets.find(validator) != targets.end())
					results.insert(validator);
			}
			if (kernel::params().user.consensus.logging)
				VI_DEBUG("%s assemble: acquired %i/%i local validators (stack: %i)", contract->as_typename().data(), (int)results.size(), (int)targets.size(), (int)steps_left);
			return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(results));
		}
		expects_promise_rt<format::wo_stream> local_delegation_adapter::execute_on_validator(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& wo_message)
		{
			format::ro_stream message = wo_message.ro(); uint32_t delegation_type;
			if (!message.read_integer(message.read_type(), &delegation_type) || contract->as_type() != delegation_type)
				return expects_promise_rt<format::wo_stream>(remote_exception("invalid delegation type"));

			uint32_t delegate;
			if (!message.read_integer(message.read_type(), &delegate))
				return expects_promise_rt<format::wo_stream>(remote_exception("invalid delegate type"));

			if (!get_runner_wallet(target))
				return expects_promise_rt<format::wo_stream>(remote_exception("delegate not found"));

			auto validation = contract->validate_transition(nullptr, *contract->runner);
			if (!validation)
				return expects_promise_rt<format::wo_stream>(remote_exception(std::move(validation.error().message())));

			auto result_wo_message = contract->yield_to_self(target, delegate, false);
			if (!result_wo_message)
				return expects_promise_rt<format::wo_stream>(remote_exception(std::move(result_wo_message.error().message())));

			return expects_promise_rt<format::wo_stream>(std::move(*result_wo_message));
		}
		algorithm::pubkey_t local_delegation_adapter::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto it = validators.find(validator);
			return it != validators.end() ? it->second.public_key : algorithm::pubkey_t();
		}
		const ledger::wallet* local_delegation_adapter::get_runner_wallet(const algorithm::pubkeyhash_t& validator) const
		{
			auto it = validators.find(validator);
			return it != validators.end() ? &it->second : nullptr;
		}
		const ledger::wallet* local_delegation_adapter::get_runner_wallet() const
		{
			return validators.empty() ? nullptr : &validators.begin()->second;
		}
	}
}