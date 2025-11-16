#include "consensus.h"
#include "oracle.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../../policy/transactions.h"
#include <array>
#define BLOCK_RATE_NORMAL ELEMENTS_MANY
#define BLOCK_DATA_CONSENSUS (uint32_t)storages::block_details::transactions | (uint32_t)storages::block_details::block_transactions
#define TASK_TOPOLOGY_OPTIMIZATION "topology_optimization"
#define TASK_MEMPOOL_VACUUM "mempool_vacuum"
#define TASK_FORK_RESOLUTION "fork_resolution"
#define TASK_BLOCK_DISPATCH_RETRIAL "block_dispatch_retrial"
#define TASK_BLOCK_PRODUCTION "block_production"
#define TASK_BLOCK_DISPATCHER "block_dispatcher"

namespace tangent
{
	namespace consensus
	{
		static option<socket_address> text_address_to_socket_address(const std::string_view& value)
		{
			auto ip_address = value.substr(0, value.find(':'));
			auto ip_port = ip_address.size() + 1 <= value.size() ? value.substr(ip_address.size() + 1) : std::string_view();
			auto address = socket_address(ip_address, from_string<uint16_t>(ip_port).or_else(0));
			return address.is_valid() ? option<socket_address>(std::move(address)) : option<socket_address>(optional::none);
		}
		static option<string> socket_address_to_text_address(const socket_address& value)
		{
			auto ip_address = value.get_ip_address();
			auto ip_port = value.get_ip_port();
			return ip_address && ip_port ? option<string>(*ip_address + ":" + to_string(*ip_port)) : option<string>(optional::none);
		}
		static uint256_t handshake_proof(const ledger::node& node, uint64_t time)
		{
			format::wo_stream message;
			node.store(&message);
			message.write_integer(time);
			return message.hash();
		}
		static uint256_t discovery_proof(const socket_address& address, const ordered_set<algorithm::pubkeyhash_t>& accounts)
		{
			format::wo_stream message;
			message.write_string(address.get_ip_address().or_else(string()));
			message.write_integer(address.get_ip_port().or_else(0));
			for (auto& account : accounts)
				message.write_typeless(account.view());
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
					return remote_exception::retry();
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
		static expects_rt<format::variables> pack_private_result(const format::variables& result, const algorithm::pubkey_t& public_key)
		{
			format::wo_stream message;
			format::variables_util::serialize_flat_into(result, &message);

			uint256_t entropy;
			memcpy(&entropy, crypto::random_bytes(sizeof(entropy))->data(), sizeof(entropy));

			auto encrypted_message = algorithm::signing::public_encrypt(public_key, message.data, entropy);
			if (!encrypted_message)
				return remote_exception("private result encryption failed");

			return format::variables({ format::variable(*encrypted_message) });
		}
		static expects_rt<format::variables> pack_private_result(const format::variables& result, const relay* state)
		{
			if (!state)
				return remote_exception("relay must be set to decrypt private result");

			auto* descriptor = state->as_descriptor();
			if (!descriptor || descriptor->second.public_key.empty())
				return remote_exception("relay must have a public key to decrypt private result");

			return pack_private_result(result, descriptor->second.public_key);
		}
		static expects_rt<format::variables> unpack_private_result(const format::variables& packed_result, const algorithm::seckey_t& secret_key)
		{
			if (packed_result.size() != 1)
				return remote_exception("invalid encrypted private result");

			auto decrypted_message = algorithm::signing::private_decrypt(secret_key, packed_result.front().as_string());
			if (!decrypted_message)
				return remote_exception("private result decryption failed");

			format::variables result;
			format::ro_stream message = format::ro_stream(*decrypted_message);
			if (!format::variables_util::deserialize_flat_from(message, &result))
				return remote_exception("invalid private result");

			return expects_rt<format::variables>(std::move(result));
		}
		static promise<bool> aggregative_sleep(uint64_t& attempt)
		{
			if (++attempt > protocol::now().user.consensus.aggregation_attempts)
				return promise<bool>(false);

			promise<bool> sleep;
			schedule::get()->set_timeout(attempt * protocol::now().user.consensus.aggregation_cooldown, [sleep]() mutable { sleep.set(true); });
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

			if (!stream.read_integer(stream.read_type(), (uint8_t*)&type))
				return false;

			args.clear();
			return format::variables_util::deserialize_merge_from(stream, &args);
		}
		bool exchange::store_exchange(string* result)
		{
			VI_ASSERT(result != nullptr, "result should be set");
			format::wo_stream stream;
			if (!store_payload(&stream))
				return false;

			uint32_t net_magic = os::hw::to_endianness(os::hw::endian::little, protocol::now().message.packet_magic);
			uint32_t net_size = os::hw::to_endianness(os::hw::endian::little, (uint32_t)stream.data.size());
			uint32_t net_checksum = os::hw::to_endianness(os::hw::endian::little, algorithm::hashing::hash32d(stream.data));

			size_t offset = result->size();
			result->resize(offset + sizeof(uint32_t) * 3 + stream.data.size());
			memcpy(result->data() + offset + sizeof(uint32_t) * 0, &net_magic, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 1, &net_size, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 2, &net_checksum, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 3, stream.data.data(), stream.data.size());
			return true;
		}
		bool exchange::load_exchange(string& message_buffer)
		{
			uint32_t magic = os::hw::to_endianness(os::hw::endian::little, protocol::now().message.packet_magic);
			uint8_t magic_buffer[sizeof(magic)];
			memcpy(magic_buffer, &magic, sizeof(magic));

			const size_t max_body_size = protocol::now().message.max_body_size;
			const size_t header_size = sizeof(uint32_t) * 3;
			const size_t message_size = 32 * header_size + max_body_size;
			if (message_buffer.size() > message_size)
				message_buffer.erase(0, message_buffer.size() - message_size);

			size_t magic_index = message_buffer.find(std::string_view((char*)magic_buffer, sizeof(magic_buffer)));
			if (magic_index == std::string::npos)
				return false;

			message_buffer.erase(0, magic_index);
			if (message_buffer.size() < header_size)
				return false;

			uint32_t size, checksum;
			memcpy(&size, message_buffer.data() + sizeof(uint32_t) * 1, sizeof(uint32_t));
			memcpy(&checksum, message_buffer.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
			size = os::hw::to_endianness(os::hw::endian::little, size);
			checksum = os::hw::to_endianness(os::hw::endian::little, checksum);
			if (size > max_body_size)
			{
				message_buffer.resize(header_size);
				return false;
			}

			auto body = std::string_view(message_buffer).substr(header_size, (size_t)size);
			if (body.size() < size)
				return false;

			format::ro_stream stream = format::ro_stream(body);
			bool satisfiable = algorithm::hashing::hash32d(body) == checksum && load_payload(stream);
			message_buffer.erase(0, magic_index + header_size + body.size());
			return satisfiable;
		}
		bool exchange::load_partial_exchange(string& message, const uint8_t* buffer, size_t size)
		{
			if (buffer != nullptr && size > 0)
			{
				size_t offset = message.size();
				message.resize(offset + size);
				memcpy(message.data() + offset, buffer, size);
			}
			return load_exchange(message);
		}
		uint64_t exchange::calculate_latency()
		{
			auto time_now = protocol::now().time.now_cpu();
			return time > 0 && time_now > time ? time_now - time : 0;
		}
		uint32_t exchange::as_type() const
		{
			return as_instance_type();
		}
		std::string_view exchange::as_typename() const
		{
			return as_instance_typename();
		}
		uptr<schema> exchange::as_schema() const
		{
			schema* data = var::set::object();
			data->set("descriptor", var::integer(descriptor));
			data->set("session", session > 0 ? var::integer(session) : var::null());
			data->set("time", var::integer(time));
			data->set("type", var::string(type == side::query ? "query" : "event"));
			data->set("args", format::variables_util::serialize(args));
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

		bool forwarder::insert(const uint256_t& message_hash)
		{
			auto it = messages.find(message_hash);
			if (it != messages.end())
				return false;

			auto& config = protocol::now();
			auto time = config.time.now_cpu();
			if (messages.size() + 1 > config.user.consensus.inventory_size)
			{
				auto oldest_it = messages.end();
				for (auto it = messages.begin(); it != messages.end();)
				{
					if (it->second >= time)
					{
						if (oldest_it == messages.end() || oldest_it->second > it->second)
							oldest_it = it;
						++it;
					}
					else
						it = messages.erase(it);
				}
				if (oldest_it != messages.end())
					messages.erase(oldest_it);
			}
			messages[message_hash] = time + config.user.consensus.inventory_timeout;
			return true;
		}
		bool forwarder::contains(const uint256_t& message_hash) const
		{
			auto it = messages.find(message_hash);
			return it != messages.end() && it->second > protocol::now().time.now_cpu();
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

		relay::relay(node_type new_type, void* new_instance) : type(new_type), instance(new_instance), counter(0), aborted(false), bandwidth(1000 * 1000 * protocol::now().user.tcp.mbps_per_socket), deferred_pull(INVALID_TASK_ID)
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
			invalidate();
		}
		expects_promise_rt<exchange> relay::push_query(const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms)
		{
			exchange message;
			message.descriptor = descriptor.id;
			message.type = exchange::side::query;
			message.args = std::move(args);

			umutex<std::recursive_mutex> unique(mutex);
			do { message.session = ++counter; } while (queries.find(message.session) != queries.end());

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
						result.set(remote_exception::retry());
				});
			}
			outgoing_messages.push(std::move(message));
			return result;
		}
		bool relay::push_event(const callable::descriptor& descriptor, format::variables&& args)
		{
			exchange message;
			message.descriptor = descriptor.id;
			message.type = exchange::side::event;
			message.args = std::move(args);
			if (!inventory.insert(message.as_hash()))
				return false;

			umutex<std::recursive_mutex> unique(mutex);
			outgoing_messages.push(std::move(message));
			return true;
		}
		void relay::push_event(uint32_t session, format::variables&& args)
		{
			exchange message;
			message.descriptor = 0;
			message.type = exchange::side::event;
			message.session = session;
			message.args = std::move(args);

			umutex<std::recursive_mutex> unique(mutex);
			outgoing_messages.push(std::move(message));
		}
		bool relay::incoming_message_into(exchange* message)
		{
			VI_ASSERT(message != nullptr, "incoming message should be set");
			umutex<std::recursive_mutex> unique(mutex);
			if (incoming_messages.empty())
				return false;

			*message = std::move(incoming_messages.front());
			incoming_messages.pop();
			return true;
		}
		bool relay::pull_incoming_message(const uint8_t* buffer, size_t size)
		{
			exchange message;
			umutex<std::recursive_mutex> unique(mutex);
			if (!message.load_partial_exchange(incoming_data, buffer, size))
				return !incoming_messages.empty();

			incoming_messages.emplace(std::move(message));
			return true;
		}
		bool relay::begin_outgoing_message()
		{
			umutex<std::recursive_mutex> unique(mutex);
			if (!outgoing_data.empty())
				return false;
		retry:
			if (outgoing_messages.empty())
				return false;

			auto& message = outgoing_messages.front();
			bool relayable = message.store_exchange(&outgoing_data) && !outgoing_data.empty();
			outgoing_messages.pop();
			if (relayable)
				return true;

			outgoing_data.clear();
			goto retry;
		}
		void relay::end_outgoing_message()
		{
			umutex<std::recursive_mutex> unique(mutex);
			outgoing_data.clear();
		}
		void relay::report_call(int8_t call_result, uint64_t call_latency)
		{
			if (descriptor)
			{
				auto mempool = storages::mempoolstate();
				mempool.apply_node_quality(descriptor->first.address, call_result, call_latency, protocol::now().user.consensus.topology_timeout);
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
		void relay::abort()
		{
			cancel_queries();
			if (deferred_pull != INVALID_TASK_ID)
			{
				schedule::get()->clear_timeout(deferred_pull);
				deferred_pull = INVALID_TASK_ID;
			}

			auto* socket = as_socket();
			if (socket != nullptr)
				socket->shutdown(true);
			aborted = true;
		}
		void relay::initialize(relay_descriptor&& new_descriptor)
		{
			descriptor = memory::init<relay_descriptor>(std::move(new_descriptor));
			if (protocol::now().user.consensus.logging)
				VI_INFO("node %s channel accept (%s %s)", peer_address().c_str(), routing_util::node_type_of(this).data(), peer_service().c_str());

			auto* socket = as_socket();
			if (socket != nullptr)
				socket->set_io_timeout(0);
		}
		void relay::invalidate()
		{
			bool graceful_shutdown = instance != nullptr && descriptor;
			if (graceful_shutdown)
			{
				report_call(0, 0);
				if (protocol::now().user.consensus.logging)
					VI_INFO("node %s channel shutdown (%s %s)", peer_address().c_str(), routing_util::node_type_of(this).data(), peer_service().c_str());
			}
			abort();

			umutex<std::recursive_mutex> unique(mutex);
			auto* inbound = as_inbound_node();
			auto* outbound = as_outbound_node();
			memory::release(inbound);
			memory::release(outbound);
			instance = nullptr;
			descriptor.destroy();
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
			if (!address.empty())
				return address;

			umutex<std::recursive_mutex> unique(mutex);
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
			if (!service.empty())
				return service;

			umutex<std::recursive_mutex> unique(mutex);
			auto* stream = as_socket();
			if (!stream)
			{
			no_service:
				service = to_string(protocol::now().user.consensus.port);
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
		const single_queue<exchange>& relay::get_incoming_messages() const
		{
			return incoming_messages;
		}
		const single_queue<exchange>& relay::get_outgoing_messages() const
		{
			return outgoing_messages;
		}
		forwarder& relay::get_inventory()
		{
			return inventory;
		}
		const uint8_t* relay::outgoing_buffer()
		{
			return (const uint8_t*)outgoing_data.data();
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
		uptr<schema> relay::as_schema() const
		{
			schema* data = var::set::object();
			switch (type)
			{
				case node_type::inbound:
					data->set("type", var::string("inbound"));
					break;
				case node_type::outbound:
					data->set("type", var::string("outbound"));
					break;
				default:
					data->set("type", var::string("unknown"));
					break;
			}
			auto* incoming = data->set("incoming", var::object());
			incoming->set("queue", algorithm::encoding::serialize_uint256(incoming_messages.size()));
			incoming->set("bytes", algorithm::encoding::serialize_uint256(incoming_data.size()));
			auto* outgoing = data->set("outgoing", var::object());
			outgoing->set("queue", algorithm::encoding::serialize_uint256(outgoing_messages.size()));
			outgoing->set("bytes", algorithm::encoding::serialize_uint256(outgoing_data.size()));
			return data;
		}
		relay_descriptor* relay::as_descriptor() const
		{
			return *descriptor;
		}

		outbound_node::outbound_node() noexcept : socket_client(protocol::now().user.tcp.timeout)
		{
		}
		void outbound_node::configure_stream()
		{
			socket_client::configure_stream();
			if (protocol::now().is(network_type::regtest))
				net.stream->bind(socket_address(protocol::now().user.consensus.address, 0));
		}

		callable::descriptor descriptors::notify_of_block_hash()
		{
			return callable::descriptor(__func__, 10);
		}
		callable::descriptor descriptors::notify_of_transaction_hash()
		{
			return callable::descriptor(__func__, 11);
		}
		callable::descriptor descriptors::notify_of_attestation()
		{
			return callable::descriptor(__func__, 12);
		}
		callable::descriptor descriptors::notify_of_aggregation()
		{
			return callable::descriptor(__func__, 13);
		}
		callable::descriptor descriptors::query_handshake()
		{
			return callable::descriptor(__func__, 14);
		}
		callable::descriptor descriptors::query_state()
		{
			return callable::descriptor(__func__, 15);
		}
		callable::descriptor descriptors::query_headers()
		{
			return callable::descriptor(__func__, 16);
		}
		callable::descriptor descriptors::query_block()
		{
			return callable::descriptor(__func__, 17);
		}
		callable::descriptor descriptors::query_mempool()
		{
			return callable::descriptor(__func__, 18);
		}
		callable::descriptor descriptors::query_transaction()
		{
			return callable::descriptor(__func__, 19);
		}
		callable::descriptor descriptors::aggregate_secret_share_state()
		{
			return callable::descriptor(__func__, 20);
		}
		callable::descriptor descriptors::aggregate_public_state()
		{
			return callable::descriptor(__func__, 21);
		}
		callable::descriptor descriptors::aggregate_signature_state()
		{
			return callable::descriptor(__func__, 22);
		}

		server_node::server_node() noexcept : socket_server(), control_sys("consensus-node")
		{
		}
		server_node::~server_node() noexcept
		{
			if (oracle::server_node::has_instance())
			{
				auto node_id = codec::hex_encode(std::string_view((char*)this, sizeof(this)));
				oracle::server_node::get()->add_transaction_callback(node_id, nullptr);
			}
			clear_pending_meeting(0);
			clear_pending_fork(nullptr);
		}
		expects_system<void> server_node::on_unlisten()
		{
			control_sys.deactivate(false);
			clear_pending_meeting(0);
			clear_pending_fork(nullptr);
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
					socket->shutdown(true);
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
				unordered_map<void*, uref<relay>> current_nodes;
				current_nodes.swap(nodes);
				unique.unlock();
				for (auto& node : current_nodes)
					node.second->abort();
			}
			unique.lock();
			if (!nodes.empty())
				goto retry;

			return expectation::met;
		}
		expects_lr<void> server_node::apply_node(storages::mempoolstate& mempool, relay_descriptor& descriptor)
		{
			auto& [node, wallet] = descriptor;
			auto ip_address = node.address.get_ip_address();
			auto ip_port = node.address.get_ip_port();
			if (!node.address.is_valid() || !ip_address || !ip_port)
				return layer_exception("bad node address");
			else if (*ip_address == "0.0.0.0")
				node.address = socket_address("127.0.0.1", *ip_port);

			if (routing_util::is_address_reserved(node.address) && !routing_util::is_address_private(node.address))
				return layer_exception("bad node address space");

			return mempool.apply_node(descriptor);
		}
		expects_lr<void> server_node::accept_local_wallet(option<ledger::wallet>&& overriding_wallet)
		{
			umutex<std::recursive_mutex> unique(sync.account);
			auto& [node, wallet] = descriptor;
			auto mempool = storages::mempoolstate();
			auto local_node = mempool.get_local_node();
			if (!local_node)
			{
				node.address = socket_address(protocol::now().user.consensus.address, protocol::now().user.consensus.port);
				wallet = overriding_wallet ? std::move(*overriding_wallet) : ledger::wallet::from_seed(*crypto::random_bytes(512));
			}
			else
			{
				node = std::move(local_node->first);
				wallet = overriding_wallet ? std::move(*overriding_wallet) : std::move(local_node->second);
			}

			fill_node_services();
			node.ports.consensus = protocol::now().user.consensus.port;
			node.ports.discovery = protocol::now().user.discovery.port;
			node.ports.rpc = protocol::now().user.rpc.port;
			node.services.has_consensus = protocol::now().user.consensus.server;
			node.services.has_discovery = protocol::now().user.discovery.server;
			node.services.has_oracle = protocol::now().user.oracle.server;
			node.services.has_rpc = protocol::now().user.rpc.server && protocol::now().user.rpc.username.empty();
			node.services.has_rpc_web_sockets = node.services.has_rpc && protocol::now().user.rpc.web_sockets;

			auto result = apply_node(mempool, descriptor);
			if (result)
				VI_INFO("local account %s accepted", wallet.get_address().c_str());
			return result;
		}
		expects_lr<void> server_node::accept_unsigned_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, uint64_t* account_nonce, uint256_t* output_hash)
		{
			auto& [node, wallet] = descriptor;
			candidate_tx->set_optimal_gas(decimal::zero());

			auto status = candidate_tx->sign(wallet.secret_key, account_nonce ? *account_nonce : 0, decimal::zero());
			if (!status)
			{
				auto purpose = candidate_tx->as_typename();
				if (protocol::now().user.consensus.logging)
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data(), status.what().c_str());

				return status;
			}

			status = accept_transaction(uref(from), std::move(candidate_tx), false);
			if (!status)
				return status;

			if (account_nonce != nullptr && *account_nonce == candidate_tx->nonce)
				++(*account_nonce);

			if (output_hash != nullptr)
				*output_hash = candidate_tx->as_hash();

			return status;
		}
		expects_lr<void> server_node::accept_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto chain = storages::chainstate();
			if (chain.get_transaction_by_hash(candidate_hash))
			{
				if (protocol::now().user.consensus.logging)
					VI_INFO("transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return expectation::met;
			}

			algorithm::pubkeyhash_t owner;
			if (!candidate_tx->recover_hash(owner))
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation failed: invalid signature", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("signature key recovery failed");
			}

			algorithm::pubkeyhash_t validation_owner;
			auto validation = ledger::transaction_context::validate_tx(*candidate_tx, candidate_hash, validation_owner);
			if (!validation)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
				return validation.error();
			}

			auto& [node, wallet] = descriptor;
			bool event = candidate_tx->is_commitment() && wallet.public_key_hash == owner;
			if (event || validate_execution)
			{
				ledger::block temp_block;
				temp_block.number = std::numeric_limits<int64_t>::max() - 1;

				ledger::evaluation_context temp_environment;
				temp_environment.validator.public_key_hash = wallet.public_key_hash;

				ledger::block_changelog temp_changelog;
				size_t transaction_size = candidate_tx->as_message().data.size();
				auto validation = ledger::transaction_context::execute_tx(&temp_environment, &temp_block, &temp_changelog, *candidate_tx, candidate_hash, owner, transaction_size, (uint8_t)ledger::transaction_context::execution_mode::pedantic);
				if (!validation)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s %.*s pre-execution failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
					return validation.error();
				}
			}

			return broadcast_transaction(uref(from), std::move(candidate_tx), owner);
		}
		expects_lr<void> server_node::accept_attestation(uref<relay>&& from, const uint256_t& attestation_hash)
		{
			auto mempool = storages::mempoolstate();
			auto batch = mempool.get_attestation(attestation_hash);
			if (!batch)
				return batch.error();
			else if (batch->proofs.empty())
				return layer_exception("proof required");

			auto context = ledger::transaction_context();
			auto collision = context.get_witness_transaction(batch->asset, batch->proofs.begin()->second.transaction_id);
			if (collision)
				return expectation::met;

			uint256_t best_commitment_hash = 0;
			ordered_map<uint256_t, ordered_set<algorithm::pubkeyhash_t>> attesters;
			auto verification = transactions::bridge_attestation::verify_proof_commitment(&context, batch->asset, batch->commitments, best_commitment_hash, attesters);
			if (!verification)
				return verification;

			auto it = batch->proofs.find(best_commitment_hash);
			if (it == batch->proofs.end())
				return layer_exception("proof required");

			auto* transaction = memory::init<transactions::bridge_attestation>();
			transaction->asset = batch->asset;
			transaction->set_computed_proof(std::move(it->second), std::move(batch->commitments));
			accept_unsigned_transaction(nullptr, transaction, nullptr);
			mempool.remove_attestation(attestation_hash);
			return expectation::met;
		}
		expects_lr<void> server_node::broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, const algorithm::pubkeyhash_t& owner)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto mempool = storages::mempoolstate();
			auto action = mempool.add_transaction(**candidate_tx, false);
			if (!action)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s mempool rejection: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), action.error().what());
				return action.error();
			}

			if (protocol::now().user.consensus.logging)
				VI_INFO("transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());

			if (events.accept_transaction)
				events.accept_transaction(candidate_hash, *candidate_tx, owner);

			size_t notifications = notify_all_except(uref(from), descriptors::notify_of_transaction_hash(), { format::variable(candidate_hash) });
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_INFO("transaction %s %.*s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), (int)notifications);

			run_block_production();
			return expectation::met;
		}
		expects_rt<void> server_node::notify_of_block_hash(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 2)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			uint256_t block_number = event.args[1].as_uint64();
			if (!block_hash && !block_number)
				return expectation::met;

			auto chain = storages::chainstate();
			auto target = block_number > 0 ? chain.get_block_header_by_number(block_number) : chain.get_block_header_by_hash(block_hash);
			if (target && (!block_number || block_number == target->number) && (!block_hash || block_hash == target->as_hash()))
				return expectation::met;

			query(uref(state), descriptors::query_block(), { format::variable(block_hash), format::variable(block_number) }, protocol::now().user.tcp.timeout).then([this, state](expects_rt<exchange>&& event) mutable
			{
				if (event && !event->args.empty())
				{
					ledger::block_evaluation candidate;
					format::ro_stream block_message = format::ro_stream(event->args.front().as_string());
					if (candidate.block.load(block_message))
						accept_block(std::move(state), std::move(candidate), 0);
				}
			});
			return expectation::met;
		}
		expects_rt<void> server_node::notify_of_transaction_hash(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint256_t transaction_hash = event.args.front().as_uint256();
			if (!transaction_hash)
				return remote_exception("invalid hash");

			auto mempool = storages::mempoolstate();
			if (mempool.get_transaction_by_hash(transaction_hash))
				return expectation::met;

			auto chain = storages::chainstate();
			if (chain.get_transaction_by_hash(transaction_hash))
				return expectation::met;

			query(uref(state), descriptors::query_transaction(), { format::variable(transaction_hash) }, protocol::now().user.tcp.timeout).then([this, state](expects_rt<exchange>&& event) mutable
			{
				if (event && !event->args.empty())
				{
					format::ro_stream transaction_message = format::ro_stream(event->args.front().as_string());
					uptr<ledger::transaction> candidate = tangent::transactions::resolver::from_stream(transaction_message);
					if (candidate && candidate->load(transaction_message))
						accept_transaction(std::move(state), std::move(candidate));
				}
			});
			return expectation::met;
		}
		expects_rt<void> server_node::notify_of_attestation(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 3)
				return remote_exception("invalid arguments");

			algorithm::asset_id asset = event.args[0].as_uint256();
			format::ro_stream proof_message = format::ro_stream(event.args[1].as_string());
			oracle::computed_transaction proof;
			if (!proof.load(proof_message))
				return remote_exception("invalid proof");

			uint256_t commitment_hash = proof.as_hash();
			algorithm::pubkeyhash_t attester;
			algorithm::hashsig_t commitment = algorithm::hashsig_t(event.args[2].as_string());
			if (!algorithm::signing::recover_hash(commitment_hash, attester, commitment))
				return remote_exception("invalid commitment");

			auto context = ledger::transaction_context();
			auto validation = context.verify_validator_attestation(asset, attester);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto mempool = storages::mempoolstate();
			auto status = mempool.add_attestation(asset, proof, commitment);
			if (!status)
				return remote_exception(std::move(status.error().message()));

			auto finalization = accept_attestation(uref(state), proof.as_attestation_hash());
			if (finalization)
				return expectation::met;

			size_t notifications = notify_all_except(std::move(state), descriptors::notify_of_attestation(), format::variables(event.args));
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_INFO("attestation %s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);

			return expectation::met;
		}
		expects_rt<void> server_node::notify_of_aggregation(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() < 3 || event.args.size() > 2 + protocol::now().policy.participation_max_per_account)
				return remote_exception("invalid arguments");

			auto signature = algorithm::hashsig_t(event.args[0].as_string());
			if (signature.empty())
				return remote_exception("invalid signature");

			auto address = text_address_to_socket_address(event.args[1].as_string());
			if (!address || routing_util::is_address_reserved(*address))
				return remote_exception("invalid address");

			auto context = ledger::transaction_context();
			size_t accounts_size = event.args.size() - 2;
			ordered_set<algorithm::pubkeyhash_t> accounts;
			for (size_t i = 2; i < event.args.size(); i++)
			{
				auto account = algorithm::pubkeyhash_t(event.args[i].as_string());
				if (account.empty())
					return remote_exception("invalid account");

				accounts.insert(account);
			}
			if (accounts.size() != accounts_size || accounts.empty())
				return remote_exception("invalid accounts");

			algorithm::pubkeyhash_t account;
			if (!algorithm::signing::recover_hash(discovery_proof(*address, accounts), account, signature))
				return remote_exception("invalid signature");

			if (accounts.find(descriptor.second.public_key_hash) != accounts.end())
				connect_to_physical_node(*address, account);

			size_t notifications = notify_all_except(std::move(state), descriptors::notify_of_aggregation(), format::variables(event.args));
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_INFO("aggregation from %s broadcasted to %i nodes", algorithm::signing::encode_address(account).c_str(), (int)notifications);

			return expectation::met;
		}
		expects_rt<format::variables> server_node::query_handshake(uref<relay>&& state, const exchange& event, bool is_acknowledgement)
		{
			if (event.args.size() != (is_acknowledgement ? 4 : 3))
				return remote_exception("invalid arguments");

			relay_descriptor peer_descriptor;
			auto& [peer_node, peer_wallet] = peer_descriptor;
			uint64_t system_time = protocol::now().time.now_cpu();
			format::ro_stream peer_message = format::ro_stream(event.args[0].as_string());
			uint64_t peer_time = event.args[1].as_uint64();
			algorithm::hashsig_t peer_signature = algorithm::hashsig_t(event.args[2].as_string());
			if (!peer_node.load(peer_message))
				return remote_exception("invalid message");
			else if (!algorithm::signing::recover(handshake_proof(peer_node, peer_time), peer_wallet.public_key, peer_signature))
				return remote_exception("invalid signature");
			
			auto mempool = storages::mempoolstate();
			uint64_t peer_latency = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
			peer_node.availability.latency = peer_latency;
			peer_node.availability.reachable = is_acknowledgement;
			peer_node.address = socket_address(state->peer_address(), peer_node.address.get_ip_port().or_else(protocol::now().user.consensus.port));
			algorithm::signing::derive_public_key_hash(peer_wallet.public_key, peer_wallet.public_key_hash);
			if (!peer_node.is_valid() || peer_wallet.public_key_hash.empty() || peer_wallet.public_key_hash.equals(descriptor.second.public_key_hash))
			{
				mempool.clear_node(peer_descriptor.first.address);
				return remote_exception("invalid node");
			}

			auto prev_descriptor = mempool.get_node(peer_node.address);
			if (prev_descriptor)
				peer_node.availability.reachable = peer_node.availability.reachable || prev_descriptor->first.availability.reachable;

			apply_node(mempool, peer_descriptor).report("mempool peer node save failed");
			state->initialize(std::move(peer_descriptor));
			if (is_acknowledgement)
				return format::variables();

			auto& [node, wallet] = descriptor;
			if (!algorithm::signing::sign(handshake_proof(node, system_time), wallet.secret_key, peer_signature))
				return remote_exception("proof generation error");

			return format::variables({ format::variable(node.as_message().data), format::variable(system_time), format::variable(peer_signature.optimized_view()), format::variable(peer_latency) });
		}
		expects_rt<format::variables> server_node::query_state(uref<relay>&& state, const exchange& event, bool is_acknowledgement)
		{
			if (event.args.size() < 3)
				return remote_exception("invalid arguments");

			auto mempool = storages::mempoolstate();
			auto address = text_address_to_socket_address(event.args[0].as_string());
			if (address && !routing_util::is_address_reserved(*address))
			{
				descriptor.first.address = std::move(*address);
				apply_node(mempool, descriptor).report("mempool local node save failed");
			}

			auto block_handle = exchange();
			block_handle.args.reserve(2);
			block_handle.args.push_back(event.args[1]);
			block_handle.args.push_back(event.args[2]);

			auto status = notify_of_block_hash(uref(state), std::move(block_handle));
			if (!status)
				return status.error();

			size_t new_nodes = 0;
			for (size_t i = 3; i < event.args.size(); i++)
			{
				auto address = text_address_to_socket_address(event.args[i].as_string());
				if (address && !routing_util::is_address_reserved(*address))
					new_nodes += mempool.apply_unknown_node(*address) ? 1 : 0;
			}

			if (new_nodes > 0)
				run_topology_optimization();

			bool accepted = accept_meeting_committee_node(uref(state));
			if (is_acknowledgement)
				return format::variables();

			if (!accepted)
			{
				umutex<std::recursive_mutex> unique(exclusive);
				if (active.size() > protocol::now().user.consensus.max_inbound_connections)
					return remote_exception("not permitted to pass connections limit");
			}

			return build_state_exchange(std::move(state));
		}
		expects_rt<format::variables> server_node::query_headers(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint64_t branch_number = event.args.front().as_uint64();
			if (!branch_number)
				return remote_exception("invalid branch");

			const uint64_t blocks_count = protocol::now().user.consensus.headers_per_query;
			const uint64_t pivot_number = branch_number > blocks_count ? branch_number - blocks_count : 1;
			auto chain = storages::chainstate();
			auto headers = chain.get_block_headers(pivot_number, blocks_count);
			if (!headers || headers->empty())
				return format::variables({ });

			format::variables result;
			result.reserve(headers->size() + 1);
			result.push_back(format::variable(pivot_number + headers->size() - 1));
			for (auto& item : *headers)
				result.push_back(format::variable(item.as_message().data));

			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::query_block(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 2)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			if (block_hash > 0)
			{
				auto chain = storages::chainstate();
				auto block = chain.get_block_by_hash(block_hash, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
					return format::variables({ format::variable(block->as_message().data) });
			}

			uint256_t block_number = event.args[1].as_uint64();
			if (block_number > 0)
			{
				auto chain = storages::chainstate();
				auto block = chain.get_block_by_number(block_number, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
					return format::variables({ format::variable(block->as_message().data) });
			}

			return format::variables();
		}
		expects_rt<format::variables> server_node::query_mempool(uref<relay>&& state, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint64_t cursor = event.args.front().as_uint64();
			const uint64_t transactions_count = protocol::now().user.consensus.hashes_per_query;
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
		expects_rt<format::variables> server_node::query_transaction(uref<relay>&& state, const exchange& event)
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
			transaction = chain.get_transaction_by_hash(transaction_hash);
			if (transaction)
				return format::variables({ format::variable((*transaction)->as_message().data) });	

			return format::variables();
		}
		expects_rt<format::variables> server_node::aggregate_secret_share_state(uref<relay>&& state, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, descriptor.second.secret_key);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry();

			auto context = ledger::transaction_context();
			auto proof_transaction = context.get_block_transaction<transactions::bridge_migration>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto aggregator = ledger::dispatch_context::secret_share_state();
			if (!aggregator.load_message(reader))
				return remote_exception("state machine not valid");

			auto dispatcher = dispatch_context(this);
			context.transaction = *proof_transaction->transaction;
			context.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatch_context::aggregate_secret_share_state(&dispatcher, &context, aggregator);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			return pack_private_result({ format::variable(aggregator.confirmation_signature.optimized_view()) }, *state);
		}
		expects_rt<format::variables> server_node::aggregate_public_state(uref<relay>&& state, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, descriptor.second.secret_key);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry();

			auto context = ledger::transaction_context();
			auto proof_transaction = context.get_block_transaction<transactions::bridge_account>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto aggregator = algorithm::composition::load_public_state(reader);
			if (!aggregator)
				return remote_exception("in state machine not valid");

			auto dispatcher = dispatch_context(this);
			context.transaction = *proof_transaction->transaction;
			context.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatch_context::aggregate_public_state(&dispatcher, &context, **aggregator);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			format::wo_stream writer;
			if (!(*aggregator)->store(&writer))
				return remote_exception("out state machine not valid");

			return pack_private_result({ format::variable(writer.data) }, *state);
		}
		expects_rt<format::variables> server_node::aggregate_signature_state(uref<relay>&& state, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, descriptor.second.secret_key);
			if (!packed)
				return packed;
			else if (packed->size() != 4)
				return remote_exception("invalid arguments");

			auto chainstate = storages::chainstate();
			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry();

			auto context = ledger::transaction_context();
			auto proof_transaction = context.get_block_transaction<transactions::bridge_withdrawal>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto message = oracle::prepared_transaction();
			if (!message.load(reader))
				return remote_exception("in state message not valid");

			reader = format::ro_stream(packed->at(3).as_string());
			auto aggregator = algorithm::composition::load_signature_state(reader);
			if (!aggregator)
				return remote_exception("in state machine not valid");

			auto* proof_transaction_ptr = (transactions::bridge_withdrawal*)*proof_transaction->transaction;
			auto validation = transactions::bridge_withdrawal_finalization::validate_possible_proof(&context, proof_transaction_ptr, message);
			if (!validation)
				return remote_exception("group validation error");

			auto dispatcher = dispatch_context(this);
			context.transaction = *proof_transaction->transaction;
			context.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatch_context::aggregate_signature_state(&dispatcher, &context, message, **aggregator);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			format::wo_stream writer;
			if (!(*aggregator)->store(&writer))
				return remote_exception("out state machine not valid");

			return pack_private_result({ format::variable(writer.data) }, *state);
		}
		expects_lr<void> server_node::dispatch_transaction_logs(const algorithm::asset_id& asset, const oracle::chain_supervisor_options& options, oracle::transaction_logs&& logs)
		{
			auto& [node, wallet] = descriptor;
			for (auto& receipt : logs.finalized)
			{
				algorithm::hashsig_t commitment_signature; uint256_t commitment_hash;
				if (!transactions::bridge_attestation::commit_to_proof(receipt, wallet.secret_key, commitment_hash, commitment_signature))
					continue;

				auto mempool = storages::mempoolstate();
				auto status = mempool.add_attestation(asset, receipt, commitment_signature);
				if (!status)
					continue;

				auto finalization = accept_attestation(nullptr, receipt.as_attestation_hash());
				if (finalization)
					continue;

				auto proof_message = receipt.as_message();
				size_t notifications = notify_all(descriptors::notify_of_attestation(), { format::variable(proof_message.data), format::variable(commitment_signature.view()) });
				if (notifications > 0 && protocol::now().user.consensus.logging)
					VI_INFO("attestation %s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);
			}
			return expectation::met;
		}
		expects_lr<socket_address> server_node::find_node_from_mempool()
		{
			size_t offset = 0;
			auto mempool = storages::mempoolstate();
		retry_known_node:
			auto known_node = mempool.get_neighbor_node(offset);
			if (!known_node)
			{
			retry_unknown_node:
				auto unknown_node = mempool.sample_unknown_node();
				if (!unknown_node)
					return layer_exception("no candidate found in mempool");

				if (has_address(*unknown_node) || routing_util::is_address_reserved(*unknown_node) || mempool.has_cooldown_on_node(*unknown_node).or_else(false))
					goto retry_unknown_node;

				if (protocol::now().user.consensus.logging)
					VI_INFO("node %s:%i handshake: try unknown node", unknown_node->get_ip_address().or_else(string("[bad_address]")).c_str(), (int)unknown_node->get_ip_port().or_else(0));

				return expects_lr<socket_address>(std::move(*unknown_node));
			}
			else if (has_address(known_node->first.address) || routing_util::is_address_reserved(known_node->first.address) || mempool.has_cooldown_on_node(known_node->first.address).or_else(false))
			{
				++offset;
				goto retry_known_node;
			}

			if (protocol::now().user.consensus.logging)
				VI_INFO("node %s:%i handshake: try known node", known_node->first.address.get_ip_address().or_else(string("[bad_address]")).c_str(), (int)known_node->first.address.get_ip_port().or_else(0));

			return expects_lr<socket_address>(std::move(known_node->first.address));
		}
		expects_promise_rt<socket_address> server_node::find_node_from_discovery()
		{
			if (!is_active())
				return expects_promise_rt<socket_address>(remote_exception::shutdown());

			auto early_test = find_node_from_mempool();
			if (early_test)
				return expects_promise_rt<socket_address>(std::move(*early_test));

			if (protocol::now().user.bootstrap_nodes.empty())
				return expects_promise_rt<socket_address>(remote_exception("no bootstrap nodes"));

			return coasync<expects_rt<socket_address>>([this]() -> expects_promise_rt<socket_address>
			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto lists = vector<string>(protocol::now().user.bootstrap_nodes.begin(), protocol::now().user.bootstrap_nodes.end());
				unique.unlock();

				auto random = std::default_random_engine();
				std::shuffle(std::begin(lists), std::end(lists), random);
				for (auto& bootstrap_url : lists)
				{
					size_t results = std::numeric_limits<size_t>::max();
					auto response = coawait(http::fetch(bootstrap_url));
					if (response)
					{
						auto addresses = uptr<schema>(response->content.get_json());
						if (addresses)
						{
							auto mempool = storages::mempoolstate(); results = 0;
							for (auto* address : addresses->get_childs())
							{
								auto endpoint = system_endpoint(address->value.get_blob(), bootstrap_url);
								if (endpoint.is_valid() && !routing_util::is_address_reserved(endpoint.address) && mempool.apply_unknown_node(endpoint.address))
									++results;
							}
						}
					}

					if (protocol::now().user.consensus.logging)
					{
						if (results != std::numeric_limits<size_t>::max())
							VI_INFO("bootstrap node %s %sresults found (addresses: %" PRIu64 ")", bootstrap_url.c_str(), results > 0 ? "" : "no ", (uint64_t)results);
						else
							VI_WARN("bootstrap node %s no results found: bad bootstrap node", bootstrap_url.c_str());
					}
				}

				auto late_test = find_node_from_mempool();
				if (!late_test)
					coreturn remote_exception(std::move(late_test.error().message()));

				coreturn expects_rt<socket_address>(std::move(*late_test));
			});
		}
		expects_promise_rt<uref<relay>> server_node::connect_to_physical_node(const socket_address& address, option<algorithm::pubkeyhash_t>&& required_account)
		{
			if (!is_active())
				return expects_promise_rt<uref<relay>>(remote_exception::shutdown());

			if (routing_util::is_address_reserved(address))
				return expects_promise_rt<uref<relay>>(remote_exception("address is reserved"));

			auto duplicate = find_by_address(address);
			if (duplicate)
				return expects_promise_rt<uref<relay>>(std::move(duplicate));
			else if (has_address(address))
				return expects_promise_rt<uref<relay>>(remote_exception("possible loopback"));

			return coasync<expects_rt<uref<relay>>>([this, address, required_account = std::move(required_account)]() mutable -> expects_promise_rt<uref<relay>>
			{
				uptr<outbound_node> candidate = new outbound_node();
				append_pending_node(*candidate);
				auto status = coawait(candidate->connect_async(address, PEER_NOT_SECURE));
				auto duplicate = find_by_address(candidate->get_peer_address());
				erase_pending_node(*candidate);
				if (duplicate)
					coreturn expects_promise_rt<uref<relay>>(std::move(duplicate));
				else if (!status)
					coreturn remote_exception(std::move(status.error().message()));

				auto& [node, wallet] = descriptor;
				algorithm::hashsig_t signature;
				uint64_t system_time = protocol::now().time.now_cpu();
				if (!algorithm::signing::sign(handshake_proof(node, system_time), wallet.secret_key, signature))
					coreturn remote_exception("proof generation error");

				uref<relay> state = new relay(node_type::outbound, candidate.reset());
				append_node(uref(state));

				auto abort = [&](remote_exception&& exception) -> remote_exception&&
				{
					state->abort();
					return std::move(exception);
				};
				auto handshake = query(uref(state), descriptors::query_handshake(), { format::variable(node.as_message().data), format::variable(system_time), format::variable(signature.optimized_view()) }, protocol::now().user.tcp.timeout, true);
				pull_messages(uref(state));
		
				auto result = coawait(std::move(handshake));
				if (!result)
					coreturn abort(std::move(result.error()));

				auto acknowledgement = query_handshake(uref(state), *result, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto* peer_descriptor = state->as_descriptor();
				if (!peer_descriptor || (required_account && !peer_descriptor->second.public_key_hash.equals(*required_account)))
					coreturn abort(remote_exception("invalid descriptor"));
				
				auto subresult = coawait(query(uref(state), descriptors::query_state(), build_state_exchange(uref(state)), protocol::now().user.tcp.timeout));
				if (!subresult)
					coreturn abort(remote_exception(std::move(subresult.error().message())));

				acknowledgement = query_state(uref(state), *subresult, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto& protocol = protocol::change();
				uint64_t peer_time = result->args[1].as_uint64();
				uint64_t peer_latency = result->args[3].as_uint64();
				uint64_t latency_time = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
				uint64_t varying_peer_time = peer_time + (peer_latency + latency_time) / 2;
				protocol.time.adjust(peer_descriptor->first.address, (int64_t)system_time - (int64_t)varying_peer_time);
				synchronize_mempool_with(uref(state));
				coreturn expects_rt<uref<relay>>(std::move(state));
			}).then<expects_rt<uref<relay>>>([address](expects_rt<uref<relay>>&& result) -> expects_rt<uref<relay>>
			{
				if (!result)
				{
					auto mempool = storages::mempoolstate();
					mempool.apply_node_quality(address, -1, protocol::now().user.tcp.timeout, protocol::now().user.consensus.topology_timeout);
					if (protocol::now().user.consensus.logging)
						VI_WARN("node %s:%i handshake: %s", address.get_ip_address().or_else("[bad_address]").c_str(), (int)address.get_ip_port().or_else(0), result.what().c_str());
				}
				return result;
			});
		}
		expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>> server_node::connect_to_meeting_committee(const uint256_t& committee_meeting_hash, unordered_set<algorithm::pubkeyhash_t>&& accounts)
		{
			if (!committee_meeting_hash || accounts.empty())
				return expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>>(remote_exception("invalid arguments"));

			size_t reduction = 0;
			unordered_map<algorithm::pubkeyhash_t, uref<relay>> early_results;
			for (auto& account : accounts)
			{
				auto target = find_by_account(account);
				if (target)
					early_results[account] = std::move(target);
				else if (account.equals(descriptor.second.public_key_hash))
					++reduction;
			}
			if (early_results.size() == accounts.size() - reduction)
				return expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>>(std::move(early_results));

			return coasync<expects_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>>>([this, committee_meeting_hash, accounts = std::move(accounts), early_results = std::move(early_results)]() mutable -> expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>>
			{
				unordered_map<algorithm::pubkeyhash_t, expects_promise_rt<uref<relay>>> directly_connected_accounts;
				ordered_set<algorithm::pubkeyhash_t> indirectly_connected_accounts;
				{
					auto mempool = storages::mempoolstate();
					for (auto& account : accounts)
					{
						auto it = early_results.find(account);
						if (it == early_results.end())
						{
							auto target = mempool.get_node(account);
							if (target && target->first.availability.reachable)
								directly_connected_accounts[account] = connect_to_physical_node(target->first.address, account);
							else
								indirectly_connected_accounts.insert(account);
						}
						else
							directly_connected_accounts[account] = expects_promise_rt<uref<relay>>(std::move(it->second));
					}
				}

				unordered_map<algorithm::pubkeyhash_t, uref<relay>> results;
				for (auto& [account, directly_connected_account] : directly_connected_accounts)
				{
					auto result = coawait(std::move(directly_connected_account));
					if (result)
						results[account] = std::move(*result);
					else
						indirectly_connected_accounts.insert(account);
				}

				if (!indirectly_connected_accounts.empty())
				{
					auto& [node, wallet] = descriptor;
					auto connections = expects_promise_rt<vector<uref<relay>>>(remote_exception::retry());
					auto address = socket_address_to_text_address(node.address);
					if (address)
					{
						algorithm::hashsig_t signature;
						if (algorithm::signing::sign(discovery_proof(node.address, indirectly_connected_accounts), wallet.secret_key, signature))
						{
							umutex<std::recursive_mutex> unique(sync.meeting);
							auto it = meetings.find(committee_meeting_hash);
							if (it == meetings.end())
							{
								auto& meeting = meetings[committee_meeting_hash];
								meeting.accounts = std::move(indirectly_connected_accounts);

								format::variables args;
								args.reserve(meeting.accounts.size() + 2);
								args.push_back(format::variable(signature.optimized_view()));
								args.push_back(format::variable(*address));
								for (auto& account : meeting.accounts)
									args.push_back(format::variable(account.optimized_view()));

								size_t notifications = notify_all(descriptors::notify_of_aggregation(), std::move(args));
								if (notifications)
									meeting.timeout = schedule::get()->set_timeout(protocol::now().user.tcp.timeout, std::bind(&server_node::clear_pending_meeting, this, committee_meeting_hash));
								else
									meetings.erase(committee_meeting_hash);

								connections = expects_promise_rt<vector<uref<relay>>>(meeting.task);
							}
						}
					}

					auto meeting_results = coawait(std::move(connections));
					if (meeting_results)
					{
						for (auto& meeting_result : *meeting_results)
						{
							auto* peer_descriptor = meeting_result->as_descriptor();
							if (peer_descriptor != nullptr)
								results[peer_descriptor->second.public_key_hash] = std::move(meeting_result);
						}
					}
				}

				coreturn expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>>(std::move(results));
			});
		}
		expects_promise_rt<void> server_node::synchronize_mempool_with(uref<relay>&& state)
		{
			return coasync<expects_rt<void>>([this, state]() -> expects_promise_rt<void>
			{
				uint64_t cursor = 0;
				while (true)
				{
					auto result = coawait(query(uref(state), descriptors::query_mempool(), { format::variable(cursor) }, protocol::now().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.size() < 2)
						break;

					ordered_set<uint256_t> transaction_hashes;
					{
						auto mempool = storages::mempoolstate();
						auto chain = storages::chainstate();
						for (size_t i = 1; i < result->args.size(); i++)
						{
							auto transaction_hash = result->args[i].as_uint256();
							if (!mempool.has_transaction(transaction_hash).or_else(false) && !chain.get_transaction_by_hash(transaction_hash))
								transaction_hashes.insert(transaction_hash);
						}
					}

					for (auto& transaction_hash : transaction_hashes)
					{
						auto subresult = coawait(query(uref(state), descriptors::query_transaction(), { format::variable(transaction_hash) }, protocol::now().user.tcp.timeout));
						if (!subresult || subresult->args.empty())
							continue;

						format::ro_stream transaction_message = format::ro_stream(subresult->args.front().as_string());
						uptr<ledger::transaction> candidate = tangent::transactions::resolver::from_stream(transaction_message);
						if (candidate && candidate->load(transaction_message))
							accept_transaction(uref(state), std::move(candidate));
					}

					const uint64_t transactions_count = protocol::now().user.consensus.hashes_per_query;
					cursor = result->args.front().as_uint64();
					if (result->args.size() < transactions_count)
						break;
				}
				coreturn expectation::met;
			}, true);
		}
		expects_promise_rt<void> server_node::resolve_and_verify_fork(std::pair<uint256_t, fork_header>&& fork)
		{
			return coasync<expects_rt<void>>([this, fork = std::move(fork)]() mutable -> expects_promise_rt<void>
			{
				auto& [new_tip_fork_hash, new_tip] = fork;
				auto new_tip_hash = uint256_t(0);
				auto new_tip_number = new_tip.header.number;
				auto old_tip_number = storages::chainstate().get_latest_block_number().or_else(0);
				while (old_tip_number > 0)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::query_headers(), { format::variable(new_tip_number) }, protocol::now().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.empty())
						break;

					new_tip_number = result->args.front().as_uint64();
					if (!new_tip_number || result->args.size() < 2)
						coreturn remote_exception("invalid branch");

					if (protocol::now().user.consensus.logging)
					{
						uint64_t blocks_count = (uint64_t)(result->args.size() - 1);
						VI_INFO("block %s chain fork: resolution in range: [%" PRIu64 "; %" PRIu64 "]", algorithm::encoding::encode_0xhex256(new_tip_fork_hash).c_str(), new_tip_number - (blocks_count > new_tip_number ? 1 : blocks_count), new_tip_number);
					}

					format::ro_stream block_message = format::ro_stream(result->args[1].as_string());
					ledger::block_header child_header;
					if (!child_header.load(block_message))
						coreturn remote_exception("invalid block header");

					ledger::block_header parent_header;
					size_t block_range = result->args.size() + 1;
					for (size_t i = 2; i < block_range; i++)
					{
						uint256_t branch_hash = child_header.as_hash(true);
						auto collision = storages::chainstate().get_block_header_by_hash(branch_hash);
						if (collision || --new_tip_number < 1)
						{
							if (protocol::now().user.consensus.logging)
								VI_INFO("block %s chain fork: collision detected (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(branch_hash).c_str(), child_header.number);

							new_tip_hash = branch_hash;
							old_tip_number = 0;
							break;
						}
						else if (i < result->args.size())
						{
							block_message.clear();
							block_message.data = result->args[i].as_string();
							if (!parent_header.load(block_message))
								coreturn remote_exception("invalid block header");
						}

						parent_header.checksum = 0;
						auto verification = child_header.verify_validity(parent_header.number > 0 ? &parent_header : nullptr);
						if (!verification)
							coreturn remote_exception("invalid block header: " + verification.error().message());

						child_header = parent_header;
					}
				}

				new_tip_number = new_tip_hash > 0 ? 0 : 1;
				while (new_tip_number > 0 || new_tip_hash > 0)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::query_block(), { format::variable(new_tip_hash), format::variable(new_tip_number) }, protocol::now().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.empty())
						break;

					ledger::block_evaluation tip;
					format::ro_stream block_message = format::ro_stream(result->args.front().as_string());
					if (!tip.block.load(block_message))
						coreturn remote_exception("fork block rejected");

					new_tip_hash = 0;
					new_tip_number = tip.block.number + 1;
					if (!accept_block(uref(new_tip.state), std::move(tip), new_tip_fork_hash))
						coreturn remote_exception("fork block rejected");
				}

				coreturn expectation::met;
			});
		}
		expects_promise_rt<exchange> server_node::query(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call)
		{
			if (!force_call && !state->fully_valid())
				return expects_promise_rt<exchange>(remote_exception("node is not in valid state (offline/unauthorized)"));

			if (protocol::now().user.consensus.logging)
				VI_DEBUG("node %s query \"%.*s\" out: %s (%s %s)", state->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str(), routing_util::node_type_of(*state).data(), state->peer_service().c_str());

			auto result = state->push_query(descriptor, std::move(args), timeout_ms);
			push_messages(uref(state));
			return result;
		}
		expects_lr<void> server_node::notify(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args)
		{
			if (!state->fully_valid())
				return layer_exception("node is not in valid state (offline/unauthorized)");

			if (protocol::now().user.consensus.logging)
				VI_DEBUG("node %s notify \"%.*s\" out: %s (%s %s)", state->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str(), routing_util::node_type_of(*state).data(), state->peer_service().c_str());

			if (!state->push_event(descriptor, std::move(args)))
				return layer_exception("duplicate notification");

			push_messages(uref(state));
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

			size_t events = 0;
			for (auto& node : receivers)
				events += *exception != *node ? notify(uref(node), descriptor, format::variables(args)) ? 1 : 0 : 0;
			return events;
		}
		format::variables server_node::build_state_exchange(uref<relay>&& state)
		{
			auto chain = storages::chainstate();
			auto tip = chain.get_latest_block_header();
			auto* descriptor = state->as_descriptor();
			auto address = descriptor ? socket_address_to_text_address(descriptor->first.address).or_else(string()) : string();
			format::variables args =
			{
				format::variable(address),
				format::variable(tip ? tip->as_hash() : uint256_t(0)),
				format::variable(tip ? tip->number : 0)
			};

			auto mempool = storages::mempoolstate();
			auto nodes = mempool.get_random_nodes_with(protocol::now().user.consensus.hashes_per_query).or_else(vector<storages::node_location_pair>());
			args.reserve(2 + nodes.size());
			for (auto& [account, address] : nodes)
			{
				auto text_address = socket_address_to_text_address(address);
				if (text_address)
					args.push_back(format::variable(*text_address));
			}
			return args;
		}
		void server_node::bind_event(const callable::descriptor& descriptor, event_callback&& on_event_callback)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.event = std::move(on_event_callback);
		}
		void server_node::bind_query(const callable::descriptor& descriptor, query_callback&& on_query_callback)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.query = std::move(on_query_callback);
		}
		void server_node::pull_messages(uref<relay>&& state)
		{
			VI_ASSERT(state, "state should be set");
			auto* stream = state->as_socket();
			if (!stream)
				return;
		retry:
			if (state->pull_incoming_message(nullptr, 0))
			{
				exchange message;
				state->incoming_message_into(&message);

				bool query_response = message.type == exchange::side::event && message.descriptor == 0 && message.session > 0;
				if (query_response)
				{
					state->resolve_query(std::move(message));
					goto retry;
				}

				auto it = callables.find(message.descriptor);
				if (it == callables.end())
				{
				abort:
					auto* descriptor = state->as_descriptor();
					if (descriptor != nullptr)
					{
						auto mempool = storages::mempoolstate();
						mempool.apply_node_quality(descriptor->first.address, -1, message.calculate_latency(), protocol::now().user.consensus.topology_timeout);
					}

					return abort_node(uref(state));
				}

				auto& target = it->second;
				if ((message.type == exchange::side::event && !target.event) || (message.type == exchange::side::query && (!target.query || !message.session)) || (message.type != exchange::side::query && message.type != exchange::side::event))
					goto abort;
				
				if (message.type == exchange::side::event)
				{
					uint256_t hash = message.as_hash();
					umutex<std::mutex> unique(sync.inventory);
					if (!inventory.insert(hash) || !state->get_inventory().insert(hash))
						goto retry;
				}

				return cospawn([this, &target, state, message = std::move(message)]() mutable
				{
					auto result = expects_rt<format::variables>(remote_exception::shutdown());
					if (message.type == exchange::side::query)
					{
						result = target.query(this, uref(state), message);
						state->push_event(message.session, pack_query_result(result));
						push_messages(uref(state));
					}
					else
					{
						auto status = target.event(this, uref(state), message);
						result = status ? expects_rt<format::variables>(format::variables()) : expects_rt<format::variables>(std::move(status.error()));
					}

					auto* descriptor = state->as_descriptor();
					if (descriptor != nullptr)
					{
						auto mempool = storages::mempoolstate();
						mempool.apply_node_quality(descriptor->first.address, result ? 1 : (result.error().is_retry() ? 0 : -1), message.calculate_latency(), protocol::now().user.consensus.topology_timeout);
					}

					if (!result)
					{
						if (protocol::now().user.consensus.logging)
							VI_WARN("node %s %s \"%.*s\" error%s: %s (%s %s)", state->peer_address().c_str(), message.type == exchange::side::query ? "query" : "event", (int)target.name.size(), target.name.data(), message.type == exchange::side::query ? " out" : "", result.what().c_str(), routing_util::node_type_of(*state).data(), state->peer_service().c_str());
						if (!result.error().is_retry())
							abort_node(std::move(state));
						else
							pull_messages(std::move(state));
					}
					else
					{
						if (protocol::now().user.consensus.logging)
							VI_DEBUG("node %s %s \"%.*s\" result%s: %s (%s %s)", state->peer_address().c_str(), message.type == exchange::side::query ? "query" : "event", (int)target.name.size(), target.name.data(), message.type == exchange::side::query ? " out" : "", result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str(), routing_util::node_type_of(*state).data(), state->peer_service().c_str());
						pull_messages(std::move(state));
					}
				});
			}
			else
			{
				uint8_t buffer[BLOB_SIZE];
				size_t max_buffer_size = sizeof(buffer);
				uint64_t next_pull_time = 0;
				while (state->bandwidth.check(max_buffer_size, next_pull_time))
				{
					auto size = stream->read(buffer, std::min(max_buffer_size, sizeof(buffer)));
					if (!size)
					{
						if (size.error() != std::errc::operation_would_block)
							return abort_node(std::move(state));

						multiplexer::get()->when_readable(stream, [this, state](socket_poll event) mutable
						{
							if (packet::is_done(event))
								pull_messages(std::move(state));
							else if (packet::is_error(event))
								abort_node(std::move(state));
						});
						return;
					}

					state->bandwidth.spend(*size);
					if (state->pull_incoming_message(buffer, *size))
						goto retry;
				}

				state->deferred_pull = schedule::get()->set_timeout(next_pull_time, [this, state]() mutable
				{
					state->deferred_pull = INVALID_TASK_ID;
					pull_messages(std::move(state));
				});
			}
		}
		void server_node::push_messages(uref<relay>&& state)
		{
			VI_ASSERT(state, "state and abort callback should be set");
			auto* stream = state->as_socket();
			if (!stream || !state->begin_outgoing_message())
				return;

			auto* ref = *state;
			ref->add_ref();
			stream->write_queued(state->outgoing_buffer(), state->outgoing_size(), [this, stream, ref](socket_poll event)
			{
				size_t size = ref->outgoing_size();
				ref->end_outgoing_message();
				if (packet::is_done(event))
					push_messages(uref(ref));
				else if (packet::is_error(event))
					abort_node(uref(ref));
			}, false);
		}
		void server_node::abort_node(uref<relay>&& state)
		{
			VI_ASSERT(state, "state should be set");
			auto* inbound_node = state->as_inbound_node();
			auto* outbound_node = state->as_outbound_node();
			state->abort();
			erase_node(std::move(state));
			if (inbound_node != nullptr)
			{
				inbound_node->abort();
				finalize(inbound_node);
			}
			if (outbound_node != nullptr)
				outbound_node->release();
		}
		void server_node::abort_node_by_account(const algorithm::pubkeyhash_t& account)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* descriptor = node.second->as_descriptor();
				if (descriptor != nullptr && descriptor->second.public_key_hash.equals(account))
				{
					unique.unlock();
					return abort_node(uref(node.second));
				}
			}
		}
		void server_node::append_node(uref<relay>&& state)
		{
			VI_ASSERT(state, "node should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(state->as_instance());
			if (it != nodes.end() && *it->second == *state)
				return;

			auto* socket = state->as_socket();
			if (socket != nullptr)
				socket->set_io_timeout(protocol::now().user.tcp.timeout);

			auto& node = nodes[state->as_instance()];
			VI_ASSERT(!node || *node == *state, "invalid state");
			node = std::move(state);
		}
		void server_node::erase_node(uref<relay>&& state)
		{
			VI_ASSERT(state, "node should be set");
			erase_node_by_instance(state->as_instance());
		}
		void server_node::erase_node_by_instance(void* instance)
		{
			VI_ASSERT(instance != nullptr, "instance should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			if (it == nodes.end())
				return;

			uref<relay> state = std::move(it->second);
			nodes.erase(it);
			unique.unlock();
			clear_pending_fork(*state);
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

			auto state = find_node_by_instance(node);
			if (state)
				return pull_messages(uref(state));

			auto duplicate = find_by_address(node->address);
			if (!duplicate)
			{
				state = new relay(node_type::inbound, node);
				append_node(uref(state));
				pull_messages(uref(state));
			}
			else
			{
				node->abort();
				finalize(node);
			}
		}
		bool server_node::run_topology_optimization()
		{
			return control_sys.async_task_if_none(TASK_TOPOLOGY_OPTIMIZATION, [this]() -> promise<void>
			{
				algorithm::pubkeyhash_t worst_account;
				unordered_set<algorithm::pubkeyhash_t> current_nodes;
				{
					uint64_t worst_preference = std::numeric_limits<uint64_t>::max();
					umutex<std::recursive_mutex> unique(exclusive);
					current_nodes.reserve(nodes.size());
					for (auto& node : nodes)
					{
						auto* descriptor = node.second->as_descriptor();
						if (descriptor != nullptr && node.second->as_outbound_node() != nullptr)
						{
							uint64_t preference = descriptor->first.get_preference();
							current_nodes.insert(descriptor->second.public_key_hash);
							if (worst_preference > preference)
							{
								worst_account = descriptor->second.public_key_hash;
								worst_preference = preference;
							}
						}
					}
				}

				bool try_unknown_nodes;
				auto may_connect_to_node = [this]() { return is_active() && size_of(node_type::inbound) < protocol::now().user.consensus.max_outbound_connections; };
				unordered_map<algorithm::pubkeyhash_t, socket_address> replacement_nodes;
				replacement_nodes.reserve(current_nodes.size());
				{
					auto mempool = storages::mempoolstate();
					for (auto& account : current_nodes)
					{
						auto better_node = mempool.get_better_node(account);
						if (better_node && current_nodes.find(better_node->second.public_key_hash) == current_nodes.end())
							replacement_nodes[account] = std::move(better_node->first.address);
					}
					try_unknown_nodes = replacement_nodes.empty() && !may_connect_to_node() && mempool.get_unknown_nodes_count().or_else(0) > 0;
				}
				for (auto& [account, address] : replacement_nodes)
					abort_node_by_account(account);
				if (try_unknown_nodes)
					abort_node_by_account(worst_account);

				for (auto& [account, address] : replacement_nodes)
				{
					if (may_connect_to_node())
						coawait(connect_to_physical_node(address));
				}

				unordered_set<uint256_t> passed_candidates;
				expects_rt<socket_address> candidate_address = socket_address();
				while (candidate_address && may_connect_to_node())
				{
					candidate_address = coawait(find_node_from_discovery());
					if (!candidate_address)
						break;

					auto ip_value = candidate_address->get_ip_value().or_else(0);
					auto ip_port = candidate_address->get_ip_port().or_else(0);
					auto ip_address = uint256_t(ip_value, ip_port);
					bool duplicate = passed_candidates.find(ip_address) != passed_candidates.end();
					if (duplicate || !coawait(connect_to_physical_node(*candidate_address)))
					{
						auto mempool = storages::mempoolstate();
						mempool.apply_cooldown_node(*candidate_address, 60000);
					}
					passed_candidates.insert(ip_address);
				}

				size_t inputs = passed_candidates.size() + replacement_nodes.size();
				size_t outputs = replacement_nodes.size() + (try_unknown_nodes ? 1 : 0);
				if ((inputs > 0 || outputs > 0) && protocol::now().user.consensus.logging)
					VI_INFO("network topology optimization: OK (connections: +%i / -%i)", (int)inputs, (int)outputs);

				run_block_dispatch_retrial();
				coreturn_void;
			});
		}
		bool server_node::run_mempool_vacuum()
		{
			return control_sys.task_if_none(TASK_MEMPOOL_VACUUM, [this](system_task&& task)
			{
				auto& [node, wallet] = descriptor;
				if (node.services.has_production && !is_syncing())
				{
					auto mempool = storages::mempoolstate();
					auto expirations = mempool.expire_transactions();
					if (protocol::now().user.consensus.logging)
					{
						if (expirations)
						{
							if (*expirations > 0)
								VI_INFO("mempool vacuum: OK (transactions: %i)", (int)*expirations);
						}
						else
							VI_ERR("mempool vacuum failed: ", expirations.what().c_str());
					}
				}
			});
		}
		bool server_node::run_fork_resolution()
		{
			return control_sys.async_task_if_none(TASK_FORK_RESOLUTION, [this]() -> promise<void>
			{
				auto best_fork = get_best_fork_header();
				if (!best_fork)
					coreturn_void;
			retry:
				auto candidate_hash = best_fork->first;
				auto state = uref(best_fork->second.state);
				auto status = coawait(resolve_and_verify_fork(std::move(*best_fork)));
				if (!status && protocol::now().user.consensus.logging)
					VI_WARN("block %s chain fork rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), status.what().c_str());

				clear_pending_fork(*state);
				auto new_best_fork = get_best_fork_header();
				if (new_best_fork && best_fork->second.header < new_best_fork->second.header)
				{
					best_fork = std::move(new_best_fork);
					goto retry;
				}

				run_block_production();
				coreturn_void;
			});
		}
		bool server_node::run_block_production()
		{
			auto& [node, wallet] = descriptor;
			if (!node.services.has_production || is_syncing())
				return false;

			if (mempool.waiting)
			{
				control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
				mempool.waiting = false;
			}

			return control_sys.task_if_none(TASK_BLOCK_PRODUCTION, [this](system_task&& task)
			{
				auto& [node, wallet] = descriptor;
				auto chain = storages::chainstate();
				auto tip = chain.get_latest_block_header();
				auto priority = environment.configure_priority_from_validator(wallet.public_key_hash, wallet.secret_key, tip.address());
				auto position = priority.or_else(protocol::now().policy.production_max_per_block);
				auto baseline_solution_time = tip ? tip->get_slot_proof_duration_average() : 0;
				auto current_node_solution_time = (uint64_t)((double)baseline_solution_time * algorithm::wesolowski::adjustment_scaling(position));
				if (position > 0 && tip)
				{
					auto current_solution_time = (int64_t)protocol::now().time.now() - (int64_t)tip->generation_time;
					for (uint64_t i = 0; i <= position; i++)
					{
						auto other_node_solution_time = (int64_t)((double)baseline_solution_time * algorithm::wesolowski::adjustment_scaling(i));
						if (current_solution_time < other_node_solution_time)
						{
							mempool.waiting = true;
							control_sys.upsert_timeout(TASK_BLOCK_PRODUCTION, other_node_solution_time - current_solution_time, [this]()
							{
								control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
								run_block_production();
							});
							return;
						}
					}
				}

				size_t offset[2] = { 0, 0 }, count = 512;
				bool accepting[2] = { true, true };
				auto mempool = storages::mempoolstate();
				while (is_active() && (accepting[0] || accepting[1]) && environment.can_accept_more_transactions())
				{
					auto transactions = accepting[0] ? mempool.get_transactions(false, offset[0], count) : expects_lr<vector<uptr<ledger::transaction>>>(layer_exception());
					auto commitments = accepting[1] ? mempool.get_transactions(true, offset[1], count) : expects_lr<vector<uptr<ledger::transaction>>>(layer_exception());
					offset[0] += transactions ? environment.try_include_transactions(std::move(*transactions)) : 0;
					offset[1] += commitments ? environment.try_include_transactions(std::move(*commitments)) : 0;
					accepting[0] = count == (transactions ? transactions->size() : 0);
					accepting[1] = count == (commitments ? commitments->size() : 0);
				}
				if (!is_active() || (environment.incoming.empty() && !ledger::block_header::is_genesis_round(tip ? tip->number + 1 : 1)))
					return environment.cleanup().report("mempool cleanup failed");

				auto evaluation = environment.evaluate_block([&](bool commitment) -> uptr<ledger::transaction>
				{
					auto candidate = mempool.get_transactions(commitment, offset[commitment ? 1 : 0]++, 1);
					return candidate && !candidate->empty() ? candidate->front().reset() : nullptr;
				});		
				if (!evaluation)
					return evaluation.report("block evaluation failed");

				auto solution = environment.solve_evaluated_block(evaluation->block);
				if (!solution)
					return solution.report("block solution failed");

				tip = chain.get_latest_block_header();
				if (is_active() && (!tip || evaluation->block.number > tip->number || (evaluation->block.number == tip->number && evaluation->block.priority < tip->priority) || (evaluation->block.transactions.empty() && !ledger::block_header::is_genesis_round(evaluation->block.number))))
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("block %s proposed (number: %" PRIu64", txns: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%" PRIu64 " sec.)", algorithm::encoding::encode_0xhex256(evaluation->block.as_hash()).c_str(), evaluation->block.number, (uint64_t)environment.incoming.size(), position + 1, current_node_solution_time / 1000 + 1);

					accept_block(nullptr, std::move(*evaluation), 0);
				}
				else if (protocol::now().user.consensus.logging)
					VI_WARN("block %s dismissed (number: %" PRIu64", txns: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%" PRIu64 " sec. wasted)", algorithm::encoding::encode_0xhex256(evaluation->block.as_hash()).c_str(), evaluation->block.number, (uint64_t)environment.incoming.size(), position + 1, current_node_solution_time / 1000 + 1);
			});
		}
		bool server_node::run_block_dispatcher(const ledger::block_header& tip)
		{
			if (is_syncing())
				return false;

			mempool.dispatcher_time = protocol::now().time.now_cpu();
			if (!tip.number)
				return false;

			return control_sys.async_task_if_none(TASK_BLOCK_DISPATCHER, [this, tip]() -> promise<void>
			{
				auto dispatcher = dispatch_context(this);
				coawait(dispatcher.dispatch_async(tip));

				auto& sendable_transactions = dispatcher.get_sendable_transactions();
				if (!sendable_transactions.empty())
				{
					umutex<std::recursive_mutex> unique(sync.account);
					auto& [node, wallet] = descriptor;
					auto account_nonce = wallet.get_latest_nonce().or_else(0);
					for (auto& transaction : sendable_transactions)
						accept_unsigned_transaction(nullptr, std::move(transaction), &account_nonce);
				}

				auto status = dispatcher.checkpoint();
				if (protocol::now().user.consensus.logging)
				{
					if (status)
					{
						if (!dispatcher.inputs.empty())
							VI_INFO("block dispatch: OK (height: %" PRIu64", txns: %" PRIu64 ", delayed: %" PRIu64 ", failed: %" PRIu64 ")", tip.number, dispatcher.inputs.size(), dispatcher.repeaters.size(), dispatcher.errors.size());
					}
					else
						VI_ERR("block dispatch failed: %s (height: %" PRIu64 ")", status.what().c_str(), tip.number);
				}
				run_block_production();
			});
		}
		bool server_node::run_block_dispatch_retrial()
		{
			if (protocol::now().time.now_cpu() - mempool.dispatcher_time <= protocol::now().user.storage.transaction_dispatch_repeat_interval)
				return false;

			auto chain = storages::chainstate();
			auto tip = chain.get_latest_block_header().or_else(ledger::block_header());
			return run_block_dispatcher(tip);
		}
		void server_node::startup()
		{
			if (!protocol::now().user.consensus.server && !protocol::now().user.consensus.max_outbound_connections)
				return;

			socket_router* config = new socket_router();
			config->socket_timeout = (size_t)protocol::now().user.tcp.timeout;
			control_sys.activate();

			if (protocol::now().user.consensus.server)
			{
				auto listener_status = config->listen(protocol::now().user.consensus.address, to_string(protocol::now().user.consensus.port));
				VI_PANIC(listener_status, "server listener error: %s", listener_status.error().what());

				auto configure_status = configure(config);
				VI_PANIC(configure_status, "server configuration error: %s", configure_status.error().what());

				auto binding_status = listen();
				VI_PANIC(binding_status, "server binding error: %s", binding_status.error().what());

				if (protocol::now().user.consensus.logging)
					VI_INFO("OK consensus node listen (location: %s:%i, type: %s)", protocol::now().user.consensus.address.c_str(), (int)protocol::now().user.consensus.port, protocol::now().user.consensus.max_outbound_connections > 0 ? "in-out" : "in");
			}
			else if (protocol::now().user.consensus.max_outbound_connections > 0 && protocol::now().user.consensus.logging)
				VI_INFO("OK consensus node listen (type: out)");

			auto mempool = storages::mempoolstate();
			auto node_id = codec::hex_encode(std::string_view((char*)this, sizeof(this)));
			oracle::server_node::get()->add_transaction_callback(node_id, std::bind(&server_node::dispatch_transaction_logs, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
			accept_local_wallet(optional::none).expect("failed to save local node");
			mempool.clear_cooldowns().report("failed to clear node cooldowns");

			for (auto& node : protocol::now().user.known_nodes)
			{
				auto endpoint = system_endpoint(node);
				if (!endpoint.is_valid() || routing_util::is_address_reserved(endpoint.address))
				{
					if (protocol::now().user.consensus.logging)
						VI_ERR("pre-configured node \"%s\" error: url not valid", node.c_str());
				}
				else
				{
					mempool.clear_node(endpoint.address);
					mempool.apply_unknown_node(endpoint.address);
				}
			}

			bind_event(descriptors::notify_of_block_hash(), std::bind(&server_node::notify_of_block_hash, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::notify_of_transaction_hash(), std::bind(&server_node::notify_of_transaction_hash, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::notify_of_attestation(), std::bind(&server_node::notify_of_attestation, this, std::placeholders::_2, std::placeholders::_3));
			bind_event(descriptors::notify_of_aggregation(), std::bind(&server_node::notify_of_aggregation, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::query_handshake(), std::bind(&server_node::query_handshake, this, std::placeholders::_2, std::placeholders::_3, false));
			bind_query(descriptors::query_state(), std::bind(&server_node::query_state, this, std::placeholders::_2, std::placeholders::_3, false));
			bind_query(descriptors::query_headers(), std::bind(&server_node::query_headers, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::query_block(), std::bind(&server_node::query_block, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::query_mempool(), std::bind(&server_node::query_mempool, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::query_transaction(), std::bind(&server_node::query_transaction, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_secret_share_state(), std::bind(&server_node::aggregate_secret_share_state, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_public_state(), std::bind(&server_node::aggregate_public_state, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_signature_state(), std::bind(&server_node::aggregate_signature_state, this, std::placeholders::_2, std::placeholders::_3));

			control_sys.interval_if_none(TASK_MEMPOOL_VACUUM "_runner", protocol::now().user.storage.transaction_timeout * 1000, std::bind(&server_node::run_mempool_vacuum, this));
			control_sys.interval_if_none(TASK_TOPOLOGY_OPTIMIZATION "_runner", protocol::now().user.consensus.topology_timeout, std::bind(&server_node::run_topology_optimization, this));
			control_sys.interval_if_none(TASK_BLOCK_DISPATCH_RETRIAL "_runner", protocol::now().user.storage.transaction_dispatch_repeat_interval * 1000, std::bind(&server_node::run_block_dispatch_retrial, this));
			run_topology_optimization();
			run_mempool_vacuum();
		}
		void server_node::shutdown()
		{
			if (is_active() || protocol::now().user.consensus.server || protocol::now().user.consensus.max_outbound_connections)
			{
				if (protocol::now().user.consensus.logging)
					VI_INFO("OK consensus node shutdown");
			}

			if (is_active())
				unlisten(false);
		}
		void server_node::clear_pending_meeting(const uint256_t& committee_meeting_hash)
		{
			auto* queue = schedule::get();
			umutex<std::recursive_mutex> unique(sync.meeting);
			if (committee_meeting_hash > 0)
			{
				auto it = meetings.find(committee_meeting_hash);
				if (it != meetings.end())
				{
					queue->clear_timeout(it->second.timeout);
					it->second.task.set(std::move(it->second.results));
					meetings.erase(it);
				}
			}
			else
			{
				for (auto& [handle, meeting] : meetings)
				{
					meeting.task.set(std::move(meeting.results));
					queue->clear_timeout(meeting.timeout);
				}
				meetings.clear();
			}
		}
		void server_node::clear_pending_fork(relay* state)
		{
			auto* queue = schedule::get();
			umutex<std::recursive_mutex> unique(sync.block);
			if (state)
			{
				for (auto it = forks.cbegin(); it != forks.cend();)
				{
					if (state == *it->second.state)
						it = forks.erase(it);
					else
						++it;
				}
			}
			else
				forks.clear();
		}
		void server_node::accept_pending_fork(uref<relay>&& state, fork_head head, const uint256_t& candidate_hash, ledger::block_header&& candidate_block)
		{
			if (!state || !candidate_hash || !is_active())
				return;

			if (head == fork_head::replace)
				clear_pending_fork(nullptr);

			umutex<std::recursive_mutex> unique(sync.block);
			auto& fork = forks[candidate_hash];
			fork.header = candidate_block;
			fork.state = state;
			mempool.dirty = true;
		}
		bool server_node::accept_block(uref<relay>&& from, ledger::block_evaluation&& candidate, const uint256_t& fork_tip)
		{
			uint256_t candidate_hash = candidate.block.as_hash();
			auto verification = from ? candidate.block.verify_validity(nullptr) : environment.verify_solved_block(candidate.block, &candidate.state);
			if (!verification)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), verification.error().what());
				return false;
			}

			auto chain = storages::chainstate();
			if (chain.get_block_header_by_hash(candidate_hash))
				return true;

			bool fork_branch = fork_tip > 0;
			auto fork_tip_block = ledger::block_header();
			if (fork_branch)
			{
				umutex<std::recursive_mutex> unique(sync.block);
				auto it = forks.find(fork_tip);
				if (it == forks.end())
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("block %s rejected: orphan fork", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					return false;
				}
				fork_tip_block = it->second.header;
			}

			auto tip_block = fork_branch ? expects_lr<ledger::block_header>(fork_tip_block) : chain.get_latest_block_header();
			auto tip_hash = tip_block ? tip_block->as_hash() : (uint256_t)0;
			auto best_tip_work = tip_block ? tip_block->absolute_work : (uint256_t)0;
			auto parent_block = tip_hash == candidate.block.parent_hash ? tip_block : chain.get_block_header_by_hash(candidate.block.parent_hash);
			auto parent_hash = parent_block ? parent_block->as_hash() : (uint256_t)0;
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
				if (protocol::now().user.consensus.logging)
					VI_WARN("block %s rejected: inferior fork %s (length: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), branch_length < 0 ? "branch" : "work", branch_length);
				return false;
			}
			else if (branch_length == 0 && tip_block && tip_hash != candidate_hash && candidate.block < *tip_block)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				if (protocol::now().user.consensus.logging)
					VI_WARN("block %s rejected: inferior fork difficulty", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
				return false;
			}
			else if (!parent_block && candidate.block.number > 1)
			{
				if (!from)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("block %s rejected: unexpected orphan", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					return false;
				}

				umutex<std::recursive_mutex> unique(sync.block);
				for (auto& fork_candidate_tip : forks)
				{
					if (*fork_candidate_tip.second.state == *from)
						return false;
				}

				bool has_better_tip = forks.empty();
				for (auto& fork_candidate_tip : forks)
				{
					if (fork_candidate_tip.second.header < candidate.block)
					{
						has_better_tip = true;
						break;
					}
				}

				if (!has_better_tip)
				{
					/*
																   <+> = better orphan
																  /
						<+> - <+> - <+> - <+> - <+> - <+> ------------
															  \
															   <+> = weaker orphan
					*/
					if (protocol::now().user.consensus.logging)
					{
						if (forks.find(candidate_hash) == forks.end())
							VI_WARN("block %s rejected: inferior fork orphan", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					}
					return false;
				}
				else if (forks.find(candidate_hash) != forks.end())
					return true;

				/*
					<+> - <+> - <+> - <+> - <+> - <+> ----
														  \
														   <+> = possibly orphan
				*/
				accept_pending_fork(uref(from), fork_head::append, candidate_hash, ledger::block_header(candidate.block));
				unique.unlock();
				run_fork_resolution();
				if (protocol::now().user.consensus.logging)
					VI_INFO("block %s chain fork: new possible best found (height: %" PRIu64 ", distance: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), candidate.block.number, std::abs((int64_t)(tip_block ? tip_block->number : 0) - (int64_t)candidate.block.number));
				return true;
			}

			if (from)
			{
				auto validation = candidate.block.validate(parent_block.address(), &candidate);
				if (!validation)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), validation.error().what());
					return false;
				}
			}
			else
			{
				auto integrity = candidate.block.verify_integrity(parent_block.address(), &candidate.state);
				if (!integrity)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), integrity.error().what());
					return false;
				}
			}

			/*
				<+> - <+> - <+> - <+> - <+> - <+> = possible extension
											\
											<+> - <+> = possible reorganization
			*/
			umutex<std::recursive_mutex> unique(sync.block);
			if (!accept_block_candidate(candidate, candidate_hash, fork_tip))
				return false;

			if (fork_tip != candidate_hash)
				accept_pending_fork(uref(from), fork_head::replace, fork_tip, std::move(fork_tip_block));
			else
				clear_pending_fork(nullptr);

			run_block_dispatcher(candidate.block);
			if (from && mempool.dirty && !is_syncing())
			{
				mempool.dirty = false;
				synchronize_mempool_with(uref(from));
			}

			size_t notifications = notify_all_except(uref(from), descriptors::notify_of_block_hash(), { format::variable(candidate_hash), format::variable(candidate.block.number) });
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_INFO("block %s broadcasted to %i nodes (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)notifications, candidate.block.number);

			return true;
		}
		bool server_node::accept_block_candidate(const ledger::block_evaluation& candidate, const uint256_t& candidate_hash, const uint256_t& fork_tip)
		{
			auto mutation = candidate.checkpoint();
			if (!mutation)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("block %s checkpoint failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation.error().what());
				return false;
			}

			if (protocol::now().user.consensus.logging)
			{
				double progress = get_sync_progress(fork_tip, candidate.block.number);
				if (mutation->is_fork)
					VI_INFO("block %s chain forked (height: %" PRIu64 ", mempool: %" PRIu64 ", block-delta: %" PRIi64 ", transaction-delta: %" PRIi64 ", state-delta: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->old_tip_block_number, mutation->mempool_transactions, mutation->block_delta, mutation->transaction_delta, mutation->state_delta);
				VI_INFO("block %s chain %s (height: %" PRIu64 ", sync: %.2f%%, priority: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->is_fork ? "shortened" : "extended", candidate.block.number, 100.0 * progress, candidate.block.priority);
			}

			if (events.accept_block)
				events.accept_block(candidate_hash, candidate.block, *mutation);

			auto& [node, wallet] = descriptor;
			for (auto& transaction : candidate.block.transactions)
			{
				if (transaction.receipt.from == wallet.public_key_hash)
					accept_proposal_transaction(candidate.block, transaction);
			}

			return true;
		}
		bool server_node::accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction)
		{
			uint32_t type = transaction.transaction->as_type();
			auto purpose = transaction.transaction->as_typename();
			if (type == transactions::validator_adjustment::as_instance_type())
			{
				if (transaction.receipt.successful)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("transaction %s %.*s finalized", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
					fill_node_services();
					run_block_production();
				}
				else if (protocol::now().user.consensus.logging)
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			else if (protocol::now().user.consensus.logging)
			{
				if (transaction.receipt.successful)
					VI_INFO("transaction %s %.*s finalized", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				else
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			return true;
		}
		bool server_node::accept_meeting_committee_node(uref<relay>&& state)
		{
			size_t meetings_accepted = 0;
			bool meeting_acepted = false;
			auto* queue = schedule::get();
			umutex<std::recursive_mutex> unique(sync.meeting);
		accept_another_meeting:
			for (auto& [handle, meeting] : meetings)
			{
				auto target = meeting.accounts.find(state->as_descriptor()->second.public_key_hash);
				if (target == meeting.accounts.end())
					continue;

				meeting_acepted = true;
				meeting.accounts.erase(target);
				meeting.results.push_back(state);
				if (meeting.accounts.empty())
				{
					clear_pending_meeting(handle);
					break;
				}
				meeting.timeout = queue->set_timeout(protocol::now().user.tcp.timeout, std::bind(&server_node::clear_pending_meeting, this, handle));
			}
			if (meeting_acepted)
			{
				++meetings_accepted;
				meeting_acepted = false;
				goto accept_another_meeting;
			}
			return meetings_accepted > 0;
		}
		void server_node::fill_node_services()
		{
			auto& [node, wallet] = descriptor;
			auto context = ledger::transaction_context();
			node.services.has_production = false;
			node.services.has_participation = false;
			node.services.has_attestation = false;
			if (protocol::now().user.consensus.may_propose)
			{
				auto production = context.get_validator_production(wallet.public_key_hash);
				node.services.has_production = production && production->active;
				if (!node.services.has_production)
					node.services.has_production = context.calculate_producers_size().or_else(0) == 0;
			}

			size_t count = 64;
			size_t offset = 0;
			while (true)
			{
				auto participations = context.get_validator_participations(wallet.public_key_hash, offset, count);
				if (!participations || participations->empty())
					break;

				for (auto& participation : *participations)
				{
					node.services.has_participation = participation.is_active();
					if (node.services.has_participation)
					{
						participations->clear();
						break;
					}
				}

				offset += participations->size();
				if (participations->size() < count)
					break;
			}

			offset = 0;
			while (true)
			{
				auto attestations = context.get_validator_attestations(wallet.public_key_hash, offset, count);
				if (!attestations || attestations->empty())
					break;

				for (auto& attestation : *attestations)
				{
					node.services.has_attestation = attestation.is_active();
					if (node.services.has_attestation)
					{
						attestations->clear();
						break;
					}
				}

				offset += attestations->size();
				if (attestations->size() < count)
					break;
			}
		}
		bool server_node::is_active()
		{
			return state == server_state::working;
		}
		bool server_node::is_syncing()
		{
			umutex<std::recursive_mutex> unique(sync.block);
			return !forks.empty();
		}
		double server_node::get_sync_progress(const uint256_t& fork_tip, uint64_t current_number)
		{
			if (!current_number)
				return 1.0;

			umutex<std::recursive_mutex> unique(sync.block);
			auto it = forks.find(fork_tip);
			return it != forks.end() ? (current_number <= it->second.header.number ? (double)current_number / (double)it->second.header.number : 1.0) : 1.0;
		}
		const unordered_map<void*, uref<relay>>& server_node::get_nodes() const
		{
			return nodes;
		}
		option<std::pair<uint256_t, server_node::fork_header>> server_node::get_best_fork_header()
		{
			umutex<std::recursive_mutex> unique(sync.block);
			option<std::pair<uint256_t, server_node::fork_header>> best_fork = optional::none;
			if (!is_active())
				return best_fork;

			for (auto& fork_candidate_tip : forks)
			{
				if (!best_fork || best_fork->second.header < fork_candidate_tip.second.header)
					best_fork = std::make_pair(fork_candidate_tip.first, fork_candidate_tip.second);
			}
			return best_fork;
		}
		dispatch_context server_node::get_dispatcher() const
		{
			return dispatch_context((server_node*)this);
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!protocol::now().user.consensus.server && !protocol::now().user.consensus.max_outbound_connections)
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
		bool server_node::has_address(const socket_address& address)
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
				if (*listener->address.get_ip_address() == *ip_address)
					return true;
			}

			return false;
		}
		uref<relay> server_node::find_by_address(const socket_address& address)
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
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr && peer_descriptor->second.public_key_hash.equals(account))
					return node.second;
			}

			return nullptr;
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
		std::string_view routing_util::node_type_of(relay* from)
		{
			switch (from->type_of())
			{
				case node_type::inbound:
					return "inbound";
				case node_type::outbound:
					return "outbound";
				default:
					return "relay";
			}
		}

		dispatch_context::dispatch_context(server_node* new_server) : server(new_server)
		{
			VI_ASSERT(server != nullptr, "server should be set");
		}
		dispatch_context::dispatch_context(const dispatch_context& other) noexcept : ledger::dispatch_context(other), server(other.server)
		{
		}
		dispatch_context& dispatch_context::operator=(const dispatch_context& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::dispatch_context*)this;
			auto& base_other = *(const ledger::dispatch_context*)&other;
			base_this = base_other;
			server = other.server;
			return *this;
		}
		algorithm::pubkey_t dispatch_context::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto target = server->find_by_account(validator);
			if (!target)
				return algorithm::pubkey_t();

			auto* descriptor = target->as_descriptor();
			if (!descriptor)
				return algorithm::pubkey_t();

			return descriptor->second.public_key;
		}
		const ledger::wallet& dispatch_context::get_runner_wallet() const
		{
			auto& [node, wallet] = server->descriptor;
			return wallet;
		}
		expects_promise_rt<void> dispatch_context::aggregate_validators(const uint256_t& transaction_hash, const ordered_set<algorithm::pubkeyhash_t>& validators)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("committee meeting: connect to %i validators (proof: %s)", (int)validators.size(), algorithm::encoding::encode_0xhex256(transaction_hash).c_str());

			return coasync<expects_rt<void>>([this, transaction_hash, &validators]() mutable -> expects_promise_rt<void>
			{
				unordered_set<algorithm::pubkeyhash_t> required_accounts;
				required_accounts.reserve(validators.size());
				required_accounts.insert(validators.begin(), validators.end());

				auto result = coawait(server->connect_to_meeting_committee(transaction_hash, std::move(required_accounts)));
				if (!result)
				{
					if (protocol::now().user.consensus.logging)
						VI_ERR("committee meeting failed: %s (proof: %s)", result.what().c_str(), algorithm::encoding::encode_0xhex256(transaction_hash).c_str());

					coreturn result.error();
				}
				else if (protocol::now().user.consensus.logging)
					VI_INFO("committee meeting: %i validators connected (proof: %s)", (int)result->size(), algorithm::encoding::encode_0xhex256(transaction_hash).c_str());

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatch_context::aggregate_secret_share_state(const ledger::transaction_context* context, secret_share_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("secret share state aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return coasync<expects_rt<void>>([this, context, &state, &validator]() mutable -> expects_promise_rt<void>
			{
				auto result = coawait(aggregate_secret_share_state_internal(context, state, validator));
				if (!result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("secret share state aggregation failed: %s (participant: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					coreturn result.error();
				}
				else if (protocol::now().user.consensus.logging)
					VI_INFO("secret share state aggregation: OK (participant: %s)", algorithm::signing::encode_address(validator).c_str());

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatch_context::aggregate_public_state(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("public state aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return coasync<expects_rt<void>>([this, context, &state, &validator]() mutable -> expects_promise_rt<void>
			{
				auto result = coawait(aggregate_public_state_internal(context, state, validator));
				if (!result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("public state aggregation failed: %s (participant: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					coreturn result.error();
				}
				else if (protocol::now().user.consensus.logging)
					VI_INFO("public state aggregation: OK (participant: %s)", algorithm::signing::encode_address(validator).c_str());

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatch_context::aggregate_signature_state(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("signature state aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return coasync<expects_rt<void>>([this, context, &state, &validator]() mutable -> expects_promise_rt<void>
			{
				auto result = coawait(aggregate_signature_state_internal(context, state, validator));
				if (!result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("signature state aggregation failed: %s (participant: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					coreturn result.error();
				}
				else if (protocol::now().user.consensus.logging)
					VI_INFO("signature state aggregation: OK (participant: %s)", algorithm::signing::encode_address(validator).c_str());

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatch_context::aggregate_secret_share_state_internal(const ledger::transaction_context* context, secret_share_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* bridge_account = (transactions::bridge_account*)context->transaction;
			if (is_running_on(validator.data))
				coreturn local_dispatch_context::aggregate_secret_share_state(this, context, state);

			auto node = server->find_by_account(validator);
			if (!node)
				coreturn remote_exception::retry();

			uint64_t attempt = 0;
			auto args = pack_private_result({ format::variable(context->receipt.block_number), format::variable(context->receipt.transaction_hash), format::variable(state.as_message().data) }, *node);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));
		retry:
			auto event = coawait(server->query(uref(node), descriptors::aggregate_secret_share_state(), format::variables(*args), protocol::now().user.consensus.response_timeout));
			if (!event)
			{
				bool is_retry = event.error().is_retry() || event.error().is_shutdown();
				if (is_retry && coawait(aggregative_sleep(attempt)))
					goto retry;

				coreturn is_retry ? remote_exception::retry() : event.error();
			}

			args = unpack_private_result(event->args, server->descriptor.second.secret_key);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));

			state.confirmation_signature = algorithm::hashsig_t(args->front().as_string());
			if (state.confirmation_signature.empty())
				coreturn remote_exception("group secret share confirmation failed");

			coreturn expectation::met;
		}
		expects_promise_rt<void> dispatch_context::aggregate_public_state_internal(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (is_running_on(validator.data))
				coreturn local_dispatch_context::aggregate_public_state(this, context, *state.aggregator);

			auto node = server->find_by_account(validator);
			if (!node)
				coreturn remote_exception::retry();

			format::wo_stream writer;
			if (!algorithm::composition::store_public_state(state.alg, *state.aggregator, &writer))
				coreturn remote_exception("out state machine not valid");

			uint64_t attempt = 0;
			auto args = pack_private_result({ format::variable(context->receipt.block_number), format::variable(context->receipt.transaction_hash), format::variable(writer.data) }, *node);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));
		retry:
			auto event = coawait(server->query(uref(node), descriptors::aggregate_public_state(), format::variables(*args), protocol::now().user.consensus.response_timeout));
			if (!event)
			{
				bool is_retry = event.error().is_retry() || event.error().is_shutdown();
				if (is_retry && coawait(aggregative_sleep(attempt)))
					goto retry;

				coreturn is_retry ? remote_exception::retry() : event.error();
			}

			args = unpack_private_result(event->args, server->descriptor.second.secret_key);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));

			auto message = format::ro_stream(args->front().as_string());
			if (!state.aggregator->load(message))
				coreturn remote_exception("group public key remote computation failed");

			coreturn expectation::met;
		}
		expects_promise_rt<void> dispatch_context::aggregate_signature_state_internal(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (is_running_on(validator.data))
				coreturn local_dispatch_context::aggregate_signature_state(this, context, **state.message, *state.aggregator);

			auto node = server->find_by_account(validator);
			if (!node)
				coreturn remote_exception::retry();

			format::wo_stream writer;
			if (!algorithm::composition::store_signature_state(state.alg, *state.aggregator, &writer))
				coreturn remote_exception("out state machine not valid");

			uint64_t attempt = 0;
			auto args = pack_private_result({ format::variable(context->receipt.block_number), format::variable(context->receipt.transaction_hash), format::variable(state.message->as_message().data), format::variable(writer.data) }, *node);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));
		retry:
			auto event = coawait(server->query(uref(node), descriptors::aggregate_signature_state(), format::variables(*args), protocol::now().user.consensus.response_timeout));
			if (!event)
			{
				bool is_retry = event.error().is_retry() || event.error().is_shutdown();
				if (is_retry && coawait(aggregative_sleep(attempt)))
					goto retry;

				coreturn is_retry ? remote_exception::retry() : event.error();
			}

			args = unpack_private_result(event->args, server->descriptor.second.secret_key);
			if (!args)
				coreturn remote_exception(std::move(args.error().message()));

			auto message = format::ro_stream(args->front().as_string());
			if (!state.load_message_if_preferred(message))
				coreturn remote_exception("group signature remote computation error");

			coreturn expectation::met;
		}

		local_dispatch_context::local_dispatch_context(const vector<ledger::wallet>& new_validators)
		{
			for (auto& target : new_validators)
				validators[algorithm::pubkeyhash_t(target.public_key_hash)] = target;
			validator = validators.find(algorithm::pubkeyhash_t(new_validators.front().public_key_hash));
		}
		local_dispatch_context::local_dispatch_context(const local_dispatch_context& other) noexcept : ledger::dispatch_context(other), validators(other.validators)
		{
			validator = validators.find(other.validator->first);
		}
		local_dispatch_context& local_dispatch_context::operator=(const local_dispatch_context& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::dispatch_context*)this;
			auto& base_other = *(const ledger::dispatch_context*)&other;
			base_this = base_other;
			validators = other.validators;
			validator = validators.find(other.validator->first);
			return *this;
		}
		algorithm::pubkey_t local_dispatch_context::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto it = validators.find(validator);
			return it != validators.end() ? it->second.public_key : algorithm::pubkey_t();
		}
		const ledger::wallet& local_dispatch_context::get_runner_wallet() const
		{
			return validator->second;
		}
		void local_dispatch_context::set_running_validator(const algorithm::pubkeyhash_t& owner)
		{
			auto it = validators.find(owner);
			if (it != validators.end())
				validator = it;
		}
		expects_promise_rt<void> local_dispatch_context::aggregate_validators(const uint256_t& transaction_hash, const ordered_set<algorithm::pubkeyhash_t>& validators)
		{
			return expects_promise_rt<void>(expectation::met);
		}
		expects_promise_rt<void> local_dispatch_context::aggregate_secret_share_state(const ledger::transaction_context* context, secret_share_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto next = validators.find(validator);
			if (next == validators.end())
				return expects_promise_rt<void>(remote_exception::retry());

			auto prev = this->validator;
			this->validator = next;
			auto result = aggregate_secret_share_state(this, context, state);
			this->validator = prev;
			return expects_promise_rt<void>(std::move(result));
		}
		expects_rt<void> local_dispatch_context::aggregate_secret_share_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, secret_share_state& state)
		{
			auto* bridge_migration = (transactions::bridge_migration*)context->transaction;
			if (!bridge_migration)
				return remote_exception("invalid transaction");

			if (state.encrypted_shares.size() != bridge_migration->shares.size())
				return remote_exception("invalid encrypted shares count");

			auto& runner_wallet = dispatcher->get_runner_wallet();
			algorithm::seckey_t tweak, tweaked_secret_key = runner_wallet.secret_key;
			algorithm::signing::derive_secret_key(context->receipt.transaction_hash, tweak);
			if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
				return remote_exception("invalid tweaked secret key");

			for (auto& [hash, encrypted_share] : state.encrypted_shares)
			{
				auto share_target = bridge_migration->shares.find(hash);
				if (encrypted_share.empty() || share_target == bridge_migration->shares.end())
					return remote_exception("invalid encrypted share");

				auto decrypted_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_share);
				if (!decrypted_share || decrypted_share->size() != sizeof(uint256_t))
					return remote_exception("invalid decrypted share");

				uint256_t scalar;
				scalar.decode((uint8_t*)decrypted_share->data());
				encrypted_share.clear();
				if (!scalar)
					return remote_exception("invalid share");

				auto& share = share_target->second;
				auto status = dispatcher->apply_secret_share(share.asset, share.manager, share.owner, scalar);
				if (!status)
					return remote_exception(std::move(status.error().message()));
			}

			auto confirmation_hash = state.as_confirmation_hash();
			if (!algorithm::signing::sign(confirmation_hash, dispatcher->get_runner_wallet().secret_key, state.confirmation_signature))
				return remote_exception("confirmation proving error");

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatch_context::aggregate_public_state(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto next = validators.find(validator);
			if (next == validators.end())
				return expects_promise_rt<void>(remote_exception::retry());

			auto prev = this->validator;
			this->validator = next;
			auto result = aggregate_public_state(this, context, *state.aggregator);
			this->validator = prev;
			return expects_promise_rt<void>(std::move(result));
		}
		expects_rt<void> local_dispatch_context::aggregate_public_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, algorithm::composition::public_state* aggregator)
		{
			auto* bridge_account = (transactions::bridge_account*)context->transaction;
			if (!bridge_account)
				return remote_exception("invalid transaction");

			auto* chain = oracle::server_node::get()->get_chainparams(bridge_account->asset);
			if (!chain)
				return remote_exception("invalid operation");

			uint256_t scalar;
			auto status = dispatcher->recover_secret_share(bridge_account->asset, bridge_account->manager, context->receipt.from, scalar);
			if (!status)
				return remote_exception(std::move(status.error().message()));

			auto keypair = algorithm::composition::derive_keypair(chain->composition, scalar);
			if (!keypair)
				return remote_exception(std::move(keypair.error().message()));

			auto derivation = aggregator->derive_from_key(keypair->secret_key);
			if (!derivation)
				return remote_exception(std::move(derivation.error().message()));

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatch_context::aggregate_signature_state(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto next = validators.find(validator);
			if (next == validators.end())
				return expects_promise_rt<void>(remote_exception::retry());

			auto prev = this->validator;
			this->validator = next;
			auto result = aggregate_signature_state(this, context, **state.message, *state.aggregator);
			this->validator = prev;
			return expects_promise_rt<void>(std::move(result));
		}
		expects_rt<void> local_dispatch_context::aggregate_signature_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, oracle::prepared_transaction& message, algorithm::composition::signature_state* aggregator)
		{
			auto* bridge_withdrawal = (transactions::bridge_withdrawal*)context->transaction;
			if (!bridge_withdrawal)
				return remote_exception("invalid transaction");

			auto validation = transactions::bridge_withdrawal_finalization::validate_possible_proof(context, bridge_withdrawal, message);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto* input = message.next_input_for_aggregation();
			if (!input)
				return remote_exception("invalid operation");

			auto witness = context->get_witness_account_tagged(bridge_withdrawal->asset, input->utxo.link.address, 0);
			if (!witness)
				return remote_exception(std::move(witness.error().message()));

			auto account = context->get_bridge_account(bridge_withdrawal->asset, witness->manager, witness->owner);
			if (!account)
				return expectation::met;

			uint256_t scalar;
			auto status = dispatcher->recover_secret_share(account->asset, account->manager, account->owner, scalar);
			if (!status)
				return remote_exception(std::move(status.error().message()));

			auto keypair = algorithm::composition::derive_keypair(input->alg, scalar);
			if (!keypair)
				return remote_exception(std::move(keypair.error().message()));

			auto accumulation = aggregator->aggregate(keypair->secret_key);
			if (!accumulation)
				return remote_exception(std::move(accumulation.error().message()));

			return expectation::met;
		}
	}
}
