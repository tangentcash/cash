#include "consensus.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../policy/transactions.h"
#include <random>
#include <array>
#define TASK_TOPOLOGY_OPTIMIZATION "topology_optimization"
#define TASK_MEMPOOL_VACUUM "mempool_vacuum"
#define TASK_FORK_RESOLUTION "fork_resolution"
#define TASK_SUPERCHAIN_SYNC "superchain_sync"
#define TASK_ATTESTATION_RESOLUTION "attestation_resolution"
#define TASK_BLOCK_DISPATCH_RETRIAL "block_dispatch_retrial"
#define TASK_BLOCK_PRODUCTION "block_production"
#define TASK_BLOCK_DISPATCHER "block_dispatcher"

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
		static uint256_t handshake_proof(const ledger::node& node, uint64_t time, string* node_message_out)
		{
			format::wo_stream message;
			node.store(&message);
			if (node_message_out != nullptr)
				node_message_out->assign(message.data);
			message.write_integer(time);
			return message.hash();
		}
		static uint256_t discovery_proof(const socket_address& address, const btree_set<algorithm::pubkeyhash_t>& accounts)
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
		static expects_rt<format::variables> unpack_private_result(const format::variables& packed_result, const algorithm::seckey_t& secret_key)
		{
			if (packed_result.size() != 1)
				return remote_exception("invalid encrypted private result");

			auto decrypted_message = algorithm::signing::private_decrypt(secret_key, packed_result.front().as_string());
			if (!decrypted_message)
				return remote_exception("private result decryption failed (possible attack)");

			format::variables result;
			format::ro_stream message = format::ro_stream(*decrypted_message);
			if (!format::variables_util::deserialize_flat_from(message, &result))
				return remote_exception("invalid private result (possible attack)");

			return expects_rt<format::variables>(std::move(result));
		}
		static expects_rt<format::variables> unpack_private_result(const format::variables& packed_result, relay_descriptor* descriptor)
		{
			if (!descriptor)
				return remote_exception("invalid descriptor secret key");

			return unpack_private_result(packed_result, descriptor->second.secret_key);
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
		uint64_t exchange::calculate_latency()
		{
			auto time_now = protocol::now().time.now_cpu();
			return time > 0 && time_now > time ? time_now - time : 0;
		}
		uint32_t exchange::as_type() const
		{
			return as_instance_type();
		}
		uint256_t exchange::as_inventory_hash() const
		{
			format::wo_stream stream;
			stream.write_integer(descriptor);
			format::variables_util::serialize_merge_into(args, &stream);
			return stream.hash();
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

		bool forwarder::insert(const uint256_t& message_hash)
		{
			if (messages.find(message_hash) != messages.end())
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

		relay::relay(node_type new_type, void* new_instance) : aborted(false), type(new_type), instance(new_instance), counter(0), bandwidth(1000 * 1000 * protocol::now().user.tcp.mbps_per_socket), handshake_time(protocol::now().time.now()), deferred_pull(INVALID_TASK_ID)
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
		expects_promise_rt<exchange> relay::push_query(const callable::descriptor& subject, format::variables&& args, uint64_t timeout_ms, bool forwarded)
		{
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
			exchange message;
			message.descriptor = subject.id;
			message.type = exchange::side::event;
			message.args = std::move(args);
			if (!inventory.insert(message.as_inventory_hash()))
				return false;

			push_outgoing(std::move(message));
			return true;
		}
		void relay::push_event(uint32_t session, format::variables&& args)
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
			incoming_data.resize(std::min(offset + size, sizeof(uint32_t) + protocol::now().message.max_body_size));
			memcpy(incoming_data.data() + offset, buffer, std::min(incoming_data.size() - offset, size));
		}
		void relay::push_outgoing(exchange&& message)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("node %s message out: %s", peer_address().c_str(), message.as_tree().as_json().substr(0, 2048).c_str());

			umutex<std::recursive_mutex> unique(mutex);
			outgoing_messages.push(std::move(message));
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

			size_t max_size = protocol::now().message.max_body_size;
			while (!outgoing_messages.empty())
			{
				auto& message = outgoing_messages.front();
				auto body = format::wo_stream();
				message.store_payload(&body);
				outgoing_messages.pop();

				message_header header;
				header.magic = os::hw::to_endianness(os::hw::endian::little, (uint32_t)protocol::now().message.packet_magic);
				header.length = os::hw::to_endianness(os::hw::endian::little, (uint32_t)std::min(body.data.size(), max_size));
				header.checksum = os::hw::to_endianness(os::hw::endian::little, algorithm::hashing::hash32d(std::string_view(body.data).substr(0, max_size)));

				size_t offset = outgoing_data.size();
				outgoing_data.resize(offset + sizeof(header) + body.data.size());
				memcpy(outgoing_data.data() + offset, &header, sizeof(header));
				memcpy(outgoing_data.data() + offset + sizeof(header), body.data.data(), body.data.size());
			}
			return true;
		}
		void relay::clear_outgoing()
		{
			umutex<std::recursive_mutex> unique(mutex);
			outgoing_data.clear();
		}
		void relay::report_call(int8_t call_result, uint64_t call_latency)
		{
			if (descriptor)
			{
				auto mempool = storages::mempoolstate();
				mempool.apply_node_quality(descriptor->first.address, call_result, call_latency);
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
		void relay::abort(const std::string_view& message)
		{
			if (shutdown_message.empty())
				shutdown_message = message;

			cancel_queries();
			if (deferred_pull != INVALID_TASK_ID)
			{
				schedule::get()->clear_timeout(deferred_pull);
				deferred_pull = INVALID_TASK_ID;
			}

			auto* socket = as_socket();
			aborted = true;
			if (socket != nullptr)
				socket->shutdown(true);
		}
		void relay::initialize(relay_descriptor&& new_descriptor)
		{
			descriptor = memory::init<relay_descriptor>(std::move(new_descriptor));
			if (protocol::now().user.consensus.logging)
				VI_INFO("node %s channel accept (mode: %s, port: %s, version: %s, account: %s)", peer_address().c_str(), connection_type().data(), peer_service().c_str(), descriptor->first.as_version().c_str(), descriptor->second.get_address().c_str());

			auto* socket = as_socket();
			if (socket != nullptr)
			{
				socket->set_io_timeout(0);
				socket->set_keep_alive(true);
				socket->set_keep_alive_params((int)protocol::now().user.tcp.keep_alive, (int)protocol::now().user.tcp.keep_alive, 5);
			}
		}
		void relay::invalidate()
		{
			bool graceful_shutdown = instance != nullptr && descriptor;
			if (graceful_shutdown)
			{
				report_call(0, 0);
				if (protocol::now().user.consensus.logging)
					VI_INFO("node %s channel shutdown (%s)", peer_address().c_str(), shutdown_message.empty() ? "abnormal" : shutdown_message.c_str());
			}
			abort(shutdown_message);

			umutex<std::recursive_mutex> unique(mutex);
			auto* inbound = type == node_type::inbound ? (inbound_node*)instance : nullptr;
			auto* outbound = type == node_type::outbound ? (outbound_node*)instance : nullptr;
			memory::release(inbound);
			memory::release(outbound);
			instance = nullptr;
			descriptor.destroy();
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
		forwarder& relay::get_inventory()
		{
			return inventory;
		}
		const uint8_t* relay::incoming_buffer()
		{
			return (const uint8_t*)incoming_data.data();
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

		outbound_node::outbound_node() noexcept : socket_client(protocol::now().user.tcp.timeout)
		{
		}
		void outbound_node::configure_stream()
		{
			socket_client::configure_stream();
			if (protocol::now().is(network_type::regtest))
				net.stream->bind(socket_address(protocol::now().user.consensus.address, 0));
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
		callable::descriptor descriptors::broadcast_intermediary()
		{
			return callable::descriptor(__func__, 4);
		}
		callable::descriptor descriptors::announce_neighbor()
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
		callable::descriptor descriptors::distribute_entropy_shares()
		{
			return callable::descriptor(__func__, 14);
		}
		callable::descriptor descriptors::aggregate_entropy_shares()
		{
			return callable::descriptor(__func__, 15);
		}
		callable::descriptor descriptors::recover_entropy()
		{
			return callable::descriptor(__func__, 16);
		}
		callable::descriptor descriptors::aggregate_public_key()
		{
			return callable::descriptor(__func__, 17);
		}
		callable::descriptor descriptors::aggregate_signature()
		{
			return callable::descriptor(__func__, 18);
		}

		server_node::server_node() noexcept : socket_server(), control_sys("consensus-node"), runner_descriptor(nullptr)
		{
		}
		server_node::~server_node() noexcept
		{
			if (superchain::bridge::has_instance())
			{
				auto* offchain = superchain::bridge::get();
				offchain->network_active = nullptr;
				offchain->network_fetch = nullptr;
			}
			clear_pending_fork(nullptr);
		}
		expects_promise_system<http::response_frame> server_node::queued_fetch_external(const algorithm::asset_id& asset, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options)
		{
			if (!is_active())
				return expects_promise_system<http::response_frame>(system_exception("cancelled due to shutdown", std::make_error_condition(std::errc::owner_dead)));

			umutex<std::mutex> unique(sync.fetcher);
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
					umutex<std::mutex> unique(sync.fetcher);
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
				umutex<std::mutex> unique(sync.fetcher);
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
			clear_pending_fork(nullptr);
			{
				single_queue<fetch_target> cancellations;
				umutex<std::mutex> unique(sync.fetcher);
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
					node.second->abort("server shutdown");
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
					return mempool.apply_runner_node(descriptor);
				case node_category::neighbor:
					return mempool.apply_neighbor_node(descriptor);
				case node_category::other:
				{
					if (find_descriptor(wallet.public_key_hash))
						return layer_exception("must not modify internal node");

					auto prev = mempool.get_node(node.address);
					if (prev && find_descriptor(prev->second.public_key_hash))
						return layer_exception("must not modify internal node");

					return mempool.apply_node(descriptor);
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
				node.address = socket_address(protocol::now().user.consensus.address, protocol::now().user.consensus.port);
				descriptors[wallet.public_key_hash] = std::make_pair(std::move(node), wallet);
			}

			if (descriptors.empty())
			{
				ledger::node node; ledger::wallet wallet = ledger::wallet::from_seed(*crypto::random_bytes(512));
				node.address = socket_address(protocol::now().user.consensus.address, protocol::now().user.consensus.port);
				runner_account = wallet.public_key_hash;
				descriptors[runner_account] = std::make_pair(std::move(node), std::move(wallet));
			}

			for (auto& [account, descriptor] : descriptors)
			{
				auto& [node, wallet] = descriptor;
				fill_node_services(descriptor);
				fill_node_neighbors(descriptor);
				VI_PANIC(wallet.has_secret_key(), "server descriptor %s wallet must have a secret key", wallet.get_address().c_str());

				node.major_version = protocol::now().message.major_version;
				node.minor_version = protocol::now().message.minor_version;
				node.ports.consensus = protocol::now().user.consensus.port;
				node.ports.discovery = protocol::now().user.discovery.port;
				node.ports.rpc = protocol::now().user.rpc.port;
				node.services.has_consensus = protocol::now().user.consensus.server;
				node.services.has_discovery = protocol::now().user.discovery.server;
				node.services.has_superchain = protocol::now().user.superchain.listener;
				node.services.has_rpc = protocol::now().user.rpc.server && protocol::now().user.rpc.username.empty();

				bool runner = account == runner_account;
				auto result = accept_node(mempool, descriptor, runner ? node_category::runner : node_category::neighbor);
				if (result)
					VI_INFO("%s account %s accepted", runner ? "runner" : "neighbor", wallet.get_address().c_str());
			}

			auto it = descriptors.find(runner_account);
			if (it == descriptors.end())
				return layer_exception("failed to bind runner account");

			runner_descriptor = &it->second;
			return expectation::met;
		}
		expects_lr<void> server_node::accept_local_transaction(const ledger::wallet* signer_wallet, uptr<ledger::transaction_message>&& candidate_tx, uint256_t* output_hash)
		{
			VI_ASSERT(signer_wallet != nullptr, "signer wallet should be set");
			umutex<std::recursive_mutex> unique(sync.account);
			auto status = candidate_tx->sign(signer_wallet->secret_key, signer_wallet->get_latest_nonce().or_else(0), decimal::zero());
			if (!status)
			{
				auto purpose = candidate_tx->as_typename();
				if (protocol::now().user.consensus.logging)
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data(), status.what().c_str());

				return status;
			}

			status = accept_transaction(nullptr, std::move(candidate_tx));
			if (!status)
				return status;

			if (output_hash != nullptr)
				*output_hash = candidate_tx->as_hash();

			return status;
		}
		expects_lr<void> server_node::accept_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx)
		{
			algorithm::pubkeyhash_t owner;
			auto purpose = candidate_tx->as_typename();
			auto candidate_message = candidate_tx->as_message();
			auto candidate_hash = candidate_message.hash();
			if (!candidate_tx->recover_hash(owner))
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation failed: invalid signature", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("signature key recovery failed");
			}

			auto chain = storages::chainstate();
			auto mempool = storages::mempoolstate();
			if (mempool.has_transaction(candidate_hash).or_else(false) || chain.has_non_aliased_transaction(candidate_hash).or_else(false))
				return expectation::met;

			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(owner), 0);
			auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
			auto nonce = value ? value->nonce : 0;
			if (candidate_tx->nonce < nonce)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation failed: invalid nonce (expired)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("nonce is too old");
			}

			if (!candidate_tx->is_commitment() && !candidate_tx->gas_price.is_positive())
			{
				if (candidate_message.data.size() > protocol::now().policy.payable_transaction_size_bytes)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s %.*s validation failed: must pay for gas (anti-spam, large transaction)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
					return layer_exception("must pay for gas (anti-spam, large transaction)");
				}

				auto tip = chain.get_latest_block_header();
				if (tip && tip->network_congestion())
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s %.*s validation failed: must pay for gas (anti-spam, network congestion)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
					return layer_exception("must pay for gas (anti-spam, network congestion)");
				}
			}

			algorithm::pubkeyhash_t validation_owner;
			auto validation = ledger::executor_context::validate_tx(*candidate_tx, candidate_hash, validation_owner);
			if (!validation)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s validation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
				return validation.error();
			}

			return broadcast_transaction(uref(from), std::move(candidate_tx), owner);
		}
		expects_lr<void> server_node::accept_attestation(const uint256_t& attestation_hash)
		{
			umutex<std::recursive_mutex> unique(sync.attestation);
			auto mempool = storages::mempoolstate();
			auto batch = mempool.get_attestation(attestation_hash);
			if (!batch)
				return batch.error();

			auto executor = ledger::executor_context(nullptr);
			transactions::attestate::optimize_proofs_and_commitments(&executor, batch->asset, batch->proofs, batch->commitments);
			if (batch->proofs.empty())
				return layer_exception("proof are either not valid or not provided");

			auto collision = executor.get_witness_transaction(batch->asset, batch->proofs.begin()->second.transaction_id);
			if (collision)
			{
				mempool.remove_attestation(attestation_hash);
				return expectation::met;
			}

			uint256_t best_commitment_hash = 0;
			btree_map<uint256_t, btree_set<algorithm::pubkeyhash_t>> attesters;
			auto verification = transactions::attestate::verify_proof_commitment(&executor, batch->asset, batch->commitments, best_commitment_hash, attesters);
			if (!verification)
				return verification;

			auto it = batch->proofs.find(best_commitment_hash);
			if (it == batch->proofs.end())
				return layer_exception("proof required");

			auto* transaction = memory::init<transactions::attestate>();
			transaction->asset = algorithm::asset::base_id_of(batch->asset);
			transaction->set_computed_proof(std::move(it->second), std::move(batch->commitments));
			if (accept_local_transaction(&runner_descriptor->second, transaction))
				mempool.remove_attestation(attestation_hash);

			return expectation::met;
		}
		expects_lr<void> server_node::accept_committed_attestation(const algorithm::asset_id& asset, const superchain::computed_transaction& proof, const algorithm::hashsig_t& signature)
		{
			umutex<std::recursive_mutex> unique(sync.attestation);
			auto mempool = storages::mempoolstate();
			auto status = mempool.add_attestation(asset, proof, signature);
			if (!status)
				return status.error();

			return accept_attestation(proof.as_attestation_hash());
		}
		expects_lr<void> server_node::broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx, const algorithm::pubkeyhash_t& owner)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto mempool = storages::mempoolstate();
			auto action = mempool.add_transaction(**candidate_tx);
			if (!action)
			{
				if (protocol::now().user.consensus.logging)
					VI_WARN("transaction %s %.*s mempool rejection: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), action.error().what());
				return action.error();
			}

			if (protocol::now().user.consensus.logging)
				VI_INFO("transaction %s queued (type: %.*s, nonce: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), candidate_tx->nonce);

			if (events.accept_transaction)
				events.accept_transaction(candidate_hash, *candidate_tx, owner);

			size_t notifications = notify_all_except(uref(from), descriptors::broadcast_transaction_hash(), { format::variable(candidate_hash) });
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_DEBUG("transaction %s broadcasted to %i nodes (type: %.*s)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)notifications, (int)purpose.size(), purpose.data());

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

			query(uref(from), descriptors::fetch_block(), { format::variable(block_hash) }, protocol::now().user.tcp.timeout).then([this, from](expects_rt<exchange>&& event) mutable
			{
				if (event && !event->args.empty())
				{
					ledger::block_evaluation candidate;
					format::ro_stream block_message = format::ro_stream(event->args.front().as_string());
					if (candidate.block.load(block_message))
					{
						auto status = accept_block(std::move(from), candidate, 0);
						if (!status && protocol::now().user.consensus.logging)
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
			if (mempool.get_transaction_by_hash(transaction_hash))
				return expectation::met;

			auto chain = storages::chainstate();
			if (chain.get_transaction_by_hash(transaction_hash))
				return expectation::met;

			query(uref(from), descriptors::fetch_transaction(), { format::variable(transaction_hash) }, protocol::now().user.tcp.timeout).then([this, from](expects_rt<exchange>&& event) mutable
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
			if (event.args.size() != 2)
				return remote_exception("invalid arguments");

			algorithm::asset_id asset = event.args[0].as_uint256();
			format::ro_stream proof_message = format::ro_stream(event.args[1].as_string());
			superchain::computed_transaction proof;
			if (!proof.load(proof_message))
				return remote_exception("invalid proof");

			uint256_t commitment_hash = proof.as_hash();
			algorithm::pubkeyhash_t attester;
			algorithm::hashsig_t commitment_signature = algorithm::hashsig_t(event.args[2].as_string());
			if (!algorithm::signing::recover_hash(commitment_hash, attester, commitment_signature))
				return remote_exception("invalid commitment");

			auto executor = ledger::executor_context(nullptr);
			auto validation = executor.get_verified_validator_attestation(asset, attester);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto finalization = accept_committed_attestation(asset, proof, commitment_signature);
			if (finalization)
				return expectation::met;

			size_t notifications = notify_all_except(std::move(from), descriptors::broadcast_attestation(), format::variables(event.args));
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_DEBUG("attestation %s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);

			return expectation::met;
		}
		expects_rt<void> server_node::broadcast_intermediary(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() < 3 || event.args.size() > 2 + protocol::now().policy.participation.max_per_account)
				return remote_exception("invalid arguments");

			auto signature = algorithm::hashsig_t(event.args[0].as_string());
			if (signature.empty())
				return remote_exception("invalid signature");

			auto address = text_address_to_socket_address(event.args[1].as_string());
			if (!address)
				return remote_exception("invalid address");

			size_t accounts_size = event.args.size() - 2;
			btree_set<algorithm::pubkeyhash_t> accounts;
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

			size_t notifications = notify_all_except(std::move(from), descriptors::broadcast_intermediary(), format::variables(event.args));
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_DEBUG("representative for %s broadcasted to %i nodes", algorithm::signing::encode_address(account).c_str(), (int)notifications);

			for (auto& target : accounts)
			{
				if (find_descriptor(target) != nullptr)
				{
					connect_to_physical_node(*address);
					break;
				}
			}

			return expectation::met;
		}
		expects_rt<void> server_node::check_socket(uref<relay>&&, const exchange& event)
		{
			if (!event.args.empty())
				return remote_exception("invalid args");

			return expectation::met;
		}
		expects_rt<void> server_node::announce_neighbor(uref<relay>&& from, const exchange& event)
		{
			if (event.args.size() != 1 && event.args.size() != 2)
				return remote_exception("invalid args");

			auto public_key = algorithm::pubkey_t(event.args[0].as_string());
			if (public_key.empty())
				return remote_exception("invalid public key");

			auto address = event.args.size() > 1 ? text_address_to_socket_address(event.args[1].as_string()) : option<socket_address>(optional::none);
			if (address)
				storages::mempoolstate().apply_unknown_node(*address, from ? from->private_network() : true);

			if (!from)
			{
				umutex<std::recursive_mutex> unique(exclusive);
				for (auto& [account, descriptor] : descriptors)
				{
					if (address)
						descriptor.first.availability.neighbors.insert(public_key);
					else
						descriptor.first.availability.neighbors.erase(public_key);
				}
			}
			else
			{
				umutex<std::recursive_mutex> unique(exclusive);
				if (address)
					from->as_descriptor()->first.availability.neighbors.insert(public_key);
				else
					from->as_descriptor()->first.availability.neighbors.erase(public_key);
			}

			umutex<std::recursive_mutex> unique(sync.neighbor);
			for (auto& [id, neighbor] : neighbors)
				neighbor(public_key, address ? 1 : -1);

			return expectation::met;
		}
		expects_rt<format::variables> server_node::perform_handshake(uref<relay>&& from, const exchange& event, bool is_acknowledgement)
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
			else if (!algorithm::signing::recover(handshake_proof(peer_node, peer_time, nullptr), peer_wallet.public_key, peer_signature))
				return remote_exception("invalid signature");
			else if (peer_node.major_version != protocol::now().message.major_version)
				return remote_exception("version " + peer_node.as_version() + " not supported");

			auto mempool = storages::mempoolstate();
			uint64_t peer_latency = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
			peer_node.availability.latency = peer_latency;
			peer_node.availability.reachable = is_acknowledgement;
			if (!from->private_network())
				peer_node.address = socket_address(from->peer_address(), peer_node.address.get_ip_port().or_else(protocol::now().user.consensus.port));

			algorithm::signing::derive_public_key_hash(peer_wallet.public_key, peer_wallet.public_key_hash);
			if (!peer_node.is_valid() || peer_wallet.public_key_hash.empty() || find_descriptor(peer_wallet.public_key_hash) || find_by_account(peer_wallet.public_key_hash))
			{
				auto prev = mempool.get_node(peer_descriptor.first.address);
				if (prev)
				{
					if (!find_descriptor(prev->second.public_key_hash))
						mempool.clear_node(peer_descriptor.first.address);
				}
				return remote_exception("node is not acceptable");
			}

			auto prev_descriptor = mempool.get_node(peer_node.address);
			if (prev_descriptor)
				peer_node.availability.reachable = peer_node.availability.reachable || prev_descriptor->first.availability.reachable;

			if (!accept_node(mempool, peer_descriptor, node_category::other))
				return remote_exception("node is not memorizable");

			from->initialize(std::move(peer_descriptor));
			if (is_acknowledgement)
				return format::variables();

			auto node_message = string();
			if (!event.callee || !algorithm::signing::sign(handshake_proof(event.callee->first, system_time, &node_message), event.callee->second.secret_key, peer_signature))
				return remote_exception("proof generation error");

			return format::variables({ format::variable(node_message), format::variable(system_time), format::variable(peer_signature.optimized_view()), format::variable(peer_latency) });
		}
		expects_rt<format::variables> server_node::perform_discovery(uref<relay>&& from, const exchange& event, bool is_acknowledgement)
		{
			if (event.args.size() < 3)
				return remote_exception("invalid arguments");

			auto block_handle = exchange();
			block_handle.args.reserve(1);
			block_handle.args.push_back(event.args[1]);

			auto status = broadcast_block_hash(uref(from), std::move(block_handle));
			if (!status)
				return status.error();

			auto mempool = storages::mempoolstate();
			auto address = text_address_to_socket_address(event.args[0].as_string());
			if (address && !storages::routing_util::is_address_reserved(*address) && !storages::routing_util::is_address_private(*address))
			{
				for (auto& [account, descriptor] : descriptors)
				{
					bool runner = runner_descriptor == &descriptor;
					descriptor.first.address = std::move(*address);
					accept_node(mempool, descriptor, runner ? node_category::runner : node_category::neighbor).report("mempool local node save failed");
				}
			}

			size_t new_nodes = 0;
			bool private_network = from->private_network();
			for (size_t i = 3; i < event.args.size(); i++)
			{
				address = text_address_to_socket_address(event.args[i].as_string());
				new_nodes += address && !connected_to_ip_address(*address) && mempool.apply_unknown_node(*address, private_network) ? 1 : 0;
			}

			size_t self_transactions = mempool.get_transactions_count().or_else(0);
			size_t other_transactions = (size_t)event.args[2].as_uint32();
			announce_peer(uref(from), true);
			if (self_transactions < other_transactions)
				synchronize_mempool_with(uref(from));
			if (new_nodes > 0)
				run_topology_optimization();

			for (auto& [account, descriptor] : descriptors)
				fill_node_neighbors(descriptor);

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

			const uint64_t blocks_count = std::min(protocol::now().message.headers_per_query, branch_length);
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
		expects_rt<format::variables> server_node::fetch_block(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint256_t block_hash = event.args[0].as_uint256();
			if (!block_hash)
				return remote_exception("invalid arguments");

			auto chain = storages::chainstate();
			auto block = chain.get_block_by_hash(block_hash, ELEMENTS_MANY, (uint32_t)storages::block_details::transactions | (uint32_t)storages::block_details::block_transactions);
			if (block)
				return format::variables({ format::variable(block->as_message().data) });

			umutex<std::recursive_mutex> unique(sync.tip);
			auto it = pending_blocks.find(block_hash);
			if (it != pending_blocks.end())
				return format::variables({ format::variable(it->second->as_message().data) });

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
			if (block_hash > 0)
			{
				auto result = chain.get_block_number_by_hash(block_hash);
				if (result)
					block_number = *result;
			}

			format::variables result;
			uint64_t size = protocol::now().message.blocks_size_per_query, offset = 0;
			while (block_number > 0 && size > 0)
			{
				auto block = chain.get_block_by_number(block_number + offset, ELEMENTS_MANY, (uint32_t)storages::block_details::transactions | (uint32_t)storages::block_details::block_transactions);
				if (!block)
					break;

				auto message = block->as_message();
				result.push_back(format::variable(message.data));
				size -= std::min(size, message.data.size());
				++offset;
			}

			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::fetch_mempool(uref<relay>&&, const exchange& event)
		{
			if (event.args.size() != 1)
				return remote_exception("invalid arguments");

			uint64_t cursor = event.args.front().as_uint64();
			const uint64_t transactions_count = protocol::now().message.hashes_per_query;
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
			transaction = chain.get_transaction_by_hash(transaction_hash);
			if (transaction)
				return format::variables({ format::variable((*transaction)->as_message().data) });

			return format::variables();
		}
		expects_rt<format::variables> server_node::fetch_transactions(uref<relay>&&, const exchange& event)
		{
			if (event.args.empty() || event.args.size() > protocol::now().message.transactions_per_query)
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
					transaction = chain.get_transaction_by_hash(transaction_hash);
				if (transaction)
					result.push_back(format::variable((*transaction)->as_message().data));
			}
			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::distribute_entropy_shares(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto proof_transaction = executor.get_block_transaction<transactions::route>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto public_key = find_public_key(((transactions::route*)*proof_transaction->transaction)->get_attester(proof_transaction->receipt));
			if (!public_key)
				return remote_exception("node public key not found");

			uint8_t encrypted_shares_size;
			auto reader = format::ro_stream(packed->at(2).as_string());
			if (!reader.read_integer(reader.read_type(), &encrypted_shares_size))
				return remote_exception("encrypted shares list size not valid");

			auto encrypted_shares = btree_map<algorithm::pubkeyhash_t, string>();
			for (uint8_t i = 0; i < encrypted_shares_size; i++)
			{
				algorithm::pubkeyhash_t participant; string intermediate;
				if (!reader.read_string(reader.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, participant.blob, sizeof(participant)))
					return remote_exception("encrypted share not valid");

				string encrypted_share;
				if (!reader.read_string(reader.read_type(), &encrypted_share))
					return remote_exception("encrypted share not valid");

				encrypted_shares[participant] = std::move(encrypted_share);
			}

			auto dispatcher = dispatcher_context(this);
			executor.transaction = *proof_transaction->transaction;
			executor.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatcher_context::distribute_entropy_shares(&dispatcher, &executor, &event.callee->second, encrypted_shares);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			return pack_private_result({ format::variable(encrypted_shares.size()) }, *public_key);
		}
		expects_rt<format::variables> server_node::aggregate_entropy_shares(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto proof_transaction = executor.get_block_transaction<transactions::setup>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto public_key = find_public_key(proof_transaction->receipt.from);
			if (!public_key)
				return remote_exception("node public key not found");

			auto intermediate = string();
			auto reader = format::ro_stream(packed->at(2).as_string());
			auto compositor = ledger::dispatcher_context::entropy_aggregation_state();
			if (!reader.read_string(reader.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, compositor.public_key.blob, sizeof(compositor.public_key)))
				return remote_exception("invalid public key of new participant");

			uint16_t encrypted_shares_size;
			if (!reader.read_integer(reader.read_type(), &encrypted_shares_size))
				return remote_exception("invalid encrypted shares size");

			for (uint16_t i = 0; i < encrypted_shares_size; i++)
			{
				uint256_t ref_hash;
				if (!reader.read_integer(reader.read_type(), &ref_hash))
					return remote_exception("invalid ref hash of encrypted share");

				compositor.encrypted_shares[ref_hash] = btree_map<algorithm::pubkeyhash_t, string>();
			}

			auto dispatcher = dispatcher_context(this);
			executor.transaction = *proof_transaction->transaction;
			executor.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatcher_context::aggregate_entropy_shares(&dispatcher, &executor, &event.callee->second, compositor.public_key, compositor.encrypted_shares);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			auto writer = format::wo_stream();
			for (auto& [ref_hash, encrypted_shares] : compositor.encrypted_shares)
			{
				writer.write_integer(ref_hash);
				writer.write_integer((uint16_t)encrypted_shares.size());
				for (auto& [participant, encrypted_share] : encrypted_shares)
				{
					writer.write_string(participant.optimized_view());
					writer.write_string(encrypted_share);
				}
			}

			return pack_private_result({ format::variable(writer.data) }, *public_key);
		}
		expects_rt<format::variables> server_node::recover_entropy(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto proof_transaction = executor.get_block_transaction<transactions::setup>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto public_key = find_public_key(proof_transaction->receipt.from);
			if (!public_key)
				return remote_exception("node public key not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto compositor = ledger::dispatcher_context::entropy_recovery_state();
			if (!compositor.load_message(reader))
				return remote_exception("state machine not valid");

			auto dispatcher = dispatcher_context(this);
			executor.transaction = *proof_transaction->transaction;
			executor.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatcher_context::recover_entropy(&dispatcher, &executor, &event.callee->second, compositor.proof, compositor.encrypted_shares, compositor.encrypted_entropies);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			return pack_private_result({ format::variable(compositor.proof.optimized_view()) }, *public_key);
		}
		expects_rt<format::variables> server_node::aggregate_public_key(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 3)
				return remote_exception("invalid arguments");

			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto proof_transaction = executor.get_block_transaction<transactions::route>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto public_key = find_public_key(((transactions::route*)*proof_transaction->transaction)->get_attester(proof_transaction->receipt));
			if (!public_key)
				return remote_exception("node public key not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto compositor = algorithm::composition::load_compositor(reader);
			if (!compositor)
				return remote_exception("in state machine not valid");

			uint8_t list_size;
			if (!reader.read_integer(reader.read_type(), &list_size))
				return remote_exception("encrypted shares list size not valid");

			auto list = btree_map<algorithm::pubkey_t, string>();
			for (uint8_t i = 0; i < list_size; i++)
			{
				algorithm::pubkey_t item; string intermediate;
				if (!reader.read_string(reader.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
					return remote_exception("encrypted share public key not valid");

				list.insert(std::make_pair(item, string()));
			}

			auto dispatcher = dispatcher_context(this);
			executor.transaction = *proof_transaction->transaction;
			executor.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatcher_context::aggregate_public_key(&dispatcher, &executor, &event.callee->second, list, **compositor);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			format::wo_stream writer;
			if (!(*compositor)->store(&writer))
				return remote_exception("out state machine not valid");

			for (auto& [target_public_key, encrypted_share] : list)
				writer.write_string(encrypted_share);

			return pack_private_result({ format::variable(writer.data) }, *public_key);
		}
		expects_rt<format::variables> server_node::aggregate_signature(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 4)
				return remote_exception("invalid arguments");

			auto chainstate = storages::chainstate();
			auto block_number = packed->at(0).as_uint64();
			auto proof_hash = packed->at(1).as_uint256();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto executor = ledger::executor_context(nullptr);
			auto proof_transaction = executor.get_block_transaction<transactions::withdraw>(proof_hash);
			if (!proof_transaction)
				return remote_exception("state proof not found");

			auto public_key = find_public_key(((transactions::withdraw*)*proof_transaction->transaction)->get_attester(proof_transaction->receipt));
			if (!public_key)
				return remote_exception("node public key not found");

			auto reader = format::ro_stream(packed->at(2).as_string());
			auto message = superchain::prepared_transaction();
			if (!message.load(reader))
				return remote_exception("in state message not valid");

			reader = format::ro_stream(packed->at(3).as_string());
			auto compositor = algorithm::composition::load_compositor(reader);
			if (!compositor)
				return remote_exception("in state machine not valid");

			auto dispatcher = dispatcher_context(this);
			executor.transaction = *proof_transaction->transaction;
			executor.receipt = std::move(proof_transaction->receipt);

			auto aggregation = local_dispatcher_context::aggregate_signature(&dispatcher, &executor, &event.callee->second, message, **compositor);
			if (!aggregation)
				return remote_exception(std::move(aggregation.error().message()));

			format::wo_stream writer;
			if (!(*compositor)->store(&writer))
				return remote_exception("out state machine not valid");

			return pack_private_result({ format::variable(writer.data) }, *public_key);
		}
		expects_lr<void> server_node::dispatch_transaction_logs(const algorithm::asset_id& asset, superchain::transaction_logs&& logs)
		{
			for (auto& receipt : logs.receipts)
			{
				for (auto& [account, descriptor] : descriptors)
				{
					auto& [node, wallet] = descriptor;
					if (!node.services.has_attestation)
						continue;

					algorithm::hashsig_t commitment_signature; uint256_t commitment_hash;
					if (!transactions::attestate::commit_to_proof(receipt, wallet.secret_key, commitment_hash, commitment_signature))
						continue;

					auto finalization = accept_committed_attestation(asset, receipt, commitment_signature);
					if (finalization)
						continue;

					auto proof_message = receipt.as_message();
					size_t notifications = notify_all(descriptors::broadcast_attestation(), { format::variable(proof_message.data), format::variable(commitment_signature.view()) });
					if (notifications > 0 && protocol::now().user.consensus.logging)
						VI_DEBUG("attestation %s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);
				}
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
				auto unknown_node = mempool.sample_connectable_unknown_node();
				if (!unknown_node)
					return layer_exception("no candidate found in mempool");
				else if (connected_to_ip_address(*unknown_node))
					goto retry_unknown_node;

				if (protocol::now().user.consensus.logging)
					VI_INFO("node %s:%i handshake: try unknown node", unknown_node->get_ip_address().or_else(string("[bad_address]")).c_str(), (int)unknown_node->get_ip_port().or_else(0));

				return expects_lr<socket_address>(std::move(*unknown_node));
			}
			else if (connected_to_ip_address(known_node->first.address) || mempool.has_cooldown_on_node(known_node->first.address).or_else(false))
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
						auto addresses = format::tree::from_json(std::string_view(response->content.data.data(), response->content.data.size()));
						if (addresses)
						{
							auto mempool = storages::mempoolstate(); results = 0;
							for (auto& address : addresses->childs())
							{
								auto endpoint = system_endpoint(address.value.as_blob(), bootstrap_url);
								if (endpoint.is_valid() && !connected_to_ip_address(endpoint.address) && mempool.apply_unknown_node(endpoint.address, false))
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
				uint64_t system_time = protocol::now().time.now_cpu();
				if (!algorithm::signing::sign(handshake_proof(node, system_time, &node_message), wallet.secret_key, signature))
					coreturn remote_exception("proof generation error");

				uref<relay> next = new relay(node_type::outbound, candidate.reset());
				append_node(uref(next));

				auto abort = [&](remote_exception&& exception) -> remote_exception&&
				{
					next->abort(exception.message());
					return std::move(exception);
				};
				cospawn([this, next]() mutable { pull_messages(std::move(next)); });

				auto result = coawait(query(uref(next), descriptors::perform_handshake(), { format::variable(node_message), format::variable(system_time), format::variable(signature.optimized_view()) }, protocol::now().user.tcp.timeout, true));
				if (!result)
					coreturn abort(std::move(result.error()));

				auto acknowledgement = perform_handshake(uref(next), *result, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto* peer_descriptor = next->as_descriptor();
				if (!peer_descriptor)
					coreturn abort(remote_exception("invalid descriptor"));

				auto subresult = coawait(query(uref(next), descriptors::perform_discovery(), build_state_exchange(uref(next)), protocol::now().user.tcp.timeout));
				if (!subresult)
					coreturn abort(remote_exception(std::move(subresult.error().message())));

				acknowledgement = perform_discovery(uref(next), *subresult, true);
				if (!acknowledgement)
					coreturn abort(remote_exception(std::move(acknowledgement.error().message())));

				auto& protocol = protocol::change();
				uint64_t peer_time = result->args[1].as_uint64();
				uint64_t peer_latency = result->args[3].as_uint64();
				uint64_t latency_time = peer_time > system_time ? peer_time - system_time : system_time - peer_time;
				uint64_t varying_peer_time = peer_time + (peer_latency + latency_time) / 2;
				protocol.time.adjust(peer_descriptor->first.address, (int64_t)system_time - (int64_t)varying_peer_time);
				synchronize_mempool_with(uref(next));
				coreturn expects_rt<uref<relay>>(std::move(next));
			}).then<expects_rt<uref<relay>>>([address](expects_rt<uref<relay>>&& result) -> expects_rt<uref<relay>>
			{
				if (!result)
				{
					auto mempool = storages::mempoolstate();
					mempool.apply_node_quality(address, -1, protocol::now().user.tcp.timeout);
					if (protocol::now().user.consensus.logging)
						VI_WARN("node %s:%i handshake: %s", address.get_ip_address().or_else("[bad_address]").c_str(), (int)address.get_ip_port().or_else(0), result.what().c_str());
				}
				return result;
			});
		}
		expects_promise_rt<hash_set<algorithm::pubkeyhash_t>> server_node::connect_to_logical_nodes(hash_set<algorithm::pubkeyhash_t>&& accounts)
		{
			if (accounts.empty())
				return expects_promise_rt<hash_set<algorithm::pubkeyhash_t>>(remote_exception("invalid arguments"));

			hash_set<algorithm::pubkeyhash_t> early_results;
			for (auto& account : accounts)
			{
				if (find_descriptor(account) || find_by_account(account) || find_with_neighbor_account(account))
					early_results.insert(account);
			}
			if (early_results.size() == accounts.size())
				return expects_promise_rt<hash_set<algorithm::pubkeyhash_t>>(std::move(early_results));

			return coasync<expects_rt<hash_set<algorithm::pubkeyhash_t>>>([this, accounts = std::move(accounts), early_results = std::move(early_results)]() mutable -> expects_promise_rt<hash_set<algorithm::pubkeyhash_t>>
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
							if (target && target->first.availability.reachable)
							{
								directly_connected_accounts[account] = connect_to_physical_node(target->first.address).then<expects_rt<void>>([](expects_rt<uref<relay>>&& result) -> expects_rt<void>
								{
									if (!result)
										return result.error();

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

				hash_set<algorithm::pubkeyhash_t> results;
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
					coreturn expects_promise_rt<hash_set<algorithm::pubkeyhash_t>>(std::move(results));
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
				if (!address || !algorithm::signing::sign(discovery_proof(best_address, indirectly_connected_accounts), runner_descriptor->second.secret_key, signature))
					goto exit;

				format::variables args;
				args.reserve(indirectly_connected_accounts.size() + 2);
				args.push_back(format::variable(signature.optimized_view()));
				args.push_back(format::variable(*address));
				for (auto& account : indirectly_connected_accounts)
					args.push_back(format::variable(account.optimized_view()));

				std::mutex mutex; promise<void> task;
				uint256_t id = algorithm::hashing::hash256i(*crypto::random_bytes(32));
				auto resolver = [&id, &mutex, &task, &results, &indirectly_connected_accounts](const algorithm::pubkey_t& public_key, int8_t status)
				{
					umutex<std::mutex> unique(mutex);
					if (task.is_pending())
					{
						if (!public_key.empty())
						{
							algorithm::pubkeyhash_t account;
							algorithm::signing::derive_public_key_hash(public_key, account);
							if (indirectly_connected_accounts.find(account) != indirectly_connected_accounts.end())
							{
								if (status > 0)
								{
									indirectly_connected_accounts.erase(account);
									results.insert(account);
								}
								else
								{
									indirectly_connected_accounts.insert(account);
									results.erase(account);
								}
							}
						}
						if (public_key.empty() || indirectly_connected_accounts.empty())
							task.set();
					}
				};
				umutex<std::recursive_mutex> unique(sync.neighbor);
				neighbors[id] = resolver;
				unique.unlock();

				task_id timeout = INVALID_TASK_ID;
				if (notify_all(descriptors::broadcast_intermediary(), std::move(args)) > 0)
				{
					auto* queue = schedule::get();
					timeout = queue->set_timeout(protocol::now().user.tcp.timeout, std::bind(resolver, algorithm::pubkey_t(), 0));
					coawait(std::move(task));
					queue->clear_timeout(timeout);
				}

				unique.lock();
				neighbors.erase(id);
				goto exit;
			});
		}
		expects_promise_rt<void> server_node::synchronize_mempool_with(uref<relay>&& from)
		{
			return coasync<expects_rt<void>>([this, from]() -> expects_promise_rt<void>
			{
				uint64_t cursor = 0;
				while (is_active())
				{
					auto result = coawait(query(uref(from), descriptors::fetch_mempool(), { format::variable(cursor) }, protocol::now().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.size() < 2)
						break;

					btree_set<uint256_t> transaction_hashes;
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

					while (!transaction_hashes.empty())
					{
						format::variables messages;
						for (size_t i = 0; i < protocol::now().message.transactions_per_query; i++)
						{
							messages.push_back(format::variable(*transaction_hashes.begin()));
							transaction_hashes.erase(transaction_hashes.begin());
							if (transaction_hashes.empty())
								break;
						}

						auto subresult = coawait(query(uref(from), descriptors::fetch_transactions(), std::move(messages), protocol::now().user.tcp.timeout));
						if (subresult && !subresult->args.empty())
						{
							for (auto& transaction : subresult->args)
							{
								format::ro_stream transaction_message = format::ro_stream(transaction.as_string());
								uptr<ledger::transaction_message> candidate = tangent::transactions::resolver::from_stream(transaction_message);
								if (candidate && candidate->load(transaction_message))
									accept_transaction(uref(from), std::move(candidate));
							}
						}
					}

					const uint64_t transactions_count = protocol::now().message.hashes_per_query;
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
				std::mutex batch_mutex;
				auto& [new_tip_fork_hash, new_tip] = fork;
				auto new_tip_number = new_tip.header.number;
				auto new_tip_hash = uint256_t(0);
				auto old_tip = storages::chainstate().get_latest_block_header();
				auto old_tip_number = old_tip ? old_tip->number : 0;
				if (old_tip_number > 0 && new_tip_number > old_tip_number)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_headers(), { format::variable(old_tip_number + 1), format::variable((uint8_t)1) }, protocol::now().user.tcp.timeout));
					if (result && result->args.size() >= 3)
					{
						auto collision_tip = ledger::block_header();
						auto message = format::ro_stream(result->args[2].as_string());
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

				while (is_active() && old_tip_number > 0 && new_tip_number > 0)
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_headers(), { format::variable(new_tip_number), format::variable(new_tip_number > old_tip_number ? 1 + new_tip_number - (old_tip_number - 1) : protocol::now().message.headers_per_query) }, protocol::now().user.tcp.timeout));
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
						VI_INFO("block %s conflict: verifying headers (range: [%" PRIu64 "; %" PRIu64 "])", algorithm::encoding::encode_0xhex256(new_tip_fork_hash).c_str(), new_tip_number - (blocks_count > new_tip_number ? 1 : blocks_count), new_tip_number);
					}

					option<remote_exception> error = optional::none;
					uint256_t best_new_tip_hash = 0;
					uint64_t best_new_tip_number = 0;
					size_t batch_size = 16, block_count = result->args.size() - 1;
					size_t batch_count = block_count / batch_size + (block_count % batch_size == 0 ? 0 : 1);
					for (auto& task : parallel::for_loop(batch_count, 1, [&](size_t batch_index)
					{
						auto chain = storages::chainstate();
						auto parent_header = ledger::block_header();
						auto child_header = ledger::block_header();
						size_t begin = 1 + batch_index * batch_size;
						size_t end = begin + (batch_index == batch_count - 1 ? block_count % batch_size : batch_size);
						for (size_t i = begin; i < end; i++)
						{
							auto message = format::ro_stream(result->args[i].as_string());
							auto verification = child_header.load(message) ? child_header.verify_validity(parent_header.number > 0 ? &parent_header : nullptr) : expects_lr<void>(layer_exception("bad message"));
							if (!verification)
							{
								umutex<std::mutex> unique(batch_mutex);
								error = remote_exception(stringify::text("invalid block header (height: %" PRIu64 "): %s", child_header.number, verification.error().what()));
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

				if (new_tip_hash > 0 && protocol::now().user.consensus.logging)
					VI_INFO("block %s conflict: collision found (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(new_tip_hash).c_str(), new_tip_number);

				uint256_t best_tip_hash = 0;
				new_tip_number = new_tip_hash > 0 ? 0 : 1;
				while (is_active() && (new_tip_number > 0 || new_tip_hash > 0))
				{
					auto result = coawait(query(uref(new_tip.state), descriptors::fetch_blocks(), { format::variable(new_tip_hash), format::variable(new_tip_number) }, protocol::now().user.tcp.timeout));
					if (!result)
						coreturn result.error();
					else if (result->args.empty())
						break;

					new_tip_hash = 0;
					for (auto& block : result->args)
					{
						ledger::block_evaluation tip;
						format::ro_stream block_message = format::ro_stream(block.as_string());
						if (!tip.block.load(block_message))
							coreturn remote_exception("block violates message protocol");

						best_tip_hash = tip.block.as_hash();
						new_tip_number = tip.block.number + 1;
						auto status = accept_block(uref(new_tip.state), tip, new_tip_fork_hash);
						if (!status)
							coreturn remote_exception(std::move(status.error().message()));

						if (!is_active())
							break;
					}
				}

				if (best_tip_hash > 0)
				{
					broadcast_pending_block(uref(new_tip.state), best_tip_hash, new_tip_number - 1);
					finalize_pending_block(uref(new_tip.state));
				}

				coreturn expectation::met;
			});
		}
		expects_promise_rt<exchange> server_node::query(uref<relay>&& from, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call)
		{
			if (!force_call && !from->fully_valid())
				return expects_promise_rt<exchange>(remote_exception("node is not in valid state (offline/unauthorized)"));
			else if (!is_active())
				return expects_promise_rt<exchange>(remote_exception::shutdown());

			if (protocol::now().user.consensus.logging)
				VI_DEBUG("node %s query \"%.*s\" out: %s", from->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str());

			auto result = from->push_query(descriptor, std::move(args), timeout_ms);
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

			auto indirect_node = find_with_neighbor_account(account);
			if (!indirect_node)
				return expects_promise_rt<exchange>(remote_exception::retry_later());

			if (protocol::now().user.consensus.logging)
				VI_DEBUG("node %s forward query \"%.*s\" out: %s", indirect_node->peer_address().c_str(), (int)descriptor.name.size(), descriptor.name.data(), args.empty() ? "OK" : stringify::text("[%i values]", (int)args.size()).c_str());

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

			if (protocol::now().user.consensus.logging)
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

			auto random_nodes = mempool.get_random_nodes_with(protocol::now().message.hashes_per_query).or_else(vector<storages::node_location_pair>());
			args.reserve(args.size() + random_nodes.size());
			for (auto& [node_account, node_address] : random_nodes)
			{
				auto text_address = socket_address_to_text_address(node_address);
				if (text_address)
					args.push_back(format::variable(*text_address));
			}
			return args;
		}
		void server_node::announce_peer(uref<relay>&& from, bool available)
		{
			auto* peer_descriptor = from ? from->as_descriptor() : nullptr;
			if (!peer_descriptor)
				return;

			exchange message;
			message.args.reserve(2);
			message.args.push_back(format::variable(peer_descriptor->second.public_key.view()));
			if (available)
				message.args.push_back(format::variable(socket_address_to_text_address(peer_descriptor->first.address).or_else("?")));
			notify_all_except(std::move(from), descriptors::announce_neighbor(), format::variables(message.args));
			announce_neighbor(nullptr, message);
		}
		void server_node::bind_event(const callable::descriptor& descriptor, event_callback&& on_event_callback, bool uses_inventory)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.event = std::move(on_event_callback);
			callable.inventory = uses_inventory;
		}
		void server_node::bind_query(const callable::descriptor& descriptor, query_callback&& on_query_callback)
		{
			auto& callable = callables[descriptor.id];
			callable.name = descriptor.name;
			callable.query = std::move(on_query_callback);
			callable.inventory = false;
		}
		void server_node::pull_messages(uref<relay>&& from)
		{
			VI_ASSERT(from, "state should be set");
			auto* stream = from->as_socket();
			if (!stream)
				return abort_node(std::move(from), "connection lost");

			uint8_t buffer[CHUNK_SIZE];
			size_t max_buffer_size = sizeof(buffer);
			uint64_t next_pull_time = 0, message_latency = 100;
			while (from->bandwidth.check(max_buffer_size, next_pull_time))
			{
				auto size = stream->read(buffer, std::min(max_buffer_size, sizeof(buffer)));
				if (!size)
				{
					if (size.error() != std::errc::operation_would_block)
						return abort_node(std::move(from), "connection reset");

					multiplexer::get()->when_readable(stream, [this, from](socket_poll event) mutable
					{
						if (packet::is_done(event))
							pull_messages(std::move(from));
						else if (packet::is_error(event))
							abort_node(std::move(from), "connection reset");
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
					if (header.magic != protocol::now().message.packet_magic || header.length > protocol::now().message.max_body_size)
					{
					abort:
						from->report_call(-1, message_latency);
						abort_node(std::move(from), "invalid message header");
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
					if (protocol::now().user.consensus.logging)
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
							if (it == callables.end() || !it->second.event)
								goto abort;

							uint256_t hash = message.as_inventory_hash();
							umutex<std::mutex> unique_inventory(sync.inventory);
							if (!inventory.insert(hash) || !from->get_inventory().insert(hash))
								break;

							unique_inventory.unlock();
							auto result = it->second.event(this, uref(from), message);
							if (!result && protocol::now().user.consensus.logging)
								VI_WARN("node %s event \"%.*s\" error: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
							else if (result && protocol::now().user.consensus.logging)
								VI_DEBUG("node %s event \"%.*s\" result: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? "OK" : "RETRY");
							break;
						}
						case exchange::side::query:
						{
							auto it = callables.find(message.descriptor);
							if (it == callables.end() || !it->second.query || !message.session)
								goto abort;

							auto result = it->second.query(this, uref(from), message);
							if (!result && protocol::now().user.consensus.logging)
								VI_WARN("node %s query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
							else if (result && protocol::now().user.consensus.logging)
								VI_DEBUG("node %s query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

							from->push_event(message.session, pack_query_result(result));
							push_messages(uref(from));
							break;
						}
						case exchange::side::forward:
						{
							auto it = callables.find(message.descriptor);
							if (it == callables.end() || !it->second.query || !message.session)
								goto abort;

							auto account = message.args.empty() ? algorithm::pubkeyhash_t() : algorithm::pubkeyhash_t(message.args[0].as_string());
							if (account.empty())
								goto abort;

							auto session = message.session;
							auto forward_state = find_by_account(account);
							auto forward_descriptor = find_descriptor(account);
							if (forward_state)
							{
								auto method = callable::descriptor(it->second.name, it->first);
								message.args.erase(message.args.begin());
								query(uref(forward_state), method, std::move(message.args), protocol::now().user.tcp.timeout).when([this, from, forward_state, method, session](expects_rt<exchange>&& result) mutable
								{
									if (!result && protocol::now().user.consensus.logging)
										VI_WARN("node %s forward query \"%.*s\" error in: %s", forward_state->peer_address().c_str(), (int)method.name.size(), method.name.data(), result.what().c_str());
									else if (result && protocol::now().user.consensus.logging)
										VI_DEBUG("node %s forward query \"%.*s\" result in: %s", from->peer_address().c_str(), (int)method.name.size(), method.name.data(), result ? result->args.empty() ? "OK" : stringify::text("[%i values]", (int)result->args.size()).c_str() : "RETRY");

									from->push_event(session, pack_query_result(result ? expects_rt<format::variables>(std::move(result->args)) : expects_rt<format::variables>(result.error())));
									push_messages(std::move(from));
								});
							}
							else if (forward_descriptor)
							{
								message.callee = forward_descriptor;
								auto result = it->second.query(this, uref(from), message);
								if (!result && protocol::now().user.consensus.logging)
									VI_WARN("node %s forward query \"%.*s\" error out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result.what().c_str());
								else if (result && protocol::now().user.consensus.logging)
									VI_DEBUG("node %s forward query \"%.*s\" result out: %s", from->peer_address().c_str(), (int)it->second.name.size(), it->second.name.data(), result ? result->empty() ? "OK" : stringify::text("[%i values]", (int)result->size()).c_str() : "RETRY");

								from->push_event(message.session, pack_query_result(result));
								push_messages(uref(from));
							}
							else
							{
								from->push_event(session, pack_query_result(remote_exception::retry_later()));
								push_messages(std::move(from));
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
				return abort_node(std::move(from), "connection lost");
			else if (!from->prepare_outgoing())
				return;

			stream->write_queued(from->outgoing_buffer(), from->outgoing_size(), [this, stream, from](socket_poll event) mutable
			{
				from->clear_outgoing();
				if (packet::is_done(event))
					cospawn([this, from = std::move(from)]() mutable { push_messages(std::move(from)); });
				else if (packet::is_error(event))
					abort_node(std::move(from), "connection reset");
			}, false);
		}
		void server_node::abort_node(uref<relay>&& from, const std::string_view& message)
		{
			VI_ASSERT(from, "state should be set");
			auto* inbound_node = from->as_inbound_node();
			auto* outbound_node = from->as_outbound_node();
			announce_peer(uref(from), false);
			from->abort(message);
			erase_node(std::move(from));
			if (inbound_node != nullptr)
			{
				inbound_node->abort();
				finalize(inbound_node);
			}
			if (outbound_node != nullptr)
				outbound_node->release();
		}
		void server_node::abort_node_by_account(const algorithm::pubkeyhash_t& account, const std::string_view& message)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* descriptor = node.second->as_descriptor();
				if (descriptor != nullptr && descriptor->second.public_key_hash.equals(account))
				{
					unique.unlock();
					return abort_node(uref(node.second), message);
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
			erase_node_by_instance(from->as_instance());
		}
		void server_node::erase_node_by_instance(void* instance)
		{
			VI_ASSERT(instance != nullptr, "instance should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			if (it == nodes.end())
				return;

			uref<relay> from = std::move(it->second);
			nodes.erase(it);
			unique.unlock();
			clear_pending_fork(*from);
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

			node->stream->set_io_timeout(protocol::now().user.tcp.timeout);
			from = new relay(node_type::inbound, node);
			append_node(uref(from));
			pull_messages(std::move(from));
		}
		bool server_node::try_acquire_checkpointer()
		{
			umutex<std::recursive_mutex> unique(sync.fork);
			if (prover.verifying.load())
				return false;

			prover.verifying = true;
			return true;
		}
		void server_node::release_checkpointer()
		{
			umutex<std::recursive_mutex> unique(sync.fork);
			prover.verifying = false;
		}
		bool server_node::run_superchain_sync(const algorithm::asset_id& asset)
		{
			if (!protocol::now().user.superchain.listener)
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
				uint64_t retry_after_timestamp = std::numeric_limits<uint64_t>::max();
				VI_INFO("%s block pulling: resuming now", blockchain.c_str());
			retry:
				while (is_active())
				{
					auto result = coawait(offchain->link_transactions(listener->asset));
					if (!result)
					{
						if (protocol::now().user.superchain.logging && !listener->options.state.retry_after_time)
							VI_WARN("%s block pulling halt: %s", blockchain.c_str(), result.error().what());

						if (!is_active())
							coreturn_void;
						else if (result.error().is_retry())
							retry_after_timestamp = std::min(retry_after_timestamp, result.error().is_retry_after() ? result.error().retry_after_timestamp() : (protocol::now().time.now_cpu() + protocol::now().user.superchain.polling_frequency));
						break;
					}

					umutex<std::mutex> unique(sync.fetcher);
					auto it = fetchers.find(listener->asset);
					size_t requests = it != fetchers.end() ? it->second.requests : 0;
					if (it != fetchers.end())
						it->second.requests = 0;

					unique.unlock();
					for (auto& log : *result)
					{
						if (protocol::now().user.superchain.logging)
							log.report_logs(listener->asset, listener->options, requests);
						if (!log.receipts.empty())
							dispatch_transaction_logs(listener->asset, std::move(log)).report("failed to dispatch transaction logs");
					}
				}

				if (!is_active())
					coreturn_void;

				uint64_t time = protocol::now().time.now_cpu();
				uint64_t timeout = std::max<uint64_t>(retry_after_timestamp != std::numeric_limits<uint64_t>::max() ? retry_after_timestamp - std::min(time, retry_after_timestamp) : protocol::now().user.superchain.polling_frequency, 2000);
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
				algorithm::pubkeyhash_t worst_account;
				hash_set<algorithm::pubkeyhash_t> current_nodes;
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
				hash_map<algorithm::pubkeyhash_t, socket_address> replacement_nodes;
				replacement_nodes.reserve(current_nodes.size());
				{
					auto mempool = storages::mempoolstate();
					for (auto& account : current_nodes)
					{
						auto better_node = mempool.get_better_node(account);
						if (better_node && current_nodes.find(better_node->second.public_key_hash) == current_nodes.end() && !connected_to_ip_address(better_node->first.address))
							replacement_nodes[account] = std::move(better_node->first.address);
					}
					try_unknown_nodes = replacement_nodes.empty() && !may_connect_to_node() && mempool.get_connectable_unknown_nodes_count().or_else(0) > 0;
				}
				for (auto& [account, address] : replacement_nodes)
					abort_node_by_account(account, "better node found");
				if (try_unknown_nodes)
					abort_node_by_account(worst_account, "trying unknown node instead");

				for (auto& [account, address] : replacement_nodes)
				{
					if (may_connect_to_node())
						coawait(connect_to_physical_node(address));
				}

				hash_set<uint256_t> passed_candidates;
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
						storages::mempoolstate().apply_cooldown_node(*candidate_address, true);
					passed_candidates.insert(ip_address);
				}

				size_t inputs = passed_candidates.size() + replacement_nodes.size();
				size_t outputs = replacement_nodes.size() + (try_unknown_nodes ? 1 : 0);
				if ((inputs > 0 || outputs > 0) && protocol::now().user.consensus.logging)
					VI_INFO("network topology optimization: OK (connections: +%i / -%i)", (int)inputs, (int)outputs);

				control_sys.upsert_timeout(TASK_BLOCK_DISPATCHER "_runner", protocol::now().policy.pow.time, [this]() { run_block_dispatcher(); });
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
				auto from = uref(best_fork->second.state);
				auto status = coawait(resolve_and_verify_fork(std::move(*best_fork)));
				if (!status && protocol::now().user.consensus.logging)
					VI_WARN("fork %s dismissed with %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), status.what().c_str());

				auto new_best_fork = get_best_fork_header();
				clear_pending_fork(*from);
				if (new_best_fork && new_best_fork->first != candidate_hash && best_fork->second.header < new_best_fork->second.header)
				{
					best_fork = std::move(new_best_fork);
					goto retry;
				}

				for (auto& [account, descriptor] : descriptors)
					fill_node_services(descriptor);

				run_block_production();
				coreturn_void;
			});
		}
		bool server_node::run_attestation_resolution()
		{
			return control_sys.task_if_none(TASK_ATTESTATION_RESOLUTION, [this](system_task&&)
			{
				size_t offset = 0, resolutions = 0;
				auto mempool = storages::mempoolstate();
				bool has_attestation = false;
				for (auto& [account, descriptor] : descriptors)
					has_attestation = has_attestation || descriptor.first.services.has_attestation;
			retry:
				auto attestation_hash = mempool.pull_best_attestation_hash(offset++);
				if (attestation_hash)
				{
					++resolutions;
					auto status = accept_attestation(*attestation_hash);
					if (status)
						goto retry;
					else if (protocol::now().user.consensus.logging)
						VI_INFO("attestation %s resolution delayed: ", algorithm::encoding::encode_0xhex256(*attestation_hash).c_str(), status.what().c_str());

					if (!has_attestation)
						goto retry;

					auto batch = mempool.get_attestation(*attestation_hash);
					if (!batch)
						goto retry;

					bool rebroadcasted = false;
					for (auto& [commitment_hash, commitments] : batch->commitments)
					{
						auto proof = batch->proofs.find(commitment_hash);
						if (proof == batch->proofs.end())
							continue;

						for (auto& commitment_signature : commitments)
						{
							algorithm::pubkeyhash_t attester;
							if (!algorithm::signing::recover_hash(commitment_hash, attester, commitment_signature) || !find_descriptor(attester))
								continue;

							size_t notifications = notify_all(descriptors::broadcast_attestation(), { format::variable(proof->second.as_message().data), format::variable(commitment_signature.view()) });
							if (notifications > 0 && protocol::now().user.consensus.logging)
								VI_DEBUG("attestation %s re-broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);

							rebroadcasted = true;
							break;
						}
						if (rebroadcasted)
							break;
					}
					goto retry;
				}
				if (resolutions > 0 && protocol::now().user.consensus.logging)
					VI_INFO("attestation resolution: %i pending", (int)resolutions);
			});
		}
		bool server_node::run_block_production()
		{
			bool has_production = false;
			for (auto& [account, descriptor] : descriptors)
				has_production = has_production || descriptor.first.services.has_production;
			if (!has_production || is_syncing())
				return false;

			if (prover.waiting)
			{
				control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
				prover.waiting = false;
			}

			return control_sys.task_if_none(TASK_BLOCK_PRODUCTION, [this](system_task&&)
			{
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
			next_block:
				if (!is_active() || (protocol::now().is(network_type::regtest) && !mempool.get_transactions_count().or_else(0)))
					return;

				auto tip = chain.get_latest_block_header();
				prover.solver = ledger::solver_context();
				prover.rewards.clear();
				prover.hashes.clear();

				auto priority = prover.solver.apply_validator_state(accounts, tip.address());
				auto position = priority.or_else(protocol::now().policy.production.max_per_block);
				if (position > 0 && tip)
				{
					auto current_solution_time = std::max<int64_t>(((int64_t)protocol::now().time.now() - (int64_t)tip->evaluation_time) - (int64_t)protocol::now().policy.pow.time * 2, 0);
					for (uint64_t i = 0; i <= position; i++)
					{
						auto other_node_solution_time = (int64_t)((double)protocol::now().policy.pow.time * algorithm::wesolowski::adjustment_scaling(i).to_double());
						if (current_solution_time >= other_node_solution_time)
							continue;

						prover.waiting = true;
						control_sys.upsert_timeout(TASK_BLOCK_PRODUCTION, (uint64_t)(other_node_solution_time - current_solution_time), [this]()
						{
							control_sys.clear_timeout(TASK_BLOCK_PRODUCTION);
							run_block_production();
						});
						return;
					}
				}

				auto span = (double)(tip ? tip->get_slot_proof_duration_average() : 0) * algorithm::wesolowski::adjustment_scaling(position).to_double();
				if (protocol::now().user.consensus.logging && position > 0)
					VI_WARN("block solver: performing %s (number: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%.2f sec.)", position < protocol::now().policy.production.max_per_block ? "leader fallback" : "network recovery", tip ? tip->number + 1 : 1, position + 1, span / 1000.0);

				auto evaluation = prover.solver.block_evalution_prepare(prover.solution);
				if (!evaluation)
					goto next_block;

				size_t iteration = 0, iteration_threshold = 16, count = 512;
				auto solution_account = prover.solver.state.public_key_hash;
				auto solution_challenge = ledger::block_header(prover.solution.block);
				auto solution_task = cotask<expects_lr<ledger::block_header>>([solution_challenge = std::move(solution_challenge), solution_account]() mutable -> expects_lr<ledger::block_header>
				{
					return solution_challenge.solve(solution_account) ? expects_lr<ledger::block_header>(std::move(solution_challenge)) : expects_lr<ledger::block_header>(layer_exception("failed to solve a block"));
				}, false);
				while (is_active() && solution_task.is_pending())
				{
					size_t offsets[2] = { 0, 0 }, queue = 0;
					while (prover.solver.can_accept_more_transactions() && (offsets[0] != std::numeric_limits<size_t>::max() || offsets[1] != std::numeric_limits<size_t>::max()))
					{
						auto results0 = mempool.get_best_transactions_from_queue(prover.solver.state.executor.options & (uint8_t)ledger::executor_context::flags::congestion ? (uint8_t)storages::transaction_queue::congestion : 0, offsets[0], count);
						auto results1 = mempool.get_best_transactions_from_queue((uint8_t)storages::transaction_queue::commitment, offsets[1], count);
						offsets[0] = count == (results0 ? results0->size() : 0) ? (results0 ? results0->size() : 0) : std::numeric_limits<size_t>::max();
						offsets[1] = count == (results1 ? results1->size() : 0) ? (results1 ? results1->size() : 0) : std::numeric_limits<size_t>::max();
						queue += prover.solver.try_include_transactions(std::move(*results0), &prover.hashes) + prover.solver.try_include_transactions(std::move(*results1), &prover.hashes);
					}

					++iteration;
					if (queue > 0)
					{
						evaluation = prover.solver.block_evalution_update(prover.solution, prover.rewards);
						if (!evaluation)
							break;
					}

					if (position > 0 && iteration % iteration_threshold == 0)
					{
						tip = chain.get_latest_block_header();
						if (ledger::solver_context().apply_validator_state(accounts, tip.address()).or_else(protocol::now().policy.production.max_per_block) == 0)
							break;
					}

					std::this_thread::sleep_for(std::chrono::microseconds(iteration < iteration_threshold ? 500 : 50000));
				}

				auto solution = !evaluation || solution_task.is_pending() ? expects_lr<ledger::block_header>(layer_exception("orphaned")) : solution_task.get();
				if (solution)
				{
					prover.solution.block.proof = std::move(solution->proof);
					prover.solution.block.evaluation_time = solution->evaluation_time;
				}

				tip = chain.get_latest_block_header();
				if (is_active() && solution && evaluation && (!tip || prover.solution.block.number > tip->number || (prover.solution.block.number == tip->number && prover.solution.block.priority < tip->priority)))
				{
					evaluation = prover.solver.block_evalution_finalize(prover.solution, prover.rewards);
					evaluation = evaluation ? prover.solver.block_solution_sign(prover.solution) : evaluation;
					auto verification = evaluation ? accept_block(nullptr, prover.solution, 0) : evaluation;
					if (evaluation && verification)
					{
						prover.solver.erase_failed_transactions().report("mempool cleanup failed");
						if (protocol::now().user.consensus.logging)
							VI_INFO("block %s solved (number: %" PRIu64", txns: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);

						goto next_block;
					}
					else if (protocol::now().user.consensus.logging)
					{
						if (!evaluation)
							VI_WARN("block %s dismissed: %s (number: %" PRIu64", txns: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
						else
							VI_WARN("%s", verification.error().what());
					}
				}
				else if (protocol::now().user.consensus.logging)
					VI_WARN("block %s dismissed: %s (number: %" PRIu64", txns: %" PRIu64 ", leader: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), evaluation ? (solution ? "cancelled" : solution.error().what()) : evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
			});
		}
		bool server_node::run_block_dispatcher()
		{
			if (is_syncing())
				return false;

			auto tip_number = storages::chainstate().get_latest_block_number().or_else(0);
			return control_sys.async_task_if_none(TASK_BLOCK_DISPATCHER, [this, tip_number]() -> promise<void>
			{
				auto dispatcher = dispatcher_context(this);
				coawait(dispatcher.dispatch_async(tip_number));

				auto& sendable_transactions = dispatcher.get_sendable_transactions();
				if (!sendable_transactions.empty())
				{
					for (auto& [runner_wallet, transaction] : sendable_transactions)
						accept_local_transaction(runner_wallet, std::move(transaction));
				}

				for (auto& [transaction_hash, error] : dispatcher.errors)
					VI_ERR("transaction %s dispatch failed: %s", algorithm::encoding::encode_0xhex256(transaction_hash).c_str(), error.c_str());

				auto status = dispatcher.checkpoint();
				if (protocol::now().user.consensus.logging && status && !dispatcher.inputs.empty())
					VI_INFO("block dispatch: OK (height: %" PRIu64", txns: %" PRIu64 ", delayed: %" PRIu64 ", dropped: %" PRIu64 ")", tip_number, dispatcher.inputs.size(), dispatcher.repeaters.size(), dispatcher.errors.size());
				else if (protocol::now().user.consensus.logging && !status)
					VI_ERR("block dispatch failed: %s (height: %" PRIu64 ")", status.what().c_str(), tip_number);

				umutex<std::recursive_mutex> unique(sync.fork);
				if (!witnesses.empty())
				{
					auto* offchain = superchain::bridge::get();
					for (auto& [asset, block_height] : witnesses)
					{
						auto earlist_block_height = offchain->get_earliest_scanned_block_height(asset);
						if (!earlist_block_height || *earlist_block_height > block_height)
							offchain->scan_from_block_height(asset, block_height);
					}
					witnesses.clear();
				}
				unique.unlock();
				run_block_production();
			});
		}
		void server_node::startup()
		{
			if (!protocol::now().user.consensus.server && !protocol::now().user.consensus.max_outbound_connections)
				return;

			socket_router* config = new socket_router();
			config->socket_timeout = (size_t)protocol::now().user.tcp.timeout;
			config->max_connections = protocol::now().user.consensus.max_inbound_connections;
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

			auto wallets = vector<ledger::wallet>();
			for (auto& seed : protocol::change().user.consensus.accounts)
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
			if (!protocol::now().user.known_nodes.empty())
			{
				auto mempool = storages::mempoolstate();
				for (auto& node : protocol::now().user.known_nodes)
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
					else if (protocol::now().user.consensus.logging)
						VI_ERR("pre-configured node \"%s\" error: url not valid", node.c_str());
				}
			}

			bind_event(descriptors::broadcast_block_hash(), std::bind(&server_node::broadcast_block_hash, this, std::placeholders::_2, std::placeholders::_3), true);
			bind_event(descriptors::broadcast_transaction_hash(), std::bind(&server_node::broadcast_transaction_hash, this, std::placeholders::_2, std::placeholders::_3), true);
			bind_event(descriptors::broadcast_attestation(), std::bind(&server_node::broadcast_attestation, this, std::placeholders::_2, std::placeholders::_3), true);
			bind_event(descriptors::broadcast_intermediary(), std::bind(&server_node::broadcast_intermediary, this, std::placeholders::_2, std::placeholders::_3), true);
			bind_event(descriptors::announce_neighbor(), std::bind(&server_node::announce_neighbor, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::perform_handshake(), std::bind(&server_node::perform_handshake, this, std::placeholders::_2, std::placeholders::_3, false));
			bind_query(descriptors::perform_discovery(), std::bind(&server_node::perform_discovery, this, std::placeholders::_2, std::placeholders::_3, false));
			bind_query(descriptors::fetch_headers(), std::bind(&server_node::fetch_headers, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_block(), std::bind(&server_node::fetch_block, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_blocks(), std::bind(&server_node::fetch_blocks, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_mempool(), std::bind(&server_node::fetch_mempool, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_transaction(), std::bind(&server_node::fetch_transaction, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::fetch_transactions(), std::bind(&server_node::fetch_transactions, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::distribute_entropy_shares(), std::bind(&server_node::distribute_entropy_shares, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_entropy_shares(), std::bind(&server_node::aggregate_entropy_shares, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::recover_entropy(), std::bind(&server_node::recover_entropy, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_public_key(), std::bind(&server_node::aggregate_public_key, this, std::placeholders::_2, std::placeholders::_3));
			bind_query(descriptors::aggregate_signature(), std::bind(&server_node::aggregate_signature, this, std::placeholders::_2, std::placeholders::_3));
			control_sys.interval_if_none(TASK_MEMPOOL_VACUUM "_runner", protocol::now().user.consensus.transaction_timeout, std::bind(&server_node::run_mempool_vacuum, this));
			control_sys.interval_if_none(TASK_TOPOLOGY_OPTIMIZATION "_runner", protocol::now().user.consensus.topology_timeout, std::bind(&server_node::run_topology_optimization, this));
			control_sys.interval_if_none(TASK_ATTESTATION_RESOLUTION "_runner", protocol::now().user.consensus.attestation_timeout, std::bind(&server_node::run_attestation_resolution, this));
			control_sys.interval_if_none(TASK_BLOCK_DISPATCH_RETRIAL "_runner", protocol::now().user.consensus.dispatch_retry_interval, std::bind(&server_node::run_block_dispatcher, this));
			run_topology_optimization();
			run_mempool_vacuum();

			if (protocol::now().user.superchain.listener)
			{
				auto* offchain = superchain::bridge::get();
				offchain->network_active = [this]() -> bool { return is_active(); };
				offchain->network_fetch = std::bind(&server_node::queued_fetch_external, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, std::placeholders::_4);
				transport_layer::link_instance();
				for (auto& [blockchain, listener] : offchain->get_networks())
					run_superchain_sync(listener.asset);
			}
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
		void server_node::clear_pending_neighbors()
		{
			umutex<std::recursive_mutex> unique(sync.neighbor);
			for (auto& [id, resolver] : neighbors)
				resolver(algorithm::pubkey_t(), 0);
			neighbors.clear();
		}
		void server_node::clear_pending_fork(relay* from)
		{
			umutex<std::recursive_mutex> unique(sync.fork);
			if (from)
			{
				for (auto it = forks.cbegin(); it != forks.cend();)
				{
					if (from == *it->second.state)
						it = forks.erase(it);
					else
						++it;
				}
			}
			else
				forks.clear();
		}
		void server_node::accept_pending_fork(uref<relay>&& from, const uint256_t& candidate_hash, ledger::block_header&& candidate_block)
		{
			if (!from || !candidate_hash || !is_active())
				return;

			umutex<std::recursive_mutex> unique(sync.fork);
		retry:
			for (auto& fork_candidate_tip : forks)
			{
				if (*fork_candidate_tip.second.state == *from)
				{
					forks.erase(fork_candidate_tip.first);
					goto retry;
				}
			}
			auto& fork = forks[candidate_hash];
			fork.header = candidate_block;
			fork.state = from;
			prover.dirty = true;
		}
		expects_lr<void> server_node::accept_block(uref<relay>&& from, ledger::block_evaluation& candidate, const uint256_t& fork_tip)
		{
			uint256_t candidate_hash = candidate.block.as_hash();
			auto chain = storages::chainstate();
			if (chain.get_block_header_by_hash(candidate_hash))
				return expectation::met;

			bool fork_branch = fork_tip > 0;
			auto fork_tip_block = ledger::block_header();
			if (fork_branch)
			{
				umutex<std::recursive_mutex> unique(sync.fork);
				auto it = forks.find(fork_tip);
				if (it != forks.end())
					fork_tip_block = it->second.header;
			}

			auto tip_block = fork_branch ? expects_lr<ledger::block_header>(fork_tip_block) : chain.get_latest_block_header();
			auto tip_hash = tip_block ? tip_block->as_hash() : (uint256_t)0;
			auto best_tip_work = tip_block ? tip_block->absolute_work : (uint256_t)0;
			auto parent_block = tip_hash == candidate.block.parent_hash ? tip_block : chain.get_block_header_by_hash(candidate.block.parent_hash);
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
				return layer_exception(stringify::text("block %s rejected: inferior fork %s (length: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), branch_length < 0 ? "branch" : "work", branch_length));
			}
			else if (branch_length == 0 && tip_block && tip_hash != candidate_hash && candidate.block < *tip_block)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				return layer_exception(stringify::text("block %s rejected: inferior fork difficulty", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));
			}
			else if (!parent_block && candidate.block.number > 1)
			{
				auto verification = from ? candidate.block.verify_validity(parent_block.address()) : expects_lr<void>(layer_exception("unexpected orphan"));
				if (!verification)
					return layer_exception(stringify::text("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), verification.error().what()));

				umutex<std::recursive_mutex> unique(sync.fork);
				if (forks.find(candidate_hash) != forks.end())
					return expectation::met;

				/*
															   <+> = better orphan (possibly)
															  /
					<+> - <+> - <+> - <+> - <+> - <+> ------------
														  \
														   <+> = weaker orphan
				*/
				bool better_than_prev_fork = forks.empty();
				for (auto& fork_candidate_tip : forks)
				{
					if (fork_candidate_tip.second.header < candidate.block)
					{
						better_than_prev_fork = true;
						break;
					}
				}
				if (!better_than_prev_fork)
					return layer_exception(stringify::text("block %s rejected: inferior fork orphan", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));

				/*
					<+> - <+> - <+> - <+> - <+> - <+> ----
														  \
														   <+> = better orphan (possibly)
				*/
				accept_pending_fork(uref(from), candidate_hash, ledger::block_header(candidate.block));
				run_fork_resolution();
				if (protocol::now().user.consensus.logging)
					VI_INFO("block %s new best found (height: %" PRIu64 ", distance: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), candidate.block.number, std::abs((int64_t)(tip_block ? tip_block->number : 0) - (int64_t)candidate.block.number));
				return expectation::met;
			}

			/*
				<+> - <+> - <+> - <+> - <+> - <+> = possible extension
											\
											<+> - <+> = possible reorganization
			*/
			auto reorganization = ledger::solver_context::requires_reorganization(candidate);
			auto validation = fork_branch && reorganization ? expects_lr<void>(expectation::met) : ledger::solver_context::validate_solved_block(parent_block.address(), candidate.block, &candidate);
			if (!validation)
				return layer_exception(stringify::text("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), validation.error().what()));
			else if (reorganization && !protocol::now().user.consensus.reorganizable)
				return layer_exception(stringify::text("block %s rejected: requires deep chain reorganization (disabled)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));

			bool chain_extension = !fork_tip;
			if (!try_acquire_checkpointer())
				return layer_exception(stringify::text("block %s checkpoint failed: checkpointer busy", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));
			else if (chain_extension)
				append_pending_block(uref(from), candidate_hash, &candidate.block);

			auto mutation = ledger::solver_context::checkpoint_solved_block(candidate);
			release_checkpointer();
			if (chain_extension)
				erase_pending_block(candidate_hash);

			if (!mutation)
				return layer_exception(stringify::text("block %s checkpoint failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation.error().what()));

			if (protocol::now().user.consensus.logging)
			{
				if (mutation->is_fork)
				{
					VI_INFO("block %s reorganized (height: %" PRIu64 ", sync: %.2f%%, size: ~%.2f kb, length: %" PRIi64 ", txns: %" PRIi64 " / %" PRIi64 ", states: %" PRIi64 ")\n",
						algorithm::encoding::encode_0xhex256(candidate_hash).c_str(),
						candidate.block.number,
						100.0 * get_sync_progress(candidate.block.number, *from),
						(double)(uint64_t)candidate.block.gas_limit / ((double)ledger::gas_cost::write_byte * 1024.0),
						mutation->block_delta,
						mutation->transaction_delta,
						mutation->mempool_transactions,
						mutation->state_delta);
				}
				else
				{
					VI_INFO("block %s finalized (height: %" PRIu64 ", sync: %.2f%%, size: ~%.2f kb)",
						algorithm::encoding::encode_0xhex256(candidate_hash).c_str(),
						candidate.block.number,
						100.0 * get_sync_progress(candidate.block.number, *from),
						(double)(uint64_t)candidate.block.gas_limit / ((double)ledger::gas_cost::write_byte * 1024.0));
				}
			}

			if (events.accept_block)
				events.accept_block(candidate_hash, candidate.block, *mutation);

			for (auto& transaction : candidate.block.transactions)
			{
				if (find_descriptor(transaction.receipt.from))
					accept_proposal_transaction(transaction);
			}

			umutex<std::recursive_mutex> unique(sync.fork);
			for (auto& [asset, block_height] : candidate.block.witnesses)
			{
				auto it = witnesses.find(asset);
				if (it != witnesses.end())
					it->second = std::min(it->second, block_height);
				else
					witnesses[asset] = block_height;
			}

			unique.unlock();
			if (chain_extension)
				finalize_pending_block(std::move(from));
			return expectation::met;
		}
		void server_node::append_pending_block(uref<relay>&& from, const uint256_t& block_hash, ledger::block_body* tip)
		{
			VI_ASSERT(tip != nullptr, "tip should be set");
			uint64_t block_number = tip->number;
			umutex<std::recursive_mutex> unique(sync.tip);
			pending_blocks[block_hash] = tip;
			unique.unlock();
			broadcast_pending_block(std::move(from), block_hash, block_number);
		}
		void server_node::erase_pending_block(const uint256_t& block_hash)
		{
			umutex<std::recursive_mutex> unique(sync.tip);
			pending_blocks.erase(block_hash);
		}
		void server_node::broadcast_pending_block(uref<relay>&& from, const uint256_t& block_hash, uint64_t block_number)
		{
			if (!block_hash || !block_number)
				return;

			size_t notifications = notify_all_except(uref(from), descriptors::broadcast_block_hash(), { format::variable(block_hash) });
			if (notifications > 0 && protocol::now().user.consensus.logging)
				VI_DEBUG("block %s broadcasted to %i nodes (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(block_hash).c_str(), (int)notifications, block_number);
		}
		void server_node::finalize_pending_block(uref<relay>&& from)
		{
			control_sys.upsert_timeout(TASK_BLOCK_DISPATCHER "_runner", protocol::now().policy.pow.time, [this]() { run_block_dispatcher(); });
			if (!from || !prover.dirty)
				return;

			prover.dirty = false;
			synchronize_mempool_with(std::move(from));
		}
		bool server_node::accept_proposal_transaction(const ledger::block_transaction& transaction)
		{
			uint32_t type = transaction.transaction->as_type();
			auto purpose = transaction.transaction->as_typename();
			if (type == transactions::setup::as_instance_type())
			{
				if (transaction.receipt.successful)
				{
					if (protocol::now().user.consensus.logging)
						VI_DEBUG("transaction %s finalized (type: %.*s)", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
					for (auto& [account, descriptor] : descriptors)
						fill_node_services(descriptor);
					run_block_production();
				}
				else if (protocol::now().user.consensus.logging)
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			else if (protocol::now().user.consensus.logging)
			{
				if (transaction.receipt.successful)
					VI_DEBUG("transaction %s finalized (type: %.*s)", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				else
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			return true;
		}
		void server_node::fill_node_services(relay_descriptor& descriptor)
		{
			auto& [node, wallet] = descriptor;
			auto executor = ledger::executor_context(nullptr);
			node.services.has_production = protocol::now().user.consensus.miner ? executor.get_validator_production(wallet.public_key_hash).or_else(states::validator_production(algorithm::pubkeyhash_t(), nullptr)).is_active() : false;
			node.services.has_participation = executor.get_validator_participation(wallet.public_key_hash).or_else(states::validator_participation(algorithm::pubkeyhash_t(), nullptr)).is_active();
			node.services.has_attestation = false;
			if (protocol::now().user.consensus.miner && !node.services.has_production)
				node.services.has_production = executor.calculate_producers_size().or_else(0) == 0;

			size_t count = 64;
			size_t offset = 0;
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
		void server_node::fill_node_neighbors(relay_descriptor& descriptor)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			descriptor.first.availability.neighbors.clear();
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr)
					descriptor.first.availability.neighbors.insert(peer_descriptor->second.public_key);
			}
			for (auto& [subaccount, subdescriptor] : descriptors)
			{
				auto& [node, wallet] = subdescriptor;
				if (wallet.public_key_hash != descriptor.second.public_key_hash)
					descriptor.first.availability.neighbors.insert(wallet.public_key);
			}
		}
		bool server_node::is_active()
		{
			return state == server_state::working && control_sys.is_active();
		}
		bool server_node::is_syncing()
		{
			umutex<std::recursive_mutex> unique(sync.fork);
			return !forks.empty();
		}
		double server_node::get_sync_progress(uint64_t current_number)
		{
			auto best = get_best_fork_header();
			if (best)
				return (current_number <= best->second.header.number ? (double)current_number / (double)best->second.header.number : 1.0);

			return 1.0;
		}
		double server_node::get_sync_progress(uint64_t current_number, relay* from)
		{
			if (!from || !current_number)
				return 1.0;

			umutex<std::recursive_mutex> unique(sync.fork);
			for (auto& fork_candidate_tip : forks)
			{
				if (*fork_candidate_tip.second.state == from)
					return (current_number <= fork_candidate_tip.second.header.number ? (double)current_number / (double)fork_candidate_tip.second.header.number : 1.0);
			}

			return 1.0;
		}
		const hash_map<void*, uref<relay>>& server_node::get_nodes() const
		{
			return nodes;
		}
		option<std::pair<uint256_t, server_node::fork_header>> server_node::get_best_fork_header()
		{
			umutex<std::recursive_mutex> unique(sync.fork);
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
		dispatcher_context server_node::get_dispatcher() const
		{
			return dispatcher_context((server_node*)this);
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
				if (*listener->address.get_ip_address() == *ip_address)
					return true;
			}

			for (auto& [account, descriptor] : descriptors)
			{
				auto& [node, wallet] = descriptor;
				if (*node.address.get_ip_address() == *ip_address)
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
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr && peer_descriptor->second.public_key_hash.equals(account))
					return node.second;
			}

			return nullptr;
		}
		uref<relay> server_node::find_with_neighbor_account(const algorithm::pubkeyhash_t& account)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr)
				{
					for (auto& public_key : peer_descriptor->first.availability.neighbors)
					{
						if (public_key == peer_descriptor->second.public_key)
							continue;

						algorithm::pubkeyhash_t neighbor;
						algorithm::signing::derive_public_key_hash(public_key, neighbor);
						if (neighbor == account && !find_descriptor(neighbor))
							return node.second;
					}
				}
			}

			return nullptr;
		}
		option<algorithm::pubkey_t> server_node::find_public_key(const algorithm::pubkeyhash_t& account)
		{
			auto* descriptor = find_descriptor(account);
			if (descriptor != nullptr)
				return descriptor->second.public_key;

			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				auto* peer_descriptor = node.second->as_descriptor();
				if (peer_descriptor != nullptr)
				{
					if (peer_descriptor->second.public_key_hash == account)
						return peer_descriptor->second.public_key;

					for (auto& public_key : peer_descriptor->first.availability.neighbors)
					{
						algorithm::pubkeyhash_t public_key_hash;
						algorithm::signing::derive_public_key_hash(public_key, public_key_hash);
						if (public_key_hash == account)
							return public_key;
					}
				}
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

		dispatcher_context::dispatcher_context(server_node* new_server) : server(new_server)
		{
			VI_ASSERT(server != nullptr, "server should be set");
		}
		dispatcher_context::dispatcher_context(const dispatcher_context& other) noexcept : ledger::dispatcher_context(other), server(other.server)
		{
		}
		dispatcher_context& dispatcher_context::operator=(const dispatcher_context& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::dispatcher_context*)this;
			auto& base_other = *(const ledger::dispatcher_context*)&other;
			base_this = base_other;
			server = other.server;
			return *this;
		}
		algorithm::pubkey_t dispatcher_context::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto target = server->find_public_key(validator);
			if (!target)
				return algorithm::pubkey_t();

			return *target;
		}
		const ledger::wallet* dispatcher_context::get_runner_wallet(const algorithm::pubkeyhash_t& validator) const
		{
			auto* result = server->find_descriptor(validator);
			return result ? &result->second : nullptr;
		}
		expects_promise_rt<void> dispatcher_context::aggregate_validators(const btree_set<algorithm::pubkeyhash_t>& validators)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("logical connection: connect to %i validators", (int)validators.size());

			hash_set<algorithm::pubkeyhash_t> required_accounts;
			required_accounts.reserve(validators.size());
			required_accounts.insert(validators.begin(), validators.end());
			return server->connect_to_logical_nodes(std::move(required_accounts)).then<expects_rt<void>>([](expects_rt<hash_set<algorithm::pubkeyhash_t>>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("logical connection: %i validators connected", (int)result->size());
					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_ERR("logical connection failed: %s", result.what().c_str());
					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::distribute_entropy_shares(const ledger::executor_context* executor, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("mpc entropy shares distribution: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return distribute_entropy_shares_internal(executor, state, validator).then<expects_rt<void>>([&state, validator](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy shares distribution: OK (to: %s, shares: %i)", algorithm::signing::encode_address(validator).c_str(), (int)state.encrypted_shares.size());

					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy shares distribution failed: %s (to: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::distribute_entropy_shares_internal(const ledger::executor_context* executor, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (runner_wallet != nullptr)
				return local_dispatcher_context::distribute_entropy_shares(this, executor, runner_wallet, state.encrypted_shares);

			auto public_key = server->find_public_key(validator);
			if (!public_key)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, &state, validator, public_key = std::move(public_key)]() mutable -> expects_promise_rt<void>
			{
				uint64_t attempt = 0;
				auto args = pack_private_result({ format::variable(executor->receipt.block_number), format::variable(executor->receipt.transaction_hash), format::variable(state.as_message().data) }, *public_key);
				if (!args)
					coreturn args.error();
			retry:
				auto event = coawait(server->indirect_query(validator, descriptors::distribute_entropy_shares(), format::variables(*args), protocol::now().user.consensus.response_timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				args = unpack_private_result(event->args, server->runner_descriptor->second.secret_key);
				if (!args)
					coreturn args.error();

				if (args->size() != 1 || args->front().as_uint8() != (uint8_t)state.encrypted_shares.size())
					coreturn remote_exception("encrypted shares distribution confirmation not received");

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_entropy_shares(const ledger::executor_context* executor, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("mpc entropy shares aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return aggregate_entropy_shares_internal(executor, state, validator).then<expects_rt<void>>([&state, validator](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy shares aggregation: OK (to: %s, shares: %i)", algorithm::signing::encode_address(validator).c_str(), (int)state.encrypted_shares.size());

					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy shares aggregation failed: %s (to: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_entropy_shares_internal(const ledger::executor_context* executor, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (runner_wallet != nullptr)
				return local_dispatcher_context::aggregate_entropy_shares(this, executor, runner_wallet, state.public_key, state.encrypted_shares);

			auto public_key = server->find_public_key(validator);
			if (!public_key)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, &state, validator, public_key = std::move(public_key)]() mutable -> expects_promise_rt<void>
			{
				uint64_t attempt = 0;
				auto args = pack_private_result({ format::variable(executor->receipt.block_number), format::variable(executor->receipt.transaction_hash), format::variable(state.as_message().data) }, *public_key);
				if (!args)
					coreturn args.error();
			retry:
				auto event = coawait(server->indirect_query(validator, descriptors::aggregate_entropy_shares(), format::variables(*args), protocol::now().user.consensus.response_timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				args = unpack_private_result(event->args, server->runner_descriptor->second.secret_key);
				if (!args)
					coreturn args.error();

				auto message = format::ro_stream(args->front().as_string());
				for (uint16_t i = 0; i < state.encrypted_shares.size(); i++)
				{
					uint256_t ref_hash;
					if (!message.read_integer(message.read_type(), &ref_hash))
						coreturn remote_exception("invalid encrypted share ref hash");

					uint16_t encrypted_values_size;
					if (!message.read_integer(message.read_type(), &encrypted_values_size))
						coreturn remote_exception("invalid encrypted share values size");

					auto encrypted_values = state.encrypted_shares.find(ref_hash);
					if (encrypted_values == state.encrypted_shares.end())
						coreturn remote_exception("ref hash not found in provided encrypted shares");

					for (uint16_t j = 0; j < encrypted_values_size; j++)
					{
						algorithm::pubkeyhash_t item; string intermediate;
						if (!message.read_string(message.read_type(), &intermediate) || !algorithm::encoding::decode_bytes(intermediate, item.blob, sizeof(item)))
							coreturn remote_exception("invalid encrypted share value participant");

						string encrypted_value;
						if (!message.read_string(message.read_type(), &encrypted_value))
							coreturn remote_exception("invalid encrypted share value data");

						encrypted_values->second[item] = std::move(encrypted_value);
					}
				}

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatcher_context::recover_entropy(const ledger::executor_context* executor, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("mpc entropy recovery: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return recover_entropy_internal(executor, state, validator).then<expects_rt<void>>([&state, validator](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy recovery: OK (to: %s, entropies: %i, shares: %i)", algorithm::signing::encode_address(validator).c_str(), (int)state.encrypted_entropies.size(), (int)state.encrypted_shares.size());

					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc entropy recovery failed: %s (to: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::recover_entropy_internal(const ledger::executor_context* executor, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (runner_wallet != nullptr)
				return local_dispatcher_context::recover_entropy(this, executor, runner_wallet, state.proof, state.encrypted_shares, state.encrypted_entropies);

			auto public_key = server->find_public_key(validator);
			if (!public_key)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, &state, validator, public_key = std::move(public_key)]() mutable -> expects_promise_rt<void>
			{
				uint64_t attempt = 0;
				auto args = pack_private_result({ format::variable(executor->receipt.block_number), format::variable(executor->receipt.transaction_hash), format::variable(state.as_message().data) }, *public_key);
				if (!args)
					coreturn args.error();
			retry:
				auto event = coawait(server->indirect_query(validator, descriptors::aggregate_signature(), format::variables(*args), protocol::now().user.consensus.response_timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				args = unpack_private_result(event->args, server->runner_descriptor->second.secret_key);
				if (!args)
					coreturn args.error();

				if (args->size() != 1)
					coreturn remote_exception("encrypted shares recovery confirmation not received");

				state.proof = algorithm::hashsig_t(args->front().as_string());
				if (state.proof.empty())
					coreturn remote_exception("group secret recovery confirmation failed");

				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_public_key(const ledger::executor_context* executor, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("mpc public key aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return aggregate_public_key_internal(executor, state, validator).then<expects_rt<void>>([&state, validator](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc public key aggregation: OK (to: %s, shares: %i, stack: %i)", algorithm::signing::encode_address(validator).c_str(), (int)state.encrypted_shares.size(), state.compositor ? (int)state.compositor->steps_left() : 0);

					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc public key aggregation failed: %s (to: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_public_key_internal(const ledger::executor_context* executor, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (runner_wallet != nullptr)
			{
				auto list = local_dispatcher_context::new_encrypted_distribution_shares(runner_wallet->public_key, state);
				auto status = local_dispatcher_context::aggregate_public_key(this, executor, runner_wallet, list, *state.compositor);
				if (status)
					local_dispatcher_context::apply_encrypted_distribution_shares(state, validator, list);
				return status;
			}

			auto public_key = server->find_public_key(validator);
			if (!public_key)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, &state, validator, public_key = std::move(public_key)]() mutable -> expects_promise_rt<void>
			{
				format::wo_stream writer;
				if (!algorithm::composition::store_compositor(state.alg, *state.compositor, &writer))
					coreturn remote_exception("out state machine not valid");

				auto list = local_dispatcher_context::new_encrypted_distribution_shares(*public_key, state);
				writer.write_integer((uint8_t)list.size());
				for (auto& [target_public_key, encrypted_share] : list)
					writer.write_string(target_public_key.optimized_view());

				uint64_t attempt = 0;
				auto args = pack_private_result({ format::variable(executor->receipt.block_number), format::variable(executor->receipt.transaction_hash), format::variable(writer.data) }, *public_key);
				if (!args)
					coreturn args.error();
			retry:
				auto event = coawait(server->indirect_query(validator, descriptors::aggregate_public_key(), format::variables(*args), protocol::now().user.consensus.response_timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				args = unpack_private_result(event->args, server->runner_descriptor->second.secret_key);
				if (!args)
					coreturn args.error();

				auto message = format::ro_stream(args->front().as_string());
				if (!state.load_compositor_transition(message))
					coreturn remote_exception("compositor transition failed (possible attack)");

				auto encrypted_share_public_key = list.begin();
				for (size_t i = 0; i < list.size(); i++)
				{
					string encrypted_share;
					if (!message.read_string(message.read_type(), &encrypted_share))
						coreturn remote_exception("encrypted share aggregation failed (possible attack)");

					encrypted_share_public_key->second = std::move(encrypted_share);
					++encrypted_share_public_key;
				}

				local_dispatcher_context::apply_encrypted_distribution_shares(state, validator, list);
				coreturn expectation::met;
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_signature(const ledger::executor_context* executor, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("mpc signature aggregation: inquiry to %s", algorithm::signing::encode_address(validator).c_str());

			return aggregate_signature_internal(executor, state, validator).then<expects_rt<void>>([&state, validator](expects_rt<void>&& result) mutable -> expects_rt<void>
			{
				if (result)
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc signature aggregation: OK (to: %s, stack: %i)", algorithm::signing::encode_address(validator).c_str(), state.compositor ? (int)state.compositor->steps_left() : 0);

					return expectation::met;
				}
				else
				{
					if (protocol::now().user.consensus.logging)
						VI_INFO("mpc signature aggregation failed: %s (to: %s)", result.what().c_str(), algorithm::signing::encode_address(validator).c_str());

					return result.error();
				}
			});
		}
		expects_promise_rt<void> dispatcher_context::aggregate_signature_internal(const ledger::executor_context* executor, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (runner_wallet != nullptr)
				return local_dispatcher_context::aggregate_signature(this, executor, runner_wallet, **state.message, *state.compositor);

			auto public_key = server->find_public_key(validator);
			if (!public_key)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return coasync<expects_rt<void>>([this, executor, &state, validator, public_key = std::move(public_key)]() mutable -> expects_promise_rt<void>
			{
				format::wo_stream writer;
				if (!algorithm::composition::store_compositor(state.alg, *state.compositor, &writer))
					coreturn remote_exception("out state machine not valid");

				uint64_t attempt = 0;
				auto args = pack_private_result({ format::variable(executor->receipt.block_number), format::variable(executor->receipt.transaction_hash), format::variable(state.message->as_message().data), format::variable(writer.data) }, *public_key);
				if (!args)
					coreturn args.error();
			retry:
				auto event = coawait(server->indirect_query(validator, descriptors::aggregate_signature(), format::variables(*args), protocol::now().user.consensus.response_timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				args = unpack_private_result(event->args, server->runner_descriptor->second.secret_key);
				if (!args)
					coreturn args.error();

				auto message = format::ro_stream(args->front().as_string());
				if (!state.load_compositor_transition(message))
					coreturn remote_exception("compositor transition failed (possible attack)");

				coreturn expectation::met;
			});
		}

		local_dispatcher_context::local_dispatcher_context(const vector<ledger::wallet>& new_validators)
		{
			for (auto& target : new_validators)
				validators[algorithm::pubkeyhash_t(target.public_key_hash)] = target;
		}
		local_dispatcher_context::local_dispatcher_context(const local_dispatcher_context& other) noexcept : ledger::dispatcher_context(other), validators(other.validators)
		{
		}
		local_dispatcher_context& local_dispatcher_context::operator=(const local_dispatcher_context& other) noexcept
		{
			if (this == &other)
				return *this;

			auto& base_this = *(ledger::dispatcher_context*)this;
			auto& base_other = *(const ledger::dispatcher_context*)&other;
			base_this = base_other;
			validators = other.validators;
			return *this;
		}
		algorithm::pubkey_t local_dispatcher_context::get_public_key(const algorithm::pubkeyhash_t& validator) const
		{
			auto it = validators.find(validator);
			return it != validators.end() ? it->second.public_key : algorithm::pubkey_t();
		}
		const ledger::wallet* local_dispatcher_context::get_runner_wallet(const algorithm::pubkeyhash_t& validator) const
		{
			auto it = validators.find(validator);
			return it != validators.end() ? &it->second : nullptr;
		}
		expects_promise_rt<void> local_dispatcher_context::aggregate_validators(const btree_set<algorithm::pubkeyhash_t>&)
		{
			return expects_promise_rt<void>(expectation::met);
		}
		expects_promise_rt<void> local_dispatcher_context::distribute_entropy_shares(const ledger::executor_context* executor, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (!runner_wallet)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return distribute_entropy_shares(this, executor, runner_wallet, state.encrypted_shares);
		}
		expects_rt<void> local_dispatcher_context::distribute_entropy_shares(ledger::dispatcher_context* dispatcher, const ledger::executor_context* executor, const ledger::wallet* runner_wallet, const btree_map<algorithm::pubkeyhash_t, string>& encrypted_shares)
		{
			auto* route = (transactions::route*)executor->transaction;
			if (!route)
				return remote_exception("invalid transaction");

			auto secret = dispatcher->recover_secret_entropy(runner_wallet, executor->receipt.from, route->asset, route->bridge_hash);
			if (!secret)
				return remote_exception(std::move(secret.error().message()));

			for (auto& [participant, encrypted_share] : encrypted_shares)
			{
				algorithm::seckey_t tweak, tweaked_secret_key = runner_wallet->secret_key;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
					return remote_exception("invalid tweaked secret key");

				auto decrypted_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_share);
				if (!decrypted_share || decrypted_share->size() > sizeof(algorithm::share_t))
					return remote_exception("group share decryption failed");

				secret->shares[participant].input = algorithm::share_t(*decrypted_share);
			}

			secret = dispatcher->apply_secret_entropy(runner_wallet, secret->owner, secret->asset, secret->hash, secret->entropy, std::move(secret->shares));
			if (!secret)
				return remote_exception(std::move(secret.error().message()));

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatcher_context::aggregate_entropy_shares(const ledger::executor_context* executor, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (!runner_wallet)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return aggregate_entropy_shares(this, executor, runner_wallet, state.public_key, state.encrypted_shares);
		}
		expects_rt<void> local_dispatcher_context::aggregate_entropy_shares(ledger::dispatcher_context* dispatcher, const ledger::executor_context* executor, const ledger::wallet* runner_wallet, const algorithm::pubkey_t& public_key, btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>>& encrypted_shares)
		{
			auto* setup = (transactions::setup*)executor->transaction;
			if (!setup)
				return remote_exception("invalid transaction");

			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant.empty())
				return remote_exception("new participant not found");

			algorithm::pubkeyhash_t public_key_check;
			algorithm::signing::derive_public_key_hash(public_key, public_key_check);
			if (new_participant != public_key_check)
				return remote_exception("public key does not match new participant");

			if (runner_wallet->public_key_hash == new_participant)
				return remote_exception("participant operation mismatch");

			auto tweaked_public_key = public_key;
			algorithm::seckey_t tweak;
			algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
			if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
				return remote_exception("invalid tweaked public key");

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return remote_exception(std::move(migrations.error().message()));

			for (auto& migration : *migrations)
			{
				if (migration.must_have_locally)
					continue;

				auto secret = dispatcher->recover_secret_entropy(runner_wallet, migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
				if (!secret)
					return remote_exception(std::move(secret.error().message()));

				auto ref_hash = secret->as_ref_hash(); bool must_update = false;
				for (auto& [broadcast_hash, participant] : setup->migrations)
				{
					if (migration.account.group.find(participant) == migration.account.group.end())
						continue;

					auto share = secret->shares.find(participant);
					if (share == secret->shares.end())
						return remote_exception("participant share not found");

					auto input_result = algorithm::signing::public_encrypt(tweaked_public_key, share->second.input.view(), algorithm::hashing::hash256i(*crypto::random_bytes(64)));
					auto output_result = algorithm::signing::public_encrypt(tweaked_public_key, share->second.output.view(), algorithm::hashing::hash256i(*crypto::random_bytes(64)));
					if (!input_result || !output_result)
						return remote_exception("participant share encryption failed");

					format::wo_stream message;
					message.write_string(*input_result);
					message.write_string(*output_result);
					encrypted_shares[ref_hash][runner_wallet->public_key_hash] = std::move(message.data);
					secret->shares[new_participant] = share->second;
					must_update = true;
				}

				if (must_update)
					secret = dispatcher->apply_secret_entropy(runner_wallet, secret->owner, secret->asset, secret->hash, secret->entropy, std::move(secret->shares));

				if (!secret)
					return remote_exception(std::move(secret.error().message()));
			}

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatcher_context::recover_entropy(const ledger::executor_context* executor, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (!runner_wallet)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return recover_entropy(this, executor, runner_wallet, state.proof, state.encrypted_shares, state.encrypted_entropies);
		}
		expects_rt<void> local_dispatcher_context::recover_entropy(ledger::dispatcher_context* dispatcher, const ledger::executor_context* executor, const ledger::wallet* runner_wallet, algorithm::hashsig_t& proof, const btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>>& encrypted_shares, const btree_map<uint256_t, string>& encrypted_entropies)
		{
			auto* setup = (transactions::setup*)executor->transaction;
			if (!setup)
				return remote_exception("invalid transaction");

			auto new_participant = setup->get_new_participant(executor->receipt);
			if (new_participant.empty())
				return remote_exception("new participant not found");

			if (runner_wallet->public_key_hash != new_participant)
				return remote_exception("participant operation mismatch");

			algorithm::seckey_t tweak, tweaked_secret_key = runner_wallet->secret_key;
			algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
			if (!algorithm::signing::scalar_add_secret_key(tweaked_secret_key, tweak))
				return remote_exception("invalid tweaked secret key");

			auto migrations = setup->get_migration_refs(executor, executor->receipt);
			if (!migrations)
				return remote_exception(std::move(migrations.error().message()));

			btree_map<uint256_t, states::bridge_account*> share_refs, entropy_refs;
			for (auto& migration : *migrations)
			{
				auto ref_hash = secret_entropy::ref_hash(migration.account.ref.owner, migration.account.ref.asset, migration.account.ref.hash);
				if (migration.must_have_locally)
					entropy_refs[ref_hash] = &migration.account;
				else
					share_refs[ref_hash] = &migration.account;
			}

			for (auto& [ref_hash, mapped_encrypted_shares] : encrypted_shares)
			{
				auto ref = share_refs.find(ref_hash);
				if (ref == share_refs.end())
					return remote_exception("share migration not permitted");

				btree_map<algorithm::pubkeyhash_t, secret_entropy::share_pair> mapped_shares;
				for (auto& [participant, encrypted_share] : mapped_encrypted_shares)
				{
					string encrypted_input_share, encrypted_output_share;
					format::ro_stream message = format::ro_stream(encrypted_share);
					if (!message.read_string(message.read_type(), &encrypted_input_share) || encrypted_input_share.empty())
						return remote_exception("encrypted input share not found");

					if (!message.read_string(message.read_type(), &encrypted_output_share) || encrypted_output_share.empty())
						return remote_exception("encrypted output share not found");

					auto decrypted_input_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_input_share);
					auto decrypted_output_share = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_output_share);
					if (!decrypted_input_share || !decrypted_output_share || decrypted_input_share->empty() || decrypted_input_share->size() > sizeof(algorithm::share_t) || decrypted_input_share->empty() || decrypted_input_share->size() > sizeof(algorithm::share_t))
						return remote_exception("input/output share decryption failed");

					auto& pair = mapped_shares[participant];
					pair.input = algorithm::share_t(*decrypted_input_share);
					pair.output = algorithm::share_t(*decrypted_output_share);
				}

				if (mapped_shares.size() < algorithm::signing::recovery_threshold(ref->second->group.size() - 1))
					return remote_exception("entropy recovery threshold not met");

				btree_set<algorithm::share_t> shares;
				for (auto& [participant, pair] : mapped_shares)
					shares.insert(pair.input);

				algorithm::storage_type<uint8_t, 64> entropy;
				if (!algorithm::signing::combine_shares_into_secret(shares, entropy.blob))
					return remote_exception("entropy recovery failed");

				auto status = dispatcher->apply_secret_entropy(runner_wallet, ref->second->ref.owner, ref->second->ref.asset, ref->second->ref.hash, entropy, std::move(mapped_shares));
				if (!status)
					return remote_exception(std::move(status.error().message()));
			}

			for (auto& [ref_hash, encrypted_entropy] : encrypted_entropies)
			{
				auto ref = entropy_refs.find(ref_hash);
				if (ref == entropy_refs.end())
					return remote_exception("entropy migration not permitted");

				auto decrypted_entropy = algorithm::signing::private_decrypt(tweaked_secret_key, encrypted_entropy);
				if (!decrypted_entropy)
					return remote_exception("entropy decryption failed");

				auto message = format::ro_stream(*decrypted_entropy);
				secret_entropy secret;
				if (!secret.load(message))
					return remote_exception("entropy deserialization failed");

				if (secret.owner != ref->second->ref.owner || secret.asset != ref->second->ref.asset || secret.hash != ref->second->ref.hash || secret.shares.size() < ref->second->group.size() - 1)
					return remote_exception("invalid entropy metadata");

				auto status = dispatcher->apply_secret_entropy(runner_wallet, secret.owner, secret.asset, secret.hash, secret.entropy, std::move(secret.shares));
				if (!status)
					return remote_exception(std::move(status.error().message()));
			}

			uint8_t transaction_hash_data[32];
			executor->receipt.transaction_hash.encode(transaction_hash_data);

			auto proof_hash = algorithm::hashing::hash256i(transaction_hash_data, sizeof(transaction_hash_data));
			if (!algorithm::signing::sign(proof_hash, runner_wallet->secret_key, proof))
				return remote_exception("confirmation proving error");

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatcher_context::aggregate_public_key(const ledger::executor_context* executor, public_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (!runner_wallet)
				return expects_promise_rt<void>(remote_exception::retry_later());

			auto list = new_encrypted_distribution_shares(runner_wallet->public_key, state);
			auto result = aggregate_public_key(this, executor, runner_wallet, list, *state.compositor);
			apply_encrypted_distribution_shares(state, runner_wallet->public_key_hash, list);
			return expects_promise_rt<void>(std::move(result));
		}
		expects_rt<void> local_dispatcher_context::aggregate_public_key(ledger::dispatcher_context* dispatcher, const ledger::executor_context* executor, const ledger::wallet* runner_wallet, btree_map<algorithm::pubkey_t, string>& encrypted_shares, algorithm::composition::compositor* compositor)
		{
			auto* route = (transactions::route*)executor->transaction;
			if (!route)
				return remote_exception("invalid transaction");

			auto* chain = superchain::bridge::get()->get_network_params(route->asset);
			if (!chain)
				return remote_exception("invalid operation");

			auto secret = dispatcher->recover_secret_entropy(runner_wallet, executor->receipt.from, route->asset, route->bridge_hash);
			if (!secret)
				return remote_exception(std::move(secret.error().message()));

			auto keypair = algorithm::composition::derive_keypair(chain->composition, secret->entropy.blob, secret->entropy.size());
			if (!keypair)
				return remote_exception(std::move(keypair.error().message()));

			auto derivation = compositor->aggregate(keypair->secret_key);
			if (!derivation)
				return remote_exception(std::move(derivation.error().message()));

			auto group = route->get_participants(executor->receipt);
			if (group.size() < protocol::now().policy.participation.min_per_account)
				return remote_exception("group is too small");

			size_t recovery_group = group.size() - 1;
			if (encrypted_shares.size() != recovery_group)
				return remote_exception("encrypted group shares count mismatch");

			btree_set<algorithm::share_t> shares;
			if (!algorithm::signing::split_secret_into_shares(secret->entropy.blob, algorithm::signing::recovery_threshold(recovery_group), (uint8_t)recovery_group, shares))
				return remote_exception("group share derivation failed");

			auto entropy_check = secret->entropy;
			memset(entropy_check.blob, 0, entropy_check.size());
			if (!algorithm::signing::combine_shares_into_secret(shares, entropy_check.blob) || secret->entropy != entropy_check)
				return remote_exception("group share recovery check failed");

			auto share = shares.begin();
			auto new_shares = btree_map<algorithm::pubkeyhash_t, secret_entropy::share_pair>();
			for (auto& [public_key, encrypted_share] : encrypted_shares)
			{
				algorithm::pubkeyhash_t participant;
				algorithm::signing::derive_public_key_hash(public_key, participant);
				if (group.find(participant) == group.end() || participant == runner_wallet->public_key_hash)
					return remote_exception("unauthorized participant included");

				auto tweaked_public_key = public_key;
				algorithm::seckey_t tweak;
				algorithm::signing::derive_secret_key(executor->receipt.transaction_hash, tweak);
				if (!algorithm::signing::scalar_add_public_key(tweaked_public_key, tweak))
					return remote_exception("invalid tweaked public key");

				uint256_t entropy = algorithm::hashing::hash256i(*crypto::random_bytes(64));
				auto result = algorithm::signing::public_encrypt(tweaked_public_key, share->view(), entropy);
				if (!result)
					return remote_exception("group share encryption failed");

				new_shares[participant].output = *share;
				encrypted_share = std::move(*result);
				++share;
			}

			secret = dispatcher->apply_secret_entropy(runner_wallet, secret->owner, secret->asset, secret->hash, secret->entropy, std::move(new_shares));
			if (!secret)
				return remote_exception(std::move(secret.error().message()));

			return expectation::met;
		}
		expects_promise_rt<void> local_dispatcher_context::aggregate_signature(const ledger::executor_context* executor, signature_state& state, const algorithm::pubkeyhash_t& validator)
		{
			auto* runner_wallet = get_runner_wallet(validator);
			if (!runner_wallet)
				return expects_promise_rt<void>(remote_exception::retry_later());

			return aggregate_signature(this, executor, runner_wallet, **state.message, *state.compositor);
		}
		expects_rt<void> local_dispatcher_context::aggregate_signature(ledger::dispatcher_context* dispatcher, const ledger::executor_context* executor, const ledger::wallet* runner_wallet, superchain::prepared_transaction& message, algorithm::composition::compositor* compositor)
		{
			auto* withdraw = (transactions::withdraw*)executor->transaction;
			if (!withdraw)
				return remote_exception("invalid transaction");

			auto validation = transactions::broadcast::validate_possible_proof(executor, withdraw, executor->receipt, message);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto* input = message.next_input_for_aggregation();
			if (!input)
				return remote_exception("invalid operation");

			auto witness = executor->get_witness_account_tagged(withdraw->asset, input->utxo.link.address, 0);
			if (!witness)
				return remote_exception(std::move(witness.error().message()));

			auto account = executor->get_bridge_account(witness->ref.owner, witness->ref.asset, witness->ref.hash);
			if (!account)
				return expectation::met;

			auto secret = dispatcher->recover_secret_entropy(runner_wallet, account->ref.owner, account->ref.asset, account->ref.hash);
			if (!secret)
				return remote_exception(std::move(secret.error().message()));

			auto keypair = algorithm::composition::derive_keypair(input->alg, secret->entropy.blob, secret->entropy.size());
			if (!keypair)
				return remote_exception(std::move(keypair.error().message()));

			auto accumulation = compositor->aggregate(keypair->secret_key);
			if (!accumulation)
				return remote_exception(std::move(accumulation.error().message()));

			return expectation::met;
		}
		btree_map<algorithm::pubkey_t, string> local_dispatcher_context::new_encrypted_distribution_shares(const algorithm::pubkey_t& validator_public_key, const public_state& state)
		{
			btree_map<algorithm::pubkey_t, string> list;
			for (auto& [public_key, encrypted_share_values] : state.encrypted_shares)
			{
				if (public_key != validator_public_key)
					list.insert(std::make_pair(public_key, string()));
			}
			return list;
		}
		void local_dispatcher_context::apply_encrypted_distribution_shares(public_state& state, const algorithm::pubkeyhash_t& validator, const btree_map<algorithm::pubkey_t, string>& list)
		{
			for (auto& [public_key, encrypted_share] : list)
			{
				if (!encrypted_share.empty())
					state.encrypted_shares[public_key][validator] = encrypted_share;
			}
		}
	}
}