#include "consensus.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../policy/transactions.h"
#include "../policy/delegations.h"
#include <random>
#define TASK_TOPOLOGY_OPTIMIZATION "topology_optimization"
#define TASK_MEMPOOL_VACUUM "mempool_vacuum"
#define TASK_FORK_RESOLUTION "fork_resolution"
#define TASK_SUPERCHAIN_SYNC "superchain_sync"
#define TASK_ATTESTATION_RESOLUTION "attestation_resolution"
#define TASK_ATTESTATION_DISPATCHER "attestation_dispatcher"
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
				return remote_exception("private result decryption failed (possible tampering attack)");

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
				report_call(0, 0, true);
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
		callable::descriptor descriptors::delegate_execution()
		{
			return callable::descriptor(__func__, 14);
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
			if (mempool.has_transaction(candidate_hash).or_else(false) || chain.get_transaction_by_hash(candidate_hash, false))
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

			uint256_t commitment_hash = 0;
			if (!candidate_tx->implements_commitment(&commitment_hash) && !candidate_tx->gas_price.is_positive())
			{
				if (candidate_message.data.size() > protocol::now().policy.gasless_size_limit)
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

			bool bypass_cooldown = false;
			if (commitment_hash > 0)
			{
				auto simulation = ledger::executor_context::calculate_tx_gas(*candidate_tx);
				if (!simulation)
				{
					mempool.add_transaction_observation(candidate_hash);
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s %.*s simulation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), simulation.error().what());
					return simulation.error();
				}
				bypass_cooldown = true;
			}
			else
			{
				algorithm::pubkeyhash_t validation_owner;
				auto validation = ledger::executor_context::validate_tx(*candidate_tx, candidate_hash, validation_owner);
				if (!validation)
				{
					if (protocol::now().user.consensus.logging)
						VI_WARN("transaction %s %.*s validation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
					return validation.error();
				}
			}

			return broadcast_transaction(uref(from), std::move(candidate_tx), owner, bypass_cooldown);
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
				return layer_exception("proofs are either not valid or not provided");

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
			pending_attestations[attestation_hash] = transaction;
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
		expects_lr<void> server_node::broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx, const algorithm::pubkeyhash_t& owner, bool bypass_cooldown)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto mempool = storages::mempoolstate();
			auto action = mempool.add_transaction(**candidate_tx, bypass_cooldown);
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
			if (chain.get_transaction_by_hash(transaction_hash, false))
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
			if (event.args.size() != 3)
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

			auto status = accept_node(mempool, peer_descriptor, node_category::other);
			if (!status)
				return remote_exception(std::move(status.error().message()));

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
			transaction = chain.get_transaction_by_hash(transaction_hash, false);
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
					transaction = chain.get_transaction_by_hash(transaction_hash, false);
				if (transaction)
					result.push_back(format::variable((*transaction)->as_message().data));
			}
			return expects_rt<format::variables>(std::move(result));
		}
		expects_rt<format::variables> server_node::delegate_execution(uref<relay>&&, const exchange& event)
		{
			auto packed = unpack_private_result(event.args, event.callee);
			if (!packed)
				return packed;
			else if (packed->size() != 4)
				return remote_exception("invalid arguments");

			auto yielding_delegator = ledger::wallet::from_public_key(algorithm::pubkey_t(packed->at(0).as_string()));
			if (yielding_delegator.public_key_hash.empty())
				return remote_exception("invalid delegator");

			auto block_number = packed->at(1).as_uint64();
			auto chainstate = storages::chainstate();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
				return remote_exception::retry_later();

			auto transaction_hash = packed->at(2).as_uint256();
			auto executor = ledger::executor_context(nullptr);
			auto context = executor.get_block_transaction_instance(transaction_hash);
			if (!context)
				return remote_exception("transaction not found");

			uint32_t delegation_type;
			executor.transaction = *context->transaction;
			executor.receipt = std::move(context->receipt);

			auto reader = format::ro_stream(packed->at(3).as_string());
			if (!reader.read_integer(reader.read_type(), &delegation_type))
				return remote_exception("invalid delegation type");

			auto adapter = server_delegation_adapter(this);
			auto delegation = uptr(delegations::resolver::from_type(delegation_type, &adapter, &executor, event.callee->second.public_key_hash));
			if (!delegation)
				return remote_exception("invalid delegation type");

			uint32_t delegate;
			if (!reader.read_integer(reader.read_type(), &delegate))
				return remote_exception("invalid delegate");

			if (!delegation->load_payload(reader))
				return remote_exception("delegation deserialization failed");

			auto validation = delegation->validate_transition(nullptr, yielding_delegator);
			if (!validation)
				return remote_exception(std::move(validation.error().message()));

			auto execution = delegation->yield_to_self(delegation->runner->public_key_hash, delegate, false);
			if (protocol::now().user.consensus.logging)
				VI_INFO("%s delegation%s: %s (delegator: %s)", delegation->as_typename().data(), execution ? "" : " failed", execution ? "OK" : execution.what().c_str(), algorithm::signing::encode_address(yielding_delegator.public_key_hash).c_str());
			if (!execution)
				return remote_exception(std::move(execution.error().message()));

			return pack_private_result({ format::variable(execution->data) }, yielding_delegator.public_key);
		}
		expects_lr<void> server_node::dispatch_transaction_logs(const algorithm::asset_id& asset, superchain::transaction_logs&& logs)
		{
			vector<std::pair<algorithm::hashsig_t, format::wo_stream>> attestations;
			for (auto& receipt : logs.receipts)
			{
				for (auto& [account, descriptor] : descriptors)
				{
					algorithm::hashsig_t commitment_signature; uint256_t commitment_hash;
					if (descriptor.first.services.has_attestation && transactions::attestate::commit_to_proof(receipt, descriptor.second.secret_key, commitment_hash, commitment_signature))
					{
						accept_committed_attestation(asset, receipt, commitment_signature);
						attestations.push_back(std::make_pair(commitment_signature, receipt.as_message()));
					}
				}
			}

			for (auto& [commitment_signature, proof_message] : attestations)
			{
				size_t notifications = notify_all(descriptors::broadcast_attestation(), { format::variable(asset), format::variable(proof_message.data), format::variable(commitment_signature.view()) });
				if (notifications > 0 && protocol::now().user.consensus.logging)
					VI_DEBUG("attestation %s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(commitment_hash).c_str(), (int)notifications);
			}

			if (!attestations.empty())
				run_attestation_dispatcher();

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
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> server_node::connect_to_logical_nodes(btree_set<algorithm::pubkeyhash_t>&& accounts)
		{
			if (accounts.empty())
				return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(remote_exception("invalid arguments"));

			btree_set<algorithm::pubkeyhash_t> early_results;
			for (auto& account : accounts)
			{
				if (find_descriptor(account) || find_by_account(account) || find_with_neighbor_account(account))
					early_results.insert(account);
			}
			if (early_results.size() == accounts.size())
				return expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(early_results));

			return coasync<expects_rt<btree_set<algorithm::pubkeyhash_t>>>([this, accounts = std::move(accounts), early_results = std::move(early_results)]() mutable -> expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>
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
					coreturn expects_promise_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(results));
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
							if (!mempool.has_transaction(transaction_hash).or_else(false) && !chain.get_transaction_by_hash(transaction_hash, false))
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
					size_t batch_size = 64, block_count = result->args.size() - 1;
					size_t batch_count = block_count / batch_size + (block_count % batch_size == 0 ? 0 : 1);
					for (auto& task : parallel::for_loop(batch_count, 2 * batch_size, [&](size_t batch_index)
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

					std::atomic<size_t> max_block_count = result->args.size();
					size_t batch_size = 64, block_count = max_block_count.load();
					size_t batch_count = block_count / batch_size + (block_count % batch_size == 0 ? 0 : 1);
					if (block_count > batch_size && protocol::now().user.consensus.logging)
						VI_INFO("block %s conflict: verifying proofs (size: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(new_tip_fork_hash).c_str(), (uint64_t)block_count);

					for (auto& task : parallel::for_loop(batch_count, 2 * batch_size, [&](size_t batch_index)
					{
						auto header = ledger::block_header();
						auto producer = algorithm::pubkeyhash_t();
						size_t begin = 1 + batch_index * batch_size;
						size_t end = std::min(begin + (batch_index == batch_count - 1 ? block_count % batch_size : batch_size), result->args.size());
						for (size_t i = begin; i < end; i++)
						{
							format::ro_stream block_message = format::ro_stream(result->args[i].as_string());
							if (!header.load(block_message) || !header.recover_hash(producer) || !header.verify_proof(producer))
							{
								size_t prev = max_block_count.load();
								while (prev > i && !max_block_count.compare_exchange_weak(prev, i));
								break;
							}
						}
					}))
						coawait(std::move(task));

					new_tip_hash = 0;
					size_t safe_block_count = max_block_count.load();
					for (size_t i = 0; i < safe_block_count; i++)
					{
						ledger::block_evaluation tip;
						format::ro_stream block_message = format::ro_stream(result->args[i].as_string());
						if (!tip.block.load(block_message))
							coreturn remote_exception("block violates message protocol");

						best_tip_hash = tip.block.as_hash();
						new_tip_number = tip.block.number + 1;
						auto status = accept_block(uref(new_tip.state), tip, new_tip_fork_hash, false);
						if (!status)
							coreturn remote_exception(std::move(status.error().message()));

						if (!is_active())
							break;
					}

					if (safe_block_count < result->args.size())
						coreturn remote_exception("stopping due to " + to_string(result->args.size() - safe_block_count) + " blocks with invalid proofs");
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
							message.args.erase(message.args.begin());
							if (forward_descriptor)
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
							else if (forward_state)
							{
								auto method = callable::descriptor(it->second.name, it->first);
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
						storages::mempoolstate().apply_cooldown_node(*candidate_address, true, false);
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

				auto chain = storages::chainstate();
				auto mempool = storages::mempoolstate();
				auto expirations = mempool.expire_transactions([&](const algorithm::pubkeyhash_t& target) -> uint64_t
				{
					auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(target), 0);
					auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
					return value ? value->nonce : 0; 
				});
				if (protocol::now().user.consensus.logging)
				{
					if (expirations)
					{
						if (*expirations > 0)
							VI_INFO("mempool transaction vacuum: OK (transactions: %i)", (int)*expirations);
					}
					else
						VI_ERR("mempool transaction vacuum failed: ", expirations.what().c_str());
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
			if (is_syncing())
				return false;

			return control_sys.task_if_none(TASK_ATTESTATION_RESOLUTION, [this](system_task&&)
			{
				size_t offset = 0, resolutions = 0;
				auto mempool = storages::mempoolstate();
				bool has_attestation = false;
				for (auto& [account, descriptor] : descriptors)
					has_attestation = has_attestation || descriptor.first.services.has_attestation;

				auto expirations = mempool.expire_attestations();
				if (protocol::now().user.consensus.logging)
				{
					if (expirations)
					{
						if (*expirations > 0)
							VI_INFO("mempool attestation vacuum: OK (attestations: %i)", (int)*expirations);
					}
					else
						VI_ERR("mempool attestation vacuum failed: ", expirations.what().c_str());
				}

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

							size_t notifications = notify_all(descriptors::broadcast_attestation(), { format::variable(batch->asset), format::variable(proof->second.as_message().data), format::variable(commitment_signature.view()) });
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
		bool server_node::run_attestation_dispatcher()
		{
			if (is_syncing())
				return false;

			return control_sys.task_if_none(TASK_ATTESTATION_DISPATCHER, [this](system_task&&)
			{
				umutex<std::recursive_mutex> unique(sync.attestation);
				auto mempool = storages::mempoolstate();
				for (auto& [attestation_hash, transaction] : pending_attestations)
				{
					auto dispatch = accept_local_transaction(&runner_descriptor->second, *transaction);
					if (dispatch)
					{
						mempool.remove_attestation(attestation_hash);
						if (protocol::now().user.consensus.logging)
							VI_INFO("attestation %s dispatch: OK", algorithm::encoding::encode_0xhex256(attestation_hash).c_str());
					}
				}
				pending_attestations.clear();
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
				auto queue_flags = prover.solver.state.executor.options & (uint8_t)ledger::executor_context::flags::congestion ? (uint8_t)storages::transaction_queue::congestion : 0;
				auto solution_account = prover.solver.state.public_key_hash;
				auto solution_challenge = ledger::block_header(prover.solution.block);
				auto solution_task = cotask<expects_lr<ledger::block_header>>([solution_challenge = std::move(solution_challenge), solution_account]() mutable -> expects_lr<ledger::block_header>
				{
					return solution_challenge.solve(solution_account) ? expects_lr<ledger::block_header>(std::move(solution_challenge)) : expects_lr<ledger::block_header>(layer_exception("failed to solve a block"));
				}, false);
				while (is_active() && solution_task.is_pending())
				{
					size_t offsets[2] = { 0, 0 };
					while (prover.solver.can_accept_more_transactions() && (offsets[0] != std::numeric_limits<size_t>::max() || offsets[1] != std::numeric_limits<size_t>::max()))
					{
						auto queue1 = mempool.get_best_transactions_from_queue(queue_flags, offsets[0], count);
						auto queue2 = mempool.get_best_transactions_from_queue((uint8_t)storages::transaction_queue::commitment, offsets[1], count);
						if (queue1)
						{
							offsets[0] = count == queue1->size() ? offsets[0] + queue1->size() : std::numeric_limits<size_t>::max();
							prover.solver.try_include_transactions(std::move(*queue1), &prover.hashes);
						}
						if (queue2)
						{
							offsets[1] = count == queue2->size() ? offsets[1] + queue2->size() : std::numeric_limits<size_t>::max();
							prover.solver.try_include_transactions(std::move(*queue2), &prover.hashes);
						}
					}

					evaluation = prover.solver.block_evalution_update(prover.solution, prover.rewards);
					if (!evaluation)
						break;

					++iteration;
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
						if (protocol::now().user.consensus.logging)
							VI_INFO("block %s solved (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);

						goto next_block;
					}
					else if (protocol::now().user.consensus.logging)
					{
						if (!evaluation)
						{
							if (evaluation.error().message() != "block producer must be active")
								VI_WARN("block %s dismissed: %s (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
						}
						else
							VI_WARN("%s", verification.error().what());
					}
				}
				else if (protocol::now().user.consensus.logging)
					VI_WARN("block %s dismissed: %s (number: %" PRIu64", txns: %" PRIu64 ", pos: %" PRIu64 ", work: < ~%.2f sec.)", algorithm::encoding::encode_0xhex256(prover.solution.block.as_hash()).c_str(), evaluation ? (solution ? "cancelled" : solution.error().what()) : evaluation.error().what(), prover.solution.block.number, (uint64_t)prover.solution.block.transactions.size(), position + 1, span / 1000.0);
			});
		}
		bool server_node::run_block_dispatcher()
		{
			if (is_syncing())
				return false;

			auto tip_number = storages::chainstate().get_latest_block_number().or_else(0);
			return control_sys.async_task_if_none(TASK_BLOCK_DISPATCHER, [this, tip_number]() -> promise<void>
			{
				auto adapter = server_delegation_adapter(this);
				auto execution = coawait(adapter.execute_dispatcher_on(tip_number));
				for (auto& [runner_wallet, transaction] : adapter.emissions)
				{
					if (runner_wallet && transaction)
						accept_local_transaction(runner_wallet, std::move(transaction));
				}

				if (protocol::now().user.consensus.logging)
				{
					if (execution.dispatches > 0 || !adapter.emissions.empty() || !execution.errors.empty())
						VI_INFO("block dispatch (number: %" PRIu64", inputs: %" PRIu64 ", outputs: %" PRIu64 ", reverts: %" PRIu64 ")", tip_number, (uint64_t)execution.dispatches, (uint64_t)adapter.emissions.size(), (uint64_t)execution.errors.size());
					for (auto& [transaction_hash, error] : execution.errors)
						VI_ERR("transaction %s dispatching failed: %s", algorithm::encoding::encode_0xhex256(transaction_hash).c_str(), error.what());
				}

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
			bind_query(descriptors::delegate_execution(), std::bind(&server_node::delegate_execution, this, std::placeholders::_2, std::placeholders::_3));
			control_sys.interval_if_none(TASK_TOPOLOGY_OPTIMIZATION "_runner", 180000, std::bind(&server_node::run_topology_optimization, this));
			control_sys.interval_if_none(TASK_BLOCK_DISPATCH_RETRIAL "_runner", 120000, std::bind(&server_node::run_block_dispatcher, this));
			control_sys.interval_if_none(TASK_ATTESTATION_RESOLUTION "_runner", 600000, std::bind(&server_node::run_attestation_resolution, this));
			control_sys.interval_if_none(TASK_ATTESTATION_DISPATCHER "_runner", 60000, std::bind(&server_node::run_attestation_dispatcher, this));
			control_sys.interval_if_none(TASK_MEMPOOL_VACUUM "_runner", 600000, std::bind(&server_node::run_mempool_vacuum, this));
			run_topology_optimization();
			run_mempool_vacuum();
			run_attestation_resolution();

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
		expects_lr<void> server_node::accept_block(uref<relay>&& from, ledger::block_evaluation& candidate, const uint256_t& fork_tip, bool verify_pow)
		{
			uint256_t candidate_hash = candidate.block.as_hash();
			auto chain = storages::chainstate();
			if (!fork_tip && chain.get_block_header_by_hash(candidate_hash))
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
				return layer_exception(stringify::text("block %s rejected: inferior fork", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));
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
			if (!try_acquire_checkpointer())
				return layer_exception(stringify::text("block %s checkpoint skipped: checkpointer busy", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));

			bool chain_extension = !fork_tip;
			if (chain_extension)
				append_pending_block(uref(from), candidate_hash, &candidate.block);

			auto reorganization = ledger::solver_context::requires_reorganization(candidate);
			auto validation = fork_branch && reorganization ? expects_lr<void>(expectation::met) : ledger::solver_context::validate_solved_block(verifier.solver, parent_block.address(), candidate.block, &candidate, verify_pow);
			if (!validation)
			{
				release_checkpointer();
				return layer_exception(stringify::text("block %s rejected: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), validation.error().what()));
			}
			else if (reorganization && !protocol::now().user.consensus.reorganizable)
			{
				release_checkpointer();
				return layer_exception(stringify::text("block %s rejected: requires deep chain reorganization (disabled)", algorithm::encoding::encode_0xhex256(candidate_hash).c_str()));
			}

			auto mutation = ledger::solver_context::checkpoint_solved_block(verifier.solver, candidate);
			release_checkpointer();
			if (chain_extension)
				erase_pending_block(candidate_hash);

			if (!mutation)
				return layer_exception(stringify::text("block %s checkpoint failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation.error().what()));

			if (protocol::now().user.consensus.logging)
			{
				int64_t progress = (int64_t)(10000.0 * get_sync_progress(candidate.block.number, *from));
				verifier.size += (uint64_t)((double)(uint64_t)candidate.block.gas_limit / ((double)ledger::gas_cost::write_byte * 1024.0) * 1000.0);
				if (progress >= 10000 || verifier.progress < progress || mutation->is_fork)
				{
					double size = (double)verifier.size.load() / 1000.0;
					if (mutation->is_fork)
					{
						VI_INFO("block %s (number: %" PRIu64 ", sync: %.2f%%, size: ~%.2f kb, depth: %" PRIi64 ", txns: %" PRIi64 ", state: %" PRIi64 ")\n",
							algorithm::encoding::encode_0xhex256(candidate_hash).c_str(),
							candidate.block.number, (double)progress / 100.0, size,
							mutation->block_delta,
							mutation->transaction_delta + mutation->mempool_transactions,
							mutation->state_delta);
					}
					else
					{
						VI_INFO("block %s (number: %" PRIu64 ", sync: %.2f%%, size: ~%.2f kb)",
							algorithm::encoding::encode_0xhex256(candidate_hash).c_str(),
							candidate.block.number, (double)progress / 100.0, size);
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
			pending_blocks[block_hash] = tip->as_message();
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
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> server_delegation_adapter::require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& validators)
		{
			if (protocol::now().user.consensus.logging)
				VI_INFO("%s delegation: assemble %i validators", contract->as_typename().data(), (int)validators.size());

			return server->connect_to_logical_nodes(btree_set<algorithm::pubkeyhash_t>(validators)).then<expects_rt<btree_set<algorithm::pubkeyhash_t>>>([contract](expects_rt<btree_set<algorithm::pubkeyhash_t>>&& result) mutable -> expects_rt<btree_set<algorithm::pubkeyhash_t>>
			{
				if (result && protocol::now().user.consensus.logging)
					VI_INFO("%s delegation: found %i validators", contract->as_typename().data(), (int)result->size());
				else if (!result && protocol::now().user.consensus.logging)
					VI_ERR("%s delegation failed: %s", contract->as_typename().data(), result.what().c_str());	
				return expects_rt<btree_set<algorithm::pubkeyhash_t>>(std::move(result));
			});
		}
		expects_promise_rt<format::wo_stream> server_delegation_adapter::execute_on_validator(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message)
		{
			if (protocol::now().user.consensus.logging)
				VI_DEBUG("%s delegation: inquiry to %s with %s", contract->as_typename().data(), algorithm::signing::encode_address(target).c_str(), message.encode().c_str());

			return execute_on_validator_internal(contract, target, message).then<expects_rt<format::wo_stream>>([contract, target](expects_rt<format::wo_stream>&& result) mutable -> expects_rt<format::wo_stream>
			{
				if (result && protocol::now().user.consensus.logging)
					VI_INFO("%s delegation: OK (delegate: %s)", contract->as_typename().data(), algorithm::signing::encode_address(target).c_str());
				else if (!result && protocol::now().user.consensus.logging)
					VI_INFO("%s delegation failed: %s (delegate: %s)", contract->as_typename().data(), result.what().c_str(), algorithm::signing::encode_address(target).c_str());
				
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

			auto private_args = pack_private_result(args, *target_public_key);
			if (!private_args)
				return expects_promise_rt<format::wo_stream>(std::move(private_args.error()));

			return coasync<expects_rt<format::wo_stream>>([this, contract, target, target_public_key = std::move(target_public_key), private_args = std::move(private_args)]() mutable -> expects_promise_rt<format::wo_stream>
			{
				uint64_t attempt = 0;
			retry:
				auto event = coawait(server->indirect_query(target, descriptors::delegate_execution(), format::variables(*private_args), protocol::now().user.tcp.timeout));
				if (!event)
				{
					bool is_retry = server->is_active() && (event.error().is_retry() || event.error().is_shutdown());
					if (is_retry && coawait(aggregative_sleep(attempt)))
						goto retry;

					coreturn is_retry || !server->is_active() ? remote_exception::retry_later() : event.error();
				}

				private_args = unpack_private_result(event->args, contract->runner->secret_key);
				if (!private_args)
					coreturn private_args.error();

				if (private_args->size() != 1 || !private_args->at(0).is_string())
					coreturn remote_exception("delegation result deserialization failed (possible attack)");

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
		expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> local_delegation_adapter::require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& targets)
		{
			btree_set<algorithm::pubkeyhash_t> results;
			for (auto& [validator, wallet] : validators)
			{
				if (targets.find(validator) != targets.end())
					results.insert(validator);
			}
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