#include "p2p.h"
#include "nss.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../../policy/transactions.h"
#include <array>
#define BLOCK_RATE_NORMAL ELEMENTS_MANY
#define BLOCK_DATA_CONSENSUS (uint32_t)storages::block_details::transactions | (uint32_t)storages::block_details::block_transactions

namespace tangent
{
	namespace p2p
	{
		bool procedure::serialize_into(string* result)
		{
			VI_ASSERT(result != nullptr, "result should be set");
			format::stream stream;
			if (!format::variables_util::serialize_flat_into(args, &stream))
				return false;

			uint32_t body_checksum = algorithm::hashing::hash32d((uint8_t*)stream.data.data(), stream.data.size());
			uint32_t net_magic = os::hw::to_endianness(os::hw::endian::little, magic = protocol::now().message.packet_magic);
			uint32_t net_method = os::hw::to_endianness(os::hw::endian::little, method);
			uint32_t net_size = os::hw::to_endianness(os::hw::endian::little, size = (uint32_t)stream.data.size());
			uint32_t net_checksum = os::hw::to_endianness(os::hw::endian::little, checksum = body_checksum);

			size_t offset = result->size();
			result->resize(offset + sizeof(uint32_t) * 4 + stream.data.size());
			memcpy(result->data() + offset + sizeof(uint32_t) * 0, &net_magic, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 1, &net_method, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 2, &net_size, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 3, &net_checksum, sizeof(uint32_t));
			memcpy(result->data() + offset + sizeof(uint32_t) * 4, stream.data.data(), stream.data.size());
			return true;
		}
		bool procedure::deserialize_from(string& message)
		{
			while (message.size() >= sizeof(uint32_t))
			{
				memcpy(&magic, message.data() + sizeof(uint32_t) * 0, sizeof(uint32_t));
				magic = os::hw::to_endianness(os::hw::endian::little, magic);
				if (magic == protocol::now().message.packet_magic)
					break;

				message.erase(message.begin(), message.begin() + sizeof(uint32_t));
			}

			const size_t header_size = sizeof(uint32_t) * 4;
			if (message.size() < header_size)
				return false;

			memcpy(&method, message.data() + sizeof(uint32_t) * 1, sizeof(uint32_t));
			memcpy(&size, message.data() + sizeof(uint32_t) * 2, sizeof(uint32_t));
			memcpy(&checksum, message.data() + sizeof(uint32_t) * 3, sizeof(uint32_t));
			method = os::hw::to_endianness(os::hw::endian::little, method);
			size = os::hw::to_endianness(os::hw::endian::little, size);
			checksum = os::hw::to_endianness(os::hw::endian::little, checksum);

			if (!size)
			{
				message.erase(message.begin(), message.begin() + header_size);
				args.clear();
				return checksum == 0;
			}
			else if (message.size() < header_size + size)
				return false;

			if (size > protocol::now().message.max_body_size)
			{
				uint32_t delta = std::min<uint32_t>(size - protocol::now().message.max_body_size, (uint32_t)(message.size() - header_size));
				size = (size > delta ? size - delta : 0);
				message.erase(message.end() - delta, message.end());
				if (size > protocol::now().message.max_body_size || message.size() < header_size + size)
					return false;
			}

			string body;
			body.resize(size);
			memcpy(body.data(), message.data() + header_size, size);
			message.erase(message.begin(), message.begin() + header_size + size);
			args.clear();

			uint32_t body_checksum = algorithm::hashing::hash32d((uint8_t*)body.data(), body.size());
			if (os::hw::to_endianness(os::hw::endian::little, body_checksum) != checksum)
				return false;

			format::stream stream = format::stream(std::move(body));
			return format::variables_util::deserialize_flat_from(stream, &args);
		}
		bool procedure::deserialize_from_stream(string& message, const uint8_t* buffer, size_t size)
		{
			if (!buffer || !size)
				return deserialize_from(message);

			size_t offset = message.size();
			message.resize(offset + size);
			memcpy(message.data() + offset, buffer, size);
			return deserialize_from(message);
		}

		relay_procedure::relay_procedure(procedure&& new_data) : data(std::move(new_data))
		{
		}

		relay::relay(node_type new_type, void* new_instance) : type(new_type), instance(new_instance)
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
		bool relay::incoming_message_into(procedure* message)
		{
			VI_ASSERT(message != nullptr, "incoming message should be set");
			umutex<std::mutex> unique(mutex);
			if (incoming_messages.empty())
				return false;

			*message = std::move(incoming_messages.front());
			incoming_messages.pop();
			return true;
		}
		bool relay::pull_incoming_message(const uint8_t* buffer, size_t size)
		{
			procedure message;
			umutex<std::mutex> unique(mutex);
			if (!message.deserialize_from_stream(incoming_data, buffer, size))
				return !incoming_messages.empty();

			incoming_messages.emplace(std::move(message));
			return true;
		}
		bool relay::begin_outgoing_message()
		{
			umutex<std::mutex> unique(mutex);
			if (!outgoing_data.empty())
				return false;
		retry:
			if (!priority_messages.empty())
			{
				auto& message = priority_messages.front();
				bool relayable = message->data.serialize_into(&outgoing_data) && !outgoing_data.empty();
				priority_messages.pop();
				if (relayable)
					return true;
			}
			else
			{
				if (outgoing_messages.empty())
					return false;

				auto& message = outgoing_messages.front();
				bool relayable = message.serialize_into(&outgoing_data) && !outgoing_data.empty();
				outgoing_messages.pop();
				if (relayable)
					return true;
			}

			outgoing_data.clear();
			goto retry;
		}
		void relay::end_outgoing_message()
		{
			umutex<std::mutex> unique(mutex);
			outgoing_data.clear();
		}
		void relay::push_message(procedure&& message)
		{
			umutex<std::mutex> unique(mutex);
			outgoing_messages.push(std::move(message));
		}
		void relay::relay_message(uref<relay_procedure>&& message)
		{
			umutex<std::mutex> unique(mutex);
			priority_messages.push(std::move(message));
		}
		void relay::invalidate()
		{
			if (user_data.pointer)
			{
				if (user_data.destructor)
					user_data.destructor(user_data.pointer);
				user_data.pointer = nullptr;
			}

			if (!instance)
				return;

			switch (type)
			{
				case node_type::inbound:
					as_inbound_node()->release();
					break;
				case node_type::outbound:
					as_outbound_node()->release();
					break;
				default:
					VI_ASSERT(false, "invalid node state");
					break;
			}
			instance = nullptr;
		}
		const string& relay::peer_address()
		{
			if (!address.empty())
				return address;

			umutex<std::mutex> unique(mutex);
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

			umutex<std::mutex> unique(mutex);
			auto* stream = as_socket();
			if (!stream)
			{
			no_service:
				service = to_string(protocol::now().user.p2p.port);
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
		const single_queue<uref<relay_procedure>>& relay::get_priority_messages() const
		{
			return priority_messages;
		}
		const single_queue<procedure>& relay::get_incoming_messages() const
		{
			return incoming_messages;
		}
		const single_queue<procedure>& relay::get_outgoing_messages() const
		{
			return outgoing_messages;
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
			return type == node_type::inbound ? (inbound_node*)instance : nullptr;
		}
		outbound_node* relay::as_outbound_node()
		{
			return type == node_type::outbound ? (outbound_node*)instance : nullptr;
		}
		socket* relay::as_socket()
		{
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
			data->set("priority_queue", algorithm::encoding::serialize_uint256(priority_messages.size()));
			auto* incoming = data->set("incoming", var::object());
			incoming->set("queue", algorithm::encoding::serialize_uint256(incoming_messages.size()));
			incoming->set("bytes", algorithm::encoding::serialize_uint256(incoming_data.size()));
			auto* outgoing = data->set("outgoing", var::object());
			outgoing->set("queue", algorithm::encoding::serialize_uint256(outgoing_messages.size()));
			outgoing->set("bytes", algorithm::encoding::serialize_uint256(outgoing_data.size()));
			return data;
		}

		outbound_node::outbound_node() noexcept : socket_client(protocol::now().user.tcp.timeout)
		{
		}
		void outbound_node::configure_stream()
		{
			socket_client::configure_stream();
			if (protocol::now().is(network_type::regtest))
				net.stream->bind(socket_address(protocol::now().user.p2p.address, 0));
		}

		server_node::server_node() noexcept : socket_server(), control_sys("p2p-node")
		{
		}
		server_node::~server_node() noexcept
		{
			if (nss::server_node::has_instance())
			{
				auto node_id = codec::hex_encode(std::string_view((char*)this, sizeof(this)));
				nss::server_node::get()->add_transaction_callback(node_id, nullptr);
			}
			clear_pending_tip();
		}
		promise<option<socket_address>> server_node::connect_node_from_mempool(option<socket_address>&& error_address, bool allow_seeding)
		{
			auto mempool = storages::mempoolstate(__func__);
			if (error_address)
			{
				auto error_validator = mempool.get_validator_by_address(*error_address);
				if (error_validator)
				{
					++error_validator->availability.calls;
					++error_validator->availability.errors;
					apply_validator(mempool, *error_validator, optional::none);
				}

				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] peer %s:%i channel skip: host not reachable", error_address->get_ip_address().or_else("[bad_address]").c_str(), (int)error_address->get_ip_port().or_else(0));
			}
		retry_validator:
			auto next_validator = mempool.get_validator_by_preference(discovery.offset);
			if (!next_validator)
			{
			retry_trial_address:
				auto next_trial_address = mempool.next_trial_address();
				if (!next_trial_address)
					goto no_candidate;

				if (find(*next_trial_address) || routing::is_address_reserved(*next_trial_address))
					goto retry_trial_address;

				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] peer %s:%i channel try: possibly candidate node", next_trial_address->get_ip_address().or_else(string("[bad_address]")).c_str(), (int)next_trial_address->get_ip_port().or_else(0));

				return promise<option<socket_address>>(std::move(*next_trial_address));
			}

			++discovery.offset;
			if (find(next_validator->address) || routing::is_address_reserved(next_validator->address))
			{
				if (discovery.offset < discovery.count)
					goto retry_validator;

			no_candidate:
				if (allow_seeding)
					return find_node_from_seeding();

				return promise<option<socket_address>>(optional::none);
			}

			if (protocol::now().user.p2p.logging)
				VI_INFO("[p2p] peer %s:%i channel try: previosly connected node", next_validator->address.get_ip_address().or_else(string("[bad_address]")).c_str(), (int)next_validator->address.get_ip_port().or_else(0));

			return promise<option<socket_address>>(std::move(next_validator->address));
		}
		promise<option<socket_address>> server_node::find_node_from_seeding()
		{
			if (protocol::now().user.seeds.empty())
				return promise<option<socket_address>>(optional::none);

			return coasync<option<socket_address>>([this]() -> promise<option<socket_address>>
			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto mempool = storages::mempoolstate(__func__);
				auto random = std::default_random_engine();
				auto lists = vector<string>(protocol::now().user.seeds.begin(), protocol::now().user.seeds.end());
				std::shuffle(std::begin(lists), std::end(lists), random);
				unique.unlock();

				for (auto& seed : lists)
				{
					size_t results = std::numeric_limits<size_t>::max();
					auto response = coawait(http::fetch(seed));
					if (response)
					{
						auto addresses = uptr<schema>(response->content.get_json());
						if (addresses)
						{
							results = 0;
							for (auto* address : addresses->get_childs())
							{
								auto endpoint = system_endpoint(address->value.get_blob());
								if (endpoint.is_valid() && !routing::is_address_reserved(endpoint.address) && mempool.apply_trial_address(endpoint.address))
									++results;
							}
						}
					}

					if (protocol::now().user.p2p.logging)
					{
						if (results != std::numeric_limits<size_t>::max())
							VI_INFO("[p2p] seed %s %sresults found (addresses: %" PRIu64 ")", seed.c_str(), results > 0 ? "" : "no ", (uint64_t)results);
						else
							VI_WARN("[p2p] seed %s no results found: bad seed", seed.c_str());
					}
				}

				coreturn connect_node_from_mempool(optional::none, false);
			});
		}
		promise<void> server_node::connect(uptr<relay>&& from)
		{
			call(*from, &server_node::propose_handshake, { format::variable(validator.node.as_message().data), format::variable(protocol::now().time.now_cpu()) });
			return return_ok(*from, __func__, "initiate handshake");
		}
		promise<void> server_node::disconnect(uptr<relay>&& from)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
			{
				auto mempool = storages::mempoolstate(__func__);
				peer_validator->availability.timestamp = protocol::now().time.now();
				apply_validator(mempool, *peer_validator, optional::none).report("mempool validator save failed");
			}

			if (discovery.offset >= discovery.count)
				discovery.offset = 0;

			if (protocol::now().user.p2p.logging)
				VI_INFO("[p2p] validator %s channel shutdown (%s %s)", from->peer_address().c_str(), node_type_of(*from).data(), from->peer_service().c_str());

			return return_ok(*from, __func__, "approve shutdown");
		}
		promise<void> server_node::propose_transaction_logs(const mediator::chain_supervisor_options& options, mediator::transaction_logs&& logs)
		{
			umutex<std::recursive_mutex> unique(sync.account);
			auto account_sequence = validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			for (auto& receipt : logs.transactions)
			{
				if (receipt.is_approved())
				{
					auto collision = ledger::transaction_context().get_witness_transaction(receipt.asset, receipt.transaction_id);
					if (!collision)
					{
						uptr<transactions::incoming_claim> transaction = memory::init<transactions::incoming_claim>();
						transaction->set_witness(receipt);

						if (propose_transaction(nullptr, std::move(*transaction), account_sequence))
							++account_sequence;
					}
					else if (protocol::now().user.p2p.logging)
						VI_INFO("[p2p] %s observer transaction %s approved", algorithm::asset::handle_of(receipt.asset).c_str(), receipt.transaction_id.c_str());
				}
				else if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] %s observer transaction %s queued", algorithm::asset::handle_of(receipt.asset).c_str(), receipt.transaction_id.c_str());
			}
			return promise<void>::null();
		}
		promise<void> server_node::propose_handshake(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 2)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uptr<ledger::validator> peer_validator = memory::init<ledger::validator>();
			format::stream validator_message = format::stream(args.front().as_blob());
			uint64_t peer_time = args.back().as_uint64();
			uint64_t server_time = protocol::now().time.now_cpu();
			uint64_t latency_time = peer_time > server_time ? peer_time - server_time : server_time - peer_time;
			if (!peer_validator->load(validator_message))
				return return_abort(relayer, *from, __func__, "invalid message");

			auto& peer = protocol::now().user.p2p;
			peer_validator->availability.latency = latency_time;
			peer_validator->address = socket_address(from->peer_address(), peer_validator->address.get_ip_port().or_else(protocol::now().user.p2p.port));
			if (!peer_validator->is_valid())
				return return_abort(relayer, *from, __func__, "invalid validator");

			auto mempool = storages::mempoolstate(__func__);
			relayer->apply_validator(mempool, **peer_validator, optional::none).report("mempool peer validator save failed");

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			relayer->call(*from, &server_node::approve_handshake, { format::variable(validator_message.data), format::variable(protocol::now().time.now_cpu()), format::variable(tip ? tip->number : 0), format::variable(tip ? tip->as_hash() : uint256_t(0)) });
			from->use<ledger::validator>(peer_validator.reset(), [](ledger::validator* value) { memory::deinit(value); });
			return return_ok(*from, __func__, "approve handshake");
		}
		promise<void> server_node::approve_handshake(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 4)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			ledger::validator self_validator;
			format::stream validator_message = format::stream(args[0].as_blob());
			if (!self_validator.load(validator_message))
				return return_abort(relayer, *from, __func__, "invalid message");
			else if (!self_validator.is_valid())
				return return_abort(relayer, *from, __func__, "invalid validator");
			else if (self_validator.availability.calls != relayer->validator.node.availability.calls || self_validator.availability.errors != relayer->validator.node.availability.errors || self_validator.availability.timestamp != relayer->validator.node.availability.timestamp)
				return return_abort(relayer, *from, __func__, "invalid validator adjustment");

			auto* peer_validator = from->as_user<ledger::validator>();
			if (!peer_validator)
				return return_abort(relayer, *from, __func__, "validator not found");

			if (self_validator.address.get_ip_address().or_else(string()) != relayer->validator.node.address.get_ip_address().or_else(string()) || self_validator.availability.latency != relayer->validator.node.availability.latency)
			{
				auto mempool = storages::mempoolstate(__func__);
				relayer->validator.node = std::move(self_validator);
				relayer->apply_validator(mempool, relayer->validator.node, relayer->validator.wallet).report("mempool self validator save failed");
			}

			auto& protocol = protocol::change();
			uint64_t peer_time = args[1].as_uint64();
			uint64_t server_time = protocol::now().time.now_cpu();
			uint64_t latency_time = peer_time > server_time ? peer_time - server_time : server_time - peer_time;
			uint64_t varying_peer_time = peer_time + (peer_validator->availability.latency + latency_time) / 2;
			protocol.time.adjust(peer_validator->address, (int64_t)server_time - (int64_t)varying_peer_time);
			if (protocol::now().user.p2p.logging)
				VI_INFO("[p2p] validator %s channel accept (%s %s)", from->peer_address().c_str(), node_type_of(*from).data(), from->peer_service().c_str());

			auto mempool = storages::mempoolstate(__func__);
			auto nodes = mempool.get_validator_addresses(0, protocol::now().user.p2p.cursor_size);
			if (nodes && !nodes->empty())
			{
				format::variables args;
				args.reserve(nodes->size() * 2);
				for (auto& item : *nodes)
				{
					auto ip_address = item.get_ip_address();
					auto ip_port = item.get_ip_port();
					if (ip_address && ip_port)
					{
						args.push_back(format::variable(*ip_address));
						args.push_back(format::variable(*ip_port));
					}
				}
				relayer->call(*from, &server_node::propose_nodes, std::move(args));
			}

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			uint64_t peer_tip_number = args[2].as_uint64();
			uint256_t peer_tip_hash = args[3].as_uint256();
			if (!tip || peer_tip_number > tip->number)
				return return_ok(*from, __func__, "tip required");
			else if (peer_tip_number == tip->number && tip->as_hash() == peer_tip_hash)
				return return_ok(*from, __func__, "tip synced");

			auto block = chain.get_block_by_number(tip->number, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
			if (!block)
				return return_ok(*from, __func__, "no tip found");

			format::stream message = block->as_message();
			relayer->call(*from, &server_node::propose_block, { format::variable(message.data) });
			return return_ok(*from, __func__, "new tip proposed");
		}
		promise<void> server_node::propose_nodes(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.empty() || args.size() % 2 != 0)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			size_t candidates = 0;
			auto mempool = storages::mempoolstate(__func__);
			for (size_t i = 0; i < args.size(); i += 2)
			{
				auto ip_address = args[i + 0].as_string();
				auto ip_port = args[i + 1].as_uint16();
				auto target = socket_address(ip_address, ip_port);
				candidates += target.is_valid() && !routing::is_address_reserved(target) && mempool.apply_trial_address(target) ? 1 : 0;
			}

			if (candidates > 0)
				relayer->accept();

			return return_ok(*from, __func__, "accept nodes");
		}
		promise<void> server_node::find_fork_collision(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 2)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = args[0].as_uint256();
			if (!fork_hash)
				return return_abort(relayer, *from, __func__, "invalid fork");

			uint64_t branch_number = args[1].as_uint64();
			if (!branch_number)
				return return_abort(relayer, *from, __func__, "invalid branch");

			const uint64_t blocks_count = protocol::now().user.p2p.cursor_size;
			const uint64_t fork_number = branch_number > blocks_count ? branch_number - blocks_count : 1;
			auto chain = storages::chainstate(__func__);
			auto headers = chain.get_block_headers(fork_number, blocks_count);
			if (!headers || headers->empty())
				return return_error(relayer, *from, __func__, "fork collision not found");

			format::variables header_args;
			header_args.reserve(headers->size() + 2);
			header_args.push_back(format::variable(fork_hash));
			header_args.push_back(format::variable(fork_number + headers->size() - 1));
			for (auto& item : *headers)
				header_args.push_back(format::variable(item.as_message().data));

			relayer->call(*from, &server_node::verify_fork_collision, std::move(header_args));
			return return_ok(*from, __func__, "fork collisions proposed");
		}
		promise<void> server_node::verify_fork_collision(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() < 2)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = args[0].as_uint256();
			if (!fork_hash)
				return return_abort(relayer, *from, __func__, "invalid fork");

			uint64_t branch_number = args[1].as_uint64();
			if (!branch_number)
				return return_abort(relayer, *from, __func__, "invalid branch");

			if (args.size() < 3)
				return return_error(relayer, *from, __func__, "fork collision not found");

			format::stream message;
			ledger::block_header child_header;
			message.data = args[2].as_string();
			if (!child_header.load(message))
				return return_abort(relayer, *from, __func__, "invalid fork block header");

			ledger::block_header parent_header;
			auto chain = storages::chainstate(__func__);
			for (size_t i = 3; i < args.size() + 1; i++)
			{
				uint256_t branch_hash = child_header.as_hash(true);
				auto collision = chain.get_block_header_by_hash(branch_hash);
				if (collision || --branch_number < 1)
				{
					relayer->call(*from, &server_node::request_fork_block, { format::variable(fork_hash), format::variable(branch_hash), format::variable((uint64_t)0) });
					return return_ok(*from, __func__, "fork collision found");
				}
				else if (i < args.size())
				{
					message.clear();
					message.data = args[i].as_string();
					if (!parent_header.load(message))
						return return_abort(relayer, *from, __func__, "invalid fork block header");
				}

				auto verification = child_header.verify_validity(parent_header.number > 0 ? &parent_header : nullptr);
				if (!verification)
					return return_abort(relayer, *from, __func__, "invalid fork block header: " + verification.error().message());

				child_header = parent_header;
			}

			relayer->call(*from, &server_node::find_fork_collision, { format::variable(fork_hash), format::variable(branch_number) });
			return return_ok(*from, __func__, "fork collision not found");
		}
		promise<void> server_node::request_fork_block(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 3)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = args[0].as_uint256();
			if (!fork_hash)
				return return_abort(relayer, *from, __func__, "invalid fork");

			uint256_t block_hash = args[1].as_uint256();
			if (block_hash > 0)
			{
				auto chain = storages::chainstate(__func__);
				auto block = chain.get_block_by_hash(block_hash, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
				{
					format::stream message = block->as_message();
					relayer->call(*from, &server_node::propose_fork_block, { format::variable(fork_hash), format::variable(message.data) });
					return return_ok(*from, __func__, "new fork block proposed");
				}
			}

			uint256_t block_number = args[2].as_uint64();
			if (block_number > 0)
			{
				auto chain = storages::chainstate(__func__);
				auto block = chain.get_block_by_number(block_number, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
				{
					format::stream message = block->as_message();
					relayer->call(*from, &server_node::propose_fork_block, { format::variable(fork_hash), format::variable(message.data) });
					return return_ok(*from, __func__, "new fork block proposed");
				}
			}

			return return_ok(*from, __func__, "fork block not found");
		}
		promise<void> server_node::propose_fork_block(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 2)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = args.front().as_uint256();
			if (!fork_hash)
				return return_abort(relayer, *from, __func__, "invalid fork");

			ledger::block tip;
			format::stream message = format::stream(args.back().as_blob());
			if (!tip.load(message) || !relayer->accept_block(*from, std::move(tip), fork_hash))
				return return_error(relayer, *from, __func__, "block rejected");

			relayer->call(*from, &server_node::request_fork_block, { format::variable(fork_hash), format::variable(uint256_t(0)), format::variable(tip.number + 1) });
			return return_ok(*from, __func__, "new fork block accepted");
		}
		promise<void> server_node::request_block(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t block_hash = args.front().as_uint256();
			if (!block_hash)
				return return_abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			auto block = chain.get_block_by_hash(block_hash, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
			if (!block)
				return return_ok(*from, __func__, "block not found");

			format::stream message = block->as_message();
			relayer->call(*from, &server_node::propose_block, { format::variable(message.data) });
			return return_ok(*from, __func__, "block proposed");
		}
		promise<void> server_node::propose_block(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			ledger::block candidate;
			format::stream message = format::stream(args.front().as_blob());
			if (!candidate.load(message) || !relayer->accept_block(*from, std::move(candidate), 0))
				return return_error(relayer, *from, __func__, "block rejected");

			return return_ok(*from, __func__, "block accepted");
		}
		promise<void> server_node::propose_block_hash(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t block_hash = args.front().as_uint256();
			if (!block_hash)
				return return_abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			if (chain.get_block_header_by_hash(block_hash))
				return return_ok(*from, __func__, "block found");

			relayer->call(*from, &server_node::request_block, { format::variable(block_hash) });
			return return_ok(*from, __func__, "block requested");
		}
		promise<void> server_node::request_transaction(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t transaction_hash = args.front().as_uint256();
			if (!transaction_hash)
				return return_abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			auto transaction = chain.get_transaction_by_hash(transaction_hash);
			if (!transaction)
			{
				auto mempool = storages::mempoolstate(__func__);
				transaction = mempool.get_transaction_by_hash(transaction_hash);
				if (!transaction)
					return return_ok(*from, __func__, "transaction not found");
			}

			format::stream message = (*transaction)->as_message();
			relayer->call(*from, &server_node::propose_transaction, { format::variable(message.data) });
			return return_ok(*from, __func__, "transaction proposed");
		}
		promise<void> server_node::propose_transaction(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			format::stream message = format::stream(args.front().as_blob());
			uptr<ledger::transaction> candidate = tangent::transactions::resolver::init(messages::authentic::resolve_type(message).or_else(0));
			if (!candidate)
				return return_error(relayer, *from, __func__, "invalid transaction");

			if (!candidate->load(message) || !relayer->accept_transaction(*from, std::move(candidate)))
				return return_error(relayer, *from, __func__, "transaction rejected");

			return return_ok(*from, __func__, "transaction accepted");
		}
		promise<void> server_node::propose_transaction_hash(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint256_t transaction_hash = args.front().as_uint256();
			if (!transaction_hash)
				return return_abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			if (chain.get_transaction_by_hash(transaction_hash))
				return return_ok(*from, __func__, "finalized transaction found");

			auto mempool = storages::mempoolstate(__func__);
			if (mempool.get_transaction_by_hash(transaction_hash))
				return return_ok(*from, __func__, "pending transaction found");

			relayer->call(*from, &server_node::request_transaction, { format::variable(transaction_hash) });
			return return_ok(*from, __func__, "transaction requested");
		}
		promise<void> server_node::request_mempool(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() != 1)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint64_t cursor = args.front().as_uint64();
			const uint64_t transactions_count = protocol::now().user.p2p.cursor_size;
			auto mempool = storages::mempoolstate(__func__);
			auto hashes = mempool.get_transaction_hashset(cursor, transactions_count);
			if (!hashes || hashes->empty())
				return return_ok(*from, __func__, "mempool is empty");

			format::variables hash_args;
			hash_args.reserve(hashes->size());
			hash_args.push_back(format::variable(cursor + hashes->size()));
			for (auto& item : *hashes)
				hash_args.push_back(format::variable(item));

			relayer->call(*from, &server_node::propose_mempool, std::move(hash_args));
			return return_ok(*from, __func__, "mempool proposed");
		}
		promise<void> server_node::propose_mempool(server_node* relayer, uptr<relay>&& from, format::variables&& args)
		{
			if (args.size() < 2)
				return return_abort(relayer, *from, __func__, "invalid arguments");

			uint64_t cursor = args.front().as_uint64();
			auto mempool = storages::mempoolstate(__func__);
			for (size_t i = 1; i < args.size(); i++)
			{
				auto transaction_hash = args[i].as_uint256();
				if (!mempool.has_transaction(transaction_hash))
					relayer->call(*from, &server_node::request_transaction, { format::variable(transaction_hash) });
			}

			const uint64_t transactions_count = protocol::now().user.p2p.cursor_size;
			if (args.size() > transactions_count)
				relayer->call(*from, &server_node::request_mempool, { format::variable(cursor) });

			return return_ok(*from, __func__, "mempool accepted");
		}
		promise<void> server_node::return_abort(server_node* relayer, relay* from, const char* function, const std::string_view& message)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
			{
				++peer_validator->availability.calls;
				++peer_validator->availability.errors;
			}

			relayer->reject(from);
			if (protocol::now().user.p2p.logging)
				VI_DEBUG("[p2p] validator %s call \"%s\" abort: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		promise<void> server_node::return_error(server_node* relayer, relay* from, const char* function, const std::string_view& message)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
			{
				++peer_validator->availability.calls;
				++peer_validator->availability.errors;
			}

			if (protocol::now().user.p2p.logging)
				VI_DEBUG("[p2p] validator %s call \"%s\" error: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		promise<void> server_node::return_ok(relay* from, const char* function, const std::string_view& message)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
				++peer_validator->availability.calls;

			if (protocol::now().user.p2p.logging)
				VI_DEBUG("[p2p] validator %s call \"%s\" OK: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		expects_system<void> server_node::on_unlisten()
		{
			control_sys.deactivate();
			return expectation::met;
		}
		expects_system<void> server_node::on_after_unlisten()
		{
			control_sys.shutdown().wait();
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& instance : candidate_nodes)
			{
				if (instance->net.stream != nullptr)
				{
					if (!schedule::is_available())
						instance->net.stream->set_blocking(true);
					instance->net.stream->shutdown(true);
				}
				instance->release();
			}
			candidate_nodes.clear();

		retry:
			unordered_map<void*, relay*> current_nodes;
			current_nodes.swap(nodes);
			unique.unlock();

			for (auto& node : current_nodes)
			{
				auto* outbound_instance = node.second->as_outbound_node();
				if (outbound_instance != nullptr)
					outbound_instance->release();

				relay* state = node.second;
				disconnect(state).wait();
			}

			unique.lock();
			if (!nodes.empty())
				goto retry;

			return expectation::met;
		}
		expects_lr<void> server_node::apply_validator(storages::mempoolstate& mempool, ledger::validator& node, option<ledger::wallet>&& wallet)
		{
			bool has_wallet = !!wallet;
			auto ip_address = node.address.get_ip_address();
			auto ip_port = node.address.get_ip_port();
			if (!node.address.is_valid() || !ip_address || !ip_port)
				return layer_exception("bad node address");

			bool is_local = *ip_address == "127.0.0.1";
			if (*ip_address == "0.0.0.0")
			{
				node.address = socket_address("127.0.0.1", *ip_port);
				is_local = true;
			}

			if (is_local && !has_wallet)
				return expectation::met;

			auto status = mempool.apply_validator(node, std::move(wallet));
			if (status && !has_wallet)
				discovery.count = mempool.get_validators_count().or_else(0);
			return status;
		}
		void server_node::bind_function(receive_function function, bool multicallable)
		{
			uint32_t method_index = method_address + (uint32_t)in_methods.size();
			void* function_index = (void*)function;
			in_methods[method_index] = std::make_pair(function_index, multicallable);
			out_methods[function_index] = method_index;
		}
		bool server_node::call_function(relay* state, receive_function function, format::variables&& args)
		{
			VI_ASSERT(state != nullptr, "state should be set");
			auto it = out_methods.find((void*)function);
			if (it == out_methods.end())
				return false;

			procedure next;
			next.method = it->second;
			next.args = std::move(args);
			state->push_message(std::move(next));
			return push_next_procedure(state);
		}
		size_t server_node::multicall_function(relay* state, receive_function function, format::variables&& args)
		{
			auto it = out_methods.find((void*)function);
			if (it == out_methods.end())
				return 0;

			procedure next;
			next.method = it->second;
			next.args = std::move(args);

			int64_t time = ::time(nullptr);
			uref<relay_procedure> relay_message = new relay_procedure(std::move(next));
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				if (state != node.second)
					node.second->relay_message(uref<relay_procedure>(relay_message));
			}

			size_t calls = 0;
			for (auto& node : nodes)
			{
				if (state != node.second)
					calls += push_next_procedure(node.second) ? 1 : 0;
			}
			return calls;
		}
		void server_node::accept_outbound_node(outbound_node* candidate, expects_system<void>&& status)
		{
			uptr<outbound_node> copy = candidate;
			umutex<std::recursive_mutex> unique(exclusive);
			candidate_nodes.erase(candidate);
			candidate->release();
			if (!is_active())
			{
				copy.reset();
				return;
			}

			auto* duplicate = find(candidate->get_peer_address());
			if (status && !duplicate)
			{
				relay* state = new relay(node_type::outbound, candidate);
				append_node(state, [state, candidate, this]()
				{
					pull_procedure(state, std::bind(&server_node::abort_outbound_node, this, candidate));
					receive_outbound_node(optional::none);
				});
			}
			else if (!duplicate)
			{
				auto address = std::move(candidate->state.address);
				unique.unlock();
				receive_outbound_node(std::move(address));
			}
			else
			{
				unique.unlock();
				receive_outbound_node(optional::none);
			}
		}
		void server_node::pull_procedure(relay* state, const abort_callback& abort_callback)
		{
			VI_ASSERT(state && abort_callback, "state and abort callback should be set");
			auto* stream = state->as_socket();
			if (!stream || !control_sys.enqueue())
				return;

		retry:
			if (state->pull_incoming_message(nullptr, 0))
			{
				procedure message;
				state->incoming_message_into(&message);
				if (in_methods.empty() || message.method < method_address || message.method > method_address + in_methods.size() - 1)
				{
				shutdown:
					if (control_sys.dequeue())
						abort_callback(state);
					return;
				}

				auto it = in_methods.find(message.method);
				if (it == in_methods.end())
					goto shutdown;

				if (it->second.second)
				{
					string body;
					if (!message.serialize_into(&body))
						goto shutdown;

					uint256_t hash = algorithm::hashing::hash256i(body);
					umutex<std::mutex> unique(sync.inventory);
					auto it = inventory.find(hash);
					if (it != inventory.end())
						goto retry;
					else if (inventory.size() + 1 > protocol::now().user.p2p.inventory_size)
						inventory.clear();
					inventory[hash] = time(nullptr) + protocol::now().user.p2p.inventory_timeout;
				}

				auto function = (receive_function)it->second.first;
				state->add_ref();
				return cospawn([this, state, abort_callback, function, message = std::move(message)]() mutable
				{
					(*function)(this, state, std::move(message.args)).when([this, state, abort_callback]()
					{
						if (control_sys.dequeue())
							pull_procedure(state, abort_callback);
					});
				});
			}
			else
			{
				stream->read_queued(BLOB_SIZE, [this, state, abort_callback](socket_poll event, const uint8_t* buffer, size_t size)
				{
					if (packet::is_done(event))
					{
						if (control_sys.dequeue())
							cospawn(std::bind_front(&server_node::pull_procedure, this, state, abort_callback));
					}
					else if (packet::is_error(event))
					{
						if (control_sys.dequeue())
							abort_callback(state);
					}
					else if (packet::is_data(event))
						return !state->pull_incoming_message(buffer, size);
					return true;
				});
			}
		}
		void server_node::push_procedure(relay* state, const abort_callback& abort_callback)
		{
			VI_ASSERT(state && abort_callback, "state and abort callback should be set");
			auto* stream = state->as_socket();
			if (!stream)
				return;

			if (!state->begin_outgoing_message())
				return;

			stream->write_queued(state->outgoing_buffer(), state->outgoing_size(), [this, stream, state, abort_callback](socket_poll event)
			{
				state->end_outgoing_message();
				if (packet::is_done(event))
					push_procedure(state, abort_callback);
				else if (packet::is_error(event))
					abort_callback(state);
			}, false);
		}
		void server_node::abort_inbound_node(inbound_node* node)
		{
			VI_ASSERT(node != nullptr, "node should be set");
			erase_node_by_instance(node, [this, node]()
			{
				node->abort();
				finalize(node);
			});
		}
		void server_node::abort_outbound_node(outbound_node* node)
		{
			VI_ASSERT(node != nullptr, "node should be set");
			erase_node_by_instance(node, [this, node]()
			{
				receive_outbound_node(optional::none);
				node->release();
			});
		}
		void server_node::append_node(relay* state, task_callback&& callback)
		{
			VI_ASSERT(state != nullptr && callback, "node and callback should be set");
			if (!control_sys.enqueue())
				return;

			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(state->as_instance());
			if (it == nodes.end() || it->second != state)
			{
				auto* socket = state->as_socket();
				if (socket != nullptr)
					socket->set_io_timeout(0);

				auto& node = nodes[state->as_instance()];
				memory::release(node);
				node = state;
				node->add_ref();
				unique.unlock();
				cospawn([this, state, callback = std::move(callback)]() mutable
				{
					connect(state).when([this, state, callback = std::move(callback)]() mutable
					{
						if (control_sys.dequeue())
							callback();
					});
				});
			}
			else
			{
				unique.unlock();
				if (control_sys.dequeue())
					callback();
			}
		}
		void server_node::erase_node(relay* state, task_callback&& callback)
		{
			VI_ASSERT(state != nullptr && callback, "node and callback should be set");
			erase_node_by_instance(state->as_instance(), std::move(callback));
		}
		void server_node::erase_node_by_instance(void* instance, task_callback&& callback)
		{
			VI_ASSERT(instance != nullptr && callback, "instance and callback should be set");
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			if (it == nodes.end())
				return;

			uptr<relay> state = it->second;
			nodes.erase(it);
			unique.unlock();
			if (!control_sys.enqueue())
			{
				state->invalidate();
				callback();
				return;
			}

			auto* copy = *state;
			copy->add_ref();
			cospawn([this, copy, callback = std::move(callback)]() mutable
			{
				copy->add_ref();
				disconnect(copy).when([this, copy, callback = std::move(callback)]() mutable
				{
					copy->invalidate();
					copy->release();
					if (control_sys.dequeue())
						callback();
				});
			});
		}
		void server_node::on_request_open(inbound_node* node)
		{
			VI_ASSERT(node != nullptr, "node should be set");
			if (!is_active())
				return;

			relay* state = find_node_by_instance(node);
			if (!state)
			{
				umutex<std::recursive_mutex> unique(exclusive);
				auto* duplicate = find(node->address);
				if (!duplicate)
				{
					state = new relay(node_type::inbound, node);
					append_node(state, [this, state, node]()
					{
						pull_procedure(state, std::bind(&server_node::abort_inbound_node, this, node));
					});
				}
				else
				{
					node->abort();
					finalize(node);
				}
			}
			else
				pull_procedure(state, std::bind(&server_node::abort_inbound_node, this, node));
		}
		void server_node::startup()
		{
			if (!protocol::now().user.p2p.server && !protocol::now().user.p2p.max_outbound_connections)
				return;

			socket_router* config = new socket_router();
			config->max_connections = (size_t)protocol::now().user.p2p.max_inbound_connections;
			config->socket_timeout = (size_t)protocol::now().user.tcp.timeout;
			control_sys.activate_and_enqueue();
			control_sys.dequeue();
			control_sys.interval_if_none("inventory_cleanup", protocol::now().user.p2p.inventory_cleanup_timeout, [this]()
			{
				int64_t time = ::time(nullptr);
				umutex<std::mutex> unique(sync.inventory);
				for (auto it = inventory.cbegin(); it != inventory.cend();)
				{
					if (it->second < time)
						inventory.erase(it++);
					else
						++it;
				}
			});

			uint32_t method_magic = os::hw::to_endianness(os::hw::endian::little, protocol::now().message.packet_magic);
			uint32_t method_range = (uint32_t)std::numeric_limits<int32_t>::max();
			method_address = (algorithm::hashing::hash32d((uint8_t*)&method_magic, sizeof(method_magic))) % method_range;
			if (protocol::now().user.p2p.server)
			{
				auto listener_status = config->listen(protocol::now().user.p2p.address, to_string(protocol::now().user.p2p.port));
				VI_PANIC(listener_status, "server listener error: %s", listener_status.error().what());

				auto configure_status = configure(config);
				VI_PANIC(configure_status, "server configuration error: %s", configure_status.error().what());

				auto binding_status = listen();
				VI_PANIC(binding_status, "server binding error: %s", binding_status.error().what());

				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] p2p node listen (location: %s:%i, type: %s)", protocol::now().user.p2p.address.c_str(), (int)protocol::now().user.p2p.port, protocol::now().user.p2p.max_outbound_connections > 0 ? "in-out" : "in");
			}
			else if (protocol::now().user.p2p.max_outbound_connections > 0 && protocol::now().user.p2p.logging)
				VI_INFO("[p2p] p2p node listen (type: out)");

			auto mempool = storages::mempoolstate(__func__);
			discovery.count = mempool.get_validators_count().or_else(0);

			auto main_validator = mempool.get_validator_by_ownership(0);
			if (!main_validator)
			{
				validator.wallet = ledger::wallet::from_seed(*crypto::random_bytes(512));
				validator.node.address = socket_address(protocol::now().user.p2p.address, protocol::now().user.p2p.port);
			}
			else
			{
				validator.wallet = std::move(main_validator->second);
				validator.node = std::move(main_validator->first);
			}

			validator.node.ports.p2p = protocol::now().user.p2p.port;
			validator.node.ports.nds = protocol::now().user.nds.port;
			validator.node.ports.rpc = protocol::now().user.rpc.port;
			validator.node.services.has_consensus = protocol::now().user.p2p.server;
			validator.node.services.has_discovery = protocol::now().user.nds.server;
			validator.node.services.has_synchronization = protocol::now().user.nss.server;
			validator.node.services.has_interfaces = protocol::now().user.rpc.server;
			validator.node.services.has_proposer = protocol::now().user.p2p.proposer;
			validator.node.services.has_publicity = protocol::now().user.rpc.user_username.empty();
			validator.node.services.has_streaming = protocol::now().user.rpc.web_sockets;
			apply_validator(mempool, validator.node, validator.wallet).expect("failed to save trusted validator");

			auto node_id = codec::hex_encode(std::string_view((char*)this, sizeof(this)));
			nss::server_node::get()->add_transaction_callback(node_id, std::bind(&server_node::propose_transaction_logs, this, std::placeholders::_1, std::placeholders::_2));
			console::get()->add_color_tokens({ console::color_token("CHECKPOINT SYNC DONE", std_color::white, std_color::dark_green) });

			for (auto& node : protocol::now().user.nodes)
			{
				auto endpoint = system_endpoint(node);
				if (!endpoint.is_valid() || routing::is_address_reserved(endpoint.address))
				{
					if (protocol::now().user.p2p.logging)
						VI_ERR("[p2p] pre-configured node \"%s\" connection failed: url not valid", node.c_str());
				}
				else
					mempool.apply_trial_address(endpoint.address);
			}

			bind_callable(&server_node::propose_handshake);
			bind_callable(&server_node::approve_handshake);
			bind_callable(&server_node::propose_nodes);
			bind_callable(&server_node::find_fork_collision);
			bind_callable(&server_node::verify_fork_collision);
			bind_callable(&server_node::request_fork_block);
			bind_callable(&server_node::propose_fork_block);
			bind_callable(&server_node::request_block);
			bind_callable(&server_node::request_transaction);
			bind_callable(&server_node::request_mempool);
			bind_callable(&server_node::propose_mempool);
			bind_multicallable(&server_node::propose_block);
			bind_multicallable(&server_node::propose_block_hash);
			bind_multicallable(&server_node::propose_transaction);
			bind_multicallable(&server_node::propose_transaction_hash);
			clear_mempool(false);
			accept();

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			if (tip)
				accept_dispatchpool(*tip);
		}
		void server_node::shutdown()
		{
			if (is_active() || protocol::now().user.p2p.server || protocol::now().user.p2p.max_outbound_connections)
			{
				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] p2p node shutdown requested");
			}

			if (is_active())
				unlisten(false);
		}
		void server_node::reject(relay* state)
		{
			auto* socket = state->as_socket();
			if (socket != nullptr)
				socket->shutdown(true);
		}
		void server_node::clear_pending_tip()
		{
			pending_tip.hash = 0;
			pending_tip.block = optional::none;
			if (pending_tip.timeout != INVALID_TASK_ID)
			{
				schedule::get()->clear_timeout(pending_tip.timeout);
				pending_tip.timeout = INVALID_TASK_ID;
			}
		}
		void server_node::accept_fork_tip(const uint256_t& fork_tip, const uint256_t& candidate_hash, ledger::block_header&& fork_tip_block)
		{
			if (!fork_tip)
				return;

			forks.clear();
			if (fork_tip != candidate_hash)
			{
				forks[fork_tip] = std::move(fork_tip_block);
				mempool.dirty = true;
			}
		}
		void server_node::accept_pending_tip()
		{
			umutex<std::recursive_mutex> unique(sync.block);
			if (pending_tip.block)
			{
				auto chain = storages::chainstate(__func__);
				auto tip_block = chain.get_latest_block_header();
				if (!tip_block || *tip_block < *pending_tip.block)
				{
					if (accept_block_candidate(*pending_tip.block, pending_tip.hash, 0))
						accept_dispatchpool(*pending_tip.block);
				}
			}
			clear_pending_tip();
		}
		bool server_node::clear_mempool(bool wait)
		{
			if (!protocol::now().user.p2p.proposer || is_syncing())
				return false;

			return control_sys.timeout_if_none("clear_mempool", wait ? (protocol::now().user.storage.transaction_timeout * 1000) : 0, [this]()
			{
				auto mempool = storages::mempoolstate(__func__);
				mempool.expire_transactions().report("mempool cleanup failed");
				control_sys.clear_timeout("clear_mempool");
				clear_mempool(true);
			});
		}
		bool server_node::accept_mempool()
		{
			if (!protocol::now().user.p2p.proposer || is_syncing())
				return false;

			return control_sys.timeout_if_none("accept_mempool", 0, [this]()
			{
			retry:
				if (mempool.activation_block && (!*mempool.activation_block || *mempool.activation_block <= storages::chainstate(__func__).get_latest_block_number().or_else(0)))
				{
					if (*mempool.activation_block != 0)
						mempool.activation_block = 0;

					auto priority = environment.priority(validator.wallet.public_key_hash, validator.wallet.secret_key);
					if (!priority)
					{
						auto chain = storages::chainstate(__func__);
						auto tip = chain.get_latest_block_header();
						if (tip)
						{
							int64_t delta = (int64_t)protocol::now().time.now() - tip->time;
							if (delta < 0 || (uint64_t)delta < protocol::now().policy.consensus_recovery_time)
							{
								control_sys.clear_timeout("accept_mempool");
								return;
							}
						}
					}

					size_t offset = 0, count = 512;
					auto mempool = storages::mempoolstate(__func__);
					while (is_active())
					{
						auto candidates = mempool.get_transactions(offset, count);
						offset += candidates ? environment.apply(std::move(*candidates)) : 0;
						if (count != (candidates ? candidates->size() : 0))
							break;
					}

					if (is_active() && !environment.incoming.empty())
					{
						if (protocol::now().user.p2p.logging)
						{
							if (priority)
								VI_INFO("[p2p] mempool chain extension evaluation (txns: %" PRIu64 ", priority: %" PRIu64 ")", (uint64_t)environment.incoming.size(), *priority);
							else
								VI_INFO("[p2p] mempool chain extension evaluation (txns: %" PRIu64 ", priority: recovery)", (uint64_t)environment.incoming.size());
						}

						string errors;
						auto evaluation = environment.evaluate(&errors);
						evaluation.report("mempool proposal evaluation failed");
						if (evaluation)
						{
							auto solution = environment.solve(*evaluation);
							solution.report("mempool proposal solution failed");
							if (solution)
								accept_block(nullptr, std::move(*evaluation), 0);
						}

						if (!errors.empty())
						{
							if (evaluation)
								VI_WARN("[p2p] mempool block %s acceptable evaluation error: %s", algorithm::encoding::encode_0xhex256(evaluation->as_hash()).c_str(), errors.c_str());
							else
								VI_ERR("[p2p] mempool block evaluation error: %s", errors.c_str());
						}
					}
					else if (is_active())
						environment.cleanup().report("mempool cleanup failed");
				}
				else if (!mempool.activation_block)
				{
					auto work = ledger::transaction_context().get_account_work(validator.wallet.public_key_hash);
					mempool.activation_block = work ? work->get_closest_proposal_block_number() - 1 : std::numeric_limits<uint64_t>::max();
					goto retry;
				}
				control_sys.clear_timeout("accept_mempool");
			});
		}
		bool server_node::accept_dispatchpool(const ledger::block_header& tip)
		{
			if (is_syncing())
				return false;

			return control_sys.timeout_if_none("accept_dispatchpool", 0, [this, tip]()
			{
				tip.dispatch_async(validator.wallet).when([this](expects_lr<ledger::block_dispatch>&& dispatch)
				{
					dispatch.report("dispatchpool execution failed");
					if (dispatch)
					{
						dispatch->checkpoint().report("dispatchpool checkpoint failed");
						if (!dispatch->outputs.empty())
						{
							umutex<std::recursive_mutex> unique(sync.account);
							auto account_sequence = validator.wallet.get_latest_sequence().or_else(1);
							unique.unlock();

							control_sys.lock_timeout("accept_mempool");
							for (auto& transaction : dispatch->outputs)
							{
								if (propose_transaction(nullptr, std::move(transaction), account_sequence))
									++account_sequence;
							}
							if (control_sys.unlock_timeout("accept_mempool"))
								accept_mempool();
						}
						else
							accept_mempool();
					}
					else
						accept_mempool();
					control_sys.clear_timeout("accept_dispatchpool");
				});
			});
		}
		bool server_node::accept_block(relay* from, ledger::block&& candidate_block, const uint256_t& fork_tip)
		{
			uint256_t candidate_hash = candidate_block.as_hash();
			auto verification = from ? candidate_block.verify_validity(nullptr) : environment.verify(candidate_block);
			if (!verification)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), verification.error().what());
				return false;
			}

			auto chain = storages::chainstate(__func__);
			if (chain.get_block_header_by_hash(candidate_hash))
			{
				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] block %s branch confirmed", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
				return true;
			}

			auto fork_tip_block = ledger::block_header();
			if (fork_tip > 0)
			{
				umutex<std::recursive_mutex> unique(sync.block);
				auto it = forks.find(fork_tip);
				if (it == forks.end())
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("[p2p] block %s branch averted: fork reverted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					return false;
				}
				fork_tip_block = it->second;
			}

			auto tip_block = fork_tip > 0 ? expects_lr<ledger::block_header>(fork_tip_block) : chain.get_latest_block_header();
			auto tip_hash = tip_block ? tip_block->as_hash() : (uint256_t)0;
			auto best_tip_work = tip_block ? tip_block->absolute_work : (uint256_t)0;
			auto parent_block = tip_hash == candidate_block.parent_hash ? tip_block : chain.get_block_header_by_hash(candidate_block.parent_hash);
			auto parent_hash = parent_block ? parent_block->as_hash() : (uint256_t)0;
			int64_t branch_length = (int64_t)candidate_block.number - (int64_t)(tip_block ? tip_block->number : 0);
			branch_length = fork_tip > 0 ? abs(branch_length) : branch_length;
			if (branch_length < 0 || (!fork_tip && candidate_block.absolute_work < best_tip_work))
			{
				/*
													  <+> - <+> - <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
											   \
												<+> = ignore (smaller branch)
				*/
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] block %s branch averted: not preferred %s (length: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), branch_length < 0 ? "branch" : "difficulty", branch_length);
				return false;
			}
			else if (branch_length == 0 && tip_block && tip_hash != candidate_hash && candidate_block < *tip_block)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] block %s branch averted: not preferred difficulty", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
				return false;
			}
			else if (!parent_block && candidate_block.number > 1)
			{
				if (!from)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("[p2p] block %s branch averted: not preferred candidate", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					return false;
				}

				umutex<std::recursive_mutex> unique(sync.block);
				bool has_better_tip = forks.empty();
				for (auto& fork_candidate_tip : forks)
				{
					if (fork_candidate_tip.second < candidate_block)
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
					if (protocol::now().user.p2p.logging)
					{
						if (forks.find(candidate_hash) != forks.end())
							VI_INFO("[p2p] block %s new best branch confirmed", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
						else
							VI_WARN("[p2p] block %s branch averted: not preferred orpan branch", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
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
				forks[candidate_hash] = candidate_block;
				mempool.dirty = true;
				unique.unlock();
				if (!tip_block)
					call(from, &server_node::request_fork_block, { format::variable(candidate_hash), format::variable(uint256_t(0)), format::variable((uint64_t)1) });
				else
					call(from, &server_node::find_fork_collision, { format::variable(candidate_hash), format::variable(tip_block->number) });

				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] block %s new best branch found (height: %" PRIu64 ", distance: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), candidate_block.number, std::abs((int64_t)(tip_block ? tip_block->number : 0) - (int64_t)candidate_block.number));
				return true;
			}

			if (from != nullptr)
			{
				ledger::block evaluated_block;
				auto validation = candidate_block.validate(parent_block.address(), &evaluated_block);
				if (!validation)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("[p2p] block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), validation.error().what());
					return false;
				}

				candidate_block = std::move(evaluated_block);
			}
			else
			{
				auto integrity = candidate_block.verify_integrity(parent_block.address());
				if (!integrity)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("[p2p] block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), integrity.error().what());
					return false;
				}
			}

			umutex<std::recursive_mutex> unique(sync.block);
			if (!fork_tip && candidate_block.priority != 0 && (branch_length == 0 || branch_length == 1))
			{
				/*
					<+> - <+> - <+> - <+> - <+> - <+> = extension (non-zero priority, possible fork, wait for zero priority block)
				*/
				if (pending_tip.block)
				{
					if (pending_tip.hash == candidate_hash)
					{
						if (protocol::now().user.p2p.logging)
							VI_INFO("[p2p] block %s branch confirmed", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
						return true;
					}
					else if (candidate_block < *pending_tip.block)
					{
						if (protocol::now().user.p2p.logging)
							VI_WARN("[p2p] block %s branch averted: not preferred priority", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
						return false;
					}
				}

				pending_tip.block = std::move(candidate_block);
				pending_tip.hash = candidate_hash;
				pending_tip.timeout = schedule::get()->set_timeout(protocol::now().policy.consensus_proof_time, std::bind(&server_node::accept_pending_tip, this));

				size_t multicalls = from ? multicall(from, &server_node::propose_block_hash, { format::variable(pending_tip.hash) }) : multicall(from, &server_node::propose_block, { format::variable(pending_tip.block->as_message().data) });
				if (multicalls > 0 && protocol::now().user.p2p.logging)
					VI_INFO("[p2p] block %s broadcasted to %i nodes (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)multicalls, candidate_block.number);

				accept_fork_tip(fork_tip, candidate_hash, std::move(fork_tip_block));
			}
			else
			{
				/*
					<+> - <+> - <+> - <+> - <+> - <+> = possible extension
											   \
												<+> - <+> = possible reorganization
				*/
				if (!accept_block_candidate(candidate_block, candidate_hash, fork_tip))
					return false;

				size_t multicalls = from ? multicall(from, &server_node::propose_block_hash, { format::variable(candidate_hash) }) : multicall(from, &server_node::propose_block, { format::variable(candidate_block.as_message().data) });
				if (multicalls > 0 && protocol::now().user.p2p.logging)
					VI_INFO("[p2p] block %s broadcasted to %i nodes (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)multicalls, candidate_block.number);

				accept_fork_tip(fork_tip, candidate_hash, std::move(fork_tip_block));
				accept_dispatchpool(candidate_block);
				clear_pending_tip();
				if (from != nullptr && mempool.dirty && !is_syncing())
				{
					call(from, &server_node::request_mempool, { format::variable((uint64_t)0) });
					mempool.dirty = false;
				}
			}

			return true;
		}
		bool server_node::accept_block_candidate(const ledger::block& candidate_block, const uint256_t& candidate_hash, const uint256_t& fork_tip)
		{
			auto mutation = candidate_block.checkpoint();
			if (!mutation)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] block %s checkpoint failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation.error().what());
				return false;
			}

			if (protocol::now().user.p2p.logging)
			{
				double progress = get_sync_progress(fork_tip, candidate_block.number);
				if (mutation->is_fork)
					VI_INFO("[p2p] block %s chain forked (height: %" PRIu64 ", mempool: %" PRIu64 ", block-delta: " PRIi64 ", transaction-delta: " PRIi64 ", state-delta: " PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->old_tip_block_number, mutation->mempool_transactions, mutation->block_delta, mutation->transaction_delta, mutation->state_delta);
				VI_INFO("[p2p] block %s chain %s (height: %" PRIu64 ", sync: %.2f%%, priority: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->is_fork ? "shortened" : "extended", candidate_block.number, 100.0 * progress, candidate_block.priority);
			}

			if (events.accept_block)
				events.accept_block(candidate_hash, candidate_block, *mutation);

			for (auto& transaction : candidate_block.transactions)
			{
				if (!memcmp(transaction.receipt.from, validator.wallet.public_key_hash, sizeof(algorithm::pubkeyhash)))
					accept_proposal_transaction(candidate_block, transaction);
			}

			return true;
		}
		bool server_node::accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction)
		{
			uint32_t type = transaction.transaction->as_type();
			auto purpose = transaction.transaction->as_typename();
			if (type == transactions::commitment::as_instance_type())
			{
				mempool.activation_block = optional::none;
				if (transaction.receipt.successful)
				{
					if (protocol::now().user.p2p.logging)
					{
						auto work = ledger::transaction_context().get_account_work(validator.wallet.public_key_hash);
						bool online = work && work->is_matching(states::account_flags::online);
						VI_INFO("[p2p] transaction %s %.*s finalized (%s%s%s)",
							algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(),
							online ? (work->is_online() ? "online" : "submit again") : "offline", online ? " after block " : "", online ? to_string(work->get_closest_proposal_block_number() - 1).c_str() : "");
					}
					accept_mempool();
				}
				else if (protocol::now().user.p2p.logging)
					VI_ERR("[p2p] transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			else if (protocol::now().user.p2p.logging)
			{
				if (transaction.receipt.successful)
					VI_INFO("[p2p] transaction %s %.*s finalized", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				else
					VI_ERR("[p2p] transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			return true;
		}
		bool server_node::accept(option<socket_address>&& address)
		{
			if (address && routing::is_address_reserved(*address))
				return false;

			return address ? connect_outbound_node(*address) : receive_outbound_node(optional::none);
		}
		expects_lr<void> server_node::propose_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, uint64_t account_sequence, uint256_t* output_hash)
		{
			auto mempool = storages::mempoolstate(__func__);
			auto bandwidth = mempool.get_bandwidth_by_owner(validator.wallet.public_key_hash, candidate_tx->get_type());
			if (bandwidth->congested)
			{
				auto price = mempool.get_gas_price(candidate_tx->asset, 0.10);
				candidate_tx->set_optimal_gas(price.or_else(decimal::zero()));
			}
			else
				candidate_tx->set_optimal_gas(decimal::zero());

			auto purpose = candidate_tx->as_typename();
			if (candidate_tx->sign(validator.wallet.secret_key, account_sequence, decimal::zero()))
			{
				if (output_hash != nullptr)
					*output_hash = candidate_tx->as_hash();

				auto status = accept_transaction(from, std::move(candidate_tx), account_sequence);
				if (protocol::now().user.p2p.logging && !status)
					VI_ERR("[p2p] transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data(), status.error().what());
				else if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				return status;
			}
			else
			{
				auto status = layer_exception("transaction sign failed");
				if (protocol::now().user.p2p.logging)
					VI_ERR("[p2p] transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data(), status.what());
				return status;
			}
		}
		expects_lr<void> server_node::accept_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto chain = storages::chainstate(__func__);
			if (chain.get_transaction_by_hash(candidate_hash))
			{
				if (protocol::now().user.p2p.logging)
					VI_INFO("[p2p] transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return expectation::met;
			}

			algorithm::pubkeyhash owner;
			if (!candidate_tx->recover_hash(owner))
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] transaction %s %.*s validation failed: invalid signature", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("signature key recovery failed");
			}

			algorithm::pubkeyhash validation_owner;
			auto validation = ledger::transaction_context::validate_tx(*candidate_tx, candidate_hash, validation_owner);
			if (!validation)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] transaction %s %.*s validation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
				return validation.error();
			}

			bool event = candidate_tx->is_consensus() && !memcmp(validator.wallet.public_key_hash, owner, sizeof(owner));
			if (event || validate_execution)
			{
				ledger::block temp_block;
				temp_block.number = std::numeric_limits<int64_t>::max() - 1;

				ledger::evaluation_context temp_environment;
				memcpy(temp_environment.proposer.public_key_hash, validator.wallet.public_key_hash, sizeof(algorithm::pubkeyhash));

				ledger::block_work cache;
				size_t transaction_size = candidate_tx->as_message().data.size();
				auto validation = ledger::transaction_context::execute_tx(&temp_block, &temp_environment, *candidate_tx, candidate_hash, owner, cache, transaction_size, (uint8_t)ledger::transaction_context::execution_flags::only_successful);
				if (!validation)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("[p2p] transaction %s %.*s pre-execution failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
					return validation.error();
				}
			}

			return broadcast_transaction(from, std::move(candidate_tx), owner);
		}
		expects_lr<void> server_node::broadcast_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, const algorithm::pubkeyhash owner)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto mempool = storages::mempoolstate(__func__);
			auto status = mempool.add_transaction(**candidate_tx);
			if (!status)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("[p2p] transaction %s %.*s mempool rejection: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), status.error().what());
				return status.error();
			}

			if (protocol::now().user.p2p.logging)
				VI_INFO("[p2p] transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());

			if (events.accept_transaction)
				events.accept_transaction(candidate_hash, *candidate_tx, owner);

			size_t multicalls = from ? multicall(from, &server_node::propose_transaction_hash, { format::variable(candidate_hash) }) : multicall(from, &server_node::propose_transaction, { format::variable(candidate_tx->as_message().data) });
			if (multicalls > 0 && protocol::now().user.p2p.logging)
				VI_INFO("[p2p] transaction %s %.*s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), (int)multicalls);

			accept_mempool();
			return expectation::met;
		}
		bool server_node::receive_outbound_node(option<socket_address>&& error_address)
		{
			auto& peer = protocol::now().user.p2p;
			umutex<std::recursive_mutex> unique(exclusive);
			size_t current_outbound_nodes = size_of(node_type::outbound) + candidate_nodes.size();
			if (!is_active() || current_outbound_nodes >= peer.max_outbound_connections)
				return false;

			unique.unlock();
			if (!control_sys.enqueue())
				return false;

			control_sys.clear_timeout("node_rediscovery");
			cospawn([this, error_address = std::move(error_address)]() mutable
			{
				connect_node_from_mempool(std::move(error_address), true).when([this](option<socket_address>&& address)
				{
					if (!control_sys.dequeue())
						return;

					if (address)
					{
						int32_t status = connect_outbound_node(*address);
						if (status == -1)
							receive_outbound_node(std::move(address));
						else if (status == 0)
							receive_outbound_node(optional::none);
					}
					else
						control_sys.timeout_if_none("node_rediscovery", protocol::now().user.p2p.rediscovery_timeout, [this]() { accept(); });
				});
			});
			return true;
		}
		bool server_node::push_next_procedure(relay* state)
		{
			switch (state->type_of())
			{
				case node_type::inbound:
				{
					auto* node = state->as_inbound_node();
					if (!node || !control_sys.enqueue())
						return false;

					codefer([this, state, node]()
					{
						if (control_sys.dequeue())
							push_procedure(state, std::bind(&server_node::abort_inbound_node, this, node));
					});
					return true;
				}
				case node_type::outbound:
				{
					auto* node = state->as_outbound_node();
					if (!node || !control_sys.enqueue())
						return false;

					codefer([this, state, node]()
					{
						if (control_sys.dequeue())
							push_procedure(state, std::bind(&server_node::abort_outbound_node, this, node));
					});
					return true;
				}
				default:
					return false;
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
			return it != forks.end() ? (current_number <= it->second.number ? (double)current_number / (double)it->second.number : 1.0) : 1.0;
		}
		const unordered_map<void*, relay*>& server_node::get_nodes() const
		{
			return nodes;
		}
		const unordered_set<outbound_node*>& server_node::get_candidate_nodes() const
		{
			return candidate_nodes;
		}
		const single_queue<uref<relay_procedure>>& server_node::get_messages() const
		{
			return messages;
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!protocol::now().user.p2p.server && !protocol::now().user.p2p.max_outbound_connections)
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
		relay* server_node::find(const socket_address& address)
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

			for (auto& listener : listeners)
			{
				if (*listener->address.get_ip_address() == *ip_address)
					return (relay*)this;
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
		int32_t server_node::connect_outbound_node(const socket_address& address)
		{
			auto ip_address = address.get_ip_address();
			if (!ip_address)
				return -1;

			auto& peer = protocol::now().user.p2p;
			umutex<std::recursive_mutex> unique(exclusive);
			size_t current_outbound_nodes = candidate_nodes.size();
			if (current_outbound_nodes >= peer.max_outbound_connections)
				return 1;

			for (auto& node : candidate_nodes)
			{
				auto peer_ip_address = node->state.address.get_ip_address();
				if (peer_ip_address && *peer_ip_address == *ip_address)
					return 0;
			}

			for (auto& node : nodes)
			{
				auto* instance = node.second->as_outbound_node();
				if (!instance)
					continue;

				++current_outbound_nodes;
				if (node.second->peer_address() == *ip_address)
					return 0;
			}

			outbound_node* node = new outbound_node();
			candidate_nodes.insert(node);
			node->add_ref();
			node->connect_queued(address, true, PEER_NOT_SECURE, std::bind(&server_node::accept_outbound_node, this, node, std::placeholders::_1));
			return 1;
		}
		relay* server_node::find_node_by_instance(void* instance)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			return it != nodes.end() ? it->second : nullptr;
		}
		std::string_view server_node::node_type_of(relay* from)
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

		bool routing::is_address_reserved(const socket_address& address)
		{
			if (protocol::now().is(network_type::regtest))
				return false;

			auto value = address.get_ip_value();
			if (!value)
				return false;

			static std::array<socket_cidr, 20> reserved_ips =
			{
				*vitex::network::utils::parse_address_mask("0.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("10.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("100.64.0.0/10"),
				*vitex::network::utils::parse_address_mask("127.0.0.0/8"),
				*vitex::network::utils::parse_address_mask("169.254.0.0/16"),
				*vitex::network::utils::parse_address_mask("172.16.0.0/12"),
				*vitex::network::utils::parse_address_mask("192.0.0.0/24"),
				*vitex::network::utils::parse_address_mask("192.0.2.0/24"),
				*vitex::network::utils::parse_address_mask("192.168.0.0/16"),
				*vitex::network::utils::parse_address_mask("198.18.0.0/15"),
				*vitex::network::utils::parse_address_mask("198.51.100.0/24"),
				*vitex::network::utils::parse_address_mask("233.252.0.0/24"),
				*vitex::network::utils::parse_address_mask("255.255.255.255/32"),
				*vitex::network::utils::parse_address_mask("::/128"),
				*vitex::network::utils::parse_address_mask("::1/128"),
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
	}
}
