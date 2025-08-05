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
		static bool save_inventory(unordered_set<uint256_t>& inventory, const uint256_t& hash)
		{
			auto it = inventory.find(hash);
			if (it != inventory.end())
				return false;
			else if (inventory.size() + 1 > protocol::now().user.p2p.inventory_size)
				inventory.clear();

			inventory.insert(hash);
			return true;
		}
		static format::variables serialize_procedure_response(const algorithm::seckey secret_key, format::variables&& args)
		{
			format::wo_stream buffer;
			format::variables_util::serialize_flat_into(args, &buffer);

			algorithm::recpubsig signature;
			algorithm::signing::sign(buffer.hash(), secret_key, signature);

			format::variables result;
			result.reserve(args.size() + 1);
			result.push_back(format::variable(algorithm::recpubsig_t(signature).optimized_view()));
			result.insert(result.end(), std::make_move_iterator(args.begin()), std::make_move_iterator(args.end()));
			return result;
		}
		static bool deserialize_procedure_response(const uint256_t& target_transaction_hash, const algorithm::pubkeyhash_t& target_owner, const p2p::procedure& message)
		{
			if (message.args.size() < 3)
				return false;

			auto message_transaction_hash = message.args[1].as_uint256();
			if (message_transaction_hash != target_transaction_hash)
				return false;

			format::wo_stream buffer;
			if (!format::variables_util::serialize_flat_into(format::variables(message.args.begin() + 1, message.args.end()), &buffer))
				return false;

			algorithm::pubkeyhash message_owner;
			algorithm::recpubsig_t signature = algorithm::recpubsig_t(message.args[0].as_blob());
			return algorithm::signing::recover_hash(buffer.hash(), message_owner, signature.data) && target_owner.equals(message_owner);
		}

		bool procedure::serialize_into(string* result)
		{
			VI_ASSERT(result != nullptr, "result should be set");
			format::wo_stream stream;
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

			format::ro_stream stream = format::ro_stream(body);
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
		uint256_t procedure::as_hash()
		{
			string body;
			serialize_into(&body);
			return algorithm::hashing::hash256i(body);
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
		bool relay::relay_message(uref<relay_procedure>&& message, const uint256_t& message_hash)
		{
			umutex<std::mutex> unique(mutex);
			if (!save_inventory(inventory, message_hash))
				return false;

			priority_messages.push(std::move(message));
			return true;
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
		unordered_set<uint256_t>& relay::get_inventory()
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
			return type == node_type::inbound ? (inbound_node*)instance : nullptr;
		}
		outbound_node* relay::as_outbound_node()
		{
			return type == node_type::outbound ? (outbound_node*)instance : nullptr;
		}
        vitex::network::socket* relay::as_socket()
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
			clear_pending_fork(nullptr);
		}
		expects_promise_rt<format::variables> server_node::call_responsive(receive_function function, format::variables&& args, uint64_t timeout_ms, response_callback&& callback)
		{
			if (!is_active())
				return expects_promise_rt<format::variables>(remote_exception::shutdown());

			if (!multicall(nullptr, function, std::move(args)))
				return expects_promise_rt<format::variables>(remote_exception::retry());

			umutex<std::recursive_mutex> unique(exclusive);
			size_t id; do { id = math64u::random() % std::numeric_limits<size_t>::max(); } while (responses.find(id) != responses.end());
			auto& response = responses[id];
			auto& result = response.result;
			response.callback = std::move(callback);
			response.timeout = schedule::get()->set_timeout(timeout_ms, [this, id, result]() mutable
			{
				result.set(remote_exception::retry());
				umutex<std::recursive_mutex> unique(exclusive);
				responses.erase(id);
			});
			return result;
		}
		promise<option<socket_address>> server_node::find_node_from_mempool(option<socket_address>&& error_address, bool allow_seeding)
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
					VI_WARN("peer %s:%i channel skip: host not reachable", error_address->get_ip_address().or_else("[bad_address]").c_str(), (int)error_address->get_ip_port().or_else(0));
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
					VI_DEBUG("peer %s:%i channel try: possibly candidate node", next_trial_address->get_ip_address().or_else(string("[bad_address]")).c_str(), (int)next_trial_address->get_ip_port().or_else(0));

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
				VI_DEBUG("peer %s:%i channel try: previosly connected node", next_validator->address.get_ip_address().or_else(string("[bad_address]")).c_str(), (int)next_validator->address.get_ip_port().or_else(0));

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
							VI_INFO("seed %s %sresults found (addresses: %" PRIu64 ")", seed.c_str(), results > 0 ? "" : "no ", (uint64_t)results);
						else
							VI_WARN("seed %s no results found: bad seed", seed.c_str());
					}
				}

				coreturn find_node_from_mempool(optional::none, false);
			});
		}
		promise<void> server_node::propose_transaction_logs(const algorithm::asset_id& asset, const warden::chain_supervisor_options& options, warden::transaction_logs&& logs)
		{
			auto context = ledger::transaction_context();
			for (auto& receipt : logs.transactions)
			{
				auto collision = context.get_witness_transaction(asset, receipt.transaction_id);
				if (!collision)
				{
					auto transaction = uptr<transactions::depository_transaction>(memory::init<transactions::depository_transaction>());
					transaction->set_computed_witness(receipt);
					accept_unsigned_transaction(nullptr, std::move(*transaction), nullptr);
					if (protocol::now().user.p2p.logging)
						VI_INFO("%s warden transaction %s accepted (status: %s)", algorithm::asset::name_of(asset).c_str(), receipt.transaction_id.c_str(), receipt.is_mature(asset) ? "finalized" : "pending");
				}
			}
			return promise<void>::null();
		}
		promise<void> server_node::internal_connect(uref<relay>&& from)
		{
			call(*from, &methods::propose_handshake, { format::variable(validator.node.as_message().data), format::variable(protocol::now().time.now_cpu()) });
			return methods::returning::ok(*from, __func__, "initiate handshake");
		}
		promise<void> server_node::internal_disconnect(uref<relay>&& from)
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
				VI_INFO("validator %s channel shutdown (%s %s)", from->peer_address().c_str(), routing::node_type_of(*from).data(), from->peer_service().c_str());

			return methods::returning::ok(*from, __func__, "approve shutdown");
		}
		expects_system<void> server_node::on_unlisten()
		{
			control_sys.deactivate();
			return expectation::met;
		}
		expects_system<void> server_node::on_after_unlisten()
		{
			umutex<std::recursive_mutex> unique(exclusive);
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
				internal_disconnect(state).wait();
			}

			unique.lock();
			if (!nodes.empty())
				goto retry;

			auto* queue = schedule::get();
			for (auto& response : responses)
			{
				queue->clear_timeout(response.second.timeout);
				response.second.result.set(remote_exception::shutdown());
			}

			responses.clear();
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
		expects_lr<void> server_node::accept_unsigned_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, uint64_t* account_nonce, uint256_t* output_hash)
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

			if (!candidate_tx->sign(validator.wallet.secret_key, account_nonce ? *account_nonce : 0, decimal::zero()))
			{
				auto purpose = candidate_tx->as_typename();
				if (protocol::now().user.p2p.logging)
					VI_ERR("transaction %s %.*s error: authentification error", algorithm::encoding::encode_0xhex256(candidate_tx->as_hash()).c_str(), (int)purpose.size(), purpose.data());

				return layer_exception("authentification error");
			}

			auto status = accept_transaction(from, std::move(candidate_tx), true);
			if (!status)
				return status;

			if (account_nonce != nullptr && *account_nonce == candidate_tx->nonce)
				++(*account_nonce);

			if (output_hash != nullptr)
				*output_hash = candidate_tx->as_hash();

			return status;
		}
		expects_lr<void> server_node::accept_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution)
		{
			auto purpose = candidate_tx->as_typename();
			auto candidate_hash = candidate_tx->as_hash();
			auto chain = storages::chainstate(__func__);
			if (chain.get_transaction_by_hash(candidate_hash))
			{
				if (protocol::now().user.p2p.logging)
					VI_INFO("transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return expectation::met;
			}

			algorithm::pubkeyhash owner = { 0 };
			if (candidate_tx->is_recoverable() && !candidate_tx->recover_hash(owner))
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("transaction %s %.*s validation failed: invalid signature", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());
				return layer_exception("signature key recovery failed");
			}

			algorithm::pubkeyhash validation_owner;
			auto validation = ledger::transaction_context::validate_tx(*candidate_tx, candidate_hash, validation_owner);
			if (!validation)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("transaction %s %.*s validation failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
				return validation.error();
			}

			bool event = candidate_tx->is_consensus() && !memcmp(validator.wallet.public_key_hash, owner, sizeof(owner));
			if (event || validate_execution)
			{
				ledger::block temp_block;
				temp_block.number = std::numeric_limits<int64_t>::max() - 1;

				ledger::evaluation_context temp_environment;
				memcpy(temp_environment.validator.public_key_hash, validator.wallet.public_key_hash, sizeof(algorithm::pubkeyhash));

				ledger::block_changelog temp_changelog;
				size_t transaction_size = candidate_tx->as_message().data.size();
				auto validation = ledger::transaction_context::execute_tx(&temp_environment, &temp_block, &temp_changelog, *candidate_tx, candidate_hash, owner, transaction_size, (uint8_t)ledger::transaction_context::execution_mode::pedantic);
				if (!validation)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("transaction %s %.*s pre-execution failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), validation.error().what());
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
			auto action = mempool.add_transaction(**candidate_tx, false);
			if (!action)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("transaction %s %.*s mempool rejection: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), action.error().what());
				return action.error();
			}

			if (protocol::now().user.p2p.logging)
				VI_INFO("transaction %s %.*s accepted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data());

			if (events.accept_transaction)
				events.accept_transaction(candidate_hash, *candidate_tx, owner);

			size_t multicalls = from ? multicall(from, &methods::propose_transaction_hash, { format::variable(candidate_hash) }) : multicall(nullptr, &methods::propose_transaction, { format::variable(candidate_tx->as_message().data) });
			if (multicalls > 0 && protocol::now().user.p2p.logging)
				VI_DEBUG("transaction %s %.*s broadcasted to %i nodes", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)purpose.size(), purpose.data(), (int)multicalls);

			accept_mempool(0);
			return expectation::met;
		}
		expects_lr<void> server_node::accept_validator_wallet(option<ledger::wallet>&& wallet)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			auto mempool = storages::mempoolstate(__func__);
			auto main_validator = mempool.get_validator_by_ownership(0);
			if (!main_validator)
			{
				validator.node.address = socket_address(protocol::now().user.p2p.address, protocol::now().user.p2p.port);
				if (wallet)
					validator.wallet = std::move(*wallet);
				else
					validator.wallet = ledger::wallet::from_seed(*crypto::random_bytes(512));
			}
			else
			{
				validator.node = std::move(main_validator->first);
				if (wallet)
					validator.wallet = std::move(*wallet);
				else
					validator.wallet = std::move(main_validator->second);
			}

			fill_validator_services();
			validator.node.ports.p2p = protocol::now().user.p2p.port;
			validator.node.ports.nds = protocol::now().user.nds.port;
			validator.node.ports.rpc = protocol::now().user.rpc.port;
			validator.node.services.has_consensus = protocol::now().user.p2p.server;
			validator.node.services.has_discovery = protocol::now().user.nds.server;
			validator.node.services.has_synchronization = protocol::now().user.nss.server;
			validator.node.services.has_interfaces = protocol::now().user.rpc.server;
			validator.node.services.has_querying = protocol::now().user.rpc.user_username.empty();
			validator.node.services.has_streaming = protocol::now().user.rpc.web_sockets;
			
			auto result = apply_validator(mempool, validator.node, validator.wallet);
			if (result)
				VI_INFO("p2p using account: %s (validator)", validator.wallet.get_address().c_str());
			return result;
		}
		void server_node::bind_callable(receive_function function)
		{
			uint32_t method_index = method_address + (uint32_t)in_methods.size();
			void* function_index = (void*)function;
			in_methods[method_index] = std::make_pair(function_index, false);
			out_methods[function_index] = method_index;
		}
		void server_node::bind_multicallable(receive_function function)
		{
			uint32_t method_index = method_address + (uint32_t)in_methods.size();
			void* function_index = (void*)function;
			in_methods[method_index] = std::make_pair(function_index, true);
			out_methods[function_index] = method_index;
		}
		bool server_node::call(relay* state, receive_function function, format::variables&& args)
		{
			VI_ASSERT(state != nullptr, "state should be set");
			auto it = out_methods.find((void*)function);
			if (it == out_methods.end())
				return false;

			procedure next;
			next.method = it->second;
			next.args = std::move(args);
			return call(state, std::move(next));
		}
		bool server_node::call(relay* state, procedure&& message)
		{
			VI_ASSERT(state != nullptr, "state should be set");
			state->push_message(std::move(message));
			return push_next_procedure(state);
		}
		size_t server_node::multicall(relay* state, receive_function function, format::variables&& args)
		{
			auto it = out_methods.find((void*)function);
			if (it == out_methods.end())
				return 0;

			procedure next;
			next.method = it->second;
			next.args = std::move(args);
			return multicall(state, std::move(next));
		}
		size_t server_node::multicall(relay* state, procedure&& message)
		{
			size_t calls = 0;
			uint256_t hash = message.as_hash();
			uref<relay_procedure> relay_message = new relay_procedure(std::move(message));
			umutex<std::recursive_mutex> unique(exclusive);
			for (auto& node : nodes)
			{
				if (state != node.second)
				{
					if (node.second->relay_message(uref<relay_procedure>(relay_message), hash))
						calls += push_next_procedure(node.second) ? 1 : 0;
				}
			}
			return calls;
		}
		void server_node::accept_outbound_node(uptr<outbound_node>&& candidate, expects_system<void>&& status)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			if (!is_active())
				return;

			auto* duplicate = find(candidate->get_peer_address());
			if (status && !duplicate)
			{
				auto* ref = candidate.reset();
				relay* state = new relay(node_type::outbound, ref);
				append_node(state, [state, ref, this]()
				{
					pull_procedure(state, std::bind(&server_node::abort_outbound_node, this, ref));
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
			if (!stream)
				return;
		retry:
			if (state->pull_incoming_message(nullptr, 0))
			{
				procedure message;
				state->incoming_message_into(&message);
				if (message.method == message.magic)
				{
					bool broadcast_further = true;
					umutex<std::recursive_mutex> unique(exclusive);
					for (auto it = responses.begin(); it != responses.end();)
					{
						auto& response = it->second;
						if (response.callback(message))
						{
							broadcast_further = false;
							response.result.set(message.args);
							it = responses.erase(it);
						}
						else
							++it;
					}
					if (broadcast_further)
						multicall(state, std::move(message));
					goto retry;
				}
				else if (in_methods.empty() || message.method < method_address || message.method > method_address + in_methods.size() - 1)
				{
				shutdown:
					abort_callback(state);
					return;
				}

				auto it = in_methods.find(message.method);
				if (it == in_methods.end())
					goto shutdown;

				if (it->second.second)
				{
					uint256_t hash = message.as_hash();
					umutex<std::mutex> unique(sync.inventory);
					if (!save_inventory(inventory, hash) || !save_inventory(state->get_inventory(), hash))
						goto retry;
				}

				auto function = (receive_function)it->second.first;
				auto copy = uref(state);
				copy->add_ref();
				return cospawn([this, abort_callback, function, copy = std::move(copy), message = std::move(message)]() mutable
				{
					auto* state = *copy;
					(*function)(this, std::move(copy), std::move(message)).when(std::bind(&server_node::pull_procedure, this, state, abort_callback));
				});
			}
			else
			{
				stream->read_queued(BLOB_SIZE, [this, state, abort_callback](socket_poll event, const uint8_t* buffer, size_t size)
				{
					if (packet::is_done(event))
						cospawn(std::bind_front(&server_node::pull_procedure, this, state, abort_callback));
					else if (packet::is_error(event))
						abort_callback(state);
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

				auto copy = uref(state);
				copy->add_ref();
				unique.unlock();
				cospawn([this, copy = std::move(copy), callback = std::move(callback)]() mutable { internal_connect(std::move(copy)).when(std::move(callback)); });
			}
			else
			{
				unique.unlock();
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

			uref<relay> state = it->second;
			clear_pending_fork(*state);
			state->add_ref();

			nodes.erase(it);
			unique.unlock();
			cospawn([this, state = std::move(state), callback = std::move(callback)]() mutable
			{
				uref<relay> copy = state;
				internal_disconnect(std::move(state)).when([this, copy = std::move(copy), callback = std::move(callback)]() mutable
				{
					copy->invalidate();
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
			control_sys.activate();

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
					VI_INFO("p2p node listen (location: %s:%i, type: %s)", protocol::now().user.p2p.address.c_str(), (int)protocol::now().user.p2p.port, protocol::now().user.p2p.max_outbound_connections > 0 ? "in-out" : "in");
			}
			else if (protocol::now().user.p2p.max_outbound_connections > 0 && protocol::now().user.p2p.logging)
				VI_INFO("p2p node listen (type: out)");

			auto node_id = codec::hex_encode(std::string_view((char*)this, sizeof(this)));
			nss::server_node::get()->add_transaction_callback(node_id, std::bind(&server_node::propose_transaction_logs, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
			console::get()->add_colorization("CHECKPOINT SYNC DONE", std_color::white, std_color::dark_green);

			auto mempool = storages::mempoolstate(__func__);
			discovery.count = mempool.get_validators_count().or_else(0);
			accept_validator_wallet(optional::none).expect("failed to save trusted validator");

			for (auto& node : protocol::now().user.nodes)
			{
				auto endpoint = system_endpoint(node);
				if (!endpoint.is_valid() || routing::is_address_reserved(endpoint.address))
				{
					if (protocol::now().user.p2p.logging)
						VI_ERR("pre-configured node \"%s\" connection failed: url not valid", node.c_str());
				}
				else
					mempool.apply_trial_address(endpoint.address);
			}

			bind_callable(&methods::propose_handshake);
			bind_callable(&methods::approve_handshake);
			bind_callable(&methods::propose_nodes);
			bind_callable(&methods::find_fork_collision);
			bind_callable(&methods::verify_fork_collision);
			bind_callable(&methods::request_fork_block);
			bind_callable(&methods::propose_fork_block);
			bind_callable(&methods::request_block);
			bind_callable(&methods::request_transaction);
			bind_callable(&methods::request_mempool);
			bind_callable(&methods::propose_mempool);
			bind_multicallable(&methods::propose_block);
			bind_multicallable(&methods::propose_block_hash);
			bind_multicallable(&methods::propose_transaction);
			bind_multicallable(&methods::propose_transaction_hash);
			bind_multicallable(&dispatch_context::calculate_group_public_key_remote);
			bind_multicallable(&dispatch_context::calculate_group_signature_remote);
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
					VI_INFO("p2p node shutdown");
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
		void server_node::clear_pending_fork(relay* state)
		{
			auto* queue = schedule::get();
			umutex<std::recursive_mutex> unique(sync.block);
			if (state != nullptr)
			{
				for (auto it = forks.cbegin(); it != forks.cend();)
				{
					if (state == *it->second.state)
					{
						if (it->second.timeout != INVALID_TASK_ID)
							queue->clear_timeout(it->second.timeout);
						it = forks.erase(it);
					}
					else
						++it;
				}
			}
			else
			{
				for (auto& fork : forks)
				{
					if (fork.second.timeout != INVALID_TASK_ID)
						queue->clear_timeout(fork.second.timeout);
				}
				forks.clear();
			}
		}
		void server_node::accept_pending_fork(relay* state, fork_head head, const uint256_t& candidate_hash, ledger::block_header&& candidate_block)
		{
			if (!state || !candidate_hash)
				return;

			if (head == fork_head::replace)
				clear_pending_fork(nullptr);

			umutex<std::recursive_mutex> unique(sync.block);
			auto& fork = forks[candidate_hash];
			if (fork.timeout != INVALID_TASK_ID)
				schedule::get()->clear_timeout(fork.timeout);
			fork.header = candidate_block;
			fork.state = state;
			fork.state->add_ref();
			fork.timeout = schedule::get()->set_timeout(protocol::now().user.p2p.response_timeout, std::bind(&server_node::clear_pending_fork, this, state));
			mempool.dirty = true;
		}
		bool server_node::clear_mempool(bool wait)
		{
			if (!validator.node.services.has_production || is_syncing())
				return false;

			return control_sys.timeout_if_none("clear_mempool", wait ? (protocol::now().user.storage.transaction_timeout * 1000) : 0, [this]()
			{
				auto mempool = storages::mempoolstate(__func__);
				mempool.expire_transactions().report("mempool cleanup failed");
				control_sys.clear_timeout("clear_mempool");
				clear_mempool(true);
			});
		}
		bool server_node::accept_mempool(uint64_t timeout_ms)
		{
			if (!validator.node.services.has_production || is_syncing())
				return false;

			if (mempool.waiting)
			{
				mempool.waiting = false;
				control_sys.clear_timeout("accept_mempool");
			}

			return control_sys.timeout_if_none("accept_mempool", timeout_ms, [this]()
			{
				auto chain = storages::chainstate(__func__);
				auto tip = chain.get_latest_block_header();
				auto priority = environment.configure_priority_from_validator(validator.wallet.public_key_hash, validator.wallet.secret_key, tip.address());
				auto position = priority.or_else(protocol::now().policy.production_max_per_block);
				auto baseline_solution_time = tip->get_slot_proof_duration_average();
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
							control_sys.clear_timeout("accept_mempool");
							accept_mempool(other_node_solution_time - current_solution_time);
							return;
						}
						else if (i < position && protocol::now().user.p2p.logging)
							VI_WARN("%" PRIu64 " mempool block producer%s failing (%" PRIu64 " until stepping in)", i + 1, i > 0 ? "s are" : " is", position - (i + 1));		
					}
				}

				size_t offset = 0, count = 512;
				auto mempool = storages::mempoolstate(__func__);
				while (is_active())
				{
					auto candidates = mempool.get_transactions(offset, count);
					offset += candidates ? environment.try_include_transactions(std::move(*candidates)) : 0;
					if (count != (candidates ? candidates->size() : 0))
						break;
				}

				if (is_active() && !environment.incoming.empty())
				{
					if (protocol::now().user.p2p.logging)
						VI_INFO("evaluating mempool block (txns: %" PRIu64 ", position: %" PRIu64 ")", (uint64_t)environment.incoming.size(), position);

					uint64_t replacements = 0;
					auto evaluation = environment.evaluate_block([&]() -> uptr<ledger::transaction>
					{
						auto candidate = mempool.get_transactions(offset++, 1);
						auto* transaction = candidate ? candidate->front().reset() : nullptr;
						if (protocol::now().user.p2p.logging)
							VI_INFO("replacing mempool block transaction (txns: %" PRIu64 ")", ++replacements);
						return transaction;
					});
					evaluation.report("mempool block evaluation failed");
					if (evaluation)
					{
						if (protocol::now().user.p2p.logging)
							VI_INFO("solving mempool block (duration: < ~%" PRIu64 " sec.)", current_node_solution_time / 1000 + 1);

						auto solution = environment.solve_evaluated_block(evaluation->block);
						solution.report("mempool block solution failed");
						if (solution)
						{
							if (evaluation->block.number > chain.get_latest_block_number().or_else(0))
							{
								if (protocol::now().user.p2p.logging)
									VI_INFO("proposing mempool block (number: %" PRIu64", hash: %s)", evaluation->block.number, algorithm::encoding::encode_0xhex256(evaluation->block.as_hash()).c_str());

								accept_block(nullptr, std::move(*evaluation), 0);
							}
							else if (protocol::now().user.p2p.logging)
								VI_WARN("mempool block is solved but dismissed (number: %" PRIu64", hash: %s)", evaluation->block.number, algorithm::encoding::encode_0xhex256(evaluation->block.as_hash()).c_str());
						}
					}
				}
				else if (is_active())
					environment.cleanup().report("mempool cleanup failed");

				control_sys.clear_timeout("accept_mempool");
			});
		}
		bool server_node::accept_dispatchpool(const ledger::block_header& tip)
		{
			if (is_syncing())
				return false;

			return control_sys.timeout_if_none("accept_dispatchpool", 0, [this, tip]()
			{
				auto dispatcher = memory::init<dispatch_context>(this);
				dispatcher->dispatch_async(tip).when([this, dispatcher]() mutable
				{
					auto& sendable_transactions = dispatcher->get_sendable_transactions();
					if (!sendable_transactions.empty())
					{
						umutex<std::recursive_mutex> unique(sync.account);
						auto account_nonce = validator.wallet.get_latest_nonce().or_else(0);
						control_sys.lock_timeout("accept_mempool");
						for (auto& transaction : sendable_transactions)
							accept_unsigned_transaction(nullptr, std::move(transaction), &account_nonce);

						dispatcher->checkpoint().report("dispatcher checkpoint error");
						if (control_sys.unlock_timeout("accept_mempool"))
							accept_mempool(0);
					}
					else
					{
						dispatcher->checkpoint().report("dispatcher checkpoint error");
						accept_mempool(0);
					}

					control_sys.clear_timeout("accept_dispatchpool");
					memory::deinit(dispatcher);
				});
			});
		}
		bool server_node::accept_block(relay* from, ledger::block_evaluation&& candidate, const uint256_t& fork_tip)
		{
			uint256_t candidate_hash = candidate.block.as_hash();
			auto verification = from ? candidate.block.verify_validity(nullptr) : environment.verify_solved_block(candidate.block, &candidate.state);
			if (!verification)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), verification.error().what());
				return false;
			}

			auto chain = storages::chainstate(__func__);
			if (chain.get_block_header_by_hash(candidate_hash))
			{
				if (protocol::now().user.p2p.logging)
					VI_INFO("block %s branch confirmed", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
				return true;
			}

			bool fork_branch = fork_tip > 0;
			auto fork_tip_block = ledger::block_header();
			if (fork_branch)
			{
				umutex<std::recursive_mutex> unique(sync.block);
				auto it = forks.find(fork_tip);
				if (it == forks.end())
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("block %s branch averted: fork reverted", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
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
				if (protocol::now().user.p2p.logging)
					VI_WARN("block %s branch averted: not preferred %s (length: %" PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), branch_length < 0 ? "branch" : "difficulty", branch_length);
				return false;
			}
			else if (branch_length == 0 && tip_block && tip_hash != candidate_hash && candidate.block < *tip_block)
			{
				/*
													  <+> = ignore (weaker branch)
													 /
					<+> - <+> - <+> - <+> - <+> - <+> - <+>
				*/
				if (protocol::now().user.p2p.logging)
					VI_WARN("block %s branch averted: not preferred difficulty", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
				return false;
			}
			else if (!parent_block && candidate.block.number > 1)
			{
				if (!from)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("block %s branch averted: not preferred candidate", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
					return false;
				}

				umutex<std::recursive_mutex> unique(sync.block);
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
					if (protocol::now().user.p2p.logging)
					{
						if (forks.find(candidate_hash) != forks.end())
							VI_INFO("block %s new best branch confirmed", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
						else
							VI_WARN("block %s branch averted: not preferred orphan branch", algorithm::encoding::encode_0xhex256(candidate_hash).c_str());
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
				accept_pending_fork(from, fork_head::append, candidate_hash, ledger::block_header(candidate.block));
				unique.unlock();
				if (!tip_block)
					call(from, &methods::request_fork_block, { format::variable(candidate_hash), format::variable(uint256_t(0)), format::variable((uint64_t)1) });
				else
					call(from, &methods::find_fork_collision, { format::variable(candidate_hash), format::variable(tip_block->number) });

				if (protocol::now().user.p2p.logging)
					VI_INFO("block %s new best branch found (height: %" PRIu64 ", distance: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), candidate.block.number, std::abs((int64_t)(tip_block ? tip_block->number : 0) - (int64_t)candidate.block.number));
				return true;
			}

			if (from != nullptr)
			{
				auto validation = candidate.block.validate(parent_block.address(), &candidate);
				if (!validation)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), validation.error().what());
					return false;
				}
			}
			else
			{
				auto integrity = candidate.block.verify_integrity(parent_block.address(), &candidate.state);
				if (!integrity)
				{
					if (protocol::now().user.p2p.logging)
						VI_WARN("block %s branch averted: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), integrity.error().what());
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

			size_t multicalls = from ? multicall(from, &methods::propose_block_hash, { format::variable(candidate_hash) }) : multicall(from, &methods::propose_block, { format::variable(candidate.block.as_message().data) });
			if (multicalls > 0 && protocol::now().user.p2p.logging)
				VI_DEBUG("block %s broadcasted to %i nodes (height: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), (int)multicalls, candidate.block.number);

			if (fork_tip != candidate_hash)
				accept_pending_fork(from, fork_head::replace, fork_tip, std::move(fork_tip_block));
			else
				clear_pending_fork(nullptr);

			accept_dispatchpool(candidate.block);
			if (from != nullptr && mempool.dirty && !is_syncing())
			{
				call(from, &methods::request_mempool, { format::variable((uint64_t)0) });
				mempool.dirty = false;
			}

			return true;
		}
		bool server_node::accept_block_candidate(const ledger::block_evaluation& candidate, const uint256_t& candidate_hash, const uint256_t& fork_tip)
		{
			auto mutation = candidate.checkpoint();
			if (!mutation)
			{
				if (protocol::now().user.p2p.logging)
					VI_WARN("block %s checkpoint failed: %s", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation.error().what());
				return false;
			}

			if (protocol::now().user.p2p.logging)
			{
				double progress = get_sync_progress(fork_tip, candidate.block.number);
				if (mutation->is_fork)
					VI_INFO("block %s chain forked (height: %" PRIu64 ", mempool: %" PRIu64 ", block-delta: " PRIi64 ", transaction-delta: " PRIi64 ", state-delta: " PRIi64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->old_tip_block_number, mutation->mempool_transactions, mutation->block_delta, mutation->transaction_delta, mutation->state_delta);
				VI_INFO("block %s chain %s (height: %" PRIu64 ", sync: %.2f%%, priority: %" PRIu64 ")", algorithm::encoding::encode_0xhex256(candidate_hash).c_str(), mutation->is_fork ? "shortened" : "extended", candidate.block.number, 100.0 * progress, candidate.block.priority);
			}

			if (events.accept_block)
				events.accept_block(candidate_hash, candidate.block, *mutation);

			for (auto& transaction : candidate.block.transactions)
			{
				if (!memcmp(transaction.receipt.from, validator.wallet.public_key_hash, sizeof(algorithm::pubkeyhash)))
					accept_proposal_transaction(candidate.block, transaction);
			}

			return true;
		}
		bool server_node::accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction)
		{
			uint32_t type = transaction.transaction->as_type();
			auto purpose = transaction.transaction->as_typename();
			if (type == transactions::certification::as_instance_type())
			{
				if (transaction.receipt.successful)
				{
					if (protocol::now().user.p2p.logging)
						VI_INFO("transaction %s %.*s finalized", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
					fill_validator_services();
					accept_mempool(0);
				}
				else if (protocol::now().user.p2p.logging)
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			else if (protocol::now().user.p2p.logging)
			{
				if (transaction.receipt.successful)
					VI_INFO("transaction %s %.*s finalized", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data());
				else
					VI_ERR("transaction %s %.*s error: %s", algorithm::encoding::encode_0xhex256(transaction.transaction->as_hash()).c_str(), (int)purpose.size(), purpose.data(), transaction.receipt.get_error_messages().or_else(string("execution error")).c_str());
			}
			return true;
		}
		bool server_node::accept(option<socket_address>&& address)
		{
			if (address && routing::is_address_reserved(*address))
				return false;

			return address ? connect_outbound_node(*address) : receive_outbound_node(optional::none);
		}
		bool server_node::receive_outbound_node(option<socket_address>&& error_address)
		{
			auto& peer = protocol::now().user.p2p;
			umutex<std::recursive_mutex> unique(exclusive);
			size_t current_outbound_nodes = size_of(node_type::outbound);
			if (!is_active() || current_outbound_nodes >= peer.max_outbound_connections)
				return false;

			unique.unlock();
			control_sys.clear_timeout("node_rediscovery");
			cospawn([this, error_address = std::move(error_address)]() mutable
			{
				find_node_from_mempool(std::move(error_address), true).when([this](option<socket_address>&& address)
				{
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
					if (!node)
						return false;

					codefer([this, state, node]() { push_procedure(state, std::bind(&server_node::abort_inbound_node, this, node)); });
					return true;
				}
				case node_type::outbound:
				{
					auto* node = state->as_outbound_node();
					if (!node)
						return false;

					codefer([this, state, node]() { push_procedure(state, std::bind(&server_node::abort_outbound_node, this, node)); });
					return true;
				}
				default:
					return false;
			}
		}
		void server_node::fill_validator_services()
		{
			auto context = ledger::transaction_context();
			auto production = context.get_validator_production(validator.wallet.public_key_hash);
			validator.node.services.has_production = production && production->active;
			validator.node.services.has_participation = false;
			validator.node.services.has_attestation = false;

			size_t count = 64;
			size_t offset = 0;
			while (true)
			{
				auto participations = context.get_validator_participations(validator.wallet.public_key_hash, offset, count);
				if (!participations || participations->empty())
					break;

				for (auto& participation : *participations)
				{
					validator.node.services.has_participation = participation.is_active();
					if (validator.node.services.has_participation)
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
				auto attestations = context.get_validator_attestations(validator.wallet.public_key_hash, offset, count);
				if (!attestations || attestations->empty())
					break;

				for (auto& attestation : *attestations)
				{
					validator.node.services.has_attestation = attestation.is_active();
					if (validator.node.services.has_attestation)
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
		const unordered_map<void*, relay*>& server_node::get_nodes() const
		{
			return nodes;
		}
		const single_queue<uref<relay_procedure>>& server_node::get_messages() const
		{
			return messages;
		}
		dispatch_context server_node::get_dispatcher() const
		{
			return dispatch_context((server_node*)this);
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
			size_t current_outbound_nodes = size_of(node_type::outbound);
			if (current_outbound_nodes >= peer.max_outbound_connections)
				return 1;

			for (auto& node : nodes)
			{
				auto* instance = node.second->as_outbound_node();
				if (!instance)
					continue;

				++current_outbound_nodes;
				if (node.second->peer_address() == *ip_address)
					return 0;
			}

			auto* node = new outbound_node();
			node->connect_queued(address, true, PEER_NOT_SECURE, std::bind(&server_node::accept_outbound_node, this, node, std::placeholders::_1));
			return 1;
		}
		relay* server_node::find_node_by_instance(void* instance)
		{
			umutex<std::recursive_mutex> unique(exclusive);
			auto it = nodes.find(instance);
			return it != nodes.end() ? it->second : nullptr;
		}

		promise<void> methods::returning::abort(server_node* relayer, relay* from, const char* function, const std::string_view& text)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
			{
				++peer_validator->availability.calls;
				++peer_validator->availability.errors;
			}

			relayer->reject(from);
			if (protocol::now().user.p2p.logging)
				VI_DEBUG("validator %s call \"%s\" abort: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), routing::node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		promise<void> methods::returning::error(server_node* relayer, relay* from, const char* function, const std::string_view& text)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
			{
				++peer_validator->availability.calls;
				++peer_validator->availability.errors;
			}

			if (protocol::now().user.p2p.logging)
				VI_DEBUG("validator %s call \"%s\" error: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), routing::node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		promise<void> methods::returning::ok(relay* from, const char* function, const std::string_view& text)
		{
			auto* peer_validator = from->as_user<ledger::validator>();
			if (peer_validator != nullptr)
				++peer_validator->availability.calls;

			if (protocol::now().user.p2p.logging)
				VI_DEBUG("validator %s call \"%s\" OK: %.*s (%s %s)", from->peer_address().c_str(), function, (int)message.size(), message.data(), routing::node_type_of(from).data(), from->peer_service().c_str());

			return promise<void>::null();
		}
		promise<void> methods::propose_handshake(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 2)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uptr<ledger::validator> peer_validator = memory::init<ledger::validator>();
			format::ro_stream validator_message = format::ro_stream(message.args.front().as_string());
			uint64_t peer_time = message.args.back().as_uint64();
			uint64_t server_time = protocol::now().time.now_cpu();
			uint64_t latency_time = peer_time > server_time ? peer_time - server_time : server_time - peer_time;
			if (!peer_validator->load(validator_message))
				return returning::abort(relayer, *from, __func__, "invalid message");

			auto& peer = protocol::now().user.p2p;
			peer_validator->availability.latency = latency_time;
			peer_validator->address = socket_address(from->peer_address(), peer_validator->address.get_ip_port().or_else(protocol::now().user.p2p.port));
			if (!peer_validator->is_valid())
				return returning::abort(relayer, *from, __func__, "invalid validator");

			auto mempool = storages::mempoolstate(__func__);
			relayer->apply_validator(mempool, **peer_validator, optional::none).report("mempool peer validator save failed");

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			relayer->call(*from, &methods::approve_handshake, { format::variable(validator_message.data), format::variable(protocol::now().time.now_cpu()), format::variable(tip ? tip->number : 0), format::variable(tip ? tip->as_hash() : uint256_t(0)) });
			from->use<ledger::validator>(peer_validator.reset(), [](ledger::validator* value) { memory::deinit(value); });
			return returning::ok(*from, __func__, "approve handshake");
		}
		promise<void> methods::approve_handshake(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 4)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			ledger::validator self_validator;
			format::ro_stream validator_message = format::ro_stream(message.args[0].as_string());
			if (!self_validator.load(validator_message))
				return returning::abort(relayer, *from, __func__, "invalid message");
			else if (!self_validator.is_valid())
				return returning::abort(relayer, *from, __func__, "invalid validator");
			else if (self_validator.availability.calls != relayer->validator.node.availability.calls || self_validator.availability.errors != relayer->validator.node.availability.errors || self_validator.availability.timestamp != relayer->validator.node.availability.timestamp)
				return returning::abort(relayer, *from, __func__, "invalid validator adjustment");

			auto* peer_validator = from->as_user<ledger::validator>();
			if (!peer_validator)
				return returning::abort(relayer, *from, __func__, "validator not found");

			if (self_validator.address.get_ip_address().or_else(string()) != relayer->validator.node.address.get_ip_address().or_else(string()) || self_validator.availability.latency != relayer->validator.node.availability.latency)
			{
				auto mempool = storages::mempoolstate(__func__);
				relayer->validator.node = std::move(self_validator);
				relayer->apply_validator(mempool, relayer->validator.node, relayer->validator.wallet).report("mempool self validator save failed");
			}

			auto& protocol = protocol::change();
			uint64_t peer_time = message.args[1].as_uint64();
			uint64_t server_time = protocol::now().time.now_cpu();
			uint64_t latency_time = peer_time > server_time ? peer_time - server_time : server_time - peer_time;
			uint64_t varying_peer_time = peer_time + (peer_validator->availability.latency + latency_time) / 2;
			protocol.time.adjust(peer_validator->address, (int64_t)server_time - (int64_t)varying_peer_time);
			if (protocol::now().user.p2p.logging)
				VI_INFO("validator %s channel accept (%s %s)", from->peer_address().c_str(), routing::node_type_of(*from).data(), from->peer_service().c_str());

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
				relayer->call(*from, &methods::propose_nodes, std::move(args));
			}

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			uint64_t peer_tip_number = message.args[2].as_uint64();
			uint256_t peer_tip_hash = message.args[3].as_uint256();
			if (!tip || peer_tip_number > tip->number)
				return returning::ok(*from, __func__, "tip required");
			else if (peer_tip_number == tip->number && tip->as_hash() == peer_tip_hash)
				return returning::ok(*from, __func__, "tip synced");

			auto block = chain.get_block_by_number(tip->number, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
			if (!block)
				return returning::ok(*from, __func__, "no tip found");

			format::wo_stream block_message = block->as_message();
			relayer->call(*from, &methods::propose_block, { format::variable(block_message.data) });
			return returning::ok(*from, __func__, "new tip proposed");
		}
		promise<void> methods::propose_nodes(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.empty() || message.args.size() % 2 != 0)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			size_t candidates = 0;
			auto mempool = storages::mempoolstate(__func__);
			for (size_t i = 0; i < message.args.size(); i += 2)
			{
				auto ip_address = message.args[i + 0].as_string();
				auto ip_port = message.args[i + 1].as_uint16();
				auto target = socket_address(ip_address, ip_port);
				candidates += target.is_valid() && !routing::is_address_reserved(target) && mempool.apply_trial_address(target) ? 1 : 0;
			}

			if (candidates > 0)
				relayer->accept();

			return returning::ok(*from, __func__, "accept nodes");
		}
		promise<void> methods::find_fork_collision(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 2)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = message.args[0].as_uint256();
			if (!fork_hash)
				return returning::abort(relayer, *from, __func__, "invalid fork");

			uint64_t branch_number = message.args[1].as_uint64();
			if (!branch_number)
				return returning::abort(relayer, *from, __func__, "invalid branch");

			const uint64_t blocks_count = protocol::now().user.p2p.cursor_size;
			const uint64_t fork_number = branch_number > blocks_count ? branch_number - blocks_count : 1;
			auto chain = storages::chainstate(__func__);
			auto headers = chain.get_block_headers(fork_number, blocks_count);
			if (!headers || headers->empty())
				return returning::error(relayer, *from, __func__, "fork collision not found");

			format::variables header_args;
			header_args.reserve(headers->size() + 2);
			header_args.push_back(format::variable(fork_hash));
			header_args.push_back(format::variable(fork_number + headers->size() - 1));
			for (auto& item : *headers)
				header_args.push_back(format::variable(item.as_message().data));

			relayer->call(*from, &methods::verify_fork_collision, std::move(header_args));
			return returning::ok(*from, __func__, "fork collisions proposed");
		}
		promise<void> methods::verify_fork_collision(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() < 2)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = message.args[0].as_uint256();
			if (!fork_hash)
				return returning::abort(relayer, *from, __func__, "invalid fork");

			uint64_t branch_number = message.args[1].as_uint64();
			if (!branch_number)
				return returning::abort(relayer, *from, __func__, "invalid branch");

			if (message.args.size() < 3)
				return returning::error(relayer, *from, __func__, "fork collision not found");

			format::ro_stream block_message = format::ro_stream(message.args[2].as_string());
			ledger::block_header child_header;
			if (!child_header.load(block_message))
				return returning::abort(relayer, *from, __func__, "invalid fork block header");

			ledger::block_header parent_header;
			auto chain = storages::chainstate(__func__);
			for (size_t i = 3; i < message.args.size() + 1; i++)
			{
				uint256_t branch_hash = child_header.as_hash(true);
				auto collision = chain.get_block_header_by_hash(branch_hash);
				if (collision || --branch_number < 1)
				{
					relayer->call(*from, &methods::request_fork_block, { format::variable(fork_hash), format::variable(branch_hash), format::variable((uint64_t)0) });
					return returning::ok(*from, __func__, "fork collision found");
				}
				else if (i < message.args.size())
				{
					block_message.clear();
					block_message.data = message.args[i].as_string();
					if (!parent_header.load(block_message))
						return returning::abort(relayer, *from, __func__, "invalid fork block header");
				}

				auto verification = child_header.verify_validity(parent_header.number > 0 ? &parent_header : nullptr);
				if (!verification)
					return returning::abort(relayer, *from, __func__, "invalid fork block header: " + verification.error().message());

				child_header = parent_header;
			}

			relayer->call(*from, &methods::find_fork_collision, { format::variable(fork_hash), format::variable(branch_number) });
			return returning::ok(*from, __func__, "fork collision not found");
		}
		promise<void> methods::request_fork_block(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 3)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = message.args[0].as_uint256();
			if (!fork_hash)
				return returning::abort(relayer, *from, __func__, "invalid fork");

			uint256_t block_hash = message.args[1].as_uint256();
			if (block_hash > 0)
			{
				auto chain = storages::chainstate(__func__);
				auto block = chain.get_block_by_hash(block_hash, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
				{
					format::wo_stream block_message = block->as_message();
					relayer->call(*from, &methods::propose_fork_block, { format::variable(fork_hash), format::variable(block_message.data) });
					return returning::ok(*from, __func__, "new fork block proposed");
				}
			}

			uint256_t block_number = message.args[2].as_uint64();
			if (block_number > 0)
			{
				auto chain = storages::chainstate(__func__);
				auto block = chain.get_block_by_number(block_number, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
				if (block)
				{
					format::wo_stream block_message = block->as_message();
					relayer->call(*from, &methods::propose_fork_block, { format::variable(fork_hash), format::variable(block_message.data) });
					return returning::ok(*from, __func__, "new fork block proposed");
				}
			}

			return returning::ok(*from, __func__, "fork block not found");
		}
		promise<void> methods::propose_fork_block(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 2)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t fork_hash = message.args.front().as_uint256();
			if (!fork_hash)
				return returning::abort(relayer, *from, __func__, "invalid fork");

			ledger::block_evaluation tip;
			format::ro_stream block_message = format::ro_stream(message.args.back().as_string());
			if (!tip.block.load(block_message))
			{
				relayer->clear_pending_fork(*from);
				return returning::abort(relayer, *from, __func__, "fork block rejected");
			}

			auto next_block_number = tip.block.number + 1;
			if (!relayer->accept_block(*from, std::move(tip), fork_hash))
			{
				relayer->clear_pending_fork(*from);
				return returning::abort(relayer, *from, __func__, "fork block rejected");
			}

			relayer->call(*from, &methods::request_fork_block, { format::variable(fork_hash), format::variable(uint256_t(0)), format::variable(next_block_number) });
			return returning::ok(*from, __func__, "new fork block accepted");
		}
		promise<void> methods::request_block(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t block_hash = message.args.front().as_uint256();
			if (!block_hash)
				return returning::abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			auto block = chain.get_block_by_hash(block_hash, BLOCK_RATE_NORMAL, BLOCK_DATA_CONSENSUS);
			if (!block)
				return returning::ok(*from, __func__, "block not found");

			format::wo_stream block_message = block->as_message();
			relayer->call(*from, &methods::propose_block, { format::variable(block_message.data) });
			return returning::ok(*from, __func__, "block proposed");
		}
		promise<void> methods::propose_block(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			ledger::block_evaluation candidate;
			format::ro_stream block_message = format::ro_stream(message.args.front().as_string());
			if (!candidate.block.load(block_message) || !relayer->accept_block(*from, std::move(candidate), 0))
				return returning::error(relayer, *from, __func__, "block rejected");

			return returning::ok(*from, __func__, "block accepted");
		}
		promise<void> methods::propose_block_hash(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t block_hash = message.args.front().as_uint256();
			if (!block_hash)
				return returning::abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			if (chain.get_block_header_by_hash(block_hash))
				return returning::ok(*from, __func__, "block found");

			relayer->call(*from, &methods::request_block, { format::variable(block_hash) });
			return returning::ok(*from, __func__, "block requested");
		}
		promise<void> methods::request_transaction(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t transaction_hash = message.args.front().as_uint256();
			if (!transaction_hash)
				return returning::abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			auto transaction = chain.get_transaction_by_hash(transaction_hash);
			if (!transaction)
			{
				auto mempool = storages::mempoolstate(__func__);
				transaction = mempool.get_transaction_by_hash(transaction_hash);
				if (!transaction)
					return returning::ok(*from, __func__, "transaction not found");
			}

			format::wo_stream transaction_message = (*transaction)->as_message();
			relayer->call(*from, &methods::propose_transaction, { format::variable(transaction_message.data) });
			return returning::ok(*from, __func__, "transaction proposed");
		}
		promise<void> methods::propose_transaction(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			format::ro_stream transaction_message = format::ro_stream(message.args.front().as_string());
			uptr<ledger::transaction> candidate = tangent::transactions::resolver::from_stream(transaction_message);
			if (!candidate)
				return returning::error(relayer, *from, __func__, "invalid transaction");

			if (!candidate->load(transaction_message) || !relayer->accept_transaction(*from, std::move(candidate)))
				return returning::error(relayer, *from, __func__, "transaction rejected");

			return returning::ok(*from, __func__, "transaction accepted");
		}
		promise<void> methods::propose_transaction_hash(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint256_t transaction_hash = message.args.front().as_uint256();
			if (!transaction_hash)
				return returning::abort(relayer, *from, __func__, "invalid hash");

			auto chain = storages::chainstate(__func__);
			if (chain.get_transaction_by_hash(transaction_hash))
				return returning::ok(*from, __func__, "finalized transaction found");

			auto mempool = storages::mempoolstate(__func__);
			if (mempool.get_transaction_by_hash(transaction_hash))
				return returning::ok(*from, __func__, "pending transaction found");

			relayer->call(*from, &methods::request_transaction, { format::variable(transaction_hash) });
			return returning::ok(*from, __func__, "transaction requested");
		}
		promise<void> methods::request_mempool(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 1)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint64_t cursor = message.args.front().as_uint64();
			const uint64_t transactions_count = protocol::now().user.p2p.cursor_size;
			auto mempool = storages::mempoolstate(__func__);
			auto hashes = mempool.get_transaction_hashset(cursor, transactions_count);
			if (!hashes || hashes->empty())
				return returning::ok(*from, __func__, "mempool is empty");

			format::variables hash_args;
			hash_args.reserve(hashes->size());
			hash_args.push_back(format::variable(cursor + hashes->size()));
			for (auto& item : *hashes)
				hash_args.push_back(format::variable(item));

			relayer->call(*from, &methods::propose_mempool, std::move(hash_args));
			return returning::ok(*from, __func__, "mempool proposed");
		}
		promise<void> methods::propose_mempool(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() < 2)
				return returning::abort(relayer, *from, __func__, "invalid arguments");

			uint64_t cursor = message.args.front().as_uint64();
			auto mempool = storages::mempoolstate(__func__);
			for (size_t i = 1; i < message.args.size(); i++)
			{
				auto transaction_hash = message.args[i].as_uint256();
				if (!mempool.has_transaction(transaction_hash))
					relayer->call(*from, &methods::request_transaction, { format::variable(transaction_hash) });
			}

			const uint64_t transactions_count = protocol::now().user.p2p.cursor_size;
			if (message.args.size() > transactions_count)
				relayer->call(*from, &methods::request_mempool, { format::variable(cursor) });

			return returning::ok(*from, __func__, "mempool accepted");
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
		std::string_view routing::node_type_of(relay* from)
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
		const ledger::wallet* dispatch_context::get_wallet() const
		{
			return &server->validator.wallet;
		}
		expects_promise_rt<void> dispatch_context::calculate_group_public_key(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, algorithm::composition::cpubkey_t& inout)
		{
			auto* depository_account = (transactions::depository_account*)context->transaction;
			if (is_running_on(validator.data))
			{
				auto* chain = nss::server_node::get()->get_chainparams(depository_account->asset);
				if (!chain)
					return expects_promise_rt<void>(remote_exception("invalid operation"));

				auto share = recover_group_share(depository_account->asset, depository_account->manager, context->receipt.from);
				if (!share)
					return expects_promise_rt<void>(remote_exception(std::move(share.error().message())));

				algorithm::composition::keypair keypair;
				auto status = algorithm::composition::derive_keypair(chain->composition, *share, &keypair);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

				status = algorithm::composition::accumulate_public_key(chain->composition, keypair.secret_key, inout.data);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

				return expects_promise_rt<void>(expectation::met);
			}

			auto args = format::variables({ format::variable(validator.optimized_view()), format::variable(context->receipt.block_number), format::variable(context->receipt.transaction_hash), format::variable(inout.optimized_view()) });
			return server->call_responsive(&calculate_group_public_key_remote, std::move(args), protocol::now().user.p2p.response_timeout, std::bind(&deserialize_procedure_response, context->receipt.transaction_hash, validator, std::placeholders::_1)).then<expects_rt<void>>([&inout](expects_rt<format::variables>&& result) -> expects_rt<void>
			{
				if ((result && result->at(2).as_boolean()) || (!result && (result.error().is_retry() || result.error().is_shutdown())))
					return remote_exception::retry();
				else if (!result)
					return result.error();

				inout = result->size() > 3 ? algorithm::composition::cpubkey_t(result->at(3).as_blob()) : algorithm::composition::cpubkey_t();
				if (inout.empty())
					return remote_exception("group public key remote computation error");

				return expectation::met;
			});
		}
		expects_promise_rt<void> dispatch_context::calculate_group_signature(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, const warden::prepared_transaction& prepared, ordered_map<uint8_t, algorithm::composition::cpubsig_t>& inout)
		{
			auto* depository_withdrawal = (transactions::depository_withdrawal*)context->transaction;
			if (is_running_on(validator.data))
			{
				auto validation = transactions::depository_withdrawal::validate_prepared_transaction(context, depository_withdrawal, prepared);
				if (!validation)
					return expects_promise_rt<void>(remote_exception(std::move(validation.error().message())));

				for (size_t i = 0; i < prepared.inputs.size(); i++)
				{
					auto& input = prepared.inputs[i];
					auto witness = context->get_witness_account_tagged(depository_withdrawal->asset, input.utxo.link.address, 0);
					if (!witness)
						return expects_promise_rt<void>(remote_exception(std::move(witness.error().message())));

					auto account = context->get_depository_account(depository_withdrawal->asset, witness->manager, witness->owner);
					if (!account || account->group.find(validator) == account->group.end())
						continue;

					auto share = recover_group_share(account->asset, account->manager, account->owner);
					if (!share)
						return expects_promise_rt<void>(remote_exception(std::move(share.error().message())));

					algorithm::composition::keypair keypair;
					auto status = algorithm::composition::derive_keypair(input.alg, *share, &keypair);
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

					status = algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, keypair.secret_key, inout[(uint8_t)i].data);
					if (!status)
						return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
				}

				return expects_promise_rt<void>(expectation::met);
			}

			format::wo_stream prepared_message;
			if (!prepared.store(&prepared_message))
				return expects_promise_rt<void>(remote_exception("prepared transaction serialization error"));

			auto args = format::variables({ format::variable(validator.optimized_view()), format::variable(context->receipt.block_number), format::variable(context->receipt.transaction_hash), format::variable(prepared_message.data) });
			for (size_t i = 0; i < prepared.inputs.size(); i++)
			{
				auto& input = prepared.inputs[i];
				auto witness = context->get_witness_account_tagged(depository_withdrawal->asset, input.utxo.link.address, 0);
				if (!witness)
					return expects_promise_rt<void>(remote_exception(std::move(witness.error().message())));

				auto account = context->get_depository_account(depository_withdrawal->asset, witness->manager, witness->owner);
				if (!account || account->group.find(validator) == account->group.end())
					continue;

				args.push_back(format::variable((uint8_t)i));
				args.push_back(format::variable(inout[(uint8_t)i].optimized_view()));
			}

			return server->call_responsive(&calculate_group_signature_remote, std::move(args), protocol::now().user.p2p.response_timeout, std::bind(&deserialize_procedure_response, context->receipt.transaction_hash, validator, std::placeholders::_1)).then<expects_rt<void>>([&inout](expects_rt<format::variables>&& result) -> expects_rt<void>
			{
				if ((result && result->at(2).as_boolean()) || (!result && (result.error().is_retry() || result.error().is_shutdown())))
					return remote_exception::retry();
				else if (!result)
					return result.error();

				for (size_t i = 3; i + 1 < result->size(); i += 2)
				{
					auto input_index = (*result)[i + 0].as_uint8();
					auto input_signature = algorithm::composition::cpubsig_t((*result)[i + 1].as_blob());
					if (input_signature.empty() || inout.find(input_index) == inout.end())
						return remote_exception("group signature remote computation error");

					inout[input_index] = input_signature;
				}
				return expectation::met;
			});
		}
		promise<void> dispatch_context::calculate_group_public_key_remote(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() != 4)
				return methods::returning::abort(relayer, *from, __func__, "invalid arguments");

			bool requires_retry = false;
			auto validator = algorithm::pubkeyhash_t(message.args[0].as_blob());
			auto block_number = message.args[1].as_uint64();
			auto depository_account_hash = message.args[2].as_uint256();
			auto chainstate = storages::chainstate(__func__);
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
			{
				requires_retry = true;
				if (!validator.equals(relayer->validator.wallet.public_key_hash))
				{
					relayer->multicall(*from, &calculate_group_public_key_remote, std::move(message.args));
					return methods::returning::ok(*from, __func__, "group public key requested");
				}
			abort_group:
				procedure response;
				response.method = protocol::now().message.packet_magic;
				response.args = serialize_procedure_response(relayer->validator.wallet.secret_key, { format::variable(depository_account_hash), format::variable(requires_retry) });
				relayer->multicall(nullptr, std::move(response));
				return methods::returning::ok(*from, __func__, "group public key computation error");
			}

			auto context = ledger::transaction_context();
			auto depository_account = context.get_block_transaction<transactions::depository_account>(depository_account_hash);
			if (!depository_account)
			{
				if (!validator.equals(relayer->validator.wallet.public_key_hash))
					return methods::returning::abort(relayer, *from, __func__, "invalid request");
				goto abort_group;
			}
			else if (!validator.equals(relayer->validator.wallet.public_key_hash))
			{
				relayer->multicall(*from, &calculate_group_public_key_remote, std::move(message.args));
				return methods::returning::ok(*from, __func__, "group public key requested");
			}

			auto* depository_account_transaction = (transactions::depository_account*)*depository_account->transaction;
			auto* chain = nss::server_node::get()->get_chainparams(depository_account_transaction->asset);
			if (!chain)
				goto abort_group;

			auto dispatcher = dispatch_context(relayer);
			auto share = dispatcher.recover_group_share(depository_account_transaction->asset, depository_account_transaction->manager, depository_account->receipt.from);
			if (!share)
				goto abort_group;

			algorithm::composition::keypair keypair;
			if (!algorithm::composition::derive_keypair(chain->composition, *share, &keypair))
				goto abort_group;

			auto group_public_key = algorithm::composition::cpubkey_t(message.args[3].as_blob());
			if (!algorithm::composition::accumulate_public_key(chain->composition, keypair.secret_key, group_public_key.data))
				goto abort_group;

			procedure response;
			response.method = protocol::now().message.packet_magic;
			response.args = serialize_procedure_response(relayer->validator.wallet.secret_key, { format::variable(depository_account_hash), format::variable(requires_retry), format::variable(group_public_key.optimized_view()) });
			relayer->multicall(nullptr, std::move(response));
			return methods::returning::ok(*from, __func__, "group public key proposed");
		}
		promise<void> dispatch_context::calculate_group_signature_remote(server_node* relayer, uref<relay>&& from, procedure&& message)
		{
			if (message.args.size() < 6)
				return methods::returning::abort(relayer, *from, __func__, "invalid arguments");

			bool requires_retry = false;
			auto chainstate = storages::chainstate(__func__);
			auto validator = algorithm::pubkeyhash_t(message.args[0].as_string());
			auto block_number = message.args[1].as_uint64();
			auto depository_withdrawal_hash = message.args[2].as_uint256();
			if (chainstate.get_latest_block_number().or_else(1) < block_number)
			{
				requires_retry = true;
				if (!validator.equals(relayer->validator.wallet.public_key_hash))
				{
					relayer->multicall(*from, &calculate_group_signature_remote, std::move(message.args));
					return methods::returning::ok(*from, __func__, "group signature requested (no checkup forward)");
				}
			abort_group:
				procedure response;
				response.method = protocol::now().message.packet_magic;
				response.args = serialize_procedure_response(relayer->validator.wallet.secret_key, { format::variable(depository_withdrawal_hash), format::variable(requires_retry) });
				relayer->multicall(nullptr, std::move(response));
				return methods::returning::ok(*from, __func__, "group signature computation error");
			}

			auto context = ledger::transaction_context();
			auto depository_withdrawal = context.get_block_transaction<transactions::depository_withdrawal>(depository_withdrawal_hash);
			if (!depository_withdrawal)
			{
				if (!validator.equals(relayer->validator.wallet.public_key_hash))
					return methods::returning::abort(relayer, *from, __func__, "invalid request");
				goto abort_group;
			}

			auto prepared_message = format::ro_stream(message.args[3].as_string());
			auto prepared = warden::prepared_transaction();
			if (!prepared.load(prepared_message))
				return methods::returning::abort(relayer, *from, __func__, "invalid arguments");

			auto* depository_withdrawal_transaction = (transactions::depository_withdrawal*)*depository_withdrawal->transaction;
			auto validation = transactions::depository_withdrawal::validate_prepared_transaction(&context, depository_withdrawal_transaction, prepared);
			if (!validation)
				return methods::returning::abort(relayer, *from, __func__, "group validation error");

			if (!validator.equals(relayer->validator.wallet.public_key_hash))
			{
				relayer->multicall(*from, &calculate_group_signature_remote, std::move(message.args));
				return methods::returning::ok(*from, __func__, "group signature requested");
			}

			auto dispatcher = dispatch_context(relayer);
			auto* server = nss::server_node::get();
			ordered_map<uint8_t, algorithm::composition::cpubsig_t> group_signature;
			for (size_t i = 4; i < message.args.size(); i++)
			{
				auto input_index = message.args[i + 0].as_uint8();
				group_signature[input_index] = algorithm::composition::cpubsig_t(message.args[i + 1].as_blob());
				if (input_index > prepared.inputs.size())
					goto abort_group;

				auto& input = prepared.inputs[input_index];
				auto witness = context.get_witness_account_tagged(depository_withdrawal_transaction->asset, input.utxo.link.address, 0);
				if (!witness)
					goto abort_group;

				auto account = context.get_depository_account(depository_withdrawal_transaction->asset, witness->manager, witness->owner);
				if (!account || account->group.find(relayer->validator.wallet.public_key_hash) == account->group.end())
					goto abort_group;

				auto share = dispatcher.recover_group_share(account->asset, account->manager, account->owner);
				if (!share)
					goto abort_group;

				algorithm::composition::keypair keypair;
				if (!algorithm::composition::derive_keypair(input.alg, *share, &keypair))
					goto abort_group;

				if (!algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, keypair.secret_key, group_signature[input_index].data))
					goto abort_group;
			}

			format::variables args = { format::variable(depository_withdrawal_hash), format::variable(requires_retry) };
			args.reserve(args.size() + group_signature.size() * 2);
			for (auto& [input_index, input_signature] : group_signature)
			{
				args.push_back(format::variable(input_index));
				args.push_back(format::variable(input_signature.optimized_view()));
			}

			procedure response;
			response.method = protocol::now().message.packet_magic;
			response.args = serialize_procedure_response(relayer->validator.wallet.secret_key, std::move(args));
			relayer->multicall(nullptr, std::move(response));
			return methods::returning::ok(*from, __func__, "group signature proposed");
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
		const ledger::wallet* local_dispatch_context::get_wallet() const
		{
			return &validator->second;
		}
		void local_dispatch_context::set_running_validator(const algorithm::pubkeyhash owner)
		{
			auto it = validators.find(algorithm::pubkeyhash_t(owner));
			if (it != validators.end())
				validator = it;
		}
		expects_promise_rt<void> local_dispatch_context::calculate_group_public_key(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, algorithm::composition::cpubkey_t& inout)
		{
			auto wallet = validators.find(validator);
			if (wallet == validators.end())
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto* depository_account = (transactions::depository_account*)context->transaction;
			auto* chain = nss::server_node::get()->get_chainparams(depository_account->asset);
			if (!chain)
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto share = recover_group_share(depository_account->asset, depository_account->manager, context->receipt.from);
			if (!share)
				return expects_promise_rt<void>(remote_exception(std::move(share.error().message())));

			algorithm::composition::keypair keypair;
			auto status = algorithm::composition::derive_keypair(chain->composition, *share, &keypair);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			status = algorithm::composition::accumulate_public_key(chain->composition, keypair.secret_key, inout.data);
			if (!status)
				return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

			return expects_promise_rt<void>(expectation::met);
		}
		expects_promise_rt<void> local_dispatch_context::calculate_group_signature(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, const warden::prepared_transaction& prepared, ordered_map<uint8_t, algorithm::composition::cpubsig_t>& inout)
		{
			auto wallet = validators.find(validator);
			if (wallet == validators.end())
				return expects_promise_rt<void>(remote_exception("invalid operation"));

			auto* depository_withdrawal = (transactions::depository_withdrawal*)context->transaction;
			auto validation = transactions::depository_withdrawal::validate_prepared_transaction(context, depository_withdrawal, prepared);
			if (!validation)
				return expects_promise_rt<void>(remote_exception(std::move(validation.error().message())));

			for (size_t i = 0; i < prepared.inputs.size(); i++)
			{
				auto& input = prepared.inputs[i];
				auto witness = context->get_witness_account_tagged(depository_withdrawal->asset, input.utxo.link.address, 0);
				if (!witness)
					return expects_promise_rt<void>(remote_exception(std::move(witness.error().message())));

				auto account = context->get_depository_account(depository_withdrawal->asset, witness->manager, witness->owner);
				if (!account || account->group.find(validator) == account->group.end())
					continue;

				auto share = recover_group_share(account->asset, account->manager, account->owner);
				if (!share)
					return expects_promise_rt<void>(remote_exception(std::move(share.error().message())));

				algorithm::composition::keypair keypair;
				auto status = algorithm::composition::derive_keypair(input.alg, *share, &keypair);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));

				status = algorithm::composition::accumulate_signature(input.alg, input.message.data(), input.message.size(), input.public_key, keypair.secret_key, inout[(uint8_t)i].data);
				if (!status)
					return expects_promise_rt<void>(remote_exception(std::move(status.error().message())));
			}

			return expects_promise_rt<void>(expectation::met);
		}
	}
}
