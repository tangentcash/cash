#include "discovery.h"
#include "../storage/mempoolstate.h"

namespace tangent
{
	namespace discovery
	{
		server_node::server_node() noexcept : control_sys("discovery-node"), node(new http::server())
		{
		}
		server_node::~server_node() noexcept
		{
		}
		void server_node::startup()
		{
			if (!protocol::now().user.discovery.server)
				return;

			http::map_router* router = new http::map_router();
			router->listen(protocol::now().user.discovery.address, to_string(protocol::now().user.discovery.port)).expect("listener binding error");
			router->get("/", std::bind(&server_node::dispatch, this, std::placeholders::_1));
			router->base->callbacks.headers = std::bind(&server_node::headers, this, std::placeholders::_1, std::placeholders::_2);
			router->base->callbacks.options = std::bind(&server_node::options, this, std::placeholders::_1);
			router->temporary_directory.clear();
			node->configure(router).expect("configuration error");
			node->listen().expect("listen queue error");

			if (protocol::now().user.discovery.logging)
				VI_INFO("OK discovery node listen (location: %s:%i)", protocol::now().user.discovery.address.c_str(), (int)protocol::now().user.discovery.port);
		}
		void server_node::shutdown()
		{
			if (!is_active())
				return;

			if (protocol::now().user.discovery.logging)
				VI_INFO("OK discovery node shutdown");

			node->unlisten(false);
		}
		bool server_node::is_active()
		{
			return node->get_state() == server_state::working;
		}
		bool server_node::headers(http::connection* client, string& content)
		{
			auto headers = client->request.compose_header("access-control-request-headers");
			if (headers.empty())
				headers = "Authorization";

			auto* origin = client->request.get_header_blob("origin");
			if (origin != nullptr)
				content.append("Access-control-allow-origin: ").append(*origin).append("\r\n");

			content.append("Access-control-allow-headers: *, ");
			content.append(headers);
			content.append("\r\n");
			content.append("Access-control-allow-methods: GET\r\n");
			content.append("Access-control-allow-credentials: true\r\n");
			content.append("Access-control-max-age: 86400\r\n");
			return true;
		}
		bool server_node::options(http::connection* client)
		{
			char date[64];
			string* content = http::hrm_cache::get()->pop();
			content->append(client->request.version);
			content->append(" 204 no content\r\nDate: ");
			content->append(date_time::serialize_global(date, sizeof(date), std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::milliseconds(client->info.start)), date_time::format_web_time())).append("\r\n", 2);
			content->append("Allow: GET\r\n");

			http::utils::update_keep_alive_headers(client, *content);
			if (client->route && client->route->callbacks.headers)
				client->route->callbacks.headers(client, *content);

			content->append("\r\n", 2);
			return !!client->stream->write_queued((uint8_t*)content->c_str(), content->size(), [client, content](socket_poll event)
			{
				http::hrm_cache::get()->push(content);
				if (packet::is_done(event))
					client->next(204);
				else if (packet::is_error(event))
					client->abort();
			}, false);
		}
		bool server_node::dispatch(http::connection* base)
		{
			http::query query;
			query.decode("application/x-www-form-urlencoded", base->request.query);

			auto* consensus_argument = query.get("consensus");
			auto* discovery_argument = query.get("discovery");
			auto* oracle_argument = query.get("oracle");
			auto* rpc_argument = query.get("rpc");
			auto* rpc_public_access_argument = query.get("rpc_public_access");
			auto* rpc_web_sockets_argument = query.get("rpc_web_sockets");
			auto* production_argument = query.get("production");
			auto* participation_argument = query.get("participation");
			auto* attestation_argument = query.get("attestation");
			auto* offset_argument = query.get("offset");
			auto* count_argument = query.get("count");
			uint64_t count = count_argument && count_argument->value.is(var_type::integer) ? count_argument->value.get_integer() : protocol::now().user.discovery.cursor_size;
			if (!count || count > protocol::now().user.discovery.cursor_size)
			{
				if (protocol::now().user.discovery.logging)
					VI_WARN("peer %s discovery failed: bad arguments (time: %" PRId64 " ms, args: %s)", base->get_peer_ip_address().or_else("[bad_address]").c_str(), date_time().milliseconds() - base->info.start, base->request.query.c_str());

				return base->abort(400, "Bad page size. count must not exceed %" PRIu64 " elements.", protocol::now().user.discovery.cursor_size);
			}

			uint32_t services = 0;
			if (consensus_argument != nullptr && consensus_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::consensus;
			if (discovery_argument != nullptr && discovery_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::discovery;
			if (oracle_argument != nullptr && oracle_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::oracle;
			if (rpc_argument != nullptr && rpc_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::rpc;
			if (rpc_public_access_argument != nullptr && rpc_public_access_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::rpc_public_access;
			if (rpc_web_sockets_argument != nullptr && rpc_web_sockets_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::rpc_web_sockets;
			if (production_argument != nullptr && production_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::production;
			if (participation_argument != nullptr && participation_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::participation;
			if (attestation_argument != nullptr && attestation_argument->value.get_boolean())
				services |= (uint32_t)storages::node_services::attestation;

			auto mempool = storages::mempoolstate();
			auto nodes = mempool.get_random_nodes_with(count, services);
			if (!nodes || nodes->empty())
			{
				if (protocol::now().user.discovery.logging)
					VI_INFO("peer %s discovery: no nodes returned (time: %" PRId64 " ms, args: %s)", base->get_peer_ip_address().or_else("[bad_address]").c_str(), date_time().milliseconds() - base->info.start, base->request.query.c_str());

				return base->abort(404, "No nodes found.");
			}

			if (protocol::now().user.discovery.logging)
				VI_INFO("peer %s discovery: %i nodes returned (time: %" PRId64 " ms, args: %s)", base->get_peer_ip_address().or_else("[bad_address]").c_str(), (int)nodes->size(), date_time().milliseconds() - base->info.start, base->request.query.c_str());

			uptr<schema> data = var::set::array();
			for (auto& [account, address] : *nodes)
				data->push(var::string(system_endpoint::to_uri(address)));

			base->response.set_header("Content-Type", "application/json");
			base->response.content.assign(schema::to_json(*data));
			return base->next(200);
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!protocol::now().user.discovery.server)
				return service_control::service_node();

			service_control::service_node entrypoint;
			entrypoint.startup = std::bind(&server_node::startup, this);
			entrypoint.shutdown = std::bind(&server_node::shutdown, this);
			return entrypoint;
		}
	}
}