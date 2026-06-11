#include "rpc.h"
#include "consensus.h"
#include "../kernel/script.h"
#include "../policy/transactions.h"
#include "../policy/delegations.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"

namespace tangent
{
	namespace rpc
	{
		struct uniform_location
		{
			string index;
			uint32_t type;

			uniform_location(uint32_t new_type, string&& new_index) : index(std::move(new_index)), type(new_type)
			{
			}
		};

		struct multiform_location
		{
			string row;
			string column;
			uint32_t type;

			multiform_location(uint32_t new_type, string&& new_row, string&& new_column) : row(std::move(new_row)), column(std::move(new_column)), type(new_type)
			{
			}
		};

		static expects_lr<uniform_location> as_uniform_location(const std::string_view& type, const format::variable& index)
		{
			if (type == states::account_nonce::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(index.as_string(), owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_nonce::as_instance_type(), states::account_nonce::as_instance_index(owner));
			}

			if (type == states::account_program::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(index.as_string(), owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_program::as_instance_type(), states::account_program::as_instance_index(owner));
			}

			if (type == states::account_uniform::as_instance_typename())
			{
				auto data = schema::from_json(index.as_string());
				if (!data)
					return layer_exception("invalid value, expected { address: string, index: string }");

				auto owner_address = data->get_var("address").get_blob();
				auto subindex = data->get_var("index").get_blob();
				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(owner_address, owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_uniform::as_instance_type(), states::account_uniform::as_instance_index(owner, subindex));
			}

			if (type == states::witness_program::as_instance_typename())
				return uniform_location(states::witness_program::as_instance_type(), states::witness_program::as_instance_index(index.as_string()));

			if (type == states::witness_event::as_instance_typename())
				return uniform_location(states::witness_event::as_instance_type(), states::witness_event::as_instance_index(index.as_uint256()));

			if (type == states::witness_transaction::as_instance_typename())
			{
				auto data = schema::from_json(index.as_string());
				if (!data)
					return layer_exception("invalid value, expected { asset: string, transaction_id: string }");

				auto id = data->get_var("asset").get_blob();
				auto transaction_id = data->get_var("transaction_id").get_blob();
				return uniform_location(states::witness_transaction::as_instance_type(), states::witness_transaction::as_instance_index(algorithm::asset::id_of_handle(id), transaction_id));
			}

			return layer_exception("invalid uniform type");
		}
		static expects_lr<multiform_location> as_multiform_location(const std::string_view& type, const format::variable& column, const format::variable& row)
		{
			if (type == states::account_multiform::as_instance_typename())
			{
				auto data = schema::from_json(column.as_string());
				if (!data)
					return layer_exception("invalid column value, expected { address: string, column: string }");

				auto owner_address = data->get_var("address").get_blob();
				auto column_value = data->get_var("column").get_blob();
				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(owner_address, owner))
					return layer_exception("invalid address");

				return multiform_location(states::account_multiform::as_instance_type(), states::account_multiform::as_instance_row(owner, row.as_string()), states::account_multiform::as_instance_column(owner, column_value));
			}

			if (type == states::account_balance::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::account_balance::as_instance_type(), states::account_balance::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::account_balance::as_instance_column(owner));
			}

			if (type == states::validator_production::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_production::as_instance_type(), states::validator_production::as_instance_row(), states::validator_production::as_instance_column(owner));
			}

			if (type == states::validator_production_reward::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_production_reward::as_instance_type(), states::validator_production_reward::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::validator_production_reward::as_instance_column(owner));
			}

			if (type == states::validator_participation::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_participation::as_instance_type(), states::validator_participation::as_instance_row(), states::validator_participation::as_instance_column(owner));
			}

			if (type == states::validator_participation_reward::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_participation_reward::as_instance_type(), states::validator_participation_reward::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::validator_participation_reward::as_instance_column(owner));
			}

			if (type == states::validator_participation_ref::as_instance_typename())
			{
				auto data = row.type_of() != format::viewable::invalid ? uptr(schema::from_json(row.as_string()).or_else(nullptr)) : uptr(var::set::object());
				if (!data)
					return layer_exception("invalid value, expected { owner: string, asset: string, hash: uint256 }");

				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				states::bridge_ref ref;
				if (!algorithm::signing::decode_address(data->get_var("owner").get_blob(), ref.owner))
					return layer_exception("invalid address");

				ref.asset = algorithm::asset::id_of_handle(data->get_var("asset").get_blob());
				ref.hash = algorithm::encoding::decode_0xhex256(data->get_var("hash").get_blob());
				return multiform_location(states::validator_participation_ref::as_instance_type(), states::validator_participation_ref::as_instance_row(ref), states::validator_participation_ref::as_instance_column(owner));
			}

			if (type == states::validator_attestation::as_instance_typename())
			{
				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_attestation::as_instance_type(), states::validator_attestation::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::validator_attestation::as_instance_column(owner));
			}

			if (type == states::bridge_instance::as_instance_typename())
				return multiform_location(states::bridge_instance::as_instance_type(), states::bridge_instance::as_instance_row(column.as_uint256()), states::bridge_instance::as_instance_column(algorithm::asset::id_of_handle(row.as_string())));

			if (type == states::bridge_balance::as_instance_typename())
				return multiform_location(states::bridge_balance::as_instance_type(), states::bridge_balance::as_instance_row(column.as_uint256()), states::bridge_balance::as_instance_column(algorithm::asset::id_of_handle(row.as_string())));

			if (type == states::bridge_account::as_instance_typename())
			{
				auto data = row.type_of() != format::viewable::invalid ? uptr(schema::from_json(row.as_string()).or_else(nullptr)) : uptr(var::set::object());
				if (!data)
					return layer_exception("invalid value, expected { asset: string, owner: string }");

				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(data->get_var("owner").get_blob(), owner))
					return layer_exception("invalid address");

				auto asset = algorithm::asset::id_of_handle(data->get_var("asset").get_blob());
				return multiform_location(states::bridge_account::as_instance_type(), states::bridge_account::as_instance_row(column.as_uint256()), states::bridge_account::as_instance_column(asset, owner));
			}

			if (type == states::witness_account::as_instance_typename())
			{
				auto data = row.type_of() != format::viewable::invalid ? uptr(schema::from_json(row.as_string()).or_else(nullptr)) : uptr(var::set::object());
				if (!data)
					return layer_exception("invalid value, expected { asset: string, address: string }");

				algorithm::pubkeyhash_t owner;
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::witness_account::as_instance_type(), states::witness_account::as_instance_row(algorithm::asset::id_of_handle(data->get_var("asset").get_blob()), data->get_var("address").get_blob()), states::witness_account::as_instance_column(owner));
			}

			return layer_exception("invalid multiform type");
		}
		static void form_response(http::connection* base, format::tree& request, option<format::tree>& responses, server_response&& response)
		{
			if (protocol::now().user.rpc.logging)
			{
				auto* params = request.child("params");
				string method = request.child_var("method").as_blob();
				string id = request.child_var("id").as_blob();
				VI_INFO("rpc %s call %s: %s (params: %" PRIu64 ", time: %" PRId64 " ms)",
					base->get_peer_ip_address().or_else("[bad_address]").c_str(),
					method.empty() ? "[bad_method]" : method.c_str(),
					response.error_message.empty() ? (response.data.is_flat() ? "[value]" : stringify::text("%" PRIu64 " rows", (uint64_t)response.data.childs().size()).c_str()) : response.error_message.c_str(),
					(uint64_t)(params ? (params->is_flat() ? 1 : params->childs().size()) : 0),
					date_time().milliseconds() - base->info.start);
			}

			auto next = response.transform(request);
			if (responses)
			{
				if (!responses->is_list())
				{
					auto prev = std::move(*responses);
					responses = format::tree::list();
					responses->push(std::move(prev));
					responses->push(std::move(next));
				}
				else
					responses->push(std::move(next));
			}
			else
				responses = std::move(next);
		};

		server_response&& server_response::success(format::tree&& value)
		{
			data = std::move(value);
			status = error_codes::response;
			return std::move(*this);
		}
		server_response&& server_response::notification(format::tree&& value)
		{
			data = std::move(value);
			status = error_codes::notification;
			return std::move(*this);
		}
		server_response&& server_response::error(error_codes code, const std::string_view& message)
		{
			error_message = message;
			status = code;
			return std::move(*this);
		}
		format::tree server_response::transform(const format::tree& request)
		{
			format::tree response;
			response.set("id", request.child_var("id"));
			response.set(status == error_codes::notification ? "notification" : "result", std::move(data));
			if (status != error_codes::response && status != error_codes::notification && !error_message.empty())
			{
				auto* error = response.set("error", format::tree::map());
				error->set("message", format::variable(error_message));
				error->set("code", (int64_t)status < 0 ? format::variable(decimal((int64_t)status)) : format::variable((uint64_t)status));
			}
			return response;
		}

		server_node::server_node(consensus::server_node* new_consensus_service) noexcept : control_sys("rpc-node"), consensus_service(new_consensus_service), node(new http::server())
		{
			if (consensus_service)
				consensus_service->add_ref();
		}
		server_node::~server_node() noexcept
		{
			memory::release(consensus_service);
		}
		void server_node::startup()
		{
			if (!protocol::now().user.rpc.server)
				return;

			auth_token = protocol::now().user.rpc.username.empty() ? string() : codec::base64_encode(protocol::now().user.rpc.username + ":" + protocol::now().user.rpc.password);
			http::map_router* router = new http::map_router();
			router->listen(protocol::now().user.rpc.address, to_string(protocol::now().user.rpc.port)).expect("listener binding error");
			router->post("/", std::bind(&server_node::http_request, this, std::placeholders::_1));
			router->web_socket_receive("/", std::bind(&server_node::ws_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
			router->web_socket_disconnect("/", std::bind(&server_node::ws_disconnect, this, std::placeholders::_1));
			router->base->callbacks.authorize = auth_token.empty() ? http::authorize_callback(nullptr) : std::bind(&server_node::authorize, this, std::placeholders::_1, std::placeholders::_2);
			router->base->callbacks.headers = std::bind(&server_node::headers, this, std::placeholders::_1, std::placeholders::_2);
			router->base->callbacks.options = std::bind(&server_node::options, this, std::placeholders::_1);
			router->base->compression.enabled = true;
			router->base->allow_web_socket = true;
			router->base->web_socket_timeout = 0;
			router->base->auth.type = "Basic";
			router->base->auth.realm = "p2p.tangent.cash";
			router->base->proxy_ip_address = "X-Real-IP";
			router->temporary_directory.clear();

			node->configure(router).expect("configuration error");
			node->listen().expect("listen queue error");
			if (consensus_service != nullptr)
			{
				consensus_service->events.accept_block = std::bind(&server_node::dispatch_accept_block, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
				consensus_service->events.accept_transaction = std::bind(&server_node::dispatch_accept_transaction, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
			}

			if (protocol::now().user.consensus.logging)
				VI_INFO("OK rpc node listen (location: %s:%i)", protocol::now().user.rpc.address.c_str(), (int)protocol::now().user.rpc.port);

			bind(0, "websocket", "subscribe", 1, 3, "string addresses, bool? blocks, bool? transactions", "uint64", "subscribe to streams of incoming blocks and transactions optionally include blocks and transactions relevant to comma separated address list", std::bind(&server_node::web_socket_subscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "websocket", "unsubscribe", 1, 1, "", "void", "unsubscribe from all streams", std::bind(&server_node::web_socket_unsubscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "encodeaddress", 1, 1, "string public_key_hash", "string", "encode public key hash", std::bind(&server_node::utility_encode_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodeaddress", 1, 1, "string address", "string", "decode address", std::bind(&server_node::utility_decode_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodemessage", 1, 1, "string message", "any[]", "decode message", std::bind(&server_node::utility_decode_message, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodetransaction", 1, 1, "string message_hex", "{ transaction: txn, signer_address: string }", "decode transaction message and convert to object", std::bind(&server_node::utility_decode_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "help", 0, 0, "", "{ declaration: string, method: string, description: string }[]", "get reference of all methods", std::bind(&server_node::utility_help, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblocks", 2, 2, "uint64 number, uint64 count", "uint256[]", "get block hashes", std::bind(&server_node::blockstate_get_blocks, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockcheckpointhash", 0, 0, "", "uint256", "get block checkpoint hash", std::bind(&server_node::blockstate_get_block_checkpoint_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockcheckpointnumber", 0, 0, "", "uint64", "get block checkpoint number", std::bind(&server_node::blockstate_get_block_checkpoint_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblocktiphash", 0, 0, "", "uint256", "get block tip hash", std::bind(&server_node::blockstate_get_block_tip_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblocktipnumber", 0, 0, "", "uint64", "get block tip number", std::bind(&server_node::blockstate_get_block_tip_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "block", "get block by hash", std::bind(&server_node::blockstate_get_block_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "block", "get block by number", std::bind(&server_node::blockstate_get_block_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getrawblockbyhash", 1, 1, "uint256 hash", "string", "get block by hash", std::bind(&server_node::blockstate_get_raw_block_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getrawblockbynumber", 1, 1, "uint64 number", "string", "get block by number", std::bind(&server_node::blockstate_get_raw_block_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockproofbyhash", 1, 4, "uint256 hash, bool? transactions, bool? receipts, bool? states", "block::proof", "get block proof by hash", std::bind(&server_node::blockstate_get_block_proof_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockproofbynumber", 1, 4, "uint64 number, bool? transactions, bool? receipts, bool? states", "block::proof", "get block proof by number", std::bind(&server_node::blockstate_get_block_proof_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblocknumberbyhash", 1, 1, "uint256 hash", "uint64", "get block number by hash", std::bind(&server_node::blockstate_get_block_number_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "blockstate", "getblockhashbynumber", 1, 1, "uint64 number", "uint256", "get block hash by number", std::bind(&server_node::blockstate_get_block_hash_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getblocktransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by hash", std::bind(&server_node::txnstate_get_block_transactions_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getblocktransactionsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by number", std::bind(&server_node::txnstate_get_block_transactions_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getpendingtransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by hash", std::bind(&server_node::txnstate_get_block_transactions_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getpendingtransactionsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by number", std::bind(&server_node::txnstate_get_block_transactions_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getfinalizedtransactions", 2, 3, "uint64 offset, uint64 count, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get latest finalized transactions", std::bind(&server_node::txnstate_get_finalized_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "gettransactionsbyowner", 3, 5, "string owner_address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get transactions by owner", std::bind(&server_node::txnstate_get_transactions_by_owner, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "gettransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "txn | block::txn", "get transactions by hash including aliases", std::bind(&server_node::txnstate_get_transactions_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "gettransactionbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "txn | block::txn", "get transaction by hash including aliases", std::bind(&server_node::txnstate_get_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getrawtransactionbyhash", 1, 1, "uint256 hash", "string", "get raw transaction by hash", std::bind(&server_node::txnstate_get_raw_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "calltransaction", 4, 32, "string asset, string from_address, string to_address, string function, any... args", "program_trace", "execute of immutable function of program assigned to to_address", std::bind(&server_node::chainstate_call_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockstatebyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block state by hash", std::bind(&server_node::chainstate_get_block_state_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockstatebynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block state by number", std::bind(&server_node::chainstate_get_block_state_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockgaspricebyhash", 2, 3, "uint256 hash, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by hash", std::bind(&server_node::chainstate_get_block_gas_price_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockgaspricebynumber", 2, 3, "uint64 number, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by number", std::bind(&server_node::chainstate_get_block_gas_price_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockassetpricebyhash", 3, 4, "uint256 hash, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by hash", std::bind(&server_node::chainstate_get_block_asset_price_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockassetpricebynumber", 3, 4, "uint64 number, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by number", std::bind(&server_node::chainstate_get_block_asset_price_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getuniform", 2, 2, "string type, any index", "uniform", "get uniform by type and index", std::bind(&server_node::chainstate_get_uniform, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiform", 3, 3, "string type, any column, any row", "multiform", "get multiform by type, column and row", std::bind(&server_node::chainstate_get_multiform, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformsbycolumn", 4, 4, "string type, any column, uint64 offset, uint64 count", "multiform[]", "get multiform by type and column", std::bind(&server_node::chainstate_get_multiforms_by_column, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformsbycolumnfilter", 7, 7, "string type, any column, string rank_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', uint256 rank_value, int8 rank_order, uint64 offset, uint64 count", "multiform[]", "get multiform by type, column and rank", std::bind(&server_node::chainstate_get_multiforms_by_column_filter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformsbyrow", 4, 4, "string type, any row, uint64 offset, uint64 count", "multiform[]", "get multiform by type and row", std::bind(&server_node::chainstate_get_multiforms_by_row, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformsbyrowfilter", 7, 7, "string type, any row, string rank_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', uint256 rank_value, int8 rank_order, uint64 offset, uint64 count", "multiform[]", "get multiform by type, row and rank", std::bind(&server_node::chainstate_get_multiforms_by_row_filter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformscountbycolumn", 2, 2, "string type, any column", "uint64", "get multiform count by type and column", std::bind(&server_node::chainstate_get_multiforms_count_by_column, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformscountbycolumnfilter", 4, 4, "string type, any column, string rank_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', uint256 rank_value", "uint64", "get multiform count by type, column and rank", std::bind(&server_node::chainstate_get_multiforms_count_by_column_filter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformscountbyrow", 2, 2, "string type, any row", "uint64", "get multiform count by type and row", std::bind(&server_node::chainstate_get_multiforms_count_by_row, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformscountbyrowfilter", 4, 4, "string type, any row, string rank_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', uint256 rank_value", "uint64", "get multiform count by type, row and rank", std::bind(&server_node::chainstate_get_multiforms_count_by_row_filter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountnonce", 1, 1, "string address", "uint64", "get account nonce by address", std::bind(&server_node::chainstate_get_account_nonce, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountprogram", 1, 1, "string address", "uniform", "get account program hashcode by address", std::bind(&server_node::chainstate_get_account_program, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountuniform", 2, 2, "string address, string index", "uniform", "get account storage by address and index", std::bind(&server_node::chainstate_get_account_uniform, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountmultiform", 3, 3, "string address, string column, string row", "multiform", "get account storage by address, column and row", std::bind(&server_node::chainstate_get_account_multiform, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountmultiforms", 4, 4, "string address, string column, uint64 offset, uint64 count", "multiform[]", "get account storage by address and column", std::bind(&server_node::chainstate_get_account_multiforms, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalance", 2, 2, "string address, string asset", "multiform", "get account balance by address and asset", std::bind(&server_node::chainstate_get_account_balance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalances", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account balances by address", std::bind(&server_node::chainstate_get_account_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorproduction", 1, 1, "string address", "multiform", "get validator production by address", std::bind(&server_node::chainstate_get_validator_production, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorproductionwithrewards", 1, 1, "string address", "multiform", "get validator production with rewards by address", std::bind(&server_node::chainstate_get_validator_production_with_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorproducers", 3, 3, "uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator producers (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_producers, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorproductionreward", 2, 2, "string address, string asset", "multiform", "get validator production reward by address and asset", std::bind(&server_node::chainstate_get_validator_production_reward, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorproductionrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform", "get validator production rewards by address", std::bind(&server_node::chainstate_get_validator_production_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipation", 1, 1, "string address", "multiform", "get validator participation by address", std::bind(&server_node::chainstate_get_validator_participation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipationwithrewards", 1, 1, "string address", "multiform", "get validator participation with rewards by address", std::bind(&server_node::chainstate_get_validator_participation_with_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipations", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get validator participations by address", std::bind(&server_node::chainstate_get_validator_participations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorparticipation", 3, 3, "uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator participations (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_participations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipationreward", 2, 2, "string address, string asset", "multiform", "get validator participation reward by address and asset", std::bind(&server_node::chainstate_get_validator_participation_reward, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipationrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform", "get validator participation rewards by address", std::bind(&server_node::chainstate_get_validator_participation_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipationref", 2, 2, "string owner_address, string ref_owner_address, string ref_asset, uint256 ref_hash", "multiform", "get validator participation by ref", std::bind(&server_node::chainstate_get_validator_participation_ref, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipationrefs", 3, 3, "string owner_address, uint64 offset, uint64 count", "multiform", "get validator participation refs by address", std::bind(&server_node::chainstate_get_validator_participation_refs, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestation", 2, 2, "string asset, string address", "multiform", "get validator attestation by address and asset", std::bind(&server_node::chainstate_get_validator_attestation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestationwithrewards", 2, 2, "string asset, string address", "multiform", "get validator attestation by address and asset", std::bind(&server_node::chainstate_get_validator_attestation_with_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestations", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get validator attestations by address", std::bind(&server_node::chainstate_get_validator_attestations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestationswithrewards", 1, 1, "string address", "multiform[]", "get validator attestations with rewards by address", std::bind(&server_node::chainstate_get_validator_attestations_with_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorattestations", 3, 3, "string asset, uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator attestations (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_attestations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestationreward", 2, 2, "string address, string asset", "multiform", "get validator attestation reward by address and asset", std::bind(&server_node::chainstate_get_validator_attestation_reward, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestationrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform", "get validator attestation rewards by address", std::bind(&server_node::chainstate_get_validator_attestation_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbridgeaccount", 3, 3, "string owner_address, string asset, uint256 hash", "multiform", "get bridge account by owner addresses, asset and hash", std::bind(&server_node::chainstate_get_bridge_account, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbridgeaccounts", 3, 3, "uint256 hash, uint64 offset, uint64 count", "multiform[]", "get bridge accounts by hash", std::bind(&server_node::chainstate_get_bridge_accounts, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbridgeinstance", 2, 2, "string asset, uint256 hash", "multiform", "get bridge instance by asset and hash", std::bind(&server_node::chainstate_get_bridge_instance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbridgeinstances", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get bridge balances by asset", std::bind(&server_node::chainstate_get_bridge_instances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestbridgeinstances", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get best bridge balances by asset", std::bind(&server_node::chainstate_get_best_bridge_instances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestbridgeinstancesbysecurity", 3, 3, "string asset, uint64 offset, uint64 count", "{ instance: multiform, balance: multiform? }[]", "get best bridge instance based on security level", std::bind(&server_node::chainstate_get_best_bridge_instances_by_security, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestbridgeinstancesbybalance", 3, 3, "string asset, uint64 offset, uint64 count", "{ instance: multiform?, balance: multiform }[]", "get best bridge instance based on total value locked", std::bind(&server_node::chainstate_get_best_bridge_instances_by_balance, this, std::placeholders::_1, std::placeholders::_2));	
			bind(0 | access_type::r, "chainstate", "getbridgebalance", 2, 2, " string asset, uint256 hash", "multiform", "get bridge balance by asset and hash", std::bind(&server_node::chainstate_get_bridge_balance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbridgebalances", 3, 3, "uint256 hash, uint64 offset, uint64 count", "multiform[]", "get bridge balances by hash", std::bind(&server_node::chainstate_get_bridge_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestbridgebalances", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best bridge balance", std::bind(&server_node::chainstate_get_best_bridge_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessprogram", 1, 1, "string hashcode", "uniform", "get witness program by hashcode (512bit number)", std::bind(&server_node::chainstate_get_witness_program, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessevent", 1, 1, "uint256 transaction_hash", "uniform", "get witness event by transaction hash", std::bind(&server_node::chainstate_get_witness_event, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccount", 3, 3, "string address, string asset, string wallet_address", "multiform", "get witness address by owner address, asset, wallet address", std::bind(&server_node::chainstate_get_witness_account, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccounttagged", 3, 3, "string asset, string wallet_address, uint64 offset", "multiform", "get witness address by asset and wallet address", std::bind(&server_node::chainstate_get_witness_account_tagged, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccounts", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_accounts, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccountsbypurpose", 4, 4, "string address, string purpose = 'witness' | 'router' | 'custodian' | 'bridge', uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_accounts_by_purpose, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnesstransaction", 2, 2, "string asset, string transaction_id", "uniform", "get witness transaction by asset and transaction id", std::bind(&server_node::chainstate_get_witness_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getassetholders", 2, 2, "string asset, uint256 rank", "uint64", "get amount of asset holders with rank (balance value) greater or equal some value", std::bind(&server_node::chainstate_get_asset_holders, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnode", 0, 1, "uint64? offset", "validator", "get closest node info", std::bind(&server_node::mempoolstate_get_closest_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnodecount", 0, 0, "", "uint64", "get closest node count", std::bind(&server_node::mempoolstate_get_closest_node_counter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnode", 1, 1, "string uri_address", "validator", "get associated node info by ip address", std::bind(&server_node::mempoolstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getaddresses", 2, 3, "uint64 offset, uint64 count, string? services = 'consensus' | 'discovery' | 'superchain' | 'rpc' | 'rpc_public_access' | 'rpc_web_sockets' | 'production' | 'participation' | 'attestation'", "string[]", "get best node ip addresses with optional comma separated list of services", std::bind(&server_node::mempoolstate_get_addresses, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getgasprice", 1, 3, "string asset, double? percentile = 0.5, bool? mempool_only", "{ price: decimal, paid: boolean }", "get gas price from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_gas_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getassetprice", 2, 3, "string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_asset_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "simulatetransaction", 1, 1, "string message_hex", "uint256", "execute transaction with block gas limit and return the receipt", std::bind(&server_node::mempoolstate_simulate_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionbyhash", 1, 1, "uint256 hash", "txn", "get mempool transaction by hash", std::bind(&server_node::mempoolstate_get_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getrawmempooltransactionbyhash", 1, 1, "uint256 hash", "string", "get raw mempool transaction by hash", std::bind(&server_node::mempoolstate_get_raw_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnextaccountnonce", 1, 1, "string owner_address", "uint64", "get account nonce for next transaction by owner", std::bind(&server_node::mempoolstate_get_next_account_nonce, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactions", 3, 4, "bool commitment, uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions", std::bind(&server_node::mempoolstate_get_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionsbyowner", 3, 5, "const string address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions by signing address", std::bind(&server_node::mempoolstate_get_transactions_by_owner, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getnode", 1, 1, "string uri_address", "validator", "get a node by ip address", std::bind(&server_node::validatorstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getblockchains", 0, 0, "", "superchain::asset_info[]", "get supported blockchains", std::bind(&server_node::validatorstate_get_blockchains, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "status", 0, 0, "", "validator::status", "get validator status", std::bind(&server_node::validatorstate_status, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::r, "mempoolstate", "submittransaction", 1, 1, "string message_hash", "uint256", "try to accept and relay a mempool transaction from raw data and possibly validate over latest chainstate", std::bind(&server_node::mempoolstate_submit_transaction, this, std::placeholders::_1, std::placeholders::_2, nullptr));
			bind(access_type::w | access_type::a, "mempoolstate", "rejecttransaction", 1, 1, "uint256 hash", "void", "remove mempool transaction by hash", std::bind(&server_node::mempoolstate_reject_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "simulatebridge", 4, 4, "string asset, string bridge_hash, string to_address, decimal to_value", "superchain_transaction", "build an off-chain attestation transaction payload using off-chain node", std::bind(&server_node::mempoolstate_simulate_bridge, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "addnode", 1, 1, "string uri_address", "void", "add node ip address to trial addresses", std::bind(&server_node::mempoolstate_add_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "clearnode", 1, 1, "string uri_address", "void", "remove associated node info by ip address", std::bind(&server_node::mempoolstate_clear_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "importentropies", 2, 1024, "string participant_address, string password, string... messages", "void", "import a set of encrypted entropy messages", std::bind(&server_node::validatorstate_import_entropies, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "exportentropies", 2, 2, "string participant_address, string password", "void", "export a set of encrypted entropy messages", std::bind(&server_node::validatorstate_export_entropies, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "setwallet", 2, 2, "string type = 'mnemonic' | 'seed' | 'key', string entropy", "wallet", "set validator wallet from mnemonic phrase, seed value or secret key", std::bind(&server_node::validatorstate_set_wallet, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "getwallet", 0, 0, "", "wallet", "get validator wallet", std::bind(&server_node::validatorstate_get_wallet, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "verify", 2, 3, "uint64 number, uint64 count, bool? validate", "uint256[]", "verify chain and possibly re-execute each block", std::bind(&server_node::validatorstate_verify, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "revert", 1, 1, "uint64 number", "{ new_tip_block_number: uint64, old_tip_block_number: uint64, block_delta: int64, transaction_delta: int64, state_delta: int64, is_fork: bool }", "revert chainstate to block number and possibly send removed transactions to mempool", std::bind(&server_node::validatorstate_revert, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "acceptnode", 1, 1, "string uri_address", "void", "try to accept and connect to a node possibly by ip address", std::bind(&server_node::validatorstate_accept_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "rejectnode", 1, 1, "string uri_address", "void", "reject and disconnect from a node by ip address", std::bind(&server_node::validatorstate_reject_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "submitblock", 0, 0, "", "void", "try to propose a block from mempool transactions", std::bind(&server_node::validatorstate_submit_block, this, std::placeholders::_1, std::placeholders::_2));
		}
		void server_node::shutdown()
		{
			if (!is_active())
				return;

			if (protocol::now().user.consensus.logging)
				VI_INFO("OK rpc node shutdown");

			node->unlisten(false);
		}
		void server_node::bind(uint32_t access_types, const std::string_view& domain, const std::string_view& method, size_t min_params, size_t max_params, const std::string_view& args, const std::string_view& returns, const std::string_view& description, server_function&& function)
		{
			server_request item;
			item.access_types = access_types;
			item.min_params = min_params;
			item.max_params = max_params;
			item.domain = domain;
			item.args = args;
			item.returns = returns;
			item.description = description;
			item.function = std::move(function);
			methods[string(method)] = std::move(item);
		}
		bool server_node::is_active()
		{
			return node->get_state() == server_state::working;
		}
		bool server_node::authorize(http::connection*, http::credentials* credentials)
		{
			return credentials->token == auth_token;
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
			content.append("Access-control-allow-methods: POST\r\n");
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
			content->append("Allow: POST\r\n");

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
		bool server_node::http_request(http::connection* base)
		{
			base->response.set_header("Content-Type", "application/json");
			return base->fetch([this](http::connection* base, socket_poll event, const std::string_view&) -> bool
			{
				if (!packet::is_done(event))
					return true;

				auto request = format::tree::from_json(std::string_view(base->request.content.data.data(), base->request.content.data.size()));
				if (request)
				{
					cospawn([this, base, request = std::move(request)]() mutable
					{
						dispatch_response(base, std::move(*request), optional::none, 0, [](http::connection* base, option<format::tree>&& responses)
						{
							base->response.content.assign((responses ? *responses : server_response().error(error_codes::bad_request, "request is empty").transform(format::tree())).as_json());
							base->next(200);
						});
					});
				}
				else
				{
					base->response.content.assign(server_response().error(error_codes::bad_request, request.error().message()).transform(format::tree()).as_json());
					base->next(200);
				}
				return true;
			});
		}
		bool server_node::ws_receive(http::web_socket_frame* web_socket, http::web_socket_op opcode, const std::string_view& buffer)
		{
			if (opcode != http::web_socket_op::binary && opcode != http::web_socket_op::text)
				return false;

			auto request = format::tree::from_json(buffer);
			if (request)
			{
				auto* base = web_socket->get_connection();
				base->info.start = vitex::network::utils::clock();
				cospawn([this, base, request = std::move(request)]() mutable
				{
					dispatch_response(base, std::move(*request), optional::none, 0, [](http::connection* base, option<format::tree>&& responses)
					{
						if (responses)
							base->web_socket->send(responses->as_json(), http::web_socket_op::text, [](http::web_socket_frame* web_socket) { web_socket->next(); });	
						else
							base->web_socket->send(server_response().error(error_codes::bad_request, "request is empty").transform(format::tree()).as_json(), http::web_socket_op::text, [](http::web_socket_frame* web_socket) { web_socket->next(); });				
					});
				});
			}
			else
				web_socket->send(server_response().error(error_codes::bad_request, request.error().message()).transform(format::tree()).as_json(), http::web_socket_op::text, [](http::web_socket_frame* web_socket) { web_socket->next(); });

			return true;
		}
		void server_node::ws_disconnect(http::web_socket_frame* web_socket)
		{
			umutex<std::mutex> unique(mutex);
			listeners.erase(web_socket->get_connection());
			unique.unlock();
			web_socket->next();
		}
		bool server_node::dispatch_response(http::connection* base, format::tree&& requests, option<format::tree>&& responses, size_t index, std::function<void(http::connection*, option<format::tree>&&)>&& callback)
		{
			if (!requests.is_list())
			{
				auto array = format::tree::list();
				array.push(std::move(requests));
				requests = std::move(array);
			}

		next_request:
			auto* request = index < requests.childs().size() ? &requests.childs()[index++] : (format::tree*)nullptr;
			if (!request)
			{
				callback(base, std::move(responses));
				return true;
			}

			auto* version = request->child("jsonrpc");
			if (!version || version->value.as_uint8() != 2)
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_version, "only version 2.0 is supported"));
				goto next_request;
			}

			auto* method = request->child("method");
			if (!method || !method->value.is_string())
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_method, "method is not a string"));
				goto next_request;
			}

			auto context = methods.find(method->value.as_string());
			if (context == methods.end())
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_method, "method \"" + method->value.as_blob() + "\" not found"));
				goto next_request;
			}

			if (protocol::now().user.rpc.sandbox && context->second.access_types & (uint32_t)access_type::a)
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_method, "access to admin level functionality requires trusted environment"));
				goto next_request;
			}

			auto* params = request->child("params");
			if (!params || !params->is_list())
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_method, "params is not an array"));
				goto next_request;
			}

			if (params->childs().size() < context->second.min_params || params->childs().size() > context->second.max_params)
			{
				form_response(base, *request, responses, server_response().error(error_codes::bad_method, "params is not an array[" + to_string(context->second.min_params) + ".." + to_string(context->second.min_params) + "]"));
				goto next_request;
			}

			format::variables args;
			args.reserve(params->childs().size());
			for (auto& param : params->childs())
			{
				if (param.is_list())
				{
					if (param.childs().size() == 2)
					{
						auto& type_ref = param.childs()[0];
						auto& value_ref = param.childs()[1];
						if (type_ref.value.is_string() && value_ref.value.is_string())
						{
							auto type = type_ref.value.as_string();
							auto value = value_ref.value.as_string();
							if (type == "$uint128")
							{
								args.push_back(format::variable(format::util::is_hex_encoding(value) ? algorithm::encoding::decode_0xhex128(value) : uint128_t(value, 10)));
								continue;
							}
							else if (type == "$uint256")
							{
								args.push_back(format::variable(format::util::is_hex_encoding(value) ? algorithm::encoding::decode_0xhex256(value) : uint256_t(value, 10)));
								continue;
							}
							else if (type == "$asset256")
							{
								args.push_back(format::variable(algorithm::asset::id_of_handle(value)));
								continue;
							}
						}
					}
					args.push_back(format::variable(param.as_json()));

				}
				else if (param.is_map())
					args.push_back(format::variable(param.as_json()));
				else
					args.push_back(param.value);
			}

			cospawn([this, request, context, base, index, requests = std::move(requests), responses = std::move(responses), callback = std::move(callback), args = std::move(args)]() mutable
			{
				auto response = context->second.function(base, std::move(args));
				form_response(base, *request, responses, std::move(response));
				if (index < requests.childs().size())
					dispatch_response(base, std::move(requests), std::move(responses), index, std::move(callback));
				else
					callback(base, std::move(responses));
			});
			return true;
		}
		void server_node::dispatch_accept_block(const uint256_t& block_hash, const ledger::block_body& block, const ledger::block_checkpoint&)
		{
			umutex<std::mutex> unique(mutex);
			if (listeners.empty())
				return;

			btree_set<algorithm::pubkeyhash_t> addresses;
			auto executor = ledger::executor_context(nullptr);
			for (auto& transaction : block.transactions)
			{
				addresses.insert(algorithm::pubkeyhash_t(transaction.receipt.from));
				transaction.transaction->recover_many(&executor, transaction.receipt, addresses);
			}

			hash_set<http::web_socket_frame*> web_sockets;
			for (auto& listener : listeners)
			{
				if (!listener.first->web_socket)
					continue;

				if (!listener.second.blocks)
				{
					bool found = false;
					for (auto& address : listener.second.addresses)
					{
						found = addresses.find(address) != addresses.end();
						if (found)
							break;
					}
					if (found)
						web_sockets.insert(listener.first->web_socket);
				}
				else
					web_sockets.insert(listener.first->web_socket);
			}

			unique.unlock();
			if (web_sockets.empty())
				return;

			uint64_t block_number = block.number;
			cospawn([block_hash, block_number, web_sockets = std::move(web_sockets)]() mutable
			{
				auto notification = format::tree::map();
				notification.set("type", format::variable("block"));

				auto result = notification.set("result", format::tree::map());
				result->set("hash", format::variable(algorithm::encoding::encode_0xhex256(block_hash)));
				result->set("number", format::variable(block_number));

				auto response = server_response().notification(std::move(notification)).transform(format::tree()).as_json();
				for (auto& web_socket : web_sockets)
					web_socket->send(response, http::web_socket_op::text, nullptr);
			});
		}
		void server_node::dispatch_accept_transaction(const uint256_t& transaction_hash, const ledger::transaction_message*, const algorithm::pubkeyhash_t& owner)
		{
			umutex<std::mutex> unique(mutex);
			if (listeners.empty())
				return;

			auto address = algorithm::pubkeyhash_t(owner);
			hash_set<http::web_socket_frame*> web_sockets;
			for (auto& listener : listeners)
			{
				if (!listener.first->web_socket)
					continue;
				else if (listener.second.transactions || listener.second.addresses.find(address) != listener.second.addresses.end())
					web_sockets.insert(listener.first->web_socket);
			}

			unique.unlock();
			if (web_sockets.empty())
				return;

			cospawn([transaction_hash, web_sockets = std::move(web_sockets)]() mutable
			{
				auto notification = format::tree::map();
				notification.set("type", format::variable("transaction"));

				auto result = notification.set("result", format::tree::map());
				result->set("hash", format::variable(algorithm::encoding::encode_0xhex256(transaction_hash)));

				auto response = server_response().notification(std::move(notification)).transform(format::tree()).as_json();
				for (auto& web_socket : web_sockets)
					web_socket->send(response, http::web_socket_op::text, nullptr);
			});
		}
		service_control::service_node server_node::get_entrypoint()
		{
			if (!protocol::now().user.rpc.server)
				return service_control::service_node();

			service_control::service_node entrypoint;
			entrypoint.startup = std::bind(&server_node::startup, this);
			entrypoint.shutdown = std::bind(&server_node::shutdown, this);
			return entrypoint;
		}
		server_response server_node::web_socket_subscribe(http::connection* base, format::variables&& args)
		{
			if (!base->web_socket)
				return server_response().error(error_codes::bad_request, "requires protocol upgrade");

			ws_listener listener;
			listener.blocks = args.size() > 1 ? args[1].as_boolean() : false;
			listener.transactions = args.size() > 2 ? args[2].as_boolean() : false;

			size_t address_index = 0;
			for (auto& address : stringify::split(args[0].as_string(), ','))
			{
				algorithm::pubkeyhash_t owner;
				if (!algorithm::signing::decode_address(stringify::trim(address), owner))
					return server_response().error(error_codes::bad_params, "address[" + to_string(address_index) + "] not valid");

				listener.addresses.insert(algorithm::pubkeyhash_t(owner));
				++address_index;
			}

			umutex<std::mutex> unique(mutex);
			listeners[base] = std::move(listener);
			unique.unlock();
			return server_response().success(format::variable(address_index + (listener.blocks || listener.transactions ? 1 : 0)));
		}
		server_response server_node::web_socket_unsubscribe(http::connection* base, format::variables&&)
		{
			if (!base->web_socket)
				return server_response().error(error_codes::bad_request, "requires protocol upgrade");

			umutex<std::mutex> unique(mutex);
			listeners.erase(base);
			unique.unlock();
			return server_response().success(format::variable());
		}
		server_response server_node::utility_encode_address(http::connection*, format::variables&& args)
		{
			auto owner = format::util::decode_0xhex(args[0].as_string());
			if (owner.size() == sizeof(algorithm::pubkeyhash_t))
				return server_response().success(format::variable(algorithm::signing::encode_address((uint8_t*)owner.data())));

			return server_response().error(error_codes::bad_params, "raw address not valid");
		}
		server_response server_node::utility_decode_address(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t data;
			if (!algorithm::signing::decode_address(args[0].as_string(), data))
				return server_response().error(error_codes::bad_params, "address not valid");

			return server_response().success(format::variable(format::util::encode_0xhex(data.view())));
		}
		server_response server_node::utility_decode_message(http::connection*, format::variables&& args)
		{
			format::variables values;
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			if (!format::variables_util::deserialize_flat_from(message, &values))
				return server_response().error(error_codes::bad_params, "invalid message");

			return server_response().success(format::variables_util::serialize(values));
		}
		server_response server_node::utility_decode_transaction(http::connection*, format::variables&& args)
		{
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction_message> candidate_tx = transactions::resolver::from_stream(message);
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			algorithm::pubkeyhash_t owner;
			bool recoverable = candidate_tx->recover_hash(owner);
			auto result = format::tree::map();
			result.set("transaction", candidate_tx->as_tree());
			result.set("signer_message", recoverable ? format::variable(candidate_tx->as_signable().encode()) : format::variable());
			result.set("signer_address", recoverable ? algorithm::signing::serialize_address(owner) : format::variable());
			return server_response().success(std::move(result));
		}
		server_response server_node::utility_help(http::connection*, format::variables&&)
		{
			auto data = format::tree::map();
			auto* params = data.set("converters", format::tree::map());
			params->set("uint128", format::variable("[\"$uint128\", \"<integer>\"] -> <uint128>"));
			params->set("uint256", format::variable("[\"$uint256\", \"<integer>\"] -> <uint256>"));
			params->set("asset", format::variable("[\"$asset256\", \"<chain>|<chain:token:checksum>\"] -> <uint256>"));

			auto* functions = data.set("functions", format::tree::map());
			for (auto& method : methods)
			{
				string inline_decl;
				if (method.second.access_types & (uint32_t)access_type::a)
					inline_decl += "private ";
				else
					inline_decl += "public ";

				if (method.second.access_types & (uint32_t)access_type::r)
					inline_decl += "view ";

				inline_decl += "function ";
				inline_decl += method.second.domain + "::";
				inline_decl += method.first;
				inline_decl += '(';
				inline_decl += method.second.args;
				if (method.second.access_types & (uint32_t)access_type::w)
					inline_decl += ") returns ";
				else
					inline_decl += ") const returns ";

				if (!method.second.returns.empty())
				{
					if (method.second.returns.find('|') != std::string::npos)
					{
						inline_decl += '(';
						inline_decl += method.second.returns;
						inline_decl += ')';
					}
					else
						inline_decl += method.second.returns;
				}
				else
					inline_decl += "null";

				auto* domain = (format::tree*)functions->child(method.second.domain);
				if (!domain)
					domain = functions->set(method.second.domain, format::tree::list());

				auto* description = domain->push(format::tree::map());
				description->set("function", format::variable(method.first));
				description->set("declaration", format::variable(inline_decl));
				description->set("description", format::variable(method.second.description));
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_blocks(http::connection*, format::variables&& args)
		{
			uint64_t count = args[1].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate();
			auto hashes = chain.get_block_hashset(number, count);
			if (!hashes)
				return server_response().error(error_codes::not_found, "blocks not found");

			auto data = format::tree::list();
			for (auto& item : *hashes)
				data.push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_checkpoint_hash(http::connection*, format::variables&&)
		{
			auto chain = storages::chainstate();
			auto block_number = chain.get_checkpoint_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			auto block_hash = chain.get_block_hash_by_number(*block_number);
			if (!block_hash)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			return server_response().success(format::variable(algorithm::encoding::encode_0xhex256(*block_hash)));
		}
		server_response server_node::blockstate_get_block_checkpoint_number(http::connection*, format::variables&&)
		{
			auto chain = storages::chainstate();
			auto block_number = chain.get_checkpoint_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::blockstate_get_block_tip_hash(http::connection*, format::variables&&)
		{
			auto chain = storages::chainstate();
			auto block_header = chain.get_latest_block_header();
			if (!block_header)
				return server_response().error(error_codes::not_found, "tip block not found");

			return server_response().success(format::variable(algorithm::encoding::encode_0xhex256(block_header->as_hash())));
		}
		server_response server_node::blockstate_get_block_tip_number(http::connection*, format::variables&&)
		{
			auto chain = storages::chainstate();
			auto block_number = chain.get_latest_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "tip block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::blockstate_get_block_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			if (unrolling > 3)
			{
				auto block = chain.get_block_by_hash(hash);
				if (!block)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block->as_tree());
			}

			auto block_header = chain.get_block_header_by_hash(hash);
			if (!block_header)
				return server_response().error(error_codes::not_found, "block not found");
			else if (unrolling == 0)
				return server_response().success(block_header->as_tree());

			auto data = block_header->as_tree();
			auto* transactions = data.set("transactions", format::tree::list());
			if (unrolling == 1)
			{
				auto transaction_hashset = chain.get_block_transaction_hashset(block_header->number);
				if (transaction_hashset)
				{
					for (auto& item : *transaction_hashset)
						transactions->push(format::variable(algorithm::encoding::encode_0xhex256(item)));
				}
			}
			else
			{
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_header->number, transactions->childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(unrolling == 2 ? item.transaction->as_tree() : item.as_tree());
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			if (unrolling > 3)
			{
				auto block = chain.get_block_by_number(number);
				if (!block)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block->as_tree());
			}

			auto block_header = chain.get_block_header_by_number(number);
			if (!block_header)
				return server_response().error(error_codes::not_found, "block not found");
			else if (unrolling == 0)
				return server_response().success(block_header->as_tree());

			auto data = block_header->as_tree();
			auto* transactions = data.set("transactions", format::tree::list());
			if (unrolling == 1)
			{
				auto transaction_hashset = chain.get_block_transaction_hashset(block_header->number);
				if (transaction_hashset)
				{
					for (auto& item : *transaction_hashset)
						transactions->push(format::variable(algorithm::encoding::encode_0xhex256(item)));
				}
			}
			else
			{
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_header->number, transactions->childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(unrolling == 2 ? item.transaction->as_tree() : item.as_tree());
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_raw_block_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate();
			auto block = chain.get_block_by_hash(hash);
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(format::variable(block->as_message().encode()));
		}
		server_response server_node::blockstate_get_raw_block_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate();
			auto block = chain.get_block_by_number(number);
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(format::variable(block->as_message().encode()));
		}
		server_response server_node::blockstate_get_block_proof_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate();
			auto block_proof = chain.get_block_proof_by_hash(hash);
			if (!block_proof)
				return server_response().error(error_codes::not_found, "block not found");

			bool transactions = args[1].as_boolean();
			bool receipts = args[2].as_boolean();
			bool states = args[3].as_boolean();
			auto data = block_proof->as_tree();
			if (!transactions)
				data.pop("transactions");
			if (!receipts)
				data.pop("receipts");
			if (!states)
				data.pop("states");

			if (data.childs().size() == 1)
			{
				auto root = std::move(data);
				data = std::move(root.childs()[0]);
			}

			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_proof_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate();
			auto block_proof = chain.get_block_proof_by_number(number);
			if (!block_proof)
				return server_response().error(error_codes::not_found, "block not found");

			bool transactions = args[1].as_boolean();
			bool receipts = args[2].as_boolean();
			bool states = args[3].as_boolean();
			auto data = block_proof->as_tree();
			if (!transactions)
				data.pop("transactions");
			if (!receipts)
				data.pop("receipts");
			if (!states)
				data.pop("states");

			if (data.childs().size() == 1)
			{
				auto root = std::move(data);
				data = std::move(root.childs()[0]);
			}

			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_number_by_hash(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate();
			auto block_hash = chain.get_block_hash_by_number(number);
			if (!block_hash)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(format::variable(algorithm::encoding::encode_0xhex256(*block_hash)));
		}
		server_response server_node::blockstate_get_block_hash_by_number(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::txnstate_get_block_transactions_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_transaction_hashset(*block_number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& item : *hashes)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			}
			else if (unrolling == 1 || unrolling == 2)
			{
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(*block_number, data.childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data.push(unrolling == 1 ? item.transaction->as_tree() : item.as_tree());
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			else
			{
				auto parties = btree_set<algorithm::pubkeyhash_t>();
				auto aliases = btree_set<uint256_t>();
				auto executor = ledger::executor_context(nullptr);
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(*block_number, data.childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
					{
						auto tx_data = item.as_tree();
						auto affected_data = tx_data.set("affected", format::tree::map());
						affected_data->childs().reserve(2);

						auto accounts_data = affected_data->set("accounts", format::tree::list());
						auto aliases_data = affected_data->set("aliases", format::tree::list());
						item.transaction->recover_many(&executor, item.receipt, parties);
						item.transaction->recover_aliases(aliases);
						accounts_data->push(algorithm::signing::serialize_address(item.receipt.from));
						for (auto& party : parties)
							accounts_data->push(algorithm::signing::serialize_address(party));
						for (auto& alias : aliases)
							aliases_data->push(format::variable(algorithm::encoding::encode_0xhex256(alias)));
						data.push(std::move(tx_data));
						parties.clear();
						aliases.clear();
					}
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_block_transactions_by_number(http::connection*, format::variables&& args)
		{
			uint64_t block_number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto data = format::tree::list();
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_transaction_hashset(block_number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& item : *hashes)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			}
			else if (unrolling == 1 || unrolling == 2)
			{
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_number, data.childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data.push(unrolling == 1 ? item.transaction->as_tree() : item.as_tree());
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			else
			{
				auto parties = btree_set<algorithm::pubkeyhash_t>();
				auto aliases = btree_set<uint256_t>();
				auto executor = ledger::executor_context(nullptr);
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_number, data.childs().size(), protocol::now().message.items_per_query);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
					{
						auto tx_data = item.as_tree();
						auto affected_data = tx_data.set("affected", format::tree::map());
						affected_data->childs().reserve(2);

						auto accounts_data = affected_data->set("accounts", format::tree::list());
						auto aliases_data = affected_data->set("aliases", format::tree::list());
						item.transaction->recover_many(&executor, item.receipt, parties);
						item.transaction->recover_aliases(aliases);
						accounts_data->push(algorithm::signing::serialize_address(item.receipt.from));
						for (auto& party : parties)
							accounts_data->push(algorithm::signing::serialize_address(party));
						for (auto& alias : aliases)
							aliases_data->push(format::variable(algorithm::encoding::encode_0xhex256(alias)));
						data.push(std::move(tx_data));
						parties.clear();
						aliases.clear();
					}
					if (list->size() < protocol::now().message.items_per_query)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_pending_transactions(http::connection*, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 2 ? args[2].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto list = chain.get_pending_block_transactions(std::numeric_limits<int64_t>::max(), offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "block not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item.receipt.transaction_hash)));
			}
			else if (unrolling == 1)
			{
				for (auto& item : *list)
					data.push(item.transaction->as_tree());
			}
			else
			{
				for (auto& item : *list)
					data.push(item.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_finalized_transactions(http::connection* base, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 2 ? args[2].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto list = chain.get_block_transactions(offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "transactions not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item.transaction->as_hash())));
			}
			else if (unrolling == 1)
			{
				for (auto& item : *list)
					data.push(item.transaction->as_tree());
			}
			else
			{
				for (auto& item : *list)
					data.push(item.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_transactions_by_owner(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t direction = args.size() > 3 ? args[3].as_uint8() : 1;
			uint8_t unrolling = args.size() > 4 ? args[4].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto list = chain.get_block_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, direction >= 1 ? 1 : -1, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "transactions not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item.transaction->as_hash())));
			}
			else if (unrolling == 1)
			{
				for (auto& item : *list)
					data.push(item.transaction->as_tree());
			}
			else
			{
				for (auto& item : *list)
					data.push(item.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_transactions_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto list = chain.get_block_transactions_by_hash(hash, true);
			if (!list)
				return server_response().error(error_codes::not_found, "transactions not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item.transaction->as_hash())));
			}
			else if (unrolling == 1)
			{
				for (auto& item : *list)
					data.push(item.transaction->as_tree());
			}
			else
			{
				for (auto& item : *list)
					data.push(item.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::txnstate_get_transaction_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto transaction = chain.get_block_transaction_by_hash(hash, true);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success(unrolling == 0 ? transaction->transaction->as_tree() : transaction->as_tree());
		}
		server_response server_node::txnstate_get_raw_transaction_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate();
			auto transaction = chain.get_block_transaction_by_hash(hash, false);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success(format::variable(transaction->transaction->as_message().encode()));
		}
		server_response server_node::chainstate_call_transaction(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t from;
			if (!algorithm::signing::decode_address(args[1].as_string(), from))
				return server_response().error(error_codes::bad_params, "from account address not valid");

			algorithm::pubkeyhash_t to;
			if (!algorithm::signing::decode_address(args[2].as_string(), to))
				return server_response().error(error_codes::bad_params, "to account address not valid");

			format::variables function_args;
			function_args.reserve(args.size() - 4);
			for (size_t i = 4; i < args.size(); i++)
				function_args.push_back(args[i]);

			auto temp_solver = ledger::solver_context();
			auto index = temp_solver.state.executor.get_account_program(to);
			if (!index)
				return server_response().error(error_codes::bad_params, "to account has no program hash");

			auto temp_transaction = transactions::call();
			temp_transaction.asset = algorithm::asset::id_of_handle(args[0].as_string());
			temp_transaction.call_to(to, args[3].as_string(), std::move(function_args), false);
			temp_transaction.set_gas(decimal::zero(), ledger::block_body::get_gas_limit());

			auto temp_receipt = ledger::transaction_receipt();
			temp_receipt.from = from;

			ledger::block_body temp_block;
			temp_solver.apply_temporary_state(&temp_block, &temp_transaction, std::move(temp_receipt));

			auto returning = format::tree();
			auto execution = temp_transaction.subexecute(&temp_solver.state.executor, [&](const transactions::call::payable_array& payable, void* module_ptr)
			{
				auto script = script::program(&temp_solver.state.executor, (asIScriptModule*)module_ptr);
				return script.execute(script::payable_repr(transactions::call::payable_array(payable)), script::ccall::const_call, temp_transaction.function, temp_transaction.args, [&](void* address, int type_id) -> expects_lr<void>
				{
					returning = format::tree::map();
					auto serialization = script::marshall::store(returning, address, type_id);
					if (!serialization)
					{
						returning = format::tree();
						return layer_exception("return value error: " + serialization.error().message());
					}
					return expectation::met;
				});
			});
			if (!execution)
				return server_response().error(error_codes::bad_params, execution.error().message());

			temp_solver.state.executor.receipt.successful = !!execution;
			temp_solver.state.executor.receipt.block_time = protocol::now().time.now();
			if (!temp_solver.state.executor.receipt.successful)
				temp_solver.state.executor.emit_event(0, { format::variable(execution.what()) }, false);

			auto data = temp_solver.state.executor.receipt.as_tree();
			data.set("to", algorithm::signing::serialize_address(to));
			data.set("result", std::move(returning));
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_block_state_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto data = format::tree::list();
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_state_hashset(*block_number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& item : *hashes)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			}
			else
			{
				auto list = chain.get_block_state_by_number(*block_number, protocol::now().message.items_per_query);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& [index, change] : *list)
					data.push(change.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_block_state_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate();
			auto data = format::tree::list();
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_state_hashset(number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& item : *hashes)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item)));
			}
			else
			{
				auto list = chain.get_block_state_by_number(number, protocol::now().message.items_per_query);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				for (auto& [index, change] : *list)
					data.push(change.as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_block_gas_price_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto price = chain.get_block_gas_price(*block_number, asset, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "gas price not found");

			return server_response().success(format::variable(*price));
		}
		server_response server_node::chainstate_get_block_gas_price_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto chain = storages::chainstate();
			auto price = chain.get_block_gas_price(number, asset, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "gas price not found");

			return server_response().success(format::variable(*price));
		}
		server_response server_node::chainstate_get_block_asset_price_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[1].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[2].as_string());
			double percentile = args.size() > 3 ? args[3].as_double() : 0.50;
			auto chain = storages::chainstate();
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto price = chain.get_block_asset_price(*block_number, asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(format::variable(*price));
		}
		server_response server_node::chainstate_get_block_asset_price_by_number(http::connection*, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[1].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[2].as_string());
			double percentile = args.size() > 3 ? args[3].as_double() : 0.50;
			auto chain = storages::chainstate();
			auto price = chain.get_block_asset_price(number, asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(format::variable(*price));
		}
		server_response server_node::chainstate_get_uniform(http::connection*, format::variables&& args)
		{
			auto location = as_uniform_location(args[0].as_string(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate();
			auto uniform = chain.get_uniform(location->type, nullptr, location->index, 0);
			if (!uniform)
				return server_response().error(error_codes::not_found, "uniform not found");

			return server_response().success(uniform->value->as_tree());
		}
		server_response server_node::chainstate_get_multiform(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], args[2]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate();
			auto multiform = chain.get_multiform(location->type, nullptr, location->column, location->row, 0);
			if (!multiform)
				return server_response().error(error_codes::not_found, "multiform not found");

			return server_response().success(multiform->value->as_tree());
		}
		server_response server_node::chainstate_get_multiforms_by_column(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(location->type, nullptr, location->column, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_column_filter(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[5].as_uint64(), count = args[6].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), args[4].as_decimal().to_int8());
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column_filter(location->type, nullptr, location->column, filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_row(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row(location->type, nullptr, location->row, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_row_filter(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[5].as_uint64(), count = args[6].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), args[4].as_decimal().to_int8());
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(location->type, nullptr, location->row, filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_count_by_column(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate();
			auto count = chain.get_multiforms_count_by_column(location->type, nullptr, location->column, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_column_filter(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), 0);
			auto chain = storages::chainstate();
			auto count = chain.get_multiforms_count_by_column_filter(location->type, nullptr, location->column, filter, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_row(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate();
			auto count = chain.get_multiforms_count_by_row(location->type, nullptr, location->row, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_row_filter(http::connection*, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), 0);
			auto chain = storages::chainstate();
			auto count = chain.get_multiforms_count_by_row_filter(location->type, nullptr, location->row, filter, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_account_nonce(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(owner), 0);
			auto* value = (states::account_nonce*)(state ? state->ptr() : nullptr);
			return server_response().success(algorithm::encoding::serialize_uint256(value ? value->nonce : 1));
		}
		server_response server_node::chainstate_get_account_program(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_program::as_instance_type(), nullptr, states::account_program::as_instance_index(owner), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_account_uniform(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::account_uniform::as_instance_type(), nullptr, states::account_uniform::as_instance_index(owner, args[1].as_string()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_account_multiform(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::account_multiform::as_instance_type(), nullptr, states::account_multiform::as_instance_column(owner, args[1].as_string()), states::account_multiform::as_instance_row(owner, args[2].as_string()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_account_multiforms(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::account_multiform::as_instance_type(), nullptr, states::account_multiform::as_instance_column(owner, args[1].as_string()), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_balance(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::account_balance::as_instance_type(), nullptr, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_account_balances(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::account_balance::as_instance_type(), nullptr, states::account_balance::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_production(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_production::as_instance_type(), nullptr, states::validator_production::as_instance_column(owner), states::validator_production::as_instance_row(), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_production_with_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_production::as_instance_type(), nullptr, states::validator_production::as_instance_column(owner), states::validator_production::as_instance_row(), 0);
			if (!state)
				return server_response().success(format::variable());

			size_t count = 512;
			auto result = state->value->as_tree();
			auto rewards = result.set("rewards", format::tree::list());
			auto stride = states::validator_production_reward::as_instance_column(owner);
			while (true)
			{
				auto states = chain.get_multiforms_by_column(states::validator_production_reward::as_instance_type(), nullptr, stride, 0, rewards->childs().size(), count);
				if (!states)
					break;

				for (auto& item : *states)
					rewards->push(item.ptr()->as_tree());

				if (states->size() != count)
					break;
			}
			return server_response().success(std::move(result));
		}
		server_response server_node::chainstate_get_best_validator_producers(http::connection*, format::variables&& args)
		{
			uint256_t commitment = args[0].as_uint256();
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(states::validator_production::as_instance_type(), nullptr, states::validator_production::as_instance_row(), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_production_reward(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::validator_production_reward::as_instance_type(), nullptr, states::validator_production_reward::as_instance_column(owner), states::validator_production_reward::as_instance_row(asset), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_production_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_production_reward::as_instance_type(), nullptr, states::validator_production_reward::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_participation(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_column(owner), states::validator_participation::as_instance_row(), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_participation_with_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_column(owner), states::validator_participation::as_instance_row(), 0);
			if (!state)
				return server_response().success(format::variable());

			size_t count = 512;
			auto result = state->value->as_tree();
			auto rewards = result.set("rewards", format::tree::list());
			auto stride = states::validator_participation_reward::as_instance_column(owner);
			while (true)
			{
				auto states = chain.get_multiforms_by_column(states::validator_participation_reward::as_instance_type(), nullptr, stride, 0, rewards->childs().size(), count);
				if (!states)
					break;

				for (auto& item : *states)
					rewards->push(item.ptr()->as_tree());

				if (states->size() != count)
					break;
			}
			return server_response().success(std::move(result));
		}
		server_response server_node::chainstate_get_validator_participations(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_validator_participations(http::connection*, format::variables&& args)
		{
			uint256_t commitment = args[0].as_uint256();
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_row(), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_participation_reward(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::validator_participation_reward::as_instance_type(), nullptr, states::validator_participation_reward::as_instance_column(owner), states::validator_participation_reward::as_instance_row(asset), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_participation_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_participation_reward::as_instance_type(), nullptr, states::validator_participation_reward::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_participation_ref(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			states::bridge_ref ref;
			ref.asset = algorithm::asset::id_of_handle(args[2].as_string());
			ref.hash = args[3].as_string();
			if (!algorithm::signing::decode_address(args[1].as_string(), ref.owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_participation_ref::as_instance_type(), nullptr, states::validator_participation_ref::as_instance_column(owner), states::validator_participation_ref::as_instance_row(ref), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_participation_refs(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_participation_ref::as_instance_type(), nullptr, states::validator_participation_ref::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_attestation(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(owner), states::validator_attestation::as_instance_row(asset), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_attestation_with_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(owner), states::validator_attestation::as_instance_row(asset), 0);
			if (!state)
				return server_response().success(format::variable());

			size_t offset = 0, count = 512;
			auto result = state->value->as_tree();
			auto rewards = result.set("rewards", format::tree::list());
			auto stride = states::validator_attestation_reward::as_instance_column(owner);
			while (true)
			{
				auto states = chain.get_multiforms_by_column(states::validator_attestation_reward::as_instance_type(), nullptr, stride, 0, offset, count);
				if (!states)
					break;

				for (auto& item : *states)
				{
					auto* ref = item.as<states::validator_attestation_reward>();
					if (asset == algorithm::asset::base_id_of(ref->asset))
						rewards->push(item.ptr()->as_tree());
				}

				offset += states->size();
				if (states->size() != count)
					break;
			}
			return server_response().success(std::move(result));
		}
		server_response server_node::chainstate_get_validator_attestations(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_attestations_with_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			size_t count = 512;
			auto chain = storages::chainstate();
			auto attestations = vector<states::validator_attestation>();
			auto stride = states::validator_attestation::as_instance_column(owner);
			while (true)
			{
				auto states = chain.get_multiforms_by_column(states::validator_attestation::as_instance_type(), nullptr, stride, 0, attestations.size(), count);
				if (!states)
					break;

				for (auto& state : *states)
					attestations.push_back(std::move(*state.as<states::validator_attestation>()));

				if (states->size() != count)
					break;
			}

			if (attestations.empty())
				return server_response().success(format::tree::list());

			auto rewards = vector<states::validator_attestation_reward>();
			stride = states::validator_attestation_reward::as_instance_column(owner);
			while (true)
			{
				auto states = chain.get_multiforms_by_column(states::validator_attestation_reward::as_instance_type(), nullptr, stride, 0, rewards.size(), count);
				if (!states)
					break;

				for (auto& state : *states)
					rewards.push_back(std::move(*state.as<states::validator_attestation_reward>()));

				if (states->size() != count)
					break;
			}

			auto data = format::tree::list();
			for (auto& attestation : attestations)
			{
				auto* result = data.push(attestation.as_tree());
				auto childs = result->set("rewards", format::tree::list());
				for (auto& reward : rewards)
				{
					if (attestation.asset == algorithm::asset::base_id_of(reward.asset))
						childs->push(reward.as_tree());
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_validator_attestations(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint256_t commitment = args[1].as_uint256();
			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_attestation_reward(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::validator_attestation_reward::as_instance_type(), nullptr, states::validator_attestation_reward::as_instance_column(owner), states::validator_attestation_reward::as_instance_row(asset), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_validator_attestation_rewards(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::validator_attestation_reward::as_instance_type(), nullptr, states::validator_attestation_reward::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_bridge_instance(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto state = chain.get_multiform(states::bridge_instance::as_instance_type(), nullptr, states::bridge_instance::as_instance_column(asset), states::bridge_instance::as_instance_row(args[1].as_uint256()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_bridge_instances(http::connection*, format::variables&& args)
		{
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto list = chain.get_multiforms_by_column(states::bridge_instance::as_instance_type(), nullptr, states::bridge_instance::as_instance_column(asset), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_bridge_instances(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column_filter(states::bridge_instance::as_instance_type(), nullptr, states::bridge_instance::as_instance_column(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_bridge_instances_by_security(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater(0, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column_filter(states::bridge_instance::as_instance_type(), nullptr, states::bridge_instance::as_instance_column(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto params = superchain::bridge::get()->get_network_params(asset);
			if (!params)
				return server_response().error(error_codes::not_found, "asset not valid");

			auto data = format::tree::list();
			for (auto& item : *list)
			{
				auto* bridge = (states::bridge_instance*)item.ptr();
				auto balance_stride = states::bridge_balance::as_instance_row(bridge->ref.hash);
				auto* next = data.push(format::tree::map());
				next->set("instance", bridge->as_tree());

				offset = 0, count = 64;
				while (!bridge->ref.owner.empty() && params->routing == superchain::routing_policy::account)
				{
					auto accounts = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(bridge->ref.owner), storages::result_filter::equal((uint8_t)states::witness_account::account_type::bridge, -1), 0, storages::result_range_window(offset, count));
					if (!accounts)
						break;

					for (auto& state : *accounts)
					{
						auto* ref = state.as<states::witness_account>();
						if (ref->active && ref->ref.owner == bridge->ref.owner && asset == ref->ref.asset && ref->ref.hash == bridge->ref.hash)
						{
							next->set("master", ref->as_tree());
							break;
						}
					}

					if (accounts->size() != count || next->has("master"))
						break;
				}

				auto tokens = next->set("balances", format::tree::list());
				while (true)
				{
					auto balances = chain.get_multiforms_by_row(states::bridge_balance::as_instance_type(), nullptr, balance_stride, 0, tokens->childs().size(), count);
					if (!balances)
						break;

					for (auto& state : *balances)
					{
						auto* ref = state.as<states::bridge_balance>();
						if (asset == algorithm::asset::base_id_of(ref->asset))
							tokens->push(state.ptr()->as_tree());
					}

					if (balances->size() != count)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_bridge_instances_by_balance(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column_filter(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_column(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto params = superchain::bridge::get()->get_network_params(asset);
			if (!params)
				return server_response().error(error_codes::not_found, "asset not valid");

			auto bridge_stride = states::bridge_instance::as_instance_column(asset);
			auto data = format::tree::list();
			for (auto& item : *list)
			{
				auto* balance_state = (states::bridge_balance*)item.ptr();
				auto balance_stride = states::bridge_balance::as_instance_row(balance_state->bridge_hash);
				auto bridge_state = chain.get_multiform(states::bridge_instance::as_instance_type(), nullptr, bridge_stride, states::bridge_instance::as_instance_row(balance_state->bridge_hash), 0);
				auto* next = data.push(format::tree::map());
				next->set("instance", bridge_state ? bridge_state->value->as_tree() : format::variable());

				offset = 0, count = 64;
				auto* bridge = (states::bridge_instance*)(bridge_state ? *bridge_state->value : nullptr);
				while (bridge != nullptr && !bridge->ref.owner.empty() && params->routing == superchain::routing_policy::account)
				{
					auto accounts = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(bridge->ref.owner), storages::result_filter::equal((uint8_t)states::witness_account::account_type::bridge, -1), 0, storages::result_range_window(offset, count));
					if (!accounts)
						break;

					for (auto& state : *accounts)
					{
						auto* ref = state.as<states::witness_account>();
						if (ref->active && ref->ref.owner == bridge->ref.owner && asset == ref->ref.asset && ref->ref.hash == bridge->ref.hash)
						{
							next->set("master", ref->as_tree());
							break;
						}
					}

					if (accounts->size() != count || next->has("master"))
						break;
				}

				auto tokens = next->set("balances", format::tree::list());
				while (true)
				{
					auto states = chain.get_multiforms_by_row(states::bridge_balance::as_instance_type(), nullptr, balance_stride, 0, tokens->childs().size(), count);
					if (!states)
						break;

					for (auto& state : *states)
					{
						auto* ref = state.as<states::bridge_balance>();
						if (asset == algorithm::asset::base_id_of(ref->asset))
							tokens->push(state.ptr()->as_tree());
					}

					if (states->size() != count)
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_bridge_balance(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto state = chain.get_multiform(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_column(asset), states::bridge_balance::as_instance_row(args[1].as_uint256()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_bridge_balances(http::connection*, format::variables&& args)
		{
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_row(args[0].as_uint256()), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_bridge_balances(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(states::bridge_balance::as_instance_type(), nullptr, states::bridge_balance::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_bridge_account(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto state = chain.get_multiform(states::bridge_account::as_instance_type(), nullptr, states::bridge_account::as_instance_column(asset, owner), states::bridge_account::as_instance_row(args[2].as_uint256()), 0);
			auto* value = (states::bridge_account*)(state ? state->ptr() : nullptr);
			return server_response().success(value ? value->as_tree() : format::tree());
		}
		server_response server_node::chainstate_get_bridge_accounts(http::connection*, format::variables&& args)
		{
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_row_filter(states::bridge_account::as_instance_type(), nullptr, states::bridge_account::as_instance_row(args[0].as_uint256()), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_program(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_program::as_instance_type(), nullptr, states::witness_program::as_instance_index(format::util::decode_0xhex(args[0].as_string())), 0);
			if (!state)
				return server_response().success(format::variable());

			auto code = ((states::witness_program*)(state->ptr()))->as_code();
			auto data = state->value->as_tree();
			data.set("storage", code ? format::variable(*code) : format::variable());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_event(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_event::as_instance_type(), nullptr, states::witness_event::as_instance_index(args[0].as_uint256()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_witness_account(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto chain = storages::chainstate();
			auto state = chain.get_multiform(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), states::witness_account::as_instance_row(asset, args[2].as_string()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_witness_account_tagged(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto executor = ledger::executor_context(nullptr);
			auto result = executor.get_witness_account_tagged(asset, args[1].as_string(), args[2].as_uint64());
			if (!result)
				return server_response().error(error_codes::not_found, result.error().message());

			return server_response().success(result->as_tree());
		}
		server_response server_node::chainstate_get_witness_accounts(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto list = chain.get_multiforms_by_column(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_accounts_by_purpose(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			int64_t purpose = std::numeric_limits<int64_t>::max();
			string type = args[1].as_blob();
			if (type == "witness")
				purpose = (int64_t)states::witness_account::account_type::witness;
			else if (type == "routing")
				purpose = (int64_t)states::witness_account::account_type::routing;
			else if (type == "bridge")
				purpose = (int64_t)states::witness_account::account_type::bridge;
			if (purpose == std::numeric_limits<int64_t>::max())
				return server_response().error(error_codes::bad_params, "address purpose not valid");

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate();
			auto filter = storages::result_filter::equal((int64_t)purpose, 1);
			auto list = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto data = format::tree::list();
			for (auto& item : *list)
				data.push(item.value->as_tree());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_transaction(http::connection*, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto chain = storages::chainstate();
			auto state = chain.get_uniform(states::witness_transaction::as_instance_type(), nullptr, states::witness_transaction::as_instance_index(asset, args[1].as_string()), 0);
			return server_response().success(state ? state->value->as_tree() : format::variable());
		}
		server_response server_node::chainstate_get_asset_holders(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto count = chain.get_multiforms_count_by_row_filter(states::account_balance::as_instance_type(), nullptr, states::account_balance::as_instance_row(asset), storages::result_filter::greater_equal(args[1].as_uint256(), -1), 0);
			return server_response().success(format::variable(count.or_else(0)));
		}
		server_response server_node::mempoolstate_add_node(http::connection*, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate();
			auto status = mempool.apply_unknown_node(endpoint.address, true);
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(format::variable());
		}
		server_response server_node::mempoolstate_clear_node(http::connection*, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate();
			auto status = mempool.clear_node(endpoint.address);
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(format::variable());
		}
		server_response server_node::mempoolstate_get_closest_node(http::connection*, format::variables&& args)
		{
			size_t offset = args.size() > 0 ? args[0].as_uint64() : 0;
			auto mempool = storages::mempoolstate();
			auto validator = mempool.get_closest_node(offset);
			if (!validator)
				return server_response().error(error_codes::bad_request, "node not found");

			auto result = format::tree::map();
			result.set("validator", validator->first.as_tree());
			result.set("wallet", validator->second.as_public_tree());
			return server_response().success(std::move(result));
		}
		server_response server_node::mempoolstate_get_closest_node_counter(http::connection*, format::variables&&)
		{
			auto mempool = storages::mempoolstate();
			auto count = mempool.get_nodes_count();
			if (!count)
				return server_response().error(error_codes::bad_request, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::mempoolstate_get_node(http::connection*, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate();
			auto validator = mempool.get_node(endpoint.address);
			if (!validator)
				return server_response().error(error_codes::bad_request, "node not found");

			auto result = format::tree::map();
			result.set("validator", validator->first.as_tree());
			result.set("wallet", validator->second.as_public_tree());
			return server_response().success(std::move(result));
		}
		server_response server_node::mempoolstate_get_addresses(http::connection*, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().message.items_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint32_t services = 0;
			if (args.size() > 2)
			{
				for (auto& service : stringify::split(args[2].as_string(), ','))
				{
					service = stringify::trim(service);
					if (service == "consensus")
						services |= (uint32_t)storages::node_services::consensus;
					else if (service == "discovery")
						services |= (uint32_t)storages::node_services::discovery;
					else if (service == "superchain")
						services |= (uint32_t)storages::node_services::superchain;
					else if (service == "rpc")
						services |= (uint32_t)storages::node_services::rpc;
					else if (service == "production")
						services |= (uint32_t)storages::node_services::production;
					else if (service == "participation")
						services |= (uint32_t)storages::node_services::participation;
					else if (service == "attestation")
						services |= (uint32_t)storages::node_services::attestation;
				}
			}

			auto mempool = storages::mempoolstate();
			auto nodes = mempool.get_closest_nodes_with(offset, count, services);
			if (!nodes)
				return server_response().error(error_codes::bad_request, "node not found");

			auto data = format::tree::list();
			for (auto& [account, address] : *nodes)
				data.push(format::variable(system_endpoint::to_uri(address)));
			return server_response().success(std::move(data));
		}
		server_response server_node::mempoolstate_get_gas_price(http::connection*, format::variables&& args)
		{
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[0].as_string());
			double percentile = args.size() > 1 ? args[1].as_double() : 0.50;
			bool mempool_only = args.size() > 2 ? args[2].as_boolean() : true;
			auto mempool = storages::mempoolstate();
			auto chain = storages::chainstate();
			auto tip = chain.get_latest_block_header();
			auto price = mempool.get_gas_price(asset, percentile);
			if (!mempool_only && !price && tip)
				price = chain.get_block_gas_price(tip->number, asset, percentile);

			auto result = format::tree::map();
			result.set("price", format::variable(price ? *price : decimal::zero()));
			result.set("paid", format::variable(tip && tip->network_congestion()));
			return server_response().success(std::move(result));
		}
		server_response server_node::mempoolstate_get_asset_price(http::connection*, format::variables&& args)
		{
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[0].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto mempool = storages::mempoolstate();
			auto price = mempool.get_asset_price(asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(format::variable(*price));
		}
		server_response server_node::mempoolstate_simulate_transaction(http::connection*, format::variables&& args)
		{
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction_message> candidate_tx = transactions::resolver::from_stream(message);
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			auto receipt = ledger::transaction_receipt();
			auto gas_limit = ledger::executor_context::calculate_tx_gas(*candidate_tx, &receipt);
			if (!gas_limit)
				return server_response().error(error_codes::bad_params, gas_limit.error().message());

			return server_response().success(receipt.as_tree());
		}
		server_response server_node::mempoolstate_submit_transaction(http::connection*, format::variables&& args, ledger::transaction_message* prebuilt)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto data = prebuilt ? string() : format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction_message> candidate_tx = prebuilt ? prebuilt : transactions::resolver::from_stream(message);
			if (!prebuilt)
			{
				if (!candidate_tx || !candidate_tx->load(message))
					return server_response().error(error_codes::bad_params, "invalid message");
			}

			auto candidate_hash = candidate_tx->as_hash();
			auto status = consensus_service->accept_transaction(nullptr, std::move(candidate_tx));
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(format::variable(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::mempoolstate_simulate_bridge(http::connection* base, format::variables&& args)
		{
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint256_t bridge_hash = args[1].as_uint256();
			auto executor = ledger::executor_context(nullptr);
			auto bridge = executor.get_bridge_instance(asset, bridge_hash);
			if (!bridge)
				return server_response().error(error_codes::not_found, "bridge not found");

			auto* offchain = superchain::bridge::get();
			bool must_reset_network_active = !offchain->network_active;
			bool must_reset_network_fetch = !offchain->network_fetch;
			if (must_reset_network_active)
				offchain->network_active = []() -> bool { return true; };
			if (must_reset_network_fetch)
				offchain->network_fetch = [](const algorithm::asset_id&, const std::string_view& a, const std::string_view& b, const http::fetch_frame& c) -> expects_promise_system<http::response_frame> { return http::fetch(a, b, c); };

			std::string_view address = args[2].as_string();
			decimal value = args[3].as_decimal();
			auto prepared = delegations::broadcast_delegation::prepare_transaction(algorithm::asset::base_id_of(asset), superchain::wallet_link::from_hash(bridge_hash), superchain::value_transfer(asset, address, std::move(value)), bridge->fee_rate).get();
			if (must_reset_network_active)
				offchain->network_active = nullptr;
			if (must_reset_network_fetch)
				offchain->network_fetch = nullptr;
			if (!prepared)
				return server_response().error(error_codes::bad_request, prepared.error().message());

			for (auto& input : prepared->inputs)
			{
				switch (input.alg)
				{
					case algorithm::composition::type::secp256k1:
						input.signature.resize(65, 0xCC);
						break;
					default:
						input.signature.resize(64, 0xCC);
						break;
				}
			}

			auto finalized = delegations::broadcast_delegation::finalize_transaction(algorithm::asset::base_id_of(asset), std::move(*prepared));
			if (!finalized)
				return server_response().success(prepared->as_tree());

			return server_response().success(finalized->as_tree());
		}
		server_response server_node::mempoolstate_reject_transaction(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate();
			auto status = mempool.remove_transactions_by_hash({ hash });
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(format::variable());
		}
		server_response server_node::mempoolstate_get_transaction_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate();
			auto transaction = mempool.get_transaction_by_hash(hash);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success((*transaction)->as_tree());
		}
		server_response server_node::mempoolstate_get_raw_transaction_by_hash(http::connection*, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate();
			auto transaction = mempool.get_transaction_by_hash(hash);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success(format::variable((*transaction)->as_message().encode()));
		}
		server_response server_node::mempoolstate_get_next_account_nonce(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			auto wallet = ledger::wallet::from_public_key_hash(owner);
			return server_response().success(format::variable(wallet.get_latest_nonce().or_else(0)));
		}
		server_response server_node::mempoolstate_get_transactions(http::connection*, format::variables&& args)
		{
			uint8_t flags = args[0].as_boolean() ? (uint8_t)storages::transaction_queue::commitment : 0;
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 3 ? args[3].as_uint8() : 0;
			auto mempool = storages::mempoolstate();
			auto data = format::tree::list();
			auto list = mempool.get_best_transactions_from_queue(flags, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "transactions not found");

			if (unrolling == 0)
			{
				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item->as_hash())));
			}
			else
			{
				for (auto& item : *list)
					data.push(item->as_tree());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::mempoolstate_get_transactions_by_owner(http::connection*, format::variables&& args)
		{
			algorithm::pubkeyhash_t owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().message.pages_per_query)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t direction = args.size() > 3 ? args[3].as_uint8() : 1;
			uint8_t unrolling = args.size() > 4 ? args[4].as_uint8() : 0;
			auto mempool = storages::mempoolstate();
			if (unrolling == 0)
			{
				auto data = format::tree::list();
				auto list = mempool.get_transactions_by_owner(owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data.push(format::variable(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else
			{
				auto data = format::tree::list();
				auto list = mempool.get_transactions_by_owner(owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data.push(item->as_tree());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::validatorstate_revert(http::connection*, format::variables&& args)
		{
			auto chain = storages::chainstate();
			auto block = chain.get_block_by_number(args[0].as_uint64());
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			auto state = chain.get_block_state_by_number(args[0].as_uint64());
			if (!state)
				return server_response().error(error_codes::not_found, "block state not found");

			if (consensus_service != nullptr && !consensus_service->try_acquire_checkpointer())
				return server_response().error(error_codes::not_found, "checkpointer busy");

			ledger::solver_context solver;
			ledger::block_evaluation evaluation;
			evaluation.block = std::move(*block);
			evaluation.state = std::move(*state);

			auto checkpoint = ledger::solver_context::checkpoint_solved_block(solver, evaluation);
			if (consensus_service != nullptr)
				consensus_service->release_checkpointer();

			if (!checkpoint)
				return server_response().error(error_codes::bad_params, checkpoint.error().message());

			auto result = format::tree::map();
			result.set("new_tip_block_number", format::variable(checkpoint->new_tip_block_number));
			result.set("old_tip_block_number", format::variable(checkpoint->old_tip_block_number));
			result.set("transaction_delta", format::variable(decimal(checkpoint->transaction_delta)));
			result.set("block_delta", format::variable(decimal(checkpoint->block_delta)));
			result.set("state_delta", format::variable(decimal(checkpoint->state_delta)));
			result.set("is_fork", format::variable(checkpoint->is_fork));
			return server_response().success(std::move(result));
		}
		server_response server_node::validatorstate_verify(http::connection*, format::variables&& args)
		{
			uint64_t count = args[1].as_uint64();
			uint64_t current_number = args[0].as_uint64();
			uint64_t target_number = current_number + count;
			bool validate = args.size() > 2 ? args[2].as_boolean() : false;
			auto chain = storages::chainstate();
			auto checkpoint_number = chain.get_checkpoint_block_number().or_else(0);
			auto parent_block = current_number > 1 ? chain.get_block_header_by_number(current_number - 1) : expects_lr<ledger::block_header>(layer_exception());
			auto data = format::tree::list();
			auto solver = ledger::solver_context();
			while (current_number < target_number)
			{
				auto next = chain.get_block_by_number(current_number);
				if (!next)
					return server_response().error(error_codes::not_found, "block " + to_string(current_number) + (checkpoint_number >= current_number ? " verification failed: block data pruned" : " verification failed: block not found"));
				else if (current_number > 1 && checkpoint_number >= current_number - 1 && !parent_block)
					return server_response().error(error_codes::not_found, "block " + to_string(current_number - 1) + " verification failed: parent block data pruned");

				if (!validate)
				{
					auto verification = next->verify_validity(parent_block.address());
					if (!verification)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " validity verification failed: " + verification.error().message());

					auto state = chain.get_block_state_by_number(next->number);
					verification = next->verify_integrity(parent_block.address(), state.address());
					if (!verification)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " integrity verification failed: " + verification.error().message());
				}
				else
				{
					auto validation = ledger::solver_context::validate_solved_block(solver, parent_block.address(), *next);
					if (!validation)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " validation failed: " + validation.error().message());
				}

				data.push(format::variable(algorithm::encoding::encode_0xhex256(next->as_hash())));
				parent_block = *next;
				++current_number;
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::validatorstate_accept_node(http::connection*, format::variables&& args)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto result = consensus_service->connect_to_physical_node(endpoint.address).get();
			if (!result)
				return server_response().error(error_codes::bad_request, result.what());

			return server_response().success(format::variable());
		}
		server_response server_node::validatorstate_reject_node(http::connection*, format::variables&& args)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			umutex<std::recursive_mutex> unique(consensus_service->get_mutex());
			auto target = consensus_service->find_by_ip_address(endpoint.address);
			if (!target)
				return server_response().error(error_codes::bad_request, "node not found");

			consensus_service->disconnect_node(std::move(target), "manual shutdown");
			return server_response().success(format::variable());
		}
		server_response server_node::validatorstate_get_node(http::connection*, format::variables&& args)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			umutex<std::recursive_mutex> unique(consensus_service->get_mutex());
			auto target = consensus_service->find_by_ip_address(endpoint.address);
			if (!target)
				return server_response().error(error_codes::bad_request, "node not found");

			auto* descriptor = target->as_descriptor();
			auto result = format::tree::map();
			result.set("validator", descriptor ? descriptor->first.as_tree() : format::variable());
			result.set("wallet", descriptor ? descriptor->second.as_public_tree() : format::variable());
			result.set("network", target->as_tree());
			return server_response().success(std::move(result));
		}
		server_response server_node::validatorstate_get_blockchains(http::connection*, format::variables&&)
		{
			auto data = format::tree::list();
			for (auto& [asset, params] : superchain::bridge::get()->get_assets_with_params())
			{
				auto* next = data.push(algorithm::asset::serialize(asset));
				next->set("divisibility", format::variable(params.divisibility));
				next->set("transaction_finality", format::variable(params.sync_latency));
				next->set("transaction_expires", format::variable(params.transaction_expires));
				switch (params.composition)
				{
					case algorithm::composition::type::ed25519:
						next->set("composition_policy", format::variable("ed25519"));
						break;
					case algorithm::composition::type::ed25519_clsag:
						next->set("composition_policy", format::variable("ed25519_clsag"));
						break;
					case algorithm::composition::type::secp256k1:
						next->set("composition_policy", format::variable("secp256k1"));
						break;
					case algorithm::composition::type::secp256k1_schnorr:
						next->set("composition_policy", format::variable("secp256k1_schnorr"));
						break;
					default:
						next->set("composition_policy", format::variable());
						break;
				}
				switch (params.tokenization)
				{
					case tangent::superchain::token_policy::none:
						next->set("token_policy", format::variable("none"));
						break;
					case tangent::superchain::token_policy::native:
						next->set("token_policy", format::variable("native"));
						break;
					case tangent::superchain::token_policy::program:
						next->set("token_policy", format::variable("program"));
						break;
					default:
						next->set("token_policy", format::variable());
						break;
				}
				switch (params.routing)
				{
					case tangent::superchain::routing_policy::account:
						next->set("routing_policy", format::variable("account"));
						break;
					case tangent::superchain::routing_policy::memo:
						next->set("routing_policy", format::variable("memo"));
						break;
					case tangent::superchain::routing_policy::utxo:
						next->set("routing_policy", format::variable("utxo"));
						break;
					default:
						next->set("routing_policy", format::variable());
						break;
				}
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::validatorstate_get_wallet(http::connection*, format::variables&&)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto& [validator, wallet] = *consensus_service->runner_descriptor;
			return server_response().success(wallet.as_tree());
		}
		server_response server_node::validatorstate_set_wallet(http::connection*, format::variables&& args)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto wallet = ledger::wallet();
			auto type = args[0].as_string();
			auto entropy = args[1].as_string();
			if (type == "key")
			{
				algorithm::seckey_t secret_key;
				if (!algorithm::signing::decode_secret_key(entropy, secret_key))
					return server_response().error(error_codes::bad_request, "invalid secret key");
			}
			else if (type == "mnemonic")
			{
				if (!algorithm::signing::verify_mnemonic(entropy))
					return server_response().error(error_codes::bad_request, "invalid mnemonic");

				wallet = ledger::wallet::from_mnemonic(entropy);
			}
			else if (type == "seed")
				wallet = ledger::wallet::from_seed(format::util::decode_0xhex(entropy));

			auto result = consensus_service->accept_local_accounts({ wallet });
			if (!result)
				return server_response().error(error_codes::bad_request, result.error().message());

			return server_response().success(wallet.as_tree());
		}
		server_response server_node::validatorstate_export_entropies(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash_t participant;
			if (!algorithm::signing::decode_address(args[0].as_string(), participant))
				return server_response().error(error_codes::bad_params, "participant address not valid");

			auto password = args[1].as_string();
			if (password.size() < 6)
				return server_response().error(error_codes::bad_request, "invalid password");

			uint8_t encryption_key[32] = { 0 };
			if (!algorithm::signing::derive_seed_from_password((uint8_t*)password.data(), password.size(), encryption_key, sizeof(encryption_key)))
				return server_response().error(error_codes::bad_request, "failed to derive an encryption key");

			auto mempool = storages::mempoolstate();
			auto results = format::tree::list();
			while (true)
			{
				auto entropy = mempool.get_key(participant, results.childs().size());
				if (!entropy)
					break;

				auto salt = *crypto::random_bytes(16);
				auto message = entropy->as_message();
				auto encrypted_message = *crypto::encrypt(ciphers::aes_256_cbc(), message.data, secret_box::view(std::string_view((char*)encryption_key, sizeof(encryption_key))), secret_box::view(salt));
				encrypted_message.insert(encrypted_message.begin(), salt.begin(), salt.end());
				results.push(format::variable(encrypted_message));
			}
			return server_response().success(std::move(results));
		}
		server_response server_node::validatorstate_import_entropies(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash_t participant;
			if (!algorithm::signing::decode_address(args[0].as_string(), participant))
				return server_response().error(error_codes::bad_params, "participant address not valid");

			auto password = args[1].as_string();
			uint8_t decryption_key[32] = { 0 };
			if (!algorithm::signing::derive_seed_from_password((uint8_t*)password.data(), password.size(), decryption_key, sizeof(decryption_key)))
				return server_response().error(error_codes::bad_request, "failed to derive a decryption key");

			auto mempool = storages::mempoolstate();
			for (size_t i = 2; i < args.size(); i++)
			{
				auto salt_and_encrypted_message = format::util::decode_0xhex(args[i].as_string());
				if (salt_and_encrypted_message.size() <= 16)
					return server_response().error(error_codes::bad_request, "invalid encrypted entropy");

				auto salt = std::string_view(salt_and_encrypted_message).substr(0, 16);
				auto encrypted_message = std::string_view(salt_and_encrypted_message).substr(salt.size());
				auto decrypted_message = crypto::decrypt(ciphers::aes_256_cbc(), encrypted_message, secret_box::view(std::string_view((char*)decryption_key, sizeof(decryption_key))), secret_box::view(salt));
				if (!decrypted_message)
					return server_response().error(error_codes::bad_request, "failed to decrypt message " + to_string(i - 1));

				auto message = format::ro_stream(*decrypted_message);
				auto entropy = ledger::distribution_key();
				if (!entropy.load(message))
					return server_response().error(error_codes::bad_request, "failed to load message " + to_string(i - 1));

				if (!mempool.apply_key(participant, entropy))
					return server_response().error(error_codes::bad_request, "failed to save message " + to_string(i - 1));
			}
			return server_response().success(format::variable());
		}
		server_response server_node::validatorstate_status(http::connection*, format::variables&&)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto chain = storages::chainstate();
			auto block_header = chain.get_latest_block_header();
			umutex<std::recursive_mutex> unique(consensus_service->get_mutex());
			auto data = format::tree::map();
			if (protocol::now().user.consensus.server)
			{
				auto* consensus = data.set("consensus", format::tree::map());
				consensus->set("port", format::variable(protocol::now().user.consensus.port));
			}

			if (protocol::now().user.discovery.server)
			{
				auto* discovery = data.set("discovery", format::tree::map());
				discovery->set("port", format::variable(protocol::now().user.discovery.port));
			}

			if (protocol::now().user.superchain.listener)
			{
				auto* superchain = data.set("superchain", format::tree::map());
				auto array = superchain->set("listeners", format::tree::list());
				for (auto& asset : superchain::bridge::get()->get_assets())
					array->push(algorithm::asset::serialize(asset));
			}

			if (protocol::now().user.rpc.server)
			{
				auto* rpc = data.set("rpc", format::tree::map());
				rpc->set("port", format::variable(protocol::now().user.rpc.port));
				rpc->set("cursor_size", format::variable(protocol::now().message.items_per_query));
				rpc->set("page_size", format::variable(protocol::now().message.pages_per_query));
				rpc->set("sandbox", format::variable(protocol::now().user.rpc.sandbox));
				rpc->set("restricted", format::variable(!protocol::now().user.rpc.username.empty()));
			}

			auto* tcp = data.set("tcp", format::tree::map());
			tcp->set("timeout", format::variable(protocol::now().user.tcp.timeout));

			auto* storage = data.set("storage", format::tree::map());
			storage->set("checkpoint_size", format::variable(protocol::now().user.storage.checkpoint_size));
			storage->set("transaction_to_account_index", format::variable(protocol::now().user.storage.transaction_to_account_index));
			storage->set("transaction_to_alias_index", format::variable(protocol::now().user.storage.transaction_to_alias_index));

			if (block_header)
			{
				auto block_hash = block_header->as_hash();
				auto* tip = data.set("tip", format::tree::map());
				tip->set("hash", format::variable(algorithm::encoding::encode_0xhex256(block_hash)));
				tip->set("number", algorithm::encoding::serialize_uint256(block_header->number));
				tip->set("sync", format::variable(decimal(consensus_service->get_sync_progress(block_header ? block_header->number : 0))));
			}
			else
				data.set("tip", format::variable());

			auto* connections = data.set("connections", format::tree::list());
			for (auto& connection : consensus_service->get_nodes())
			{
				auto* descriptor = connection.second->as_descriptor();
				auto node_data = format::tree::map();
				node_data.set("validator", descriptor ? descriptor->first.as_tree() : format::variable());
				node_data.set("wallet", descriptor ? descriptor->second.as_public_tree() : format::variable());
				node_data.set("network", connection.second->as_tree());
				connections->push(std::move(node_data));
			}

			auto* forks = data.set("forks", format::tree::list());
			for (auto& fork : consensus_service->forks)
			{
				auto* item = forks->push(format::tree::map());
				item->set("fork_hash", format::variable(algorithm::encoding::encode_0xhex256(fork.first)));
				item->set("tip_hash", algorithm::encoding::serialize_uint256(fork.second.header.as_hash()));
				item->set("tip_number", algorithm::encoding::serialize_uint256(fork.second.header.number));
				item->set("progress", format::variable(decimal(consensus_service->get_sync_progress(block_header ? block_header->number : 0, *fork.second.state))));
			}

			switch (protocol::now().user.network)
			{
				case network_type::mainnet:
					data.set("network", format::variable("mainnet"));
					break;
				case network_type::testnet:
					data.set("network", format::variable("testnet"));
					break;
				case network_type::regtest:
					data.set("network", format::variable("regtest"));
					break;
				default:
					data.set("network", format::variable());
					break;
			}

			auto version = data.set("version", format::tree::map());
			version->set("major", format::variable(protocol::now().message.major_version));
			version->set("minor", format::variable(protocol::now().message.minor_version));
			version->set("tag", consensus_service->runner_descriptor ? format::variable(consensus_service->runner_descriptor->first.as_version()) : format::variable());
			data.set("checkpoint", algorithm::encoding::serialize_uint256(chain.get_checkpoint_block_number().or_else(0)));
			return server_response().success(std::move(data));
		}
		server_response server_node::validatorstate_submit_block(http::connection*, format::variables&&)
		{
			if (!consensus_service)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			consensus_service->run_block_production();
			return server_response().success(format::variable());
		}
	}
}