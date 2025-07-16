#include "rpc.h"
#include "p2p.h"
#include "nss.h"
#include "../../kernel/svm.h"
#include "../../policy/transactions.h"
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

			uniform_location(uint32_t new_type, string&& new_index) : type(new_type), index(std::move(new_index))
			{
			}
		};

		struct multiform_location
		{
			string row;
			string column;
			uint32_t type;

			multiform_location(uint32_t new_type, string&& new_row, string&& new_column) : type(new_type), row(std::move(new_row)), column(std::move(new_column))
			{
			}
		};

		static expects_lr<uniform_location> as_uniform_location(const std::string_view& type, const format::variable& index)
		{
			if (type == states::account_nonce::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(index.as_string(), owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_nonce::as_instance_type(), states::account_nonce::as_instance_index(owner));
			}

			if (type == states::account_program::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(index.as_string(), owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_program::as_instance_type(), states::account_program::as_instance_index(owner));
			}

			if (type == states::account_uniform::as_instance_typename())
			{
				auto data = index.as_schema();
				if (!data)
					return layer_exception("invalid value, expected { address: string, index: string }");

				auto owner_address = data->get_var("address").get_blob();
				auto index = data->get_var("index").get_blob();
				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(owner_address, owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_uniform::as_instance_type(), states::account_uniform::as_instance_index(owner, index));
			}

			if (type == states::account_delegation::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(index.as_string(), owner))
					return layer_exception("invalid address");

				return uniform_location(states::account_delegation::as_instance_type(), states::account_delegation::as_instance_index(owner));
			}

			if (type == states::witness_program::as_instance_typename())
				return uniform_location(states::witness_program::as_instance_type(), states::witness_program::as_instance_index(index.as_string()));

			if (type == states::witness_event::as_instance_typename())
				return uniform_location(states::witness_event::as_instance_type(), states::witness_event::as_instance_index(index.as_uint256()));

			if (type == states::witness_transaction::as_instance_typename())
			{
				auto data = index.as_schema();
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
				auto data = column.as_schema();
				if (!data)
					return layer_exception("invalid column value, expected { address: string, column: string }");

				auto owner_address = data->get_var("address").get_blob();
				auto column_value = data->get_var("column").get_blob();
				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(owner_address, owner))
					return layer_exception("invalid address");

				return multiform_location(states::account_multiform::as_instance_type(), states::account_multiform::as_instance_row(owner, row.as_string()), states::account_multiform::as_instance_column(owner, column_value));
			}

			if (type == states::account_balance::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::account_balance::as_instance_type(), states::account_balance::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::account_balance::as_instance_column(owner));
			}

			if (type == states::validator_production::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_production::as_instance_type(), states::validator_production::as_instance_row(), states::validator_production::as_instance_column(owner));
			}

			if (type == states::validator_participation::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_participation::as_instance_type(), states::validator_participation::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::validator_participation::as_instance_column(owner));
			}

			if (type == states::validator_attestation::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::validator_attestation::as_instance_type(), states::validator_attestation::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::validator_attestation::as_instance_column(owner));
			}

			if (type == states::depository_reward::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::depository_reward::as_instance_type(), states::depository_reward::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::depository_reward::as_instance_column(owner));
			}

			if (type == states::depository_balance::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::depository_balance::as_instance_type(), states::depository_balance::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::depository_balance::as_instance_column(owner));
			}

			if (type == states::depository_policy::as_instance_typename())
			{
				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::depository_policy::as_instance_type(), states::depository_policy::as_instance_row(algorithm::asset::id_of_handle(row.as_string())), states::depository_policy::as_instance_column(owner));
			}

			if (type == states::depository_account::as_instance_typename())
			{
				auto data = row.type_of() != format::viewable::invalid ? row.as_schema() : uptr(var::set::object());
				if (!data)
					return layer_exception("invalid value, expected { asset: string, address: string }");

				algorithm::pubkeyhash manager = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), manager))
					return layer_exception("invalid address");

				auto id = data->get_var("asset").get_blob();
				auto owner_address = data->get_var("owner").get_blob();
				algorithm::pubkeyhash owner = { 0 };
				if (!algorithm::signing::decode_address(owner_address, owner))
					return layer_exception("invalid address");

				return multiform_location(states::depository_account::as_instance_type(), states::depository_account::as_instance_row(algorithm::asset::id_of_handle(id), owner), states::depository_account::as_instance_column(manager));
			}

			if (type == states::witness_account::as_instance_typename())
			{
				auto data = row.type_of() != format::viewable::invalid ? row.as_schema() : uptr(var::set::object());
				if (!data)
					return layer_exception("invalid value, expected { asset: string, address: string }");

				algorithm::pubkeyhash owner = { 0 };
				if (column.type_of() != format::viewable::invalid && !algorithm::signing::decode_address(column.as_string(), owner))
					return layer_exception("invalid address");

				return multiform_location(states::depository_account::as_instance_type(), states::witness_account::as_instance_row(algorithm::asset::id_of_handle(data->get_var("asset").get_blob()), data->get_var("address").get_blob()), states::witness_account::as_instance_column(owner));
			}

			return layer_exception("invalid multiform type");
		}
		static void form_response(http::connection* base, schema* request, uptr<schema>& responses, server_response&& response)
		{
			if (protocol::now().user.rpc.logging)
			{
				auto* params = request->get("params");
				string method = request->get_var("method").get_blob();
				string id = request->get_var("id").get_blob();
				VI_INFO("peer %s call %s: %s (params: %" PRIu64 ", time: %" PRId64 " ms)",
					base->get_peer_ip_address().or_else("[bad_address]").c_str(),
					method.empty() ? "[bad_method]" : method.c_str(),
					response.error_message.empty() ? (response.data ? (response.data->value.is_object() ? stringify::text("%" PRIu64 " rows", (uint64_t)response.data->size()).c_str() : "[value]") : "[null]") : response.error_message.c_str(),
					(uint64_t)(params ? (params->value.is_object() ? params->size() : 1) : 0),
					date_time().milliseconds() - base->info.start);
			}

			auto next = response.transform(request);
			if (responses)
			{
				if (!responses->value.is(var_type::array))
				{
					auto* prev = responses.reset();
					responses = var::set::array();
					responses->push(prev);
					responses->push(next.reset());
				}
				else
					responses->push(next.reset());
			}
			else
				responses = std::move(next);
		};

		server_response&& server_response::success(uptr<schema>&& value)
		{
			data = std::move(value);
			status = error_codes::response;
			return std::move(*this);
		}
		server_response&& server_response::notification(uptr<schema>&& value)
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
		uptr<schema> server_response::transform(schema* request)
		{
			auto* id = request ? request->get("id") : nullptr;
			uptr<schema> response = var::set::object();
			response->set("id", id ? id : var::set::null());

			auto* result = response->set(status == error_codes::notification ? "notification" : "result", data.reset());
			if (status != error_codes::response && status != error_codes::notification && !error_message.empty())
			{
				auto* error = response->set("error", var::object());
				error->set("message", var::string(error_message));
				error->set("code", var::integer((int64_t)status));
			}
			return response;
		}

		server_node::server_node(p2p::server_node* new_validator) noexcept : control_sys("rpc-node"), node(new http::server()), validator(new_validator)
		{
			if (validator != nullptr)
				validator->add_ref();
		}
		server_node::~server_node() noexcept
		{
			memory::release(validator);
		}
		void server_node::startup()
		{
			if (!protocol::now().user.rpc.server)
				return;

			admin_token = has_admin_authorization() ? codec::base64_encode(protocol::now().user.rpc.admin_username + ":" + protocol::now().user.rpc.admin_password) : string();
			user_token = has_user_authorization() ? codec::base64_encode(protocol::now().user.rpc.user_username + ":" + protocol::now().user.rpc.user_password) : string();

			http::map_router* router = new http::map_router();
			router->listen(protocol::now().user.rpc.address, to_string(protocol::now().user.rpc.port)).expect("listener binding error");
			router->post("/", std::bind(&server_node::http_request, this, std::placeholders::_1));
			router->base->callbacks.authorize = (admin_token.empty() && user_token.empty()) ? http::authorize_callback(nullptr) : std::bind(&server_node::authorize, this, std::placeholders::_1, std::placeholders::_2);
			router->base->callbacks.headers = std::bind(&server_node::headers, this, std::placeholders::_1, std::placeholders::_2);
			router->base->callbacks.options = std::bind(&server_node::options, this, std::placeholders::_1);
			router->base->auth.type = "Basic";
			router->base->auth.realm = "rpc.tan";
			router->temporary_directory.clear();
			if (protocol::now().user.rpc.web_sockets)
			{
				router->web_socket_receive("/", std::bind(&server_node::ws_receive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
				router->web_socket_disconnect("/", std::bind(&server_node::ws_disconnect, this, std::placeholders::_1));
				router->base->allow_web_socket = true;
				router->base->web_socket_timeout = 0;
			}

			node->configure(router).expect("configuration error");
			node->listen().expect("listen queue error");
			if (validator != nullptr)
			{
				validator->add_ref();
				if (protocol::now().user.rpc.web_sockets)
				{
					validator->events.accept_block = std::bind(&server_node::dispatch_accept_block, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
					validator->events.accept_transaction = std::bind(&server_node::dispatch_accept_transaction, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
				}
			}

			if (protocol::now().user.p2p.logging)
				VI_INFO("rpc node listen (location: %s:%i)", protocol::now().user.rpc.address.c_str(), (int)protocol::now().user.rpc.port);

			bind(0, "websocket", "subscribe", 1, 3, "string addresses, bool? blocks, bool? transactions", "uint64", "subscribe to streams of incoming blocks and transactions optionally include blocks and transactions relevant to comma separated address list", std::bind(&server_node::web_socket_subscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "websocket", "unsubscribe", 1, 1, "", "void", "unsubscribe from all streams", std::bind(&server_node::web_socket_unsubscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "transformaddressfromhash", 2, 2, "string address, string derivation_hash_hex", "string", "calculate subaddress from derivation hash", std::bind(&server_node::utility_transform_address_from_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "transformaddressfromdata", 2, 2, "string address, string derivation_data", "string", "calculate subaddress from derivation data", std::bind(&server_node::utility_transform_address_from_data, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "encodeaddress", 1, 1, "string public_key_hash", "string", "encode public key hash", std::bind(&server_node::utility_encode_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodeaddress", 1, 1, "string address", "{ public_key_hash: string,  }", "decode address", std::bind(&server_node::utility_decode_address, this, std::placeholders::_1, std::placeholders::_2));
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
			bind(0 | access_type::r, "txnstate", "getblockreceiptsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | receipt[]", "get block receipts by hash", std::bind(&server_node::txnstate_get_block_receipts_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getblockreceiptsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | receipt[]", "get block receipts by number", std::bind(&server_node::txnstate_get_block_receipts_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getpendingtransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by hash", std::bind(&server_node::txnstate_get_block_transactions_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getpendingtransactionsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by number", std::bind(&server_node::txnstate_get_block_transactions_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "gettransactionsbyowner", 3, 5, "string owner_address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get transactions by owner", std::bind(&server_node::txnstate_get_transactions_by_owner, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "gettransactionbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "txn | block::txn", "get transaction by hash", std::bind(&server_node::txnstate_get_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getrawtransactionbyhash", 1, 1, "uint256 hash", "string", "get raw transaction by hash", std::bind(&server_node::txnstate_get_raw_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "txnstate", "getreceiptbytransactionhash", 1, 1, "uint256 hash", "receipt", "get receipt by transaction hash", std::bind(&server_node::txnstate_get_receipt_by_transaction_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "call", 5, 32, "string asset, string from_address, string to_address, decimal value, string function, ...", "program_trace", "execute of immutable function of program assigned to to_address", std::bind(&server_node::chainstate_call, this, std::placeholders::_1, std::placeholders::_2));
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
			bind(0 | access_type::r, "chainstate", "getaccountdelegation", 1, 1, "string address", "uniform", "get account delegation by address", std::bind(&server_node::chainstate_get_account_delegation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalance", 2, 2, "string address, string asset", "multiform", "get account balance by address and asset", std::bind(&server_node::chainstate_get_account_balance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalances", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account balances by address", std::bind(&server_node::chainstate_get_account_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorproduction", 1, 1, "string address", "multiform", "get validator production by address", std::bind(&server_node::chainstate_get_validator_production, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorproducers", 3, 3, "uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator producers (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_producers, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipation", 2, 2, "string asset, string address", "multiform", "get validator participation by address and asset", std::bind(&server_node::chainstate_get_validator_participation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorparticipations", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get validator participations by address", std::bind(&server_node::chainstate_get_validator_participations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorparticipation", 3, 3, "string asset, uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator participations (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_participations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestation", 2, 2, "string asset, string address", "multiform", "get validator attestation by address and asset", std::bind(&server_node::chainstate_get_validator_attestation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getvalidatorattestations", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get validator attestations by address", std::bind(&server_node::chainstate_get_validator_attestations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestvalidatorattestation", 3, 3, "string asset, uint256 commitment, uint64 offset, uint64 count", "multiform[]", "get best validator attestations (zero commitment = offline, non-zero commitment = online threshold)", std::bind(&server_node::chainstate_get_best_validator_attestations, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositoryreward", 2, 2, "string address, string asset", "multiform", "get depository reward by address and asset", std::bind(&server_node::chainstate_get_depository_reward, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositoryrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get depository rewards by address", std::bind(&server_node::chainstate_get_depository_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositoryrewards", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best rewards", std::bind(&server_node::chainstate_get_best_depository_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositoryrewardsforselection", 3, 3, "string asset, uint64 offset, uint64 count", "{ depository: multiform?, reward: multiform }[]", "get accounts with best rewards with additional manager info", std::bind(&server_node::chainstate_get_best_depository_rewards_for_selection, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositorypolicy", 2, 2, "string address, string asset", "uint64", "get depository policy by address and asset", std::bind(&server_node::chainstate_get_depository_policy, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositoryaccount", 3, 3, "string asset, string manager_address, string owner_address", "multiform", "get depository account by manager and owner addresses and asset", std::bind(&server_node::chainstate_get_depository_account, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositoryaccounts", 3, 3, "string manager_address", "multiform[]", "get depository accounts by manager", std::bind(&server_node::chainstate_get_depository_accounts, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositorybalance", 2, 2, "string address, string asset", "multiform", "get depository balance by address and asset", std::bind(&server_node::chainstate_get_depository_balance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getdepositorybalances", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get depository balances by address", std::bind(&server_node::chainstate_get_depository_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositorybalances", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best depository balance", std::bind(&server_node::chainstate_get_best_depository_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositorybalancesforselection", 3, 3, "string asset, uint64 offset, uint64 count", "{ depository: multiform, reward: multiform? }[]", "get accounts with best depository balance with additional manager info", std::bind(&server_node::chainstate_get_best_depository_balances_for_selection, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositorypolicies", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best depository security", std::bind(&server_node::chainstate_get_best_depository_policies, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestdepositorypoliciesforselection", 3, 3, "string asset, uint64 offset, uint64 count", "{ depository: multiform, reward: multiform? }[]", "get accounts with best depository security with additional manager info", std::bind(&server_node::chainstate_get_best_depository_policies_for_selection, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessprogram", 1, 1, "string hashcode", "uniform", "get witness program by hashcode (512bit number)", std::bind(&server_node::chainstate_get_witness_program, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessevent", 1, 1, "uint256 transaction_hash", "uniform", "get witness event by transaction hash", std::bind(&server_node::chainstate_get_witness_event, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccount", 3, 3, "string address, string asset, string wallet_address", "multiform", "get witness address by owner address, asset, wallet address", std::bind(&server_node::chainstate_get_witness_account, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccounts", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_accounts, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaccountsbypurpose", 4, 4, "string address, string purpose = 'witness' | 'router' | 'custodian' | 'depository', uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_accounts_by_purpose, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnesstransaction", 2, 2, "string asset, string transaction_id", "uniform", "get witness transaction by asset and transaction id", std::bind(&server_node::chainstate_get_witness_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnode", 0, 1, "uint64? offset", "validator", "get closest node info", std::bind(&server_node::mempoolstate_get_closest_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnodecount", 0, 0, "", "uint64", "get closest node count", std::bind(&server_node::mempoolstate_get_closest_node_counter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnode", 1, 1, "string uri_address", "validator", "get associated node info by ip address", std::bind(&server_node::mempoolstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getaddresses", 2, 3, "uint64 offset, uint64 count, string? services = 'consensus' | 'discovery' | 'synchronization' | 'interface' | 'production' | 'participation' | 'attestation' | 'querying' | 'streaming'", "string[]", "get best node ip addresses with optional comma separated list of services", std::bind(&server_node::mempoolstate_get_addresses, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getgasprice", 1, 3, "string asset, double? percentile = 0.5, bool? mempool_only", "decimal", "get gas price from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_gas_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getassetprice", 2, 3, "string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_asset_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getoptimaltransactiongas", 1, 1, "string message_hex", "uint256", "execute transaction with block gas limit and return ceil of spent gas", std::bind(&server_node::mempoolstate_get_optimal_transaction_gas, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionbyhash", 1, 1, "uint256 hash", "txn", "get mempool transaction by hash", std::bind(&server_node::mempoolstate_get_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getrawmempooltransactionbyhash", 1, 1, "uint256 hash", "string", "get raw mempool transaction by hash", std::bind(&server_node::mempoolstate_get_raw_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnextaccountnonce", 1, 1, "string owner_address", "{ min: uint64, max: uint64 }", "get account nonce for next transaction by owner", std::bind(&server_node::mempoolstate_get_next_account_nonce, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactions", 2, 3, "uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions", std::bind(&server_node::mempoolstate_get_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionsbyowner", 3, 5, "const string address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions by signing address", std::bind(&server_node::mempoolstate_get_transactions_by_owner, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempoolattestationtransactions", 3, 4, "uint256 hash, uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get mempool attestation transactions", std::bind(&server_node::mempoolstate_get_attestation_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempoolattestation", 1, 1, "uint256 hash", "{ branch: uint256, threshold: double, progress: double, committee: uint64, reached: boolean }", "get mempool attestation transaction consensus state", std::bind(&server_node::mempoolstate_get_attestation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getnode", 1, 1, "string uri_address", "validator", "get a node by ip address", std::bind(&server_node::validatorstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getblockchains", 0, 0, "", "warden::asset", "get supported blockchains", std::bind(&server_node::validatorstate_get_blockchains, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "status", 0, 0, "", "validator::status", "get validator status", std::bind(&server_node::validatorstate_status, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::r, "mempoolstate", "submittransaction", 1, 2, "string message_hex, bool? validate", "uint256", "try to accept and relay a mempool transaction from raw data and possibly validate over latest chainstate", std::bind(&server_node::mempoolstate_submit_transaction, this, std::placeholders::_1, std::placeholders::_2, nullptr));
			bind(access_type::w | access_type::a, "mempoolstate", "rejecttransaction", 1, 1, "uint256 hash", "void", "remove mempool transaction by hash", std::bind(&server_node::mempoolstate_reject_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "addnode", 1, 1, "string uri_address", "void", "add node ip address to trial addresses", std::bind(&server_node::mempoolstate_add_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "clearnode", 1, 1, "string uri_address", "void", "remove associated node info by ip address", std::bind(&server_node::mempoolstate_clear_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "setwallet", 2, 2, "string type = 'mnemonic' | 'seed' | 'key', string entropy", "wallet", "set validator wallet from mnemonic phrase, seed value or secret key", std::bind(&server_node::validatorstate_set_wallet, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "getwallet", 0, 0, "", "wallet", "get validator wallet", std::bind(&server_node::validatorstate_get_wallet, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "getparticipations", 0, 0, "", "multiform[]", "get validator participations (for regrouping transaction)", std::bind(&server_node::validatorstate_get_participations, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "verify", 2, 3, "uint64 number, uint64 count, bool? validate", "uint256[]", "verify chain and possibly re-execute each block", std::bind(&server_node::validatorstate_verify, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "prune", 2, 2, "string types = 'state' | 'blocktrie' | 'transactiontrie', uint64 number", "void", "prune chainstate data using pruning level (types is '|' separated list)", std::bind(&server_node::validatorstate_prune, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "revert", 1, 2, "uint64 number, bool? keep_reverted_transactions", "{ new_tip_block_number: uint64, old_tip_block_number: uint64, mempool_transactions: uint64, block_delta: int64, transaction_delta: int64, state_delta: int64, is_fork: bool }", "revert chainstate to block number and possibly send removed transactions to mempool", std::bind(&server_node::validatorstate_revert, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "reorganize", 0, 0, "", "{ new_tip_block_number: uint64, old_tip_block_number: uint64, mempool_transactions: uint64, block_delta: int64, transaction_delta: int64, state_delta: int64, is_fork: bool }", "reorganize current chain which re-executes every saved block from genesis to tip and re-calculates the final chain state (helpful for corrupted state recovery or pruning checkpoint size change without re-downloading full block history)", std::bind(&server_node::validatorstate_reorganize, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "acceptnode", 0, 1, "string? uri_address", "void", "try to accept and connect to a node possibly by ip address", std::bind(&server_node::validatorstate_accept_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "rejectnode", 1, 1, "string uri_address", "void", "reject and disconnect from a node by ip address", std::bind(&server_node::validatorstate_reject_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "submitblock", 0, 0, "", "void", "try to propose a block from mempool transactions", std::bind(&server_node::validatorstate_submit_block, this, std::placeholders::_1, std::placeholders::_2));
		}
		void server_node::shutdown()
		{
			if (!is_active())
				return;

			if (protocol::now().user.p2p.logging)
				VI_INFO("rpc node shutdown");

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
		bool server_node::has_admin_authorization()
		{
			return !protocol::now().user.rpc.admin_username.empty();
		}
		bool server_node::has_user_authorization()
		{
			return !protocol::now().user.rpc.user_username.empty();
		}
		bool server_node::is_active()
		{
			return node->get_state() == server_state::working;
		}
		bool server_node::authorize(http::connection* base, http::credentials* credentials)
		{
			if (has_admin_authorization() && credentials->token == admin_token)
				return true;

			if (has_user_authorization() && credentials->token == user_token)
				return true;

			return false;
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

				auto request = base->request.content.get_json();
				if (request)
				{
					cospawn(std::bind(&server_node::dispatch_response, this, base, *request, nullptr, 0, [](http::connection* base, uptr<schema>&& responses)
					{
						auto response = schema::to_json(responses ? *responses : *server_response().error(error_codes::bad_request, "request is empty").transform(nullptr));
						base->response.content.assign(response);
						base->next(200);
					}));
				}
				else
				{
					base->response.content.assign(schema::to_json(*server_response().error(error_codes::bad_request, request.error().message()).transform(nullptr)));
					base->next(200);
				}
				return true;
			});
		}
		bool server_node::ws_receive(http::web_socket_frame* web_socket, http::web_socket_op opcode, const std::string_view& buffer)
		{
			if (opcode != http::web_socket_op::binary && opcode != http::web_socket_op::text)
				return false;

			auto request = schema::from_json(buffer);
			if (request)
			{
				auto* base = web_socket->get_connection();
				base->info.start = vitex::network::utils::clock();
				cospawn(std::bind(&server_node::dispatch_response, this, base, *request, nullptr, 0, [](http::connection* base, uptr<schema>&& responses)
				{
					auto response = schema::to_json(responses ? *responses : *server_response().error(error_codes::bad_request, "request is empty").transform(nullptr));
					base->web_socket->send(response, http::web_socket_op::text, [](http::web_socket_frame* web_socket) { web_socket->next(); });
				}));
			}
			else
				web_socket->send(schema::to_json(*server_response().error(error_codes::bad_request, request.error().message()).transform(nullptr)), http::web_socket_op::text, [](http::web_socket_frame* web_socket) { web_socket->next(); });

			return true;
		}
		void server_node::ws_disconnect(http::web_socket_frame* web_socket)
		{
			umutex<std::mutex> unique(mutex);
			listeners.erase(web_socket->get_connection());
			unique.unlock();
			web_socket->next();
		}
		bool server_node::dispatch_response(http::connection* base, uptr<schema>&& requests, uptr<schema>&& responses, size_t index, std::function<void(http::connection*, uptr<schema>&&)>&& callback)
		{
			if (!requests->value.is(var_type::array))
			{
				auto* array = var::set::array();
				array->push(requests.reset());
				requests = array;
			}

		next_request:
			auto* request = index < requests->size() ? requests->get(index++) : (schema*)nullptr;
			if (!request)
			{
				callback(base, std::move(responses));
				return true;
			}

			auto* version = request->get("jsonrpc");
			if (!version || version->value.get_integer() != 2)
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_version, "only version 2.0 is supported"));
				goto next_request;
			}

			auto* method = request->get("method");
			if (!method || !method->value.is(var_type::string))
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "method is not a string"));
				goto next_request;
			}

			auto context = methods.find(method->value.get_blob());
			if (context == methods.end())
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "method \"" + method->value.get_blob() + "\" not found"));
				goto next_request;
			}

			if (has_admin_authorization() && context->second.access_types & (uint32_t)access_type::a && base->request.user.token != admin_token)
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "admin level access required"));
				goto next_request;
			}
			else if (has_user_authorization() && base->request.user.token != user_token && base->request.user.token != admin_token)
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "user level access required"));
				goto next_request;
			}

			auto* params = request->get("params");
			if (!params || !params->value.is(var_type::array))
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "params is not an array"));
				goto next_request;
			}

			if (params->size() < context->second.min_params || params->size() > context->second.max_params)
			{
				form_response(base, request, responses, server_response().error(error_codes::bad_method, "params is not an array[" + to_string(context->second.min_params) + ".." + to_string(context->second.min_params) + "]"));
				goto next_request;
			}

			format::variables args;
			args.reserve(params->size());
			for (auto& param : params->get_childs())
			{
				switch (param->value.get_type())
				{
					case var_type::object:
					case var_type::array:
						args.push_back(format::variable(schema::to_json(param)));
						break;
					case var_type::string:
					case var_type::binary:
						args.push_back(format::variable(param->value.get_blob()));
						break;
					case var_type::integer:
					{
						int64_t value = param->value.get_integer();
						if (value >= 0)
							args.push_back(format::variable((uint64_t)value));
						else
							args.push_back(format::variable(decimal(value)));
						break;
					}
					case var_type::number:
						args.push_back(format::variable(decimal(param->value.get_number())));
						break;
					case var_type::decimal:
						args.push_back(format::variable(param->value.get_decimal()));
						break;
					case var_type::boolean:
						args.push_back(format::variable(param->value.get_boolean()));
						break;
					case var_type::null:
					case var_type::undefined:
					case var_type::pointer:
					default:
						args.push_back(format::variable((uint8_t)0));
						break;
				}
			}

			auto* requests_ref = requests.reset();
			auto* responses_ref = responses.reset();
			cospawn([this, base, requests_ref, responses_ref, index, callback = std::move(callback), request, context, args = std::move(args)]() mutable
			{
				uptr<schema> requests = requests_ref;
				uptr<schema> responses = responses_ref;
				auto response = context->second.function(base, std::move(args));
				form_response(base, request, responses, std::move(response));
				if (index < requests->size())
					dispatch_response(base, std::move(requests), std::move(responses), index, std::move(callback));
				else
					callback(base, std::move(responses));
			});
			return true;
		}
		void server_node::dispatch_accept_block(const uint256_t& hash, const ledger::block& block, const ledger::block_checkpoint& checkpoint)
		{
			umutex<std::mutex> unique(mutex);
			if (listeners.empty())
				return;

			ordered_set<algorithm::pubkeyhash_t> addresses;
			auto context = ledger::transaction_context();
			for (auto& transaction : block.transactions)
			{
				addresses.insert(algorithm::pubkeyhash_t(transaction.receipt.from));
				transaction.transaction->recover_many(&context, transaction.receipt, addresses);
			}

			unordered_set<http::web_socket_frame*> web_sockets;
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

			cospawn([hash, web_sockets = std::move(web_sockets)]() mutable
			{
				auto notification = var::set::object();
				notification->set("type", var::string("block"));
				notification->set("result", var::string(algorithm::encoding::encode_0xhex256(hash)));

				auto response = schema::to_json(*server_response().notification(notification).transform(nullptr));
				for (auto& web_socket : web_sockets)
					web_socket->send(response, http::web_socket_op::text, nullptr);
			});
		}
		void server_node::dispatch_accept_transaction(const uint256_t& hash, const ledger::transaction* transaction, const algorithm::pubkeyhash owner)
		{
			umutex<std::mutex> unique(mutex);
			if (listeners.empty())
				return;

			auto address = algorithm::pubkeyhash_t(owner);
			unordered_set<http::web_socket_frame*> web_sockets;
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

			cospawn([hash, web_sockets = std::move(web_sockets)]() mutable
			{
				auto notification = var::set::object();
				notification->set("type", var::string("transaction"));
				notification->set("result", var::string(algorithm::encoding::encode_0xhex256(hash)));

				auto response = schema::to_json(*server_response().notification(notification).transform(nullptr));
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
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(address, owner))
					return server_response().error(error_codes::bad_params, "address[" + to_string(address_index) + "] not valid");

				listener.addresses.insert(algorithm::pubkeyhash_t(owner));
				++address_index;
			}

			umutex<std::mutex> unique(mutex);
			listeners[base] = std::move(listener);
			unique.unlock();
			return server_response().success(var::set::integer(address_index + (listener.blocks || listener.transactions ? 1 : 0)));
		}
		server_response server_node::web_socket_unsubscribe(http::connection* base, format::variables&& args)
		{
			if (!base->web_socket)
				return server_response().error(error_codes::bad_request, "requires protocol upgrade");

			umutex<std::mutex> unique(mutex);
			listeners.erase(base);
			unique.unlock();
			return server_response().success(var::set::null());
		}
		server_response server_node::utility_transform_address_from_hash(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash data;
			if (!algorithm::signing::decode_address(args[0].as_string(), data))
				return server_response().error(error_codes::bad_params, "address not valid");

			auto derivation_data = format::util::decode_0xhex(args[1].as_string());
			if (derivation_data.size() > sizeof(algorithm::pubkeyhash))
				return server_response().error(error_codes::bad_params, "derivation not valid");

			auto derivation_hash = algorithm::pubkeyhash_t(derivation_data);
			return server_response().success(algorithm::signing::serialize_subaddress(data, derivation_hash.data));
		}
		server_response server_node::utility_transform_address_from_data(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash data;
			if (!algorithm::signing::decode_address(args[0].as_string(), data))
				return server_response().error(error_codes::bad_params, "address not valid");

			return server_response().success(algorithm::signing::serialize_subaddress(data, args[1].as_string()));
		}
		server_response server_node::utility_encode_address(http::connection* base, format::variables&& args)
		{
			auto owner = format::util::decode_0xhex(args[0].as_string());
			if (owner.size() == sizeof(algorithm::subpubkeyhash))
			{
				string address;
				algorithm::signing::encode_subaddress((uint8_t*)owner.data(), address);
				return server_response().success(var::set::string(address));
			}
			else if (owner.size() == sizeof(algorithm::pubkeyhash))
			{
				string address;
				algorithm::signing::encode_address((uint8_t*)owner.data(), address);
				return server_response().success(var::set::string(address));
			}

			return server_response().error(error_codes::bad_params, "raw address not valid");
		}
		server_response server_node::utility_decode_address(http::connection* base, format::variables&& args)
		{
			algorithm::subpubkeyhash data;
			if (!algorithm::signing::decode_subaddress(args[0].as_string(), data))
				return server_response().error(error_codes::bad_params, "address not valid");

			auto* result = var::set::object();
			result->set("public_key_hash", var::string(format::util::encode_0xhex(std::string_view((char*)data, sizeof(algorithm::pubkeyhash)))));
			result->set("derivation_hash", var::string(format::util::encode_0xhex(std::string_view((char*)data + sizeof(algorithm::pubkeyhash), sizeof(algorithm::pubkeyhash)))));
			return server_response().success(result);
		}
		server_response server_node::utility_decode_message(http::connection* base, format::variables&& args)
		{
			format::variables values;
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			if (!format::variables_util::deserialize_flat_from(message, &values))
				return server_response().error(error_codes::bad_params, "invalid message");

			return server_response().success(format::variables_util::serialize(values));
		}
		server_response server_node::utility_decode_transaction(http::connection* base, format::variables&& args)
		{
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction> candidate_tx = transactions::resolver::from_stream(message);
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			algorithm::pubkeyhash owner = { 0 }, null = { 0 };
			bool recoverable = candidate_tx->recover_hash(owner);
			uptr<schema> result = var::set::object();
			result->set("transaction", candidate_tx->as_schema().reset());
			result->set("signer_message", recoverable ? var::string(candidate_tx->as_signable().encode()) : var::null());
			result->set("signer_address", recoverable ? algorithm::signing::serialize_address(owner) : var::set::null());
			return server_response().success(std::move(result));
		}
		server_response server_node::utility_help(http::connection* base, format::variables&& args)
		{
			uptr<schema> data = var::set::object();
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

				auto* domain = data->get(method.second.domain);
				if (!domain)
					domain = data->set(method.second.domain, var::set::array());

				auto* description = domain->push(var::set::object());
				description->set("function", var::string(method.first));
				description->set("declaration", var::string(inline_decl));
				description->set("description", var::string(method.second.description));
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_blocks(http::connection* base, format::variables&& args)
		{
			uint64_t count = args[1].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate(__func__);
			auto hashes = chain.get_block_hashset(number, count);
			if (!hashes)
				return server_response().error(error_codes::not_found, "blocks not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *hashes)
				data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_checkpoint_hash(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_checkpoint_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			auto block_hash = chain.get_block_hash_by_number(*block_number);
			if (!block_hash)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(*block_hash)));
		}
		server_response server_node::blockstate_get_block_checkpoint_number(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_checkpoint_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "checkpoint block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::blockstate_get_block_tip_hash(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto block_header = chain.get_latest_block_header();
			if (!block_header)
				return server_response().error(error_codes::not_found, "tip block not found");

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(block_header->as_hash())));
		}
		server_response server_node::blockstate_get_block_tip_number(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_latest_block_number();
			if (!block_number)
				return server_response().error(error_codes::not_found, "tip block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::blockstate_get_block_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto block_header = chain.get_block_header_by_hash(hash);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block_header->as_schema());
			}
			else if (unrolling == 1)
			{
				auto block_header = chain.get_block_header_by_hash(hash);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				auto transaction_hashset = chain.get_block_transaction_hashset(block_header->number);
				if (transaction_hashset)
				{
					for (auto& item : *transaction_hashset)
						transactions->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				}

				return server_response().success(std::move(data));
			}
			else if (unrolling == 2)
			{
				auto block_header = chain.get_block_header_by_hash(hash);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				while (true)
				{
					auto list = chain.get_transactions_by_number(block_header->number, transactions->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(item->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else if (unrolling == 3)
			{
				auto block_header = chain.get_block_header_by_hash(hash);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_header->number, transactions->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				auto block = chain.get_block_by_hash(hash);
				if (!block)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block->as_schema());
			}
		}
		server_response server_node::blockstate_get_block_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto block_header = chain.get_block_header_by_number(number);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block_header->as_schema());
			}
			else if (unrolling == 1)
			{
				auto block_header = chain.get_block_header_by_number(number);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				auto transaction_hashset = chain.get_block_transaction_hashset(block_header->number);
				if (transaction_hashset)
				{
					for (auto& item : *transaction_hashset)
						transactions->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				}

				return server_response().success(std::move(data));
			}
			else if (unrolling == 2)
			{
				auto block_header = chain.get_block_header_by_number(number);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				while (true)
				{
					auto list = chain.get_transactions_by_number(block_header->number, transactions->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(item->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else if (unrolling == 3)
			{
				auto block_header = chain.get_block_header_by_number(number);
				if (!block_header)
					return server_response().error(error_codes::not_found, "block not found");

				auto data = block_header->as_schema();
				auto* transactions = data->set("transactions", var::set::array());
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(block_header->number, transactions->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						transactions->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				auto block = chain.get_block_by_number(number);
				if (!block)
					return server_response().error(error_codes::not_found, "block not found");

				return server_response().success(block->as_schema());
			}
		}
		server_response server_node::blockstate_get_raw_block_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate(__func__);
			auto block = chain.get_block_by_hash(hash);
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(var::set::string(block->as_message().encode()));
		}
		server_response server_node::blockstate_get_raw_block_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate(__func__);
			auto block = chain.get_block_by_number(number);
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(var::set::string(block->as_message().encode()));
		}
		server_response server_node::blockstate_get_block_proof_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate(__func__);
			auto block_proof = chain.get_block_proof_by_hash(hash);
			if (!block_proof)
				return server_response().error(error_codes::not_found, "block not found");

			bool transactions = args[1].as_boolean();
			bool receipts = args[2].as_boolean();
			bool states = args[3].as_boolean();
			if (transactions)
				block_proof->get_transaction_tree();
			if (receipts)
				block_proof->get_receipt_tree();
			if (states)
				block_proof->get_state_tree();

			auto data = block_proof->as_schema();
			if (!transactions)
				data->pop("transactions");
			if (!receipts)
				data->pop("receipts");
			if (!states)
				data->pop("states");

			if (data->size() == 1)
			{
				uptr<schema> root = std::move(data);
				data = root->get(0);
				data->unlink();
			}

			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_proof_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate(__func__);
			auto block_proof = chain.get_block_proof_by_number(number);
			if (!block_proof)
				return server_response().error(error_codes::not_found, "block not found");

			bool transactions = args[1].as_boolean();
			bool receipts = args[2].as_boolean();
			bool states = args[3].as_boolean();
			if (transactions)
				block_proof->get_transaction_tree();
			if (receipts)
				block_proof->get_receipt_tree();
			if (states)
				block_proof->get_state_tree();

			auto data = block_proof->as_schema();
			if (!transactions)
				data->pop("transactions");
			if (!receipts)
				data->pop("receipts");
			if (!states)
				data->pop("states");

			if (data->size() == 1)
			{
				uptr<schema> root = std::move(data);
				data = root->get(0);
				data->unlink();
			}

			return server_response().success(std::move(data));
		}
		server_response server_node::blockstate_get_block_number_by_hash(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			auto chain = storages::chainstate(__func__);
			auto block_hash = chain.get_block_hash_by_number(number);
			if (!block_hash)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(*block_hash)));
		}
		server_response server_node::blockstate_get_block_hash_by_number(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*block_number));
		}
		server_response server_node::txnstate_get_block_transactions_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto block_number = chain.get_block_number_by_hash(hash);
				if (!block_number)
					return server_response().error(error_codes::not_found, "block not found");

				auto hashes = chain.get_block_transaction_hashset(*block_number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *hashes)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				return server_response().success(std::move(data));
			}
			else if (unrolling == 1)
			{
				auto block_number = chain.get_block_number_by_hash(hash);
				if (!block_number)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_transactions_by_number(*block_number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				auto block_number = chain.get_block_number_by_hash(hash);
				if (!block_number)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(*block_number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_block_transactions_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_transaction_hashset(number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *hashes)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				return server_response().success(std::move(data));
			}
			else if (unrolling == 1)
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_transactions_by_number(number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_transactions_by_number(number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_block_receipts_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_receipts_by_number(*block_number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(var::set::string(algorithm::encoding::encode_0xhex256(item.as_hash())));
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_receipts_by_number(*block_number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_block_receipts_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_receipts_by_number(number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(var::set::string(algorithm::encoding::encode_0xhex256(item.as_hash())));
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_receipts_by_number(number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_pending_transactions(http::connection* base, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 2 ? args[2].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto list = chain.get_pending_block_transactions(std::numeric_limits<int64_t>::max(), offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item.receipt.transaction_hash)));
				return server_response().success(std::move(data));
			}
			else if (unrolling == 1)
			{
				auto list = chain.get_pending_block_transactions(std::numeric_limits<int64_t>::max(), offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *list)
					data->push(item.transaction->as_schema().reset());
				return server_response().success(std::move(data));
			}
			else
			{
				auto list = chain.get_pending_block_transactions(std::numeric_limits<int64_t>::max(), offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *list)
					data->push(item.as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_transactions_by_owner(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t direction = args.size() > 3 ? args[3].as_uint8() : 1;
			uint8_t unrolling = args.size() > 4 ? args[4].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				auto list = chain.get_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else if (unrolling == 1)
			{
				uptr<schema> data = var::set::array();
				auto list = chain.get_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item->as_schema().reset());
				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				auto list = chain.get_block_transactions_by_owner(std::numeric_limits<int64_t>::max(), owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item.as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::txnstate_get_transaction_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto transaction = chain.get_transaction_by_hash(hash);
				if (!transaction)
					return server_response().error(error_codes::not_found, "transaction not found");

				return server_response().success((*transaction)->as_schema());
			}
			else
			{
				auto transaction = chain.get_block_transaction_by_hash(hash);
				if (!transaction)
					return server_response().error(error_codes::not_found, "transaction not found");

				return server_response().success(transaction->as_schema());
			}
		}
		server_response server_node::txnstate_get_raw_transaction_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate(__func__);
			auto transaction = chain.get_transaction_by_hash(hash);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success(var::set::string((*transaction)->as_message().encode()));
		}
		server_response server_node::txnstate_get_receipt_by_transaction_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto chain = storages::chainstate(__func__);
			auto receipt = chain.get_receipt_by_transaction_hash(hash);
			if (!receipt)
				return server_response().error(error_codes::not_found, "receipt not found");

			return server_response().success(receipt->as_schema());
		}
		server_response server_node::chainstate_call(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash from;
			if (!algorithm::signing::decode_address(args[1].as_string(), from))
				return server_response().error(error_codes::bad_params, "from account address not valid");

			algorithm::subpubkeyhash to;
			if (!algorithm::signing::decode_subaddress(args[2].as_string(), to))
				return server_response().error(error_codes::bad_params, "to account address not valid");

			format::variables function_args;
			function_args.reserve(args.size() - 5);
			for (size_t i = 5; i < args.size(); i++)
				function_args.push_back(args[i]);

			auto environment = ledger::evaluation_context();
			auto index = environment.validation.context.get_account_program(to);
			if (!index)
				return server_response().error(error_codes::bad_params, "to account has no program hash");

			auto* host = ledger::svm_host::get();
			auto& hashcode = index->hashcode;
			auto compiler = host->allocate();
			if (!host->precompile(*compiler, hashcode))
			{
				auto program = environment.validation.context.get_witness_program(hashcode);
				if (!program)
				{
					host->deallocate(std::move(compiler));
					return server_response().error(error_codes::bad_params, "to account has no program storage");
				}

				auto code = program->as_code();
				if (!code)
				{
					host->deallocate(std::move(compiler));
					return server_response().error(error_codes::bad_params, code.error().message());
				}

				auto compilation = host->compile(*compiler, hashcode, format::util::encode_0xhex(hashcode), *code);
				if (!compilation)
				{
					host->deallocate(std::move(compiler));
					return server_response().error(error_codes::bad_params, compilation.error().message());
				}
			}

			auto function = args[4].as_string();
			auto module = compiler->get_module();
			auto entrypoint = module.get_function_by_decl(function);
			if (!entrypoint.is_valid())
				entrypoint = module.get_function_by_name(function);
			if (!entrypoint.is_valid())
				return server_response().error(error_codes::bad_params, "to account has no such function");

			transactions::call transaction;
			transaction.asset = algorithm::asset::id_of_handle(args[0].as_string());
			transaction.signature[0] = 0xFF;
			transaction.nonce = std::max<size_t>(1, environment.validation.context.get_account_nonce(from).or_else(states::account_nonce(nullptr, nullptr)).nonce);
			transaction.program_call(to, args[3].as_decimal(), function, std::move(function_args));
			transaction.set_gas(decimal::zero(), ledger::block::get_gas_limit());

			auto chain = storages::chainstate(__func__);
			auto tip = chain.get_latest_block_header();
			if (tip)
				environment.tip = std::move(*tip);

			auto block = ledger::block();
			block.set_parent_block(environment.tip.address());

			auto receipt = ledger::receipt();
			receipt.transaction_hash = transaction.as_hash();
			receipt.generation_time = protocol::now().time.now();
			receipt.block_number = block.number + 1;
			memcpy(receipt.from, from, sizeof(algorithm::pubkeyhash));

			environment.validation.context = ledger::transaction_context(&environment, &block, &environment.validation.changelog, &transaction, std::move(receipt));
			memset(environment.validator.public_key_hash, 0xFF, sizeof(algorithm::pubkeyhash));
			memset(environment.validator.secret_key, 0xFF, sizeof(algorithm::seckey));

			auto returning = uptr<schema>();
			auto script = ledger::svm_program(&environment.validation.context);
			auto execution = script.execute(ledger::svm_call::immutable_call, entrypoint, args, [&](void* address, int type_id) -> expects_lr<void>
			{
				returning = var::set::object();
				auto serialization = ledger::svm_marshalling::store(*returning, address, type_id);
				if (!serialization)
				{
					returning.destroy();
					return layer_exception("return value error: " + serialization.error().message());
				}
				return expectation::met;
			});
			if (!execution)
				return server_response().error(error_codes::bad_params, execution.error().message());

			environment.validation.context.receipt.successful = !!execution;
			environment.validation.context.receipt.finalization_time = protocol::now().time.now();
			if (!environment.validation.context.receipt.successful)
				environment.validation.context.emit_event(0, { format::variable(execution.what()) }, false);

			auto data = environment.validation.context.receipt.as_schema();
			data->set("to", algorithm::signing::serialize_subaddress(script.to().hash.data));
			data->set("result", returning ? returning->copy() : var::set::null());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_block_state_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto block_number = chain.get_block_number_by_hash(hash);
				if (!block_number)
					return server_response().error(error_codes::not_found, "block not found");

				auto hashes = chain.get_block_transaction_hashset(*block_number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *hashes)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				return server_response().success(std::move(data));
			}
			else
			{
				auto block_number = chain.get_block_number_by_hash(hash);
				if (!block_number)
					return server_response().error(error_codes::not_found, "block not found");

				auto list = chain.get_block_state_by_number(*block_number, protocol::now().user.rpc.cursor_size);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& [index, change] : list->finalized)
					data->push(change.as_schema().reset());

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::chainstate_get_block_state_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			uint8_t unrolling = args.size() > 1 ? args[1].as_uint8() : 0;
			auto chain = storages::chainstate(__func__);
			if (unrolling == 0)
			{
				auto hashes = chain.get_block_transaction_hashset(number);
				if (!hashes)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& item : *hashes)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item)));
				return server_response().success(std::move(data));
			}
			else
			{
				auto list = chain.get_block_state_by_number(number, protocol::now().user.rpc.cursor_size);
				if (!list)
					return server_response().error(error_codes::not_found, "block not found");

				uptr<schema> data = var::set::array();
				for (auto& [index, change] : list->finalized)
					data->push(change.as_schema().reset());

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::chainstate_get_block_gas_price_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto price = chain.get_block_gas_price(*block_number, asset, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "gas price not found");

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::chainstate_get_block_gas_price_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto chain = storages::chainstate(__func__);
			auto price = chain.get_block_gas_price(number, asset, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "gas price not found");

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::chainstate_get_block_asset_price_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[1].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[2].as_string());
			double percentile = args.size() > 3 ? args[3].as_double() : 0.50;
			auto chain = storages::chainstate(__func__);
			auto block_number = chain.get_block_number_by_hash(hash);
			if (!block_number)
				return server_response().error(error_codes::not_found, "block not found");

			auto price = chain.get_block_asset_price(*block_number, asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::chainstate_get_block_asset_price_by_number(http::connection* base, format::variables&& args)
		{
			uint64_t number = args[0].as_uint64();
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[1].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[2].as_string());
			double percentile = args.size() > 3 ? args[3].as_double() : 0.50;
			auto chain = storages::chainstate(__func__);
			auto price = chain.get_block_asset_price(number, asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::chainstate_get_uniform(http::connection* base, format::variables&& args)
		{
			auto location = as_uniform_location(args[0].as_string(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate(__func__);
			auto uniform = chain.get_uniform(location->type, nullptr, location->index, 0);
			if (!uniform)
				return server_response().error(error_codes::not_found, "uniform not found");

			return server_response().success((*uniform)->as_schema());
		}
		server_response server_node::chainstate_get_multiform(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], args[2]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate(__func__);
			auto multiform = chain.get_multiform(location->type, nullptr, location->column, location->row, 0);
			if (!multiform)
				return server_response().error(error_codes::not_found, "multiform not found");

			return server_response().success((*multiform)->as_schema());
		}
		server_response server_node::chainstate_get_multiforms_by_column(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(location->type, nullptr, location->column, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_column_filter(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[5].as_uint64(), count = args[6].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), args[4].as_decimal().to_int8());
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(location->type, nullptr, location->column, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_row(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row(location->type, nullptr, location->row, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_by_row_filter(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			uint64_t offset = args[5].as_uint64(), count = args[6].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), args[4].as_decimal().to_int8());
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(location->type, nullptr, location->row, filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_count_by_column(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate(__func__);
			auto count = chain.get_multiforms_count_by_column(location->type, nullptr, location->column, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_column_filter(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), args[1], format::variable());
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), 0);
			auto chain = storages::chainstate(__func__);
			auto count = chain.get_multiforms_count_by_column_filter(location->type, nullptr, location->column, filter, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_row(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto chain = storages::chainstate(__func__);
			auto count = chain.get_multiforms_count_by_row(location->type, nullptr, location->row, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_multiforms_count_by_row_filter(http::connection* base, format::variables&& args)
		{
			auto location = as_multiform_location(args[0].as_string(), format::variable(), args[1]);
			if (!location)
				return server_response().error(error_codes::bad_params, "location not valid: " + location.error().message());

			auto filter = storages::result_filter::from(args[2].as_string(), args[3].as_uint256(), 0);
			auto chain = storages::chainstate(__func__);
			auto count = chain.get_multiforms_count_by_row_filter(location->type, nullptr, location->row, filter, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_account_nonce(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(owner), 0);
			auto* value = (states::account_nonce*)(state ? **state : nullptr);
			return server_response().success(algorithm::encoding::serialize_uint256(value ? value->nonce : 1));
		}
		server_response server_node::chainstate_get_account_program(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::account_program::as_instance_type(), nullptr, states::account_program::as_instance_index(owner), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_uniform(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::account_uniform::as_instance_type(), nullptr, states::account_uniform::as_instance_index(owner, args[1].as_string()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_multiform(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform(states::account_multiform::as_instance_type(), nullptr, states::account_multiform::as_instance_column(owner, args[1].as_string()), states::account_multiform::as_instance_row(owner, args[2].as_string()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_multiforms(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::account_multiform::as_instance_type(), nullptr, states::account_multiform::as_instance_column(owner, args[1].as_string()), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_delegation(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::account_delegation::as_instance_type(), nullptr, states::account_delegation::as_instance_index(owner), 0);
			auto* value = (states::account_delegation*)(state ? **state : nullptr);
			auto result = value ? value->as_schema().reset() : var::set::null();
			if (value != nullptr)
			{
				uint64_t block_number = chain.get_latest_block_number().or_else(value->block_number);
				uint64_t zeroing_block_number = value->get_delegation_zeroing_block(block_number);
				result->set("zeroing_block_number", var::integer(zeroing_block_number));
				result->set("requires_zeroing", var::boolean(block_number < zeroing_block_number));
			}
			return server_response().success(result);
		}
		server_response server_node::chainstate_get_account_balance(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::account_balance::as_instance_type(), nullptr, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_balances(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::account_balance::as_instance_type(), nullptr, states::account_balance::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_production(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform(states::validator_production::as_instance_type(), nullptr, states::validator_production::as_instance_column(owner), states::validator_production::as_instance_row(), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_best_validator_producers(http::connection* base, format::variables&& args)
		{
			uint256_t commitment = args[0].as_uint256();
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::validator_production::as_instance_type(), nullptr, states::validator_production::as_instance_row(), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_participation(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_column(owner), states::validator_participation::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_validator_participations(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_validator_participations(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint256_t commitment = args[1].as_uint256();
			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::validator_participation::as_instance_type(), nullptr, states::validator_participation::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_validator_attestation(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(owner), states::validator_attestation::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_validator_attestations(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_validator_attestations(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint256_t commitment = args[1].as_uint256();
			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::result_filter::greater_equal(commitment, -1) : storages::result_filter::equal(commitment, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_depository_reward(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_column(owner), states::depository_reward::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_depository_rewards(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_rewards(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, 1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_rewards_for_selection(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, 1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto attestation_stride = states::validator_attestation::as_instance_row(asset);
			auto policy_stride = states::depository_policy::as_instance_row(asset);
			auto balance_stride = states::depository_balance::as_instance_row(asset);
			uptr<schema> data = var::set::array();
			for (auto& item : *list)
			{
				auto* reward_state = (states::depository_reward*)*item;
				auto attestation_state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(reward_state->owner), attestation_stride, 0);
				auto policy_state = chain.get_multiform(states::depository_policy::as_instance_type(), nullptr, states::depository_policy::as_instance_column(reward_state->owner), policy_stride, 0);
				auto balance_state = chain.get_multiform(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_column(reward_state->owner), balance_stride, 0);
				auto* next = data->push(var::set::object());
				next->set("attestation", attestation_state ? (*attestation_state)->as_schema().reset() : var::set::null());
				next->set("balance", balance_state ? (*balance_state)->as_schema().reset() : var::set::null());
				next->set("policy", policy_state ? (*policy_state)->as_schema().reset() : var::set::null());
				next->set("reward", reward_state->as_schema().reset());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_depository_policy(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::depository_policy::as_instance_type(), nullptr, states::depository_policy::as_instance_column(owner), states::depository_policy::as_instance_row(asset), 0);
			auto* value = (states::depository_policy*)(state ? **state : nullptr);
			return server_response().success(value ? value->as_schema().reset() : nullptr);
		}
		server_response server_node::chainstate_get_depository_account(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash proposer;
			if (!algorithm::signing::decode_address(args[1].as_string(), proposer))
				return server_response().error(error_codes::bad_params, "account address not valid");

			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[2].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto state = chain.get_multiform(states::depository_account::as_instance_type(), nullptr, states::depository_account::as_instance_column(proposer), states::depository_account::as_instance_row(asset, owner), 0);
			auto* value = (states::depository_account*)(state ? **state : nullptr);
			return server_response().success(value ? value->as_schema().reset() : nullptr);
		}
		server_response server_node::chainstate_get_depository_accounts(http::connection* base, format::variables&& args)
		{
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			algorithm::pubkeyhash proposer;
			if (!algorithm::signing::decode_address(args[0].as_string(), proposer))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column_filter(states::depository_account::as_instance_type(), nullptr, states::depository_account::as_instance_column(proposer), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_depository_balance(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_column(owner), states::depository_balance::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_depository_balances(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_balances(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_balances_for_selection(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto attestation_stride = states::validator_attestation::as_instance_row(asset);
			auto policy_stride = states::depository_policy::as_instance_row(asset);
			auto reward_stride = states::depository_reward::as_instance_row(asset);
			uptr<schema> data = var::set::array();
			for (auto& item : *list)
			{
				auto* balance_state = (states::depository_balance*)*item;
				auto attestation_state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(balance_state->owner), attestation_stride, 0);
				auto policy_state = chain.get_multiform(states::depository_policy::as_instance_type(), nullptr, states::depository_policy::as_instance_column(balance_state->owner), policy_stride, 0);
				auto reward_state = chain.get_multiform(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_column(balance_state->owner), reward_stride, 0);
				auto* next = data->push(var::set::object());
				next->set("attestation", attestation_state ? (*attestation_state)->as_schema().reset() : var::set::null());
				next->set("balance", balance_state->as_schema().reset());
				next->set("policy", policy_state ? (*policy_state)->as_schema().reset() : var::set::null());
				next->set("reward", reward_state ? (*reward_state)->as_schema().reset() : var::set::null());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_policies(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_policy::as_instance_type(), nullptr, states::depository_policy::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_depository_policies_for_selection(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::result_filter::greater(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(states::depository_policy::as_instance_type(), nullptr, states::depository_policy::as_instance_row(asset), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto attestation_stride = states::validator_attestation::as_instance_row(asset);
			auto balance_stride = states::depository_balance::as_instance_row(asset);
			auto reward_stride = states::depository_reward::as_instance_row(asset);
			uptr<schema> data = var::set::array();
			for (auto& item : *list)
			{
				auto* policy_state = (states::depository_policy*)*item;
				auto attestation_state = chain.get_multiform(states::validator_attestation::as_instance_type(), nullptr, states::validator_attestation::as_instance_column(policy_state->owner), attestation_stride, 0);
				auto balance_state = chain.get_multiform(states::depository_balance::as_instance_type(), nullptr, states::depository_balance::as_instance_column(policy_state->owner), balance_stride, 0);
				auto reward_state = chain.get_multiform(states::depository_reward::as_instance_type(), nullptr, states::depository_reward::as_instance_column(policy_state->owner), reward_stride, 0);
				auto* next = data->push(var::set::object());
				next->set("attestation", attestation_state ? (*attestation_state)->as_schema().reset() : var::set::null());
				next->set("balance", balance_state ? (*balance_state)->as_schema().reset() : var::set::null());
				next->set("policy", policy_state->as_schema().reset());
				next->set("reward", reward_state ? (*reward_state)->as_schema().reset() : var::set::null());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_program(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::witness_program::as_instance_type(), nullptr, states::witness_program::as_instance_index(args[0].as_string()), 0);
			if (!state)
				return server_response().success(var::set::null());

			auto code = ((states::witness_program*)(**state))->as_code();
			auto* data = (*state)->as_schema().reset();
			data->set("storage", code ? var::string(*code) : var::null());
			return server_response().success(data);
		}
		server_response server_node::chainstate_get_witness_event(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::witness_event::as_instance_type(), nullptr, states::witness_event::as_instance_index(args[0].as_uint256()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_witness_account(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), states::witness_account::as_instance_row(asset, args[2].as_string()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_witness_accounts(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_accounts_by_purpose(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			int64_t purpose = std::numeric_limits<int64_t>::max();
			string type = args[1].as_blob();
			if (type == "witness")
				purpose = (int64_t)states::witness_account::account_type::witness;
			else if (type == "routing")
				purpose = (int64_t)states::witness_account::account_type::routing;
			else if (type == "depository")
				purpose = (int64_t)states::witness_account::account_type::depository;
			if (purpose == std::numeric_limits<int64_t>::max())
				return server_response().error(error_codes::bad_params, "address purpose not valid");

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto filter = storages::result_filter::equal((int64_t)purpose, 1);
			auto list = chain.get_multiforms_by_column_filter(states::witness_account::as_instance_type(), nullptr, states::witness_account::as_instance_column(owner), filter, 0, storages::result_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_transaction(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::witness_transaction::as_instance_type(), nullptr, states::witness_transaction::as_instance_index(asset, args[1].as_string()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::mempoolstate_add_node(http::connection* base, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate(__func__);
			auto status = mempool.apply_trial_address(endpoint.address);
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(var::set::null());
		}
		server_response server_node::mempoolstate_clear_node(http::connection* base, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate(__func__);
			auto status = mempool.clear_validator(endpoint.address);
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(var::set::null());
		}
		server_response server_node::mempoolstate_get_closest_node(http::connection* base, format::variables&& args)
		{
			size_t offset = args.size() > 0 ? args[0].as_uint64() : 0;
			auto mempool = storages::mempoolstate(__func__);
			auto validator = mempool.get_validator_by_preference(offset);
			if (!validator)
				return server_response().error(error_codes::bad_request, "node not found");

			return server_response().success(validator->as_schema().reset());
		}
		server_response server_node::mempoolstate_get_closest_node_counter(http::connection* base, format::variables&& args)
		{
			auto mempool = storages::mempoolstate(__func__);
			auto count = mempool.get_validators_count();
			if (!count)
				return server_response().error(error_codes::bad_request, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::mempoolstate_get_node(http::connection* base, format::variables&& args)
		{
			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			auto mempool = storages::mempoolstate(__func__);
			auto validator = mempool.get_validator_by_address(endpoint.address);
			if (!validator)
				return server_response().error(error_codes::bad_request, "node not found");

			return server_response().success(validator->as_schema().reset());
		}
		server_response server_node::mempoolstate_get_addresses(http::connection* base, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().user.rpc.cursor_size)
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
					else if (service == "synchronization")
						services |= (uint32_t)storages::node_services::synchronization;
					else if (service == "interface")
						services |= (uint32_t)storages::node_services::interfaces;
					else if (service == "production")
						services |= (uint32_t)storages::node_services::production;
					else if (service == "participation")
						services |= (uint32_t)storages::node_services::participation;
					else if (service == "attestation")
						services |= (uint32_t)storages::node_services::attestation;
					else if (service == "querying")
						services |= (uint32_t)storages::node_services::querying;
					else if (service == "streaming")
						services |= (uint32_t)storages::node_services::streaming;
				}
			}

			auto mempool = storages::mempoolstate(__func__);
			auto seeds = mempool.get_validator_addresses(offset, count, services);
			if (!seeds)
				return server_response().error(error_codes::bad_request, "node not found");

			uptr<schema> data = var::set::array();
			for (auto& seed : *seeds)
				data->push(var::string(system_endpoint::to_uri(seed)));
			return server_response().success(std::move(data));
		}
		server_response server_node::mempoolstate_get_gas_price(http::connection* base, format::variables&& args)
		{
			algorithm::asset_id asset = algorithm::asset::id_of_handle(args[0].as_string());
			double percentile = args.size() > 1 ? args[1].as_double() : 0.50;
			bool mempool_only = args.size() > 2 ? args[2].as_boolean() : true;
			auto mempool = storages::mempoolstate(__func__);
			auto price = mempool.get_gas_price(asset, percentile);
			if (!price && !mempool_only)
			{
				auto chain = storages::chainstate(__func__);
				auto number = chain.get_latest_block_number();
				if (!number)
					return server_response().error(error_codes::not_found, "gas price not found");

				price = chain.get_block_gas_price(*number, asset, percentile);
				if (!price)
					return server_response().error(error_codes::not_found, "gas price not found");
			}
			else if (!price)
				return server_response().success(var::set::decimal(decimal::zero()));

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::mempoolstate_get_asset_price(http::connection* base, format::variables&& args)
		{
			algorithm::asset_id asset1 = algorithm::asset::id_of_handle(args[0].as_string());
			algorithm::asset_id asset2 = algorithm::asset::id_of_handle(args[1].as_string());
			double percentile = args.size() > 2 ? args[2].as_double() : 0.50;
			auto mempool = storages::mempoolstate(__func__);
			auto price = mempool.get_asset_price(asset1, asset2, percentile);
			if (!price)
				return server_response().error(error_codes::not_found, "asset price not found");

			return server_response().success(var::set::decimal(*price));
		}
		server_response server_node::mempoolstate_get_optimal_transaction_gas(http::connection* base, format::variables&& args)
		{
			auto data = format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction> candidate_tx = transactions::resolver::from_stream(message);
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			auto gas_limit = ledger::transaction_context::calculate_tx_gas(*candidate_tx);
			if (!gas_limit)
				return server_response().error(error_codes::bad_params, gas_limit.error().message());

			return server_response().success(algorithm::encoding::serialize_uint256(*gas_limit));
		}
		server_response server_node::mempoolstate_submit_transaction(http::connection* base, format::variables&& args, ledger::transaction* prebuilt)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto data = prebuilt ? string() : format::util::decode_stream(args[0].as_string());
			auto message = format::ro_stream(data);
			uptr<ledger::transaction> candidate_tx = prebuilt ? prebuilt : transactions::resolver::from_stream(message);
			if (!prebuilt)
			{
				if (!candidate_tx || !candidate_tx->load(message))
					return server_response().error(error_codes::bad_params, "invalid message");
			}

			auto candidate_hash = candidate_tx->as_hash();
			auto deep_validation = (args.size() > 1 ? args[1].as_boolean() : false);
			auto status = validator->accept_transaction(nullptr, std::move(candidate_tx), deep_validation);
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::mempoolstate_reject_transaction(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate(__func__);
			auto status = mempool.remove_transactions(vector<uint256_t>({ hash }));
			if (!status)
				return server_response().error(error_codes::bad_request, status.error().message());

			return server_response().success(var::set::null());
		}
		server_response server_node::mempoolstate_get_transaction_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate(__func__);
			auto transaction = mempool.get_transaction_by_hash(hash);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success((*transaction)->as_schema());
		}
		server_response server_node::mempoolstate_get_raw_transaction_by_hash(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate(__func__);
			auto transaction = mempool.get_transaction_by_hash(hash);
			if (!transaction)
				return server_response().error(error_codes::not_found, "transaction not found");

			return server_response().success(var::set::string((*transaction)->as_message().encode()));
		}
		server_response server_node::mempoolstate_get_next_account_nonce(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			auto mempool = storages::mempoolstate(__func__);
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform(states::account_nonce::as_instance_type(), nullptr, states::account_nonce::as_instance_index(owner), 0);
			auto* value = (states::account_nonce*)(state ? **state : nullptr);
			auto lowest = mempool.get_lowest_transaction_nonce(owner);
			auto highest = mempool.get_highest_transaction_nonce(owner);
			if (!lowest)
				lowest = value ? value->nonce : 0;
			if (!highest)
				highest = value ? value->nonce : 0;
			else if (value != nullptr && *highest < value->nonce)
				highest = value->nonce;
			else
				highest = *highest + 0;

			uptr<schema> data = var::set::object();
			data->set("min", algorithm::encoding::serialize_uint256(*lowest));
			data->set("max", algorithm::encoding::serialize_uint256(*highest));
			return server_response().success(std::move(data));
		}
		server_response server_node::mempoolstate_get_transactions(http::connection* base, format::variables&& args)
		{
			uint64_t offset = args[0].as_uint64(), count = args[1].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 2 ? args[2].as_uint8() : 0;
			auto mempool = storages::mempoolstate(__func__);
			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions(offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions(offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item->as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::mempoolstate_get_transactions_by_owner(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t direction = args.size() > 3 ? args[3].as_uint8() : 1;
			uint8_t unrolling = args.size() > 4 ? args[4].as_uint8() : 0;
			auto mempool = storages::mempoolstate(__func__);
			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions_by_owner(owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions_by_owner(owner, direction >= 1 ? 1 : -1, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item->as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::mempoolstate_get_attestation_transactions(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			uint8_t unrolling = args.size() > 3 ? args[3].as_uint8() : 0;
			auto mempool = storages::mempoolstate(__func__);
			if (unrolling == 0)
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions_by_group(hash, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_transactions_by_group(hash, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item->as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::mempoolstate_get_attestation(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate(__func__);
			auto reference = mempool.get_transaction_by_hash(hash);
			if (!reference)
				return server_response().error(error_codes::not_found, "transaction not found");

			auto& transaction = *reference;
			if (transaction->get_type() != ledger::transaction_level::attestation)
				return server_response().error(error_codes::not_found, "transaction consensus is not applicable");

			auto context = ledger::transaction_context();
			auto* aggregation = (ledger::attestation_transaction*)*transaction;
			auto branch = aggregation->get_best_branch(&context, nullptr);
			if (!branch)
				return server_response().error(error_codes::not_found, "transaction consensus is not computable");

			auto result = var::set::object();
			result->set("branch", var::string(algorithm::encoding::encode_0xhex256(branch->message.hash())));
			result->set("signatures", var::number(branch->signatures.size()));
			return server_response().success(result);
		}
		server_response server_node::validatorstate_prune(http::connection* base, format::variables&& args)
		{
			uint32_t types = 0;
			for (auto& subtype : stringify::split(args[0].as_string(), '|'))
			{
				if (subtype == "block")
					types |= (uint32_t)storages::pruning::block;
				else if (subtype == "transaction")
					types |= (uint32_t)storages::pruning::transaction;
				else if (subtype == "state")
					types |= (uint32_t)storages::pruning::state;
			}

			if (types == 0)
				return server_response().error(error_codes::not_found, "invalid type");

			uint64_t number = args[1].as_uint64();
			auto chain = storages::chainstate(__func__);
			auto status = chain.prune(types, number);
			if (!status)
				return server_response().error(error_codes::not_found, status.error().message());

			return server_response().success(var::set::null());
		}
		server_response server_node::validatorstate_revert(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto block = chain.get_block_by_number(args[0].as_uint64());
			if (!block)
				return server_response().error(error_codes::not_found, "block not found");

			auto state = chain.get_block_state_by_number(args[0].as_uint64());
			if (!state)
				return server_response().error(error_codes::not_found, "block state not found");

			ledger::block_evaluation evaluation;
			evaluation.block = std::move(*block);
			evaluation.state = std::move(*state);
			auto checkpoint = evaluation.checkpoint(args.size() > 1 ? args[1].as_boolean() : false);
			if (!checkpoint)
				return server_response().error(error_codes::bad_params, checkpoint.error().message());

			auto* result = var::set::object();
			result->set("new_tip_block_number", var::integer(checkpoint->new_tip_block_number));
			result->set("old_tip_block_number", var::integer(checkpoint->old_tip_block_number));
			result->set("mempool_transactions", var::integer(checkpoint->mempool_transactions));
			result->set("transaction_delta", var::integer(checkpoint->transaction_delta));
			result->set("block_delta", var::integer(checkpoint->block_delta));
			result->set("state_delta", var::integer(checkpoint->state_delta));
			result->set("is_fork", var::integer(checkpoint->is_fork));
			return server_response().success(result);
		}
		server_response server_node::validatorstate_reorganize(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto checkpoint = ledger::block_checkpoint();
			checkpoint.old_tip_block_number = chain.get_latest_block_number().or_else(0);
			checkpoint.new_tip_block_number = checkpoint.old_tip_block_number;
			if (!checkpoint.new_tip_block_number)
				return server_response().error(error_codes::not_found, "block tip not found");

			auto reorganization = chain.reorganize(&checkpoint.block_delta, &checkpoint.transaction_delta, &checkpoint.state_delta);
			if (!reorganization)
				return server_response().error(error_codes::bad_params, reorganization.error().message());

			auto* result = var::set::object();
			result->set("new_tip_block_number", var::integer(checkpoint.new_tip_block_number));
			result->set("old_tip_block_number", var::integer(checkpoint.old_tip_block_number));
			result->set("mempool_transactions", var::integer(checkpoint.mempool_transactions));
			result->set("transaction_delta", var::integer(checkpoint.transaction_delta));
			result->set("block_delta", var::integer(checkpoint.block_delta));
			result->set("state_delta", var::integer(checkpoint.state_delta));
			result->set("is_fork", var::integer(checkpoint.is_fork));
			return server_response().success(result);
		}
		server_response server_node::validatorstate_verify(http::connection* base, format::variables&& args)
		{
			uint64_t count = args[1].as_uint64();
			uint64_t current_number = args[0].as_uint64();
			uint64_t target_number = current_number + count;
			bool validate = args.size() > 2 ? args[2].as_boolean() : false;
			auto chain = storages::chainstate(__func__);
			auto checkpoint_number = chain.get_checkpoint_block_number().or_else(0);
			auto tip_number = chain.get_latest_block_number().or_else(0);
			auto parent_block = current_number > 1 ? chain.get_block_header_by_number(current_number - 1) : expects_lr<ledger::block_header>(layer_exception());
			uptr<schema> data = var::set::array();
			while (current_number < target_number)
			{
				auto next = chain.get_block_by_number(current_number);
				if (!next)
					return server_response().error(error_codes::not_found, "block " + to_string(current_number) + (checkpoint_number >= current_number ? " verification failed: block data pruned" : " verification failed: block not found"));
				else if (current_number > 1 && checkpoint_number >= current_number - 1 && !parent_block)
					return server_response().error(error_codes::not_found, "block " + to_string(current_number - 1) + " verification failed: parent block data pruned");

				if (validate)
				{
					auto validation = next->validate(parent_block.address());
					if (!validation)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " validation failed: " + validation.error().message());
				}
				else
				{
					auto verification = next->verify_validity(parent_block.address());
					if (!verification)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " validity verification failed: " + verification.error().message());

					auto state = chain.get_block_state_by_number(next->number);
					verification = next->verify_integrity(parent_block.address(), state.address());
					if (!verification)
						return server_response().error(error_codes::not_found, "block " + to_string(current_number) + " integrity verification failed: " + verification.error().message());
				}

				data->push(var::string(algorithm::encoding::encode_0xhex256(next->as_hash())));
				parent_block = *next;
				++current_number;
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::validatorstate_accept_node(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			if (!args.empty())
			{
				auto endpoint = system_endpoint(args[0].as_string());
				if (!endpoint.is_valid())
					return server_response().error(error_codes::bad_params, "address not valid");

				if (!validator->accept(endpoint.address))
					return server_response().error(error_codes::bad_request, "node not found");
			}
			else if (!validator->accept())
				return server_response().error(error_codes::bad_request, "node not found");

			return server_response().success(var::set::null());
		}
		server_response server_node::validatorstate_reject_node(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			umutex<std::recursive_mutex> unique(validator->get_mutex());
			auto* node = validator->find(endpoint.address);
			if (!node || node == (p2p::relay*)validator)
				return server_response().error(error_codes::bad_request, "node not found");

			auto* user = node->as_user<ledger::validator>();
			validator->reject(node);
			return server_response().success(var::set::null());
		}
		server_response server_node::validatorstate_get_node(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto endpoint = system_endpoint(args[0].as_string());
			if (!endpoint.is_valid())
				return server_response().error(error_codes::bad_params, "address not valid");

			umutex<std::recursive_mutex> unique(validator->get_mutex());
			auto* node = validator->find(endpoint.address);
			if (!node || node == (p2p::relay*)validator)
				return server_response().error(error_codes::bad_request, "node not found");

			auto* user = node->as_user<ledger::validator>();
			auto data = user->as_schema();
			data->set("network", node->as_schema().reset());
			return server_response().success(data.reset());
		}
		server_response server_node::validatorstate_get_blockchains(http::connection* base, format::variables&& args)
		{
			uptr<schema> data = var::set::array();
			for (auto& asset : nss::server_node::get()->get_chains())
			{
				auto* next = data->push(algorithm::asset::serialize(asset.first));
				next->set("divisibility", var::decimal(asset.second.divisibility));
				next->set("sync_latency", var::integer(asset.second.sync_latency));
				switch (asset.second.composition)
				{
					case algorithm::composition::type::ed25519:
						next->set("composition_policy", var::string("ed25519"));
						break;
					case algorithm::composition::type::secp256k1:
						next->set("composition_policy", var::string("secp256k1"));
						break;
					case algorithm::composition::type::schnorr:
						next->set("composition_policy", var::string("schnorr"));
						break;
					case algorithm::composition::type::schnorr_taproot:
						next->set("composition_policy", var::string("schnorr_taproot"));
						break;
					default:
						next->set("composition_policy", var::null());
						break;
				}
				switch (asset.second.routing)
				{
					case tangent::warden::routing_policy::account:
						next->set("routing_policy", var::string("account"));
						break;
					case tangent::warden::routing_policy::memo:
						next->set("routing_policy", var::string("memo"));
						break;
					case tangent::warden::routing_policy::utxo:
						next->set("routing_policy", var::string("utxo"));
						break;
					default:
						next->set("routing_policy", var::null());
						break;
				}

				auto* supports = next->set("supports");
				supports->set("token_transfer", var::string(asset.second.supports_token_transfer));
				supports->set("bulk_transfer", var::boolean(asset.second.supports_bulk_transfer));
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::validatorstate_get_participations(http::connection* base, format::variables&& args)
		{
			auto result = uptr<schema>(var::set::array());
			auto mempool = storages::mempoolstate(__func__);
			size_t offset = 0, count = 64;
			while (true)
			{
				auto accounts = mempool.get_group_accounts(nullptr, offset, count);
				if (!accounts)
					return server_response().error(error_codes::bad_request, accounts.error().message());

				offset += accounts->size();
				for (auto& account : *accounts)
					result->push(account.as_schema().reset());
				if (accounts->empty())
					break;
			}

			return server_response().success(std::move(result));
		}
		server_response server_node::validatorstate_get_wallet(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			return server_response().success(validator->validator.wallet.as_schema());
		}
		server_response server_node::validatorstate_set_wallet(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto wallet = ledger::wallet();
			auto type = args[0].as_string();
			auto entropy = args[1].as_string();
			if (type == "key")
			{
				algorithm::seckey secret_key;
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

			auto result = validator->accept_validator_wallet(wallet);
			if (!result)
				return server_response().error(error_codes::bad_request, result.error().message());

			return server_response().success(wallet.as_schema());
		}
		server_response server_node::validatorstate_status(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto chain = storages::chainstate(__func__);
			auto block_header = chain.get_latest_block_header();
			umutex<std::recursive_mutex> unique(validator->get_mutex());
			uptr<schema> data = var::set::object();
			if (protocol::now().user.p2p.server)
			{
				auto* p2p = data->set("p2p", var::set::object());
				p2p->set("port", var::integer(protocol::now().user.p2p.port));
				p2p->set("time_offset", var::integer(protocol::now().user.p2p.time_offset));
				p2p->set("cursor_size", var::integer(protocol::now().user.p2p.cursor_size));
				p2p->set("max_inbound_connection", var::integer(protocol::now().user.p2p.max_inbound_connections));
				p2p->set("max_outbound_connection", var::integer(protocol::now().user.p2p.max_outbound_connections));
			}

			if (protocol::now().user.rpc.server)
			{
				auto* rpc = data->set("rpc", var::set::object());
				rpc->set("port", var::integer(protocol::now().user.rpc.port));
				rpc->set("admin_restriction", var::boolean(!protocol::now().user.rpc.admin_username.empty()));
				rpc->set("user_restriction", var::boolean(!protocol::now().user.rpc.user_username.empty()));
				rpc->set("cursor_size", var::integer(protocol::now().user.rpc.cursor_size));
				rpc->set("page_size", var::integer(protocol::now().user.rpc.page_size));
				rpc->set("websockets", var::boolean(protocol::now().user.rpc.web_sockets));
			}

			if (protocol::now().user.nds.server)
			{
				auto* nds = data->set("nds", var::set::object());
				nds->set("port", var::integer(protocol::now().user.nds.port));
				nds->set("cursor_size", var::integer(protocol::now().user.nds.cursor_size));
			}

			if (protocol::now().user.nss.server)
			{
				auto* nss = data->set("nss", var::set::object());
				nss->set("block_relay_multiplier", var::integer(protocol::now().user.nss.block_replay_multiplier));
				nss->set("relaying_timeout", var::integer(protocol::now().user.nss.relaying_timeout));
				nss->set("relaying_retry_timeout", var::integer(protocol::now().user.nss.relaying_retry_timeout));
				nss->set("fee_estimation_seconds", var::integer(protocol::now().user.nss.fee_estimation_seconds));
				auto array = nss->set("nodes", var::set::array());
				for (auto& asset : nss::server_node::get()->get_assets())
					array->push(algorithm::asset::serialize(asset));
			}

			auto* tcp = data->set("tcp", var::set::object());
			tcp->set("timeout", var::integer(protocol::now().user.tcp.timeout));

			auto* storage = data->set("storage", var::set::object());
			storage->set("checkpoint_size", var::integer(protocol::now().user.storage.checkpoint_size));
			storage->set("transaction_to_account_index", var::boolean(protocol::now().user.storage.transaction_to_account_index));
			storage->set("transaction_to_rollup_index", var::boolean(protocol::now().user.storage.transaction_to_rollup_index));
			storage->set("full_sync_available", var::boolean(!protocol::now().user.storage.prune_aggressively));

			if (validator->pending.hash > 0 && validator->pending.evaluation)
			{
				schema* tip = data->set("tip", var::object());
				tip->set("hash", var::string(algorithm::encoding::encode_0xhex256(validator->pending.hash)));
				tip->set("number", algorithm::encoding::serialize_uint256(validator->pending.evaluation->block.number));
				tip->set("sync", var::number(validator->get_sync_progress(validator->pending.hash, block_header ? block_header->number : 0)));
			}
			else if (block_header)
			{
				auto block_hash = block_header->as_hash();
				schema* tip = data->set("tip", var::object());
				tip->set("hash", var::string(algorithm::encoding::encode_0xhex256(block_hash)));
				tip->set("number", algorithm::encoding::serialize_uint256(block_header->number));
				tip->set("sync", var::number(validator->get_sync_progress(block_hash, block_header ? block_header->number : 0)));
			}
			else
				data->set("tip", var::null());

			auto* connections = data->set("connections", var::set::array());
			for (auto& node : validator->get_nodes())
			{
				auto* user = node.second->as_user<ledger::validator>();
				auto data = user->as_schema();
				data->set("network", node.second->as_schema().reset());
				connections->push(data.reset());
			}

			auto* forks = data->set("forks", var::set::array());
			for (auto& fork : validator->forks)
			{
				schema* item = forks->push(var::set::object());
				item->set("fork_hash", var::string(algorithm::encoding::encode_0xhex256(fork.first)));
				item->set("tip_hash", algorithm::encoding::serialize_uint256(fork.second.header.as_hash()));
				item->set("tip_number", algorithm::encoding::serialize_uint256(fork.second.header.number));
				item->set("progress", var::number(validator->get_sync_progress(fork.first, block_header ? block_header->number : 0)));
			}

			switch (protocol::now().user.network)
			{
				case network_type::mainnet:
					data->set("network", var::set::string("mainnet"));
					break;
				case network_type::testnet:
					data->set("network", var::set::string("testnet"));
					break;
				case network_type::regtest:
					data->set("network", var::set::string("regtest"));
					break;
				default:
					data->set("network", var::set::null());
					break;
			}

			data->set("version", var::string(algorithm::encoding::encode_0xhex128(protocol::now().message.protocol_version)));
			data->set("checkpoint", algorithm::encoding::serialize_uint256(chain.get_checkpoint_block_number().or_else(0)));
			return server_response().success(data.reset());
		}
		server_response server_node::validatorstate_submit_block(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			validator->accept_mempool();
			return server_response().success(var::set::null());
		}
	}
}