#include "rpc.h"
#include "p2p.h"
#include "nss.h"
#include "../../kernel/script.h"
#include "../../policy/transactions.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"

namespace tangent
{
	namespace rpc
	{
		static expects_lr<string> as_index(const std::string_view& type, const format::variable& value1, const format::variable& value2)
		{
			if (type == states::account_sequence::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value1.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_sequence::as_instance_index(owner);
			}

			if (type == states::account_program::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value1.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_program::as_instance_index(owner);
			}

			if (type == states::account_storage::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value1.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_storage::as_instance_index(owner, value2.as_string());
			}

			if (type == states::account_derivation::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value1.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_derivation::as_instance_index(owner, algorithm::asset::id_of_handle(value2.as_string()));
			}

			if (type == states::witness_program::as_instance_typename())
				return states::witness_program::as_instance_index(value1.as_string());

			if (type == states::witness_event::as_instance_typename())
				return states::witness_event::as_instance_index(value1.as_uint256());

			if (type == states::witness_transaction::as_instance_typename())
				return states::witness_transaction::as_instance_index(algorithm::asset::id_of_handle(value1.as_string()), value2.as_string());

			return layer_exception("invalid uniform type");
		}
		static expects_lr<string> as_column(const std::string_view& type, const format::variable& value)
		{
			if (type == states::account_work::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_work::as_instance_column(owner);
			}

			if (type == states::account_observer::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_observer::as_instance_column(owner);
			}

			if (type == states::account_reward::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_reward::as_instance_column(owner);
			}

			if (type == states::account_balance::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_balance::as_instance_column(owner);
			}

			if (type == states::account_depository::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::account_depository::as_instance_column(owner);
			}

			if (type == states::witness_address::as_instance_typename())
			{
				algorithm::pubkeyhash owner;
				if (!algorithm::signing::decode_address(value.as_string(), owner))
					return layer_exception("invalid address");

				return states::witness_address::as_instance_column(owner);
			}

			return layer_exception("invalid multiform type");
		}
		static expects_lr<string> as_row(const std::string_view& type, const format::variable& value)
		{
			if (type == states::account_work::as_instance_typename())
				return states::account_work::as_instance_row();

			if (type == states::account_observer::as_instance_typename())
				return states::account_observer::as_instance_row(algorithm::asset::id_of_handle(value.as_string()));

			if (type == states::account_reward::as_instance_typename())
				return states::account_reward::as_instance_row(algorithm::asset::id_of_handle(value.as_string()));

			if (type == states::account_balance::as_instance_typename())
				return states::account_balance::as_instance_row(algorithm::asset::id_of_handle(value.as_string()));

			if (type == states::account_depository::as_instance_typename())
				return states::account_depository::as_instance_row(algorithm::asset::id_of_handle(value.as_string()));

			if (type == states::witness_address::as_instance_typename())
			{
				auto data = value.as_schema();
				if (!data)
					return layer_exception("invalid value, expected { asset: string, address: string, derivation_index: uint64 }");

				return states::witness_address::as_instance_row(algorithm::asset::id_of_handle(data->get_var("asset").get_blob()), data->get_var("address").get_blob(), data->get_var("derivation_index").get_integer());
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
				VI_INFO("[rpc] peer %s call %s: %s (params: %" PRIu64 ", time: %" PRId64 " ms)",
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
				VI_INFO("[rpc] rpc node listen (location: %s:%i)", protocol::now().user.rpc.address.c_str(), (int)protocol::now().user.rpc.port);

			bind(0, "websocket", "subscribe", 1, 3, "string addresses, bool? blocks, bool? transactions", "uint64", "Subscribe to streams of incoming blocks and transactions optionally include blocks and transactions relevant to comma separated address list", std::bind(&server_node::web_socket_subscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "websocket", "unsubscribe", 1, 1, "", "void", "Unsubscribe from all streams", std::bind(&server_node::web_socket_unsubscribe, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "encodeaddress", 1, 1, "string hex_address", "string", "encode hex address", std::bind(&server_node::utility_encode_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodeaddress", 1, 1, "string address", "string", "decode address", std::bind(&server_node::utility_decode_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodemessage", 1, 1, "string message", "any[]", "decode message", std::bind(&server_node::utility_decode_message, this, std::placeholders::_1, std::placeholders::_2));
			bind(0, "utility", "decodetransaction", 1, 1, "string hex_message", "{ transaction: txn, signer_address: string }", "decode transaction message and convert to object", std::bind(&server_node::utility_decode_transaction, this, std::placeholders::_1, std::placeholders::_2));
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
			bind(0 | access_type::r, "chainstate", "immutablecall", 4, 32, "string asset, string from_address, string to_address, string function, ...", "program_trace", "execute of immutable function of program assigned to to_address", std::bind(&server_node::chainstate_immutable_call, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockstatesbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block states by hash", std::bind(&server_node::chainstate_get_block_states_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockstatesbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block states by number", std::bind(&server_node::chainstate_get_block_states_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockgaspricebyhash", 2, 3, "uint256 hash, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by hash", std::bind(&server_node::chainstate_get_block_gas_price_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockgaspricebynumber", 2, 3, "uint64 number, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by number", std::bind(&server_node::chainstate_get_block_gas_price_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockassetpricebyhash", 3, 4, "uint256 hash, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by hash", std::bind(&server_node::chainstate_get_block_asset_price_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getblockassetpricebynumber", 3, 4, "uint64 number, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by number", std::bind(&server_node::chainstate_get_block_asset_price_by_number, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getuniformbyindex", 2, 3, "string type, any argument1, any? argument2", "uniform", "get uniform by type, address and stride", std::bind(&server_node::chainstate_get_multiform_by_composition, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformbycomposition", 3, 3, "string type, any column, any row", "multiform", "get multiform by type, address and stride", std::bind(&server_node::chainstate_get_multiform_by_composition, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformbyaddress", 2, 3, "string type, any column, uint64? offset", "multiform", "get multiform by type and address", std::bind(&server_node::chainstate_get_multiform_by_column, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformsbyaddress", 4, 4, "string type, any column, uint64 offset, uint64 count", "multiform[]", "get filtered multiform by type and address", std::bind(&server_node::chainstate_get_multiforms_by_column, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformbystride", 2, 3, "string type, any row, uint64? offset", "multiform", "get multiform by type and stride", std::bind(&server_node::chainstate_get_multiform_by_row, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformbystridequery", 7, 7, "string type, any row, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value, int8 weight_order, uint64 offset, uint64 count", "multiform", "get filtered multiform by type stride", std::bind(&server_node::chainstate_get_multiforms_by_row, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getmultiformscountbystride", 4, 4, "string type, any row, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value", "uint64", "get filtered multiform count by type and stride", std::bind(&server_node::chainstate_get_multiforms_count_by_row, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountsequence", 1, 1, "string address", "uint64", "get account sequence by address", std::bind(&server_node::chainstate_get_account_sequence, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountwork", 1, 1, "string address", "multiform", "get account work by address", std::bind(&server_node::chainstate_get_account_work, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountworkers", 3, 3, "uint64 commitment, uint64 offset, uint64 count", "multiform[]", "get best block proposers (zero commitment = offline proposers, non-zero commitment = online proposers threshold)", std::bind(&server_node::chainstate_get_best_account_workers, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountobserver", 2, 2, "string asset, string address", "multiform", "get account observer by address and asset", std::bind(&server_node::chainstate_get_account_observer, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountobservers", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account observers by address", std::bind(&server_node::chainstate_get_account_observers, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountobservers", 3, 3, "string asset, bool commitment, uint64 offset, uint64 count", "multiform[]", "get best account observers (zero commitment = offline observers, non-zero commitment = online observers threshold)", std::bind(&server_node::chainstate_get_best_account_observers, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountprogram", 1, 1, "string address", "uniform", "get account program hashcode by address", std::bind(&server_node::chainstate_get_account_program, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountstorage", 2, 2, "string address, string location", "uniform", "get account storage by address and location", std::bind(&server_node::chainstate_get_account_storage, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountreward", 2, 2, "string address, string asset", "multiform", "get account reward by address and asset", std::bind(&server_node::chainstate_get_account_reward, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account rewards by address", std::bind(&server_node::chainstate_get_account_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountrewards", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best rewards", std::bind(&server_node::chainstate_get_best_account_rewards, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountrewardsforselection", 3, 3, "string asset, uint64 offset, uint64 count", "{ depository: multiform?, reward: multiform }[]", "get accounts with best rewards with additional proposer info", std::bind(&server_node::chainstate_get_best_account_rewards_for_selection, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountderivation", 2, 2, "string address, string asset", "uint64", "get account derivation by address and asset", std::bind(&server_node::chainstate_get_account_derivation, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalance", 2, 2, "string address, string asset", "multiform", "get account balance by address and asset", std::bind(&server_node::chainstate_get_account_balance, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountbalances", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account balances by address", std::bind(&server_node::chainstate_get_account_balances, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountdepository", 2, 2, "string address, string asset", "multiform", "get account depository by address and asset", std::bind(&server_node::chainstate_get_account_depository, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getaccountdepositories", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account depositories by address", std::bind(&server_node::chainstate_get_account_depositories, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountdepositories", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best depository", std::bind(&server_node::chainstate_get_best_account_depositories, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getbestaccountdepositoriesforselection", 3, 3, "string asset, uint64 offset, uint64 count", "{ depository: multiform, reward: multiform? }[]", "get accounts with best depository with additional proposer info", std::bind(&server_node::chainstate_get_best_account_depositories_for_selection, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessprogram", 1, 1, "string hashcode", "uniform", "get witness program by hashcode (512bit number)", std::bind(&server_node::chainstate_get_witness_program, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessevent", 1, 1, "uint256 transaction_hash", "uniform", "get witness event by transaction hash", std::bind(&server_node::chainstate_get_witness_event, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaddress", 3, 4, "string address, string asset, string wallet_address, uint64? derivation_index", "multiform", "get witness address by owner address, asset, wallet address and derivation index", std::bind(&server_node::chainstate_get_witness_address, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaddresses", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_addresses, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnessaddressesbypurpose", 4, 4, "string address, string purpose = 'witness' | 'router' | 'custodian' | 'depository', uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&server_node::chainstate_get_witness_addresses_by_purpose, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "chainstate", "getwitnesstransaction", 2, 2, "string asset, string transaction_id", "uniform", "get witness transaction by asset and transaction id", std::bind(&server_node::chainstate_get_witness_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnode", 0, 1, "uint64? offset", "validator", "get closest node info", std::bind(&server_node::mempoolstate_get_closest_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getclosestnodecount", 0, 0, "", "uint64", "get closest node count", std::bind(&server_node::mempoolstate_get_closest_node_counter, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnode", 1, 1, "string uri_address", "validator", "get associated node info by ip address", std::bind(&server_node::mempoolstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getaddresses", 2, 3, "uint64 offset, uint64 count, string? services = 'consensus' | 'discovery' | 'synchronization' | 'interface' | 'proposer' | 'public' | 'streaming'", "string[]", "get best node ip addresses with optional comma separated list of services", std::bind(&server_node::mempoolstate_get_addresses, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getgasprice", 1, 3, "string asset, double? percentile = 0.5, bool? mempool_only", "decimal", "get gas price from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_gas_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getassetprice", 2, 3, "string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of pending transactions", std::bind(&server_node::mempoolstate_get_asset_price, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getoptimaltransactiongas", 1, 1, "string hex_message", "uint256", "execute transaction with block gas limit and return ceil of spent gas", std::bind(&server_node::mempoolstate_get_optimal_transaction_gas, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getestimatetransactiongas", 1, 1, "string hex_message", "uint256", "get rough estimate of required gas limit than could be considerably lower or higher than actual required gas limit", std::bind(&server_node::mempoolstate_get_estimate_transaction_gas, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionbyhash", 1, 1, "uint256 hash", "txn", "get mempool transaction by hash", std::bind(&server_node::mempoolstate_get_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getrawmempooltransactionbyhash", 1, 1, "uint256 hash", "string", "get raw mempool transaction by hash", std::bind(&server_node::mempoolstate_get_raw_transaction_by_hash, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getnextaccountsequence", 1, 1, "string owner_address", "{ min: uint64, max: uint64 }", "get account sequence for next transaction by owner", std::bind(&server_node::mempoolstate_get_next_account_sequence, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactions", 2, 3, "uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions", std::bind(&server_node::mempoolstate_get_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getmempooltransactionsbyowner", 3, 5, "const string address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions by signing address", std::bind(&server_node::mempoolstate_get_transactions_by_owner, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getcumulativemempooltransactions", 3, 4, "uint256 hash, uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get cumulative mempool transactions", std::bind(&server_node::mempoolstate_get_cumulative_event_transactions, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "mempoolstate", "getcumulativemempoolconsensus", 1, 1, "uint256 hash", "{ branch: uint256, threshold: double, progress: double, committee: uint64, reached: boolean }", "get cumulative mempool transaction consensus state", std::bind(&server_node::mempoolstate_get_cumulative_consensus, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getnode", 1, 1, "string uri_address", "validator", "get a node by ip address", std::bind(&server_node::validatorstate_get_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "getblockchains", 0, 0, "", "observer::asset", "get supported blockchains", std::bind(&server_node::validatorstate_get_blockchains, this, std::placeholders::_1, std::placeholders::_2));
			bind(0 | access_type::r, "validatorstate", "status", 0, 0, "", "validator::status", "get validator status", std::bind(&server_node::validatorstate_status, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "chainstate", "tracecall", 4, 32, "string asset, string from_address, string to_address, string function, ...", "program_trace", "trace execution of mutable / immutable function of program assigned to to_address", std::bind(&server_node::chainstate_trace_call, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::r, "mempoolstate", "submittransaction", 1, 2, "string hex_message, bool? validate", "uint256", "try to accept and relay a mempool transaction from raw data and possibly validate over latest chainstate", std::bind(&server_node::mempoolstate_submit_transaction, this, std::placeholders::_1, std::placeholders::_2, nullptr));
			bind(access_type::w | access_type::a, "mempoolstate", "rejecttransaction", 1, 1, "uint256 hash", "void", "remove mempool transaction by hash", std::bind(&server_node::mempoolstate_reject_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "addnode", 1, 1, "string uri_address", "void", "add node ip address to trial addresses", std::bind(&server_node::mempoolstate_add_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "mempoolstate", "clearnode", 1, 1, "string uri_address", "void", "remove associated node info by ip address", std::bind(&server_node::mempoolstate_clear_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::r | access_type::a, "validatorstate", "verify", 2, 3, "uint64 number, uint64 count, bool? validate", "uint256[]", "verify chain and possibly re-execute each block", std::bind(&server_node::validatorstate_verify, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "prune", 2, 2, "string types = 'statetrie' | 'blocktrie' | 'transactiontrie', uint64 number", "void", "prune chainstate data using pruning level (types is '|' separated list)", std::bind(&server_node::validatorstate_prune, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "revert", 1, 2, "uint64 number, bool? keep_reverted_transactions", "{ new_tip_block_number: uint64, old_tip_block_number: uint64, mempool_transactions: uint64, block_delta: int64, transaction_delta: int64, state_delta: int64, is_fork: bool }", "revert chainstate to block number and possibly send removed transactions to mempool", std::bind(&server_node::validatorstate_revert, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "reorganize", 0, 0, "", "{ new_tip_block_number: uint64, old_tip_block_number: uint64, mempool_transactions: uint64, block_delta: int64, transaction_delta: int64, state_delta: int64, is_fork: bool }", "reorganize current chain which re-executes every saved block from genesis to tip and re-calculates the final chain state (helpful for corrupted state recovery or pruning checkpoint size change without re-downloading full block history)", std::bind(&server_node::validatorstate_reorganize, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "acceptnode", 0, 1, "string? uri_address", "void", "try to accept and connect to a node possibly by ip address", std::bind(&server_node::validatorstate_accept_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "validatorstate", "rejectnode", 1, 1, "string uri_address", "void", "reject and disconnect from a node by ip address", std::bind(&server_node::validatorstate_reject_node, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitblock", 0, 0, "", "void", "try to propose a block from mempool transactions", std::bind(&server_node::proposerstate_submit_block, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitcommitmenttransaction", 3, 4, "string asset, bool online, bool? proposer, string? observers", "uint256", "submit commitment transaction that enables/disables block proposer and/or blockchain observer(s) defined by a comma separated list of asset handles", std::bind(&server_node::proposerstate_submit_commitment_transaction, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitcontributionallocation", 1, 1, "string asset", "uint256", "request for allocation of a depository wallet", std::bind(&server_node::proposerstate_submit_contribution_allocation, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitcontributiondeallocation", 1, 1, "uint256 depository_activation_hash", "uint256", "request for deallocation of depository wallet to withdraw locked depository funds", std::bind(&server_node::proposerstate_submit_contribution_allocation, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitcontributionwithdrawal", 2, 2, "uint256 depository_deactivation_hash, string to_address", "observer::outgoing_transaction", "send unlocked depository funds to desired wallet address", std::bind(&server_node::proposerstate_submit_contribution_withdrawal, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitdepositoryadjustment", 5, 5, "string asset, decimal incoming_absolute_fee, decimal incoming_realtive_fee, decimal outgoing_absolute_fee, decimal outgoing_realtive_fee", "uint256", "adjust depository fee policy", std::bind(&server_node::proposerstate_submit_depository_adjustment, this, std::placeholders::_1, std::placeholders::_2));
			bind(access_type::w | access_type::a, "proposerstate", "submitdepositorymigration", 3, 3, "string asset, string proposer_address, decimal value", "uint256", "send custodial funds to another depository wallet", std::bind(&server_node::proposerstate_submit_depository_migration, this, std::placeholders::_1, std::placeholders::_2));
		}
		void server_node::shutdown()
		{
			if (!is_active())
				return;

			if (protocol::now().user.p2p.logging)
				VI_INFO("[rpc] rpc node shutdown requested");

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
				cospawn(std::bind(&server_node::dispatch_response, this, web_socket->get_connection(), *request, nullptr, 0, [](http::connection* base, uptr<schema>&& responses)
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
						args.push_back(format::variable(param));
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
						args.push_back(format::variable((schema*)nullptr));
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

			ordered_set<string> addresses;
			for (auto& transaction : block.transactions)
			{
				addresses.insert(string((char*)transaction.receipt.from, sizeof(algorithm::pubkeyhash)));
				transaction.transaction->recover_many(transaction.receipt, addresses);
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

			string address = string((char*)owner, sizeof(algorithm::pubkeyhash));
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

				listener.addresses.insert(string((char*)owner, sizeof(owner)));
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
		server_response server_node::utility_encode_address(http::connection* base, format::variables&& args)
		{
			auto owner = format::util::decode_0xhex(args[0].as_string());
			if (owner.size() != sizeof(algorithm::pubkeyhash))
				return server_response().error(error_codes::bad_params, "raw address not valid");

			string address;
			algorithm::signing::encode_address((uint8_t*)owner.data(), address);
			return server_response().success(var::set::string(address));
		}
		server_response server_node::utility_decode_address(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "address not valid");

			return server_response().success(var::set::string(format::util::encode_0xhex(std::string_view((char*)owner, sizeof(owner)))));
		}
		server_response server_node::utility_decode_message(http::connection* base, format::variables&& args)
		{
			format::variables values;
			format::stream message = format::stream::decode(args[0].as_blob());
			if (!format::variables_util::deserialize_flat_from(message, &values))
				return server_response().error(error_codes::bad_params, "invalid message");

			return server_response().success(format::variables_util::serialize(values));
		}
		server_response server_node::utility_decode_transaction(http::connection* base, format::variables&& args)
		{
			format::stream message = format::stream::decode(args[0].as_blob());
			uptr<ledger::transaction> candidate_tx = transactions::resolver::init(messages::authentic::resolve_type(message).or_else(0));
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			algorithm::pubkeyhash owner = { 0 }, null = { 0 };
			bool successful = candidate_tx->recover_hash(owner);
			uptr<schema> result = var::set::object();
			result->set("transaction", candidate_tx->as_schema().reset());
			result->set("signer_address", successful ? algorithm::signing::serialize_address(owner) : var::set::null());
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
				block_proof->get_transactions_tree();
			if (receipts)
				block_proof->get_receipts_tree();
			if (states)
				block_proof->get_states_tree();

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
				block_proof->get_transactions_tree();
			if (receipts)
				block_proof->get_receipts_tree();
			if (states)
				block_proof->get_states_tree();

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
		server_response server_node::chainstate_call(format::variables&& args, bool tracing)
		{
			algorithm::pubkeyhash from;
			if (!algorithm::signing::decode_address(args[1].as_string(), from))
				return server_response().error(error_codes::bad_params, "from account address not valid");

			algorithm::pubkeyhash to;
			if (!algorithm::signing::decode_address(args[2].as_string(), to))
				return server_response().error(error_codes::bad_params, "to account address not valid");

			format::variables values;
			values.reserve(args.size() - 4);
			for (size_t i = 4; i < args.size(); i++)
				values.push_back(args[i]);

			transactions::invocation transaction;
			transaction.asset = algorithm::asset::id_of_handle(args[0].as_string());
			transaction.signature[0] = 0xFF;
			transaction.set_calldata(to, args[3].as_string(), std::move(values));
			transaction.set_gas(decimal::zero(), ledger::block::get_gas_limit());

			auto context = ledger::transaction_context();
			auto sequence = context.get_account_sequence(from);
			transaction.sequence = sequence ? sequence->sequence : 1;

			auto script = ledger::script_program_trace(&transaction, from, tracing);
			auto execution = script.trace_call(transaction.function, transaction.args, tracing ? -1 : 0);
			if (!execution)
				return server_response().error(error_codes::bad_params, execution.error().message());

			return server_response().success(script.as_schema());
		}
		server_response server_node::chainstate_immutable_call(http::connection* base, format::variables&& args)
		{
			return chainstate_call(std::move(args), false);
		}
		server_response server_node::chainstate_trace_call(http::connection* base, format::variables&& args)
		{
			return chainstate_call(std::move(args), true);
		}
		server_response server_node::chainstate_get_block_states_by_hash(http::connection* base, format::variables&& args)
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

				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_statetrie_by_number(*block_number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.second->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

				return server_response().success(std::move(data));
			}
		}
		server_response server_node::chainstate_get_block_states_by_number(http::connection* base, format::variables&& args)
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
				uptr<schema> data = var::set::array();
				while (true)
				{
					auto list = chain.get_block_statetrie_by_number(number, data->size(), protocol::now().user.rpc.cursor_size);
					if (!list)
						return server_response().error(error_codes::not_found, "block not found");

					for (auto& item : *list)
						data->push(item.second->as_schema().reset());
					if (list->size() < protocol::now().user.rpc.cursor_size)
						break;
				}

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
		server_response server_node::chainstate_get_uniform_by_index(http::connection* base, format::variables&& args)
		{
			auto index = as_index(args[0].as_string(), args[1], args.size() > 2 ? args[2] : format::variable());
			if (!index)
				return server_response().error(error_codes::bad_params, "index not valid: " + index.error().message());

			auto chain = storages::chainstate(__func__);
			auto uniform = chain.get_uniform_by_index(nullptr, *index, 0);
			if (!uniform)
				return server_response().error(error_codes::not_found, "uniform not found");

			return server_response().success((*uniform)->as_schema());
		}
		server_response server_node::chainstate_get_multiform_by_composition(http::connection* base, format::variables&& args)
		{
			auto column = as_column(args[0].as_string(), args[1]);
			if (!column)
				return server_response().error(error_codes::bad_params, "column not valid: " + column.error().message());

			auto row = as_row(args[0].as_string(), args[2]);
			if (!row)
				return server_response().error(error_codes::bad_params, "row not valid: " + row.error().message());

			auto chain = storages::chainstate(__func__);
			auto multiform = chain.get_multiform_by_composition(nullptr, *column, *row, 0);
			if (!multiform)
				return server_response().error(error_codes::not_found, "multiform not found");

			return server_response().success((*multiform)->as_schema());
		}
		server_response server_node::chainstate_get_multiform_by_column(http::connection* base, format::variables&& args)
		{
			auto column = as_column(args[0].as_string(), args[1]);
			if (!column)
				return server_response().error(error_codes::bad_params, "column not valid: " + column.error().message());

			size_t offset = args.size() > 2 ? args[2].as_uint64() : 0;
			auto chain = storages::chainstate(__func__);
			auto multiform = chain.get_multiform_by_column(nullptr, *column, 0, offset);
			if (!multiform)
				return server_response().error(error_codes::not_found, "multiform not found");

			return server_response().success((*multiform)->as_schema());
		}
		server_response server_node::chainstate_get_multiforms_by_column(http::connection* base, format::variables&& args)
		{
			auto column = as_column(args[0].as_string(), args[1]);
			if (!column)
				return server_response().error(error_codes::bad_params, "column not valid: " + column.error().message());

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(nullptr, *column, 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiform_by_row(http::connection* base, format::variables&& args)
		{
			auto row = as_row(args[0].as_string(), args[1]);
			if (!row)
				return server_response().error(error_codes::bad_params, "row not valid: " + row.error().message());

			size_t offset = args.size() > 2 ? args[2].as_uint64() : 0;
			auto chain = storages::chainstate(__func__);
			auto multiform = chain.get_multiform_by_row(nullptr, *row, 0, offset);
			if (!multiform)
				return server_response().error(error_codes::not_found, "multiform not found");

			return server_response().success((*multiform)->as_schema());
		}
		server_response server_node::chainstate_get_multiforms_by_row(http::connection* base, format::variables&& args)
		{
			auto row = as_row(args[0].as_string(), args[1]);
			if (!row)
				return server_response().error(error_codes::bad_params, "row not valid: " + row.error().message());

			uint64_t offset = args[5].as_uint64(), count = args[6].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::from(args[2].as_string(), args[3].as_decimal().to_int64(), args[4].as_decimal().to_int8());
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, *row, filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "multiform not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_multiforms_count_by_row(http::connection* base, format::variables&& args)
		{
			auto row = as_row(args[0].as_string(), args[1]);
			if (!row)
				return server_response().error(error_codes::bad_params, "row not valid: " + row.error().message());

			auto filter = storages::factor_filter::from(args[2].as_string(), args[3].as_decimal().to_int64(), 0);
			auto chain = storages::chainstate(__func__);
			auto count = chain.get_multiforms_count_by_row_filter(*row, filter, 0);
			if (!count)
				return server_response().error(error_codes::not_found, "count not found");

			return server_response().success(algorithm::encoding::serialize_uint256(*count));
		}
		server_response server_node::chainstate_get_account_sequence(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::account_sequence::as_instance_index(owner), 0);
			auto* value = (states::account_sequence*)(state ? **state : nullptr);
			return server_response().success(algorithm::encoding::serialize_uint256(value ? value->sequence : 1));
		}
		server_response server_node::chainstate_get_account_work(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(nullptr, states::account_work::as_instance_column(owner), states::account_work::as_instance_row(), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_best_account_workers(http::connection* base, format::variables&& args)
		{
			uint64_t commitment = args[0].as_uint64();
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = commitment > 0 ? storages::factor_filter::greater_equal(commitment - 1, -1) : storages::factor_filter::equal(-1, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_work::as_instance_row(), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_observer(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(nullptr, states::account_observer::as_instance_column(owner), states::account_observer::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_observers(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(nullptr, states::account_observer::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_account_observers(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			bool commitment = args[1].as_boolean();
			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::equal(commitment ? 1 : -1, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_observer::as_instance_row(asset), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_program(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::account_program::as_instance_index(owner), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_storage(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::account_storage::as_instance_index(owner, args[1].as_string()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_reward(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform_by_composition(nullptr, states::account_reward::as_instance_column(owner), states::account_reward::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_rewards(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(nullptr, states::account_reward::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_account_rewards(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_reward::as_instance_row(asset), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_account_rewards_for_selection(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_reward::as_instance_row(asset), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto asset_stride = states::account_depository::as_instance_row(asset);
			auto work_stride = states::account_work::as_instance_row();
			uptr<schema> data = var::set::array();
			for (auto& item : *list)
			{
				auto* reward_state = (states::account_reward*)*item;
				auto depository_state = chain.get_multiform_by_composition(nullptr, states::account_depository::as_instance_column(reward_state->owner), asset_stride, 0);
				auto work_state = chain.get_multiform_by_composition(nullptr, states::account_work::as_instance_column(reward_state->owner), work_stride, 0);
				auto* next = data->push(var::set::object());
				next->set("work", work_state ? (*work_state)->as_schema().reset() : var::set::null());
				next->set("depository", depository_state ? (*depository_state)->as_schema().reset() : var::set::null());
				next->set("reward", reward_state->as_schema().reset());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_derivation(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_uniform_by_index(nullptr, states::account_derivation::as_instance_index(owner, asset), 0);
			auto* value = (states::account_derivation*)(state ? **state : nullptr);
			return server_response().success(algorithm::encoding::serialize_uint256(value ? value->max_address_index : protocol::now().account.root_address_index));
		}
		server_response server_node::chainstate_get_account_balance(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform_by_composition(nullptr, states::account_balance::as_instance_column(owner), states::account_balance::as_instance_row(asset), 0);
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
			auto list = chain.get_multiforms_by_column(nullptr, states::account_balance::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_account_depository(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto chain = storages::chainstate(__func__);
			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto state = chain.get_multiform_by_composition(nullptr, states::account_depository::as_instance_column(owner), states::account_depository::as_instance_row(asset), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_account_depositories(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(nullptr, states::account_depository::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_account_depositories(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_depository::as_instance_row(asset), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_best_account_depositories_for_selection(http::connection* base, format::variables&& args)
		{
			auto asset = algorithm::asset::id_of_handle(args[0].as_string());
			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto filter = storages::factor_filter::greater_equal(0, -1);
			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_row_filter(nullptr, states::account_depository::as_instance_row(asset), filter, 0, storages::factor_range_window(offset, count));
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			auto asset_stride = states::account_reward::as_instance_row(asset);
			auto work_stride = states::account_work::as_instance_row();
			uptr<schema> data = var::set::array();
			for (auto& item : *list)
			{
				auto* depository_state = (states::account_depository*)*item;
				auto work_state = chain.get_multiform_by_composition(nullptr, states::account_work::as_instance_column(depository_state->owner), work_stride, 0);
				auto reward_state = chain.get_multiform_by_composition(nullptr, states::account_reward::as_instance_column(depository_state->owner), asset_stride, 0);
				auto* next = data->push(var::set::object());
				next->set("work", work_state ? (*work_state)->as_schema().reset() : var::set::null());
				next->set("depository", depository_state->as_schema().reset());
				next->set("reward", reward_state ? (*reward_state)->as_schema().reset() : var::set::null());
			}
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_program(http::connection* base, format::variables&& args)
		{
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::witness_program::as_instance_index(args[0].as_string()), 0);
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
			auto state = chain.get_uniform_by_index(nullptr, states::witness_event::as_instance_index(args[0].as_uint256()), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_witness_address(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			auto asset = algorithm::asset::id_of_handle(args[1].as_string());
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_multiform_by_composition(nullptr, states::witness_address::as_instance_column(owner), states::witness_address::as_instance_row(asset, args[2].as_string(), args.size() > 3 ? args[3].as_uint64() : protocol::now().account.root_address_index), 0);
			return server_response().success(state ? (*state)->as_schema().reset() : var::set::null());
		}
		server_response server_node::chainstate_get_witness_addresses(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			uint64_t offset = args[1].as_uint64(), count = args[2].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto list = chain.get_multiforms_by_column(nullptr, states::witness_address::as_instance_column(owner), 0, offset, count);
			if (!list)
				return server_response().error(error_codes::not_found, "data not found");

			uptr<schema> data = var::set::array();
			for (auto& item : *list)
				data->push(item->as_schema().reset());
			return server_response().success(std::move(data));
		}
		server_response server_node::chainstate_get_witness_addresses_by_purpose(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "account address not valid");

			int64_t purpose = std::numeric_limits<int64_t>::max();
			string type = args[1].as_blob();
			if (type == "witness")
				purpose = (int64_t)states::address_type::witness;
			else if (type == "router")
				purpose = (int64_t)states::address_type::router;
			else if (type == "custodian")
				purpose = (int64_t)states::address_type::custodian;
			else if (type == "depository")
				purpose = (int64_t)states::address_type::contribution;
			if (purpose == std::numeric_limits<int64_t>::max())
				return server_response().error(error_codes::bad_params, "address purpose not valid");

			uint64_t offset = args[2].as_uint64(), count = args[3].as_uint64();
			if (!count || count > protocol::now().user.rpc.page_size)
				return server_response().error(error_codes::bad_params, "count not valid");

			auto chain = storages::chainstate(__func__);
			auto filter = storages::factor_filter::equal((int64_t)purpose, 1);
			auto list = chain.get_multiforms_by_column_filter(nullptr, states::witness_address::as_instance_column(owner), filter, 0, storages::factor_range_window(offset, count));
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
			auto state = chain.get_uniform_by_index(nullptr, states::witness_transaction::as_instance_index(asset, args[1].as_string()), 0);
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
					else if (service == "proposer")
						services |= (uint32_t)storages::node_services::proposer;
					else if (service == "public")
						services |= (uint32_t)storages::node_services::publicity;
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
		server_response server_node::mempoolstate_get_estimate_transaction_gas(http::connection* base, format::variables&& args)
		{
			format::stream message = format::stream::decode(args[0].as_blob());
			uptr<ledger::transaction> candidate_tx = transactions::resolver::init(messages::authentic::resolve_type(message).or_else(0));
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			return server_response().success(algorithm::encoding::serialize_uint256(candidate_tx->get_gas_estimate()));
		}
		server_response server_node::mempoolstate_get_optimal_transaction_gas(http::connection* base, format::variables&& args)
		{
			format::stream message = format::stream::decode(args[0].as_blob());
			uptr<ledger::transaction> candidate_tx = transactions::resolver::init(messages::authentic::resolve_type(message).or_else(0));
			if (!candidate_tx || !candidate_tx->load(message))
				return server_response().error(error_codes::bad_params, "invalid message");

			candidate_tx->set_optimal_gas(candidate_tx->gas_price);
			return server_response().success(algorithm::encoding::serialize_uint256(candidate_tx->gas_limit));
		}
		server_response server_node::mempoolstate_submit_transaction(http::connection* base, format::variables&& args, ledger::transaction* prebuilt)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			format::stream message = prebuilt ? format::stream() : format::stream::decode(args[0].as_blob());
			uptr<ledger::transaction> candidate_tx = prebuilt ? prebuilt : transactions::resolver::init(messages::authentic::resolve_type(message).or_else(0));
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
		server_response server_node::mempoolstate_get_next_account_sequence(http::connection* base, format::variables&& args)
		{
			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[0].as_string(), owner))
				return server_response().error(error_codes::bad_params, "owner address not valid");

			auto mempool = storages::mempoolstate(__func__);
			auto chain = storages::chainstate(__func__);
			auto state = chain.get_uniform_by_index(nullptr, states::account_sequence::as_instance_index(owner), 0);
			auto* value = (states::account_sequence*)(state ? **state : nullptr);
			auto lowest = mempool.get_lowest_transaction_sequence(owner);
			auto highest = mempool.get_highest_transaction_sequence(owner);
			if (!lowest)
				lowest = value ? value->sequence : 1;
			if (!highest)
				highest = value ? value->sequence : 1;
			else if (value != nullptr && *highest < value->sequence)
				highest = value->sequence;
			else
				highest = *highest + 1;

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
		server_response server_node::mempoolstate_get_cumulative_event_transactions(http::connection* base, format::variables&& args)
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
				auto list = mempool.get_cumulative_event_transactions(hash, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(var::set::string(algorithm::encoding::encode_0xhex256(item->as_hash())));
				return server_response().success(std::move(data));
			}
			else
			{
				uptr<schema> data = var::set::array();
				auto list = mempool.get_cumulative_event_transactions(hash, offset, count);
				if (!list)
					return server_response().error(error_codes::not_found, "transactions not found");

				for (auto& item : *list)
					data->push(item->as_schema().reset());
				return server_response().success(std::move(data));
			}
		}
		server_response server_node::mempoolstate_get_cumulative_consensus(http::connection* base, format::variables&& args)
		{
			uint256_t hash = args[0].as_uint256();
			auto mempool = storages::mempoolstate(__func__);
			auto reference = mempool.get_transaction_by_hash(hash);
			if (!reference)
				return server_response().error(error_codes::not_found, "transaction not found");

			auto& transaction = *reference;
			if (transaction->get_type() != ledger::transaction_level::aggregation)
				return server_response().error(error_codes::not_found, "transaction consensus is not applicable");

			auto context = ledger::transaction_context();
			auto* aggregation = (ledger::aggregation_transaction*)*transaction;
			auto consensus = aggregation->calculate_cumulative_consensus(nullptr, &context);
			if (!consensus)
				return server_response().error(error_codes::not_found, "transaction consensus is not computable");

			auto result = var::set::object();
			result->set("branch", var::string(algorithm::encoding::encode_0xhex256(consensus->branch->message.hash())));
			result->set("threshold", var::number(consensus->threshold));
			result->set("progress", var::number(consensus->progress));
			result->set("committee", var::integer(consensus->committee));
			result->set("reached", var::boolean(consensus->reached));
			return server_response().success(result);
		}
		server_response server_node::validatorstate_prune(http::connection* base, format::variables&& args)
		{
			uint32_t types = 0;
			for (auto& subtype : stringify::split(args[0].as_string(), '|'))
			{
				if (subtype == "blocktrie")
					types |= (uint32_t)storages::pruning::blocktrie;
				else if (subtype == "transactiontrie")
					types |= (uint32_t)storages::pruning::transactiontrie;
				else if (subtype == "statetrie")
					types |= (uint32_t)storages::pruning::statetrie;
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

			auto checkpoint = block->checkpoint(args.size() > 1 ? args[1].as_boolean() : false);
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

					verification = next->verify_integrity(parent_block.address());
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
					case algorithm::composition::type::ED25519:
						next->set("composition_policy", var::string("ed25519"));
						break;
					case algorithm::composition::type::SECP256K1:
						next->set("composition_policy", var::string("secp256k1"));
						break;
					default:
						next->set("composition_policy", var::null());
						break;
				}
				switch (asset.second.routing)
				{
					case tangent::mediator::routing_policy::account:
						next->set("routing_policy", var::string("account"));
						break;
					case tangent::mediator::routing_policy::memo:
						next->set("routing_policy", var::string("memo"));
						break;
					case tangent::mediator::routing_policy::UTXO:
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
				auto* P2P = data->set("p2p", var::set::object());
				P2P->set("port", var::integer(protocol::now().user.p2p.port));
				P2P->set("time_offset", var::integer(protocol::now().user.p2p.time_offset));
				P2P->set("cursor_size", var::integer(protocol::now().user.p2p.cursor_size));
				P2P->set("max_inbound_connection", var::integer(protocol::now().user.p2p.max_inbound_connections));
				P2P->set("max_outbound_connection", var::integer(protocol::now().user.p2p.max_outbound_connections));
				P2P->set("proposer", var::boolean(protocol::now().user.p2p.proposer));
			}

			if (protocol::now().user.rpc.server)
			{
				auto* RPC = data->set("rpc", var::set::object());
				RPC->set("port", var::integer(protocol::now().user.rpc.port));
				RPC->set("admin_restriction", var::boolean(!protocol::now().user.rpc.admin_username.empty()));
				RPC->set("user_restriction", var::boolean(!protocol::now().user.rpc.user_username.empty()));
				RPC->set("cursor_size", var::integer(protocol::now().user.rpc.cursor_size));
				RPC->set("page_size", var::integer(protocol::now().user.rpc.page_size));
				RPC->set("websockets", var::boolean(protocol::now().user.rpc.web_sockets));
				if (protocol::now().user.rpc.messaging && validator != nullptr)
					RPC->set("public_key", var::string(validator->validator.wallet.get_public_key()));
			}

			if (protocol::now().user.nds.server)
			{
				auto* NDS = data->set("nds", var::set::object());
				NDS->set("port", var::integer(protocol::now().user.nds.port));
				NDS->set("cursor_size", var::integer(protocol::now().user.nds.cursor_size));
			}

			if (protocol::now().user.nss.server)
			{
				auto* NSS = data->set("nss", var::set::object());
				NSS->set("block_relay_multiplier", var::integer(protocol::now().user.nss.block_replay_multiplier));
				NSS->set("relaying_timeout", var::integer(protocol::now().user.nss.relaying_timeout));
				NSS->set("relaying_retry_timeout", var::integer(protocol::now().user.nss.relaying_retry_timeout));
				NSS->set("fee_estimation_seconds", var::integer(protocol::now().user.nss.fee_estimation_seconds));
				NSS->set("withdrawal_time", var::integer(protocol::now().user.nss.withdrawal_time));
				auto array = NSS->set("nodes", var::set::array());
				for (auto& asset : nss::server_node::get()->get_assets())
					array->push(algorithm::asset::serialize(asset));
			}

			auto* TCP = data->set("tcp", var::set::object());
			TCP->set("timeout", var::integer(protocol::now().user.tcp.timeout));

			auto* storage = data->set("storage", var::set::object());
			storage->set("checkpoint_size", var::integer(protocol::now().user.storage.checkpoint_size));
			storage->set("transaction_to_account_index", var::boolean(protocol::now().user.storage.transaction_to_account_index));
			storage->set("transaction_to_rollup_index", var::boolean(protocol::now().user.storage.transaction_to_rollup_index));
			storage->set("full_sync_available", var::boolean(!protocol::now().user.storage.prune_aggressively));

			if (validator->pending_tip.hash > 0 && validator->pending_tip.block)
			{
				schema* tip = data->set("tip", var::object());
				tip->set("hash", var::string(algorithm::encoding::encode_0xhex256(validator->pending_tip.hash)));
				tip->set("number", algorithm::encoding::serialize_uint256(validator->pending_tip.block->number));
				tip->set("sync", var::number(validator->get_sync_progress(validator->pending_tip.hash, block_header ? block_header->number : 0)));
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

			auto* candidates = data->set("candidates", var::set::array());
			for (auto& node : validator->get_candidate_nodes())
			{
				auto& address = node->get_peer_address();
				auto ip_address = address.get_ip_address();
				auto ip_port = address.get_ip_port();
				candidates->push(var::string(ip_port ? ip_address.or_else("[???]") + ":" + to_string(*ip_port) : ip_address.or_else("[???]")));
			}

			auto* forks = data->set("forks", var::set::array());
			for (auto& fork : validator->forks)
			{
				schema* item = forks->push(var::set::object());
				item->set("branch_hash", var::string(algorithm::encoding::encode_0xhex256(fork.first)));
				item->set("tip_hash", algorithm::encoding::serialize_uint256(fork.second.as_hash()));
				item->set("tip_number", algorithm::encoding::serialize_uint256(fork.second.number));
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
					data->set("network", var::set::string("unspecified"));
					break;
			}

			data->set("version", var::string(algorithm::encoding::encode_0xhex128(protocol::now().message.protocol_version)));
			data->set("checkpoint", algorithm::encoding::serialize_uint256(chain.get_checkpoint_block_number().or_else(0)));
			return server_response().success(data.reset());
		}
		server_response server_node::proposerstate_submit_block(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			validator->accept_mempool();
			return server_response().success(var::set::null());
		}
		server_response server_node::proposerstate_submit_commitment_transaction(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			bool online = args[1].as_boolean();
			auto context = ledger::transaction_context();
			auto work = context.get_account_work(validator->validator.wallet.public_key_hash);
			auto transaction = memory::init<transactions::commitment>();
			transaction->asset = algorithm::asset::id_of_handle(args[0].as_string());
			if (args.size() > 2 ? args[2].as_boolean() : false)
			{
				if (online)
				{
					if (!work || !work->is_online())
						transaction->set_online();
				}
				else if (work && work->is_matching(states::account_flags::online))
					transaction->set_offline();
			}

			if (args.size() > 3)
			{
				auto assets = nss::server_node::get()->get_assets();
				auto observers = context.get_account_observers(validator->validator.wallet.public_key_hash, 0, assets.size()).or_else(vector<states::account_observer>());
				for (auto& id : stringify::split(args[3].as_string(), ','))
				{
					auto asset = algorithm::asset::id_of_handle(stringify::trim(id));
					auto it = std::find_if(observers.begin(), observers.end(), [&](const states::account_observer& item) { return item.asset == asset; });
					if (online)
					{
						if (it == observers.end() || !it->observing)
							transaction->set_online(asset);
					}
					else if (it != observers.end() && it->observing)
						transaction->set_offline(asset);
				}
			}

			umutex<std::recursive_mutex> unique(validator->sync.account);
			auto account_sequence = validator->validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			uint256_t candidate_hash = 0;
			auto status = validator->propose_transaction(nullptr, transaction, account_sequence, &candidate_hash);
			if (!status)
				return server_response().error(error_codes::bad_params, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::proposerstate_submit_contribution_allocation(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto transaction = memory::init<transactions::contribution_allocation>();
			transaction->asset = algorithm::asset::id_of_handle(args[0].as_string());

			umutex<std::recursive_mutex> unique(validator->sync.account);
			auto account_sequence = validator->validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			uint256_t candidate_hash = 0;
			auto status = validator->propose_transaction(nullptr, transaction, account_sequence, &candidate_hash);
			if (!status)
				return server_response().error(error_codes::bad_params, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::proposerstate_submit_contribution_deallocation(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto context = ledger::transaction_context();
			auto initiator = context.get_block_transaction<transactions::contribution_activation>(args[0].as_uint256());
			if (!initiator)
				return server_response().error(error_codes::bad_request, "transaction not found");

			auto transaction = memory::init<transactions::contribution_deallocation>();
			transaction->asset = initiator->transaction->asset;
			transaction->set_witness(validator->validator.wallet.secret_key, initiator->receipt.transaction_hash);

			umutex<std::recursive_mutex> unique(validator->sync.account);
			auto account_sequence = validator->validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			uint256_t candidate_hash = 0;
			auto status = validator->propose_transaction(nullptr, transaction, account_sequence, &candidate_hash);
			if (!status)
				return server_response().error(error_codes::bad_params, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::proposerstate_submit_contribution_withdrawal(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto result = coasync<expects_rt<mediator::outgoing_transaction>>([this, args = std::move(args)]() mutable -> promise<expects_rt<mediator::outgoing_transaction>>
			{
				auto context = ledger::transaction_context();
				auto initiator = context.get_block_transaction<transactions::contribution_deactivation>(args[0].as_uint256());
				if (!initiator)
					coreturn remote_exception("transaction not found");

				auto* transaction = (transactions::contribution_deactivation*)*initiator->transaction;
				auto result = coawait(transaction->withdraw_to_address(&context, validator->validator.wallet.secret_key, args[1].as_string()));
				coreturn std::move(result);
			}).get();
			if (!result)
				return server_response().error(error_codes::bad_request, result.error().message());

			return server_response().success(result->as_schema().reset());
		}
		server_response server_node::proposerstate_submit_depository_adjustment(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			auto transaction = memory::init<transactions::depository_adjustment>();
			transaction->asset = algorithm::asset::id_of_handle(args[0].as_string());
			transaction->set_incoming_fee(args[1].as_decimal(), args[2].as_decimal());
			transaction->set_outgoing_fee(args[3].as_decimal(), args[4].as_decimal());

			umutex<std::recursive_mutex> unique(validator->sync.account);
			auto account_sequence = validator->validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			uint256_t candidate_hash = 0;
			auto status = validator->propose_transaction(nullptr, transaction, account_sequence, &candidate_hash);
			if (!status)
				return server_response().error(error_codes::bad_params, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
		server_response server_node::proposerstate_submit_depository_migration(http::connection* base, format::variables&& args)
		{
			if (!validator)
				return server_response().error(error_codes::bad_request, "validator node disabled");

			algorithm::pubkeyhash owner;
			if (!algorithm::signing::decode_address(args[1].as_string(), owner))
				return server_response().error(error_codes::bad_params, "invalid address");

			auto transaction = memory::init<transactions::depository_migration>();
			transaction->asset = algorithm::asset::id_of_handle(args[0].as_string());
			transaction->set_proposer(owner, args[1].as_decimal());

			umutex<std::recursive_mutex> unique(validator->sync.account);
			auto account_sequence = validator->validator.wallet.get_latest_sequence().or_else(1);
			unique.unlock();

			uint256_t candidate_hash = 0;
			auto status = validator->propose_transaction(nullptr, transaction, account_sequence, &candidate_hash);
			if (!status)
				return server_response().error(error_codes::bad_params, status.error().message());

			return server_response().success(var::set::string(algorithm::encoding::encode_0xhex256(candidate_hash)));
		}
	}
}