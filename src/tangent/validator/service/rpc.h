#ifndef TAN_LAYER_RPC_H
#define TAN_LAYER_RPC_H
#include "../../layer/format.h"
#include "../../layer/control.h"
#include "../../kernel/block.h"

namespace tangent
{
	namespace consensus
	{
		class server_node;
	}

	namespace rpc
	{
		using server_function = std::function<struct server_response(http::connection*, format::variables&&)>;

		enum class access_type
		{
			r = (1 << 0),
			w = (1 << 1),
			a = (1 << 2)
		};

		enum class error_codes
		{
			response = 0,
			notification = 1,
			bad_request = -1,
			bad_version = -2,
			bad_method = -3,
			bad_params = -4,
			not_found = -5
		};

		inline uint32_t operator |(access_type a, access_type b)
		{
			return static_cast<uint32_t>(a) | static_cast<uint32_t>(b);
		}
		inline uint32_t operator |(uint32_t, access_type a)
		{
			return static_cast<uint32_t>(a);
		}

		struct server_response
		{
			uptr<schema> data;
			string error_message;
			error_codes status = error_codes::response;

			server_response&& success(uptr<schema>&& value);
			server_response&& notification(uptr<schema>&& value);
			server_response&& error(error_codes code, const std::string_view& message);
			uptr<schema> transform(schema* request);
		};

		struct server_request
		{
			uint32_t access_types = 0;
			size_t min_params = 0;
			size_t max_params = 0;
			server_function function;
			string description;
			string args;
			string domain;
			string returns;
		};

		class server_node : public reference<server_node>
		{
		private:
			struct ws_listener
			{
				unordered_set<algorithm::pubkeyhash_t> addresses;
				bool transactions = false;
				bool blocks = false;
			};

		private:
			unordered_map<http::connection*, ws_listener> listeners;
			unordered_map<string, server_request> methods;
			std::mutex mutex;

		protected:
			system_control control_sys;
			consensus::server_node* consensus_service;
			uptr<http::server> node;
			string auth_token;

		public:
			server_node(consensus::server_node* new_consensus_service) noexcept;
			~server_node() noexcept;
			void startup();
			void shutdown();
			void bind(uint32_t access_types, const std::string_view& domain, const std::string_view& method, size_t min_params, size_t max_params, const std::string_view& args, const std::string_view& returns, const std::string_view& description, server_function&& function);
			bool is_active();
			service_control::service_node get_entrypoint();

		private:
			bool authorize(http::connection* base, http::credentials* credentials);
			bool headers(http::connection* base, string& content);
			bool options(http::connection* base);
			bool http_request(http::connection* base);
			bool ws_receive(http::web_socket_frame* web_socket, http::web_socket_op opcode, const std::string_view& buffer);
			void ws_disconnect(http::web_socket_frame* web_socket);
			bool dispatch_response(http::connection* base, uptr<schema>&& requests, uptr<schema>&& responses, size_t index, std::function<void(http::connection*, uptr<schema>&&)>&& callback);
			void dispatch_accept_block(const uint256_t& hash, const ledger::block& block, const ledger::block_checkpoint& checkpoint);
			void dispatch_accept_transaction(const uint256_t& hash, const ledger::transaction* transaction, const algorithm::pubkeyhash_t& owner);
			server_response web_socket_subscribe(http::connection* base, format::variables&& args);
			server_response web_socket_unsubscribe(http::connection* base, format::variables&& args);
			server_response utility_encode_address(http::connection* base, format::variables&& args);
			server_response utility_decode_address(http::connection* base, format::variables&& args);
			server_response utility_decode_message(http::connection* base, format::variables&& args);
			server_response utility_decode_transaction(http::connection* base, format::variables&& args);
			server_response utility_help(http::connection* base, format::variables&& args);
			server_response blockstate_get_blocks(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_checkpoint_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_checkpoint_number(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_tip_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_tip_number(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_by_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_by_number(http::connection* base, format::variables&& args);
			server_response blockstate_get_raw_block_by_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_raw_block_by_number(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_proof_by_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_proof_by_number(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_number_by_hash(http::connection* base, format::variables&& args);
			server_response blockstate_get_block_hash_by_number(http::connection* base, format::variables&& args);
			server_response txnstate_get_block_transactions_by_hash(http::connection* base, format::variables&& args);
			server_response txnstate_get_block_transactions_by_number(http::connection* base, format::variables&& args);
			server_response txnstate_get_block_receipts_by_hash(http::connection* base, format::variables&& args);
			server_response txnstate_get_block_receipts_by_number(http::connection* base, format::variables&& args);
			server_response txnstate_get_pending_transactions(http::connection* base, format::variables&& args);
			server_response txnstate_get_transactions_by_owner(http::connection* base, format::variables&& args);
			server_response txnstate_get_transaction_by_hash(http::connection* base, format::variables&& args);
			server_response txnstate_get_raw_transaction_by_hash(http::connection* base, format::variables&& args);
			server_response txnstate_get_receipt_by_transaction_hash(http::connection* base, format::variables&& args);
			server_response chainstate_call_transaction(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_state_by_hash(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_state_by_number(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_gas_price_by_hash(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_gas_price_by_number(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_asset_price_by_hash(http::connection* base, format::variables&& args);
			server_response chainstate_get_block_asset_price_by_number(http::connection* base, format::variables&& args);
			server_response chainstate_get_uniform(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiform(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_by_column(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_by_column_filter(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_by_row(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_by_row_filter(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_count_by_column(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_count_by_column_filter(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_count_by_row(http::connection* base, format::variables&& args);
			server_response chainstate_get_multiforms_count_by_row_filter(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_nonce(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_program(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_uniform(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_multiform(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_multiforms(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_delegation(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_balance(http::connection* base, format::variables&& args);
			server_response chainstate_get_account_balances(http::connection* base, format::variables&& args);
			server_response chainstate_get_validator_production(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_validator_producers(http::connection* base, format::variables&& args);
			server_response chainstate_get_validator_participation(http::connection* base, format::variables&& args);
			server_response chainstate_get_validator_participations(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_validator_participations(http::connection* base, format::variables&& args);
			server_response chainstate_get_validator_attestation(http::connection* base, format::variables&& args);
			server_response chainstate_get_validator_attestations(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_validator_attestations(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_reward(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_rewards(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_rewards(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_rewards_for_selection(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_policy(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_account(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_accounts(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_balance(http::connection* base, format::variables&& args);
			server_response chainstate_get_bridge_balances(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_balances(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_balances_for_selection(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_policies(http::connection* base, format::variables&& args);
			server_response chainstate_get_best_bridge_policies_for_selection(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_program(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_event(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_account(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_accounts(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_accounts_by_purpose(http::connection* base, format::variables&& args);
			server_response chainstate_get_witness_transaction(http::connection* base, format::variables&& args);
			server_response chainstate_get_asset_holders(http::connection* base, format::variables&& args);
			server_response mempoolstate_add_node(http::connection* base, format::variables&& args);
			server_response mempoolstate_clear_node(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_closest_node(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_closest_node_counter(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_node(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_addresses(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_gas_price(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_asset_price(http::connection* base, format::variables&& args);
			server_response mempoolstate_simulate_transaction(http::connection* base, format::variables&& args);
			server_response mempoolstate_submit_transaction(http::connection* base, format::variables&& args, ledger::transaction* prebuilt);
			server_response mempoolstate_reject_transaction(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_transaction_by_hash(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_raw_transaction_by_hash(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_next_account_nonce(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_transactions(http::connection* base, format::variables&& args);
			server_response mempoolstate_get_transactions_by_owner(http::connection* base, format::variables&& args);
			server_response validatorstate_prune(http::connection* base, format::variables&& args);
			server_response validatorstate_revert(http::connection* base, format::variables&& args);
			server_response validatorstate_reorganize(http::connection* base, format::variables&& args);
			server_response validatorstate_verify(http::connection* base, format::variables&& args);
			server_response validatorstate_accept_node(http::connection* base, format::variables&& args);
			server_response validatorstate_reject_node(http::connection* base, format::variables&& args);
			server_response validatorstate_get_node(http::connection* base, format::variables&& args);
			server_response validatorstate_get_blockchains(http::connection* base, format::variables&& args);
			server_response validatorstate_get_participations(http::connection* base, format::variables&& args);
			server_response validatorstate_get_wallet(http::connection* base, format::variables&& args);
			server_response validatorstate_set_wallet(http::connection* base, format::variables&& args);
			server_response validatorstate_status(http::connection* base, format::variables&& args);
			server_response validatorstate_submit_block(http::connection* base, format::variables&& args);
		};
	}
}
#endif