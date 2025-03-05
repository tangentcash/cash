#ifndef TAN_LAYER_NSS_H
#define TAN_LAYER_NSS_H
#include "../../kernel/mediator.h"

namespace tangent
{
	namespace nss
	{
		typedef std::function<bool(const std::string_view&)> invocation_callback;
		typedef std::function<promise<void>(const mediator::chain_supervisor_options&, mediator::transaction_logs&&)> transaction_callback;

		struct transaction_listener
		{
			algorithm::asset_id asset = 0;
			mediator::chain_supervisor_options options;
			task_id cooldown_id = INVALID_TASK_ID;
			bool is_dry_run = true;
			bool is_dead = false;
		};

		struct transaction_params
		{
			vector<mediator::transferer> to;
			option<mediator::base_fee> fee = optional::none;
			uint256_t external_id = 0;
			algorithm::asset_id asset = 0;
			mediator::dynamic_wallet wallet = mediator::dynamic_wallet();
			expects_promise_rt<mediator::outgoing_transaction> future;
		};

		struct transaction_queue_state
		{
			single_queue<transaction_params*> queue;
			string blockchain;
			size_t transactions = 0;
			bool is_busy = false;
		};

		class server_node : public singleton<server_node>
		{
		protected:
			unordered_set<string> connections;
			unordered_map<string, invocation_callback> registrations;
			unordered_map<string, uptr<transaction_queue_state>> states;
			unordered_map<string, transaction_callback> callbacks;
			unordered_map<string, std::pair<mediator::base_fee, int64_t>> fees;
			unordered_map<string, vector<uptr<mediator::server_relay>>> nodes;
			unordered_map<string, uptr<mediator::relay_backend>> chains;
			unordered_map<string, uptr<schema>> specifications;
			vector<uptr<transaction_listener>> listeners;
			mediator::multichain_supervisor_options options;
			system_control control_sys;

		public:
			server_node() noexcept;
			~server_node() noexcept;
			expects_promise_system<http::response_frame> internal_call(const std::string_view& location, const std::string_view& method, const http::fetch_frame& options);
			expects_promise_rt<mediator::outgoing_transaction> submit_transaction(const uint256_t& external_id, const algorithm::asset_id& asset, mediator::dynamic_wallet&& wallet, vector<mediator::transferer>&& to, option<mediator::base_fee>&& fee = optional::none);
			expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const mediator::outgoing_transaction& tx_data);
			expects_promise_rt<void> validate_transaction(const mediator::incoming_transaction& value);
			expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset);
			expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash);
			expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id);
			expects_promise_rt<vector<mediator::incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data);
			expects_promise_rt<schema*> execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, mediator::cache_policy cache);
			expects_promise_rt<mediator::outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, const vector<mediator::transferer>& to, option<mediator::base_fee>&& fee = optional::none);
			expects_promise_rt<mediator::transaction_logs> get_transaction_logs(const algorithm::asset_id& asset, mediator::chain_supervisor_options* options);
			expects_promise_rt<mediator::base_fee> estimate_fee(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, const vector<mediator::transferer>& to, const mediator::fee_supervisor_options& options = mediator::fee_supervisor_options());
			expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const mediator::dynamic_wallet& wallet, option<string>&& address = optional::none);
			expects_lr<mediator::master_wallet> new_master_wallet(const algorithm::asset_id& asset, const std::string_view& seed);
			expects_lr<mediator::master_wallet> new_master_wallet(const algorithm::asset_id& asset, const algorithm::seckey private_key);
			expects_lr<mediator::derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const mediator::master_wallet& wallet, option<uint64_t>&& address_index = optional::none);
			expects_lr<mediator::derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key);
			expects_lr<mediator::derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key);
			expects_lr<string> new_public_key_hash(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key);
			expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature);
			expects_lr<void> enable_signing_wallet(const algorithm::asset_id& asset, const mediator::master_wallet& wallet, const mediator::derived_signing_wallet& signing_wallet);
			expects_lr<void> enable_checkpoint_height(const algorithm::asset_id& asset, uint64_t block_height);
			expects_lr<void> enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address);
			expects_lr<void> enable_wallet_address(const algorithm::asset_id& asset, const std::string_view& binding, const std::string_view& address, uint64_t address_index);
			expects_lr<void> disable_wallet_address(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<uint64_t> get_latest_known_block_height(const algorithm::asset_id& asset);
			expects_lr<mediator::index_address> get_address_index(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<unordered_map<string, mediator::index_address>> get_address_indices(const algorithm::asset_id& asset, const unordered_set<string>& addresses);
			expects_lr<vector<string>> get_address_indices(const algorithm::asset_id& asset);
			expects_lr<void> add_utxo(const algorithm::asset_id& asset, const mediator::index_utxo& value);
			expects_lr<void> remove_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index);
			expects_lr<mediator::index_utxo> get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index);
			expects_lr<vector<mediator::index_utxo>> get_utxos(const algorithm::asset_id& asset, const std::string_view& binding, size_t offset, size_t count);
			expects_lr<schema*> load_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key);
			expects_lr<void> store_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			option<string> get_contract_address(const algorithm::asset_id& asset);
			unordered_map<algorithm::asset_id, mediator::relay_backend::chainparams> get_chains();
			unordered_map<string, mediator::master_wallet> get_wallets(const algorithm::seckey private_key);
			unordered_map<string, invocation_callback>& get_registrations();
			vector<algorithm::asset_id> get_assets(bool observing_only = false);
			vector<uptr<mediator::server_relay>>* get_nodes(const algorithm::asset_id& asset);
			const mediator::relay_backend::chainparams* get_chainparams(const algorithm::asset_id& asset);
			mediator::server_relay* add_node(const algorithm::asset_id& asset, const std::string_view& URL, double throttling);
			mediator::server_relay* get_node(const algorithm::asset_id& asset);
			mediator::relay_backend* get_chain(const algorithm::asset_id& asset);
			schema* get_specifications(const algorithm::asset_id& asset);
			schema* add_specifications(const algorithm::asset_id& asset, uptr<schema>&& value);
			service_control::service_node get_entrypoint();
			mediator::multichain_supervisor_options& get_options();
			system_control& get_control();
			void add_transaction_callback(const std::string_view& name, transaction_callback&& callback);
			void startup();
			void shutdown();
			bool has_chain(const algorithm::asset_id& asset);
			bool has_node(const algorithm::asset_id& asset);
			bool has_observer(const algorithm::asset_id& asset);
			bool has_support(const algorithm::asset_id& asset);
			bool is_active();

		public:
			template <typename t, typename... args>
			t* add_chain(const algorithm::asset_id& asset, args&&... values)
			{
				t* instance = new t(values...);
				add_chain_instance(asset, instance);
				return instance;
			}

		private:
			void add_node_instance(const algorithm::asset_id& asset, mediator::server_relay* instance);
			void add_chain_instance(const algorithm::asset_id& asset, mediator::relay_backend* instance);
			void dispatch_transaction_queue(transaction_queue_state* state, transaction_params* from_params);
			void finalize_transaction(transaction_queue_state* state, uptr<transaction_params>&& params, expects_rt<mediator::outgoing_transaction>&& transaction);
			bool call_transaction_listener(transaction_listener* listener);
		};
	}
}
#endif