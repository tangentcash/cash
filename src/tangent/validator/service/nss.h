#ifndef TAN_LAYER_NSS_H
#define TAN_LAYER_NSS_H
#include "../../kernel/mediator.h"

namespace tangent
{
	namespace nss
	{
		typedef std::function<bool(const std::string_view&)> invocation_callback;
		typedef std::function<promise<void>(const algorithm::asset_id&, const mediator::chain_supervisor_options&, mediator::transaction_logs&&)> transaction_callback;

		struct transaction_listener
		{
			algorithm::asset_id asset = 0;
			mediator::chain_supervisor_options options;
			task_id cooldown_id = INVALID_TASK_ID;
			bool is_dry_run = true;
			bool is_dead = false;
		};

		struct computed_wallet
		{
			uint256_t seed = 0;
			algorithm::composition::cseckey secret_key = { 0 };
			algorithm::composition::cpubkey public_key = { 0 };
			address_map addresses;
			address_map encoded_addresses;
			secret_box encoded_seed;
			secret_box encoded_secret_key;
			string encoded_public_key;
			size_t secret_key_size = 0;
			size_t public_key_size = 0;

			uptr<schema> as_schema() const;
		};

		class server_node : public singleton<server_node>
		{
		protected:
			unordered_set<string> connections;
			unordered_map<string, invocation_callback> registrations;
			unordered_map<string, transaction_callback> callbacks;
			unordered_map<string, std::pair<mediator::computed_fee, int64_t>> fees;
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
			expects_promise_rt<schema*> execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, mediator::cache_policy cache);
			expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset);
			expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash);
			expects_promise_rt<mediator::transaction_logs> link_transactions(const algorithm::asset_id& asset, mediator::chain_supervisor_options* options);
			expects_promise_rt<mediator::computed_transaction> link_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data);
			expects_promise_rt<mediator::computed_fee> estimate_fee(const algorithm::asset_id& asset, const std::string_view& from_address, const vector<mediator::value_transfer>& to, const mediator::fee_supervisor_options& options = mediator::fee_supervisor_options());
			expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const mediator::wallet_link& link);
			expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const mediator::finalized_transaction& finalized);
			expects_promise_rt<mediator::prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const mediator::wallet_link& from_link, const vector<mediator::value_transfer>& to, option<mediator::computed_fee>&& fee = optional::none);
			expects_lr<mediator::finalized_transaction> finalize_transaction(const algorithm::asset_id& asset, mediator::prepared_transaction&& prepared);
			expects_lr<computed_wallet> compute_wallet(const algorithm::asset_id& asset, const uint256_t& seed);
			expects_lr<secret_box> encode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key);
			expects_lr<secret_box> decode_secret_key(const algorithm::asset_id& asset, const secret_box& secret_key);
			expects_lr<string> encode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key);
			expects_lr<string> decode_public_key(const algorithm::asset_id& asset, const std::string_view& public_key);
			expects_lr<string> encode_address(const algorithm::asset_id& asset, const std::string_view& public_key_hash);
			expects_lr<string> decode_address(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<string> encode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id);
			expects_lr<string> decode_transaction_id(const algorithm::asset_id& asset, const std::string_view& transaction_id);
			expects_lr<void> normalize_secret_key(const algorithm::asset_id& asset, secret_box* secret_key);
			expects_lr<void> normalize_public_key(const algorithm::asset_id& asset, string* public_key);
			expects_lr<void> normalize_address(const algorithm::asset_id& asset, string* address);
			expects_lr<void> normalize_transaction_id(const algorithm::asset_id& asset, string* transaction_id);
			expects_lr<algorithm::composition::cpubkey_t> to_composite_public_key(const algorithm::asset_id& asset, const std::string_view& public_key);
			expects_lr<address_map> to_addresses(const algorithm::asset_id& asset, const std::string_view& public_key);
			expects_lr<void> scan_from_block_height(const algorithm::asset_id& asset, uint64_t block_height);
			expects_lr<void> enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address);
			expects_lr<void> enable_link(const algorithm::asset_id& asset, const mediator::wallet_link& link);
			expects_lr<void> disable_link(const algorithm::asset_id& asset, const mediator::wallet_link& link);
			expects_lr<mediator::wallet_link> normalize_link(const algorithm::asset_id& asset, const mediator::wallet_link& link);
			expects_lr<uint64_t> get_latest_known_block_height(const algorithm::asset_id& asset);
			expects_lr<mediator::wallet_link> get_link(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_public_keys(const algorithm::asset_id& asset, const unordered_set<string>& public_keys);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_addresses(const algorithm::asset_id& asset, const unordered_set<string>& addresses);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_owner(const algorithm::asset_id& asset, const algorithm::pubkeyhash owner, size_t offset, size_t count);
			expects_lr<void> add_utxo(const algorithm::asset_id& asset, const mediator::coin_utxo& value);
			expects_lr<void> remove_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index);
			expects_lr<mediator::coin_utxo> get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<mediator::coin_utxo>> get_utxos(const algorithm::asset_id& asset, const mediator::wallet_link& link, size_t offset, size_t count);
			expects_lr<schema*> load_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key);
			expects_lr<void> store_cache(const algorithm::asset_id& asset, mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			option<string> get_contract_address(const algorithm::asset_id& asset);
			unordered_map<algorithm::asset_id, mediator::relay_backend::chainparams> get_chains();
			unordered_map<string, invocation_callback>& get_registrations();
			vector<algorithm::asset_id> get_assets(bool observing_only = false);
			vector<uptr<mediator::server_relay>>* get_nodes(const algorithm::asset_id& asset);
			const mediator::relay_backend::chainparams* get_chainparams(const algorithm::asset_id& asset);
			mediator::server_relay* add_node(const algorithm::asset_id& asset, const std::string_view& url, double rps);
			mediator::server_relay* add_multi_node(const algorithm::asset_id& asset, unordered_map<string, string>&& urls, double rps);
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
				t* instance = new t(asset, values...);
				add_chain_instance(asset, instance);
				return instance;
			}

		private:
			void add_node_instance(const algorithm::asset_id& asset, mediator::server_relay* instance);
			void add_chain_instance(const algorithm::asset_id& asset, mediator::relay_backend* instance);
			bool call_transaction_listener(transaction_listener* listener);
		};
	}
}
#endif