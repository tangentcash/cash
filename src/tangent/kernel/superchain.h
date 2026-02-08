#ifndef TAN_KERNEL_SUPERCHAIN_H
#define TAN_KERNEL_SUPERCHAIN_H
#include "control.h"
#include "../policy/messages.h"
#include <vitex/network/http.h>

namespace tangent
{
	namespace superchain
	{
		enum
		{
			KEY_LIMIT = 1024
		};

		enum class routing_policy
		{
			account,
			memo,
			utxo
		};

		enum class token_policy
		{
			none,
			native,
			program
		};

		enum class cache_policy
		{
			no_cache,
			no_cache_no_throttling,
			temporary_cache,
			blob_cache,
			lifetime_cache
		};

		struct network_options;

		class translation_unit;

		struct wallet_link : messages::uniform
		{
			enum class search_term
			{
				none,
				hash,
				public_key,
				address
			};

			uint256_t hash;
			string public_key;
			string address;

			wallet_link() = default;
			wallet_link(const uint256_t& new_hash, const std::string_view& new_public_key, const std::string_view& new_address);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			search_term as_search_wide() const;
			search_term as_search_narrow() const;
			string as_tag_address(const std::string_view& tag = "0") const;
			string as_name() const;
			bool has_hash() const;
			bool has_public_key() const;
			bool has_address() const;
			bool has_all() const;
			bool has_any() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static wallet_link from_hash(const uint256_t& new_hash);
			static wallet_link from_public_key(const std::string_view& new_public_key);
			static wallet_link from_address(const std::string_view& new_address);
		};

		struct value_transfer
		{
			algorithm::asset_id asset;
			string address;
			decimal value;

			value_transfer();
			value_transfer(const algorithm::asset_id& new_asset, const std::string_view& new_address, decimal&& new_value);
			value_transfer(const value_transfer&) = default;
			value_transfer(value_transfer&&) noexcept = default;
			value_transfer& operator=(const value_transfer&) = default;
			value_transfer& operator=(value_transfer&&) noexcept = default;
			bool is_valid() const;
		};

		struct coin_utxo : messages::uniform
		{
			struct token_utxo
			{
				string contract_address;
				string symbol;
				decimal value;
				uint8_t decimals;

				token_utxo();
				token_utxo(const algorithm::asset_id& new_asset, const decimal& new_value);
				token_utxo(const std::string_view& new_contract_address, const std::string_view& new_symbol, const decimal& new_value, uint8_t new_decimals);
				decimal get_divisibility() const;
				algorithm::asset_id get_asset(const algorithm::asset_id& base_asset) const;
				bool is_account() const;
				bool is_valid() const;
				uint256_t as_hash() const;
			};

			btree_map<uint256_t, token_utxo> tokens;
			wallet_link link;
			string transaction_id;
			decimal value;
			uint64_t index = 0;

			coin_utxo() = default;
			coin_utxo(wallet_link&& new_link, hash_map<algorithm::asset_id, decimal>&& new_values);
			coin_utxo(wallet_link&& new_link, const std::string_view& new_transaction_id, uint64_t new_index, decimal&& new_value);
			void apply_token_value(const std::string_view& contract_address, const std::string_view& symbol, const decimal& value, uint8_t decimals);
			option<decimal> get_token_value(const std::string_view& contract_address);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_account() const;
			bool is_valid_input() const;
			bool is_valid_output() const;
			algorithm::asset_id get_asset(const algorithm::asset_id& base_asset) const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct computed_transaction : messages::uniform
		{
			btree_map<uint256_t, coin_utxo> inputs;
			btree_map<uint256_t, coin_utxo> outputs;
			string transaction_id;
			uint64_t block_id = 0;

			computed_transaction() = default;
			void add_input(coin_utxo&& input);
			void add_output(coin_utxo&& output);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_valid() const;
			uint256_t as_attestation_hash() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct prepared_transaction : messages::uniform
		{
			enum class status
			{
				invalid,
				signable,
				finalizeable
			};

			struct signable_coin_utxo
			{
				algorithm::composition::cpubkey_t public_key;
				algorithm::composition::chashsig_t signature;
				algorithm::composition::type alg = algorithm::composition::type::unknown;
				vector<uint8_t> message;
				coin_utxo utxo;
			};

			vector<signable_coin_utxo> inputs;
			vector<coin_utxo> outputs;
			format::variables abi;

			prepared_transaction() = default;
			prepared_transaction& requires_input(algorithm::composition::type new_alg, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, coin_utxo&& input);
			prepared_transaction& requires_account_input(algorithm::composition::type new_alg, wallet_link&& new_link, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, hash_map<algorithm::asset_id, decimal>&& input);
			prepared_transaction& requires_output(coin_utxo&& output);
			prepared_transaction& requires_account_output(const std::string_view& to_address, hash_map<algorithm::asset_id, decimal>&& output);
			prepared_transaction& requires_abi(format::variable&& value);
			format::variable* load_abi(size_t* ptr);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			signable_coin_utxo* next_input_for_aggregation();
			status as_status() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct finalized_transaction : messages::uniform
		{
			prepared_transaction prepared;
			string calldata;
			string hashdata;
			uint64_t locktime = 0;

			finalized_transaction() = default;
			finalized_transaction(prepared_transaction&& new_prepared, string&& new_calldata, string&& new_hashdata, uint64_t new_locktime = 0);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_valid() const;
			computed_transaction as_computed() const;
			format::tree as_tree() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct block_log
		{
			string block_hash;
			format::tree transactions;
		};

		struct transaction_logs
		{
			vector<computed_transaction> receipts;
			uint64_t block_height = (uint64_t)-1;
			string block_hash;

			void report_logs(const algorithm::asset_id& asset, const network_options& options, size_t requests);
		};

		struct computed_fee
		{
			enum class fee_type
			{
				fee,
				gas
			};
			struct
			{
				decimal fee_rate = 0.0;
				size_t byte_rate = 0;
			} fee;
			struct
			{
				decimal gas_premium = 0.0;
				decimal gas_price = 0.0;
				uint256_t gas_limit = 0;
			} gas;
			fee_type type;

			decimal get_max_fee() const;
			bool is_flat_fee() const;
			bool is_valid() const;
			static computed_fee flat_fee(const decimal& fee);
			static computed_fee fee_per_byte(const decimal& rate, size_t bytes);
			static computed_fee fee_per_kilobyte(const decimal& rate);
			static computed_fee fee_per_gas(const decimal& price, const uint256_t& limit);
			static computed_fee fee_per_gas_priority(const decimal& premium, const decimal& price, const uint256_t& limit);
		};

		struct computed_wallet
		{
			algorithm::composition::cseckey_t secret_key;
			algorithm::composition::cpubkey_t public_key;
			vector<uint8_t> seed;
			address_map addresses;
			address_map encoded_addresses;
			secret_box encoded_seed;
			secret_box encoded_secret_key;
			string encoded_public_key;

			format::tree as_tree() const;
		};

		struct network_options
		{
			struct
			{
				uint64_t inital_block_height = 0;
				uint64_t index_block_height = 0;
				uint64_t target_block_height = 0;
				uint64_t retry_after_time = 0;
			} state;
			uint64_t blocks_batching = 1;

			void set_checkpoint_from_block(uint64_t block_height);
			void set_checkpoint_to_block(uint64_t block_height);
			uint64_t get_next_block_height(uint64_t block_count);
			bool has_next_block_height(uint64_t block_count) const;
			bool has_target_block_height() const;
			double get_checkpoint_percentage() const;
		};

		struct connection_instance
		{
			struct
			{
				uint64_t rps_retry_after_timestamp = 0;
				uint64_t error_retry_after_timestamp = 0;
			} state;
			string connection_url;
			btree_map<string, string> headers;
			double rps = 0.0;
		};

		struct network_instance
		{
			vector<connection_instance> connections;
			uptr<translation_unit> translation;
			network_options options;
			algorithm::asset_id asset;
			format::tree props;
		};

		class address_util
		{
		public:
			static string encode_tag_address(const std::string_view& address, const std::string_view& destination_tag);
			static std::pair<string, string> decode_tag_address(const std::string_view& address_destination_tag);
		};

		class translation_unit : public reference<translation_unit>
		{
			friend class datamaster;

		public:
			typedef std::pair<string, string> contract_address_symbol_pair;

		public:
			struct chainparams
			{
				algorithm::composition::type composition;
				routing_policy routing;
				token_policy tokenization;
				uint64_t sync_latency;
				decimal divisibility;
				bool transaction_expires;
			};

		protected:
			algorithm::asset_id native_asset;
			std::atomic<uint64_t> round_robin_index;
			bool allow_any_token;

		public:
			translation_unit(const algorithm::asset_id& new_asset) noexcept;
			virtual ~translation_unit() noexcept;
			virtual expects_promise_rt<format::tree> execute_rpc(const std::string_view& method, format::tree&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<format::tree> execute_rpc_multi(const std::string_view& method, format::tree&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<format::tree> execute_rest(const std::string_view& method, const std::string_view& path, format::tree&& args, cache_policy cache);
			virtual expects_promise_rt<format::tree> execute_http(const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache);
			virtual expects_promise_rt<uint64_t> get_linked_block_height(uint64_t seen_block_height);
			virtual expects_promise_rt<uint64_t> get_latest_block_height() = 0;
			virtual expects_promise_rt<vector<block_log>> get_block_transactions(uint64_t block_height, uint64_t block_count) = 0;
			virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) = 0;
			virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) = 0;
			virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee) = 0;
			virtual expects_lr<finalized_transaction> finalize_transaction(prepared_transaction&& prepared) = 0;
			virtual expects_lr<secret_box> encode_secret_key(const secret_box& secret_key) = 0;
			virtual expects_lr<secret_box> decode_secret_key(const secret_box& secret_key) = 0;
			virtual expects_lr<string> encode_public_key(const std::string_view& public_key) = 0;
			virtual expects_lr<string> decode_public_key(const std::string_view& public_key) = 0;
			virtual expects_lr<string> encode_address(const std::string_view& public_key_hash) = 0;
			virtual expects_lr<string> decode_address(const std::string_view& address) = 0;
			virtual expects_lr<string> encode_transaction_id(const std::string_view& transaction_id) = 0;
			virtual expects_lr<string> decode_transaction_id(const std::string_view& transaction_id) = 0;
			virtual expects_lr<algorithm::composition::cpubkey_t> to_composite_public_key(const std::string_view& public_key);
			virtual expects_lr<address_map> to_addresses(const std::string_view& public_key) = 0;
			virtual expects_lr<btree_map<string, wallet_link>> find_linked_addresses(const hash_set<string>& addresses);
			virtual expects_lr<btree_map<string, wallet_link>> find_linked_addresses(const uint256_t& hash, size_t offset, size_t count);
			virtual expects_lr<btree_map<string, wallet_link>> find_linked_addresses(size_t offset, size_t count);
			virtual decimal to_value(const decimal& value) const;
			virtual uint256_t to_baseline_value(const decimal& value) const;
			virtual decimal from_baseline_value(const uint256_t& value) const;
			virtual const chainparams& get_chainparams() const = 0;
		};

		class utxo_translation_unit : public translation_unit
		{
		public:
			struct balance_query
			{
				hash_map<algorithm::asset_id, decimal> min_token_values;
				decimal min_native_value;

				balance_query(const decimal& new_min_native_value, const hash_map<algorithm::asset_id, decimal>& new_min_token_values);
			};

		public:
			utxo_translation_unit(const algorithm::asset_id& new_asset) noexcept;
			virtual ~utxo_translation_unit() = default;
			virtual expects_promise_rt<coin_utxo> get_transaction_output(const std::string_view& transaction_id, uint64_t index) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
			virtual expects_lr<vector<coin_utxo>> calculate_utxo(const wallet_link& link, option<balance_query>&& query);
			virtual expects_lr<coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			virtual expects_lr<void> update_utxo(const computed_transaction& computed);
			virtual expects_lr<void> receive_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t receiver_block_id, const coin_utxo& output);
			virtual expects_lr<void> spend_utxo(const std::string_view& transaction_id, uint64_t index, uint64_t spender_block_id);
			virtual decimal get_utxo_value(const vector<coin_utxo>& values, option<string>&& contract_address);

		public:
			static utxo_translation_unit* from(translation_unit* base);
		};

		class bridge : public singleton<bridge>
		{
		public:
			struct error_reporter
			{
				string type;
				string method;
			};

			typedef std::function<expects_promise_system<http::response_frame>(const algorithm::asset_id&, const std::string_view&, const std::string_view&, const http::fetch_frame&)> fetch_callback;
			typedef std::function<expects_promise_system<void>(const algorithm::asset_id&, const std::string_view&, const http::ws_fetch_frame&)> ws_fetch_callback;
			typedef std::function<bool(const std::string_view&)> invocation_callback;

		protected:
			hash_map<string, invocation_callback> registrations;
			hash_map<string, network_instance> networks;

		public:
			fetch_callback network_fetch;
			ws_fetch_callback network_ws_fetch;
			activity_callback network_active;

		public:
			bridge() noexcept;
			~bridge() noexcept;
			expects_promise_rt<format::tree> execute_rpc(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const format::tree& args, cache_policy cache, const std::string_view& path, bool multi);
			expects_promise_rt<format::tree> execute_rest(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const format::tree& args, cache_policy cache);
			expects_promise_rt<format::tree> execute_http(const algorithm::asset_id& asset, connection_instance& connection, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache);
			expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset);
			expects_promise_rt<vector<block_log>> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, uint64_t block_count);
			expects_promise_rt<vector<transaction_logs>> link_transactions(const algorithm::asset_id& asset);
			expects_promise_rt<computed_transaction> link_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data);
			expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const wallet_link& link);
			expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, const finalized_transaction& finalized);
			expects_promise_rt<prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const wallet_link& from_link, const value_transfer& to, const decimal& max_fee);
			expects_lr<finalized_transaction> finalize_transaction(const algorithm::asset_id& asset, prepared_transaction&& prepared);
			expects_lr<computed_transaction> get_computed_transaction(const algorithm::asset_id& asset, const std::string_view& transaction_id, const uint256_t& external_id, const uint256_t& optimized_id);
			expects_lr<computed_wallet> compute_wallet(const algorithm::asset_id& asset, const uint8_t* seed, size_t seed_size);
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
			expects_lr<void> scan_from_block_height(const algorithm::asset_id& asset, option<uint64_t>&& block_height);
			expects_lr<void> enable_contract_address(const algorithm::asset_id& asset, const std::string_view& contract_address);
			expects_lr<void> enable_link(const algorithm::asset_id& asset, const wallet_link& link);
			expects_lr<void> disable_link(const algorithm::asset_id& asset, const wallet_link& link);
			expects_lr<wallet_link> normalize_link(const algorithm::asset_id& asset, const wallet_link& link);
			expects_lr<uint64_t> get_earliest_scanned_block_height(const algorithm::asset_id& asset);
			expects_lr<uint64_t> get_latest_known_block_height(const algorithm::asset_id& asset);
			expects_lr<wallet_link> get_link(const algorithm::asset_id& asset, const std::string_view& address);
			expects_lr<hash_map<string, wallet_link>> get_links_by_public_keys(const algorithm::asset_id& asset, const hash_set<string>& public_keys);
			expects_lr<hash_map<string, wallet_link>> get_links_by_addresses(const algorithm::asset_id& asset, const hash_set<string>& addresses);
			expects_lr<hash_map<string, wallet_link>> get_links_by_hash(const algorithm::asset_id& asset, const uint256_t& hash, size_t offset, size_t count);
			expects_lr<hash_map<string, wallet_link>> get_links_with_hash(const algorithm::asset_id& asset, size_t offset, size_t count);
			expects_lr<void> receive_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index, uint64_t block_id, const coin_utxo& value);
			expects_lr<void> spend_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index, uint64_t block_id);
			expects_lr<void> revive_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index);
			expects_lr<void> revive_utxo_tree(const algorithm::asset_id& asset, const computed_transaction& computed);
			expects_lr<void> update_utxo_tree(const algorithm::asset_id& asset, const computed_transaction& computed);
			expects_lr<coin_utxo> get_utxo(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<coin_utxo>> get_utxos(const algorithm::asset_id& asset, const wallet_link& link, size_t offset, size_t count);
			expects_lr<format::tree> load_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key);
			expects_lr<void> store_cache(const algorithm::asset_id& asset, cache_policy policy, const std::string_view& key, const format::tree& value);
			option<string> get_contract_address(const algorithm::asset_id& asset);
			vector<algorithm::asset_id> get_assets(bool observing_only = false);
			hash_map<algorithm::asset_id, translation_unit::chainparams> get_assets_with_params();
			const hash_map<string, invocation_callback>& get_registrations();
			hash_map<string, network_instance>& get_networks();
			translation_unit* get_network(const algorithm::asset_id& asset);
			network_instance* get_network_instance(const algorithm::asset_id& asset);
			const translation_unit::chainparams* get_network_params(const algorithm::asset_id& asset);
			connection_instance* add_network_connection(const algorithm::asset_id& asset, const std::string_view& url, btree_map<string, string>&& headers, double rps);
			format::tree* add_network_props(const algorithm::asset_id& asset, const format::tree& value);
			format::tree* get_network_props(const algorithm::asset_id& asset);
			void remove_network(const algorithm::asset_id& asset);
			bool has_network(const algorithm::asset_id& asset, bool and_connections = false);

		public:
			template <typename t, typename... args>
			t* add_network(const algorithm::asset_id& asset, args&&... values)
			{
				t* instance = new t(asset, values...);
				add_network_instance(asset, instance);
				return instance;
			}

		private:
			void add_network_instance(const algorithm::asset_id& asset, translation_unit* instance);

		public:
			static std::string_view cache_type_of(cache_policy cache);
		};
	}
}
#endif