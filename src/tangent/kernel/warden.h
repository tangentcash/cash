#ifndef TAN_WARDEN_H
#define TAN_WARDEN_H
#include "../policy/messages.h"
#include "../layer/control.h"

namespace tangent
{
	namespace warden
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

		class server_relay;

		class relay_backend;

		struct wallet_link : messages::uniform
		{
			enum class search_term
			{
				none,
				owner,
				public_key,
				address
			};

			algorithm::pubkeyhash_t owner;
			string public_key;
			string address;

			wallet_link() = default;
			wallet_link(const algorithm::pubkeyhash_t& new_owner, const std::string_view& new_public_key, const std::string_view& new_address);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			search_term as_search_wide() const;
			search_term as_search_narrow() const;
			string as_tag_address(const std::string_view& tag = "0") const;
			string as_name() const;
			bool has_owner() const;
			bool has_public_key() const;
			bool has_address() const;
			bool has_all() const;
			bool has_any() const;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static wallet_link from_owner(const algorithm::pubkeyhash_t& new_owner);
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
			};

			vector<token_utxo> tokens;
			wallet_link link;
			string transaction_id;
			decimal value;
			uint64_t index = 0;

			coin_utxo() = default;
			coin_utxo(wallet_link&& new_link, unordered_map<algorithm::asset_id, decimal>&& new_values);
			coin_utxo(wallet_link&& new_link, const std::string_view& new_transaction_id, uint64_t new_index, decimal&& new_value);
			void apply_token_value(const std::string_view& contract_address, const std::string_view& symbol, const decimal& value, uint8_t decimals);
			option<decimal> get_token_value(const std::string_view& contract_address);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_account() const;
			bool is_valid_input() const;
			bool is_valid_output() const;
			algorithm::asset_id get_asset(const algorithm::asset_id& base_asset) const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct computed_transaction : messages::uniform
		{
			vector<coin_utxo> inputs;
			vector<coin_utxo> outputs;
			string transaction_id;
			uint64_t block_id;

			computed_transaction() = default;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool is_valid() const;
			uptr<schema> as_schema() const override;
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
				requires_signature,
				requires_finalization
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
			prepared_transaction& requires_account_input(algorithm::composition::type new_alg, wallet_link&& new_link, const algorithm::composition::cpubkey_t& new_public_key, uint8_t* new_message, size_t new_message_size, unordered_map<algorithm::asset_id, decimal>&& input);
			prepared_transaction& requires_output(coin_utxo&& output);
			prepared_transaction& requires_account_output(const std::string_view& to_address, unordered_map<algorithm::asset_id, decimal>&& output);
			prepared_transaction& requires_abi(format::variable&& value);
			format::variable* load_abi(size_t* ptr);
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			signable_coin_utxo* next_input_for_aggregation();
			status as_status() const;
			uptr<schema> as_schema() const override;
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
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct transaction_logs
		{
			vector<computed_transaction> pending;
			vector<computed_transaction> finalized;
			uint64_t block_height = (uint64_t)-1;
			string block_hash;
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
				decimal gas_base_price = 0.0;
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
			static computed_fee fee_per_gas_priority(const decimal& base_price, const decimal& price, const uint256_t& limit);
		};

		struct supervisor_options
		{
			uint64_t polling_frequency_ms = 70000;
			uint64_t min_block_confirmations = 0;
		};

		struct chain_supervisor_options : supervisor_options
		{
			struct
			{
				unordered_set<server_relay*> interactions;
				uint64_t current_block_height = 0;
				uint64_t latest_block_height = 0;
				uint64_t starting_block_height = 0;
				uint64_t latest_time_awaited = 0;
			} state;

			void set_checkpoint_from_block(uint64_t block_height);
			void set_checkpoint_to_block(uint64_t block_height);
			uint64_t get_next_block_height();
			uint64_t get_time_awaited() const;
			bool has_next_block_height() const;
			bool has_current_block_height() const;
			bool has_latest_block_height() const;
			bool will_wait_for_transactions() const;
			double get_checkpoint_percentage() const;
			const unordered_set<server_relay*>& get_interacted_nodes() const;
			bool is_cancelled(const algorithm::asset_id& asset);
		};

		struct multichain_supervisor_options : supervisor_options
		{
			unordered_map<string, chain_supervisor_options> specifics;
			uint64_t retry_waiting_time_ms = 30000;

			chain_supervisor_options& add_specific_options(const std::string_view& blockchain);
		};

		struct fee_supervisor_options
		{
			uint64_t block_height_offset = 1;
			uint64_t max_blocks = 10;
			uint64_t max_transactions = 32;
		};

		class server_relay : public reference<server_relay>
		{
		public:
			struct error_reporter
			{
				string type;
				string method;
			};

		private:
			vector<std::pair<promise<bool>, task_id>> tasks;
			unordered_map<string, string> urls;
			std::recursive_mutex mutex;
			int64_t latest;
			double rps;
			bool allowed;

		public:
			void* user_data;

		public:
			server_relay(unordered_map<string, string>&& node_urls, double node_rps) noexcept;
			~server_relay() noexcept;
			expects_promise_rt<schema*> execute_rpc(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const schema_list& args, cache_policy cache, const std::string_view& path);
			expects_promise_rt<schema*> execute_rpc3(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const schema_args& args, cache_policy cache, const std::string_view& path);
			expects_promise_rt<schema*> execute_rest(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache);
			expects_promise_rt<schema*> execute_http(const algorithm::asset_id& asset, error_reporter& reporter, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache);
			promise<bool> yield_for_cooldown(uint64_t& retry_timeout, uint64_t total_timeout_ms);
			promise<bool> yield_for_discovery(chain_supervisor_options* options);
			expects_lr<void> verify_compatibility(const algorithm::asset_id& asset);
			task_id enqueue_activity(const promise<bool>& future, task_id timer_id);
			void dequeue_activity(task_id timer_id);
			void allow_activities();
			void cancel_activities();
			bool has_distinct_url(const std::string_view& type) const;
			bool is_activity_allowed() const;
			const string& get_node_url(const std::string_view& type) const;
			string get_node_url(const std::string_view& type, const std::string_view& path) const;

		public:
			static std::string_view get_cache_type(cache_policy cache);

		private:
			static string generate_error_message(const expects_system<http::response_frame>& response, const error_reporter& reporter, const std::string_view& error_code, const std::string_view& error_message);
		};

		class relay_backend : public reference<relay_backend>
		{
			friend class datamaster;

		public:
			typedef std::function<void(server_relay*)> interaction_callback;
			typedef std::pair<string, string> contract_address_symbol_pair;

		public:
			struct chainparams
			{
				algorithm::composition::type composition;
				routing_policy routing;
				token_policy tokenization;
				uint64_t sync_latency;
				decimal divisibility;
				bool supports_bulk_transfer;
				bool requires_transaction_expiration;
			};

		protected:
			algorithm::asset_id native_asset;
			bool allow_any_token;

		public:
			interaction_callback interact;

		public:
			relay_backend(const algorithm::asset_id& new_asset) noexcept;
			virtual ~relay_backend() noexcept;
			virtual expects_promise_rt<schema*> execute_rpc(const std::string_view& method, schema_list&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<schema*> execute_rpc3(const std::string_view& method, schema_args&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<schema*> execute_rest(const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache);
			virtual expects_promise_rt<schema*> execute_http(const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache);
			virtual expects_promise_rt<uint64_t> get_latest_block_height() = 0;
			virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) = 0;
			virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) = 0;
			virtual expects_promise_rt<computed_fee> estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) = 0;
			virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) = 0;
			virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee) = 0;
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
			virtual expects_lr<ordered_map<string, wallet_link>> find_linked_addresses(const unordered_set<string>& addresses);
			virtual expects_lr<ordered_map<string, wallet_link>> find_linked_addresses(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count);
			virtual expects_lr<void> verify_node_compatibility(server_relay* node);
			virtual decimal to_value(const decimal& value) const;
			virtual uint256_t to_baseline_value(const decimal& value) const;
			virtual decimal from_baseline_value(const uint256_t& value) const;
			virtual uint64_t get_retirement_block_number() const;
			virtual const chainparams& get_chainparams() const = 0;
		};

		class relay_backend_utxo : public relay_backend
		{
		public:
			struct balance_query
			{
				unordered_map<algorithm::asset_id, decimal> min_token_values;
				decimal min_native_value;

				balance_query(const decimal& new_min_native_value, const unordered_map<algorithm::asset_id, decimal>& new_min_token_values);
			};

		public:
			relay_backend_utxo(const algorithm::asset_id& new_asset) noexcept;
			virtual ~relay_backend_utxo() = default;
			virtual expects_promise_rt<coin_utxo> get_transaction_output(const std::string_view& transaction_id, uint64_t index) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
			virtual expects_lr<vector<coin_utxo>> calculate_utxo(const wallet_link& link, option<balance_query>&& query);
			virtual expects_lr<coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			virtual expects_lr<void> update_utxo(const prepared_transaction& computed);
			virtual expects_lr<void> update_utxo(const computed_transaction& computed);
			virtual expects_lr<void> add_utxo(const coin_utxo& output);
			virtual expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint64_t index);
			virtual decimal get_utxo_value(const vector<coin_utxo>& values, option<string>&& contract_address);

		public:
			static relay_backend_utxo* from_relay(relay_backend* base);
		};

		class address_util
		{
		public:
			static string encode_tag_address(const std::string_view& address, const std::string_view& destination_tag);
			static std::pair<string, string> decode_tag_address(const std::string_view& address_destination_tag);
		};
	}
}
#endif