#ifndef TAN_MEDIATOR_H
#define TAN_MEDIATOR_H
#include "../policy/messages.h"
#include "../layer/control.h"

namespace tangent
{
	namespace mediator
	{
		enum
		{
			KEY_LIMIT = 1024
		};

		enum class routing_policy
		{
			account,
			memo,
			UTXO
		};

		enum class cache_policy
		{
			greedy,
			lazy,
			shortened,
			extended,
			persistent
		};

		class server_relay;

		class relay_backend;

		struct token_utxo
		{
			string contract_address;
			string symbol;
			decimal value;
			uint8_t decimals;

			token_utxo();
			token_utxo(const std::string_view& new_contract_address, const decimal& new_value);
			token_utxo(const std::string_view& new_contract_address, const std::string_view& new_symbol, const decimal& new_value, uint8_t new_decimals);
			decimal get_divisibility();
			bool is_coin_valid() const;
		};

		struct coin_utxo
		{
			vector<token_utxo> tokens;
			option<uint64_t> address_index = optional::none;
			string transaction_id;
			string address;
			decimal value;
			uint32_t index = 0;

			coin_utxo() = default;
			coin_utxo(const std::string_view& new_transaction_id, const std::string_view& new_address, option<uint64_t>&& address_index, decimal&& new_value, uint32_t new_index);
			void apply_token_value(const std::string_view& contract_address, const std::string_view& symbol, const decimal& value, uint8_t decimals);
			option<decimal> get_token_value(const std::string_view& contract_address);
			bool is_valid() const;
		};

		struct transferer
		{
			option<uint64_t> address_index = optional::none;
			string address;
			decimal value;

			transferer();
			transferer(const std::string_view& new_address, option<uint64_t>&& address_index, decimal&& new_value);
			bool is_valid() const;
		};

		struct master_wallet : messages::standard
		{
			secret_box seeding_key;
			secret_box signing_key;
			string verifying_key;
			uint64_t max_address_index = 0;

			master_wallet() = default;
			master_wallet(secret_box&& new_seeding_key, secret_box&& new_signing_key, string&& new_verifying_key);
			master_wallet(const master_wallet&) = default;
			master_wallet(master_wallet&&) = default;
			master_wallet& operator=(const master_wallet&) = default;
			master_wallet& operator=(master_wallet&&) = default;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_valid() const;
			uptr<schema> as_schema() const override;
			uint256_t as_hash(bool renew = false) const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct derived_verifying_wallet : messages::standard
		{
			address_map addresses;
			option<uint64_t> address_index = optional::none;
			string verifying_key;

			derived_verifying_wallet() = default;
			derived_verifying_wallet(address_map&& new_addresses, option<uint64_t>&& new_address_index, string&& new_verifying_key);
			derived_verifying_wallet(const derived_verifying_wallet&) = default;
			derived_verifying_wallet(derived_verifying_wallet&&) = default;
			derived_verifying_wallet& operator=(const derived_verifying_wallet&) = default;
			derived_verifying_wallet& operator=(derived_verifying_wallet&&) = default;
			virtual bool store_payload(format::stream* stream) const override;
			virtual bool load_payload(format::stream& stream) override;
			virtual bool is_valid() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct derived_signing_wallet : derived_verifying_wallet
		{
			secret_box signing_key;

			derived_signing_wallet() = default;
			derived_signing_wallet(derived_verifying_wallet&& new_wallet, secret_box&& new_signing_key);
			derived_signing_wallet(const derived_signing_wallet&) = default;
			derived_signing_wallet(derived_signing_wallet&&) = default;
			derived_signing_wallet& operator=(const derived_signing_wallet&) = default;
			derived_signing_wallet& operator=(derived_signing_wallet&&) = default;
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_valid() const override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct dynamic_wallet
		{
			option<master_wallet> parent;
			option<derived_verifying_wallet> verifying_child;
			option<derived_signing_wallet> signing_child;

			dynamic_wallet();
			dynamic_wallet(const master_wallet& value);
			dynamic_wallet(const derived_verifying_wallet& value);
			dynamic_wallet(const derived_signing_wallet& value);
			dynamic_wallet(const dynamic_wallet&) = default;
			dynamic_wallet(dynamic_wallet&&) = default;
			dynamic_wallet& operator=(const dynamic_wallet&) = default;
			dynamic_wallet& operator=(dynamic_wallet&&) = default;
			option<string> get_binding() const;
			bool is_valid() const;
		};

		struct incoming_transaction : messages::standard
		{
			vector<transferer> to;
			vector<transferer> from;
			algorithm::asset_id asset;
			string transaction_id;
			uint64_t block_id = 0;
			decimal fee;

			incoming_transaction();
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_valid() const;
			void set_transaction(const algorithm::asset_id& new_asset, uint64_t new_block_id, const std::string_view& new_transaction_id, decimal&& new_fee);
			void set_operations(vector<transferer>&& new_from, vector<transferer>&& new_to);
			bool is_latency_approved() const;
			bool is_approved() const;
			decimal get_input_value() const;
			decimal get_output_value() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct outgoing_transaction : messages::standard
		{
			option<vector<coin_utxo>> inputs;
			option<vector<coin_utxo>> outputs;
			incoming_transaction transaction;
			string data;

			outgoing_transaction();
			outgoing_transaction(incoming_transaction&& new_transaction, const std::string_view& new_data, option<vector<coin_utxo>>&& new_inputs = optional::none, option<vector<coin_utxo>>&& new_outputs = optional::none);
			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			bool is_valid() const;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct transaction_logs
		{
			vector<incoming_transaction> transactions;
			uint64_t block_height = (uint64_t)-1;
			string block_hash;
		};

		struct index_address : messages::standard
		{
			option<uint64_t> address_index = optional::none;
			string address;
			string binding;

			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct index_utxo : messages::standard
		{
			coin_utxo UTXO;
			string binding;

			bool store_payload(format::stream* stream) const override;
			bool load_payload(format::stream& stream) override;
			uptr<schema> as_schema() const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct base_fee
		{
			decimal price;
			decimal limit;

			base_fee();
			base_fee(const decimal& new_price, const decimal& new_limit);
			decimal get_fee() const;
			bool is_valid() const;
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
			enum class transmit_type
			{
				any,
				JSONRPC,
				REST,
				HTTP
			};

			struct error_reporter
			{
				transmit_type type = transmit_type::any;
				string method;
			};

		private:
			struct
			{
				string json_rpc_path;
				bool json_rpc_distinct = false;
				string rest_path;
				bool rest_distinct = false;
				string http_path;
				bool http_distinct = false;
			} paths;

		private:
			vector<std::pair<promise<bool>, task_id>> tasks;
			std::recursive_mutex mutex;
			double throttling;
			int64_t latest;
			bool allowed;

		public:
			void* user_data;

		public:
			server_relay(const std::string_view& node_url, double node_throttling) noexcept;
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
			bool has_distinct_url(transmit_type type) const;
			bool is_activity_allowed() const;
			const string& get_node_url(transmit_type type) const;
			string get_node_url(transmit_type type, const std::string_view& path) const;

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

		public:
			struct chainparams
			{
				algorithm::composition::type composition;
				routing_policy routing;
				uint64_t sync_latency;
				decimal divisibility;
				string supports_token_transfer;
				bool supports_bulk_transfer;
			};

		public:
			interaction_callback interact;

		public:
			relay_backend() noexcept;
			virtual ~relay_backend() noexcept;
			virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) = 0;
			virtual expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset) = 0;
			virtual expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash) = 0;
			virtual expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id) = 0;
			virtual expects_promise_rt<vector<incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) = 0;
			virtual expects_promise_rt<base_fee> estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address) = 0;
			virtual expects_promise_rt<schema*> execute_rpc(const algorithm::asset_id& asset, const std::string_view& method, schema_list&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<schema*> execute_rpc3(const algorithm::asset_id& asset, const std::string_view& method, schema_args&& args, cache_policy cache, const std::string_view& path = std::string_view());
			virtual expects_promise_rt<schema*> execute_rest(const algorithm::asset_id& asset, const std::string_view& method, const std::string_view& path, schema* args, cache_policy cache);
			virtual expects_promise_rt<schema*> execute_http(const algorithm::asset_id& asset, const std::string_view& method, const std::string_view& path, const std::string_view& type, const std::string_view& body, cache_policy cache);
			virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) = 0;
			virtual expects_lr<master_wallet> new_master_wallet(const std::string_view& seed) = 0;
			virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index) = 0;
			virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key) = 0;
			virtual expects_lr<derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key) = 0;
			virtual expects_lr<string> new_public_key_hash(const std::string_view& address) = 0;
			virtual expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key) = 0;
			virtual expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature) = 0;
			virtual expects_lr<ordered_map<string, uint64_t>> find_checkpoint_addresses(const algorithm::asset_id& asset, const unordered_set<string>& addresses);
			virtual expects_lr<vector<string>> get_checkpoint_addresses(const algorithm::asset_id& asset);
			virtual expects_lr<void> verify_node_compatibility(server_relay* node);
			virtual string get_derivation(uint64_t address_index) const = 0;
			virtual string get_checksum_hash(const std::string_view& value) const;
			virtual uint256_t to_baseline_value(const decimal& value) const;
			virtual uint64_t get_retirement_block_number() const;
			virtual const chainparams& get_chainparams() const = 0;
		};

		class relay_backend_utxo : public relay_backend
		{
		public:
			relay_backend_utxo() noexcept;
			virtual ~relay_backend_utxo() = default;
			virtual expects_promise_rt<coin_utxo> get_transaction_output(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index) = 0;
			virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address) override;
			virtual expects_lr<vector<coin_utxo>> calculate_coins(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<decimal>&& min_native_value, option<token_utxo>&& min_token_value);
			virtual expects_lr<coin_utxo> get_coins(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index);
			virtual expects_lr<void> update_coins(const algorithm::asset_id& asset, const outgoing_transaction& tx_data);
			virtual expects_lr<void> add_coins(const algorithm::asset_id& asset, const coin_utxo& output);
			virtual expects_lr<void> remove_coins(const algorithm::asset_id& asset, const std::string_view& transaction_id, uint32_t index);
			virtual decimal get_coins_value(const vector<coin_utxo>& values, option<string>&& contract_address);
		};
	}
}
#endif