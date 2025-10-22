#ifndef TAN_LAYER_CONSENSUS_H
#define TAN_LAYER_CONSENSUS_H
#include "../../kernel/block.h"
#include "../../kernel/wallet.h"
#include "../../kernel/warden.h"

namespace tangent
{
	namespace storages
	{
		struct mempoolstate;
	}

	namespace consensus
	{
		class relay;
		class outbound_node;
		class server_node;
		class dispatch_context;

		typedef std::function<expects_lr<void>(server_node*, uref<relay>&&, const struct exchange&)> event_callback;
		typedef std::function<expects_lr<format::variables>(server_node*, uref<relay>&&, const struct exchange&)> query_callback;
		typedef std::pair<ledger::node, ledger::wallet> relay_descriptor;
		typedef socket_connection inbound_node;

		enum class node_type
		{
			inbound,
			outbound
		};

		struct callable
		{
			struct descriptor
			{
				std::string_view name;
				size_t checksum;

				descriptor() = default;
				descriptor(const std::string_view& new_name, size_t new_checksum) : name(new_name), checksum(new_checksum)
				{
				}
			};

			event_callback event;
			query_callback query;
			std::string_view name;
		};

		struct exchange : messages::uniform
		{
			enum class side : uint8_t
			{
				event,
				query
			};

			format::variables args;
			uint64_t time = protocol::now().time.now_cpu();
			uint32_t method = 0;
			uint32_t session = 0;
			side type;

			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			bool store_exchange(string* result);
			bool load_exchange(string& message);
			bool load_partial_exchange(string& message, const uint8_t* buffer, size_t size);
			uint64_t calculate_latency();
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			uptr<schema> as_schema() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct forwarder
		{
			unordered_map<uint256_t, uint64_t> messages;

			bool insert(const uint256_t& message_hash);
			bool contains(const uint256_t& message_hash) const;
		};

		struct pacemaker
		{
			size_t max_bytes_per_window;
			uint64_t window_size;
			size_t bytes_used_in_window;
			uint64_t window_start_time;

			pacemaker(size_t bits_per_window, uint64_t window_ms = 1000);
			bool check(size_t& bytes_available, uint64_t& timeout_ms);
			void spend(size_t bytes);
		};

		class relay : public reference<relay>
		{
		private:
			struct query_exchange
			{
				expects_promise_rt<exchange> result;
				task_id timeout = INVALID_TASK_ID;
			};

		private:
			std::recursive_mutex mutex;
			unordered_map<uint32_t, query_exchange> queries;
			single_queue<exchange> incoming_messages;
			single_queue<exchange> outgoing_messages;
			forwarder inventory;
			uptr<relay_descriptor> descriptor;
			string incoming_data;
			string outgoing_data;
			string address;
			string service;
			node_type type;
			void* instance;
			uint32_t counter;

		public:
			pacemaker bandwidth;
			task_id deferred_pull;

		public:
			relay(node_type new_type, void* new_instance);
			~relay();
			expects_promise_rt<exchange> push_query(const std::string_view& method, format::variables&& args, uint64_t timeout_ms);
			bool push_event(const std::string_view& method, format::variables&& args);
			void push_event(uint32_t session, format::variables&& args);
			bool incoming_message_into(exchange* message);
			bool pull_incoming_message(const uint8_t* buffer, size_t size);
			bool begin_outgoing_message();
			void end_outgoing_message();
			void report_call(int8_t call_result, uint64_t call_latency);
			void resolve_query(exchange&& result);
			void cancel_queries();
			void abort();
			void initialize(relay_descriptor&& target);
			void invalidate();
			bool partially_valid() const;
			bool fully_valid() const;
			const string& peer_address();
			const string& peer_service();
			const single_queue<exchange>& get_incoming_messages() const;
			const single_queue<exchange>& get_outgoing_messages() const;
			forwarder& get_inventory();
			const uint8_t* outgoing_buffer();
			node_type type_of();
			size_t incoming_size();
			size_t outgoing_size();
			inbound_node* as_inbound_node();
			outbound_node* as_outbound_node();
            vitex::network::socket* as_socket();
			void* as_instance();
			uptr<schema> as_schema() const;
			relay_descriptor* as_descriptor() const;
		};

		class outbound_node final : public socket_client
		{
			friend server_node;

		public:
			outbound_node() noexcept;
			~outbound_node() override = default;

		protected:
			void configure_stream() override;
		};

		class server_node final : public socket_server
		{
			friend class methods;

		public:
			enum class fork_head
			{
				append,
				replace
			};

			struct fork_header
			{
				ledger::block_header header;
				task_id timeout = INVALID_TASK_ID;
				uref<relay> state;
			};

			struct connection_permit
			{
				unordered_set<algorithm::pubkeyhash_t> accounts;
				vector<uref<relay>> results;
				expects_promise_rt<vector<uref<relay>>> task;
				task_id timeout = INVALID_TASK_ID;
			};

		public:
			struct
			{
				std::recursive_mutex account;
				std::recursive_mutex block;
				std::mutex inventory;
			} sync;

			struct
			{
				std::function<void(const uint256_t&, const ledger::block&, const ledger::block_checkpoint&)> accept_block;
				std::function<void(const uint256_t&, const ledger::transaction*, const algorithm::pubkeyhash_t&)> accept_transaction;
			} events;

		private:
			struct
			{
				std::atomic<bool> waiting = false;
				std::atomic<bool> dirty = false;
				std::atomic<uint64_t> dispatcher_time = 0;
			} mempool;

		private:
			unordered_map<uint256_t, connection_permit> permits;
			unordered_map<uint32_t, callable> callables;
			unordered_map<void*, uref<relay>> nodes;
			unordered_set<outbound_node*> pending_nodes;
			forwarder inventory;
			system_control control_sys;

		public:
			ledger::evaluation_context environment;
			unordered_map<uint256_t, fork_header> forks;
			relay_descriptor descriptor;

		public:
			server_node() noexcept;
			virtual ~server_node() noexcept override;
			expects_lr<void> accept_local_wallet(option<ledger::wallet>&& wallet);
			expects_lr<void> accept_unsigned_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, uint64_t* account_nonce, uint256_t* output_hash = nullptr);
			expects_lr<void> accept_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution = false);
			expects_lr<void> broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, const algorithm::pubkeyhash_t& owner);
			expects_lr<void> notify_of_possibly_new_block_hash(uref<relay>&& state, const exchange& event);
			expects_lr<void> notify_of_possibly_new_transaction_hash(uref<relay>&& state, const exchange& event);
			expects_lr<void> reverse_connect_to_node_by_accounts(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_handshake(uref<relay>&& state, const exchange& event, bool is_acknowledgement);
			expects_lr<format::variables> query_state(uref<relay>&& state, const exchange& event, bool is_acknowledgement);
			expects_lr<format::variables> query_block_headers(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_block(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_mempool_transaction_hashes(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_transaction(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_secret_share_state_aggregation(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_public_state_aggregation(uref<relay>&& state, const exchange& event);
			expects_lr<format::variables> query_signature_state_aggreation(uref<relay>&& state, const exchange& event);
			expects_lr<void> dispatch_transaction_logs(const algorithm::asset_id& asset, const warden::chain_supervisor_options& options, warden::transaction_logs&& logs);
			expects_lr<socket_address> find_node_from_mempool();
			expects_promise_rt<socket_address> find_node_from_discovery();
			expects_promise_rt<uref<relay>> connect_to_physical_node(const socket_address& address, option<algorithm::pubkeyhash_t>&& required_account = optional::none);
			expects_promise_rt<unordered_map<algorithm::pubkeyhash_t, uref<relay>>> connect_to_logical_nodes_with_permit(const uint256_t& permit_hash, unordered_set<algorithm::pubkeyhash_t>&& accounts);
			expects_promise_rt<vector<uref<relay>>> accept_permit_for_accounts(const uint256_t& permit_hash, unordered_set<algorithm::pubkeyhash_t>&& accounts);
			expects_promise_rt<void> synchronize_mempool_with(uref<relay>&& state);
			expects_promise_rt<void> find_pivot_and_replace_branch(uref<relay>&& state, const uint256_t& fork_hash, uint64_t branch_number);
			expects_promise_rt<void> replace_branch_pivot(uref<relay>&& state, const uint256_t& fork_hash, const uint256_t& block_hash, uint64_t block_number);
			expects_promise_rt<exchange> query(uref<relay>&& state, const callable::descriptor& method, format::variables&& args, uint64_t timeout_ms);
			expects_lr<void> notify(uref<relay>&& state, const callable::descriptor& method, format::variables&& args);
			size_t notify_all(const callable::descriptor& method, format::variables&& args);
			size_t notify_all_except(uref<relay>&& exception, const callable::descriptor& method, format::variables&& args);
			void bind_event(const callable::descriptor& method, event_callback&& on_event_callback);
			void bind_query(const callable::descriptor& method, query_callback&& on_query_callback);
			bool run_topology_optimization();
			bool run_mempool_vacuum();
			bool run_block_production();
			bool run_block_dispatcher(const ledger::block_header& tip);
			bool run_block_dispatch_retrial();
			void startup();
			void shutdown();
			void clear_pending_permit(const uint256_t& permit_hash);
			void clear_pending_fork(relay* state);
			void accept_pending_fork(uref<relay>&& state, fork_head head, const uint256_t& candidate_hash, ledger::block_header&& candidate_block);
			bool accept_block(uref<relay>&& from, ledger::block_evaluation&& candidate, const uint256_t& fork_tip);
			bool has_address(const socket_address& address);
			uref<relay> find_by_address(const socket_address& address);
			uref<relay> find_by_account(const algorithm::pubkeyhash_t& account);
			size_t size_of(node_type type);
			size_t get_connections();
			bool is_active();
			bool is_syncing();
			double get_sync_progress(const uint256_t& fork_tip, uint64_t current_number);
			service_control::service_node get_entrypoint();
			std::recursive_mutex& get_mutex();
			const unordered_map<void*, uref<relay>>& get_nodes() const;
			dispatch_context get_dispatcher() const;

		private:
			expects_system<void> on_unlisten() override;
			expects_system<void> on_after_unlisten() override;
			expects_lr<void> apply_node(storages::mempoolstate& mempool, relay_descriptor& descriptor);
			uref<relay> find_node_by_instance(void* instance);
			format::variables build_state_exchange(uref<relay>&& state);
			void fill_node_services();
			bool accept_block_candidate(const ledger::block_evaluation& candidate, const uint256_t& candidate_hash, const uint256_t& fork_tip);
			bool accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction);
			bool spend_permit_on(uref<relay>&& state);
			void pull_messages(uref<relay>&& state);
			void push_messages(uref<relay>&& state);
			void abort_node(uref<relay>&& state);
			void abort_node_by_account(const algorithm::pubkeyhash_t& account);
			void append_node(uref<relay>&& state);
			void erase_node(uref<relay>&& state);
			void erase_node_by_instance(void* instance);
			void append_pending_node(outbound_node* base);
			void erase_pending_node(outbound_node* base);
			void on_request_open(inbound_node* base) override;
		};

		class routing_util
		{
		public:
			static bool is_address_reserved(const socket_address& address);
			static bool is_address_private(const socket_address& address);
			static std::string_view node_type_of(relay* from);
		};

		class dispatch_context final : public ledger::dispatch_context
		{
		public:
			server_node* server;

		public:
			dispatch_context(server_node* new_server);
			dispatch_context(const dispatch_context& other) noexcept;
			dispatch_context(dispatch_context&&) noexcept = default;
			dispatch_context& operator=(const dispatch_context& other) noexcept;
			dispatch_context& operator=(dispatch_context&&) noexcept = default;
			expects_promise_rt<void> aggregate_validators(const uint256_t& transaction_hash, const ordered_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<void> aggregate_secret_share_state(const ledger::transaction_context* context, secret_share_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_public_state(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_signature_state(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator) override;
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet& get_runner_wallet() const override;
		};

		class local_dispatch_context final : public ledger::dispatch_context
		{
		public:
			ordered_map<algorithm::pubkeyhash_t, ledger::wallet> validators;
			ordered_map<algorithm::pubkeyhash_t, ledger::wallet>::iterator validator;

		public:
			local_dispatch_context(const vector<ledger::wallet>& new_validators);
			local_dispatch_context(const local_dispatch_context& other) noexcept;
			local_dispatch_context(local_dispatch_context&&) noexcept = default;
			local_dispatch_context& operator=(const local_dispatch_context& other) noexcept;
			local_dispatch_context& operator=(local_dispatch_context&&) noexcept = default;
			void set_running_validator(const algorithm::pubkeyhash_t& owner);
			expects_promise_rt<void> aggregate_validators(const uint256_t& transaction_hash, const ordered_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<void> aggregate_secret_share_state(const ledger::transaction_context* context, secret_share_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_public_state(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_signature_state(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator) override;
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet& get_runner_wallet() const override;

		public:
			static expects_rt<void> aggregate_secret_share_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, secret_share_state& state);
			static expects_rt<void> aggregate_public_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, public_state& state);
			static expects_rt<void> aggregate_signature_state(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, signature_state& state);
		};
	}
}
#endif
