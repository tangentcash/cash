#ifndef TAN_SERVICE_CONSENSUS_H
#define TAN_SERVICE_CONSENSUS_H
#include "../kernel/block.h"
#include "../kernel/wallet.h"
#include "../kernel/superchain.h"

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

		typedef std::function<expects_rt<void>(server_node*, uref<relay>&&, const struct exchange&)> event_callback;
		typedef std::function<expects_rt<format::variables>(server_node*, uref<relay>&&, const struct exchange&)> query_callback;
		typedef std::function<void(const algorithm::pubkey_t&, int8_t)> neighbor_callback;
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
				uint8_t id;

				descriptor() = default;
				descriptor(const std::string_view& new_name, uint8_t new_id) : name(new_name), id(new_id)
				{
				}
			};

			event_callback event;
			query_callback query;
			std::string_view name;
			bool inventory;
		};

		struct exchange : messages::uniform
		{
			enum class side : uint8_t
			{
				event,
				query,
				forward
			};

			format::variables args;
			uint64_t time = protocol::now().time.now_cpu();
			uint32_t session = 0;
			uint8_t descriptor = 0;
			side type;

			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			uint64_t calculate_latency();
			uint32_t as_type() const override;
			uint256_t as_inventory_hash() const;
			std::string_view as_typename() const override;
			uptr<schema> as_schema() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
		};

		struct forwarder
		{
			hash_map<uint256_t, uint64_t> messages;

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

		struct descriptors
		{
			static callable::descriptor broadcast_block_hash();
			static callable::descriptor broadcast_transaction_hash();
			static callable::descriptor broadcast_attestation();
			static callable::descriptor broadcast_intermediary();
			static callable::descriptor announce_neighbor();
			static callable::descriptor perform_handshake();
			static callable::descriptor perform_discovery();
			static callable::descriptor fetch_headers();
			static callable::descriptor fetch_block();
			static callable::descriptor fetch_blocks();
			static callable::descriptor fetch_mempool();
			static callable::descriptor fetch_transaction();
			static callable::descriptor fetch_transactions();
			static callable::descriptor distribute_entropy_shares();
			static callable::descriptor aggregate_entropy_shares();
			static callable::descriptor recover_entropy();
			static callable::descriptor aggregate_public_key();
			static callable::descriptor aggregate_signature();
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
			hash_map<uint32_t, query_exchange> queries;
			single_queue<exchange> outgoing_messages;
			uptr<relay_descriptor> descriptor;
			std::atomic<bool> aborted;
			forwarder inventory;
			string incoming_data;
			string outgoing_data;
			string address;
			string service;
			node_type type;
			void* instance;
			uint32_t counter;

		public:
			std::recursive_mutex mutex;
			pacemaker bandwidth;
			uint64_t handshake_time;
			task_id deferred_pull;

		public:
			relay(node_type new_type, void* new_instance);
			~relay();
			expects_promise_rt<exchange> push_query(const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool forwarded = false);
			bool push_event(const callable::descriptor& descriptor, format::variables&& args);
			void push_event(uint32_t session, format::variables&& args);
			void push_incoming(const uint8_t* buffer, size_t size);
			void push_outgoing(exchange&& message);
			void erase_incoming(size_t starting_bytes_to_erase);
			bool prepare_outgoing();
			void clear_outgoing();
			void report_call(int8_t call_result, uint64_t call_latency);
			void resolve_query(exchange&& result);
			void cancel_queries();
			void abort();
			void initialize(relay_descriptor&& target);
			void invalidate();
			bool private_network() const;
			bool partially_valid() const;
			bool fully_valid() const;
			const string& peer_address();
			const string& peer_service();
			forwarder& get_inventory();
			const uint8_t* incoming_buffer();
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
			std::string_view connection_type() const;
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
		public:
			enum class fork_head
			{
				append,
				replace
			};

			struct fork_header
			{
				ledger::block_header header;
				uref<relay> state;
			};

		public:
			struct
			{
				std::recursive_mutex account;
				std::recursive_mutex block;
				std::recursive_mutex attestation;
				std::recursive_mutex neighbor;
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
				std::atomic<bool> prepared = false;
				std::atomic<bool> waiting = false;
				std::atomic<bool> dirty = false;
			} mempool;

		private:
			hash_map<uint256_t, neighbor_callback> neighbors;
			hash_map<uint8_t, callable> callables;
			hash_map<void*, uref<relay>> nodes;
			hash_set<outbound_node*> pending_nodes;
			forwarder inventory;
			system_control control_sys;

		public:
			ledger::evaluation_context environment;
			hash_map<uint256_t, fork_header> forks;
			relay_descriptor descriptor;

		public:
			server_node() noexcept;
			virtual ~server_node() noexcept override;
			expects_lr<void> accept_local_wallet(option<ledger::wallet>&& wallet);
			expects_lr<void> accept_unsigned_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, uint64_t* account_nonce = nullptr, uint256_t* output_hash = nullptr);
			expects_lr<void> accept_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution = false);
			expects_lr<void> accept_attestation(uref<relay>&& from, const uint256_t& attestation_hash);
			expects_lr<void> accept_committed_attestation(uref<relay>&& from, const algorithm::asset_id& asset, const superchain::computed_transaction& proof, const algorithm::hashsig_t& signature);
			expects_lr<void> broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction>&& candidate_tx, const algorithm::pubkeyhash_t& owner);
			expects_rt<void> check_socket(uref<relay>&& state, const exchange& event);
			expects_rt<void> broadcast_block_hash(uref<relay>&& state, const exchange& event);
			expects_rt<void> broadcast_transaction_hash(uref<relay>&& state, const exchange& event);
			expects_rt<void> broadcast_attestation(uref<relay>&& state, const exchange& event);
			expects_rt<void> announce_neighbor(uref<relay>&& state, const exchange& event);
			expects_rt<void> broadcast_intermediary(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> perform_handshake(uref<relay>&& state, const exchange& event, bool is_acknowledgement);
			expects_rt<format::variables> perform_discovery(uref<relay>&& state, const exchange& event, bool is_acknowledgement);
			expects_rt<format::variables> fetch_headers(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> fetch_block(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> fetch_blocks(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> fetch_mempool(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> fetch_transaction(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> fetch_transactions(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> distribute_entropy_shares(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> aggregate_entropy_shares(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> recover_entropy(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> aggregate_public_key(uref<relay>&& state, const exchange& event);
			expects_rt<format::variables> aggregate_signature(uref<relay>&& state, const exchange& event);
			expects_lr<void> dispatch_transaction_logs(const algorithm::asset_id& asset, const superchain::chain_supervisor_options& options, superchain::transaction_logs&& logs);
			expects_lr<socket_address> find_node_from_mempool();
			expects_promise_rt<socket_address> find_node_from_discovery();
			expects_promise_rt<uref<relay>> connect_to_physical_node(const socket_address& address);
			expects_promise_rt<hash_set<algorithm::pubkeyhash_t>> connect_to_logical_nodes(hash_set<algorithm::pubkeyhash_t>&& accounts);
			expects_promise_rt<void> synchronize_mempool_with(uref<relay>&& state);
			expects_promise_rt<void> resolve_and_verify_fork(std::pair<uint256_t, fork_header>&& fork);
			expects_promise_rt<exchange> query(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call = false);
			expects_promise_rt<exchange> indirect_query(const algorithm::pubkeyhash_t& account, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call = false);
			expects_lr<void> notify(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args);
			size_t notify_all(const callable::descriptor& descriptor, format::variables&& args);
			size_t notify_all_except(uref<relay>&& exception, const callable::descriptor& descriptor, format::variables&& args);
			void bind_event(const callable::descriptor& descriptor, event_callback&& on_event_callback, bool inventory = false);
			void bind_query(const callable::descriptor& descriptor, query_callback&& on_query_callback);
			bool run_topology_optimization();
			bool run_mempool_vacuum();
			bool run_fork_resolution();
			bool run_attestation_resolution();
			bool run_block_production();
			bool run_block_dispatcher();
			void startup();
			void shutdown();
			void clear_pending_neighbors();
			void clear_pending_fork(relay* state);
			void accept_pending_fork(uref<relay>&& state, fork_head head, const uint256_t& candidate_hash, ledger::block_header&& candidate_block);
			bool accept_block(uref<relay>&& from, ledger::block_evaluation&& candidate, const uint256_t& fork_tip);
			bool has_address(const socket_address& address);
			uref<relay> find_by_address(const socket_address& address);
			uref<relay> find_by_account(const algorithm::pubkeyhash_t& account);
			uref<relay> find_with_neighbor_account(const algorithm::pubkeyhash_t& account);
			option<algorithm::pubkey_t> find_public_key(const algorithm::pubkeyhash_t& account);
			size_t size_of(node_type type);
			size_t get_connections();
			bool is_active();
			bool is_syncing();
			double get_sync_progress(const uint256_t& fork_tip, uint64_t current_number);
			service_control::service_node get_entrypoint();
			std::recursive_mutex& get_mutex();
			const hash_map<void*, uref<relay>>& get_nodes() const;
			dispatch_context get_dispatcher() const;
			option<std::pair<uint256_t, fork_header>> get_best_fork_header();

		private:
			expects_system<void> on_unlisten() override;
			expects_system<void> on_after_unlisten() override;
			expects_lr<void> apply_node(storages::mempoolstate& mempool, relay_descriptor& descriptor);
			uref<relay> find_node_by_instance(void* instance);
			format::variables build_state_exchange(uref<relay>&& state);
			void announce_peer(uref<relay>&& state, bool available);
			void fill_node_services();
			void fill_node_neighbors();
			bool accept_block_candidate(ledger::block_evaluation& candidate, const uint256_t& candidate_hash, const uint256_t& fork_tip);
			bool accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction);
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
			expects_promise_rt<void> aggregate_validators(const btree_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<void> distribute_entropy_shares(const ledger::transaction_context* context, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_entropy_shares(const ledger::transaction_context* context, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> recover_entropy(const ledger::transaction_context* context, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_public_key(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_signature(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator) override;
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet& get_runner_wallet() const override;

		private:
			expects_promise_rt<void> distribute_entropy_shares_internal(const ledger::transaction_context* context, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator);
			expects_promise_rt<void> aggregate_entropy_shares_internal(const ledger::transaction_context* context, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator);
			expects_promise_rt<void> recover_entropy_internal(const ledger::transaction_context* context, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator);
			expects_promise_rt<void> aggregate_public_key_internal(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator);
			expects_promise_rt<void> aggregate_signature_internal(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator);
		};

		class local_dispatch_context final : public ledger::dispatch_context
		{
		public:
			btree_map<algorithm::pubkeyhash_t, ledger::wallet> validators;
			btree_map<algorithm::pubkeyhash_t, ledger::wallet>::iterator validator;

		public:
			local_dispatch_context(const vector<ledger::wallet>& new_validators);
			local_dispatch_context(const local_dispatch_context& other) noexcept;
			local_dispatch_context(local_dispatch_context&&) noexcept = default;
			local_dispatch_context& operator=(const local_dispatch_context& other) noexcept;
			local_dispatch_context& operator=(local_dispatch_context&&) noexcept = default;
			void set_running_validator(const algorithm::pubkeyhash_t& owner);
			expects_promise_rt<void> aggregate_validators(const btree_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<void> distribute_entropy_shares(const ledger::transaction_context* context, entropy_distribution_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_entropy_shares(const ledger::transaction_context* context, entropy_aggregation_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> recover_entropy(const ledger::transaction_context* context, entropy_recovery_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_public_key(const ledger::transaction_context* context, public_state& state, const algorithm::pubkeyhash_t& validator) override;
			expects_promise_rt<void> aggregate_signature(const ledger::transaction_context* context, signature_state& state, const algorithm::pubkeyhash_t& validator) override;
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet& get_runner_wallet() const override;

		public:
			static expects_rt<void> distribute_entropy_shares(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, const btree_map<algorithm::pubkeyhash_t, string>& encrypted_shares);
			static expects_rt<void> aggregate_entropy_shares(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, const algorithm::pubkey_t& public_key, btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>>& encrypted_shares);
			static expects_rt<void> recover_entropy(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, algorithm::hashsig_t& proof, const btree_map<uint256_t, btree_map<algorithm::pubkeyhash_t, string>>& encrypted_shares, const btree_map<uint256_t, string>& encrypted_entropies);
			static expects_rt<void> aggregate_public_key(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, btree_map<algorithm::pubkey_t, string>& encrypted_shares, algorithm::composition::public_state* aggregator);
			static expects_rt<void> aggregate_signature(ledger::dispatch_context* dispatcher, const ledger::transaction_context* context, superchain::prepared_transaction& message, algorithm::composition::signature_state* aggregator);
			static btree_map<algorithm::pubkey_t, string> new_encrypted_distribution_shares(const algorithm::pubkey_t& validator_public_key, const public_state& state);
			static bool apply_encrypted_distribution_shares(public_state& state, const algorithm::pubkeyhash_t& validator, const btree_map<algorithm::pubkey_t, string>& list);
		};
	}
}
#endif
