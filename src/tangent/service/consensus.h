#ifndef TAN_SERVICE_CONSENSUS_H
#define TAN_SERVICE_CONSENSUS_H
#include "../kernel/block.h"
#include "../kernel/superchain.h"
#include "../kernel/control.h"

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

		enum class node_category
		{
			runner,
			neighbor,
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

		struct exchange : ledger::uniform_serializer
		{
			enum class side : uint8_t
			{
				event,
				query,
				forward
			};

			relay_descriptor* callee = nullptr;
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
			format::tree as_tree() const override;
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
			static callable::descriptor delegate_execution();
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
			expects_promise_rt<exchange> push_query(const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool forwarded);
			bool push_event(const callable::descriptor& descriptor, format::variables&& args);
			void push_event(uint32_t session, format::variables&& args);
			void push_incoming(const uint8_t* buffer, size_t size);
			void push_outgoing(exchange&& message);
			void erase_incoming(size_t starting_bytes_to_erase);
			bool prepare_outgoing();
			void clear_outgoing();
			void report_call(int8_t call_result, uint64_t call_latency, bool cooldown = false);
			void resolve_query(exchange&& result);
			void cancel_queries();
			void open_channel(relay_descriptor&& target);
			void close_channel(const std::string_view& message);
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
			format::tree as_tree() const;
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
			struct tip_header
			{
				ledger::block_header header;
				uref<relay> state;
			};

			struct fetch_target
			{
				string location;
				string method;
				http::fetch_frame options;
				expects_promise_system<http::response_frame> result;
			};

			struct fetch_queue
			{
				single_queue<fetch_target> queue;
				size_t requests = 0;
				bool busy = false;
			};

		public:
			struct
			{
				std::recursive_mutex account;
				std::recursive_mutex attestation;
				std::recursive_mutex neighbor;
				std::recursive_mutex tip;
				std::mutex inventory;
				std::mutex fetcher;
			} sync;

			struct
			{
				std::function<void(const uint256_t&, const ledger::block_body&, const ledger::block_checkpoint&)> accept_block;
				std::function<void(const uint256_t&, const ledger::transaction_message*, const algorithm::pubkeyhash_t&)> accept_transaction;
			} events;

			struct
			{
				ledger::solver_context solver;
				ledger::block_evaluation solution;
				ledger::block_rewards rewards;
				hash_set<uint256_t> hashes;
				std::atomic<bool> queued = false;
			} prover;

			struct
			{
				ledger::solver_context solver;
				ledger::solver_context::tip_cache cache;
				option<ledger::block_header> tip_cache = optional::none;
				uint64_t progress_time = 0;
				uint64_t progress_block_number = 0;
				std::atomic<int64_t> progress = std::atomic<int64_t>(-1);
				std::atomic<uint64_t> size = std::atomic<uint64_t>(0);
				std::atomic<bool> busy = false;
				std::atomic<bool> stale = false;
			} verifier;

		private:
			hash_map<algorithm::asset_id, fetch_queue> fetchers;
			hash_map<algorithm::asset_id, uint64_t> witnesses;
			hash_map<uint256_t, neighbor_callback> neighbors;
			hash_map<uint8_t, callable> callables;
			hash_map<void*, uref<relay>> nodes;
			hash_map<uint256_t, format::wo_stream> maybe_tips;
			hash_set<outbound_node*> pending_nodes;
			forwarder inventory;
			system_control control_sys;

		public:
			btree_map<algorithm::pubkeyhash_t, relay_descriptor> descriptors;
			hash_map<uint256_t, tip_header> tips;
			relay_descriptor* runner_descriptor;

		public:
			server_node() noexcept;
			virtual ~server_node() noexcept override;
			expects_lr<void> accept_local_accounts(const vector<ledger::wallet>& accounts);
			expects_lr<void> accept_local_transaction(const ledger::wallet* signer_wallet, uptr<ledger::transaction_message>&& candidate_tx, uint256_t* output_hash = nullptr);
			expects_lr<void> accept_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_t);
			expects_lr<void> accept_attestation(const uint256_t& attestation_hash);
			expects_lr<void> accept_committed_attestation(const algorithm::asset_id& asset, const superchain::computed_transaction& proof, const btree_set<algorithm::hashsig_t>& signatures);
			expects_lr<void> broadcast_transaction(uref<relay>&& from, uptr<ledger::transaction_message>&& candidate_tx, const algorithm::pubkeyhash_t& owner, bool bypass_cooldown = false);
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
			expects_rt<format::variables> delegate_execution(uref<relay>&& state, const exchange& event);
			expects_lr<void> dispatch_transaction_logs(const algorithm::asset_id& asset, superchain::transaction_logs&& logs);
			expects_lr<socket_address> find_node_from_mempool();
			expects_promise_rt<socket_address> find_node_from_discovery();
			expects_promise_rt<uref<relay>> connect_to_physical_node(const socket_address& address);
			expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> connect_to_logical_nodes(btree_set<algorithm::pubkeyhash_t>&& accounts);
			expects_promise_rt<void> synchronize_mempool_with(uref<relay>&& state);
			expects_promise_rt<void> resolve_and_verify_fork(const std::pair<uint256_t, tip_header>* fork);
			expects_promise_rt<exchange> query(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call = false);
			expects_promise_rt<exchange> indirect_query(const algorithm::pubkeyhash_t& account, const callable::descriptor& descriptor, format::variables&& args, uint64_t timeout_ms, bool force_call = false);
			expects_lr<void> notify(uref<relay>&& state, const callable::descriptor& descriptor, format::variables&& args);
			size_t notify_all(const callable::descriptor& descriptor, format::variables&& args);
			size_t notify_all_except(uref<relay>&& exception, const callable::descriptor& descriptor, format::variables&& args);
			void bind_event(const callable::descriptor& descriptor, event_callback&& on_event_callback, bool inventory = false);
			void bind_query(const callable::descriptor& descriptor, query_callback&& on_query_callback);
			bool try_acquire_checkpointer();
			void release_checkpointer();
			bool run_superchain_sync(const algorithm::asset_id& asset);
			bool run_topology_optimization();
			bool run_mempool_vacuum();
			bool run_fork_resolution();
			bool run_attestation_resolution();
			bool run_block_production();
			bool run_block_dispatcher();
			void startup();
			void shutdown();
			void clear_pending_neighbors();
			void clear_tip(relay* state, ledger::block_header* prev_best);
			void accept_tip(uref<relay>&& state, const uint256_t& candidate_hash, ledger::block_header&& candidate_block);
			void disconnect_node(uref<relay>&& state, const std::string_view& message);
			void disconnect_node_by_account(const algorithm::pubkeyhash_t& account, const std::string_view& message);
			expects_lr<void> accept_block(uref<relay>&& from, ledger::block_evaluation& candidate, const uint256_t& fork_tip, bool verify_pow = true);
			bool connected_to_ip_address(const socket_address& address);
			relay_descriptor* find_descriptor(const algorithm::pubkeyhash_t& account);
			uref<relay> find_by_ip_address(const socket_address& address);
			uref<relay> find_by_account(const algorithm::pubkeyhash_t& account);
			uref<relay> find_with_neighbor_account(const algorithm::pubkeyhash_t& account);
			option<algorithm::pubkey_t> find_public_key(const algorithm::pubkeyhash_t& account);
			size_t size_of(node_type type);
			size_t get_connections();
			bool is_active();
			bool is_syncing();
			double get_sync_progress(uint64_t current_number);
			double get_sync_progress(uint64_t current_number, relay* state);
			service_control::service_node get_entrypoint();
			std::recursive_mutex& get_mutex();
			const hash_map<void*, uref<relay>>& get_nodes() const;
			option<std::pair<uint256_t, tip_header>> get_best_tip_header();

		private:
			expects_promise_system<http::response_frame> queued_fetch_external(const algorithm::asset_id& asset, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options);
			expects_promise_system<http::response_frame> queued_fetch_internal(const algorithm::asset_id& asset, const std::string_view& location, const std::string_view& method, const http::fetch_frame& options);
			expects_system<void> on_unlisten() override;
			expects_system<void> on_after_unlisten() override;
			expects_lr<void> accept_node(storages::mempoolstate& mempool, relay_descriptor& descriptor, node_category category);
			uref<relay> find_node_by_instance(void* instance);
			format::variables build_state_exchange(uref<relay>&& state);
			void announce_peer(uref<relay>&& state, bool available);
			void fill_node_services(relay_descriptor& descriptor);
			void fill_node_neighbors(relay_descriptor& descriptor);
			void append_pending_tip(uref<relay>&& from, const uint256_t& block_hash, ledger::block_body* tip);
			void erase_pending_tip(const uint256_t& block_hash);
			void broadcast_pending_tip(uref<relay>&& from, const uint256_t& block_hash, uint64_t block_number);
			void finalize_pending_tip(uref<relay>&& from, const uint256_t& block_hash, uint64_t block_number);
			bool accept_proposal_transaction(const ledger::block_transaction& transaction);
			void pull_messages(uref<relay>&& state);
			void push_messages(uref<relay>&& state);
			void append_node(uref<relay>&& state);
			void erase_node(uref<relay>&& state);
			void erase_node_by_instance(void* instance);
			void erase_node_by_iterator(hash_map<void*, uref<relay>>::iterator& it);
			void append_pending_node(outbound_node* base);
			void erase_pending_node(outbound_node* base);
			void on_request_open(inbound_node* base) override;
		};

		struct server_delegation_adapter final : ledger::delegation_adapter
		{
			server_node* server;

			server_delegation_adapter(server_node* new_server);
			server_delegation_adapter(const server_delegation_adapter& other) noexcept;
			server_delegation_adapter(server_delegation_adapter&&) noexcept = default;
			server_delegation_adapter& operator=(const server_delegation_adapter& other) noexcept;
			server_delegation_adapter& operator=(server_delegation_adapter&&) noexcept = default;
			expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<format::wo_stream> execute_on_validator(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message) override;
			expects_promise_rt<format::wo_stream> execute_on_validator_internal(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message);
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet* get_runner_wallet(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet* get_runner_wallet() const override;
		};

		struct local_delegation_adapter final : ledger::delegation_adapter
		{
			btree_map<algorithm::pubkeyhash_t, ledger::wallet> validators;

			local_delegation_adapter(const vector<ledger::wallet>& new_validators);
			local_delegation_adapter(const local_delegation_adapter& other) noexcept;
			local_delegation_adapter(local_delegation_adapter&&) noexcept = default;
			local_delegation_adapter& operator=(const local_delegation_adapter& other) noexcept;
			local_delegation_adapter& operator=(local_delegation_adapter&&) noexcept = default;
			expects_promise_rt<btree_set<algorithm::pubkeyhash_t>> require_validators(ledger::delegation_contract* contract, const btree_set<algorithm::pubkeyhash_t>& validators) override;
			expects_promise_rt<format::wo_stream> execute_on_validator(ledger::delegation_contract* contract, const algorithm::pubkeyhash_t& target, const format::wo_stream& message) override;
			algorithm::pubkey_t get_public_key(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet* get_runner_wallet(const algorithm::pubkeyhash_t& validator) const override;
			const ledger::wallet* get_runner_wallet() const override;
		};
	}
}
#endif
