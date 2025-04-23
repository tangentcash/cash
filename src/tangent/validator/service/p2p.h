#ifndef TAN_LAYER_P2P_H
#define TAN_LAYER_P2P_H
#include "../../kernel/block.h"
#include "../../kernel/wallet.h"
#include "../../kernel/mediator.h"

namespace tangent
{
	namespace storages
	{
		struct mempoolstate;
	};

	namespace p2p
	{
		struct procedure;
		class relay;
		class outbound_node;
		class server_node;
		class dispatch_context;

		typedef std::function<void(relay*)> abort_callback;
		typedef std::function<bool(const struct procedure&)> response_callback;
		typedef socket_connection inbound_node;

		enum class node_type
		{
			inbound,
			outbound
		};

		struct procedure
		{
			format::variables args;
			uint32_t magic = 0;
			uint32_t method = 0;
			uint32_t size = 0;
			uint32_t checksum = 0;

			bool serialize_into(string* buffer);
			bool deserialize_from(string& message);
			bool deserialize_from_stream(string& message, const uint8_t* buffer, size_t size);
			uint256_t as_hash();
		};

		struct response_procedure final
		{
			expects_promise_rt<format::variables> result;
			response_callback callback;
			task_id timeout = INVALID_TASK_ID;
		};

		class relay_procedure : public reference<relay_procedure>
		{
		public:
			procedure data;

		public:
			relay_procedure(procedure&& new_data);
			~relay_procedure() = default;
		};

		class relay : public reference<relay>
		{
		private:
			struct
			{
				void(*destructor)(void*) = nullptr;
				void* pointer = nullptr;
			} user_data;
			std::mutex mutex;
			single_queue<uref<relay_procedure>> priority_messages;
			single_queue<procedure> incoming_messages;
			single_queue<procedure> outgoing_messages;
			unordered_set<uint256_t> inventory;
			string incoming_data;
			string outgoing_data;
			string address;
			string service;
			void* instance;
			node_type type;

		public:
			relay(node_type new_type, void* new_instance);
			~relay();
			bool incoming_message_into(procedure* message);
			bool pull_incoming_message(const uint8_t* buffer, size_t size);
			bool begin_outgoing_message();
			void end_outgoing_message();
			void push_message(procedure&& message);
			bool relay_message(uref<relay_procedure>&& message, const uint256_t& message_hash);
			void invalidate();
			const string& peer_address();
			const string& peer_service();
			const single_queue<uref<relay_procedure>>& get_priority_messages() const;
			const single_queue<procedure>& get_incoming_messages() const;
			const single_queue<procedure>& get_outgoing_messages() const;
			unordered_set<uint256_t>& get_inventory();
			const uint8_t* outgoing_buffer();
			node_type type_of();
			size_t incoming_size();
			size_t outgoing_size();
			inbound_node* as_inbound_node();
			outbound_node* as_outbound_node();
			socket* as_socket();
			void* as_instance();
			uptr<schema> as_schema() const;
			template <typename t>
			void use(t* pointer, void(*destructor)(t*) = nullptr)
			{
				if (user_data.pointer && user_data.destructor)
					user_data.destructor(user_data.pointer);
				user_data.pointer = (void*)pointer;
				user_data.destructor = (void(*)(void*))destructor;
			}
			template <typename t>
			t* as_user() const
			{
				return (t*)user_data.pointer;
			}
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
			using receive_function = promise<void>(*)(server_node*, uref<relay>&&, procedure&&);

		public:
			struct
			{
				option<ledger::block> block = optional::none;
				uint256_t hash = 0;
				task_id timeout = INVALID_TASK_ID;
			} pending_tip;

			struct
			{
				ledger::wallet wallet;
				ledger::validator node;
			} validator;

			struct
			{
				std::recursive_mutex account;
				std::recursive_mutex block;
				std::mutex inventory;
			} sync;

			struct
			{
				size_t count = 0;
				size_t offset = 0;
			} discovery;

			struct
			{
				std::function<void(const uint256_t&, const ledger::block&, const ledger::block_checkpoint&)> accept_block;
				std::function<void(const uint256_t&, const ledger::transaction*, const algorithm::pubkeyhash)> accept_transaction;
			} events;

		private:
			struct
			{
				bool dirty = false;
			} mempool;

		private:
			unordered_map<uint32_t, std::pair<void*, bool>> in_methods;
			unordered_map<void*, uint32_t> out_methods;
			unordered_map<void*, relay*> nodes;
			unordered_set<uint256_t> inventory;
			unordered_map<size_t, response_procedure> responses;
			single_queue<uref<relay_procedure>> messages;
			uint32_t method_address;
			system_control control_sys;

		public:
			ledger::evaluation_context environment;
			unordered_map<uint256_t, ledger::block_header> forks;

		public:
			server_node() noexcept;
			virtual ~server_node() noexcept override;
			expects_promise_rt<format::variables> call_responsive(receive_function function, format::variables&& args, uint64_t timeout_ms, response_callback&& callback);
			promise<option<socket_address>> find_node_from_mempool(option<socket_address>&& error_address, bool allow_seeding);
			promise<option<socket_address>> find_node_from_seeding();
			promise<void> propose_transaction_logs(const algorithm::asset_id& asset, const mediator::chain_supervisor_options& options, mediator::transaction_logs&& logs);
			expects_lr<void> build_transaction(ledger::transaction* candidate_tx, uint64_t account_nonce, uint256_t* output_hash = nullptr);
			expects_lr<void> accept_unsigned_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, uint64_t account_nonce, uint256_t* output_hash = nullptr);
			expects_lr<void> accept_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, bool validate_execution = false);
			expects_lr<void> broadcast_transaction(relay* from, uptr<ledger::transaction>&& candidate_tx, const algorithm::pubkeyhash owner);
			void bind_callable(receive_function function);
			void bind_multicallable(receive_function function);
			bool call(relay* state, receive_function function, format::variables&& args);
			bool call(relay* state, procedure&& message);
			size_t multicall(relay* state, receive_function function, format::variables&& args);
			size_t multicall(relay* state, procedure&& message);
			void startup();
			void shutdown();
			void reject(relay* state);
			void clear_pending_tip();
			void accept_fork_tip(const uint256_t& fork_tip, const uint256_t& candidate_hash, ledger::block_header&& fork_tip_block);
			void accept_pending_tip();
			bool clear_mempool(bool wait);
			bool accept_mempool();
			bool accept_dispatchpool(const ledger::block_header& tip);
			bool accept_block(relay* from, ledger::block&& candidate_block, const uint256_t& fork_tip);
			bool accept(option<socket_address>&& address = optional::none);
			relay* find(const socket_address& address);
			size_t size_of(node_type type);
			size_t get_connections();
			bool is_active();
			bool is_syncing();
			double get_sync_progress(const uint256_t& fork_tip, uint64_t current_number);
			service_control::service_node get_entrypoint();
			std::recursive_mutex& get_mutex();
			const unordered_map<void*, relay*>& get_nodes() const;
			const single_queue<uref<relay_procedure>>& get_messages() const;
			dispatch_context get_dispatcher() const;

		private:
			promise<void> internal_connect(uref<relay>&& from);
			promise<void> internal_disconnect(uref<relay>&& from);
			expects_system<void> on_unlisten() override;
			expects_system<void> on_after_unlisten() override;
			expects_lr<void> apply_validator(storages::mempoolstate& mempool, ledger::validator& node, option<ledger::wallet>&& wallet);
			relay* find_node_by_instance(void* instance);
			int32_t connect_outbound_node(const socket_address& address);
			void fill_validator_services();
			bool accept_block_candidate(const ledger::block& candidate_block, const uint256_t& candidate_hash, const uint256_t& fork_tip);
			bool accept_proposal_transaction(const ledger::block& checkpoint_block, const ledger::block_transaction& transaction);
			bool receive_outbound_node(option<socket_address>&& error_address);
			bool push_next_procedure(relay* state);
			void accept_outbound_node(uptr<outbound_node>&& candidate, expects_system<void>&& status);
			void pull_procedure(relay* state, const abort_callback& abort_callback);
			void push_procedure(relay* state, const abort_callback& abort_callback);
			void abort_inbound_node(inbound_node* node);
			void abort_outbound_node(outbound_node* node);
			void append_node(relay* state, task_callback&& callback);
			void erase_node(relay* state, task_callback&& callback);
			void erase_node_by_instance(void* instance, task_callback&& callback);
			void on_request_open(inbound_node* base) override;
		};

		class methods
		{
			friend class server_node;

		public:
			class returning
			{
			public:
				static promise<void> abort(server_node* relayer, relay* from, const char* function, const std::string_view& text);
				static promise<void> error(server_node* relayer, relay* from, const char* function, const std::string_view& text);
				static promise<void> ok(relay* from, const char* function, const std::string_view& text);
			};
			
		public:
			static promise<void> propose_handshake(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> approve_handshake(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_nodes(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> find_fork_collision(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> verify_fork_collision(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> request_fork_block(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_fork_block(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> request_block(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_block(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_block_hash(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> request_transaction(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_transaction(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_transaction_hash(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> request_mempool(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> propose_mempool(server_node* relayer, uref<relay>&& from, procedure&& message);
		};

		class routing
		{
		public:
			static bool is_address_reserved(const socket_address& address);
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
			expects_promise_rt<void> calculate_group_public_key(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, algorithm::composition::cpubkey_t& inout) override;
			expects_promise_rt<void> calculate_group_signature(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, const mediator::prepared_transaction& prepared, ordered_map<uint8_t, algorithm::composition::cpubsig_t>& inout) override;
			const ledger::wallet* get_wallet() const override;

		public:
			static promise<void> calculate_group_public_key_remote(server_node* relayer, uref<relay>&& from, procedure&& message);
			static promise<void> calculate_group_signature_remote(server_node* relayer, uref<relay>&& from, procedure&& message);
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
			void set_running_validator(const algorithm::pubkeyhash owner);
			expects_promise_rt<void> calculate_group_public_key(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, algorithm::composition::cpubkey_t& inout) override;
			expects_promise_rt<void> calculate_group_signature(const ledger::transaction_context* context, const algorithm::pubkeyhash_t& validator, const mediator::prepared_transaction& prepared, ordered_map<uint8_t, algorithm::composition::cpubsig_t>& inout) override;
			const ledger::wallet* get_wallet() const override;
		};

	}
}
#endif