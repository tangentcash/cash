#ifndef TAN_STORAGE_MEMPOOLSTATE_H
#define TAN_STORAGE_MEMPOOLSTATE_H
#include "engine.h"
#include "../kernel/block.h"
#include "../kernel/superchain.h"

namespace tangent
{
	namespace storages
	{
		typedef std::pair<ledger::node, ledger::wallet> node_pair;
		typedef std::pair<algorithm::pubkeyhash_t, socket_address> node_location_pair;

		enum class fee_priority
		{
			fastest,
			fast,
			medium,
			slow
		};

		enum class mempool_action
		{
			broatcast_again,
			may_finalize
		};

		enum class node_ports : uint16_t
		{
			consensus = (1 << 0),
			discovery = (1 << 1),
			rpc = (1 << 2),
		};

		enum class node_services : uint16_t
		{
			consensus = (1 << 0),
			discovery = (1 << 1),
			superchain = (1 << 2),
			rpc = (1 << 3),
			rpc_web_sockets = (1 << 4),
			production = (1 << 5),
			participation = (1 << 6),
			attestation = (1 << 7)
		};

		class routing_util
		{
		public:
			static bool is_address_reserved(const socket_address& address);
			static bool is_address_loopback(const socket_address& address);
			static bool is_address_private(const socket_address& address);
			static bool is_address_reserved_or_private(const socket_address& address);
		};

		struct attestation_tree
		{
			btree_map<uint256_t, btree_set<algorithm::hashsig_t>> commitments;
			btree_map<uint256_t, superchain::computed_transaction> proofs;
			algorithm::asset_id asset;
		};

		struct mempoolstate
		{
		private:
			ledger::storage_index_ptr peer_local_storage;
			ledger::storage_index_ptr secret_local_storage;
#ifndef NDEBUG
			std::thread::id local_id;
#endif
		public:
			mempoolstate() noexcept;
			mempoolstate(const mempoolstate&) = delete;
			mempoolstate(mempoolstate&&) noexcept = delete;
			mempoolstate& operator=(const mempoolstate&) = delete;
			mempoolstate& operator=(mempoolstate&&) noexcept = delete;
			~mempoolstate() noexcept;
			expects_lr<void> apply_cooldown_node(const socket_address& address, bool cooldown);
			expects_lr<void> apply_unknown_node(const socket_address& address, bool allow_reserved);
			expects_lr<void> apply_custom_node(const node_pair& node, int8_t type);
			expects_lr<void> apply_runner_node(const node_pair& node);
			expects_lr<void> apply_neighbor_node(const node_pair& node);
			expects_lr<void> apply_node(const node_pair& node);
			expects_lr<void> apply_node_quality(const socket_address& address, int8_t call_result, uint64_t call_latency);
			expects_lr<void> clear_node(const algorithm::pubkeyhash_t& account);
			expects_lr<void> clear_node(const socket_address& address);
			expects_lr<void> clear_cooldowns();
			expects_lr<vector<node_pair>> get_local_nodes();
			expects_lr<node_pair> get_neighbor_node(size_t offset);
			expects_lr<node_pair> get_better_node(const algorithm::pubkeyhash_t& account);
			expects_lr<node_pair> get_node(const socket_address& address);
			expects_lr<node_pair> get_node(const algorithm::pubkeyhash_t& account);
			expects_lr<vector<node_location_pair>> get_neighbor_nodes_with(size_t offset, size_t count, uint32_t services = 0);
			expects_lr<vector<node_location_pair>> get_random_nodes_with(size_t count, uint32_t services = 0, node_ports port = node_ports::consensus);
			expects_lr<socket_address> sample_connectable_unknown_node();
			expects_lr<size_t> get_connectable_unknown_nodes_count();
			expects_lr<size_t> get_nodes_count();
			expects_lr<bool> has_cooldown_on_node(const socket_address& address);
			expects_lr<decimal> get_gas_price(const algorithm::asset_id& asset, double priority_percentile);
			expects_lr<decimal> get_asset_price(const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double priority_percentile = 0.5);
			expects_lr<void> add_attestation(const algorithm::asset_id& asset, const superchain::computed_transaction& value, const algorithm::hashsig_t& signature);
			expects_lr<uint256_t> pull_best_attestation_hash(size_t offset);
			expects_lr<attestation_tree> get_attestation(const uint256_t& attestation_hash);
			expects_lr<void> remove_attestation(const uint256_t& attestation_hash);
			expects_lr<void> add_transaction(const ledger::transaction& value, bool resurrection);
			expects_lr<void> remove_transactions(const hash_set<uint256_t>& transaction_hashes);
			expects_lr<size_t> expire_transactions();
			expects_lr<size_t> get_transactions_count();
			expects_lr<void> apply_secret_entropy(const algorithm::pubkeyhash_t& participant, const ledger::dispatcher_context::secret_entropy& entropy);
			expects_lr<ledger::dispatcher_context::secret_entropy> get_secret_entropy(const algorithm::pubkeyhash_t& participant, const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& manager, const algorithm::pubkeyhash_t& owner);
			expects_lr<vector<states::bridge_account>> get_secret_entropies_by_manager(const algorithm::pubkeyhash_t& manager, size_t offset, size_t count);
			expects_lr<bool> has_transaction(const uint256_t& transaction_hash);
			expects_lr<uint64_t> get_lowest_transaction_nonce(const algorithm::pubkeyhash_t& owner);
			expects_lr<uint64_t> get_highest_transaction_nonce(const algorithm::pubkeyhash_t& owner);
			expects_lr<uptr<ledger::transaction>> get_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions(bool commitment, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_owner(const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<uint256_t>> get_transaction_hashset(size_t offset, size_t count);
			ledger::storage_index_ptr& get_peer_storage();
			ledger::storage_index_ptr& get_secret_storage();
			ledger::storage_util::multi_storage_index_ptr get_multi_storage();
			uint32_t get_queries() const;

		public:
			static double fee_percentile(fee_priority priority);
			static uint32_t services_of(const ledger::node& node);
			static uint64_t transaction_limit();

		private:
			static bool make_schema(sqlite::connection* connection, const std::string_view& name);
		};
	}
}
#endif