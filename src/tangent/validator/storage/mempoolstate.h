#ifndef TAN_STORAGE_MEMPOOLSTATE_H
#define TAN_STORAGE_MEMPOOLSTATE_H
#include "engine.h"
#include "../../kernel/block.h"

namespace tangent
{
	namespace storages
	{
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

		enum class node_services : uint16_t
		{
			consensus = (1 << 0),
			discovery = (1 << 1),
			synchronization = (1 << 2),
			interfaces = (1 << 3),
			production = (1 << 4),
			participation = (1 << 5),
			attestation = (1 << 6),
			querying = (1 << 7),
			streaming = (1 << 8)
		};

		struct account_bandwidth
		{
			uint64_t nonce = 0;
			size_t count = 0;
			bool congested = false;
		};

		struct mempoolstate : ledger::mutable_storage
		{
		private:
			std::string_view label;
			bool borrows;

		public:
			mempoolstate(const std::string_view& new_label) noexcept;
			virtual ~mempoolstate() noexcept override;
			expects_lr<void> apply_trial_address(const socket_address& address);
			expects_lr<void> apply_validator(const ledger::validator& node, option<ledger::wallet>&& wallet);
			expects_lr<void> clear_validator(const socket_address& validator_address);
			expects_lr<std::pair<ledger::validator, ledger::wallet>> get_validator_by_ownership(size_t offset);
			expects_lr<ledger::validator> get_validator_by_address(const socket_address& validator_address);
			expects_lr<ledger::validator> get_validator_by_preference(size_t offset);
			expects_lr<vector<socket_address>> get_validator_addresses(size_t offset, size_t count, uint32_t services = 0);
			expects_lr<vector<socket_address>> get_randomized_validator_addresses(size_t count, uint32_t services = 0);
			expects_lr<socket_address> next_trial_address();
			expects_lr<size_t> get_validators_count();
			expects_lr<decimal> get_gas_price(const algorithm::asset_id& asset, double priority_percentile);
			expects_lr<decimal> get_asset_price(const algorithm::asset_id& price_of, const algorithm::asset_id& relative_to, double priority_percentile = 0.5);
			expects_lr<void> add_transaction(ledger::transaction& value, bool resurrection);
			expects_lr<void> remove_transactions_by_group(const uint256_t& group_hash);
			expects_lr<void> remove_transactions(const vector<uint256_t>& transaction_hashes);
			expects_lr<void> remove_transactions(const unordered_set<uint256_t>& transaction_hashes);
			expects_lr<void> expire_transactions();
			expects_lr<void> apply_group_account(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& proposer, const algorithm::pubkeyhash_t& owner, const uint256_t& share);
			expects_lr<uint256_t> get_or_apply_group_account_share(const algorithm::asset_id& asset, const algorithm::pubkeyhash_t& proposer, const algorithm::pubkeyhash_t& owner, const uint256_t& entropy);
			expects_lr<vector<states::depository_account>> get_group_accounts(const algorithm::pubkeyhash_t& proposer, size_t offset, size_t count);
			expects_lr<account_bandwidth> get_bandwidth_by_owner(const algorithm::pubkeyhash_t& owner, ledger::transaction_level type);
			expects_lr<bool> has_transaction(const uint256_t& transaction_hash);
			expects_lr<uint64_t> get_lowest_transaction_nonce(const algorithm::pubkeyhash_t& owner);
			expects_lr<uint64_t> get_highest_transaction_nonce(const algorithm::pubkeyhash_t& owner);
			expects_lr<uptr<ledger::transaction>> get_transaction_by_hash(const uint256_t& transaction_hash);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions(size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_owner(const algorithm::pubkeyhash_t& owner, int8_t direction, size_t offset, size_t count);
			expects_lr<vector<uptr<ledger::transaction>>> get_transactions_by_group(const uint256_t& group_hash, size_t offset, size_t count);
			expects_lr<vector<uint256_t>> get_transaction_hashset(size_t offset, size_t count);

		public:
			static double fee_percentile(fee_priority priority);

		protected:
			bool reconstruct_storage() override;
		};
	}
}
#endif