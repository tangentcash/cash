#ifndef TAN_STORAGE_MEDIATORSTATE_H
#define TAN_STORAGE_MEDIATORSTATE_H
#include "engine.h"
#include "../../kernel/mediator.h"

namespace tangent
{
	namespace storages
	{
		struct mediatorstate : ledger::mutable_storage
		{
		private:
			algorithm::asset_id asset;
			std::string_view label;

		public:
			mediatorstate(const std::string_view& new_label, const algorithm::asset_id& new_asset) noexcept;
			virtual ~mediatorstate() noexcept = default;
			expects_lr<void> add_utxo(const mediator::coin_utxo& value);
			expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<mediator::coin_utxo> get_stxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<mediator::coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<mediator::coin_utxo>> get_utxos(const mediator::wallet_link& link, size_t offset, size_t count);
			expects_lr<void> add_computed_transaction(const mediator::computed_transaction& value, uint64_t block_id);
			expects_lr<void> add_finalized_transaction(const mediator::computed_transaction& value, const uint256_t& external_id);
			expects_lr<mediator::computed_transaction> get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id);
			expects_lr<vector<mediator::computed_transaction>> approve_computed_transactions(uint64_t block_height, uint64_t block_latency);
			expects_lr<void> set_property(const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_property(const std::string_view& key);
			expects_lr<void> set_cache(mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_cache(mediator::cache_policy policy, const std::string_view& key);
			expects_lr<void> set_link(const mediator::wallet_link& value);
			expects_lr<void> clear_link(const mediator::wallet_link& address);
			expects_lr<mediator::wallet_link> get_link(const std::string_view& address);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_owner(const algorithm::pubkeyhash owner, size_t offset, size_t count);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_public_keys(const unordered_set<string>& public_key);
			expects_lr<unordered_map<string, mediator::wallet_link>> get_links_by_addresses(const unordered_set<string>& addresses);

		protected:
			bool reconstruct_storage() override;

		private:
			static std::string_view get_cache_location(mediator::cache_policy policy);
		};
	}
}
#endif