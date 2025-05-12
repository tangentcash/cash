#ifndef TAN_STORAGE_WARDENSTATE_H
#define TAN_STORAGE_WARDENSTATE_H
#include "engine.h"
#include "../../kernel/warden.h"

namespace tangent
{
	namespace storages
	{
		struct wardenstate : ledger::mutable_storage
		{
		private:
			algorithm::asset_id asset;
			std::string_view label;

		public:
			wardenstate(const std::string_view& new_label, const algorithm::asset_id& new_asset) noexcept;
			virtual ~wardenstate() noexcept = default;
			expects_lr<void> add_utxo(const warden::coin_utxo& value);
			expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<warden::coin_utxo> get_stxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<warden::coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<warden::coin_utxo>> get_utxos(const warden::wallet_link& link, size_t offset, size_t count);
			expects_lr<void> add_computed_transaction(const warden::computed_transaction& value);
			expects_lr<void> add_finalized_transaction(const warden::computed_transaction& value, const uint256_t& external_id);
			expects_lr<warden::computed_transaction> get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id);
			expects_lr<vector<warden::computed_transaction>> finalize_computed_transactions(uint64_t block_height, uint64_t block_latency);
			expects_lr<void> set_property(const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_property(const std::string_view& key);
			expects_lr<void> set_cache(warden::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_cache(warden::cache_policy policy, const std::string_view& key);
			expects_lr<void> set_link(const warden::wallet_link& value);
			expects_lr<void> clear_link(const warden::wallet_link& address);
			expects_lr<warden::wallet_link> get_link(const std::string_view& address);
			expects_lr<unordered_map<string, warden::wallet_link>> get_links_by_owner(const algorithm::pubkeyhash owner, size_t offset, size_t count);
			expects_lr<unordered_map<string, warden::wallet_link>> get_links_by_public_keys(const unordered_set<string>& public_key);
			expects_lr<unordered_map<string, warden::wallet_link>> get_links_by_addresses(const unordered_set<string>& addresses);

		protected:
			bool reconstruct_storage() override;

		private:
			static std::string_view get_cache_location(warden::cache_policy policy);
		};
	}
}
#endif