#ifndef TAN_STORAGE_ORACLESTATE_H
#define TAN_STORAGE_ORACLESTATE_H
#include "engine.h"
#include "../kernel/superchain.h"

namespace tangent
{
	namespace storages
	{
		struct superchainstate
		{
		private:
			algorithm::asset_id asset;
			ledger::storage_index_ptr local_storage;
#ifndef NDEBUG
			std::thread::id local_id;
#endif
		public:
			superchainstate(const algorithm::asset_id& new_asset) noexcept;
			superchainstate(const superchainstate&) = delete;
			superchainstate(superchainstate&&) noexcept = delete;
			superchainstate& operator=(const superchainstate&) = delete;
			superchainstate& operator=(superchainstate&&) noexcept = delete;
			~superchainstate() noexcept;
			expects_lr<void> add_utxo(const superchain::coin_utxo& value);
			expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<superchain::coin_utxo> get_stxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<superchain::coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<superchain::coin_utxo>> get_utxos(const superchain::wallet_link& link, size_t offset, size_t count);
			expects_lr<void> add_incoming_transaction(const superchain::computed_transaction& value, bool finalized);
			expects_lr<void> add_outgoing_transaction(const superchain::computed_transaction& value, const uint256_t& external_id);
			expects_lr<superchain::computed_transaction> get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id, const uint256_t& optimized_id);
			expects_lr<vector<superchain::computed_transaction>> finalize_computed_transactions(uint64_t block_height, uint64_t block_latency);
			expects_lr<void> set_property(const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_property(const std::string_view& key);
			expects_lr<void> set_cache(superchain::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_cache(superchain::cache_policy policy, const std::string_view& key);
			expects_lr<void> set_link(const superchain::wallet_link& value);
			expects_lr<void> clear_link(const superchain::wallet_link& address);
			expects_lr<superchain::wallet_link> get_link(const std::string_view& address);
			expects_lr<unordered_map<string, superchain::wallet_link>> get_links_by_owner(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count);
			expects_lr<unordered_map<string, superchain::wallet_link>> get_links_by_public_keys(const unordered_set<string>& public_key);
			expects_lr<unordered_map<string, superchain::wallet_link>> get_links_by_addresses(const unordered_set<string>& addresses);
			ledger::storage_index_ptr& get_storage();
			uint32_t get_queries() const;

		private:
			static std::string_view get_cache_location(superchain::cache_policy policy);
			static bool make_schema(sqlite::connection* connection);
		};
	}
}
#endif