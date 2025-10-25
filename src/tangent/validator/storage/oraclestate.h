#ifndef TAN_STORAGE_ORACLESTATE_H
#define TAN_STORAGE_ORACLESTATE_H
#include "engine.h"
#include "../../kernel/oracle.h"

namespace tangent
{
	namespace storages
	{
		struct oraclestate
		{
		private:
			algorithm::asset_id asset;
			ledger::storage_index_ptr local_storage;
#ifndef NDEBUG
			std::thread::id local_id;
#endif
		public:
			oraclestate(const algorithm::asset_id& new_asset) noexcept;
			oraclestate(const oraclestate&) = delete;
			oraclestate(oraclestate&&) noexcept = delete;
			oraclestate& operator=(const oraclestate&) = delete;
			oraclestate& operator=(oraclestate&&) noexcept = delete;
			~oraclestate() noexcept;
			expects_lr<void> add_utxo(const oracle::coin_utxo& value);
			expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<oracle::coin_utxo> get_stxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<oracle::coin_utxo> get_utxo(const std::string_view& transaction_id, uint64_t index);
			expects_lr<vector<oracle::coin_utxo>> get_utxos(const oracle::wallet_link& link, size_t offset, size_t count);
			expects_lr<void> add_incoming_transaction(const oracle::computed_transaction& value, bool finalized);
			expects_lr<void> add_outgoing_transaction(const oracle::computed_transaction& value, const uint256_t& external_id);
			expects_lr<oracle::computed_transaction> get_computed_transaction(const std::string_view& transaction_id, const uint256_t& external_id);
			expects_lr<vector<oracle::computed_transaction>> finalize_computed_transactions(uint64_t block_height, uint64_t block_latency);
			expects_lr<void> set_property(const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_property(const std::string_view& key);
			expects_lr<void> set_cache(oracle::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_cache(oracle::cache_policy policy, const std::string_view& key);
			expects_lr<void> set_link(const oracle::wallet_link& value);
			expects_lr<void> clear_link(const oracle::wallet_link& address);
			expects_lr<oracle::wallet_link> get_link(const std::string_view& address);
			expects_lr<unordered_map<string, oracle::wallet_link>> get_links_by_owner(const algorithm::pubkeyhash_t& owner, size_t offset, size_t count);
			expects_lr<unordered_map<string, oracle::wallet_link>> get_links_by_public_keys(const unordered_set<string>& public_key);
			expects_lr<unordered_map<string, oracle::wallet_link>> get_links_by_addresses(const unordered_set<string>& addresses);
			ledger::storage_index_ptr& get_storage();
			uint32_t get_queries() const;

		private:
			static std::string_view get_cache_location(oracle::cache_policy policy);
			static bool make_schema(sqlite::connection* connection);
		};
	}
}
#endif