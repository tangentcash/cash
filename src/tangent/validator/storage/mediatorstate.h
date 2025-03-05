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
			expects_lr<void> add_master_wallet(const mediator::master_wallet& value);
			expects_lr<mediator::master_wallet> get_master_wallet();
			expects_lr<mediator::master_wallet> get_master_wallet_by_hash(const uint256_t& master_wallet_hash);
			expects_lr<void> add_derived_wallet(const mediator::master_wallet& parent, const mediator::derived_signing_wallet& value);
			expects_lr<mediator::derived_signing_wallet> get_derived_wallet(const uint256_t& master_wallet_hash, uint64_t address_index);
			expects_lr<void> add_utxo(const mediator::index_utxo& value);
			expects_lr<void> remove_utxo(const std::string_view& transaction_id, uint32_t index);
			expects_lr<mediator::index_utxo> get_stxo(const std::string_view& transaction_id, uint32_t index);
			expects_lr<mediator::index_utxo> get_utxo(const std::string_view& transaction_id, uint32_t index);
			expects_lr<vector<mediator::index_utxo>> get_utxos(const std::string_view& binding, size_t offset, size_t count);
			expects_lr<void> add_incoming_transaction(const mediator::incoming_transaction& value, uint64_t block_id);
			expects_lr<void> add_outgoing_transaction(const mediator::incoming_transaction& value, const uint256_t external_id);
			expects_lr<mediator::incoming_transaction> get_transaction(const std::string_view& transaction_id, const uint256_t& external_id);
			expects_lr<vector<mediator::incoming_transaction>> approve_transactions(uint64_t block_height, uint64_t block_latency);
			expects_lr<void> set_property(const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_property(const std::string_view& key);
			expects_lr<void> set_cache(mediator::cache_policy policy, const std::string_view& key, uptr<schema>&& value);
			expects_lr<schema*> get_cache(mediator::cache_policy policy, const std::string_view& key);
			expects_lr<void> set_address_index(const std::string_view& address, const mediator::index_address& value);
			expects_lr<void> clear_address_index(const std::string_view& address);
			expects_lr<mediator::index_address> get_address_index(const std::string_view& address);
			expects_lr<unordered_map<string, mediator::index_address>> get_address_indices(const unordered_set<string>& addresses);
			expects_lr<vector<string>> get_address_indices();

		protected:
			string get_address_location(const std::string_view& address);
			string get_transaction_location(const std::string_view& transaction_id);
			string get_coin_location(const std::string_view& transaction_id, uint32_t index);
			bool reconstruct_storage() override;

		private:
			static std::string_view get_cache_location(mediator::cache_policy policy);
		};
	}
}
#endif