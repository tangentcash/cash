#ifndef TAN_TRANSLATION_TRON_H
#define TAN_TRANSLATION_TRON_H
#include "ethereum.h"

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			class tron : public ethereum
			{
			public:
				struct trx_tx_block_header_info
				{
					string ref_block_bytes;
					string ref_block_hash;
					int64_t expiration;
					int64_t timestamp;
				};

			public:
				class trx_nd_call
				{
				public:
					static const char* broadcast_transaction();
					static const char* get_transaction_by_id();
					static const char* get_transaction_info_by_id();
					static const char* get_block();
				};

			public:
				tron(const algorithm::asset_id& new_asset) noexcept;
				virtual ~tron() override = default;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<vector<block_log>> get_block_transactions(uint64_t block_height, uint64_t block_count) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(superchain::prepared_transaction&& prepared) override;
				virtual const sc_chainparams_* get_chain() override;

			public:
				virtual expects_promise_rt<trx_tx_block_header_info> get_block_header_for_tx();
				virtual string encode_eth_address(const std::string_view& eth_address) override;
				virtual string decode_non_eth_address(const std::string_view& non_eth_address) override;
				virtual string decode_non_eth_address_pf(const std::string_view& non_eth_address, bool tron_prefix = true);
				virtual decimal get_divisibility_gwei() override;
			};
		}
	}
}
#endif