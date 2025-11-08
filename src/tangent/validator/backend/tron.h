#ifndef TAN_ORACLE_TRON_H
#define TAN_ORACLE_TRON_H
#include "ethereum.h"

namespace tangent
{
	namespace oracle
	{
		namespace backends
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
					static const char* get_block();
				};

			public:
				tron(const algorithm::asset_id& new_asset) noexcept;
				virtual ~tron() override = default;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const decimal& max_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(oracle::prepared_transaction&& prepared) override;
				virtual expects_lr<void> verify_node_compatibility(server_relay* node) override;
				virtual const btc_chainparams_* get_chain() override;

			public:
				virtual expects_promise_rt<trx_tx_block_header_info> get_block_header_for_tx();
				virtual string encode_eth_address(const std::string_view& eth_address) override;
				virtual string decode_non_eth_address(const std::string_view& non_eth_address) override;
				virtual string decode_non_eth_address_pf(const std::string_view& non_eth_address);
				virtual decimal get_divisibility_gwei() override;
			};
		}
	}
}
#endif