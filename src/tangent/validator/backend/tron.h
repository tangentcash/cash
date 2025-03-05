#ifndef TAN_MEDIATOR_TRON_H
#define TAN_MEDIATOR_TRON_H
#include "ethereum.h"

namespace tangent
{
	namespace mediator
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
				tron() noexcept;
				virtual ~tron() override = default;
				virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& seed, option<string>&& address) override;
				virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) override;
				virtual expects_lr<string> new_public_key_hash(const std::string_view& address) override;
				virtual expects_lr<void> verify_node_compatibility(server_relay* node) override;
				virtual string get_message_magic() override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const btc_chainparams_* get_chain() override;

			public:
				virtual expects_promise_rt<trx_tx_block_header_info> get_block_header_for_tx(const algorithm::asset_id& asset);
				virtual void generate_message_hash(const string& input, uint8_t output[32]);
				virtual string encode_eth_address(const std::string_view& eth_address) override;
				virtual string decode_non_eth_address(const std::string_view& non_eth_address) override;
				virtual string decode_non_eth_address_pf(const std::string_view& non_eth_address);
				virtual decimal get_divisibility_gwei() override;
			};
		}
	}
}
#endif