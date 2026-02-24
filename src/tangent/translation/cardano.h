#ifndef TAN_TRANSLATION_CARDANO_H
#define TAN_TRANSLATION_CARDANO_H
#include "../kernel/superchain.h"

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			class cardano : public utxo_translation_unit
			{
			public:
				class nd_call
				{
				public:
					static const char* network_status();
					static const char* block_data();
					static const char* submit_transaction();
				};

			protected:
				chainparams netdata;

			public:
				cardano(const algorithm::asset_id& new_asset) noexcept;
				virtual ~cardano() noexcept = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<vector<block_log>> get_block_transactions(uint64_t block_height, uint64_t block_count) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const std::string_view& tx_id, uint64_t index) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_slot();
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(superchain::prepared_transaction&& prepared) override;
				virtual expects_lr<secret_box> encode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<secret_box> decode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<string> encode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> decode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> encode_address(const std::string_view& public_key_hash) override;
				virtual expects_lr<string> decode_address(const std::string_view& address) override;
				virtual expects_lr<string> encode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<string> decode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<address_map> to_addresses(const std::string_view& public_key) override;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual decimal get_min_protocol_value_per_output(size_t tokens);
				virtual uint256_t to_lovelace(const decimal& value);
				virtual string get_blockchain();
				virtual string get_network();
				virtual size_t get_tx_fee_blocks();
				virtual size_t get_tx_fee_block_delta();
				virtual size_t get_tx_fee_base_size();
			};
		}
	}
}
#endif
