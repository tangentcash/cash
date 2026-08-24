#ifndef TAN_TRANSLATION_MONERO_H
#define TAN_TRANSLATION_MONERO_H
#include "../kernel/superchain.h"

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			class monero : public utxo_translation_unit
			{
			public:
				enum TX_EXTRA_TAG
				{
					TX_EXTRA_TAG_PADDING = 0x00,
					TX_EXTRA_TAG_PUBKEY = 0x01,
					TX_EXTRA_NONCE = 0x02,
					TX_EXTRA_NONCE_PAYMENT_ID = 0x00,
					TX_EXTRA_NONCE_ENCRYPTED_PAYMENT_ID = 0x01,
					TX_EXTRA_MERGE_MINING_TAG = 0x03,
					TX_EXTRA_TAG_ADDITIONAL_PUBKEYS = 0x04,
					TX_EXTRA_MYSTERIOUS_MINERGATE_TAG = 0xDE,
					TX_EXTRA_PADDING_MAX_COUNT = 0xFF,
				};

			public:
				class nd_call
				{
				public:
					static const char* json_rpc();
					static const char* send_raw_transaction();
					static const char* get_transactions();
					static const char* get_height();
					static const char* get_block();
					static const char* get_fee_estimate();
					static const char* get_output_distribution();
					static const char* get_outs();
					static const char* get_o_indexes();
				};

				struct pseudo_transaction
				{
					struct input
					{
						vector<uint64_t> key_offsets;
						uint8_t key_image[32] = { 0 };
						uint64_t amount = 0;
						bool is_coinbase;
					};

					struct output
					{
						uint8_t ring_out_key[32] = { 0 };
						uint8_t key[32] = { 0 };
						uint8_t view_tag = 0;
						uint64_t amount = 0;
						string ecdh_amount;
						string ecdh_mask;
					};

					vector<algorithm::storage_type<uint8_t, 32>> public_keys;
					vector<input> inputs;
					vector<output> outputs;
					string to_address;
					string encrypted_payment_id;
					string payment_id;
					string hash;
					decimal fee;
				};

				struct address_prefix
				{
					uint8_t standard_address = 0;
					uint8_t integrated_address = 0;
					uint8_t subaddress = 0;
				};

			protected:
				chainparams netdata;

			public:
				monero(const algorithm::asset_id& new_asset) noexcept;
				virtual ~monero() noexcept = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<vector<block_log>> get_block_transactions(uint64_t block_height, uint64_t block_count) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const std::string_view& tx_id, uint64_t index) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const value_transfer& to, const decimal& max_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(superchain::prepared_transaction&& prepared) override;
				virtual expects_lr<void> update_utxo(const computed_transaction& computed, const finalized_transaction* finalized) override;
				virtual expects_lr<secret_box> encode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<secret_box> decode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<string> encode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> decode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> encode_address(const std::string_view& public_key_hash) override;
				virtual expects_lr<string> decode_address(const std::string_view& address) override;
				virtual expects_lr<string> encode_signature(const std::string_view& signature) override;
				virtual expects_lr<string> decode_signature(const std::string_view& signature) override;
				virtual expects_lr<string> encode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<string> decode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<address_map> to_addresses(const std::string_view& public_key) override;
				virtual address_prefix get_address_prefix() const;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual expects_promise_rt<vector<uint64_t>> get_output_indices(const std::string_view& transaction_id);
				virtual pseudo_transaction decode_pseudo_transaction(const format::tree& transaction_data);
				virtual decimal from_atomic(const uint256_t& value);
				virtual uint256_t to_atomic(const decimal& value);
			};
		}
	}
}
#endif
