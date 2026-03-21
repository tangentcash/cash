#ifndef TAN_TRANSLATION_MONERO_H
#define TAN_TRANSLATION_MONERO_H
#include "../kernel/superchain.h"

struct sc_chainparams_;

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			class monero : public utxo_translation_unit
			{
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
					static const char* get_o_indexes();
				};

				struct pseudo_transaction_input
				{
					vector<uint64_t> key_offsets;
					uint8_t key_image[32] = { 0 };
					uint64_t amount = 0;
					bool is_coinbase;
				};

				struct pseudo_transaction_output
				{
					uint8_t ring_out_key[32] = { 0 };
					uint8_t key[32] = { 0 };
					uint8_t view_tag = 0;
					uint64_t amount = 0;
					string ecdh_amount;
					string ecdh_mask;
				};

				struct pseudo_transaction_body
				{
					btree_map<uint8_t, algorithm::storage_type<uint8_t, 64>> output_addresses;
					vector<algorithm::storage_type<uint8_t, 32>> public_keys;
					vector<size_t> key_offset_indices;
					string encrypted_payment_id;
					string payment_id;
					string hash;
				};

				struct transaction_data
				{
					struct bulletproof_plus
					{
						uint8_t a[32], a1[32], b[32];
						uint8_t r1[32], s1[32], d1[32];
						vector<std::array<uint8_t, 32>> l, r;
					};

					struct txin_to_key
					{
						struct clsag_proof
						{
							vector<std::array<uint8_t, 32>> s;
							uint8_t c1[32];
							uint8_t d[32];
						} clsag;
						struct
						{
							uint8_t blinding_factor[32];
							uint8_t mask[32];
						} pseudo_out;
						vector<uint64_t> key_offsets;
						uint8_t key_image[32];
						size_t key_offset_out;
					};

					struct tx_out
					{
						struct tx_out_to_key
						{
							uint8_t key[32];
						} target;
						struct
						{
							uint8_t amount[32];
						} ecdh_info;
						struct
						{
							uint8_t blinding_factor[32];
							uint8_t mask[32];
						} out_pk;
					};

					vector<txin_to_key> vin;
					vector<tx_out> vout;
					vector<uint8_t> extra;
					bulletproof_plus bpp;
					uint64_t fee;
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
				virtual expects_lr<secret_box> encode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<secret_box> decode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<string> encode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> decode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> encode_address(const std::string_view& public_key_hash) override;
				virtual expects_lr<string> decode_address(const std::string_view& address) override;
				virtual expects_lr<string> encode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<string> decode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<address_map> to_addresses(const std::string_view& public_key) override;
				virtual const sc_chainparams_* get_chain();
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual expects_promise_rt<vector<uint64_t>> get_output_indices(const std::string_view& transaction_id);
				virtual bool generate_key_image(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], const uint8_t public_view_key[32], const uint8_t private_spend_key[32], uint8_t key_image[32]);
				virtual bool generate_derivation_key(const uint8_t transaction_public_key[32], const uint8_t private_view_key[32], uint8_t derivation_key[32]);
				virtual void derive_private_key(const uint8_t derivation_scalar[32], const uint8_t private_spend_key[32], uint8_t private_key[32]);
				virtual bool derive_public_key(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], uint8_t public_key[32]);
				virtual void derivation_to_scalar(const uint8_t derivation_key[32], uint64_t derivation_index, uint8_t derivation_scalar[32]);
				virtual void hash_to_scalar(const uint8_t* buffer, size_t buffer_size, uint8_t scalar[32]);
				virtual void hash_to_point(const uint8_t* buffer, size_t buffer_size, uint8_t point[32]);
				virtual bool pedersen_commit(uint8_t mask[32], uint8_t amount[32], uint8_t commitment[32]);
				virtual void derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32]);
				virtual void derive_known_public_view_key(const uint8_t public_spend_key[32], uint8_t public_view_key[32]);
				virtual void derive_stealth_address(const uint8_t public_view_key[32], const uint8_t public_spend_key[32], const uint8_t tx_private_key[32], size_t index, uint8_t stealth_address[32]);
				virtual void derive_amount_256(uint64_t amount_in, uint8_t amount_out[32]);
				virtual pseudo_transaction_body decode_pseudo_transaction_info(const format::tree& transaction_data);
				virtual vector<pseudo_transaction_input> decode_pseudo_transaction_inputs(const format::tree& transaction_data);
				virtual vector<pseudo_transaction_output> decode_pseudo_transaction_outputs(const format::tree& transaction_data);
				virtual decimal from_piconero(const uint256_t& value);
				virtual uint256_t to_piconero(const decimal& value);
				virtual uint64_t get_network_type() const;
			};
		}
	}
}
#endif
