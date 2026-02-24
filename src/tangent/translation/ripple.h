#ifndef TAN_TRANSLATION_RIPPLE_H
#define TAN_TRANSLATION_RIPPLE_H
#include "../kernel/superchain.h"

struct sc_chainparams_;

namespace tangent
{
	namespace superchain
	{
		namespace translations
		{
			class ripple : public translation_unit
			{
			public:
				struct transaction_buffer
				{
					uint16_t transaction_type = 0;
					uint32_t flags = 0;
					uint32_t sequence = 0;
					uint32_t destination_tag = 0;
					uint32_t last_ledger_sequence = 0;
					struct
					{
						uint64_t base_value = 0;
						decimal token_value = decimal::nan();
						string asset;
						string issuer;
					} amount;
					uint64_t fee = 0;
					string signing_pub_key;
					string txn_signature;
					string account;
					string destination;
				};

				struct account_info
				{
					decimal balance;
					uint64_t sequence = 0;
				};

				struct account_token_info
				{
					decimal balance;
				};

				struct ledger_sequence_info
				{
					uint64_t index = 0;
					uint64_t sequence = 0;
				};

			public:
				class nd_call
				{
				public:
					static const char* ledger();
					static const char* account_info();
					static const char* account_objects();
					static const char* server_info();
					static const char* submit_transaction();
				};

			protected:
				chainparams netdata;

			public:
				ripple(const algorithm::asset_id& new_asset) noexcept;
				virtual ~ripple() override = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<vector<block_log>> get_block_transactions(uint64_t block_height, uint64_t block_count) override;
				virtual expects_promise_rt<extended_computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, format::tree& transaction_data) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
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
				virtual expects_promise_rt<account_info> get_account_info(const std::string_view& address);
				virtual expects_promise_rt<account_token_info> get_account_token_info(const algorithm::asset_id& for_asset, const std::string_view& address);
				virtual expects_promise_rt<ledger_sequence_info> get_ledger_sequence_info();
				virtual vector<uint8_t> tx_serialize(transaction_buffer* tx_data, bool signing_data);
				virtual string tx_hash(const vector<uint8_t>& tx_blob);
				virtual decimal get_base_fee_xrp();
				virtual decimal from_drop(const uint256_t& value);
				virtual uint256_t to_drop(const decimal& value);
				virtual const sc_chainparams_* get_chain();
			};
		}
	}
}
#endif