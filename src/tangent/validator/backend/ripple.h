#ifndef TAN_ORACLE_RIPPLE_H
#define TAN_ORACLE_RIPPLE_H
#include "../../kernel/oracle.h"

struct btc_chainparams_;

namespace tangent
{
	namespace oracle
	{
		namespace backends
		{
			class ripple : public relay_backend
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
				virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<computed_fee> estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee, bool inclusive_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(oracle::prepared_transaction&& prepared) override;
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
				virtual const btc_chainparams_* get_chain();
			};
		}
	}
}
#endif