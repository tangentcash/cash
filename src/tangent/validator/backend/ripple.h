#ifndef TAN_MEDIATOR_RIPPLE_H
#define TAN_MEDIATOR_RIPPLE_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace tangent
{
	namespace mediator
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
					static const char* transaction();
					static const char* account_info();
					static const char* account_objects();
					static const char* server_info();
					static const char* submit_transaction();
				};

			protected:
				chainparams netdata;

			public:
				ripple() noexcept;
				virtual ~ripple() override = default;
				virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset) override;
				virtual expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id) override;
				virtual expects_promise_rt<vector<incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<base_fee> estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& asset, const dynamic_wallet& wallet, option<string>&& address) override;
				virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) override;
				virtual expects_lr<master_wallet> new_master_wallet(const std::string_view& seed) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key) override;
				virtual expects_lr<derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key) override;
				virtual expects_lr<string> new_public_key_hash(const std::string_view& address) override;
				virtual expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key) override;
				virtual expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature) override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual expects_promise_rt<account_info> get_account_info(const algorithm::asset_id& asset, const std::string_view& address);
				virtual expects_promise_rt<account_token_info> get_account_token_info(const algorithm::asset_id& asset, const std::string_view& address);
				virtual expects_promise_rt<ledger_sequence_info> get_ledger_sequence_info(const algorithm::asset_id& asset);
				virtual bool tx_sign_and_verify(transaction_buffer* tx_data, const std::string_view& encoded_public_key, const secret_box& encoded_private_key);
				virtual vector<uint8_t> tx_serialize(transaction_buffer* tx_data, bool signing_data);
				virtual string tx_hash(const vector<uint8_t>& tx_blob);
				virtual decimal get_base_fee_xrp();
				virtual decimal from_drop(const uint256_t& value);
				virtual uint256_t to_drop(const decimal& value);
				virtual string encode_secret_key(uint8_t* secret_key, size_t secret_key_size);
				virtual string encode_public_key(uint8_t* public_key, size_t public_key_size);
				virtual string encode_private_key(uint8_t* private_key, size_t private_key_size);
				virtual string encode_and_hash_public_key(uint8_t* public_key, size_t public_key_size);
				virtual bool decode_secret_key(const std::string_view& data, uint8_t secret_key[16]);
				virtual bool decode_private_key(const std::string_view& data, uint8_t private_key[65]);
				virtual bool decode_public_key(const std::string_view& data, uint8_t public_key[33]);
				virtual bool decode_public_key_hash(const std::string_view& data, uint8_t public_key_hash[20]);
				virtual const btc_chainparams_* get_chain();
			};
		}
	}
}
#endif