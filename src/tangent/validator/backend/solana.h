#ifndef TAN_MEDIATOR_SOLANA_H
#define TAN_MEDIATOR_SOLANA_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class solana : public relay_backend
			{
			public:
				struct token_account
				{
					string program_id;
					string account;
					decimal balance;
					decimal divisibility;
				};

			public:
				class nd_call
				{
				public:
					static string get_token_metadata(const std::string_view& mint);
					static const char* get_token_balance();
					static const char* get_balance();
					static const char* get_block_hash();
					static const char* get_block_number();
					static const char* get_block();
					static const char* get_transaction();
					static const char* send_transaction();
				};

			protected:
				chainparams netdata;

			public:
				solana() noexcept;
				virtual ~solana() override = default;
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
				virtual expects_promise_rt<string> get_token_symbol(const std::string_view& mint);
				virtual expects_promise_rt<token_account> get_token_balance(const algorithm::asset_id& asset, const std::string_view& mint, const std::string_view& owner);
				virtual expects_promise_rt<decimal> get_balance(const algorithm::asset_id& asset, const std::string_view& owner);
				virtual expects_promise_rt<string> get_recent_block_hash(const algorithm::asset_id& asset);
				virtual bool decode_private_key(const std::string_view& data, uint8_t private_key[64]);
				virtual bool decode_secret_or_public_key(const std::string_view& data, uint8_t secret_key[32]);
				virtual const btc_chainparams_* get_chain();
			};
		}
	}
}
#endif