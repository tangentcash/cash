#ifndef TAN_MEDIATOR_MONERO_H
#define TAN_MEDIATOR_MONERO_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class monero : public relay_backend_utxo
			{
			public:
				class nd_call
				{
				public:
					static const char* json_rpc();
					static const char* send_raw_transaction();
					static const char* get_transactions();
					static const char* get_height();
				};

				class nd_call_restricted
				{
				public:
					static const char* get_block();
					static const char* get_fee_estimate();
				};

			protected:
				chainparams netdata;

			public:
				monero() noexcept;
				virtual ~monero() noexcept = default;
				virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset) override;
				virtual expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id) override;
				virtual expects_promise_rt<vector<incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<base_fee> estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const algorithm::asset_id& asset, const std::string_view& tx_id, uint32_t index) override;
				virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) override;
				virtual expects_lr<master_wallet> new_master_wallet(const std::string_view& seed) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key) override;
				virtual expects_lr<derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key) override;
				virtual expects_lr<string> new_public_key_hash(const std::string_view& address) override;
				virtual expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key) override;
				virtual expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature) override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const btc_chainparams_* get_chain();
				virtual const chainparams& get_chainparams() const override;
				virtual uint64_t get_retirement_block_number() const override;

			public:
				virtual bool message_hash(uint8_t hash[32], const uint8_t* message, size_t message_size, const uint8_t public_spend_key[32], const uint8_t public_view_key[32], const uint8_t mode);
				virtual void derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32]);
				virtual void derive_known_public_view_key(const uint8_t public_spend_key[32], uint8_t public_view_key[32]);
				virtual uint64_t get_network_type() const;
			};
		}
	}
}
#endif
