#ifndef TAN_MEDIATOR_CARDANO_H
#define TAN_MEDIATOR_CARDANO_H
#include "../../kernel/mediator.h"

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class cardano : public relay_backend_utxo
			{
			public:
				class nd_call
				{
				public:
					static const char* network_status();
					static const char* block_data();
					static const char* transaction_data();
					static const char* submit_transaction();
				};

			private:
				struct
				{
					uint64_t block_height = 0;
					size_t transactions = 0;
					size_t total_size = 0;
				} tx_analytics;

			protected:
				chainparams netdata;

			public:
				cardano() noexcept;
				virtual ~cardano() noexcept = default;
				virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset) override;
				virtual expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id) override;
				virtual expects_promise_rt<vector<incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<base_fee> estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const algorithm::asset_id& asset, const std::string_view& tx_id, uint32_t index) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_slot(const algorithm::asset_id& asset);
				virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) override;
				virtual expects_lr<master_wallet> new_master_wallet(const std::string_view& seed) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key) override;
				virtual expects_lr<derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key) override;
				virtual expects_lr<string> new_public_key_hash(const std::string_view& address) override;
				virtual expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key) override;
				virtual expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature) override;
				virtual expects_lr<void> verify_node_compatibility(server_relay* node) override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual bool decode_private_key(const std::string_view& data, uint8_t private_key[96], size_t* private_key_size);
				virtual bool decode_public_key(const std::string_view& data, uint8_t public_key[64], size_t* public_key_size);
				virtual decimal get_min_value_per_output();
				virtual uint256_t to_lovelace(const decimal& value);
				virtual uint64_t get_min_protocol_fee_a();
				virtual uint64_t get_min_protocol_fee_b();
				virtual size_t get_block_slot_offset();
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
