#ifndef TAN_MEDIATOR_STELLAR_H
#define TAN_MEDIATOR_STELLAR_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class stellar : public relay_backend
			{
			public:
				enum class asset_type : uint32_t
				{
					ASSET_TYPE_NATIVE = 0,
					ASSET_TYPE_CREDIT_ALPHANUM4 = 1,
					ASSET_TYPE_CREDIT_ALPHANUM12 = 2
				};

			public:
				struct chain_info
				{
					uint8_t ed25519_public_key = 6 << 3;
					uint8_t ed25519_secret_seed = 18 << 3;
					uint8_t med25519_public_key = 12 << 3;
					uint8_t pre_auth_tx = 19 << 3;
					uint8_t sha256_hash = 23 << 3;
				};

				struct chain_config
				{
					chain_info mainnet;
					chain_info testnet;
					chain_info regtest;
				};

				struct asset_info
				{
					string type;
					string code;
					string issuer;
				};

				struct asset_balance
				{
					asset_info info;
					decimal balance;
				};

				struct account_info
				{
					unordered_map<string, asset_balance> balances;
					uint64_t sequence = 0;
				};


			public:
				class nd_call
				{
				public:
					static string get_ledger(uint64_t block_height);
					static string get_ledger_operations(uint64_t block_height);
					static string get_operations(const std::string_view& tx_id);
					static string get_transactions(const std::string_view& tx_id);
					static string get_accounts(const std::string_view& address);
					static string get_assets(const std::string_view& issuer, const std::string_view& code);
					static const char* get_last_ledger();
					static const char* submit_transaction();
				};

			protected:
				chain_config config;
				chainparams netdata;

			public:
				stellar(chain_config* config = nullptr) noexcept;
				virtual ~stellar() override = default;
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
				virtual expects_promise_rt<asset_info> get_asset_info(const algorithm::asset_id& asset, const std::string_view& address, const std::string_view& code);
				virtual expects_promise_rt<account_info> get_account_info(const algorithm::asset_id& asset, const std::string_view& address);
				virtual expects_promise_rt<string> get_transaction_memo(const algorithm::asset_id& asset, const std::string_view& tx_id);
				virtual expects_promise_rt<bool> is_account_exists(const algorithm::asset_id& asset, const std::string_view& address);
				virtual string get_network_passphrase();
				virtual decimal from_stroop(const uint256_t& value);
				virtual uint256_t to_stroop(const decimal& value);
				virtual uint64_t get_base_stroop_fee();
				virtual uint16_t calculate_checksum(const uint8_t* value, size_t size);
				virtual bool decode_private_key(const std::string_view& data, uint8_t private_key[64]);
				virtual bool decode_key(uint8_t version, const std::string_view& data, uint8_t* out_value, size_t* out_size);
				virtual bool decode_base32(const std::string_view& data, uint8_t* out_value, size_t* out_size);
				virtual string encode_private_key(uint8_t* private_key, size_t private_key_size);
				virtual string encode_key(uint8_t version, const uint8_t* value, size_t size);
				virtual string encode_base32(const uint8_t* value, size_t size);
				virtual const btc_chainparams_* get_chain();
				virtual chain_info& get_params();
			};
		}
	}
}
#endif