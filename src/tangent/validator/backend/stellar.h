#ifndef TAN_ORACLE_STELLAR_H
#define TAN_ORACLE_STELLAR_H
#include "../../kernel/oracle.h"

struct btc_chainparams_;

namespace tangent
{
	namespace oracle
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
					unordered_map<algorithm::asset_id, asset_balance> balances;
					uint64_t sequence = 0;
				};

			public:
				class nd_call
				{
				public:
					static string get_ledger(uint64_t block_height);
					static string get_ledger_operations(uint64_t block_height);
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
				stellar(const algorithm::asset_id& new_asset, chain_config* config = nullptr) noexcept;
				virtual ~stellar() override = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const decimal& max_fee) override;
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
				virtual expects_promise_rt<asset_info> get_asset_info(const std::string_view& address, const std::string_view& code);
				virtual expects_promise_rt<account_info> get_account_info(const std::string_view& address);
				virtual expects_promise_rt<string> get_transaction_memo(const std::string_view& tx_id);
				virtual expects_promise_rt<bool> is_account_exists(const std::string_view& address);
				virtual string get_network_passphrase();
				virtual decimal from_stroop(const uint256_t& value);
				virtual uint256_t to_stroop(const decimal& value);
				virtual uint64_t get_base_stroop_fee();
				virtual uint16_t calculate_checksum(const uint8_t* value, size_t size);
				virtual bool decode_key(uint8_t version, const std::string_view& data, uint8_t* out_value, size_t* out_size);
				virtual string encode_key(uint8_t version, const uint8_t* value, size_t size);
				virtual const btc_chainparams_* get_chain();
				virtual chain_info& get_params();
			};
		}
	}
}
#endif