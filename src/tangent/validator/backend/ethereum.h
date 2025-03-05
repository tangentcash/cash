#ifndef TAN_MEDIATOR_ETHEREUM_H
#define TAN_MEDIATOR_ETHEREUM_H
#include "../../kernel/mediator.h"

struct btc_chainparams_;

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class ethereum : public relay_backend
			{
			public:
				typedef uint256_t wei256_t;
				typedef uint256_t gwei256_t;
				typedef string address336_t;
				typedef string evm_abi_t;
				typedef string binary_data_t;

			public:
				struct evm_signature
				{
					binary_data_t r;
					binary_data_t s;
					uint32_t v = 0;
				};

				struct evm_signed_transaction
				{
					evm_signature signature;
					binary_data_t data;
					binary_data_t id;
				};

				struct evm_transaction
				{
					uint256_t nonce = 0;
					uint256_t chain_id = 0;
					gwei256_t gas_price = 0;
					gwei256_t gas_limit = 0;
					wei256_t value = 0;
					address336_t address;
					binary_data_t abi_data;

					evm_signature sign(const binary_data_t& hash, const uint8_t private_key[32]);
					evm_signed_transaction serialize_and_sign(const uint8_t private_key[32]);
					binary_data_t hash(const binary_data_t& serialized_data);
					binary_data_t serialize(evm_signature* signature = nullptr);
				};

			public:
				class sc_function
				{
				public:
					static const char* symbol();
					static const char* decimals();
					static const char* balance_of();
					static const char* transfer();
					static const char* transfer_from();
				};

				class sc_call
				{
				public:
					static binary_data_t symbol();
					static binary_data_t decimals();
					static binary_data_t balance_of(const string& address);
					static binary_data_t transfer(const string& address, const uint256_t& value);
				};

				class nd_call
				{
				public:
					static const char* get_block_by_number();
					static const char* get_transaction_receipt();
					static const char* get_transaction_by_hash();
					static const char* get_transaction_count();
					static const char* get_balance();
					static const char* get_chain_id();
					static const char* block_number();
					static const char* estimate_gas();
					static const char* gas_price();
					static const char* call();
					static const char* send_raw_transaction();
				};

			private:
				struct
				{
					uint8_t get_logs = 0;
				} legacy;

			protected:
				chainparams netdata;

			public:
				ethereum() noexcept;
				virtual ~ethereum() override = default;
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
				virtual string get_checksum_hash(const std::string_view& value) const override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual expects_promise_rt<schema*> get_transaction_receipt(const algorithm::asset_id& asset, const std::string_view& tx_id);
				virtual expects_promise_rt<uint256_t> get_transactions_count(const algorithm::asset_id& asset, const std::string_view& address);
				virtual expects_promise_rt<uint256_t> get_chain_id(const algorithm::asset_id& asset);
				virtual expects_promise_rt<string> get_contract_symbol(const algorithm::asset_id& asset, backends::ethereum* implementation, const std::string_view& contract_address);
				virtual expects_promise_rt<decimal> get_contract_divisibility(const algorithm::asset_id& asset, backends::ethereum* implementation, const std::string_view& contract_address);
				virtual const char* get_token_transfer_signature();
				virtual bool is_token_transfer(const std::string_view& function_signature);
				virtual void generate_public_key_hash_from_public_key(const uint8_t public_key[64], char out_public_key_hash[20]);
				virtual void generate_private_key_data_from_private_key(const char* private_key, size_t private_key_size, uint8_t out_private_key_hash[20]);
				virtual void generate_message_hash(const std::string_view& input, uint8_t output[32]);
				virtual string get_message_magic();
				virtual string generate_pkh_address(const char* public_key_hash20);
				virtual string generate_unchecked_address(const std::string_view& data);
				virtual string generate_checksum_address(const std::string_view& address);
				virtual string encode_eth_address(const std::string_view& eth_address);
				virtual string decode_non_eth_address(const std::string_view& non_eth_address);
				virtual string normalize_topic_address(const std::string_view& address);
				virtual string uint256_to_hex(const uint256_t& data);
				virtual string get_raw_gas_limit(schema* tx_data);
				virtual uint256_t hex_to_uint256(const std::string_view& data);
				virtual uint256_t from_eth(const decimal& value, const decimal& divisibility = 1);
				virtual decimal to_eth(const uint256_t& value, const decimal& divisibility = 1);
				virtual decimal get_divisibility_gwei();
				virtual uint256_t get_eth_transfer_gas_limit_gwei();
				virtual uint256_t get_erc20_transfer_gas_limit_gwei();
				virtual const btc_chainparams_* get_chain();
			};
		}
	}
}
#endif