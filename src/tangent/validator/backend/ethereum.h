#ifndef TAN_WARDEN_ETHEREUM_H
#define TAN_WARDEN_ETHEREUM_H
#include "../../kernel/warden.h"

struct btc_chainparams_;

namespace tangent
{
	namespace warden
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
					enum class evm_type
					{
						eip_155,
						eip_1559
					};

					uint256_t nonce = 0;
					uint256_t chain_id = 0;
					gwei256_t gas_base_price = 0;
					gwei256_t gas_price = 0;
					gwei256_t gas_limit = 0;
					wei256_t value = 0;
					address336_t address;
					binary_data_t abi_data;

					evm_signature sign(const binary_data_t& hash, const uint8_t private_key[32]);
					evm_signature presign(const uint8_t signature_r[32], const uint8_t signature_s[32], int recovery_id);
					evm_signed_transaction serialize_and_sign(evm_type type, const uint8_t private_key[32]);
					evm_signed_transaction serialize_and_presign(evm_type type, const uint8_t signature[65]);
					binary_data_t hash(const binary_data_t& serialized_data);
					binary_data_t serialize(evm_type type, evm_signature* signature = nullptr);
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
					static const char* get_transaction_count();
					static const char* get_balance();
					static const char* get_chain_id();
					static const char* block_number();
					static const char* estimate_gas();
					static const char* gas_price();
					static const char* call();
					static const char* send_raw_transaction();
				};

			protected:
				struct
				{
					uint8_t get_logs = 0;
					uint8_t eip_155 = 0;
					uint8_t estimate_gas = 0;
				} legacy;
				chainparams netdata;

			public:
				ethereum(const algorithm::asset_id& new_asset) noexcept;
				virtual ~ethereum() override = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<computed_fee> estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(warden::prepared_transaction&& prepared) override;
				virtual expects_lr<secret_box> encode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<secret_box> decode_secret_key(const secret_box& secret_key) override;
				virtual expects_lr<string> encode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> decode_public_key(const std::string_view& public_key) override;
				virtual expects_lr<string> encode_address(const std::string_view& public_key_hash) override;
				virtual expects_lr<string> decode_address(const std::string_view& address) override;
				virtual expects_lr<string> encode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<string> decode_transaction_id(const std::string_view& transaction_id) override;
				virtual expects_lr<algorithm::composition::cpubkey_t> to_composite_public_key(const std::string_view& public_key) override;
				virtual expects_lr<address_map> to_addresses(const std::string_view& public_key) override;
				virtual const chainparams& get_chainparams() const override;

			public:
				virtual expects_promise_rt<schema*> get_transaction_receipt(const std::string_view& tx_id);
				virtual expects_promise_rt<uint256_t> get_transactions_count(const std::string_view& address);
				virtual expects_promise_rt<uint256_t> get_chain_id();
				virtual expects_promise_rt<string> get_contract_symbol(const std::string_view& contract_address);
				virtual expects_promise_rt<decimal> get_contract_divisibility(const std::string_view& contract_address);
				virtual const char* get_token_transfer_signature();
				virtual bool is_token_transfer(const std::string_view& function_signature);
				virtual string encode_0xhex(const std::string_view& data);
				virtual string encode_0xhex_checksum(const uint8_t* data, size_t data_size);
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