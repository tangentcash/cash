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

				struct token_transfer
				{
					string from_account;
					string to_account;
					decimal value;
				};

				struct sol_transaction
				{
					string token_program_address;
					string from_token_address;
					string to_token_address;
					string from_address;
					string to_address;
					string recent_block_hash;
					uint64_t value = 0;
				};

			public:
				class nd_call
				{
				public:
					static string get_token_metadata(const std::string_view& mint);
					static const char* get_token_balance();
					static const char* get_balance();
					static const char* get_block_hash();
					static const char* get_slot();
					static const char* get_block();
					static const char* send_transaction();
				};

			protected:
				chainparams netdata;

			public:
				solana(const algorithm::asset_id& new_asset) noexcept;
				virtual ~solana() override = default;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<computed_fee> estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<decimal> calculate_balance(const algorithm::asset_id& for_asset, const wallet_link& link) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(mediator::prepared_transaction&& prepared) override;
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
				virtual expects_promise_rt<string> get_token_symbol(const std::string_view& mint);
				virtual expects_promise_rt<token_account> get_token_balance(const std::string_view& mint, const std::string_view& owner);
				virtual expects_promise_rt<decimal> get_balance(const std::string_view& owner);
				virtual expects_promise_rt<string> get_recent_block_hash();
				virtual vector<uint8_t> tx_message_serialize(sol_transaction* tx_data);
				virtual vector<uint8_t> tx_result_serialize(const vector<uint8_t>& message_buffer, const algorithm::composition::cpubsig signature, size_t signature_size);
				virtual const btc_chainparams_* get_chain();
			};
		}
	}
}
#endif