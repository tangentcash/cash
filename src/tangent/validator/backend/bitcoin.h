#ifndef TAN_MEDIATOR_BITCOIN_H
#define TAN_MEDIATOR_BITCOIN_H
#include "../../kernel/mediator.h"

struct btc_tx_;
struct btc_chainparams_;
struct cstring;

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class bitcoin : public relay_backend_utxo
			{
			public:
				enum class address_format
				{
					unknown = 0,
					pay2_public_key = (1 << 0),
					pay2_script_hash = (1 << 1),
					pay2_public_key_hash = (1 << 2),
					pay2_witness_script_hash = (1 << 3),
					pay2_witness_public_key_hash = (1 << 4),
					pay2_tapscript = (1 << 5),
					pay2_taproot = (1 << 6),
					pay2_cashaddr_script_hash = (1 << 7),
					pay2_cashaddr_public_key_hash = (1 << 8),
					all = (pay2_public_key | pay2_public_key_hash | pay2_script_hash | pay2_witness_public_key_hash | pay2_witness_public_key_hash | pay2_witness_script_hash | pay2_taproot | pay2_tapscript | pay2_cashaddr_public_key_hash | pay2_cashaddr_script_hash)
				};

				struct sighash_context
				{
					struct
					{
						vector<cstring*> locking;
						vector<vector<cstring*>> unlocking;
					} scripts;
					vector<string> keys;
					vector<uint64_t> values;
					vector<uint8_t> types;

					~sighash_context();
				};

			public:
				class nd_call
				{
				public:
					static const char* get_block_count();
					static const char* get_block_hash();
					static const char* get_block_stats();
					static const char* get_block();
					static const char* get_raw_transaction();
					static const char* send_raw_transaction();
				};

			private:
				struct
				{
					uint8_t get_raw_transaction = 0;
					uint8_t get_block = 0;
				} legacy;

			protected:
				chainparams netdata;

			public:
				bitcoin() noexcept;
				virtual ~bitcoin() override;
				virtual expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const outgoing_transaction& tx_data) override;
				virtual expects_promise_rt<uint64_t> get_latest_block_height(const algorithm::asset_id& asset) override;
				virtual expects_promise_rt<schema*> get_block_transactions(const algorithm::asset_id& asset, uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<schema*> get_block_transaction(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, const std::string_view& transaction_id) override;
				virtual expects_promise_rt<vector<incoming_transaction>> get_authentic_transactions(const algorithm::asset_id& asset, uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<base_fee> estimate_fee(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const algorithm::asset_id& asset, const std::string_view& tx_id, uint32_t index) override;
				virtual expects_promise_rt<outgoing_transaction> new_transaction(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& fee) override;
				virtual expects_lr<master_wallet> new_master_wallet(const std::string_view& wallet) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const master_wallet& wallet, uint64_t address_index) override;
				virtual expects_lr<derived_signing_wallet> new_signing_wallet(const algorithm::asset_id& asset, const secret_box& signing_key) override;
				virtual expects_lr<derived_verifying_wallet> new_verifying_wallet(const algorithm::asset_id& asset, const std::string_view& verifying_key) override;
				virtual expects_lr<string> new_public_key_hash(const std::string_view& address) override;
				virtual expects_lr<string> sign_message(const algorithm::asset_id& asset, const std::string_view& message, const secret_box& signing_key) override;
				virtual expects_lr<void> verify_message(const algorithm::asset_id& asset, const std::string_view& message, const std::string_view& verifying_key, const std::string_view& signature) override;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const chainparams& get_chainparams() const override;
				virtual unordered_set<string> get_output_addresses(schema* tx_output, bool* is_allowed);
				virtual expects_promise_rt<base_fee> calculate_transaction_fee_from_fee_estimate(const algorithm::asset_id& asset, const dynamic_wallet& wallet, const vector<transferer>& to, const base_fee& estimate, const std::string_view& change_address);
				virtual option<layer_exception> sign_transaction_input(btc_tx_* transaction, const coin_utxo& output, const sighash_context& context, size_t index);
				virtual option<layer_exception> add_transaction_input(btc_tx_* transaction, const coin_utxo& output, sighash_context& context, const char* private_key);
				virtual option<layer_exception> add_transaction_output(btc_tx_* transaction, const std::string_view& address, const decimal& value);
				virtual string serialize_transaction_data(btc_tx_* transaction);
				virtual string serialize_transaction_id(btc_tx_* transaction);
				virtual address_format parse_address(const std::string_view& address, uint8_t* data_out = nullptr, size_t* data_size_out = nullptr);
				virtual string get_message_magic();
				virtual void generate_message_hash(const std::string_view& input, uint8_t output[32]);
				virtual const btc_chainparams_* get_chain();
				virtual address_format get_address_type();
				virtual uint32_t get_sig_hash_type();
			};
		}
	}
}
#endif