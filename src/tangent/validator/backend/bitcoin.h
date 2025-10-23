#ifndef TAN_WARDEN_BITCOIN_H
#define TAN_WARDEN_BITCOIN_H
#include "../../kernel/warden.h"

struct btc_tx_;
struct btc_chainparams_;
struct cstring;

namespace tangent
{
	namespace warden
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

				struct btc_tx_context
				{
					struct program
					{
						cstring* script = nullptr;
						cstring* stack = nullptr;
						cstring* redeem = nullptr;
					};

					vector<string> public_keys;
					vector<program> scripts;
					vector<uint64_t> values;
					vector<uint8_t> types;
					btc_tx_* state;

					btc_tx_context();
					~btc_tx_context();
					bool is_in_range(size_t index) const;
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

			protected:
				struct
				{
					uint8_t get_raw_transaction = 0;
					uint8_t get_block = 0;
				} legacy;
				chainparams netdata;

			public:
				bitcoin(const algorithm::asset_id& new_asset) noexcept;
				virtual ~bitcoin() override;
				virtual expects_promise_rt<uint64_t> get_latest_block_height() override;
				virtual expects_promise_rt<schema*> get_block_transactions(uint64_t block_height, string* block_hash) override;
				virtual expects_promise_rt<coin_utxo> get_transaction_output(const std::string_view& tx_id, uint64_t index) override;
				virtual expects_promise_rt<computed_transaction> link_transaction(uint64_t block_height, const std::string_view& block_hash, schema* transaction_data) override;
				virtual expects_promise_rt<computed_fee> estimate_fee(const std::string_view& from_address, const vector<value_transfer>& to, const fee_supervisor_options& options) override;
				virtual expects_promise_rt<void> broadcast_transaction(const finalized_transaction& finalized) override;
				virtual expects_promise_rt<prepared_transaction> prepare_transaction(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& fee, bool inclusive_fee) override;
				virtual expects_lr<finalized_transaction> finalize_transaction(prepared_transaction&& prepared) override;
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
				virtual expects_lr<computed_fee> calculate_transaction_fee_from_fee_estimate(const wallet_link& from_link, const vector<value_transfer>& to, const computed_fee& estimate);
				virtual expects_lr<string> prepare_transaction_input(btc_tx_context& context, const coin_utxo& output, size_t index);
				virtual expects_lr<void> finalize_transaction_input(btc_tx_context& context, const prepared_transaction::signable_coin_utxo& output, size_t index);
				virtual expects_lr<void> add_transaction_input(btc_tx_context& context, const coin_utxo& output, const std::string_view& public_key);
				virtual expects_lr<void> add_transaction_output(btc_tx_context& context, const std::string_view& address, const decimal& value);
				virtual unordered_set<string> get_output_addresses(schema* tx_output, bool* is_allowed);
				virtual string serialize_transaction_data(btc_tx_context& context);
				virtual string serialize_transaction_id(btc_tx_context& context);
				virtual address_format parse_address(const std::string_view& address, uint8_t* data_out = nullptr, size_t* data_size_out = nullptr);
				virtual const btc_chainparams_* get_chain();
				virtual address_format get_address_type();
				virtual uint32_t get_sig_hash_type();
			};
		}
	}
}
#endif