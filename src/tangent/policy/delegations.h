#ifndef TAN_POLICY_DELEGATIONS_H
#define TAN_POLICY_DELEGATIONS_H
#include "../kernel/block.h"
#include "../kernel/superchain.h"

namespace tangent
{
	namespace delegations
	{
		struct bind_delegation final : ledger::delegation_contract
		{
			uptr<algorithm::composition::compositor> compositor;
			btree_map<algorithm::pubkey_t, btree_map<algorithm::pubkeyhash_t, string>> encrypted_shares;
			btree_map<algorithm::pubkeyhash_t, algorithm::composition::cpubkey_t> key_contributions;
			algorithm::hashsig_t key_commitment;
			uint8_t attempt = 0;

			bind_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner);
			bind_delegation(const bind_delegation& other);
			expects_promise_rt<void> execute_transition() override;
			expects_lr<void> validate_transition(delegation_contract* parent, const ledger::wallet& yielding_runner) const override;
			expects_lr<void> aggregate_public_key();
			expects_lr<void> distribute_encrypted_shares();
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			delegate_ptr as_delegate_ptr(uint32_t hash) const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static uint256_t key_challenge_hash(const uint8_t message_hash[32], const algorithm::composition::cpubkey_t& correction_key, const algorithm::composition::cpubkey_t& corrected_key);
		};

		struct rebind_delegation final : ledger::delegation_contract
		{
			struct migration_proof
			{
				algorithm::hashsig_t correction_commitment;
				algorithm::composition::cpubkey_t correction_key;
				algorithm::composition::cpubkey_t imperfect_key;
				algorithm::composition::chashsig_t key_commitment;
			};

			struct migration_context
			{
				btree_map<algorithm::pubkeyhash_t, string> encrypted_recovery_shares;
				btree_map<algorithm::pubkey_t, btree_map<algorithm::pubkeyhash_t, string>> encrypted_shares;
				btree_map<algorithm::pubkeyhash_t, algorithm::composition::cpubkey_t> key_contributions;
				uptr<algorithm::composition::compositor> compositor;
				algorithm::hashsig_t key_commitment;
				algorithm::pubkey_t new_participant_key;
				algorithm::paillier_scalar_t accumulator_key;
				algorithm::paillier_scalar_t encrypted_accumulator;
				uint8_t attempt = 0;
			};

			vector<migration_proof> proofs;
			migration_context context;

			rebind_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner);
			rebind_delegation(const rebind_delegation& other);
			expects_promise_rt<void> execute_transition() override;
			expects_lr<void> aggregate_encrypted_shares_and_tweak();
			expects_lr<void> recover_encrypted_shares_and_tweak();
			expects_lr<void> aggregate_tweaked_public_key();
			expects_lr<void> distribute_tweaked_encrypted_shares();
			expects_lr<void> validate_transition(delegation_contract* parent, const ledger::wallet& yielding_runner) const override;
			expects_lr<algorithm::composition::cseckey_t> as_individual_tweak(uint64_t nonce) const;
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			delegate_ptr as_delegate_ptr(uint32_t hash) const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static std::string_view retweak_phrase();
			static size_t tweaking_key_size();
			static void tweaking_seed(const algorithm::seckey_t& secret_key, const uint256_t& transaction_hash, uint8_t message[64]);
		};

		struct broadcast_delegation final : ledger::delegation_contract
		{
			uptr<algorithm::composition::compositor> compositor;
			uptr<superchain::prepared_transaction> message;
			uint8_t attempt = 0;

			broadcast_delegation(ledger::delegation_adapter* new_adapter, const ledger::executor_context* new_executor, const algorithm::pubkeyhash_t& new_runner);
			broadcast_delegation(const broadcast_delegation& other);
			expects_promise_rt<void> execute_transition() override;
			expects_lr<void> validate_transition(ledger::delegation_contract* parent, const ledger::wallet& yielding_runner) const override;
			expects_lr<void> aggregate_signature();
			bool store_payload(format::wo_stream* stream) const override;
			bool load_payload(format::ro_stream& stream) override;
			delegate_ptr as_delegate_ptr(uint32_t hash) const override;
			uint32_t as_type() const override;
			std::string_view as_typename() const override;
			static uint32_t as_instance_type();
			static std::string_view as_instance_typename();
			static string mockup_target_broadcast_error();
			static string mockup_target_broadcast_underflow();
			static string mockup_target_attestate_error();
			static string mockup_target_attestate_absent();
			static expects_promise_rt<superchain::prepared_transaction> prepare_transaction(const algorithm::asset_id& asset, const superchain::wallet_link& from_link, const superchain::value_transfer& to, const decimal& max_fee);
			static expects_lr<superchain::finalized_transaction> finalize_transaction(const algorithm::asset_id& asset, superchain::prepared_transaction&& prepared);
			static expects_promise_rt<void> broadcast_transaction(const algorithm::asset_id& asset, const uint256_t& external_id, superchain::finalized_transaction&& finalized, ledger::delegation_contract* contract);
		};

		class resolver
		{
		public:
			static ledger::delegation_contract* from_stream(format::ro_stream& stream, ledger::delegation_adapter* adapter, const ledger::executor_context* executor, const algorithm::pubkeyhash_t& delegator);
			static ledger::delegation_contract* from_type(uint32_t hash, ledger::delegation_adapter* adapter, const ledger::executor_context* executor, const algorithm::pubkeyhash_t& delegator);
			static ledger::delegation_contract* from_copy(const ledger::delegation_contract* base);
		};
	}
}
#endif