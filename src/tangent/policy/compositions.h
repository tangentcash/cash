#ifndef TAN_POLICY_COMPOSITIONS_H
#define TAN_POLICY_COMPOSITIONS_H
#include "../kernel/algorithm.h"

namespace tangent
{
	namespace compositions
	{
		typedef algorithm::storage_type<uint8_t, 32> ed25519_scalar_t;
		typedef algorithm::storage_type<uint8_t, 32> ed25519_point_t;
		typedef algorithm::storage_type<uint8_t, 32> secp256k1_scalar_t;
		typedef algorithm::storage_type<uint8_t, 33> secp256k1_point_t;

		struct ed25519_compositor final : algorithm::composition::compositor
		{
			ed25519_point_t group_public_key;
			ed25519_point_t cumulative_r;
			ed25519_scalar_t cumulative_s;
			vector<uint256_t> indices;
			vector<uint8_t> message;
			uint16_t participants = 0;
			uint16_t z_steps = 0;
			uint16_t r_steps = 0;
			uint16_t s_steps = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const override;
			expects_lr<void> tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const override;
			expects_lr<void> tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const override;
			expects_lr<void> combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const override;
			expects_lr<void> derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const override;
			expects_lr<void> derive_public_key(algorithm::composition::cpubkey_t* output) const override;
			expects_lr<void> derive_signature(algorithm::composition::chashsig_t* output) const override;
			expects_lr<void> verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const override;
			algorithm::composition::type alg_type() const override;
			algorithm::composition::phase next_phase() const override;
			uint32_t steps_left() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool may_transition_to(const compositor& next) const override;
		};

		struct ed25519_clsag_compositor final : algorithm::composition::compositor
		{
			ed25519_point_t group_public_key;
			vector<uint8_t> message;
			uint16_t participants = 0;
			uint16_t z_steps = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const override;
			expects_lr<void> tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const override;
			expects_lr<void> tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const override;
			expects_lr<void> combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const override;
			expects_lr<void> derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const override;
			expects_lr<void> derive_public_key(algorithm::composition::cpubkey_t* output) const override;
			expects_lr<void> derive_signature(algorithm::composition::chashsig_t* output) const override;
			expects_lr<void> verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const override;
			algorithm::composition::type alg_type() const override;
			algorithm::composition::phase next_phase() const override;
			uint32_t steps_left() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool may_transition_to(const compositor& next) const override;
		};

		struct secp256k1_compositor final : algorithm::composition::compositor
		{
			secp256k1_point_t group_public_key;
			secp256k1_point_t cumulative_r;
			secp256k1_scalar_t cumulative_s;
			algorithm::paillier_scalar_t cumulative_i;
			algorithm::paillier_scalar_t group_paillier_key;
			vector<uint256_t> indices;
			uint8_t message_hash[32] = { 0 };
			uint16_t additions = 0;
			uint16_t multiplications = 0;
			uint16_t z_steps = 0;
			uint16_t r_steps = 0;
			uint16_t i_steps = 0;
			uint16_t s_steps = 0;
			uint16_t p_bits = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const override;
			expects_lr<void> tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const override;
			expects_lr<void> tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const override;
			expects_lr<void> combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const override;
			expects_lr<void> derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const override;
			expects_lr<void> derive_public_key(algorithm::composition::cpubkey_t* output) const override;
			expects_lr<void> derive_signature(algorithm::composition::chashsig_t* output) const override;
			expects_lr<void> verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const override;
			expects_lr<void> verify_signature_set_recovery_id(const uint8_t* message, size_t message_size, algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const;
			algorithm::composition::type alg_type() const override;
			algorithm::composition::phase next_phase() const override;
			uint32_t steps_left() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool may_transition_to(const compositor& next) const override;
		};

		struct secp256k1_schnorr_compositor final : algorithm::composition::compositor
		{
			secp256k1_point_t group_public_key;
			secp256k1_scalar_t group_public_key_tweak;
			secp256k1_point_t cumulative_r;
			secp256k1_scalar_t cumulative_s;
			vector<uint256_t> indices;
			uint8_t message_hash[32] = { 0 };
			uint16_t participants = 0;
			uint16_t z_steps = 0;
			uint16_t r_steps = 0;
			uint16_t s_steps = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> derive_tweaking_key(const uint8_t* seed, size_t seed_size, size_t key_size, algorithm::paillier_scalar_t* public_key) const override;
			expects_lr<void> tweak_secret_key(const algorithm::paillier_scalar_t& public_key, size_t key_size, const algorithm::composition::cseckey_t& tweak, algorithm::composition::cseckey_t* secret_key_input_output, algorithm::paillier_scalar_t* accumulator_output) const override;
			expects_lr<void> tweak_secret_key(const uint8_t* seed, size_t seed_size, size_t key_size, const algorithm::paillier_scalar_t& accumulator, algorithm::composition::cseckey_t* secret_key_input_output) const override;
			expects_lr<void> combine_public_keys(const algorithm::composition::cpubkey_t* input, algorithm::composition::cpubkey_t* input_output) const override;
			expects_lr<void> derive_secret_key(const uint8_t* seed, size_t seed_size, algorithm::composition::cseckey_t* output) const override;
			expects_lr<void> derive_public_key(algorithm::composition::cpubkey_t* output) const override;
			expects_lr<void> derive_signature(algorithm::composition::chashsig_t* output) const override;
			expects_lr<void> verify_signature(const uint8_t* message, size_t message_size, const algorithm::composition::chashsig_t& signature, const algorithm::composition::cpubkey_t& public_key) const override;
			algorithm::composition::type alg_type() const override;
			algorithm::composition::phase next_phase() const override;
			uint32_t steps_left() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool may_transition_to(const compositor& next) const override;
			static expects_lr<algorithm::composition::cpubkey_t> to_tweaked_public_key(const secp256k1_point_t& public_key, const secp256k1_scalar_t& tweak);
		};
	}
}
#endif