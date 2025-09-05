#ifndef TAN_POLICY_COMPOSITIONS_H
#define TAN_POLICY_COMPOSITIONS_H
#include "../kernel/algorithm.h"

namespace tangent
{
	namespace compositions
	{
		struct ed25519_secret_state final : algorithm::composition::secret_state
		{
			typedef algorithm::storage_type<uint8_t, 32> scalar_t;
			scalar_t cumulative_key;

			expects_lr<void> derive_from_seed(const uint256_t& seed) override;
			expects_lr<void> derive_from_key(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::cseckey_t* output) const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
		};

		struct ed25519_public_state final : algorithm::composition::public_state
		{
			typedef algorithm::storage_type<uint8_t, 32> point_t;
			point_t cumulative_key;

			expects_lr<void> derive_from_key(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::cpubkey_t* output) const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
		};

		struct ed25519_signature_state final : algorithm::composition::signature_state
		{
			ed25519_public_state::point_t public_key;
			ed25519_public_state::point_t cumulative_r;
			ed25519_secret_state::scalar_t cumulative_s;
			vector<uint256_t> indices;
			vector<uint8_t> message;
			uint16_t participants;
			uint16_t r_steps;
			uint16_t s_steps;

			expects_lr<void> setup(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::chashsig_t* output) const override;
			algorithm::composition::phase next_phase() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool prefer_over(const signature_state& other) const override;
		};

		struct ed25519_clsag_signature_state final : algorithm::composition::signature_state
		{
			expects_lr<void> setup(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::chashsig_t* output) const override;
			algorithm::composition::phase next_phase() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool prefer_over(const signature_state& other) const override;
		};

		struct secp256k1_secret_state final : algorithm::composition::secret_state
		{
			typedef algorithm::storage_type<uint8_t, 32> scalar_t;
			scalar_t cumulative_key;

			expects_lr<void> derive_from_seed(const uint256_t& seed) override;
			expects_lr<void> derive_from_key(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::cseckey_t* output) const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
		};

		struct secp256k1_public_state final : algorithm::composition::public_state
		{
			typedef algorithm::storage_type<uint8_t, 33> point_t;
			point_t cumulative_key;

			expects_lr<void> derive_from_key(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::cpubkey_t* output) const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
		};

		struct secp256k1_signature_state final : algorithm::composition::signature_state
		{
			typedef vector<uint8_t> paillier_scalar_t;
			secp256k1_public_state::point_t public_key;
			secp256k1_public_state::point_t cumulative_r;
			secp256k1_secret_state::scalar_t cumulative_s;
			paillier_scalar_t cumulative_i;
			paillier_scalar_t group_key;
			vector<uint256_t> indices;
			uint8_t message_hash[32];
			uint16_t additions;
			uint16_t multiplications;
			uint16_t r_steps;
			uint16_t i_steps;
			uint16_t s_steps;
			uint16_t p_bits;

			expects_lr<void> setup(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::chashsig_t* output) const override;
			algorithm::composition::phase next_phase() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool prefer_over(const signature_state& other) const override;
		};

		struct secp256k1_schnorr_signature_state final : algorithm::composition::signature_state
		{
			secp256k1_public_state::point_t public_key;
			secp256k1_secret_state::scalar_t public_key_tweak;
			secp256k1_public_state::point_t cumulative_r;
			secp256k1_secret_state::scalar_t cumulative_s;
			vector<uint256_t> indices;
			uint8_t message_hash[32];
			uint16_t participants;
			uint16_t r_steps;
			uint16_t s_steps;

			expects_lr<void> setup(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> aggregate(const algorithm::composition::cseckey_t& secret_key) override;
			expects_lr<void> finalize(algorithm::composition::chashsig_t* output) const override;
			algorithm::composition::phase next_phase() const override;
			bool store(format::wo_stream* stream) const override;
			bool load(format::ro_stream& stream) override;
			bool prefer_over(const signature_state& other) const override;
			static expects_lr<algorithm::composition::cpubkey_t> to_tweaked_public_key(const secp256k1_public_state::point_t& public_key, const secp256k1_secret_state::scalar_t& tweak);
		};
	}
}
#endif