#ifndef TAN_POLICY_COMPOSITIONS_H
#define TAN_POLICY_COMPOSITIONS_H
#include "../kernel/transaction.h"
#include <array>

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
			ed25519_point_t cumulative_key;
			ed25519_point_t cumulative_r;
			ed25519_scalar_t cumulative_s;
			vector<uint256_t> indices;
			vector<uint8_t> message;
			uint16_t participants = 0;
			uint16_t z_steps = 0;
			uint16_t r_steps = 0;
			uint16_t s_steps = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, const algorithm::composition::shared_message* shared, uint16_t participants) override;
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
			struct clsag_message : ledger::uniform_serializer
			{
				struct bulletproof_plus
				{
					uint8_t a[32] = { 0 }, a1[32] = { 0 }, b[32] = { 0 };
					uint8_t r1[32] = { 0 }, s1[32] = { 0 }, d1[32] = { 0 };
					vector<std::array<uint8_t, 32>> l, r;
				};

				struct txin_to_key
				{
					struct ref
					{
						uint8_t key[32] = { 0 };
						uint8_t mask[32] = { 0 };
						uint64_t index = 0;
						bool decoy = true;
					};
					struct sig
					{
						vector<std::array<uint8_t, 32>> s;
						uint8_t c1[32] = { 0 };
						uint8_t d[32] = { 0 };
					} clsag;
					struct
					{
						uint8_t mask[32] = { 0 };
						uint8_t key[32] = { 0 };
					} pseudo_out;
					struct out
					{
						uint8_t commitment_mask[32] = { 0 };
						uint8_t derivation_scalar[32] = { 0 };
						uint64_t index = 0;
					} prev_out;
					vector<ref> keys;
					uint8_t key_image[32] = { 0 };
				};

				struct tx_out
				{
					struct tx_out_to_key
					{
						uint8_t key[32] = { 0 };
						uint8_t tag = 0;
					} target;
					struct
					{
						uint8_t amount[32] = { 0 };
					} ecdh_info;
					struct
					{
						uint8_t blinding_factor[32] = { 0 };
						uint8_t mask[32] = { 0 };
					} out_pk;
				};

				vector<txin_to_key> vin;
				vector<tx_out> vout;
				vector<uint8_t> extra;
				bulletproof_plus bpp;
				uint8_t tx_key[32] = { 0 };
				uint64_t fee = 0;

				void optimize_index(uint16_t* vin_index_inout);
				bool store_payload(format::wo_stream* stream) const override;
				bool load_payload(format::ro_stream& stream) override;
				void write_prefix(vector<uint8_t>& buffer, bool no_key_image = false) const;
				void write_rctsig_base(vector<uint8_t>& buffer) const;
				void write_rctsig_prunable(vector<uint8_t>& buffer, bool no_clsag = false, bool no_pseudo_size = false) const;
				void write_all(vector<uint8_t>& buffer, bool no_clsag = false, bool no_pseudo_size = false) const;
				void as_prefix_hash(uint8_t prefix_hash[32]) const;
				void as_rctsig_base_hash(uint8_t rctsig_base_hash[32]) const;
				void as_rctsig_prunable_hash(uint8_t rctsig_prunable_hash[32]) const;
				void as_id_hash(uint8_t id_hash[32], bool no_clsag = false, bool no_pseudo_size = false, bool no_key_image = false) const;
				format::tree as_tree() const override;
				uint32_t as_type() const override;
				std::string_view as_typename() const override;
				static uint32_t as_instance_type();
				static std::string_view as_instance_typename();
			};

			ed25519_point_t cumulative_key;
			ed25519_point_t cumulative_I;
			ed25519_point_t cumulative_aH;
			ed25519_point_t cumulative_aG;
			ed25519_scalar_t cumulative_c_mu_P;
			clsag_message message;
			uint16_t participants = 0;
			uint16_t vin_index = 0;
			uint16_t z_steps = 0;
			uint16_t i_steps = 0;
			uint16_t a_steps = 0;
			uint16_t s_steps = 0;

			expects_lr<void> setup_public_key(const uint8_t* message, size_t message_size, uint16_t participants) override;
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, const algorithm::composition::shared_message* shared, uint16_t participants) override;
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
			static bool generate_derivation_key(const uint8_t transaction_public_key[32], const uint8_t private_view_key[32], uint8_t derivation_key[32]);
			static bool generate_derivation_key_out(const uint8_t transaction_private_key[32], const uint8_t public_view_key[32], uint8_t derivation_key[32]);
			static void derive_private_key(const uint8_t derivation_scalar[32], const uint8_t private_spend_key[32], uint8_t private_key[32]);
			static bool derive_public_key(const uint8_t derivation_scalar[32], const uint8_t public_spend_key[32], uint8_t public_key[32]);
			static void derivation_to_scalar(const uint8_t derivation_key[32], uint64_t derivation_index, uint8_t derivation_scalar[32]);
			static uint8_t derivation_to_view_tag(const uint8_t derivation_scalar[32], uint64_t derivation_index);
			static void hash_to_scalar(const uint8_t* buffer, size_t buffer_size, uint8_t scalar[32]);
			static void hash_to_point(const uint8_t* buffer, size_t buffer_size, uint8_t point[32]);
			static bool pedersen_commit(const uint8_t mask[32], const uint8_t amount[32], uint8_t commitment[32]);
			static void derive_known_private_view_key(const uint8_t public_spend_key[32], uint8_t private_view_key[32]);
			static void derive_known_public_view_key(const uint8_t public_spend_key[32], uint8_t public_view_key[32]);
			static void encode_amount_256(uint64_t amount_in, uint8_t amount_out[32]);
			static void vector32_to_vector8(const vector<std::array<uint8_t, 32>>& in, vector<uint8_t>& out);
			static void derive_pseudo_message(const uint8_t* message, size_t message_size, clsag_message& out, uint16_t& index_out);
			static void write_varint(uint64_t i, vector<uint8_t>& buffer);
			static size_t write_varint_fixed(uint64_t i, uint8_t buffer[10]);
		};

		struct secp256k1_compositor final : algorithm::composition::compositor
		{
			secp256k1_point_t cumulative_key;
			secp256k1_point_t cumulative_r;
			secp256k1_scalar_t cumulative_s;
			algorithm::paillier_scalar_t cumulative_i;
			algorithm::paillier_scalar_t encryption_key;
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
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, const algorithm::composition::shared_message* shared, uint16_t participants) override;
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
			secp256k1_point_t cumulative_key;
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
			expects_lr<void> setup_signature(const algorithm::composition::cpubkey_t& public_key, const uint8_t* message, size_t message_size, const algorithm::composition::shared_message* shared, uint16_t participants) override;
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