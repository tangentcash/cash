/**
 * @file zk_paillier.h
 *
 * Non-interactive zero-knowledge proof that a Paillier ciphertext encrypts a
 * small value (a secp256k1 scalar, < 2^256), with defense against maliciously
 * chosen Paillier moduli.
 *
 * The proof is the conjunction of:
 *   1. modulus-validity proof (NiCorrectKeyProof, eprint 2018/057): n is
 *      square-free, has no prime factor < 6370, and the prover knows the
 *      factorization — i.e. n is a valid Paillier modulus;
 *   2. compact range proof (GG18, eprint 2019/114 Appendix A.1): the
 *      plaintext m of the ciphertext satisfies |m| <= 2^768.
 *
 * Proof size for a 2048-bit modulus: 11 elements mod n (~2.8 KiB) for the
 * modulus-validity part + 5 integers (~0.7 KiB) for the range part.
 *
 * Hashing: SHA-256 from trezor-crypto hazmat (crypto/sha2.h). The
 * Fiat-Shamir digest and the mask-generation function are byte-compatible
 * with the Python reference implementation (python/zkrange), so proofs can be
 * cross-validated between C and Python.
 *
 * Trust model: the range proof needs an unknown-order RSA modulus Ntilde
 * (product of two safe primes) and generators h1, h2. These are fixed system
 * parameters whose factorization must be unknown to the prover (trusted
 * setup), see zk_paillier_setup.
 */
#ifndef ZK_PAILLIER_H_
#define ZK_PAILLIER_H_

#include <gmp.h>
#include "paillier.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* ---- parameters ---------------------------------------------------------- */

/* modulus-validity proof (NiCorrectKeyProof): number of n-th roots.
	* Must satisfy M2 >= ceil(128 / log2(ALPHA)) for ~128-bit statistical
	* soundness. Tunable together with ALPHA:
	*   ALPHA 6370    -> M2 11, primorial ~9 Kbit  (proof 2816 B)
	*   ALPHA 65537   -> M2  8, primorial ~94 Kbit (proof 2048 B)
	*   ALPHA 1048576 -> M2  7, primorial ~1.5 Mbit (proof 1792 B)  <-- default */
#define ZK_PAILLIER_M2 8
	/* modulus-validity proof: n must have no prime factor < ALPHA. The primorial
	* of primes < ALPHA is a LOCAL constant (computed once at constants_init,
	* ~185 KB for ALPHA = 65537); it is NOT transmitted with the proof. */
#define ZK_PAILLIER_ALPHA 65537
	/* range proof: base bound q = 2^256 (secp256k1 field size) */
#define ZK_PAILLIER_Q_BITS 256
/** The bit bound proven by the range proof: |m| <= 2^bound (768). */
#define ZK_PAILLIER_BOUND_BITS (3 * ZK_PAILLIER_Q_BITS)
/* minimum Paillier modulus size accepted by the verifier */
#define ZK_PAILLIER_MIN_MODULUS_BITS 2048

/* ---- system parameters (trusted setup) ---------------------------------- */

/** Fully self-contained system parameters.
 *
 *  Holds the unknown-order group used by the compact range proof (generated
 *  once by a trusted setup; the factorization of `ntilde` must be unknown to
 *  provers) together with all derived constants (q, q^2, q^3, primorial).
 *  `zk_paillier_setup_init` initialises every field; `setup_random` fills the
 *  unknown-order group; `zk_paillier_setup_clear` frees everything. No hidden
 *  global state is used by the library. */
typedef struct
{
	/* unknown-order group (trusted setup) */
	mpz_t ntilde; /**< Ntilde = P*Q, product of two safe primes */
	mpz_t h1;     /**< generator of the commitment group */
	mpz_t h2;     /**< second generator, h2 = h1^chi */
	/* derived constants (initialized by zk_paillier_setup_init) */
	mpz_t q;       /**< q = 2^256: base bound of the range proof */
	mpz_t q2;      /**< q^2 = 2^512 */
	mpz_t q3;      /**< q^3 = 2^768: the proven bound |m| <= q^3 */
	mpz_t primorial; /**< product of all primes < ZK_PAILLIER_ALPHA */
} zk_paillier_setup;

/* ---- proof --------------------------------------------------------------- */

/** Full non-interactive proof: modulus validity */
typedef struct
{
	/* modulus-validity proof (NiCorrectKeyProof) */
	mpz_t sigma[ZK_PAILLIER_M2]; /**< n-th roots of the derived rho_i */
} zk_paillier_key_proof;

/** Full non-interactive proof: compact range proof. */
typedef struct
{
	/* compact range proof (GG18): proves |m| <= 2^768 for c = Enc(m) */
	mpz_t z;   /**< z = h1^m * h2^rho  mod Ntilde */
	mpz_t e;   /**< Fiat-Shamir challenge (256-bit) */
	mpz_t s;   /**< s = r^e * beta  mod n */
	mpz_t s1;  /**< s1 = e*m + alpha  (<= 2^768) */
	mpz_t s2;  /**< s2 = e*rho + gamma */
} zk_paillier_range_proof;

/* ---- memory -------------------------------------------------------------- */

/** Initialise a setup: allocates and fills ALL fields, including the derived
	*  constants q = 2^256, q^2, q^3 = 2^768 and the primorial of primes
	*  < ZK_PAILLIER_ALPHA (this is where the primorial is computed; it is a
	*  per-setup constant, ~185 KB for ALPHA = 1048576). Must be called before
	*  any use of the setup. */
PE_CPP_IMPORT void zk_paillier_setup_init(zk_paillier_setup* setup);

/** Free all memory held by the setup (including the derived constants). */
PE_CPP_IMPORT void zk_paillier_setup_clear(zk_paillier_setup* setup);
PE_CPP_IMPORT void zk_paillier_key_proof_init(zk_paillier_key_proof* proof);
PE_CPP_IMPORT void zk_paillier_key_proof_clear(zk_paillier_key_proof* proof);
PE_CPP_IMPORT void zk_paillier_range_proof_init(zk_paillier_range_proof* proof);
PE_CPP_IMPORT void zk_paillier_range_proof_clear(zk_paillier_range_proof* proof);

/** Generate fresh system parameters: Ntilde = P*Q with P, Q safe primes of
	*  ntilde_bits/2 bits (so Ntilde has at least ntilde_bits bits), h1 a random
	*  generator, h2 = h1^chi.
	*
	*  The caller is the *trusted setup*: it must keep the factorization of
	*  Ntilde secret and discard it, so that provers cannot break the range proof.
	*
	*  @param[out] setup        output system parameters (must be initialised)
	*  @param[in]  ntilde_bits  target bit size of Ntilde (>= 1024; 2048 for
	*                           production)
	*  @return 0 on success, -1 on error
	*/
PE_CPP_IMPORT int zk_paillier_setup_random(zk_paillier_setup* setup, mp_bitcnt_t ntilde_bits);
PE_CPP_IMPORT int zk_paillier_setup_secp256k1(zk_paillier_setup* setup);

/* ---- the two API functions ----------------------------------------------- */

/**
	* Encrypt `plaintext` under the Paillier private key and produce the FULL
	* non-interactive proof that the plaintext is small.
	*
	* The secret key carries everything needed: the modulus n and lambda
	* (lcm(p-1, q-1)) are used for the encryption and the modulus-validity
	* proof, so no public key has to be passed.
	*
	* @param[out] ciphertext output ciphertext c = (1+n)^m * r^n mod n^2
	* @param[out] proof      full proof (modulus validity + range proof)
	* @param[in]  plaintext  the message m; must satisfy 0 <= m < 2^256
	* @param[in]  priv       the Paillier private key (n >= 2048 bits)
	* @param[in]  setup      system parameters (Ntilde, h1, h2)
	* @return 0 on success, -1 on error (bad inputs / RNG failure)
	*
	* The encryption randomness r is chosen internally (secure RNG).
	*/
PE_CPP_IMPORT int zk_paillier_prove_key(
	zk_paillier_key_proof* key_proof,
	const paillier_seckey* priv);
PE_CPP_IMPORT int zk_paillier_prove_range(
	zk_paillier_range_proof* range_proof,
	const mpz_t plaintext,
	const mpz_t ciphertext,
	const mpz_t r,
	const paillier_seckey* priv,
	const zk_paillier_setup* setup);

/**
	* Verify the full non-interactive proof for the public statement
	* (public key, ciphertext).
	*
	* @param[in] proof      the proof (modulus validity + range proof)
	* @param[in] ciphertext the ciphertext c
	* @param[in] pub        the Paillier public key (modulus n)
	* @param[in] setup      system parameters (Ntilde, h1, h2)
	* @return 1 if the proof is valid, 0 otherwise
	*/
PE_CPP_IMPORT int zk_paillier_verify_key(
	const zk_paillier_key_proof* key_proof,
	const paillier_pubkey* pub,
	const zk_paillier_setup* setup);
PE_CPP_IMPORT int zk_paillier_verify_range(
	const zk_paillier_range_proof* range_proof,
	const mpz_t ciphertext,
	const paillier_pubkey* pub,
	const zk_paillier_setup* setup);

#ifdef __cplusplus
}
#endif

#endif /* ZK_PAILLIER_H_ */
