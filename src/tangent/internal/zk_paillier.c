/**
 * @file zk_paillier.c
 *
 * Implementation of the compact Paillier range proof with malicious-modulus
 * defense (see zk-paillier.h). Uses GMP for big-integer arithmetic and
 * SHA-256 from trezor-crypto hazmat (crypto/sha2.h) for the Fiat-Shamir
 * transform and the mask-generation function.
 *
 * The construction matches the Python reference (python/zkrange):
 *   - modulus-validity proof: NiCorrectKeyProof (eprint 2018/057, m2=11,
 *     alpha=6370), SHA-256 based MGF;
 *   - range proof: GG18 Appendix A.1 (eprint 2019/114), Fiat-Shamir,
 *     proving |m| <= q^3 = 2^768 with q = 2^256.
 */
#include "zk_paillier.h"

#include "sha2.h"   /* trezor-crypto hazmat: sha256_Init/Update/Final/Raw */
#include "rand.h"   /* random_u8a */

 /* ------------------------------------------------------------------------- */
 /* hashing helpers (mpz <-> minimal big-endian bytes, matching Python)       */
 /* ------------------------------------------------------------------------- */

static void zk_hash_update_mpz(SHA256_CTX* ctx, const mpz_t v)
{
	size_t count = 0;
	unsigned char* buf;
	unsigned char zero = 0;

	if (mpz_sgn(v) == 0)
	{ /* Python encodes 0 as a single zero byte */
		sha256_Update(ctx, &zero, 1);
		return;
	}
	buf = (unsigned char*)mpz_export(NULL, &count, 1, 1, 1, 0, v);
	sha256_Update(ctx, buf, count);
	free(buf);
}

/* digest = SHA256(n || n+1 || c || z || u || w || Ntilde || h1 || h2 || Q3) */
static void zk_fs_digest(mpz_t e, const mpz_t n, const mpz_t c, const mpz_t z, const mpz_t u, const mpz_t w, const zk_paillier_setup* setup)
{
	SHA256_CTX ctx;
	unsigned char hash[32];
	mpz_t np1;

	mpz_init(np1);
	mpz_add_ui(np1, n, 1);

	sha256_Init(&ctx);
	zk_hash_update_mpz(&ctx, n);
	zk_hash_update_mpz(&ctx, np1);
	zk_hash_update_mpz(&ctx, c);
	zk_hash_update_mpz(&ctx, z);
	zk_hash_update_mpz(&ctx, u);
	zk_hash_update_mpz(&ctx, w);
	zk_hash_update_mpz(&ctx, setup->ntilde);
	zk_hash_update_mpz(&ctx, setup->h1);
	zk_hash_update_mpz(&ctx, setup->h2);
	zk_hash_update_mpz(&ctx, setup->q3);
	sha256_Final(&ctx, hash);

	mpz_import(e, 32, 1, 1, 1, 0, hash);
	mpz_clear(np1);
}

/* MGF: out = sum_j SHA256(seed || j) << (j*256), j = 0..out_bits/256 */
static void zk_mask_generation(mpz_t out, const mpz_t seed, mp_bitcnt_t out_bits)
{
	unsigned long msklen = (unsigned long)(out_bits / 256) + 1;
	unsigned long j;
	SHA256_CTX ctx;
	unsigned char hash[32];
	mpz_t term, jj;

	mpz_init(term);
	mpz_init(jj);
	mpz_set_ui(out, 0);
	for (j = 0; j < msklen; j++)
	{
		sha256_Init(&ctx);
		zk_hash_update_mpz(&ctx, seed);
		mpz_set_ui(jj, j);
		zk_hash_update_mpz(&ctx, jj);
		sha256_Final(&ctx, hash);
		mpz_import(term, 32, 1, 1, 1, 0, hash);
		mpz_mul_2exp(term, term, j * 256);
		mpz_add(out, out, term);
	}
	mpz_clear(term);
	mpz_clear(jj);
}

/* rho_i = MGF(n.bit_length, SHA256(n || "kzen" || i)) mod n */
static void zk_modulus_rho(mpz_t rho, const mpz_t n, int i)
{
	static const unsigned char salt[] = { 'k', 'z', 'e', 'n' };
	SHA256_CTX ctx;
	unsigned char hash[32];
	mpz_t seed, ii;

	mpz_init(seed);
	mpz_init_set_ui(ii, (unsigned long)i);

	sha256_Init(&ctx);
	zk_hash_update_mpz(&ctx, n);
	sha256_Update(&ctx, salt, sizeof(salt));
	zk_hash_update_mpz(&ctx, ii);
	sha256_Final(&ctx, hash);

	mpz_import(seed, 32, 1, 1, 1, 0, hash);
	zk_mask_generation(rho, seed, (mp_bitcnt_t)mpz_sizeinbase(n, 2));
	mpz_mod(rho, rho, n);

	mpz_clear(seed);
	mpz_clear(ii);
}

/* ------------------------------------------------------------------------- */
/* random sampling                                                           */
/* ------------------------------------------------------------------------- */

/* uniform sample in [0, bound); returns 0 on success, -1 on RNG failure */
static int zk_rand_below(mpz_t out, const mpz_t bound)
{
	mp_bitcnt_t bl = (mp_bitcnt_t)mpz_sizeinbase(bound, 2);
	size_t nbytes = (size_t)((bl + 7) / 8);
	unsigned char* buf = (unsigned char*)malloc(nbytes);
	mpz_t cand;
	int tries;

	if (!buf) return -1;
	mpz_init(cand);
	for (tries = 0; tries < 256; tries++)
	{
		if (random_u8a(buf, nbytes) != 0)
		{
			free(buf);
			mpz_clear(cand);
			return -1;
		}
		/* clear bits above bitlen(bound) in the top byte */
		if (bl % 8) buf[0] &= (unsigned char)((1u << (bl % 8)) - 1);
		mpz_import(cand, nbytes, 1, 1, 1, 0, buf);
		if (mpz_cmp(cand, bound) < 0)
		{
			mpz_set(out, cand);
			free(buf);
			mpz_clear(cand);
			return 0;
		}
	}
	free(buf);
	mpz_clear(cand);
	return -1;
}

/* uniform sample in Z_n* (coprime to n) */
static int zk_rand_unit(mpz_t out, const mpz_t n)
{
	int tries;
	for (tries = 0; tries < 256; tries++)
	{
		mpz_t g;
		if (zk_rand_below(out, n) != 0) return -1;
		if (mpz_cmp_ui(out, 1) < 0 || mpz_cmp(out, n) >= 0) continue;
		mpz_init(g);
		mpz_gcd(g, out, n);
		if (mpz_cmp_ui(g, 1) == 0)
		{
			mpz_clear(g);
			return 0;
		}
		mpz_clear(g);
	}
	return -1;
}

/* ------------------------------------------------------------------------- */
/* system parameters generation (trusted setup)                              */
/* ------------------------------------------------------------------------- */

/* find a safe prime p of exactly `bits` bits (q = 2p+1 also prime) */
static int zk_next_safe_prime(mpz_t p, mp_bitcnt_t bits)
{
	mpz_t q, rnd;
	int ok = -1;
	mpz_inits(q, rnd, NULL);
	for (;;)
	{
		size_t nb = (size_t)((bits + 7) / 8);
		unsigned char buf[256];
		if (nb > sizeof(buf)) break;
		if (random_u8a(buf, nb) != 0) break;
		mpz_import(rnd, nb, 1, 1, 1, 0, buf);
		mpz_setbit(rnd, bits - 1);
		mpz_nextprime(p, rnd);
		if (mpz_sizeinbase(p, 2) != bits) continue;
		mpz_mul_ui(q, p, 2);
		mpz_add_ui(q, q, 1);
		if (mpz_probab_prime_p(q, 40) && mpz_probab_prime_p(p, 40))
		{
			ok = 0;
			break;
		}
	}
	mpz_clears(q, rnd, NULL);
	return ok;
}

int zk_paillier_setup_random(zk_paillier_setup* setup, mp_bitcnt_t ntilde_bits)
{
	mpz_t P, Q, phi, chi, g;
	int ret = -1;

	if (!setup || ntilde_bits < 1024) return -1;
	mpz_inits(P, Q, phi, chi, g, NULL);

	/* Ntilde = P * Q with P, Q safe primes, Ntilde >= 2^(ntilde_bits-1) */
	do
	{
		if (zk_next_safe_prime(P, ntilde_bits / 2) != 0) goto out;
		if (zk_next_safe_prime(Q, ntilde_bits / 2) != 0) goto out;
		mpz_mul(setup->ntilde, P, Q);
	} while (mpz_sizeinbase(setup->ntilde, 2) < ntilde_bits);

	/* h1 random element of Z_ntilde* */
	do
	{
		if (zk_rand_below(setup->h1, setup->ntilde) != 0) goto out;
		mpz_gcd(g, setup->h1, setup->ntilde);
	} while (mpz_cmp_ui(setup->h1, 2) < 0 || mpz_cmp_ui(g, 1) != 0);

	/* phi = (P-1)(Q-1); chi random unit; h2 = h1^chi mod Ntilde */
	mpz_sub_ui(g, P, 1);
	mpz_sub_ui(phi, Q, 1);
	mpz_mul(phi, phi, g);
	do
	{
		if (zk_rand_below(chi, phi) != 0) goto out;
		mpz_gcd(g, chi, phi);
	} while (mpz_cmp_ui(g, 1) != 0);
	mpz_powm(setup->h2, setup->h1, chi, setup->ntilde);

	ret = 0;
out:
	mpz_clears(P, Q, phi, chi, g, NULL);
	return ret;
}

int zk_paillier_setup_secp256k1(zk_paillier_setup* setup)
{
	if (mpz_set_str(setup->ntilde, "VoixVqd8ugkNPSX9ojjp9LJCFlv1Qi3sTMXHj88IKuxvLGwzEXUEQnzAheKLoLPIsmKDMa5KRZChk8GfFGhImbL1gAojeThSxmV2O4Vb6jvK38tAnjArGhIZ68XFiJK1yEB9VOSDLWHeEjegS02Sfj3NwndSam3uSZi7M8I58PX7C3G2vA7JWT7FE3Tkvny3bQGIWocW7UIuZhp3pViDYOzpVBAUhidUC77kSu3b6apHB1Ju2fm9HSMJdh0Ckh2OV12T3xpscxTcXPGU9y8uxlXkVwAkiQskshcZy8e24fDzy0BmeIgAJkKUFu5KNbBvptNyLJW5yYsShSbxp7JtyI6f", 62) != 0) return -1;
	if (mpz_set_str(setup->h1, "LxPe44TMK6kCor1gngb6DmnCvVldyPWgwIMIjJFGlUTs0bdPgRvrpvBciFIiLml5J1RDuoZSTvD609ArgTKqCbedwNifVwSIqgh36oADdTLohc6ROBOxJGxqbyiy8uwyCTcSgPDzWEMr2egd7KhBuBfFp5mg2er5btYE0jcU9cV8qxJqrXWwHAXAMCLJeay4XajaNgUhVSi3yZwTHA1acTsjyCe6JRIbKZC4LyHtT2LDdBTJ7V198S2S8lz45xmk070HctlCDe6es2f9bxt4wmQolkywUDKqkbBd6XmwYUk8KGsI82pF3j13EwmyQZMlJHpu1ZjSBzdRG407P78WIwfH", 62) != 0) return -1;
	if (mpz_set_str(setup->h2, "JXyvpYtecaTmBvqhKAnv1nvDrmc3AWnPbUspthzoZ9aRAc5Se953rzoOgIrKMCctT0l8H3e9oFJOBH9SDdsFXFLSsYICbHu6Fj9gOsmiuo1n5HAotWfRJlikxuV9NakhDf0epUJioExOXuyjgf6UfkyWXOCEnWsnhq33trih28zoyyOeoVBAL1sFG7H4L9wcTf3JaT0IXY2gwftLYexYbzjfLcvwuJQqShf8je2HfP3friIZWwDHz2eP2gSnkBGYeaEanMffpz2W3UuflAnDIBt5Z5YTlAhO10bv9YpLS1pqkqxZh5XhqrsfsYETT9NdRDxX6laeAuUySaJOslJ8tWW0", 62) != 0) return -1;
	return 0;
}

/* ------------------------------------------------------------------------- */
/* modulus-validity proof (NiCorrectKeyProof)                                */
/* ------------------------------------------------------------------------- */

/* create: sigma_i = rho_i^{n^{-1} mod lambda} mod n */
static int zk_modulus_proof_prove(mpz_t sigma[ZK_PAILLIER_M2], const mpz_t n, const mpz_t lambda)
{
	mpz_t d, rho;
	int i;

	mpz_init(d);
	mpz_init(rho);
	if (!mpz_invert(d, n, lambda))
	{ /* gcd(n, lambda) != 1: not a valid key */
		mpz_clear(d);
		mpz_clear(rho);
		return -1;
	}
	for (i = 0; i < ZK_PAILLIER_M2; i++)
	{
		zk_modulus_rho(rho, n, i);
		mpz_powm(sigma[i], rho, d, n);
	}
	mpz_clear(d);
	mpz_clear(rho);
	return 0;
}

/* verify: sigma_i^n == rho_i mod n for all i, and gcd(n, primorial) == 1 */
static int zk_modulus_proof_verify(const mpz_t sigma[ZK_PAILLIER_M2], const mpz_t n, const zk_paillier_setup* setup)
{
	mpz_t rho, t, g;
	int i, ok = 1;

	mpz_init(rho);
	mpz_init(t);
	mpz_init(g);

	mpz_gcd(g, n, setup->primorial);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;

	for (i = 0; ok && i < ZK_PAILLIER_M2; i++)
	{
		zk_modulus_rho(rho, n, i);
		mpz_powm(t, sigma[i], n, n);
		if (mpz_cmp(t, rho) != 0) ok = 0;
	}

	mpz_clear(rho);
	mpz_clear(t);
	mpz_clear(g);
	return ok;
}

/* ------------------------------------------------------------------------- */
/* compact range proof (GG18 Appendix A.1, Fiat-Shamir)                      */
/* ------------------------------------------------------------------------- */

/* create: given c = (1+n)^m r^n mod n^2, produce {z, e, s, s1, s2} */
static int zk_range_proof_prove(zk_paillier_range_proof* proof, const mpz_t n, const mpz_t c, const mpz_t m, const mpz_t r, const zk_paillier_setup* setup)
{
	mpz_t n2, alpha, beta, gamma, rho, u, w, t, bound, e_mpz;
	int ret = -1;

	mpz_inits(n2, alpha, beta, gamma, rho, u, w, t, bound, e_mpz, NULL);
	mpz_mul(n2, n, n);

	/* alpha in [0, Q3 - Q2) */
	mpz_sub(bound, setup->q3, setup->q2);
	if (zk_rand_below(alpha, bound) != 0) goto out;
	/* beta in Z_n* */
	if (zk_rand_unit(beta, n) != 0) goto out;
	/* gamma in [0, Q3 * Ntilde) */
	mpz_mul(bound, setup->q3, setup->ntilde);
	if (zk_rand_below(gamma, bound) != 0) goto out;
	/* rho in [0, Q * Ntilde) */
	mpz_mul(bound, setup->q, setup->ntilde);
	if (zk_rand_below(rho, bound) != 0) goto out;

	/* z = h1^m * h2^rho mod Ntilde */
	mpz_powm(proof->z, setup->h1, m, setup->ntilde);
	mpz_powm(t, setup->h2, rho, setup->ntilde);
	mpz_mul(proof->z, proof->z, t);
	mpz_mod(proof->z, proof->z, setup->ntilde);

	/* u = (1+n)^alpha * beta^n mod n^2 */
	mpz_add_ui(t, n, 1);
	mpz_powm(u, t, alpha, n2);
	mpz_powm(t, beta, n, n2);
	mpz_mul(u, u, t);
	mpz_mod(u, u, n2);

	/* w = h1^alpha * h2^gamma mod Ntilde */
	mpz_powm(w, setup->h1, alpha, setup->ntilde);
	mpz_powm(t, setup->h2, gamma, setup->ntilde);
	mpz_mul(w, w, t);
	mpz_mod(w, w, setup->ntilde);

	/* e = H(...) */
	zk_fs_digest(proof->e, n, c, proof->z, u, w, setup);

	/* s = r^e * beta mod n */
	mpz_powm(proof->s, r, proof->e, n);
	mpz_mul(proof->s, proof->s, beta);
	mpz_mod(proof->s, proof->s, n);

	/* s1 = e*m + alpha */
	mpz_mul(proof->s1, proof->e, m);
	mpz_add(proof->s1, proof->s1, alpha);
	/* s2 = e*rho + gamma */
	mpz_mul(proof->s2, proof->e, rho);
	mpz_add(proof->s2, proof->s2, gamma);

	ret = 0;
out:
	mpz_clears(n2, alpha, beta, gamma, rho, u, w, t, bound, e_mpz, NULL);
	return ret;
}

/* verify: check the GG18 verification equations */
static int zk_range_proof_verify(const zk_paillier_range_proof* proof, const mpz_t n, const mpz_t c, const zk_paillier_setup* setup)
{
	mpz_t n2, u, w, t, inv, e2;
	int ok = 1;

	mpz_inits(n2, u, w, t, inv, e2, NULL);
	mpz_mul(n2, n, n);

	/* claimed bound: s1 <= Q3 and e is a 256-bit challenge */
	if (mpz_cmp(proof->s1, setup->q3) > 0) ok = 0;
	if (mpz_sizeinbase(proof->e, 2) > ZK_PAILLIER_Q_BITS) ok = 0;

	if (ok)
	{
		/* u = (1+n)^s1 * s^n * c^{-e} mod n^2 */
		mpz_add_ui(t, n, 1);
		mpz_powm(u, t, proof->s1, n2);
		mpz_powm(t, proof->s, n, n2);
		mpz_mul(u, u, t);
		mpz_mod(u, u, n2);
		if (mpz_invert(inv, c, n2) == 0)
		{
			ok = 0;
		}
		else
		{
			mpz_powm(t, inv, proof->e, n2);
			mpz_mul(u, u, t);
			mpz_mod(u, u, n2);
		}
	}

	if (ok)
	{
		/* w = h1^s1 * h2^s2 * z^{-e} mod Ntilde */
		mpz_powm(w, setup->h1, proof->s1, setup->ntilde);
		mpz_powm(t, setup->h2, proof->s2, setup->ntilde);
		mpz_mul(w, w, t);
		mpz_mod(w, w, setup->ntilde);
		if (mpz_invert(inv, proof->z, setup->ntilde) == 0)
		{
			ok = 0;
		}
		else
		{
			mpz_powm(t, inv, proof->e, setup->ntilde);
			mpz_mul(w, w, t);
			mpz_mod(w, w, setup->ntilde);
		}
	}

	if (ok)
	{
		/* recompute the Fiat-Shamir challenge and compare */
		zk_fs_digest(e2, n, c, proof->z, u, w, setup);
		if (mpz_cmp(e2, proof->e) != 0) ok = 0;
	}

	mpz_clears(n2, u, w, t, inv, e2, NULL);
	return ok;
}

/* ------------------------------------------------------------------------- */
/* memory                                                                    */
/* ------------------------------------------------------------------------- */

/* compute the derived constants q = 2^256, q^2, q^3 = 2^768, primorial */
static void zk_setup_derive_constants(zk_paillier_setup* setup)
{
	mpz_init_set_ui(setup->q, 1);
	mpz_mul_2exp(setup->q, setup->q, ZK_PAILLIER_Q_BITS);
	mpz_init_set(setup->q2, setup->q);
	mpz_mul(setup->q2, setup->q2, setup->q);   /* 2^512 */
	mpz_init_set(setup->q3, setup->q2);
	mpz_mul(setup->q3, setup->q3, setup->q);   /* 2^768 */

	mpz_init_set_ui(setup->primorial, 1);
	{
		int limit = ZK_PAILLIER_ALPHA;
		unsigned char* comp = (unsigned char*)calloc((size_t)limit, 1);
		int i, j;
		for (i = 2; i * i < limit; i++)
			if (!comp[i])
				for (j = i * i; j < limit; j += i) comp[j] = 1;
		for (i = 2; i < limit; i++)
			if (!comp[i]) mpz_mul_ui(setup->primorial, setup->primorial,
									 (unsigned long)i);
		free(comp);
	}
}

void zk_paillier_setup_init(zk_paillier_setup* setup)
{
	mpz_init(setup->ntilde);
	mpz_init(setup->h1);
	mpz_init(setup->h2);
	/* derived constants live in the setup: no hidden global state */
	zk_setup_derive_constants(setup);
}

void zk_paillier_setup_clear(zk_paillier_setup* setup)
{
	mpz_clear(setup->ntilde);
	mpz_clear(setup->h1);
	mpz_clear(setup->h2);
	mpz_clear(setup->q);
	mpz_clear(setup->q2);
	mpz_clear(setup->q3);
	mpz_clear(setup->primorial);
}

void zk_paillier_key_proof_init(zk_paillier_key_proof* proof)
{
	int i;
	for (i = 0; i < ZK_PAILLIER_M2; i++) mpz_init(proof->sigma[i]);
}

void zk_paillier_key_proof_clear(zk_paillier_key_proof* proof)
{
	int i;
	for (i = 0; i < ZK_PAILLIER_M2; i++) mpz_clear(proof->sigma[i]);
}

void zk_paillier_range_proof_init(zk_paillier_range_proof* proof)
{
	mpz_init(proof->z);
	mpz_init(proof->e);
	mpz_init(proof->s);
	mpz_init(proof->s1);
	mpz_init(proof->s2);
}

void zk_paillier_range_proof_clear(zk_paillier_range_proof* proof)
{
	mpz_clear(proof->z);
	mpz_clear(proof->e);
	mpz_clear(proof->s);
	mpz_clear(proof->s1);
	mpz_clear(proof->s2);
}

/* ------------------------------------------------------------------------- */
/* the two API functions                                                     */
/* ------------------------------------------------------------------------- */

int zk_paillier_prove_key(zk_paillier_key_proof* key_proof, const paillier_seckey* priv)
{
	int ret = -1;
	/* sanity checks (prover side) */
	if (mpz_sizeinbase(priv->n, 2) < ZK_PAILLIER_MIN_MODULUS_BITS) return -1;
	if (mpz_sgn(priv->lambda) <= 0) return -1;

	/* gcd(n, lambda) must be 1 for a valid Paillier key */
	mpz_t g;
	mpz_init(g);
	mpz_gcd(g, priv->n, priv->lambda);
	int gcd_fail = mpz_cmp_ui(g, 1) != 0;
	mpz_clear(g);
	if (gcd_fail) return -1;

	/* --- modulus-validity proof --- */
	return zk_modulus_proof_prove(key_proof->sigma, priv->n, priv->lambda);
}

int zk_paillier_prove_range(zk_paillier_range_proof* range_proof, const mpz_t plaintext, const mpz_t ciphertext, const mpz_t r, const paillier_seckey* priv, const zk_paillier_setup* setup)
{
	/* sanity checks (prover side) */
	if (mpz_sgn(plaintext) < 0 || mpz_cmp(plaintext, setup->q) >= 0) return -1; /* 0 <= m < 2^256 */
	if (mpz_sizeinbase(priv->n, 2) < ZK_PAILLIER_MIN_MODULUS_BITS) return -1;
	if (mpz_sgn(priv->lambda) <= 0) return -1;

	/* gcd(n, lambda) must be 1 for a valid Paillier key */
	mpz_t g;
	mpz_init(g);
	mpz_gcd(g, priv->n, priv->lambda);
	int gcd_fail = mpz_cmp_ui(g, 1) != 0;
	mpz_clear(g);
	if (gcd_fail) return -1;

	/* --- compact range proof --- */
	return zk_range_proof_prove(range_proof, priv->n, ciphertext, plaintext, r, setup);
}

int zk_paillier_verify_key(const zk_paillier_key_proof* key_proof, const paillier_pubkey* pub, const zk_paillier_setup* setup)
{
	mpz_t g;
	int ok = 1;

	mpz_init(g);

	/* --- statement sanity (malicious-modulus defense) --- */
	if (mpz_sizeinbase(pub->n, 2) < ZK_PAILLIER_MIN_MODULUS_BITS) ok = 0; /* n >= 2048 bits */
	if (mpz_sizeinbase(setup->ntilde, 2) < 1024) ok = 0;
	/* ntilde has no small factor (not prime / no small factors) */
	mpz_gcd(g, setup->ntilde, setup->primorial);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;
	/* generators are proper elements of Z_ntilde* */
	if (mpz_cmp_ui(setup->h1, 1) <= 0 || mpz_cmp(setup->h1, setup->ntilde) >= 0) ok = 0;
	if (mpz_cmp_ui(setup->h2, 1) <= 0 || mpz_cmp(setup->h2, setup->ntilde) >= 0) ok = 0;
	mpz_gcd(g, setup->h1, setup->ntilde);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;
	mpz_gcd(g, setup->h2, setup->ntilde);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;

	/* --- modulus validity --- */
	if (ok) ok = zk_modulus_proof_verify(key_proof->sigma, pub->n, setup);

	mpz_clear(g);
	return ok;
}

int zk_paillier_verify_range(const zk_paillier_range_proof* range_proof, const mpz_t ciphertext, const paillier_pubkey* pub, const zk_paillier_setup* setup)
{
	mpz_t g;
	int ok = 1;

	mpz_init(g);

	/* --- statement sanity (malicious-modulus defense) --- */
	if (mpz_sizeinbase(pub->n, 2) < ZK_PAILLIER_MIN_MODULUS_BITS) ok = 0; /* n >= 2048 bits */
	if (mpz_sgn(ciphertext) <= 0) ok = 0;
	if (mpz_sizeinbase(setup->ntilde, 2) < 1024) ok = 0;
	/* ntilde has no small factor (not prime / no small factors) */
	mpz_gcd(g, setup->ntilde, setup->primorial);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;
	/* generators are proper elements of Z_ntilde* */
	if (mpz_cmp_ui(setup->h1, 1) <= 0 || mpz_cmp(setup->h1, setup->ntilde) >= 0) ok = 0;
	if (mpz_cmp_ui(setup->h2, 1) <= 0 || mpz_cmp(setup->h2, setup->ntilde) >= 0) ok = 0;
	mpz_gcd(g, setup->h1, setup->ntilde);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;
	mpz_gcd(g, setup->h2, setup->ntilde);
	if (mpz_cmp_ui(g, 1) != 0) ok = 0;

	/* --- compact range proof: |plaintext| <= 2^768 --- */
	if (ok) ok = zk_range_proof_verify(range_proof, pub->n, ciphertext, setup);

	mpz_clear(g);
	return ok;
}
