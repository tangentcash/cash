/**
 * @file paillier.c
 *
 * @date Created on: Sep 06, 2012
 * @author Camille Vuillaume (modified)
 * @copyright Camille Vuillaume, 2012
 *
 * This file is part of Paillier-GMP.
 *
 * Paillier-GMP is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 *
 * Paillier-GMP is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Paillier-GMP.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "paillier.h"
#include <stdlib.h>
#include "sha3.h"
#include "rand.h"
#define BIT2BYTE(a) (a+7)>>3

typedef struct
{
	mpz_t result; /**< result of exponentiation */
	mpz_t basis; /**< basis of exponentiation */
	mpz_t exponent; /**< exponent of exponentiation */
	mpz_t modulus; /**< modulus of exponentiation */
} exp_args;

void mpz_random_prime(mpz_t prime, mp_bitcnt_t len)
{
	mpz_t random_num;
	mpz_init(random_num);
	size_t seed_size = BIT2BYTE(len);
	char* seed = (char*)malloc(sizeof(char) * seed_size);
	do
	{
		random_buffer(seed, seed_size);
		mpz_import(random_num, seed_size, 1, sizeof(seed[0]), 0, 0, seed);
		mpz_setbit(random_num, len - 1);
		mpz_nextprime(prime, random_num);
	} while (len != (mp_bitcnt_t)mpz_sizeinbase(prime, 2));
	mpz_clear(random_num);
	free(seed);
}

void mpz_derive_prime(mpz_t prime, mp_bitcnt_t len, gmp_randstate_t random)
{
	mpz_t random_num;
	mpz_init(random_num);
	size_t seed_size = BIT2BYTE(len);
	char* seed = (char*)malloc(sizeof(char) * seed_size);
	do
	{
		random_buffer(seed, seed_size);
		mpz_urandomb(random_num, random, len);
		mpz_setbit(random_num, len - 1);
		mpz_nextprime(prime, random_num);
	} while (len != (mp_bitcnt_t)mpz_sizeinbase(prime, 2));
	mpz_clear(random_num);
	free(seed);
}

/**
 * The exponentiation is computed using Garner's method for the CRT:
 * - Exponentiation mod p: y_p = (x mod p)^{exp_p} mod p
 * - Exponentiation mod q: y_q = (x mod q)^{exp_q} mod q
 * - Recombination: y = y_p + p*(p^{-1} mod q)*(y_q-y_p) mod n
 * .
 * The exponentiations mod p and mod q run in their own thread.
 */
void mpz_crt_exp(mpz_t result, mpz_t base, mpz_t exp_p, mpz_t exp_q, mpz_t pinvq, mpz_t p, mpz_t q)
{
	mpz_t pq;
	exp_args* args_p, * args_q;

	mpz_init(pq);

	//prepare arguments for exponentiation mod p
	args_p = (exp_args*)malloc(sizeof(exp_args));
	mpz_init(args_p->result);
	mpz_init(args_p->basis);
	mpz_init(args_p->exponent);
	mpz_init(args_p->modulus);
	mpz_set(args_p->basis, base);
	mpz_set(args_p->exponent, exp_p);
	mpz_set(args_p->modulus, p);

	//prepare arguments for exponentiation mod q
	args_q = (exp_args*)malloc(sizeof(exp_args));
	mpz_init(args_q->result);
	mpz_init(args_q->basis);
	mpz_init(args_q->exponent);
	mpz_init(args_q->modulus);
	mpz_set(args_q->basis, base);
	mpz_set(args_q->exponent, exp_q);
	mpz_set(args_q->modulus, q);

	//compute exponentiation modulo p
	mpz_mod(args_p->result, base, p);
	mpz_powm(args_p->result, args_p->result, exp_p, p);

	//compute exponentiation modulo q
	mpz_mod(args_q->result, base, q);
	mpz_powm(args_q->result, args_q->result, exp_q, q);

	//recombination
	mpz_mul(pq, p, q);
	mpz_sub(result, args_q->result, args_p->result);
	mpz_mul(result, result, p);
	mpz_mul(result, result, pinvq);
	mpz_add(result, result, args_p->result);
	mpz_mod(result, result, pq);
	mpz_clear(pq);
	mpz_clear(args_p->result);
	mpz_clear(args_p->basis);
	mpz_clear(args_p->exponent);
	mpz_clear(args_p->modulus);
	mpz_clear(args_q->result);
	mpz_clear(args_q->basis);
	mpz_clear(args_q->exponent);
	mpz_clear(args_q->modulus);
	free(args_p);
	free(args_q);
}

void paillier_pubkey_init(paillier_pubkey* pub)
{
	mpz_init(pub->n);
	pub->len = 0;
}

void paillier_seckey_init(paillier_seckey* priv)
{
	mpz_init(priv->lambda);
	mpz_init(priv->mu);
	mpz_init(priv->p2);
	mpz_init(priv->q2);
	mpz_init(priv->p2invq2);
	mpz_init(priv->ninv);
	mpz_init(priv->n);
	priv->len = 0;
}

void paillier_pubkey_clear(paillier_pubkey* pub)
{
	mpz_clear(pub->n);
}

void paillier_seckey_clear(paillier_seckey* priv)
{
	mpz_clear(priv->lambda);
	mpz_clear(priv->mu);
	mpz_clear(priv->p2);
	mpz_clear(priv->q2);
	mpz_clear(priv->p2invq2);
	mpz_clear(priv->ninv);
	mpz_clear(priv->n);
}

/** Function L(u)=(u-1)/n
  *
  * @ingroup Paillier
  * @param[out] result output result (u-1)/n
  * @param[in] input u
  * @param[in] ninv input n^{-1} mod 2^len
  * @param[in] len input bit length
  * @return 0 if no error
  *
  * The function L is evaluated using the pre-computed value n^{-1} mod 2^len.
  * The calculation a/n is computed as a*n^{-1} mod 2^len
  * - First a non-modular multiplication with n^{-1} mod 2^len is calculated.
  * - Then the result is reduced by masking higher bits.
  */
void paillier_ell(mpz_t result, mpz_t input, mpz_t ninv, mp_bitcnt_t len)
{
	mpz_t mask;
	mpz_init(mask);
	mpz_sub_ui(result, input, 1);
	mpz_mul(result, result, ninv);
	mpz_setbit(mask, len);
	mpz_sub_ui(mask, mask, 1);
	mpz_and(result, result, mask);
	mpz_clear(mask);
}

/**
 * The function does the following.
 * - It generates two (probable) primes p and q having bits/2 bits.
 * - It computes the modulus n=p*q and sets the basis g to 1+n.
 * - It pre-computes n^{-1} mod 2^len.
 * - It pre-computes the CRT paramter p^{-2} mod q^2.
 * - It calculates lambda = lcm((p-1)*(q-1))
 * - It calculates mu = L(g^lambda mod n^2)^{-1} mod n using the CRT.
 * .
 * Since /dev/random is one of the sources of randomness in prime generation, the program may block.
 * In that case, you have to wait or move your mouse to feed /dev/random with fresh randomness.
 */
void paillier_keypair_random(paillier_pubkey* pub, paillier_seckey* priv, mp_bitcnt_t len)
{
	mpz_t p, q, n2, temp, mask, g;
	mpz_init(p);
	mpz_init(q);
	mpz_init(n2);
	mpz_init(temp);
	mpz_init(mask);
	mpz_init(g);

	//write bit lengths
	priv->len = len;
	pub->len = len;
retry:
	//generate p and q
	mpz_random_prime(p, len / 2);
	mpz_random_prime(q, len / 2);

	//calculate modulus n=p*q
	mpz_mul(pub->n, p, q);
	mpz_mul(priv->n, p, q);

	//set g = 1+n
	mpz_add_ui(g, pub->n, 1);

	//compute n^{-1} mod 2^{len}
	mpz_setbit(temp, len);
	if (!mpz_invert(priv->ninv, pub->n, temp))
		goto retry;

	//compute p^2 and q^2
	mpz_mul(priv->p2, p, p);
	mpz_mul(priv->q2, q, q);

	//generate CRT parameter
	mpz_invert(priv->p2invq2, priv->p2, priv->q2);

	//calculate lambda = lcm(p-1,q-1)
	mpz_clrbit(p, 0);
	mpz_clrbit(q, 0);
	mpz_lcm(priv->lambda, p, q);

	//calculate n^2
	mpz_mul(n2, pub->n, pub->n);

	//calculate mu
	mpz_crt_exp(temp, g, priv->lambda, priv->lambda, priv->p2invq2, priv->p2, priv->q2);
	paillier_ell(temp, temp, priv->ninv, len);
	if (!mpz_invert(priv->mu, temp, pub->n))
		goto retry;

	//free memory and exit
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n2);
	mpz_clear(temp);
	mpz_clear(mask);
	mpz_clear(g);
}

void paillier_keypair_derive(paillier_pubkey* pub, paillier_seckey* priv, mp_bitcnt_t len, const unsigned char* message, mp_bitcnt_t message_size)
{
	gmp_randstate_t random;
	gmp_randinit_mt(random);
	
	uint8_t digest[64];
	sha3_512(message, message_size, digest);

	mpz_t seed;
	mpz_init(seed);
	mpz_import(seed, sizeof(digest), 1, 1, 1, 0, digest);
	gmp_randseed(random, seed);
	mpz_clear(seed);

	mpz_t p, q, n2, temp, mask, g;
	mpz_init(p);
	mpz_init(q);
	mpz_init(n2);
	mpz_init(temp);
	mpz_init(mask);
	mpz_init(g);

	//write bit lengths
	priv->len = len;
	pub->len = len;
retry:
	//generate p and q
	mpz_derive_prime(p, len / 2, random);
	mpz_derive_prime(q, len / 2, random);

	//calculate modulus n=p*q
	mpz_mul(pub->n, p, q);
	mpz_mul(priv->n, p, q);

	//set g = 1+n
	mpz_add_ui(g, pub->n, 1);

	//compute n^{-1} mod 2^{len}
	mpz_setbit(temp, len);
	if (!mpz_invert(priv->ninv, pub->n, temp))
		goto retry;

	//compute p^2 and q^2
	mpz_mul(priv->p2, p, p);
	mpz_mul(priv->q2, q, q);

	//generate CRT parameter
	mpz_invert(priv->p2invq2, priv->p2, priv->q2);

	//calculate lambda = lcm(p-1,q-1)
	mpz_clrbit(p, 0);
	mpz_clrbit(q, 0);
	mpz_lcm(priv->lambda, p, q);

	//calculate n^2
	mpz_mul(n2, pub->n, pub->n);

	//calculate mu
	mpz_crt_exp(temp, g, priv->lambda, priv->lambda, priv->p2invq2, priv->p2, priv->q2);
	paillier_ell(temp, temp, priv->ninv, len);
	if (!mpz_invert(priv->mu, temp, pub->n))
		goto retry;

	//free memory and exit
	mpz_clear(p);
	mpz_clear(q);
	mpz_clear(n2);
	mpz_clear(temp);
	mpz_clear(mask);
	mpz_clear(g);
	gmp_randclear(random);
}

/**
 * The function calculates c=g^m*r^n mod n^2 with r random number.
 * Encryption benefits from the fact that g=1+n, because (1+n)^m = 1+n*m mod n^2.
 */
void paillier_encrypt(mpz_t ciphertext, mpz_t plaintext, paillier_pubkey* pub)
{
	mpz_t n2, r;
	mpz_init(n2);
	mpz_init(r);

	//re-compute n^2
	mpz_mul(n2, pub->n, pub->n);

	//generate random r and reduce modulo n
retry:
	mpz_random_prime(r, pub->len);
	mpz_mod(r, r, pub->n);
	if (mpz_cmp_ui(r, 0) == 0)
		goto retry;

	//compute r^n mod n2
	mpz_powm(ciphertext, r, pub->n, n2);

	//compute (1+m*n)
	mpz_mul(r, plaintext, pub->n);
	mpz_add_ui(r, r, 1);

	//multiply with (1+m*n)
	mpz_mul(ciphertext, ciphertext, r);
	mpz_mod(ciphertext, ciphertext, n2);
	mpz_clear(n2);
	mpz_clear(r);
}

/**
 * The decryption function computes m = L(c^lambda mod n^2)*mu mod n.
 * The exponentiation is calculated using the CRT, and exponentiations mod p^2 and q^2 run in their own thread.
 *
 */
void paillier_decrypt(mpz_t plaintext, mpz_t ciphertext, paillier_seckey* priv)
{
	//compute exponentiation c^lambda mod n^2
	mpz_crt_exp(plaintext, ciphertext, priv->lambda, priv->lambda, priv->p2invq2, priv->p2, priv->q2);

	//compute L(c^lambda mod n^2)
	paillier_ell(plaintext, plaintext, priv->ninv, priv->len);

	//compute L(c^lambda mod n^2)*mu mod n
	mpz_mul(plaintext, plaintext, priv->mu);
	mpz_mod(plaintext, plaintext, priv->n);
}

/**
 * "Add" two plaintexts homomorphically by multiplying ciphertexts modulo n^2.
 * For example, given the ciphertexts c1 and c2, encryptions of plaintexts m1 and m2,
 * the value c3=c1*c2 mod n^2 is a ciphertext that decrypts to m1+m2 mod n.
 */
void paillier_homomorphic_add(mpz_t ciphertext3, mpz_t ciphertext1, mpz_t ciphertext2, paillier_pubkey* pub)
{
	mpz_t n2;
	mpz_init(n2);
	mpz_mul(n2, pub->n, pub->n);
	mpz_mul(ciphertext3, ciphertext1, ciphertext2);
	mpz_mod(ciphertext3, ciphertext3, n2);
	mpz_clear(n2);
}

void paillier_homomorphic_addc(mpz_t ciphertext2, mpz_t ciphertext1, mpz_t constant, paillier_pubkey* pub)
{
	mpz_t ciphertext3;
	mpz_init(ciphertext3);
	paillier_encrypt(ciphertext3, constant, pub);
	paillier_homomorphic_add(ciphertext2, ciphertext1, ciphertext3, pub);
	mpz_clear(ciphertext3);
}

/**
 * "Multiplies" a plaintext with a constant homomorphically by exponentiating the ciphertext modulo n^2 with the constant as exponent.
 * For example, given the ciphertext c, encryptions of plaintext m, and the constant 5,
 * the value c3=c^5 n^2 is a ciphertext that decrypts to 5*m mod n.
 */
void paillier_homomorphic_mulc(mpz_t ciphertext2, mpz_t ciphertext1, mpz_t constant, paillier_pubkey* pub)
{
	mpz_t n2;
	mpz_init(n2);
	mpz_mul(n2, pub->n, pub->n);
	mpz_powm(ciphertext2, ciphertext1, constant, n2);
	mpz_clear(n2);
}