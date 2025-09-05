/**
 * @file paillier.h
 *
 * @date 		Created on: Aug 25, 2012
 * @author 		Camille Vuillaume (modified)
 * @copyright 	Camille Vuillaume, 2012
 * @defgroup 	Paillier Paillier cryptosystem
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
 */
#ifndef PAILLIER_H_
#define PAILLIER_H_
#include <stdio.h>
#include <gmp.h>
#ifdef __cplusplus
#define PE_CPP_IMPORT extern "C"
#else
#define PE_CPP_IMPORT
#endif

 /** Private key
  *
  * @ingroup Paillier
  *
  * In addition to the usual private key elements, the structure contains:
  * - CRT parameters for accelerating exponentiations during decryption
  * - The modular inverse n^{-1} mod 2^len for accelerating the calculation of L
  */
typedef struct
{
	mp_bitcnt_t len; /**< bit length of n */
	mpz_t lambda;		/**< least common multiple of p and q */
	mpz_t mu;			/**< Modular inverse */
	mpz_t p2;			/**< square of prime number p */
	mpz_t q2;			/**< square of prime number q */
	mpz_t p2invq2;		/**< CRT parameter p^{-2} mod q^2 */
	mpz_t ninv;			/**< modular inverse n^{-1} mod 2^len */
	mpz_t n;			/**< n=p*q */
} paillier_seckey;

/** Public key
 *
 * @ingroup Paillier
 *
 * The generator is 1+n. This is fine in view of security because Class[g,n] is random self-reducible over g,
 * therefore the security of the cryptosystem does not depend on the choice of g.
 */
typedef struct
{
	mp_bitcnt_t len; /**< bit length of n */
	mpz_t n; 			/**< modulus n */
} paillier_pubkey;

/** Memory allocation for public key
 *
 * @ingroup Paillier
 * @param[in] pub input public key
 */
PE_CPP_IMPORT void paillier_pubkey_init(paillier_pubkey* pub);

/** Memory allocation for private key
 *
 * @ingroup Paillier
 * @param[in] priv input private key
 */
PE_CPP_IMPORT void paillier_seckey_init(paillier_seckey* priv);

/** Free memory for public key
 *
 * @ingroup Paillier
 * @param[in] pub input public key
 */
PE_CPP_IMPORT void paillier_pubkey_clear(paillier_pubkey* pub);

/** Free memory for private key
 *
 * @ingroup Paillier
 * @param[in] priv input private key
 */
PE_CPP_IMPORT void paillier_seckey_clear(paillier_seckey* priv);

/** Key generation
 *
 * @ingroup Paillier
 * @param[out] pub output public key
 * @param[out] priv output private key
 * @param[in] len input bit length of public modulus
 * @return 0 if no error
 */
PE_CPP_IMPORT void paillier_keypair_random(
	paillier_pubkey* pub,
	paillier_seckey* priv,
	mp_bitcnt_t len);

PE_CPP_IMPORT void paillier_keypair_derive(
	paillier_pubkey* pub,
	paillier_seckey* priv,
	mp_bitcnt_t len,
	const unsigned char* message,
	mp_bitcnt_t message_size);

/** Encrypt
 *
 * @ingroup Paillier
 * @param[out] ciphertext output ciphertext c=g^m*r^n mod n^2
 * @param[in] plaintext input plaintext m
 * @param[in] pub input public key
 * @return 0 if no error
 */
PE_CPP_IMPORT void paillier_encrypt(
	mpz_t ciphertext,
	mpz_t plaintext,
	paillier_pubkey* pub);

/** Decrypt
 *
 * @ingroup Paillier
 * @param[out] plaintext output plaintext m
 * @param[in] ciphertext input ciphertext
 * @param[in] priv input private key
 * @return 0 if no error
 */
PE_CPP_IMPORT void paillier_decrypt(
	mpz_t plaintext,
	mpz_t ciphertext,
	paillier_seckey* priv);

/** Homomorphically add two plaintexts
 *
 * @ingroup Paillier
 * @param[out] ciphertext3 output ciphertext corresponding to the homomorphic addition of the two plaintexts
 * @param[in] ciphertext1 input first ciphertext corresponding to a plaintext to be homomorphically added
 * @param[in] ciphertext2 input second ciphertext corresponding to a plaintext to be homomorphically added
 * @param[in] pub input public key
 * @return 0 if no error
 */
PE_CPP_IMPORT void paillier_homomorphic_add(
	mpz_t ciphertext3,
	mpz_t ciphertext1,
	mpz_t ciphertext2,
	paillier_pubkey* pub);

PE_CPP_IMPORT void paillier_homomorphic_addc(
	mpz_t ciphertext2,
	mpz_t ciphertext1,
	mpz_t constant,
	paillier_pubkey* pub);

/** Homomorphically multiply a plaintext with a constant
 *
 * @ingroup Paillier
 * @param[out] ciphertext2 output ciphertext corresponding to the homomorphic multiplication of the plaintext with the constant
 * @param[in] ciphertext1 input ciphertext corresponding to a plaintext to be homomorphically multiplied
 * @param[in] constant input constant to be homomorphically multiplied
 * @param[in] pub input public key
 * @return 0 if no error
 */
PE_CPP_IMPORT void paillier_homomorphic_mulc(
	mpz_t ciphertext2,
	mpz_t ciphertext1,
	mpz_t constant,
	paillier_pubkey* pub);

#endif /* PAILLIER_H_ */