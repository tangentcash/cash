/*
 * Intermediate level API for Daan Sprenkels' Shamir secret sharing library
 * Copyright (c) 2017 Daan Sprenkels <hello@dsprenkels.com>
 */


#ifndef sss_SSS_H_
#define sss_SSS_H_
#include <inttypes.h>
#define sss_KEYSHARE_LEN 33 /* 1 + 32 */
#define sss_MLEN sizeof(uint8_t[64]) /* Length of the message (must be known at compile-time) */
#define sss_CLEN (sss_MLEN + 16) /* Length of the ciphertext, including the message authentication code */
#define sss_SHARE_LEN (sss_CLEN + sss_KEYSHARE_LEN) /* Length of a SSS share */

typedef uint8_t sss_Keyshare[sss_KEYSHARE_LEN]; /* One share of a cryptographic key which is shared using Shamir's the `sss_create_keyshares` function. */
typedef uint8_t sss_Share[sss_SHARE_LEN]; /* One share of a secret which is shared using Shamir's the `sss_create_shares` function. */


/*
 * Share the secret given in `key` into `n` shares with a treshold value given
 * in `k`. The resulting shares are written to `out`.
 *
 * The share generation that is done in this function is only secure if the key
 * that is given is indeed a cryptographic key. This means that it should be
 * randomly and uniformly generated string of 32 bytes.
 *
 * Also, for performance reasons, this function assumes that both `n` and `k`
 * are *public* values.
 *
 * If you are looking for a function that *just* creates shares of arbitrary
 * data, you should use the `sss_create_shares` function in `sss.h`.
 */
void sss_create_keyshares(sss_Keyshare* out,
                          const uint8_t key[32],
                          uint8_t n,
                          uint8_t k);


/*
 * Combine the `k` shares provided in `shares` and write the resulting key to
 * `key`. The amount of shares used to restore a secret may be larger than the
 * threshold needed to restore them.
 *
 * This function does *not* do *any* checking for integrity. If any of the
 * shares not original, this will result in an invalid resored value.
 * All values written to `key` should be treated as secret. Even if some of the
 * shares that were provided as input were incorrect, the resulting key *still*
 * allows an attacker to gain information about the real key.
 *
 * This function treats `shares` and `key` as secret values. `k` is treated as
 * a public value (for performance reasons).
 *
 * If you are looking for a function that combines shares of arbitrary
 * data, you should use the `sss_combine_shares` function in `sss.h`.
 */
void sss_combine_keyshares(uint8_t key[32],
                           const sss_Keyshare* shares,
                           uint8_t k);

/*
 * Create `n` shares of the secret data `data`. Share such that `k` or more
 * shares will be able to restore the secret.
 *
 * This function will put the resulting shares in the array pointed to by
 * `out`. The caller has to guarantee that this array will fit at least `n`
 * instances of `sss_Share`.
 */
void sss_create_shares(sss_Share* out,
                       const uint8_t* data,
                       uint8_t n,
                       uint8_t k);


/*
 * Combine the `k` shares pointed to by `shares` and put the resulting secret
 * data in `data`. The caller has to ensure that the `data` array will fit
 * at least `sss_MLEN` (default: 64) bytes.
 *
 * On success, this function will return 0. If combining the secret fails,
 * this function will return a nonzero return code. On failure, the value
 * in `data` may have been altered, but must still be considered secret.
 */
int sss_combine_shares(uint8_t* data,
                       const sss_Share* shares,
                       uint8_t k);


#endif /* sss_SSS_H_ */
