#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "btc.h"
#include "random.h"

static secp256k1_context* secp256k1_ctx = NULL;
static size_t start_stop_count = 0;

btc_bool btc_ecc_start(void)
{
    if (start_stop_count > 0)
        return true;

    btc_random_init();

    secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (secp256k1_ctx == NULL)
        return false;

    uint8_t seed[32];
    int ret;
    ret = btc_random_bytes(seed, 32, 0);
    if (!ret)
        return false;

    ret = secp256k1_context_randomize(secp256k1_ctx, seed);
    if (!ret)
        return false;

    ++start_stop_count;
    return true;
}

void btc_ecc_stop(void)
{
    if (start_stop_count-- > 1)
        return;

    secp256k1_context* ctx = secp256k1_ctx;
    secp256k1_ctx = NULL;
    start_stop_count = 0;

    if (ctx) {
        secp256k1_context_destroy(ctx);
    }
}

void btc_ecc_get_pubkey(const uint8_t* private_key, uint8_t* public_key, size_t* in_outlen, btc_bool compressed)
{
    secp256k1_pubkey pubkey;
    assert(secp256k1_ctx);
    assert((int)*in_outlen == (compressed ? 33 : 65));
    memset(public_key, 0, *in_outlen);

    if (!secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, (const unsigned char*)private_key)) {
        return;
    }

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, in_outlen, &pubkey, compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED)) {
        return;
    }

    return;
}

btc_bool btc_ecc_private_key_tweak_add(uint8_t* private_key, const uint8_t* tweak)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_seckey_tweak_add(secp256k1_ctx, (unsigned char*)private_key, (const unsigned char*)tweak);
}

btc_bool btc_ecc_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak)
{
    size_t out = BTC_ECKEY_COMPRESSED_LENGTH;
    secp256k1_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout, 33))
        return false;

    if (!secp256k1_ec_pubkey_tweak_add(secp256k1_ctx, &pubkey, (const unsigned char*)tweak))
        return false;

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key_inout, &out, &pubkey, SECP256K1_EC_COMPRESSED))
        return false;

    return true;
}

btc_bool btc_xonly_public_key_tweak_add(uint8_t* public_key_inout, const uint8_t* tweak)
{
    secp256k1_xonly_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_xonly_pubkey_parse(secp256k1_ctx, &pubkey, public_key_inout))
        return false;

    secp256k1_pubkey tweak_pubkey;
    if (!secp256k1_xonly_pubkey_tweak_add(secp256k1_ctx, &tweak_pubkey, &pubkey, (const unsigned char*)tweak))
        return false;

    size_t out = BTC_ECKEY_UNCOMPRESSED_LENGTH;
    uint8_t serialized_pubkey[BTC_ECKEY_UNCOMPRESSED_LENGTH];
    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, serialized_pubkey, &out, &tweak_pubkey, SECP256K1_EC_UNCOMPRESSED))
        return false;

    memcpy(public_key_inout, serialized_pubkey + 1, 32);
    return true;
}

btc_bool btc_ecc_verify_privatekey(const uint8_t* private_key)
{
    assert(secp256k1_ctx);
    return secp256k1_ec_seckey_verify(secp256k1_ctx, (const unsigned char*)private_key);
}

btc_bool btc_ecc_verify_pubkey(const uint8_t* public_key, btc_bool compressed)
{
    secp256k1_pubkey pubkey;

    assert(secp256k1_ctx);
    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65)) {
        memset(&pubkey, 0, sizeof(pubkey));
        return false;
    }

    memset(&pubkey, 0, sizeof(pubkey));
    return true;
}

btc_bool btc_ecc_sign(const uint8_t* private_key, const uint256 hash, unsigned char* sigder, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    if (!secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder, outlen, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_sign_compact(const uint8_t* private_key, const uint256 hash, unsigned char* sigcomp, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_sign(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    *outlen = 64;
    if (!secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_sign_compact_recoverable(const uint8_t* private_key, const uint256 hash, unsigned char* sigrec, size_t* outlen, int *recid)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_recoverable_signature sig;
    if (!secp256k1_ecdsa_sign_recoverable(secp256k1_ctx, &sig, hash, private_key, secp256k1_nonce_function_rfc6979, NULL))
        return 0;

    *outlen = 65;
    if (!secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_ctx, sigrec, recid, &sig))
        return 0;

    return 1;
}

btc_bool btc_ecc_recover_pubkey(const unsigned char* sigrec, const uint256 hash, const int recid, uint8_t* public_key, size_t *outlen)
{
    assert(secp256k1_ctx);

    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_recoverable_signature sig;

    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1_ctx, &sig, sigrec, recid))
        return false;

    if (!secp256k1_ecdsa_recover(secp256k1_ctx, &pubkey, &sig, hash))
        return 0;

    if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, public_key, outlen, &pubkey, SECP256K1_EC_COMPRESSED))
        return 0;

    return 1;
}

btc_bool btc_ecc_verify_sig(const uint8_t* public_key, btc_bool compressed, const uint256 hash, unsigned char* sigder, size_t siglen)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pubkey;

    if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &pubkey, public_key, compressed ? 33 : 65))
        return false;

    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder, siglen))
        return false;

    return secp256k1_ecdsa_verify(secp256k1_ctx, &sig, hash, &pubkey);
}

btc_bool btc_ecc_compact_to_der_normalized(unsigned char* sigcomp_in, unsigned char* sigder_out, size_t* sigder_len_out)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(secp256k1_ctx, &sig, sigcomp_in))
        return false;

    secp256k1_ecdsa_signature sigNorm;
    secp256k1_ecdsa_signature_normalize(secp256k1_ctx, &sigNorm, &sig);

    return secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx, sigder_out, sigder_len_out, &sigNorm);
}

btc_bool btc_ecc_der_to_compact(unsigned char* sigder_in, size_t sigder_len, unsigned char* sigcomp_out)
{
    assert(secp256k1_ctx);

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx, &sig, sigder_in, sigder_len))
        return false;

    return secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, sigcomp_out, &sig);
}

btc_bool btc_ecc_sign_schnorr(const uint8_t* private_key, const uint256 hash, const uint256 auxiliary, unsigned char* sigcomp, size_t* outlen)
{
    assert(secp256k1_ctx);

    secp256k1_keypair keypair;
    if (secp256k1_keypair_create(secp256k1_ctx, &keypair, private_key) != 1)
        return 0;

    *outlen = 64;
    if (secp256k1_schnorrsig_sign32(secp256k1_ctx, sigcomp, hash, &keypair, auxiliary) != 1)
        return 0;

    return 1;
}

btc_bool btc_ecc_tagged_sha256(const uint8_t* message, size_t message_size, const uint8_t* tag, size_t tag_size, uint256 hash_out)
{
    assert(secp256k1_ctx);
    return secp256k1_tagged_sha256(secp256k1_ctx, hash_out, tag, tag_size, message, message_size) == 1;
}