/*
 * Copyright (c) 2016-2018 . All Rights Reserved.
 */

#ifndef XDRPROJECT_STELLAR_H
#define XDRPROJECT_STELLAR_H

#include <stdbool.h>
#include <stdint.h>

typedef uint32_t pb_size_t;
typedef uint_least8_t pb_byte_t;

#define PB_BYTES_ARRAY_T(n) struct { pb_size_t size; pb_byte_t bytes[n]; }

#define STELLAR_KEY_SIZE 32
#define STELLAR_ADDRESS_SIZE_RAW 35
#define STELLAR_ADDRESS_SIZE 56

typedef struct _StellarAssetType {
    bool has_type;
    uint32_t type;
    bool has_code;
    char code[13];
    bool has_issuer;
    char issuer[57];
/* @@protoc_insertion_point(struct:StellarAssetType) */
} StellarAssetType;

typedef struct _StellarPaymentOp {
    bool has_source_account;
    char source_account[57];
    bool has_destination_account;
    char destination_account[57];
    bool has_asset;
    StellarAssetType asset;
    bool has_amount;
    int64_t amount;
/* @@protoc_insertion_point(struct:StellarPaymentOp) */
} StellarPaymentOp;

typedef struct _StellarCreateAccountOp {
    bool has_source_account;
    char source_account[57];
    bool has_new_account;
    char new_account[57];
    bool has_starting_balance;
    int64_t starting_balance;
/* @@protoc_insertion_point(struct:StellarCreateAccountOp) */
} StellarCreateAccountOp;

typedef PB_BYTES_ARRAY_T(32) StellarSignedTx_public_key_t;
typedef PB_BYTES_ARRAY_T(64) StellarSignedTx_signature_t;
typedef struct _StellarSignedTx {
    bool has_public_key;
    StellarSignedTx_public_key_t public_key;
    bool has_signature;
    StellarSignedTx_signature_t signature;
/* @@protoc_insertion_point(struct:StellarSignedTx) */
} StellarSignedTx;

typedef PB_BYTES_ARRAY_T(32) StellarSignTx_memo_hash_t;
typedef struct _StellarSignTx {
    pb_size_t address_n_count;
    uint32_t address_n[10];
    bool has_network_passphrase;
    char network_passphrase[1024];
    bool has_source_account;
    char source_account[57];
    bool has_fee;
    uint32_t fee;
    bool has_sequence_number;
    uint64_t sequence_number;
    bool has_timebounds_start;
    uint32_t timebounds_start;
    bool has_timebounds_end;
    uint32_t timebounds_end;
    bool has_memo_type;
    uint32_t memo_type;
    bool has_memo_text;
    char memo_text[29];
    bool has_memo_id;
    uint64_t memo_id;
    bool has_memo_hash;
    StellarSignTx_memo_hash_t memo_hash;
    bool has_num_operations;
    uint32_t num_operations;
/* @@protoc_insertion_point(struct:StellarSignTx) */
} StellarSignTx;

bool stellar_getAddressBytes(char* str_address, uint8_t *out_bytes);

#endif //XDRPROJECT_STELLAR_H
