#ifndef ETHC_H
#define ETHC_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#define eth_signed eth_ecdsa_signature
#define ETH_RLP_ENCODE 0
#define ETH_RLP_DECODE 1
#define ETHC_RLP_FRAME_INITIAL_SIZE 1024
#define ETH_ABI_ENCODE 0
#define ETH_ABI_DECODE 1
#define ETH_ABI_WORD_SIZE 32
#define ETHC_ABI_BUFFER_INITIAL_SIZE ETH_ABI_WORD_SIZE * 128

/*! @brief Holds ECDSA signature */
struct eth_ecdsa_signature
{
    /*! @brief R value */
    uint8_t r[32];
    /*! @brief S value */
    uint8_t s[32];
    /*! @brief Recovery id */
    int recid;
};

struct eth_rlp
{
    struct ethc_rlp_frame* cframe;
    int m;
};

struct ethc_rlp_frame
{
    struct ethc_rlp_frame* pframe;
    size_t offset;
    uint8_t* buf;
    size_t len;
};

struct eth_abi
{
    struct ethc_abi_frame* cframe;
    int m;
};

struct ethc_abi_buf
{
    uint8_t* buf;
    size_t len;
    size_t offset;
    size_t doffset;
};

struct ethc_abi_frame
{
    struct ethc_abi_frame* pframe;
    struct ethc_abi_buf* buf;
    struct ethc_abi_buf* dybufs[64];
    uint8_t dybuflen;
    uint64_t len;
};

/*!
 * @brief Computes the keccak hash for the input data.
 *
 * @param[out] dest A pointer to a 32-byte array to write the hash to.
 * @param[in] bytes A pointer to the input data.
 * @param[in] len The length of the input data.
 *
 * @code{.c}
 *   #include <stdio.h>
 *   #include "keccak256.h"
 *
 *   int main(void) {
 *     uint8_t keccak[32], data[2] = {0x28, 0xa1};
 *     size_t datalen = 2, i;
 *
 *     eth_keccak256(keccak, data, datalen);
 *
 *     for(i = 0; i < 32; i++)
 *       printf("%.2x", keccak[i]);
 *     printf("\n");
 *
 *     return 0;
 *   }
 * @endcode
 */
int eth_keccak256(uint8_t* dest, const uint8_t* bytes, size_t len);

/*!
 * @brief Checks whether the given string is hex or not
 *
 * @param[in] str Target string to check
 * @param[in] len Length of the input string (`-1` if the string is NUL-terminated)
 * @return `1` when the input is valid hex, `-1` otherwise
 */
int eth_is_hex(const char* str, int len);

/*!
 * @brief Left pads the hexadecimal input
 *
 * @param[in] dest String to write the result to
 * @param[in] str Original hexadecimal value
 * @param[in] len Length of the input string (`-1` if the string is NUL-terminated)
 * @param[in] width Total width of the output
 * @return `1` on success, `-1` otherwise
 */
int eth_hex_pad_left(char* dest, const char* str, int len, size_t width);

/*!
 * @brief Right pads the hexadecimal input
 *
 * @param[in] dest String to write the result to
 * @param[in] str Original hexadecimal value
 * @param[in] len Length of the input string (`-1` if the string is NUL-terminated)
 * @param[in] width Total width of the output
 * @return `1` on success, `-1` otherwise
 */
int eth_hex_pad_right(char* dest, const char* str, int len, size_t width);

/*!
 * @brief Converts bytes to hexadecimal string
 *
 * @param[in] dest String to write the result to
 * @param[in] bytes Bytes to read the data from
 * @param[in] len Length of the input bytes
 * @return `1` on success, `-1` otherwise
 */
int eth_hex_from_bytes(char** dest, const uint8_t* bytes, size_t len);

/*!
 * @brief Converts hexadecimal string to bytes
 *
 * @param[in] dest Bytes to write the data to
 * @param[in] hex Hexadecimal string to read the data from
 * @param[in] hlen Length of hexadecimal input string
 * @return `1` on success, `-1` otherwise
 */
int eth_hex_to_bytes(uint8_t** dest, const char* hex, int hlen);

int ethc_rand(uint8_t* bytes, size_t len);
int ethc_strncasecmp(const char* s1, const char* s2, size_t len);
int ethc_hexcharb(char h);
char ethc_hexchar(uint8_t d);


/**
 * @brief Checks whether the `addr` is an address or not.
 *
 * @param[in] addr Target address to check.
 * @return `1` if `addr` is valid, `-1` otherwise.
 */
int eth_is_address(const char* addr);

/**
 * @brief Checks whether the `addr` is a valid checksum address or not.
 *
 * @param[in] addr Target address to check.
 * @return `1` if `addr` is valid, `-1` otherwise.
 *
 * @code{.c}
 *   #include <stdio.h>
 *   #include "address.h"
 *
 *   int main(void) {
 *     const char *addr0 = "0x1B9F402eaE18F10B1fD20d15b0c91EA64e3Ae1Ed";
 *     const char *addr1 = "0x51fabbb96a297368f0bf2dedffa285a921f7d613";
 *
 *     printf("addr0 is checksum address: %d\n", eth_is_checksum_address(addr0));
 *     printf("addr1 is checksum address: %d\n", eth_is_checksum_address(addr1));
 *
 *     return 0
 *   }
 * @endcode
 */
int eth_is_checksum_address(const char* addr);

/**
 * @brief Converts given `addr` to checksum address.
 *
 * @param[out] addr Target address.
 * @return `1` on success, `-1` otherwise.
 *
 * @code{.c}
 *   #include <stdio.h>
 *   #include "address.h"
 *
 *   int main(void) {
 *     char *addr = "0x1b9f402eae18f10b1fd20d15b0c91ea64e3ae1ed";
 *
 *     printf("before checksum: %s\n", addr);
 *
 *     eth_to_checksum_address(addr);
 *
 *     printf("after checksumm: %s\n", addr);
 *
 *     return 0
 *   }
 * @endcode
 */
int eth_to_checksum_address(char* addr);

/*!
    * @brief Extracts public key from private key.
    *
    * @param[out] dest A pointer to 64-byte array where the public key will be placed.
    * @param[in] privkey A pointer to 32-byte array to read the private key from.
    * @return `1` on success, `-1` otherwise.
    */
int eth_ecdsa_pubkey_get(uint8_t* dest, const uint8_t* privkey);

/*!
    * @brief Creates an ECDSA signature.
    *
    * @param[out] dest A pointer to `eth_ecdsa_signature` where the signature will be placed..
    * @param[in] privkey A pointer to 32-byte array to read the private key from.
    * @param[in] data32 A pointer to 32-byte input data.
    * @return `1` on success, `-1` otherwise.
    */
int eth_ecdsa_sign(struct eth_ecdsa_signature* dest, const uint8_t* privkey, const uint8_t* data32);

int eth_rlp_init(struct eth_rlp* rlp, int m);
int eth_rlp_uint8(struct eth_rlp* rlp, uint8_t* d);
int eth_rlp_uint16(struct eth_rlp* rlp, uint16_t* d);
int eth_rlp_uint32(struct eth_rlp* rlp, uint32_t* d);
int eth_rlp_uint64(struct eth_rlp* rlp, uint64_t* d);

/*!
    * @brief Encodes/decodes at most 64 bit unsigned integer.
    * @details The difference between this function and `eth_rlp_uint64` is that,
    *          `eth_rlp_uint64` reads exactly 8 bytes from the integer, while this
    *          function will read bytes based on the size of the integer.
    *
    * @param[in] rlp Target rlp.
    * @param[inout] d Ponter to uint64_t to read/write the data from/to.
    * @return `1` on success, `-1` otherwise.
    */
int eth_rlp_uint(struct eth_rlp* rlp, uint64_t* d);
int eth_rlp_address(struct eth_rlp* rlp, char** addr);
int eth_rlp_array(struct eth_rlp* rlp);
int eth_rlp_array_end(struct eth_rlp* rlp);
int eth_rlp_bytes(struct eth_rlp* rlp, uint8_t** bytes, size_t* len);
int eth_rlp_hex(struct eth_rlp* rlp, char** hex, int* len);
int eth_rlp_len(struct eth_rlp* rlp, size_t* len, uint8_t* base);
int eth_rlp_to_hex(char** dest, struct eth_rlp* src);
int eth_rlp_to_bytes(uint8_t** dest, size_t* len, struct eth_rlp* src);
int eth_rlp_from_hex(struct eth_rlp* dest, char* hex, int len);
int eth_rlp_free(struct eth_rlp* rlp);


/*!
 * @brief Initializes the given abi struct.
 *
 * @param[in] abi Target abi struct that needs to be initialized.
 * @param[in] m Mode in which the abi functions should work (accepts ``ETH_ABI_ENCODE`` or ``ETH_ABI_DECODE``)
 * @return `1` on success, `-1` otherwise.
 * @see `eth_abi_free`
 */
int eth_abi_init(struct eth_abi* abi, int m);

/*!
 * @brief Releases internal memory allocated for the given abi struct.
 *
 * @param[in] abi Target abi
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_free(struct eth_abi* abi);

/*!
 * @brief Encodes/decodes "boolean value" (1 or 0)
 *
 * @param[in] abi Target abi.
 * @param[inout] b Ponter to uint8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_bool(struct eth_abi* abi, uint8_t* b);

/*!
 * @brief Encodes/decodes signed 8 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to int8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_int8(struct eth_abi* abi, int8_t* d);

/*!
 * @brief Encodes/decodes signed 16 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to int16_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_int16(struct eth_abi* abi, int16_t* d);

/*!
 * @brief Encodes/decodes signed 32 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to int32_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_int32(struct eth_abi* abi, int32_t* d);

/*!
 * @brief Encodes/decodes signed 64 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to int64_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_int64(struct eth_abi* abi, int64_t* d);

/*!
 * @brief Encodes/decodes unsigned 8 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to uint8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_uint8(struct eth_abi* abi, uint8_t* d);

/*!
 * @brief Encodes/decodes unsigned 16 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to uint16_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_uint16(struct eth_abi* abi, uint16_t* d);

/*!
 * @brief Encodes/decodes unsigned 32 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to uint32_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_uint32(struct eth_abi* abi, uint32_t* d);

/*!
 * @brief Encodes/decodes unsigned 64 bit integer.
 *
 * @param[in] abi Target abi.
 * @param[inout] d Ponter to uint64_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_uint64(struct eth_abi* abi, uint64_t* d);

/*!
 * @brief Encodes/decodes address.
 *
 * @param[in] abi Target abi.
 * @param[inout] addr Ponter to address to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_address(struct eth_abi* abi, char** addr);

/*!
 * @brief Encodes/decodes 8 byte array.
 *
 * @param[in] abi Target abi.
 * @param[inout] bytes Ponter to uint8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_bytes8(struct eth_abi* abi, uint8_t* bytes);

/*!
 * @brief Encodes/decodes 16 byte array.
 *
 * @param[in] abi Target abi.
 * @param[inout] bytes Ponter to uint8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_bytes16(struct eth_abi* abi, uint8_t* bytes);

/*!
 * @brief Encodes/decodes 32 byte array.
 *
 * @param[in] abi Target abi.
 * @param[inout] bytes Ponter to uint8_t to read/write the data from/to.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_bytes32(struct eth_abi* abi, uint8_t* bytes);

/*!
 * @brief Encodes/decodes variable length bytes.
 *
 * @param[in] abi Target abi.
 * @param[inout] bytes Ponter to uint8_t array to read/write the data from/to.
 * @param[inout] len Length of encoded/decodes bytes.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_bytes(struct eth_abi* abi, uint8_t** bytes, size_t* len);

/*!
 * @brief Converts ABI to hex string.
 *
 * @param[in] abi Target abi.
 * @param[out] hex Pointer to string where the hexadecimal value will be placed.
 * @param[out] len Pointer to size_to where the length of hexadecimal value will be placed.
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_to_hex(struct eth_abi* abi, char** hex, size_t* len);

/*!
 * @brief Loads ABI from hex string.
 *
 * @param[in] abi Target abi.
 * @param[out] hex Hexadecimal string.
 * @param[out] len Length of `hex`
 * @return `1` on success, `-1` otherwise.
 */
int eth_abi_from_hex(struct eth_abi* abi, char* hex, int len);

/*!
 * @brief Denotes the start of a call.
 *
 * @param[in] abi Target abi.
 * @param[inout] fn Pointer to string to read/write the data from/to.
 * @param[inout] len Pointer to int to read/write the length from/to.
 * @return `1` on success, `-1` otherwise.
 *
 * @code{.c}
 *   // ...
 *   char *func = "balanceOf(address)";
 *   eth_abi_call(&abi, &func, NULL);
 * @endcode
 *
 * @note `len` can be `NULL` (`NULL` means the `fn` is NULL terminated on encode and the length is not needed on decode)
 * @see `eth_abi_call_end`
 */
int eth_abi_call(struct eth_abi* abi, char** fn, int* len);

/*!
 * @brief Denotes the end of a call.
 *
 * @param[in] abi Target abi.
 */
int eth_abi_call_end(struct eth_abi* abi);

/*!
 * @brief Denotes the start of an array.
 *
 * @param[in] abi Target abi.
 * @param[out] len Length of the array.
 *
 * @code{.c}
 *   // ...
 *   eth_abi_call(&abi, NULL);
 *     eth_abi_uint8(&abi, &myint);
 *   eth_abi_call_end(&abi, NULL);
 * @endcode
 *
 * @note `len` is ignored on encode.
 * @see `eth_abi_array_end`
 */
int eth_abi_array(struct eth_abi* abi, uint64_t* len);

/*!
 * @brief Denotes the end of an array.
 *
 * @param[in] abi Target abi.
 */
int eth_abi_array_end(struct eth_abi* abi);


#endif