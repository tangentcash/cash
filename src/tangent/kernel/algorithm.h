#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "../layer/format.h"

namespace Tangent
{
	namespace Algorithm
	{
		using AssetId = uint256_t;
		using Sighash = uint8_t[65];
		using Seckey = uint8_t[32];
		using Pubkey = uint8_t[33];
		using Pubkeyhash = uint8_t[20];

		class Signing
		{
		public:
			static String Mnemonicgen(uint16_t Strength = 256);
			static void Keygen(Seckey PrivateKey);
			static bool Recover(const uint256_t& Hash, Pubkey PublicKey, const Sighash Signature);
			static bool RecoverHash(const uint256_t& Hash, Pubkeyhash PublicKeyHash, const Sighash Signature);
			static bool Sign(const uint256_t& Hash, const Seckey PrivateKey, Sighash Signature);
			static bool Verify(const uint256_t& Hash, const Pubkey PublicKey, const Sighash Signature);
			static bool VerifyMnemonic(const std::string_view& Mnemonic);
			static bool VerifyPrivateKey(const Seckey PrivateKey);
			static bool VerifyPublicKey(const Pubkey PublicKey);
			static bool VerifyAddress(const std::string_view& Address);
			static bool DerivePrivateKey(const std::string_view& Mnemonic, Seckey PrivateKey);
			static void DerivePrivateKey(const std::string_view& Seed, Seckey PrivateKey, size_t Iterations);
			static void DerivePublicKey(const Seckey PrivateKey, Pubkey PublicKey);
			static void DerivePublicKeyHash(const Pubkey PublicKey, Pubkeyhash PublicKeyHash);
			static Option<void> DeriveSealingKeypair(const Seckey PrivateKey, Seckey SealingPrivateKey, Pubkey SealingPublicKey);
			static Option<String> EncryptWithSealingPublicKey(const Pubkey SealingPublicKey, const std::string_view& Plaintext);
			static Option<String> DecryptWithSealingPrivateKey(const Seckey SealingPrivateKey, const Pubkey SealingPublicKey, const std::string_view& Ciphertext);
			static bool DecodePrivateKey(const std::string_view& Value, Seckey PrivateKey);
			static bool EncodePrivateKey(const Seckey PrivateKey, String& Value);
			static bool DecodePublicKey(const std::string_view& Value, Pubkey PublicKey);
			static bool EncodePublicKey(const Pubkey PublicKey, String& Value);
			static bool DecodeAddress(const std::string_view& Address, Pubkeyhash PublicKeyHash);
			static bool EncodeAddress(const Pubkeyhash PublicKeyHash, String& Address);
			static bool DecodeSealingPrivateKey(const std::string_view& Value, Seckey SealingPrivateKey);
			static bool EncodeSealingPrivateKey(const Seckey SealingPrivateKey, String& Value);
			static bool DecodeSealingPublicKey(const std::string_view& Value, Pubkey SealingPublicKey);
			static bool EncodeSealingPublicKey(const Pubkey SealingPublicKey, String& Value);
			static Schema* SerializePrivateKey(const Seckey PrivateKey);
			static Schema* SerializePublicKey(const Pubkey PublicKey);
			static Schema* SerializeAddress(const Pubkeyhash PublicKeyHash);
			static Schema* SerializeSealingPrivateKey(const Seckey PrivateKey);
			static Schema* SerializeSealingPublicKey(const Pubkey PublicKey);
		};

		class Encoding
		{
		public:
			static bool DecodeUintBlob(const String& Value, uint8_t* Data, size_t DataSize);
			static void EncodeUint128(const uint8_t Value[16], uint128_t& Data);
			static void DecodeUint128(const uint128_t& Value, uint8_t Data[16]);
			static void EncodeUint256(const uint8_t Value[32], uint256_t& Data);
			static void DecodeUint256(const uint256_t& Value, uint8_t Data[32]);
			static String Encode0xHex256(const uint256_t& Data);
			static uint256_t Decode0xHex256(const std::string_view& Data);
			static String Encode0xHex128(const uint128_t& Data);
			static uint128_t Decode0xHex128(const std::string_view& Data);
			static uint32_t TypeOf(const std::string_view& Name);
			static Schema* SerializeUint256(const uint256_t& Data);
		};

		class Hashing
		{
		public:
			static uint32_t Hash32d(const uint8_t* Buffer, size_t Size);
			static uint32_t Hash32d(const std::string_view& Buffer);
			static void Hash160(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[20]);
			static String Hash160(const uint8_t* Buffer, size_t Size);
			static void Hash256(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[32]);
			static String Hash256(const uint8_t* Buffer, size_t Size);
			static void Hash512(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[64]);
			static String Hash512(const uint8_t* Buffer, size_t Size);
			static uint256_t Hash256i(const uint8_t* Buffer, size_t Size);
			static uint256_t Hash256i(const std::string_view& Data);
		};

		class Asset
		{
		public:
			static AssetId IdOfHandle(const std::string_view& Handle);
			static AssetId IdOf(const std::string_view& Blockchain, const std::string_view& Token = std::string_view(), const std::string_view& ContractAddress = std::string_view());
			static AssetId BaseIdOf(const AssetId& Value);
			static String HandleOf(const std::string_view& Blockchain, const std::string_view& Token = std::string_view(), const std::string_view& ContractAddress = std::string_view());
			static String HandleOf(const AssetId& Value);
			static String BaseHandleOf(const AssetId& Value);
			static String BlockchainOf(const AssetId& Value);
			static String TokenOf(const AssetId& Value);
			static String ChecksumOf(const AssetId& Value);
			static bool IsValid(const AssetId& Value);
			static Schema* Serialize(const AssetId& Value);
		};

		class Composition
		{
		public:
			using CSeckey = uint8_t[64];
			using CPubkey = uint8_t[64];

		public:
			enum class Type
			{
				ED25519,
				SECP256K1
			};

		public:
			static ExpectsLR<void> DeriveKeypair1(Type Alg, CSeckey PrivateKey1, CPubkey PublicKey1);
			static ExpectsLR<void> DeriveKeypair2(Type Alg, const CPubkey PublicKey1, CSeckey PrivateKey2, CPubkey PublicKey2, Pubkey PublicKey, size_t* PublicKeySize);
			static ExpectsLR<void> DerivePrivateKey(Type Alg, const CSeckey PrivateKey1, const CSeckey PrivateKey2, CSeckey PrivateKey, size_t* PrivateKeySize);
			static void ConvertToED25519Curve(uint8_t PrivateKey[64]);
		};
	}
}
#endif