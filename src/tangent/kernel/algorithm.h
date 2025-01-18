#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "../layer/format.h"

typedef struct secp256k1_context_struct secp256k1_context;

namespace Tangent
{
	namespace Algorithm
	{
		using AssetId = uint256_t;
		using Sighash = uint8_t[65];
		using Seckey = uint8_t[32];
		using Pubkey = uint8_t[33];
		using Pubkeyhash = uint8_t[20];

		struct Endpoint
		{
			Location Scheme;
			SocketAddress Address;
			bool Secure;

			Endpoint(const std::string_view& URI);
			bool IsValid() const;
			static String ToURI(const SocketAddress& Address, const std::string_view& Protocol = "tcp");
		};

		class Segwit
		{
		public:
			static int Tweak(uint8_t* Output, size_t* OutputSize, int32_t OutputBits, const uint8_t* Input, size_t InputSize, int32_t InputBits, int32_t Padding);
			static int Encode(char* Output, const char* Prefix, int32_t Version, const uint8_t* Program, size_t ProgramSize);
			static int Decode(int* Version, uint8_t* Program, size_t* ProgramSize, const char* Prefix, const char* Input);
		};

		class Signing
		{
		private:
			static secp256k1_context* SharedContext;

		public:
			static void Initialize();
			static void Deinitialize();
			static String Mnemonicgen(uint16_t Strength = 256);
			static uint256_t MessageHash(const std::string_view& InsecureMessage);
			static void Keygen(Seckey SecretKey);
			static bool RecoverNormal(const uint256_t& Hash, Pubkey PublicKey, const Sighash Signature);
			static bool RecoverTweaked(const uint256_t& Hash, Pubkey TweakedPublicKey, const Sighash Signature);
			static bool RecoverNormalHash(const uint256_t& Hash, Pubkeyhash PublicKeyHash, const Sighash Signature);
			static bool RecoverTweakedHash(const uint256_t& Hash, Pubkeyhash TweakedPublicKeyHash, const Sighash Signature);
			static bool SignNormal(const uint256_t& Hash, const Seckey SecretKey, Sighash Signature);
			static bool SignTweaked(const uint256_t& Hash, const Seckey RootSecretKey, Sighash Signature);
			static bool VerifyNormal(const uint256_t& Hash, const Pubkey PublicKey, const Sighash Signature);
			static bool VerifyTweaked(const uint256_t& Hash, const Pubkey TweakedPublicKey, const Sighash Signature);
			static bool VerifyMnemonic(const std::string_view& Mnemonic);
			static bool VerifySecretKey(const Seckey SecretKey);
			static bool VerifyPublicKey(const Pubkey PublicKey);
			static bool VerifyAddress(const std::string_view& Address);
			static bool VerifySealedMessage(const std::string_view& Ciphertext);
			static bool DeriveSecretKey(const std::string_view& Mnemonic, Seckey SecretKey);
			static bool DeriveSecretKey(const std::string_view& Seed, Seckey SecretKey, size_t Iterations);
			static void DeriveSealingKey(const Seckey SecretKey, Pubkey SealingKey);
			static bool DerivePublicKey(const Seckey SecretKey, Pubkey PublicKey);
			static void DerivePublicKeyHash(const Pubkey PublicKey, Pubkeyhash PublicKeyHash);
			static void DeriveScalar(const uint8_t* Input, size_t Size, Seckey Tweak);
			static bool DeriveTweakAlpha(const Seckey RootSecretKey, const Pubkey RootPublicKey, Seckey TweakAlpha);
			static void DeriveTweakBeta(const Pubkey RootPublicKey, Seckey TweakBeta);
			static bool DeriveTweakGamma(const uint256_t& Hash, Seckey TweakGamma);
			static bool DeriveTweakedPublicKey(const Seckey RootSecretKey, const Pubkey RootPublicKey, Pubkey TweakedPublicKey);
			static bool ScalarNegate(const Seckey Scalar, Seckey Result);
			static bool ScalarAdd(const Seckey ScalarA, const Seckey ScalarB, Seckey Result);
			static bool ScalarMultiply(const Seckey ScalarA, const Seckey ScalarB, Seckey Result);
			static bool PointNegate(const Pubkey Point, Pubkey Result);
			static bool PointAdd(const Pubkey PointA, const Seckey ScalarB, Pubkey Result);
			static bool PointMultiply(const Pubkey PointA, const Seckey ScalarB, Pubkey Result);
			static Option<String> PublicEncrypt(const Pubkey SealingKey, const std::string_view& Plaintext);
			static Option<String> PrivateDecrypt(const Seckey SecretKey, const std::string_view& Ciphertext);
			static bool DecodeSecretKey(const std::string_view& Value, Seckey SecretKey);
			static bool EncodeSecretKey(const Seckey SecretKey, String& Value);
			static bool DecodeSealingKey(const std::string_view& Value, Pubkey SealingKey);
			static bool EncodeSealingKey(const Pubkey SealingKey, String& Value);
			static bool DecodePublicKey(const std::string_view& Value, Pubkey PublicKey);
			static bool EncodePublicKey(const Pubkey PublicKey, String& Value);
			static bool DecodeAddress(const std::string_view& Address, Pubkeyhash PublicKeyHash);
			static bool EncodeAddress(const Pubkeyhash PublicKeyHash, String& Address);
			static Schema* SerializeSecretKey(const Seckey SecretKey);
			static Schema* SerializeSealingKey(const Pubkey PublicKey);
			static Schema* SerializePublicKey(const Pubkey PublicKey);
			static Schema* SerializeAddress(const Pubkeyhash PublicKeyHash);
			static secp256k1_context* GetContext();
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
			static ExpectsLR<void> DeriveKeypair1(Type Alg, CSeckey SecretKey1, CPubkey PublicKey1);
			static ExpectsLR<void> DeriveKeypair2(Type Alg, const CPubkey PublicKey1, CSeckey SecretKey2, CPubkey PublicKey2, Pubkey PublicKey, size_t* PublicKeySize);
			static ExpectsLR<void> DeriveSecretKey(Type Alg, const CSeckey SecretKey1, const CSeckey SecretKey2, CSeckey SecretKey, size_t* SecretKeySize);
			static void ConvertToED25519Curve(uint8_t SecretKey[64]);
		};
	}
}
#endif