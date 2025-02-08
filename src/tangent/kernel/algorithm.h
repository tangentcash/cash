#ifndef TAN_KERNEL_ALGORITHM_H
#define TAN_KERNEL_ALGORITHM_H
#include "../layer/format.h"
#include <array>

typedef struct secp256k1_context_struct secp256k1_context;

namespace Tangent
{
	namespace Algorithm
	{
		using AssetId = uint256_t;
		using Sighash = uint8_t[64];
		using Recsighash = uint8_t[65];
		using Seckey = uint8_t[32];
		using Pubkey = uint8_t[33];
		using Pubkeyhash = uint8_t[20];
        typedef uint256_t(*HashFunction)(const uint256_t&, const uint256_t&);

        class WVDF
        {
        public:
            typedef String Digest;

        public:
            struct Parameters
            {
                uint32_t Length = 512;
                uint32_t Bits = 256;
                uint64_t Pow = 131072;

                uint128_t Difficulty() const;
            };

            struct Distribution
            {
                String Signature;
                uint256_t Value = 0;
                uint256_t Nonce = 0;

                uint256_t Derive();
                uint256_t Derive(const uint256_t& Step) const;
            };

        private:
            static Parameters DefaultAlg;

        public:
            static Distribution Random(const Parameters& Alg, const Format::Stream& Seed);
            static Parameters Calibrate(uint64_t Confidence, uint64_t TargetTime = Protocol::Now().Policy.ConsensusProofTime);
            static Parameters Adjust(const Parameters& PrevAlg, uint64_t PrevTime, uint64_t TargetIndex);
            static Parameters Bump(const Parameters& Alg, double Bump);
            static String Evaluate(const Parameters& Alg, const std::string_view& Message);
            static bool Verify(const Parameters& Alg, const std::string_view& Message, const std::string_view& Sig);
            static int8_t Compare(const std::string_view& Sig1, const std::string_view& Sig2);
            static uint64_t Locktime(const std::string_view& Sig);
            static uint64_t AdjustmentInterval();
            static uint64_t AdjustmentIndex(uint64_t Index);
            static void SetDefault(const Parameters& Alg);
            static const Parameters& GetDefault();
        };

        class NPOW
        {
        public:
            static uint256_t Evaluate(const uint256_t& Nonce, const std::string_view& Message);
            static bool Verify(const uint256_t& Nonce, const std::string_view& Message, const uint256_t& Target, const uint256_t& Solution);
            static void Serialize(Format::Stream& Stream, const uint256_t& Nonce, const std::string_view& Message);
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
			static uint256_t MessageHash(const std::string_view& SignableMessage);
			static String Mnemonicgen(uint16_t Strength = 256);
			static void Keygen(Seckey SecretKey);
			static bool Recover(const uint256_t& Hash, Pubkey PublicKey, const Recsighash Signature);
			static bool RecoverHash(const uint256_t& Hash, Pubkeyhash PublicKeyHash, const Recsighash Signature);
			static bool Sign(const uint256_t& Hash, const Seckey SecretKey, Recsighash Signature);
			static bool Verify(const uint256_t& Hash, const Pubkey PublicKey, const Recsighash Signature);
			static bool VerifyMnemonic(const std::string_view& Mnemonic);
			static bool VerifySecretKey(const Seckey SecretKey);
			static bool VerifyPublicKey(const Pubkey PublicKey);
			static bool VerifyAddress(const std::string_view& Address);
			static bool VerifySealedMessage(const std::string_view& Ciphertext);
			static void DeriveSecretKeyFromMnemonic(const std::string_view& Mnemonic, Seckey SecretKey);
			static void DeriveSecretKey(const std::string_view& Seed, Seckey SecretKey);
			static bool DerivePublicKey(const Seckey SecretKey, Pubkey PublicKey);
			static void DerivePublicKeyHash(const Pubkey PublicKey, Pubkeyhash PublicKeyHash);
			static void DeriveCipherKeypair(const Seckey SecretKey, const uint256_t& Nonce, Seckey CipherSecretKey, Pubkey CipherPublicKey);
			static Option<String> PublicEncrypt(const Pubkey CipherPublicKey, const std::string_view& Plaintext, const std::string_view& Entropy);
			static Option<String> PrivateDecrypt(const Seckey CipherSecretKey, const Pubkey CipherPublicKey, const std::string_view& Ciphertext);
			static bool DecodeSecretKey(const std::string_view& Value, Seckey SecretKey);
			static bool EncodeSecretKey(const Seckey SecretKey, String& Value);
			static bool DecodePublicKey(const std::string_view& Value, Pubkey PublicKey);
			static bool EncodePublicKey(const Pubkey PublicKey, String& Value);
			static bool DecodeAddress(const std::string_view& Address, Pubkeyhash PublicKeyHash);
			static bool EncodeAddress(const Pubkeyhash PublicKeyHash, String& Address);
			static Schema* SerializeSecretKey(const Seckey SecretKey);
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
            static uint256_t Sha256ci(const uint256_t& A, const uint256_t& B);
            static uint64_t Sha64d(const uint8_t* Buffer, size_t Size);
            static uint64_t Sha64d(const std::string_view& Buffer);
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
			using CSeed = uint8_t[64];
			using CSeckey = uint8_t[64];
			using CPubkey = uint8_t[64];

		public:
			enum class Type
			{
				ED25519,
				SECP256K1
			};

		public:
			static ExpectsLR<void> DeriveKeypair1(Type Alg, const CSeed Seed, CSeckey SecretKey1, CPubkey PublicKey1);
			static ExpectsLR<void> DeriveKeypair2(Type Alg, const CSeed Seed, const CPubkey PublicKey1, CSeckey SecretKey2, CPubkey PublicKey2, CPubkey PublicKey, size_t* PublicKeySize);
			static ExpectsLR<void> DeriveSecretKey(Type Alg, const CSeckey SecretKey1, const CSeckey SecretKey2, CSeckey SecretKey, size_t* SecretKeySize);
			static void ConvertToED25519Curve(uint8_t SecretKey[64]);
			static void ConvertToSecretSeed(const Seckey SecretKey, const std::string_view& Entropy, CSeed Seed);
		};

        struct MerkleTree
        {
        public:
            struct Path
            {
                friend MerkleTree;

            private:
                Vector<uint256_t> Nodes;
                size_t Index = 0;

            public:
                HashFunction Hasher = &Hashing::Sha256ci;

            public:
                uint256_t CalculateRoot(uint256_t Hash) const;
                Vector<uint256_t>& GetBranch();
                const Vector<uint256_t>& GetBranch() const;
                size_t GetIndex() const;
                bool Empty();
            };

        private:
            Vector<uint256_t> Nodes;
            size_t Hashes = 0;

        public:
            HashFunction Hasher = &Hashing::Sha256ci;

        public:
            MerkleTree();
            MerkleTree(const uint256_t& PrevMerkleRoot);
            MerkleTree(const MerkleTree&) = default;
            MerkleTree(MerkleTree&&) = default;
            MerkleTree& operator=(const MerkleTree&) = default;
            MerkleTree& operator=(MerkleTree&&) = default;
            MerkleTree& Shift(const uint256_t& Hash);
            MerkleTree& Push(const uint256_t& Hash);
            MerkleTree& Reset();
            MerkleTree& Calculate();
            Path CalculatePath(const uint256_t& Hash);
            uint256_t CalculateRoot();
            const Vector<uint256_t>& GetTree();
            const Vector<uint256_t>& GetTree() const;
            size_t GetComplexity() const;
            bool IsCalculated() const;
        };
	}
}
#endif