#include "algorithm.h"
#ifdef TAN_VALIDATOR
#include "../validator/service/nss.h"
#endif
#ifdef TAN_GMP
#include <gmp.h>
#endif
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../internal/segwit_addr.h"
#include "../internal/ecdsa.h"
#include "../internal/ed25519.h"
#include "../internal/ripemd160.h"
#include "../internal/bip39.h"
#include "../internal/sha2.h"
}

namespace Tangent
{
	namespace Algorithm
	{
#ifdef TAN_GMP
		struct Gmp
		{
			static void Free(void* Data, size_t Size)
			{
				typedef void (*gmp_free_t)(void*, size_t);
				static gmp_free_t gmp_free = nullptr;
				if (!gmp_free)
					mp_get_memory_functions(nullptr, nullptr, &gmp_free);
				gmp_free(Data, Size);
			}
			static void Import(const uint8_t* Data, size_t Size, mpz_t Value)
			{
				mpz_import(Value, Size, 1, 1, 1, 0, Data);
			}
			static void Import256(const uint256_t& Data, mpz_t Value)
			{
				uint8_t Buffer[32];
				Encoding::DecodeUint256(Data, Buffer);
				mpz_import(Value, sizeof(Buffer), 1, 1, 1, 0, Buffer);
			}
			static String Export(const mpz_t Value)
			{
				size_t Size = 0;
				char* Data = (char*)mpz_export(nullptr, &Size, 1, 1, 1, 0, Value);
				String Buffer = String(Data, Size);
				Free(Data, Size);
				return Buffer;
			}
			static uint256_t Export256(const mpz_t Value)
			{
				size_t Size = 0;
				char* Data = (char*)mpz_export(nullptr, &Size, 1, 1, 1, 0, Value);
				uint8_t Buffer[32] = { 0 };
				memcpy((char*)Buffer + (sizeof(Buffer) - Size), Data, Size);
				Free(Data, Size);

				uint256_t V;
				Encoding::EncodeUint256(Buffer, V);
				return V;
			}
			static void Export256(const mpz_t Value, uint8_t Buffer[32])
			{
				size_t Size = 0;
				char* Data = (char*)mpz_export(nullptr, &Size, 1, 1, 1, 0, Value);
				memset(Buffer, 0, sizeof(uint256_t));
				memcpy((char*)Buffer + (sizeof(uint256_t) - Size), Data, Size);
				Free(Data, Size);
			}
		};

		struct GmpSignature
		{
			mpz_t P;
			mpz_t L;
			mpz_t Y;
			mpz_t N;
			uint64_t T;

			GmpSignature()
			{
				mpz_init(P);
				mpz_init(L);
				mpz_init(Y);
				mpz_init(N);
			}
			GmpSignature(const GmpSignature&) = delete;
			GmpSignature(GmpSignature&& Other) noexcept
			{
				memcpy(this, &Other, sizeof(Other));
				memset(&Other, 0, sizeof(Other));
			}
			~GmpSignature()
			{
				if (P)
					mpz_clear(P);
				if (L)
					mpz_clear(L);
				if (Y)
					mpz_clear(Y);
				if (N)
					mpz_clear(N);
			}
			GmpSignature& operator= (const GmpSignature&) = delete;
			GmpSignature& operator= (GmpSignature&& Other) noexcept
			{
				if (this == &Other)
					return *this;

				this->~GmpSignature();
				memcpy(this, &Other, sizeof(Other));
				memset(&Other, 0, sizeof(Other));
				return *this;
			}
			String Serialize() const
			{
				Format::Stream Stream;
				Stream.WriteInteger(T);
				Stream.WriteString(Gmp::Export(P));
				Stream.WriteString(Gmp::Export(L));
				Stream.WriteString(Gmp::Export(Y));
				Stream.WriteString(Gmp::Export(N));
				Stream.WriteInteger(Hashing::Sha64d(Stream.Data));
				return Stream.Data;
			}
			static Option<GmpSignature> Deserialize(const std::string_view& Sig)
			{
				GmpSignature Result;
				Format::Stream Stream = Format::Stream(Sig);
				if (!Stream.ReadInteger(Stream.ReadType(), &Result.T))
					return Optional::None;

				String Numeric;
				if (!Stream.ReadString(Stream.ReadType(), &Numeric))
					return Optional::None;

				Gmp::Import((uint8_t*)Numeric.data(), Numeric.size(), Result.P);
				if (!Stream.ReadString(Stream.ReadType(), &Numeric))
					return Optional::None;

				Gmp::Import((uint8_t*)Numeric.data(), Numeric.size(), Result.L);
				if (!Stream.ReadString(Stream.ReadType(), &Numeric))
					return Optional::None;

				Gmp::Import((uint8_t*)Numeric.data(), Numeric.size(), Result.Y);
				if (!Stream.ReadString(Stream.ReadType(), &Numeric))
					return Optional::None;

				uint64_t Checksum, Seek = Stream.Seek;
				Gmp::Import((uint8_t*)Numeric.data(), Numeric.size(), Result.N);
				if (!Stream.ReadInteger(Stream.ReadType(), &Checksum))
					return Optional::None;

				if (Checksum != Hashing::Sha64d(std::string_view(Stream.Data.data(), Seek)))
					return Optional::None;

				return Result;
			}
		};
#endif
		uint128_t WVDF::Parameters::Difficulty() const
		{
			return uint128_t(Length) * uint128_t(Bits) + uint128_t(Pow);
		}

		uint256_t WVDF::Distribution::Derive()
		{
			return Derive(Nonce++);
		}
		uint256_t WVDF::Distribution::Derive(const uint256_t& Step) const
		{
			char Data[sizeof(uint256_t) * 2] = { 0 };
			Encoding::DecodeUint256(Step, (uint8_t*)((char*)Data + sizeof(uint256_t) * 0));
			Encoding::DecodeUint256(Value, (uint8_t*)((char*)Data + sizeof(uint256_t) * 1));
			return Hashing::Hash256i(std::string_view(Data, sizeof(Data)));
		}

		WVDF::Distribution WVDF::Random(const Parameters& Alg, const Format::Stream& Seed)
		{
			Distribution Result;
			Result.Signature = Evaluate(Alg, Seed.Data);
			Result.Value = Hashing::Hash256i(*Crypto::HashRaw(Digests::SHA512(), Result.Signature));
			return Result;
		}
		WVDF::Parameters WVDF::Calibrate(uint64_t Confidence, uint64_t TargetTime)
		{
			uint64_t TargetNonce = Confidence;
			auto Alg = DefaultAlg;
			while (true)
			{
			Retry:
				uint64_t StartTime = Protocol::Now().Time.Now();
				auto Signature = Evaluate(Alg, *Crypto::RandomBytes(Math32u::Random(256, 1024)));
				if (Signature.empty())
					break;

				uint64_t EndTime = Protocol::Now().Time.Now();
				uint64_t DeltaTime = EndTime - StartTime;
				double DeltaTarget = (double)DeltaTime - (double)TargetTime;
				if (std::abs(DeltaTarget) / TargetTime < 0.05)
				{
					if (!TargetNonce--)
						break;
					goto Retry;
				}

				Alg = Adjust(Alg, DeltaTime, AdjustmentInterval());
				TargetNonce = Confidence;
			}
			return Alg;
		}
		WVDF::Parameters WVDF::Adjust(const Parameters& PrevAlg, uint64_t PrevTime, uint64_t TargetIndex)
		{
			if (TargetIndex <= 1)
				return DefaultAlg;

			if (AdjustmentIndex(TargetIndex) != TargetIndex)
			{
			LeaveAsIs:
				return (PrevAlg.Difficulty() < DefaultAlg.Difficulty() ? DefaultAlg : PrevAlg);
			}

			auto& Policy = Protocol::Now().Policy;
			PrevTime = std::max(Policy.ConsensusProofTime / 4, std::min(Policy.ConsensusProofTime * 4, PrevTime));

			int64_t TimeDelta = (int64_t)Policy.ConsensusProofTime - (int64_t)PrevTime;
			if (std::abs((double)TimeDelta) / (double)Policy.ConsensusProofTime < 0.05)
				goto LeaveAsIs;

			Parameters NewAlg = PrevAlg;
			Decimal Adjustment = Decimal(TimeDelta).Truncate(Protocol::Now().Message.Precision) / PrevTime;
			if (Adjustment > 1.0 + Policy.MaxConsensusDifficultyIncrease)
				Adjustment = 1.0 + Policy.MaxConsensusDifficultyIncrease;
			else if (Adjustment < Policy.MaxConsensusDifficultyDecrease)
				Adjustment = Policy.MaxConsensusDifficultyDecrease;

			uint64_t PowOffset = (Decimal(NewAlg.Pow) * Adjustment).ToUInt64();
			if (NewAlg.Pow + PowOffset < NewAlg.Pow)
				NewAlg.Pow = std::numeric_limits<uint64_t>::max();
			else
				NewAlg.Pow += PowOffset;

			if (NewAlg.Pow < DefaultAlg.Pow)
				NewAlg.Pow = DefaultAlg.Pow;

			return (NewAlg.Difficulty() < DefaultAlg.Difficulty() ? DefaultAlg : NewAlg);
		}
		WVDF::Parameters WVDF::Bump(const Parameters& Alg, double Bump)
		{
			Parameters NewAlg = Alg;
			uint64_t NewPow = (Decimal(NewAlg.Pow) * Decimal(Bump)).ToUInt64();
			if (NewPow < NewAlg.Pow)
				NewAlg.Pow = std::numeric_limits<uint64_t>::max();
			else
				NewAlg.Pow = NewPow;

			if (NewAlg.Pow < DefaultAlg.Pow)
				NewAlg.Pow = DefaultAlg.Pow;

			return (NewAlg.Difficulty() < DefaultAlg.Difficulty() ? DefaultAlg : NewAlg);
		}
		String WVDF::Evaluate(const Parameters& Alg, const std::string_view& Message)
		{
#ifdef TAN_GMP
			uint8_t MData[64];
			Hashing::Hash512((uint8_t*)Message.data(), Message.size(), MData);

			mpz_t V;
			mpz_init(V);
			Gmp::Import(MData, sizeof(MData), V);

			GmpSignature Signature;
			gmp_randstate_t R;
			gmp_randinit_mt(R);
			gmp_randseed(R, V);

			mpz_t P;
			mpz_init(P);
			mpz_urandomb(P, R, Alg.Length / 2);
			mpz_nextprime(P, P);

			mpz_t Q;
			mpz_init(Q);
			mpz_urandomb(Q, R, Alg.Length / 2);
			mpz_nextprime(Q, Q);
			mpz_init(Signature.N);
			mpz_mul(Signature.N, P, Q);
			mpz_clear(P);
			mpz_clear(Q);

			mpz_t E, C;
			mpz_init(E);
			mpz_ui_pow_ui(E, 2, Alg.Pow);
			mpz_init(Signature.Y);
			mpz_init(C);
			mpz_urandomb(C, R, 2 * Alg.Bits);
			mpz_nextprime(Signature.L, C);
			mpz_init(Q);
			mpz_powm(Signature.Y, V, E, Signature.N);
			mpz_fdiv_q(Q, E, Signature.L);
			mpz_powm(Signature.P, V, Q, Signature.N);
			mpz_clear(Q);
			mpz_clear(E);
			mpz_clear(C);
			mpz_clear(V);
			gmp_randclear(R);

			Signature.T = Protocol::Now().Time.Now();
			return Signature.Serialize();
#else
			return String();
#endif
		}
		bool WVDF::Verify(const Parameters& Alg, const std::string_view& Message, const std::string_view& Sig)
		{
#ifdef TAN_GMP
			auto Signature = GmpSignature::Deserialize(Sig);
			if (!Signature)
				return false;

			uint8_t MData[64];
			Hashing::Hash512((uint8_t*)Message.data(), Message.size(), MData);

			mpz_t V;
			mpz_init(V);
			Gmp::Import(MData, sizeof(MData), V);

			mpz_t P;
			mpz_init(P);
			mpz_sub_ui(P, Signature->L, 1);

			mpz_t T;
			mpz_init(T);
			mpz_set_ui(T, Alg.Pow);
			mpz_mod(T, T, P);
			mpz_clear(P);

			mpz_t D;
			mpz_init(D);
			mpz_set_ui(D, 2);

			mpz_t R;
			mpz_init(R);
			mpz_powm(R, D, T, Signature->L);
			mpz_clear(T);
			mpz_clear(D);

			mpz_t Y, W;
			mpz_init(Y);
			mpz_init(W);
			mpz_powm(Y, Signature->P, Signature->L, Signature->N);
			mpz_powm(W, V, R, Signature->N);
			mpz_mul(Y, Y, W);
			mpz_mod(Y, Y, Signature->N);
			mpz_clear(R);
			mpz_clear(W);
			mpz_clear(V);

			int Diff = mpz_cmp(Y, Signature->Y);
			mpz_clear(Y);
			return Diff == 0;
#else
			return false;
#endif
		}
		int8_t WVDF::Compare(const std::string_view& Sig1, const std::string_view& Sig2)
		{
#ifdef TAN_GMP
			auto Signature1 = GmpSignature::Deserialize(Sig1);
			auto Signature2 = GmpSignature::Deserialize(Sig2);
			if (!Signature1 || !Signature2)
				return Signature1 ? 1 : -1;

			int CompareY = mpz_cmp(Signature1->Y, Signature2->Y);
			if (CompareY != 0)
				return (int8_t)CompareY;

			int CompareP = mpz_cmp(Signature1->P, Signature2->P);
			if (CompareP != 0)
				return (int8_t)CompareP;

			int CompareN = mpz_cmp(Signature1->N, Signature2->N);
			if (CompareN != 0)
				return (int8_t)CompareN;

			int CompareL = mpz_cmp(Signature1->L, Signature2->L);
			if (CompareL != 0)
				return (int8_t)CompareL;

			if (Signature1->T < Signature2->T)
				return 1;
			else if (Signature1->T > Signature2->T)
				return -1;

			return 0;
#else
			return -2;
#endif
		}
		uint64_t WVDF::Locktime(const std::string_view& Sig)
		{
#ifdef TAN_GMP
			auto Signature = GmpSignature::Deserialize(Sig);
			if (!Signature)
				return 0;

			return Signature->T;
#endif
		}
		uint64_t WVDF::AdjustmentInterval()
		{
			auto& Policy = Protocol::Now().Policy;
			return Policy.ConsensusAdjustmentTime / Policy.ConsensusProofTime;
		}
		uint64_t WVDF::AdjustmentIndex(uint64_t Index)
		{
			return Index - Index % AdjustmentInterval();
		}
		void WVDF::SetDefault(const Parameters& Alg)
		{
			DefaultAlg = Alg;
		}
		const WVDF::Parameters& WVDF::GetDefault()
		{
			return DefaultAlg;
		}
		WVDF::Parameters WVDF::DefaultAlg;

		uint256_t NPOW::Evaluate(const uint256_t& Nonce, const std::string_view& Message)
		{
			Format::Stream Stream;
			Serialize(Stream, Nonce, Message);
			return Stream.Hash();
		}
		bool NPOW::Verify(const uint256_t& Nonce, const std::string_view& Message, const uint256_t& Target, const uint256_t& Solution)
		{
			if (Solution > Target)
				return false;
			else if (Nonce == uint256_t::Max())
				return false;

			return Solution == Evaluate(Nonce, Message);
		}
		void NPOW::Serialize(Format::Stream& Stream, const uint256_t& Nonce, const std::string_view& Message)
		{
			Stream.Clear();
			Stream.WriteTypeless(Message);
			Stream.WriteTypeless(Nonce);
		}

		int Segwit::Tweak(uint8_t* Output, size_t* OutputSize, int32_t OutputBits, const uint8_t* Input, size_t InputSize, int32_t InputBits, int32_t Padding)
		{
			int32_t Bits = 0;
			uint32_t Value = 0;
			uint32_t Max = (((uint32_t)1) << OutputBits) - 1;
			while (InputSize--)
			{
				Value = (Value << InputBits) | *(Input++);
				Bits += InputBits;
				while (Bits >= OutputBits)
				{
					Bits -= OutputBits;
					Output[(*OutputSize)++] = (Value >> Bits) & Max;
				}
			}

			if (Padding)
			{
				if (Bits)
					Output[(*OutputSize)++] = (Value << (OutputBits - Bits)) & Max;
			}
			else if (((Value << (OutputBits - Bits)) & Max) || Bits >= InputBits)
				return 0;

			return 1;
		}
		int Segwit::Encode(char* Output, const char* Prefix, int32_t Version, const uint8_t* Program, size_t ProgramSize)
		{
			uint8_t Data[65] = { 0 };
			size_t DataSize = 0;
			if (Version == 0 && ProgramSize != 20 && ProgramSize != 32)
				return 0;
			else if (ProgramSize < 2 || ProgramSize > 40)
				return 0;

			Data[0] = Version;
			Tweak(Data + 1, &DataSize, 5, Program, ProgramSize, 8, 1);
			++DataSize;

			return bech32_encode(Output, Prefix, Data, DataSize, BECH32_ENCODING_BECH32M);
		}
		int Segwit::Decode(int* Version, uint8_t* Program, size_t* ProgramSize, const char* Prefix, const char* Input)
		{
			char Hrp[84] = { 0 };
			uint8_t Data[84] = { 0 };
			size_t DataSize = 0;
			if (bech32_decode(Hrp, Data, &DataSize, Input) != BECH32_ENCODING_BECH32M)
				return 0;

			if (DataSize == 0 || DataSize > 65)
				return 0;

			if (strncmp(Prefix, Hrp, 84) != 0)
				return 0;

			*ProgramSize = 0;
			if (!Tweak(Program, ProgramSize, 8, Data + 1, DataSize - 1, 5, 0))
				return 0;

			if (*ProgramSize < 2 || *ProgramSize > 40)
				return 0;

			if (Data[0] == 0 && *ProgramSize != 20 && *ProgramSize != 32)
				return 0;

			*Version = Data[0];
			return 1;
		}

		void Signing::Initialize()
		{
			if (!SharedContext)
				SharedContext = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
		}
		void Signing::Deinitialize()
		{
			if (SharedContext != nullptr)
			{
				secp256k1_context_destroy(SharedContext);
				SharedContext = nullptr;
			}
		}
		uint256_t Signing::MessageHash(const std::string_view& SignableMessage)
		{
			Format::Stream Message;
			Message.WriteTypeless(Protocol::Now().Account.MessageMagic);
			Message.WriteTypeless(SignableMessage.data(), (uint32_t)SignableMessage.size());
			return Message.Hash();
		}
		String Signing::Mnemonicgen(uint16_t Strength)
		{
			char Buffer[256] = { 0 };
			mnemonic_generate((int)Strength, Buffer, (int)sizeof(Buffer));
			return String(Buffer, strnlen(Buffer, sizeof(Buffer)));
		}
		void Signing::Keygen(Seckey SecretKey)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			while (true)
			{
				if (!Crypto::FillRandomBytes(SecretKey, sizeof(Seckey)))
					break;
				else if (VerifySecretKey(SecretKey))
					break;
			}
		}
		bool Signing::Recover(const uint256_t& Hash, Pubkey PublicKey, const Recsighash Signature)
		{
			VI_ASSERT(PublicKey != nullptr && Signature != nullptr, "public key and signature should be set");
			uint8_t RecoveryId = 0;
			size_t SignatureSize = sizeof(Recsighash);
			size_t RecoveryOffset = SignatureSize - sizeof(RecoveryId);
			memcpy(&RecoveryId, Signature + RecoveryOffset, sizeof(RecoveryId));
			if (RecoveryId > 4)
				return false;

			secp256k1_context* Context = GetContext();
			secp256k1_ecdsa_recoverable_signature RecoverableSignature;
			if (!secp256k1_ecdsa_recoverable_signature_parse_compact(Context, &RecoverableSignature, Signature, RecoveryId))
				return false;

			uint8_t Data[32];
			Encoding::DecodeUint256(Hash, Data);

			secp256k1_pubkey RecoveredPublicKey;
			if (secp256k1_ecdsa_recover(Context, &RecoveredPublicKey, &RecoverableSignature, Data) != 1)
				return false;

			size_t PublicKeySize = sizeof(Pubkey);
			return secp256k1_ec_pubkey_serialize(Context, PublicKey, &PublicKeySize, &RecoveredPublicKey, SECP256K1_EC_COMPRESSED) == 1;
		}
		bool Signing::RecoverHash(const uint256_t& Hash, Pubkeyhash PublicKeyHash, const Recsighash Signature)
		{
			VI_ASSERT(PublicKeyHash != nullptr && Signature != nullptr, "public key hash and signature should be set");
			Pubkey PublicKey;
			if (!Recover(Hash, PublicKey, Signature))
				return false;

			DerivePublicKeyHash(PublicKey, PublicKeyHash);
			return true;
		}
		bool Signing::Sign(const uint256_t& Hash, const Seckey SecretKey, Recsighash Signature)
		{
			VI_ASSERT(SecretKey != nullptr && Signature != nullptr, "secret key and signature should be set");
			uint8_t Data[32];
			Encoding::DecodeUint256(Hash, Data);
			memset(Signature, 0, sizeof(Recsighash));

			secp256k1_context* Context = GetContext();
			secp256k1_ecdsa_recoverable_signature RecoverableSignature;
			if (secp256k1_ecdsa_sign_recoverable(Context, &RecoverableSignature, Data, SecretKey, secp256k1_nonce_function_rfc6979, nullptr) != 1)
				return false;

			int RecoveryId = 0;
			if (secp256k1_ecdsa_recoverable_signature_serialize_compact(Context, Signature, &RecoveryId, &RecoverableSignature) != 1)
				return false;

			Signature[sizeof(Sighash)] = (uint8_t)RecoveryId;
			return true;
		}
		bool Signing::Verify(const uint256_t& Hash, const Pubkey PublicKey, const Recsighash Signature)
		{
			VI_ASSERT(PublicKey != nullptr && Signature != nullptr, "public key and signature should be set");
			secp256k1_context* Context = GetContext();
			secp256k1_ecdsa_signature CompactSignature;
			if (secp256k1_ecdsa_signature_parse_compact(Context, &CompactSignature, Signature) != 1)
				return false;

			secp256k1_ecdsa_signature NormalizedSignature;
			secp256k1_ecdsa_signature_normalize(Context, &NormalizedSignature, &CompactSignature);

			secp256k1_pubkey DerivedPublicKey;
			if (secp256k1_ec_pubkey_parse(Context, &DerivedPublicKey, PublicKey, sizeof(Pubkey)) != 1)
				return false;

			uint8_t Data[32];
			Encoding::DecodeUint256(Hash, Data);
			return secp256k1_ecdsa_verify(Context, &NormalizedSignature, Data, &DerivedPublicKey) == 1;
		}
		bool Signing::VerifyMnemonic(const std::string_view& Mnemonic)
		{
			String Data = String(Mnemonic);
			return mnemonic_check(Data.c_str()) == 1;
		}
		bool Signing::VerifySecretKey(const Seckey SecretKey)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			secp256k1_context* Context = GetContext();
			return secp256k1_ec_seckey_verify(Context, SecretKey) == 1;
		}
		bool Signing::VerifyPublicKey(const Pubkey PublicKey)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			secp256k1_pubkey DerivedPublicKey;
			secp256k1_context* Context = GetContext();
			return secp256k1_ec_pubkey_parse(Context, &DerivedPublicKey, PublicKey, sizeof(Pubkey)) == 1;
		}
		bool Signing::VerifyAddress(const std::string_view& Address)
		{
			Pubkeyhash PublicKeyHash;
			return DecodeAddress(Address, PublicKeyHash);
		}
		bool Signing::VerifySealedMessage(const std::string_view& Ciphertext)
		{
			return Ciphertext.size() > crypto_box_SEALBYTES;
		}
		void Signing::DeriveSecretKeyFromMnemonic(const std::string_view& Mnemonic, Seckey SecretKey)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			VI_ASSERT(Stringify::IsCString(Mnemonic), "mnemonic should be set");
			uint8_t Seed[64] = { 0 };
			mnemonic_to_seed(Mnemonic.data(), "", Seed, nullptr);
			DeriveSecretKey(std::string_view((char*)Seed, sizeof(Seed)), SecretKey);
		}
		void Signing::DeriveSecretKey(const std::string_view& Seed, Seckey SecretKey)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			String Derivation = String(Seed);
			while (true)
			{
				Derivation = Hashing::Hash256((uint8_t*)Derivation.data(), Derivation.size());
				memcpy(SecretKey, Derivation.data(), sizeof(Seckey));
				if (VerifySecretKey(SecretKey))
					break;
			}
		}
		bool Signing::DerivePublicKey(const Seckey SecretKey, Pubkey PublicKey)
		{
			VI_ASSERT(SecretKey != nullptr && PublicKey != nullptr, "secret key and public key should be set");
			secp256k1_pubkey DerivedPublicKey;
			secp256k1_context* Context = GetContext();
			memset(PublicKey, 0, sizeof(Pubkey));
			if (secp256k1_ec_pubkey_create(Context, &DerivedPublicKey, SecretKey) != 1)
				return false;

			size_t PublicKeySize = sizeof(Pubkey);
			return secp256k1_ec_pubkey_serialize(Context, PublicKey, &PublicKeySize, &DerivedPublicKey, SECP256K1_EC_COMPRESSED) == 1;
		}
		void Signing::DerivePublicKeyHash(const Pubkey PublicKey, Pubkeyhash PublicKeyHash)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			VI_ASSERT(PublicKeyHash != nullptr, "public key hash should be set");
			Hashing::Hash160(PublicKey, sizeof(Pubkey), PublicKeyHash);
		}
		void Signing::DeriveCipherKeypair(const Seckey SecretKey, const uint256_t& Nonce, Seckey CipherSecretKey, Pubkey CipherPublicKey)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			VI_ASSERT(CipherSecretKey != nullptr, "cipher secret key should be set");
			VI_ASSERT(CipherPublicKey != nullptr, "cipher public key should be set");
			Format::Stream Message;
			Message.WriteTypeless((char*)SecretKey, (uint32_t)sizeof(Seckey));
			Message.WriteTypeless(Nonce);
			
			uint8_t Seed[32];
			Encoding::DecodeUint256(Message.Hash(), Seed);
			memset(CipherPublicKey, 0, sizeof(Pubkey));
			crypto_box_seed_keypair(CipherPublicKey, CipherSecretKey, Seed);
		}
		Option<String> Signing::PublicEncrypt(const Pubkey CipherPublicKey, const std::string_view& Plaintext, const std::string_view& Entropy)
		{
			VI_ASSERT(CipherPublicKey != nullptr, "cipher public key should be set");
			if (Plaintext.empty())
				return Optional::None;

			auto Input = Hashing::Hash512((uint8_t*)Entropy.data(), Entropy.size());
			String Shuffletext = String(Plaintext);
			Shuffletext.insert(0, Input.substr(16, 16));

			uint256_t X, Y;
			String Hash = *Crypto::HashRaw(Digests::SHA512(), Shuffletext);
			Encoding::EncodeUint256((uint8_t*)Hash.data() + 00, X);
			Encoding::EncodeUint256((uint8_t*)Hash.data() + 32, Y);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.Low().Low(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.Low().High(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.High().Low(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.High().High(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.Low().Low(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.Low().High(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.High().Low(), 1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.High().High(), 1);

			size_t PaddingX = (size_t)(uint64_t)(X % 64), PaddingY = (size_t)(uint64_t)(Y % 64);
			Shuffletext.append(Crypto::HashRaw(Digests::SHA512(), Shuffletext)->substr(0, PaddingX));
			Shuffletext.append(Crypto::HashRaw(Digests::SHA512(), Shuffletext)->substr(0, PaddingY));
			Shuffletext.append(Hash);

			String Ciphertext;
			Ciphertext.resize(crypto_box_SEALBYTES + Shuffletext.size());
			if (crypto_box_seal((uint8_t*)Ciphertext.data(), (uint8_t*)Shuffletext.data(), Shuffletext.size(), CipherPublicKey) != 0)
				return Optional::None;

			return Ciphertext;
		}
		Option<String> Signing::PrivateDecrypt(const Seckey CipherSecretKey, const Pubkey CipherPublicKey, const std::string_view& Ciphertext)
		{
			VI_ASSERT(CipherSecretKey != nullptr, "cipher secret key should be set");
			VI_ASSERT(CipherPublicKey != nullptr, "cipher public key should be set");
			if (Ciphertext.size() <= crypto_box_SEALBYTES)
				return Optional::None;

			String Shuffletext;
			Shuffletext.resize(Ciphertext.size() - crypto_box_SEALBYTES);
			if (crypto_box_seal_open((uint8_t*)Shuffletext.data(), (uint8_t*)Ciphertext.data(), Ciphertext.size(), CipherPublicKey, CipherSecretKey) != 0)
				return Optional::None;

			if (Shuffletext.size() < 64)
				return Optional::None;

			uint256_t X, Y;
			String Hash = Shuffletext.substr(Shuffletext.size() - 64);
			Encoding::EncodeUint256((uint8_t*)Hash.data() + 00, X);
			Encoding::EncodeUint256((uint8_t*)Hash.data() + 32, Y);
			Shuffletext.resize(Shuffletext.size() - Hash.size());

			size_t Padding = (size_t)(uint64_t)(X % 64 + Y % 64);
			if (Padding > Shuffletext.size())
				return Optional::None;

			Shuffletext.resize(Shuffletext.size() - Padding);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.High().High(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.High().Low(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.Low().High(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), Y.Low().Low(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.High().High(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.High().Low(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.Low().High(), -1);
			Codec::RotateBuffer((uint8_t*)Shuffletext.data(), Shuffletext.size(), X.Low().Low(), -1);
			if (*Crypto::HashRaw(Digests::SHA512(), Shuffletext) != Hash)
				return Optional::None;

			Shuffletext.erase(0, 16);
			return Shuffletext;
		}
		bool Signing::DecodeSecretKey(const std::string_view& Value, Seckey SecretKey)
		{
			VI_ASSERT(SecretKey != nullptr && Stringify::IsCString(Value), "secret key and value should be set");
			auto& Account = Protocol::Now().Account;
			uint8_t Decoded[40];
			size_t DecodedSize = sizeof(Decoded);
			int Version = 0;

			if (Segwit::Decode(&Version, Decoded, &DecodedSize, Account.SecretKeyPrefix.c_str(), Value.data()) != 1)
				return false;
			else if (Version != (int)Account.SecretKeyVersion)
				return false;
			else if (DecodedSize != sizeof(Seckey))
				return false;

			memcpy(SecretKey, Decoded, sizeof(Seckey));
			return true;
		}
		bool Signing::EncodeSecretKey(const Seckey SecretKey, String& Value)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			auto& Account = Protocol::Now().Account;
			char Encoded[128];
			if (Segwit::Encode(Encoded, Account.SecretKeyPrefix.c_str(), (int)Account.SecretKeyVersion, SecretKey, sizeof(Seckey)) != 1)
				return false;

			size_t Size = strnlen(Encoded, sizeof(Encoded));
			Value.resize(Size);
			memcpy(Value.data(), Encoded, Size);
			return true;
		}
		bool Signing::DecodePublicKey(const std::string_view& Value, Pubkey PublicKey)
		{
			VI_ASSERT(PublicKey != nullptr && Stringify::IsCString(Value), "public key and value should be set");
			auto& Account = Protocol::Now().Account;
			uint8_t Decoded[40];
			size_t DecodedSize = sizeof(Decoded);
			int Version = 0;

			if (Segwit::Decode(&Version, Decoded, &DecodedSize, Account.PublicKeyPrefix.c_str(), Value.data()) != 1)
				return false;
			else if (Version != (int)Account.PublicKeyVersion)
				return false;
			else if (DecodedSize != sizeof(Pubkey))
				return false;

			memcpy(PublicKey, Decoded, sizeof(Pubkey));
			return true;
		}
		bool Signing::EncodePublicKey(const Pubkey PublicKey, String& Value)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			auto& Account = Protocol::Now().Account;
			char Encoded[128];
			if (Segwit::Encode(Encoded, Account.PublicKeyPrefix.c_str(), (int)Account.PublicKeyVersion, PublicKey, sizeof(Pubkey)) != 1)
				return false;

			size_t Size = strnlen(Encoded, sizeof(Encoded));
			Value.resize(Size);
			memcpy(Value.data(), Encoded, Size);
			return true;
		}
		bool Signing::DecodeAddress(const std::string_view& Address, Pubkeyhash PublicKeyHash)
		{
			VI_ASSERT(PublicKeyHash != nullptr && Stringify::IsCString(Address), "public key hash and address should be set");
			auto& Account = Protocol::Now().Account;
			uint8_t Decoded[40];
			size_t DecodedSize = sizeof(Decoded);
			int Version = 0;

			if (Segwit::Decode(&Version, Decoded, &DecodedSize, Account.AddressPrefix.c_str(), Address.data()) != 1)
				return false;
			else if (Version != (int)Account.AddressVersion)
				return false;
			else if (DecodedSize != sizeof(Pubkeyhash))
				return false;

			memcpy(PublicKeyHash, Decoded, sizeof(Pubkeyhash));
			return true;
		}
		bool Signing::EncodeAddress(const Pubkeyhash PublicKeyHash, String& Address)
		{
			VI_ASSERT(PublicKeyHash != nullptr, "public key hash should be set");
			auto& Account = Protocol::Now().Account;
			char Encoded[128];

			if (Segwit::Encode(Encoded, Account.AddressPrefix.c_str(), (int)Account.AddressVersion, PublicKeyHash, sizeof(Pubkeyhash)) != 1)
				return false;

			size_t Size = strnlen(Encoded, sizeof(Encoded));
			Address.resize(Size);
			memcpy(Address.data(), Encoded, Size);
			return true;
		}
		Schema* Signing::SerializeSecretKey(const Seckey SecretKey)
		{
			Seckey Null = { 0 };
			if (!memcmp(SecretKey, Null, sizeof(Null)))
				return Var::Set::Null();

			String Data;
			if (!EncodeSecretKey(SecretKey, Data))
				return Var::Set::Null();

			return Var::Set::String(Data);
		}
		Schema* Signing::SerializePublicKey(const Pubkey PublicKey)
		{
			Pubkey Null = { 0 };
			if (!memcmp(PublicKey, Null, sizeof(Null)))
				return Var::Set::Null();

			String Data;
			if (!EncodePublicKey(PublicKey, Data))
				return Var::Set::Null();

			return Var::Set::String(Data);
		}
		Schema* Signing::SerializeAddress(const Pubkeyhash PublicKeyHash)
		{
			Pubkeyhash Null = { 0 };
			if (!memcmp(PublicKeyHash, Null, sizeof(Null)))
				return Var::Set::Null();

			String Data;
			if (!EncodeAddress(PublicKeyHash, Data))
				return Var::Set::Null();

			return Var::Set::String(Data);
		}
		secp256k1_context* Signing::GetContext()
		{
			VI_ASSERT(SharedContext != nullptr, "secp256k1 context is not initialized");
			return SharedContext;
		}
		secp256k1_context* Signing::SharedContext = nullptr;

		bool Encoding::DecodeUintBlob(const String& Value, uint8_t* Data, size_t DataSize)
		{
			VI_ASSERT(Data != nullptr, "data should be set");
			if (Value.size() != DataSize)
			{
				memset(Data, 0, DataSize);
				return Value.empty();
			}

			memcpy(Data, Value.data(), Value.size());
			return true;
		}
		void Encoding::EncodeUint128(const uint8_t Value[16], uint128_t& Data)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint64_t Array[2] = { 0 };
			memcpy(Array, Value, sizeof(Array));
			auto& Bits0 = Data.High();
			auto& Bits1 = Data.Low();
			Array[1] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[1]);
			Array[0] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[0]);
			memcpy((uint64_t*)&Bits0, &Array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits1, &Array[1], sizeof(uint64_t));
		}
		void Encoding::DecodeUint128(const uint128_t& Value, uint8_t Data[16])
		{
			VI_ASSERT(Data != nullptr, "data should be set");
			uint64_t Array[2] =
			{
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.High()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.Low())
			};
			memcpy((char*)Data, Array, sizeof(Array));
		}
		void Encoding::EncodeUint256(const uint8_t Value[32], uint256_t& Data)
		{
			VI_ASSERT(Value != nullptr, "value should be set");
			uint64_t Array[4] = { 0 };
			memcpy(Array, Value, sizeof(Array));
			auto& Bits0 = Data.High().High();
			auto& Bits1 = Data.High().Low();
			auto& Bits2 = Data.Low().High();
			auto& Bits3 = Data.Low().Low();
			Array[0] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[0]);
			Array[1] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[1]);
			Array[2] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[2]);
			Array[3] = OS::CPU::ToEndianness(OS::CPU::Endian::Big, Array[3]);
			memcpy((uint64_t*)&Bits0, &Array[0], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits1, &Array[1], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits2, &Array[2], sizeof(uint64_t));
			memcpy((uint64_t*)&Bits3, &Array[3], sizeof(uint64_t));
		}
		void Encoding::DecodeUint256(const uint256_t& Value, uint8_t Data[32])
		{
			VI_ASSERT(Data != nullptr, "data should be set");
			uint64_t Array[4] =
			{
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.High().High()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.High().Low()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.Low().High()),
				OS::CPU::ToEndianness(OS::CPU::Endian::Big, Value.Low().Low())
			};
			memcpy((char*)Data, Array, sizeof(Array));
		}
		String Encoding::Encode0xHex256(const uint256_t& Value)
		{
			uint8_t Data[32];
			DecodeUint256(Value, Data);
			return "0x" + Codec::HexEncode(std::string_view((char*)Data, sizeof(Data)));
		}
		uint256_t Encoding::Decode0xHex256(const std::string_view& Data)
		{
			if (Data.size() < 2)
				return uint256_t(0);

			return uint256_t(Data[0] == '0' && Data[1] == 'x' ? Data.substr(2) : Data, 16);
		}
		String Encoding::Encode0xHex128(const uint128_t& Value)
		{
			uint8_t Data[16];
			DecodeUint128(Value, Data);
			return "0x" + Codec::HexEncode(std::string_view((char*)Data, sizeof(Data)));
		}
		uint128_t Encoding::Decode0xHex128(const std::string_view& Data)
		{
			if (Data.size() < 2)
				return uint128_t(0);

			return uint128_t(Data[0] == '0' && Data[1] == 'x' ? Data.substr(2) : Data, 16);
		}
		uint32_t Encoding::TypeOf(const std::string_view& Name)
		{
			return Hashing::Hash32d(Name);
		}
		Schema* Encoding::SerializeUint256(const uint256_t& Value)
		{
			if (Value <= std::numeric_limits<int64_t>::max())
				return Var::Set::Integer((uint64_t)Value);

			uint8_t Data[32];
			DecodeUint256(Value, Data);

			size_t Size = Value.Bytes();
			return Var::Set::String(Format::Util::Encode0xHex(std::string_view((char*)Data + (sizeof(Data) - Size), Size)));
		}

		uint256_t Hashing::Sha256ci(const uint256_t& A, const uint256_t& B)
		{
			uint8_t CombineBuffer[sizeof(uint256_t) * 2];
			Encoding::DecodeUint256(A, CombineBuffer + sizeof(uint256_t) * 0);
			Encoding::DecodeUint256(B, CombineBuffer + sizeof(uint256_t) * 1);
			return Hashing::Hash256i(CombineBuffer, sizeof(CombineBuffer));
		}
		uint64_t Hashing::Sha64d(const uint8_t* Buffer, size_t Size)
		{
			uint64_t Result = 0;
			if (!Size)
				return uint64_t(0);

			String Hash = Hashing::Hash256(Buffer, Size);
			if (Hash.size() < sizeof(Result))
				return uint64_t(0);

			memcpy(&Result, Hash.data(), sizeof(Result));
			return OS::CPU::ToEndianness(OS::CPU::Endian::Little, Result);
		}
		uint64_t Hashing::Sha64d(const std::string_view& Buffer)
		{
			return Sha64d((uint8_t*)Buffer.data(), Buffer.size());
		}
		uint32_t Hashing::Hash32d(const uint8_t* Buffer, size_t Size)
		{
			uint8_t Data[20];
			sha1_Raw(Buffer, Size, Data);

			uint32_t Result;
			memcpy(&Result, Data, sizeof(Result));
			return OS::CPU::ToEndianness(OS::CPU::Endian::Little, Result);
		}
		uint32_t Hashing::Hash32d(const std::string_view& Buffer)
		{
			return Hash32d((uint8_t*)Buffer.data(), Buffer.size());
		}
		void Hashing::Hash160(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[20])
		{
			ripemd160(Buffer, (uint32_t)Size, OutBuffer);
		}
		String Hashing::Hash160(const uint8_t* Buffer, size_t Size)
		{
			uint8_t Hash[RIPEMD160_DIGEST_LENGTH];
			Hash160(Buffer, Size, Hash);
			return String((char*)Hash, sizeof(Hash));
		}
		void Hashing::Hash256(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[32])
		{
			blake2b(Buffer, (uint32_t)Size, OutBuffer, sizeof(uint256_t));
		}
		String Hashing::Hash256(const uint8_t* Buffer, size_t Size)
		{
			uint8_t Hash[BLAKE256_DIGEST_LENGTH];
			Hash256(Buffer, Size, Hash);
			return String((char*)Hash, sizeof(Hash));
		}
		void Hashing::Hash512(const uint8_t* Buffer, size_t Size, uint8_t OutBuffer[64])
		{
			sha3_512(Buffer, Size, OutBuffer);
		}
		String Hashing::Hash512(const uint8_t* Buffer, size_t Size)
		{
			uint8_t Hash[SHA3_512_DIGEST_LENGTH];
			Hash512(Buffer, Size, Hash);
			return String((char*)Hash, sizeof(Hash));
		}
		uint256_t Hashing::Hash256i(const uint8_t* Buffer, size_t Size)
		{
			uint256_t Value;
			auto Hash = Hash256(Buffer, Size);
			Encoding::EncodeUint256((uint8_t*)Hash.data(), Value);
			return Value;
		}
		uint256_t Hashing::Hash256i(const std::string_view& Data)
		{
			return Hash256i((uint8_t*)Data.data(), Data.size());
		}

		AssetId Asset::IdOfHandle(const std::string_view& Handle)
		{
			uint8_t Data[32] = { 0 };
			size_t Size = std::min<size_t>(sizeof(Data), Handle.size());
			memcpy((char*)Data + (sizeof(Data) - Size), Handle.data(), Size);

			uint256_t Value;
			Encoding::EncodeUint256(Data, Value);
			return IdOf(BlockchainOf(Value), TokenOf(Value), ChecksumOf(Value));
		}
		AssetId Asset::IdOf(const std::string_view& Blockchain, const std::string_view& Token, const std::string_view& ContractAddress)
		{
			uint8_t Data[32] = { 0 };
			String Handle = HandleOf(Blockchain, Token, ContractAddress);
			size_t Size = std::min<size_t>(sizeof(Data), Handle.size());
			memcpy((char*)Data + (sizeof(Data) - Size), Handle.data(), Size);

			uint256_t Value;
			Encoding::EncodeUint256(Data, Value);
			return Value;
		}
		AssetId Asset::BaseIdOf(const AssetId& Value)
		{
			return IdOf(BlockchainOf(Value));
		}
		String Asset::HandleOf(const std::string_view& Blockchain, const std::string_view& Token, const std::string_view& ContractAddress)
		{
			String Handle;
			Handle.append(Blockchain.substr(0, 8));
			if (!Token.empty())
			{
				Handle.append(1, ':').append(Token.substr(0, 8));
				Stringify::ToUpper(Handle);
				if (!ContractAddress.empty())
				{
					auto Hash = Codec::Base64URLEncode(*Crypto::HashRaw(Digests::SHA1(), Format::Util::IsHexEncoding(ContractAddress) ? Codec::HexDecode(ContractAddress) : String(ContractAddress)));
					Handle.append(1, ':').append(Hash.substr(0, 32 - Handle.size()));
				}
			}
			else
				Stringify::ToUpper(Handle);
			return Handle.substr(0, 32);
		}
		String Asset::HandleOf(const AssetId& Value)
		{
			uint8_t Data[33];
			Encoding::DecodeUint256(Value, Data);

			size_t Offset = 0;
			while (!Data[Offset] && Offset + 1 < sizeof(Data))
				++Offset;

			char* Handle = (char*)Data + Offset;
			return String(Handle, strnlen(Handle, (sizeof(Data) - 1) - Offset));
		}
		String Asset::BaseHandleOf(const AssetId& Value)
		{
			return HandleOf(BaseIdOf(Value));
		}
		String Asset::BlockchainOf(const AssetId& Value)
		{
			String Handle = HandleOf(Value);
			size_t Index = Handle.find(':');
			return Handle.substr(0, Index);
		}
		String Asset::TokenOf(const AssetId& Value)
		{
			String Handle = HandleOf(Value);
			size_t Index = Handle.find(':');
			return Index == std::string::npos ? String() : Handle.substr(Index + 1, Handle.rfind(':', Index) + 1);
		}
		String Asset::ChecksumOf(const AssetId& Value)
		{
			String Handle = HandleOf(Value);
			size_t Index1 = Handle.find(':');
			size_t Index2 = Handle.rfind(':');
			return Index1 == std::string::npos || Index2 == std::string::npos || Index1 == Index2 ? String() : Handle.substr(Index2 + 1);
		}
		bool Asset::IsValid(const AssetId& Value)
		{
			if (!Value)
				return false;

			auto Blockchain = BlockchainOf(Value);
			if (Stringify::IsEmptyOrWhitespace(Blockchain))
				return false;
#ifdef TAN_VALIDATOR
			if (!NSS::ServerNode::Get()->HasChain(Value))
				return false;
#endif
			auto Token = TokenOf(Value);
			if (Stringify::IsEmptyOrWhitespace(Token))
				return true;

			auto Checksum = ChecksumOf(Value);
			return !Stringify::IsEmptyOrWhitespace(Checksum);
		}
		Schema* Asset::Serialize(const AssetId& Value)
		{
			Schema* Data = Var::Set::Object();
			Data->Set("id", Encoding::SerializeUint256(Value));
			String Chain = BlockchainOf(Value);
			if (!Chain.empty())
				Data->Set("chain", Var::String(Chain));
			String Token = TokenOf(Value);
			if (!Token.empty())
				Data->Set("token", Var::String(Token));
			String Checksum = ChecksumOf(Value);
			if (!Checksum.empty())
				Data->Set("checksum", Var::String(Checksum));
			return Data;
		}

		ExpectsLR<void> Composition::DeriveKeypair1(Type Alg, const CSeed Seed, CSeckey SecretKey1, CPubkey PublicKey1)
		{
			VI_ASSERT(SecretKey1 != nullptr, "secret key 1 should be set");
			VI_ASSERT(PublicKey1 != nullptr, "public key 1 should be set");
			Hashing::Hash512(Seed, sizeof(CSeed), SecretKey1);
			switch (Alg)
			{
				case Type::ED25519:
				{
					ed25519_public_key Point1;
					ConvertToED25519Curve(SecretKey1);
					ed25519_publickey_ext(SecretKey1, Point1);
					memcpy(PublicKey1, Point1, sizeof(Point1));
					Hashing::Hash256(SecretKey1, sizeof(CSeckey), PublicKey1 + sizeof(Point1));
					return Expectation::Met;
				}
				case Type::SECP256K1:
				{
					secp256k1_context* Context = Signing::GetContext();
					while (secp256k1_ec_seckey_verify(Context, SecretKey1) != 1)
						Hashing::Hash512(SecretKey1, sizeof(CSeckey), SecretKey1);

					secp256k1_pubkey Point1;
					if (secp256k1_ec_pubkey_create(Context, &Point1, SecretKey1) != 1)
						return LayerException("bad secret key 1");

					memcpy(PublicKey1, Point1.data, sizeof(Point1.data));
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		ExpectsLR<void> Composition::DeriveKeypair2(Type Alg, const CSeed Seed, const CPubkey PublicKey1, CSeckey SecretKey2, CPubkey PublicKey2, CPubkey PublicKey, size_t* PublicKeySize)
		{
			VI_ASSERT(PublicKey1 != nullptr, "public key 1 should be set");
			VI_ASSERT(SecretKey2 != nullptr, "secret key 2 should be set");
			VI_ASSERT(PublicKey2 != nullptr, "public key 2 should be set");
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			Hashing::Hash512(Seed, sizeof(CSeed), SecretKey2);
			memset(PublicKey, 0, sizeof(CPubkey));
			switch (Alg)
			{
				case Type::ED25519:
				{
					uint8_t Point1[crypto_sign_PUBLICKEYBYTES];
					memcpy(Point1, PublicKey1, sizeof(Point1));

					uint8_t Point2[crypto_sign_PUBLICKEYBYTES];
					ConvertToED25519Curve(SecretKey2);
					ed25519_publickey_ext(SecretKey2, Point2);
					memcpy(PublicKey2, Point2, sizeof(Point2));
					Hashing::Hash256(SecretKey2, sizeof(CSeckey), PublicKey2 + sizeof(Point2));

					Seckey FX, FY;
					SHA256_CTX Hash = { 0 };
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1 + 00, sizeof(Point1) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2 + 00, sizeof(Point2) / 2);
					sha256_Final(&Hash, FX);
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1 + 16, sizeof(Point1) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2 + 16, sizeof(Point2) / 2);
					sha256_Final(&Hash, FY);

					uint8_t X[crypto_sign_PUBLICKEYBYTES], Y[crypto_sign_PUBLICKEYBYTES];
					ConvertToED25519Curve(FX);
					ed25519_publickey_ext(FX, X);
					ConvertToED25519Curve(FY);
					ed25519_publickey_ext(FY, Y);

					uint8_t Z[crypto_sign_PUBLICKEYBYTES];
					crypto_core_ed25519_add(Z, Point1, X);
					if (crypto_scalarmult_ed25519(Point1, SecretKey2, Z) != 0)
						return LayerException("bad secret key 2");

					crypto_core_ed25519_add(Z, Point1, Y);
					memcpy(PublicKey, Z, sizeof(Z));
					if (PublicKeySize != nullptr)
						*PublicKeySize = sizeof(Z);
					return Expectation::Met;
				}
				case Type::SECP256K1:
				{
					secp256k1_context* Context = Signing::GetContext();
					while (secp256k1_ec_seckey_verify(Context, SecretKey2) != 1)
						Hashing::Hash512(SecretKey2, sizeof(CSeckey), SecretKey2);

					secp256k1_pubkey Point1;
					memcpy(Point1.data, PublicKey1, sizeof(Point1));

					secp256k1_pubkey Point2;
					if (secp256k1_ec_pubkey_create(Context, &Point2, SecretKey2) != 1)
						return LayerException("bad secret key 2");

					memcpy(PublicKey2, Point2.data, sizeof(Point2.data));
					Seckey X, Y;
					SHA256_CTX Hash = { 0 };
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1.data + 00, sizeof(Point1.data) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2.data + 00, sizeof(Point2.data) / 2);
					sha256_Final(&Hash, X);
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1.data + 32, sizeof(Point1.data) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2.data + 32, sizeof(Point2.data) / 2);
					sha256_Final(&Hash, Y);

					while (secp256k1_ec_seckey_verify(Context, X) != 1)
					{
						Seckey Data;
						memcpy(Data, X, sizeof(X));
						sha256_Raw(Data, sizeof(Data), X);
					}

					while (secp256k1_ec_seckey_verify(Context, Y) != 1)
					{
						Seckey Data;
						memcpy(Data, Y, sizeof(Y));
						sha256_Raw(Data, sizeof(Data), Y);
					}

					size_t KeySize = sizeof(CPubkey);
					if (secp256k1_ec_pubkey_tweak_add(Context, &Point1, X) != 1)
						return LayerException("bad secret key 2");

					if (secp256k1_ec_pubkey_tweak_mul(Context, &Point1, SecretKey2) != 1)
						return LayerException("bad secret key 2");

					if (secp256k1_ec_pubkey_tweak_add(Context, &Point1, Y) != 1)
						return LayerException("bad secret key 2");

					secp256k1_ec_pubkey_serialize(Context, PublicKey, &KeySize, &Point1, SECP256K1_EC_COMPRESSED);
					if (PublicKeySize != nullptr)
						*PublicKeySize = KeySize;
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		ExpectsLR<void> Composition::DeriveSecretKey(Type Alg, const CSeckey Secret1, const CSeckey Secret2, CSeckey SecretKey, size_t* SecretKeySize)
		{
			VI_ASSERT(SecretKey != nullptr, "secret key should be set");
			VI_ASSERT(Secret1 != nullptr, "secret1 should be set");
			VI_ASSERT(Secret2 != nullptr, "secret2 should be set");
			memset(SecretKey, 0, sizeof(CSeckey));
			switch (Alg)
			{
				case Type::ED25519:
				{
					uint8_t Point1[crypto_sign_PUBLICKEYBYTES];
					ed25519_publickey_ext(Secret1, Point1);

					uint8_t Point2[crypto_sign_PUBLICKEYBYTES];
					ed25519_publickey_ext(Secret2, Point2);

					Seckey FX, FY, FZ;
					SHA256_CTX Hash = { 0 };
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1 + 00, sizeof(Point1) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2 + 00, sizeof(Point2) / 2);
					sha256_Final(&Hash, FX);
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1 + 16, sizeof(Point1) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2 + 16, sizeof(Point2) / 2);
					sha256_Final(&Hash, FY);
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1, sizeof(Point1));
					sha256_Update(&Hash, (uint8_t*)Point2, sizeof(Point2));
					sha256_Final(&Hash, FZ);

					uint8_t X[crypto_sign_PUBLICKEYBYTES], Y[crypto_sign_PUBLICKEYBYTES];
					ConvertToED25519Curve(FX);
					ed25519_publickey_ext(FX, X);
					ConvertToED25519Curve(FY);
					ed25519_publickey_ext(FY, Y);

					uint8_t Z[crypto_sign_SECRETKEYBYTES], W[crypto_sign_SECRETKEYBYTES];
					crypto_core_ed25519_scalar_add(Z, Secret1, FX);
					crypto_core_ed25519_scalar_mul(W, Z, Secret2);
					crypto_core_ed25519_scalar_add(Z, W, FY);
					memcpy(Z + 32, FZ, sizeof(FZ));
					memcpy(SecretKey, Z, sizeof(Z));
					if (SecretKeySize != nullptr)
						*SecretKeySize = sizeof(Z);
					return Expectation::Met;
				}
				case Type::SECP256K1:
				{
					secp256k1_context* Context = Signing::GetContext();
					secp256k1_pubkey Point1, Point2;
					if (secp256k1_ec_pubkey_create(Context, &Point1, Secret1) != 1)
						return LayerException("bad secret key 1");

					if (secp256k1_ec_pubkey_create(Context, &Point2, Secret2) != 1)
						return LayerException("bad secret key 2");

					Seckey X, Y;
					SHA256_CTX Hash = { 0 };
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1.data + 00, sizeof(Point1.data) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2.data + 00, sizeof(Point2.data) / 2);
					sha256_Final(&Hash, X);
					sha256_Init(&Hash);
					sha256_Update(&Hash, (uint8_t*)Point1.data + 32, sizeof(Point1.data) / 2);
					sha256_Update(&Hash, (uint8_t*)Point2.data + 32, sizeof(Point2.data) / 2);
					sha256_Final(&Hash, Y);

					while (secp256k1_ec_seckey_verify(Context, X) != 1)
					{
						Seckey Data;
						memcpy(Data, X, sizeof(X));
						sha256_Raw(Data, sizeof(Data), X);
					}

					while (secp256k1_ec_seckey_verify(Context, Y) != 1)
					{
						Seckey Data;
						memcpy(Data, Y, sizeof(Y));
						sha256_Raw(Data, sizeof(Data), Y);
					}

					memcpy(SecretKey, Secret1, sizeof(Seckey));
					if (secp256k1_ec_seckey_tweak_add(Context, SecretKey, X) != 1)
						return LayerException("bad secret key 2");

					if (secp256k1_ec_seckey_tweak_mul(Context, SecretKey, Secret2) != 1)
						return LayerException("bad secret key 2");

					if (secp256k1_ec_seckey_tweak_add(Context, SecretKey, Y) != 1)
						return LayerException("bad secret key 2");

					if (SecretKeySize)
						*SecretKeySize = 32;
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		void Composition::ConvertToED25519Curve(uint8_t SecretKey[64])
		{
			SecretKey[0] &= 248;
			SecretKey[31] &= 127;
			SecretKey[31] |= 64;
		}
		void Composition::ConvertToSecretSeed(const Seckey SecretKey, const std::string_view& Entropy, CSeed Seed)
		{
			auto Input = Hashing::Hash512((uint8_t*)Entropy.data(), Entropy.size());
			Input += Hashing::Hash256(SecretKey, sizeof(Seckey));
			Hashing::Hash512((uint8_t*)Input.data(), Input.size(), Seed);
		}

		uint256_t MerkleTree::Path::CalculateRoot(uint256_t Hash) const
		{
			size_t Offset = Index;
			for (size_t i = 0; i < Nodes.size(); i++)
			{
				Hash = (Offset & 1 ? Hasher(Nodes[i], Hash) : Hasher(Hash, Nodes[i]));
				Offset >>= 1;
			}
			return Hash;
		}
		Vector<uint256_t>& MerkleTree::Path::GetBranch()
		{
			return Nodes;
		}
		const Vector<uint256_t>& MerkleTree::Path::GetBranch() const
		{
			return Nodes;
		}
		size_t MerkleTree::Path::GetIndex() const
		{
			return Index;
		}
		bool MerkleTree::Path::Empty()
		{
			return Nodes.empty();
		}

		MerkleTree::MerkleTree()
		{
		}
		MerkleTree::MerkleTree(const uint256_t& PrevMerkleRoot)
		{
			if (PrevMerkleRoot > 0)
				Push(PrevMerkleRoot);
		}
		MerkleTree& MerkleTree::Shift(const uint256_t& Hash)
		{
			Nodes.insert(Nodes.begin(), Hash);
			++Hashes;
			return *this;
		}
		MerkleTree& MerkleTree::Push(const uint256_t& Hash)
		{
			Nodes.push_back(Hash);
			++Hashes;
			return *this;
		}
		MerkleTree& MerkleTree::Reset()
		{
			Nodes.clear();
			Hashes = 0;
			return *this;
		}
		MerkleTree& MerkleTree::Calculate()
		{
			VI_ASSERT(Hasher != nullptr, "hash function should be set");
			if (IsCalculated())
				return *this;

			std::sort(Nodes.begin(), Nodes.end());
			for (size_t Size = Hashes, Node = 0; Size > 1; Size = (Size + 1) / 2)
			{
				for (size_t Offset = 0; Offset < Size; Offset += 2)
					Nodes.push_back(Hasher(Nodes[Node + Offset], Nodes[Node + std::min(Offset + 1, Size - 1)]));
				Node += Size;
			}
			return *this;
		}
		MerkleTree::Path MerkleTree::CalculatePath(const uint256_t& Hash)
		{
			Path Branch;
			Branch.Hasher = Hasher;
			Calculate();

			auto Begin = Nodes.begin(), End = Nodes.begin() + Hashes;
			auto It = std::lower_bound(Nodes.begin(), Nodes.begin() + Hashes, Hash);
			if (It == End)
				return Branch;

			size_t Index = It - Begin;
			Branch.Index = Index;

			for (size_t Size = Hashes, Node = 0; Size > 1; Size = (Size + 1) / 2)
			{
				Branch.Nodes.push_back(Nodes[Node + std::min(Index ^ 1, Size - 1)]);
				Index >>= 1;
				Node += Size;
			}

			return Branch;
		}
		uint256_t MerkleTree::CalculateRoot()
		{
			Calculate();
			return Nodes.empty() ? uint256_t(0) : Nodes.back();
		}
		const Vector<uint256_t>& MerkleTree::GetTree()
		{
			if (!IsCalculated())
				Calculate();

			return Nodes;
		}
		const Vector<uint256_t>& MerkleTree::GetTree() const
		{
			return Nodes;
		}
		size_t MerkleTree::GetComplexity() const
		{
			return Hashes;
		}
		bool MerkleTree::IsCalculated() const
		{
			return !Hashes || Hashes < Nodes.size();
		}
	}
}
