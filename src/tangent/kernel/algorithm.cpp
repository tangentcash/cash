#include "algorithm.h"
#include "oracle.h"
extern "C"
{
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <sodium.h>
#include "../../utils/trezor-crypto/segwit_addr.h"
#include "../../utils/trezor-crypto/ecdsa.h"
#include "../../utils/trezor-crypto/ed25519.h"
#include "../../utils/trezor-crypto/ripemd160.h"
#include "../../utils/trezor-crypto/bip39.h"
}

namespace Tangent
{
	namespace Algorithm
	{
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

		Endpoint::Endpoint(const std::string_view& URI) : Scheme(URI), Secure(false)
		{
			if (Scheme.Hostname.empty())
				return;

			SocketAddress PrimaryCandidate = SocketAddress(Scheme.Hostname, Scheme.Port > 0 ? Scheme.Port : Protocol::Now().User.P2P.Port);
			if (!PrimaryCandidate.IsValid())
			{
				auto SecondaryCandidate = DNS::Get()->Lookup(Scheme.Hostname, ToString(Scheme.Port > 0 ? Scheme.Port : Protocol::Now().User.P2P.Port), DNSType::Listen);
				if (!SecondaryCandidate)
					return;

				auto IpAddress = SecondaryCandidate->GetIpAddress();
				if (!IpAddress)
					return;

				Scheme.Hostname = std::move(*IpAddress);
			}

			if (Scheme.Protocol == "tcp" || Scheme.Protocol == "tcps")
				Address = SocketAddress(Scheme.Hostname, Scheme.Port > 0 ? Scheme.Port : Protocol::Now().User.P2P.Port);
			else if (Scheme.Protocol == "http" || Scheme.Protocol == "https")
				Address = SocketAddress(Scheme.Hostname, Scheme.Port > 0 ? Scheme.Port : Protocol::Now().User.NDS.Port);
			else if (Scheme.Protocol == "rpc" || Scheme.Protocol == "rpcs")
				Address = SocketAddress(Scheme.Hostname, Scheme.Port > 0 ? Scheme.Port : Protocol::Now().User.RPC.Port);
			Secure = Address.IsValid() && Scheme.Protocol.back() == 's';
		}
		bool Endpoint::IsValid() const
		{
			return Address.IsValid() && !Scheme.Hostname.empty() && !Scheme.Protocol.empty() && (Scheme.Protocol == "tcp" || Scheme.Protocol == "tcps" || Scheme.Protocol == "http" || Scheme.Protocol == "https" || Scheme.Protocol == "rpc" || Scheme.Protocol == "rpcs");
		}
		String Endpoint::ToURI(const SocketAddress& Address, const std::string_view& Protocol)
		{
			String URI = String(Protocol);
			URI.append("://");
			URI.append(Address.GetIpAddress().Or("[bad_address]"));

			auto IpPort = Address.GetIpPort();
			if (IpPort)
				URI.append(":").append(ToString(*IpPort));

			return URI;
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
		String Signing::Mnemonicgen(uint16_t Strength)
		{
			char Buffer[256] = { 0 };
			mnemonic_generate((int)Strength, Buffer, (int)sizeof(Buffer));
			return String(Buffer, strnlen(Buffer, sizeof(Buffer)));
		}
		uint256_t Signing::MessageHash(const std::string_view& InsecureMessage)
		{
			String Size(1, (char)InsecureMessage.size());
			if (InsecureMessage.size() > 253)
			{
				uint16_t Size16 = OS::CPU::ToEndianness(OS::CPU::Endian::Little, (uint16_t)InsecureMessage.size());
				Size.append((char*)&Size16, sizeof(Size16));
			}

			const String& Header = Protocol::Now().Account.SignedMessageMagic;
			String Payload = Stringify::Text("%c%s%.*s%.*s", (char)Header.size(), Header.c_str(), (int)Size.size(), Size.c_str(), (int)InsecureMessage.size(), InsecureMessage.data());
			return Hashing::Hash256i(Payload);
		}
		void Signing::Keygen(Seckey PrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			while (true)
			{
				if (!Crypto::FillRandomBytes(PrivateKey, sizeof(Seckey)))
					break;
				else if (VerifyPrivateKey(PrivateKey))
					break;
			}
		}
		bool Signing::RecoverNormal(const uint256_t& Hash, Pubkey PublicKey, const Sighash Signature)
		{
			VI_ASSERT(PublicKey != nullptr && Signature != nullptr, "public key and signature should be set");
			uint8_t RecoveryId = 0;
			size_t SignatureSize = sizeof(Sighash);
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
		bool Signing::RecoverTweaked(const uint256_t& Hash, Pubkey TweakedPublicKey, const Sighash Signature)
		{
			VI_ASSERT(TweakedPublicKey != nullptr && Signature != nullptr, "tweaked public key and signature should be set");
			Pubkey SignaturePublicKey;
			if (!RecoverNormal(Hash, SignaturePublicKey, Signature))
				return false;

			Seckey SignatureTweak;
			if (!DeriveSignatureTweak(Hash, SignatureTweak))
				return false;

			Seckey SignatureTweakNegated;
			if (!NegatePrivateKey(SignatureTweak, SignatureTweakNegated))
				return false;

			return PublicKeyTweakAdd(SignaturePublicKey, SignatureTweakNegated, TweakedPublicKey);
		}
		bool Signing::RecoverNormalHash(const uint256_t& Hash, Pubkeyhash PublicKeyHash, const Sighash Signature)
		{
			VI_ASSERT(PublicKeyHash != nullptr && Signature != nullptr, "public key hash and signature should be set");
			Pubkey PublicKey;
			if (!RecoverNormal(Hash, PublicKey, Signature))
				return false;

			DerivePublicKeyHash(PublicKey, PublicKeyHash);
			return true;
		}
		bool Signing::RecoverTweakedHash(const uint256_t& Hash, Pubkeyhash TweakedPublicKeyHash, const Sighash Signature)
		{
			VI_ASSERT(TweakedPublicKeyHash != nullptr && Signature != nullptr, "tweaked public key hash and signature should be set");
			Pubkey TweakedPublicKey;
			if (!RecoverTweaked(Hash, TweakedPublicKey, Signature))
				return false;

			DerivePublicKeyHash(TweakedPublicKey, TweakedPublicKeyHash);
			return true;
		}
		bool Signing::SignNormal(const uint256_t& Hash, const Seckey PrivateKey, Sighash Signature)
		{
			VI_ASSERT(PrivateKey != nullptr && Signature != nullptr, "private key and signature should be set");
			uint8_t Data[32];
			Encoding::DecodeUint256(Hash, Data);
			memset(Signature, 0, sizeof(Sighash));

			secp256k1_context* Context = GetContext();
			secp256k1_ecdsa_recoverable_signature RecoverableSignature;
			if (secp256k1_ecdsa_sign_recoverable(Context, &RecoverableSignature, Data, PrivateKey, secp256k1_nonce_function_rfc6979, nullptr) != 1)
				return false;

			int BaseRecoveryId = 0;
			if (secp256k1_ecdsa_recoverable_signature_serialize_compact(Context, Signature, &BaseRecoveryId, &RecoverableSignature) != 1)
				return false;

			size_t SignatureSize = sizeof(Sighash);
			uint8_t RecoveryId = (uint8_t)BaseRecoveryId;
			memcpy(Signature + SignatureSize - 1, &RecoveryId, sizeof(RecoveryId));
			return true;
		}
		bool Signing::SignTweaked(const uint256_t& Hash, const Seckey RootPrivateKey, Sighash Signature)
		{
			VI_ASSERT(RootPrivateKey != nullptr && Signature != nullptr, "root private key and signature should be set");
			Seckey SignatureTweak;
			if (!DeriveSignatureTweak(Hash, SignatureTweak))
				return false;

			Pubkey RootPublicKey;
			if (!DerivePublicKey(RootPrivateKey, RootPublicKey))
				return false;

			Seckey RootTweak;
			DeriveRootTweak(RootPublicKey, RootTweak);

			Seckey SignaturePrivateKey;
			if (!PrivateKeyTweakMul(RootPrivateKey, RootTweak, SignaturePrivateKey))
				return false;

			if (!PrivateKeyTweakAdd(SignaturePrivateKey, SignatureTweak, SignaturePrivateKey))
				return false;

			return SignNormal(Hash, SignaturePrivateKey, Signature);
		}
		bool Signing::VerifyNormal(const uint256_t& Hash, const Pubkey PublicKey, const Sighash Signature)
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
		bool Signing::VerifyTweaked(const uint256_t& Hash, const Pubkey TweakedPublicKey, const Sighash Signature)
		{
			VI_ASSERT(TweakedPublicKey != nullptr && Signature != nullptr, "tweaked public key and signature should be set");
			Seckey SignatureTweak;
			if (!DeriveSignatureTweak(Hash, SignatureTweak))
				return false;

			Pubkey SignaturePublicKey;
			memcpy(SignaturePublicKey, TweakedPublicKey, sizeof(Pubkey));
			if (!PrivateKeyTweakAdd(SignaturePublicKey, SignatureTweak, SignaturePublicKey))
				return false;

			return VerifyNormal(Hash, SignaturePublicKey, Signature);
		}
		bool Signing::VerifyMnemonic(const std::string_view& Mnemonic)
		{
			String Data = String(Mnemonic);
			return mnemonic_check(Data.c_str()) == 1;
		}
		bool Signing::VerifyPrivateKey(const Seckey PrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			secp256k1_context* Context = GetContext();
			return secp256k1_ec_seckey_verify(Context, PrivateKey) == 1;
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
		bool Signing::DerivePrivateKey(const std::string_view& Mnemonic, Seckey PrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			uint8_t Seed[64] = { 0 };
			String Data = String(Mnemonic);
			mnemonic_to_seed(Data.c_str(), "", Seed, nullptr);
			DerivePrivateKey(std::string_view((char*)Seed, sizeof(Seed)), PrivateKey, 1);
			return true;
		}
		bool Signing::DerivePrivateKey(const std::string_view& Seed, Seckey PrivateKey, size_t Iterations)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(Iterations > 0, "iterations should be greater than zero");
			String Derivation = String(Seed);
			for (size_t i = 0; i < Iterations; i++)
			{
				while (true)
				{
					Derivation = Hashing::Hash256((uint8_t*)Derivation.data(), Derivation.size());
					memcpy(PrivateKey, Derivation.data(), sizeof(Seckey));
					if (VerifyPrivateKey(PrivateKey))
						return true;
				}
			}
			return false;
		}
		void Signing::DeriveSealingKey(const Seckey PrivateKey, Pubkey SealingKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(SealingKey != nullptr, "sealing key should be set");
			memset(SealingKey, 0, sizeof(Pubkey));
			crypto_scalarmult_curve25519_base(SealingKey, PrivateKey);
		}
		bool Signing::DerivePublicKey(const Seckey PrivateKey, Pubkey PublicKey)
		{
			VI_ASSERT(PrivateKey != nullptr && PublicKey != nullptr, "private key and public key should be set");
			secp256k1_pubkey DerivedPublicKey;
			secp256k1_context* Context = GetContext();
			memset(PublicKey, 0, sizeof(Pubkey));
			if (secp256k1_ec_pubkey_create(Context, &DerivedPublicKey, PrivateKey) != 1)
				return false;

			size_t PublicKeySize = sizeof(Pubkey);
			return secp256k1_ec_pubkey_serialize(Context, PublicKey, &PublicKeySize, &DerivedPublicKey, SECP256K1_EC_COMPRESSED) == 1;
		}
		void Signing::DerivePublicKeyHash(const Pubkey PublicKey, Pubkeyhash PublicKeyHash)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			VI_ASSERT(PublicKeyHash != nullptr, "public key hash should be set");
			ecdsa_get_pubkeyhash(PublicKey, HASHER_SHA3K, PublicKeyHash);
		}
		void Signing::DeriveRootTweak(const Pubkey RootPublicKey, Seckey RootTweak)
		{
			VI_ASSERT(RootPublicKey != nullptr, "root public key should be set");
			VI_ASSERT(RootTweak != nullptr, "root tweak should be set");
			Hashing::Hash256(RootPublicKey, sizeof(Pubkey), RootTweak);
			while (!VerifyPrivateKey(RootTweak))
				Hashing::Hash256(RootTweak, sizeof(Seckey), RootTweak);
		}
		bool Signing::DeriveSignatureTweak(const uint256_t& Hash, Seckey SignatureTweak)
		{
			Seckey InputHash;
			Encoding::DecodeUint256(Hash, InputHash);
			while (!VerifyPrivateKey(InputHash))
				Hashing::Hash256(InputHash, sizeof(InputHash), InputHash);
		
			Seckey OutputHash;
			Hashing::Hash256(InputHash, sizeof(InputHash), OutputHash);
			while (!VerifyPrivateKey(OutputHash))
				Hashing::Hash256(OutputHash, sizeof(OutputHash), OutputHash);

			return PrivateKeyTweakMul(InputHash, OutputHash, SignatureTweak);
		}
		bool Signing::DeriveTweakedPublicKey(const Pubkey RootPublicKey, Pubkey TweakedPublicKey)
		{
			Seckey RootTweak;
			DeriveRootTweak(RootPublicKey, RootTweak);
			return PublicKeyTweakMul(RootPublicKey, RootTweak, TweakedPublicKey);
		}
		bool Signing::NegatePrivateKey(const Seckey PrivateKey, Seckey NegatedPrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(NegatedPrivateKey != nullptr, "negated private key should be set");
			secp256k1_context* Context = GetContext();
			if (PrivateKey != NegatedPrivateKey)
				memcpy(NegatedPrivateKey, PrivateKey, sizeof(Seckey));
			return secp256k1_ec_privkey_negate(Context, NegatedPrivateKey) == 1;
		}
		bool Signing::PrivateKeyTweakAdd(const Seckey PrivateKey, const Seckey Tweak, Seckey TweakedPrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(Tweak != nullptr, "tweak should be set");
			VI_ASSERT(TweakedPrivateKey != nullptr, "tweaked private key should be set");
			secp256k1_context* Context = GetContext();
			if (PrivateKey != TweakedPrivateKey)
				memcpy(TweakedPrivateKey, PrivateKey, sizeof(Seckey));
			return secp256k1_ec_seckey_tweak_add(Context, TweakedPrivateKey, Tweak) == 1;
		}
		bool Signing::PrivateKeyTweakMul(const Seckey PrivateKey, const Seckey Tweak, Seckey TweakedPrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(Tweak != nullptr, "tweak should be set");
			VI_ASSERT(TweakedPrivateKey != nullptr, "tweaked private key should be set");
			secp256k1_context* Context = GetContext();
			if (PrivateKey != TweakedPrivateKey)
				memcpy(TweakedPrivateKey, PrivateKey, sizeof(Seckey));
			return secp256k1_ec_seckey_tweak_mul(Context, TweakedPrivateKey, Tweak) == 1;
		}
		bool Signing::NegatePublicKey(const Pubkey PublicKey, Pubkey NegatedPublicKey)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			VI_ASSERT(NegatedPublicKey != nullptr, "negated public key should be set");
			secp256k1_pubkey SerializedPublicKey;
			secp256k1_context* Context = GetContext();
			if (secp256k1_ec_pubkey_parse(Context, &SerializedPublicKey, PublicKey, sizeof(Pubkey)) != 1)
				return false;

			size_t NegatedPublicKeySize = sizeof(Pubkey);
			bool Success = secp256k1_ec_pubkey_negate(Context, &SerializedPublicKey) == 1;
			secp256k1_ec_pubkey_serialize(Context, NegatedPublicKey, &NegatedPublicKeySize, &SerializedPublicKey, SECP256K1_EC_COMPRESSED);
			return Success;
		}
		bool Signing::PublicKeyTweakAdd(const Pubkey PublicKey, const Seckey Tweak, Pubkey TweakedPublicKey)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			VI_ASSERT(Tweak != nullptr, "tweak should be set");
			VI_ASSERT(TweakedPublicKey != nullptr, "tweaked public key should be set");
			secp256k1_pubkey SerializedPublicKey;
			secp256k1_context* Context = GetContext();
			if (secp256k1_ec_pubkey_parse(Context, &SerializedPublicKey, PublicKey, sizeof(Pubkey)) != 1)
				return false;

			size_t TweakedPublicKeySize = sizeof(Pubkey);
			bool Success = secp256k1_ec_pubkey_tweak_add(Context, &SerializedPublicKey, Tweak) == 1;
			secp256k1_ec_pubkey_serialize(Context, TweakedPublicKey, &TweakedPublicKeySize, &SerializedPublicKey, SECP256K1_EC_COMPRESSED);
			return Success;
		}
		bool Signing::PublicKeyTweakMul(const Pubkey PublicKey, const Seckey Tweak, Pubkey TweakedPublicKey)
		{
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			VI_ASSERT(Tweak != nullptr, "tweak should be set");
			VI_ASSERT(TweakedPublicKey != nullptr, "tweaked public key should be set");
			secp256k1_pubkey SerializedPublicKey;
			secp256k1_context* Context = GetContext();
			if (secp256k1_ec_pubkey_parse(Context, &SerializedPublicKey, PublicKey, sizeof(Pubkey)) != 1)
				return false;

			size_t TweakedPublicKeySize = sizeof(Pubkey);
			bool Success = secp256k1_ec_pubkey_tweak_mul(Context, &SerializedPublicKey, Tweak) == 1;
			secp256k1_ec_pubkey_serialize(Context, TweakedPublicKey, &TweakedPublicKeySize, &SerializedPublicKey, SECP256K1_EC_COMPRESSED);
			return Success;
		}
		Option<String> Signing::PublicEncrypt(const Pubkey SealingKey, const std::string_view& Plaintext)
		{
			VI_ASSERT(SealingKey != nullptr, "sealing key should be set");
			if (Plaintext.empty())
				return Optional::None;

			String Shuffletext = String(Plaintext);
			Shuffletext.insert(0, *Crypto::RandomBytes(16));

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
			if (crypto_box_seal((uint8_t*)Ciphertext.data(), (uint8_t*)Shuffletext.data(), Shuffletext.size(), SealingKey) != 0)
				return Optional::None;

			return Ciphertext;
		}
		Option<String> Signing::PrivateDecrypt(const Seckey PrivateKey, const std::string_view& Ciphertext)
		{
			VI_ASSERT(PrivateKey != nullptr, "sealing private key should be set");
			if (Ciphertext.size() <= crypto_box_SEALBYTES)
				return Optional::None;

			Pubkey SealingKey;
			DeriveSealingKey(PrivateKey, SealingKey);

			String Shuffletext;
			Shuffletext.resize(Ciphertext.size() - crypto_box_SEALBYTES);
			if (crypto_box_seal_open((uint8_t*)Shuffletext.data(), (uint8_t*)Ciphertext.data(), Ciphertext.size(), SealingKey, PrivateKey) != 0)
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
		bool Signing::DecodePrivateKey(const std::string_view& Value, Seckey PrivateKey)
		{
			VI_ASSERT(PrivateKey != nullptr && Stringify::IsCString(Value), "private key and value should be set");
			auto& Account = Protocol::Now().Account;
			uint8_t Decoded[40];
			size_t DecodedSize = sizeof(Decoded);
			int Version = 0;

			if (Segwit::Decode(&Version, Decoded, &DecodedSize, Account.PrivateKeyPrefix.c_str(), Value.data()) != 1)
				return false;
			else if (Version != (int)Account.PrivateKeyVersion)
				return false;
			else if (DecodedSize != sizeof(Seckey))
				return false;

			memcpy(PrivateKey, Decoded, sizeof(Seckey));
			return true;
		}
		bool Signing::EncodePrivateKey(const Seckey PrivateKey, String& Value)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			auto& Account = Protocol::Now().Account;
			char Encoded[128];
			if (Segwit::Encode(Encoded, Account.PrivateKeyPrefix.c_str(), (int)Account.PrivateKeyVersion, PrivateKey, sizeof(Seckey)) != 1)
				return false;

			size_t Size = strnlen(Encoded, sizeof(Encoded));
			Value.resize(Size);
			memcpy(Value.data(), Encoded, Size);
			return true;
		}
		bool Signing::DecodeSealingKey(const std::string_view& Value, Pubkey SealingKey)
		{
			VI_ASSERT(SealingKey != nullptr && Stringify::IsCString(Value), "public key and value should be set");
			auto& Account = Protocol::Now().Account;
			uint8_t Decoded[40];
			size_t DecodedSize = sizeof(Decoded);
			int Version = 0;

			if (Segwit::Decode(&Version, Decoded, &DecodedSize, Account.SealingKeyPrefix.c_str(), Value.data()) != 1)
				return false;
			else if (Version != (int)Account.SealingKeyVersion)
				return false;
			else if (DecodedSize != sizeof(Pubkey))
				return false;

			memcpy(SealingKey, Decoded, sizeof(Pubkey));
			return true;
		}
		bool Signing::EncodeSealingKey(const Pubkey SealingKey, String& Value)
		{
			VI_ASSERT(SealingKey != nullptr, "public key should be set");
			auto& Account = Protocol::Now().Account;
			char Encoded[128];
			if (Segwit::Encode(Encoded, Account.SealingKeyPrefix.c_str(), (int)Account.SealingKeyVersion, SealingKey, sizeof(Pubkey)) != 1)
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
		Schema* Signing::SerializePrivateKey(const Seckey PrivateKey)
		{
			Seckey Null = { 0 };
			if (!memcmp(PrivateKey, Null, sizeof(Null)))
				return Var::Set::Null();

			String Data;
			if (!EncodePrivateKey(PrivateKey, Data))
				return Var::Set::Null();

			return Var::Set::String(Data);
		}
		Schema* Signing::SerializeSealingKey(const Pubkey PublicKey)
		{
			Pubkey Null = { 0 };
			if (!memcmp(PublicKey, Null, sizeof(Null)))
				return Var::Set::Null();

			String Data;
			if (!EncodeSealingKey(PublicKey, Data))
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

		uint32_t Hashing::Hash32d(const uint8_t* Buffer, size_t Size)
		{
			return Crypto::CRC32(std::string_view((char*)Buffer, Size)) % std::numeric_limits<uint32_t>::max();
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

			if (!Oracle::Datamaster::IsInitialized() || !Oracle::Datamaster::HasChain(Value))
				return false;

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

		ExpectsLR<void> Composition::DeriveKeypair1(Type Alg, CSeckey PrivateKey1, CPubkey PublicKey1)
		{
			VI_ASSERT(PrivateKey1 != nullptr, "private key 1 should be set");
			VI_ASSERT(PublicKey1 != nullptr, "public key 1 should be set");
			Crypto::FillRandomBytes(PrivateKey1, sizeof(CSeckey));
			switch (Alg)
			{
				case Type::ED25519:
				{
					ed25519_public_key Point1;
					ConvertToED25519Curve(PrivateKey1);
					ed25519_publickey_ext(PrivateKey1, Point1);
					memcpy(PublicKey1, Point1, sizeof(Point1));
					Crypto::FillRandomBytes(PublicKey1 + sizeof(Point1), sizeof(Point1));
					return Expectation::Met;
				}
				case Type::SECP256K1:
				{
					secp256k1_context* Context = Signing::GetContext();
					while (secp256k1_ec_seckey_verify(Context, PrivateKey1) != 1)
						Crypto::FillRandomBytes(PrivateKey1, sizeof(CSeckey));

					secp256k1_pubkey Point1;
					if (secp256k1_ec_pubkey_create(Context, &Point1, PrivateKey1) != 1)
                        return LayerException("bad private key 1");
                    
					memcpy(PublicKey1, Point1.data, sizeof(Point1.data));
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		ExpectsLR<void> Composition::DeriveKeypair2(Type Alg, const CPubkey PublicKey1, CSeckey PrivateKey2, CPubkey PublicKey2, Pubkey PublicKey, size_t* PublicKeySize)
		{
			VI_ASSERT(PublicKey1 != nullptr, "public key 1 should be set");
			VI_ASSERT(PrivateKey2 != nullptr, "private key 2 should be set");
			VI_ASSERT(PublicKey2 != nullptr, "public key 2 should be set");
			VI_ASSERT(PublicKey != nullptr, "public key should be set");
			Crypto::FillRandomBytes(PrivateKey2, sizeof(CSeckey));
			memset(PublicKey, 0, sizeof(Pubkey));
			switch (Alg)
			{
				case Type::ED25519:
				{
					uint8_t Point1[crypto_sign_PUBLICKEYBYTES];
					memcpy(Point1, PublicKey1, sizeof(Point1));

					uint8_t Point2[crypto_sign_PUBLICKEYBYTES];
					ConvertToED25519Curve(PrivateKey2);
					ed25519_publickey_ext(PrivateKey2, Point2);
					memcpy(PublicKey2, Point2, sizeof(Point2));
					Crypto::FillRandomBytes(PublicKey2 + sizeof(Point2), sizeof(Point2));

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
					if (crypto_scalarmult_ed25519(Point1, PrivateKey2, Z) != 0)
                        return LayerException("bad private key 2");
                    
					crypto_core_ed25519_add(Z, Point1, Y);
					memcpy(PublicKey, Z, sizeof(Z));
					if (PublicKeySize != nullptr)
						*PublicKeySize = sizeof(Z);
					return Expectation::Met;
				}
				case Type::SECP256K1:
				{
					secp256k1_context* Context = Signing::GetContext();
					while (secp256k1_ec_seckey_verify(Context, PrivateKey2) != 1)
						Crypto::FillRandomBytes(PrivateKey2, sizeof(CSeckey));

					secp256k1_pubkey Point1;
					memcpy(Point1.data, PublicKey1, sizeof(Point1));

					secp256k1_pubkey Point2;
					if (secp256k1_ec_pubkey_create(Context, &Point2, PrivateKey2) != 1)
                        return LayerException("bad private key 2");

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

					size_t KeySize = sizeof(Pubkey);
					if (secp256k1_ec_pubkey_tweak_add(Context, &Point1, X) != 1)
                        return LayerException("bad private key 2");
                    
                    if (secp256k1_ec_pubkey_tweak_mul(Context, &Point1, PrivateKey2) != 1)
                        return LayerException("bad private key 2");
                    
                    if (secp256k1_ec_pubkey_tweak_add(Context, &Point1, Y) != 1)
                        return LayerException("bad private key 2");
                    
					secp256k1_ec_pubkey_serialize(Context, PublicKey, &KeySize, &Point1, SECP256K1_EC_COMPRESSED);
					if (PublicKeySize != nullptr)
						*PublicKeySize = KeySize;
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		ExpectsLR<void> Composition::DerivePrivateKey(Type Alg, const CSeckey Secret1, const CSeckey Secret2, CSeckey PrivateKey, size_t* PrivateKeySize)
		{
			VI_ASSERT(PrivateKey != nullptr, "private key should be set");
			VI_ASSERT(Secret1 != nullptr, "secret1 should be set");
			VI_ASSERT(Secret2 != nullptr, "secret2 should be set");
			memset(PrivateKey, 0, sizeof(CSeckey));
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
					memcpy(PrivateKey, Z, sizeof(Z));
					if (PrivateKeySize != nullptr)
						*PrivateKeySize = sizeof(Z);
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

					memcpy(PrivateKey, Secret1, sizeof(Seckey));
                    if (secp256k1_ec_seckey_tweak_add(Context, PrivateKey, X) != 1)
                        return LayerException("bad secret key 2");
                    
                    if (secp256k1_ec_seckey_tweak_mul(Context, PrivateKey, Secret2) != 1)
                        return LayerException("bad secret key 2");

                    if (secp256k1_ec_seckey_tweak_add(Context, PrivateKey, Y) != 1)
                        return LayerException("bad secret key 2");

					if (PrivateKeySize)
						*PrivateKeySize = 32;
					return Expectation::Met;
				}
				default:
					return LayerException("invalid composition algorithm");
			}
		}
		void Composition::ConvertToED25519Curve(uint8_t PrivateKey[64])
		{
			PrivateKey[0] &= 248;
			PrivateKey[31] &= 127;
			PrivateKey[31] |= 64;
		}
	}
}
