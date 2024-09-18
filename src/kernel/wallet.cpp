#include "wallet.h"
#include "../policy/typenames.h"
#ifdef TAN_VALIDATOR
#include "../policy/storages.h"
#include "../layer/p2p.h"
#endif

namespace Tangent
{
	namespace Ledger
	{
		void Wallet::SetPrivateKey(const Algorithm::Seckey Value)
		{
			memset(PrivateKey, 0, sizeof(PrivateKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(PrivateKey, Value, sizeof(PrivateKey));

			if (HasPrivateKey())
			{
				Algorithm::Signing::DerivePublicKey(PrivateKey, PublicKey);
				Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);
				Algorithm::Signing::DeriveSealingKeypair(PrivateKey, SealingPrivateKey, SealingPublicKey);
			}
		}
		void Wallet::SetPublicKey(const Algorithm::Pubkey Value)
		{
			memset(PrivateKey, 0, sizeof(PrivateKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(PublicKey, Value, sizeof(PublicKey));

			if (HasPublicKey())
				Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);
		}
		void Wallet::SetPublicKeyHash(const Algorithm::Pubkeyhash Value)
		{
			memset(PrivateKey, 0, sizeof(PrivateKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(PublicKeyHash, Value, sizeof(PublicKeyHash));
		}
		bool Wallet::VerifyPrivateKey() const
		{
			return HasPrivateKey() && Algorithm::Signing::VerifyPrivateKey(PrivateKey);
		}
		bool Wallet::VerifyPublicKey() const
		{
			if (!VerifyPrivateKey())
				return false;

			Algorithm::Pubkey Copy = { 0 };
			Algorithm::Signing::DerivePublicKey(PrivateKey, Copy);
			if (memcmp(PublicKey, Copy, sizeof(Copy)) != 0)
				return false;

			return HasPublicKey() && Algorithm::Signing::VerifyPublicKey(PublicKey);
		}
		bool Wallet::VerifyAddress() const
		{
			if (!VerifyPublicKey())
				return false;

			Algorithm::Pubkeyhash Copy;
			Algorithm::Signing::DerivePublicKeyHash(PublicKey, Copy);
			if (memcmp(PublicKeyHash, Copy, sizeof(Copy)) != 0)
				return false;

			return HasPublicKeyHash() && Algorithm::Signing::VerifyAddress(GetAddress());
		}
		bool Wallet::VerifySealingPrivateKey() const
		{
			if (!VerifyPrivateKey())
				return false;

			Algorithm::Seckey SealingPrivateKeyCandidate = { 0 };
			Algorithm::Pubkey SealingPublicKeyCandidate = { 0 };
			Algorithm::Signing::DeriveSealingKeypair(PrivateKey, SealingPrivateKeyCandidate, SealingPublicKeyCandidate);
			return memcmp(SealingPrivateKeyCandidate, SealingPrivateKey, sizeof(SealingPrivateKey)) == 0;
		}
		bool Wallet::VerifySealingPublicKey() const
		{
			if (!VerifySealingPrivateKey())
				return false;

			Algorithm::Seckey SealingPrivateKeyCandidate = { 0 };
			Algorithm::Pubkey SealingPublicKeyCandidate = { 0 };
			Algorithm::Signing::DeriveSealingKeypair(PrivateKey, SealingPrivateKeyCandidate, SealingPublicKeyCandidate);
			return memcmp(SealingPublicKeyCandidate, SealingPublicKey, sizeof(SealingPublicKey)) == 0;
		}
		bool Wallet::Verify(const Messages::Authentic& Message) const
		{
			return HasPublicKey() && Message.Verify(PublicKey);
		}
		bool Wallet::Recover(Messages::Authentic& Message) const
		{
			Algorithm::Pubkeyhash RecoverPublicKeyHash;
			return Message.Recover(RecoverPublicKeyHash) && memcmp(RecoverPublicKeyHash, PublicKeyHash, sizeof(PublicKeyHash)) == 0;
		}
		bool Wallet::Sign(Messages::Authentic& Message) const
		{
			return HasPrivateKey() && Message.Sign(PrivateKey);
		}
		bool Wallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(std::string_view((char*)PrivateKey, HasPrivateKey() ? sizeof(PrivateKey) : 0));
			Stream->WriteString(std::string_view((char*)PublicKey, HasPublicKey() ? sizeof(PublicKey) : 0));
			Stream->WriteString(std::string_view((char*)PublicKeyHash, HasPublicKeyHash() ? sizeof(PublicKeyHash) : 0));
			return true;
		}
		bool Wallet::LoadPayload(Format::Stream& Stream)
		{
			String PrivateKeyAssembly; memset(PrivateKey, 0, sizeof(PrivateKey));
			if (!Stream.ReadString(Stream.ReadType(), &PrivateKeyAssembly))
				return false;

			if (!PrivateKeyAssembly.empty())
			{
				if (PrivateKeyAssembly.size() != sizeof(PrivateKey))
					return false;

				memcpy(PrivateKey, PrivateKeyAssembly.data(), sizeof(PrivateKey));
			}

			String PublicKeyAssembly; memset(PublicKey, 0, sizeof(PublicKey));
			if (!Stream.ReadString(Stream.ReadType(), &PublicKeyAssembly))
				return false;

			if (!PublicKeyAssembly.empty())
			{
				if (PublicKeyAssembly.size() != sizeof(PublicKey))
					return false;

				memcpy(PublicKey, PublicKeyAssembly.data(), sizeof(PublicKey));
			}

			String PublicKeyHashAssembly; memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (!Stream.ReadString(Stream.ReadType(), &PublicKeyHashAssembly))
				return false;

			if (!PublicKeyHashAssembly.empty())
			{
				if (PublicKeyHashAssembly.size() != sizeof(PublicKeyHash))
					return false;

				memcpy(PublicKeyHash, PublicKeyHashAssembly.data(), sizeof(PublicKeyHash));
			}

			return true;
		}
		bool Wallet::HasPrivateKey() const
		{
			Algorithm::Seckey Null = { 0 };
			return memcmp(PrivateKey, Null, sizeof(Null)) != 0;
		}
		bool Wallet::HasPublicKey() const
		{
			Algorithm::Pubkey Null = { 0 };
			return memcmp(PublicKey, Null, sizeof(Null)) != 0;
		}
		bool Wallet::HasPublicKeyHash() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(PublicKeyHash, Null, sizeof(Null)) != 0;
		}
		bool Wallet::HasSealingPrivateKey() const
		{
			Algorithm::Seckey Null = { 0 };
			return memcmp(SealingPrivateKey, Null, sizeof(Null)) != 0;
		}
		bool Wallet::HasSealingPublicKey() const
		{
			Algorithm::Pubkey Null = { 0 };
			return memcmp(SealingPublicKey, Null, sizeof(Null)) != 0;
		}
		Option<String> Wallet::SealMessage(const std::string_view& Plaintext, const Algorithm::Pubkey SealingPublicKey) const
		{
			return Algorithm::Signing::EncryptWithSealingPublicKey(SealingPublicKey, Plaintext);
		}
		Option<String> Wallet::OpenMessage(const std::string_view& Ciphertext) const
		{
			if (!HasSealingPrivateKey() || !HasSealingPublicKey())
				return Optional::None;

			return Algorithm::Signing::DecryptWithSealingPrivateKey(SealingPrivateKey, SealingPublicKey, Ciphertext);
		}
		String Wallet::GetPrivateKey() const
		{
			String Value;
			if (!HasPrivateKey())
				return Value;

			Algorithm::Signing::EncodePrivateKey(PrivateKey, Value);
			return Value;
		}
		String Wallet::GetPublicKey() const
		{
			String Value;
			if (!HasPublicKey())
				return Value;

			Algorithm::Signing::EncodePublicKey(PublicKey, Value);
			return Value;
		}
		String Wallet::GetAddress() const
		{
			String Value;
			if (!HasPublicKeyHash())
				return Value;

			Algorithm::Signing::EncodeAddress(PublicKeyHash, Value);
			return Value;
		}
		String Wallet::GetSealingPrivateKey() const
		{
			String Value;
			if (!HasPrivateKey())
				return Value;

			Algorithm::Signing::EncodeSealingPrivateKey(SealingPrivateKey, Value);
			return Value;
		}
		String Wallet::GetSealingPublicKey() const
		{
			String Value;
			if (!HasPublicKey())
				return Value;

			Algorithm::Signing::EncodeSealingPublicKey(SealingPublicKey, Value);
			return Value;
		}
		ExpectsLR<uint64_t> Wallet::GetLatestSequence() const
		{
#ifdef TAN_VALIDATOR
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::AccountSequence::AsInstanceAddress(PublicKeyHash), States::AccountSequence::AsInstanceStride(), 0);
			uint64_t PendingSequence = Mempool.GetHighestTransactionSequence(PublicKeyHash).Or(1);
			uint64_t FinalizedSequence = (State ? ((States::AccountSequence*)**State)->Sequence : 1);
			return std::max(FinalizedSequence, PendingSequence);
#else
			return LayerException("chainstate data not available");
#endif
		}
		UPtr<Schema> Wallet::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("private_key", Algorithm::Signing::SerializePrivateKey(PrivateKey));
			Data->Set("public_key", Algorithm::Signing::SerializePublicKey(PublicKey));
			Data->Set("public_key_hash", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKeyHash, sizeof(PublicKeyHash)))));
			Data->Set("address", Algorithm::Signing::SerializeAddress(PublicKeyHash));
			Data->Set("sealing_private_key", Algorithm::Signing::SerializeSealingPrivateKey(SealingPrivateKey));
			Data->Set("sealing_public_key", Algorithm::Signing::SerializeSealingPublicKey(SealingPublicKey));
			return Data;
		}
		UPtr<Schema> Wallet::AsPublicSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("public_key", Algorithm::Signing::SerializePublicKey(PublicKey));
			Data->Set("public_key_hash", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKeyHash, sizeof(PublicKeyHash)))));
			Data->Set("address", Algorithm::Signing::SerializeAddress(PublicKeyHash));
			Data->Set("sealing_public_key", Algorithm::Signing::SerializeSealingPublicKey(SealingPublicKey));
			return Data;
		}
		uint32_t Wallet::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Wallet::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t Wallet::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Wallet::AsInstanceTypename()
		{
			return "wallet";
		}
		Wallet Wallet::FromMnemonic(const std::string_view& Mnemonic)
		{
			Algorithm::Seckey Key;
			Algorithm::Signing::DerivePrivateKey(Mnemonic, Key);
			return FromPrivateKey(Key);
		}
		Wallet Wallet::FromSeed(const std::string_view& Seed)
		{
			Algorithm::Seckey Key;
			Algorithm::Signing::DerivePrivateKey(Seed, Key, 1);
			return FromPrivateKey(Key);
		}
		Wallet Wallet::FromPrivateKey(const Algorithm::Seckey Key)
		{
			Wallet Result;
			Result.SetPrivateKey(Key);
			return Result;
		}
		Wallet Wallet::FromPublicKey(const Algorithm::Pubkey Key)
		{
			Wallet Result;
			Result.SetPublicKey(Key);
			return Result;
		}
		Wallet Wallet::FromPublicKeyHash(const Algorithm::Pubkeyhash Key)
		{
			Wallet Result;
			Result.SetPublicKeyHash(Key);
			return Result;
		}

		bool Edge::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Address);
			Stream->WriteInteger(Requests);
			Stream->WriteInteger(Errors);
			Stream->WriteInteger(Timestamp);
			Stream->WriteInteger(Latency);
			return true;
		}
		bool Edge::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Address))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Requests))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Errors))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Timestamp))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Latency))
				return false;

			return true;
		}
		bool Edge::IsValid() const
		{
			if (Address.empty())
				return false;
#ifdef TAN_VALIDATOR
			return !P2P::Routing::IsAddressReserved(SocketAddress(Address, Protocol::Now().User.P2P.NodePort));
#else
			return true;
#endif
		}
		uint64_t Edge::GetPreference() const
		{
			double Messages = (double)Requests;
			double Confidence = Messages > 0.0 ? Mathd::Exp((double)(Requests < Errors ? 0 : Requests - Errors) / Messages) : 0.0;
			double Uncertainty = Messages > 0.0 ? Mathd::Exp((double)Errors / Messages) : 0.0;
			double Preference = Latency > 0.0 ? 1000.0 / (double)Latency : 1000.0;
			double Score = (Confidence - Uncertainty) * Preference + Preference * 0.1;
			return (uint64_t)(1000.0 * Score);
		}
		UPtr<Schema> Edge::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("address", Var::String(Address));
			Data->Set("requests", Algorithm::Encoding::SerializeUint256(Requests));
			Data->Set("errors", Algorithm::Encoding::SerializeUint256(Errors));
			Data->Set("timestamp", Algorithm::Encoding::SerializeUint256(Timestamp));
			Data->Set("latency", Algorithm::Encoding::SerializeUint256(Latency));
			return Data;
		}
		uint32_t Edge::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Edge::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t Edge::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Edge::AsInstanceTypename()
		{
			return "edge";
		}
	}
}