#include "wallet.h"
#ifdef TAN_VALIDATOR
#include "../validator/storage/mempoolstate.h"
#include "../validator/storage/chainstate.h"
#include "../validator/service/p2p.h"
#endif

namespace Tangent
{
	namespace Ledger
	{
		bool Wallet::SetSecretKey(const Algorithm::Seckey Value)
		{
			memset(SecretKey, 0, sizeof(SecretKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(SecretKey, Value, sizeof(SecretKey));

			if (!HasSecretKey())
				return false;

			Algorithm::Pubkey RootPublicKey;
			if (!Algorithm::Signing::DerivePublicKey(SecretKey, RootPublicKey))
				return false;

			Algorithm::Seckey SealingSecretKey;
			Algorithm::Signing::DeriveSealingKeypair(SecretKey, SealingSecretKey, SealingKey);
			if (!Algorithm::Signing::DeriveTweakedPublicKey(SecretKey, RootPublicKey, PublicKey))
				return false;

			Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);
			return true;
		}
		void Wallet::SetPublicKey(const Algorithm::Pubkey Value)
		{
			memset(SecretKey, 0, sizeof(SecretKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(PublicKey, Value, sizeof(PublicKey));

			if (HasPublicKey())
				Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);
		}
		void Wallet::SetPublicKeyHash(const Algorithm::Pubkeyhash Value)
		{
			memset(SecretKey, 0, sizeof(SecretKey));
			memset(PublicKey, 0, sizeof(PublicKey));
			memset(PublicKeyHash, 0, sizeof(PublicKeyHash));
			if (Value != nullptr)
				memcpy(PublicKeyHash, Value, sizeof(PublicKeyHash));
		}
		bool Wallet::VerifySecretKey() const
		{
			return HasSecretKey() && Algorithm::Signing::VerifySecretKey(SecretKey);
		}
		bool Wallet::VerifySealingKey() const
		{
			if (!VerifySecretKey())
				return false;

			Algorithm::Seckey SealingSecretKey;
			Algorithm::Pubkey SealingKeyCandidate = { 0 };
			Algorithm::Signing::DeriveSealingKeypair(SecretKey, SealingSecretKey, SealingKeyCandidate);
			return memcmp(SealingKeyCandidate, SealingKey, sizeof(SealingKey)) == 0;
		}
		bool Wallet::VerifyPublicKey() const
		{
			if (!VerifySecretKey())
				return false;

			Algorithm::Pubkey RootPublicKey;
			if (!Algorithm::Signing::DerivePublicKey(SecretKey, RootPublicKey))
				return false;

			Algorithm::Pubkey Copy = { 0 };
			if (!Algorithm::Signing::DeriveTweakedPublicKey(SecretKey, RootPublicKey, Copy))
				return false;

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
			return HasSecretKey() && Message.Sign(SecretKey);
		}
		bool Wallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(std::string_view((char*)SecretKey, HasSecretKey() ? sizeof(SecretKey) : 0));
			Stream->WriteString(std::string_view((char*)SealingKey, HasSealingKey() ? sizeof(SealingKey) : 0));
			Stream->WriteString(std::string_view((char*)PublicKey, HasPublicKey() ? sizeof(PublicKey) : 0));
			Stream->WriteString(std::string_view((char*)PublicKeyHash, HasPublicKeyHash() ? sizeof(PublicKeyHash) : 0));
			return true;
		}
		bool Wallet::LoadPayload(Format::Stream& Stream)
		{
			String SecretKeyAssembly; memset(SecretKey, 0, sizeof(SecretKey));
			if (!Stream.ReadString(Stream.ReadType(), &SecretKeyAssembly))
				return false;

			if (!SecretKeyAssembly.empty())
			{
				if (SecretKeyAssembly.size() != sizeof(SecretKey))
					return false;

				memcpy(SecretKey, SecretKeyAssembly.data(), sizeof(SecretKey));
			}

			String SealingKeyAssembly; memset(SealingKey, 0, sizeof(SealingKey));
			if (!Stream.ReadString(Stream.ReadType(), &SealingKeyAssembly))
				return false;

			if (!SealingKeyAssembly.empty())
			{
				if (SealingKeyAssembly.size() != sizeof(SealingKey))
					return false;

				memcpy(SealingKey, SealingKeyAssembly.data(), sizeof(SealingKey));
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
		bool Wallet::HasSecretKey() const
		{
			Algorithm::Seckey Null = { 0 };
			return memcmp(SecretKey, Null, sizeof(Null)) != 0;
		}
		bool Wallet::HasSealingKey() const
		{
			Algorithm::Pubkey Null = { 0 };
			return memcmp(SealingKey, Null, sizeof(Null)) != 0;
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
		Option<String> Wallet::SealMessage(const std::string_view& Plaintext, const Algorithm::Pubkey ForSealingKey, const std::string_view& Entropy) const
		{
			return Algorithm::Signing::PublicEncrypt(ForSealingKey, Plaintext, Entropy);
		}
		Option<String> Wallet::OpenMessage(const std::string_view& Ciphertext) const
		{
			if (!HasSecretKey())
				return Optional::None;

			return Algorithm::Signing::PrivateDecrypt(SecretKey, Ciphertext);
		}
		String Wallet::GetSecretKey() const
		{
			String Value;
			if (!HasSecretKey())
				return Value;

			Algorithm::Signing::EncodeSecretKey(SecretKey, Value);
			return Value;
		}
		String Wallet::GetSealingKey() const
		{
			String Value;
			if (!HasSealingKey())
				return Value;

			Algorithm::Signing::EncodeSealingKey(SealingKey, Value);
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
		ExpectsLR<uint64_t> Wallet::GetLatestSequence() const
		{
#ifdef TAN_VALIDATOR
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountSequence::AsInstanceIndex(PublicKeyHash), 0);
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
			Data->Set("secret_key", Algorithm::Signing::SerializeSecretKey(SecretKey));
			Data->Set("sealing_key", Algorithm::Signing::SerializeSealingKey(SealingKey));
			Data->Set("public_key", Algorithm::Signing::SerializePublicKey(PublicKey));
			Data->Set("public_key_hash", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKeyHash, sizeof(PublicKeyHash)))));
			Data->Set("address", Algorithm::Signing::SerializeAddress(PublicKeyHash));
			return Data;
		}
		UPtr<Schema> Wallet::AsPublicSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("sealing_key", Algorithm::Signing::SerializeSealingKey(SealingKey));
			Data->Set("public_key", Algorithm::Signing::SerializePublicKey(PublicKey));
			Data->Set("public_key_hash", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKeyHash, sizeof(PublicKeyHash)))));
			Data->Set("address", Algorithm::Signing::SerializeAddress(PublicKeyHash));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Wallet::AsInstanceTypename()
		{
			return "wallet";
		}
		Wallet Wallet::FromMnemonic(const std::string_view& Mnemonic)
		{
			Algorithm::Seckey Key;
			if (!Algorithm::Signing::DeriveSecretKey(Mnemonic, Key))
				return Wallet();

			return FromSecretKey(Key);
		}
		Wallet Wallet::FromSeed(const std::string_view& Seed)
		{
			Algorithm::Seckey Key;
			if (!Algorithm::Signing::DeriveSecretKey(Seed, Key, 1))
				return Wallet();

			return FromSecretKey(Key);
		}
		Wallet Wallet::FromSecretKey(const Algorithm::Seckey Key)
		{
			Wallet Result;
			Result.SetSecretKey(Key);
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

		bool Validator::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Address.GetIpAddress().Or(String()));
			Stream->WriteInteger(Address.GetIpPort().Or(0));
			Stream->WriteInteger(Availability.Latency);
			Stream->WriteInteger(Availability.Timestamp);
			Stream->WriteInteger(Availability.Calls);
			Stream->WriteInteger(Availability.Errors);
			Stream->WriteInteger(Ports.P2P);
			Stream->WriteInteger(Ports.NDS);
			Stream->WriteInteger(Ports.RPC);
			Stream->WriteBoolean(Services.Consensus);
			Stream->WriteBoolean(Services.Discovery);
			Stream->WriteBoolean(Services.Synchronization);
			Stream->WriteBoolean(Services.Interface);
			Stream->WriteBoolean(Services.Proposer);
			Stream->WriteBoolean(Services.Public);
			Stream->WriteBoolean(Services.Streaming);
			return true;
		}
		bool Validator::LoadPayload(Format::Stream& Stream)
		{
			String IpAddress;
			if (!Stream.ReadString(Stream.ReadType(), &IpAddress))
				return false;

			uint16_t IpPort;
			if (!Stream.ReadInteger(Stream.ReadType(), &IpPort))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Availability.Latency))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Availability.Timestamp))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Availability.Calls))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Availability.Errors))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Ports.P2P))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Ports.NDS))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Ports.RPC))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Consensus))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Discovery))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Synchronization))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Interface))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Proposer))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Public))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Services.Streaming))
				return false;

			Address = SocketAddress(IpAddress, IpPort);
			return true;
		}
		bool Validator::IsValid() const
		{
			if (!Address.IsValid())
				return false;
#ifdef TAN_VALIDATOR
			return !P2P::Routing::IsAddressReserved(Address);
#else
			return true;
#endif
		}
		uint64_t Validator::GetPreference() const
		{
			double Messages = (double)Availability.Calls;
			double Confidence = Messages > 0.0 ? Mathd::Exp((double)(Availability.Calls < Availability.Errors ? 0 : Availability.Calls - Availability.Errors) / Messages) : 0.0;
			double Uncertainty = Messages > 0.0 ? Mathd::Exp((double)Availability.Errors / Messages) : 0.0;
			double Preference = Availability.Latency > 0.0 ? 1000.0 / (double)Availability.Latency : 1000.0;
			double Score = (Confidence - Uncertainty) * Preference + Preference * 0.1;
			return (uint64_t)(1000.0 * Score);
		}
		UPtr<Schema> Validator::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("address", Var::String(Address.GetIpAddress().Or("[bad_address]") + ":" + ToString(Address.GetIpPort().Or(0))));

			auto* AvailabilityData = Data->Set("availability");
			AvailabilityData->Set("latency", Algorithm::Encoding::SerializeUint256(Availability.Latency));
			AvailabilityData->Set("timestamp", Algorithm::Encoding::SerializeUint256(Availability.Timestamp));
			AvailabilityData->Set("calls", Algorithm::Encoding::SerializeUint256(Availability.Calls));
			AvailabilityData->Set("errors", Algorithm::Encoding::SerializeUint256(Availability.Errors));

			auto* PortsData = Data->Set("ports");
			PortsData->Set("p2p", Var::Integer(Ports.P2P));
			PortsData->Set("nds", Var::Integer(Ports.NDS));
			PortsData->Set("rpc", Var::Integer(Ports.RPC));

			auto* ServicesData = Data->Set("services");
			ServicesData->Set("consensus", Var::Boolean(Services.Consensus));
			ServicesData->Set("discovery", Var::Boolean(Services.Discovery));
			ServicesData->Set("synchronization", Var::Boolean(Services.Synchronization));
			ServicesData->Set("interface", Var::Boolean(Services.Interface));
			ServicesData->Set("proposer", Var::Boolean(Services.Proposer));
			ServicesData->Set("public", Var::Boolean(Services.Public));
			ServicesData->Set("streaming", Var::Boolean(Services.Streaming));
			return Data;
		}
		uint32_t Validator::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Validator::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t Validator::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Validator::AsInstanceTypename()
		{
			return "validator";
		}
	}
}