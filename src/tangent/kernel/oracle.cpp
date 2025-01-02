#include "oracle.h"
#include "../policy/typenames.h"
#ifdef TAN_VALIDATOR
#include "../storage/sidechainstate.h"
#include "../oracle/bitcoin.h"
#include "../oracle/forks/bitcoin.h"
#include "../oracle/cardano.h"
#include "../oracle/ethereum.h"
#include "../oracle/forks/ethereum.h"
#include "../oracle/ripple.h"
#include "../oracle/solana.h"
#include "../oracle/stellar.h"
#include "../oracle/tron.h"
#endif
#include <sstream>

namespace Tangent
{
	namespace Oracle
	{
		static bool IsPrivateKeyEmptyOrWhitespace(const PrivateKey& Value)
		{
			if (!Value.Size())
				return true;

			auto Data = Value.Expose<2048>();
			for (size_t i = 0; i < Data.Size; i++)
			{
				char V = Data.Key[i];
				if (V != ' ' && V != '\t' && V != '\r' && V != '\n')
					return false;
			}

			return true;
		}

		TokenUTXO::TokenUTXO() : Decimals(0)
		{
		}
		TokenUTXO::TokenUTXO(const std::string_view& NewContractAddress, const Decimal& NewValue) : ContractAddress(NewContractAddress), Value(NewValue), Decimals(0)
		{
		}
		TokenUTXO::TokenUTXO(const std::string_view& NewContractAddress, const std::string_view& NewSymbol, const Decimal& NewValue, uint8_t NewDecimals) : ContractAddress(NewContractAddress), Symbol(NewSymbol), Value(NewValue), Decimals(NewDecimals)
		{
		}
		Decimal TokenUTXO::GetDivisibility()
		{
			Decimal Divisibility = Decimals > 0 ? Decimal("1" + String(Decimals, '0')) : Decimal(1);
			return Divisibility.Truncate(Protocol::Now().Message.Precision);
		}
		bool TokenUTXO::IsCoinValid() const
		{
			return !ContractAddress.empty() && !Symbol.empty() && !Value.IsNegative() && !Value.IsNaN();
		}

		CoinUTXO::CoinUTXO(const std::string_view& NewTransactionId, const std::string_view& NewAddress, Option<uint64_t>&& NewAddressIndex, Decimal&& NewValue, uint32_t NewIndex) : TransactionId(NewTransactionId), Address(NewAddress), Value(std::move(NewValue)), AddressIndex(NewAddressIndex), Index(NewIndex)
		{
		}
		void CoinUTXO::ApplyTokenValue(const std::string_view& ContractAddress, const std::string_view& Symbol, const Decimal& NewValue, uint8_t Decimals)
		{
			if (!ContractAddress.empty())
			{
				for (auto& Item : Tokens)
				{
					if (Item.ContractAddress == ContractAddress)
					{
						if (Item.Value.IsNaN())
							Item.Value = NewValue;
						else
							Item.Value += NewValue;
						return;
					}
				}
				Tokens.push_back(TokenUTXO(ContractAddress, Symbol, NewValue, Decimals));
			}
			else if (Value.IsNaN())
				Value = NewValue;
			else
				Value += NewValue;
		}
		Option<Decimal> CoinUTXO::GetTokenValue(const std::string_view& ContractAddress)
		{
			if (ContractAddress.empty())
				return Value;

			for (auto& Item : Tokens)
			{
				if (Item.ContractAddress == ContractAddress)
					return Item.Value;
			}

			return Optional::None;
		}
		bool CoinUTXO::IsValid() const
		{
			for (auto& Token : Tokens)
			{
				if (!Token.IsCoinValid())
					return false;
			}

			return !TransactionId.empty() && !Value.IsNaN() && !Value.IsNegative() && !Stringify::IsEmptyOrWhitespace(Address);
		}

		Transferer::Transferer() : Value(Decimal::NaN())
		{
		}
		Transferer::Transferer(const std::string_view& NewAddress, Option<uint64_t>&& NewAddressIndex, Decimal&& NewValue) : Address(NewAddress), Value(std::move(NewValue)), AddressIndex(NewAddressIndex)
		{
		}
		bool Transferer::IsValid() const
		{
			return !Stringify::IsEmptyOrWhitespace(Address) && (Value.IsZero() || Value.IsPositive());
		}

		MasterWallet::MasterWallet(PrivateKey&& NewSeedingKey, PrivateKey&& NewVerifyingKey, PrivateKey&& NewSigningKey) : SeedingKey(std::move(NewSeedingKey)), VerifyingKey(std::move(NewVerifyingKey)), SigningKey(std::move(NewSigningKey))
		{
		}
		bool MasterWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			auto RawSeedingKey = SeedingKey.Expose<2048>();
			auto RawVerifyingKey = VerifyingKey.Expose<2048>();
			auto RawSigningKey = SigningKey.Expose<2048>();
			Stream->WriteInteger(MaxAddressIndex);
			Stream->WriteString(std::string_view(RawSeedingKey.Key, RawSeedingKey.Size));
			Stream->WriteString(std::string_view(RawVerifyingKey.Key, RawVerifyingKey.Size));
			Stream->WriteString(std::string_view(RawSigningKey.Key, RawSigningKey.Size));
			return true;
		}
		bool MasterWallet::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &MaxAddressIndex))
				return false;

			String RawSignature;
			if (!Stream.ReadString(Stream.ReadType(), &RawSignature))
				return false;

			String RawVerifyingKey;
			if (!Stream.ReadString(Stream.ReadType(), &RawVerifyingKey))
				return false;

			String RawSigningKey;
			if (!Stream.ReadString(Stream.ReadType(), &RawSigningKey))
				return false;

			SeedingKey = PrivateKey(RawSignature);
			VerifyingKey = PrivateKey(RawVerifyingKey);
			SigningKey = PrivateKey(RawSigningKey);
			return true;
		}
		bool MasterWallet::IsValid() const
		{
			return !IsPrivateKeyEmptyOrWhitespace(SeedingKey) && !IsPrivateKeyEmptyOrWhitespace(VerifyingKey) && !IsPrivateKeyEmptyOrWhitespace(SigningKey);
		}
		UPtr<Schema> MasterWallet::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("seeding_key", Var::String(SeedingKey.ExposeToHeap()));
			Data->Set("verifying_key", Var::String(VerifyingKey.ExposeToHeap()));
			Data->Set("signing_key", Var::String(SigningKey.ExposeToHeap()));
			Data->Set("max_address_index", Algorithm::Encoding::SerializeUint256(MaxAddressIndex));
			return Data;
		}
		uint256_t MasterWallet::AsHash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			auto RawSigningKey = SigningKey.Expose<2048>();
			Format::Stream Message;
			Message.WriteString(*Crypto::HashHex(Digests::SHA512(), std::string_view(RawSigningKey.Key, RawSigningKey.Size)));
			((MasterWallet*)this)->Checksum = Message.Hash();
			return Checksum;
		}
		uint32_t MasterWallet::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view MasterWallet::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t MasterWallet::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view MasterWallet::AsInstanceTypename()
		{
			return "oracle_master_wallet";
		}

		DerivedVerifyingWallet::DerivedVerifyingWallet(AddressMap&& NewAddresses, Option<uint64_t>&& NewAddressIndex, PrivateKey&& NewVerifyingKey) : Addresses(std::move(NewAddresses)), VerifyingKey(std::move(NewVerifyingKey)), AddressIndex(NewAddressIndex)
		{
		}
		bool DerivedVerifyingWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			auto RawVerifyingKey = VerifyingKey.Expose<2048>();
			Stream->WriteBoolean(!!AddressIndex);
			if (AddressIndex)
				Stream->WriteInteger(*AddressIndex);
			Stream->WriteInteger((uint8_t)Addresses.size());
			for (auto& Address : Addresses)
			{
				Stream->WriteInteger(Address.first);
				Stream->WriteString(Address.second);
			}
			Stream->WriteString(std::string_view(RawVerifyingKey.Key, RawVerifyingKey.Size));
			return true;
		}
		bool DerivedVerifyingWallet::LoadPayload(Format::Stream& Stream)
		{
			bool HasAddressIndex;
			if (!Stream.ReadBoolean(Stream.ReadType(), &HasAddressIndex))
				return false;
			
			AddressIndex = HasAddressIndex ? Option<uint64_t>(0) : Option<uint64_t>(Optional::None);
			if (AddressIndex && !Stream.ReadInteger(Stream.ReadType(), AddressIndex.Address()))
				return false;

			uint8_t AddressesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &AddressesSize))
				return false;

			Addresses.clear();
			for (uint8_t i = 0; i < AddressesSize; i++)
			{
				uint8_t Version;
				if (!Stream.ReadInteger(Stream.ReadType(), &Version))
					return false;

				String Address;
				if (!Stream.ReadString(Stream.ReadType(), &Address))
					return false;

				Addresses[Version] = std::move(Address);
			}

			String RawVerifyingKey;
			if (!Stream.ReadString(Stream.ReadType(), &RawVerifyingKey))
				return false;

			VerifyingKey = PrivateKey(RawVerifyingKey);
			return true;
		}
		bool DerivedVerifyingWallet::IsValid() const
		{
			if (Addresses.empty())
				return false;

			if (IsPrivateKeyEmptyOrWhitespace(VerifyingKey))
				return false;

			for (auto& Address : Addresses)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.second))
					return false;
			}

			return true;
		}
		UPtr<Schema> DerivedVerifyingWallet::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			auto* AddressesData = Data->Set("addresses", Var::Set::Array());
			for (auto& Address : Addresses)
				AddressesData->Push(Var::String(Address.second));
			Data->Set("address_index", AddressIndex ? Algorithm::Encoding::SerializeUint256(*AddressIndex) : Var::Set::Null());
			Data->Set("verifying_key", Var::String(VerifyingKey.ExposeToHeap()));
			return Data;
		}
		uint32_t DerivedVerifyingWallet::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view DerivedVerifyingWallet::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t DerivedVerifyingWallet::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DerivedVerifyingWallet::AsInstanceTypename()
		{
			return "oracle_derived_verifying_wallet";
		}

		DerivedSigningWallet::DerivedSigningWallet(DerivedVerifyingWallet&& NewWallet, PrivateKey&& NewSigningKey) : DerivedVerifyingWallet(std::move(NewWallet)), SigningKey(std::move(NewSigningKey))
		{
		}
		bool DerivedSigningWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!DerivedVerifyingWallet::StorePayload(Stream))
				return false;

			auto RawSigningKey = SigningKey.Expose<2048>();
			Stream->WriteString(std::string_view(RawSigningKey.Key, RawSigningKey.Size));
			return true;
		}
		bool DerivedSigningWallet::LoadPayload(Format::Stream& Stream)
		{
			if (!DerivedVerifyingWallet::LoadPayload(Stream))
				return false;

			String RawSigningKey;
			if (!Stream.ReadString(Stream.ReadType(), &RawSigningKey))
				return false;

			SigningKey = PrivateKey(RawSigningKey);
			return true;
		}
		bool DerivedSigningWallet::IsValid() const
		{
			return DerivedVerifyingWallet::IsValid() && !IsPrivateKeyEmptyOrWhitespace(SigningKey);
		}
		UPtr<Schema> DerivedSigningWallet::AsSchema() const
		{
			Schema* Data = DerivedVerifyingWallet::AsSchema().Reset();
			Data->Set("signing_key", Var::String(SigningKey.ExposeToHeap()));
			return Data;
		}
		uint32_t DerivedSigningWallet::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view DerivedSigningWallet::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t DerivedSigningWallet::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DerivedSigningWallet::AsInstanceTypename()
		{
			return "oracle_derived_signing_wallet";
		}

		DynamicWallet::DynamicWallet() : Parent(Optional::None), VerifyingChild(Optional::None), SigningChild(Optional::None)
		{
		}
		DynamicWallet::DynamicWallet(const MasterWallet& Value) : Parent(Value), VerifyingChild(Optional::None), SigningChild(Optional::None)
		{
			if (!Parent->IsValid())
				Parent = Optional::None;
		}
		DynamicWallet::DynamicWallet(const DerivedVerifyingWallet& Value) : Parent(Optional::None), VerifyingChild(Value), SigningChild(Optional::None)
		{
			if (!VerifyingChild->IsValid())
				VerifyingChild = Optional::None;
		}
		DynamicWallet::DynamicWallet(const DerivedSigningWallet& Value) : Parent(Optional::None), VerifyingChild(Optional::None), SigningChild(Value)
		{
			if (!SigningChild->IsValid())
				SigningChild = Optional::None;
		}
		Option<String> DynamicWallet::GetBinding() const
		{
			const PrivateKey* VerifyingKey = nullptr;
			if (Parent)
				VerifyingKey = &Parent->VerifyingKey;
			else if (VerifyingChild)
				VerifyingKey = &VerifyingChild->VerifyingKey;
			else if (SigningChild)
				VerifyingKey = &SigningChild->VerifyingKey;

			if (!VerifyingKey)
				return Optional::None;

			auto Data = VerifyingKey->Expose<2048>();
			return Algorithm::Hashing::Hash256((uint8_t*)Data.Key, Data.Size);
		}
		bool DynamicWallet::IsValid() const
		{
			return (Parent && Parent->IsValid()) || (VerifyingChild && VerifyingChild->IsValid()) || (SigningChild && SigningChild->IsValid());
		}

		IncomingTransaction::IncomingTransaction() : Asset(0), BlockId(0)
		{
		}
		bool IncomingTransaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Asset);
			Stream->WriteInteger(BlockId);
			Stream->WriteString(TransactionId);
			Stream->WriteDecimal(Fee);
			Stream->WriteInteger((uint32_t)From.size());
			for (auto& Item : From)
			{
				Stream->WriteString(Item.Address);
				Stream->WriteBoolean(!!Item.AddressIndex);
				if (Item.AddressIndex)
					Stream->WriteInteger(*Item.AddressIndex);
				Stream->WriteDecimal(Item.Value);
			}
			Stream->WriteInteger((uint32_t)To.size());
			for (auto& Item : To)
			{
				Stream->WriteString(Item.Address);
				Stream->WriteBoolean(!!Item.AddressIndex);
				if (Item.AddressIndex)
					Stream->WriteInteger(*Item.AddressIndex);
				Stream->WriteDecimal(Item.Value);
			}
			return true;
		}
		bool IncomingTransaction::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &BlockId))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &TransactionId))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Fee))
				return false;

			uint32_t FromSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &FromSize))
				return false;

			From.reserve(FromSize);
			for (size_t i = 0; i < FromSize; i++)
			{
				Transferer Transferer;
				if (!Stream.ReadString(Stream.ReadType(), &Transferer.Address))
					return false;

				bool HasAddressIndex;
				if (!Stream.ReadBoolean(Stream.ReadType(), &HasAddressIndex))
					return false;

				Transferer.AddressIndex = HasAddressIndex ? Option<uint64_t>(0) : Option<uint64_t>(Optional::None);
				if (Transferer.AddressIndex && !Stream.ReadInteger(Stream.ReadType(), Transferer.AddressIndex.Address()))
					return false;

				if (!Stream.ReadDecimal(Stream.ReadType(), &Transferer.Value))
					return false;

				From.emplace_back(std::move(Transferer));
			}

			uint32_t ToSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &ToSize))
				return false;

			To.reserve(ToSize);
			for (size_t i = 0; i < ToSize; i++)
			{
				Transferer Transferer;
				if (!Stream.ReadString(Stream.ReadType(), &Transferer.Address))
					return false;

				bool HasAddressIndex;
				if (!Stream.ReadBoolean(Stream.ReadType(), &HasAddressIndex))
					return false;

				Transferer.AddressIndex = HasAddressIndex ? Option<uint64_t>(0) : Option<uint64_t>(Optional::None);
				if (Transferer.AddressIndex && !Stream.ReadInteger(Stream.ReadType(), Transferer.AddressIndex.Address()))
					return false;

				if (!Stream.ReadDecimal(Stream.ReadType(), &Transferer.Value))
					return false;

				To.emplace_back(std::move(Transferer));
			}

			return true;
		}
		bool IncomingTransaction::IsValid() const
		{
			if (From.empty() || To.empty())
				return false;

			if (Fee.IsNegative() || Fee.IsNaN())
				return false;

			Decimal Input = 0.0;
			for (auto& Address : From)
			{
				if (!Address.Value.IsPositive() && !Address.Value.IsZero())
					return false;
				Input += Address.Value;
			}

			if (Input < Fee)
				return false;

			Decimal Output = 0.0;
			for (auto& Address : To)
			{
				if (!Address.IsValid())
					return false;
				Output += Address.Value;
			}

			return Algorithm::Asset::IsValid(Asset) && !Stringify::IsEmptyOrWhitespace(TransactionId) && Output <= Input;
		}
		void IncomingTransaction::SetTransaction(const Algorithm::AssetId& NewAsset, uint64_t NewBlockId, const std::string_view& NewTransactionId, Decimal&& NewFee)
		{
			BlockId = NewBlockId;
			TransactionId = NewTransactionId;
			Asset = NewAsset;
			Fee = std::move(NewFee);
		}
		void IncomingTransaction::SetOperations(Vector<Transferer>&& NewFrom, Vector<Transferer>&& NewTo)
		{
			From = std::move(NewFrom);
			To = std::move(NewTo);
		}
		Decimal IncomingTransaction::GetInputValue() const
		{
			Decimal Value = 0.0;
			for (auto& Address : To)
				Value += Address.Value;
			return Value;
		}
		Decimal IncomingTransaction::GetOutputValue() const
		{
			Decimal Value = 0.0;
			for (auto& Address : To)
				Value += Address.Value;
			return Value;
		}
		bool IncomingTransaction::IsLatencyApproved() const
		{
			auto* Chain = Datamaster::GetChain(Asset);
			if (!Chain)
				return false;

			return BlockId >= Chain->GetChainparams().SyncLatency;
		}
		bool IncomingTransaction::IsApproved() const
		{
			auto* Chain = Datamaster::GetChain(Asset);
			if (!Chain)
				return false;

			auto LatestBlockId = Datamaster::GetLatestKnownBlockHeight(Asset).Or(0);
			if (LatestBlockId < BlockId)
				return BlockId >= Chain->GetChainparams().SyncLatency;

			return LatestBlockId - BlockId >= Chain->GetChainparams().SyncLatency;
		}
		UPtr<Schema> IncomingTransaction::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			auto* FromData = Data->Set("from", Var::Set::Array());
			for (auto& Item : From)
			{
				auto* CoinData = FromData->Push(Var::Set::Object());
				CoinData->Set("address", Var::String(Item.Address));
				CoinData->Set("address_index", Item.AddressIndex ? Algorithm::Encoding::SerializeUint256(*Item.AddressIndex) : Var::Set::Null());
				CoinData->Set("value", Var::Decimal(Item.Value));
			}
			auto* ToData = Data->Set("to", Var::Set::Array());
			for (auto& Item : To)
			{
				auto* CoinData = ToData->Push(Var::Set::Object());
				CoinData->Set("address", Var::String(Item.Address));
				CoinData->Set("address_index", Item.AddressIndex ? Algorithm::Encoding::SerializeUint256(*Item.AddressIndex) : Var::Set::Null());
				CoinData->Set("value", Var::Decimal(Item.Value));
			}
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("transaction_id", Var::String(TransactionId));
			Data->Set("block_id", Algorithm::Encoding::SerializeUint256(BlockId));
			Data->Set("fee", Var::Decimal(Fee));
			return Data;
		}
		uint32_t IncomingTransaction::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view IncomingTransaction::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t IncomingTransaction::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IncomingTransaction::AsInstanceTypename()
		{
			return "oracle_incoming_transaction";
		}

		OutgoingTransaction::OutgoingTransaction() : Inputs(Optional::None), Outputs(Optional::None)
		{
		}
		OutgoingTransaction::OutgoingTransaction(IncomingTransaction&& NewTransaction, const std::string_view& NewData, Option<Vector<CoinUTXO>>&& NewInputs, Option<Vector<CoinUTXO>>&& NewOutputs) : Inputs(std::move(NewInputs)), Outputs(std::move(NewOutputs)), Transaction(std::move(NewTransaction)), Data(NewData)
		{
		}
		bool OutgoingTransaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (Transaction.StorePayload(Stream))
				return false;

			Stream->WriteString(Data);
			Stream->WriteInteger(Inputs ? (uint32_t)Inputs->size() : (uint32_t)0);
			if (Inputs)
			{
				for (auto& Item : *Inputs)
				{
					IndexUTXO Next;
					Next.UTXO = Item;
					if (!Next.StorePayload(Stream))
						return false;
				}
			}

			Stream->WriteInteger(Outputs ? (uint32_t)Outputs->size() : (uint32_t)0);
			if (Outputs)
			{
				for (auto& Item : *Outputs)
				{
					IndexUTXO Next;
					Next.UTXO = Item;
					if (!Next.StorePayload(Stream))
						return false;
				}
			}
			return true;
		}
		bool OutgoingTransaction::LoadPayload(Format::Stream& Stream)
		{
			if (Transaction.LoadPayload(Stream))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Data))
				return false;

			uint32_t InputsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &InputsSize))
				return false;

			if (InputsSize > 0)
			{
				Inputs = Vector<CoinUTXO>();
				Inputs->reserve(InputsSize);
				for (size_t i = 0; i < InputsSize; i++)
				{
					IndexUTXO Next;
					if (!Next.LoadPayload(Stream))
						return false;

					Inputs->emplace_back(std::move(Next.UTXO));
				}
			}

			uint32_t OutputsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &OutputsSize))
				return false;

			if (OutputsSize > 0)
			{
				Outputs = Vector<CoinUTXO>();
				Outputs->reserve(OutputsSize);
				for (size_t i = 0; i < OutputsSize; i++)
				{
					IndexUTXO Next;
					if (!Next.LoadPayload(Stream))
						return false;

					Outputs->emplace_back(std::move(Next.UTXO));
				}
			}

			return true;
		}
		bool OutgoingTransaction::IsValid() const
		{
			if (Inputs)
			{
				for (auto& Item : *Inputs)
				{
					if (!Item.IsValid())
						return false;
				}
			}

			if (Outputs)
			{
				for (auto& Item : *Outputs)
				{
					if (!Item.IsValid())
						return false;
				}
			}
			return Transaction.IsValid() && !Data.empty();
		}
		UPtr<Schema> OutgoingTransaction::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("transaction_info", Transaction.AsSchema().Reset());
			Data->Set("transaction_data", Var::String(this->Data));
			return Data;
		}
		uint32_t OutgoingTransaction::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view OutgoingTransaction::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t OutgoingTransaction::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view OutgoingTransaction::AsInstanceTypename()
		{
			return "oracle_outgoing_transaction";
		}

		bool IndexAddress::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Binding);
			Stream->WriteString(Address);
			Stream->WriteBoolean(!!AddressIndex);
			if (AddressIndex)
				Stream->WriteInteger(*AddressIndex);
			return true;
		}
		bool IndexAddress::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Binding))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Address))
				return false;

			bool HasAddressIndex;
			if (!Stream.ReadBoolean(Stream.ReadType(), &HasAddressIndex))
				return false;

			AddressIndex = HasAddressIndex ? Option<uint64_t>(0) : Option<uint64_t>(Optional::None);
			if (AddressIndex && !Stream.ReadInteger(Stream.ReadType(), AddressIndex.Address()))
				return false;

			return true;
		}
		UPtr<Schema> IndexAddress::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("address", Var::String(Address));
			Data->Set("address_index", AddressIndex ? Algorithm::Encoding::SerializeUint256(*AddressIndex) : Var::Set::Null());
			Data->Set("binding", Var::String(Binding));
			return Data;
		}
		uint32_t IndexAddress::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view IndexAddress::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t IndexAddress::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IndexAddress::AsInstanceTypename()
		{
			return "oracle_index_address";
		}

		bool IndexUTXO::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(UTXO.Address);
			Stream->WriteBoolean(!!UTXO.AddressIndex);
			if (UTXO.AddressIndex)
				Stream->WriteInteger(*UTXO.AddressIndex);
			Stream->WriteString(UTXO.TransactionId);
			Stream->WriteInteger(UTXO.Index);
			Stream->WriteDecimal(UTXO.Value);
			Stream->WriteInteger((uint32_t)UTXO.Tokens.size());
			for (auto& Item : UTXO.Tokens)
			{
				Stream->WriteString(Item.ContractAddress);
				Stream->WriteString(Item.Symbol);
				Stream->WriteDecimal(Item.Value);
				Stream->WriteInteger(Item.Decimals);
			}
			return true;
		}
		bool IndexUTXO::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &UTXO.Address))
				return false;

			bool HasAddressIndex;
			if (!Stream.ReadBoolean(Stream.ReadType(), &HasAddressIndex))
				return false;

			UTXO.AddressIndex = HasAddressIndex ? Option<uint64_t>(0) : Option<uint64_t>(Optional::None);
			if (UTXO.AddressIndex && !Stream.ReadInteger(Stream.ReadType(), UTXO.AddressIndex.Address()))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &UTXO.TransactionId))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &UTXO.Index))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &UTXO.Value))
				return false;

			uint32_t Size;
			if (!Stream.ReadInteger(Stream.ReadType(), &Size))
				return false;

			UTXO.Tokens.reserve(Size);
			for (uint32_t i = 0; i < Size; i++)
			{
				TokenUTXO Token;
				if (!Stream.ReadString(Stream.ReadType(), &Token.ContractAddress))
					return false;

				if (!Stream.ReadString(Stream.ReadType(), &Token.Symbol))
					return false;

				if (!Stream.ReadDecimal(Stream.ReadType(), &Token.Value))
					return false;

				if (!Stream.ReadInteger(Stream.ReadType(), &Token.Decimals))
					return false;

				UTXO.Tokens.emplace_back(std::move(Token));
			}

			return true;
		}
		UPtr<Schema> IndexUTXO::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			auto* UTXOData = Data->Set("utxo", Var::Set::Object());
			auto* TokensData = UTXOData->Set("tokens", Var::Set::Array());
			for (auto& Item : UTXO.Tokens)
			{
				auto* TokenData = TokensData->Push(Var::Set::Object());
				TokenData->Set("contract_address", Var::String(Item.ContractAddress));
				TokenData->Set("symbol", Var::String(Item.Symbol));
				TokenData->Set("value", Var::Decimal(Item.Value));
				TokenData->Set("Decimals", Var::Integer(Item.Decimals));
			}
			Data->Set("transaction_id", Var::String(UTXO.TransactionId));
			Data->Set("address", Var::String(UTXO.Address));
			Data->Set("address_index", UTXO.AddressIndex ? Algorithm::Encoding::SerializeUint256(*UTXO.AddressIndex) : Var::Set::Null());
			Data->Set("value", Var::Decimal(UTXO.Value));
			Data->Set("index", Var::Integer(UTXO.Index));
			Data->Set("binding", Var::String(Binding));
			return Data;
		}
		uint32_t IndexUTXO::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view IndexUTXO::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t IndexUTXO::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IndexUTXO::AsInstanceTypename()
		{
			return "oracle_index_utxo";
		}

		BaseFee::BaseFee() : Price(Decimal::NaN()), Limit(Decimal::NaN())
		{
		}
		BaseFee::BaseFee(const Decimal& NewPrice, const Decimal& NewLimit) : Price(NewPrice), Limit(NewLimit)
		{
		}
		Decimal BaseFee::GetFee() const
		{
			return Price * Limit;
		}
		bool BaseFee::IsValid() const
		{
			return Price.IsPositive() && !Limit.IsNaN() && Limit >= 0.0;
		}

		void ChainSupervisorOptions::SetCheckpointFromBlock(uint64_t BlockHeight)
		{
			if (!State.StartingBlockHeight)
				State.StartingBlockHeight = BlockHeight;
			State.LatestBlockHeight = BlockHeight;
		}
		void ChainSupervisorOptions::SetCheckpointToBlock(uint64_t BlockHeight)
		{
			if (!State.CurrentBlockHeight && !State.LatestBlockHeight && !State.StartingBlockHeight)
				SetCheckpointFromBlock(BlockHeight > 1 ? BlockHeight - 1 : BlockHeight);
			State.CurrentBlockHeight = BlockHeight;
		}
		uint64_t ChainSupervisorOptions::GetNextBlockHeight()
		{
			return ++State.LatestBlockHeight;
		}
		uint64_t ChainSupervisorOptions::GetTimeAwaited() const
		{
			return State.LatestTimeAwaited;
		}
		bool ChainSupervisorOptions::HasNextBlockHeight() const
		{
			return State.CurrentBlockHeight > State.LatestBlockHeight + MinBlockConfirmations;
		}
		bool ChainSupervisorOptions::HasCurrentBlockHeight() const
		{
			return State.CurrentBlockHeight > 0;
		}
		bool ChainSupervisorOptions::HasLatestBlockHeight() const
		{
			return State.LatestBlockHeight > 0;
		}
		bool ChainSupervisorOptions::WillWaitForTransactions() const
		{
			return HasLatestBlockHeight() && !HasNextBlockHeight();
		}
		double ChainSupervisorOptions::GetCheckpointPercentage() const
		{
			if (!HasLatestBlockHeight() || !HasCurrentBlockHeight())
				return 0.0;

			double Multiplier = 100.0;
			double CurrentValue = (double)(State.LatestBlockHeight - State.StartingBlockHeight);
			double TargetValue = (double)(State.CurrentBlockHeight - State.StartingBlockHeight);
			double Percentage = Multiplier * CurrentValue / TargetValue;
			return std::floor(Percentage * Multiplier) / Multiplier;
		}
		const UnorderedSet<Nodemaster*>& ChainSupervisorOptions::GetInteractedNodes() const
		{
			return State.Interactions;
		}
		bool ChainSupervisorOptions::IsCancelled(const Algorithm::AssetId& Asset)
		{
			auto* Nodes = Datamaster::GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				return true;

			for (auto& Node : *Nodes)
			{
				if (!Node->IsActivityAllowed())
					return true;
			}

			return false;
		}

		ChainSupervisorOptions& MultichainSupervisorOptions::AddSpecificOptions(const std::string_view& Blockchain)
		{
			auto& Options = Specifics[String(Blockchain)];
			auto* Settings = (SupervisorOptions*)&Options;
			*Settings = *(SupervisorOptions*)this;
			return Options;
		}

		Nodemaster::Nodemaster(const std::string_view& NodeURL, double NodeThrottling) noexcept : Throttling(NodeThrottling), Latest(0), Allowed(true), UserData(nullptr)
		{
			for (auto& Path : Stringify::Split(NodeURL, ';'))
			{
				if (Stringify::StartsWith(Path, "jsonrpc="))
				{
					Paths.JsonRpcPath = Path.substr(8);
					Paths.JsonRpcDistinct = true;
				}
				else if (Stringify::StartsWith(Path, "rest="))
				{
					Paths.RestPath = Path.substr(5);
					Paths.RestDistinct = true;
				}
				else if (Stringify::StartsWith(Path, "http="))
				{
					Paths.HttpPath = Path.substr(5);
					Paths.HttpDistinct = true;
				}
			}
			if (Paths.HttpPath.empty())
			{
				size_t Index = NodeURL.find('=');
				if (Index != std::string::npos)
				{
					Paths.HttpPath = NodeURL.substr(Index + 1);
					Paths.HttpDistinct = true;
				}
				else
				{
					Paths.HttpPath = NodeURL;
					Paths.HttpDistinct = false;
				}
			}
			if (Paths.JsonRpcPath.empty())
			{
				Paths.JsonRpcPath = Paths.HttpPath;
				Paths.JsonRpcDistinct = false;
			}
			if (Paths.RestPath.empty())
			{
				Paths.RestPath = Paths.HttpPath;
				Paths.RestDistinct = false;
			}
			Stringify::Trim(Paths.JsonRpcPath);
			Stringify::Trim(Paths.RestPath);
			Stringify::Trim(Paths.HttpPath);
		}
		Nodemaster::~Nodemaster() noexcept
		{
			CancelActivities();
		}
		Promise<ExpectsLR<Schema*>> Nodemaster::ExecuteRPC(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaList& Args, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::JSONRPC;
			if (Reporter.Method.empty())
				Reporter.Method = Method;

			Schema* Params = Var::Set::Array();
			Params->Reserve(Args.size());
			for (auto& Item : Args)
				Params->Push(Item->Copy());

			UPtr<Schema> Setup = Var::Set::Object();
			Setup->Set("jsonrpc", Var::String("2.0"));
			Setup->Set("id", Var::String(GetCacheType(Cache)));
			Setup->Set("method", Var::String(Method));
			Setup->Set("params", Params);

			auto ResponseStatus = Coawait(ExecuteREST(Asset, Reporter, "POST", String(), *Setup, Cache));
			if (!ResponseStatus)
				Coreturn ExpectsLR<Schema*>(std::move(ResponseStatus.Error()));

			UPtr<Schema> Response = *ResponseStatus;
			if (Response->Has("error.code"))
			{
				String Code = Response->FetchVar("error.code").GetBlob();
				String Description = Response->Has("error.message") ? Response->FetchVar("error.message").GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}
			else if (Response->Has("result.error_code"))
			{
				String Code = Response->FetchVar("result.error_code").GetBlob();
				String Description = Response->Has("result.error_message") ? Response->FetchVar("result.error_message").GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}

			Schema* Result = Response->Get("result");
			if (!Result)
			{
				String Description = Response->Value.GetType() == VarType::String ? Response->Value.GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", Description)));
			}

			Result->Unlink();
			Coreturn ExpectsLR<Schema*>(Result);
		}
		Promise<ExpectsLR<Schema*>> Nodemaster::ExecuteRPC3(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaArgs& Args, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::JSONRPC;
			if (Reporter.Method.empty())
				Reporter.Method = Method;

			Schema* Params = Var::Set::Object();
			Params->Reserve(Args.size());
			for (auto& Item : Args)
				Params->Set(Item.first, Item.second->Copy());

			UPtr<Schema> Setup = Var::Set::Object();
			Setup->Set("jsonrpc", Var::String("2.0"));
			Setup->Set("id", Var::String(GetCacheType(Cache)));
			Setup->Set("method", Var::String(Method));
			Setup->Set("params", Params);

			auto ResponseStatus = Coawait(ExecuteREST(Asset, Reporter, "POST", String(), *Setup, Cache));
			if (!ResponseStatus)
				Coreturn ExpectsLR<Schema*>(std::move(ResponseStatus.Error()));

			UPtr<Schema> Response = *ResponseStatus;
			if (Response->Has("error.code"))
			{
				String Code = Response->FetchVar("error.code").GetBlob();
				String Description = Response->Has("error.message") ? Response->FetchVar("error.message").GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}
			else if (Response->Has("result.error_code"))
			{
				String Code = Response->FetchVar("result.error_code").GetBlob();
				String Description = Response->Has("result.error_message") ? Response->FetchVar("result.error_message").GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}

			Schema* Result = Response->Get("result");
			if (!Result)
			{
				String Description = Response->Value.GetType() == VarType::String ? Response->Value.GetBlob() : "no error description";
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", Description)));
			}

			Result->Unlink();
			Coreturn ExpectsLR<Schema*>(Result);
		}
		Promise<ExpectsLR<Schema*>> Nodemaster::ExecuteREST(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::REST;
			if (Reporter.Method.empty())
				Reporter.Method = Location(GetNodeURL(Reporter.Type, Path)).Path.substr(1);

			String Body = (Args ? Schema::ToJSON(Args) : String());
			Coreturn Coawait(ExecuteHTTP(Asset, Reporter, Method, Path, "application/json", Body, Cache));
		}
		Promise<ExpectsLR<Schema*>> Nodemaster::ExecuteHTTP(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::HTTP;

			String TargetURL = GetNodeURL(Reporter.Type, Path);
			if (Reporter.Method.empty())
				Reporter.Method = Location(TargetURL).Path.substr(1);

			if (!Allowed)
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", "system shutdown (cancelled)")));

			if (Path.empty() && Body.empty())
				Cache = CachePolicy::Lazy;
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			String Message = String(Path).append(Body);
			String Hash = Codec::HexEncode(Algorithm::Hashing::Hash256((uint8_t*)Message.data(), Message.size()));
			if (Cache != CachePolicy::Lazy && Cache != CachePolicy::Greedy)
			{
				auto Data = Sidechain.GetCache(Cache, Hash);
				if (Data)
					Coreturn Data;
			}
#endif
			if (Throttling > 0.0 && Cache != CachePolicy::Greedy)
			{
				const int64_t Time = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
				const double Timeout = (double)(Time - Latest);
				const double Limit = 1000.0 / Throttling;
				const uint64_t Cooldown = (uint64_t)(Limit - Timeout);
				uint64_t RetryTimeout = Cooldown;
				if (Timeout < Limit && !Coawait(YieldForCooldown(RetryTimeout, Protocol::Now().User.Oracle.RelayingTimeout)))
					Coreturn ExpectsLR<Schema*>(LayerException("retry"));
				else if (!Allowed)
					Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", "system shutdown (timeout)")));
				Latest = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			}

			HTTP::FetchFrame Setup;
			Setup.MaxSize = 16 * 1024 * 1024;
			Setup.VerifyPeers = (uint32_t)Protocol::Now().User.TCP.TlsTrustedPeers;
			Setup.Timeout = Protocol::Now().User.Oracle.RelayingTimeout;

			uint64_t RetryResponses = 0;
			uint64_t RetryTimeout = Protocol::Now().User.Oracle.RelayingRetryTimeout;
			if (!Body.empty())
			{
				Setup.SetHeader("Content-Type", Type);
				Setup.Content.Assign(Body);
			}
		Retry:
			auto Response = Coawait(HTTP::Fetch(TargetURL, Method, Setup));
			if (!Response || Response->StatusCode == 408 || Response->StatusCode == 429 || Response->StatusCode == 502 || Response->StatusCode == 503 || Response->StatusCode == 504)
			{
				++RetryResponses;
				if (Cache == CachePolicy::Greedy)
					Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(Response, Reporter, "null", Response ? "node has rejected the request" : "node is offline")));
				else if (RetryResponses > 5)
					Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(Response, Reporter, "null", Response ? "node has rejected the request too many times" : "node is offline after several retries")));
				else if (!Coawait(YieldForCooldown(RetryTimeout, Setup.Timeout)))
					Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(Response, Reporter, "null", Response ? "node has rejected the request after cooldown" : "node is offline after timer cooldown")));
				else if (!Allowed)
					Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(Response, Reporter, "null", "system shutdown (cooldown)")));
				goto Retry;
			}

			auto Text = Response->Content.GetText();
			auto Data = Response->Content.GetJSON();
			if (!Data)
				Coreturn ExpectsLR<Schema*>(LayerException(GenerateErrorMessage(Response, Reporter, "null", "node's response is not JSON compliant")));
#ifdef TAN_VALIDATOR
			if (Cache != CachePolicy::Lazy && Cache != CachePolicy::Greedy && (Response->StatusCode < 400 || Response->StatusCode == 404))
			{
				Data->AddRef();
				Sidechain.SetCache(Cache, Hash, UPtr<Schema>(Data));
			}
#endif
			Coreturn ExpectsLR<Schema*>(*Data);
		}
		Promise<bool> Nodemaster::YieldForCooldown(uint64_t& RetryTimeout, uint64_t TotalTimeoutMs)
		{
			if (TotalTimeoutMs > 0 && RetryTimeout >= TotalTimeoutMs)
				Coreturn false;

			Promise<bool> Future;
			TaskId TimerId = EnqueueActivity(Future, Schedule::Get()->SetTimeout(RetryTimeout, [Future]() mutable
			{
				if (Future.IsPending())
					Future.Set(true);
			}));
			if (!Coawait(std::move(Future)))
				Coreturn false;

			DequeueActivity(TimerId);
			RetryTimeout *= 2;
			Coreturn true;
		}
		Promise<bool> Nodemaster::YieldForDiscovery(ChainSupervisorOptions* Options)
		{
			if (!Allowed)
				Coreturn Promise<bool>(false);

			Promise<bool> Future;
			Options->State.LatestTimeAwaited += Options->PollingFrequencyMs;
			TaskId TimerId = EnqueueActivity(Future, Schedule::Get()->SetTimeout(Options->PollingFrequencyMs, [Future]() mutable
			{
				if (Future.IsPending())
					Future.Set(true);
			}));
			if (!Coawait(std::move(Future)))
				Coreturn false;

			DequeueActivity(TimerId);
			Coreturn true;
		}
		ExpectsLR<void> Nodemaster::VerifyCompatibility(const Algorithm::AssetId& Asset)
		{
			auto* Implementation = Datamaster::GetChain(Asset);
			if (!Implementation)
				return Expectation::Met;

			return Implementation->VerifyNodeCompatibility(this);
		}
		TaskId Nodemaster::EnqueueActivity(const Promise<bool>& Future, TaskId TimerId)
		{
			if (Future.IsPending())
			{
				UMutex<std::recursive_mutex> Unique(Mutex);
				Tasks.push_back(std::make_pair(Future, TimerId));
			}
			if (!Allowed)
				CancelActivities();
			return TimerId;
		}
		void Nodemaster::DequeueActivity(TaskId TimerId)
		{
			UMutex<std::recursive_mutex> Unique(Mutex);
			for (auto It = Tasks.begin(); It != Tasks.end(); It++)
			{
				if (It->second == TimerId)
				{
					Tasks.erase(It);
					break;
				}
			}
		}
		void Nodemaster::AllowActivities()
		{
			Allowed = true;
		}
		void Nodemaster::CancelActivities()
		{
			UMutex<std::recursive_mutex> Unique(Mutex);
			Allowed = false;
			for (auto& Task : Tasks)
			{
				Schedule::Get()->ClearTimeout(Task.second);
				if (Task.first.IsPending())
					Task.first.Set(false);
			}
			Tasks.clear();
		}
		bool Nodemaster::HasDistinctURL(TransmitType Type) const
		{
			switch (Type)
			{
				case TransmitType::JSONRPC:
					return Paths.JsonRpcDistinct;
				case TransmitType::REST:
					return Paths.RestDistinct;
				case TransmitType::HTTP:
					return Paths.HttpDistinct;
				default:
					return Paths.JsonRpcDistinct || Paths.RestDistinct || Paths.HttpDistinct;
			}
		}
		bool Nodemaster::IsActivityAllowed() const
		{
			return Allowed;
		}
		const String& Nodemaster::GetNodeURL(TransmitType Type) const
		{
			switch (Type)
			{
				case Nodemaster::TransmitType::JSONRPC:
					return Paths.JsonRpcPath;
				case Nodemaster::TransmitType::REST:
					return Paths.RestPath;
				case Nodemaster::TransmitType::HTTP:
				default:
					return Paths.HttpPath;
			}
		}
		String Nodemaster::GetNodeURL(TransmitType Type, const std::string_view& Endpoint) const
		{
			if (Stringify::StartsWith(Endpoint, "http"))
				return String(Endpoint);

			String URL = GetNodeURL(Type);
			if (URL.empty() || Endpoint.empty())
				return URL;

			if (URL.back() == '/' && Endpoint.front() == '/')
				URL.erase(URL.end() - 1);
			else if (URL.back() != '/' && Endpoint.front() != '/')
				URL += '/';
			URL += Endpoint;
			return URL;
		}
		std::string_view Nodemaster::GetCacheType(CachePolicy Cache)
		{
			switch (Cache)
			{
				case CachePolicy::Greedy:
					return "greedy";
				case CachePolicy::Lazy:
					return "lazy";
				case CachePolicy::Shortened:
					return "scache";
				case CachePolicy::Extended:
					return "ecache";
				case CachePolicy::Persistent:
					return "pcache";
				default:
					return "any";
			}
		}
		String Nodemaster::GenerateErrorMessage(const ExpectsSystem<HTTP::ResponseFrame>& Response, const ErrorReporter& Reporter, const std::string_view& ErrorCode, const std::string_view& ErrorMessage)
		{
			std::string_view Domain;
			switch (Reporter.Type)
			{
				case Nodemaster::TransmitType::JSONRPC:
					Domain = "jrpc";
					break;
				case Nodemaster::TransmitType::REST:
					Domain = "rest";
					break;
				case Nodemaster::TransmitType::HTTP:
					Domain = "http";
					break;
				default:
					Domain = "call";
					break;
			}

			StringStream Message;
			String Method = Reporter.Method;
			Message << "oracle::" << Domain << "::" << Stringify::ToLower(Method) << " error: ";
			if (ErrorMessage.empty())
				Message << "no response";
			else
				Message << ErrorMessage;
			Message << " (netc: " << (Response ? Response->StatusCode : 500) << ", " << Domain << "c: " << ErrorCode << ")";
			return Message.str();
		}

		Chainmaster::Chainmaster() noexcept : Interact(nullptr)
		{
		}
		Chainmaster::~Chainmaster() noexcept
		{
		}
		Promise<ExpectsLR<Schema*>> Chainmaster::ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache)
		{
			auto* Nodes = Datamaster::GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsLR<Schema*>(LayerException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				Nodemaster::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteRPC(Asset, Reporter, Method, Args, Cache));
				if (Interact) Interact(Node);
				if (Result || Result.Error().Info != "retry")
					Coreturn Result;
			}

			Coreturn ExpectsLR<Schema*>(LayerException("node not found"));
		}
		Promise<ExpectsLR<Schema*>> Chainmaster::ExecuteRPC3(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaArgs&& Args, CachePolicy Cache)
		{
			auto* Nodes = Datamaster::GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsLR<Schema*>(LayerException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				Nodemaster::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteRPC3(Asset, Reporter, Method, Args, Cache));
				if (Interact) Interact(Node);
				if (Result || Result.Error().Info != "retry")
					Coreturn Result;
			}

			Coreturn ExpectsLR<Schema*>(LayerException("node not found"));
		}
		Promise<ExpectsLR<Schema*>> Chainmaster::ExecuteREST(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache)
		{
			UPtr<Schema> Body = Args;
			auto* Nodes = Datamaster::GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsLR<Schema*>(LayerException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				Nodemaster::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteREST(Asset, Reporter, Method, Path, *Body, Cache));
				if (Interact) Interact(Node);
				if (Result || Result.Error().Info != "retry")
					Coreturn Result;
			}

			Coreturn ExpectsLR<Schema*>(LayerException("node not found"));
		}
		Promise<ExpectsLR<Schema*>> Chainmaster::ExecuteHTTP(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache)
		{
			auto* Nodes = Datamaster::GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsLR<Schema*>(LayerException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				Nodemaster::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteHTTP(Asset, Reporter, Method, Path, Type, Body, Cache));
				if (Interact) Interact(Node);
				if (Result || Result.Error().Info != "retry")
					Coreturn Result;
			}

			Coreturn ExpectsLR<Schema*>(LayerException("node not found"));
		}
		ExpectsLR<OrderedMap<String, uint64_t>> Chainmaster::FindCheckpointAddresses(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses)
		{
			if (Addresses.empty())
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("no addresses supplied"));

			auto* Implementation = Datamaster::GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("chain not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Results = Sidechain.GetAddressIndices(Addresses);
			if (!Results || Results->empty())
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("no addresses found"));

			OrderedMap<String, uint64_t> Info;
			for (auto& Item : *Results)
				Info[Item.first] = Item.second.AddressIndex.Or(Protocol::Now().Account.RootAddressIndex);

			return ExpectsLR<OrderedMap<String, uint64_t>>(std::move(Info));
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<Vector<String>> Chainmaster::GetCheckpointAddresses(const Algorithm::AssetId& Asset)
		{
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			return Sidechain.GetAddressIndices();
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<void> Chainmaster::VerifyNodeCompatibility(Nodemaster* Node)
		{
			return Expectation::Met;
		}
		String Chainmaster::GetChecksumHash(const std::string_view& Value) const
		{
			return String(Value);
		}
		uint256_t Chainmaster::ToBaselineValue(const Decimal& Value) const
		{
			Decimal Baseline = Value * GetChainparams().Divisibility;
			return uint256_t(Baseline.Truncate(0).ToString());
		}

		ChainmasterUTXO::ChainmasterUTXO() noexcept : Chainmaster()
		{
		}
		Promise<ExpectsLR<Decimal>> ChainmasterUTXO::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
		{
			Decimal Balance = 0.0;
			auto Outputs = CalculateCoins(Asset, Wallet, Optional::None, Optional::None);
			if (!Outputs)
				return Promise<ExpectsLR<Decimal>>(std::move(Balance));

			auto ContractAddress = Datamaster::GetContractAddress(Asset);
			if (ContractAddress)
			{
				for (auto& Output : *Outputs)
				{
					auto Value = Output.GetTokenValue(*ContractAddress);
					if (Value)
						Balance += *Value;
				}
			}
			else
			{
				for (auto& Output : *Outputs)
					Balance += Output.Value;
			}

			return Promise<ExpectsLR<Decimal>>(std::move(Balance));
		}
		ExpectsLR<Vector<CoinUTXO>> ChainmasterUTXO::CalculateCoins(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<Decimal>&& MinValue, Option<TokenUTXO>&& MinTokenValue)
		{
			if (!Wallet.IsValid())
				return ExpectsLR<Vector<CoinUTXO>>(LayerException("wallet not found"));

			auto Binding = Wallet.GetBinding();
			if (!Binding)
				return ExpectsLR<Vector<CoinUTXO>>(LayerException("binding not found"));
#ifdef TAN_VALIDATOR
			Decimal CurrentValue = 0.0, CurrentTokenValue = 0.0;
			auto ContinueAccumulation = [&]() { return (!MinValue || CurrentValue < *MinValue) && (!MinTokenValue || CurrentTokenValue < MinTokenValue->Value); };

			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			Vector<CoinUTXO> Values;
			while (ContinueAccumulation())
			{
				const size_t Count = 64;
				auto Outputs = Sidechain.GetUTXOs(*Binding, Values.size(), Count);
				if (!Outputs || Outputs->empty())
					break;

				bool EofValue = false;
				bool EofUTXO = Outputs->size() < Count;
				Values.reserve(Values.size() + Outputs->size());
				for (auto& Output : *Outputs)
				{
					CurrentValue += Output.UTXO.Value;
					EofValue = !ContinueAccumulation();
					Values.emplace_back(std::move(Output.UTXO));
					if (EofValue)
						break;
				}
				if (EofUTXO || EofValue)
					break;
			}

			if (ContinueAccumulation() && (MinValue || MinTokenValue))
				return ExpectsLR<Vector<CoinUTXO>>(LayerException("insufficient funds"));

			return ExpectsLR<Vector<CoinUTXO>>(std::move(Values));
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<CoinUTXO> ChainmasterUTXO::GetCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Output = Sidechain.GetUTXO(TransactionId, Index);
			if (!Output)
				return ExpectsLR<CoinUTXO>(LayerException("transaction output was not found"));

			return ExpectsLR<CoinUTXO>(std::move(Output->UTXO));
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<void> ChainmasterUTXO::UpdateCoins(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
		{
			if (TxData.Inputs)
			{
				for (auto& Output : *TxData.Inputs)
					RemoveCoins(Asset, Output.TransactionId, Output.Index);
			}
			if (TxData.Outputs)
			{
				for (auto& Input : *TxData.Outputs)
					AddCoins(Asset, Input);
			}
			return ExpectsLR<void>(Expectation::Met);
		}
		ExpectsLR<void> ChainmasterUTXO::AddCoins(const Algorithm::AssetId& Asset, const CoinUTXO& Output)
		{
			auto* Implementation = Datamaster::GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto AddressIndex = Sidechain.GetAddressIndex(Implementation->GetChecksumHash(Output.Address));
			if (!AddressIndex)
				return ExpectsLR<void>(LayerException("transaction output is not being watched"));

			IndexUTXO NewOutput;
			NewOutput.Binding = std::move(AddressIndex->Binding);
			NewOutput.UTXO = Output;

			auto Status = Sidechain.AddUTXO(NewOutput);
			if (Status)
				return ExpectsLR<void>(Expectation::Met);

			RemoveCoins(Asset, Output.TransactionId, Output.Index);
			return ExpectsLR<void>(std::move(Status.Error()));
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<void> ChainmasterUTXO::RemoveCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			return Sidechain.RemoveUTXO(TransactionId, Index);
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		Decimal ChainmasterUTXO::GetCoinsValue(const Vector<CoinUTXO>& Values, Option<String>&& ContractAddress)
		{
			Decimal Value = 0.0;
			if (ContractAddress)
			{
				for (auto& Item : Values)
				{
					for (auto& Token : Item.Tokens)
					{
						if (Token.ContractAddress == *ContractAddress)
							Value += Token.Value;
					}
				}
			}
			else
			{
				for (auto& Item : Values)
					Value += Item.Value;
			}
			return Value;
		}

		Promise<ExpectsLR<OutgoingTransaction>> Paymaster::SubmitTransaction(const uint256_t& ExternalId, const Algorithm::AssetId& Asset, DynamicWallet&& Wallet, Vector<Transferer>&& To, Option<BaseFee>&& Fee)
		{
			if (!ControlSys.IsActive())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("%s blockchain operations are shutdown", Algorithm::Asset::HandleOf(Asset).c_str())));

			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (Connections->find(Blockchain) == Connections->end())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("%s blockchain operations are disabled", Algorithm::Asset::HandleOf(Asset).c_str())));

			TransactionParams* Params = Memory::New<TransactionParams>();
			Params->Asset = std::move(Asset);
			Params->Wallet = std::move(Wallet);
			Params->To = std::move(To);
			Params->Fee = std::move(Fee);
			Params->ExternalId = ExternalId;

			auto& State = (*States)[Blockchain];
			if (!State)
			{
				State = Memory::New<TransactionQueueState>();
				State->Blockchain = Blockchain;
			}

			auto Future = Params->Future;
			State->Queue.push(Params);
			DispatchTransactionQueue(*State, Params);
			Unique.Negate();
			Coreturn Coawait(std::move(Future));
		}
		Promise<bool> Paymaster::Startup(const MultichainSupervisorOptions& Options)
		{
			if (!Options.RetryWaitingTimeMs || !ControlSys.ActivateAndEnqueue())
				Coreturn false;

			VI_PANIC(Datamaster::IsInitialized(), "blockchain service is not initialized");
			using ConnectionsType = UnorderedSet<String>;
			using StatesType = UnorderedMap<String, UPtr<TransactionQueueState>>;
			using CallbacksType = UnorderedMap<String, TransactionCallback>;
			using ListenersType = Vector<UPtr<TransactionListener>>;
			Connections = Memory::New<ConnectionsType>();
			States = Memory::New<StatesType>();
			Listeners = Memory::New<ListenersType>();
			Callbacks = Memory::New<CallbacksType>();
			Settings = Memory::New<MultichainSupervisorOptions>();

			UnorderedSet<String> Blockchains;
			{
				UMutex<std::recursive_mutex> Unique1(Datamaster::Mutex);
				Blockchains.reserve(Datamaster::Nodes->size());
				for (auto& Implementation : *Datamaster::Nodes)
					Blockchains.insert(Implementation.first);

				UMutex<std::recursive_mutex> Unique2(ControlSys.Sync);
				Listeners->reserve(Blockchains.size());
				*Settings = Options;
			}

			for (auto& Blockchain : Blockchains)
			{
				TransactionListener* Listener = Memory::New<TransactionListener>();
				Listener->Asset = Algorithm::Asset::IdOf(Blockchain);
				Listeners->emplace_back(Listener);

				auto& Suboptions = *(SupervisorOptions*)&Listener->Options;
				Suboptions = *(SupervisorOptions*)&Options;

				auto It = Options.Specifics.find(Blockchain);
				if (It != Options.Specifics.end())
					Listener->Options = It->second;

				if (!CallTransactionListener(Listener))
				{
					ControlSys.Dequeue();
					Coawait(Shutdown());
					Coreturn false;
				}

				Connections->insert(Algorithm::Asset::BlockchainOf(Listener->Asset));
			}

			ControlSys.Dequeue();
			Coreturn true;
		}
		Promise<bool> Paymaster::Shutdown()
		{
			if (!ControlSys.Deactivate())
				Coreturn false;
			{
				UMutex<std::recursive_mutex> Unique1(Datamaster::Mutex);
				for (auto& Nodes : *Datamaster::Nodes)
				{
					for (auto& Node : Nodes.second)
						Node->CancelActivities();
				}

				UMutex<std::recursive_mutex> Unique2(ControlSys.Sync);
				for (auto& Listener : *Listeners)
				{
					if (Schedule::Get()->ClearTimeout(Listener->CooldownId))
						Listener->IsDead = true;
				}
			}

			Coawait(ControlSys.Shutdown());
			UMutex<std::recursive_mutex> Unique1(ControlSys.Sync);
			Memory::Delete(Connections);
			Memory::Delete(States);
			Memory::Delete(Listeners);
			Memory::Delete(Callbacks);
			Memory::Delete(Settings);

			UMutex<std::recursive_mutex> Unique2(Datamaster::Mutex);
			for (auto& Nodes : *Datamaster::Nodes)
			{
				for (auto& Node : Nodes.second)
					Node->AllowActivities();
			}
			Coreturn true;
		}
		void Paymaster::SubmitCallback(const std::string_view& Name, TransactionCallback&& Callback)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (!Callbacks)
				return;

			if (Callback)
				(*Callbacks)[String(Name)] = std::move(Callback);
			else
				Callbacks->erase(String(Name));
		}
		bool Paymaster::HasSupport(const Algorithm::AssetId& Asset)
		{
			if (!ControlSys.IsActive())
				return false;

			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			return Connections->find(Blockchain) != Connections->end();
		}
		bool Paymaster::CallTransactionListener(TransactionListener* Listener)
		{
			if (Listener->Options.IsCancelled(Listener->Asset) || !ControlSys.Enqueue())
			{
				Listener->IsDead = true;
				return false;
			}
			else if (Listener->CooldownId != INVALID_TASK_ID)
			{
				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s scan re-initialize: OK", Algorithm::Asset::HandleOf(Listener->Asset).c_str());
				Listener->CooldownId = INVALID_TASK_ID;
			}
			else if (Listener->IsDryRun)
			{
				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s scan initialize: OK", Algorithm::Asset::HandleOf(Listener->Asset).c_str());
				Listener->IsDryRun = false;
			}
			else if (Listener->Options.WillWaitForTransactions())
			{
				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s scan complete: awaiting new data for at least %is (waiting time = %is)",
						Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
						(int)(Listener->Options.PollingFrequencyMs / 1000),
						(int)(Listener->Options.State.LatestTimeAwaited / 1000));
				Listener->Options.State.LatestTimeAwaited = 0;
			}

			Coasync<void>([Listener]() -> Promise<void>
			{
				auto Info = Coawait(Datamaster::GetTransactionLogs(Listener->Asset, &Listener->Options));
				if (!Info)
				{
					if (Info.Error().Info == "retry")
					{
						if (Protocol::Now().User.Oracle.Logging)
							VI_INFO("[oracle] %s scan cancellation: OK", Algorithm::Asset::HandleOf(Listener->Asset).c_str());

						CallTransactionListener(Listener);
						ControlSys.Dequeue();
						CoreturnVoid;
					}

					if (Protocol::Now().User.Oracle.Logging)
						VI_ERR("[oracle] %s scan cooldown { %s }", Algorithm::Asset::HandleOf(Listener->Asset).c_str(), Info.Error().what());

					UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
					if (ControlSys.IsActive() && !Listener->Options.IsCancelled(Listener->Asset))
						Listener->CooldownId = Schedule::Get()->SetTimeout(Settings->RetryWaitingTimeMs, [Listener]() { CallTransactionListener(Listener); });
					else
						Listener->IsDead = true;
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Info->Transactions.empty())
				{
					if (!Info->BlockHash.empty())
					{
						if (Protocol::Now().User.Oracle.Logging)
							VI_INFO("[oracle] %s scan block: %s (height = %i, percentage = %.2f%%)",
								Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
								Info->BlockHash.c_str(),
								(int)Info->BlockHeight,
								Listener->Options.GetCheckpointPercentage());
					}

					for (auto& Item : *Callbacks)
						Coawait(Item.second(Listener->Options, std::move(*Info)));

					CallTransactionListener(Listener);
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s in %s: %s (height = %i, percentage = %.2f%%, transactions = %i)",
						Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
						"block",
						Info->BlockHash.c_str(),
						(int)Info->BlockHeight,
						Listener->Options.GetCheckpointPercentage(),
						(int)Info->Transactions.size());

				if (Protocol::Now().User.Oracle.Logging)
				{
					for (auto& Tx : Info->Transactions)
					{
						auto Chain = Oracle::Datamaster::GetChain(Tx.Asset);
						String TransferLogs = Stringify::Text(
							"%s in transaction: %s (status: %s, costs: %s %s)\n",
							Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
							Tx.TransactionId.c_str(), Tx.IsApproved() ? "confirmation" : "pending",
							Tx.Fee.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str());

						if (!Tx.IsApproved() || (Chain && !Chain->GetChainparams().SyncLatency))
						{
							for (auto& Item : Tx.From)
							{
								TransferLogs += Stringify::Text("  <-- %s spends %s %s%s%s%s\n",
									Item.Address.empty() ? "coinbase" : Item.Address.c_str(), Item.Value.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str(),
									Item.AddressIndex ? " (index: " : "", Item.AddressIndex ? ToString(*Item.AddressIndex).c_str() : "", Item.AddressIndex ? ", status: spent)" : "");
							}
							for (auto& Item : Tx.To)
							{
								TransferLogs += Stringify::Text("  --> %s receives %s %s%s%s%s\n",
									Item.Address.empty() ? "reward" : Item.Address.c_str(), Item.Value.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str(),
									Item.AddressIndex ? " (index: " : "", Item.AddressIndex ? ToString(*Item.AddressIndex).c_str() : "", Item.AddressIndex ? ", status: unspent)" : "");
							}
						}

						if (TransferLogs.back() == '\n')
							TransferLogs.erase(TransferLogs.end() - 1);

						VI_INFO("[oracle] %s", TransferLogs.c_str());
					}
				}

				for (auto& Item : *Callbacks)
					Coawait(Item.second(Listener->Options, std::move(*Info)));

				CallTransactionListener(Listener);
				ControlSys.Dequeue();
				CoreturnVoid;
			}, true);
			return true;
		}
		void Paymaster::DispatchTransactionQueue(TransactionQueueState* State, TransactionParams* FromParams)
		{
			if (!ControlSys.Enqueue())
				return;

			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (State->IsBusy && FromParams != nullptr)
			{
				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s tx queue: push 0x%p (position = %i)", State->Blockchain.c_str(), FromParams, (int)State->Transactions);

				++State->Transactions;
				ControlSys.Dequeue();
				return;
			}
			else if (State->Queue.empty())
			{
				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s tx queue: finish (dispatches = %i)", State->Blockchain.c_str(), (int)State->Transactions);

				State->Transactions = 0;
				State->IsBusy = false;
				ControlSys.Dequeue();
				return;
			}
			else if (FromParams != nullptr)
				++State->Transactions;

			auto* Params = State->Queue.front();
			State->IsBusy = true;
			State->Queue.pop();

			if (Protocol::Now().User.Oracle.Logging)
				VI_INFO("[oracle] %s tx queue: dispatch 0x%p (position = %i)", State->Blockchain.c_str(), Params, (int)(State->Transactions - State->Queue.size() - 1));

			Coasync<void>([State, Params]() -> Promise<void>
			{
				auto SignedTransaction = Coawait(Datamaster::NewTransaction(Params->Asset, Params->Wallet, Params->To, std::move(Params->Fee)));
				if (!SignedTransaction)
				{
					if (Protocol::Now().User.Oracle.Logging)
						VI_ERR("[oracle] %s tx queue: sign error { %s }", State->Blockchain.c_str(), SignedTransaction.Error().what());

					FinalizeTransaction(State, Params, std::move(SignedTransaction));
					ControlSys.Dequeue();
					CoreturnVoid;
				}

				if (Protocol::Now().User.Oracle.Logging)
					VI_INFO(
						"[oracle] %s tx queue: sign %s OK\n"
						"  data: %s",
						State->Blockchain.c_str(),
						SignedTransaction->Transaction.TransactionId.c_str(),
						SignedTransaction->Data.c_str());

				auto Status = Coawait(Datamaster::BroadcastTransaction(Params->Asset, Params->ExternalId, *SignedTransaction));
				if (!Status)
				{
					if (Protocol::Now().User.Oracle.Logging)
						VI_ERR("[oracle] %s tx queue: submit error { %s }", State->Blockchain.c_str(), Status.Error().what());

					FinalizeTransaction(State, Params, Status.Error());
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Protocol::Now().User.Oracle.Logging)
					VI_INFO("[oracle] %s tx queue: submit %s OK", State->Blockchain.c_str(), SignedTransaction->Transaction.TransactionId.c_str());

				FinalizeTransaction(State, Params, std::move(SignedTransaction));
				ControlSys.Dequeue();
				CoreturnVoid;
			}, true);
		}
		void Paymaster::FinalizeTransaction(TransactionQueueState* State, UPtr<TransactionParams>&& Params, ExpectsLR<OutgoingTransaction>&& Transaction)
		{
			if (Protocol::Now().User.Oracle.Logging)
				VI_INFO("[oracle] %s tx queue: finalize 0x%p (position = %i)", State->Blockchain.c_str(), *Params, (int)(State->Transactions - State->Queue.size() - 1));

			Params->Future.Set(std::move(Transaction));
			DispatchTransactionQueue(State, nullptr);
		}
		MultichainSupervisorOptions& Paymaster::GetOptions()
		{
			VI_PANIC(Settings != nullptr, "blockchain service in not active");
			return *Settings;
		}
		SystemControl& Paymaster::GetControl()
		{
			return ControlSys;
		}
		UnorderedSet<String>* Paymaster::Connections = nullptr;
		UnorderedMap<String, UPtr<Paymaster::TransactionQueueState>>* Paymaster::States = nullptr;
		Vector<UPtr<Paymaster::TransactionListener>>* Paymaster::Listeners = nullptr;
		UnorderedMap<String, Paymaster::TransactionCallback>* Paymaster::Callbacks = nullptr;
		MultichainSupervisorOptions* Paymaster::Settings = nullptr;
		SystemControl Paymaster::ControlSys = SystemControl("scanner");

		Promise<ExpectsLR<void>> Datamaster::BroadcastTransaction(const Algorithm::AssetId& Asset, const uint256_t& ExternalId, const OutgoingTransaction& TxData)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<void>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset) || TxData.Transaction.Asset != Asset)
				Coreturn ExpectsLR<void>(LayerException("asset not found"));

			if (!TxData.IsValid())
				Coreturn ExpectsLR<void>(LayerException("transaction not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<void>(LayerException("chain not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto DuplicateTransaction = Sidechain.GetTransaction(TxData.Transaction.TransactionId, ExternalId);
			if (DuplicateTransaction)
				Coreturn ExpectsLR<void>(Expectation::Met);
#endif
			auto NewTransaction = TxData.Transaction;
			NewTransaction.TransactionId = Implementation->GetChecksumHash(NewTransaction.TransactionId);
			NewTransaction.BlockId = 0;
#ifdef TAN_VALIDATOR
			Sidechain.AddOutgoingTransaction(NewTransaction, ExternalId);
#endif
			Coreturn Coawait(Implementation->BroadcastTransaction(Asset, TxData));
		}
		Promise<ExpectsLR<void>> Datamaster::ValidateTransaction(const IncomingTransaction& Value)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<void>(LayerException("oracle not found"));

			if (!Value.IsValid())
				Coreturn ExpectsLR<void>(LayerException("transaction not valid"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Value.Asset);
			if (Sidechain.GetTransaction(Value.TransactionId, 0))
				Coreturn ExpectsLR<void>(Expectation::Met);
#endif
			auto TransactionData = Coawait(GetBlockTransaction(Value.Asset, Value.BlockId, std::string_view(), Value.TransactionId));
			if (!TransactionData)
				Coreturn ExpectsLR<void>(std::move(TransactionData.Error()));

			auto Transactions = Coawait(GetAuthenticTransactions(Value.Asset, Value.BlockId, std::string_view(), *TransactionData));
			Memory::Release(*TransactionData);
			if (!Transactions)
				Coreturn ExpectsLR<void>(std::move(Transactions.Error()));

			auto Left = Value;
			for (auto& Item : Left.To)
				Item.AddressIndex = 0;
			for (auto& Item : Left.From)
				Item.AddressIndex = 0;

			uint256_t Hash = Left.AsHash();
			for (auto& Right : *Transactions)
			{
				for (auto& Item : Right.To)
					Item.AddressIndex = 0;
				for (auto& Item : Right.From)
					Item.AddressIndex = 0;
				if (Right.AsHash() == Hash)
					Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Coreturn ExpectsLR<void>(LayerException("transaction not valid"));
		}
		Promise<ExpectsLR<uint64_t>> Datamaster::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<uint64_t>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<uint64_t>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<uint64_t>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->GetLatestBlockHeight(Asset));
		}
		Promise<ExpectsLR<Schema*>> Datamaster::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<Schema*>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<Schema*>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<Schema*>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->GetBlockTransactions(Asset, BlockHeight, BlockHash));
		}
		Promise<ExpectsLR<Schema*>> Datamaster::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<Schema*>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<Schema*>(LayerException("asset not found"));

			if (!BlockHeight || Stringify::IsEmptyOrWhitespace(TransactionId))
				Coreturn ExpectsLR<Schema*>(LayerException("tx not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<Schema*>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->GetBlockTransaction(Asset, BlockHeight, BlockHash, TransactionId));
		}
		Promise<ExpectsLR<Vector<IncomingTransaction>>> Datamaster::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("asset not found"));

			if (!BlockHeight)
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("txs not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->GetAuthenticTransactions(Asset, BlockHeight, BlockHash, TransactionData));
		}
		Promise<ExpectsLR<Schema*>> Datamaster::ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<Schema*>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<Schema*>(LayerException("asset not found"));

			if (Method.empty())
				Coreturn ExpectsLR<Schema*>(LayerException("method not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<Schema*>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->ExecuteRPC(Asset, Method, std::move(Args), Cache));
		}
		Promise<ExpectsLR<OutgoingTransaction>> Datamaster::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, Option<BaseFee>&& Fee)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("asset not found"));

			if (!Wallet.IsValid())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("wallet not found"));

			if (To.empty())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("to address not found"));

			for (auto& Address : To)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.Address))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("receiver address not valid"));

				if (!Address.Value.IsPositive())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("receiver quantity not valid"));
			}

			if (Fee && !Fee->IsValid())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("fee not valid"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("chain not found"));

			if (!Implementation->GetChainparams().SupportsBulkTransfer && To.size() > 1)
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException("only one receiver allowed"));

			BaseFee ActualFee = BaseFee(Decimal::NaN(), Decimal::NaN());
			if (!Fee)
			{
				auto EstimatedFee = Coawait(EstimateFee(Asset, Wallet, To));
				if (!EstimatedFee)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(EstimatedFee.Error()));
				ActualFee = *EstimatedFee;
			}
			else
				ActualFee = *Fee;

			Decimal FeeValue = ActualFee.GetFee();
			if (!FeeValue.IsPositive())
				Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("fee not valid: %s", FeeValue.ToString().c_str())));

			Coreturn Coawait(Implementation->NewTransaction(Asset, Wallet, To, ActualFee));
		}
		Promise<ExpectsLR<TransactionLogs>> Datamaster::GetTransactionLogs(const Algorithm::AssetId& Asset, ChainSupervisorOptions* Options)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<TransactionLogs>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<TransactionLogs>(LayerException("asset not found"));

			if (!Options)
				Coreturn ExpectsLR<TransactionLogs>(LayerException("options not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<TransactionLogs>(LayerException("chain not found"));

			auto* Provider = GetNode(Asset);
			if (!Provider)
				Coreturn ExpectsLR<TransactionLogs>(LayerException("node not found"));

			bool IsDryRun = !Options->HasLatestBlockHeight();
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			Implementation->Interact = [Options](Nodemaster* Service) { Options->State.Interactions.insert(Service); };
			Options->State.Interactions.clear();

			auto TipCheckpoint = UPtr<Schema>(Sidechain.GetProperty("tip_checkpoint"));
			if (TipCheckpoint)
				Options->SetCheckpointFromBlock((uint64_t)std::max<int64_t>(1, TipCheckpoint->Value.GetInteger()) - 1);

			auto TipLatest = UPtr<Schema>(Sidechain.GetProperty("tip_latest"));
			if (TipLatest && (uint64_t)TipLatest->Value.GetInteger() > Options->State.LatestBlockHeight)
				Options->SetCheckpointFromBlock((uint64_t)TipLatest->Value.GetInteger());

			auto TipOverride = UPtr<Schema>(Sidechain.GetProperty("tip_override"));
			if (TipOverride)
			{
				uint64_t Tip = (uint64_t)TipOverride->Value.GetInteger();
				Options->State.StartingBlockHeight = Tip;
				Options->SetCheckpointFromBlock(Tip);
			}
#endif
			if (!Options->HasCurrentBlockHeight())
			{
			Retry:
				auto LatestBlockHeight = Coawait(Implementation->GetLatestBlockHeight(Asset));
				if (!LatestBlockHeight)
					Coreturn ExpectsLR<TransactionLogs>(std::move(LatestBlockHeight.Error()));
				Options->SetCheckpointToBlock(*LatestBlockHeight);
			}

			if (!Options->HasNextBlockHeight())
			{
				if (IsDryRun)
					Coreturn ExpectsLR<TransactionLogs>(TransactionLogs());
				else if (!Coawait(Provider->YieldForDiscovery(Options)))
					Coreturn ExpectsLR<TransactionLogs>(LayerException("retry"));
				goto Retry;
			}

			TransactionLogs Logs;
#ifdef TAN_VALIDATOR
			Logs.BlockHeight = TipOverride ? (uint64_t)TipOverride->Value.GetInteger() : Options->GetNextBlockHeight();
#else
			Logs.BlockHeight = Options->GetNextBlockHeight();
#endif
			Logs.BlockHash = ToString(Logs.BlockHeight);

			auto Transactions = UPtr<Schema>(Coawait(Implementation->GetBlockTransactions(Asset, Logs.BlockHeight, &Logs.BlockHash)));
			if (Transactions)
			{
				for (auto& Item : Transactions->GetChilds())
				{
					if (!Item->Value.IsObject())
					{
						auto Details = UPtr<Schema>(Coawait(Implementation->GetBlockTransaction(Asset, Logs.BlockHeight, Logs.BlockHash, Item->Value.GetBlob())));
						if (!Details)
							continue;

						Memory::Release(Item);
						Item = *Details;
					}

					auto Authentics = Coawait(Implementation->GetAuthenticTransactions(Asset, Logs.BlockHeight, Logs.BlockHash, Item));
					if (Authentics)
					{
						for (auto& Next : *Authentics)
							Logs.Transactions.push_back(std::move(Next));
					}
				}
			}
#ifdef TAN_VALIDATOR
			if (!TipCheckpoint || (uint64_t)TipCheckpoint->Value.GetInteger() != Logs.BlockHeight)
				Sidechain.SetProperty("tip_checkpoint", Var::Set::Integer(Logs.BlockHeight));
			if (!TipLatest || (uint64_t)TipLatest->Value.GetInteger() != Options->State.LatestBlockHeight)
				Sidechain.SetProperty("tip_latest", Var::Set::Integer(Options->State.LatestBlockHeight));
			if (TipOverride)
				Sidechain.SetProperty("tip_override", nullptr);
#endif
			UnorderedSet<String> TransactionIds;
			for (auto& NewTransaction : Logs.Transactions)
			{
				NewTransaction.BlockId = Logs.BlockHeight;
				NewTransaction.TransactionId = Implementation->GetChecksumHash(NewTransaction.TransactionId);
#ifdef TAN_VALIDATOR
				Sidechain.AddIncomingTransaction(NewTransaction, Logs.BlockHeight);
#endif
				TransactionIds.insert(Algorithm::Asset::HandleOf(NewTransaction.Asset) + ":" + NewTransaction.TransactionId);
			}
#ifdef TAN_VALIDATOR
			auto Approvals = Sidechain.ApproveTransactions(Logs.BlockHeight, Implementation->GetChainparams().SyncLatency);
			if (Approvals && !Approvals->empty())
			{
				Logs.Transactions.reserve(Logs.Transactions.size() + Approvals->size());
				for (auto& NewTransaction : *Approvals)
				{
					if (TransactionIds.find(Algorithm::Asset::HandleOf(NewTransaction.Asset) + ":" + NewTransaction.TransactionId) == TransactionIds.end())
						Logs.Transactions.push_back(std::move(NewTransaction));
				}
			}
#endif
			Coreturn ExpectsLR<TransactionLogs>(std::move(Logs));
		}
		Promise<ExpectsLR<BaseFee>> Datamaster::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<BaseFee>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset) || !Options.MaxBlocks || !Options.MaxTransactions)
				Coreturn ExpectsLR<BaseFee>(LayerException("asset not found"));

			if (!Wallet.IsValid())
				Coreturn ExpectsLR<BaseFee>(LayerException("wallet not found"));

			if (To.empty())
				Coreturn ExpectsLR<BaseFee>(LayerException("to address not found"));

			for (auto& Address : To)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.Address))
					Coreturn ExpectsLR<BaseFee>(LayerException("receiver address not valid"));

				if (!Address.Value.IsPositive())
					Coreturn ExpectsLR<BaseFee>(LayerException("receiver quantity not valid"));
			}

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<BaseFee>(LayerException("chain not found"));

			if (!Implementation->GetChainparams().SupportsBulkTransfer && To.size() > 1)
				Coreturn ExpectsLR<BaseFee>(LayerException("only one receiver allowed"));

			int64_t Time = time(nullptr);
			String FeeKey = Stringify::Text("%s:%i", Algorithm::Asset::BlockchainOf(Asset).c_str(), To.size());
			{
				UMutex<std::recursive_mutex> Unique(Mutex);
				auto It = Fees->find(FeeKey);
				if (It != Fees->end() && It->second.second >= Time)
					Coreturn ExpectsLR<BaseFee>(It->second.first);
			}

			auto Estimate = Coawait(Implementation->EstimateFee(Asset, Wallet, To, Options));
			if (!Estimate)
				Coreturn ExpectsLR<BaseFee>(std::move(Estimate.Error()));

			UMutex<std::recursive_mutex> Unique(Mutex);
			(*Fees)[FeeKey] = std::make_pair(*Estimate, Time + (int64_t)Protocol::Now().User.Oracle.FeeEstimationSeconds);
			Coreturn Estimate;
		}
		Promise<ExpectsLR<Decimal>> Datamaster::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
		{
			if (!IsInitialized())
				Coreturn ExpectsLR<Decimal>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsLR<Decimal>(LayerException("asset not found"));

			auto Binding = Wallet.GetBinding();
			if (!Binding || Binding->empty())
				Coreturn ExpectsLR<Decimal>(LayerException("binding not found"));

			if (Address && Stringify::IsEmptyOrWhitespace(*Address))
				Coreturn ExpectsLR<Decimal>(LayerException("address not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsLR<Decimal>(LayerException("chain not found"));

			Coreturn Coawait(Implementation->CalculateBalance(Asset, Wallet, std::move(Address)));
		}
		ExpectsLR<MasterWallet> Datamaster::NewMasterWallet(const Algorithm::AssetId& Asset, const std::string_view& SeedingKey)
		{
			if (!IsInitialized())
				return ExpectsLR<MasterWallet>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<MasterWallet>(LayerException("asset not found"));

			String Seed = Format::Util::IsHexEncoding(SeedingKey) ? Codec::HexDecode(SeedingKey) : String(SeedingKey);
			if (Seed.empty())
				return ExpectsLR<MasterWallet>(LayerException("seed not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<MasterWallet>(LayerException("chain not found"));

			auto Result = Implementation->NewMasterWallet(Seed);
#ifdef TAN_VALIDATOR
			if (!Result)
				return Result;

			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Status = Sidechain.AddMasterWallet(*Result);
			if (!Status)
				return Status.Error();
#endif
			return Result;
		}
		ExpectsLR<MasterWallet> Datamaster::NewMasterWallet(const Algorithm::AssetId& Asset, const Algorithm::Seckey PrivateKey)
		{
			Format::Stream Message;
			Message.WriteInteger(Asset);
			Message.WriteString(*Crypto::HashRaw(Digests::SHA512(), std::string_view((char*)PrivateKey, sizeof(Algorithm::Seckey))));
			return NewMasterWallet(Asset, *Crypto::HashRaw(Digests::SHA512(), Message.Data));
		}
		ExpectsLR<DerivedSigningWallet> Datamaster::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, Option<uint64_t>&& AddressIndex)
		{
			if (!IsInitialized())
				return ExpectsLR<DerivedSigningWallet>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<DerivedSigningWallet>(LayerException("asset not found"));

			if (!Wallet.IsValid())
				return ExpectsLR<DerivedSigningWallet>(LayerException("wallet not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<DerivedSigningWallet>(LayerException("chain not found"));

			if (AddressIndex)
			{
#ifdef TAN_VALIDATOR
				Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
				auto Result = Sidechain.GetDerivedWallet(Wallet.AsHash(), *AddressIndex);
				if (Result)
					return Result;
#endif
			}
			else
				AddressIndex = Wallet.MaxAddressIndex + 1;

			auto Result = Implementation->NewSigningWallet(Asset, Wallet, *AddressIndex);
			if (!Result || *AddressIndex <= Wallet.MaxAddressIndex)
				return Result;

			auto WalletCopy = Wallet;
			WalletCopy.MaxAddressIndex = *AddressIndex;
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Status = Sidechain.AddDerivedWallet(WalletCopy, *Result);
			if (!Status)
				return Status.Error();
#endif
			return Result;
		}
		ExpectsLR<DerivedSigningWallet> Datamaster::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKeyKey)
		{
			if (!IsInitialized())
				return ExpectsLR<DerivedSigningWallet>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<DerivedSigningWallet>(LayerException("asset not found"));

			if (SigningKeyKey.empty())
				return ExpectsLR<DerivedSigningWallet>(LayerException("key not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<DerivedSigningWallet>(LayerException("chain not found"));

			return Implementation->NewSigningWallet(Asset, SigningKeyKey);
		}
		ExpectsLR<DerivedVerifyingWallet> Datamaster::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
		{
			if (!IsInitialized())
				return ExpectsLR<DerivedVerifyingWallet>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<DerivedVerifyingWallet>(LayerException("asset not found"));

			if (VerifyingKey.empty())
				return ExpectsLR<DerivedVerifyingWallet>(LayerException("key not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<DerivedVerifyingWallet>(LayerException("chain not found"));

			return Implementation->NewVerifyingWallet(Asset, VerifyingKey);
		}
		ExpectsLR<String> Datamaster::NewPublicKeyHash(const Algorithm::AssetId& Asset, const std::string_view& Address)
		{
			if (!IsInitialized())
				return ExpectsLR<String>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<String>(LayerException("asset not found"));

			if (Address.empty())
				return ExpectsLR<String>(LayerException("address not found"));

			if (Format::Util::IsHexEncoding(Address))
				return ExpectsLR<String>(Codec::HexDecode(Address));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<String>(LayerException("chain not found"));

			return Implementation->NewPublicKeyHash(Address);
		}
		ExpectsLR<String> Datamaster::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
		{
			if (!IsInitialized())
				return ExpectsLR<String>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<String>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<String>(LayerException("chain not found"));

			return Implementation->SignMessage(Asset, Message, SigningKey);
		}
		ExpectsLR<void> Datamaster::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
		{
			if (!IsInitialized())
				return ExpectsLR<void>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			bool IsMessageHex = Format::Util::IsHexEncoding(Message);
			String MessageData1 = IsMessageHex ? Format::Util::Decode0xHex(Message) : String(Message);
			String MessageData2 = IsMessageHex ? String(Message) : Format::Util::Encode0xHex(Message);

			if (Format::Util::IsHexEncoding(Signature))
			{
				String SignatureData = Format::Util::Decode0xHex(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}
			
			if (Format::Util::IsBase64Encoding(Signature))
			{
				String SignatureData = Codec::Base64Decode(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}
			
			if (Format::Util::IsBase64URLEncoding(Signature))
			{
				String SignatureData = Codec::Base64URLDecode(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}

			auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, Signature);
			if (Status)
				return Status;

			return Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, Signature);
		}
		ExpectsLR<void> Datamaster::EnableCheckpointHeight(const Algorithm::AssetId& Asset, uint64_t BlockHeight)
		{
			if (!IsInitialized())
				return ExpectsLR<void>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			return Sidechain.SetProperty("tip_override", Var::Set::Integer(BlockHeight));
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<void> Datamaster::EnableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Binding, const std::string_view& Address, uint64_t AddressIndex)
		{
			if (!IsInitialized())
				return ExpectsLR<void>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			if (Stringify::IsEmptyOrWhitespace(Address))
				return ExpectsLR<void>(LayerException("address not found"));

			if (Binding.empty())
				return ExpectsLR<void>(LayerException("binding not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			String CanonicalAddress = Implementation->GetChecksumHash(Address);
			auto CandidateAddressIndex = Sidechain.GetAddressIndex(CanonicalAddress);
			if (!CandidateAddressIndex)
			{
				IndexAddress NewAddressIndex;
				NewAddressIndex.Binding = Binding;
				NewAddressIndex.Address = Address;
				NewAddressIndex.AddressIndex = AddressIndex;

				auto Status = Sidechain.SetAddressIndex(CanonicalAddress, NewAddressIndex);
				if (!Status)
					return Status;
				goto Degrade;
			}
			else if (!CandidateAddressIndex->AddressIndex || AddressIndex != *CandidateAddressIndex->AddressIndex)
			{
				CandidateAddressIndex->AddressIndex = AddressIndex;
				auto Status = Sidechain.SetAddressIndex(CanonicalAddress, *CandidateAddressIndex);
				if (!Status)
					return Status;
				goto Degrade;
			}
			
			return Expectation::Met;
		Degrade:
			auto BlockHeight = Oracle::Datamaster::GetLatestKnownBlockHeight(Asset);
			if (!BlockHeight || !*BlockHeight)
				return Expectation::Met;

			uint64_t Latency = Implementation->GetChainparams().SyncLatency * Protocol::Now().User.Oracle.BlockReplayMultiplier;
			if (Latency > 0)
				Oracle::Datamaster::EnableCheckpointHeight(Asset, Latency >= *BlockHeight ? 1 : *BlockHeight - Latency);

			return Expectation::Met;
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<void> Datamaster::EnableContractAddress(const Algorithm::AssetId& Asset, const std::string_view& ContractAddress)
		{
			if (!IsInitialized())
				return ExpectsLR<void>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			if (ContractAddress.empty())
				return ExpectsLR<void>(LayerException("contract address not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));
#ifdef TAN_VALIDATOR
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Key = "contract_address:" + Algorithm::Asset::TokenOf(Asset);
			auto Value = Sidechain.GetProperty(Key);
			if (!Value)
				Value = Var::Set::Array();

			UnorderedSet<String> Addresses;
			for (auto& Item : Value->GetChilds())
				Addresses.insert(Item->Value.GetBlob());

			auto Address = Implementation->GetChecksumHash(ContractAddress);
			if (Addresses.find(Address) != Addresses.end())
				return Expectation::Met;
			
			Value->Push(Var::Set::String(Address));
			return Sidechain.SetProperty(Key, *Value);
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		ExpectsLR<uint64_t> Datamaster::GetLatestKnownBlockHeight(const Algorithm::AssetId& Asset)
		{
			if (!IsInitialized())
				return ExpectsLR<uint64_t>(LayerException("oracle not found"));

			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<uint64_t>(LayerException("asset not found"));
#ifdef TAN_VALIDATOR
			uint64_t BlockHeight = 0;
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto LatestBlockHeight = UPtr<Schema>(Sidechain.GetProperty("tip_latest"));
			if (LatestBlockHeight)
			{
				uint64_t PossibleBlockHeight = (uint64_t)LatestBlockHeight->Value.GetInteger();
				if (PossibleBlockHeight > BlockHeight)
					BlockHeight = PossibleBlockHeight;
			}

			auto CheckpointBlockHeight = UPtr<Schema>(Sidechain.GetProperty("tip_checkpoint"));
			if (CheckpointBlockHeight)
			{
				uint64_t PossibleBlockHeight = (uint64_t)CheckpointBlockHeight->Value.GetInteger();
				if (PossibleBlockHeight > BlockHeight)
					BlockHeight = PossibleBlockHeight;
			}

			if (!BlockHeight)
				return ExpectsLR<uint64_t>(LayerException("block not found"));
			
			return ExpectsLR<uint64_t>(BlockHeight);
#else
			return LayerException("sidechainstate data not available");
#endif
		}
		Option<String> Datamaster::GetContractAddress(const Algorithm::AssetId& Asset)
		{
			if (!IsInitialized())
				return Optional::None;

			if (!Algorithm::Asset::IsValid(Asset))
				return Optional::None;
#ifdef TAN_VALIDATOR
			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			auto Token = Algorithm::Asset::TokenOf(Asset);
			Storages::Sidechainstate Sidechain = Storages::Sidechainstate(__func__, Asset);
			auto Value = UPtr<Schema>(Sidechain.GetProperty("contract_address:" + Token));
			if (!Value || Value->Empty())
				return Optional::None;

			auto TargetChecksum = Algorithm::Asset::ChecksumOf(Asset);
			for (auto& Item : Value->GetChilds())
			{
				auto CandidateAddress = Item->Value.GetBlob();
				auto CandidateChecksum = Algorithm::Asset::ChecksumOf(Algorithm::Asset::IdOf(Blockchain, Token, CandidateAddress));
				if (CandidateChecksum == TargetChecksum)
					return CandidateAddress;
			}

			return Value->Get(0)->Value.GetBlob();
#else
			return Optional::None;
#endif
		}
		void Datamaster::AddNodeInstance(const Algorithm::AssetId& Asset, Nodemaster* Instance)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			(*Nodes)[Algorithm::Asset::BlockchainOf(Asset)].push_back(Instance);
		}
		void Datamaster::AddChainInstance(const Algorithm::AssetId& Asset, Chainmaster* Instance)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			(*Chains)[Algorithm::Asset::BlockchainOf(Asset)] = Instance;
		}
		void Datamaster::Initialize()
		{
			using FeesType = UnorderedMap<String, std::pair<BaseFee, int64_t>>;
			using NodesType = UnorderedMap<String, Vector<UPtr<Nodemaster>>>;
			using OptionsType = UnorderedMap<String, UPtr<Schema>>;
			using ImplementationsType = UnorderedMap<String, UPtr<Chainmaster>>;
			UMutex<std::recursive_mutex> Unique(Mutex);
			Fees = Memory::New<FeesType>();
			Nodes = Memory::New<NodesType>();
			Chains = Memory::New<ImplementationsType>();
			Options = Memory::New<OptionsType>();
		}
		void Datamaster::Cleanup()
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			Memory::Delete(Fees);
			Memory::Delete(Nodes);
			Memory::Delete(Chains);
			Memory::Delete(Options);
		}
		bool Datamaster::HasNode(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto Target = Nodes->find(Algorithm::Asset::BlockchainOf(Asset));
			return Target != Nodes->end();
		}
		bool Datamaster::HasChain(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto Target = Chains->find(Algorithm::Asset::BlockchainOf(Asset));
			return Target != Chains->end();
		}
		bool Datamaster::HasOracle(const Algorithm::AssetId& Asset)
		{
			return IsInitialized() && GetChain(Asset) != nullptr && GetNode(Asset) != nullptr;
		}
		bool Datamaster::IsInitialized()
		{
			return Fees && Nodes && Nodes && Chains;
		}
		Nodemaster* Datamaster::AddNode(const Algorithm::AssetId& Asset, const std::string_view& URL, double Throttling)
		{
			Nodemaster* Instance = new Nodemaster(URL, Throttling);
			AddNodeInstance(Asset, Instance);
			return Instance;
		}
		Schema* Datamaster::AddOptions(const Algorithm::AssetId& Asset, UPtr<Schema>&& Value)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto& Instance = (*Options)[Algorithm::Asset::BlockchainOf(Asset)];
			Instance = std::move(Value);
			return *Instance;
		}
		UnorderedMap<Algorithm::AssetId, Chainmaster::Chainparams> Datamaster::GetChains()
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			UnorderedMap<Algorithm::AssetId, Chainmaster::Chainparams> Result;
			Result.reserve(Chains->size());
			for (auto& Next : *Chains)
				Result[Algorithm::Asset::IdOf(Next.first)] = Next.second->GetChainparams();
			return Result;
		}
		Vector<Algorithm::AssetId> Datamaster::GetAssets(bool ObservingOnly)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			Vector<Algorithm::AssetId> Currencies;
			if (ObservingOnly)
			{
				Currencies.reserve(Nodes->size());
				for (auto& Node : *Nodes)
					Currencies.push_back(Algorithm::Asset::IdOf(Node.first));
			}
			else
			{
				Currencies.reserve(Chains->size());
				for (auto& Next : *Chains)
					Currencies.push_back(Algorithm::Asset::IdOf(Next.first));
			}
			return Currencies;
		}
		Vector<UPtr<Nodemaster>>* Datamaster::GetNodes(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto It = Nodes->find(Algorithm::Asset::BlockchainOf(Asset));
			if (It == Nodes->end() || It->second.empty())
				return nullptr;

			return &It->second;
		}
		Nodemaster* Datamaster::GetNode(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto It = Nodes->find(Algorithm::Asset::BlockchainOf(Asset));
			if (It == Nodes->end() || It->second.empty())
				return nullptr;

			if (It->second.size() == 1)
				return *It->second.front();

			size_t Index = ((size_t)Math<size_t>::Random()) % It->second.size();
			return *It->second[Index];
		}
		Chainmaster* Datamaster::GetChain(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto It = Chains->find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Chains->end())
				return *It->second;

			return nullptr;
		}
		const Chainmaster::Chainparams* Datamaster::GetChainparams(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto It = Chains->find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Chains->end())
			{
				auto& Params = It->second->GetChainparams();
				return &Params;
			}

			return nullptr;
		}
		Schema* Datamaster::GetOptions(const Algorithm::AssetId& Asset)
		{
			VI_PANIC(IsInitialized(), "blockchain service is not initialized");
			UMutex<std::recursive_mutex> Unique(Mutex);
			auto It = Options->find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Options->end())
				return *It->second;

			return nullptr;
		}
		UnorderedMap<String, std::pair<BaseFee, int64_t>>* Datamaster::Fees = nullptr;
		UnorderedMap<String, Vector<UPtr<Nodemaster>>>* Datamaster::Nodes = nullptr;
		UnorderedMap<String, UPtr<Chainmaster>>* Datamaster::Chains = nullptr;
		UnorderedMap<String, UPtr<Schema>>* Datamaster::Options = nullptr;
		std::recursive_mutex Datamaster::Mutex;

		template <typename T>
		static Bridge::InvocationCallback Chain()
		{
			return [](const std::string_view& Blockchain) -> bool
			{
				Algorithm::AssetId Asset = Algorithm::Asset::IdOf(Blockchain);
				if (Datamaster::HasChain(Asset))
					return false;

				Datamaster::AddChain<T>(Asset);
				return true;
			};
		}

		static uint64_t Activations = 0;
		void Bridge::Open(Schema* Config, bool Observe)
		{
			if (Activations++)
				return;

			if (!Datamaster::IsInitialized())
				Datamaster::Initialize();

			auto Chains = GetRegistrations();
			for (auto& Chain : Chains)
				Chain.second(Chain.first);

			Oracle::MultichainSupervisorOptions Options;
			if (Config != nullptr)
			{
				auto* RetryTimeout = Config->Fetch("oracle.supervisor.retry_timeout");
				if (RetryTimeout != nullptr && RetryTimeout->Value.Is(VarType::Integer))
					Options.RetryWaitingTimeMs = RetryTimeout->Value.GetInteger();

				auto* PollingFrequency = Config->Fetch("oracle.supervisor.polling_frequency");
				if (PollingFrequency != nullptr && PollingFrequency->Value.Is(VarType::Integer))
					Options.PollingFrequencyMs = PollingFrequency->Value.GetInteger();

				auto* BlockConfirmations = Config->Fetch("oracle.supervisor.block_confirmations");
				if (BlockConfirmations != nullptr && BlockConfirmations->Value.Is(VarType::Integer))
					Options.MinBlockConfirmations = BlockConfirmations->Value.GetInteger();

				auto* Oracles = Config->Fetch("oracle.observers");
				if (Oracles != nullptr)
				{
					for (auto& Root : Oracles->GetChilds())
					{
						Algorithm::AssetId Asset = Algorithm::Asset::IdOf(Root->Key);
						auto* Peers = Root->Get("peers");
						if (Peers && !Peers->Empty())
						{
							UnorderedMap<std::string_view, double> Sources;
							for (auto& Child : Peers->GetChilds())
							{
								auto Source = Child->Size() > 0 ? Child->Get(0)->Value.GetString() : Child->Value.GetString();
								auto Throttling = Child->Size() > 1 ? Child->Get(1)->Value.GetNumber() : 0.0;
								if (!Stringify::IsEmptyOrWhitespace(Source) && Throttling >= 0.0)
									Sources[Source] = 1000.0 / Throttling;
							}

							for (auto& Source : Sources)
							{
								if (Oracle::Datamaster::AddNode(Asset, Source.first, Source.second))
								{
									if (Observe && Protocol::Now().User.Oracle.Logging)
										VI_INFO("[oracle] OK add %s node on %.*s (%.2f rps limit)", Algorithm::Asset::HandleOf(Asset).c_str(), (int)Source.first.size(), Source.first.data(), Source.second);
								}
								else if (Protocol::Now().User.Oracle.Logging)
									VI_ERR("[oracle] failed to add %s node on %.*s (%.2f rps limit)", Algorithm::Asset::HandleOf(Asset).c_str(), (int)Source.first.size(), Source.first.data(), Source.second);
							}
						}

						auto* Props = Root->Get("props");
						if (Props != nullptr)
						{
							Datamaster::AddOptions(Asset, Props);
							Props->Unlink();
						}

						auto* Tip = Root->Fetch("observer.tip");
						if (Tip != nullptr && Tip->Value.Is(VarType::Integer))
							Datamaster::EnableCheckpointHeight(Asset, Tip->Value.GetInteger());

						BlockConfirmations = Root->Fetch("observer.delay");
						if (BlockConfirmations != nullptr && BlockConfirmations->Value.Is(VarType::Integer))
							Options.AddSpecificOptions(Root->Key).MinBlockConfirmations = BlockConfirmations->Value.GetInteger();
					}
				}
			}
			if (Observe)
				Oracle::Paymaster::Startup(Options);
		}
		void Bridge::Close()
		{
			if (!Activations)
				return;
			else if (--Activations > 0)
				return;

			Paymaster::Shutdown().Wait();
			Datamaster::Cleanup();
		}
		UnorderedMap<String, MasterWallet> Bridge::GetWallets(const Algorithm::Seckey PrivateKey)
		{
			if (!Datamaster::IsInitialized())
				Datamaster::Initialize();

			UnorderedMap<String, MasterWallet> Wallets;
			for (auto& Chain : Datamaster::GetAssets())
			{
				auto Wallet = Datamaster::NewMasterWallet(Chain, PrivateKey);
				if (Wallet)
					Wallets[Algorithm::Asset::HandleOf(Chain)] = std::move(*Wallet);
			}
			return Wallets;
		}
		UnorderedMap<String, Bridge::InvocationCallback> Bridge::GetRegistrations()
		{
#ifdef TAN_VALIDATOR
#define CHAIN(X) Chain<Chains::X>()
#else
#define CHAIN(X) nullptr
#endif
			UnorderedMap<String, InvocationCallback> Entries =
			{
				{ "ARB", CHAIN(Arbitrum) },
				{ "AVAX", CHAIN(Avalanche) },
				{ "BTC", CHAIN(Bitcoin) },
				{ "BCH", CHAIN(BitcoinCash) },
				{ "BTG", CHAIN(BitcoinGold) },
				{ "BSC", CHAIN(BinanceSmartChain) },
				{ "BSV", CHAIN(BitcoinSV) },
				{ "ADA", CHAIN(Cardano) },
				{ "CELO", CHAIN(Celo) },
				{ "DASH", CHAIN(Dash) },
				{ "DGB", CHAIN(Digibyte) },
				{ "DOGE", CHAIN(Dogecoin) },
				{ "ETH", CHAIN(Ethereum) },
				{ "ETC", CHAIN(EthereumClassic) },
				{ "FTM", CHAIN(Fantom) },
				{ "FUSE", CHAIN(Fuse) },
				{ "ONE", CHAIN(Harmony) },
				{ "LTC", CHAIN(Litecoin) },
				{ "GLMR", CHAIN(Moonbeam) },
				{ "OP", CHAIN(Optimism) },
				{ "MATIC", CHAIN(Polygon) },
				{ "XRP", CHAIN(Ripple) },
				{ "XEC", CHAIN(ECash) },
				{ "RIF", CHAIN(Rootstock) },
				{ "SOL", CHAIN(Solana) },
				{ "XLM", CHAIN(Stellar) },
				{ "TRX", CHAIN(Tron) },
				{ "ZEC", CHAIN(ZCash) },
			};
#undef CHAIN
			return Entries;
		}
	}
}
