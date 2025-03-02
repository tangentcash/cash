#include "mediator.h"
#include "../validator/service/nss.h"
#include <sstream>

namespace Tangent
{
	namespace Mediator
	{
		static bool IsPrivateKeyEmptyOrWhitespace(const PrivateKey& Value)
		{
			if (!Value.Size())
				return true;

			auto Data = Value.Expose<KEY_LIMIT>();
			for (char V : Data.View)
			{
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

		MasterWallet::MasterWallet(PrivateKey&& NewSeedingKey, PrivateKey&& NewSigningKey, String&& NewVerifyingKey) : SeedingKey(std::move(NewSeedingKey)), SigningKey(std::move(NewSigningKey)), VerifyingKey(std::move(NewVerifyingKey))
		{
		}
		bool MasterWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(MaxAddressIndex);
			Stream->WriteString(SeedingKey.Expose<KEY_LIMIT>().View);
			Stream->WriteString(SigningKey.Expose<KEY_LIMIT>().View);
			Stream->WriteString(VerifyingKey);
			return true;
		}
		bool MasterWallet::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &MaxAddressIndex))
				return false;

			String SeedingKeyData;
			if (!Stream.ReadString(Stream.ReadType(), &SeedingKeyData))
				return false;

			String SigningKeyData;
			if (!Stream.ReadString(Stream.ReadType(), &SigningKeyData))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &VerifyingKey))
				return false;

			SeedingKey = PrivateKey(SeedingKeyData);
			SigningKey = PrivateKey(SigningKeyData);
			return true;
		}
		bool MasterWallet::IsValid() const
		{
			return !IsPrivateKeyEmptyOrWhitespace(SeedingKey) && !IsPrivateKeyEmptyOrWhitespace(SigningKey) && !Stringify::IsEmptyOrWhitespace(VerifyingKey);
		}
		UPtr<Schema> MasterWallet::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("seeding_key", Var::String(SeedingKey.ExposeToHeap()));
			Data->Set("signing_key", Var::String(SigningKey.ExposeToHeap()));
			Data->Set("verifying_key", Var::String(VerifyingKey));
			Data->Set("max_address_index", Algorithm::Encoding::SerializeUint256(MaxAddressIndex));
			return Data;
		}
		uint256_t MasterWallet::AsHash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			Format::Stream Message;
			Message.WriteString(*Crypto::HashHex(Digests::SHA512(), SigningKey.Expose<KEY_LIMIT>().View));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view MasterWallet::AsInstanceTypename()
		{
			return "observer_master_wallet";
		}

		DerivedVerifyingWallet::DerivedVerifyingWallet(AddressMap&& NewAddresses, Option<uint64_t>&& NewAddressIndex, String&& NewVerifyingKey) : Addresses(std::move(NewAddresses)), AddressIndex(std::move(NewAddressIndex)), VerifyingKey(std::move(NewVerifyingKey))
		{
		}
		bool DerivedVerifyingWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteBoolean(!!AddressIndex);
			if (AddressIndex)
				Stream->WriteInteger(*AddressIndex);
			Stream->WriteInteger((uint8_t)Addresses.size());
			for (auto& Address : Addresses)
			{
				Stream->WriteInteger(Address.first);
				Stream->WriteString(Address.second);
			}
			Stream->WriteString(VerifyingKey);
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

			if (!Stream.ReadString(Stream.ReadType(), &VerifyingKey))
				return false;

			return true;
		}
		bool DerivedVerifyingWallet::IsValid() const
		{
			if (Addresses.empty())
				return false;

			if (Stringify::IsEmptyOrWhitespace(VerifyingKey))
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
			Data->Set("verifying_key", Var::String(VerifyingKey));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DerivedVerifyingWallet::AsInstanceTypename()
		{
			return "observer_derived_verifying_wallet";
		}

		DerivedSigningWallet::DerivedSigningWallet(DerivedVerifyingWallet&& NewWallet, PrivateKey&& NewSigningKey) : DerivedVerifyingWallet(std::move(NewWallet)), SigningKey(std::move(NewSigningKey))
		{
		}
		bool DerivedSigningWallet::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!DerivedVerifyingWallet::StorePayload(Stream))
				return false;

			Stream->WriteString(SigningKey.Expose<KEY_LIMIT>().View);
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DerivedSigningWallet::AsInstanceTypename()
		{
			return "observer_derived_signing_wallet";
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
			const String* VerifyingKey = nullptr;
			if (Parent)
				VerifyingKey = &Parent->VerifyingKey;
			else if (VerifyingChild)
				VerifyingKey = &VerifyingChild->VerifyingKey;
			else if (SigningChild)
				VerifyingKey = &SigningChild->VerifyingKey;
			if (!VerifyingKey)
				return Optional::None;

			return Algorithm::Hashing::Hash256((uint8_t*)VerifyingKey->data(), VerifyingKey->size());
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
			auto* Chain = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Chain)
				return false;

			return BlockId >= Chain->GetChainparams().SyncLatency;
		}
		bool IncomingTransaction::IsApproved() const
		{
			auto* Server = NSS::ServerNode::Get();
			auto* Chain = Server->GetChain(Asset);
			if (!Chain)
				return false;

			auto LatestBlockId = Server->GetLatestKnownBlockHeight(Asset).Or(0);
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IncomingTransaction::AsInstanceTypename()
		{
			return "observer_incoming_transaction";
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
			if (!Transaction.StorePayload(Stream))
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
			if (!Transaction.LoadPayload(Stream))
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view OutgoingTransaction::AsInstanceTypename()
		{
			return "observer_outgoing_transaction";
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IndexAddress::AsInstanceTypename()
		{
			return "observer_index_address";
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IndexUTXO::AsInstanceTypename()
		{
			return "observer_index_utxo";
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
		const UnorderedSet<ServerRelay*>& ChainSupervisorOptions::GetInteractedNodes() const
		{
			return State.Interactions;
		}
		bool ChainSupervisorOptions::IsCancelled(const Algorithm::AssetId& Asset)
		{
			auto* Nodes = NSS::ServerNode::Get()->GetNodes(Asset);
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

		ServerRelay::ServerRelay(const std::string_view& NodeURL, double NodeThrottling) noexcept : Throttling(NodeThrottling), Latest(0), Allowed(true), UserData(nullptr)
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
		ServerRelay::~ServerRelay() noexcept
		{
			CancelActivities();
		}
		ExpectsPromiseRT<Schema*> ServerRelay::ExecuteRPC(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaList& Args, CachePolicy Cache, const std::string_view& Path)
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

			auto ResponseStatus = Coawait(ExecuteREST(Asset, Reporter, "POST", Path, *Setup, Cache));
			if (!ResponseStatus)
				Coreturn ExpectsRT<Schema*>(std::move(ResponseStatus.Error()));

			UPtr<Schema> Response = *ResponseStatus;
			if (Response->Has("error.code"))
			{
				String Code = Response->FetchVar("error.code").GetBlob();
				String Description = Response->Has("error.message") ? Response->FetchVar("error.message").GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}
			else if (Response->Has("result.error_code"))
			{
				String Code = Response->FetchVar("result.error_code").GetBlob();
				String Description = Response->Has("result.error_message") ? Response->FetchVar("result.error_message").GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}

			Schema* Result = Response->Get("result");
			if (!Result)
			{
				String Description = Response->Value.GetType() == VarType::String ? Response->Value.GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", Description)));
			}

			Result->Unlink();
			Coreturn ExpectsRT<Schema*>(Result);
		}
		ExpectsPromiseRT<Schema*> ServerRelay::ExecuteRPC3(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const SchemaArgs& Args, CachePolicy Cache, const std::string_view& Path)
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

			auto ResponseStatus = Coawait(ExecuteREST(Asset, Reporter, "POST", Path, *Setup, Cache));
			if (!ResponseStatus)
				Coreturn ExpectsRT<Schema*>(std::move(ResponseStatus.Error()));

			UPtr<Schema> Response = *ResponseStatus;
			if (Response->Has("error.code"))
			{
				String Code = Response->FetchVar("error.code").GetBlob();
				String Description = Response->Has("error.message") ? Response->FetchVar("error.message").GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}
			else if (Response->Has("result.error_code"))
			{
				String Code = Response->FetchVar("result.error_code").GetBlob();
				String Description = Response->Has("result.error_message") ? Response->FetchVar("result.error_message").GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, Code, Description)));
			}

			Schema* Result = Response->Get("result");
			if (!Result)
			{
				String Description = Response->Value.GetType() == VarType::String ? Response->Value.GetBlob() : "no error description";
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", Description)));
			}

			Result->Unlink();
			Coreturn ExpectsRT<Schema*>(Result);
		}
		ExpectsPromiseRT<Schema*> ServerRelay::ExecuteREST(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::REST;
			if (Reporter.Method.empty())
				Reporter.Method = Location(GetNodeURL(Reporter.Type, Path)).Path.substr(1);

			String Body = (Args ? Schema::ToJSON(Args) : String());
			Coreturn Coawait(ExecuteHTTP(Asset, Reporter, Method, Path, "application/json", Body, Cache));
		}
		ExpectsPromiseRT<Schema*> ServerRelay::ExecuteHTTP(const Algorithm::AssetId& Asset, ErrorReporter& Reporter, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache)
		{
			if (Reporter.Type == TransmitType::Any)
				Reporter.Type = TransmitType::HTTP;

			String TargetURL = GetNodeURL(Reporter.Type, Path);
			if (Reporter.Method.empty())
				Reporter.Method = Location(TargetURL).Path.substr(1);

			if (!Allowed)
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(ExpectsSystem<HTTP::ResponseFrame>(SystemException()), Reporter, "null", "system shutdown (cancelled)")));

			if (Path.empty() && Body.empty())
				Cache = CachePolicy::Lazy;

			auto* Server = NSS::ServerNode::Get();
			String Message = String(Path).append(Body);
			String Hash = Codec::HexEncode(Algorithm::Hashing::Hash256((uint8_t*)Message.data(), Message.size()));
			if (Cache != CachePolicy::Lazy && Cache != CachePolicy::Greedy)
			{
				auto Data = Server->LoadCache(Asset, Cache, Hash);
				if (Data)
					Coreturn ExpectsRT<Schema*>(*Data);
			}

			if (Throttling > 0.0 && Cache != CachePolicy::Greedy)
			{
				const int64_t Time = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
				const double Timeout = (double)(Time - Latest);
				const double Limit = 1000.0 / Throttling;
				const uint64_t Cooldown = (uint64_t)(Limit - Timeout);
				uint64_t RetryTimeout = Cooldown;
				if (Timeout < Limit && !Coawait(YieldForCooldown(RetryTimeout, Protocol::Now().User.NSS.RelayingTimeout)))
					Coreturn ExpectsRT<Schema*>(RemoteException::Retry());
				else if (!Allowed)
					Coreturn ExpectsRT<Schema*>(RemoteException::Shutdown());
				Latest = (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			}

			HTTP::FetchFrame Setup;
			Setup.MaxSize = 16 * 1024 * 1024;
			Setup.VerifyPeers = (uint32_t)Protocol::Now().User.TCP.TlsTrustedPeers;
			Setup.Timeout = Protocol::Now().User.NSS.RelayingTimeout;

			uint64_t RetryResponses = 0;
			uint64_t RetryTimeout = Protocol::Now().User.NSS.RelayingRetryTimeout;
			if (!Body.empty())
			{
				Setup.SetHeader("Content-Type", Type);
				Setup.Content.Assign(Body);
			}
		Retry:
			auto Response = Coawait(Server->InternalCall(TargetURL, Method, Setup));
			if (!Response || Response->StatusCode == 408 || Response->StatusCode == 429 || Response->StatusCode == 502 || Response->StatusCode == 503 || Response->StatusCode == 504)
			{
				++RetryResponses;
				if (Cache == CachePolicy::Greedy)
					Coreturn  Response ? ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(Response, Reporter, "null", "node has rejected the request"))) : ExpectsRT<Schema*>(RemoteException::Shutdown());
				else if (RetryResponses > 5)
					Coreturn Response ? ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(Response, Reporter, "null", "node has rejected the request too many times"))) : ExpectsRT<Schema*>(RemoteException::Shutdown());
				else if (!Coawait(YieldForCooldown(RetryTimeout, Setup.Timeout)))
					Coreturn Response ? ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(Response, Reporter, "null", "node has rejected the request after cooldown"))) : ExpectsRT<Schema*>(RemoteException::Shutdown());
				else if (!Allowed)
					Coreturn ExpectsRT<Schema*>(RemoteException::Shutdown());
				goto Retry;
			}

			auto Text = Response->Content.GetText();
			auto Data = Response->Content.GetJSON();
			if (!Data)
				Coreturn ExpectsRT<Schema*>(RemoteException(GenerateErrorMessage(Response, Reporter, "null", "node's response is not JSON compliant")));

			if (Cache != CachePolicy::Lazy && Cache != CachePolicy::Greedy && (Response->StatusCode < 400 || Response->StatusCode == 404))
			{
				Data->AddRef();
				Server->StoreCache(Asset, Cache, Hash, UPtr<Schema>(Data));
			}

			Coreturn ExpectsRT<Schema*>(*Data);
		}
		Promise<bool> ServerRelay::YieldForCooldown(uint64_t& RetryTimeout, uint64_t TotalTimeoutMs)
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
		Promise<bool> ServerRelay::YieldForDiscovery(ChainSupervisorOptions* Options)
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
		ExpectsLR<void> ServerRelay::VerifyCompatibility(const Algorithm::AssetId& Asset)
		{
			auto* Implementation = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Implementation)
				return Expectation::Met;

			return Implementation->VerifyNodeCompatibility(this);
		}
		TaskId ServerRelay::EnqueueActivity(const Promise<bool>& Future, TaskId TimerId)
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
		void ServerRelay::DequeueActivity(TaskId TimerId)
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
		void ServerRelay::AllowActivities()
		{
			Allowed = true;
		}
		void ServerRelay::CancelActivities()
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
		bool ServerRelay::HasDistinctURL(TransmitType Type) const
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
		bool ServerRelay::IsActivityAllowed() const
		{
			return Allowed;
		}
		const String& ServerRelay::GetNodeURL(TransmitType Type) const
		{
			switch (Type)
			{
				case ServerRelay::TransmitType::JSONRPC:
					return Paths.JsonRpcPath;
				case ServerRelay::TransmitType::REST:
					return Paths.RestPath;
				case ServerRelay::TransmitType::HTTP:
				default:
					return Paths.HttpPath;
			}
		}
		String ServerRelay::GetNodeURL(TransmitType Type, const std::string_view& Endpoint) const
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
		std::string_view ServerRelay::GetCacheType(CachePolicy Cache)
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
		String ServerRelay::GenerateErrorMessage(const ExpectsSystem<HTTP::ResponseFrame>& Response, const ErrorReporter& Reporter, const std::string_view& ErrorCode, const std::string_view& ErrorMessage)
		{
			std::string_view Domain;
			switch (Reporter.Type)
			{
				case ServerRelay::TransmitType::JSONRPC:
					Domain = "jrpc";
					break;
				case ServerRelay::TransmitType::REST:
					Domain = "rest";
					break;
				case ServerRelay::TransmitType::HTTP:
					Domain = "http";
					break;
				default:
					Domain = "call";
					break;
			}

			StringStream Message;
			String Method = Reporter.Method;
			Message << "observer::" << Domain << "::" << Stringify::ToLower(Method) << " error: ";
			if (ErrorMessage.empty())
				Message << "no response";
			else
				Message << ErrorMessage;
			Message << " (netc: " << (Response ? Response->StatusCode : 500) << ", " << Domain << "c: " << ErrorCode << ")";
			return Message.str();
		}

		RelayBackend::RelayBackend() noexcept : Interact(nullptr)
		{
		}
		RelayBackend::~RelayBackend() noexcept
		{
		}
		ExpectsPromiseRT<Schema*> RelayBackend::ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, CachePolicy Cache, const std::string_view& Path)
		{
			auto* Nodes = NSS::ServerNode::Get()->GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				ServerRelay::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteRPC(Asset, Reporter, Method, Args, Cache, Path));
				if (Interact) Interact(Node);
				if (Result || !Result.Error().retry())
					Coreturn Result;
			}

			Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));
		}
		ExpectsPromiseRT<Schema*> RelayBackend::ExecuteRPC3(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaArgs&& Args, CachePolicy Cache, const std::string_view& Path)
		{
			auto* Nodes = NSS::ServerNode::Get()->GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				ServerRelay::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteRPC3(Asset, Reporter, Method, Args, Cache, Path));
				if (Interact) Interact(Node);
				if (Result || !Result.Error().retry())
					Coreturn Result;
			}

			Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));
		}
		ExpectsPromiseRT<Schema*> RelayBackend::ExecuteREST(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, Schema* Args, CachePolicy Cache)
		{
			UPtr<Schema> Body = Args;
			auto* Nodes = NSS::ServerNode::Get()->GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				ServerRelay::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteREST(Asset, Reporter, Method, Path, *Body, Cache));
				if (Interact) Interact(Node);
				if (Result || !Result.Error().retry())
					Coreturn Result;
			}

			Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));
		}
		ExpectsPromiseRT<Schema*> RelayBackend::ExecuteHTTP(const Algorithm::AssetId& Asset, const std::string_view& Method, const std::string_view& Path, const std::string_view& Type, const std::string_view& Body, CachePolicy Cache)
		{
			auto* Nodes = NSS::ServerNode::Get()->GetNodes(Asset);
			if (!Nodes || Nodes->empty())
				Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));

			size_t Index = Crypto::Random();
			while (true)
			{
				ServerRelay::ErrorReporter Reporter;
				Index = (Index + 1) % Nodes->size();
				auto* Node = *Nodes->at(Index);
				auto Result = Coawait(Node->ExecuteHTTP(Asset, Reporter, Method, Path, Type, Body, Cache));
				if (Interact) Interact(Node);
				if (Result || !Result.Error().retry())
					Coreturn Result;
			}

			Coreturn ExpectsRT<Schema*>(RemoteException("node not found"));
		}
		ExpectsLR<OrderedMap<String, uint64_t>> RelayBackend::FindCheckpointAddresses(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses)
		{
			if (Addresses.empty())
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("no addresses supplied"));

			auto* Server = NSS::ServerNode::Get();
			auto* Implementation = Server->GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("chain not found"));

			auto Results = Server->GetAddressIndices(Asset, Addresses);
			if (!Results || Results->empty())
				return ExpectsLR<OrderedMap<String, uint64_t>>(LayerException("no addresses found"));

			OrderedMap<String, uint64_t> Info;
			for (auto& Item : *Results)
				Info[Item.first] = Item.second.AddressIndex.Or(Protocol::Now().Account.RootAddressIndex);

			return ExpectsLR<OrderedMap<String, uint64_t>>(std::move(Info));
		}
		ExpectsLR<Vector<String>> RelayBackend::GetCheckpointAddresses(const Algorithm::AssetId& Asset)
		{
			return NSS::ServerNode::Get()->GetAddressIndices(Asset);
		}
		ExpectsLR<void> RelayBackend::VerifyNodeCompatibility(ServerRelay* Node)
		{
			return Expectation::Met;
		}
		String RelayBackend::GetChecksumHash(const std::string_view& Value) const
		{
			return String(Value);
		}
		uint256_t RelayBackend::ToBaselineValue(const Decimal& Value) const
		{
			Decimal Baseline = Value * GetChainparams().Divisibility;
			return uint256_t(Baseline.Truncate(0).ToString());
		}
		uint64_t RelayBackend::GetRetirementBlockNumber() const
		{
			return std::numeric_limits<uint64_t>::max();
		}

		RelayBackendUTXO::RelayBackendUTXO() noexcept : RelayBackend()
		{
		}
		ExpectsPromiseRT<Decimal> RelayBackendUTXO::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
		{
			Decimal Balance = 0.0;
			auto Outputs = CalculateCoins(Asset, Wallet, Optional::None, Optional::None);
			if (!Outputs)
				return ExpectsPromiseRT<Decimal>(std::move(Balance));

			auto ContractAddress = NSS::ServerNode::Get()->GetContractAddress(Asset);
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

			return ExpectsPromiseRT<Decimal>(std::move(Balance));
		}
		ExpectsLR<Vector<CoinUTXO>> RelayBackendUTXO::CalculateCoins(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<Decimal>&& MinValue, Option<TokenUTXO>&& MinTokenValue)
		{
			if (!Wallet.IsValid())
				return ExpectsLR<Vector<CoinUTXO>>(LayerException("wallet not found"));

			auto Binding = Wallet.GetBinding();
			if (!Binding)
				return ExpectsLR<Vector<CoinUTXO>>(LayerException("binding not found"));

			Vector<CoinUTXO> Values;
			Decimal CurrentValue = 0.0, CurrentTokenValue = 0.0;
			auto* Server = NSS::ServerNode::Get();
			auto ContinueAccumulation = [&]() { return (!MinValue || CurrentValue < *MinValue) && (!MinTokenValue || CurrentTokenValue < MinTokenValue->Value); };
			while (ContinueAccumulation())
			{
				const size_t Count = 64;
				auto Outputs = Server->GetUTXOs(Asset, *Binding, Values.size(), Count);
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
		}
		ExpectsLR<CoinUTXO> RelayBackendUTXO::GetCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
			auto Output = NSS::ServerNode::Get()->GetUTXO(Asset, TransactionId, Index);
			if (!Output)
				return ExpectsLR<CoinUTXO>(LayerException("transaction output was not found"));

			return ExpectsLR<CoinUTXO>(std::move(Output->UTXO));
		}
		ExpectsLR<void> RelayBackendUTXO::UpdateCoins(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
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
		ExpectsLR<void> RelayBackendUTXO::AddCoins(const Algorithm::AssetId& Asset, const CoinUTXO& Output)
		{
			auto* Server = NSS::ServerNode::Get();
			auto* Implementation = Server->GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			auto AddressIndex = Server->GetAddressIndex(Asset, Implementation->GetChecksumHash(Output.Address));
			if (!AddressIndex)
				return ExpectsLR<void>(LayerException("transaction output is not being watched"));

			IndexUTXO NewOutput;
			NewOutput.Binding = std::move(AddressIndex->Binding);
			NewOutput.UTXO = Output;

			auto Status = Server->AddUTXO(Asset, NewOutput);
			if (Status)
				return ExpectsLR<void>(Expectation::Met);

			RemoveCoins(Asset, Output.TransactionId, Output.Index);
			return ExpectsLR<void>(std::move(Status.Error()));
		}
		ExpectsLR<void> RelayBackendUTXO::RemoveCoins(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
			return NSS::ServerNode::Get()->RemoveUTXO(Asset, TransactionId, Index);
		}
		Decimal RelayBackendUTXO::GetCoinsValue(const Vector<CoinUTXO>& Values, Option<String>&& ContractAddress)
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
	}
}
