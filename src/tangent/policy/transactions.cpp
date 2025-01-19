#include "transactions.h"
#include "typenames.h"
#include "../kernel/block.h"
#include "../kernel/script.h"

namespace Tangent
{
	namespace Transactions
	{
		static ExpectsPromiseLR<Observer::OutgoingTransaction> EmitTransaction(const Ledger::Wallet& Proposer, const Algorithm::AssetId& Asset, const uint256_t& TransactionHash, Vector<UPtr<Ledger::Transaction>>* Pipeline, Vector<Observer::Transferer>&& To)
		{
			auto Wallet = Observer::Datamaster::NewMasterWallet(Asset, Proposer.SecretKey);
			if (!Wallet)
				return ExpectsPromiseLR<Observer::OutgoingTransaction>(LayerException("wallet not found"));

			if (!Protocol::Now().Is(NetworkType::Regtest) || Observer::Paymaster::HasSupport(Asset))
				return Observer::Paymaster::SubmitTransaction(TransactionHash, Asset, *Wallet, std::move(To));

			auto SigningWallet = Observer::Datamaster::NewSigningWallet(Asset, *Wallet, Protocol::Now().Account.RootAddressIndex);
			if (!SigningWallet)
				return ExpectsPromiseLR<Observer::OutgoingTransaction>(LayerException("wallet not found"));

			Observer::OutgoingTransaction Ephimeric;
			Ephimeric.Transaction.To = To;
			Ephimeric.Transaction.From.push_back(Observer::Transferer(SigningWallet->Addresses.begin()->second, Option<uint64_t>(SigningWallet->AddressIndex), Ephimeric.Transaction.GetOutputValue()));
			Ephimeric.Transaction.Asset = Asset;
			Ephimeric.Transaction.TransactionId = Algorithm::Encoding::Encode0xHex256(Algorithm::Hashing::Hash256i(TransactionHash.ToString()));
			Ephimeric.Transaction.BlockId = Algorithm::Hashing::Hash256i(Ephimeric.Transaction.TransactionId) % std::numeric_limits<uint64_t>::max();
			Ephimeric.Transaction.Fee = Decimal::Zero();
			Ephimeric.Data = Ephimeric.AsMessage().Encode();

			auto* Transaction = Memory::New<Transactions::Claim>();
			Transaction->Asset = Asset;
			Transaction->SetEstimateGas(Decimal::Zero());
			Transaction->SetWitness(Ephimeric.Transaction);
			Pipeline->push_back(Transaction);
			return ExpectsPromiseLR<Observer::OutgoingTransaction>(std::move(Ephimeric));
		}

		ExpectsLR<void> Transfer::Prevalidate() const
		{
			if (!Value.IsPositive())
				return LayerException("invalid value");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Transfer::Validate(const Ledger::TransactionContext* Context) const
		{
			if (memcmp(Context->Receipt.From, To, sizeof(Algorithm::Pubkeyhash)) == 0)
				return LayerException("invalid receiver");

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Transfer::Execute(Ledger::TransactionContext* Context) const
		{
			auto Payment = Context->ApplyPayment(To, Value);
			if (!Payment)
				return Payment.Error();

			return Expectation::Met;
		}
		bool Transfer::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(Memo);
			Stream->WriteDecimal(Value);
			Stream->WriteString(std::string_view((char*)To, memcmp(To, Null, sizeof(Null)) == 0 ? 0 : sizeof(To)));
			return true;
		}
		bool Transfer::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Memo))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Value))
				return false;

			String ToAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ToAssembly) || !Algorithm::Encoding::DecodeUintBlob(ToAssembly, To, sizeof(To)))
				return false;

			return true;
		}
		bool Transfer::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)To, sizeof(To)));
			return true;
		}
		void Transfer::SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, const std::string_view& NewMemo)
		{
			Value = NewValue;
			Memo = NewMemo;
			if (!NewTo)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(To, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(To, NewTo, sizeof(Algorithm::Pubkeyhash));
		}
		bool Transfer::IsToNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(To, Null, sizeof(Null)) == 0;
		}
		UPtr<Schema> Transfer::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("to", Algorithm::Signing::SerializeAddress(To));
			Data->Set("value", Var::Decimal(Value));
			Data->Set("memo", Memo.empty() ? Var::Null() : Var::String(Memo));
			return Data;
		}
		uint32_t Transfer::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Transfer::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Transfer::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Transfer, 20>();
		}
		uint32_t Transfer::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Transfer::AsInstanceTypename()
		{
			return "transfer";
		}

		ExpectsLR<void> Omnitransfer::Prevalidate() const
		{
			if (Transfers.empty())
				return LayerException("no transfers");

			for (auto& Transfer : Transfers)
			{
				if (!Transfer.Value.IsPositive())
					return LayerException("invalid value");
			}

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Omnitransfer::Validate(const Ledger::TransactionContext* Context) const
		{
			for (auto& Transfer : Transfers)
			{
				if (memcmp(Context->Receipt.From, Transfer.To, sizeof(Algorithm::Pubkeyhash)) == 0)
					return LayerException("invalid receiver");
			}

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Omnitransfer::Execute(Ledger::TransactionContext* Context) const
		{
			for (auto& Transfer : Transfers)
			{
				auto Payment = Context->ApplyPayment(Transfer.To, Transfer.Value);
				if (!Payment)
					return Payment.Error();
			}

			return Expectation::Met;
		}
		bool Omnitransfer::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteInteger((uint16_t)Transfers.size());
			for (auto& Transfer : Transfers)
			{
				Stream->WriteString(Transfer.Memo);
				Stream->WriteDecimal(Transfer.Value);
				Stream->WriteString(std::string_view((char*)Transfer.To, memcmp(Transfer.To, Null, sizeof(Null)) == 0 ? 0 : sizeof(Transfer.To)));
			}

			return true;
		}
		bool Omnitransfer::LoadBody(Format::Stream& Stream)
		{
			uint16_t TransfersSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &TransfersSize))
				return false;

			Transfers.clear();
			Transfers.reserve(TransfersSize);
			for (uint16_t i = 0; i < TransfersSize; i++)
			{
				Subtransfer Transfer;
				if (!Stream.ReadString(Stream.ReadType(), &Transfer.Memo))
					return false;

				if (!Stream.ReadDecimal(Stream.ReadType(), &Transfer.Value))
					return false;

				String ToAssembly;
				if (!Stream.ReadString(Stream.ReadType(), &ToAssembly) || !Algorithm::Encoding::DecodeUintBlob(ToAssembly, Transfer.To, sizeof(Transfer.To)))
					return false;

				Transfers.push_back(std::move(Transfer));
			}

			return true;
		}
		bool Omnitransfer::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			for (auto& Transfer : Transfers)
				Parties.insert(String((char*)Transfer.To, sizeof(Transfer.To)));
			return true;
		}
		void Omnitransfer::SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, const std::string_view& NewMemo)
		{
			Subtransfer Transfer;
			Transfer.Value = NewValue;
			Transfer.Memo = NewMemo;
			if (!NewTo)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Transfer.To, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Transfer.To, NewTo, sizeof(Algorithm::Pubkeyhash));
			Transfers.push_back(std::move(Transfer));
		}
		bool Omnitransfer::IsToNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			for (auto& Transfer : Transfers)
			{
				if (memcmp(Transfer.To, Null, sizeof(Null)) == 0)
					return true;
			}
			return Transfers.empty();
		}
		UPtr<Schema> Omnitransfer::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			auto* TransfersData = Data->Set("transfers", Var::Set::Array());
			for (auto& Transfer : Transfers)
			{
				auto* TransferData = TransfersData->Push(Var::Set::Object());
				TransferData->Set("to", Algorithm::Signing::SerializeAddress(Transfer.To));
				TransferData->Set("value", Var::Decimal(Transfer.Value));
				TransferData->Set("memo", Transfer.Memo.empty() ? Var::Null() : Var::String(Transfer.Memo));
			}
			return Data;
		}
		uint32_t Omnitransfer::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Omnitransfer::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Omnitransfer::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Omnitransfer, 64>();
		}
		uint32_t Omnitransfer::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Omnitransfer::AsInstanceTypename()
		{
			return "omnitransfer";
		}

		ExpectsLR<void> Deployment::Prevalidate() const
		{
			if (IsLocationNull())
				return LayerException("invalid location");
			else if (Segregated && Calldata.size() != 64)
				return LayerException("invalid hashcode");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Deployment::Validate(const Ledger::TransactionContext* Context) const
		{
			Algorithm::Pubkeyhash Owner;
			if (!RecoverLocation(Owner))
				return LayerException("invalid location");

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Deployment::Execute(Ledger::TransactionContext* Context) const
		{
			Algorithm::Pubkeyhash Owner;
			if (!RecoverLocation(Owner))
				return LayerException("invalid location");

			auto* Host = Ledger::ScriptHost::Get();
			auto Compiler = Host->Allocate();
			if (!Segregated)
			{
				auto Code = Host->Unpack(Calldata);
				if (!Code)
					return Code.Error();

				auto Hashcode = Host->Hashcode(*Code);
				if (!Host->Precompile(*Compiler, Hashcode))
				{
					auto Compilation = Host->Compile(*Compiler, Hashcode, *Code);
					if (!Compilation)
					{
						Host->Deallocate(std::move(Compiler));
						return Compilation.Error();
					}
				}

				auto Collision = Context->GetWitnessProgram(Hashcode);
				if (!Collision)
				{
					auto Status = Context->ApplyWitnessProgram(Calldata);
					if (!Status)
					{
						Host->Deallocate(std::move(Compiler));
						return Status.Error();
					}
				}
				else if (Collision->Storage != Calldata)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException("program hashcode collision");
				}

				auto Status = Context->ApplyAccountProgram(Owner, Hashcode);
				if (!Status)
				{
					Host->Deallocate(std::move(Compiler));
					return Status.Error();
				}
			}
			else
			{
				if (!Host->Precompile(*Compiler, Calldata))
				{
					auto Program = Context->GetWitnessProgram(Calldata);
					if (!Program)
					{
						Host->Deallocate(std::move(Compiler));
						return LayerException("program is not stored");
					}

					auto Code = Program->AsCode();
					if (!Code)
					{
						Host->Deallocate(std::move(Compiler));
						return Code.Error();
					}

					auto Compilation = Host->Compile(*Compiler, Calldata, *Code);
					if (!Compilation)
					{
						Host->Deallocate(std::move(Compiler));
						return Compilation.Error();
					}
				}

				auto Status = Context->ApplyAccountProgram(Owner, Calldata);
				if (!Status)
				{
					Host->Deallocate(std::move(Compiler));
					return Status.Error();
				}
			}
			
			if (!Patchable)
			{
				auto Sequence = Context->ApplyAccountSequence(Owner, std::numeric_limits<uint64_t>::max());
				if (!Sequence)
				{
					Host->Deallocate(std::move(Compiler));
					return Sequence.Error();
				}
			}

			auto Script = Ledger::ScriptProgram(Context);
			auto Execution = Script.Initialize(*Compiler, Args);
			Host->Deallocate(std::move(Compiler));
			return Execution;
		}
		bool Deployment::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteBoolean(Patchable);
			Stream->WriteBoolean(Segregated);
			Stream->WriteString(Calldata);
			Stream->WriteString(std::string_view((char*)Location, sizeof(Location)));
			return Format::VariablesUtil::SerializeMergeInto(Args, Stream);
		}
		bool Deployment::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadBoolean(Stream.ReadType(), &Patchable))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Segregated))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Calldata))
				return false;

			String LocationAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &LocationAssembly) || LocationAssembly.size() != sizeof(Algorithm::Sighash))
				return false;

			Args.clear();
			memcpy(Location, LocationAssembly.data(), LocationAssembly.size());
			return Format::VariablesUtil::DeserializeMergeFrom(Stream, &Args);
		}
		bool Deployment::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Algorithm::Pubkeyhash Owner;
			if (RecoverLocation(Owner))
				Parties.insert(String((char*)Owner, sizeof(Owner)));
			return true;
		}
		bool Deployment::SignLocation(const Algorithm::Seckey SecretKey)
		{
			Format::Stream Message;
			Format::VariablesUtil::SerializeMergeInto(Args, &Message);
			Message.WriteBoolean(Patchable);
			Message.WriteBoolean(Segregated);
			Message.WriteString(Calldata);
			return Algorithm::Signing::SignTweaked(Algorithm::Signing::MessageHash(Message.Data), SecretKey, Location);
		}
		bool Deployment::VerifyLocation(const Algorithm::Pubkey PublicKey) const
		{
			Format::Stream Message;
			Format::VariablesUtil::SerializeMergeInto(Args, &Message);
			Message.WriteBoolean(Patchable);
			Message.WriteBoolean(Segregated);
			Message.WriteString(Calldata);
			return Algorithm::Signing::VerifyTweaked(Algorithm::Signing::MessageHash(Message.Data), PublicKey, Location);
		}
		bool Deployment::RecoverLocation(Algorithm::Pubkeyhash PublicKeyHash) const
		{
			Format::Stream Message;
			Format::VariablesUtil::SerializeMergeInto(Args, &Message);
			Message.WriteBoolean(Patchable);
			Message.WriteBoolean(Segregated);
			Message.WriteString(Calldata);
			return Algorithm::Signing::RecoverTweakedHash(Algorithm::Signing::MessageHash(Message.Data), PublicKeyHash, Location);
		}
		bool Deployment::IsLocationNull() const
		{
			Algorithm::Sighash Null = { 0 };
			return memcmp(Location, Null, sizeof(Null)) == 0;
		}
		void Deployment::SetLocation(const Algorithm::Sighash NewValue)
		{
			VI_ASSERT(NewValue != nullptr, "new value should be set");
			memcpy(Location, NewValue, sizeof(Algorithm::Sighash));
		}
		void Deployment::SetCalldata(const std::string_view& NewProgram, Format::Variables&& NewArgs, bool MayPatch)
		{
			Calldata = Ledger::ScriptHost::Get()->Pack(NewProgram).Or(String());
			Args = std::move(NewArgs);
			Patchable = MayPatch;
			Segregated = false;
		}
		void Deployment::SetSegregatedCalldata(const std::string_view& NewHashcode, Format::Variables&& NewArgs, bool MayPatch)
		{
			Calldata = NewHashcode.substr(0, 64);
			Args = std::move(NewArgs);
			Patchable = MayPatch;
			Segregated = true;
		}
		UPtr<Schema> Deployment::AsSchema() const
		{
			Algorithm::Pubkeyhash Owner;
			RecoverLocation(Owner);

			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("location_signature", Var::String(Format::Util::Encode0xHex(std::string_view((char*)Location, sizeof(Location)))));
			Data->Set("location_address", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("calldata", Var::String(Format::Util::Encode0xHex(Calldata)));
			Data->Set("args", Format::VariablesUtil::Serialize(Args));
			Data->Set("patchable", Var::Boolean(Patchable));
			Data->Set("segregated", Var::Boolean(Segregated));
			return Data;
		}
		uint32_t Deployment::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Deployment::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Deployment::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Deployment, 128>();
		}
		uint32_t Deployment::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Deployment::AsInstanceTypename()
		{
			return "deployment";
		}

		ExpectsLR<void> Invocation::Prevalidate() const
		{
			if (Function.empty())
				return LayerException("invalid function invocation");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Invocation::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Index = Context->GetAccountProgram(To);
			if (!Index)
				return LayerException("program is not assigned");

			if (Hashcode > 0)
			{
				uint32_t Basecode = Algorithm::Hashing::Hash32d(Index->Hashcode);
				if (Hashcode != Basecode)
					return LayerException(Stringify::Text("program hashcode does not match (%i != %i)", Hashcode, Basecode));
			}

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Invocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Index = Context->GetAccountProgram(To);
			if (!Index)
				return LayerException("program is not assigned");

			auto* Host = Ledger::ScriptHost::Get();
			auto& Hashcode = Index->Hashcode;
			auto Compiler = Host->Allocate();
			if (!Host->Precompile(*Compiler, Hashcode))
			{
				auto Program = Context->GetWitnessProgram(Hashcode);
				if (!Program)
				{
					Host->Deallocate(std::move(Compiler));
					return LayerException("program is not stored");
				}

				auto Code = Program->AsCode();
				if (!Code)
				{
					Host->Deallocate(std::move(Compiler));
					return Code.Error();
				}

				auto Compilation = Host->Compile(*Compiler, Hashcode, *Code);
				if (!Compilation)
				{
					Host->Deallocate(std::move(Compiler));
					return Compilation.Error();
				}
			}

			auto Script = Ledger::ScriptProgram(Context);
			auto Execution = Script.MutableCall(*Compiler, Function, Args);
			Host->Deallocate(std::move(Compiler));
			return Execution;
		}
		bool Invocation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteInteger(Hashcode);
			Stream->WriteString(std::string_view((char*)To, memcmp(To, Null, sizeof(Null)) == 0 ? 0 : sizeof(To)));
			Stream->WriteString(Function);
			return Format::VariablesUtil::SerializeMergeInto(Args, Stream);
		}
		bool Invocation::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &Hashcode))
				return false;

			String ToAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ToAssembly) || !Algorithm::Encoding::DecodeUintBlob(ToAssembly, To, sizeof(To)))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Function))
				return false;

			Args.clear();
			return Format::VariablesUtil::DeserializeMergeFrom(Stream, &Args);
		}
		bool Invocation::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)To, sizeof(To)));
			return true;
		}
		void Invocation::SetCalldata(const Algorithm::Pubkeyhash NewTo, const std::string_view& NewFunction, Format::Variables&& NewArgs)
		{
			SetCalldata(NewTo, 0, NewFunction, std::move(NewArgs));
		}
		void Invocation::SetCalldata(const Algorithm::Pubkeyhash NewTo, uint32_t NewHashcode, const std::string_view& NewFunction, Format::Variables&& NewArgs)
		{
			Args = std::move(NewArgs);
			Function = NewFunction;
			Hashcode = NewHashcode;
			if (!NewTo)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(To, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(To, NewTo, sizeof(Algorithm::Pubkeyhash));
		}
		bool Invocation::IsToNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(To, Null, sizeof(Null)) == 0;
		}
		UPtr<Schema> Invocation::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("to", Algorithm::Signing::SerializeAddress(To));
			Data->Set("hashcode", Var::Integer(Hashcode));
			Data->Set("function", Var::String(Function));
			Data->Set("args", Format::VariablesUtil::Serialize(Args));
			return Data;
		}
		uint32_t Invocation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Invocation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Invocation::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Invocation, 128>();
		}
		uint32_t Invocation::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Invocation::AsInstanceTypename()
		{
			return "invocation";
		}

		ExpectsLR<void> Withdrawal::Prevalidate() const
		{
			if (To.empty())
				return LayerException("invalid to");

			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			if (!Chain->SupportsBulkTransfer && To.size() > 1)
				return LayerException("too many to addresses");

			UnorderedSet<String> Addresses;
			for (auto& Item : To)
			{
				if (Addresses.find(Item.first) != Addresses.end())
					return LayerException("duplicate to address");

				if (!Item.second.IsPositive())
					return LayerException("invalid to value");

				Addresses.insert(Item.first);
			}

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Withdrawal::Validate(const Ledger::TransactionContext* Context) const
		{
			Decimal Value = 0.0;
			auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
			for (auto& Item : To)
			{
				auto Collision = Context->GetWitnessAddress(BaseAsset, Item.first, Protocol::Now().Account.RootAddressIndex, 0);
				if (Collision && memcmp(Collision->Owner, Context->Receipt.From, sizeof(Collision->Owner)) != 0)
					return LayerException("invalid to address (not owned by sender)");

				Value += Item.second;
			}

			bool Charges = memcmp(Context->Receipt.From, Proposer, sizeof(Algorithm::Pubkeyhash)) != 0;
			auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, Proposer) : ExpectsLR<States::AccountReward>(LayerException());
			if (BaseReward && BaseAsset != Asset)
			{
				auto BalanceRequirement = Context->VerifyTransferBalance(BaseAsset, BaseReward->OutgoingAbsoluteFee);
				if (!BalanceRequirement)
					return BalanceRequirement.Error();

				auto Contribution = Context->GetAccountContribution(BaseAsset, Proposer);
				if (!Contribution || Contribution->Custody < BaseReward->OutgoingAbsoluteFee)
					return LayerException("proposer's " + Algorithm::Asset::HandleOf(BaseAsset) + " balance is insufficient to cover withdrawal fee (value: " + BaseReward->OutgoingAbsoluteFee.ToString() + ")");
			}

			auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, Proposer);
			auto BalanceRequirement = Context->VerifyTransferBalance(std::max(Value, TokenReward ? TokenReward->CalculateOutgoingFee(Value) : Decimal::Zero()));
			if (!BalanceRequirement)
				return BalanceRequirement;

			auto Contribution = Context->GetAccountContribution(Proposer);
			auto& ss = *Contribution;
			if (!Contribution || Contribution->Custody < Value)
				return LayerException("proposer's " + Algorithm::Asset::HandleOf(Asset) + " balance is insufficient to cover withdrawal value (value: " + Value.ToString() + ")");

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Withdrawal::Execute(Ledger::TransactionContext* Context) const
		{
			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
			for (auto& Item : To)
			{
				auto Collision = Context->GetWitnessAddress(BaseAsset, Item.first, Protocol::Now().Account.RootAddressIndex, 0);
				if (!Collision)
					Collision = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, { { (uint8_t)0, String(Item.first) } }, AddressIndex, States::WitnessAddress::Class::Router);
				if (!Collision)
					return Collision.Error();
			}

			bool Charges = memcmp(Context->Receipt.From, Proposer, sizeof(Algorithm::Pubkeyhash)) != 0;
			auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, Proposer) : ExpectsLR<States::AccountReward>(LayerException());
			auto BaseFee = (BaseReward ? BaseReward->OutgoingAbsoluteFee : Decimal::Zero());
			if (BaseAsset != Asset && BaseFee.IsPositive())
			{
				auto BaseTransfer = Context->ApplyTransfer(BaseAsset, Context->Receipt.From, -BaseFee, Decimal::Zero());
				if (!BaseTransfer)
					return BaseTransfer.Error();

				BaseTransfer = Context->ApplyTransfer(BaseAsset, Proposer, BaseFee, Decimal::Zero());
				if (!BaseTransfer)
					return BaseTransfer.Error();
			}

			auto Value = GetTotalValue();
			auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, Proposer);
			auto TokenFee = (TokenReward ? TokenReward->CalculateOutgoingFee(Value) : Decimal::Zero());
			auto TokenTransfer = Context->ApplyTransfer(Context->Receipt.From, -TokenFee, Value - TokenFee);
			if (!TokenTransfer)
				return TokenTransfer.Error();

			if (TokenFee.IsPositive())
			{
				TokenTransfer = Context->ApplyTransfer(Proposer, TokenFee, Decimal::Zero());
				if (!TokenTransfer)
					return TokenTransfer.Error();
			}

			return Expectation::Met;
		}
		ExpectsPromiseLR<void> Withdrawal::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(Proposer.PublicKeyHash, this->Proposer, sizeof(this->Proposer)) != 0)
				return ExpectsPromiseLR<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseLR<void>(Expectation::Met);

			bool Charges = memcmp(Context->Receipt.From, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0;
			auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
			auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, Proposer.PublicKeyHash) : ExpectsLR<States::AccountReward>(LayerException());
			auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, Proposer.PublicKeyHash);
			auto PartitionFee = (TokenReward ? TokenReward->CalculateOutgoingFee(GetTotalValue()) : Decimal::Zero());
			if (To.size() > 1)
				PartitionFee /= Decimal(To.size()).Truncate(Protocol::Now().Message.Precision);

			auto* Transaction = Memory::New<Transactions::Replay>();
			Transaction->Asset = Asset;
			Pipeline->push_back(Transaction);

			Vector<Observer::Transferer> Destinations;
			Destinations.reserve(To.size());
			for (auto& Item : To)
				Destinations.push_back(Observer::Transferer(Item.first, Optional::None, Item.second - PartitionFee));

			return EmitTransaction(Proposer, Asset, Context->Receipt.TransactionHash, Pipeline, std::move(Destinations)).Then<ExpectsLR<void>>([this, Context, Pipeline, Transaction](ExpectsLR<Observer::OutgoingTransaction>&& Result)
			{
				if (!Result || Result->Transaction.TransactionId.empty())
					Transaction->SetFailureWitness(Result ? "transaction broadcast failed" : Result.What(), Context->Receipt.TransactionHash);
				else
					Transaction->SetSuccessWitness(Result->Transaction.TransactionId, Result->Data, Context->Receipt.TransactionHash);
				return ExpectsLR<void>(Expectation::Met);
			});
		}
		bool Withdrawal::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger((uint16_t)To.size());
			for (auto& Item : To)
			{
				Stream->WriteString(Item.first);
				Stream->WriteDecimal(Item.second);
			}
			return true;
		}
		bool Withdrawal::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			uint16_t ToSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &ToSize))
				return false;

			for (uint16_t i = 0; i < ToSize; i++)
			{
				String Address;
				if (!Stream.ReadString(Stream.ReadType(), &Address))
					return false;

				Decimal Value;
				if (!Stream.ReadDecimal(Stream.ReadType(), &Value))
					return false;

				To.push_back(std::make_pair(std::move(Address), std::move(Value)));
			}

			return true;
		}
		bool Withdrawal::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			if (!IsProposerNull())
				Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		void Withdrawal::SetTo(const std::string_view& Address, const Decimal& Value)
		{
			for (auto& Item : To)
			{
				if (Item.first == Address)
				{
					Item.second = Value;
					return;
				}
			}
			To.push_back(std::make_pair(String(Address), Decimal(Value)));
		}
		void Withdrawal::SetProposer(const Algorithm::Pubkeyhash NewProposer)
		{
			if (!NewProposer)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Proposer, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Proposer, NewProposer, sizeof(Algorithm::Pubkeyhash));
		}
		bool Withdrawal::IsProposerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(Proposer, Null, sizeof(Null)) == 0;
		}
		Decimal Withdrawal::GetTotalValue() const
		{
			Decimal Value = 0.0;
			for (auto& Item : To)
				Value += Item.second;
			return Value;
		}
		UPtr<Schema> Withdrawal::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			auto* ToData = Data->Set("to", Var::Set::Array());
			for (auto& Item : To)
			{
				auto* CoinData = ToData->Push(Var::Set::Object());
				CoinData->Set("address", Var::String(Item.first));
				CoinData->Set("value", Var::Decimal(Item.second));
			}
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			return Data;
		}
		uint32_t Withdrawal::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Withdrawal::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Withdrawal::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Withdrawal, 36>();
		}
		uint64_t Withdrawal::GetDispatchOffset() const
		{
			return Protocol::Now().User.Observer.WithdrawalTime / Protocol::Now().Policy.ConsensusProofTime;
		}
		uint32_t Withdrawal::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Withdrawal::AsInstanceTypename()
		{
			return "withdrawal";
		}

		Rollup::Rollup(const Rollup& Other)
		{
			Ledger::Transaction& Base = *this;
			Base = *(Ledger::Transaction*)&Other;
			Transactions.clear();
			for (auto& Group : Other.Transactions)
			{
				auto& GroupCopy = Transactions[Group.first];
				GroupCopy.reserve(Group.second.size());
				for (auto& Transaction : Group.second)
				{
					auto* Copy = Resolver::Copy(*Transaction);
					if (Copy != nullptr)
						GroupCopy.push_back(Copy);
				}
			}
		}
		Rollup& Rollup::operator= (const Rollup& Other)
		{
			if (this == &Other)
				return *this;

			Ledger::Transaction& Base = *this;
			Base = *(Ledger::Transaction*)&Other;
			Transactions.clear();
			for (auto& Group : Other.Transactions)
			{
				auto& GroupCopy = Transactions[Group.first];
				GroupCopy.reserve(Group.second.size());
				for (auto& Transaction : Group.second)
				{
					auto* Copy = Resolver::Copy(*Transaction);
					if (Copy != nullptr)
						GroupCopy.push_back(Copy);
				}
			}
			return *this;
		}
		ExpectsLR<void> Rollup::Prevalidate() const
		{
			if (Transactions.empty())
				return LayerException("invalid transactions");

			for (auto& Group : Transactions)
			{
				if (Group.second.empty())
					return LayerException("invalid transactions");

				for (auto& Transaction : Group.second)
				{
					if (!Transaction || Transaction->AsType() == AsType())
						return LayerException("invalid sub-transaction");

					auto* Mutable = (Ledger::Transaction*)*Transaction;
					if (Transaction->Asset != Group.first || Transaction->Conservative || !Transaction->GasPrice.IsNaN() || !Transaction->GasLimit)
						return LayerException("invalid sub-transaction data");

					uint256_t TransactionHash = Transaction->AsHash();
					Mutable->GasPrice = Decimal::Zero();
					auto Prevalidation = Transaction->Prevalidate();
					Mutable->GasPrice = Decimal::NaN();
					if (!Prevalidation)
						return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(TransactionHash) + " prevalidation failed: " + Prevalidation.Error().Info);
				}
			}

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Rollup::Validate(const Ledger::TransactionContext* Context) const
		{
			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Rollup::Execute(Ledger::TransactionContext* Context) const
		{
			Vector<std::pair<Ledger::Transaction*, uint16_t>> Queue;
			for (auto& Group : Transactions)
			{
				uint16_t Index = 0;
				Queue.reserve(Queue.size() + Group.second.size());
				for (auto& Transaction : Group.second)
					Queue.push_back(std::make_pair(*Transaction, Index++));
			}

			uint256_t AbsoluteGasLimit = Context->Block->GasLimit;
			uint256_t AbsoluteGasUse = Context->Block->GasUse;
			uint256_t RelativeGasUse = Context->Receipt.RelativeGasUse;
			std::sort(Queue.begin(), Queue.end(), [](const std::pair<Ledger::Transaction*, uint16_t>& A, const std::pair<Ledger::Transaction*, uint16_t>& B)
			{
				return A.first->Sequence < B.first->Sequence;
			});

			Algorithm::Pubkeyhash Null = { 0 };
			for (auto& [Transaction, Index] : Queue)
			{
				Format::Stream Message;
				Message.WriteInteger(Rollup::AsInstanceType());
				Message.WriteInteger(Asset);
				Message.WriteInteger(Index);
				if (!Transaction->StorePayload(&Message))
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " prevalidation failed: invalid payload");

				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::RecoverTweakedHash(Message.Hash(), Owner, Transaction->Signature) || !memcmp(Owner, Null, sizeof(Null)))
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " prevalidation failed: invalid signature");

				Transaction->GasPrice = Decimal::Zero();
				auto Validation = Ledger::TransactionContext::ValidateTx((Ledger::Block*)Context->Block, Context->Environment, Transaction, Transaction->AsHash(), Owner, *Context->Delta.Incoming);
				Transaction->GasPrice = Decimal::NaN();
				if (!Validation)
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " validation failed: " + Validation.Error().Info);

				auto Finalization = Ledger::TransactionContext::ExecuteTx(*Validation, Transaction->AsMessage().Data.size(), true);
				RelativeGasUse += Validation->Receipt.RelativeGasUse;
				if (!Finalization)
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " finalization failed: " + Finalization.Error().Info);

				auto Report = Context->EmitEvent<Rollup>({ Format::Variable(Validation->Receipt.TransactionHash), Format::Variable(Validation->Receipt.RelativeGasUse), Format::Variable(Validation->Receipt.RelativeGasPaid) });
				if (!Report)
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " event merge failed: " + Report.Error().Info);

				Context->Receipt.Events.reserve(Context->Receipt.Events.size() + Validation->Receipt.Events.size());
				for (auto& Event : Validation->Receipt.Events)
					Context->Receipt.Events.push_back(std::move(Event));
			}

			Context->Block->GasLimit = AbsoluteGasLimit;
			Context->Block->GasUse = AbsoluteGasUse;
			Context->Receipt.RelativeGasUse = RelativeGasUse;
			return Expectation::Met;
		}
		ExpectsPromiseLR<void> Rollup::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			auto Requirement = GetDispatchOffset();
			if (!Requirement)
				return ExpectsPromiseLR<void>(Expectation::Met);

			return Coasync<ExpectsLR<void>>([this, Proposer, Context, Pipeline]() -> ExpectsPromiseLR<void>
			{
				LayerException CumulativeException;
				for (auto& Group : Transactions)
				{
					for (auto& Transaction : Group.second)
					{
						auto Status = Coawait(Transaction->Dispatch(Proposer, Context, Pipeline));
						if (!Status)
							CumulativeException.Info += "sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " dispatch failed: " + Status.Error().Info + "\n";
					}
				}
				if (CumulativeException.Info.empty())
					Coreturn Expectation::Met;
				
				CumulativeException.Info.pop_back();
				Coreturn CumulativeException;
			});
		}
		bool Rollup::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger((uint16_t)Transactions.size());
			for (auto& Group : Transactions)
			{
				Stream->WriteInteger(Group.first == Asset ? uint256_t(0) : Group.first);
				Stream->WriteInteger((uint32_t)Group.second.size());
				for (auto& Transaction : Group.second)
				{
					Stream->WriteInteger(Transaction->AsType());
					Stream->WriteInteger(Transaction->Sequence);
					Stream->WriteInteger(Transaction->GasLimit);
					Stream->WriteString(std::string_view((char*)Transaction->Signature, sizeof(Transaction->Signature)));
					if (!Transaction->StoreBody(Stream))
						return false;
				}
			}

			return true;
		}
		bool Rollup::LoadBody(Format::Stream& Stream)
		{
			Transactions.clear();
			uint16_t GroupsCount;
			if (!Stream.ReadInteger(Stream.ReadType(), &GroupsCount))
				return false;

			String SignatureAssembly;
			for (uint16_t i = 0; i < GroupsCount; i++)
			{
				Algorithm::AssetId GroupAsset;
				if (!Stream.ReadInteger(Stream.ReadType(), &GroupAsset))
					return false;

				uint32_t TransactionsCount;
				if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsCount))
					return false;

				GroupAsset = GroupAsset ? GroupAsset : Asset;
				auto& Group = Transactions[GroupAsset];
				Group.reserve(TransactionsCount);
				for (uint32_t j = 0; j < TransactionsCount; j++)
				{
					uint32_t Type;
					if (!Stream.ReadInteger(Stream.ReadType(), &Type))
						return false;

					UPtr<Ledger::Transaction> Next = Resolver::New(Type);
					if (!Next || !Stream.ReadInteger(Stream.ReadType(), &Next->Sequence))
						return false;

					if (!Stream.ReadInteger(Stream.ReadType(), &Next->GasLimit))
						return false;

					if (!Stream.ReadString(Stream.ReadType(), &SignatureAssembly) || SignatureAssembly.size() != sizeof(Algorithm::Sighash))
						return false;

					Next->Asset = GroupAsset;
					if (!Next->LoadBody(Stream))
						return false;

					SetupChild(**Next, Asset);
					memcpy(Next->Signature, SignatureAssembly.data(), SignatureAssembly.size());
					Group.push_back(std::move(Next));
				}
			}
			return true;
		}
		bool Rollup::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					Algorithm::Pubkeyhash From = { 0 };
					if (Transaction->Recover(From))
					{
						Parties.insert(String((char*)From, sizeof(From)));
						Transaction->RecoverAlt(Receipt, Parties);
					}
				}
			}
			return true;
		}
		bool Rollup::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<uint256_t>& Aliases) const
		{
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					Algorithm::Pubkeyhash From = { 0 };
					Aliases.insert(Transaction->AsHash());
					Transaction->RecoverAlt(Receipt, Aliases);
				}
			}
			return true;
		}
		bool Rollup::Merge(const Ledger::Transaction& Transaction)
		{
			auto* Next = Resolver::Copy(&Transaction);
			if (!Next)
				return false;

			Transactions[Next->Asset].push_back(Next);
			return true;
		}
		bool Rollup::Merge(Ledger::Transaction& Transaction, const Algorithm::Seckey SecretKey)
		{
			auto It = Transactions.find(Transaction.Asset ? Transaction.Asset : Asset);
			uint16_t Index = It != Transactions.end() ? It->second.size() : 0;
			return SignChild(Transaction, SecretKey, Asset, Index) && Merge(Transaction);
		}
		bool Rollup::Merge(Ledger::Transaction& Transaction, const Algorithm::Seckey SecretKey, uint64_t Sequence)
		{
			Transaction.Sequence = Sequence;
			return Merge(Transaction, SecretKey);
		}
		ExpectsLR<Ledger::BlockTransaction> Rollup::ResolveBlockTransaction(const Ledger::Receipt& Receipt, const uint256_t& TransactionHash) const
		{
			if (!TransactionHash)
				return LayerException("sub-transaction not found");

			Ledger::Transaction* Target = nullptr;
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					if (Transaction->AsHash() == TransactionHash)
					{
						Target = *Transaction;
						break;
					}
					else if (Transaction->AsType() != Rollup::AsInstanceType())
						continue;

					auto Candidate = ((Rollup*)*Transaction)->ResolveBlockTransaction(Receipt, TransactionHash);
					if (Candidate)
						return Candidate;
				}
			}

			if (!Target)
				return LayerException("sub-transaction not found");

			Ledger::BlockTransaction Transaction;
			Transaction.Transaction = Resolver::Copy(Target);
			Transaction.Receipt = Receipt;
			if (!Transaction.Transaction)
				return LayerException("sub-transaction not valid");

			Transaction.Receipt.RelativeGasUse = 0;
			Transaction.Receipt.RelativeGasPaid = 0;
			Transaction.Receipt.TransactionHash = Transaction.Transaction->AsHash();
			if (!Transaction.Transaction->Recover(Transaction.Receipt.From))
				return LayerException("sub-transaction not valid");

			size_t Offset = 0;
			size_t Begin = std::string::npos, End = std::string::npos;
			for (auto& Event : Receipt.Events)
			{
				++Offset;
				if (Event.first != Rollup::AsInstanceType() || Event.second.size() != 3)
					continue;

				uint256_t CandidateHash = Event.second[0].AsUint256();
				if (CandidateHash == TransactionHash)
				{
					Begin = Offset - 1;
					Transaction.Receipt.RelativeGasUse = Event.second[1].AsUint256();
					Transaction.Receipt.RelativeGasPaid = Event.second[2].AsUint256();
					continue;
				}
				else if (Begin != std::string::npos)
				{
					End = Offset - 1;
					break;
				}
			}

			if (Begin == std::string::npos)
				return LayerException("sub-transaction not valid");
			else if (End == std::string::npos)
				End = Offset;

			Transaction.Receipt.Events.resize(End - 1);
			Transaction.Receipt.Events.erase(Transaction.Receipt.Events.begin(), Transaction.Receipt.Events.begin() + Begin + 1);
			return Transaction;
		}
		const Ledger::Transaction* Rollup::ResolveTransaction(const uint256_t& TransactionHash) const
		{
			if (!TransactionHash)
				return nullptr;

			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					if (Transaction->AsHash() == TransactionHash)
						return *Transaction;
					else if (Transaction->AsType() != Rollup::AsInstanceType())
						continue;

					auto* Candidate = ((Rollup*)*Transaction)->ResolveTransaction(TransactionHash);
					if (Candidate != nullptr)
						return Candidate;
				}
			}

			return nullptr;
		}
		UPtr<Schema> Rollup::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Schema* TransactionsData = Data->Set("transactions", Var::Array());
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
					TransactionsData->Push(Transaction->AsSchema().Reset());
			}
			return Data;
		}
		uint32_t Rollup::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Rollup::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Rollup::GetGasEstimate() const
		{
			uint256_t GasRequirement = Ledger::GasUtil::GetGasEstimate<Rollup, 8>();
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
					GasRequirement += Transaction->GasLimit;
			}
			return GasRequirement;
		}
		uint64_t Rollup::GetDispatchOffset() const
		{
			uint64_t Max = 0;
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					uint64_t Value = Transaction->GetDispatchOffset();
					if (Value > Max)
						Max = Value;
				}
			}
			return Max;
		}
		uint32_t Rollup::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Rollup::AsInstanceTypename()
		{
			return "rollup";
		}
		void Rollup::SetupChild(Ledger::Transaction& Transaction, const Algorithm::AssetId& Asset)
		{
			if (!Transaction.Asset)
				Transaction.Asset = Asset;
			Transaction.Conservative = false;
			Transaction.GasPrice = Decimal::NaN();
			if (!Transaction.GasLimit)
				Transaction.GasLimit = Transaction.GetGasEstimate();
		}
		bool Rollup::SignChild(Ledger::Transaction& Transaction, const Algorithm::Seckey SecretKey, const Algorithm::AssetId& Asset, uint16_t Index)
		{
			Format::Stream Message;
			Message.WriteInteger(Rollup::AsInstanceType());
			Message.WriteInteger(Asset);
			Message.WriteInteger(Index);
			SetupChild(Transaction, Asset);

			if (!Transaction.StorePayload(&Message))
				return false;
			
			return Algorithm::Signing::SignTweaked(Message.Hash(), SecretKey, Transaction.Signature);
		}

		ExpectsLR<void> Commitment::Prevalidate() const
		{
			if (Worker == Ledger::WorkStatus::Standby && Observers.empty())
				return LayerException("invalid status");
			else if (Worker != Ledger::WorkStatus::Standby && Worker != Ledger::WorkStatus::Online && Worker != Ledger::WorkStatus::Offline)
				return LayerException("invalid status");

			for (auto& Observer : Observers)
			{
				if (!Algorithm::Asset::IsValid(Observer.first))
					return LayerException("invalid oracle asset");

				if (Observer.second != Ledger::WorkStatus::Online && Observer.second != Ledger::WorkStatus::Offline)
					return LayerException("invalid oracle status");
			}

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> Commitment::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Status = Context->VerifyAccountWork();
			if (!Status)
				return Status;

			if (Worker != Ledger::WorkStatus::Standby)
			{
				auto Work = Context->GetAccountWork(Context->Receipt.From);
				if ((Work ? Work->Status : Ledger::WorkStatus::Offline) == Worker)
				{
					if (Worker != Ledger::WorkStatus::Online || !Work || Work->IsOnline())
						return LayerException("work status is already set to required value");
				}
			}

			for (auto& Observer : Observers)
			{
				auto ObserverWork = Context->GetAccountObserver(Observer.first, Context->Receipt.From);
				if ((ObserverWork ? ObserverWork->Status : Ledger::WorkStatus::Offline) == Observer.second)
					return LayerException(Algorithm::Asset::BlockchainOf(Observer.first) + " observer status is already set to required value");
			}

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> Commitment::Execute(Ledger::TransactionContext* Context) const
		{
			if (Worker != Ledger::WorkStatus::Standby)
			{
				auto Work = Context->ApplyAccountWork(Context->Receipt.From, Worker, 0, 0, 0);
				if (!Work)
					return Work.Error();
			}

			for (auto& Observer : Observers)
			{
				auto ObserverWork = Context->ApplyAccountObserver(Observer.first, Context->Receipt.From, Observer.second);
				if (!ObserverWork)
					return ObserverWork.Error();
			}

			return Expectation::Met;
		}
		bool Commitment::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger((uint8_t)Worker);
			Stream->WriteInteger((uint16_t)Observers.size());
			for (auto& Observer : Observers)
			{
				Stream->WriteInteger(Observer.first);
				Stream->WriteInteger((uint8_t)Observer.second);
			}
			return true;
		}
		bool Commitment::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), (uint8_t*)&Worker))
				return false;

			uint16_t ObserversSize = 0;
			if (!Stream.ReadInteger(Stream.ReadType(), &ObserversSize))
				return false;

			Observers.clear();
			for (uint16_t i = 0; i < ObserversSize; i++)
			{
				Algorithm::AssetId Asset;
				if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
					return false;

				Ledger::WorkStatus Status;
				if (!Stream.ReadInteger(Stream.ReadType(), (uint8_t*)&Status))
					return false;

				Observers[Asset] = Status;
			}

			return true;
		}
		bool Commitment::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			return true;
		}
		void Commitment::SetOnline()
		{
			Worker = Ledger::WorkStatus::Online;
		}
		void Commitment::SetOnline(const Algorithm::AssetId& Asset)
		{
			Observers[Asset] = Ledger::WorkStatus::Online;
		}
		void Commitment::SetOffline()
		{
			Worker = Ledger::WorkStatus::Offline;
		}
		void Commitment::SetOffline(const Algorithm::AssetId& Asset)
		{
			Observers[Asset] = Ledger::WorkStatus::Offline;
		}
		UPtr<Schema> Commitment::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("status", Var::Integer((int64_t)Worker));
			
			auto* ObserversData = Data->Set("observers", Var::Set::Array());
			for (auto& Observer : Observers)
			{
				auto* ObserverData = ObserversData->Push(Var::Set::Object());
				ObserverData->Set("asset", Algorithm::Asset::Serialize(Observer.first));
				ObserverData->Set("status", Var::Integer((int64_t)Observer.second));
			}
			return Data;
		}
		uint32_t Commitment::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Commitment::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Commitment::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Commitment, 64>();
		}
		uint32_t Commitment::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Commitment::AsInstanceTypename()
		{
			return "commitment";
		}

		ExpectsLR<void> Claim::Prevalidate() const
		{
			auto Assertion = GetAssertion(nullptr);
			if (!Assertion || !Assertion->IsValid())
				return LayerException("invalid assertion");

			if (Assertion->Asset != Asset)
				return LayerException("invalid assertion asset");

			if (!Assertion->IsLatencyApproved())
				return LayerException("invalid assertion status");

			return Ledger::AggregationTransaction::Prevalidate();
		}
		ExpectsLR<void> Claim::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Assertion = GetAssertion(Context);
			if (!Assertion)
				return LayerException("invalid assertion");

			if (Assertion->Asset != Asset)
				return LayerException("invalid assertion asset");

			if (!Assertion->IsLatencyApproved())
				return LayerException("invalid assertion status");

			auto Collision = Context->GetWitnessTransaction(Assertion->TransactionId);
			if (Collision)
				return LayerException("assertion " + Assertion->TransactionId + " finalized");

			return Ledger::AggregationTransaction::Validate(Context);
		}
		ExpectsLR<void> Claim::Execute(Ledger::TransactionContext* Context) const
		{
			auto BaseDerivationIndex = Protocol::Now().Account.RootAddressIndex;
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid chain");

			auto Assertion = GetAssertion(Context);
			if (!Assertion)
				return LayerException("invalid assertion");

			Transition Operations;
			bool Migration = true;
			Algorithm::Pubkeyhash Null = { 0 };
			Algorithm::Pubkeyhash Router = { 0 };
			UnorderedMap<String, Decimal> Inputs, Outputs;
			Decimal Change = Decimal::Zero(), Input = Decimal::Zero(), Output = Decimal::Zero();
			std::for_each(Assertion->From.begin(), Assertion->From.end(), [&](auto& Item) { auto& Value = Inputs[Item.Address]; Value = Value.IsNaN() ? Item.Value : Value + Item.Value; Input += Item.Value; });
			std::for_each(Assertion->To.begin(), Assertion->To.end(), [&](auto& Item) { auto& Value = Outputs[Item.Address]; Value = Value.IsNaN() ? Item.Value : Value + Item.Value; Output += Item.Value; });
			std::for_each(Inputs.begin(), Inputs.end(), [&](auto& Item) { auto Value = Outputs.find(Item.first); if (Value != Outputs.end()) { auto Delta = Item.second; Item.second -= Value->second; Value->second -= Delta; } });
			Assertion->From.erase(std::remove_if(Assertion->From.begin(), Assertion->From.end(), [&](auto& Item) { return !Inputs[Item.Address].IsPositive(); }), Assertion->From.end());
			Assertion->To.erase(std::remove_if(Assertion->To.begin(), Assertion->To.end(), [&](auto& Item) { return !Outputs[Item.Address].IsPositive(); }), Assertion->To.end());

			if (Input.IsNaN() || Input.IsNegative())
				return LayerException("invalid input value");

			if (Input < Output || Output.IsNaN() || Output.IsNegative())
				return LayerException("invalid output value");

			switch (Chain->Routing)
			{
				case Tangent::Observer::RoutingPolicy::Account:
				case Tangent::Observer::RoutingPolicy::Memo:
					if (Assertion->From.size() > 1)
						return LayerException("too many inputs");

					if (Assertion->To.size() > 1)
						return LayerException("too many outputs");
					break;
				default:
					break;
			}

			for (auto& Item : Assertion->From)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Observer::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context->GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
				{
					if (Source->IsCustodianAddress() || Source->IsContributionAddress())
					{
						auto& Contribution = Operations.Contributions[String((char*)Source->Proposer, sizeof(Source->Proposer))];
						Contribution.Custody -= Item.Value;
					}
					else if (Source->IsRouterAddress())
					{
						memcpy(Router, Source->Owner, sizeof(Source->Owner));
						Migration = false;
					}
				}
				else
				{
					Change -= Item.Value;
					Migration = false;
				}
			}

			for (auto& Item : Assertion->To)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Observer::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context->GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
				{
					auto* Owner = (Chain->Routing == Observer::RoutingPolicy::Account && memcmp(Router, Null, sizeof(Null)) != 0 ? Router : Source->Owner);
					if (!Source->IsRouterAddress())
					{
						auto& Contribution = Operations.Contributions[String((char*)Source->Proposer, sizeof(Source->Proposer))];
						if (Source->IsCustodianAddress())
						{
							Contribution.Custody += Item.Value;
							if (!Migration)
							{
								auto& Balance = Operations.Transfers[String((char*)Owner, sizeof(Source->Owner))];
								Balance.Supply += Item.Value;

								auto Reward = Context->GetAccountReward(Asset, Source->Proposer);
								if (Reward && Reward->HasIncomingFee())
								{
									auto Fee = Reward->CalculateIncomingFee(Item.Value);
									Balance.Supply -= Fee;

									auto& Redeemer = Operations.Transfers[String((char*)Source->Proposer, sizeof(Source->Proposer))];
									Redeemer.Supply += Fee;
								}
							}
						}
						else if (Source->IsContributionAddress())
						{
							auto& Coverage = Contribution.Contributions[Item.Address];
							Coverage = Coverage.IsNaN() ? Item.Value : Coverage + Item.Value;
						}
					}
					else
					{
						auto& Balance = Operations.Transfers[String((char*)Owner, sizeof(Source->Owner))];
						Balance.Supply -= Item.Value;
						Balance.Reserve -= Item.Value;
					}
				}
				else
					Change += Item.Value;
			}

			for (auto& Item : Operations.Contributions)
			{
				if (Change.IsNegative() && Item.second.Custody.IsNegative())
				{
					Item.second.Custody = Decimal::NaN();
					continue;
				}

				auto Info = Context->GetAccountContribution((uint8_t*)Item.first.data()).Or(States::AccountContribution((uint8_t*)Item.first.data(), Context->Block));
				Info.Custody += Item.second.Custody;
				for (auto& Coverage : Item.second.Contributions)
				{
					auto& Merging = Info.Contributions[Coverage.first];
					Merging = Merging.IsNaN() ? Coverage.second : Merging + Coverage.second;
				}

				Decimal Coverage = Info.GetCoverage();
				if (!Coverage.IsNegative())
					continue;

				Coverage = -Coverage;
				auto It = Operations.Transfers.begin();
				while (It != Operations.Transfers.end() && Coverage.IsPositive())
				{
					auto& Reserve = std::min(It->second.Supply, Coverage);
					if (Reserve.IsPositive())
					{
						auto& Reservation = Item.second.Reservations[It->first];
						Reservation = Reservation.IsNaN() ? Reserve : Reservation + Reserve;
						It->second.Reserve += Reserve;
						Coverage -= Reserve;
					}
					++It;
				}
			}

			if (Operations.Transfers.empty() && Operations.Contributions.empty())
				return LayerException("invalid claim");

			for (auto& Operation : Operations.Transfers)
			{
				if (Operation.second.Supply.IsZeroOrNaN() && Operation.second.Reserve.IsZeroOrNaN())
					continue;

				auto SupplyDelta = Operation.second.Supply.IsNaN() ? Decimal::Zero() : Operation.second.Supply;
				auto ReserveDelta = Operation.second.Reserve.IsNaN() ? Decimal::Zero() : Operation.second.Reserve;
				if (SupplyDelta.IsNegative() || ReserveDelta.IsNegative())
				{
					auto Balance = Context->GetAccountBalance((uint8_t*)Operation.first.data());
					auto Supply = (Balance ? Balance->Supply : Decimal::Zero()) + SupplyDelta;
					auto Reserve = (Balance ? Balance->Reserve : Decimal::Zero()) + ReserveDelta;
					if (Supply < 0.0 || Reserve < 0.0)
					{
						for (auto& Item : Operations.Contributions)
							Item.second.Custody = Decimal::NaN();
						continue;
					}
				}

				auto Transfer = Context->ApplyTransfer((uint8_t*)Operation.first.data(), SupplyDelta, ReserveDelta);
				if (!Transfer)
					return Transfer.Error();
			}

			for (auto& Operation : Operations.Contributions)
			{
				auto Contribution = Context->ApplyAccountContribution((uint8_t*)Operation.first.data(), Operation.second.Custody, std::move(Operation.second.Contributions), std::move(Operation.second.Reservations));
				if (!Contribution)
					return Contribution.Error();
			}

			auto Witness = Context->ApplyWitnessTransaction(Assertion->TransactionId);
			if (!Witness)
				return Witness.Error();

			return Context->EmitWitness(Assertion->BlockId);
		}
		bool Claim::StoreBody(Format::Stream* Stream) const
		{
			return true;
		}
		bool Claim::LoadBody(Format::Stream& Stream)
		{
			return true;
		}
		bool Claim::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return false;

			auto Assertion = GetAssertion(nullptr);
			if (!Assertion)
				return false;

			auto Context = Ledger::TransactionContext();
			auto BaseDerivationIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Item : Assertion->From)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Observer::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context.GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
					Parties.insert(String((char*)Source->Owner, sizeof(Source->Owner)));
			}
			for (auto& Item : Assertion->To)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Observer::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context.GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
					Parties.insert(String((char*)Source->Owner, sizeof(Source->Owner)));
			}
			return true;
		}
		void Claim::SetWitness(uint64_t BlockHeight, const std::string_view& TransactionId, Decimal&& Fee, Vector<Observer::Transferer>&& Senders, Vector<Observer::Transferer>&& Receivers)
		{
			Observer::IncomingTransaction Target;
			Target.SetTransaction(Asset, BlockHeight, TransactionId, std::move(Fee));
			Target.SetOperations(std::move(Senders), std::move(Receivers));
			SetWitness(Target);
		}
		void Claim::SetWitness(const Observer::IncomingTransaction& Witness)
		{
			Asset = Witness.Asset;
			SetStatement(Algorithm::Hashing::Hash256i(Witness.TransactionId), Witness.AsMessage());
		}
		Option<Observer::IncomingTransaction> Claim::GetAssertion(const Ledger::TransactionContext* Context) const
		{
			auto* BestBranch = GetCumulativeBranch(Context);
			if (!BestBranch)
				return Optional::None;

			auto Message = BestBranch->Message;
			Message.Seek = 0;

			Observer::IncomingTransaction Assertion;
			if (!Assertion.Load(Message))
				return Optional::None;

			return Assertion;
		}
		UPtr<Schema> Claim::AsSchema() const
		{
			auto Assertion = GetAssertion(nullptr);
			Schema* Data = Ledger::AggregationTransaction::AsSchema().Reset();
			Data->Set("assertion", Assertion ? Assertion->AsSchema().Reset() : Var::Set::Null());
			return Data;
		}
		uint32_t Claim::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Claim::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Claim::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Claim, 144>();
		}
		uint32_t Claim::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Claim::AsInstanceTypename()
		{
			return "claim";
		}

		ExpectsLR<void> Replay::Prevalidate() const
		{
			if (!TransactionHash)
				return LayerException("transaction hash not valid");

			return Ledger::ConsensusTransaction::Prevalidate();
		}
		ExpectsLR<void> Replay::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Parent = Context->GetBlockTransaction<Withdrawal>(TransactionHash);
			if (!Parent)
			{
				Parent = Context->GetBlockTransaction<ContributionMigration>(TransactionHash);
				if (!Parent)
					return Parent.Error();

				auto* ParentTransaction = (ContributionMigration*)*Parent->Transaction;
				if (memcmp(ParentTransaction->Proposer, Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) == 0)
					return LayerException("contribution migration transaction not valid");
			}
			else
			{
				auto* ParentTransaction = (Withdrawal*)*Parent->Transaction;
				if (memcmp(ParentTransaction->Proposer, Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) != 0)
					return LayerException("withdrawal transaction not valid");
			}

			if (Context->GetWitnessEvent(TransactionHash))
				return LayerException("event transaction finalized");

			return Ledger::ConsensusTransaction::Validate(Context);
		}
		ExpectsLR<void> Replay::Execute(Ledger::TransactionContext* Context) const
		{
			auto Event = Context->ApplyWitnessEvent(TransactionHash);
			if (!Event)
				return Event.Error();

			if (!TransactionId.empty())
				return Expectation::Met;

			auto Parent = Context->GetBlockTransaction<Withdrawal>(TransactionHash);
			if (!Parent)
				return Expectation::Met;

			auto* ParentTransaction = (Withdrawal*)*Parent->Transaction;
			if (ParentTransaction->AsType() != Withdrawal::AsInstanceType() || ParentTransaction->To.empty())
				return LayerException("withdrawal transaction not valid");

			auto Collision = Context->GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), ParentTransaction->To.front().first, Protocol::Now().Account.RootAddressIndex, 0);
			if (!Collision || memcmp(Collision->Owner, Context->Receipt.From, sizeof(Collision->Owner)) != 0)
				return LayerException("invalid to address (not owned by sender)");

			auto Value = ParentTransaction->GetTotalValue();
			auto Balance = Context->GetAccountBalance(Parent->Receipt.From);
			auto Reserve = Balance ? Balance->Reserve : Decimal::Zero();
			if (Reserve - Value >= 0.0)
			{
				bool Charges = memcmp(Parent->Receipt.From, ParentTransaction->Proposer, sizeof(Algorithm::Pubkeyhash)) != 0;
				auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
				auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, ParentTransaction->Proposer) : ExpectsLR<States::AccountReward>(LayerException());
				auto BaseFee = (BaseReward ? BaseReward->OutgoingAbsoluteFee : Decimal::Zero());
				if (BaseAsset != Asset && BaseFee.IsPositive())
				{
					auto BaseTransfer = Context->ApplyTransfer(BaseAsset, Parent->Receipt.From, BaseFee, Decimal::Zero());
					if (!BaseTransfer)
						return BaseTransfer.Error();

					BaseTransfer = Context->ApplyTransfer(BaseAsset, ParentTransaction->Proposer, -BaseFee, Decimal::Zero());
					if (!BaseTransfer)
						return BaseTransfer.Error();
				}

				auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, ParentTransaction->Proposer);
				auto TokenFee = (TokenReward ? TokenReward->CalculateOutgoingFee(Value) : Decimal::Zero());
				auto TokenTransfer = Context->ApplyTransfer(Parent->Receipt.From, TokenFee, TokenFee - Value);
				if (!TokenTransfer)
					return TokenTransfer.Error();

				if (TokenFee.IsPositive())
				{
					TokenTransfer = Context->ApplyTransfer(ParentTransaction->Proposer, -TokenFee, Decimal::Zero());
					if (!TokenTransfer)
						return TokenTransfer.Error();
				}
			}
			else
			{
				auto Contribution = Context->ApplyAccountContribution(ParentTransaction->Proposer, Decimal::NaN(), { }, { });
				if (!Contribution)
					return Contribution.Error();
			}

			return Expectation::Met;
		}
		bool Replay::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(TransactionId);
			Stream->WriteString(TransactionData);
			Stream->WriteString(TransactionMessage);
			Stream->WriteInteger(TransactionHash);
			return true;
		}
		bool Replay::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &TransactionId))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &TransactionData))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &TransactionMessage))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionHash))
				return false;

			return true;
		}
		bool Replay::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto Context = Ledger::TransactionContext();
			auto Parent = Context.GetBlockTransactionInstance(TransactionHash);
			if (!Parent)
				return false;

			Parties.insert(String((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)));
			return true;
		}
		void Replay::SetSuccessWitness(const std::string_view& NewTransactionId, const std::string_view& NewTransactionData, const uint256_t& NewTransactionHash)
		{
			TransactionId = NewTransactionId;
			TransactionData = NewTransactionData;
			TransactionMessage.clear();
			TransactionHash = NewTransactionHash;
		}
		void Replay::SetFailureWitness(const std::string_view& NewTransactionMessage, const uint256_t& NewTransactionHash)
		{
			TransactionId.clear();
			TransactionData.clear();
			TransactionMessage = NewTransactionMessage;
			TransactionHash = NewTransactionHash;
		}
		UPtr<Schema> Replay::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(TransactionHash)));
			Data->Set("transaction_id", TransactionId.empty() ? Var::Null() : Var::String(TransactionId));
			Data->Set("transaction_data", TransactionData.empty() ? Var::Null() : Var::String(TransactionData));
			Data->Set("transaction_message", TransactionMessage.empty() ? Var::Null() : Var::String(TransactionMessage));
			return Data;
		}
		uint32_t Replay::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Replay::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t Replay::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<Replay, 32>();
		}
		uint32_t Replay::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Replay::AsInstanceTypename()
		{
			return "replay";
		}

		ExpectsLR<void> AddressAccount::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (Address.empty())
				return LayerException("invalid address");

			return Expectation::Met;
		}
		ExpectsLR<void> AddressAccount::Validate(const Ledger::TransactionContext* Context) const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto PublicKeyHash = Chain->NewPublicKeyHash(Address);
			if (!PublicKeyHash)
				return PublicKeyHash.Error();

			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Collision = Context->GetWitnessAddress(Address, AddressIndex, 0);
			if (Collision)
				return LayerException("account address " + Address + " taken");

			return Expectation::Met;
		}
		ExpectsLR<void> AddressAccount::Execute(Ledger::TransactionContext* Context) const
		{
			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, { { (uint8_t)0, String(Address) } }, AddressIndex, States::WitnessAddress::Class::Router);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
		}
		bool AddressAccount::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Address);
			return true;
		}
		bool AddressAccount::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Address))
				return false;

			return true;
		}
		bool AddressAccount::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			return true;
		}
		void AddressAccount::SetAddress(const std::string_view& NewAddress)
		{
			Address = NewAddress;
		}
		UPtr<Schema> AddressAccount::AsSchema() const
		{
			Schema* Data = Ledger::DelegationTransaction::AsSchema().Reset();
			Data->Set("address", Var::String(Address));
			return Data;
		}
		uint32_t AddressAccount::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AddressAccount::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t AddressAccount::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<AddressAccount, 128>();
		}
		uint32_t AddressAccount::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AddressAccount::AsInstanceTypename()
		{
			return "address_account";
		}

		ExpectsLR<void> PubkeyAccount::SignPubkey(const PrivateKey& SigningKey)
		{
			UPtr<PubkeyAccount> Copy = (PubkeyAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			auto Signature = Observer::Datamaster::SignMessage(Asset, Message.Data, SigningKey);
			if (!Signature)
				return Signature.Error();

			Sighash = std::move(*Signature);
			return Expectation::Met;
		}
		ExpectsLR<void> PubkeyAccount::VerifyPubkey() const
		{
			UPtr<PubkeyAccount> Copy = (PubkeyAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			return Observer::Datamaster::VerifyMessage(Asset, Message.Data, Pubkey, Sighash);
		}
		ExpectsLR<void> PubkeyAccount::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (Pubkey.empty())
				return LayerException("invalid public key");

			if (Sighash.empty())
				return LayerException("invalid public key signature");

			return Ledger::DelegationTransaction::Prevalidate();
		}
		ExpectsLR<void> PubkeyAccount::Validate(const Ledger::TransactionContext* Context) const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto Verification = VerifyPubkey();
			if (!Verification)
				return Verification.Error();

			return Ledger::DelegationTransaction::Validate(Context);
		}
		ExpectsLR<void> PubkeyAccount::Execute(Ledger::TransactionContext* Context) const
		{
			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, VerifyingWallet->Addresses, AddressIndex, States::WitnessAddress::Class::Router);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
		}
		bool PubkeyAccount::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Pubkey);
			Stream->WriteString(Sighash);
			return true;
		}
		bool PubkeyAccount::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Pubkey))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Sighash))
				return false;

			return true;
		}
		bool PubkeyAccount::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			return true;
		}
		void PubkeyAccount::SetPubkey(const std::string_view& VerifyingKey)
		{
			Pubkey = VerifyingKey;
		}
		UPtr<Schema> PubkeyAccount::AsSchema() const
		{
			Schema* Data = Ledger::DelegationTransaction::AsSchema().Reset();
			Data->Set("pubkey", Var::Set::String(Pubkey));
			Data->Set("sighash", Var::String(Format::Util::Encode0xHex(Sighash)));
			return Data;
		}
		uint32_t PubkeyAccount::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view PubkeyAccount::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t PubkeyAccount::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<PubkeyAccount, 128>();
		}
		uint32_t PubkeyAccount::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view PubkeyAccount::AsInstanceTypename()
		{
			return "pubkey_account";
		}

		ExpectsLR<void> DelegationAccount::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Pubkeyhash Null = { 0 };
			if (memcmp(Proposer, Null, sizeof(Null)) == 0)
				return LayerException("invalid account proposer");

			return Ledger::DelegationTransaction::Prevalidate();
		}
		ExpectsLR<void> DelegationAccount::Validate(const Ledger::TransactionContext* Context) const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto WorkRequirement = Context->VerifyAccountWork(Proposer);
			if (!WorkRequirement)
				return WorkRequirement.Error();

			auto Contribution = Context->GetAccountContribution(Proposer);
			Decimal Value = Contribution ? Contribution->GetContribution() : Decimal::Zero();
			Decimal Coverage = Contribution ? Contribution->GetCoverage() : Decimal::Zero();
			double Threshold = Contribution ? Contribution->Threshold.Or(Protocol::Now().Policy.AccountContributionRequired) : Protocol::Now().Policy.AccountContributionRequired;
			bool Honest = Contribution ? Contribution->Honest : true;
			if (Threshold != 0.0 && !Coverage.IsNegative() && !(Value * Threshold).IsPositive())
				return LayerException("contribution is too low for custodian account creation");
			else if (!Honest)
				return LayerException("contribution is not honest");

			switch (Chain->Routing)
			{
				case Observer::RoutingPolicy::Account:
				{
					if (memcmp(Context->Receipt.From, Proposer, sizeof(Proposer)) != 0)
						return LayerException("invalid account proposer");

					return Ledger::DelegationTransaction::Validate(Context);
				}
				case Observer::RoutingPolicy::Memo:
				case Observer::RoutingPolicy::UTXO:
					return Ledger::DelegationTransaction::Validate(Context);
				default:
					return LayerException("invalid operation");
			}
		}
		ExpectsLR<void> DelegationAccount::Execute(Ledger::TransactionContext* Context) const
		{
			return Expectation::Met;
		}
		ExpectsPromiseLR<void> DelegationAccount::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(this->Proposer, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0)
				return ExpectsPromiseLR<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseLR<void>(Expectation::Met);

			UPtr<Transactions::CustodianAccount> Transaction = Memory::New<Transactions::CustodianAccount>();
			Transaction->Asset = Asset;
			Transaction->SetWitness(Context->Receipt.TransactionHash);

			auto Account = Transaction->SetWallet(Proposer, Context->Receipt.From);
			if (!Account)
				return ExpectsPromiseLR<void>(std::move(Account));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool DelegationAccount::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			return true;
		}
		bool DelegationAccount::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			return true;
		}
		bool DelegationAccount::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		void DelegationAccount::SetProposer(const Algorithm::Pubkeyhash NewProposer)
		{
			if (!NewProposer)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Proposer, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Proposer, NewProposer, sizeof(Algorithm::Pubkeyhash));
		}
		bool DelegationAccount::IsProposerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(Proposer, Null, sizeof(Null)) == 0;
		}
		UPtr<Schema> DelegationAccount::AsSchema() const
		{
			Schema* Data = Ledger::DelegationTransaction::AsSchema().Reset();
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			return Data;
		}
		uint32_t DelegationAccount::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view DelegationAccount::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t DelegationAccount::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<DelegationAccount, 16>();
		}
		uint64_t DelegationAccount::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t DelegationAccount::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DelegationAccount::AsInstanceTypename()
		{
			return "delegation_account";
		}

		ExpectsLR<void> CustodianAccount::SetWallet(const Ledger::Wallet& Proposer, const Algorithm::Pubkeyhash NewOwner)
		{
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Ledger::TransactionContext Context;
			auto Derivation = Context.GetAccountDerivation(Asset, Proposer.PublicKeyHash);
			uint64_t AddressIndex = (Derivation ? Derivation->MaxAddressIndex + 1 : Protocol::Now().Account.RootAddressIndex);
			if (Chain->Routing == Observer::RoutingPolicy::Account)
			{
				AddressIndex = Protocol::Now().Account.RootAddressIndex;
				if (Derivation)
					return LayerException("account exists");
				else if (memcmp(NewOwner, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0)
					return LayerException("invalid account owner");
			}

			auto Parent = Observer::Datamaster::NewMasterWallet(Asset, Proposer.SecretKey);
			if (!Parent)
				return LayerException("invalid master wallet");

			auto Child = Observer::Datamaster::NewSigningWallet(Asset, *Parent, AddressIndex);
			if (!Child)
				return Child.Error();

			SetPubkey(Child->VerifyingKey.ExposeToHeap(), AddressIndex);
			SetOwner(NewOwner);
			return SignPubkey(Child->SigningKey);
		}
		ExpectsLR<void> CustodianAccount::SignPubkey(const PrivateKey& SigningKey)
		{
			UPtr<CustodianAccount> Copy = (CustodianAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			auto Signature = Observer::Datamaster::SignMessage(Asset, Message.Data, SigningKey);
			if (!Signature)
				return Signature.Error();

			Sighash = std::move(*Signature);
			return Expectation::Met;
		}
		ExpectsLR<void> CustodianAccount::VerifyPubkey() const
		{
			UPtr<CustodianAccount> Copy = (CustodianAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			return Observer::Datamaster::VerifyMessage(Asset, Message.Data, Pubkey, Sighash);
		}
		ExpectsLR<void> CustodianAccount::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (Pubkey.empty())
				return LayerException("invalid public key");

			if (Sighash.empty())
				return LayerException("invalid public key signature");

			Algorithm::Pubkeyhash Null = { 0 };
			if (!memcmp(Owner, Null, sizeof(Null)))
				return LayerException("invalid owner");

			return Ledger::ConsensusTransaction::Prevalidate();
		}
		ExpectsLR<void> CustodianAccount::Validate(const Ledger::TransactionContext* Context) const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto Verification = VerifyPubkey();
			if (!Verification)
				return Verification.Error();

			auto* Params = Observer::Datamaster::GetChainparams(Asset);
			if (!Params)
				return LayerException("invalid operation");
		
			if (DelegationAccountHash > 0)
			{
				auto Parent = Context->GetBlockTransaction<DelegationAccount>(DelegationAccountHash);
				if (!Parent)
					return Parent.Error();

				auto* ParentTransaction = (DelegationAccount*)*Parent->Transaction;
				if (memcmp(ParentTransaction->Proposer, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
					return LayerException("invalid origin");

				if (Params->Routing == Observer::RoutingPolicy::Account && memcmp(Parent->Receipt.From, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
					return LayerException("invalid account owner");

				if (Context->GetWitnessEvent(DelegationAccountHash))
					return LayerException("event transaction finalized");
			}

			auto Contribution = Context->GetAccountContribution(Context->Receipt.From);
			Decimal Value = Contribution ? Contribution->GetContribution() : Decimal::Zero();
			Decimal Coverage = Contribution ? Contribution->GetCoverage() : Decimal::Zero();
			double Threshold = Contribution ? Contribution->Threshold.Or(Protocol::Now().Policy.AccountContributionRequired) : Protocol::Now().Policy.AccountContributionRequired;
			bool Honest = Contribution ? Contribution->Honest : true;
			if (Threshold != 0.0 && !Coverage.IsNegative() && !(Value * Threshold).IsPositive())
				return LayerException("contribution is too low for custodian account creation");
			else if (!Honest)
				return LayerException("contribution is not honest");

			uint64_t AddressIndex = Params->Routing == Observer::RoutingPolicy::Memo ? PubkeyIndex : Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Collision = Context->GetWitnessAddress(Address.second, AddressIndex, 0);
				if (Collision)
					return LayerException("account address " + Address.second + " taken");
			}

			auto WorkRequirement = Context->VerifyAccountWork(Context->Receipt.From);
			if (!WorkRequirement)
				return WorkRequirement.Error();

			return Ledger::ConsensusTransaction::Validate(Context);
		}
		ExpectsLR<void> CustodianAccount::Execute(Ledger::TransactionContext* Context) const
		{
			if (DelegationAccountHash > 0)
			{
				auto Event = Context->ApplyWitnessEvent(DelegationAccountHash);
				if (!Event)
					return Event.Error();
			}

			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto* Params = Observer::Datamaster::GetChainparams(Asset);
			if (!Params)
				return LayerException("invalid operation");

			uint64_t AddressIndex = Params->Routing == Observer::RoutingPolicy::Memo ? PubkeyIndex : Protocol::Now().Account.RootAddressIndex;
			auto Derivation = Context->GetAccountDerivation(Context->Receipt.From);
			if (!Derivation || Derivation->MaxAddressIndex < AddressIndex)
			{
				auto Status = Context->ApplyAccountDerivation(Context->Receipt.From, AddressIndex);
				if (!Status)
					return Status.Error();
			}

			auto Status = Context->ApplyWitnessAddress(Owner, Context->Receipt.From, VerifyingWallet->Addresses, AddressIndex, States::WitnessAddress::Class::Custodian);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
		}
		ExpectsPromiseLR<void> CustodianAccount::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			auto* Chain = Observer::Datamaster::GetChain(Asset);
			if (!Chain)
				return ExpectsPromiseLR<void>(LayerException("invalid operation"));

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return ExpectsPromiseLR<void>(VerifyingWallet.Error());

			auto* Params = Observer::Datamaster::GetChainparams(Asset);
			if (!Params)
				return ExpectsPromiseLR<void>(LayerException("invalid operation"));

			uint64_t AddressIndex = Params->Routing == Observer::RoutingPolicy::Memo ? PubkeyIndex : Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Status = Observer::Datamaster::EnableWalletAddress(Asset, std::string_view((char*)Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)), Address.second, AddressIndex);
				if (!Status)
					return ExpectsPromiseLR<void>(Status.Error());
			}

			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool CustodianAccount::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(DelegationAccountHash);
			Stream->WriteInteger(PubkeyIndex);
			Stream->WriteString(Pubkey);
			Stream->WriteString(Sighash);
			return true;
		}
		bool CustodianAccount::LoadBody(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &DelegationAccountHash))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &PubkeyIndex))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Pubkey))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Sighash))
				return false;

			return true;
		}
		bool CustodianAccount::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Owner, sizeof(Owner)));
			return true;
		}
		void CustodianAccount::SetWitness(const uint256_t& NewDelegationAccountHash)
		{
			DelegationAccountHash = NewDelegationAccountHash;
		}
		void CustodianAccount::SetPubkey(const std::string_view& VerifyingKey, uint64_t NewPubkeyIndex)
		{
			Pubkey = VerifyingKey;
			PubkeyIndex = NewPubkeyIndex;
		}
		void CustodianAccount::SetOwner(const Algorithm::Pubkeyhash NewOwner)
		{
			if (!NewOwner)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Owner, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Owner, NewOwner, sizeof(Algorithm::Pubkeyhash));
		}
		bool CustodianAccount::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(Owner, Null, sizeof(Null)) == 0;
		}
		UPtr<Schema> CustodianAccount::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("delegation_account_hash", DelegationAccountHash > 0 ? Var::String(Algorithm::Encoding::Encode0xHex256(DelegationAccountHash)) : Var::Null());
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("pubkey_index", Var::Integer(PubkeyIndex));
			Data->Set("pubkey", Var::String(Pubkey));
			Data->Set("sighash", Var::String(Format::Util::Encode0xHex(Sighash)));
			return Data;
		}
		uint32_t CustodianAccount::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view CustodianAccount::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t CustodianAccount::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<CustodianAccount, 128>();
		}
		uint64_t CustodianAccount::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t CustodianAccount::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view CustodianAccount::AsInstanceTypename()
		{
			return "custodian_account";
		}

		ExpectsLR<void> ContributionAllocation::SetShare1(const Algorithm::Seckey SecretKey)
		{
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Algorithm::Composition::CSeckey SecretKey1;
			auto Status = Algorithm::Composition::DeriveKeypair1(Chain->Composition, SecretKey1, PublicKey1);
			if (!Status)
				return Status;

			Algorithm::Signing::DeriveSealingKey(SecretKey, SealingKey1);
			EncryptedSecretKey1For1 = Algorithm::Signing::PublicEncrypt(SealingKey1, std::string_view((char*)SecretKey1, sizeof(SecretKey1))).Or(String());
			if (EncryptedSecretKey1For1.empty())
				return LayerException("invalid sealing secret");

			return Expectation::Met;
		}
		ExpectsLR<void> ContributionAllocation::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Composition::CPubkey Null = { 0 };
			if (!memcmp(PublicKey1, Null, sizeof(Null)))
				return LayerException("invalid public key 1");

			if (EncryptedSecretKey1For1.empty())
				return LayerException("invalid encrypted secret key 1");

			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Algorithm::Pubkey PublicKey;
			Algorithm::Composition::CSeckey SecretKey2;
			Algorithm::Composition::CPubkey PublicKey2;
			auto Status = Algorithm::Composition::DeriveKeypair2(Chain->Composition, PublicKey1, SecretKey2, PublicKey2, PublicKey, nullptr);
			if (!Status)
				return LayerException("invalid operation");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> ContributionAllocation::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Work = Context->VerifyAccountWork();
			if (!Work)
				return Work;

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> ContributionAllocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Work = Context->CalculateSharingWitness({ String((char*)Context->Receipt.From, sizeof(Context->Receipt.From)) }, true);
			if (!Work)
				return Work.Error();

			return Context->EmitEvent<ContributionAllocation>({ Format::Variable(std::string_view((char*)Work->Owner, sizeof(Work->Owner))) });
		}
		ExpectsPromiseLR<void> ContributionAllocation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			OrderedSet<String> Parties;
			if (!RecoverAlt(Context->Receipt, Parties) || Parties.empty())
				return ExpectsPromiseLR<void>(LayerException("transaction receipt does not have a proposer"));

			Algorithm::Pubkeyhash Chosen = { 0 };
			memcpy(Chosen, Parties.begin()->data(), sizeof(Chosen));
			if (memcmp(Chosen, Proposer.PublicKeyHash, sizeof(Chosen)) != 0)
				return ExpectsPromiseLR<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseLR<void>(Expectation::Met);

			UPtr<Transactions::ContributionActivation> Transaction = Memory::New<Transactions::ContributionActivation>();
			Transaction->Asset = Asset;
			Transaction->SetWitness(Context->Receipt.TransactionHash);

			auto Status = Transaction->SetShare2(Proposer.SecretKey, PublicKey1);
			if (!Status)
				return ExpectsPromiseLR<void>(Status.Error());

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool ContributionAllocation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkey PubNull = { 0 };
			Algorithm::Composition::CPubkey CPubNull = { 0 };
			Stream->WriteString(std::string_view((char*)SealingKey1, memcmp(SealingKey1, PubNull, sizeof(PubNull)) == 0 ? 0 : sizeof(SealingKey1)));
			Stream->WriteString(std::string_view((char*)PublicKey1, memcmp(PublicKey1, CPubNull, sizeof(CPubNull)) == 0 ? 0 : sizeof(PublicKey1)));
			Stream->WriteString(EncryptedSecretKey1For1);
			return true;
		}
		bool ContributionAllocation::LoadBody(Format::Stream& Stream)
		{
			String SealingKey1Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &SealingKey1Assembly) || !Algorithm::Encoding::DecodeUintBlob(SealingKey1Assembly, SealingKey1, sizeof(SealingKey1)))
				return false;

			String PublicKey1Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKey1Assembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKey1Assembly, PublicKey1, sizeof(PublicKey1)))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &EncryptedSecretKey1For1))
				return false;

			return true;
		}
		bool ContributionAllocation::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto* Event = Receipt.FindEvent<ContributionAllocation>();
			if (!Event || Event->size() != 1 || Event->front().AsString().size() != sizeof(Algorithm::Pubkeyhash))
				return false;

			Parties.insert(Event->front().AsBlob());
			return true;
		}
		Option<String> ContributionAllocation::GetSecretKey1(const Algorithm::Seckey SecretKey) const
		{
			return Algorithm::Signing::PrivateDecrypt(SecretKey, EncryptedSecretKey1For1);
		}
		UPtr<Schema> ContributionAllocation::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("sealing_key_1", Algorithm::Signing::SerializeSealingKey(SealingKey1));
			Data->Set("public_key_1", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKey1, sizeof(PublicKey1)))));
			Data->Set("encrypted_secret_key_1_for_1", Var::String(Format::Util::Encode0xHex(EncryptedSecretKey1For1)));
			return Data;
		}
		uint32_t ContributionAllocation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionAllocation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionAllocation::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionAllocation, 36>();
		}
		uint64_t ContributionAllocation::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionAllocation::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionAllocation::AsInstanceTypename()
		{
			return "contribution_allocation";
		}

		ExpectsLR<void> ContributionActivation::SetShare2(const Algorithm::Seckey SecretKey, const Algorithm::Composition::CPubkey PublicKey1)
		{
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			size_t PublicKeySize32 = 0;
			Algorithm::Composition::CSeckey SecretKey2;
			auto Status = Algorithm::Composition::DeriveKeypair2(Chain->Composition, PublicKey1, SecretKey2, PublicKey2, PublicKey, &PublicKeySize32);
			if (!Status)
				return LayerException("invalid message");

			PublicKeySize = (uint16_t)PublicKeySize32;
			Algorithm::Signing::DeriveSealingKey(SecretKey, SealingKey2);
			EncryptedSecretKey2For2 = Algorithm::Signing::PublicEncrypt(SealingKey2, std::string_view((char*)SecretKey2, sizeof(SecretKey2))).Or(String());
			if (EncryptedSecretKey2For2.empty())
				return LayerException("invalid sealing secret");

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			return Expectation::Met;
		}
		ExpectsLR<void> ContributionActivation::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Pubkey PubNull = { 0 };
			if (!memcmp(PublicKey, PubNull, sizeof(PubNull)) || !PublicKeySize || PublicKeySize > sizeof(PublicKey))
				return LayerException("invalid public key");

			Algorithm::Composition::CPubkey CPubNull = { 0 };
			if (!memcmp(PublicKey2, CPubNull, sizeof(CPubNull)))
				return LayerException("invalid public key 2");

			if (EncryptedSecretKey2For2.empty())
				return LayerException("invalid encrypted secret key 2");

			if (!ContributionAllocationHash)
				return LayerException("invalid parent transaction");

			return Ledger::ConsensusTransaction::Prevalidate();
		}
		ExpectsLR<void> ContributionActivation::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Parent)
				return Parent.Error();
			
			if (!memcmp(Parent->Receipt.From, Context->Receipt.From, sizeof(Context->Receipt.From)))
				return LayerException("invalid origin");

			if (Context->GetWitnessEvent(ContributionAllocationHash))
				return LayerException("event transaction finalized");

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Collision = Context->GetWitnessAddress(Address.second, AddressIndex, 0);
				if (Collision)
					return LayerException("address " + Address.second + " taken");
			}

			return Ledger::ConsensusTransaction::Validate(Context);
		}
		ExpectsLR<void> ContributionActivation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Event = Context->ApplyWitnessEvent(ContributionAllocationHash);
			if (!Event)
				return Event.Error();

			auto Parent = Context->GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Parent)
				return Parent.Error();

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(Parent->Receipt.From, Parent->Receipt.From, VerifyingWallet->Addresses, AddressIndex, States::WitnessAddress::Class::Contribution);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
		}
		ExpectsPromiseLR<void> ContributionActivation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Parent)
				return ExpectsPromiseLR<void>(Parent.Error());

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return ExpectsPromiseLR<void>(VerifyingWallet.Error());

			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Status = Observer::Datamaster::EnableWalletAddress(Asset, std::string_view((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)), Address.second, AddressIndex);
				if (!Status)
					return ExpectsPromiseLR<void>(Status.Error());
			}

			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool ContributionActivation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkey PubNull = { 0 };
			Algorithm::Pubkeyhash PkhNull = { 0 };
			Algorithm::Composition::CPubkey CPubNull = { 0 };
			Algorithm::Composition::CSeckey CSecNull = { 0 };
			Stream->WriteString(std::string_view((char*)PublicKey, memcmp(PublicKey, PubNull, sizeof(PubNull)) == 0 ? 0 : sizeof(PublicKey)));
			Stream->WriteString(std::string_view((char*)SealingKey2, memcmp(SealingKey2, PubNull, sizeof(PubNull)) == 0 ? 0 : sizeof(SealingKey2)));
			Stream->WriteString(std::string_view((char*)PublicKey2, memcmp(PublicKey2, CPubNull, sizeof(CPubNull)) == 0 ? 0 : sizeof(PublicKey2)));
			Stream->WriteString(EncryptedSecretKey2For2);
			Stream->WriteInteger(PublicKeySize);
			Stream->WriteInteger(ContributionAllocationHash);
			return true;
		}
		bool ContributionActivation::LoadBody(Format::Stream& Stream)
		{
			String PublicKeyAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKeyAssembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKeyAssembly, PublicKey, sizeof(PublicKey)))
				return false;

			String SealingKey2Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &SealingKey2Assembly) || !Algorithm::Encoding::DecodeUintBlob(SealingKey2Assembly, SealingKey2, sizeof(SealingKey2)))
				return false;

			String PublicKey2Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKey2Assembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKey2Assembly, PublicKey2, sizeof(PublicKey2)))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &EncryptedSecretKey2For2))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &PublicKeySize))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionAllocationHash))
				return false;

			return true;
		}
		void ContributionActivation::SetWitness(const uint256_t& NewContributionAllocationHash)
		{
			ContributionAllocationHash = NewContributionAllocationHash;
		}
		bool ContributionActivation::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto Context = Ledger::TransactionContext();
			auto Parent = Context.GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Parent)
				return false;

			Parties.insert(String((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)));
			return true;
		}
		Option<String> ContributionActivation::GetSecretKey2(const Algorithm::Seckey SecretKey) const
		{
			return Algorithm::Signing::PrivateDecrypt(SecretKey, EncryptedSecretKey2For2);
		}
		ExpectsLR<Observer::DerivedVerifyingWallet> ContributionActivation::GetVerifyingWallet() const
		{
			return Observer::Datamaster::NewVerifyingWallet(Asset, std::string_view((char*)PublicKey, PublicKeySize));
		}
		UPtr<Schema> ContributionActivation::AsSchema() const
		{
			auto VerifyingWallet = GetVerifyingWallet();
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("sealing_key_2", Algorithm::Signing::SerializeSealingKey(SealingKey2));
			Data->Set("public_key_2", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKey2, sizeof(PublicKey2)))));
			Data->Set("encrypted_secret_key_2_for_2", Var::String(Format::Util::Encode0xHex(EncryptedSecretKey2For2)));
			Data->Set("contribution_allocation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionAllocationHash)));
			Data->Set("contribution_wallet", VerifyingWallet ? VerifyingWallet->AsSchema().Reset() : Var::Set::Null());
			return Data;
		}
		uint32_t ContributionActivation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionActivation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionActivation::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionActivation, 96>();
		}
		uint64_t ContributionActivation::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionActivation::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionActivation::AsInstanceTypename()
		{
			return "contribution_activation";
		}

		ExpectsLR<void> ContributionDeallocation::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (!ContributionActivationHash)
				return LayerException("invalid parent transaction");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> ContributionDeallocation::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Parent)
				return Parent.Error();

			auto* ParentTransaction = (ContributionActivation*)*Parent->Transaction;
			auto Initiator = Context->GetBlockTransaction<ContributionAllocation>(ParentTransaction->ContributionAllocationHash);
			if (!Initiator)
				return Initiator.Error();

			if (memcmp(Initiator->Receipt.From, Context->Receipt.From, sizeof(Parent->Receipt.From)) != 0)
				return LayerException("invalid transaction owner");

			auto Work = Context->VerifyAccountWork();
			if (!Work)
				return Work;

			auto Contribution = Context->GetAccountContribution(Context->Receipt.From);
			if (!Contribution)
				return Ledger::Transaction::Validate(Context);
			else if (!Contribution->Honest)
				return LayerException("contribution is not honest");

			auto Wallet = ParentTransaction->GetVerifyingWallet();
			if (!Wallet)
				return Wallet.Error();

			for (auto& Address : Wallet->Addresses)
				Contribution->Contributions.erase(Address.second);

			auto Coverage = Contribution->GetCoverage();
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("contribution change does not cover balance (contribution: " + Contribution->GetContribution().ToString() + ", custody: " + Contribution->Custody.ToString() + ")");
			
			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> ContributionDeallocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Parent)
				return Parent.Error();

			auto* ParentTransaction = (ContributionActivation*)*Parent->Transaction;
			auto Wallet = ParentTransaction->GetVerifyingWallet();
			if (!Wallet)
				return Wallet.Error();

			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Algorithm::Pubkeyhash Null = { 0 };
			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(Context->Receipt.From, Null, Wallet->Addresses, AddressIndex, States::WitnessAddress::Class::Witness);
			if (!Status)
				return Status.Error();

			auto Contribution = Context->GetAccountContribution(Context->Receipt.From);
			if (!Contribution)
				return Expectation::Met;

			for (auto& Address : Wallet->Addresses)
			{
				auto Value = Contribution->GetContribution(Address.second);
				if (Value.IsPositive())
				{
					auto Transfer = Context->ApplyAccountContribution(Context->Receipt.From, Decimal::Zero(), { { Address.second, -Value } }, { });
					if (!Transfer)
						return Transfer.Error();
				}
				Contribution->Contributions.erase(Address.second);
			}

			auto Resignation = Context->Store(Contribution.Address());
			if (!Resignation)
				return Resignation.Error();

			return Expectation::Met;
		}
		ExpectsPromiseLR<void> ContributionDeallocation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Parent)
				return ExpectsPromiseLR<void>(Parent.Error());

			if (memcmp(Parent->Receipt.From, Proposer.PublicKeyHash, sizeof(Parent->Receipt.From)) != 0)
				return ExpectsPromiseLR<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseLR<void>(Expectation::Met);

			UPtr<Transactions::ContributionDeactivation> Transaction = Memory::New<Transactions::ContributionDeactivation>();
			Transaction->Asset = Asset;

			auto Status = Transaction->SetRevealingShare2(Context->Receipt.TransactionHash, Proposer.SecretKey);
			if (!Status)
				return ExpectsPromiseLR<void>(Status.Error());

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool ContributionDeallocation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(ContributionActivationHash);
			return true;
		}
		bool ContributionDeallocation::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionActivationHash))
				return false;

			return true;
		}
		bool ContributionDeallocation::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto Context = Ledger::TransactionContext();
			auto Parent = Context.GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Parent)
				return false;

			Parties.insert(String((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)));
			return true;
		}
		void ContributionDeallocation::SetWitness(const uint256_t& NewContributionActivationHash)
		{
			ContributionActivationHash = NewContributionActivationHash;
		}
		UPtr<Schema> ContributionDeallocation::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("contribution_activation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionActivationHash)));
			return Data;
		}
		uint32_t ContributionDeallocation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionDeallocation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionDeallocation::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionDeallocation, 64>();
		}
		uint64_t ContributionDeallocation::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionDeallocation::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionDeallocation::AsInstanceTypename()
		{
			return "contribution_deallocation";
		}

		ExpectsLR<void> ContributionDeactivation::SetRevealingShare2(const uint256_t& NewContributionDeallocationHash, const Algorithm::Seckey SecretKey)
		{
			Algorithm::Pubkey SealingKey2;
			ContributionDeallocationHash = NewContributionDeallocationHash;
			Algorithm::Signing::DeriveSealingKey(SecretKey, SealingKey2);

			Ledger::TransactionContext Context;
			auto Parent = Context.GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Parent)
				return Parent.Error();

			auto* ParentTransaction = (ContributionDeallocation*)*Parent->Transaction;
			auto Initiator = Context.GetBlockTransaction<ContributionActivation>(ParentTransaction->ContributionActivationHash);
			if (!Initiator)
				return Initiator.Error();

			auto* InitiatorTransaction = (ContributionActivation*)*Initiator->Transaction;
			if (memcmp(SealingKey2, InitiatorTransaction->SealingKey2, sizeof(SealingKey2)) != 0)
				return LayerException("invalid secret key");

			auto Origin = Context.GetBlockTransaction<ContributionAllocation>(InitiatorTransaction->ContributionAllocationHash);
			if (!Origin)
				return Origin.Error();

			String SecretKey2 = Algorithm::Signing::PrivateDecrypt(SecretKey, InitiatorTransaction->EncryptedSecretKey2For2).Or(String());
			if (SecretKey2.empty())
				return LayerException("invalid sealing secret");

			auto* OriginTransaction = (ContributionAllocation*)*Origin->Transaction;
			EncryptedSecretKey2For1 = Algorithm::Signing::PublicEncrypt(OriginTransaction->SealingKey1, SecretKey2).Or(String());
			if (EncryptedSecretKey2For1.empty())
				return LayerException("invalid sealing secret");

			return Expectation::Met;
		}
		ExpectsLR<void> ContributionDeactivation::Prevalidate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (!ContributionDeallocationHash)
				return LayerException("invalid parent transaction");

			if (EncryptedSecretKey2For1.empty())
				return LayerException("invalid encrypted secret key 2");

			return Ledger::ConsensusTransaction::Prevalidate();
		}
		ExpectsLR<void> ContributionDeactivation::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Parent = Context->GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Parent)
				return Parent.Error();

			if (memcmp(Parent->Receipt.From, Context->Receipt.From, sizeof(Parent->Receipt.From)) == 0)
				return LayerException("invalid transaction owner");

			if (Context->GetWitnessEvent(ContributionDeallocationHash))
				return LayerException("event transaction finalized");

			return Ledger::ConsensusTransaction::Validate(Context);
		}
		ExpectsLR<void> ContributionDeactivation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Event = Context->ApplyWitnessEvent(ContributionDeallocationHash);
			if (!Event)
				return Event.Error();

			return Expectation::Met;
		}
		bool ContributionDeactivation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(ContributionDeallocationHash);
			Stream->WriteString(EncryptedSecretKey2For1);
			return true;
		}
		bool ContributionDeactivation::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionDeallocationHash))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &EncryptedSecretKey2For1))
				return false;

			return true;
		}
		bool ContributionDeactivation::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto Context = Ledger::TransactionContext();
			auto Parent = Context.GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Parent)
				return false;

			Parties.insert(String((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)));
			return true;
		}
		Option<String> ContributionDeactivation::GetSecretKey1(const Algorithm::Seckey SecretKey) const
		{
			Ledger::TransactionContext Context;
			auto Parent = Context.GetBlockTransaction<ContributionActivation>(ContributionDeallocationHash);
			if (!Parent)
				return Optional::None;

			auto* ParentTransaction = (ContributionActivation*)*Parent->Transaction;
			auto Origin = Context.GetBlockTransaction<ContributionAllocation>(ParentTransaction->ContributionAllocationHash);
			if (!Origin)
				return Optional::None;

			auto* OriginTransaction = (ContributionAllocation*)*Origin->Transaction;
			return Algorithm::Signing::PrivateDecrypt(SecretKey, OriginTransaction->EncryptedSecretKey1For1);
		}
		Option<String> ContributionDeactivation::GetSecretKey2(const Algorithm::Seckey SecretKey) const
		{
			return Algorithm::Signing::PrivateDecrypt(SecretKey, EncryptedSecretKey2For1);
		}
		ExpectsLR<Observer::DerivedSigningWallet> ContributionDeactivation::GetSigningWallet(const Algorithm::Seckey SecretKey) const
		{
			auto* Chain = Observer::Datamaster::GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Ledger::TransactionContext Context;
			auto Parent = Context.GetBlockTransaction<ContributionActivation>(ContributionDeallocationHash);
			if (!Parent)
				return Parent.Error();

			auto* ParentTransaction = (ContributionActivation*)*Parent->Transaction;
			auto VerifyingWallet = ParentTransaction->GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto Origin = Context.GetBlockTransaction<ContributionAllocation>(ParentTransaction->ContributionAllocationHash);
			if (!Origin)
				return Origin.Error();

			auto* OriginTransaction = (ContributionAllocation*)*Origin->Transaction;
			auto SecretKey1 = Algorithm::Signing::PrivateDecrypt(SecretKey, OriginTransaction->EncryptedSecretKey1For1);
			if (!SecretKey1)
				return LayerException("invalid secret key 1");

			auto SecretKey2 = Algorithm::Signing::PrivateDecrypt(SecretKey, EncryptedSecretKey2For1);
			if (!SecretKey2)
				return LayerException("invalid secret key 2");

			size_t SharedSecretKeySize = 0;
			Algorithm::Composition::CSeckey SharedSecretKey;
			auto Status = Algorithm::Composition::DeriveSecretKey(Chain->Composition, (uint8_t*)SecretKey1->data(), (uint8_t*)SecretKey2->data(), SharedSecretKey, &SharedSecretKeySize);
			if (!Status)
				return LayerException("invalid message");

			auto SigningWallet = Observer::Datamaster::NewSigningWallet(Asset, std::string_view((char*)SharedSecretKey, SharedSecretKeySize));
			if (SigningWallet && SigningWallet->VerifyingKey.ExposeToHeap() != VerifyingWallet->VerifyingKey.ExposeToHeap())
				return LayerException("signing wallet public key does not match verifying wallet public key");

			return SigningWallet;
		}
		UPtr<Schema> ContributionDeactivation::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("contribution_deallocation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionDeallocationHash)));
			Data->Set("encrypted_secret_key_2_for_1", Var::String(Format::Util::Encode0xHex(EncryptedSecretKey2For1)));
			return Data;
		}
		uint32_t ContributionDeactivation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionDeactivation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionDeactivation::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionDeactivation, 52>();
		}
		uint32_t ContributionDeactivation::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionDeactivation::AsInstanceTypename()
		{
			return "contribution_deactivation";
		}

		ExpectsLR<void> ContributionAdjustment::Prevalidate() const
		{
			if (IncomingAbsoluteFee.IsNaN() || IncomingAbsoluteFee.IsNegative())
				return LayerException("invalid incoming absolute fee");

			if (IncomingRelativeFee.IsNaN() || IncomingRelativeFee.IsNegative() || IncomingRelativeFee > 1.0)
				return LayerException("invalid incoming relative fee");

			if (OutgoingAbsoluteFee.IsNaN() || OutgoingAbsoluteFee.IsNegative())
				return LayerException("invalid outgoing absolute fee");

			if (OutgoingRelativeFee.IsNaN() || OutgoingRelativeFee.IsNegative() || OutgoingRelativeFee > 1.0)
				return LayerException("invalid outgoing relative fee");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> ContributionAdjustment::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Work = Context->VerifyAccountWork();
			if (!Work)
				return Work;

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> ContributionAdjustment::Execute(Ledger::TransactionContext* Context) const
		{
			auto Reward = Context->ApplyAccountReward(Context->Receipt.From, IncomingAbsoluteFee, IncomingRelativeFee, OutgoingAbsoluteFee, OutgoingRelativeFee);
			if (!Reward)
				return Reward.Error();

			return Expectation::Met;
		}
		bool ContributionAdjustment::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteDecimal(IncomingAbsoluteFee);
			Stream->WriteDecimal(IncomingRelativeFee);
			Stream->WriteDecimal(OutgoingAbsoluteFee);
			Stream->WriteDecimal(OutgoingRelativeFee);
			return true;
		}
		bool ContributionAdjustment::LoadBody(Format::Stream& Stream)
		{
			if (!Stream.ReadDecimal(Stream.ReadType(), &IncomingAbsoluteFee))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &IncomingRelativeFee))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &OutgoingAbsoluteFee))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &OutgoingRelativeFee))
				return false;

			return true;
		}
		bool ContributionAdjustment::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			return true;
		}
		void ContributionAdjustment::SetIncomingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee)
		{
			IncomingAbsoluteFee = AbsoluteFee;
			IncomingRelativeFee = RelativeFee;
		}
		void ContributionAdjustment::SetOutgoingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee)
		{
			OutgoingAbsoluteFee = AbsoluteFee;
			OutgoingRelativeFee = RelativeFee;
		}
		UPtr<Schema> ContributionAdjustment::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("incoming_absolute_fee", Var::Decimal(IncomingAbsoluteFee));
			Data->Set("incoming_relative_fee", Var::Decimal(IncomingRelativeFee));
			Data->Set("outgoing_absolute_fee", Var::Decimal(OutgoingAbsoluteFee));
			Data->Set("outgoing_relative_fee", Var::Decimal(OutgoingRelativeFee));
			return Data;
		}
		uint32_t ContributionAdjustment::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionAdjustment::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionAdjustment::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionAdjustment, 20>();
		}
		uint32_t ContributionAdjustment::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionAdjustment::AsInstanceTypename()
		{
			return "contribution_adjustment";
		}

		ExpectsLR<void> ContributionAllowance::Prevalidate() const
		{
			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> ContributionAllowance::Validate(const Ledger::TransactionContext* Context) const
		{
			auto Work = Context->VerifyAccountWork();
			if (!Work)
				return Work;

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> ContributionAllowance::Execute(Ledger::TransactionContext* Context) const
		{
			auto CurrentContribution = Context->GetAccountContribution(Context->Receipt.From);
			auto CurrentThreshold = (CurrentContribution ? CurrentContribution->Threshold.Or(-1.0) : -1.0);
			if (CurrentThreshold < 0.0 && Context->Block->Number > 1)
				return LayerException("invalid contribution migration");
			else if (CurrentThreshold < 0.0 && Threshold == Protocol::Now().Policy.AccountContributionRequired)
				return Expectation::Met;

			if (!IsToNull())
			{
				auto FromContribution = Context->ApplyAccountContribution(Context->Receipt.From, Decimal::Zero(), { }, { }, -1.0);
				if (!FromContribution)
					return FromContribution.Error();

				auto ToContribution = Context->ApplyAccountContribution(To, Decimal::Zero(), { }, { }, Threshold);
				if (!ToContribution)
					return ToContribution.Error();
			}
			else
			{
				auto Contribution = Context->ApplyAccountContribution(Context->Receipt.From, Decimal::Zero(), { }, { }, Threshold);
				if (!Contribution)
					return Contribution.Error();
			}

			return Expectation::Met;
		}
		bool ContributionAllowance::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)To, memcmp(To, Null, sizeof(Null)) == 0 ? 0 : sizeof(To)));
			Stream->WriteDecimal(Decimal(Threshold));
			return true;
		}
		bool ContributionAllowance::LoadBody(Format::Stream& Stream)
		{
			String ToAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ToAssembly) || !Algorithm::Encoding::DecodeUintBlob(ToAssembly, To, sizeof(To)))
				return false;

			Decimal ThresholdValue;
			if (!Stream.ReadDecimal(Stream.ReadType(), &ThresholdValue))
				return false;

			Threshold = ThresholdValue.ToDouble();
			return true;
		}
		bool ContributionAllowance::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			return true;
		}
		void ContributionAllowance::SetThreshold(const Algorithm::Pubkeyhash NewTo, double NewThreshold)
		{
			Threshold = std::max(-1.0, NewThreshold);
			if (!NewTo)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(To, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(To, NewTo, sizeof(Algorithm::Pubkeyhash));
		}
		void ContributionAllowance::ClearThreshold(const Algorithm::Pubkeyhash NewTo)
		{
			return SetThreshold(NewTo, -1.0);
		}
		bool ContributionAllowance::IsToNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(To, Null, sizeof(Null)) == 0;
		}
		UPtr<Schema> ContributionAllowance::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("to", Algorithm::Signing::SerializeAddress(To));
			Data->Set("threshold", Var::Number(Threshold));
			return Data;
		}
		uint32_t ContributionAllowance::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionAllowance::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionAllowance::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionAllowance, 20>();
		}
		uint32_t ContributionAllowance::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionAllowance::AsInstanceTypename()
		{
			return "contribution_allowance";
		}

		ExpectsLR<void> ContributionMigration::Prevalidate() const
		{
			if (IsProposerNull())
				return LayerException("invalid proposer");

			if (!Value.IsPositive())
				return LayerException("invalid to value");

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> ContributionMigration::Validate(const Ledger::TransactionContext* Context) const
		{
			if (!memcmp(Context->Receipt.From, Proposer, sizeof(Proposer)))
				return LayerException("self migration not allowed");

			auto Work = Context->VerifyAccountWork();
			if (!Work)
				return Work;

			auto Contribution = Context->GetAccountContribution(Context->Receipt.From);
			if (!Contribution)
				return LayerException("proposer has no contribution");

			auto Coverage = Contribution->GetCoverage();
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("proposer does not cover balance (contribution: " + Contribution->GetContribution().ToString() + ", custody: " + Contribution->Custody.ToString() + ")");
			else if (Contribution->Custody < Value)
				return LayerException("proposer does not have enough custody (value: " + Value.ToString() + ", custody: " + Contribution->Custody.ToString() + ")");

			Contribution = Context->GetAccountContribution(Proposer);
			if (!Contribution)
				return LayerException("migration proposer has no contribution");
			
			Contribution->Custody += Value;
			Coverage = Contribution->GetCoverage();
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("migration proposer does not cover balance (contribution: " + Contribution->GetContribution().ToString() + ", custody: " + Contribution->Custody.ToString() + ")");

			auto Address = GetDestination(Context);
			if (!Address)
				return LayerException("migration proposer has no usable custodian address");

			return Ledger::Transaction::Validate(Context);
		}
		ExpectsLR<void> ContributionMigration::Execute(Ledger::TransactionContext* Context) const
		{
			return Expectation::Met;
		}
		ExpectsPromiseLR<void> ContributionMigration::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(Proposer.PublicKeyHash, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
				return ExpectsPromiseLR<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseLR<void>(Expectation::Met);

			auto Address = GetDestination(Context);
			if (!Address)
				return ExpectsPromiseLR<void>(LayerException("migration proposer has no usable custodian address"));

			auto* Transaction = Memory::New<Transactions::Replay>();
			Transaction->Asset = Asset;
			Pipeline->push_back(Transaction);

			auto Destinations = { Observer::Transferer(Address->Addresses.begin()->second, Address->AddressIndex, Decimal(Value)) };
			return EmitTransaction(Proposer, Asset, Context->Receipt.TransactionHash, Pipeline, std::move(Destinations)).Then<ExpectsLR<void>>([this, Context, Pipeline, Transaction](ExpectsLR<Observer::OutgoingTransaction>&& Result)
			{
				if (!Result || Result->Transaction.TransactionId.empty())
					Transaction->SetFailureWitness(Result ? "transaction broadcast failed" : Result.What(), Context->Receipt.TransactionHash);
				else
					Transaction->SetSuccessWitness(Result->Transaction.TransactionId, Result->Data, Context->Receipt.TransactionHash);
				return ExpectsLR<void>(Expectation::Met);
			});
		}
		bool ContributionMigration::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteDecimal(Value);
			return true;
		}
		bool ContributionMigration::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Value))
				return false;

			return true;
		}
		bool ContributionMigration::RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			if (!IsProposerNull())
				Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		void ContributionMigration::SetProposer(const Algorithm::Pubkeyhash NewProposer, const Decimal& NewValue)
		{
			Value = NewValue;
			if (!NewProposer)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Proposer, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Proposer, NewProposer, sizeof(Algorithm::Pubkeyhash));
		}
		bool ContributionMigration::IsProposerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(Proposer, Null, sizeof(Null)) == 0;
		}
		ExpectsLR<States::WitnessAddress> ContributionMigration::GetDestination(const Ledger::TransactionContext* Context) const
		{
			size_t Offset = 0;
			auto Address = ExpectsLR<States::WitnessAddress>(LayerException());
			while (true)
			{
				auto Addresses = Context->GetWitnessAddresses(Proposer, Offset, 16);
				if (!Addresses)
					return Addresses.Error();
				else if (Addresses->empty())
					return LayerException("destination not found");

				Offset += Addresses->size();
				auto It = std::find_if(Addresses->begin(), Addresses->end(), [&](States::WitnessAddress& Item) { return Item.IsCustodianAddress() && !memcmp(Item.Proposer, Proposer, sizeof(Proposer)) && Item.Asset == Asset; });
				if (It != Addresses->end())
				{
					Address = std::move(*It);
					break;
				}
			}
			return Address;
		}
		UPtr<Schema> ContributionMigration::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			Data->Set("value", Var::Decimal(Value));
			return Data;
		}
		uint32_t ContributionMigration::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionMigration::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionMigration::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionMigration, 64>();
		}
		uint64_t ContributionMigration::GetDispatchOffset() const
		{
			return Protocol::Now().User.Observer.WithdrawalTime / Protocol::Now().Policy.ConsensusProofTime;
		}
		uint32_t ContributionMigration::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionMigration::AsInstanceTypename()
		{
			return "contribution_migration";
		}

		Ledger::Transaction* Resolver::New(uint32_t Hash)
		{
			if (Hash == Transfer::AsInstanceType())
				return Memory::New<Transfer>();
			else if (Hash == Omnitransfer::AsInstanceType())
				return Memory::New<Omnitransfer>();
			else if (Hash == Deployment::AsInstanceType())
				return Memory::New<Deployment>();
			else if (Hash == Invocation::AsInstanceType())
				return Memory::New<Invocation>();
			else if (Hash == Withdrawal::AsInstanceType())
				return Memory::New<Withdrawal>();
			else if (Hash == Rollup::AsInstanceType())
				return Memory::New<Rollup>();
			else if (Hash == AddressAccount::AsInstanceType())
				return Memory::New<AddressAccount>();
			else if (Hash == PubkeyAccount::AsInstanceType())
				return Memory::New<PubkeyAccount>();
			else if (Hash == DelegationAccount::AsInstanceType())
				return Memory::New<DelegationAccount>();
			else if (Hash == CustodianAccount::AsInstanceType())
				return Memory::New<CustodianAccount>();
			else if (Hash == Commitment::AsInstanceType())
				return Memory::New<Commitment>();
			else if (Hash == Replay::AsInstanceType())
				return Memory::New<Replay>();
			else if (Hash == ContributionAllocation::AsInstanceType())
				return Memory::New<ContributionAllocation>();
			else if (Hash == ContributionActivation::AsInstanceType())
				return Memory::New<ContributionActivation>();
			else if (Hash == ContributionDeallocation::AsInstanceType())
				return Memory::New<ContributionDeallocation>();
			else if (Hash == ContributionDeactivation::AsInstanceType())
				return Memory::New<ContributionDeactivation>();
			else if (Hash == ContributionAdjustment::AsInstanceType())
				return Memory::New<ContributionAdjustment>();
			else if (Hash == ContributionAllowance::AsInstanceType())
				return Memory::New<ContributionAllowance>();
			else if (Hash == ContributionMigration::AsInstanceType())
				return Memory::New<ContributionMigration>();
			else if (Hash == Claim::AsInstanceType())
				return Memory::New<Claim>();
			return nullptr;
		}
		Ledger::Transaction* Resolver::Copy(const Ledger::Transaction* Base)
		{
			uint32_t Hash = Base->AsType();
			if (Hash == Transfer::AsInstanceType())
				return Memory::New<Transfer>(*(const Transfer*)Base);
			else if (Hash == Omnitransfer::AsInstanceType())
				return Memory::New<Omnitransfer>(*(const Omnitransfer*)Base);
			else if (Hash == Deployment::AsInstanceType())
				return Memory::New<Deployment>(*(const Deployment*)Base);
			else if (Hash == Invocation::AsInstanceType())
				return Memory::New<Invocation>(*(const Invocation*)Base);
			else if (Hash == Withdrawal::AsInstanceType())
				return Memory::New<Withdrawal>(*(const Withdrawal*)Base);
			else if (Hash == Rollup::AsInstanceType())
				return Memory::New<Rollup>(*(const Rollup*)Base);
			else if (Hash == AddressAccount::AsInstanceType())
				return Memory::New<AddressAccount>(*(const AddressAccount*)Base);
			else if (Hash == PubkeyAccount::AsInstanceType())
				return Memory::New<PubkeyAccount>(*(const PubkeyAccount*)Base);
			else if (Hash == DelegationAccount::AsInstanceType())
				return Memory::New<DelegationAccount>(*(const DelegationAccount*)Base);
			else if (Hash == CustodianAccount::AsInstanceType())
				return Memory::New<CustodianAccount>(*(const CustodianAccount*)Base);
			else if (Hash == Commitment::AsInstanceType())
				return Memory::New<Commitment>(*(const Commitment*)Base);
			else if (Hash == Replay::AsInstanceType())
				return Memory::New<Replay>(*(const Replay*)Base);
			else if (Hash == ContributionAllocation::AsInstanceType())
				return Memory::New<ContributionAllocation>(*(const ContributionAllocation*)Base);
			else if (Hash == ContributionActivation::AsInstanceType())
				return Memory::New<ContributionActivation>(*(const ContributionActivation*)Base);
			else if (Hash == ContributionDeallocation::AsInstanceType())
				return Memory::New<ContributionDeallocation>(*(const ContributionDeallocation*)Base);
			else if (Hash == ContributionDeactivation::AsInstanceType())
				return Memory::New<ContributionDeactivation>(*(const ContributionDeactivation*)Base);
			else if (Hash == ContributionAdjustment::AsInstanceType())
				return Memory::New<ContributionAdjustment>(*(const ContributionAdjustment*)Base);
			else if (Hash == ContributionAllowance::AsInstanceType())
				return Memory::New<ContributionAllowance>(*(const ContributionAllowance*)Base);
			else if (Hash == ContributionMigration::AsInstanceType())
				return Memory::New<ContributionMigration>(*(const ContributionMigration*)Base);
			else if (Hash == Claim::AsInstanceType())
				return Memory::New<Claim>(*(const Claim*)Base);
			return nullptr;
		}
	}
}