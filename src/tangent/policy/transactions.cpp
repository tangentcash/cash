#include "transactions.h"
#include "../kernel/block.h"
#include "../kernel/script.h"
#ifdef TAN_VALIDATOR
#include "../validator/service/nss.h"
#endif

namespace Tangent
{
	namespace Transactions
	{
		ExpectsLR<void> Transfer::Validate() const
		{
			if (!Value.IsPositive())
				return LayerException("invalid value");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Transfer::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();
			else if (memcmp(Context->Receipt.From, To, sizeof(Algorithm::Pubkeyhash)) == 0)
				return LayerException("invalid receiver");

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
		bool Transfer::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Transfer::AsInstanceTypename()
		{
			return "transfer";
		}

		ExpectsLR<void> Omnitransfer::Validate() const
		{
			if (Transfers.empty())
				return LayerException("no transfers");

			for (auto& Transfer : Transfers)
			{
				if (!Transfer.Value.IsPositive())
					return LayerException("invalid value");
			}

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Omnitransfer::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			for (auto& Transfer : Transfers)
			{
				if (memcmp(Context->Receipt.From, Transfer.To, sizeof(Algorithm::Pubkeyhash)) == 0)
					return LayerException("invalid receiver");

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
		bool Omnitransfer::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Omnitransfer::AsInstanceTypename()
		{
			return "omnitransfer";
		}

		ExpectsLR<void> Deployment::Validate() const
		{
			if (IsLocationNull())
				return LayerException("invalid location");
			else if (Segregated && Calldata.size() != 64)
				return LayerException("invalid hashcode");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Deployment::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

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
			if (!Stream.ReadString(Stream.ReadType(), &LocationAssembly) || LocationAssembly.size() != sizeof(Algorithm::Recsighash))
				return false;

			Args.clear();
			memcpy(Location, LocationAssembly.data(), LocationAssembly.size());
			return Format::VariablesUtil::DeserializeMergeFrom(Stream, &Args);
		}
		bool Deployment::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			return Algorithm::Signing::Sign(Algorithm::Signing::MessageHash(Message.Data), SecretKey, Location);
		}
		bool Deployment::VerifyLocation(const Algorithm::Pubkey PublicKey) const
		{
			Format::Stream Message;
			Format::VariablesUtil::SerializeMergeInto(Args, &Message);
			Message.WriteBoolean(Patchable);
			Message.WriteBoolean(Segregated);
			Message.WriteString(Calldata);
			return Algorithm::Signing::Verify(Algorithm::Signing::MessageHash(Message.Data), PublicKey, Location);
		}
		bool Deployment::RecoverLocation(Algorithm::Pubkeyhash PublicKeyHash) const
		{
			Format::Stream Message;
			Format::VariablesUtil::SerializeMergeInto(Args, &Message);
			Message.WriteBoolean(Patchable);
			Message.WriteBoolean(Segregated);
			Message.WriteString(Calldata);
			return Algorithm::Signing::RecoverHash(Algorithm::Signing::MessageHash(Message.Data), PublicKeyHash, Location);
		}
		bool Deployment::IsLocationNull() const
		{
			Algorithm::Recsighash Null = { 0 };
			return memcmp(Location, Null, sizeof(Null)) == 0;
		}
		void Deployment::SetLocation(const Algorithm::Recsighash NewValue)
		{
			VI_ASSERT(NewValue != nullptr, "new value should be set");
			memcpy(Location, NewValue, sizeof(Algorithm::Recsighash));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Deployment::AsInstanceTypename()
		{
			return "deployment";
		}

		ExpectsLR<void> Invocation::Validate() const
		{
			if (Function.empty())
				return LayerException("invalid function invocation");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Invocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Index = Context->GetAccountProgram(To);
			if (!Index)
				return LayerException("program is not assigned");

			if (Hashcode > 0)
			{
				uint32_t Basecode = Algorithm::Hashing::Hash32d(Index->Hashcode);
				if (Hashcode != Basecode)
					return LayerException(Stringify::Text("program hashcode does not match (%i != %i)", Hashcode, Basecode));
			}

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
		bool Invocation::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Invocation::AsInstanceTypename()
		{
			return "invocation";
		}

		ExpectsLR<void> Withdrawal::Validate() const
		{
			if (To.empty())
				return LayerException("invalid to");
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			if (!Chain->SupportsBulkTransfer && To.size() > 1)
				return LayerException("too many to addresses");
#endif
			UnorderedSet<String> Addresses;
			for (auto& Item : To)
			{
				if (Addresses.find(Item.first) != Addresses.end())
					return LayerException("duplicate to address");

				if (!Item.second.IsPositive())
					return LayerException("invalid to value");

				Addresses.insert(Item.first);
			}

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Withdrawal::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			bool Charges = memcmp(Context->Receipt.From, Proposer, sizeof(Algorithm::Pubkeyhash)) != 0;
			auto Value = GetTotalValue();
			auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
			auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, Proposer) : ExpectsLR<States::AccountReward>(LayerException());
			auto BaseFee = (BaseReward ? BaseReward->OutgoingAbsoluteFee : Decimal::Zero());
			if (BaseReward && BaseAsset != Asset)
			{
				auto BalanceRequirement = Context->VerifyTransferBalance(BaseAsset, BaseReward->OutgoingAbsoluteFee);
				if (!BalanceRequirement)
					return BalanceRequirement.Error();

				auto Depository = Context->GetAccountDepository(BaseAsset, Proposer);
				if (!Depository || Depository->Custody < BaseReward->OutgoingAbsoluteFee)
					return LayerException("proposer's " + Algorithm::Asset::HandleOf(BaseAsset) + " balance is insufficient to cover withdrawal fee (value: " + BaseReward->OutgoingAbsoluteFee.ToString() + ")");
			}

			auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, Proposer);
			auto BalanceRequirement = Context->VerifyTransferBalance(std::max(Value, TokenReward ? TokenReward->CalculateOutgoingFee(Value) : Decimal::Zero()));
			if (!BalanceRequirement)
				return BalanceRequirement;

			auto Depository = Context->GetAccountDepository(Proposer);
			if (!Depository || Depository->Custody < Value)
				return LayerException("proposer's " + Algorithm::Asset::HandleOf(Asset) + " balance is insufficient to cover withdrawal value (value: " + Value.ToString() + ")");

			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Item : To)
			{
				auto Collision = Context->GetWitnessAddress(BaseAsset, Item.first, Protocol::Now().Account.RootAddressIndex, 0);
				if (Collision && memcmp(Collision->Owner, Context->Receipt.From, sizeof(Collision->Owner)) != 0)
					return LayerException("invalid to address (not owned by sender)");
				else if (!Collision)
					Collision = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, { { (uint8_t)0, String(Item.first) } }, AddressIndex, States::AddressType::Router);
				if (!Collision)
					return Collision.Error();
			}

			if (BaseAsset != Asset && BaseFee.IsPositive())
			{
				auto BaseTransfer = Context->ApplyTransfer(BaseAsset, Context->Receipt.From, -BaseFee, Decimal::Zero());
				if (!BaseTransfer)
					return BaseTransfer.Error();

				BaseTransfer = Context->ApplyTransfer(BaseAsset, Proposer, BaseFee, Decimal::Zero());
				if (!BaseTransfer)
					return BaseTransfer.Error();
			}

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

			auto Registration = Context->ApplyAccountDepositoryTransaction(Proposer, Context->Receipt.TransactionHash, 1);
			if (!Registration)
				return Registration.Error();

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> Withdrawal::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(Proposer.PublicKeyHash, this->Proposer, sizeof(this->Proposer)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			bool Charges = memcmp(Context->Receipt.From, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0;
			auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
			auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, Proposer.PublicKeyHash) : ExpectsLR<States::AccountReward>(LayerException());
			auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, Proposer.PublicKeyHash);
			auto PartitionFee = (TokenReward ? TokenReward->CalculateOutgoingFee(GetTotalValue()) : Decimal::Zero());
			if (To.size() > 1)
				PartitionFee /= Decimal(To.size()).Truncate(Protocol::Now().Message.Precision);

			auto* Transaction = Memory::New<OutgoingClaim>();
			Transaction->Asset = Asset;
			Pipeline->push_back(Transaction);

			Vector<Mediator::Transferer> Destinations;
			Destinations.reserve(To.size());
			for (auto& Item : To)
				Destinations.push_back(Mediator::Transferer(Item.first, Optional::None, Item.second - PartitionFee));
#ifdef TAN_VALIDATOR
			auto Parent = NSS::ServerNode::Get()->NewMasterWallet(Asset, Proposer.SecretKey);
			auto Child = Parent ? Mediator::DynamicWallet(*Parent) : Mediator::DynamicWallet();
			return Resolver::EmitTransaction(Pipeline, std::move(Child), Asset, Context->Receipt.TransactionHash, std::move(Destinations)).Then<ExpectsRT<void>>([this, Context, Pipeline, Transaction](ExpectsRT<Mediator::OutgoingTransaction>&& Result)
			{
				if (!Result || Result->Transaction.TransactionId.empty())
				{
					Transaction->SetFailureWitness(Result ? "transaction broadcast failed" : Result.What(), Context->Receipt.TransactionHash);
					if (!Result && (Result.Error().retry() || Result.Error().shutdown()))
					{
						Pipeline->pop_back();
						Memory::Delete(Transaction);
						return ExpectsRT<void>(Result.Error());
					}
				}
				else
					Transaction->SetSuccessWitness(Result->Transaction.TransactionId, Result->Data, Context->Receipt.TransactionHash);
				return ExpectsRT<void>(Expectation::Met);
			});
#else
			return ExpectsPromiseRT<void>(RemoteException("nss data not available"));
#endif
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
		bool Withdrawal::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			return Protocol::Now().User.NSS.WithdrawalTime / Protocol::Now().Policy.ConsensusProofTime;
		}
		uint32_t Withdrawal::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
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
		ExpectsLR<void> Rollup::Validate() const
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
					auto Validation = Transaction->Validate();
					Mutable->GasPrice = Decimal::NaN();
					if (!Validation)
						return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(TransactionHash) + " validation failed: " + Validation.Error().message());
				}
			}

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Rollup::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

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
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " validation failed: invalid payload");

				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::RecoverHash(Message.Hash(), Owner, Transaction->Signature) || !memcmp(Owner, Null, sizeof(Null)))
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " validation failed: invalid signature");

				Transaction->GasPrice = Decimal::Zero();
				auto Execution = Ledger::TransactionContext::ExecuteTx((Ledger::Block*)Context->Block, Context->Environment, Transaction, Transaction->AsHash(), Owner, *Context->Delta.Incoming, Transaction->AsMessage().Data.size(), (uint8_t)Ledger::TransactionContext::ExecutionFlags::OnlySuccessful);
				Transaction->GasPrice = Decimal::NaN();
				RelativeGasUse += Execution->Receipt.RelativeGasUse;
				if (!Execution)
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " execution failed: " + Execution.Error().message());

				auto Report = Context->EmitEvent<Rollup>({ Format::Variable(Execution->Receipt.TransactionHash), Format::Variable(Execution->Receipt.RelativeGasUse), Format::Variable(Execution->Receipt.RelativeGasPaid) });
				if (!Report)
					return LayerException("sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " event merge failed: " + Report.Error().message());

				Context->Receipt.Events.reserve(Context->Receipt.Events.size() + Execution->Receipt.Events.size());
				for (auto& Event : Execution->Receipt.Events)
					Context->Receipt.Events.push_back(std::move(Event));
			}

			Context->Block->GasLimit = AbsoluteGasLimit;
			Context->Block->GasUse = AbsoluteGasUse;
			Context->Receipt.RelativeGasUse = RelativeGasUse;
			return Expectation::Met;
		}
		ExpectsPromiseRT<void> Rollup::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			auto Requirement = GetDispatchOffset();
			if (!Requirement)
				return ExpectsPromiseRT<void>(Expectation::Met);

			return Coasync<ExpectsRT<void>>([this, Proposer, Context, Pipeline]() -> ExpectsPromiseRT<void>
			{
				String ErrorMessage;
				for (auto& Group : Transactions)
				{
					for (auto& Transaction : Group.second)
					{
						auto Status = Coawait(Transaction->Dispatch(Proposer, Context, Pipeline));
						if (Status)
							continue;
						else if (Status.Error().retry() || Status.Error().shutdown())
							Coreturn Status;

						ErrorMessage += "sub-transaction " + Algorithm::Encoding::Encode0xHex256(Transaction->AsHash()) + " dispatch failed: " + Status.Error().message() + "\n";
					}
				}
				if (ErrorMessage.empty())
					Coreturn Expectation::Met;
				
				ErrorMessage.pop_back();
				Coreturn RemoteException(std::move(ErrorMessage));
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

					if (!Stream.ReadString(Stream.ReadType(), &SignatureAssembly) || SignatureAssembly.size() != sizeof(Algorithm::Recsighash))
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
		bool Rollup::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					Algorithm::Pubkeyhash From = { 0 };
					if (Transaction->RecoverHash(From))
					{
						Parties.insert(String((char*)From, sizeof(From)));
						Transaction->RecoverMany(Receipt, Parties);
					}
				}
			}
			return true;
		}
		bool Rollup::RecoverAliases(const Ledger::Receipt& Receipt, OrderedSet<uint256_t>& Aliases) const
		{
			for (auto& Group : Transactions)
			{
				for (auto& Transaction : Group.second)
				{
					Algorithm::Pubkeyhash From = { 0 };
					Aliases.insert(Transaction->AsHash());
					Transaction->RecoverAliases(Receipt, Aliases);
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
			if (!Transaction.Transaction->RecoverHash(Transaction.Receipt.From))
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
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
			
			return Algorithm::Signing::Sign(Message.Hash(), SecretKey, Transaction.Signature);
		}

		ExpectsLR<void> Commitment::Validate() const
		{
			if (!Online && Observers.empty())
				return LayerException("invalid status");

			for (auto& Mediator : Observers)
			{
				if (!Algorithm::Asset::IsValid(Mediator.first))
					return LayerException("invalid oracle asset");
			}

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> Commitment::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			bool GoesOnline = Online.Or(false);
			for (auto& Mediator : Observers)
				GoesOnline = Mediator.second || GoesOnline;

			if (GoesOnline)
			{
				auto Status = Context->VerifyAccountWork(false);
				if (!Status)
					return Status;
			}

			if (Online)
			{
				auto Work = Context->ApplyAccountWork(Context->Receipt.From, *Online ? States::AccountFlags::Online : States::AccountFlags::Offline, 0, 0, 0);
				if (!Work)
					return Work.Error();
			}

			for (auto& Mediator : Observers)
			{
				auto ObserverWork = Context->ApplyAccountObserver(Mediator.first, Context->Receipt.From, Mediator.second);
				if (!ObserverWork)
					return ObserverWork.Error();
			}

			return Expectation::Met;
		}
		bool Commitment::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger((uint8_t)(Online ? (*Online ? 1 : 0) : 2));
			Stream->WriteInteger((uint16_t)Observers.size());
			for (auto& Mediator : Observers)
			{
				Stream->WriteInteger(Mediator.first);
				Stream->WriteBoolean(Mediator.second);
			}
			return true;
		}
		bool Commitment::LoadBody(Format::Stream& Stream)
		{
			uint8_t Status;
			if (!Stream.ReadInteger(Stream.ReadType(), &Status))
				return false;

			if (Status == 0)
				Online = false;
			else if (Status == 1)
				Online = true;
			else
				Online = Optional::None;

			uint16_t ObserversSize = 0;
			if (!Stream.ReadInteger(Stream.ReadType(), &ObserversSize))
				return false;

			Observers.clear();
			for (uint16_t i = 0; i < ObserversSize; i++)
			{
				Algorithm::AssetId Asset;
				if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
					return false;

				bool Observing;
				if (!Stream.ReadBoolean(Stream.ReadType(), &Observing))
					return false;

				Observers[Asset] = Observing;
			}

			return true;
		}
		void Commitment::SetOnline()
		{
			Online = true;
		}
		void Commitment::SetOnline(const Algorithm::AssetId& Asset)
		{
			Observers[Asset] = true;
		}
		void Commitment::SetOffline()
		{
			Online = false;
		}
		void Commitment::SetOffline(const Algorithm::AssetId& Asset)
		{
			Observers[Asset] = false;
		}
		void Commitment::SetStandby()
		{
			Online = Optional::None;
		}
		void Commitment::SetStandby(const Algorithm::AssetId& Asset)
		{
			Observers.erase(Asset);
		}
		UPtr<Schema> Commitment::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("online", Var::Integer(Online ? (*Online ? 1 : 0) : -1));
			
			auto* ObserversData = Data->Set("observers", Var::Set::Array());
			for (auto& Mediator : Observers)
			{
				auto* ObserverData = ObserversData->Push(Var::Set::Object());
				ObserverData->Set("asset", Algorithm::Asset::Serialize(Mediator.first));
				ObserverData->Set("online", Var::Boolean(Mediator.second));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Commitment::AsInstanceTypename()
		{
			return "commitment";
		}

		ExpectsLR<void> IncomingClaim::Validate() const
		{
			auto Assertion = GetAssertion(nullptr);
			if (!Assertion || !Assertion->IsValid())
				return LayerException("invalid assertion");

			if (Assertion->Asset != Asset)
				return LayerException("invalid assertion asset");

			if (!Assertion->IsLatencyApproved())
				return LayerException("invalid assertion status");

			return Ledger::AggregationTransaction::Validate();
		}
		ExpectsLR<void> IncomingClaim::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = AggregationTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

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

			auto BaseDerivationIndex = Protocol::Now().Account.RootAddressIndex;
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid chain");

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
				case Tangent::Mediator::RoutingPolicy::Account:
				case Tangent::Mediator::RoutingPolicy::Memo:
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
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Mediator::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
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
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Mediator::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context->GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
				{
					auto* Owner = (Chain->Routing == Mediator::RoutingPolicy::Account && memcmp(Router, Null, sizeof(Null)) != 0 ? Router : Source->Owner);
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

				auto Depository = Context->GetAccountDepository((uint8_t*)Item.first.data()).Or(States::AccountDepository((uint8_t*)Item.first.data(), Context->Block));
				Depository.Custody += Item.second.Custody;
				for (auto& Coverage : Item.second.Contributions)
				{
					auto& Merging = Depository.Contributions[Coverage.first];
					Merging = Merging.IsNaN() ? Coverage.second : Merging + Coverage.second;
				}

				auto Work = Context->GetAccountWork((uint8_t*)Item.first.data());
				Decimal Coverage = Depository.GetCoverage(Work ? Work->Flags : 0);
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
				auto Depository = Context->ApplyAccountDepositoryChange((uint8_t*)Operation.first.data(), Operation.second.Custody, std::move(Operation.second.Contributions), std::move(Operation.second.Reservations));
				if (!Depository)
					return Depository.Error();
			}

			auto Witness = Context->ApplyWitnessTransaction(Assertion->TransactionId);
			if (!Witness)
				return Witness.Error();

			return Context->EmitWitness(Assertion->BlockId);
#else
			return LayerException("nss data not available");
#endif
		}
		bool IncomingClaim::StoreBody(Format::Stream* Stream) const
		{
			return true;
		}
		bool IncomingClaim::LoadBody(Format::Stream& Stream)
		{
			return true;
		}
		bool IncomingClaim::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return false;

			auto Assertion = GetAssertion(nullptr);
			if (!Assertion)
				return false;

			auto Context = Ledger::TransactionContext();
			auto BaseDerivationIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Item : Assertion->From)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Mediator::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context.GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
					Parties.insert(String((char*)Source->Owner, sizeof(Source->Owner)));
			}
			for (auto& Item : Assertion->To)
			{
				uint64_t AddressIndex = Item.AddressIndex && Chain->Routing == Mediator::RoutingPolicy::Memo ? *Item.AddressIndex : BaseDerivationIndex;
				auto Source = Context.GetWitnessAddress(Algorithm::Asset::BaseIdOf(Asset), Item.Address, AddressIndex, 0);
				if (Source)
					Parties.insert(String((char*)Source->Owner, sizeof(Source->Owner)));
			}
			return true;
#else
			return false;
#endif
		}
		void IncomingClaim::SetWitness(uint64_t BlockHeight, const std::string_view& TransactionId, Decimal&& Fee, Vector<Mediator::Transferer>&& Senders, Vector<Mediator::Transferer>&& Receivers)
		{
			Mediator::IncomingTransaction Target;
			Target.SetTransaction(Asset, BlockHeight, TransactionId, std::move(Fee));
			Target.SetOperations(std::move(Senders), std::move(Receivers));
			SetWitness(Target);
		}
		void IncomingClaim::SetWitness(const Mediator::IncomingTransaction& Witness)
		{
			Asset = Witness.Asset;
			SetStatement(Algorithm::Hashing::Hash256i(Witness.TransactionId), Witness.AsMessage());
		}
		Option<Mediator::IncomingTransaction> IncomingClaim::GetAssertion(const Ledger::TransactionContext* Context) const
		{
			auto* BestBranch = GetCumulativeBranch(Context);
			if (!BestBranch)
				return Optional::None;

			auto Message = BestBranch->Message;
			Message.Seek = 0;

			Mediator::IncomingTransaction Assertion;
			if (!Assertion.Load(Message))
				return Optional::None;

			return Assertion;
		}
		UPtr<Schema> IncomingClaim::AsSchema() const
		{
			auto Assertion = GetAssertion(nullptr);
			Schema* Data = Ledger::AggregationTransaction::AsSchema().Reset();
			Data->Set("assertion", Assertion ? Assertion->AsSchema().Reset() : Var::Set::Null());
			return Data;
		}
		uint32_t IncomingClaim::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view IncomingClaim::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t IncomingClaim::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<IncomingClaim, 144>();
		}
		uint32_t IncomingClaim::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view IncomingClaim::AsInstanceTypename()
		{
			return "incoming_claim";
		}

		ExpectsLR<void> OutgoingClaim::Validate() const
		{
			if (!TransactionHash)
				return LayerException("transaction hash not valid");

			return Ledger::ConsensusTransaction::Validate();
		}
		ExpectsLR<void> OutgoingClaim::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Event = Context->ApplyWitnessEvent(TransactionHash);
			if (!Event)
				return Event.Error();

			auto Parent = Context->GetBlockTransactionInstance(TransactionHash);
			if (!Parent)
				return LayerException("parent transaction not found");

			uint32_t Type = Parent->Transaction->AsType();
			if (Type == Withdrawal::AsInstanceType())
			{
				auto* ParentTransaction = (Withdrawal*)*Parent->Transaction;
				if (memcmp(ParentTransaction->Proposer, Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) != 0)
					return LayerException("parent transaction not valid");

				auto Finalization = Context->ApplyAccountDepositoryTransaction(ParentTransaction->Proposer, TransactionHash, -1);
				if (!Finalization)
					return Finalization.Error();

				if (!TransactionId.empty())
					return Expectation::Met;

				bool Honest = true;
				bool Charges = memcmp(Parent->Receipt.From, ParentTransaction->Proposer, sizeof(Algorithm::Pubkeyhash)) != 0;
				auto BaseAsset = Algorithm::Asset::BaseIdOf(Asset);
				auto BaseReward = Charges ? Context->GetAccountReward(BaseAsset, ParentTransaction->Proposer) : ExpectsLR<States::AccountReward>(LayerException());
				auto BaseFee = (BaseReward ? BaseReward->OutgoingAbsoluteFee : Decimal::Zero());
				if (BaseAsset != Asset && BaseFee.IsPositive())
				{
					auto BaseTransfer = Context->ApplyTransfer(BaseAsset, Parent->Receipt.From, BaseFee, Decimal::Zero());
					if (!BaseTransfer)
						return BaseTransfer.Error();
					else if (!Context->ApplyTransfer(BaseAsset, ParentTransaction->Proposer, -BaseFee, Decimal::Zero()))
						Honest = false;
				}

				auto Value = ParentTransaction->GetTotalValue();
				auto TokenReward = BaseAsset == Asset || !Charges ? BaseReward : Context->GetAccountReward(Asset, ParentTransaction->Proposer);
				auto TokenFee = (TokenReward ? TokenReward->CalculateOutgoingFee(Value) : Decimal::Zero());
				auto TokenTransfer = Context->ApplyTransfer(Parent->Receipt.From, TokenFee, TokenFee - Value);
				if (!TokenTransfer)
					return TokenTransfer.Error();
				else if (TokenFee.IsPositive() && !Context->ApplyTransfer(ParentTransaction->Proposer, -TokenFee, Decimal::Zero()))
					Honest = false;

				if (!Honest)
				{
					auto Depository = Context->ApplyAccountDepositoryCustody(ParentTransaction->Proposer, Decimal::NaN());
					if (!Depository)
						return Depository.Error();
				}

				return Expectation::Met;
			}
			else if (Type == ContributionDeactivation::AsInstanceType())
			{
				auto* ParentTransaction = (ContributionDeactivation*)*Parent->Transaction;
				auto Deactivation = Context->GetBlockTransaction<ContributionDeselection>(ParentTransaction->ContributionDeselectionHash);
				if (!Deactivation)
					return Deactivation.Error();

				auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(((ContributionDeselection*)*Deactivation->Transaction)->ContributionDeallocationHash);
				if (!Deallocation)
					return Deallocation.Error();

				if (memcmp(Deallocation->Receipt.From, Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) != 0)
					return LayerException("parent transaction not valid");

				return Expectation::Met;
			}
			else if (Type == DepositoryMigration::AsInstanceType())
			{
				auto* ParentTransaction = (DepositoryMigration*)*Parent->Transaction;
				if (memcmp(ParentTransaction->Proposer, Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) == 0)
					return LayerException("depository migration transaction not valid");

				return Expectation::Met;
			}

			return LayerException("parent transaction not valid");
		}
		bool OutgoingClaim::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(TransactionId);
			Stream->WriteString(TransactionData);
			Stream->WriteString(TransactionMessage);
			Stream->WriteInteger(TransactionHash);
			return true;
		}
		bool OutgoingClaim::LoadBody(Format::Stream& Stream)
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
		bool OutgoingClaim::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto Context = Ledger::TransactionContext();
			auto Parent = Context.GetBlockTransactionInstance(TransactionHash);
			if (!Parent)
				return false;

			Parties.insert(String((char*)Parent->Receipt.From, sizeof(Parent->Receipt.From)));
			return true;
		}
		void OutgoingClaim::SetSuccessWitness(const std::string_view& NewTransactionId, const std::string_view& NewTransactionData, const uint256_t& NewTransactionHash)
		{
			TransactionId = NewTransactionId;
			TransactionData = NewTransactionData;
			TransactionMessage.clear();
			TransactionHash = NewTransactionHash;
		}
		void OutgoingClaim::SetFailureWitness(const std::string_view& NewTransactionMessage, const uint256_t& NewTransactionHash)
		{
			TransactionId.clear();
			TransactionData.clear();
			TransactionMessage = NewTransactionMessage;
			TransactionHash = NewTransactionHash;
		}
		UPtr<Schema> OutgoingClaim::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(TransactionHash)));
			Data->Set("transaction_id", TransactionId.empty() ? Var::Null() : Var::String(TransactionId));
			Data->Set("transaction_data", TransactionData.empty() ? Var::Null() : Var::String(TransactionData));
			Data->Set("transaction_message", TransactionMessage.empty() ? Var::Null() : Var::String(TransactionMessage));
			return Data;
		}
		uint32_t OutgoingClaim::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view OutgoingClaim::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t OutgoingClaim::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<OutgoingClaim, 32>();
		}
		uint32_t OutgoingClaim::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view OutgoingClaim::AsInstanceTypename()
		{
			return "outgoing_claim";
		}

		ExpectsLR<void> AddressAccount::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (Address.empty())
				return LayerException("invalid address");

			return Expectation::Met;
		}
		ExpectsLR<void> AddressAccount::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = DelegationTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto PublicKeyHash = Chain->NewPublicKeyHash(Address);
			if (!PublicKeyHash)
				return PublicKeyHash.Error();
#endif
			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Collision = Context->GetWitnessAddress(Address, AddressIndex, 0);
			if (Collision)
				return LayerException("account address " + Address + " taken");

			auto Status = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, { { (uint8_t)0, String(Address) } }, AddressIndex, States::AddressType::Router);
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AddressAccount::AsInstanceTypename()
		{
			return "address_account";
		}

		ExpectsLR<void> PubkeyAccount::SignPubkey(const PrivateKey& SigningKey)
		{
#ifdef TAN_VALIDATOR
			UPtr<PubkeyAccount> Copy = (PubkeyAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			auto Signature = NSS::ServerNode::Get()->SignMessage(Asset, Message.Data, SigningKey);
			if (!Signature)
				return Signature.Error();

			Sighash = std::move(*Signature);
			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> PubkeyAccount::VerifyPubkey() const
		{
#ifdef TAN_VALIDATOR
			UPtr<PubkeyAccount> Copy = (PubkeyAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			return NSS::ServerNode::Get()->VerifyMessage(Asset, Message.Data, Pubkey, Sighash);
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> PubkeyAccount::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (Pubkey.empty())
				return LayerException("invalid public key");

			if (Sighash.empty())
				return LayerException("invalid public key signature");

			return Ledger::DelegationTransaction::Validate();
		}
		ExpectsLR<void> PubkeyAccount::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = DelegationTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto Verification = VerifyPubkey();
			if (!Verification)
				return Verification.Error();
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			uint64_t AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(Context->Receipt.From, nullptr, VerifyingWallet->Addresses, AddressIndex, States::AddressType::Router);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view PubkeyAccount::AsInstanceTypename()
		{
			return "pubkey_account";
		}

		ExpectsLR<void> DelegationAccount::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Pubkeyhash Null = { 0 };
			if (memcmp(Proposer, Null, sizeof(Null)) == 0)
				return LayerException("invalid account proposer");

			return Ledger::DelegationTransaction::Validate();
		}
		ExpectsLR<void> DelegationAccount::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = DelegationTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto WorkRequirement = Context->VerifyAccountWork(Proposer);
			if (!WorkRequirement)
				return WorkRequirement.Error();

			auto Work = Context->GetAccountWork(Proposer);
			auto Depository = Context->GetAccountDepository(Proposer);
			auto Coverage = Depository ? Depository->GetCoverage(Work ? Work->Flags : 0) : Decimal::Zero();
			if (Coverage.IsNegative())
				return LayerException("depository contribution is too low for custodian account creation");

			switch (Chain->Routing)
			{
				case Mediator::RoutingPolicy::Account:
				{
					if (memcmp(Context->Receipt.From, Proposer, sizeof(Proposer)) != 0)
						return LayerException("invalid account proposer");

					return Expectation::Met;
				}
				case Mediator::RoutingPolicy::Memo:
				case Mediator::RoutingPolicy::UTXO:
					return Expectation::Met;
				default:
					return LayerException("invalid operation");
			}
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsPromiseRT<void> DelegationAccount::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(this->Proposer, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			UPtr<CustodianAccount> Transaction = Memory::New<CustodianAccount>();
			Transaction->Asset = Asset;
			Transaction->SetWitness(Context->Receipt.TransactionHash);

			auto Account = Transaction->SetWallet(Context, Proposer, Context->Receipt.From);
			if (!Account)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Account.Error().message())));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseRT<void>(Expectation::Met);
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
		bool DelegationAccount::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DelegationAccount::AsInstanceTypename()
		{
			return "delegation_account";
		}

		ExpectsLR<void> CustodianAccount::SetWallet(const Ledger::TransactionContext* Context, const Ledger::Wallet& Proposer, const Algorithm::Pubkeyhash NewOwner)
		{
#ifdef TAN_VALIDATOR
			auto* Server = NSS::ServerNode::Get();
			auto* Chain = Server->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto Derivation = Context->GetAccountDerivation(Asset, Proposer.PublicKeyHash);
			uint64_t AddressIndex = (Derivation ? Derivation->MaxAddressIndex + 1 : Protocol::Now().Account.RootAddressIndex);
			if (Chain->Routing == Mediator::RoutingPolicy::Account)
			{
				AddressIndex = Protocol::Now().Account.RootAddressIndex;
				if (Derivation)
					return LayerException("account exists");
				else if (memcmp(NewOwner, Proposer.PublicKeyHash, sizeof(Algorithm::Pubkeyhash)) != 0)
					return LayerException("invalid account owner");
			}

			auto Parent = Server->NewMasterWallet(Asset, Proposer.SecretKey);
			if (!Parent)
				return LayerException("invalid master wallet");

			auto Child = Server->NewSigningWallet(Asset, *Parent, AddressIndex);
			if (!Child)
				return Child.Error();

			SetPubkey(Child->VerifyingKey.ExposeToHeap(), AddressIndex);
			SetOwner(NewOwner);
			return SignPubkey(Child->SigningKey);
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> CustodianAccount::SignPubkey(const PrivateKey& SigningKey)
		{
#ifdef TAN_VALIDATOR
			UPtr<CustodianAccount> Copy = (CustodianAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			auto Signature = NSS::ServerNode::Get()->SignMessage(Asset, Message.Data, SigningKey);
			if (!Signature)
				return Signature.Error();

			Sighash = std::move(*Signature);
			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> CustodianAccount::VerifyPubkey() const
		{
#ifdef TAN_VALIDATOR
			UPtr<CustodianAccount> Copy = (CustodianAccount*)Resolver::Copy(this);
			Copy->GasPrice = Decimal::NaN();
			Copy->GasLimit = 0;
			Copy->Sighash.clear();
			Copy->Sequence = 0;

			Format::Stream Message;
			if (!Copy->StorePayload(&Message))
				return LayerException("serialization error");

			return NSS::ServerNode::Get()->VerifyMessage(Asset, Message.Data, Pubkey, Sighash);
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> CustodianAccount::Validate() const
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

			return Ledger::ConsensusTransaction::Validate();
		}
		ExpectsLR<void> CustodianAccount::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			auto Verification = VerifyPubkey();
			if (!Verification)
				return Verification.Error();
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			auto* Params = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Params)
				return LayerException("invalid operation");

			if (DelegationAccountHash > 0)
			{
				auto Event = Context->ApplyWitnessEvent(DelegationAccountHash);
				if (!Event)
					return Event.Error();

				auto Delegation = Context->GetBlockTransaction<DelegationAccount>(DelegationAccountHash);
				if (!Delegation)
					return Delegation.Error();

				auto* DelegationTransaction = (DelegationAccount*)*Delegation->Transaction;
				if (memcmp(DelegationTransaction->Proposer, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
					return LayerException("invalid origin");

				if (Params->Routing == Mediator::RoutingPolicy::Account && memcmp(Delegation->Receipt.From, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
					return LayerException("invalid account owner");
			}

			auto WorkRequirement = Context->VerifyAccountWork(Context->Receipt.From);
			if (!WorkRequirement)
				return WorkRequirement.Error();

			auto Work = Context->GetAccountWork(Context->Receipt.From);
			auto Depository = Context->GetAccountDepository(Context->Receipt.From);
			auto Coverage = Depository ? Depository->GetCoverage(Work ? Work->Flags : 0) : Decimal::Zero();
			if (Coverage.IsNegative())
				return LayerException("depository contribution is too low for custodian account creation");

			uint64_t AddressIndex = Params->Routing == Mediator::RoutingPolicy::Memo ? PubkeyIndex : Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Collision = Context->GetWitnessAddress(Address.second, AddressIndex, 0);
				if (Collision)
					return LayerException("account address " + Address.second + " taken");
			}

			auto Derivation = Context->GetAccountDerivation(Context->Receipt.From);
			if (!Derivation || Derivation->MaxAddressIndex < AddressIndex)
			{
				auto Status = Context->ApplyAccountDerivation(Context->Receipt.From, AddressIndex);
				if (!Status)
					return Status.Error();
			}

			auto Status = Context->ApplyWitnessAddress(Owner, Context->Receipt.From, VerifyingWallet->Addresses, AddressIndex, States::AddressType::Custodian);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsPromiseRT<void> CustodianAccount::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChain(Asset);
			if (!Chain)
				return ExpectsPromiseRT<void>(RemoteException("invalid operation"));

			auto VerifyingWallet = Chain->NewVerifyingWallet(Asset, Pubkey);
			if (!VerifyingWallet)
				return ExpectsPromiseRT<void>(RemoteException(std::move(VerifyingWallet.Error().message())));

			auto* Params = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Params)
				return ExpectsPromiseRT<void>(RemoteException("invalid operation"));

			uint64_t AddressIndex = Params->Routing == Mediator::RoutingPolicy::Memo ? PubkeyIndex : Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Status = NSS::ServerNode::Get()->EnableWalletAddress(Asset, std::string_view((char*)Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)), Address.second, AddressIndex);
				if (!Status)
					return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));
			}

			return ExpectsPromiseRT<void>(Expectation::Met);
#else
			return ExpectsPromiseRT<void>(RemoteException("nss data not available"));
#endif
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
		bool CustodianAccount::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view CustodianAccount::AsInstanceTypename()
		{
			return "custodian_account";
		}

		ExpectsLR<void> ContributionAllocation::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");
#endif
			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> ContributionAllocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Work = Context->VerifyAccountWork(false);
			if (!Work)
				return Work;

			OrderedSet<String> Hashset = { String((char*)Context->Receipt.From, sizeof(Algorithm::Pubkeyhash)) };
			auto Committee = Context->CalculateSharingCommittee(Hashset, 2);
			if (!Committee)
				return Committee.Error();

			for (auto& Work : *Committee)
			{
				auto Event = Context->EmitEvent<ContributionAllocation>({ Format::Variable(std::string_view((char*)Work.Owner, sizeof(Work.Owner))) });
				if (!Event)
					return Event;
			}

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionAllocation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			OrderedSet<String> Parties;
			if (!RecoverMany(Context->Receipt, Parties) || Parties.size() != 2)
				return ExpectsPromiseRT<void>(RemoteException("transaction receipt does not have a proposer"));

			Algorithm::Pubkeyhash Chosen = { 0 };
			memcpy(Chosen, Parties.begin()->data(), sizeof(Chosen));
			if (memcmp(Chosen, Proposer.PublicKeyHash, sizeof(Chosen)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			UPtr<ContributionSelection> Transaction = Memory::New<ContributionSelection>();
			Transaction->Asset = Asset;

			auto Status = Transaction->SetShare1(Proposer.SecretKey, Context->Receipt.TransactionHash, Context->Receipt.From);
			if (!Status)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseRT<void>(Expectation::Met);
		}
		bool ContributionAllocation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			return true;
		}
		bool ContributionAllocation::LoadBody(Format::Stream& Stream)
		{
			return true;
		}
		bool ContributionAllocation::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			auto* Event1 = Receipt.FindEvent<ContributionAllocation>();
			if (!Event1 || Event1->size() != 1 || Event1->front().AsString().size() != sizeof(Algorithm::Pubkeyhash))
				return false;

			auto* Event2 = Receipt.FindEvent<ContributionAllocation>(1);
			if (!Event2 || Event2->size() != 1 || Event2->front().AsString().size() != sizeof(Algorithm::Pubkeyhash))
				return false;

			Parties.insert(Event1->front().AsBlob());
			Parties.insert(Event2->back().AsBlob());
			return true;
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
			return Ledger::GasUtil::GetGasEstimate<ContributionAllocation, 24>();
		}
		uint64_t ContributionAllocation::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionAllocation::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionAllocation::AsInstanceTypename()
		{
			return "contribution_allocation";
		}

		ExpectsLR<void> ContributionSelection::SetShare1(const Algorithm::Seckey SecretKey, const uint256_t& NewContributionAllocationHash, const Algorithm::Pubkeyhash NewProposer)
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Format::Stream Entropy;
			Entropy.WriteTypeless(ContributionAllocationHash = NewContributionAllocationHash);
			Entropy.WriteTypeless((char*)NewProposer, (uint32_t)sizeof(Algorithm::Pubkeyhash));
			memcpy(Proposer, NewProposer, sizeof(Proposer));

			Algorithm::Composition::CSeed Seed1;
			Algorithm::Composition::CSeckey SecretKey1;
			Algorithm::Composition::ConvertToSecretSeed(SecretKey, Entropy.Data, Seed1);
			return Algorithm::Composition::DeriveKeypair1(Chain->Composition, Seed1, SecretKey1, PublicKey1);
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> ContributionSelection::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Composition::CPubkey Null = { 0 };
			if (!memcmp(PublicKey1, Null, sizeof(Null)))
				return LayerException("invalid public key 1");
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");
#endif
			if (!ContributionAllocationHash)
				return LayerException("invalid parent transaction");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> ContributionSelection::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Event = Context->ApplyWitnessEvent(ContributionAllocationHash);
			if (!Event)
				return Event.Error();

			auto Allocation = Context->GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Allocation)
				return Allocation.Error();

			if (memcmp(Proposer, Allocation->Receipt.From, sizeof(Proposer)) != 0)
				return LayerException("invalid proposer");
			else if (Asset != Allocation->Transaction->Asset)
				return LayerException("invalid asset");

			OrderedSet<String> Parties;
			if (!Allocation->Transaction->RecoverMany(Allocation->Receipt, Parties) || Parties.size() != 2)
				return LayerException("transaction receipt does not have a proposer");

			auto It = Parties.begin();
			if (It->size() != sizeof(Algorithm::Pubkeyhash) || memcmp(It->data(), Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
				return LayerException("invalid origin");

			auto Work = Context->VerifyAccountWork(false);
			if (!Work)
				return Work;

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionSelection::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			auto Allocation = Context->GetBlockTransaction<ContributionAllocation>(ContributionAllocationHash);
			if (!Allocation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Allocation.Error().message())));

			OrderedSet<String> Parties;
			if (!Allocation->Transaction->RecoverMany(Allocation->Receipt, Parties) || Parties.size() != 2)
				return ExpectsPromiseRT<void>(RemoteException("transaction receipt does not have a proposer"));

			Algorithm::Pubkeyhash Chosen = { 0 };
			memcpy(Chosen, (++Parties.begin())->data(), sizeof(Chosen));
			if (memcmp(Chosen, Proposer.PublicKeyHash, sizeof(Chosen)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			UPtr<ContributionActivation> Transaction = Memory::New<ContributionActivation>();
			Transaction->Asset = Asset;

			auto Status = Transaction->SetShare2(Proposer.SecretKey, Context->Receipt.TransactionHash, Allocation->Receipt.From, PublicKey1);
			if (!Status)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseRT<void>(Expectation::Met);
		}
		bool ContributionSelection::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash PkhNull = { 0 };
			Algorithm::Pubkey PubNull = { 0 };
			Algorithm::Composition::CPubkey CPubNull = { 0 };
			Stream->WriteString(std::string_view((char*)PublicKey1, memcmp(PublicKey1, CPubNull, sizeof(CPubNull)) == 0 ? 0 : sizeof(PublicKey1)));
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, PkhNull, sizeof(PkhNull)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger(ContributionAllocationHash);
			return true;
		}
		bool ContributionSelection::LoadBody(Format::Stream& Stream)
		{
			String PublicKey1Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKey1Assembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKey1Assembly, PublicKey1, sizeof(PublicKey1)))
				return false;

			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionAllocationHash))
				return false;

			return true;
		}
		bool ContributionSelection::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		UPtr<Schema> ContributionSelection::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("contribution_allocation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionAllocationHash)));
			Data->Set("public_key_1", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKey1, sizeof(PublicKey1)))));
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			return Data;
		}
		uint32_t ContributionSelection::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionSelection::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionSelection::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionSelection, 36>();
		}
		uint64_t ContributionSelection::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionSelection::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionSelection::AsInstanceTypename()
		{
			return "contribution_selection";
		}

		ExpectsLR<void> ContributionActivation::SetShare2(const Algorithm::Seckey SecretKey, const uint256_t& NewContributionSelectionHash, const Algorithm::Pubkeyhash NewProposer, const Algorithm::Composition::CPubkey PublicKey1)
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			Format::Stream Entropy;
			Entropy.WriteTypeless(ContributionSelectionHash = NewContributionSelectionHash);
			Entropy.WriteTypeless((char*)PublicKey1, (uint32_t)sizeof(Algorithm::Composition::CPubkey));
			Entropy.WriteTypeless((char*)NewProposer, (uint32_t)sizeof(Algorithm::Pubkeyhash));
			memcpy(Proposer, NewProposer, sizeof(Proposer));

			size_t PublicKeySize32 = 0;
			Algorithm::Composition::CSeed Seed2;
			Algorithm::Composition::CSeckey SecretKey2;
			Algorithm::Composition::ConvertToSecretSeed(SecretKey, Entropy.Data, Seed2);
			auto Status = Algorithm::Composition::DeriveKeypair2(Chain->Composition, Seed2, PublicKey1, SecretKey2, PublicKey2, PublicKey, &PublicKeySize32);
			if (!Status)
				return LayerException("invalid message");

			PublicKeySize = (uint16_t)PublicKeySize32;
			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> ContributionActivation::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			Algorithm::Composition::CPubkey PubNull = { 0 };
			if (!memcmp(PublicKey, PubNull, sizeof(PubNull)) || !PublicKeySize || PublicKeySize > sizeof(PublicKey))
				return LayerException("invalid public key");

			Algorithm::Composition::CPubkey CPubNull = { 0 };
			if (!memcmp(PublicKey2, CPubNull, sizeof(CPubNull)))
				return LayerException("invalid public key 2");

			if (!ContributionSelectionHash)
				return LayerException("invalid parent transaction");

			return Ledger::ConsensusTransaction::Validate();
		}
		ExpectsLR<void> ContributionActivation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Event = Context->ApplyWitnessEvent(ContributionSelectionHash);
			if (!Event)
				return Event.Error();

			auto Selection = Context->GetBlockTransaction<ContributionSelection>(ContributionSelectionHash);
			if (!Selection)
				return Selection.Error();

			auto Allocation = Context->GetBlockTransaction<ContributionAllocation>(((ContributionSelection*)*Selection->Transaction)->ContributionAllocationHash);
			if (!Allocation)
				return Allocation.Error();

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return VerifyingWallet.Error();

			if (memcmp(Proposer, Allocation->Receipt.From, sizeof(Proposer)) != 0)
				return LayerException("invalid proposer");
			else if (Asset != Allocation->Transaction->Asset)
				return LayerException("invalid asset");

			OrderedSet<String> Parties;
			if (!Allocation->Transaction->RecoverMany(Allocation->Receipt, Parties) || Parties.size() != 2)
				return LayerException("transaction receipt does not have a proposer");

			auto It = ++Parties.begin();
			if (It->size() != sizeof(Algorithm::Pubkeyhash) || memcmp(It->data(), Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
				return LayerException("invalid origin");

			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Collision = Context->GetWitnessAddress(Address.second, AddressIndex, 0);
				if (Collision)
					return LayerException("address " + Address.second + " taken");
			}

			auto Status = Context->ApplyWitnessAddress(Allocation->Receipt.From, Allocation->Receipt.From, VerifyingWallet->Addresses, AddressIndex, States::AddressType::Contribution);
			if (!Status)
				return Status.Error();

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionActivation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
#ifdef TAN_VALIDATOR
			auto Selection = Context->GetBlockTransaction<ContributionSelection>(ContributionSelectionHash);
			if (!Selection)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Selection.Error().message())));

			auto Allocation = Context->GetBlockTransaction<ContributionAllocation>(((ContributionSelection*)*Selection->Transaction)->ContributionAllocationHash);
			if (!Allocation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Allocation.Error().message())));

			auto VerifyingWallet = GetVerifyingWallet();
			if (!VerifyingWallet)
				return ExpectsPromiseRT<void>(RemoteException(std::move(VerifyingWallet.Error().message())));

			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			for (auto& Address : VerifyingWallet->Addresses)
			{
				auto Status = NSS::ServerNode::Get()->EnableWalletAddress(Asset, std::string_view((char*)Allocation->Receipt.From, sizeof(Allocation->Receipt.From)), Address.second, AddressIndex);
				if (!Status)
					return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));
			}

			return ExpectsPromiseRT<void>(Expectation::Met);
#else
			return ExpectsPromiseRT<void>(RemoteException("nss data not available"));
#endif
		}
		bool ContributionActivation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash PkhNull = { 0 };
			Algorithm::Composition::CPubkey CPubNull = { 0 };
			Stream->WriteString(std::string_view((char*)PublicKey, std::min<size_t>(sizeof(PublicKey), PublicKeySize)));
			Stream->WriteString(std::string_view((char*)PublicKey2, memcmp(PublicKey2, CPubNull, sizeof(CPubNull)) == 0 ? 0 : sizeof(PublicKey2)));
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, PkhNull, sizeof(PkhNull)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger(ContributionSelectionHash);
			return true;
		}
		bool ContributionActivation::LoadBody(Format::Stream& Stream)
		{
			String PublicKeyAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKeyAssembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKeyAssembly, PublicKey, std::min(PublicKeyAssembly.size(), sizeof(PublicKey))))
				return false;

			String PublicKey2Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &PublicKey2Assembly) || !Algorithm::Encoding::DecodeUintBlob(PublicKey2Assembly, PublicKey2, sizeof(PublicKey2)))
				return false;

			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionSelectionHash))
				return false;

			PublicKeySize = (uint16_t)std::min(PublicKeyAssembly.size(), sizeof(PublicKey));
			return true;
		}
		bool ContributionActivation::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		ExpectsLR<Mediator::DerivedVerifyingWallet> ContributionActivation::GetVerifyingWallet() const
		{
#ifdef TAN_VALIDATOR
			return NSS::ServerNode::Get()->NewVerifyingWallet(Asset, std::string_view((char*)PublicKey, PublicKeySize));
#else
			return LayerException("nss data not available");
#endif
		}
		UPtr<Schema> ContributionActivation::AsSchema() const
		{
			auto VerifyingWallet = GetVerifyingWallet();
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("contribution_selection_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionSelectionHash)));
			Data->Set("public_key_2", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKey2, sizeof(PublicKey2)))));
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			Data->Set("verifying_wallet", VerifyingWallet ? VerifyingWallet->AsSchema().Reset() : Var::Set::Null());
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionActivation::AsInstanceTypename()
		{
			return "contribution_activation";
		}

		ExpectsLR<void> ContributionDeallocation::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (!ContributionActivationHash)
				return LayerException("invalid parent transaction");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> ContributionDeallocation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Activation)
				return Activation.Error();

			auto* ActivationTransaction = (ContributionActivation*)*Activation->Transaction;
			if (Asset != ActivationTransaction->Asset)
				return LayerException("invalid asset");

			auto WorkRequirement = Context->VerifyAccountWork(false);
			if (!WorkRequirement)
				return WorkRequirement;

			auto Wallet = ActivationTransaction->GetVerifyingWallet();
			if (!Wallet)
				return Wallet.Error();

			bool Migration = memcmp(ActivationTransaction->Proposer, Context->Receipt.From, sizeof(ActivationTransaction->Proposer)) != 0;
			auto FromDepository = Context->GetAccountDepository(ActivationTransaction->Proposer);
			if (FromDepository)
			{
				if (Migration)
				{
					auto Work = Context->GetAccountWork(ActivationTransaction->Proposer);
					if (!Work->IsMatching(States::AccountFlags::Outlaw))
						return LayerException("contribution's proposer is honest");

					auto ToDepository = Context->GetAccountDepository(ActivationTransaction->Proposer);
					if (!ToDepository)
						return LayerException("migration's proposer depository does not exist");

					for (auto& Address : Wallet->Addresses)
					{
						auto It = FromDepository->Contributions.find(Address.second);
						if (It != FromDepository->Contributions.end())
							ToDepository->Custody += It->second;
					}

					auto Coverage = ToDepository->GetCoverage(Work ? Work->Flags : 0);
					if (Coverage.IsNaN() || Coverage.IsNegative())
						return LayerException("migration's proposer depository contribution change does not cover balance (contribution: " + ToDepository->GetContribution().ToString() + ", custody: " + ToDepository->Custody.ToString() + ")");
				}
				else
				{
					for (auto& Address : Wallet->Addresses)
						FromDepository->Contributions.erase(Address.second);

					auto Work = Context->GetAccountWork(Context->Receipt.From);
					auto Coverage = FromDepository->GetCoverage(Work ? Work->Flags : 0);
					if (Coverage.IsNaN() || Coverage.IsNegative())
						return LayerException("depository contribution change does not cover balance (contribution: " + FromDepository->GetContribution().ToString() + ", custody: " + FromDepository->Custody.ToString() + ")");
				}
			}

			auto ToDepository = Migration ? Context->GetAccountDepository(Context->Receipt.From) : FromDepository;
			if (Migration && !ToDepository)
				return LayerException("migration's proposer depository does not exist");

			Algorithm::Pubkeyhash Null = { 0 };
			auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
			auto Status = Context->ApplyWitnessAddress(ActivationTransaction->Proposer, Null, Wallet->Addresses, AddressIndex, States::AddressType::Witness);
			if (!Status)
				return Status.Error();

			for (auto& Address : Wallet->Addresses)
			{
				auto Value = FromDepository->GetContribution(Address.second);
				FromDepository->Contributions.erase(Address.second);
				if (Migration && Value.IsPositive())
					ToDepository->Custody += Value;
			}

			auto Work = Context->GetAccountWork(ActivationTransaction->Proposer);
			auto Coverage = FromDepository->GetCoverage(Work ? Work->Flags : 0);
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("depository contribution change does not cover balance (contribution: " + FromDepository->GetContribution().ToString() + ", custody: " + FromDepository->Custody.ToString() + ")");

			auto Resignation = Context->Store(FromDepository.Address());
			if (!Resignation)
				return Resignation.Error();

			if (!Migration)
				return Expectation::Met;

			Work = Context->GetAccountWork(Context->Receipt.From);
			Coverage = FromDepository->GetCoverage(Work ? Work->Flags : 0);
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("migration's depository contribution change does not cover balance (contribution: " + FromDepository->GetContribution().ToString() + ", custody: " + FromDepository->Custody.ToString() + ")");

			auto Application = Context->Store(ToDepository.Address());
			if (!Application)
				return Application.Error();

			auto Derivation = Context->GetAccountDerivation(Asset, Context->Receipt.From);
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			AddressIndex = (Derivation && Chain->Routing != Mediator::RoutingPolicy::Memo ? Derivation->MaxAddressIndex + 1 : Protocol::Now().Account.RootAddressIndex);
#endif
			Status = Context->ApplyWitnessAddress(ActivationTransaction->Proposer, Context->Receipt.From, Wallet->Addresses, AddressIndex, States::AddressType::Custodian);
			if (!Status)
				return Status.Error();

			if (!Derivation || Derivation->MaxAddressIndex < AddressIndex)
			{
				auto Substatus = Context->ApplyAccountDerivation(Derivation->Owner, AddressIndex);
				if (!Substatus)
					return Substatus.Error();
			}

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionDeallocation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(ContributionActivationHash);
			if (!Activation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Activation.Error().message())));

			auto* ActivationTransaction = (ContributionActivation*)*Activation->Transaction;
			auto Selection = Context->GetBlockTransaction<ContributionSelection>(ActivationTransaction->ContributionSelectionHash);
			if (!Selection)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Selection.Error().message())));

			if (memcmp(Selection->Receipt.From, Proposer.PublicKeyHash, sizeof(Selection->Receipt.From)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			UPtr<ContributionDeselection> Transaction = Memory::New<ContributionDeselection>();
			Transaction->Asset = Asset;

			auto Status = Transaction->SetRevealingShare1(Context, Context->Receipt.TransactionHash, Proposer.SecretKey);
			if (!Status)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseRT<void>(Expectation::Met);
		}
		bool ContributionDeallocation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkey Null = { 0 };
			Stream->WriteString(std::string_view((char*)CipherPublicKey1, memcmp(CipherPublicKey1, Null, sizeof(Null)) == 0 ? 0 : sizeof(CipherPublicKey1)));
			Stream->WriteString(std::string_view((char*)CipherPublicKey2, memcmp(CipherPublicKey2, Null, sizeof(Null)) == 0 ? 0 : sizeof(CipherPublicKey2)));
			Stream->WriteInteger(ContributionActivationHash);
			return true;
		}
		bool ContributionDeallocation::LoadBody(Format::Stream& Stream)
		{
			String CipherPublicKey1Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &CipherPublicKey1Assembly) || !Algorithm::Encoding::DecodeUintBlob(CipherPublicKey1Assembly, CipherPublicKey1, sizeof(CipherPublicKey1)))
				return false;

			String CipherPublicKey2Assembly;
			if (!Stream.ReadString(Stream.ReadType(), &CipherPublicKey2Assembly) || !Algorithm::Encoding::DecodeUintBlob(CipherPublicKey2Assembly, CipherPublicKey2, sizeof(CipherPublicKey2)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionActivationHash))
				return false;

			return true;
		}
		void ContributionDeallocation::SetWitness(const Algorithm::Seckey SecretKey, const uint256_t& NewContributionActivationHash)
		{
			uint8_t Seed[32];
			Algorithm::Encoding::DecodeUint256(ContributionActivationHash = NewContributionActivationHash, Seed);

			Algorithm::Seckey CipherSecretKey;
			Algorithm::Signing::DeriveCipherKeypair(SecretKey, ContributionActivationHash, CipherSecretKey, CipherPublicKey1);
			Algorithm::Signing::DeriveCipherKeypair(SecretKey, Algorithm::Hashing::Hash256i(Seed, sizeof(Seed)), CipherSecretKey, CipherPublicKey2);
		}
		UPtr<Schema> ContributionDeallocation::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("contribution_activation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionActivationHash)));
			Data->Set("cipher_public_key_1", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherPublicKey1, sizeof(CipherPublicKey1)))));
			Data->Set("cipher_public_key_2", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherPublicKey2, sizeof(CipherPublicKey2)))));
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
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionDeallocation::AsInstanceTypename()
		{
			return "contribution_deallocation";
		}

		ExpectsLR<void> ContributionDeselection::SetRevealingShare1(const Ledger::TransactionContext* Context, const uint256_t& NewContributionDeallocationHash, const Algorithm::Seckey SecretKey)
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash = NewContributionDeallocationHash);
			if (!Deallocation)
				return Deallocation.Error();

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return Activation.Error();

			auto Selection = Context->GetBlockTransaction<ContributionSelection>(((ContributionActivation*)*Activation->Transaction)->ContributionSelectionHash);
			if (!Selection)
				return Selection.Error();

			auto SelectionTransaction = (ContributionSelection*)*Selection->Transaction;
			Format::Stream Entropy;
			Entropy.WriteTypeless(SelectionTransaction->ContributionAllocationHash);
			Entropy.WriteTypeless((char*)SelectionTransaction->Proposer, (uint32_t)sizeof(Algorithm::Pubkeyhash));
			memcpy(Proposer, SelectionTransaction->Proposer, sizeof(SelectionTransaction->Proposer));

			Algorithm::Pubkey ProposerPublicKey;
			if (!SelectionTransaction->Recover(ProposerPublicKey))
				return LayerException("invalid proposer public key");

			Algorithm::Composition::CSeed Seed1;
			Algorithm::Composition::CSeckey SecretKey1;
			Algorithm::Composition::CPubkey PublicKey1;
			Algorithm::Composition::ConvertToSecretSeed(SecretKey, Entropy.Data, Seed1);
			auto Status = Algorithm::Composition::DeriveKeypair1(Chain->Composition, Seed1, SecretKey1, PublicKey1);
			if (!Status)
				return Status;

			Entropy.WriteTypeless((char*)Seed1, (uint32_t)sizeof(Seed1));
			Entropy.WriteTypeless(Deallocation->Receipt.TransactionHash);
			Entropy.WriteTypeless(Activation->Receipt.TransactionHash);
			Entropy.WriteTypeless(Selection->Receipt.TransactionHash);
			EncryptedSecretKey1 = Algorithm::Signing::PublicEncrypt(ProposerPublicKey, std::string_view((char*)SecretKey1, sizeof(SecretKey1)), Entropy.Data).Or(String());
			if (EncryptedSecretKey1.empty())
				return LayerException("secret key encryption error");

			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> ContributionDeselection::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (!ContributionDeallocationHash)
				return LayerException("invalid parent transaction");

			if (EncryptedSecretKey1.empty())
				return LayerException("invalid encrypted secret key 1");

			return Ledger::ConsensusTransaction::Validate();
		}
		ExpectsLR<void> ContributionDeselection::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Event = Context->ApplyWitnessEvent(ContributionDeallocationHash);
			if (!Event)
				return Event.Error();

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Deallocation)
				return Deallocation.Error();

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return Activation.Error();

			auto Selection = Context->GetBlockTransaction<ContributionSelection>(((ContributionActivation*)*Activation->Transaction)->ContributionSelectionHash);
			if (!Selection)
				return Selection.Error();

			if (Asset != Deallocation->Transaction->Asset)
				return LayerException("invalid asset");

			if (memcmp(Selection->Receipt.From, Context->Receipt.From, sizeof(Selection->Receipt.From)) != 0)
				return LayerException("invalid transaction owner");

			auto* SelectionTransaction = (ContributionSelection*)*Selection->Transaction;
			if (memcmp(SelectionTransaction->Proposer, Proposer, sizeof(Proposer)) != 0)
				return LayerException("invalid proposer");

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionDeselection::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Deallocation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Deallocation.Error().message())));

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Activation.Error().message())));

			if (memcmp(Activation->Receipt.From, Proposer.PublicKeyHash, sizeof(Activation->Receipt.From)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			UPtr<ContributionDeactivation> Transaction = Memory::New<ContributionDeactivation>();
			Transaction->Asset = Asset;

			auto Status = Transaction->SetRevealingShare2(Context, Context->Receipt.TransactionHash, Proposer.SecretKey);
			if (!Status)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));

			Pipeline->push_back(Transaction.Reset());
			return ExpectsPromiseRT<void>(Expectation::Met);
		}
		bool ContributionDeselection::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger(ContributionDeallocationHash);
			Stream->WriteString(EncryptedSecretKey1);
			return true;
		}
		bool ContributionDeselection::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionDeallocationHash))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &EncryptedSecretKey1))
				return false;

			return true;
		}
		bool ContributionDeselection::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		Option<String> ContributionDeselection::GetSecretKey1(const Ledger::TransactionContext* Context, const Algorithm::Seckey SecretKey) const
		{
			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(ContributionDeallocationHash);
			if (!Deallocation)
				return Optional::None;

			auto* DeallocationTransaction = (ContributionDeallocation*)*Deallocation->Transaction;
			Algorithm::Seckey CipherSecretKey; Algorithm::Pubkey CipherPublicKey;
			Algorithm::Signing::DeriveCipherKeypair(SecretKey, DeallocationTransaction->ContributionActivationHash, CipherSecretKey, CipherPublicKey);
			return Algorithm::Signing::PrivateDecrypt(CipherSecretKey, CipherPublicKey, EncryptedSecretKey1);
		}
		UPtr<Schema> ContributionDeselection::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("contribution_deallocation_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionDeallocationHash)));
			Data->Set("encrypted_secret_key_1", Var::String(Format::Util::Encode0xHex(EncryptedSecretKey1)));
			return Data;
		}
		uint32_t ContributionDeselection::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view ContributionDeselection::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t ContributionDeselection::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<ContributionDeselection, 52>();
		}
		uint64_t ContributionDeselection::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionDeselection::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionDeselection::AsInstanceTypename()
		{
			return "contribution_deselection";
		}

		ExpectsLR<void> ContributionDeactivation::SetRevealingShare2(const Ledger::TransactionContext* Context, const uint256_t& NewContributionDeselectionHash, const Algorithm::Seckey SecretKey)
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");
			
			ContributionDeselectionHash = NewContributionDeselectionHash;
			auto Deselection = Context->GetBlockTransaction<ContributionDeselection>(ContributionDeselectionHash);
			if (!Deselection)
				return Deselection.Error();

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(((ContributionDeselection*)*Deselection->Transaction)->ContributionDeallocationHash);
			if (!Deallocation)
				return Deallocation.Error();

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return Activation.Error();

			auto* ActivationTransaction = ((ContributionActivation*)*Activation->Transaction);
			auto Selection = Context->GetBlockTransaction<ContributionSelection>(ActivationTransaction->ContributionSelectionHash);
			if (!Selection)
				return Selection.Error();

			auto SelectionTransaction = (ContributionSelection*)*Selection->Transaction;
			Format::Stream Entropy;
			Entropy.WriteTypeless(ActivationTransaction->ContributionSelectionHash);
			Entropy.WriteTypeless((char*)SelectionTransaction->PublicKey1, (uint32_t)sizeof(Algorithm::Composition::CPubkey));
			Entropy.WriteTypeless((char*)SelectionTransaction->Proposer, (uint32_t)sizeof(Algorithm::Pubkeyhash));
			memcpy(Proposer, SelectionTransaction->Proposer, sizeof(SelectionTransaction->Proposer));

			Algorithm::Pubkey ProposerPublicKey;
			if (!SelectionTransaction->Recover(ProposerPublicKey))
				return LayerException("invalid proposer public key");

			size_t SharedPublicKeySize = 0;
			Algorithm::Composition::CPubkey SharedPublicKey;
			Algorithm::Composition::CSeed Seed2;
			Algorithm::Composition::CSeckey SecretKey2;
			Algorithm::Composition::CPubkey PublicKey2;
			Algorithm::Composition::ConvertToSecretSeed(SecretKey, Entropy.Data, Seed2);
			auto Status = Algorithm::Composition::DeriveKeypair2(Chain->Composition, Seed2, SelectionTransaction->PublicKey1, SecretKey2, PublicKey2, SharedPublicKey, &SharedPublicKeySize);
			if (!Status)
				return Status;

			Entropy.WriteTypeless((char*)Seed2, (uint32_t)sizeof(Seed2));
			Entropy.WriteTypeless(Deselection->Receipt.TransactionHash);
			Entropy.WriteTypeless(Deallocation->Receipt.TransactionHash);
			Entropy.WriteTypeless(Activation->Receipt.TransactionHash);
			Entropy.WriteTypeless(Selection->Receipt.TransactionHash);
			EncryptedSecretKey2 = Algorithm::Signing::PublicEncrypt(ProposerPublicKey, std::string_view((char*)SecretKey2, sizeof(SecretKey2)), Entropy.Data).Or(String());
			if (EncryptedSecretKey2.empty())
				return LayerException("secret key encryption error");

			return Expectation::Met;
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsLR<void> ContributionDeactivation::Validate() const
		{
			if (!Algorithm::Asset::TokenOf(Asset).empty())
				return LayerException("invalid asset");

			if (!ContributionDeselectionHash)
				return LayerException("invalid parent transaction");

			if (EncryptedSecretKey2.empty())
				return LayerException("invalid encrypted secret key 2");

			return Ledger::ConsensusTransaction::Validate();
		}
		ExpectsLR<void> ContributionDeactivation::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = ConsensusTransaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Event = Context->ApplyWitnessEvent(ContributionDeselectionHash);
			if (!Event)
				return Event.Error();

			auto Deselection = Context->GetBlockTransaction<ContributionDeselection>(ContributionDeselectionHash);
			if (!Deselection)
				return Deselection.Error();

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(((ContributionDeselection*)*Deselection->Transaction)->ContributionDeallocationHash);
			if (!Deallocation)
				return Deallocation.Error();

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return Activation.Error();

			if (Asset != Deallocation->Transaction->Asset)
				return LayerException("invalid asset");

			if (memcmp(Activation->Receipt.From, Context->Receipt.From, sizeof(Activation->Receipt.From)) != 0)
				return LayerException("invalid transaction owner");

			auto* ActivationTransaction = (ContributionActivation*)*Activation->Transaction;
			if (memcmp(ActivationTransaction->Proposer, Proposer, sizeof(Proposer)) != 0)
				return LayerException("invalid proposer");

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> ContributionDeactivation::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
#ifdef TAN_VALIDATOR
			auto Deselection = Context->GetBlockTransaction<ContributionDeselection>(ContributionDeselectionHash);
			if (!Deselection)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Deselection.Error().message())));

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(((ContributionDeselection*)*Deselection->Transaction)->ContributionDeallocationHash);
			if (!Deallocation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Deallocation.Error().message())));

			auto Activation = Context->GetBlockTransaction<ContributionActivation>(((ContributionDeallocation*)*Deallocation->Transaction)->ContributionActivationHash);
			if (!Activation)
				return ExpectsPromiseRT<void>(RemoteException(std::move(Activation.Error().message())));

			auto* ActivationTransaction = ((ContributionActivation*)*Activation->Transaction);
			auto VerifyingWallet = ActivationTransaction->GetVerifyingWallet();
			if (!VerifyingWallet)
				return ExpectsPromiseRT<void>(RemoteException(std::move(VerifyingWallet.Error().message())));

			if (memcmp(ActivationTransaction->Proposer, Deallocation->Receipt.From, sizeof(ActivationTransaction->Proposer)) != 0)
			{
				auto* Server = NSS::ServerNode::Get();
				auto* Event = Deallocation->Receipt.ReverseFindEvent<States::WitnessAddress>();
				if (!Event || Event->size() < 2)
					return ExpectsPromiseRT<void>(RemoteException("bad event type"));

				auto AddressIndex = (*Event)[1].AsUint64();
				if (!memcmp(Proposer.PublicKeyHash, Deallocation->Receipt.From, sizeof(Proposer.PublicKeyHash)))
				{
					auto Parent = Server->NewMasterWallet(Asset, Proposer.SecretKey);
					if (!Parent)
						return ExpectsPromiseRT<void>(RemoteException(std::move(Parent.Error().message())));

					auto Child = GetSigningWallet(Context, Proposer.SecretKey);
					if (!Child)
						return ExpectsPromiseRT<void>(RemoteException(std::move(Child.Error().message())));

					Child->AddressIndex = AddressIndex;
					if (Parent->MaxAddressIndex < AddressIndex)
						Parent->MaxAddressIndex = AddressIndex;

					auto Status = Server->EnableSigningWallet(Asset, *Parent, *Child);
					if (!Status)
						return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));
				}

				for (auto& Address : VerifyingWallet->Addresses)
				{
					auto Status = Server->EnableWalletAddress(Asset, std::string_view((char*)Deallocation->Receipt.From, sizeof(Algorithm::Pubkeyhash)), Address.second, AddressIndex);
					if (!Status)
						return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));
				}
			}
			else
			{
				auto AddressIndex = Protocol::Now().Account.RootAddressIndex;
				for (auto& Address : VerifyingWallet->Addresses)
				{
					auto Status = NSS::ServerNode::Get()->DisableWalletAddress(Asset, Address.second);
					if (!Status)
						return ExpectsPromiseRT<void>(RemoteException(std::move(Status.Error().message())));
				}
			}

			return ExpectsPromiseRT<void>(Expectation::Met);
#else
			return ExpectsPromiseRT<void>(RemoteException("nss data not available"));
#endif
		}
		bool ContributionDeactivation::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger(ContributionDeselectionHash);
			Stream->WriteString(EncryptedSecretKey2);
			return true;
		}
		bool ContributionDeactivation::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionDeselectionHash))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &EncryptedSecretKey2))
				return false;

			return true;
		}
		bool ContributionDeactivation::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		Option<String> ContributionDeactivation::GetSecretKey1(const Ledger::TransactionContext* Context, const Algorithm::Seckey SecretKey) const
		{
			auto Deselection = Context->GetBlockTransaction<ContributionDeselection>(ContributionDeselectionHash);
			if (!Deselection)
				return Optional::None;

			return ((ContributionDeselection*)*Deselection->Transaction)->GetSecretKey1(Context, SecretKey);
		}
		Option<String> ContributionDeactivation::GetSecretKey2(const Ledger::TransactionContext* Context, const Algorithm::Seckey SecretKey) const
		{
			auto Deselection = Context->GetBlockTransaction<ContributionDeselection>(ContributionDeselectionHash);
			if (!Deselection)
				return Optional::None;

			auto Deallocation = Context->GetBlockTransaction<ContributionDeallocation>(((ContributionDeselection*)*Deselection->Transaction)->ContributionDeallocationHash);
			if (!Deallocation)
				return Optional::None;

			uint8_t Seed[32];
			auto* DeallocationTransaction = (ContributionDeallocation*)*Deallocation->Transaction;
			Algorithm::Seckey CipherSecretKey; Algorithm::Pubkey CipherPublicKey;
			Algorithm::Encoding::DecodeUint256(DeallocationTransaction->ContributionActivationHash, Seed);
			Algorithm::Signing::DeriveCipherKeypair(SecretKey, Algorithm::Hashing::Hash256i(Seed, sizeof(Seed)), CipherSecretKey, CipherPublicKey);
			return Algorithm::Signing::PrivateDecrypt(CipherSecretKey, CipherPublicKey, EncryptedSecretKey2);
		}
		ExpectsLR<Mediator::DerivedSigningWallet> ContributionDeactivation::GetSigningWallet(const Ledger::TransactionContext* Context, const Algorithm::Seckey SecretKey) const
		{
#ifdef TAN_VALIDATOR
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			if (!Chain)
				return LayerException("invalid operation");

			auto SecretKey2 = GetSecretKey2(Context, SecretKey);
			if (!SecretKey2)
				return LayerException("invalid secret key 2");

			auto SecretKey1 = GetSecretKey1(Context, SecretKey);
			if (!SecretKey1)
				return LayerException("invalid secret key 1");

			size_t SharedSecretKeySize = 0;
			Algorithm::Composition::CSeckey SharedSecretKey;
			auto Status = Algorithm::Composition::DeriveSecretKey(Chain->Composition, (uint8_t*)SecretKey1->data(), (uint8_t*)SecretKey2->data(), SharedSecretKey, &SharedSecretKeySize);
			if (!Status)
				return LayerException("invalid message");

			return NSS::ServerNode::Get()->NewSigningWallet(Asset, std::string_view((char*)SharedSecretKey, SharedSecretKeySize));
#else
			return LayerException("nss data not available");
#endif
		}
		ExpectsPromiseRT<Mediator::OutgoingTransaction> ContributionDeactivation::WithdrawToAddress(const Ledger::TransactionContext* Context, const Algorithm::Seckey SecretKey, const std::string_view& Address)
		{
#ifdef TAN_VALIDATOR
			return Coasync<ExpectsRT<Mediator::OutgoingTransaction>>([this, Context, SecretKey, Address]() -> ExpectsPromiseRT<Mediator::OutgoingTransaction>
			{
				auto SigningWallet = GetSigningWallet(Context, SecretKey);
				if (!SigningWallet)
					Coreturn RemoteException(std::move(SigningWallet.Error().message()));

				auto DynamicWallet = Mediator::DynamicWallet(*SigningWallet);
				auto RemainingBalance = Coawait(NSS::ServerNode::Get()->CalculateBalance(Asset, DynamicWallet, SigningWallet->Addresses.begin()->second));
				if (!RemainingBalance)
					Coreturn RemainingBalance.Error();
				else if (!RemainingBalance->IsPositive())
					Coreturn RemoteException("contribution wallet balance is zero");

				auto Destinations = { Mediator::Transferer(Address, Optional::None, std::move(*RemainingBalance)) };
				auto Result = Coawait(Resolver::EmitTransaction(nullptr, std::move(DynamicWallet), Asset, Context->Receipt.TransactionHash, std::move(Destinations)));
				Coreturn std::move(Result);
			});
#else
			return ExpectsPromiseRT<Mediator::OutgoingTransaction>(RemoteException("nss data not available"));
#endif
		}
		UPtr<Schema> ContributionDeactivation::AsSchema() const
		{
			Schema* Data = Ledger::ConsensusTransaction::AsSchema().Reset();
			Data->Set("contribution_deselection_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ContributionDeselectionHash)));
			Data->Set("encrypted_secret_key_2", Var::String(Format::Util::Encode0xHex(EncryptedSecretKey2)));
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
		uint64_t ContributionDeactivation::GetDispatchOffset() const
		{
			return 1;
		}
		uint32_t ContributionDeactivation::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view ContributionDeactivation::AsInstanceTypename()
		{
			return "contribution_deactivation";
		}

		ExpectsLR<void> DepositoryAdjustment::Validate() const
		{
			if (IncomingAbsoluteFee.IsNaN() || IncomingAbsoluteFee.IsNegative())
				return LayerException("invalid incoming absolute fee");

			if (IncomingRelativeFee.IsNaN() || IncomingRelativeFee.IsNegative() || IncomingRelativeFee > 1.0)
				return LayerException("invalid incoming relative fee");

			if (OutgoingAbsoluteFee.IsNaN() || OutgoingAbsoluteFee.IsNegative())
				return LayerException("invalid outgoing absolute fee");

			if (OutgoingRelativeFee.IsNaN() || OutgoingRelativeFee.IsNegative() || OutgoingRelativeFee > 1.0)
				return LayerException("invalid outgoing relative fee");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> DepositoryAdjustment::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			auto Work = Context->VerifyAccountWork(false);
			if (!Work)
				return Work;

			auto Reward = Context->ApplyAccountReward(Context->Receipt.From, IncomingAbsoluteFee, IncomingRelativeFee, OutgoingAbsoluteFee, OutgoingRelativeFee);
			if (!Reward)
				return Reward.Error();

			return Expectation::Met;
		}
		bool DepositoryAdjustment::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteDecimal(IncomingAbsoluteFee);
			Stream->WriteDecimal(IncomingRelativeFee);
			Stream->WriteDecimal(OutgoingAbsoluteFee);
			Stream->WriteDecimal(OutgoingRelativeFee);
			return true;
		}
		bool DepositoryAdjustment::LoadBody(Format::Stream& Stream)
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
		void DepositoryAdjustment::SetIncomingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee)
		{
			IncomingAbsoluteFee = AbsoluteFee;
			IncomingRelativeFee = RelativeFee;
		}
		void DepositoryAdjustment::SetOutgoingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee)
		{
			OutgoingAbsoluteFee = AbsoluteFee;
			OutgoingRelativeFee = RelativeFee;
		}
		UPtr<Schema> DepositoryAdjustment::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("incoming_absolute_fee", Var::Decimal(IncomingAbsoluteFee));
			Data->Set("incoming_relative_fee", Var::Decimal(IncomingRelativeFee));
			Data->Set("outgoing_absolute_fee", Var::Decimal(OutgoingAbsoluteFee));
			Data->Set("outgoing_relative_fee", Var::Decimal(OutgoingRelativeFee));
			return Data;
		}
		uint32_t DepositoryAdjustment::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view DepositoryAdjustment::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t DepositoryAdjustment::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<DepositoryAdjustment, 20>();
		}
		uint32_t DepositoryAdjustment::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DepositoryAdjustment::AsInstanceTypename()
		{
			return "depository_adjustment";
		}

		ExpectsLR<void> DepositoryMigration::Validate() const
		{
			if (IsProposerNull())
				return LayerException("invalid proposer");

			if (!Value.IsPositive())
				return LayerException("invalid value");

			return Ledger::Transaction::Validate();
		}
		ExpectsLR<void> DepositoryMigration::Execute(Ledger::TransactionContext* Context) const
		{
			auto Validation = Transaction::Execute(Context);
			if (!Validation)
				return Validation.Error();

			if (!memcmp(Context->Receipt.From, Proposer, sizeof(Proposer)))
				return LayerException("self migration not allowed");

			auto WorkRequirement = Context->VerifyAccountWork(true);
			if (!WorkRequirement)
				return WorkRequirement;

			auto Depository = Context->GetAccountDepository(Context->Receipt.From);
			if (!Depository)
				return LayerException("proposer has no depository");

			auto Work = Context->GetAccountWork(Context->Receipt.From);
			auto Coverage = Depository->GetCoverage(Work ? Work->Flags : 0);
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("proposer does not cover balance (contribution: " + Depository->GetContribution().ToString() + ", custody: " + Depository->Custody.ToString() + ")");
			else if (Depository->Custody < Value)
				return LayerException("proposer does not have enough custody (value: " + Value.ToString() + ", custody: " + Depository->Custody.ToString() + ")");

			Work = Context->GetAccountWork(Proposer);
			Depository = Context->GetAccountDepository(Proposer);
			if (!Depository)
				return LayerException("migration proposer has no depository");

			Depository->Custody += Value;
			Coverage = Depository->GetCoverage(Work ? Work->Flags : 0);
			if (Coverage.IsNaN() || Coverage.IsNegative())
				return LayerException("migration proposer does not cover balance (contribution: " + Depository->GetContribution().ToString() + ", custody: " + Depository->Custody.ToString() + ")");

			auto Address = GetDestination(Context);
			if (!Address)
				return LayerException("migration proposer has no usable custodian address");

			return Expectation::Met;
		}
		ExpectsPromiseRT<void> DepositoryMigration::Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const
		{
			if (memcmp(Proposer.PublicKeyHash, Context->Receipt.From, sizeof(Context->Receipt.From)) != 0)
				return ExpectsPromiseRT<void>(Expectation::Met);

			if (Context->GetWitnessEvent(Context->Receipt.TransactionHash))
				return ExpectsPromiseRT<void>(Expectation::Met);

			auto Address = GetDestination(Context);
			if (!Address)
				return ExpectsPromiseRT<void>(RemoteException("migration proposer has no usable custodian address"));
#ifdef TAN_VALIDATOR
			auto* Transaction = Memory::New<OutgoingClaim>();
			Transaction->Asset = Asset;
			Pipeline->push_back(Transaction);

			auto Destinations = { Mediator::Transferer(Address->Addresses.begin()->second, Address->AddressIndex, Decimal(Value)) };
			auto Parent = NSS::ServerNode::Get()->NewMasterWallet(Asset, Proposer.SecretKey);
			auto Child = Parent ? Mediator::DynamicWallet(*Parent) : Mediator::DynamicWallet();
			return Resolver::EmitTransaction(Pipeline, std::move(Child), Asset, Context->Receipt.TransactionHash, std::move(Destinations)).Then<ExpectsRT<void>>([this, Context, Pipeline, Transaction](ExpectsRT<Mediator::OutgoingTransaction>&& Result)
			{
				if (!Result || Result->Transaction.TransactionId.empty())
				{
					Transaction->SetFailureWitness(Result ? "transaction broadcast failed" : Result.What(), Context->Receipt.TransactionHash);
					if (!Result && (Result.Error().retry() || Result.Error().shutdown()))
					{
						Pipeline->pop_back();
						Memory::Delete(Transaction);
						return ExpectsRT<void>(Result.Error());
					}
				}
				else
					Transaction->SetSuccessWitness(Result->Transaction.TransactionId, Result->Data, Context->Receipt.TransactionHash);
				return ExpectsRT<void>(Expectation::Met);
			});
#else
			return ExpectsPromiseRT<void>(RemoteException("nss data not available"));
#endif
		}
		bool DepositoryMigration::StoreBody(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteDecimal(Value);
			return true;
		}
		bool DepositoryMigration::LoadBody(Format::Stream& Stream)
		{
			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Value))
				return false;

			return true;
		}
		bool DepositoryMigration::RecoverMany(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const
		{
			if (!IsProposerNull())
				Parties.insert(String((char*)Proposer, sizeof(Proposer)));
			return true;
		}
		void DepositoryMigration::SetProposer(const Algorithm::Pubkeyhash NewProposer, const Decimal& NewValue)
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
		bool DepositoryMigration::IsProposerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(Proposer, Null, sizeof(Null)) == 0;
		}
		ExpectsLR<States::WitnessAddress> DepositoryMigration::GetDestination(const Ledger::TransactionContext* Context) const
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
		UPtr<Schema> DepositoryMigration::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			Data->Set("value", Var::Decimal(Value));
			return Data;
		}
		uint32_t DepositoryMigration::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view DepositoryMigration::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint256_t DepositoryMigration::GetGasEstimate() const
		{
			return Ledger::GasUtil::GetGasEstimate<DepositoryMigration, 64>();
		}
		uint64_t DepositoryMigration::GetDispatchOffset() const
		{
			return Protocol::Now().User.NSS.WithdrawalTime / Protocol::Now().Policy.ConsensusProofTime;
		}
		uint32_t DepositoryMigration::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view DepositoryMigration::AsInstanceTypename()
		{
			return "depository_migration";
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
			else if (Hash == Commitment::AsInstanceType())
				return Memory::New<Commitment>();
			else if (Hash == IncomingClaim::AsInstanceType())
				return Memory::New<IncomingClaim>();
			else if (Hash == OutgoingClaim::AsInstanceType())
				return Memory::New<OutgoingClaim>();
			else if (Hash == AddressAccount::AsInstanceType())
				return Memory::New<AddressAccount>();
			else if (Hash == PubkeyAccount::AsInstanceType())
				return Memory::New<PubkeyAccount>();
			else if (Hash == DelegationAccount::AsInstanceType())
				return Memory::New<DelegationAccount>();
			else if (Hash == CustodianAccount::AsInstanceType())
				return Memory::New<CustodianAccount>();
			else if (Hash == ContributionAllocation::AsInstanceType())
				return Memory::New<ContributionAllocation>();
			else if (Hash == ContributionSelection::AsInstanceType())
				return Memory::New<ContributionSelection>();
			else if (Hash == ContributionActivation::AsInstanceType())
				return Memory::New<ContributionActivation>();
			else if (Hash == ContributionDeallocation::AsInstanceType())
				return Memory::New<ContributionDeallocation>();
			else if (Hash == ContributionDeselection::AsInstanceType())
				return Memory::New<ContributionDeselection>();
			else if (Hash == ContributionDeactivation::AsInstanceType())
				return Memory::New<ContributionDeactivation>();
			else if (Hash == DepositoryAdjustment::AsInstanceType())
				return Memory::New<DepositoryAdjustment>();
			else if (Hash == DepositoryMigration::AsInstanceType())
				return Memory::New<DepositoryMigration>();
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
			else if (Hash == Commitment::AsInstanceType())
				return Memory::New<Commitment>(*(const Commitment*)Base);
			else if (Hash == IncomingClaim::AsInstanceType())
				return Memory::New<IncomingClaim>(*(const IncomingClaim*)Base);
			else if (Hash == OutgoingClaim::AsInstanceType())
				return Memory::New<OutgoingClaim>(*(const OutgoingClaim*)Base);
			else if (Hash == AddressAccount::AsInstanceType())
				return Memory::New<AddressAccount>(*(const AddressAccount*)Base);
			else if (Hash == PubkeyAccount::AsInstanceType())
				return Memory::New<PubkeyAccount>(*(const PubkeyAccount*)Base);
			else if (Hash == DelegationAccount::AsInstanceType())
				return Memory::New<DelegationAccount>(*(const DelegationAccount*)Base);
			else if (Hash == CustodianAccount::AsInstanceType())
				return Memory::New<CustodianAccount>(*(const CustodianAccount*)Base);
			else if (Hash == ContributionAllocation::AsInstanceType())
				return Memory::New<ContributionAllocation>(*(const ContributionAllocation*)Base);
			else if (Hash == ContributionSelection::AsInstanceType())
				return Memory::New<ContributionSelection>(*(const ContributionSelection*)Base);
			else if (Hash == ContributionActivation::AsInstanceType())
				return Memory::New<ContributionActivation>(*(const ContributionActivation*)Base);
			else if (Hash == ContributionDeallocation::AsInstanceType())
				return Memory::New<ContributionDeallocation>(*(const ContributionDeallocation*)Base);
			else if (Hash == ContributionDeselection::AsInstanceType())
				return Memory::New<ContributionDeselection>(*(const ContributionDeselection*)Base);
			else if (Hash == ContributionDeactivation::AsInstanceType())
				return Memory::New<ContributionDeactivation>(*(const ContributionDeactivation*)Base);
			else if (Hash == DepositoryAdjustment::AsInstanceType())
				return Memory::New<DepositoryAdjustment>(*(const DepositoryAdjustment*)Base);
			else if (Hash == DepositoryMigration::AsInstanceType())
				return Memory::New<DepositoryMigration>(*(const DepositoryMigration*)Base);
			return nullptr;
		}
		ExpectsPromiseRT<Mediator::OutgoingTransaction> Resolver::EmitTransaction(Vector<UPtr<Ledger::Transaction>>* Pipeline, Mediator::DynamicWallet&& Wallet, const Algorithm::AssetId& Asset, const uint256_t& TransactionHash, Vector<Mediator::Transferer>&& To)
		{
#ifdef TAN_VALIDATOR
			auto* Server = NSS::ServerNode::Get();
			if (!Protocol::Now().Is(NetworkType::Regtest) || Server->HasSupport(Asset))
				return Server->SubmitTransaction(TransactionHash, Asset, std::move(Wallet), std::move(To));

			ExpectsLR<Mediator::DerivedVerifyingWallet> VerifyingWallet = LayerException();
			if (Wallet.Parent)
			{
				auto SigningWallet = Server->NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				if (!SigningWallet)
					return ExpectsPromiseRT<Mediator::OutgoingTransaction>(RemoteException("wallet not found"));

				VerifyingWallet = std::move(*SigningWallet);
			}
			else if (Wallet.SigningChild)
				VerifyingWallet = std::move(*Wallet.SigningChild);
			else if (Wallet.VerifyingChild)
				VerifyingWallet = std::move(*Wallet.VerifyingChild);
			if (!VerifyingWallet)
				return ExpectsPromiseRT<Mediator::OutgoingTransaction>(RemoteException("wallet not found"));

			Mediator::OutgoingTransaction Ephimeric;
			Ephimeric.Transaction.To = To;
			Ephimeric.Transaction.From.push_back(Mediator::Transferer(VerifyingWallet->Addresses.begin()->second, Option<uint64_t>(VerifyingWallet->AddressIndex), Ephimeric.Transaction.GetOutputValue()));
			Ephimeric.Transaction.Asset = Asset;
			Ephimeric.Transaction.TransactionId = Algorithm::Encoding::Encode0xHex256(Algorithm::Hashing::Hash256i(TransactionHash.ToString()));
			Ephimeric.Transaction.BlockId = Algorithm::Hashing::Hash256i(Ephimeric.Transaction.TransactionId) % std::numeric_limits<uint64_t>::max();
			Ephimeric.Transaction.Fee = Decimal::Zero();
			Ephimeric.Data = Ephimeric.AsMessage().Encode();

			if (Pipeline != nullptr)
			{
				auto* Transaction = Memory::New<IncomingClaim>();
				Transaction->Asset = Asset;
				Transaction->SetEstimateGas(Decimal::Zero());
				Transaction->SetWitness(Ephimeric.Transaction);
				Pipeline->push_back(Transaction);
			}

			return ExpectsPromiseRT<Mediator::OutgoingTransaction>(std::move(Ephimeric));
#else
			return ExpectsPromiseRT<Mediator::OutgoingTransaction>(RemoteException("nss data not available"));
#endif
		}
	}
}