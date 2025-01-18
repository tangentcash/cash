#include "block.h"
#include "../policy/typenames.h"
#include "../policy/transactions.h"
#ifdef TAN_VALIDATOR
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#endif

namespace Tangent
{
	namespace Ledger
	{
		BlockTransaction::BlockTransaction(UPtr<Ledger::Transaction>&& NewTransaction, Ledger::Receipt&& NewReceipt) : Transaction(std::move(NewTransaction)), Receipt(std::move(NewReceipt))
		{
			VI_ASSERT(Transaction, "transaction should be set");
		}
		BlockTransaction::BlockTransaction(const BlockTransaction& Other) : Transaction(Other.Transaction ? Transactions::Resolver::Copy(*Other.Transaction) : nullptr), Receipt(Other.Receipt)
		{
		}
		BlockTransaction& BlockTransaction::operator= (const BlockTransaction& Other)
		{
			if (this == &Other)
				return *this;

			Transaction = Other.Transaction ? Transactions::Resolver::Copy(*Other.Transaction) : nullptr;
			Receipt = Other.Receipt;
			return *this;
		}
		bool BlockTransaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!Transaction->Store(Stream))
				return false;

			if (!Receipt.StorePayload(Stream))
				return false;

			return true;
		}
		bool BlockTransaction::LoadPayload(Format::Stream& Stream)
		{
			Transaction = Tangent::Transactions::Resolver::New(Messages::Authentic::ResolveType(Stream).Or(0));
			if (!Transaction->Load(Stream))
				return false;

			if (!Receipt.LoadPayload(Stream))
				return false;

			return true;
		}
		UPtr<Schema> BlockTransaction::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("transaction", Transaction ? Transaction->AsSchema().Reset() : Var::Set::Null());
			Data->Set("receipt", Receipt.AsSchema().Reset());
			return Data;
		}
		uint32_t BlockTransaction::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view BlockTransaction::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t BlockTransaction::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view BlockTransaction::AsInstanceTypename()
		{
			return "block_transaction";
		}

		BlockWork::BlockWork(const BlockWork& Other) : ParentWork(Other.ParentWork)
		{
			for (size_t i = 0; i < (size_t)WorkCommitment::__Count__; i++)
			{
				auto& Mapping = Map[i];
				for (auto& Item : Other.Map[i])
					Mapping[Item.first] = Item.second ? States::Resolver::Copy(*Item.second) : nullptr;
			}
		}
		BlockWork& BlockWork::operator= (const BlockWork& Other)
		{
			if (&Other == this)
				return *this;

			ParentWork = Other.ParentWork;
			for (size_t i = 0; i < (size_t)WorkCommitment::__Count__; i++)
			{
				auto& Mapping = Map[i];
				Mapping.clear();
				for (auto& Item : Other.Map[i])
					Mapping[Item.first] = Item.second ? States::Resolver::Copy(*Item.second) : nullptr;
			}
			return *this;
		}
		Option<UPtr<State>> BlockWork::FindUniform(const std::string_view& Index) const
		{
			auto Composite = Uniform::AsInstanceComposite(Index);
			for (size_t i = 0; i < (size_t)WorkCommitment::__Count__; i++)
			{
				auto& Mapping = Map[i];
				auto It = Mapping.find(Composite);
				if (It != Mapping.end())
					return It->second ? Option<UPtr<State>>(States::Resolver::Copy(*It->second)) : Option<UPtr<State>>(nullptr);
			}
			return ParentWork ? ParentWork->FindUniform(Index) : Option<UPtr<State>>(Optional::None);
		}
		Option<UPtr<State>> BlockWork::FindMultiform(const std::string_view& Column, const std::string_view& Row) const
		{
			auto Composite = Multiform::AsInstanceComposite(Column, Row);
			for (size_t i = 0; i < (size_t)WorkCommitment::__Count__; i++)
			{
				auto& Mapping = Map[i];
				auto It = Mapping.find(Composite);
				if (It != Mapping.end())
					return It->second ? Option<UPtr<State>>(States::Resolver::Copy(*It->second)) : Option<UPtr<State>>(nullptr);
			}
			return ParentWork ? ParentWork->FindMultiform(Column, Row) : Option<UPtr<State>>(Optional::None);
		}
		void BlockWork::ClearUniform(const std::string_view& Index)
		{
			Map[(size_t)WorkCommitment::Pending][Uniform::AsInstanceComposite(Index)].Destroy();
		}
		void BlockWork::ClearMultiform(const std::string_view& Column, const std::string_view& Row)
		{
			Map[(size_t)WorkCommitment::Pending][Multiform::AsInstanceComposite(Column, Row)].Destroy();
		}
		void BlockWork::CopyAny(State* Value)
		{
			if (Value)
			{
				auto Copy = States::Resolver::Copy(Value);
				if (Copy)
					Map[(size_t)WorkCommitment::Pending][Value->AsComposite()] = Copy;
			}
		}
		void BlockWork::MoveAny(UPtr<State>&& Value)
		{
			auto Composite = Value->AsComposite();
			Map[(size_t)WorkCommitment::Pending][Composite] = std::move(Value);
		}
		const StateWork& BlockWork::At(WorkCommitment Level) const
		{
			switch (Level)
			{
				case Tangent::Ledger::WorkCommitment::Pending:
				case Tangent::Ledger::WorkCommitment::Finalized:
					return Map[(size_t)Level];
				default:
					return Map[(size_t)WorkCommitment::Finalized];
			}
		}
		StateWork& BlockWork::Clear()
		{
			Map[(size_t)WorkCommitment::Pending].clear();
			Map[(size_t)WorkCommitment::Finalized].clear();
			return Map[(size_t)WorkCommitment::Finalized];
		}
		StateWork& BlockWork::Rollback()
		{
			Map[(size_t)WorkCommitment::Pending].clear();
			return Map[(size_t)WorkCommitment::Finalized];
		}
		StateWork& BlockWork::Commit()
		{
			for (auto& Item : Map[(size_t)WorkCommitment::Pending])
			{
				if (Item.second)
					Map[(size_t)WorkCommitment::Finalized][Item.first] = std::move(Item.second);
			}
			Map[(size_t)WorkCommitment::Pending].clear();
			return Map[(size_t)WorkCommitment::Finalized];
		}

		BlockMutation::BlockMutation() noexcept : Outgoing(nullptr)
		{
			Incoming = &Cache;
		}
		BlockMutation::BlockMutation(const BlockMutation& Other) noexcept : Cache(Other.Cache), Outgoing(Other.Outgoing)
		{
			Incoming = Other.Incoming == &Other.Cache ? &Cache : Other.Incoming;
		}
		BlockMutation::BlockMutation(BlockMutation&& Other) noexcept : Cache(std::move(Other.Cache)), Outgoing(Other.Outgoing)
		{
			Other.Outgoing = nullptr;
			Incoming = Other.Incoming == &Other.Cache ? &Cache : Other.Incoming;
		}
		BlockMutation& BlockMutation::operator=(const BlockMutation& Other) noexcept
		{
			if (this == &Other)
				return *this;

			Cache = Other.Cache;
			Outgoing = Other.Outgoing;
			Incoming = Other.Incoming == &Other.Cache ? &Cache : Other.Incoming;
			return *this;
		}
		BlockMutation& BlockMutation::operator=(BlockMutation&& Other) noexcept
		{
			if (this == &Other)
				return *this;

			Cache = std::move(Other.Cache);
			Outgoing = Other.Outgoing;
			Incoming = Other.Incoming == &Other.Cache ? &Cache : Other.Incoming;
			Other.Outgoing = nullptr;
			return *this;
		}

		BlockDispatch::BlockDispatch(const BlockDispatch& Other) noexcept : Inputs(Other.Inputs)
		{
			Outputs.reserve(Other.Outputs.size());
			for (auto& Output : Other.Outputs)
			{
				auto* Copy = Transactions::Resolver::Copy(*Output);
				if (Copy)
					Outputs.push_back(Copy);
			}
		}
		BlockDispatch& BlockDispatch::operator=(const BlockDispatch& Other) noexcept
		{
			if (this == &Other)
				return *this;

			Inputs = Other.Inputs;
			Outputs.clear();
			Outputs.reserve(Other.Outputs.size());
			for (auto& Output : Other.Outputs)
			{
				auto* Copy = Transactions::Resolver::Copy(*Output);
				if (Copy)
					Outputs.push_back(Copy);
			}
			return *this;
		}
		ExpectsLR<void> BlockDispatch::Checkpoint() const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			return Chain.Dispatch(Inputs);
#else
			return LayerException("chainstate data not available");
#endif
		}

		bool BlockHeader::operator<(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) < 0;
		}
		bool BlockHeader::operator>(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) > 0;
		}
		bool BlockHeader::operator<=(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) <= 0;
		}
		bool BlockHeader::operator>=(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) >= 0;
		}
		bool BlockHeader::operator==(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) == 0;
		}
		bool BlockHeader::operator!=(const BlockHeader& Other) const
		{
			return GetRelativeOrder(Other) != 0;
		}
		ExpectsLR<BlockDispatch> BlockHeader::DispatchSync(const Wallet& Proposer) const
		{
#ifdef TAN_VALIDATOR
			size_t Offset = 0, Count = 512;
			BlockDispatch Pipeline;
			while (true)
			{
				auto Chain = Storages::Chainstate(__func__);
				auto Candidates = Chain.GetPendingBlockTransactions(Number, Offset, Count);
				if (!Candidates || Candidates->empty())
					break;

				Offset += Candidates->size();
				for (auto& Input : *Candidates)
				{
					auto Execution = Ledger::TransactionContext::DispatchTx(Proposer, &Input, &Pipeline.Outputs).Get();
					if (!Execution)
						Pipeline.Errors[Input.Receipt.TransactionHash].append(Stringify::Text("in transaction %s dispatch reverted: %s\n", Algorithm::Encoding::Encode0xHex256(Input.Receipt.TransactionHash).c_str(), Execution.Error().what()));
					Pipeline.Inputs.push_back(Input.Receipt.TransactionHash);
				}
				if (Candidates->size() < Count)
					break;
			}

			for (auto& Item : Pipeline.Errors)
				Item.second.pop_back();

			return Pipeline;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsPromiseLR<BlockDispatch> BlockHeader::DispatchAsync(const Wallet& Proposer) const
		{
#ifdef TAN_VALIDATOR
			return Coasync<ExpectsLR<BlockDispatch>>([this, Proposer]() -> ExpectsPromiseLR<BlockDispatch>
			{
				size_t Offset = 0, Count = 512;
				BlockDispatch Pipeline;
				while (true)
				{
					auto Chain = Storages::Chainstate(__func__);
					auto Candidates = Chain.GetPendingBlockTransactions(Number, Offset, Count);
					if (!Candidates || Candidates->empty())
						break;

					Offset += Candidates->size();
					for (auto& Input : *Candidates)
					{
						auto Execution = Coawait(Ledger::TransactionContext::DispatchTx(Proposer, &Input, &Pipeline.Outputs));
						if (!Execution)
							Pipeline.Errors[Input.Receipt.TransactionHash].append(Stringify::Text("in transaction %s dispatch reverted: %s\n", Algorithm::Encoding::Encode0xHex256(Input.Receipt.TransactionHash).c_str(), Execution.Error().what()));
						Pipeline.Inputs.push_back(Input.Receipt.TransactionHash);
					}
					if (Candidates->size() < Count)
						break;
				}

				for (auto& Item : Pipeline.Errors)
					Item.second.pop_back();

				Coreturn Pipeline;
			});
#else
			return ExpectsPromiseLR<BlockDispatch>(LayerException("chainstate data not available"));
#endif
		}
		ExpectsLR<void> BlockHeader::VerifyValidity(const BlockHeader* ParentBlock) const
		{
			if (!Number || (!ParentHash && Number > 1) || (Number == 1 && ParentHash > 0))
				return LayerException("invalid number");

			uint128_t Difficulty = Target.Difficulty();
			if (Wesolowski.empty() || Difficulty < Provability::WesolowskiVDF::GetDefault().Difficulty())
				return LayerException("invalid wesolowski target");

			if (!TransactionsRoot || !ReceiptsRoot || !StatesRoot)
				return LayerException("invalid transactions/receipts/states merkle tree root");

			uint256_t GasWork = GasUtil::GetGasWork(Difficulty, GasUse, GasLimit);
			if (!GasLimit || GasUse > GasLimit || AbsoluteWork < GasWork)
				return LayerException("invalid gas work");

			if (!TransactionsCount)
				return LayerException("invalid transactions count");

			Algorithm::Pubkeyhash PublicKeyHash = { 0 };
			if (!Recover(PublicKeyHash))
				return LayerException("proposer proof verification failed");

			if (!VerifyWesolowski())
				return LayerException("wesolowski proof verification failed");

			if (!ParentBlock && Number > 1)
				return Expectation::Met;

			if (AbsoluteWork != (ParentBlock ? ParentBlock->AbsoluteWork + GasWork : GasWork))
				return LayerException("invalid absolute gas work");

			uint256_t Cumulative = GetSlotLength() > 1 ? uint256_t(1) : uint256_t(0);
            if (SlotGasUse != ((ParentBlock ? ParentBlock->SlotGasUse : uint256_t(0)) * Cumulative + GasUse))
				return LayerException("invalid slot gas use");

			if (SlotGasTarget != ((ParentBlock ? ParentBlock->SlotGasTarget : uint256_t(0)) * Cumulative + (TransactionsCount > 0 ? GasUse / TransactionsCount : uint256_t(0))))
				return LayerException("invalid slot gas target");

			if (SlotDuration != ((ParentBlock ? ParentBlock->SlotDuration + ParentBlock->GetDuration() : uint256_t(0)) * Cumulative))
				return LayerException("invalid slot duration");

			for (auto& Witness : Witnesses)
			{
				if (!Algorithm::Asset::IsValid(Witness.first))
					return LayerException("invalid witness " + Algorithm::Asset::HandleOf(Witness.first));
			}

			return Expectation::Met;
		}
		bool BlockHeader::StorePayloadWesolowski(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(ParentHash);
			Stream->WriteInteger(TransactionsRoot);
			Stream->WriteInteger(ReceiptsRoot);
			Stream->WriteInteger(StatesRoot);
			Stream->WriteInteger(GasUse);
			Stream->WriteInteger(GasLimit);
			Stream->WriteInteger(AbsoluteWork);
			Stream->WriteInteger(SlotGasUse);
			Stream->WriteInteger(SlotGasTarget);
			Stream->WriteInteger(SlotDuration);
			Stream->WriteInteger(Target.Length);
			Stream->WriteInteger(Target.Bits);
			Stream->WriteInteger(Target.Pow);
			Stream->WriteInteger(Recovery);
			Stream->WriteInteger(Time);
			Stream->WriteInteger(Priority);
			Stream->WriteInteger(Number);
			Stream->WriteInteger(MutationsCount);
			Stream->WriteInteger(TransactionsCount);
			Stream->WriteInteger(StatesCount);
			Stream->WriteInteger((uint16_t)Witnesses.size());
			for (auto& Item : Witnesses)
			{
				Stream->WriteInteger(Item.first);
				Stream->WriteInteger(Item.second);
			}
			return true;
		}
		bool BlockHeader::LoadPayloadWesolowski(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &ParentHash))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsRoot))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ReceiptsRoot))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &StatesRoot))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GasUse))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GasLimit))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &AbsoluteWork))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &SlotGasUse))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &SlotGasTarget))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &SlotDuration))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Target.Length))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Target.Bits))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Target.Pow))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Recovery))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Time))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Priority))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Number))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &MutationsCount))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsCount))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &StatesCount))
				return false;

			uint16_t WitnessesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &WitnessesSize))
				return false;

			Witnesses.clear();
			for (size_t i = 0; i < WitnessesSize; i++)
			{
				Algorithm::AssetId Asset;
				if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
					return false;

				uint64_t BlockNumber;
				if (!Stream.ReadInteger(Stream.ReadType(), &BlockNumber))
					return false;

				SetWitnessRequirement(Asset, BlockNumber);
			}

			return true;
		}
		bool BlockHeader::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!StorePayloadWesolowski(Stream))
				return false;

			Stream->WriteString(Wesolowski);
			return true;
		}
		bool BlockHeader::LoadPayload(Format::Stream& Stream)
		{
			if (!LoadPayloadWesolowski(Stream))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Wesolowski))
				return false;

			return true;
		}
		bool BlockHeader::Sign(const Algorithm::Seckey SecretKey)
		{
			Format::Stream Message;
			if (!BlockHeader::StorePayload(&Message))
				return false;

			return Algorithm::Signing::SignTweaked(Message.Hash(), SecretKey, Signature);
		}
		bool BlockHeader::Solve(const Algorithm::Seckey SecretKey)
		{
			Format::Stream Message;
			if (!StorePayloadWesolowski(&Message))
				return false;

			Wesolowski = Provability::WesolowskiVDF::Evaluate(Target, Message.Data);
			return !Wesolowski.empty();
		}
		bool BlockHeader::Verify(const Algorithm::Pubkey PublicKey) const
		{
			Format::Stream Message;
			if (!BlockHeader::StorePayload(&Message))
				return false;

			return Algorithm::Signing::VerifyTweaked(Message.Hash(), PublicKey, Signature);
		}
		bool BlockHeader::Recover(Algorithm::Pubkeyhash PublicKeyHash) const
		{
			Format::Stream Message;
			if (!BlockHeader::StorePayload(&Message))
				return false;

			return Algorithm::Signing::RecoverTweakedHash(Message.Hash(), PublicKeyHash, Signature);
		}
		bool BlockHeader::VerifyWesolowski() const
		{
			Format::Stream Message;
			if (!StorePayloadWesolowski(&Message))
				return false;

			return Provability::WesolowskiVDF::Verify(Target, Message.Data, Wesolowski);
		}
		void BlockHeader::SetParentBlock(const BlockHeader* ParentBlock)
		{
			ParentHash = (ParentBlock ? ParentBlock->AsHash() : uint256_t(0));
			Number = (ParentBlock ? ParentBlock->Number : 0) + 1;
			Time = Protocol::Now().Time.Now();
		}
		void BlockHeader::SetWitnessRequirement(const Algorithm::AssetId& Asset, uint64_t BlockNumber)
		{
			auto& Number = Witnesses[Algorithm::Asset::BaseIdOf(Asset)];
			if (Number < BlockNumber)
				Number = BlockNumber;
		}
		uint64_t BlockHeader::GetWitnessRequirement(const Algorithm::AssetId& Asset) const
		{
			auto It = Witnesses.find(Algorithm::Asset::BaseIdOf(Asset));
			return It != Witnesses.end() ? It->second : 0;
		}
		int8_t BlockHeader::GetRelativeOrder(const BlockHeader& Other) const
		{
			/*
				order priority:
				1. HIGHEST block number
				2. LOWEST  block priority
				3. HIGHEST block cumulative work
				4. HIGHEST block difficulty
				5. HIGHEST block wesolowski number
				6. HIGHEST block gas use
				7. HIGHEST block mutations
				8. LOWEST  block hash
				9. HIGHEST block data (lexicographical order)
			*/
			if (Number != Other.Number)
				return Number > Other.Number ? 1 : -1;

			if (Priority != Other.Priority)
				return Priority < Other.Priority ? 1 : -1;

			if (AbsoluteWork != Other.AbsoluteWork)
				return AbsoluteWork > Other.AbsoluteWork ? 1 : -1;

			if (Recovery != Other.Recovery)
				return Recovery < Other.Recovery ? 1 : -1;

			uint128_t DifficultyA = Target.Difficulty();
			uint128_t DifficultyB = Other.Target.Difficulty();
			if (DifficultyA != DifficultyB)
				return DifficultyA > DifficultyB ? 1 : -1;

			int8_t Security = Provability::WesolowskiVDF::Compare(Wesolowski, Other.Wesolowski);
			if (Security != 0)
				return Security;

			if (GasUse != Other.GasUse)
				return GasUse > Other.GasUse ? 1 : -1;

			uint256_t MutationsA = uint256_t(TransactionsCount) * uint256_t(StatesCount);
			uint256_t MutationsB = uint256_t(Other.TransactionsCount) * uint256_t(Other.StatesCount);
			if (MutationsA != MutationsB)
				return MutationsA > MutationsB ? 1 : -1;

			Format::Stream MessageA;
			if (!Store(&MessageA))
				return -1;

			Format::Stream MessageB;
			if (!Other.Store(&MessageB))
				return 1;

			uint256_t HashA = MessageA.Hash();
			uint256_t HashB = MessageB.Hash();
			if (HashA != HashB)
				return HashA > HashB ? -1 : 1;

			return MessageA.Data.compare(MessageB.Data);
		}
		uint256_t BlockHeader::GetSlotGasUse() const
		{
			return SlotGasUse / GetSlotLength();
		}
		uint256_t BlockHeader::GetSlotGasTarget() const
		{
			return SlotGasTarget / GetSlotLength();
		}
		uint64_t BlockHeader::GetSlotDuration() const
		{
			return (SlotDuration + GetDuration()) / GetSlotLength();
		}
		uint64_t BlockHeader::GetSlotLength() const
		{
			auto Interval = Provability::WesolowskiVDF::AdjustmentInterval();
			return Number < Interval ? Number : ((Number % Interval) + 1);
		}
		uint64_t BlockHeader::GetDuration() const
		{
			uint64_t ProofTime = GetProofTime();
			return ProofTime > Time ? ProofTime - Time : 0;
		}
		uint64_t BlockHeader::GetProofTime() const
		{
			return Provability::WesolowskiVDF::Locktime(Wesolowski);
		}
		UPtr<Schema> BlockHeader::AsSchema() const
		{
			Algorithm::Pubkeyhash Proposer = { 0 };
			bool HasProposer = Recover(Proposer);
			Schema* Data = Var::Set::Object();
			Data->Set("wesolowski", Var::String(Format::Util::Encode0xHex(Wesolowski)));
			Data->Set("signature", Var::String(Format::Util::Encode0xHex(std::string_view((char*)Signature, sizeof(Signature)))));
			Data->Set("proposer", HasProposer ? Algorithm::Signing::SerializeAddress(Proposer) : Var::Set::Null());
			Data->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(AsHash())));
			Data->Set("parent_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ParentHash)));
			Data->Set("transactions_root", Var::String(Algorithm::Encoding::Encode0xHex256(TransactionsRoot)));
			Data->Set("receipts_root", Var::String(Algorithm::Encoding::Encode0xHex256(ReceiptsRoot)));
			Data->Set("states_root", Var::String(Algorithm::Encoding::Encode0xHex256(StatesRoot)));
			Data->Set("absolute_work", Algorithm::Encoding::SerializeUint256(AbsoluteWork));
			Data->Set("difficulty", Algorithm::Encoding::SerializeUint256(Target.Difficulty()));
			Data->Set("gas_use", Algorithm::Encoding::SerializeUint256(GasUse));
			Data->Set("gas_limit", Algorithm::Encoding::SerializeUint256(GasLimit));
			Data->Set("slot_gas_use", Algorithm::Encoding::SerializeUint256(GetSlotGasUse()));
			Data->Set("slot_gas_target", Algorithm::Encoding::SerializeUint256(GetSlotGasTarget()));
			Data->Set("slot_duration", Algorithm::Encoding::SerializeUint256(GetSlotDuration()));
			Data->Set("slot_length", Algorithm::Encoding::SerializeUint256(GetSlotLength()));
			Data->Set("proposal_time", Algorithm::Encoding::SerializeUint256(Time));
			Data->Set("approval_time", Algorithm::Encoding::SerializeUint256(GetProofTime()));
			Data->Set("wesolowski_time", Algorithm::Encoding::SerializeUint256(GetDuration()));
			Data->Set("priority", Algorithm::Encoding::SerializeUint256(Priority));
			Data->Set("number", Algorithm::Encoding::SerializeUint256(Number));
			Data->Set("recovery", Algorithm::Encoding::SerializeUint256(Recovery));
			Data->Set("mutations_count", Algorithm::Encoding::SerializeUint256(MutationsCount));
			Data->Set("transactions_count", Algorithm::Encoding::SerializeUint256(TransactionsCount));
			Data->Set("states_count", Algorithm::Encoding::SerializeUint256(StatesCount));
			auto* WitnessesData = Data->Set("witnesses", Var::Set::Array());
			for (auto& Item : Witnesses)
			{
				auto* WitnessData = WitnessesData->Push(Var::Set::Object());
				WitnessData->Set("asset", Algorithm::Asset::Serialize(Item.first));
				WitnessData->Set("number", Algorithm::Encoding::SerializeUint256(Item.second));
			}
			return Data;
		}
		uint256_t BlockHeader::AsHash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			Format::Stream Message;
			((BlockHeader*)this)->Checksum = BlockHeader::Store(&Message) ? Message.Hash() : uint256_t(0);
			return Checksum;
		}
		uint32_t BlockHeader::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view BlockHeader::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t BlockHeader::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view BlockHeader::AsInstanceTypename()
		{
			return "block";
		}
		uint256_t BlockHeader::GetGasLimit()
		{
			static uint256_t Limit = Transactions::Transfer().GetGasEstimate() * (uint64_t)std::ceil((double)Protocol::Now().Policy.ConsensusProofTime * (double)Protocol::Now().Policy.TransactionThroughput / 1000.0);
			return Limit;
		}

		Block::Block(const BlockHeader& Other) : BlockHeader(Other)
		{
		}
		ExpectsLR<void> Block::Evaluate(const BlockHeader* ParentBlock, EvaluationContext* Environment, String* Errors)
		{
			VI_ASSERT(Environment != nullptr, "evaluation context should be set");
			if (Environment->Incoming.empty())
				return LayerException("empty block is not valid");

			BlockHeader::SetParentBlock(ParentBlock);
			auto Position = std::find_if(Environment->Proposers.begin(), Environment->Proposers.end(), [&Environment](const States::AccountWork& A) { return !memcmp(A.Owner, Environment->Proposer.PublicKeyHash, sizeof(Environment->Proposer.PublicKeyHash)); });
			auto PrevDuration = ParentBlock ? ParentBlock->GetSlotDuration() : (uint64_t)((double)Protocol::Now().Policy.ConsensusProofTime * Protocol::Now().Policy.GenesisSlotTimeBump);
			auto PrevTarget = ParentBlock ? ParentBlock->Target : Provability::WesolowskiVDF::GetDefault();
			if (ParentBlock && ParentBlock->Recovery)
				PrevTarget = Provability::WesolowskiVDF::Bump(Target, 1.0 / Protocol::Now().Policy.ConsensusRecoveryBump);

			Recovery = (Position == Environment->Proposers.end() ? 1 : 0);
			Priority = Recovery ? 0 : (uint64_t)std::distance(Environment->Proposers.begin(), Position);
			Target = Provability::WesolowskiVDF::Adjust(PrevTarget, PrevDuration, Number);
			if (Recovery)
				Target = Provability::WesolowskiVDF::Bump(Target, Protocol::Now().Policy.ConsensusRecoveryBump);

			BlockWork Cache;
			for (auto& Item : Environment->Incoming)
			{
				auto Validation = TransactionContext::ValidateTx(this, Environment, *Item.Candidate, Item.Hash, Item.Owner, Cache);
				if (!Validation)
				{
					if (Errors != nullptr)
						Errors->append(Stringify::Text("\n  in transaction %s validation error: %s", Algorithm::Encoding::Encode0xHex256(Item.Hash).c_str(), Validation.Error().what()));
				Cleanup:
					Environment->Outgoing.push_back(Item.Hash);
					continue;
				}

				auto& Context = *Validation;
				auto Finalization = TransactionContext::ExecuteTx(Context, Item.Size, !Item.Candidate->Conservative);
				if (!Finalization)
				{
					if (Errors != nullptr)
						Errors->append(Stringify::Text("\n  in transaction %s execution error: %s", Algorithm::Encoding::Encode0xHex256(Item.Hash).c_str(), Finalization.Error().what()));
					goto Cleanup;
				}

				auto& Blob = Transactions.emplace_back();
				Blob.Transaction = std::move(Item.Candidate);
				Blob.Receipt = std::move(Context.Receipt);
				States.Commit();
			}

			if (Transactions.empty())
			{
				if (!Errors)
					return LayerException("block does not have any valid transaction");
				else if (Errors->empty())
					Errors->assign("\n  block does not have any valid transactions");

				return LayerException(String(*Errors));
			}

			size_t Participants = (size_t)(Priority + 1);
			uint256_t GasPenalty = Participants > 0 ? (GasUse / Participants) : uint256_t(0);
			for (size_t i = 0; i < Participants; i++)
			{
				bool Winner = (i == Priority);
				auto& Participant = Environment->Proposers[i];
				auto Work = Winner ? Environment->Validation.Context.ApplyAccountWork(Participant.Owner, Participant.Status != WorkStatus::Online ? WorkStatus::Online : WorkStatus::Standby, 0, GasUse, 0) : Environment->Validation.Context.ApplyAccountWork(Participant.Owner, WorkStatus::Offline, 1, 0, GasPenalty);
				if (!Work)
					return Work.Error();
			}

			States.Commit();
			Recalculate(ParentBlock);
			return Expectation::Met;
		}
		ExpectsLR<void> Block::Validate(const BlockHeader* ParentBlock, Block* EvaluatedBlock) const
		{
			if (ParentBlock && (ParentBlock->Number != Number - 1 || ParentBlock->AsHash() != ParentHash))
				return LayerException("invalid parent block");

			Algorithm::Pubkeyhash Proposer = { 0 };
			if (!Recover(Proposer))
				return LayerException("invalid proposer signature");

			EvaluationContext Environment;
			if (!Environment.Priority(Proposer, nullptr, Option<BlockHeader*>((BlockHeader*)ParentBlock)))
			{
				if (!Recovery)
					return LayerException("invalid proposer election");

				auto PrevDuration = ParentBlock ? ParentBlock->GetSlotDuration() : (uint64_t)((double)Protocol::Now().Policy.ConsensusProofTime * Protocol::Now().Policy.GenesisSlotTimeBump);
				auto PrevTarget = ParentBlock ? ParentBlock->Target : Provability::WesolowskiVDF::GetDefault();
				if (ParentBlock && ParentBlock->Recovery)
					PrevTarget = Provability::WesolowskiVDF::Bump(Target, 1.0 / Protocol::Now().Policy.ConsensusRecoveryBump);

				auto CandidateTarget = Provability::WesolowskiVDF::Bump(Provability::WesolowskiVDF::Adjust(PrevTarget, PrevDuration, Number), Protocol::Now().Policy.ConsensusRecoveryBump);
				if (Target.Difficulty() != CandidateTarget.Difficulty())
					return LayerException("invalid proposer election");
			}

			UnorderedMap<uint256_t, std::pair<const BlockTransaction*, const EvaluationContext::TransactionInfo*>> Childs;
			Environment.Incoming.reserve(Transactions.size());
			for (auto& Transaction : Transactions)
			{
				auto& Info = Environment.Include(Transactions::Resolver::Copy(*Transaction.Transaction));
				Childs[Transaction.Receipt.TransactionHash] = std::make_pair(&Transaction, (const EvaluationContext::TransactionInfo*)&Info);
			}

			auto Evaluation = Environment.Evaluate();
			if (!Evaluation)
				return Evaluation.Error();

			auto& Result = *Evaluation;
			for (auto& Transaction : Result.Transactions)
			{
				auto It = Childs.find(Transaction.Receipt.TransactionHash);
				if (It == Childs.end())
					return LayerException("transaction " + Algorithm::Encoding::Encode0xHex256(Transaction.Receipt.TransactionHash) + " not found in block");

				auto& Child = It->second;
				if (memcmp(Transaction.Receipt.From, Child.second->Owner, sizeof(Child.second->Owner)) != 0)
					return LayerException("transaction " + Algorithm::Encoding::Encode0xHex256(Transaction.Receipt.TransactionHash) + " public key recovery failed");

				Transaction.Receipt.GenerationTime = Child.first->Receipt.GenerationTime;
				Transaction.Receipt.FinalizationTime = Child.first->Receipt.FinalizationTime;
				Transaction.Receipt.Checksum = 0;
			}

			memcpy(Result.Signature, Signature, sizeof(Signature));
			Result.Wesolowski = Wesolowski;
			Result.Time = Time;
			Result.Recalculate(ParentBlock);

			size_t CurrentStatesCount = States.At(WorkCommitment::Finalized).size() + States.At(WorkCommitment::Pending).size();
			bool PrunedStateTrie = CurrentStatesCount != StatesCount;
			if (PrunedStateTrie)
			{
				auto* Mutable = (Block*)this;
				auto Copy = std::move(Mutable->States);
				Mutable->States = Result.States;
				bool Matching = Result.AsMessage().Data == AsMessage().Data;
				Mutable->States = std::move(Copy);
				if (!Matching)
					return LayerException("evaluated block does not match proposed block");
			}
			else if (Result.AsMessage().Data != AsMessage().Data)
				return LayerException("evaluated block does not match proposed block");

			auto Validity = Result.VerifyValidity(ParentBlock);
			if (!Validity)
				return Validity;

			auto Integrity = Result.VerifyIntegrity(ParentBlock);
			if (!Integrity)
				return Integrity;
			
			if (EvaluatedBlock != nullptr)
				*EvaluatedBlock = std::move(Result);

			return Expectation::Met;
		}
		ExpectsLR<void> Block::VerifyIntegrity(const BlockHeader* ParentBlock) const
		{
			if (Transactions.empty() || TransactionsCount != (uint32_t)Transactions.size())
				return LayerException("invalid transactions count");
			else if (!StatesCount || StatesCount != (uint32_t)States.At(WorkCommitment::Finalized).size())
				return LayerException("invalid states count");

			if (!ParentBlock && Number > 1)
				return Expectation::Met;

			Provability::MerkleTree Tree = (ParentBlock ? ParentBlock->TransactionsRoot : uint256_t(0));
			for (auto& Item : Transactions)
				Tree.Push(Item.Receipt.TransactionHash);
			if (Tree.CalculateRoot() != TransactionsRoot)
				return LayerException("invalid transactions merkle tree root");

			Tree = (ParentBlock ? ParentBlock->ReceiptsRoot : uint256_t(0));
			for (auto& Item : Transactions)
				Tree.Push(Item.Receipt.AsHash());
			if (Tree.CalculateRoot() != ReceiptsRoot)
				return LayerException("invalid receipts merkle tree root");

			Tree = (ParentBlock ? ParentBlock->StatesRoot : uint256_t(0));
			for (auto& Item : States.At(WorkCommitment::Finalized))
				Tree.Push(Item.second->AsHash());
			if (Tree.CalculateRoot() != StatesRoot)
				return LayerException("invalid states merkle tree root");

			return Expectation::Met;
		}
		ExpectsLR<BlockCheckpoint> Block::Checkpoint(bool KeepRevertedTransactions) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto ChainSession = Chain.MultiTxBegin("chainwork", "apply", LDB::Isolation::Default);
			if (!ChainSession)
				return LayerException(std::move(ChainSession.Error().message()));

			UnorderedSet<uint256_t> FinalizedTransactions;
			FinalizedTransactions.reserve(Transactions.size());
			for (auto& Transaction : Transactions)
				FinalizedTransactions.insert(Transaction.Receipt.TransactionHash);

			BlockCheckpoint Mutation;
			Mutation.OldTipBlockNumber = Chain.GetLatestBlockNumber().Or(0);
			Mutation.NewTipBlockNumber = Number;
			Mutation.BlockDelta = 1;
			Mutation.TransactionDelta = TransactionsCount;
			Mutation.StateDelta = StatesCount;
			Mutation.IsFork = Mutation.OldTipBlockNumber > 0 && Mutation.OldTipBlockNumber >= Mutation.NewTipBlockNumber;
			if (Mutation.IsFork)
			{
				if (KeepRevertedTransactions)
				{
					auto Mempool = Storages::Mempoolstate(__func__);
					auto MempoolSession = Mempool.TxBegin("mempoolwork", "apply", LDB::Isolation::Default);
					if (!MempoolSession)
					{
						Chain.MultiTxRollback("chainwork", "apply");
						return LayerException(std::move(MempoolSession.Error().message()));
					}

					uint64_t RevertNumber = Mutation.OldTipBlockNumber;
					while (RevertNumber >= Mutation.NewTipBlockNumber)
					{
						size_t Offset = 0, Count = 512;
						while (true)
						{
							auto Transactions = Chain.GetTransactionsByNumber(RevertNumber, Offset, Count);
							if (!Transactions || Transactions->empty())
								break;

							for (auto& Item : *Transactions)
							{
								if (FinalizedTransactions.find(Item->AsHash()) == FinalizedTransactions.end())
								{
									auto Status = Mempool.AddTransaction(**Item, true);
									Status.Report("transaction resurrection failed");
									Mutation.MempoolTransactions += Status ? 1 : 0;
								}
							}

							Offset += Transactions->size();
							if (Transactions->size() < Count)
								break;
						}
						--RevertNumber;
					}

					auto Status = Chain.Revert(Mutation.NewTipBlockNumber - 1, &Mutation.BlockDelta, &Mutation.TransactionDelta, &Mutation.StateDelta);
					if (!Status)
					{
						Chain.MultiTxRollback("chainwork", "apply");
						Mempool.TxRollback("mempoolwork", "apply");
						return Status.Error();
					}

					if (Protocol::Now().User.Storage.Logging)
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", mempool: +%" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", Algorithm::Encoding::Encode0xHex256(AsHash()).c_str(), Mutation.NewTipBlockNumber, Mutation.MempoolTransactions, Mutation.BlockDelta, Mutation.TransactionDelta, Mutation.StateDelta);

					Status = Chain.Checkpoint(*this);
					if (!Status)
					{
						Chain.MultiTxRollback("chainwork", "apply");
						Mempool.TxRollback("mempoolwork", "apply");
						return Status.Error();
					}

					auto Result = Chain.MultiTxCommit("chainwork", "apply");
					if (!Result)
					{
						Mempool.TxRollback("mempoolwork", "apply");
						return LayerException(std::move(Result.Error().message()));
					}

					Mempool.RemoveTransactions(FinalizedTransactions).Report("mempool cleanup failed");
					Mempool.TxCommit("mempoolwork", "apply").Report("mempool commit failed");
				}
				else
				{
					auto Status = Chain.Revert(Mutation.NewTipBlockNumber - 1, &Mutation.BlockDelta, &Mutation.TransactionDelta, &Mutation.StateDelta);
					if (!Status)
					{
						Chain.MultiTxRollback("chainwork", "apply");
						return Status.Error();
					}

					if (Protocol::Now().User.Storage.Logging)
						VI_INFO("[checkpoint] revert chain to block %s (height: %" PRIu64 ", blocktrie: %" PRIi64 ", transactiontrie: %" PRIi64 ", statetrie: %" PRIi64 ")", Algorithm::Encoding::Encode0xHex256(AsHash()).c_str(), Mutation.NewTipBlockNumber, Mutation.BlockDelta, Mutation.TransactionDelta, Mutation.StateDelta);

					Status = Chain.Checkpoint(*this);
					if (!Status)
					{
						Chain.MultiTxRollback("chainwork", "apply");
						return Status.Error();
					}

					auto Result = Chain.MultiTxCommit("chainwork", "apply");
					if (!Result)
						return LayerException(std::move(Result.Error().message()));
				}
			}
			else
			{
				auto Status = Chain.Checkpoint(*this);
				if (!Status)
				{
					Chain.MultiTxRollback("chainwork", "apply");
					return Status.Error();
				}

				auto Result = Chain.MultiTxCommit("chainwork", "apply");
				if (!Result)
					return LayerException(std::move(Result.Error().message()));

				auto Mempool = Storages::Mempoolstate(__func__);
				Mempool.RemoveTransactions(FinalizedTransactions).Report("mempool cleanup failed");
			}
			return Mutation;
#else
			return LayerException("chainstate and mempool are not available");
#endif
		}
		bool Block::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!StoreHeaderPayload(Stream))
				return false;

			if (!StoreBodyPayload(Stream))
				return false;

			return true;
		}
		bool Block::LoadPayload(Format::Stream& Stream)
		{
			if (!LoadHeaderPayload(Stream))
				return false;

			if (!LoadBodyPayload(Stream))
				return false;

			return true;
		}
		bool Block::StoreHeaderPayload(Format::Stream* Stream) const
		{
			return BlockHeader::StorePayload(Stream);
		}
		bool Block::LoadHeaderPayload(Format::Stream& Stream)
		{
			return BlockHeader::LoadPayload(Stream);
		}
		bool Block::StoreBodyPayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger((uint32_t)Transactions.size());
			for (auto& Item : Transactions)
				Item.StorePayload(Stream);

			Stream->WriteInteger((uint32_t)States.At(WorkCommitment::Finalized).size());
			for (auto& Item : States.At(WorkCommitment::Finalized))
				Item.second->Store(Stream);
			return true;
		}
		bool Block::LoadBodyPayload(Format::Stream& Stream)
		{
			uint32_t TransactionsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsSize))
				return false;

			Transactions.clear();
			Transactions.reserve(TransactionsSize);
			for (size_t i = 0; i < TransactionsSize; i++)
			{
				BlockTransaction Value;
				if (!Value.LoadPayload(Stream))
					return false;

				Transactions.emplace_back(std::move(Value));
			}

			uint32_t StatesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &StatesSize))
				return false;

			States.Clear();
			for (size_t i = 0; i < StatesSize; i++)
			{
				UPtr<Ledger::State> Value = States::Resolver::New(Messages::Generic::ResolveType(Stream).Or(0));
				if (!Value || !Value->Load(Stream))
					return false;

				States.MoveAny(std::move(Value));
			}

			States.Commit();
			return true;
		}
		void Block::Recalculate(const BlockHeader* ParentBlock)
		{
			auto& StateTree = States.At(WorkCommitment::Finalized);
			auto TaskQueue1 = ParallelForEachNode(StateTree.begin(), StateTree.end(), StateTree.size(), [](const std::pair<const String, UPtr<Ledger::State>>& Item) { Item.second->AsHash(); });
			auto TaskQueue2 = ParallelForEach(Transactions.begin(), Transactions.end(), [](BlockTransaction& Item) { Item.Receipt.AsHash(); });
			Parallel::WailAll(std::move(TaskQueue1));
			Parallel::WailAll(std::move(TaskQueue2));

			Provability::MerkleTree Tree = (ParentBlock ? ParentBlock->TransactionsRoot : uint256_t(0));
			for (auto& Item : Transactions)
				Tree.Push(Item.Receipt.TransactionHash);
			TransactionsRoot = Tree.CalculateRoot();

			Tree = (ParentBlock ? ParentBlock->ReceiptsRoot : uint256_t(0));
			for (auto& Item : Transactions)
				Tree.Push(Item.Receipt.AsHash());
			ReceiptsRoot = Tree.CalculateRoot();

			Tree = (ParentBlock ? ParentBlock->StatesRoot : uint256_t(0));
			for (auto& Item : StateTree)
				Tree.Push(Item.second->AsHash());
			StatesRoot = Tree.CalculateRoot();

			uint256_t Cumulative = GetSlotLength() > 1 ? 1 : 0;
			AbsoluteWork = (ParentBlock ? ParentBlock->AbsoluteWork : uint256_t(0)) + GasUtil::GetGasWork(Target.Difficulty(), GasUse, GasLimit);
			SlotGasUse = (ParentBlock ? ParentBlock->SlotGasUse : uint256_t(0)) * Cumulative + GasUse;
			SlotGasTarget = (ParentBlock ? ParentBlock->SlotGasTarget : uint256_t(0)) * Cumulative + (Transactions.size() > 0 ? GasUse / Transactions.size() : uint256_t(0));
			SlotDuration = (ParentBlock ? ParentBlock->SlotDuration + ParentBlock->GetDuration() : uint256_t(0)) * Cumulative;
			TransactionsCount = (uint32_t)Transactions.size();
			StatesCount = (uint32_t)StateTree.size();
		}
		void Block::InheritWork(const Block* ParentBlock)
		{
			States.ParentWork = ParentBlock ? &ParentBlock->States : nullptr;
		}
		void Block::InheritWork(const BlockWork* ParentWork)
		{
			States.ParentWork = ParentWork;
		}
		UPtr<Schema> Block::AsSchema() const
		{
			Schema* Data = BlockHeader::AsSchema().Reset();
			auto* TransactionsData = Data->Set("transactions", Var::Set::Array());
			for (auto& Item : Transactions)
				TransactionsData->Push(Item.AsSchema().Reset());
			auto* StatesData = Data->Set("states", Var::Set::Array());
			for (auto& Item : States.At(WorkCommitment::Finalized))
				StatesData->Push(Item.second->AsSchema().Reset());
			return Data;
		}
		BlockHeader Block::AsHeader() const
		{
			return BlockHeader(*this);
		}
		BlockProof Block::AsProof(const BlockHeader* ParentBlock) const
		{
			auto Proof = BlockProof(*this, ParentBlock);
			Proof.Transactions.reserve(Transactions.size());
			Proof.Receipts.reserve(Transactions.size());
			for (auto& Item : Transactions)
			{
				Proof.Transactions.push_back(Item.Receipt.TransactionHash);
				Proof.Receipts.push_back(Item.Receipt.AsHash());
			}

			Proof.States.reserve(States.At(WorkCommitment::Finalized).size());
			for (auto& Item : States.At(WorkCommitment::Finalized))
				Proof.States.push_back(Item.second->AsHash());

			return Proof;
		}
		uint256_t Block::AsHash(bool Renew) const
		{
			return AsHeader().AsHash(Renew);
		}

		BlockProof::BlockProof(const BlockHeader& FromBlock, const BlockHeader* FromParentBlock)
		{
			Internal.TransactionsTree = Provability::MerkleTree(FromParentBlock ? FromParentBlock->TransactionsRoot : uint256_t(0));
			Internal.ReceiptsTree = Provability::MerkleTree(FromParentBlock ? FromParentBlock->ReceiptsRoot : uint256_t(0));
			Internal.StatesTree = Provability::MerkleTree(FromParentBlock ? FromParentBlock->StatesRoot : uint256_t(0));
			TransactionsRoot = FromBlock.TransactionsRoot;
			ReceiptsRoot = FromBlock.ReceiptsRoot;
			StatesRoot = FromBlock.StatesRoot;
		}
		Option<Provability::MerkleTree::Path> BlockProof::FindTransaction(const uint256_t& Hash)
		{
			auto Path = GetTransactionsTree().CalculatePath(Hash);
			if (Path.Empty())
				return Optional::None;

			return Path;
		}
		Option<Provability::MerkleTree::Path> BlockProof::FindReceipt(const uint256_t& Hash)
		{
			auto Path = GetReceiptsTree().CalculatePath(Hash);
			if (Path.Empty())
				return Optional::None;

			return Path;
		}
		Option<Provability::MerkleTree::Path> BlockProof::FindState(const uint256_t& Hash)
		{
			auto Path = GetStatesTree().CalculatePath(Hash);
			if (Path.Empty())
				return Optional::None;

			return Path;
		}
		bool BlockProof::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(TransactionsRoot);
			Stream->WriteInteger((uint32_t)Transactions.size());
			for (auto& Item : Transactions)
				Stream->WriteInteger(Item);

			Stream->WriteInteger(ReceiptsRoot);
			Stream->WriteInteger((uint32_t)Receipts.size());
			for (auto& Item : Receipts)
				Stream->WriteInteger(Item);

			Stream->WriteInteger(StatesRoot);
			Stream->WriteInteger((uint32_t)States.size());
			for (auto& Item : States)
				Stream->WriteInteger(Item);

			return true;
		}
		bool BlockProof::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsRoot))
				return false;

			uint32_t TransactionsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsSize))
				return false;

			Transactions.resize(TransactionsSize);
			for (size_t i = 0; i < TransactionsSize; i++)
			{
				if (!Stream.ReadInteger(Stream.ReadType(), &Transactions[i]))
					return false;
			}

			if (!Stream.ReadInteger(Stream.ReadType(), &ReceiptsRoot))
				return false;

			uint32_t ReceiptsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &ReceiptsSize))
				return false;

			Receipts.resize(ReceiptsSize);
			for (size_t i = 0; i < ReceiptsSize; i++)
			{
				if (!Stream.ReadInteger(Stream.ReadType(), &Receipts[i]))
					return false;
			}

			if (!Stream.ReadInteger(Stream.ReadType(), &StatesRoot))
				return false;

			uint32_t StatesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &StatesSize))
				return false;

			States.resize(StatesSize);
			for (size_t i = 0; i < StatesSize; i++)
			{
				if (!Stream.ReadInteger(Stream.ReadType(), &States[i]))
					return false;
			}

			return true;
		}
		bool BlockProof::HasTransaction(const uint256_t& Hash)
		{
			auto Path = FindTransaction(Hash);
			return Path && Path->CalculateRoot(Hash) == TransactionsRoot;
		}
		bool BlockProof::HasReceipt(const uint256_t& Hash)
		{
			auto Path = FindReceipt(Hash);
			return Path && Path->CalculateRoot(Hash) == ReceiptsRoot;
		}
		bool BlockProof::HasState(const uint256_t& Hash)
		{
			auto Path = FindState(Hash);
			return Path && Path->CalculateRoot(Hash) == StatesRoot;
		}
		Provability::MerkleTree& BlockProof::GetTransactionsTree()
		{
			if (!Internal.TransactionsTree.IsCalculated() || Internal.TransactionsTree.GetTree().size() < Transactions.size())
			{
				for (auto& Item : Transactions)
					Internal.TransactionsTree.Push(Item);
			}
			return Internal.TransactionsTree.Calculate();
		}
		Provability::MerkleTree& BlockProof::GetReceiptsTree()
		{
			if (!Internal.ReceiptsTree.IsCalculated() || Internal.ReceiptsTree.GetTree().size() < Receipts.size())
			{
				for (auto& Item : Receipts)
					Internal.ReceiptsTree.Push(Item);
			}
			return Internal.ReceiptsTree.Calculate();
		}
		Provability::MerkleTree& BlockProof::GetStatesTree()
		{
			if (!Internal.StatesTree.IsCalculated() || Internal.StatesTree.GetTree().size() < States.size())
			{
				for (auto& Item : States)
					Internal.StatesTree.Push(Item);
			}
			return Internal.StatesTree.Calculate();
		}
		UPtr<Schema> BlockProof::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			auto* TransactionsData = Data->Set("transactions", Var::Set::Object());
			auto* TransactionsHashes = TransactionsData->Set("hashes", Var::Set::Array());
			auto* TransactionsTree = TransactionsData->Set("tree", Var::Set::Array());
			TransactionsData->Set("root", Var::String(Algorithm::Encoding::Encode0xHex256(TransactionsRoot)));
			if (Internal.TransactionsTree.GetTree().empty())
			{
				for (auto& Item : Transactions)
					TransactionsHashes->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
			}
			else
				TransactionsHashes->Value = Var::Integer(Transactions.size());
			for (auto& Item : Internal.TransactionsTree.GetTree())
				TransactionsTree->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));

			auto* ReceiptsData = Data->Set("receipts", Var::Set::Object());
			auto* ReceiptsHashes = ReceiptsData->Set("hashes", Var::Set::Array());
			auto* ReceiptsTree = ReceiptsData->Set("tree", Var::Set::Array());
			ReceiptsData->Set("root", Var::String(Algorithm::Encoding::Encode0xHex256(ReceiptsRoot)));
			if (Internal.ReceiptsTree.GetTree().empty())
			{
				for (auto& Item : Receipts)
					ReceiptsHashes->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
			}
			else
				ReceiptsHashes->Value = Var::Integer(Receipts.size());
			for (auto& Item : Internal.ReceiptsTree.GetTree())
				ReceiptsTree->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));

			auto* StatesData = Data->Set("states", Var::Set::Object());
			auto* StatesHashes = StatesData->Set("hashes", Var::Set::Array());
			auto* StatesTree = StatesData->Set("tree", Var::Set::Array());
			StatesData->Set("root", Var::String(Algorithm::Encoding::Encode0xHex256(StatesRoot)));
			if (Internal.StatesTree.GetTree().empty())
			{
				for (auto& Item : States)
					StatesHashes->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
			}
			else
				StatesHashes->Value = Var::Integer(States.size());
			for (auto& Item : Internal.StatesTree.GetTree())
				StatesTree->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
			return Data;
		}
		uint32_t BlockProof::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view BlockProof::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t BlockProof::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view BlockProof::AsInstanceTypename()
		{
			return "block_proof";
		}

		TransactionContext::TransactionContext() : Environment(nullptr), Transaction(nullptr), Block(nullptr)
		{
		}
		TransactionContext::TransactionContext(Ledger::Block* NewBlock) : Environment(nullptr), Transaction(nullptr), Block(NewBlock)
		{
			if (NewBlock)
				Delta.Outgoing = &NewBlock->States;
		}
		TransactionContext::TransactionContext(Ledger::BlockHeader* NewBlockHeader) : Environment(nullptr), Transaction(nullptr), Block(NewBlockHeader)
		{
		}
		TransactionContext::TransactionContext(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, Ledger::Receipt&& NewReceipt) : Environment(NewEnvironment), Transaction(NewTransaction), Block(NewBlock), Receipt(std::move(NewReceipt))
		{
			if (NewBlock)
				Delta.Outgoing = &NewBlock->States;
		}
		TransactionContext::TransactionContext(Ledger::BlockHeader* NewBlockHeader, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, Ledger::Receipt&& NewReceipt) : Environment(NewEnvironment), Transaction(NewTransaction), Block(NewBlockHeader), Receipt(std::move(NewReceipt))
		{
		}
		TransactionContext::TransactionContext(const TransactionContext& Other) : Delta(Other.Delta), Environment(Other.Environment), Receipt(Other.Receipt), Block(Other.Block)
		{
			Transaction = Other.Transaction ? Transactions::Resolver::Copy(Other.Transaction) : nullptr;
		}
		TransactionContext& TransactionContext::operator=(const TransactionContext& Other)
		{
			if (this == &Other)
				return *this;

			Delta = Other.Delta;
			Environment = Other.Environment;
			Transaction = Other.Transaction ? Transactions::Resolver::Copy(Other.Transaction) : nullptr;
			Receipt = Other.Receipt;
			Block = Other.Block;
			return *this;
		}
		ExpectsLR<void> TransactionContext::Load(State* Next, bool Paid)
		{
			if (!Next)
				return LayerException("state not found");
			else if (!Paid)
				return Expectation::Met;

			return BurnGas(Next->AsMessage().Data.size() * (size_t)GasCost::ReadByte);
		}
		ExpectsLR<void> TransactionContext::Store(State* Next, bool Paid)
		{
			if (!Next)
				return LayerException("invalid state");
#ifdef TAN_VALIDATOR
			if (Block != nullptr)
			{
				Next->BlockNumber = Block->Number;
				Next->BlockNonce = Block->MutationsCount++;
			}

			if (!Next->BlockNumber)
				return LayerException("invalid state block number");
			else if (!Delta.Outgoing)
				return LayerException("invalid state delta");

			auto Chain = Storages::Chainstate(__func__);
			switch (Next->AsLevel())
			{
				case StateLevel::Uniform:
				{
					auto* State = (Uniform*)Next;
					auto Prev = Chain.GetUniformByIndex(&Delta, State->AsIndex(), GetValidationNonce());
					auto Status = State->Transition(this, Prev ? **Prev : nullptr);
					if (!Status)
						return Status;
					break;
				}
				case StateLevel::Multiform:
				{
					auto* State = (Multiform*)Next;
					auto Prev = Chain.GetMultiformByComposition(&Delta, State->AsColumn(), State->AsRow(), GetValidationNonce());
					auto Status = State->Transition(this, Prev ? **Prev : nullptr);
					if (!Status)
						return Status;
					break;
				}
				default:
					return LayerException("invalid state level");
			}

			if (Paid)
			{
				auto Status = BurnGas(Next->AsMessage().Data.size() * (size_t)GasCost::WriteByte);
				if (!Status)
					return Status;
			}

			Delta.Outgoing->CopyAny(Next);
			return Expectation::Met;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<void> TransactionContext::EmitWitness(uint64_t BlockNumber)
		{
			return EmitWitness(Transaction ? Transaction->Asset : uint256_t(0), BlockNumber);
		}
		ExpectsLR<void> TransactionContext::EmitWitness(const Algorithm::AssetId& Asset, uint64_t BlockNumber)
		{
			if (!Asset || !BlockNumber)
				return LayerException("invalid witness");

			auto& CurrentNumber = Witnesses[Algorithm::Asset::BaseIdOf(Asset)];
			if (CurrentNumber < BlockNumber)
				CurrentNumber = BlockNumber;

			return Expectation::Met;
		}
		ExpectsLR<void> TransactionContext::EmitEvent(uint32_t Event, Format::Variables&& Values, bool Paid)
		{
			if (Paid)
			{
				Format::Stream Stream;
				Format::VariablesUtil::SerializeMergeInto(Values, &Stream);
				Stream.WriteInteger(Event);

				auto Status = BurnGas(Stream.Data.size() * (size_t)GasCost::WriteByte);
				if (!Status)
					return Status;
			}
			Receipt.EmitEvent(Event, std::move(Values));
			return Expectation::Met;
		}
		ExpectsLR<void> TransactionContext::BurnGas()
		{
			if (!Transaction)
				return Expectation::Met;

			return BurnGas(Transaction->GasLimit - Receipt.RelativeGasUse);
		}
		ExpectsLR<void> TransactionContext::BurnGas(const uint256_t& Value)
		{
			if (!Transaction)
				return Expectation::Met;

			Receipt.RelativeGasUse += Value;
			if (Receipt.RelativeGasUse <= Transaction->GasLimit)
				return Expectation::Met;

			Receipt.RelativeGasUse = Transaction->GasLimit;
			return LayerException("ran out of gas");
		}
		ExpectsLR<void> TransactionContext::VerifyAccountSequence() const
		{
			if (!Transaction)
				return LayerException("invalid transaction");

			auto CurrentSequence = GetAccountSequence(Receipt.From);
			if (CurrentSequence && CurrentSequence->Sequence > Transaction->Sequence)
				return LayerException("sequence is invalid (now: " + ToString(CurrentSequence->Sequence) + ")");

			return Expectation::Met;
		}
		ExpectsLR<void> TransactionContext::VerifyAccountWork() const
		{
			return VerifyAccountWork(Receipt.From);
		}
		ExpectsLR<void> TransactionContext::VerifyAccountWork(const Algorithm::Pubkeyhash Owner) const
		{
			if (!Environment)
				return LayerException("invalid evaluation context");

			auto CurrentWork = GetAccountWork(Owner);
			uint256_t CurrentGasWork = CurrentWork ? CurrentWork->GetGasUse() : uint256_t(0);
			uint256_t CurrentGasRequirement = States::AccountWork::GetGasWorkRequired(Block, CurrentGasWork);
			if (CurrentGasRequirement > 0)
				return LayerException((memcmp(Receipt.From, Environment->Proposer.PublicKeyHash, sizeof(Receipt.From)) != 0 ? "work is insufficient (work: " : "proposer's work is insufficient (work: ") + CurrentGasWork.ToString() + ", value: " + CurrentGasRequirement.ToString() + ")");

			auto CurrentContribution = GetAccountContribution(Owner);
			if (CurrentContribution && !CurrentContribution->Honest)
				return LayerException(memcmp(Receipt.From, Environment->Proposer.PublicKeyHash, sizeof(Receipt.From)) != 0 ? "contribution is not honest" : "proposer's contribution is not honest");

			return Expectation::Met;
		}
		ExpectsLR<void> TransactionContext::VerifyGasTransferBalance() const
		{
			if (!Transaction)
				return LayerException("invalid transaction");

			if (!Transaction->GasPrice.IsPositive())
				return Expectation::Met;

			auto CurrentBalance = GetAccountBalance(Transaction->Asset, Receipt.From);
			Decimal MaxPaidValue = Transaction->GasPrice * Transaction->GasLimit.ToDecimal();
			Decimal MaxPayableValue = CurrentBalance ? CurrentBalance->GetBalance() : Decimal::Zero();
			if (MaxPayableValue < MaxPaidValue)
				return LayerException(Algorithm::Asset::HandleOf(Transaction->Asset) + " balance is insufficient (balance: " + MaxPayableValue.ToString() + ", value: " + MaxPaidValue.ToString() + ")");

			return Expectation::Met;
		}
		ExpectsLR<void> TransactionContext::VerifyTransferBalance(const Decimal& Value) const
		{
			if (!Transaction)
				return LayerException("invalid transaction");

			return VerifyTransferBalance(Transaction->Asset, Value);
		}
		ExpectsLR<void> TransactionContext::VerifyTransferBalance(const Algorithm::AssetId& Asset, const Decimal& Value) const
		{
			if (!Transaction)
				return LayerException("invalid transaction");

			Decimal MaxPaidValue = Value;
			if (Transaction->GasPrice.IsPositive())
				MaxPaidValue += Transaction->GasPrice * Transaction->GasLimit.ToDecimal();
			else if (!MaxPaidValue.IsPositive())
				return Expectation::Met;

			auto CurrentBalance = GetAccountBalance(Asset, Receipt.From);
			Decimal MaxPayableValue = CurrentBalance ? CurrentBalance->GetBalance() : Decimal::Zero();
			if (MaxPayableValue < MaxPaidValue)
				return LayerException(Algorithm::Asset::HandleOf(Asset) + " balance is insufficient (balance: " + MaxPayableValue.ToString() + ", value: " + MaxPaidValue.ToString() + ")");

			return Expectation::Met;
		}
		ExpectsLR<Provability::WesolowskiVDF::Distribution> TransactionContext::CalculateRandom(const uint256_t& Seed)
		{
			if (!Block)
				return LayerException("block not found");

			Format::Stream Message;
			Message.WriteTypeless(Block->ParentHash);
			Message.WriteTypeless(Block->Recovery);
			Message.WriteTypeless(Block->Priority);
			Message.WriteTypeless(Block->Target.Difficulty());
			Message.WriteTypeless(Block->MutationsCount);
			Message.WriteTypeless(Seed);

			Provability::WesolowskiVDF::Distribution Distribution;
			Distribution.Signature = Message.Data;
			Distribution.Value = Algorithm::Hashing::Hash256i(*Crypto::HashRaw(Digests::SHA512(), Distribution.Signature));
			return Distribution;
		}
		ExpectsLR<size_t> TransactionContext::CalculateAggregationCommitteeSize(const Algorithm::AssetId& Asset)
		{
#ifdef TAN_VALIDATOR
			auto Nonce = GetValidationNonce();
			auto Chain = Storages::Chainstate(__func__);
			auto Filter = Storages::FactorFilter::Equal((int64_t)Ledger::WorkStatus::Online, 1);
			return Chain.GetMultiformsCountByRowFilter(States::AccountObserver::AsInstanceRow(Asset), Filter, Nonce);
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<Vector<States::AccountWork>> TransactionContext::CalculateProposalCommittee(size_t Majors, size_t Minors, size_t* Proposers)
		{
#ifdef TAN_VALIDATOR
			auto Random = CalculateRandom(0);
			if (!Random)
				return Random.Error();

			auto Nonce = GetValidationNonce();
			auto Chain = Storages::Chainstate(__func__);
			auto Filter = Storages::FactorFilter::GreaterEqual(0, -1);
			auto TotalSize = Chain.GetMultiformsCountByRowFilter(States::AccountWork::AsInstanceRow(), Filter, Nonce).Or(0);
			if (Proposers != nullptr)
				*Proposers = TotalSize;

			if (!TotalSize)
				return LayerException("committee threshold not met");

			size_t MajorsSize = std::min(TotalSize, Majors);
			auto MajorComittee = Chain.GetMultiformsByRowFilter(&Delta, States::AccountWork::AsInstanceRow(), Filter, Nonce, 0, MajorsSize);
			if (!MajorComittee)
				return LayerException("committee threshold not met");

			size_t MinorsSize = std::min(TotalSize - MajorComittee->size(), Minors);
			size_t MinorsOffset = (MinorsSize > 0 ? (size_t)(uint64_t)(Random->Derive() % MinorsSize) : 0) + MajorComittee->size();
			auto MinorCommittee = MinorsSize > 0 ? Chain.GetMultiformsByRowFilter(&Delta, States::AccountWork::AsInstanceRow(), Filter, Nonce, MinorsSize, MinorsSize) : ExpectsLR<Vector<UPtr<Ledger::State>>>(Vector<UPtr<Ledger::State>>());
			if (!MinorCommittee)
				return LayerException("committee threshold not met");

			OrderedSet<String> Composites;
			Vector<States::AccountWork> Secondary;
			for (auto& Proposer : *MinorCommittee)
			{
				auto Composite = Proposer->AsComposite();
				if (Composites.find(Composite) == Composites.end())
				{
					Secondary.emplace_back(std::move(*(States::AccountWork*)*Proposer));
					Composites.insert(Composite);
				}
			}
			std::sort(Secondary.begin(), Secondary.end(), [](const States::AccountWork& A, const States::AccountWork& B) { return A.GetGasUse() < B.GetGasUse(); });

			OrderedSet<uint256_t> Slots;
			Vector<std::pair<States::AccountWork, uint256_t>> Primary;
			for (auto& Proposer : *MajorComittee)
			{
				auto Composite = Proposer->AsComposite();
				if (Composites.find(Composite) == Composites.end())
				{
					uint256_t Slot = Random->Derive();
					while (Slots.find(Slot) != Slots.end())
						Slot = Random->Derive();
					Primary.emplace_back(std::make_pair(std::move(*(States::AccountWork*)*Proposer), Slot));
					Composites.insert(Composite);
					Slots.insert(Slot);
				}
			}

			std::sort(Primary.begin(), Primary.end(), [&](const std::pair<States::AccountWork, uint256_t>& A, const std::pair<States::AccountWork, uint256_t>& B) { return A.second < B.second; });
			Secondary.reserve(Secondary.size() + Primary.size());
			for (auto& Slot : Primary)
				Secondary.emplace_back(std::move(Slot.first));

			if (Secondary.empty())
				return LayerException("committee threshold not met");

			return Secondary;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountWork> TransactionContext::CalculateSharingWitness(const OrderedSet<String>& Owners, bool WorkRequired)
		{
#ifdef TAN_VALIDATOR
			auto Random = CalculateRandom(1);
			if (!Random)
				return Random.Error();

			auto Nonce = GetValidationNonce();
			auto Chain = Storages::Chainstate(__func__);
			auto Filter = Storages::FactorFilter::GreaterEqual(0, -1);
			uint64_t CurrentCommitteeSize = (uint64_t)Chain.GetMultiformsCountByRowFilter(States::AccountWork::AsInstanceRow(), Filter, Nonce).Or(0);
			UnorderedSet<size_t> Indices;

			while (Indices.size() < CurrentCommitteeSize)
			{
				size_t Index = (size_t)(uint64_t)(Random->Derive() % CurrentCommitteeSize);
				if (Indices.find(Index) == Indices.end())
				{
					auto Tree = Chain.GetMultiformsByRowFilter(&Delta, States::AccountWork::AsInstanceRow(), Filter, Nonce, Index, 1);
					auto* Work = (States::AccountWork*)*Tree->front();
					if (Owners.find(String((char*)Work->Owner, sizeof(Work->Owner))) == Owners.end() && ((!WorkRequired || VerifyAccountWork(Work->Owner))))
						return *Work;
					Indices.insert(Index);
				}
			}

			return LayerException("proposer not found");
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountSequence> TransactionContext::ApplyAccountSequence()
		{
			return ApplyAccountSequence(Receipt.From, (Transaction ? Transaction->Sequence : 0) + 1);
		}
		ExpectsLR<States::AccountSequence> TransactionContext::ApplyAccountSequence(const Algorithm::Pubkeyhash Owner, uint64_t Sequence)
		{
			States::AccountSequence NewState = States::AccountSequence(Owner, Block);
			NewState.Sequence = Sequence;

			auto Status = Store(&NewState, false);
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::AccountWork> TransactionContext::ApplyAccountWork(const Algorithm::Pubkeyhash Owner, WorkStatus Status, uint64_t Penalty, const uint256_t& GasInput, const uint256_t& GasOutput)
		{
			States::AccountWork NewState = States::AccountWork(Owner, Block);
			NewState.GasInput = GasInput;
			NewState.GasOutput = GasOutput;
			NewState.Status = Status;
			if (Penalty > 0)
				NewState.Penalty = (Block ? Block->Number : 0) + Penalty * (Protocol::Now().Policy.ConsensusPenaltyPointTime / Protocol::Now().Policy.ConsensusProofTime);

			auto Result = Store(&NewState);
			if (!Result)
				return Result.Error();

			return NewState;
		}
		ExpectsLR<States::AccountObserver> TransactionContext::ApplyAccountObserver(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, WorkStatus Status)
		{
			States::AccountObserver NewState = States::AccountObserver(Owner, Block);
			NewState.Asset = Asset;
			NewState.Status = Status;

			auto Result = Store(&NewState);
			if (!Result)
				return Result.Error();

			return NewState;
		}
		ExpectsLR<States::AccountProgram> TransactionContext::ApplyAccountProgram(const std::string_view& ProgramHashcode)
		{
			return ApplyAccountProgram(Receipt.From, ProgramHashcode);
		}
		ExpectsLR<States::AccountProgram> TransactionContext::ApplyAccountProgram(const Algorithm::Pubkeyhash Owner, const std::string_view& ProgramHashcode)
		{
			States::AccountProgram NewState = States::AccountProgram(Owner, Block);
			NewState.Hashcode = ProgramHashcode;

			auto Result = Store(&NewState);
			if (!Result)
				return Result.Error();

			return NewState;
		}
		ExpectsLR<States::AccountStorage> TransactionContext::ApplyAccountStorage(const std::string_view& Location, const std::string_view& Storage)
		{
			return ApplyAccountStorage(Receipt.From, Location, Storage);
		}
		ExpectsLR<States::AccountStorage> TransactionContext::ApplyAccountStorage(const Algorithm::Pubkeyhash Owner, const std::string_view& Location, const std::string_view& Storage)
		{
			States::AccountStorage NewState = States::AccountStorage(Owner, Block);
			NewState.Location = Location;
			NewState.Storage = Storage;

			auto Result = Store(&NewState);
			if (!Result)
				return Result.Error();

			return NewState;
		}
		ExpectsLR<States::AccountReward> TransactionContext::ApplyAccountReward(const Algorithm::Pubkeyhash Owner, const Decimal& IncomingAbsoluteFee, const Decimal& IncomingRelativeFee, const Decimal& OutgoingAbsoluteFee, const Decimal& OutgoingRelativeFee)
		{
			return ApplyAccountReward(Transaction ? Transaction->Asset : uint256_t(0), Owner, IncomingAbsoluteFee, IncomingRelativeFee, OutgoingAbsoluteFee, OutgoingRelativeFee);
		}
		ExpectsLR<States::AccountReward> TransactionContext::ApplyAccountReward(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& IncomingAbsoluteFee, const Decimal& IncomingRelativeFee, const Decimal& OutgoingAbsoluteFee, const Decimal& OutgoingRelativeFee)
		{
			States::AccountReward NewState = States::AccountReward(Owner, Block);
			NewState.IncomingAbsoluteFee = IncomingAbsoluteFee;
			NewState.IncomingRelativeFee = IncomingRelativeFee;
			NewState.OutgoingAbsoluteFee = OutgoingAbsoluteFee;
			NewState.OutgoingRelativeFee = OutgoingRelativeFee;
			NewState.Asset = Asset;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::AccountDerivation> TransactionContext::ApplyAccountDerivation(const Algorithm::Pubkeyhash Owner, uint64_t MaxAddressIndex)
		{
			return ApplyAccountDerivation(Transaction ? Transaction->Asset : uint256_t(0), Owner, MaxAddressIndex);
		}
		ExpectsLR<States::AccountDerivation> TransactionContext::ApplyAccountDerivation(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, uint64_t MaxAddressIndex)
		{
			States::AccountDerivation NewState = States::AccountDerivation(Owner, Block);
			NewState.Asset = Asset;
			NewState.MaxAddressIndex = MaxAddressIndex;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::AccountContribution> TransactionContext::ApplyAccountContribution(const Algorithm::Pubkeyhash Owner, const Decimal& Custody, ContributionMap&& Contributions, ReservationMap&& Reservations, Option<double>&& Threshold)
		{
			return ApplyAccountContribution(Transaction ? Transaction->Asset : uint256_t(0), Owner, Custody, std::move(Contributions), std::move(Reservations), std::move(Threshold));
		}
		ExpectsLR<States::AccountContribution> TransactionContext::ApplyAccountContribution(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& Custody, ContributionMap&& Contributions, ReservationMap&& Reservations, Option<double>&& Threshold)
		{
			States::AccountContribution NewState = States::AccountContribution(Owner, Block);
			NewState.Asset = Asset;
			NewState.Custody = Custody.IsNaN() ? Decimal::Zero() : Custody;
			NewState.Reservations = std::move(Reservations);
			NewState.Contributions = std::move(Contributions);
			NewState.Threshold = std::move(Threshold);
			NewState.Honest = !Custody.IsNaN();

			auto OldState = GetAccountContribution(Asset, Owner);
			Decimal OldContribution = (OldState ? OldState->GetContribution() : Decimal::Zero());
			if (OldState)
			{
				NewState.Custody += OldState->Custody;
				for (auto& Item : OldState->Reservations)
				{
					auto& Reservation = NewState.Reservations[Item.first];
					Reservation = Reservation.IsNaN() ? Item.second : Reservation + Item.second;
				}

				for (auto& Item : OldState->Contributions)
				{
					auto& Contibution = NewState.Contributions[Item.first];
					Contibution = Contibution.IsNaN() ? Item.second : Contibution + Item.second;
				}
			}

			Decimal NewContribution = NewState.GetContribution();
			Decimal Coverage = NewContribution - OldContribution;
			while (Coverage.IsPositive() && !NewState.Reservations.empty())
			{
				auto Reservation = NewState.Reservations.begin();
				auto Reserve = std::min(Coverage, Reservation->second);
				auto Transfer = ApplyTransfer((uint8_t*)Reservation->first.data(), Decimal::Zero(), -Reserve);
				if (!Transfer)
					return Transfer.Error();

				Reservation->second -= Reserve;
				if (Reservation->second.IsPositive())
					break;

				Coverage -= Reserve;
				NewState.Reservations.erase(Reservation);
			}

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			Status = EmitEvent<States::AccountContribution>({ Format::Variable(Asset), Format::Variable(std::string_view((char*)Owner, sizeof(Algorithm::Pubkeyhash))), Format::Variable(Custody), Format::Variable(NewState.GetCoverage()) });
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::WitnessProgram> TransactionContext::ApplyWitnessProgram(const std::string_view& PackedProgramCode)
		{
			States::WitnessProgram NewState = States::WitnessProgram(Block);
			NewState.Storage = PackedProgramCode;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::WitnessEvent> TransactionContext::ApplyWitnessEvent(const uint256_t& ParentTransactionHash)
		{
			return ApplyWitnessEvent(ParentTransactionHash, Receipt.TransactionHash);
		}
		ExpectsLR<States::WitnessEvent> TransactionContext::ApplyWitnessEvent(const uint256_t& ParentTransactionHash, const uint256_t& ChildTransactionHash)
		{
			States::WitnessEvent NewState = States::WitnessEvent(Block);
			NewState.ParentTransactionHash = ParentTransactionHash;
			NewState.ChildTransactionHash = ChildTransactionHash;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::ApplyWitnessAddress(const Algorithm::Pubkeyhash Owner, const Algorithm::Pubkeyhash Proposer, const AddressMap& Addresses, uint64_t AddressIndex, States::WitnessAddress::Class Purpose)
		{
			return ApplyWitnessAddress(Transaction ? Transaction->Asset : uint256_t(0), Owner, Proposer, Addresses, AddressIndex, Purpose);
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::ApplyWitnessAddress(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Algorithm::Pubkeyhash Proposer, const AddressMap& Addresses, uint64_t AddressIndex, States::WitnessAddress::Class Purpose)
		{
			auto* Chain = Oracle::Datamaster::GetChain(Asset);
			if (!Chain || Addresses.empty())
				return LayerException("invalid operation");

			OrderedMap<String, AddressMap> Segments;
			for (auto& Address : Addresses)
			{
				auto Hash = Chain->NewPublicKeyHash(Address.second);
				if (Hash)
					Segments[*Hash][Address.first] = Address.second;
				else
					Segments[Address.second][Address.first] = Address.second;
			}

			States::WitnessAddress NewState = States::WitnessAddress(nullptr, nullptr);
			for (auto& Segment : Segments)
			{
				NewState = States::WitnessAddress(Owner, Block);
				NewState.SetProposer(Proposer);
				NewState.AddressIndex = AddressIndex;
				NewState.Addresses = std::move(Segment.second);
				NewState.Asset = Asset;
				NewState.Purpose = (uint8_t)Purpose;

				auto Status = Store(&NewState);
				if (!Status)
					return Status.Error();

				Format::Variables Event = { Format::Variable(Asset), Format::Variable(AddressIndex) };
				for (auto& Address : NewState.Addresses)
					Event.push_back(Format::Variable(Address.second));

				Status = EmitEvent<States::WitnessAddress>(std::move(Event));
				if (!Status)
					return Status.Error();

			}
			return NewState;
		}
		ExpectsLR<States::WitnessTransaction> TransactionContext::ApplyWitnessTransaction(const std::string_view& TransactionId)
		{
			return ApplyWitnessTransaction(Transaction ? Transaction->Asset : uint256_t(0), TransactionId);
		}
		ExpectsLR<States::WitnessTransaction> TransactionContext::ApplyWitnessTransaction(const Algorithm::AssetId& Asset, const std::string_view& TransactionId)
		{
			States::WitnessTransaction NewState = States::WitnessTransaction(Block);
			NewState.TransactionId = TransactionId;
			NewState.Asset = Asset;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			Status = EmitEvent<States::WitnessTransaction>({ Format::Variable(Asset), Format::Variable(TransactionId) });
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyTransfer(const Algorithm::Pubkeyhash Owner, const Decimal& Supply, const Decimal& Reserve)
		{
			return ApplyTransfer(Transaction ? Transaction->Asset : uint256_t(0), Owner, Supply, Reserve);
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyTransfer(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& Supply, const Decimal& Reserve)
		{
			States::AccountBalance NewState = States::AccountBalance(Owner, Block);
			NewState.Asset = Asset;
			NewState.Supply = Supply;
			NewState.Reserve = Reserve;

			auto Status = Store(&NewState);
			if (!Status)
				return Status.Error();

			Status = EmitEvent<States::AccountBalance>({ Format::Variable(Asset), Format::Variable(std::string_view((char*)Owner, sizeof(Algorithm::Pubkeyhash))), Format::Variable(Supply), Format::Variable(Reserve) });
			if (!Status)
				return Status.Error();

			return NewState;
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyPayment(const Algorithm::Pubkeyhash To, const Decimal& Value)
		{
			return ApplyPayment(Transaction ? Transaction->Asset : uint256_t(0), To, Value);
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyPayment(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash To, const Decimal& Value)
		{
			return ApplyPayment(Transaction ? Transaction->Asset : uint256_t(0), Receipt.From, To, Value);
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyPayment(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash From, const Algorithm::Pubkeyhash To, const Decimal& Value)
		{
			States::AccountBalance NewState1 = States::AccountBalance(From, Block);
			NewState1.Asset = Asset;
			NewState1.Supply = -Value;
			if (!memcmp(From, To, sizeof(Algorithm::Pubkeyhash)))
				return NewState1;

			auto Status = Store(&NewState1);
			if (!Status)
				return Status.Error();

			States::AccountBalance NewState2 = States::AccountBalance(To, Block);
			NewState2.Asset = Asset;
			NewState2.Supply = Value;

			Status = Store(&NewState2);
			if (!Status)
				return Status.Error();

			Status = EmitEvent<States::AccountBalance>({ Format::Variable(Asset), Format::Variable(std::string_view((char*)From, sizeof(Algorithm::Pubkeyhash))), Format::Variable(std::string_view((char*)To, sizeof(Algorithm::Pubkeyhash))), Format::Variable(Value) });
			if (!Status)
				return Status.Error();

			return NewState1;
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyFunding(const Decimal& Value)
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return ApplyFunding(Transaction ? Transaction->Asset : uint256_t(0), Receipt.From, Environment ? Environment->Proposer.PublicKeyHash : Null, Value);
		}
		ExpectsLR<States::AccountBalance> TransactionContext::ApplyFunding(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash From, const Algorithm::Pubkeyhash To, const Decimal& Value)
		{
			States::AccountBalance NewState1 = States::AccountBalance(From, Block);
			NewState1.Asset = Asset;
			NewState1.Supply = -Value;
			if (!memcmp(From, To, sizeof(Algorithm::Pubkeyhash)))
				return NewState1;

			auto Status = Store(&NewState1, false);
			if (!Status)
				return Status.Error();

			States::AccountBalance NewState2 = States::AccountBalance(To, Block);
			NewState2.Asset = Asset;
			NewState2.Supply = Value;

			Status = Store(&NewState2, false);
			if (!Status)
				return Status.Error();

			Status = EmitEvent<States::AccountBalance>({ Format::Variable(Asset), Format::Variable(std::string_view((char*)From, sizeof(Algorithm::Pubkeyhash))), Format::Variable(std::string_view((char*)To, sizeof(Algorithm::Pubkeyhash))), Format::Variable(Value) }, false);
			if (!Status)
				return Status.Error();

			return NewState1;
		}
		ExpectsLR<States::AccountSequence> TransactionContext::GetAccountSequence(const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::AccountSequence::AsInstanceIndex(Owner), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountSequence(std::move(*(States::AccountSequence*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountWork> TransactionContext::GetAccountWork(const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			Algorithm::Pubkeyhash Null = { 0 };
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::AccountWork::AsInstanceColumn(Owner), States::AccountWork::AsInstanceRow(), GetValidationNonce());
			if (!State)
			{
				if (memcmp(Owner, Environment ? Environment->Proposer.PublicKeyHash : Null, sizeof(Null)) != 0)
					return State.Error();

				States::AccountWork Result = States::AccountWork(Owner, Block);
				return Result;
			}

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
			{
				if (memcmp(Owner, Environment ? Environment->Proposer.PublicKeyHash : Null, sizeof(Null)) != 0)
					return Status.Error();

				States::AccountWork Result = States::AccountWork(Owner, Block);
				return Result;
			}

			return States::AccountWork(std::move(*(States::AccountWork*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountObserver> TransactionContext::GetAccountObserver(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			Algorithm::Pubkeyhash Null = { 0 };
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::AccountObserver::AsInstanceColumn(Owner), States::AccountObserver::AsInstanceRow(Asset), GetValidationNonce());
			if (!State)
			{
				if (memcmp(Owner, Environment ? Environment->Proposer.PublicKeyHash : Null, sizeof(Null)) != 0)
					return State.Error();

				States::AccountObserver Result = States::AccountObserver(Owner, Block);
				return Result;
			}

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
			{
				if (memcmp(Owner, Environment ? Environment->Proposer.PublicKeyHash : Null, sizeof(Null)) != 0)
					return Status.Error();

				States::AccountObserver Result = States::AccountObserver(Owner, Block);
				return Result;
			}

			return States::AccountObserver(std::move(*(States::AccountObserver*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<Vector<States::AccountObserver>> TransactionContext::GetAccountObservers(const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto States = Chain.GetMultiformsByColumn(&Delta, States::AccountObserver::AsInstanceColumn(Owner), GetValidationNonce(), Offset, Count);
			if (!States)
				return States.Error();

			if (!States->empty())
			{
				auto Status = ((TransactionContext*)this)->Load(*States->front(), Chain.QueryUsed());
				if (!Status)
					return Status.Error();
			}

			Vector<States::AccountObserver> Addresses;
			Addresses.reserve(States->size());
			for (auto& State : *States)
				Addresses.emplace_back(std::move(*(States::AccountObserver*)*State));
			return Addresses;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountProgram> TransactionContext::GetAccountProgram(const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::AccountProgram::AsInstanceIndex(Owner), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountProgram(std::move(*(States::AccountProgram*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountStorage> TransactionContext::GetAccountStorage(const Algorithm::Pubkeyhash Owner, const std::string_view& Location) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::AccountStorage::AsInstanceIndex(Owner, Location), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountStorage(std::move(*(States::AccountStorage*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountReward> TransactionContext::GetAccountReward(const Algorithm::Pubkeyhash Owner) const
		{
			return GetAccountReward(Transaction ? Transaction->Asset : uint256_t(0), Owner);
		}
		ExpectsLR<States::AccountReward> TransactionContext::GetAccountReward(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::AccountReward::AsInstanceColumn(Owner), States::AccountReward::AsInstanceRow(Asset), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountReward(std::move(*(States::AccountReward*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountBalance> TransactionContext::GetAccountBalance(const Algorithm::Pubkeyhash Owner) const
		{
			return GetAccountBalance(Transaction ? Transaction->Asset : uint256_t(0), Owner);
		}
		ExpectsLR<States::AccountBalance> TransactionContext::GetAccountBalance(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::AccountBalance::AsInstanceColumn(Owner), States::AccountBalance::AsInstanceRow(Asset), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountBalance(std::move(*(States::AccountBalance*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountContribution> TransactionContext::GetAccountContribution(const Algorithm::Pubkeyhash Owner) const
		{
			return GetAccountContribution(Transaction ? Transaction->Asset : uint256_t(0), Owner);
		}
		ExpectsLR<States::AccountContribution> TransactionContext::GetAccountContribution(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::AccountContribution::AsInstanceColumn(Owner), States::AccountContribution::AsInstanceRow(Asset), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountContribution(std::move(*(States::AccountContribution*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::AccountDerivation> TransactionContext::GetAccountDerivation(const Algorithm::Pubkeyhash Owner) const
		{
			return GetAccountDerivation(Transaction ? Transaction->Asset : uint256_t(0), Owner);
		}
		ExpectsLR<States::AccountDerivation> TransactionContext::GetAccountDerivation(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const
		{
			VI_ASSERT(Owner != nullptr, "owner should be set");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::AccountDerivation::AsInstanceIndex(Owner, Asset), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::AccountDerivation(std::move(*(States::AccountDerivation*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::WitnessProgram> TransactionContext::GetWitnessProgram(const std::string_view& ProgramHashcode) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::WitnessProgram::AsInstanceIndex(ProgramHashcode), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::WitnessProgram(std::move(*(States::WitnessProgram*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::WitnessEvent> TransactionContext::GetWitnessEvent(const uint256_t& ParentTransactionHash) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::WitnessEvent::AsInstanceIndex(ParentTransactionHash), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::WitnessEvent(std::move(*(States::WitnessEvent*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<Vector<States::WitnessAddress>> TransactionContext::GetWitnessAddresses(const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto States = Chain.GetMultiformsByColumn(&Delta, States::WitnessAddress::AsInstanceColumn(Owner), GetValidationNonce(), Offset, Count);
			if (!States)
				return States.Error();

			if (!States->empty())
			{
				auto Status = ((TransactionContext*)this)->Load(*States->front(), Chain.QueryUsed());
				if (!Status)
					return Status.Error();
			}

			Vector<States::WitnessAddress> Addresses;
			Addresses.reserve(States->size());
			for (auto& State : *States)
				Addresses.emplace_back(std::move(*(States::WitnessAddress*)*State));
			return Addresses;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<Vector<States::WitnessAddress>> TransactionContext::GetWitnessAddressesByPurpose(const Algorithm::Pubkeyhash Owner, States::WitnessAddress::Class Purpose, size_t Offset, size_t Count) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto Filter = Storages::FactorFilter::Equal((int64_t)Purpose, 1);
			auto States = Chain.GetMultiformsByColumnFilter(&Delta, States::WitnessAddress::AsInstanceColumn(Owner), Filter, GetValidationNonce(), Offset, Count);
			if (!States)
				return States.Error();

			if (!States->empty())
			{
				auto Status = ((TransactionContext*)this)->Load(*States->front(), Chain.QueryUsed());
				if (!Status)
					return Status.Error();
			}

			Vector<States::WitnessAddress> Addresses;
			Addresses.reserve(States->size());
			for (auto& State : *States)
				Addresses.emplace_back(std::move(*(States::WitnessAddress*)*State));
			return Addresses;
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::GetWitnessAddress(const Algorithm::Pubkeyhash Owner, const std::string_view& Address, uint64_t AddressIndex) const
		{
			return GetWitnessAddress(Transaction ? Transaction->Asset : uint256_t(0), Owner, Address, AddressIndex);
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::GetWitnessAddress(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const std::string_view& Address, uint64_t AddressIndex) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(&Delta, States::WitnessAddress::AsInstanceColumn(Owner), States::WitnessAddress::AsInstanceRow(Asset, Address, AddressIndex), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::WitnessAddress(std::move(*(States::WitnessAddress*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::GetWitnessAddress(const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const
		{
			return GetWitnessAddress(Transaction ? Transaction->Asset : uint256_t(0), Address, AddressIndex, Offset);
		}
		ExpectsLR<States::WitnessAddress> TransactionContext::GetWitnessAddress(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByRow(&Delta, States::WitnessAddress::AsInstanceRow(Asset, Address, AddressIndex), GetValidationNonce(), Offset);
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::WitnessAddress(std::move(*(States::WitnessAddress*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<States::WitnessTransaction> TransactionContext::GetWitnessTransaction(const std::string_view& TransactionId) const
		{
			return GetWitnessTransaction(Transaction ? Transaction->Asset : uint256_t(0), TransactionId);
		}
		ExpectsLR<States::WitnessTransaction> TransactionContext::GetWitnessTransaction(const Algorithm::AssetId& Asset, const std::string_view& TransactionId) const
		{
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(&Delta, States::WitnessTransaction::AsInstanceIndex(Asset, TransactionId), GetValidationNonce());
			if (!State)
				return State.Error();

			auto Status = ((TransactionContext*)this)->Load(**State, Chain.QueryUsed());
			if (!Status)
				return Status.Error();

			return States::WitnessTransaction(std::move(*(States::WitnessTransaction*)**State));
#else
			return LayerException("chainstate data not available");
#endif
		}
		ExpectsLR<Ledger::BlockTransaction> TransactionContext::GetBlockTransactionInstance(const uint256_t& TransactionHash) const
		{
			if (!TransactionHash)
				return LayerException("block transaction not found");
#ifdef TAN_VALIDATOR
			auto Chain = Storages::Chainstate(__func__);
			auto Candidate = Chain.GetBlockTransactionByHash(TransactionHash);
			if (!Candidate || !Candidate->Transaction || !Candidate->Receipt.Successful)
				return LayerException("block transaction not found");

			if (Transaction && Transaction->Asset != Candidate->Transaction->Asset)
				return LayerException("block transaction asset is distinct");

			if (Candidate->Receipt.TransactionHash != TransactionHash && Candidate->Transaction->AsType() == Transactions::Rollup::AsInstanceType())
				Candidate = ((Transactions::Rollup*)*Candidate->Transaction)->ResolveBlockTransaction(Candidate->Receipt, TransactionHash);

			return Candidate;
#else
			return LayerException("chainstate data not available");
#endif
		}
		uint64_t TransactionContext::GetValidationNonce() const
		{
			if (!Environment)
				return Block ? Block->Number : 0;
			else if (!Environment->Validation.Tip)
				return Block ? Block->Number : 1;
			return 0;
		}
		uint256_t TransactionContext::GetGasUse() const
		{
			return Receipt.RelativeGasUse;
		}
		uint256_t TransactionContext::GetGasLeft() const
		{
			if (!Transaction)
				return 0;

			return Transaction->GasLimit > Receipt.RelativeGasUse ? Transaction->GasLimit - Receipt.RelativeGasUse : uint256_t(0);
		}
		Decimal TransactionContext::GetGasCost() const
		{
			if (!Transaction || !Transaction->GasPrice.IsPositive())
				return 0;

			return Transaction->GasPrice * GetGasUse().ToDecimal();
		}
		ExpectsLR<void> TransactionContext::PrevalidateTx(const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, Algorithm::Pubkeyhash Owner)
		{
			VI_ASSERT(NewTransaction && Owner, "transaction and owner should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			if (!Algorithm::Signing::RecoverTweakedHash(NewTransactionHash, Owner, NewTransaction->Signature) || !memcmp(Owner, Null, sizeof(Null)))
				return LayerException("invalid signature");

			return NewTransaction->Prevalidate();
		}
		ExpectsLR<TransactionContext> TransactionContext::ValidateTx(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, BlockWork& Cache)
		{
			VI_ASSERT(NewBlock && NewEnvironment && NewTransaction, "block, utilization and transaction should be set");
			Algorithm::Pubkeyhash Null = { 0 }, Owner;
			if (!Algorithm::Signing::RecoverTweakedHash(NewTransaction->AsPayload().Hash(), Owner, NewTransaction->Signature) || !memcmp(Owner, Null, sizeof(Null)))
				return LayerException("invalid signature");

			return ValidateTx(NewBlock, NewEnvironment, NewTransaction, NewTransactionHash, Owner, Cache);
		}
		ExpectsLR<TransactionContext> TransactionContext::ValidateTx(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, const Algorithm::Pubkeyhash Owner, BlockWork& Cache)
		{
			VI_ASSERT(NewBlock && NewEnvironment && NewTransaction && Owner, "block, env, transaction and owner should be set");
			Ledger::Receipt NewReceipt;
			NewReceipt.TransactionHash = NewTransactionHash;
			NewReceipt.GenerationTime = Protocol::Now().Time.Now();
			NewReceipt.AbsoluteGasUse = NewBlock->GasUse;
			NewReceipt.BlockNumber = NewBlock->Number;
			memcpy(NewReceipt.From, Owner, sizeof(NewReceipt.From));

			auto Prevalidation = NewTransaction->Prevalidate();
			if (!Prevalidation)
				return Prevalidation.Error();

			TransactionContext Context = TransactionContext(NewBlock, NewEnvironment, NewTransaction, std::move(NewReceipt));
			Context.Delta.Incoming = &Cache;

			auto Validation = Context.Transaction->Validate(&Context);
			if (!Validation)
			{
				Context.EmitEvent(0, { Format::Variable(Validation.What()) }, false);
				if (!Context.Transaction->Conservative)
					return Validation.Error();
			}

			return ExpectsLR<TransactionContext>(std::move(Context));
		}
		ExpectsLR<void> TransactionContext::ExecuteTx(TransactionContext& Context, size_t TransactionSize, bool OnlySuccessful)
		{
			VI_ASSERT(Context.Block && Context.Delta.Outgoing && Context.Environment && Context.Transaction, "block, outgoing delta, utilization and transaction should be set");
			auto Deployment = Context.BurnGas(TransactionSize * (size_t)GasCost::WriteByte);
			if (!Deployment)
				return Deployment;

			bool Discard = (Context.Receipt.Events.size() == 1 && Context.Receipt.Events.front().first == 0 && Context.Receipt.Events.front().second.size() == 1);
			auto Status = Discard ? ExpectsLR<void>(LayerException(Context.Receipt.Events.front().second.front().AsBlob())) : Context.Transaction->Execute(&Context);
			Context.Receipt.Successful = !!Status;
			if (!Context.Receipt.Successful)
				Context.Delta.Outgoing->Rollback();
			if (Discard)
				Context.Receipt.Events.clear();
			if (OnlySuccessful && !Context.Receipt.Successful)
				return Status;

			auto Info = Context.ApplyAccountSequence();
			if (!Info)
				return Info.Error();

			auto Work = Context.GetAccountWork(Context.Receipt.From);
			auto GasUse = Work ? Work->GetGasUse() : uint256_t(0);
			Context.Receipt.RelativeGasPaid = States::AccountWork::GetAdjustedGasPaid(GasUse, Context.Receipt.RelativeGasUse);
			Context.Receipt.FinalizationTime = Protocol::Now().Time.Now();
			if (memcmp(Context.Environment->Proposer.PublicKeyHash, Context.Receipt.From, sizeof(Context.Receipt.From)) != 0)
			{
				if (Context.Receipt.RelativeGasPaid > 0 && Context.Transaction->GasPrice.IsPositive())
				{
					auto Funding = Context.ApplyFunding(Context.Transaction->GasPrice * Context.Receipt.RelativeGasPaid.ToDecimal());
					if (!Funding)
						return Funding.Error();
				}

				auto GasOutput = States::AccountWork::GetAdjustedGasOutput(GasUse, Context.Receipt.RelativeGasUse);
				if (GasOutput > 0)
				{
					Work = Context.ApplyAccountWork(Context.Receipt.From, WorkStatus::Standby, 0, 0, GasOutput);
					if (!Work)
						return Work.Error();
				}
			}

			if (Context.Receipt.Successful)
			{
				for (auto& Item : Context.Witnesses)
					Context.Block->SetWitnessRequirement(Item.first, Item.second);
			}
			else
				Context.EmitEvent(0, { Format::Variable(Status.What()) }, false);

			Context.Block->GasUse += Context.Receipt.RelativeGasUse;
			Context.Block->GasLimit += Context.Transaction->GasLimit;
			return Expectation::Met;
		}
		ExpectsLR<uint256_t> TransactionContext::CalculateTxGas(const Ledger::Transaction* Transaction)
		{
			VI_ASSERT(Transaction != nullptr, "transaction should be set");
			Algorithm::Pubkeyhash Owner;
			if (!Transaction->Recover(Owner))
				return LayerException("invalid signature");

			auto* Mutable = (Ledger::Transaction*)Transaction;
			auto InitialChecksum = Transaction->Checksum;
			auto InitialGasLimit = Transaction->GasLimit;
			auto InitialConservative = Transaction->Conservative;
			auto RevertTransaction = [&]()
			{
				Mutable->Checksum = InitialChecksum;
				Mutable->GasLimit = InitialGasLimit;
				Mutable->Conservative = InitialConservative;
			};
			Mutable->Checksum = 0;
			Mutable->GasLimit = Block::GetGasLimit();
			Mutable->Conservative = false;

			Ledger::Block TempBlock;
			TempBlock.Number = std::numeric_limits<int64_t>::max() - 1;

			Algorithm::Pubkeyhash PublicKeyHash = { 1 };
			Ledger::EvaluationContext TempEnvironment;
			memcpy(TempEnvironment.Proposer.PublicKeyHash, PublicKeyHash, sizeof(Algorithm::Pubkeyhash));

			Ledger::BlockWork Cache;
			auto Prevalidation = Transaction->Prevalidate();
			if (!Prevalidation)
			{
				RevertTransaction();
				return Prevalidation.Error();
			}

			auto Validation = TransactionContext::ValidateTx(&TempBlock, &TempEnvironment, Transaction, Transaction->AsHash(), Owner, Cache);
			if (!Validation)
			{
				RevertTransaction();
				return Validation.Error();
			}

			auto& Context = *Validation;
			size_t TransactionSize = Transaction->AsMessage().Data.size();
			auto Execution = TransactionContext::ExecuteTx(Context, TransactionSize, false);
			if (!Execution)
			{
				RevertTransaction();
				return Execution.Error();
			}

			RevertTransaction();
			auto Gas = Context.Receipt.RelativeGasUse;
			Gas -= Gas % 1000;
			return Gas + 1000;
		}
		ExpectsPromiseLR<void> TransactionContext::DispatchTx(const Wallet& Proposer, Ledger::BlockTransaction* Transaction, Vector<UPtr<Ledger::Transaction>>* Pipeline)
		{
			VI_ASSERT(Transaction != nullptr, "transaction should be set");
			VI_ASSERT(Pipeline != nullptr, "pipeline should be set");
			auto GasLimit = Transaction->Transaction->GasLimit;
			Transaction->Transaction->GasLimit = Block::GetGasLimit();

			auto* Context = Memory::New<Ledger::TransactionContext>();
			Context->Transaction = *Transaction->Transaction;
			Context->Receipt = Transaction->Receipt;
			return Transaction->Transaction->Dispatch(Proposer, Context, Pipeline).Then<ExpectsLR<void>>([Transaction, Context, GasLimit](ExpectsLR<void>&& Result)
			{
				Transaction->Transaction->GasLimit = GasLimit;
				Memory::Delete(Context);
				return std::move(Result);
			});
		}

		Option<uint64_t> EvaluationContext::Priority(const Algorithm::Pubkeyhash PublicKeyHash, const Algorithm::Seckey SecretKey, Option<BlockHeader*>&& ParentBlock)
		{
			Validation.Tip = false;
			if (!ParentBlock)
			{
#ifdef TAN_VALIDATOR
				auto Chain = Storages::Chainstate(__func__);
				auto Latest = Chain.GetLatestBlockHeader();
				Tip = Latest ? Option<Ledger::BlockHeader>(std::move(*Latest)) : Option<Ledger::BlockHeader>(Optional::None);
				Validation.Tip = true;
#else
				return Optional::None;
#endif
			}
			else if (*ParentBlock != nullptr)
				Tip = **ParentBlock;
			else
				Tip = Optional::None;

			memcpy(Proposer.PublicKeyHash, PublicKeyHash, sizeof(Algorithm::Pubkeyhash));
			if (SecretKey != nullptr)
				memcpy(Proposer.SecretKey, SecretKey, sizeof(Algorithm::Seckey));

			Validation.Cache = BlockWork();
			Validation.Context = Ledger::TransactionContext(Tip.Address());
			Validation.Context.Environment = this;
			Validation.Context.Delta.Incoming = &Validation.Cache;
			Validation.CumulativeGas = 0;
			Precomputed = 0;
			Proposers.clear();
			Aggregators.clear();
			Incoming.clear();
			Outgoing.clear();

			if (Validation.Context.Block && !Validation.Tip)
				++Validation.Context.Block->Number;

			auto& Policy = Protocol::Now().Policy;
			auto Committee = Validation.Context.CalculateProposalCommittee(Policy.ConsensusCommitteeMajors, Policy.ConsensusCommitteeMinors, nullptr);
			if (Committee)
				Proposers = std::move(*Committee);

			if (Proposers.empty())
			{
				auto Work = Validation.Context.GetAccountWork(Proposer.PublicKeyHash);
				if (!Work)
					Proposers.push_back(States::AccountWork(Proposer.PublicKeyHash, Tip.Address()));
				else
					Proposers.push_back(std::move(*Work));
			}

			if (Validation.Context.Block && !Validation.Tip)
				--Validation.Context.Block->Number;

			auto Position = std::find_if(Proposers.begin(), Proposers.end(), [this](const States::AccountWork& A) { return !memcmp(A.Owner, Proposer.PublicKeyHash, sizeof(Proposer.PublicKeyHash)); });
			if (Position == Proposers.end())
				return Optional::None;

			return std::distance(Proposers.begin(), Position);
		}
		size_t EvaluationContext::Apply(Vector<UPtr<Transaction>>&& Candidates)
		{
			Vector<TransactionInfo> Subqueue;
			Subqueue.reserve(Candidates.size());
			for (auto& Candidate : Candidates)
			{
				TransactionInfo Info;
				Info.Candidate = std::move(Candidate);
				Subqueue.emplace_back(std::move(Info));
			}

			auto TotalGasLimit = BlockHeader::GetGasLimit();
			Precompute(Subqueue);

			Algorithm::Pubkeyhash Null = { 0 };
			for (auto& Item : Subqueue)
			{
				if (!memcmp(Item.Owner, Null, sizeof(Null)))
				{
				Erase:
					Outgoing.push_back(Item.Hash);
					continue;
				}

				uint256_t NewCumulativeGas = Validation.CumulativeGas + Item.Candidate->GasLimit;
				if (NewCumulativeGas > TotalGasLimit)
					continue;

				auto AccountSequence = Validation.Context.GetAccountSequence(Item.Owner);
				uint64_t SequenceTarget = (AccountSequence ? AccountSequence->Sequence : 0);
				uint64_t SequenceDelta = (SequenceTarget > Item.Candidate->Sequence ? SequenceTarget - Item.Candidate->Sequence : 0);
				if (SequenceDelta > 1)
					goto Erase;
				else if (SequenceDelta > 0)
					continue;

				if (Item.Candidate->GetType() == TransactionLevel::Aggregation)
				{
					auto* Aggregation = ((AggregationTransaction*)*Item.Candidate);
					auto Consensus = Aggregation->CalculateCumulativeConsensus(&Aggregators, &Validation.Context);
					if (!Consensus || !Consensus->Reached)
						continue;

					Aggregation->SetConsensus(Consensus->Branch->Message.Hash());
				}

				Validation.CumulativeGas = NewCumulativeGas;
				Incoming.emplace_back(std::move(Item));
				++Precomputed;
			}
			return Candidates.size();
		}
		EvaluationContext::TransactionInfo& EvaluationContext::Include(UPtr<Transaction>&& Candidate)
		{
			Incoming.emplace_back();
			auto& Info = Incoming.back();
			Info.Candidate = std::move(Candidate);
			return Info;
		}
		ExpectsLR<Block> EvaluationContext::Evaluate(String* Errors)
		{
			Ledger::Block Candidate;
			auto Status = Precompute(Candidate);
			if (!Status)
				return Status.Error();

			auto Chain = Storages::Chainstate(__func__);
			auto Evaluation = Candidate.Evaluate(Tip.Address(), this, Errors);
			Cleanup().Report("mempool cleanup failed");
			if (!Evaluation)
				return Evaluation.Error();

			return Candidate;
		}
		ExpectsLR<void> EvaluationContext::Solve(Block& Candidate)
		{
			if (!Candidate.Solve(Proposer.SecretKey))
				return LayerException("block proof evaluation failed");

			if (!Candidate.Sign(Proposer.SecretKey))
				return LayerException("block signature evaluation failed");

			return Expectation::Met;
		}
		ExpectsLR<void> EvaluationContext::Verify(const Block& Candidate)
		{
			auto Validity = Candidate.VerifyValidity(Tip.Address());
			if (!Validity)
				return Validity;

			return Candidate.VerifyIntegrity(Tip.Address());
		}
		ExpectsLR<void> EvaluationContext::Precompute(Block& Candidate)
		{
			Validation.Context = TransactionContext(&Candidate);
			Validation.Context.Environment = this;
			if (Precomputed != Incoming.size())
			{
				Precomputed = Incoming.size();
				Precompute(Incoming);
			}
			return Expectation::Met;
		}
		ExpectsLR<void> EvaluationContext::Cleanup()
		{
			if (Outgoing.empty())
				return Expectation::Met;
#ifdef TAN_VALIDATOR
			auto Mempool = Storages::Mempoolstate(__func__);
			return Mempool.RemoveTransactions(Outgoing);
#else
			return LayerException("mempoolstate data not available");
#endif
		}
		void EvaluationContext::Precompute(Vector<TransactionInfo>& Candidates)
		{
			Algorithm::Pubkeyhash Null = { 0 };
			Parallel::WailAll(ParallelForEach(Candidates.begin(), Candidates.end(), [&Null](TransactionInfo& Item)
			{
				Item.Hash = Item.Candidate->AsHash();
				if (memcmp(Item.Owner, Null, sizeof(Null)) != 0)
					return;

				Item.Size = Item.Candidate->AsMessage().Data.size();
				if (Item.Candidate->GetType() != TransactionLevel::Aggregation)
					Algorithm::Signing::RecoverTweakedHash(Item.Candidate->AsPayload().Hash(), Item.Owner, Item.Candidate->Signature);
				else
					Item.Candidate->Recover(Item.Owner);
			}));
		}
	}
}
