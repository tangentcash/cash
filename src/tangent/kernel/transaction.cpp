#include "transaction.h"
#include "block.h"
#include "../policy/typenames.h"

namespace Tangent
{
	namespace Ledger
	{
		ExpectsLR<void> Transaction::Prevalidate() const
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");

			if (!Sequence || Sequence >= std::numeric_limits<uint64_t>::max() - 1)
				return LayerException("invalid sequence");

			if (!GasLimit)
				return LayerException("gas limit requirement not met (min: 1)");

			uint256_t MaxGasLimit = Block::GetGasLimit();
			if (GasLimit > MaxGasLimit)
				return LayerException("gas limit requirement not met (max: " + MaxGasLimit.ToString() + ")");

			if (GasPrice.IsNaN() || GasPrice.IsNegative())
				return LayerException("invalid gas price");

			if (GasPrice.IsZero() && Conservative)
				return LayerException("invalid gas price");

			if (IsSignatureNull())
				return LayerException("invalid signature");

			return Expectation::Met;
		}
		ExpectsLR<void> Transaction::Validate(const TransactionContext* Context) const
		{
			auto SequenceRequirement = Context->VerifyAccountSequence();
			if (!SequenceRequirement)
				return SequenceRequirement;

			return Context->VerifyTransferBalance(Decimal::Zero());
		}
		ExpectsPromiseLR<void> Transaction::Dispatch(const Wallet& Proposer, const TransactionContext* Context, Vector<UPtr<Transaction>>* Pipeline) const
		{
			return ExpectsPromiseLR<void>(Expectation::Met);
		}
		bool Transaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Asset);
			Stream->WriteDecimal(GasPrice);
			Stream->WriteInteger(GasLimit);
			Stream->WriteInteger(Sequence);
			Stream->WriteBoolean(Conservative);
			return StoreBody(Stream);
		}
		bool Transaction::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &GasPrice))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GasLimit))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Sequence))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Conservative))
				return false;

			return LoadBody(Stream);
		}
		bool Transaction::StoreBody(Format::Stream* Stream) const
		{
			return true;
		}
		bool Transaction::LoadBody(Format::Stream& Stream)
		{
			return true;
		}
		bool Transaction::RecoverAlt(const Receipt& Receipt, OrderedSet<uint256_t>& Aliases) const
		{
			return true;
		}
		bool Transaction::Sign(const Algorithm::Seckey SecretKey)
		{
			return Authentic::Sign(SecretKey);
		}
		bool Transaction::Sign(const Algorithm::Seckey SecretKey, uint64_t NewSequence)
		{
			Sequence = NewSequence;
			return Sign(SecretKey);
		}
		bool Transaction::Sign(const Algorithm::Seckey SecretKey, uint64_t NewSequence, const Decimal& Price)
		{
			SetEstimateGas(Price);
			if (!Sign(SecretKey, NewSequence))
				return false;

			auto OptimalGas = Ledger::TransactionContext::CalculateTxGas(this);
			if (!OptimalGas || GasLimit == *OptimalGas)
				return true;

			GasLimit = *OptimalGas;
			return Sign(SecretKey);
		}
		void Transaction::SetOptimalGas(const Decimal& Price)
		{
			auto OptimalGas = Ledger::TransactionContext::CalculateTxGas(this);
			if (!OptimalGas)
				OptimalGas = GetGasEstimate();
			SetGas(Price, *OptimalGas);
		}
		void Transaction::SetEstimateGas(const Decimal& Price)
		{
			SetGas(Price, GetGasEstimate());
		}
		void Transaction::SetGas(const Decimal& Price, const uint256_t& Limit)
		{
			GasPrice = Price;
			GasLimit = Limit;
		}
		void Transaction::SetAsset(const std::string_view& Blockchain, const std::string_view& Token, const std::string_view& ContractAddress)
		{
			Asset = Algorithm::Asset::IdOf(Blockchain, Token, ContractAddress);
		}
		bool Transaction::IsConsensus() const
		{
			auto Level = GetType();
			return Level == TransactionLevel::Consensus || Level == TransactionLevel::Aggregation;
		}
		TransactionLevel Transaction::GetType() const
		{
			return TransactionLevel::Functional;
		}
		UPtr<Schema> Transaction::AsSchema() const
		{
			std::string_view Category;
			switch (GetType())
			{
				case TransactionLevel::Functional:
					Category = "functional";
					break;
				case TransactionLevel::Delegation:
					Category = "delegation";
					break;
				case TransactionLevel::Consensus:
					Category = "consensus";
					break;
				case TransactionLevel::Aggregation:
					Category = "aggregation";
					break;
				default:
					Category = "unknown";
					break;
			}

			Schema* Data = Var::Set::Object();
			Data->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(AsHash())));
			Data->Set("signature", Var::String(Format::Util::Encode0xHex(std::string_view((char*)Signature, sizeof(Signature)))));
			Data->Set("type", Var::String(AsTypename()));
			Data->Set("category", Var::String(Category));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("sequence", Var::Integer(Sequence));
			Data->Set("gas_price", Var::Decimal(GasPrice));
			Data->Set("gas_limit", Algorithm::Encoding::SerializeUint256(GasLimit));
			return Data;
		}
		uint64_t Transaction::GetDispatchOffset() const
		{
			return 0;
		}

		ExpectsLR<void> DelegationTransaction::Validate(const TransactionContext* Context) const
		{
			return Context->VerifyAccountSequence();
		}
		TransactionLevel DelegationTransaction::GetType() const
		{
			return TransactionLevel::Delegation;
		}

		ExpectsLR<void> ConsensusTransaction::Validate(const TransactionContext* Context) const
		{
			auto SequenceRequirement = Context->VerifyAccountSequence();
			if (!SequenceRequirement)
				return SequenceRequirement;

			return Context->VerifyAccountWork();
		}
		TransactionLevel ConsensusTransaction::GetType() const
		{
			return TransactionLevel::Consensus;
		}

		ExpectsLR<void> AggregationTransaction::Prevalidate() const
		{
			if (Conservative)
				return LayerException("cumulative transaction cannot be conservative");

			if (!InputHash)
				return LayerException("invalid input hash");

			if (OutputHashes.empty())
				return LayerException("invalid output hashes");

			size_t BranchIndex = 0;
			for (auto& Branch : OutputHashes)
			{
				++BranchIndex;
				if (!Branch.first)
					return LayerException(Stringify::Text("invalid output hash (branch: %i)", (int)BranchIndex));

				size_t SignatureIndex = 0;
				for (auto& Signature : Branch.second.Attestations)
				{
					++SignatureIndex;
					if (Signature.size() != sizeof(Algorithm::Sighash))
						return LayerException(Stringify::Text("invalid attestation signature (branch: %i, signature: %i)", (int)BranchIndex, (int)SignatureIndex));

					Algorithm::Pubkeyhash Proposer = { 0 }, Null = { 0 };
					if (!Recover(Proposer, Branch.first, SignatureIndex - 1) || !memcmp(Proposer, Null, sizeof(Null)))
						return LayerException(Stringify::Text("invalid attestation proposer (branch: %i, signature: %i)", (int)BranchIndex, (int)SignatureIndex));
				}
			}

			return Ledger::Transaction::Prevalidate();
		}
		ExpectsLR<void> AggregationTransaction::Validate(const TransactionContext* Context) const
		{
			auto SequenceRequirement = Context->VerifyAccountSequence();
			if (!SequenceRequirement)
				return SequenceRequirement;

			size_t BranchIndex = 0;
			for (auto& Branch : OutputHashes)
			{
				++BranchIndex;
				if (!Branch.first)
					return LayerException(Stringify::Text("invalid output hash (branch: %i)", (int)BranchIndex));

				size_t SignatureIndex = 0;
				for (auto& Signature : Branch.second.Attestations)
				{
					Algorithm::Pubkeyhash Proposer = { 0 };
					if (!Recover(Proposer, Branch.first, SignatureIndex++))
						return LayerException(Stringify::Text("invalid attestation proposer (branch: %i, signature: %i)", (int)BranchIndex, (int)SignatureIndex));

					auto Status = Context->VerifyAccountWork(Proposer);
					if (!Status)
						return Status;
				}
			}

			return Context->VerifyAccountWork();
		}
		bool AggregationTransaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			if (!Ledger::Transaction::StorePayload(Stream))
				return false;

			Stream->WriteInteger(InputHash);
			Stream->WriteInteger((uint16_t)OutputHashes.size());
			for (auto& Branch : OutputHashes)
			{
				Stream->WriteString(Branch.second.Message.Data);
				Stream->WriteInteger((uint16_t)Branch.second.Attestations.size());
				for (auto& Signature : Branch.second.Attestations)
				{
					if (Signature.size() != sizeof(Algorithm::Sighash))
						return false;

					Stream->WriteString(Signature);
				}
			}
			return true;
		}
		bool AggregationTransaction::LoadPayload(Format::Stream& Stream)
		{
			if (!Ledger::Transaction::LoadPayload(Stream))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &InputHash))
				return false;

			uint16_t OutputHashesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &OutputHashesSize))
				return false;

			OutputHashes.clear();
			for (uint16_t i = 0; i < OutputHashesSize; i++)
			{
				Format::Stream Message;
				if (!Stream.ReadString(Stream.ReadType(), &Message.Data))
					return false;

				uint16_t SignaturesSize;
				if (!Stream.ReadInteger(Stream.ReadType(), &SignaturesSize))
					return false;

				OrderedSet<String> Signatures;
				for (uint16_t i = 0; i < SignaturesSize; i++)
				{
					String Signature;
					if (!Stream.ReadString(Stream.ReadType(), &Signature) || Signature.size() != sizeof(Algorithm::Sighash))
						return false;

					Signatures.insert(Signature);
				}

				auto& Branch = OutputHashes[Message.Hash()];
				Branch.Message = std::move(Message);
				Branch.Attestations = std::move(Signatures);
			}

			return true;
		}
		bool AggregationTransaction::Sign(const Algorithm::Seckey SecretKey)
		{
			Format::Stream Message;
			Message.WriteInteger(InputHash);
			if (!Transaction::StorePayload(&Message))
				return false;

			if (!Algorithm::Signing::SignTweaked(Message.Hash(), SecretKey, Signature))
				return false;

			return Attestate(SecretKey);
		}
		bool AggregationTransaction::Sign(const Algorithm::Seckey SecretKey, uint64_t NewSequence)
		{
			Sequence = NewSequence;
			return Sign(SecretKey);
		}
		bool AggregationTransaction::Sign(const Algorithm::Seckey SecretKey, uint64_t NewSequence, const Decimal& Price)
		{
			SetEstimateGas(Price);
			if (!Sign(SecretKey, NewSequence))
				return false;

			size_t TransactionSize1 = AsMessage().Data.size();
			auto OptimalGas = Ledger::TransactionContext::CalculateTxGas(this);
			if (!OptimalGas || GasLimit == *OptimalGas)
				return true;

			GasLimit = *OptimalGas;
			return Sign(SecretKey);
		}
		bool AggregationTransaction::Verify(const Algorithm::Pubkey PublicKey) const
		{
			Format::Stream Message;
			Message.WriteInteger(InputHash);
			if (!Transaction::StorePayload(&Message))
				return false;

			if (!Algorithm::Signing::VerifyTweaked(Message.Hash(), PublicKey, Signature))
				return false;

			for (auto& Branch : OutputHashes)
			{
				size_t SignatureIndex = 0;
				for (auto& Candidate : Branch.second.Attestations)
				{
					if (Candidate.size() != sizeof(Algorithm::Sighash))
						return false;

					if (Verify(PublicKey, Branch.first, SignatureIndex++))
						return true;
				}
			}

			return false;
		}
		bool AggregationTransaction::Verify(const Algorithm::Pubkey PublicKey, const uint256_t& OutputHash, size_t Index) const
		{
			auto Branch = OutputHashes.find(OutputHash);
			if (Branch == OutputHashes.end())
				return false;

			if (Index >= Branch->second.Attestations.size())
				return false;

			auto Signature = Branch->second.Attestations.begin();
			for (size_t i = 0; i < Index; i++)
				++Signature;

			if (Signature->size() != sizeof(Algorithm::Sighash))
				return false;

			Format::Stream Message;
			Message.WriteInteger(Asset);
			Message.WriteInteger(InputHash);
			Message.WriteInteger(OutputHash);
			return Algorithm::Signing::VerifyTweaked(Message.Hash(), PublicKey, (uint8_t*)Signature->data());
		}
		bool AggregationTransaction::Recover(Algorithm::Pubkeyhash PublicKeyHash) const
		{
			Format::Stream Message;
			Message.WriteInteger(InputHash);
			if (!Transaction::StorePayload(&Message))
				return false;

			if (!Algorithm::Signing::RecoverTweakedHash(Message.Hash(), PublicKeyHash, Signature))
				return false;

			for (auto& Branch : OutputHashes)
			{
				size_t SignatureIndex = 0;
				for (auto& Candidate : Branch.second.Attestations)
				{
					if (Candidate.size() != sizeof(Algorithm::Sighash))
						return false;

					Algorithm::Pubkeyhash Owner = { 0 };
					if (Recover(Owner, Branch.first, SignatureIndex++) && !memcmp(Owner, PublicKeyHash, sizeof(Owner)))
						return true;
				}
			}

			return false;
		}
		bool AggregationTransaction::Recover(Algorithm::Pubkeyhash PublicKeyHash, const uint256_t& OutputHash, size_t Index) const
		{
			auto Branch = OutputHashes.find(OutputHash);
			if (Branch == OutputHashes.end())
				return false;

			if (Index >= Branch->second.Attestations.size())
				return false;

			auto Signature = Branch->second.Attestations.begin();
			for (size_t i = 0; i < Index; i++)
				++Signature;

			if (Signature->size() != sizeof(Algorithm::Sighash))
				return false;

			Format::Stream Message;
			Message.WriteInteger(Asset);
			Message.WriteInteger(InputHash);
			Message.WriteInteger(OutputHash);
			return Algorithm::Signing::RecoverTweakedHash(Message.Hash(), PublicKeyHash, (uint8_t*)Signature->data());
		}
		bool AggregationTransaction::Attestate(const Algorithm::Seckey SecretKey)
		{
			if (OutputHashes.size() > 1)
				return false;

			auto GenesisBranch = OutputHashes.begin();
			Format::Stream CumulativeMessage;
			CumulativeMessage.WriteInteger(Asset);
			CumulativeMessage.WriteInteger(InputHash);
			CumulativeMessage.WriteInteger(GenesisBranch->first);

			Algorithm::Sighash CumulativeSignature;
			if (!Algorithm::Signing::SignTweaked(CumulativeMessage.Hash(), SecretKey, CumulativeSignature))
				return false;

			GenesisBranch->second.Attestations.insert(String((char*)CumulativeSignature, sizeof(CumulativeSignature)));
			return true;
		}
		bool AggregationTransaction::Merge(const TransactionContext* Context, const AggregationTransaction& Other)
		{
			if (Asset > 0 && Other.Asset != Asset)
				return false;
			else if (InputHash > 0 && Other.InputHash != InputHash)
				return false;

			Algorithm::Pubkeyhash Null = { 0 }, Owner = { 0 };
			if (!Other.Recover(Owner) || !memcmp(Owner, Null, sizeof(Null)))
				return false;

			UnorderedSet<String> Proposers;
			auto Branches = std::move(OutputHashes);
			auto* BranchA = GetCumulativeBranch(Context);
			auto* BranchB = Other.GetCumulativeBranch(Context);
			size_t BranchLengthA = (BranchA ? BranchA->Attestations.size() : 0);
			size_t BranchLengthB = (BranchB ? BranchB->Attestations.size() : 0);
			if (BranchLengthA < BranchLengthB)
				*this = Other;

			Asset = Other.Asset;
			InputHash = Other.InputHash;
			OutputHashes = std::move(Branches);
			for (auto& Branch : OutputHashes)
			{
				Format::Stream CumulativeMessage;
				CumulativeMessage.WriteInteger(Asset);
				CumulativeMessage.WriteInteger(InputHash);
				CumulativeMessage.WriteInteger(Branch.first);

				uint256_t CumulativeMessageHash = CumulativeMessage.Hash();
				for (auto& Signature : Branch.second.Attestations)
				{
					Algorithm::Pubkeyhash Proposer = { 0 };
					if (Signature.size() == sizeof(Algorithm::Sighash) && Algorithm::Signing::RecoverTweakedHash(CumulativeMessageHash, Proposer, (uint8_t*)Signature.data()))
						Proposers.insert(String((char*)Proposer, sizeof(Proposer)));
				}
			}
			for (auto& Branch : Other.OutputHashes)
			{
				Format::Stream CumulativeMessage;
				CumulativeMessage.WriteInteger(Asset);
				CumulativeMessage.WriteInteger(InputHash);
				CumulativeMessage.WriteInteger(Branch.first);

				uint256_t CumulativeMessageHash = CumulativeMessage.Hash();
				auto& Fork = OutputHashes[Branch.first];
				for (auto& Signature : Branch.second.Attestations)
				{
					Algorithm::Pubkeyhash Proposer = { 0 };
					if (Signature.size() == sizeof(Algorithm::Sighash) && Algorithm::Signing::RecoverTweakedHash(CumulativeMessageHash, Proposer, (uint8_t*)Signature.data()) && Proposers.find(String((char*)Proposer, sizeof(Proposer))) == Proposers.end())
					{
						Proposers.insert(String((char*)Proposer, sizeof(Proposer)));
						Fork.Attestations.insert(Signature);
					}
				}
			}

			return true;
		}
		bool AggregationTransaction::IsSignatureNull() const
		{
			Algorithm::Sighash Null = { 0 };
			for (auto& Branch : OutputHashes)
			{
				for (auto& Candidate : Branch.second.Attestations)
				{
					if (Candidate.size() != sizeof(Null) || !memcmp(Candidate.data(), Null, sizeof(Null)))
						return true;
				}
			}
			return memcmp(Signature, Null, sizeof(Null)) == 0;
		}
		bool AggregationTransaction::IsConsensusReached() const
		{
			if (OutputHashes.size() != 1)
				return false;

			auto GenesisBranch = OutputHashes.begin();
			if (GenesisBranch->second.Attestations.empty())
				return false;

			return GenesisBranch->second.Message.Hash() == GenesisBranch->first;
		}
		void AggregationTransaction::SetOptimalGas(const Decimal& Price)
		{
			auto OptimalGas = Ledger::TransactionContext::CalculateTxGas(this);
			if (OptimalGas)
			{
				Format::Stream Message;
				auto Blob = String(sizeof(Algorithm::Sighash), '0');
				size_t Size = (size_t)Protocol::Now().Policy.ConsensusCommitteeAggregators;
				Message.WriteInteger((uint16_t)OutputHashes.size());
				Message.WriteString(String(sizeof(Oracle::IncomingTransaction) * 10, '0'));
				Message.WriteInteger((uint16_t)Size);
				for (size_t i = 0; i < Size; i++)
					Message.WriteString(Blob);

				SetGas(Price, *OptimalGas + Message.Data.size() * (uint64_t)GasCost::WriteByte);
			}
			else
				SetGas(Price, GetGasEstimate());
		}
		void AggregationTransaction::SetConsensus(const uint256_t& OutputHash)
		{
			auto It = OutputHashes.find(OutputHash);
			if (It == OutputHashes.end())
				return OutputHashes.clear();

			auto Value = std::move(It->second);
			OutputHashes.clear();
			OutputHashes[OutputHash] = std::move(Value);
		}
		void AggregationTransaction::SetSignature(const Algorithm::Sighash NewValue)
		{
			VI_ASSERT(NewValue != nullptr, "new value should be set");
			memcpy(Signature, NewValue, sizeof(Algorithm::Sighash));
		}
		void AggregationTransaction::SetStatement(const uint256_t& NewInputHash, const Format::Stream& OutputMessage)
		{
			OutputHashes.clear();
			OutputHashes[OutputMessage.Hash()].Message = OutputMessage;
			InputHash = NewInputHash;
		}
		const AggregationTransaction::CumulativeBranch* AggregationTransaction::GetCumulativeBranch(const TransactionContext* Context) const
		{
			if (!Context)
				return OutputHashes.size() == 1 ? &OutputHashes.begin()->second : nullptr;

			uint256_t BestBranchWork = 0;
			const CumulativeBranch* BestBranch = nullptr;
			auto& Policy = Protocol::Now().Policy;
			for (auto& Branch : OutputHashes)
			{
				Format::Stream CumulativeMessage;
				CumulativeMessage.WriteInteger(Asset);
				CumulativeMessage.WriteInteger(InputHash);
				CumulativeMessage.WriteInteger(Branch.first);

				uint256_t CumulativeMessageHash = CumulativeMessage.Hash();
				uint256_t BranchWork = 0, WorkLimit = uint256_t::Max() / uint256_t(Branch.second.Attestations.size());
				for (auto& Signature : Branch.second.Attestations)
				{
					Algorithm::Pubkeyhash Proposer = { 0 };
					if (Signature.size() != sizeof(Algorithm::Sighash) || !Algorithm::Signing::RecoverTweakedHash(CumulativeMessageHash, Proposer, (uint8_t*)Signature.data()))
						continue;

					auto Work = Context->GetAccountWork(Proposer);
					BranchWork += std::min(Work ? Work->GetGasUse() : uint256_t(0), WorkLimit);
				}

				if (BranchWork > BestBranchWork)
				{
					BestBranch = &Branch.second;
					BestBranchWork = BranchWork;
				}
			}
			return BestBranch;
		}
		Option<AggregationTransaction::CumulativeConsensus> AggregationTransaction::CalculateCumulativeConsensus(OrderedMap<Algorithm::AssetId, size_t>* Aggregators, TransactionContext* Context) const
		{
			if (!Context)
				return Optional::None;

			auto* Branch = GetCumulativeBranch(Context);
			if (!Branch || Branch->Attestations.empty())
				return Optional::None;
			
			size_t Committee = 0;
			if (Aggregators != nullptr)
			{
				auto It = Aggregators->find(Asset);
				if (It == Aggregators->end())
					(*Aggregators)[Asset] = Committee = Context->CalculateAggregationCommitteeSize(Asset).Or(0);
				else
					Committee = It->second;
			}
			else
				Committee = Context->CalculateAggregationCommitteeSize(Asset).Or(0);

			CumulativeConsensus Consensus;
			Consensus.Branch = Branch;
			Consensus.Committee = std::min(Committee, Protocol::Now().Policy.ConsensusCommitteeAggregators);
			Consensus.Threshold = Protocol::Now().Policy.ConsensusAggregationThreshold;
			Consensus.Progress = Consensus.Committee > 0 ? ((double)Branch->Attestations.size() / (double)Consensus.Committee) : 0.0;
			Consensus.Reached = Consensus.Progress >= Consensus.Threshold;
			return Consensus;
		}
		uint256_t AggregationTransaction::GetCumulativeHash() const
		{
			Format::Stream Message;
			Message.WriteInteger(Asset);
			Message.WriteInteger(InputHash);
			return Message.Hash();
		}
		TransactionLevel AggregationTransaction::GetType() const
		{
			return TransactionLevel::Aggregation;
		}
		UPtr<Schema> AggregationTransaction::AsSchema() const
		{
			Schema* Data = Ledger::Transaction::AsSchema().Reset();
			Data->Set("input_hash", Var::String(Algorithm::Encoding::Encode0xHex256(InputHash)));

			auto* Branches = Data->Set("output_hashes", Var::Set::Object());
			for (auto& Branch : OutputHashes)
			{
				auto* Signatures = Branches->Set(Algorithm::Encoding::Encode0xHex256(Branch.first), Var::Set::Array());
				for (auto& Signature : Branch.second.Attestations)
					Signatures->Push(Var::String(Format::Util::Encode0xHex(Signature)));
			}
			return Data;
		}

		bool Receipt::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(TransactionHash);
			Stream->WriteInteger(AbsoluteGasUse);
			Stream->WriteInteger(RelativeGasUse);
			Stream->WriteInteger(RelativeGasPaid);
			Stream->WriteInteger(GenerationTime);
			Stream->WriteInteger(FinalizationTime);
			Stream->WriteInteger(BlockNumber);
			Stream->WriteBoolean(Successful);
			Stream->WriteString(std::string_view((char*)From, IsFromNull() ? 0 : sizeof(From)));
			Stream->WriteInteger((uint16_t)Events.size());
			for (auto& Item : Events)
			{
				Stream->WriteInteger(Item.first);
				if (!Format::VariablesUtil::SerializeMergeInto(Item.second, Stream))
					return false;
			}
			return true;
		}
		bool Receipt::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionHash))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &AbsoluteGasUse))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &RelativeGasUse))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &RelativeGasPaid))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GenerationTime))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &FinalizationTime))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &BlockNumber))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Successful))
				return false;

			String FromAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &FromAssembly) || !Algorithm::Encoding::DecodeUintBlob(FromAssembly, From, sizeof(From)))
				return false;

			uint16_t Size;
			if (!Stream.ReadInteger(Stream.ReadType(), &Size))
				return false;

			Events.clear();
			Events.reserve((size_t)Size);
			for (uint16_t i = 0; i < Size; i++)
			{
				uint32_t Type;
				if (!Stream.ReadInteger(Stream.ReadType(), &Type))
					return false;

				Format::Variables Values;
				if (!Format::VariablesUtil::DeserializeMergeFrom(Stream, &Values))
					return false;

				Events.emplace_back(std::make_pair(Type, std::move(Values)));
			}

			return true;
		}
		bool Receipt::IsFromNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return memcmp(From, Null, sizeof(Null)) == 0;
		}
		void Receipt::EmitEvent(uint32_t Type, Format::Variables&& Values)
		{
			Events.emplace_back(std::make_pair(Type, std::move(Values)));
		}
		const Format::Variables* Receipt::FindEvent(uint32_t Type, size_t Offset) const
		{
			for (auto& Item : Events)
			{
				if (Item.first == Type && !Offset--)
					return &Item.second;
			}
			return nullptr;
		}
		Option<String> Receipt::GetErrorMessages() const
		{
			String Messages;
			size_t Offset = 0;
			while (true)
			{
				auto* Event = FindEvent(0, Offset++);
				if (Event && !Event->empty())
					Messages.append(Event->front().AsBlob()).push_back('\n');
				else if (!Event)
					break;
			}

			if (Messages.empty())
				return Optional::None;

			Messages.pop_back();
			return Messages;
		}
		UPtr<Schema> Receipt::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(AsHash())));
			Data->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(TransactionHash)));
			Data->Set("from", Algorithm::Signing::SerializeAddress(From));
			Data->Set("absolute_gas_use", Algorithm::Encoding::SerializeUint256(AbsoluteGasUse));
			Data->Set("relative_gas_use", Algorithm::Encoding::SerializeUint256(RelativeGasUse));
			Data->Set("relative_gas_paid", Algorithm::Encoding::SerializeUint256(RelativeGasPaid));
			Data->Set("generation_time", Algorithm::Encoding::SerializeUint256(GenerationTime));
			Data->Set("finalization_time", Algorithm::Encoding::SerializeUint256(FinalizationTime));
			Data->Set("block_number", Algorithm::Encoding::SerializeUint256(BlockNumber));
			Data->Set("successful", Var::Boolean(Successful));
			auto* EventsData = Data->Set("events", Var::Set::Array());
			for (auto& Item : Events)
			{
				auto* EventData = EventsData->Push(Var::Set::Object());
				EventData->Set("event", Var::Integer(Item.first));
				EventData->Set("args", Format::VariablesUtil::Serialize(Item.second));
			}
			return Data;
		}
		uint32_t Receipt::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view Receipt::AsTypename() const
		{
			return AsInstanceTypename();
		}
		uint32_t Receipt::AsInstanceType()
		{
			static uint32_t Hash = Types::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view Receipt::AsInstanceTypename()
		{
			return "receipt";
		}

		State::State(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : BlockNumber(NewBlockNumber), BlockNonce(NewBlockNonce)
		{
		}
		State::State(const BlockHeader* NewBlockHeader) : BlockNumber(NewBlockHeader ? NewBlockHeader->Number : 0), BlockNonce(NewBlockHeader ? NewBlockHeader->MutationsCount : 0)
		{
		}
		bool State::Store(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Version);
			Stream->WriteInteger(AsType());
			Stream->WriteInteger(BlockNumber);
			Stream->WriteInteger(BlockNonce);
			return StorePayload(Stream);
		}
		bool State::Load(Format::Stream& Stream)
		{
			auto Type = ResolveType(Stream, &Version);
			if (!Type || *Type != AsType())
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &BlockNumber))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &BlockNonce))
				return false;

			if (!LoadPayload(Stream))
				return false;

			return true;
		}

		Uniform::Uniform(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : State(NewBlockNumber, NewBlockNonce)
		{
		}
		Uniform::Uniform(const BlockHeader* NewBlockHeader) : State(NewBlockHeader)
		{
		}
		UPtr<Schema> Uniform::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(AsHash())));
			Data->Set("type", Var::String(AsTypename()));
			Data->Set("index", Var::String(Format::Util::Encode0xHex(AsIndex())));
			Data->Set("block_number", Algorithm::Encoding::SerializeUint256(BlockNumber));
			Data->Set("block_nonce", Algorithm::Encoding::SerializeUint256(BlockNonce));
			return Data;
		}
		StateLevel Uniform::AsLevel() const
		{
			return StateLevel::Uniform;
		}
		String Uniform::AsComposite() const
		{
			return AsInstanceComposite(AsIndex());
		}
		String Uniform::AsInstanceComposite(const std::string_view& Index)
		{
			auto Composite = String(1 + Index.size(), 1);
			memcpy(Composite.data() + 1, Index.data(), Index.size());
			return Composite;
		}

		Multiform::Multiform(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : State(NewBlockNumber, NewBlockNonce)
		{
		}
		Multiform::Multiform(const BlockHeader* NewBlockHeader) : State(NewBlockHeader)
		{
		}
		UPtr<Schema> Multiform::AsSchema() const
		{
			Schema* Data = Var::Set::Object();
			Data->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(AsHash())));
			Data->Set("type", Var::String(AsTypename()));
			Data->Set("column", Var::String(Format::Util::Encode0xHex(AsColumn())));
			Data->Set("row", Var::String(Format::Util::Encode0xHex(AsRow())));
			Data->Set("factor", Var::Integer(AsFactor()));
			Data->Set("block_number", Algorithm::Encoding::SerializeUint256(BlockNumber));
			Data->Set("block_nonce", Algorithm::Encoding::SerializeUint256(BlockNonce));
			return Data;
		}
		StateLevel Multiform::AsLevel() const
		{
			return StateLevel::Multiform;
		}
		String Multiform::AsComposite() const
		{
			return AsInstanceComposite(AsColumn(), AsRow());
		}
		String Multiform::AsInstanceComposite(const std::string_view& Column, const std::string_view& Row)
		{
			auto Composite = String(1 + Column.size() + Row.size(), 2);
			memcpy(Composite.data() + 1, Column.data(), Column.size());
			memcpy(Composite.data() + 1 + Column.size(), Row.data(), Row.size());
			return Composite;
		}

		uint256_t GasUtil::GetGasWork(const uint128_t& Difficulty, const uint256_t& GasUse, const uint256_t& GasLimit)
		{
			if (!GasLimit)
				return 0;

			uint256_t Multiplier = 16;
			uint256_t Work = (8192 * GasUse) / GasLimit;
			return Work - (Work % Multiplier) + Multiplier;
		}
		uint256_t GasUtil::GetOperationalGasEstimate(size_t Bytes, size_t Operations)
		{
			Algorithm::Pubkeyhash Owner = { 1 };
			static size_t Limit = States::AccountSequence(Owner, 1, 1).AsMessage().Data.size();
			Bytes += Limit * Operations;
			return GetStorageGasEstimate(Bytes, Bytes);
		}
		uint256_t GasUtil::GetStorageGasEstimate(size_t BytesIn, size_t BytesOut)
		{
			const double HeapOverhead = 2.0, FormatOverhead = 1.05;
			BytesIn = (size_t)((double)BytesIn * FormatOverhead / HeapOverhead);
			BytesOut = (size_t)((double)BytesOut * FormatOverhead / HeapOverhead);

			uint256_t Gas = BytesIn * (size_t)Ledger::GasCost::WriteByte + BytesOut * (size_t)Ledger::GasCost::ReadByte;
			Gas -= Gas % 1000;
			return Gas + 1000;
		}
	}
}
