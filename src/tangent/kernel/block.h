#ifndef TAN_KERNEL_BLOCK_H
#define TAN_KERNEL_BLOCK_H
#include "wallet.h"
#include "../policy/states.h"

namespace Tangent
{
	namespace Ledger
	{
		struct Block;
		struct BlockHeader;
		struct BlockProof;
		struct EvaluationContext;

		typedef OrderedMap<String, UPtr<Ledger::State>> StateWork;

		enum class GasCost
		{
			WriteByte = 24,
			ReadByte = 3,
			Opcode = 1
		};

		enum class WorkCommitment
		{
			Pending,
			Finalized,
			__Count__
		};

		struct BlockTransaction final : Messages::Generic
		{
			UPtr<Ledger::Transaction> Transaction;
			Ledger::Receipt Receipt;

			BlockTransaction() = default;
			BlockTransaction(UPtr<Ledger::Transaction>&& NewTransaction, Ledger::Receipt&& NewReceipt);
			BlockTransaction(BlockTransaction&&) noexcept = default;
			BlockTransaction(const BlockTransaction& Other);
			BlockTransaction& operator= (BlockTransaction&&) noexcept = default;
			BlockTransaction& operator= (const BlockTransaction& Other);
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct BlockWork
		{
			StateWork Map[(size_t)WorkCommitment::__Count__];
			const BlockWork* ParentWork = nullptr;

			BlockWork() = default;
			BlockWork(const BlockWork& Other);
			BlockWork(BlockWork&&) noexcept = default;
			BlockWork& operator= (const BlockWork& Other);
			BlockWork& operator= (BlockWork&&) noexcept = default;
			Option<UPtr<State>> FindUniform(const std::string_view& Index) const;
			Option<UPtr<State>> FindMultiform(const std::string_view& Column, const std::string_view& Row) const;
			void ClearUniform(const std::string_view& Index);
			void ClearMultiform(const std::string_view& Column, const std::string_view& Row);
			void CopyAny(State* Value);
			void MoveAny(UPtr<State>&& Value);
			const StateWork& At(WorkCommitment Level) const;
			StateWork& Clear();
			StateWork& Rollback();
			StateWork& Commit();
		};

		struct BlockMutation
		{
			BlockWork Cache;
			BlockWork* Outgoing;
			BlockWork* Incoming;

			BlockMutation() noexcept;
			BlockMutation(const BlockMutation& Other) noexcept;
			BlockMutation(BlockMutation&& Other) noexcept;
			BlockMutation& operator=(const BlockMutation& Other) noexcept;
			BlockMutation& operator=(BlockMutation&& Other) noexcept;
		};

		struct BlockDispatch
		{
			OrderedMap<uint256_t, String> Errors;
			Vector<uint256_t> Inputs;
			Vector<UPtr<Transaction>> Outputs;

			BlockDispatch() noexcept = default;
			BlockDispatch(const BlockDispatch& Other) noexcept;
			BlockDispatch(BlockDispatch&&) noexcept = default;
			BlockDispatch& operator=(const BlockDispatch& Other) noexcept;
			BlockDispatch& operator=(BlockDispatch&&) noexcept = default;
			ExpectsLR<void> Checkpoint() const;
		};
		
		struct BlockCheckpoint
		{
			uint64_t NewTipBlockNumber = 0;
			uint64_t OldTipBlockNumber = 0;
			uint64_t Resurrections = 0;
			bool IsFork = false;
		};

		struct BlockHeader : Messages::Authentic
		{
			Provability::WesolowskiVDF::Digest Wesolowski;
			Provability::WesolowskiVDF::Parameters Target;
			OrderedMap<Algorithm::AssetId, uint64_t> Witnesses;
			uint256_t ParentHash = 0;
			uint256_t TransactionsRoot = 0;
			uint256_t ReceiptsRoot = 0;
			uint256_t StatesRoot = 0;
			uint256_t GasUse = 0;
			uint256_t GasLimit = 0;
			uint256_t AbsoluteWork = 0;
			uint256_t SlotGasUse = 0;
			uint256_t SlotGasTarget = 0;
			uint256_t SlotDuration = 0;
			uint8_t Recovery = 0;
			uint64_t Time = 0;
			uint64_t Priority = 0;
			uint64_t Number = 0;
			uint64_t MutationsCount = 0;
			uint32_t TransactionsCount = 0;
			uint32_t StatesCount = 0;

			virtual ~BlockHeader() = default;
			virtual bool operator<(const BlockHeader& Other) const;
			virtual bool operator>(const BlockHeader& Other) const;
			virtual bool operator<=(const BlockHeader& Other) const;
			virtual bool operator>=(const BlockHeader& Other) const;
			virtual bool operator==(const BlockHeader& Other) const;
			virtual bool operator!=(const BlockHeader& Other) const;
			virtual ExpectsLR<BlockDispatch> DispatchSync(const Wallet& Proposer) const;
			virtual ExpectsPromiseLR<BlockDispatch> DispatchAsync(const Wallet& Proposer) const;
			virtual ExpectsLR<void> Verify(const BlockHeader* ParentBlock) const;
			virtual bool StorePayloadWesolowski(Format::Stream* Stream) const;
			virtual bool LoadPayloadWesolowski(Format::Stream& Stream);
			virtual bool StorePayload(Format::Stream* Stream) const override;
			virtual bool LoadPayload(Format::Stream& Stream) override;
			virtual bool Sign(const Algorithm::Seckey PrivateKey) override;
			virtual bool Solve(const Algorithm::Seckey PrivateKey);
			virtual bool Verify(const Algorithm::Pubkey PublicKey) const override;
			virtual bool Recover(Algorithm::Pubkeyhash PublicKeyHash) const override;
			virtual bool VerifyWesolowski() const;
			virtual void SetParentBlock(const BlockHeader* ParentBlock);
			virtual void SetWitnessRequirement(const Algorithm::AssetId& Asset, uint64_t BlockNumber);
			virtual uint64_t GetWitnessRequirement(const Algorithm::AssetId& Asset) const;
			virtual int8_t GetRelativeOrder(const BlockHeader& Other) const;
			virtual uint256_t GetSlotGasUse() const;
			virtual uint256_t GetSlotGasTarget() const;
			virtual uint64_t GetSlotDuration() const;
			virtual uint64_t GetSlotLength() const;
			virtual uint64_t GetDuration() const;
			virtual uint64_t GetProofTime() const;
			virtual uint256_t AsHash(bool Renew = false) const override;
			virtual UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static uint256_t GetGasLimit();
		};

		struct Block final : BlockHeader
		{
			Vector<BlockTransaction> Transactions;
			BlockWork States;

			Block() = default;
			Block(const BlockHeader& Other);
			Block(const Block&) = default;
			Block(Block&&) = default;
			virtual ~Block() override = default;
			Block& operator=(const Block&) = default;
			Block& operator=(Block&&) = default;
			ExpectsLR<void> Evaluate(const BlockHeader* ParentBlock, EvaluationContext* Environment, String* Errors);
			ExpectsLR<void> Validate(const BlockHeader* ParentBlock) const;
			ExpectsLR<void> Verify(const BlockHeader* ParentBlock) const override;
			ExpectsLR<BlockCheckpoint> Checkpoint() const;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool StoreHeaderPayload(Format::Stream* Stream) const;
			bool LoadHeaderPayload(Format::Stream& Stream);
			bool StoreBodyPayload(Format::Stream* Stream) const;
			bool LoadBodyPayload(Format::Stream& Stream);
			void Recalculate(const BlockHeader* ParentBlock);
			void InheritWork(const Block* ParentBlock);
			void InheritWork(const BlockWork* ParentWork);
			UPtr<Schema> AsSchema() const override;
			BlockHeader AsHeader() const;
			BlockProof AsProof(const BlockHeader* ParentBlock) const;
			uint256_t AsHash(bool Renew = false) const override;
		};

		struct BlockProof final : Messages::Generic
		{
			struct InternalState
			{
				Provability::MerkleTree TransactionsTree;
				Provability::MerkleTree ReceiptsTree;
				Provability::MerkleTree StatesTree;
			} Internal;
			Vector<uint256_t> Transactions;
			Vector<uint256_t> Receipts;
			Vector<uint256_t> States;
			uint256_t TransactionsRoot = 0;
			uint256_t ReceiptsRoot = 0;
			uint256_t StatesRoot = 0;

			BlockProof(const BlockHeader& FromBlock, const BlockHeader* FromParentBlock);
			Option<Provability::MerkleTree::Path> FindTransaction(const uint256_t& Hash);
			Option<Provability::MerkleTree::Path> FindReceipt(const uint256_t& Hash);
			Option<Provability::MerkleTree::Path> FindState(const uint256_t& Hash);
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool HasTransaction(const uint256_t& Hash);
			bool HasReceipt(const uint256_t& Hash);
			bool HasState(const uint256_t& Hash);
			Provability::MerkleTree& GetTransactionsTree();
			Provability::MerkleTree& GetReceiptsTree();
			Provability::MerkleTree& GetStatesTree();
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct TransactionContext
		{
		public:
			OrderedMap<Algorithm::AssetId, uint64_t> Witnesses;
			const EvaluationContext* Environment;
			const Ledger::Transaction* Transaction;
			Ledger::BlockHeader* Block;
			Ledger::Receipt Receipt;
			BlockMutation Delta;

		public:
			TransactionContext();
			TransactionContext(Ledger::Block* NewBlock);
			TransactionContext(Ledger::BlockHeader* NewBlockHeader);
			TransactionContext(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, Ledger::Receipt&& NewReceipt);
			TransactionContext(Ledger::BlockHeader* NewBlockHeader, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, Ledger::Receipt&& NewReceipt);
			TransactionContext(const TransactionContext& Other);
			TransactionContext(TransactionContext&&) = default;
			TransactionContext& operator=(const TransactionContext& Other);
			TransactionContext& operator=(TransactionContext&&) = default;
			ExpectsLR<void> Load(State* Value, bool Paid = true);
			ExpectsLR<void> Store(State* Value, bool Paid = true);
			ExpectsLR<void> EmitWitness(uint64_t BlockNumber);
			ExpectsLR<void> EmitWitness(const Algorithm::AssetId& Asset, uint64_t BlockNumber);
			ExpectsLR<void> EmitEvent(uint32_t Type, Format::Variables&& Values, bool Paid = true);
			ExpectsLR<void> BurnGas();
			ExpectsLR<void> BurnGas(const uint256_t& Value);
			ExpectsLR<void> VerifyAccountSequence() const;
			ExpectsLR<void> VerifyAccountWork() const;
			ExpectsLR<void> VerifyAccountWork(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<void> VerifyGasTransferBalance() const;
			ExpectsLR<void> VerifyTransferBalance(const Decimal& Value) const;
			ExpectsLR<void> VerifyTransferBalance(const Algorithm::AssetId& Asset, const Decimal& Value) const;
			ExpectsLR<Provability::WesolowskiVDF::Distribution> CalculateRandom(const uint256_t& Seed);
			ExpectsLR<size_t> CalculateAggregationCommitteeSize(const Algorithm::AssetId& Asset);
			ExpectsLR<Vector<States::AccountWork>> CalculateProposalCommittee(size_t Majors, size_t Minors, size_t* Proposers);
			ExpectsLR<States::AccountWork> CalculateSharingWitness(const OrderedSet<String>& Owners, bool WorkRequired);
			ExpectsLR<States::AccountSequence> ApplyAccountSequence();
			ExpectsLR<States::AccountSequence> ApplyAccountSequence(const Algorithm::Pubkeyhash Owner, uint64_t Sequence);
			ExpectsLR<States::AccountWork> ApplyAccountWork(const Algorithm::Pubkeyhash Owner, WorkStatus Status, uint64_t Penalty, const uint256_t& GasInput, const uint256_t& GasOutput);
			ExpectsLR<States::AccountObserver> ApplyAccountObserver(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, WorkStatus Status);
			ExpectsLR<States::AccountProgram> ApplyAccountProgram(const std::string_view& ProgramHashcode);
			ExpectsLR<States::AccountProgram> ApplyAccountProgram(const Algorithm::Pubkeyhash Owner, const std::string_view& ProgramHashcode);
			ExpectsLR<States::AccountStorage> ApplyAccountStorage(const std::string_view& Location, const std::string_view& Storage);
			ExpectsLR<States::AccountStorage> ApplyAccountStorage(const Algorithm::Pubkeyhash Owner, const std::string_view& Location, const std::string_view& Storage);
			ExpectsLR<States::AccountReward> ApplyAccountReward(const Algorithm::Pubkeyhash Owner, const Decimal& IncomingAbsoluteFee, const Decimal& IncomingRelativeFee, const Decimal& OutgoingAbsoluteFee, const Decimal& OutgoingRelativeFee);
			ExpectsLR<States::AccountReward> ApplyAccountReward(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& IncomingAbsoluteFee, const Decimal& IncomingRelativeFee, const Decimal& OutgoingAbsoluteFee, const Decimal& OutgoingRelativeFee);
			ExpectsLR<States::AccountDerivation> ApplyAccountDerivation(const Algorithm::Pubkeyhash Owner, uint64_t MaxAddressIndex);
			ExpectsLR<States::AccountDerivation> ApplyAccountDerivation(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, uint64_t MaxAddressIndex);
			ExpectsLR<States::AccountContribution> ApplyAccountContribution(const Algorithm::Pubkeyhash Owner, const Decimal& Custody, ContributionMap&& Contributions, ReservationMap&& Reservations, Option<double>&& Threshold = Optional::None);
			ExpectsLR<States::AccountContribution> ApplyAccountContribution(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& Custody, ContributionMap&& Contributions, ReservationMap&& Reservations, Option<double>&& Threshold = Optional::None);
			ExpectsLR<States::WitnessProgram> ApplyWitnessProgram(const std::string_view& PackedProgramCode);
			ExpectsLR<States::WitnessEvent> ApplyWitnessEvent(const uint256_t& ParentTransactionHash);
			ExpectsLR<States::WitnessEvent> ApplyWitnessEvent(const uint256_t& ParentTransactionHash, const uint256_t& ChildTransactionHash);
			ExpectsLR<States::WitnessAddress> ApplyWitnessAddress(const Algorithm::Pubkeyhash Owner, const Algorithm::Pubkeyhash Proposer, const AddressMap& Addresses, uint64_t AddressIndex, States::WitnessAddress::Class Purpose);
			ExpectsLR<States::WitnessAddress> ApplyWitnessAddress(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Algorithm::Pubkeyhash Proposer, const AddressMap& Addresses, uint64_t AddressIndex, States::WitnessAddress::Class Purpose);
			ExpectsLR<States::WitnessTransaction> ApplyWitnessTransaction(const std::string_view& TransactionId);
			ExpectsLR<States::WitnessTransaction> ApplyWitnessTransaction(const Algorithm::AssetId& Asset, const std::string_view& TransactionId);
			ExpectsLR<States::AccountBalance> ApplyTransfer(const Algorithm::Pubkeyhash Owner, const Decimal& Supply, const Decimal& Reserve);
			ExpectsLR<States::AccountBalance> ApplyTransfer(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const Decimal& Supply, const Decimal& Reserve);
			ExpectsLR<States::AccountBalance> ApplyPayment(const Algorithm::Pubkeyhash To, const Decimal& Value);
			ExpectsLR<States::AccountBalance> ApplyPayment(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash To, const Decimal& Value);
			ExpectsLR<States::AccountBalance> ApplyPayment(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash From, const Algorithm::Pubkeyhash To, const Decimal& Value);
			ExpectsLR<States::AccountBalance> ApplyFunding(const Decimal& Value);
			ExpectsLR<States::AccountBalance> ApplyFunding(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash From, const Algorithm::Pubkeyhash To, const Decimal& Value);
			ExpectsLR<States::AccountSequence> GetAccountSequence(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountWork> GetAccountWork(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountObserver> GetAccountObserver(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<Vector<States::AccountObserver>> GetAccountObservers(const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count) const;
			ExpectsLR<States::AccountProgram> GetAccountProgram(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountStorage> GetAccountStorage(const Algorithm::Pubkeyhash Owner, const std::string_view& Location) const;
			ExpectsLR<States::AccountReward> GetAccountReward(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountReward> GetAccountReward(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountDerivation> GetAccountDerivation(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountDerivation> GetAccountDerivation(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountBalance> GetAccountBalance(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountBalance> GetAccountBalance(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountContribution> GetAccountContribution(const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::AccountContribution> GetAccountContribution(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner) const;
			ExpectsLR<States::WitnessProgram> GetWitnessProgram(const std::string_view& ProgramHashcode) const;
			ExpectsLR<States::WitnessEvent> GetWitnessEvent(const uint256_t& ParentTransactionHash) const;
			ExpectsLR<Vector<States::WitnessAddress>> GetWitnessAddresses(const Algorithm::Pubkeyhash Owner, size_t Offset, size_t Count) const;
			ExpectsLR<Vector<States::WitnessAddress>> GetWitnessAddressesByPurpose(const Algorithm::Pubkeyhash Owner, States::WitnessAddress::Class Purpose, size_t Offset, size_t Count) const;
			ExpectsLR<States::WitnessAddress> GetWitnessAddress(const Algorithm::Pubkeyhash Owner, const std::string_view& Address, uint64_t AddressIndex) const;
			ExpectsLR<States::WitnessAddress> GetWitnessAddress(const Algorithm::AssetId& Asset, const Algorithm::Pubkeyhash Owner, const std::string_view& Address, uint64_t AddressIndex) const;
			ExpectsLR<States::WitnessAddress> GetWitnessAddress(const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const;
			ExpectsLR<States::WitnessAddress> GetWitnessAddress(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex, size_t Offset) const;
			ExpectsLR<States::WitnessTransaction> GetWitnessTransaction(const std::string_view& TransactionId) const;
			ExpectsLR<States::WitnessTransaction> GetWitnessTransaction(const Algorithm::AssetId& Asset, const std::string_view& TransactionId) const;
			ExpectsLR<Ledger::BlockTransaction> GetBlockTransactionInstance(const uint256_t& TransactionHash) const;
			uint64_t GetValidationNonce() const;
			uint256_t GetGasUse() const;
			uint256_t GetGasLeft() const;
			Decimal GetGasCost() const;

		public:
			template <typename T>
			ExpectsLR<void> EmitEvent(Format::Variables&& Values, bool Paid = true)
			{
				return EmitEvent(T::AsInstanceType(), std::move(Values), Paid);
			}
			template <typename T>
			ExpectsLR<Ledger::BlockTransaction> GetBlockTransaction(const uint256_t& TransactionHash) const
			{
				auto Transaction = GetBlockTransactionInstance(TransactionHash);
				if (!Transaction)
					return Transaction.Error();

				if (Transaction->Transaction->AsType() != T::AsInstanceType())
					return LayerException("block transaction not valid");

				return Transaction;
			}

		public:
			static ExpectsLR<void> PrevalidateTx(const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, Algorithm::Pubkeyhash Owner);
			static ExpectsLR<TransactionContext> ValidateTx(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, BlockWork& Cache);
			static ExpectsLR<TransactionContext> ValidateTx(Ledger::Block* NewBlock, const Ledger::EvaluationContext* NewEnvironment, const Ledger::Transaction* NewTransaction, const uint256_t& NewTransactionHash, const Algorithm::Pubkeyhash Owner, BlockWork& Cache);
			static ExpectsLR<void> ExecuteTx(TransactionContext& Context, size_t TransactionSize, bool OnlySuccessful = false);
			static ExpectsLR<uint256_t> CalculateTxGas(const Ledger::Transaction* Transaction);
			static ExpectsPromiseLR<void> DispatchTx(const Wallet& Proposer, Ledger::BlockTransaction* Transaction, Vector<UPtr<Ledger::Transaction>>* Pipeline);
		};

		struct EvaluationContext
		{
			struct TransactionInfo
			{
				uint256_t Hash = 0;
				Algorithm::Pubkeyhash Owner = { 0 };
				UPtr<Transaction> Candidate;
				size_t Size = 0;
			};
			struct ValidationInfo
			{
				TransactionContext Context;
				uint256_t CumulativeGas = 0;
				BlockWork Cache;
				bool Tip = false;
			} Validation;
			struct ProposerContext
			{
				Algorithm::Pubkeyhash PublicKeyHash = { 0 };
				Algorithm::Seckey PrivateKey = { 0 };
			} Proposer;
			Option<BlockHeader> Tip = Optional::None;
			OrderedMap<Algorithm::AssetId, size_t> Aggregators;
			Vector<States::AccountWork> Proposers;
			Vector<TransactionInfo> Incoming;
			Vector<uint256_t> Outgoing;
			size_t Precomputed = 0;

			Option<uint64_t> Priority(const Algorithm::Pubkeyhash PublicKeyHash, const Algorithm::Seckey PrivateKey, Option<BlockHeader*>&& ParentBlock = Optional::None);
			size_t Apply(Vector<UPtr<Transaction>>&& Candidates);
			ExpectsLR<Block> Evaluate(String* Errors);
			ExpectsLR<void> Solve(Block& Candidate);
			ExpectsLR<void> Verify(const Block& Candidate);
			ExpectsLR<void> Cleanup();

		private:
			void Precompute(Vector<TransactionInfo>& Candidates);
		};
	}
}
#endif