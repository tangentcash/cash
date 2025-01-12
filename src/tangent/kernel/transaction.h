#ifndef TAN_KERNEL_TRANSACTION_H
#define TAN_KERNEL_TRANSACTION_H
#include "wallet.h"
#include "provability.h"

namespace Tangent
{
	namespace Ledger
	{
		struct State;
		struct BlockHeader;
		struct TransactionContext;
		struct Receipt;

		enum class WorkStatus : int8_t
		{
			Online = 1,
			Standby = 0,
			Offline = -1
		};

		enum class StateLevel
		{
			Uniform,
			Multiform
		};

		enum class TransactionLevel
		{
			Functional,
			Delegation,
			Consensus,
			Aggregation
		};

		struct Transaction : Messages::Authentic
		{
			Algorithm::AssetId Asset = 0;
			Decimal GasPrice;
			uint256_t GasLimit = 0;
			uint64_t Sequence = 0;
			bool Conservative = false;

			virtual ExpectsLR<void> Prevalidate() const;
			virtual ExpectsLR<void> Validate(const TransactionContext* Context) const;
			virtual ExpectsLR<void> Execute(TransactionContext* Context) const = 0;
			virtual ExpectsPromiseLR<void> Dispatch(const Wallet& Proposer, const TransactionContext* Context, Vector<UPtr<Transaction>>* Pipeline) const;
			virtual bool StorePayload(Format::Stream* Stream) const override;
			virtual bool LoadPayload(Format::Stream& Stream) override;
			virtual bool StoreBody(Format::Stream* Stream) const = 0;
			virtual bool LoadBody(Format::Stream& Stream) = 0;
			virtual bool RecoverAlt(const Receipt& Receipt, OrderedSet<String>& Parties) const = 0;
			virtual bool RecoverAlt(const Receipt& Receipt, OrderedSet<uint256_t>& Aliases) const;
			virtual bool Sign(const Algorithm::Seckey PrivateKey) override;
			virtual bool Sign(const Algorithm::Seckey PrivateKey, uint64_t NewSequence);
			virtual bool Sign(const Algorithm::Seckey PrivateKey, uint64_t NewSequence, const Decimal& Price);
			virtual void SetOptimalGas(const Decimal& Price);
			virtual void SetEstimateGas(const Decimal& Price);
			virtual void SetGas(const Decimal& Price, const uint256_t& Limit);
			virtual void SetAsset(const std::string_view& Blockchain, const std::string_view& Token = std::string_view(), const std::string_view& ContractAddress = std::string_view());
			virtual bool IsConsensus() const;
			virtual TransactionLevel GetType() const;
			virtual UPtr<Schema> AsSchema() const override;
			virtual uint32_t AsType() const override = 0;
			virtual std::string_view AsTypename() const override = 0;
			virtual uint256_t GetGasEstimate() const = 0;
			virtual uint64_t GetDispatchOffset() const;
		};

		struct DelegationTransaction : Transaction
		{
			virtual ExpectsLR<void> Validate(const TransactionContext* Context) const override;
			TransactionLevel GetType() const override;
		};

		struct ConsensusTransaction : Transaction
		{
			virtual ExpectsLR<void> Validate(const TransactionContext* Context) const override;
			TransactionLevel GetType() const override;
		};

		struct AggregationTransaction : Transaction
		{
			struct CumulativeBranch
			{
				OrderedSet<String> Attestations;
				Format::Stream Message;
			};

			struct CumulativeConsensus
			{
				const CumulativeBranch* Branch = nullptr;
				double Threshold = 0.0;
				double Progress = 0.0;
				size_t Committee = 0;
				bool Reached = false;
			};

			OrderedMap<uint256_t, CumulativeBranch> OutputHashes;
			uint256_t InputHash = 0;

			virtual ExpectsLR<void> Prevalidate() const override;
			virtual ExpectsLR<void> Validate(const TransactionContext* Context) const override;
			virtual bool StorePayload(Format::Stream* Stream) const override;
			virtual bool LoadPayload(Format::Stream& Stream) override;
			virtual bool Sign(const Algorithm::Seckey PrivateKey) override;
			virtual bool Sign(const Algorithm::Seckey PrivateKey, uint64_t NewSequence) override;
			virtual bool Sign(const Algorithm::Seckey PrivateKey, uint64_t NewSequence, const Decimal& Price) override;
			virtual bool Verify(const Algorithm::Pubkey PublicKey) const override;
			virtual bool Verify(const Algorithm::Pubkey PublicKey, const uint256_t& OutputHash, size_t Index) const;
			virtual bool Recover(Algorithm::Pubkeyhash PublicKeyHash) const override;
			virtual bool Recover(Algorithm::Pubkeyhash PublicKeyHash, const uint256_t& OutputHash, size_t Index) const;
			virtual bool Attestate(const Algorithm::Seckey PrivateKey);
			virtual bool Merge(const TransactionContext* Context, const AggregationTransaction& Other);
			virtual bool IsSignatureNull() const override;
			virtual bool IsConsensusReached() const;
			virtual void SetOptimalGas(const Decimal& Price) override;
			virtual void SetConsensus(const uint256_t& OutputHash);
			virtual void SetSignature(const Algorithm::Sighash NewValue) override;
			virtual void SetStatement(const uint256_t& NewInputHash, const Format::Stream& OutputMessage);
			virtual const CumulativeBranch* GetCumulativeBranch(const TransactionContext* Context) const;
			virtual Option<CumulativeConsensus> CalculateCumulativeConsensus(OrderedMap<Algorithm::AssetId, size_t>* Aggregators, TransactionContext* Context) const;
			virtual uint256_t GetCumulativeHash() const;
			virtual UPtr<Schema> AsSchema() const override;
			TransactionLevel GetType() const override;
		};

		struct Receipt final : Messages::Generic
		{
			Vector<std::pair<uint32_t, Format::Variables>> Events;
			Algorithm::Pubkeyhash From = { 0 };
			uint256_t TransactionHash = 0;
			uint256_t AbsoluteGasUse = 0;
			uint256_t RelativeGasUse = 0;
			uint256_t RelativeGasPaid = 0;
			uint64_t GenerationTime = 0;
			uint64_t FinalizationTime = 0;
			uint64_t BlockNumber = 0;
			bool Successful = false;

			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsFromNull() const;
			void EmitEvent(uint32_t Type, Format::Variables&& Values);
			const Format::Variables* FindEvent(uint32_t Type, size_t Offset = 0) const;
			Option<String> GetErrorMessages() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			template <typename T>
			void EmitEvent(Format::Variables&& Values)
			{
				EmitEvent(T::AsInstanceType(), std::move(Values));
			}
			template <typename T>
			const Format::Variables* FindEvent(size_t Offset = 0) const
			{
				return FindEvent(T::AsInstanceType(), Offset);
			}
		};

		struct State : Messages::Generic
		{
			uint64_t BlockNumber = 0;
			uint64_t BlockNonce = 0;

			State(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			State(const BlockHeader* NewBlockHeader);
			virtual ~State() = default;
			virtual ExpectsLR<void> Transition(const TransactionContext* Context, const State* PrevState) = 0;
			virtual bool Store(Format::Stream* Stream) const override;
			virtual bool Load(Format::Stream& Stream) override;
			virtual bool StorePayload(Format::Stream* Stream) const override = 0;
			virtual bool LoadPayload(Format::Stream& Stream) override = 0;
			virtual StateLevel AsLevel() const = 0;
			virtual String AsComposite() const = 0;
			virtual UPtr<Schema> AsSchema() const override = 0;
			virtual uint32_t AsType() const override = 0;
			virtual std::string_view AsTypename() const override = 0;
		};

		struct Uniform : State
		{
			Uniform(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			Uniform(const BlockHeader* NewBlockHeader);
			virtual UPtr<Schema> AsSchema() const override;
			virtual StateLevel AsLevel() const override;
			virtual String AsComposite() const override;
			virtual String AsIndex() const = 0;
			static String AsInstanceComposite(const std::string_view& Index);
		};
		
		struct Multiform : State
		{
			Multiform(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			Multiform(const BlockHeader* NewBlockHeader);
			virtual UPtr<Schema> AsSchema() const override;
			virtual StateLevel AsLevel() const override;
			virtual String AsComposite() const override;
			virtual String AsColumn() const = 0;
			virtual String AsRow() const = 0;
			virtual int64_t AsFactor() const = 0;
			static String AsInstanceComposite(const std::string_view& Column, const std::string_view& Row);
		};

		class GasUtil
		{
		public:
			static uint256_t GetGasWork(const uint128_t& Difficulty, const uint256_t& GasUse, const uint256_t& GasLimit);
			static uint256_t GetOperationalGasEstimate(size_t Size, size_t Operations);
			static uint256_t GetStorageGasEstimate(size_t BytesIn, size_t BytesOut);
			template <typename T, size_t Operations>
			static uint256_t GetGasEstimate()
			{
				static uint256_t Limit = GetOperationalGasEstimate(T().AsMessage().Data.size(), Operations);
				return Limit;
			}
		};
	}
}
#endif
