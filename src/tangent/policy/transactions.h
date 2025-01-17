#ifndef TAN_POLICY_TRANSACTIONS_H
#define TAN_POLICY_TRANSACTIONS_H
#include "states.h"
#include "../kernel/oracle.h"

namespace Tangent
{
	namespace Ledger
	{
		struct BlockTransaction;
	}

	namespace Transactions
	{
		struct Transfer final : Ledger::Transaction
		{
			Algorithm::Pubkeyhash To = { 0 };
			Decimal Value;
			String Memo;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, const std::string_view& NewMemo = std::string_view());
			bool IsToNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Omnitransfer final : Ledger::Transaction
		{
			struct Subtransfer
			{
				Algorithm::Pubkeyhash To = { 0 };
				Decimal Value;
				String Memo;
			};
			Vector<Subtransfer> Transfers;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, const std::string_view& NewMemo = std::string_view());
			bool IsToNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Deployment final : Ledger::Transaction
		{
			Algorithm::Sighash Location = { 0 };
			Format::Variables Args;
			String Calldata;
			bool Patchable = false;
			bool Segregated = false;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			bool SignLocation(const Algorithm::Seckey PrivateKey);
			bool VerifyLocation(const Algorithm::Pubkey PublicKey) const;
			bool RecoverLocation(Algorithm::Pubkeyhash PublicKeyHash) const;
			bool IsLocationNull() const;
			void SetLocation(const Algorithm::Sighash NewValue);
			void SetCalldata(const std::string_view& NewProgram, Format::Variables&& NewArgs, bool MayPatch = false);
			void SetSegregatedCalldata(const std::string_view& NewHashcode, Format::Variables&& NewArgs, bool MayPatch = false);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Invocation final : Ledger::Transaction
		{
			Algorithm::Pubkeyhash To = { 0 };
			Format::Variables Args;
			String Function;
			uint32_t Hashcode = 0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetCalldata(const Algorithm::Pubkeyhash NewTo, const std::string_view& NewFunction, Format::Variables&& NewArgs);
			void SetCalldata(const Algorithm::Pubkeyhash NewTo, uint32_t NewHashcode, const std::string_view& NewFunction, Format::Variables&& NewArgs);
			bool IsToNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Withdrawal final : Ledger::Transaction
		{
			Vector<std::pair<String, Decimal>> To;
			Algorithm::Pubkeyhash Proposer = { 0 };

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetTo(const std::string_view& Address, const Decimal& Value);
			void SetProposer(const Algorithm::Pubkeyhash NewProposer);
			bool IsProposerNull() const;
			Decimal GetTotalValue() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Rollup final : Ledger::Transaction
		{
			OrderedMap<Algorithm::AssetId, Vector<UPtr<Ledger::Transaction>>> Transactions;

			Rollup() = default;
			Rollup(const Rollup& Other);
			Rollup(Rollup&&) noexcept = default;
			Rollup& operator= (const Rollup& Other);
			Rollup& operator= (Rollup&&) noexcept = default;
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<uint256_t>& Aliases) const override;
			bool Merge(const Ledger::Transaction& Transaction);
			bool Merge(Ledger::Transaction& Transaction, const Algorithm::Seckey PrivateKey);
			bool Merge(Ledger::Transaction& Transaction, const Algorithm::Seckey PrivateKey, uint64_t Sequence);
			ExpectsLR<Ledger::BlockTransaction> ResolveBlockTransaction(const Ledger::Receipt& Receipt, const uint256_t& TransactionHash) const;
			const Ledger::Transaction* ResolveTransaction(const uint256_t& TransactionHash) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static void SetupChild(Ledger::Transaction& Transaction, const Algorithm::AssetId& Asset);
			static bool SignChild(Ledger::Transaction& Transaction, const Algorithm::Seckey PrivateKey, const Algorithm::AssetId& Asset, uint16_t Index);
		};

		struct Commitment final : Ledger::Transaction
		{
			OrderedMap<Algorithm::AssetId, Ledger::WorkStatus> Observers;
			Ledger::WorkStatus Worker = Ledger::WorkStatus::Standby;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetOnline();
			void SetOnline(const Algorithm::AssetId& Asset);
			void SetOffline();
			void SetOffline(const Algorithm::AssetId& Asset);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Claim final : Ledger::AggregationTransaction
		{
			struct CustodyTransfer
			{
				ContributionMap Contributions;
				ReservationMap Reservations;
				Decimal Custody = Decimal::Zero();
			};

			struct BalanceTransfer
			{
				Decimal Supply = Decimal::Zero();
				Decimal Reserve = Decimal::Zero();
			};

			struct Transition
			{
				OrderedMap<String, CustodyTransfer> Contributions;
				OrderedMap<String, BalanceTransfer> Transfers;
			};

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetWitness(uint64_t BlockHeight, const std::string_view& TransactionId, Decimal&& Fee, Vector<Oracle::Transferer>&& Senders, Vector<Oracle::Transferer>&& Receivers);
			void SetWitness(const Oracle::IncomingTransaction& Witness);
			Option<Oracle::IncomingTransaction> GetAssertion(const Ledger::TransactionContext* Context) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Replay final : Ledger::ConsensusTransaction
		{
			String TransactionId;
			String TransactionData;
			String TransactionMessage;
			uint256_t TransactionHash = 0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetSuccessWitness(const std::string_view& TransactionId, const std::string_view& TransactionData, const uint256_t& TransactionHash);
			void SetFailureWitness(const std::string_view& TransactionMessage, const uint256_t& TransactionHash);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct AddressAccount final : Ledger::DelegationTransaction
		{
			String Address;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetAddress(const std::string_view& NewAddress);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct PubkeyAccount final : Ledger::DelegationTransaction
		{
			String Pubkey;
			String Sighash;

			ExpectsLR<void> SignPubkey(const PrivateKey& SigningKey);
			ExpectsLR<void> VerifyPubkey() const;
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetPubkey(const std::string_view& VerifyingKey);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct DelegationAccount final : Ledger::DelegationTransaction
		{
			Algorithm::Pubkeyhash Proposer = { 0 };

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetProposer(const Algorithm::Pubkeyhash NewProposer);
			bool IsProposerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct CustodianAccount final : Ledger::ConsensusTransaction
		{
			uint256_t DelegationAccountHash = 0;
			Algorithm::Pubkeyhash Owner = { 0 };
			uint64_t PubkeyIndex = 0;
			String Pubkey;
			String Sighash;

			ExpectsLR<void> SetWallet(const Ledger::Wallet& Proposer, const Algorithm::Pubkeyhash NewOwner);
			ExpectsLR<void> SignPubkey(const PrivateKey& SigningKey);
			ExpectsLR<void> VerifyPubkey() const;
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetWitness(const uint256_t& DelegationAccountHash);
			void SetPubkey(const std::string_view& VerifyingKey, uint64_t NewPubkeyIndex);
			void SetOwner(const Algorithm::Pubkeyhash NewOwner);
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionAllocation final : Ledger::Transaction
		{
			Algorithm::Pubkey SealingKey1 = { 0 };
			Algorithm::Composition::CPubkey PublicKey1 = { 0 };
			String EncryptedPrivateKey1For1;

			ExpectsLR<void> SetShare1(const Algorithm::Seckey PrivateKey);
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			Option<String> GetPrivateKey1(const Algorithm::Seckey PrivateKey) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionActivation final : Ledger::ConsensusTransaction
		{
			Algorithm::Pubkey PublicKey = { 0 };
			Algorithm::Pubkey SealingKey2 = { 0 };
			Algorithm::Composition::CPubkey PublicKey2 = { 0 };
			String EncryptedPrivateKey2For2;
			uint16_t PublicKeySize = 0;
			uint256_t ContributionAllocationHash = 0;

			ExpectsLR<void> SetShare2(const Algorithm::Seckey PrivateKey, const Algorithm::Composition::CPubkey PublicKey1);
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetWitness(const uint256_t& ContributionAllocationHash);
			Option<String> GetPrivateKey2(const Algorithm::Seckey PrivateKey) const;
			ExpectsLR<Oracle::DerivedVerifyingWallet> GetVerifyingWallet() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionDeallocation final : Ledger::Transaction
		{
			uint256_t ContributionActivationHash = 0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetWitness(const uint256_t& ContributionActivationHash);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionDeactivation final : Ledger::ConsensusTransaction
		{
			String EncryptedPrivateKey2For1;
			uint256_t ContributionDeallocationHash = 0;

			ExpectsLR<void> SetRevealingShare2(const uint256_t& ContributionDeallocationHash, const Algorithm::Seckey PrivateKey);
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			Option<String> GetPrivateKey1(const Algorithm::Seckey PrivateKey) const;
			Option<String> GetPrivateKey2(const Algorithm::Seckey PrivateKey) const;
			ExpectsLR<Oracle::DerivedSigningWallet> GetSigningWallet(const Algorithm::Seckey PrivateKey) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionAdjustment final : Ledger::Transaction
		{
			Decimal IncomingAbsoluteFee = Decimal::Zero();
			Decimal IncomingRelativeFee = Decimal::Zero();
			Decimal OutgoingAbsoluteFee = Decimal::Zero();
			Decimal OutgoingRelativeFee = Decimal::Zero();

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetIncomingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee);
			void SetOutgoingFee(const Decimal& AbsoluteFee, const Decimal& RelativeFee);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionAllowance final : Ledger::Transaction
		{
			Algorithm::Pubkeyhash To = { 0 };
			double Threshold = -1.0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetThreshold(const Algorithm::Pubkeyhash To, double Threshold);
			void ClearThreshold(const Algorithm::Pubkeyhash To);
			bool IsToNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionMigration final : Ledger::Transaction
		{
			Algorithm::Pubkeyhash Proposer = { 0 };
			Decimal Value;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetProposer(const Algorithm::Pubkeyhash NewProposer, const Decimal& NewValue);
			bool IsProposerNull() const;
			ExpectsLR<States::WitnessAddress> GetDestination(const Ledger::TransactionContext* Context) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		class Resolver
		{
		public:
			static Ledger::Transaction* New(uint32_t Hash);
			static Ledger::Transaction* Copy(const Ledger::Transaction* Base);
		};
	}
}
#endif