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
		struct Commitment final : Ledger::Transaction
		{
			int8_t Status = 0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetOnline();
			void SetOffline();
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Transfer final : Ledger::Transaction
		{
			Decimal Value;
			Algorithm::Pubkeyhash To = { 0 };
			uint32_t Memo = 0;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, uint32_t NewMemo = 0);
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
				Decimal Value;
				Algorithm::Pubkeyhash To = { 0 };
				uint32_t Memo = 0;
			};
			Vector<Subtransfer> Transfers;

			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			void SetTo(const Algorithm::Pubkeyhash NewTo, const Decimal& NewValue, uint32_t NewMemo = 0);
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
			bool Apply(const Ledger::Transaction& Transaction);
			bool Apply(Ledger::Transaction& Transaction, const Algorithm::Seckey PrivateKey);
			bool Apply(Ledger::Transaction& Transaction, const Algorithm::Seckey PrivateKey, uint64_t Sequence);
			void Setup(Ledger::Transaction& Transaction) const;
			ExpectsLR<Ledger::BlockTransaction> ResolveBlockTransaction(const Ledger::Receipt& Receipt, const uint256_t& TransactionHash) const;
			const Ledger::Transaction* ResolveTransaction(const uint256_t& TransactionHash) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Account final : Ledger::EventTransaction
		{
			Algorithm::Sighash OwnerSignature = { 0 };
			Oracle::VerifiableMessage Router;
			Oracle::VerifiableMessage Custodian;
			String RouterSignature;
			String CustodianSignature;

			ExpectsLR<void> DeployRouterAddress(const Ledger::Wallet& Owner, const std::string_view& NewAddress = std::string_view());
			ExpectsLR<void> DeployRouterAddress(const Ledger::Wallet& Owner, const std::string_view& NewAddress, const std::string_view& NewPublicKey, const std::string_view& NewPrivateKey);
			ExpectsLR<void> DeployCustodianAddress(const Ledger::Wallet& Proposer, const Algorithm::Pubkeyhash Owner);
			ExpectsLR<bool> VerifyRouterAddress() const;
			ExpectsLR<bool> VerifyCustodianAddress() const;
			ExpectsLR<void> Prevalidate() const override;
			ExpectsLR<void> Validate(const Ledger::TransactionContext* Context) const override;
			ExpectsLR<void> Execute(Ledger::TransactionContext* Context) const override;
			ExpectsPromiseLR<void> Dispatch(const Ledger::Wallet& Proposer, const Ledger::TransactionContext* Context, Vector<UPtr<Ledger::Transaction>>* Pipeline) const override;
			bool StoreBody(Format::Stream* Stream) const override;
			bool LoadBody(Format::Stream& Stream) override;
			bool RecoverAlt(const Ledger::Receipt& Receipt, OrderedSet<String>& Parties) const override;
			bool IsOwnerSignatureNull() const;
			void SetOwnerSignature(const Algorithm::Sighash NewValue);
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			uint64_t GetDispatchOffset() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct Replay final : Ledger::EventTransaction
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

		struct Claim final : Ledger::CumulativeEventTransaction
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
			Option<Oracle::IncomingTransaction> GetAssertion() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			uint256_t GetGasEstimate() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};

		struct ContributionAllocation final : Ledger::EventTransaction
		{
			Algorithm::Pubkey SealingPublicKey1 = { 0 };
			Algorithm::Composition::CPubkey PublicKey1 = { 0 };
			String EncryptedPrivateKey1For1;

			ExpectsLR<void> DeployShare1(const Algorithm::Seckey PrivateKey);
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

		struct ContributionActivation final : Ledger::EventTransaction
		{
			Algorithm::Pubkey PublicKey = { 0 };
			Algorithm::Pubkey SealingPublicKey2 = { 0 };
			Algorithm::Composition::CPubkey PublicKey2 = { 0 };
			String EncryptedPrivateKey2For2;
			uint16_t PublicKeySize = 0;
			uint256_t ContributionAllocationHash = 0;

			ExpectsLR<void> DeployShare2(const Algorithm::Seckey PrivateKey, const Algorithm::Composition::CPubkey PublicKey1);
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

		struct ContributionDeallocation final : Ledger::EventTransaction
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

		struct ContributionDeactivation final : Ledger::EventTransaction
		{
			String EncryptedPrivateKey2For1;
			uint256_t ContributionDeallocationHash = 0;

			ExpectsLR<void> RevealShare2(const uint256_t& ContributionDeallocationHash, const Algorithm::Seckey PrivateKey);
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

		struct ContributionAdjustment final : Ledger::EventTransaction
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

		struct ContributionAllowance final : Ledger::EventTransaction
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

		struct ContributionMigration final : Ledger::EventTransaction
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