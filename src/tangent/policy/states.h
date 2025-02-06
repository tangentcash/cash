#ifndef TAN_POLICY_STATES_H
#define TAN_POLICY_STATES_H
#include "../kernel/transaction.h"

namespace Tangent
{
	namespace States
	{
		enum class AccountFlags : uint8_t
		{
			AsIs = 0,
			Offline = 1 << 0,
			Online = 1 << 1,
			Founder = 1 << 2,
			Outlaw = 1 << 3
		};

		enum class AddressType : uint8_t
		{
			Witness = 0,
			Router,
			Custodian,
			Contribution
		};

		struct AccountSequence final : Ledger::Uniform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			uint64_t Sequence = 0;

			AccountSequence(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountSequence(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::Pubkeyhash Owner);
		};

		struct AccountSealing final : Ledger::Uniform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::Pubkey SealingKey = { 0 };

			AccountSealing(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountSealing(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			bool IsSealingKeyNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::Pubkeyhash Owner);
		};

		struct AccountWork final : Ledger::Multiform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			uint8_t Flags = 0;
			uint64_t Penalty = 0;
			uint256_t GasInput = 0;
			uint256_t GasOutput = 0;

			AccountWork(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountWork(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsEligible(const Ledger::BlockHeader* BlockHeader) const;
			bool IsMatching(AccountFlags Flag) const;
			bool IsOnline() const;
			bool IsOwnerNull() const;
			uint256_t GetGasUse() const;
			uint64_t GetClosestProposalBlockNumber() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow();
			static uint256_t GetGasWorkRequired(const Ledger::BlockHeader* BlockHeader, const uint256_t& GasUse);
			static uint256_t GetAdjustedGasPaid(const uint256_t& GasUse, const uint256_t& GasPaid);
			static uint256_t GetAdjustedGasOutput(const uint256_t& GasUse, const uint256_t& GasPaid);
		};

		struct AccountObserver final : Ledger::Multiform
		{
			Algorithm::AssetId Asset = 0;
			Algorithm::Pubkeyhash Owner = { 0 };
			bool Observing = false;

			AccountObserver(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountObserver(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow(const Algorithm::AssetId& Asset);
		};

		struct AccountProgram final : Ledger::Uniform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			String Hashcode;

			AccountProgram(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountProgram(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::Pubkeyhash Owner);
		};

		struct AccountStorage final : Ledger::Uniform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			String Location;
			String Storage;

			AccountStorage(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountStorage(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::Pubkeyhash Owner, const std::string_view& Location);
		};

		struct AccountReward final : Ledger::Multiform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::AssetId Asset = 0;
			Decimal IncomingAbsoluteFee = Decimal::Zero();
			Decimal IncomingRelativeFee = Decimal::Zero();
			Decimal OutgoingAbsoluteFee = Decimal::Zero();
			Decimal OutgoingRelativeFee = Decimal::Zero();

			AccountReward(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountReward(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool HasIncomingFee() const;
			bool HasOutgoingFee() const;
			bool IsOwnerNull() const;
			Decimal CalculateIncomingFee(const Decimal& Value) const;
			Decimal CalculateOutgoingFee(const Decimal& Value) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow(const Algorithm::AssetId& Asset);
		};

		struct AccountDerivation final : Ledger::Uniform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::AssetId Asset = 0;
			uint64_t MaxAddressIndex = 0;

			AccountDerivation(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountDerivation(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::Pubkeyhash Owner, const Algorithm::AssetId& Asset);
		};

		struct AccountBalance final : Ledger::Multiform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::AssetId Asset = 0;
			Decimal Supply = Decimal::Zero();
			Decimal Reserve = Decimal::Zero();

			AccountBalance(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountBalance(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			Decimal GetBalance() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow(const Algorithm::AssetId& Asset);
		};

		struct AccountDepository final : Ledger::Multiform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::AssetId Asset = 0;
			AddressValueMap Contributions;
			AccountValueMap Reservations;
			OrderedSet<uint256_t> Transactions;
			Decimal Custody = Decimal::Zero();

			AccountDepository(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountDepository(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			Decimal GetReservation() const;
			Decimal GetContribution(const std::string_view& Address) const;
			Decimal GetContribution(const OrderedSet<String>& Addresses) const;
			Decimal GetContribution() const;
			Decimal GetCoverage(uint8_t Flags) const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow(const Algorithm::AssetId& Asset);
		};

		struct WitnessProgram final : Ledger::Uniform
		{
			String Hashcode;
			String Storage;

			WitnessProgram(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			WitnessProgram(const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			ExpectsLR<String> AsCode() const;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const std::string_view& ProgramHashcode);
		};

		struct WitnessEvent final : Ledger::Uniform
		{
			uint256_t ParentTransactionHash;
			uint256_t ChildTransactionHash;

			WitnessEvent(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			WitnessEvent(const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const uint256_t& TransactionHash);
		};

		struct WitnessAddress final : Ledger::Multiform
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::Pubkeyhash Proposer = { 0 };
			Algorithm::AssetId Asset = 0;
			AddressType Purpose = AddressType::Witness;
			AddressMap Addresses;
			uint64_t AddressIndex = 0;

			WitnessAddress(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			WitnessAddress(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			void SetProposer(const Algorithm::Pubkeyhash NewValue);
			bool IsWitnessAddress() const;
			bool IsRouterAddress() const;
			bool IsCustodianAddress() const;
			bool IsContributionAddress() const;
			bool IsOwnerNull() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsFactor() const override;
			String AsColumn() const override;
			String AsRow() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceColumn(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceRow(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex);
		};

		struct WitnessTransaction final : Ledger::Uniform
		{
			Algorithm::AssetId Asset = 0;
			String TransactionId;

			WitnessTransaction(uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			WitnessTransaction(const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			String AsIndex() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceIndex(const Algorithm::AssetId& Asset, const std::string_view& TransactionId);
		};

		class Resolver
		{
		public:
			static Ledger::State* New(uint32_t Hash);
			static Ledger::State* Copy(const Ledger::State* Base);
			static UnorderedSet<uint32_t> GetHashes();
		};
	}
}
#endif