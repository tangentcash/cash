#ifndef TAN_POLICY_STATES_H
#define TAN_POLICY_STATES_H
#include "../kernel/transaction.h"

namespace Tangent
{
	namespace States
	{
		struct AccountSequence final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride();
		};

		struct AccountWork final : Ledger::State
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			uint256_t GasInput = 0;
			uint256_t GasOutput = 0;
			uint64_t Penalty = 0;
			int8_t Status = -1;

			AccountWork(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountWork(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsEligible(const Ledger::BlockHeader* BlockHeader) const;
			bool IsOnline() const;
			bool IsOwnerNull() const;
			uint256_t GetGasUse() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride();
			static uint256_t GetGasWorkRequired(const Ledger::BlockHeader* BlockHeader, const uint256_t& GasUse);
			static uint256_t GetAdjustedGasPaid(const uint256_t& GasUse, const uint256_t& GasPaid);
			static uint256_t GetAdjustedGasOutput(const uint256_t& GasUse, const uint256_t& GasPaid);
		};

		struct AccountProgram final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride();
		};

		struct AccountStorage final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const std::string_view& Location);
		};

		struct AccountReward final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const Algorithm::AssetId& Asset);
		};

		struct AccountDerivation final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const Algorithm::AssetId& Asset);
		};

		struct AccountBalance final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const Algorithm::AssetId& Asset);
		};

		struct AccountContribution final : Ledger::State
		{
			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::AssetId Asset = 0;
			ContributionMap Contributions;
			ReservationMap Reservations;
			Option<double> Threshold = Optional::None;
			Decimal Custody = Decimal::Zero();
			bool Honest = true;

			AccountContribution(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce);
			AccountContribution(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader);
			ExpectsLR<void> Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState) override;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsOwnerNull() const;
			Decimal GetReservation() const;
			Decimal GetContribution(const std::string_view& Address) const;
			Decimal GetContribution(const OrderedSet<String>& Addresses) const;
			Decimal GetContribution() const;
			Decimal GetCoverage() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const Algorithm::AssetId& Asset);
		};

		struct WitnessProgram final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			ExpectsLR<String> AsCode() const;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const std::string_view& ProgramHashcode);
			static String AsInstanceStride();
		};

		struct WitnessEvent final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const uint256_t& TransactionHash);
			static String AsInstanceStride();
		};

		struct WitnessAddress final : Ledger::State
		{
			enum class Class : uint8_t
			{
				Witness = 0,
				Router,
				Custodian,
				Contribution
			};

			Algorithm::Pubkeyhash Owner = { 0 };
			Algorithm::Pubkeyhash Proposer = { 0 };
			Algorithm::AssetId Asset = 0;
			AddressMap Addresses;
			uint64_t AddressIndex = 0;
			uint8_t Purpose = 0;

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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::Pubkeyhash Owner);
			static String AsInstanceStride(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t AddressIndex);
		};

		struct WitnessTransaction final : Ledger::State
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
			int64_t AsWeight() const override;
			String AsAddress() const override;
			String AsStride() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static String AsInstanceAddress(const Algorithm::AssetId& Asset);
			static String AsInstanceStride(const std::string_view& TransactionId);
		};

		class Resolver
		{
		public:
			static Ledger::State* New(uint32_t Hash);
			static Ledger::State* Copy(const Ledger::State* Base);
		};
	}
}
#endif