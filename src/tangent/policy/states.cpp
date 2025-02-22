#include "states.h"
#include "../kernel/block.h"
#include "../kernel/script.h"
#include "../validator/service/nss.h"

namespace Tangent
{
	namespace States
	{
		AccountSequence::AccountSequence(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce), Sequence(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountSequence::AccountSequence(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader), Sequence(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountSequence::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountSequence*)PrevState;
			if (Prev != nullptr && Sequence != std::numeric_limits<uint64_t>::max())
			{
				if (!Sequence)
					Sequence = Prev->Sequence + 1;
				else if (Prev->Sequence > Sequence)
					return LayerException("sequence lower than " + ToString(Prev->Sequence));
				else if (Sequence - Prev->Sequence > 1)
					return LayerException("excessive sequence gap " + ToString(Sequence - Prev->Sequence));
			}
			else if (!Sequence)
				return LayerException("zero sequence not allowed");

			return Expectation::Met;
		}
		bool AccountSequence::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Sequence);
			return true;
		}
		bool AccountSequence::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Sequence))
				return false;

			return true;
		}
		bool AccountSequence::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> AccountSequence::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("sequence", Algorithm::Encoding::SerializeUint256(Sequence));
			return Data;
		}
		uint32_t AccountSequence::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountSequence::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String AccountSequence::AsIndex() const
		{
			return AsInstanceIndex(Owner);
		}
		uint32_t AccountSequence::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountSequence::AsInstanceTypename()
		{
			return "account_sequence";
		}
		String AccountSequence::AsInstanceIndex(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}

		AccountWork::AccountWork(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountWork::AccountWork(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountWork::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountWork*)PrevState;
			if (Prev != nullptr)
			{
				uint256_t GasInputChange = GasInput + Prev->GasInput;
				uint256_t GasOutputChange = GasOutput + Prev->GasOutput;
				GasInput = (GasInputChange >= GasInput ? GasInputChange : uint256_t::Max());
				GasOutput = (GasOutputChange >= GasOutput ? GasOutputChange : uint256_t::Max());
				if (!Flags || Prev->IsMatching(AccountFlags::Outlaw))
					Flags = Prev->Flags;
				if (Prev->IsMatching(AccountFlags::Founder))
					Flags |= (uint8_t)AccountFlags::Founder;		
				if (Penalty < Prev->Penalty)
					Penalty = Prev->Penalty;
			}
			else if (BlockNumber == 1)
				Flags |= (uint8_t)AccountFlags::Founder;
			
			if (!Flags || (IsMatching(AccountFlags::Online) && IsMatching(AccountFlags::Offline)) || (IsMatching(AccountFlags::Online) && IsMatching(AccountFlags::Outlaw)))
				return LayerException("invalid status");

			if (GasOutput > GasInput)
				GasOutput = GasInput;

			if (Penalty < BlockNumber)
				Penalty = 0;

			return Expectation::Met;
		}
		bool AccountWork::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(GasInput);
			Stream->WriteInteger(GasOutput);
			Stream->WriteInteger(Penalty);
			Stream->WriteInteger(Flags);
			return true;
		}
		bool AccountWork::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GasInput))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &GasOutput))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Penalty))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Flags))
				return false;

			return true;
		}
		bool AccountWork::IsEligible(const Ledger::BlockHeader* BlockHeader) const
		{
			return !GetGasWorkRequired(BlockHeader, GetGasUse());
		}
		bool AccountWork::IsMatching(AccountFlags Flag) const
		{
			return Flags & (uint8_t)Flag;
		}
		bool AccountWork::IsOnline() const
		{
			return BlockNumber > Penalty && IsMatching(AccountFlags::Online);
		}
		bool AccountWork::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		uint256_t AccountWork::GetGasUse() const
		{
			return GasInput - GasOutput;
		}
		uint64_t AccountWork::GetClosestProposalBlockNumber() const
		{
			return std::max(BlockNumber, Penalty) + 1;
		}
		UPtr<Schema> AccountWork::AsSchema() const
		{
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("gas_input", Algorithm::Encoding::SerializeUint256(GasInput));
			Data->Set("gas_output", Algorithm::Encoding::SerializeUint256(GasOutput));
			Data->Set("gas_use", Algorithm::Encoding::SerializeUint256(GetGasUse()));
			Data->Set("penalty", Algorithm::Encoding::SerializeUint256(Penalty));
			Data->Set("online", Var::Boolean(IsOnline()));

			auto* FlagsArray = Data->Set("flags", Var::Set::Array());
			if (IsMatching(AccountFlags::Offline))
				FlagsArray->Push(Var::String("offline"));
			if (IsMatching(AccountFlags::Online))
				FlagsArray->Push(Var::String("online"));
			if (IsMatching(AccountFlags::Founder))
				FlagsArray->Push(Var::String("founder"));
			if (IsMatching(AccountFlags::Outlaw))
				FlagsArray->Push(Var::String("outlaw"));
			return Data;
		}
		uint32_t AccountWork::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountWork::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t AccountWork::AsFactor() const
		{
			if (!IsOnline())
				return -1;

			auto GasUse = GetGasUse() / 100;
			return GasUse > std::numeric_limits<int64_t>::max() ? std::numeric_limits<int64_t>::max() : (int64_t)(uint64_t)GasUse;
		}
		String AccountWork::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String AccountWork::AsRow() const
		{
			return AsInstanceRow();
		}
		uint32_t AccountWork::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountWork::AsInstanceTypename()
		{
			return "account_work";
		}
		String AccountWork::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String AccountWork::AsInstanceRow()
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			return std::move(Stream.Data);
		}
		uint256_t AccountWork::GetGasWorkRequired(const Ledger::BlockHeader* BlockHeader, const uint256_t& GasUse)
		{
			auto& Config = Protocol::Now();
			auto TotalGasLimit = Ledger::BlockHeader::GetGasLimit();
			auto Requirement = BlockHeader ? BlockHeader->GetSlotGasTarget() : uint256_t(0);
			auto Utility = (BlockHeader ? TotalGasLimit.ToDecimal() / BlockHeader->GetSlotGasUse().ToDecimal() : 1);
			if (Utility.IsNaN())
				Utility = Decimal::Zero();

			auto Multiplier = Requirement.ToDecimal() * Utility * Config.Policy.AccountGasWorkRequired;
			Requirement = uint256_t(Multiplier.Truncate(0).ToString(), 10);
			return Requirement > GasUse ? Requirement - GasUse : uint256_t(0);
		}
		uint256_t AccountWork::GetAdjustedGasPaid(const uint256_t& GasUse, const uint256_t& GasPaid)
		{
			return GasPaid > GasUse ? GasPaid - GasUse : uint256_t(0);
		}
		uint256_t AccountWork::GetAdjustedGasOutput(const uint256_t& GasUse, const uint256_t& GasPaid)
		{
			return GasPaid < GasUse ? GasUse - GasPaid : uint256_t(0);
		}

		AccountObserver::AccountObserver(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountObserver::AccountObserver(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountObserver::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountObserver*)PrevState;
			if (!Prev && !(Algorithm::Asset::IsValid(Asset) && Algorithm::Asset::TokenOf(Asset).empty()))
				return LayerException("invalid asset");

			return Expectation::Met;
		}
		bool AccountObserver::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Asset);
			Stream->WriteBoolean(Observing);
			return true;
		}
		bool AccountObserver::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadBoolean(Stream.ReadType(), &Observing))
				return false;

			return true;
		}
		bool AccountObserver::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> AccountObserver::AsSchema() const
		{
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("observing", Var::Boolean(Observing));
			return Data;
		}
		uint32_t AccountObserver::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountObserver::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t AccountObserver::AsFactor() const
		{
			return Observing ? 1 : -1;
		}
		String AccountObserver::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String AccountObserver::AsRow() const
		{
			return AsInstanceRow(Asset);
		}
		uint32_t AccountObserver::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountObserver::AsInstanceTypename()
		{
			return "account_observer";
		}
		String AccountObserver::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String AccountObserver::AsInstanceRow(const Algorithm::AssetId& Asset)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Asset);
			return std::move(Stream.Data);
		}

		AccountProgram::AccountProgram(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountProgram::AccountProgram(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountProgram::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			return Expectation::Met;
		}
		bool AccountProgram::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteString(Hashcode);
			return true;
		}
		bool AccountProgram::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Hashcode))
				return false;

			return true;
		}
		bool AccountProgram::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> AccountProgram::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("hashcode", Var::String(Format::Util::Encode0xHex(Hashcode)));
			return Data;
		}
		uint32_t AccountProgram::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountProgram::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String AccountProgram::AsIndex() const
		{
			return AsInstanceIndex(Owner);
		}
		uint32_t AccountProgram::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountProgram::AsInstanceTypename()
		{
			return "account_program";
		}
		String AccountProgram::AsInstanceIndex(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}

		AccountStorage::AccountStorage(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountStorage::AccountStorage(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountStorage::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			if (Location.size() > std::numeric_limits<uint8_t>::max())
				return LayerException("invalid state location");

			return Expectation::Met;
		}
		bool AccountStorage::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteString(Location);
			Stream->WriteString(Storage);
			return true;
		}
		bool AccountStorage::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Location))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Storage))
				return false;

			return true;
		}
		bool AccountStorage::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> AccountStorage::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("location", Var::String(Format::Util::Encode0xHex(Location)));
			Data->Set("storage", Var::String(Format::Util::Encode0xHex(Storage)));
			return Data;
		}
		uint32_t AccountStorage::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountStorage::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String AccountStorage::AsIndex() const
		{
			return AsInstanceIndex(Owner, Location);
		}
		uint32_t AccountStorage::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountStorage::AsInstanceTypename()
		{
			return "account_storage";
		}
		String AccountStorage::AsInstanceIndex(const Algorithm::Pubkeyhash Owner, const std::string_view& Location)
		{
			auto Data = Format::Util::IsHexEncoding(Location) ? Codec::HexDecode(Location) : String(Location);
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			Stream.WriteTypeless((char*)Data.data(), (uint8_t)Data.size());
			return std::move(Stream.Data);
		}

		AccountReward::AccountReward(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountReward::AccountReward(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountReward::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			if (IncomingAbsoluteFee.IsNaN() || IncomingAbsoluteFee.IsNegative())
				return LayerException("invalid incoming absolute fee");

			if (IncomingRelativeFee.IsNaN() || IncomingRelativeFee.IsNegative() || IncomingRelativeFee > 1.0)
				return LayerException("invalid incoming relative fee");

			if (OutgoingAbsoluteFee.IsNaN() || OutgoingAbsoluteFee.IsNegative())
				return LayerException("invalid outgoing absolute fee");

			if (OutgoingRelativeFee.IsNaN() || OutgoingRelativeFee.IsNegative() || OutgoingRelativeFee > 1.0)
				return LayerException("invalid outgoing relative fee");

			auto* Prev = (AccountReward*)PrevState;
			if (!Prev)
			{
				if (!Algorithm::Asset::IsValid(Asset) || !Algorithm::Asset::TokenOf(Asset).empty())
					return LayerException("invalid asset");

				return Expectation::Met;
			}

			Decimal Threshold = 1.0 - Protocol::Now().Policy.AccountRewardMaxIncrease;
			if (IncomingAbsoluteFee.IsPositive() && Prev->IncomingAbsoluteFee / Decimal(IncomingAbsoluteFee).Truncate(Protocol::Now().Message.Precision) < Threshold)
				return LayerException("incoming absolute fee increase overflows step threshold");

			if (IncomingRelativeFee.IsPositive() && Prev->IncomingRelativeFee / Decimal(IncomingRelativeFee).Truncate(Protocol::Now().Message.Precision) < Threshold)
				return LayerException("incoming absolute fee relative overflows step threshold");

			if (OutgoingAbsoluteFee.IsPositive() && Prev->OutgoingAbsoluteFee / Decimal(OutgoingAbsoluteFee).Truncate(Protocol::Now().Message.Precision) < Threshold)
				return LayerException("outgoing absolute fee increase overflows step threshold");

			if (OutgoingRelativeFee.IsPositive() && Prev->OutgoingRelativeFee / Decimal(OutgoingRelativeFee).Truncate(Protocol::Now().Message.Precision) < Threshold)
				return LayerException("outgoing absolute fee relative overflows step threshold");

			return Expectation::Met;
		}
		bool AccountReward::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Asset);
			Stream->WriteDecimal(IncomingAbsoluteFee);
			Stream->WriteDecimal(IncomingRelativeFee);
			Stream->WriteDecimal(OutgoingAbsoluteFee);
			Stream->WriteDecimal(OutgoingRelativeFee);
			return true;
		}
		bool AccountReward::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

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
		bool AccountReward::HasIncomingFee() const
		{
			return IncomingAbsoluteFee.IsPositive() || IncomingRelativeFee.IsPositive();
		}
		bool AccountReward::HasOutgoingFee() const
		{
			return OutgoingAbsoluteFee.IsPositive() || OutgoingRelativeFee.IsPositive();
		}
		bool AccountReward::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		Decimal AccountReward::CalculateIncomingFee(const Decimal& Value) const
		{
			auto RelativeFee = Value * Decimal(IncomingRelativeFee).Truncate(Protocol::Now().Message.Precision);
			auto LeftoverValue = Value - RelativeFee;
			auto AbsoluteFee = std::min(LeftoverValue, IncomingAbsoluteFee);
			return RelativeFee + AbsoluteFee;
		}
		Decimal AccountReward::CalculateOutgoingFee(const Decimal& Value) const
		{
			auto RelativeFee = Value * Decimal(OutgoingRelativeFee).Truncate(Protocol::Now().Message.Precision);
			auto LeftoverValue = Value - RelativeFee;
			auto AbsoluteFee = std::min(LeftoverValue, OutgoingAbsoluteFee);
			return RelativeFee + AbsoluteFee;
		}
		UPtr<Schema> AccountReward::AsSchema() const
		{
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("incoming_absolute_fee", Var::Decimal(IncomingAbsoluteFee));
			Data->Set("incoming_relative_fee", Var::Decimal(IncomingRelativeFee));
			Data->Set("outgoing_absolute_fee", Var::Decimal(OutgoingAbsoluteFee));
			Data->Set("outgoing_relative_fee", Var::Decimal(OutgoingRelativeFee));
			return Data;
		}
		uint32_t AccountReward::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountReward::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t AccountReward::AsFactor() const
		{
			Decimal AbsoluteFee = IncomingAbsoluteFee + OutgoingAbsoluteFee;
			Decimal RelativeFee = IncomingRelativeFee + OutgoingRelativeFee + 1.0;
			AbsoluteFee *= RelativeFee;
			AbsoluteFee *= Protocol::Now().Policy.WeightMultiplier;
			return std::numeric_limits<int64_t>::max() - AbsoluteFee.ToInt64();
		}
		String AccountReward::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String AccountReward::AsRow() const
		{
			return AsInstanceRow(Asset);
		}
		uint32_t AccountReward::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountReward::AsInstanceTypename()
		{
			return "account_reward";
		}
		String AccountReward::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String AccountReward::AsInstanceRow(const Algorithm::AssetId& Asset)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Asset);
			return std::move(Stream.Data);
		}

		AccountDerivation::AccountDerivation(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce), Asset(0), MaxAddressIndex(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountDerivation::AccountDerivation(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader), Asset(0), MaxAddressIndex(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountDerivation::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountDerivation*)PrevState;
			if (Prev && Prev->MaxAddressIndex >= MaxAddressIndex)
				return LayerException("invalid max address index");
			else if (!Prev && !Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");

			return Expectation::Met;
		}
		bool AccountDerivation::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Asset);
			Stream->WriteInteger(MaxAddressIndex);
			return true;
		}
		bool AccountDerivation::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &MaxAddressIndex))
				return false;

			return true;
		}
		bool AccountDerivation::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> AccountDerivation::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("max_address_index", Algorithm::Encoding::SerializeUint256(MaxAddressIndex));
			return Data;
		}
		uint32_t AccountDerivation::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountDerivation::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String AccountDerivation::AsIndex() const
		{
			return AsInstanceIndex(Owner, Asset);
		}
		uint32_t AccountDerivation::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountDerivation::AsInstanceTypename()
		{
			return "account_derivation";
		}
		String AccountDerivation::AsInstanceIndex(const Algorithm::Pubkeyhash Owner, const Algorithm::AssetId& Asset)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			Stream.WriteTypeless(Asset);
			return std::move(Stream.Data);
		}

		AccountBalance::AccountBalance(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce), Asset(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountBalance::AccountBalance(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader), Asset(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountBalance::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountBalance*)PrevState;
			if (Prev)
			{
				Supply += Prev->Supply;
				Reserve += Prev->Reserve;
			}
			else if (!Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");
			
			if (Supply.IsNaN() || Supply.IsNegative())
				return LayerException("ran out of supply balance");

			if (Reserve.IsNaN() || Reserve.IsNegative())
				return LayerException("ran out of reserve balance");

			if (Supply < Reserve)
				return LayerException("ran out of balance");

			return Expectation::Met;
		}
		bool AccountBalance::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Asset);
			Stream->WriteDecimal(Supply);
			Stream->WriteDecimal(Reserve);
			return true;
		}
		bool AccountBalance::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Supply))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Reserve))
				return false;

			return true;
		}
		bool AccountBalance::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		Decimal AccountBalance::GetBalance() const
		{
			if (Supply.IsNaN() || Supply.IsNegative() || Reserve.IsNaN() || Reserve.IsNegative())
				return Decimal::NaN();

			auto Balance = Supply - Reserve;
			if (Balance.IsNegative())
				return Decimal::NaN();

			return Balance;
		}
		UPtr<Schema> AccountBalance::AsSchema() const
		{
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("supply", Var::Decimal(Supply));
			Data->Set("reserve", Var::Decimal(Reserve));
			Data->Set("balance", Var::Decimal(GetBalance()));
			return Data;
		}
		uint32_t AccountBalance::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountBalance::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t AccountBalance::AsFactor() const
		{
			auto Balance = GetBalance();
			Balance *= Protocol::Now().Policy.WeightMultiplier;
			return Balance.ToUInt64();
		}
		String AccountBalance::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String AccountBalance::AsRow() const
		{
			return AsInstanceRow(Asset);
		}
		uint32_t AccountBalance::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountBalance::AsInstanceTypename()
		{
			return "account_balance";
		}
		String AccountBalance::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String AccountBalance::AsInstanceRow(const Algorithm::AssetId& Asset)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Asset);
			return std::move(Stream.Data);
		}

		AccountDepository::AccountDepository(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce), Asset(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		AccountDepository::AccountDepository(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader), Asset(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> AccountDepository::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (AccountDepository*)PrevState;
			if (!Prev && !Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");

			for (auto It = Contributions.cbegin(); It != Contributions.cend();)
			{
				if (It->second.IsNaN() || It->second.IsNegative())
					return LayerException("invalid contribution");

				if (It->second.IsZero())
					Contributions.erase(It++);
				else
					++It;
			}

			for (auto It = Reservations.cbegin(); It != Reservations.cend();)
			{
				if (It->second.IsNaN() || It->second.IsNegative())
					return LayerException("invalid reservation");

				if (It->second.IsZero())
					Reservations.erase(It++);
				else
					++It;
			}

			for (auto& Item : Transactions)
			{
				if (!Item)
					return LayerException("invalid transaction hash");
			}

			if (Custody.IsNegative())
				return LayerException("invalid custody value");

			return Expectation::Met;
		}
		bool AccountDepository::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteInteger(Asset);
			Stream->WriteDecimal(Custody);
			Stream->WriteInteger((uint32_t)Contributions.size());
			for (auto& Item : Contributions)
			{
				Stream->WriteString(Item.first);
				Stream->WriteDecimal(Item.second);
			}
			Stream->WriteInteger((uint32_t)Reservations.size());
			for (auto& Item : Reservations)
			{
				Stream->WriteString(Item.first);
				Stream->WriteDecimal(Item.second);
			}
			Stream->WriteInteger((uint32_t)Transactions.size());
			for (auto& Item : Transactions)
				Stream->WriteInteger(Item);
			return true;
		}
		bool AccountDepository::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadDecimal(Stream.ReadType(), &Custody))
				return false;

			uint32_t ContributionsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &ContributionsSize))
				return false;

			Contributions.clear();
			for (uint32_t i = 0; i < ContributionsSize; i++)
			{
				String Address;
				if (!Stream.ReadString(Stream.ReadType(), &Address))
					return false;

				auto& Contribution = Contributions[Address];
				if (!Stream.ReadDecimal(Stream.ReadType(), &Contribution))
					return false;
			}

			uint32_t ReservationsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &ReservationsSize))
				return false;

			Reservations.clear();
			for (uint32_t i = 0; i < ReservationsSize; i++)
			{
				String Owner;
				if (!Stream.ReadString(Stream.ReadType(), &Owner))
					return false;

				auto& Reservation = Reservations[Owner];
				if (!Stream.ReadDecimal(Stream.ReadType(), &Reservation))
					return false;
			}

			uint32_t TransactionsSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &TransactionsSize))
				return false;

			Transactions.clear();
			for (uint32_t i = 0; i < TransactionsSize; i++)
			{
				uint256_t TransactionHash;
				if (!Stream.ReadInteger(Stream.ReadType(), &TransactionHash))
					return false;

				Transactions.insert(TransactionHash);
			}

			return true;
		}
		bool AccountDepository::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		Decimal AccountDepository::GetReservation() const
		{
			Decimal Value = Decimal::Zero();
			for (auto& Item : Reservations)
				Value += Item.second;
			return Value;
		}
		Decimal AccountDepository::GetContribution(const std::string_view& Address) const
		{
			auto Contribution = Contributions.find(String(Address));
			return Contribution != Contributions.end() ? Contribution->second : Decimal::Zero();
		}
		Decimal AccountDepository::GetContribution(const OrderedSet<String>& Addresses) const
		{
			Decimal Value = Decimal::Zero();
			for (auto& Address : Addresses)
				Value += GetContribution(Address);
			return Value;
		}
		Decimal AccountDepository::GetContribution() const
		{
			Decimal Value = Decimal::Zero();
			for (auto& Item : Contributions)
				Value += Item.second;
			return Value;
		}
		Decimal AccountDepository::GetCoverage(uint8_t Flags) const
		{
			if (!Custody.IsPositive())
				return Decimal::Zero();

			auto Contribution = GetContribution();
			if (!(Flags & (uint8_t)AccountFlags::Founder))
				Contribution -= Custody * Decimal(Protocol::Now().Policy.AccountContributionRequired).Truncate(Protocol::Now().Message.Precision);
			if (Contribution.IsNaN())
				Contribution = Decimal::Zero();
			if (Flags & (uint8_t)AccountFlags::Outlaw)
			{
				if (Contribution.IsPositive())
					Contribution = -Contribution;
				else if (Contribution.IsZero())
					Contribution = Decimal(-1);
			}

			return Contribution;
		}
		UPtr<Schema> AccountDepository::AsSchema() const
		{
			auto Reservation = GetReservation();
			auto Contribution = GetContribution();
			auto Coverage = GetCoverage(0);
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("custody", Custody.IsNaN() ? Var::Null() : Var::Decimal(Custody));
			Data->Set("contribution", Contribution.IsNaN() ? Var::Null() : Var::Decimal(Contribution));
			Data->Set("reservation", Reservation.IsNaN() ? Var::Null() : Var::Decimal(Reservation));
			Data->Set("coverage", Coverage.IsNaN() ? Var::Null() : Var::Decimal(Coverage));
			if (!Contributions.empty())
			{
				auto* ContributionsData = Data->Set("contributions", Var::Set::Array());
				for (auto& Item : Contributions)
				{
					auto* ContributionData = ContributionsData->Push(Var::Set::Object());
					ContributionData->Set("address", Var::String(Item.first));
					ContributionData->Set("value", Var::Decimal(Item.second));
				}
			}
			if (!Reservations.empty())
			{
				auto* ReservationsData = Data->Set("reservations", Var::Set::Array());
				for (auto& Item : Reservations)
				{
					Algorithm::Pubkeyhash Owner; String Address;
					memcpy(Owner, Item.first.data(), std::min(sizeof(Owner), Item.first.size()));
					Algorithm::Signing::EncodeAddress(Owner, Address);

					auto* ReservationData = ReservationsData->Push(Var::Set::Object());
					ReservationData->Set("owner", Var::String(Address));
					ReservationData->Set("value", Var::Decimal(Item.second));
				}
			}
			if (!Transactions.empty())
			{
				auto* TransactionsData = Data->Set("transactions", Var::Set::Array());
				for (auto& Item : Transactions)
					TransactionsData->Push(Algorithm::Encoding::SerializeUint256(Item));
			}
			return Data;
		}
		uint32_t AccountDepository::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view AccountDepository::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t AccountDepository::AsFactor() const
		{
			Decimal Coverage = GetCoverage(0) * Protocol::Now().Policy.WeightMultiplier;
			return Coverage.ToInt64();
		}
		String AccountDepository::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String AccountDepository::AsRow() const
		{
			return AsInstanceRow(Asset);
		}
		uint32_t AccountDepository::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view AccountDepository::AsInstanceTypename()
		{
			return "account_depository";
		}
		String AccountDepository::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String AccountDepository::AsInstanceRow(const Algorithm::AssetId& Asset)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Asset);
			return std::move(Stream.Data);
		}

		WitnessProgram::WitnessProgram(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce)
		{
		}
		WitnessProgram::WitnessProgram(const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader)
		{
		}
		ExpectsLR<void> WitnessProgram::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (PrevState != nullptr)
				return LayerException("program already exists");

			if (Storage.empty())
				return LayerException("program storage not valid");

			auto Code = AsCode();
			if (!Code)
				return LayerException("program storage not valid: " + Code.Error().message());

			Hashcode = Ledger::ScriptHost::Get()->Hashcode(*Code);
			return Expectation::Met;
		}
		bool WitnessProgram::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteString(Hashcode);
			Stream->WriteString(Storage);
			return true;
		}
		bool WitnessProgram::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadString(Stream.ReadType(), &Hashcode))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &Storage))
				return false;

			return true;
		}
		UPtr<Schema> WitnessProgram::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("hashcode", Var::String(Format::Util::Encode0xHex(Hashcode)));
			Data->Set("storage", Var::String(Format::Util::Encode0xHex(Storage)));
			return Data;
		}
		uint32_t WitnessProgram::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view WitnessProgram::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String WitnessProgram::AsIndex() const
		{
			return AsInstanceIndex(Hashcode);
		}
		ExpectsLR<String> WitnessProgram::AsCode() const
		{
			return Ledger::ScriptHost::Get()->Unpack(Storage);
		}
		uint32_t WitnessProgram::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view WitnessProgram::AsInstanceTypename()
		{
			return "witness_program";
		}
		String WitnessProgram::AsInstanceIndex(const std::string_view& Hashcode)
		{
			auto Data = Format::Util::IsHexEncoding(Hashcode) ? Codec::HexDecode(Hashcode) : String(Hashcode);
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Data.data(), (uint8_t)Data.size());
			return std::move(Stream.Data);
		}

		WitnessEvent::WitnessEvent(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce)
		{
		}
		WitnessEvent::WitnessEvent(const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader)
		{
		}
		ExpectsLR<void> WitnessEvent::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (!ParentTransactionHash)
				return LayerException("invalid parent transaction hash");

			if (!ChildTransactionHash)
				return LayerException("invalid child transaction hash");

			if (PrevState != nullptr)
				return LayerException("event already finalized");

			return Expectation::Met;
		}
		bool WitnessEvent::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(ParentTransactionHash);
			Stream->WriteInteger(ChildTransactionHash);
			return true;
		}
		bool WitnessEvent::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &ParentTransactionHash))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &ChildTransactionHash))
				return false;

			return true;
		}
		UPtr<Schema> WitnessEvent::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("parent_transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ParentTransactionHash)));
			Data->Set("child_transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(ChildTransactionHash)));
			return Data;
		}
		uint32_t WitnessEvent::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view WitnessEvent::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String WitnessEvent::AsIndex() const
		{
			return AsInstanceIndex(ParentTransactionHash);
		}
		uint32_t WitnessEvent::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view WitnessEvent::AsInstanceTypename()
		{
			return "witness_event";
		}
		String WitnessEvent::AsInstanceIndex(const uint256_t& TransactionHash)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(TransactionHash);
			return std::move(Stream.Data);
		}

		WitnessAddress::WitnessAddress(const Algorithm::Pubkeyhash NewOwner, uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Multiform(NewBlockNumber, NewBlockNonce), AddressIndex(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		WitnessAddress::WitnessAddress(const Algorithm::Pubkeyhash NewOwner, const Ledger::BlockHeader* NewBlockHeader) : Ledger::Multiform(NewBlockHeader), AddressIndex(0)
		{
			if (NewOwner)
				memcpy(Owner, NewOwner, sizeof(Owner));
		}
		ExpectsLR<void> WitnessAddress::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			if (IsOwnerNull())
				return LayerException("invalid state owner");

			auto* Prev = (WitnessAddress*)PrevState;
			if (!Prev && !Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");

			if (Addresses.empty())
				return LayerException("invalid address");

			for (auto& Address : Addresses)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.second))
					return LayerException("invalid address");
			}

			return Expectation::Met;
		}
		bool WitnessAddress::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Algorithm::Pubkeyhash Null = { 0 };
			Stream->WriteString(std::string_view((char*)Owner, memcmp(Owner, Null, sizeof(Null)) == 0 ? 0 : sizeof(Owner)));
			Stream->WriteString(std::string_view((char*)Proposer, memcmp(Proposer, Null, sizeof(Null)) == 0 ? 0 : sizeof(Proposer)));
			Stream->WriteInteger((uint8_t)Purpose);
			Stream->WriteInteger(Asset);
			Stream->WriteInteger(AddressIndex);
			Stream->WriteInteger((uint8_t)Addresses.size());
			for (auto& Address : Addresses)
			{
				Stream->WriteInteger(Address.first);
				Stream->WriteString(Address.second);
			}
			return true;
		}
		bool WitnessAddress::LoadPayload(Format::Stream& Stream)
		{
			String OwnerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &OwnerAssembly) || !Algorithm::Encoding::DecodeUintBlob(OwnerAssembly, Owner, sizeof(Owner)))
				return false;

			String ProposerAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &ProposerAssembly) || !Algorithm::Encoding::DecodeUintBlob(ProposerAssembly, Proposer, sizeof(Proposer)))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), (uint8_t*)&Purpose))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadInteger(Stream.ReadType(), &AddressIndex))
				return false;

			uint8_t AddressesSize;
			if (!Stream.ReadInteger(Stream.ReadType(), &AddressesSize))
				return false;

			Addresses.clear();
			for (uint8_t i = 0; i < AddressesSize; i++)
			{
				uint8_t Version;
				if (!Stream.ReadInteger(Stream.ReadType(), &Version))
					return false;

				String Address;
				if (!Stream.ReadString(Stream.ReadType(), &Address))
					return false;

				Addresses[Version] = std::move(Address);
			}

			return true;
		}
		void WitnessAddress::SetProposer(const Algorithm::Pubkeyhash NewValue)
		{
			if (!NewValue)
			{
				Algorithm::Pubkeyhash Null = { 0 };
				memcpy(Proposer, Null, sizeof(Algorithm::Pubkeyhash));
			}
			else
				memcpy(Proposer, NewValue, sizeof(Algorithm::Pubkeyhash));
		}
		bool WitnessAddress::IsWitnessAddress() const
		{
			return Purpose == AddressType::Witness && memcmp(Proposer, Owner, sizeof(Owner)) == 0;
		}
		bool WitnessAddress::IsRouterAddress() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return Purpose == AddressType::Router && memcmp(Proposer, Null, sizeof(Null)) == 0;
		}
		bool WitnessAddress::IsCustodianAddress() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return Purpose == AddressType::Custodian && memcmp(Proposer, Null, sizeof(Null)) != 0;
		}
		bool WitnessAddress::IsContributionAddress() const
		{
			return Purpose == AddressType::Contribution && memcmp(Proposer, Owner, sizeof(Owner)) == 0;
		}
		bool WitnessAddress::IsOwnerNull() const
		{
			Algorithm::Pubkeyhash Null = { 0 };
			return !memcmp(Owner, Null, sizeof(Null));
		}
		UPtr<Schema> WitnessAddress::AsSchema() const
		{
			Schema* Data = Ledger::Multiform::AsSchema().Reset();
			Data->Set("owner", Algorithm::Signing::SerializeAddress(Owner));
			Data->Set("proposer", Algorithm::Signing::SerializeAddress(Proposer));
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			auto* AddressesData = Data->Set("addresses", Var::Set::Array());
			for (auto& Address : Addresses)
				AddressesData->Push(Var::String(Address.second));
			Data->Set("address_index", Algorithm::Encoding::SerializeUint256(AddressIndex));
			switch (Purpose)
			{
				case AddressType::Witness:
					Data->Set("purpose", Var::String("witness"));
					break;
				case AddressType::Router:
					Data->Set("purpose", Var::String("router"));
					break;
				case AddressType::Custodian:
					Data->Set("purpose", Var::String("custodian"));
					break;
				case AddressType::Contribution:
					Data->Set("purpose", Var::String("contribution"));
					break;
				default:
					Data->Set("purpose", Var::String("bad"));
					break;
			}
			return Data;
		}
		uint32_t WitnessAddress::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view WitnessAddress::AsTypename() const
		{
			return AsInstanceTypename();
		}
		int64_t WitnessAddress::AsFactor() const
		{
			return (int64_t)Purpose;
		}
		String WitnessAddress::AsColumn() const
		{
			return AsInstanceColumn(Owner);
		}
		String WitnessAddress::AsRow() const
		{
			auto* Chain = NSS::ServerNode::Get()->GetChainparams(Asset);
			return AsInstanceRow(Asset, Addresses.empty() ? std::string_view() : Addresses.begin()->second, Chain && Chain->Routing == Mediator::RoutingPolicy::Memo ? AddressIndex : Protocol::Now().Account.RootAddressIndex);
		}
		uint32_t WitnessAddress::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view WitnessAddress::AsInstanceTypename()
		{
			return "witness_address";
		}
		String WitnessAddress::AsInstanceColumn(const Algorithm::Pubkeyhash Owner)
		{
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless((char*)Owner, (uint8_t)sizeof(Algorithm::Pubkeyhash));
			return std::move(Stream.Data);
		}
		String WitnessAddress::AsInstanceRow(const Algorithm::AssetId& Asset, const std::string_view& Address, uint64_t MaxAddressIndex)
		{
			auto Location = NSS::ServerNode::Get()->NewPublicKeyHash(Asset, Address).Or(String(Address));
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Location.data(), (uint8_t)Location.size());
			Stream.WriteTypeless(Asset);
			Stream.WriteTypeless(MaxAddressIndex);
			return std::move(Stream.Data);
		}

		WitnessTransaction::WitnessTransaction(uint64_t NewBlockNumber, uint64_t NewBlockNonce) : Ledger::Uniform(NewBlockNumber, NewBlockNonce)
		{
		}
		WitnessTransaction::WitnessTransaction(const Ledger::BlockHeader* NewBlockHeader) : Ledger::Uniform(NewBlockHeader)
		{
		}
		ExpectsLR<void> WitnessTransaction::Transition(const Ledger::TransactionContext* Context, const Ledger::State* PrevState)
		{
			auto* Prev = (WitnessAddress*)PrevState;
			if (!Prev && !Algorithm::Asset::IsValid(Asset))
				return LayerException("invalid asset");

			if (TransactionId.empty())
				return LayerException("invalid transaction id");

			return Expectation::Met;
		}
		bool WitnessTransaction::StorePayload(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Asset);
			Stream->WriteString(TransactionId);
			return true;
		}
		bool WitnessTransaction::LoadPayload(Format::Stream& Stream)
		{
			if (!Stream.ReadInteger(Stream.ReadType(), &Asset))
				return false;

			if (!Stream.ReadString(Stream.ReadType(), &TransactionId))
				return false;

			return true;
		}
		UPtr<Schema> WitnessTransaction::AsSchema() const
		{
			Schema* Data = Ledger::Uniform::AsSchema().Reset();
			Data->Set("asset", Algorithm::Asset::Serialize(Asset));
			Data->Set("transaction_id", Var::String(TransactionId));
			return Data;
		}
		uint32_t WitnessTransaction::AsType() const
		{
			return AsInstanceType();
		}
		std::string_view WitnessTransaction::AsTypename() const
		{
			return AsInstanceTypename();
		}
		String WitnessTransaction::AsIndex() const
		{
			return AsInstanceIndex(Asset, TransactionId);
		}
		uint32_t WitnessTransaction::AsInstanceType()
		{
			static uint32_t Hash = Algorithm::Encoding::TypeOf(AsInstanceTypename());
			return Hash;
		}
		std::string_view WitnessTransaction::AsInstanceTypename()
		{
			return "witness_transaction";
		}
		String WitnessTransaction::AsInstanceIndex(const Algorithm::AssetId& Asset, const std::string_view& TransactionId)
		{
			auto Id = Format::Util::IsHexEncoding(TransactionId) ? Codec::HexDecode(TransactionId) : String(TransactionId);
			Format::Stream Stream;
			Stream.WriteTypeless(AsInstanceType());
			Stream.WriteTypeless(Asset);
			Stream.WriteTypeless(Id.data(), (uint8_t)Id.size());
			return std::move(Stream.Data);
		}

		Ledger::State* Resolver::New(uint32_t Hash)
		{
			if (Hash == AccountSequence::AsInstanceType())
				return Memory::New<AccountSequence>(nullptr, nullptr);
			else if (Hash == AccountWork::AsInstanceType())
				return Memory::New<AccountWork>(nullptr, nullptr);
			else if (Hash == AccountObserver::AsInstanceType())
				return Memory::New<AccountObserver>(nullptr, nullptr);
			else if (Hash == AccountProgram::AsInstanceType())
				return Memory::New<AccountProgram>(nullptr, nullptr);
			else if (Hash == AccountStorage::AsInstanceType())
				return Memory::New<AccountStorage>(nullptr, nullptr);
			else if (Hash == AccountReward::AsInstanceType())
				return Memory::New<AccountReward>(nullptr, nullptr);
			else if (Hash == AccountDerivation::AsInstanceType())
				return Memory::New<AccountDerivation>(nullptr, nullptr);
			else if (Hash == AccountBalance::AsInstanceType())
				return Memory::New<AccountBalance>(nullptr, nullptr);
			else if (Hash == AccountDepository::AsInstanceType())
				return Memory::New<AccountDepository>(nullptr, nullptr);
			else if (Hash == WitnessProgram::AsInstanceType())
				return Memory::New<WitnessProgram>(nullptr);
			else if (Hash == WitnessEvent::AsInstanceType())
				return Memory::New<WitnessEvent>(nullptr);
			else if (Hash == WitnessAddress::AsInstanceType())
				return Memory::New<WitnessAddress>(nullptr, nullptr);
			else if (Hash == WitnessTransaction::AsInstanceType())
				return Memory::New<WitnessTransaction>(nullptr);
			return nullptr;
		}
		Ledger::State* Resolver::Copy(const Ledger::State* Base)
		{
			uint32_t Hash = Base->AsType();
			if (Hash == AccountSequence::AsInstanceType())
				return Memory::New<AccountSequence>(*(const AccountSequence*)Base);
			else if (Hash == AccountWork::AsInstanceType())
				return Memory::New<AccountWork>(*(const AccountWork*)Base);
			else if (Hash == AccountObserver::AsInstanceType())
				return Memory::New<AccountObserver>(*(const AccountObserver*)Base);
			else if (Hash == AccountProgram::AsInstanceType())
				return Memory::New<AccountProgram>(*(const AccountProgram*)Base);
			else if (Hash == AccountStorage::AsInstanceType())
				return Memory::New<AccountStorage>(*(const AccountStorage*)Base);
			else if (Hash == AccountReward::AsInstanceType())
				return Memory::New<AccountReward>(*(const AccountReward*)Base);
			else if (Hash == AccountDerivation::AsInstanceType())
				return Memory::New<AccountDerivation>(*(const AccountDerivation*)Base);
			else if (Hash == AccountBalance::AsInstanceType())
				return Memory::New<AccountBalance>(*(const AccountBalance*)Base);
			else if (Hash == AccountDepository::AsInstanceType())
				return Memory::New<AccountDepository>(*(const AccountDepository*)Base);
			else if (Hash == WitnessProgram::AsInstanceType())
				return Memory::New<WitnessProgram>(*(const WitnessProgram*)Base);
			else if (Hash == WitnessEvent::AsInstanceType())
				return Memory::New<WitnessEvent>(*(const WitnessEvent*)Base);
			else if (Hash == WitnessAddress::AsInstanceType())
				return Memory::New<WitnessAddress>(*(const WitnessAddress*)Base);
			else if (Hash == WitnessTransaction::AsInstanceType())
				return Memory::New<WitnessTransaction>(*(const WitnessTransaction*)Base);
			return nullptr;
		}
		UnorderedSet<uint32_t> Resolver::GetHashes()
		{
			UnorderedSet<uint32_t> Hashes;
			Hashes.insert(AccountSequence::AsInstanceType());
			Hashes.insert(AccountWork::AsInstanceType());
			Hashes.insert(AccountObserver::AsInstanceType());
			Hashes.insert(AccountProgram::AsInstanceType());
			Hashes.insert(AccountStorage::AsInstanceType());
			Hashes.insert(AccountReward::AsInstanceType());
			Hashes.insert(AccountDerivation::AsInstanceType());
			Hashes.insert(AccountBalance::AsInstanceType());
			Hashes.insert(AccountDepository::AsInstanceType());
			Hashes.insert(WitnessProgram::AsInstanceType());
			Hashes.insert(WitnessEvent::AsInstanceType());
			Hashes.insert(WitnessAddress::AsInstanceType());
			Hashes.insert(WitnessTransaction::AsInstanceType());
			return Hashes;
		}
	}
}
