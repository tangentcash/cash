#include "mempoolstate.h"
#include "../policy/transactions.h"
#undef NULL

namespace Tangent
{
	namespace Storages
	{
		static void FinalizeChecksum(Messages::Authentic& Message, const Variant& Column)
		{
			if (Column.Size() == sizeof(uint256_t))
				Algorithm::Encoding::EncodeUint256(Column.GetBinary(), Message.Checksum);
		}
		static String AddressToMessage(const SocketAddress& Address)
		{
			Format::Stream Message;
			Message.WriteString(Address.GetIpAddress().Or("[bad_address]"));
			Message.WriteInteger(Address.GetIpPort().Or(0));
			return Message.Data;
		}
		static Option<SocketAddress> MessageToAddress(const std::string_view& Data)
		{
			Format::Stream Message(Data);
			String IpAddress;
			if (!Message.ReadString(Message.ReadType(), &IpAddress))
				return Optional::None;

			uint16_t IpPort;
			if (!Message.ReadInteger(Message.ReadType(), &IpPort))
				return Optional::None;

			SocketAddress Address(IpAddress, IpPort);
			if (!Address.IsValid())
				return Optional::None;

			return Address;
		}

		static thread_local Mempoolstate* LatestMempoolstate = nullptr;
		Mempoolstate::Mempoolstate(const std::string_view& NewLabel) noexcept : Label(NewLabel), Borrows(false)
		{
			if (LatestMempoolstate != nullptr)
			{
				Storage = *LatestMempoolstate->Storage;
				Borrows = !!Storage;
			}
			if (!Borrows)
			{
				StorageOf("mempoolstate");
				if (Storage)
					LatestMempoolstate = this;
			}
		}
		Mempoolstate::~Mempoolstate() noexcept
		{
			if (Borrows)
				Storage.Reset();
			if (LatestMempoolstate == this)
				LatestMempoolstate = nullptr;
		}
		ExpectsLR<void> Mempoolstate::ApplyTrialAddress(const SocketAddress& Address)
		{
			if (!Address.IsValid())
				return ExpectsLR<void>(LayerException("invalid ip address"));

			if (GetValidatorByAddress(Address))
				return ExpectsLR<void>(LayerException("ip address and port found"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(AddressToMessage(Address)));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR IGNORE INTO seeds (address) VALUES (?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::ApplyValidator(const Ledger::Validator& Value, Option<Ledger::Wallet>&& Wallet)
		{
			Format::Stream EdgeMessage;
			if (!Value.Store(&EdgeMessage))
				return ExpectsLR<void>(LayerException("validator serialization error"));

			Format::Stream WalletMessage;
			if (Wallet && !Wallet->Store(&WalletMessage))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			if (!Wallet)
			{
				SchemaList Map;
				Map.push_back(Var::Set::Binary(AddressToMessage(Value.Address)));

				auto Cursor = EmplaceQuery(Label, __func__, "SELECT wallet_message FROM validators WHERE address = ? AND wallet_message IS NOT NULL", &Map);
				if (Cursor && !Cursor->ErrorOrEmpty())
				{
					WalletMessage.Data = (*Cursor)["wallet_message"].Get().GetBlob();
					Wallet = Ledger::Wallet();
				}
			}
			else
			{
				auto Blob = Protocol::Now().Key.EncryptBlob(WalletMessage.Data);
				if (!Blob)
					return Blob.Error();

				WalletMessage.Data = std::move(*Blob);
			}

			uint32_t Services = 0;
			if (Value.Services.Consensus)
				Services |= (uint32_t)NodeServices::Consensus;
			if (Value.Services.Discovery)
				Services |= (uint32_t)NodeServices::Discovery;
			if (Value.Services.Interface)
				Services |= (uint32_t)NodeServices::Interface;
			if (Value.Services.Proposer)
				Services |= (uint32_t)NodeServices::Proposer;
			if (Value.Services.Public)
				Services |= (uint32_t)NodeServices::Public;

			SchemaList Map;
			Map.push_back(Var::Set::Binary(AddressToMessage(Value.Address)));
			Map.push_back(Var::Set::Integer(Value.GetPreference()));
			Map.push_back(Var::Set::Integer(Services));
			Map.push_back(Var::Set::Binary(EdgeMessage.Data));
			Map.push_back(Wallet ? Var::Set::Binary(WalletMessage.Data) : Var::Set::Null());

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO validators (address, preference, services, validator_message, wallet_message) VALUES (?, ?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::ClearValidator(const SocketAddress& ValidatorAddress)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(AddressToMessage(ValidatorAddress)));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM validators WHERE address = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<std::pair<Ledger::Validator, Ledger::Wallet>> Mempoolstate::GetValidatorByOwnership(size_t Offset)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT validator_message, wallet_message FROM validators WHERE NOT (wallet_message IS NULL) LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<std::pair<Ledger::Validator, Ledger::Wallet>>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["wallet_message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Ledger::Validator Node;
			Format::Stream EdgeMessage = Format::Stream((*Cursor)["validator_message"].Get().GetBlob());
			if (!Node.Load(EdgeMessage))
				return ExpectsLR<std::pair<Ledger::Validator, Ledger::Wallet>>(LayerException("validator deserialization error"));

			Ledger::Wallet Wallet;
			Format::Stream WalletMessage = Format::Stream(std::move(*Blob));
			if (!Wallet.Load(WalletMessage))
				return ExpectsLR<std::pair<Ledger::Validator, Ledger::Wallet>>(LayerException("wallet deserialization error"));

			return std::make_pair(std::move(Node), std::move(Wallet));
		}
		ExpectsLR<Ledger::Validator> Mempoolstate::GetValidatorByAddress(const SocketAddress& ValidatorAddress)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(AddressToMessage(ValidatorAddress)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT validator_message FROM validators WHERE address = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Validator>(LayerException(ErrorOf(Cursor)));

			Ledger::Validator Value;
			Format::Stream Message = Format::Stream((*Cursor)["validator_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Validator>(LayerException("validator deserialization error"));

			return Value;
		}
		ExpectsLR<Ledger::Validator> Mempoolstate::GetValidatorByPreference(size_t Offset)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT validator_message FROM validators WHERE wallet_message IS NULL ORDER BY preference DESC NULLS FIRST LIMIT 1 OFFSET ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Ledger::Validator>(LayerException(ErrorOf(Cursor)));

			Ledger::Validator Value;
			Format::Stream Message = Format::Stream((*Cursor)["validator_message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Ledger::Validator>(LayerException("validator deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<SocketAddress>> Mempoolstate::GetValidatorAddresses(size_t Offset, size_t Count, uint32_t Services)
		{
			SchemaList Map;
			if (Services > 0)
				Map.push_back(Var::Set::Integer(Services));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("SELECT validator_message FROM validators WHERE wallet_message IS NULL %s ORDER BY preference DESC NULLS FIRST LIMIT ? OFFSET ?", Services > 0 ? "AND services & ? > 0" : ""), &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<SocketAddress>>(LayerException(ErrorOf(Cursor)));

			Vector<SocketAddress> Result;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				Ledger::Validator Value;
				Format::Stream Message = Format::Stream(Response[i]["validator_message"].Get().GetBlob());
				if (Value.Load(Message))
					Result.push_back(std::move(Value.Address));
			}

			return Result;
		}
		ExpectsLR<Vector<SocketAddress>> Mempoolstate::GetRandomizedValidatorAddresses(size_t Count, uint32_t Services)
		{
			SchemaList Map;
			if (Services > 0)
				Map.push_back(Var::Set::Integer(Services));
			Map.push_back(Var::Set::Integer(Count));

			auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("SELECT validator_message FROM validators WHERE wallet_message IS NULL %s ORDER BY random() LIMIT ?", Services > 0 ? "AND services & ? > 0" : ""), &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<SocketAddress>>(LayerException(ErrorOf(Cursor)));

			Vector<SocketAddress> Result;
			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			for (size_t i = 0; i < Size; i++)
			{
				Ledger::Validator Value;
				Format::Stream Message = Format::Stream(Response[i]["validator_message"].Get().GetBlob());
				if (Value.Load(Message))
					Result.push_back(std::move(Value.Address));
			}

			return Result;
		}
		ExpectsLR<SocketAddress> Mempoolstate::NextTrialAddress()
		{
			auto Cursor = Query(Label, __func__, "SELECT address FROM seeds ORDER BY random() LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<SocketAddress>(LayerException(ErrorOf(Cursor)));

			auto Message = (*Cursor)["address"].Get().GetBlob();
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Message));

			Cursor = EmplaceQuery(Label, __func__, "DELETE FROM seeds WHERE address = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<SocketAddress>(LayerException(ErrorOf(Cursor)));

			auto Address = MessageToAddress(Message);
			if (!Address)
				return ExpectsLR<SocketAddress>(LayerException("bad address"));

			return *Address;
		}
		ExpectsLR<size_t> Mempoolstate::GetValidatorsCount()
		{
			auto Cursor = Query(Label, __func__, "SELECT COUNT(1) AS counter FROM validators WHERE wallet_message IS NULL");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<size_t>(LayerException(ErrorOf(Cursor)));

			return (size_t)(*Cursor)["counter"].Get().GetInteger();
		}
		ExpectsLR<Decimal> Mempoolstate::GetGasPrice(const Algorithm::AssetId& Asset, double PriorityPercentile)
		{
			if (PriorityPercentile < 0.0 || PriorityPercentile > 1.0)
				return ExpectsLR<Decimal>(LayerException("invalid priority percentile"));

			uint8_t Hash[16];
			Algorithm::Encoding::DecodeUint128(Asset, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Number(1.0 - PriorityPercentile));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT price FROM transactions WHERE asset = ? ORDER BY preference DESC NULLS FIRST LIMIT 1 OFFSET (SELECT CAST((COUNT(1) * ?) AS INT) FROM transactions)", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Decimal>(LayerException(ErrorOf(Cursor)));

			Decimal Price = (*Cursor)["price"].Get().GetDecimal();
			return Price;
		}
		ExpectsLR<Decimal> Mempoolstate::GetAssetPrice(const Algorithm::AssetId& PriceOf, const Algorithm::AssetId& RelativeTo, double PriorityPercentile)
		{
			auto A = GetGasPrice(PriceOf, PriorityPercentile);
			if (!A || A->IsZero())
				return Decimal::Zero();

			auto B = GetGasPrice(RelativeTo, PriorityPercentile);
			if (!B)
				return Decimal::Zero();

			return *B / A->Truncate(Protocol::Now().Message.Precision);
		}
		ExpectsLR<void> Mempoolstate::AddTransaction(Ledger::Transaction& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("transaction serialization error"));

			Algorithm::Pubkeyhash Owner;
			if (!Value.Recover(Owner))
				return ExpectsLR<void>(LayerException("transaction owner recovery error"));

			uint256_t Group = 0;
			Decimal Preference = Decimal::NaN();
			auto Type = Value.GetType();
			auto Queue = [this, &Value]() -> Decimal
			{
				auto MedianGasPrice = GetGasPrice(Value.Asset, FeePercentile(FeePriority::Medium));
				Decimal DeltaGas = MedianGasPrice && MedianGasPrice->IsPositive() ? Value.GasPrice / *MedianGasPrice : 1.0;
				Decimal MaxGas = DeltaGas.IsPositive() ? Value.GasPrice * Value.GasLimit.ToDecimal() / DeltaGas.Truncate(Protocol::Now().Message.Precision) : Decimal::Zero();
				Decimal Multiplier = 2 << 20;
				return MaxGas * Multiplier;
			};
			switch (Type)
			{
				case Ledger::TransactionLevel::Functional:
				{
					Preference = Queue();
					break;
				}
				case Ledger::TransactionLevel::Delegation:
				{
					auto Bandwidth = GetBandwidthByOwner(Owner, Type);
					if (!Bandwidth->Congested || Bandwidth->Sequence >= Value.Sequence)
						break;

					if (!Value.GasPrice.IsPositive())
						return ExpectsLR<void>(LayerException(Stringify::Text("wait for finalization of or replace previous delegation transaction (queue: %" PRIu64 ", sequence: %" PRIu64 ")", (uint64_t)Bandwidth->Count, Bandwidth->Sequence)));

					Preference = Queue();
					break;
				}
				case Ledger::TransactionLevel::Consensus:
				{
					auto Bandwidth = GetBandwidthByOwner(Owner, Type);
					if (!Bandwidth->Congested || Bandwidth->Sequence >= Value.Sequence)
						break;

					if (!Value.GasPrice.IsPositive())
						return ExpectsLR<void>(LayerException(Stringify::Text("wait for finalization of or replace previous consensus transaction (queue: %" PRIu64 ", sequence: %" PRIu64 ")", (uint64_t)Bandwidth->Count, Bandwidth->Sequence)));

					Preference = Queue();
					break;
				}
				case Ledger::TransactionLevel::Aggregation:
				{
					Vector<uint256_t> Merges;
					size_t Offset = 0, Count = 64;
					auto Context = Ledger::TransactionContext();
					auto* Aggregation = ((Ledger::AggregationTransaction*)&Value);
					Group = Aggregation->GetCumulativeHash();
					while (true)
					{
						auto Transactions = GetCumulativeEventTransactions(Group, Offset, Count);
						if (!Transactions || Transactions->empty())
							break;

						for (auto& Item : *Transactions)
						{
							Merges.push_back(Item->AsHash());
							if (Item->GetType() == Ledger::TransactionLevel::Aggregation)
								Aggregation->Merge(&Context, *(Ledger::AggregationTransaction*)*Item);
						}

						Offset += Transactions->size();
						if (Transactions->size() != Count)
							break;
					}

					auto Status = RemoveTransactions(Merges);
					if (!Status)
						return Status;
					else if (!Merges.empty())
						break;

					auto Bandwidth = GetBandwidthByOwner(Owner, Type);
					if (!Bandwidth->Congested || Bandwidth->Sequence >= Value.Sequence)
						break;

					if (!Value.GasPrice.IsPositive())
						return ExpectsLR<void>(LayerException(Stringify::Text("wait for finalization of or replace previous aggregation transaction (queue: %" PRIu64 ", sequence: %" PRIu64 ")", (uint64_t)Bandwidth->Count, Bandwidth->Sequence)));

					Preference = Queue();
					break;
				}
				default:
					break;
			}

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

			uint8_t GroupHash[32];
			Algorithm::Encoding::DecodeUint256(Group, GroupHash);

			uint8_t Asset[16];
			Algorithm::Encoding::DecodeUint128(Value.Asset, Asset);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Binary(GroupHash, sizeof(GroupHash)));
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));
			Map.push_back(Var::Set::Binary(Asset, sizeof(Asset)));
			Map.push_back(Var::Set::Integer(Value.Sequence));
			Map.push_back(Preference.IsNaN() ? Var::Set::Null() : Var::Set::Integer(Preference.ToUInt64()));
			Map.push_back(Var::Set::Integer((int64_t)Type));
			Map.push_back(Var::Set::Integer(time(nullptr)));
			Map.push_back(Var::Set::String(Value.GasPrice.ToString()));
			Map.push_back(Var::Set::Binary(Message.Data));
			Map.push_back(Var::Set::Binary(Owner, sizeof(Owner)));

			auto Cursor = EmplaceQuery(Label, __func__,
				"INSERT OR REPLACE INTO transactions (hash, attestation, owner, asset, sequence, preference, type, time, price, message) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
				"WITH epochs AS (SELECT rowid, ROW_NUMBER() OVER (ORDER BY sequence) AS epoch FROM transactions WHERE owner = ?) UPDATE transactions SET epoch = epochs.epoch FROM epochs WHERE transactions.rowid = epochs.rowid", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::RemoveTransactions(const Vector<uint256_t>& TransactionHashes)
		{
			if (TransactionHashes.empty())
				return Expectation::Met;

			UPtr<Schema> HashList = Var::Set::Array();
			HashList->Reserve(TransactionHashes.size());
			for (auto& Item : TransactionHashes)
			{
				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Item, Hash);
				HashList->Push(Var::Binary(Hash, sizeof(Hash)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(HashList))));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::RemoveTransactions(const UnorderedSet<uint256_t>& TransactionHashes)
		{
			if (TransactionHashes.empty())
				return Expectation::Met;

			UPtr<Schema> HashList = Var::Set::Array();
			HashList->Reserve(TransactionHashes.size());
			for (auto& Item : TransactionHashes)
			{
				uint8_t Hash[32];
				Algorithm::Encoding::DecodeUint256(Item, Hash);
				HashList->Push(Var::Binary(Hash, sizeof(Hash)));
			}

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(HashList))));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM transactions WHERE hash IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mempoolstate::ExpireTransactions()
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(time(nullptr) - Protocol::Now().User.Storage.TransactionTimeout));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM transactions WHERE time < ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<AccountBandwidth> Mempoolstate::GetBandwidthByOwner(const Algorithm::Pubkeyhash Owner, Ledger::TransactionLevel Type)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Algorithm::Pubkeyhash)));
			Map.push_back(Var::Set::Integer((int64_t)Type));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT COUNT(1) AS counter, MAX(sequence) AS sequence FROM transactions WHERE owner = ? AND type = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<AccountBandwidth>(LayerException(ErrorOf(Cursor)));

			AccountBandwidth Result;
			Result.Count = Cursor->Empty() ? 0 : (size_t)(*Cursor)["counter"].Get().GetInteger();
			Result.Sequence = Cursor->Empty() ? 1 : (size_t)(*Cursor)["sequence"].Get().GetInteger();
			switch (Type)
			{
				case Tangent::Ledger::TransactionLevel::Functional:
					Result.Congested = true;
					break;
				case Tangent::Ledger::TransactionLevel::Delegation:
					Result.Congested = Result.Count >= Protocol::Now().Policy.ParallelDelegationLimit;
					break;
				case Tangent::Ledger::TransactionLevel::Consensus:
					Result.Congested = Result.Count >= Protocol::Now().Policy.ParallelConsensusLimit;
					break;
				case Tangent::Ledger::TransactionLevel::Aggregation:
					Result.Congested = Result.Count >= Protocol::Now().Policy.ParallelAggregationLimit;
					break;
				default:
					Result.Congested = true;
					break;
			}
			return Result;
		}
		ExpectsLR<bool> Mempoolstate::HasTransaction(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT TRUE FROM transactions WHERE hash = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<bool>(LayerException(ErrorOf(Cursor)));

			return !Cursor->Empty();
		}
		ExpectsLR<uint64_t> Mempoolstate::GetLowestTransactionSequence(const Algorithm::Pubkeyhash Owner)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Algorithm::Pubkeyhash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT MIN(sequence) AS sequence FROM transactions WHERE owner = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t Sequence = (*Cursor)["sequence"].Get().GetInteger();
			return Sequence;
		}
		ExpectsLR<uint64_t> Mempoolstate::GetHighestTransactionSequence(const Algorithm::Pubkeyhash Owner)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Algorithm::Pubkeyhash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT MAX(sequence) AS sequence FROM transactions WHERE owner = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<uint64_t>(LayerException(ErrorOf(Cursor)));

			uint64_t Sequence = (*Cursor)["sequence"].Get().GetInteger();
			return Sequence;
		}
		ExpectsLR<UPtr<Ledger::Transaction>> Mempoolstate::GetTransactionByHash(const uint256_t& TransactionHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(TransactionHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT hash, message FROM transactions WHERE hash = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException(ErrorOf(Cursor)));

			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Value || !Value->Load(Message))
				return ExpectsLR<UPtr<Ledger::Transaction>>(LayerException("transaction deserialization error"));

			FinalizeChecksum(**Value, (*Cursor)["hash"].Get());
			return Value;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Mempoolstate::GetTransactions(size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions ORDER BY epoch ASC, preference DESC NULLS FIRST LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["hash"].Get());
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Mempoolstate::GetTransactionsByOwner(const Algorithm::Pubkeyhash Owner, int8_t Direction, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Owner, sizeof(Algorithm::Pubkeyhash)));
			Map.push_back(Var::Set::String(Direction < 0 ? "DESC" : "ASC"));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE owner = ? ORDER BY sequence $? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["hash"].Get());
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<UPtr<Ledger::Transaction>>> Mempoolstate::GetCumulativeEventTransactions(const uint256_t& CumulativeHash, size_t Offset, size_t Count)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(CumulativeHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE attestation = ? ORDER BY attestation ASC LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<UPtr<Ledger::Transaction>>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<UPtr<Ledger::Transaction>> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				auto Row = Response[i];
				Format::Stream Message = Format::Stream(Row["message"].Get().GetBlob());
				UPtr<Ledger::Transaction> Value = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
				if (Value && Value->Load(Message))
				{
					FinalizeChecksum(**Value, Row["hash"].Get());
					Values.emplace_back(std::move(Value));
				}
			}

			return Values;
		}
		ExpectsLR<Vector<uint256_t>> Mempoolstate::GetTransactionHashset(size_t Offset, size_t Count)
		{
			if (!Count)
				return LayerException("invalid count");

			SchemaList Map;
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT hash FROM transactions ORDER BY hash ASC LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<uint256_t>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<uint256_t> Result;
			Result.reserve(Result.size() + Size);
			for (size_t i = 0; i < Size; i++)
			{
				auto InHash = Response[i]["hash"].Get().GetBlob();
				if (InHash.size() != sizeof(uint256_t))
					continue;

				uint256_t OutHash;
				Algorithm::Encoding::EncodeUint256((uint8_t*)InHash.data(), OutHash);
				Result.push_back(OutHash);
			}

			return Result;
		}
		double Mempoolstate::FeePercentile(FeePriority Priority)
		{
			switch (Priority)
			{
				case Tangent::Storages::FeePriority::Fastest:
					return 0.90;
				case Tangent::Storages::FeePriority::Fast:
					return 0.75;
				case Tangent::Storages::FeePriority::Medium:
					return 0.50;
				case Tangent::Storages::FeePriority::Slow:
					return 0.25;
				default:
					return 1.00;
			}
		}
		bool Mempoolstate::Verify()
		{
			String Command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS validators
				(
					address BINARY NOT NULL,
					preference INTEGER NOT NULL,
					services INTEGER NOT NULL,
					validator_message BINARY NOT NULL,
					wallet_message BINARY DEFAULT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS validators_wallet_message_preference ON validators (wallet_message IS NULL, preference);
				CREATE TABLE IF NOT EXISTS seeds
				(
					address BINARY NOT NULL,
					PRIMARY KEY (address)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS transactions
				(
					hash BINARY(32) NOT NULL,
					attestation BINARY(32) DEFAULT NULL,
					owner BINARY(20) NOT NULL,
					asset BINARY(16) NOT NULL,
					sequence BIGINT NOT NULL,
					epoch INTEGER DEFAULT 0,
					preference INTEGER DEFAULT NULL,
					type INTEGER NOT NULL,
					time INTEGER NOT NULL,
					price TEXT NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (hash)
				);
				CREATE INDEX IF NOT EXISTS transactions_attestation ON transactions (attestation);
				CREATE INDEX IF NOT EXISTS transactions_owner_sequence ON transactions (owner, sequence);
				CREATE INDEX IF NOT EXISTS transactions_asset_preference ON transactions (asset ASC, preference DESC);
				CREATE INDEX IF NOT EXISTS transactions_epoch_preference ON transactions (epoch ASC, preference DESC););

			auto Cursor = Query(Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}
	}
}