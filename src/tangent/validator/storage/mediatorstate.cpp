#include "mediatorstate.h"
#include "../service/nss.h"
#undef NULL

namespace Tangent
{
	namespace Storages
	{
		Mediatorstate::Mediatorstate(const std::string_view& NewLabel, const Algorithm::AssetId& NewAsset) noexcept : Asset(NewAsset), Label(NewLabel)
		{
			String Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			StorageOf("mediatorstate." + Stringify::ToLower(Blockchain) + "data");
		}
		ExpectsLR<void> Mediatorstate::AddMasterWallet(const Mediator::MasterWallet& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			auto Blob = Protocol::Now().Key.EncryptBlob(Message.Data);
			if (!Blob)
				return Blob.Error();

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Value.AsHash(), Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(DateTime().Milliseconds()));
			Map.push_back(Var::Set::Binary(*Blob));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, -1, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Mediator::MasterWallet> Mediatorstate::GetMasterWallet()
		{
			auto Cursor = Query(Label, __func__, "SELECT message FROM wallets WHERE address_index = -1 ORDER BY nonce DESC LIMIT 1");
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::MasterWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Mediator::MasterWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::MasterWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<Mediator::MasterWallet> Mediatorstate::GetMasterWalletByHash(const uint256_t& MasterWalletHash)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(MasterWalletHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = -1", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::MasterWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Mediator::MasterWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::MasterWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<void> Mediatorstate::AddDerivedWallet(const Mediator::MasterWallet& Parent, const Mediator::DerivedSigningWallet& Value)
		{
			if (!Value.IsValid())
				return ExpectsLR<void>(LayerException("invalid wallet"));

			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("wallet serialization error"));

			auto Blob = Protocol::Now().Key.EncryptBlob(Message.Data);
			if (!Blob)
				return Blob.Error();

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Parent.AsHash(), Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(Value.AddressIndex.Or(0)));
			Map.push_back(Var::Set::Integer(DateTime().Milliseconds()));
			Map.push_back(Var::Set::Binary(*Blob));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO wallets (hash, address_index, nonce, message) VALUES (?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return AddMasterWallet(Parent);
		}
		ExpectsLR<Mediator::DerivedSigningWallet> Mediatorstate::GetDerivedWallet(const uint256_t& MasterWalletHash, uint64_t AddressIndex)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(MasterWalletHash, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Hash, sizeof(Hash)));
			Map.push_back(Var::Set::Integer(AddressIndex));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM wallets WHERE hash = ? AND address_index = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException(ErrorOf(Cursor)));

			auto Blob = Protocol::Now().Key.DecryptBlob((*Cursor)["message"].Get().GetBlob());
			if (!Blob)
				return Blob.Error();

			Mediator::DerivedSigningWallet Value;
			Format::Stream Message = Format::Stream(std::move(*Blob));
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("wallet deserialization error"));

			return Value;
		}
		ExpectsLR<void> Mediatorstate::AddUTXO(const Mediator::IndexUTXO& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("utxo serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(Value.UTXO.TransactionId, Value.UTXO.Index)));
			Map.push_back(Var::Set::Binary(Value.Binding));
			Map.push_back(Var::Set::Boolean(false));
			Map.push_back(Var::Set::Binary(Message.Data));
			
			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO coins (location, binding, spent, message) VALUES (?, ?, ?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mediatorstate::RemoveUTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(TransactionId, Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "UPDATE coins SET spent = TRUE WHERE location = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Mediator::IndexUTXO> Mediatorstate::GetSTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(String(TransactionId) + ":" + ToString(Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE location = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::IndexUTXO>(LayerException(ErrorOf(Cursor)));

			Mediator::IndexUTXO Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::IndexUTXO>(LayerException("utxo deserialization error"));

			return Value;
		}
		ExpectsLR<Mediator::IndexUTXO> Mediatorstate::GetUTXO(const std::string_view& TransactionId, uint32_t Index)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetCoinLocation(TransactionId, Index)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE location = ? AND spent = FALSE", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::IndexUTXO>(LayerException(ErrorOf(Cursor)));

			Mediator::IndexUTXO Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::IndexUTXO>(LayerException("utxo deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<Mediator::IndexUTXO>> Mediatorstate::GetUTXOs(const std::string_view& Binding, size_t Offset, size_t Count)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Binding));
			Map.push_back(Var::Set::Integer(Count));
			Map.push_back(Var::Set::Integer(Offset));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM coins WHERE spent = FALSE AND binding = ? LIMIT ? OFFSET ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Mediator::IndexUTXO>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Mediator::IndexUTXO> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Mediator::IndexUTXO Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values.emplace_back(std::move(Value));
			}

			return Values;
		}
		ExpectsLR<void> Mediatorstate::AddIncomingTransaction(const Mediator::IncomingTransaction& Value, uint64_t BlockId)
		{
			auto* Chain = NSS::ServerNode::Get()->GetChain(Value.Asset);
			if (!Chain)
				return ExpectsLR<void>(LayerException("invalid witness transaction asset"));

			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("witness transaction serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(Value.TransactionId)));
			Map.push_back(Var::Set::Null());
			Map.push_back(Var::Set::Integer(Value.BlockId));
			Map.push_back(Var::Set::Boolean(Value.BlockId <= BlockId ? BlockId - Value.BlockId >= Chain->GetChainparams().SyncLatency : false));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT INTO transactions (location, binding, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET binding = (CASE WHEN binding IS NOT NULL THEN binding ELSE EXCLUDED.binding END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mediatorstate::AddOutgoingTransaction(const Mediator::IncomingTransaction& Value, const uint256_t ExternalId)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("witness transaction serialization error"));

			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ExternalId, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(Value.TransactionId)));
			Map.push_back(ExternalId > 0 ? Var::Set::Binary(Hash, sizeof(Hash)) : Var::Set::Null());
			Map.push_back(Var::Set::Integer(Value.BlockId));
			Map.push_back(Var::Set::Boolean(false));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT INTO transactions (location, external_id, block_id, approved, message) VALUES (?, ?, ?, ?, ?) ON CONFLICT (location) DO UPDATE SET external_id = (CASE WHEN external_id IS NOT NULL THEN external_id ELSE EXCLUDED.external_id END), block_id = EXCLUDED.block_id, approved = EXCLUDED.approved, message = EXCLUDED.message", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Mediator::IncomingTransaction> Mediatorstate::GetTransaction(const std::string_view& TransactionId, const uint256_t& ExternalId)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(ExternalId, Hash);

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetTransactionLocation(TransactionId)));
			Map.push_back(ExternalId > 0 ? Var::Set::Binary(Hash, sizeof(Hash)) : Var::Set::Null());

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE location = ? OR binding = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::IncomingTransaction>(LayerException(ErrorOf(Cursor)));

			Mediator::IncomingTransaction Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::IncomingTransaction>(LayerException("witness transaction deserialization error"));

			return Value;
		}
		ExpectsLR<Vector<Mediator::IncomingTransaction>> Mediatorstate::ApproveTransactions(uint64_t BlockHeight, uint64_t BlockLatency)
		{
			if (!BlockHeight || !BlockLatency)
				return ExpectsLR<Vector<Mediator::IncomingTransaction>>(LayerException("invalid block height or block latency"));
			else if (BlockHeight <= BlockLatency)
				return ExpectsLR<Vector<Mediator::IncomingTransaction>>(Vector<Mediator::IncomingTransaction>());

			SchemaList Map;
			Map.push_back(Var::Set::Integer(BlockHeight - BlockLatency));
			Map.push_back(Var::Set::Integer(BlockHeight - BlockLatency));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM transactions WHERE block_id <= ? AND approved = FALSE", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<Mediator::IncomingTransaction>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<Mediator::IncomingTransaction> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Mediator::IncomingTransaction Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (!Value.Load(Message))
					continue;

				if (Value.BlockId > 0)
				{
					if (AddIncomingTransaction(Value, BlockHeight))
						Values.emplace_back(std::move(Value));
				}
				else
				{
					Value.BlockId = BlockHeight;
					AddIncomingTransaction(Value, BlockHeight);
				}
			}

			return ExpectsLR<Vector<Mediator::IncomingTransaction>>(std::move(Values));
		}
		ExpectsLR<void> Mediatorstate::SetProperty(const std::string_view& Key, UPtr<Schema>&& Value)
		{
			auto Buffer = Schema::ToJSONB(*Value);
			Format::Stream Message;
			Message.WriteString(std::string_view(Buffer.begin(), Buffer.end()));

			SchemaList Map;
			Map.push_back(Var::Set::String(Algorithm::Asset::BlockchainOf(Asset) + ":" + String(Key)));
			Map.push_back(Var::Set::Binary(Message.Compress()));

			if (Value)
			{
				auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO properties (key, message) VALUES (?, ?)", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}
			else
			{
				auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM properties WHERE key = ?", &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			return Expectation::Met;
		}
		ExpectsLR<Schema*> Mediatorstate::GetProperty(const std::string_view& Key)
		{
			SchemaList Map;
			Map.push_back(Var::Set::String(Algorithm::Asset::BlockchainOf(Asset) + ":" + String(Key)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM properties WHERE key = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Schema*>(LayerException(ErrorOf(Cursor)));

			String Buffer;
			Format::Stream Message = Format::Stream::Decompress((*Cursor)["message"].Get().GetString());
			if (!Message.ReadString(Message.ReadType(), &Buffer))
				return ExpectsLR<Schema*>(LayerException("state value deserialization error"));
			
			auto Value = Schema::FromJSONB(Buffer);
			if (!Value)
				return ExpectsLR<Schema*>(LayerException(std::move(Value.Error().message())));

			return *Value;
		}
		ExpectsLR<void> Mediatorstate::SetCache(Mediator::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value)
		{
			auto Buffer = Schema::ToJSONB(*Value);
			Format::Stream Message;
			Message.WriteString(std::string_view(Buffer.begin(), Buffer.end()));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(Format::Util::IsHexEncoding(Key) ? Codec::HexDecode(Key) : String(Key)));
			Map.push_back(Var::Set::Binary(Message.Compress()));

			if (Value)
			{
				auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("INSERT INTO %s (key, message) VALUES (?, ?)", GetCacheLocation(Policy).data()), &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}
			else
			{
				auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("DELETE FROM %s WHERE key = ?", GetCacheLocation(Policy).data()), &Map);
				if (!Cursor || Cursor->Error())
					return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));
			}

			return Expectation::Met;
		}
		ExpectsLR<Schema*> Mediatorstate::GetCache(Mediator::CachePolicy Policy, const std::string_view& Key)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(Format::Util::IsHexEncoding(Key) ? Codec::HexDecode(Key) : String(Key)));

			auto Cursor = EmplaceQuery(Label, __func__, Stringify::Text("SELECT message FROM %s WHERE key = ?", GetCacheLocation(Policy).data()), &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Schema*>(LayerException(ErrorOf(Cursor)));

			String Buffer;
			Format::Stream Message = Format::Stream::Decompress((*Cursor)["message"].Get().GetString());
			if (!Message.ReadString(Message.ReadType(), &Buffer))
				return ExpectsLR<Schema*>(LayerException("cache value deserialization error"));

			auto Value = Schema::FromJSONB(Buffer);
			if (!Value)
				return ExpectsLR<Schema*>(LayerException(std::move(Value.Error().message())));

			return *Value;
		}
		ExpectsLR<void> Mediatorstate::SetAddressIndex(const std::string_view& Address, const Mediator::IndexAddress& Value)
		{
			Format::Stream Message;
			if (!Value.Store(&Message))
				return ExpectsLR<void>(LayerException("address index serialization error"));

			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetAddressLocation(Address)));
			Map.push_back(Var::Set::Binary(Message.Data));

			auto Cursor = EmplaceQuery(Label, __func__, "INSERT OR REPLACE INTO addresses (location, message) VALUES (?, ?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<void> Mediatorstate::ClearAddressIndex(const std::string_view& Address)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetAddressLocation(Address)));

			auto Cursor = EmplaceQuery(Label, __func__, "DELETE FROM addresses WHERE location = ?", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<void>(LayerException(ErrorOf(Cursor)));

			return Expectation::Met;
		}
		ExpectsLR<Mediator::IndexAddress> Mediatorstate::GetAddressIndex(const std::string_view& Address)
		{
			SchemaList Map;
			Map.push_back(Var::Set::Binary(GetAddressLocation(Address)));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM addresses WHERE location = ?", &Map);
			if (!Cursor || Cursor->ErrorOrEmpty())
				return ExpectsLR<Mediator::IndexAddress>(LayerException(ErrorOf(Cursor)));

			Mediator::IndexAddress Value;
			Format::Stream Message = Format::Stream((*Cursor)["message"].Get().GetBlob());
			if (!Value.Load(Message))
				return ExpectsLR<Mediator::IndexAddress>(LayerException("address index deserialization error"));

			return Value;
		}
		ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>> Mediatorstate::GetAddressIndices(const UnorderedSet<String>& Addresses)
		{
			UPtr<Schema> AddressList = Var::Set::Array();
			AddressList->Reserve(Addresses.size());
			for (auto& Item : Addresses)
			{
				if (!Item.empty())
					AddressList->Push(Var::Binary(GetAddressLocation(Item)));
			}
			if (AddressList->Empty())
				return ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>>(LayerException("no locations"));

			SchemaList Map;
			Map.push_back(Var::Set::String(*LDB::Utils::InlineArray(std::move(AddressList))));

			auto Cursor = EmplaceQuery(Label, __func__, "SELECT message FROM addresses WHERE location IN ($?)", &Map);
			if (!Cursor || Cursor->Error())
				return ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			UnorderedMap<String, Mediator::IndexAddress> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Mediator::IndexAddress Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values[Value.Address] = std::move(Value);
			}

			return Values;
		}
		ExpectsLR<Vector<String>> Mediatorstate::GetAddressIndices()
		{
			auto Cursor = Query(Label, __func__, "SELECT message FROM addresses");
			if (!Cursor || Cursor->Error())
				return ExpectsLR<Vector<String>>(LayerException(ErrorOf(Cursor)));

			auto& Response = Cursor->First();
			size_t Size = Response.Size();
			Vector<String> Values;
			Values.reserve(Size);

			for (size_t i = 0; i < Size; i++)
			{
				Mediator::IndexAddress Value;
				Format::Stream Message = Format::Stream(Response[i]["message"].Get().GetBlob());
				if (Value.Load(Message))
					Values.emplace_back(std::move(Value.Address));
			}

			return Values;
		}
		std::string_view Mediatorstate::GetCacheLocation(Mediator::CachePolicy Policy)
		{
			switch (Policy)
			{
				case Mediator::CachePolicy::Persistent:
					return "persistent_caches";
				case Mediator::CachePolicy::Extended:
					return "extended_caches";
				case Mediator::CachePolicy::Greedy:
				case Mediator::CachePolicy::Lazy:
				case Mediator::CachePolicy::Shortened:
				default:
					return "shortened_caches";
			}
		}
		String Mediatorstate::GetAddressLocation(const std::string_view& Address)
		{
			Format::Stream Message;
			Message.WriteString(Address);
			return Message.Data;
		}
		String Mediatorstate::GetTransactionLocation(const std::string_view& TransactionId)
		{
			Format::Stream Message;
			Message.WriteString(TransactionId);
			return Message.Data;
		}
		String Mediatorstate::GetCoinLocation(const std::string_view& TransactionId, uint32_t Index)
		{
			Format::Stream Message;
			Message.WriteString(TransactionId);
			Message.WriteTypeless(Index);
			return Message.Data;
		}
		bool Mediatorstate::ReconstructStorage()
		{
			const uint32_t MaxECacheCapacity = Protocol::Now().User.NSS.CacheExtendedSize;
			const uint32_t MaxSCacheCapacity = Protocol::Now().User.NSS.CacheShortSize;
			String Command = VI_STRINGIFY(
				CREATE TABLE IF NOT EXISTS wallets
				(
					hash BINARY(32) NOT NULL,
					address_index INTEGER NOT NULL,
					nonce INTEGER NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (hash, address_index)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS wallets_nonce_address_index ON wallets (nonce, address_index);
				CREATE TABLE IF NOT EXISTS coins
				(
					location BINARY NOT NULL,
					binding BINARY(32) NOT NULL,
					spent BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS coins_spent_binding ON coins (spent, binding);
				CREATE TABLE IF NOT EXISTS transactions
				(
					location BINARY NOT NULL,
					binding BINARY(32) DEFAULT NULL,
					block_id BIGINT NOT NULL,
					approved BOOLEAN NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE INDEX IF NOT EXISTS transactions_binding ON transactions (binding);
				CREATE INDEX IF NOT EXISTS transactions_block_id_approved ON transactions (block_id, approved);
				CREATE TABLE IF NOT EXISTS addresses
				(
					location BINARY NOT NULL,
					message BINARY NOT NULL,
					PRIMARY KEY (location)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS properties
				(
					key TEXT NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS persistent_caches
				(
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (key)
				) WITHOUT ROWID;
				CREATE TABLE IF NOT EXISTS extended_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				) WITHOUT ROWID;
				CREATE TRIGGER IF NOT EXISTS extended_caches_capacity AFTER INSERT ON extended_caches BEGIN
					DELETE FROM extended_caches WHERE id = (SELECT id FROM extended_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM extended_caches) > max_extended_cache_capacity;
				END;
				CREATE TABLE IF NOT EXISTS shortened_caches
				(
					id INTEGER NOT NULL,
					key BINARY NOT NULL,
					message BINARY NOT NULL,
  					PRIMARY KEY (id),
					UNIQUE (key)
				) WITHOUT ROWID;
				CREATE TRIGGER IF NOT EXISTS shortened_caches_capacity AFTER INSERT ON shortened_caches BEGIN
					DELETE FROM shortened_caches WHERE id = (SELECT id FROM shortened_caches ORDER BY id ASC) AND (SELECT COUNT(1) FROM shortened_caches) > max_shortened_cache_capacity;
				END;);
			Stringify::Replace(Command, "max_extended_cache_capacity", ToString(MaxECacheCapacity));
			Stringify::Replace(Command, "max_shortened_cache_capacity", ToString(MaxSCacheCapacity));

			auto Cursor = Query(Label, __func__, Command);
			return (Cursor && !Cursor->Error());
		}
	}
}