#include "nss.h"
#include "../storage/mediatorstate.h"
#include "../backend/bitcoin.h"
#include "../backend/forks/bitcoin.h"
#include "../backend/cardano.h"
#include "../backend/ethereum.h"
#include "../backend/forks/ethereum.h"
#include "../backend/ripple.h"
#include "../backend/solana.h"
#include "../backend/stellar.h"
#include "../backend/tron.h"
extern "C"
{
#include "../internal/libbitcoin/ecc.h"
}

namespace Tangent
{
	namespace NSS
	{
		template <typename T>
		static InvocationCallback Chain(ServerNode* Server)
		{
			return [Server](const std::string_view& Blockchain) -> bool
			{
				Algorithm::AssetId Asset = Algorithm::Asset::IdOf(Blockchain);
				if (Server->HasChain(Asset))
					return false;

				Server->AddChain<T>(Asset);
				return true;
			};
		}

		ServerNode::ServerNode() noexcept : ControlSys("nss-node")
		{
			auto& Chains = GetRegistrations();
			for (auto& Chain : Chains)
				Chain.second(Chain.first);

			auto& Config = Protocol::Now().User.NSS.Options;
			if (Config)
			{
				auto* RetryTimeout = Config->Fetch("strategy.retry_timeout");
				if (RetryTimeout != nullptr && RetryTimeout->Value.Is(VarType::Integer))
					Options.RetryWaitingTimeMs = RetryTimeout->Value.GetInteger();

				auto* PollingFrequency = Config->Fetch("strategy.polling_frequency");
				if (PollingFrequency != nullptr && PollingFrequency->Value.Is(VarType::Integer))
					Options.PollingFrequencyMs = PollingFrequency->Value.GetInteger();

				auto* BlockConfirmations = Config->Fetch("strategy.block_confirmations");
				if (BlockConfirmations != nullptr && BlockConfirmations->Value.Is(VarType::Integer))
					Options.MinBlockConfirmations = BlockConfirmations->Value.GetInteger();

				auto* Protocols = Config->Get("protocols");
				if (Protocols != nullptr)
				{
					for (auto& Root : Protocols->GetChilds())
					{
						Algorithm::AssetId Asset = Algorithm::Asset::IdOf(Root->Key);
						auto* Peers = Root->Get("peers");
						if (Peers && !Peers->Empty())
						{
							UnorderedMap<std::string_view, double> Sources;
							for (auto& Child : Peers->GetChilds())
							{
								auto Source = Child->Size() > 0 ? Child->Get(0)->Value.GetString() : Child->Value.GetString();
								auto Throttling = Child->Size() > 1 ? Child->Get(1)->Value.GetNumber() : 0.0;
								if (!Stringify::IsEmptyOrWhitespace(Source) && Throttling >= 0.0)
									Sources[Source] = 1000.0 / Throttling;
							}

							for (auto& Source : Sources)
							{
								if (AddNode(Asset, Source.first, Source.second))
								{
									if (Protocol::Now().User.NSS.Server && Protocol::Now().User.NSS.Logging)
										VI_INFO("[observer] %s server node %.*s added (limit: %.2f rps)", Algorithm::Asset::HandleOf(Asset).c_str(), (int)Source.first.size(), Source.first.data(), Source.second);
								}
								else if (Protocol::Now().User.NSS.Logging)
									VI_ERR("[observer] %s server node on %.*s add failed (limit: %.2f rps)", Algorithm::Asset::HandleOf(Asset).c_str(), (int)Source.first.size(), Source.first.data(), Source.second);
							}
						}

						auto* Props = Root->Fetch("server.props");
						if (Props != nullptr && Props->Value.GetType() != VarType::Null)
						{
							AddSpecifications(Asset, Props);
							Props->Unlink();
						}

						auto* Tip = Root->Fetch("server.tip");
						if (Tip != nullptr && Tip->Value.Is(VarType::Integer))
							EnableCheckpointHeight(Asset, Tip->Value.GetInteger());

						BlockConfirmations = Root->Fetch("server.delay");
						if (BlockConfirmations != nullptr && BlockConfirmations->Value.Is(VarType::Integer))
							Options.AddSpecificOptions(Root->Key).MinBlockConfirmations = BlockConfirmations->Value.GetInteger();
					}
				}
			}
			btc_ecc_start();
		}
		ServerNode::~ServerNode() noexcept
		{
			btc_ecc_stop();
		}
		ExpectsPromiseSystem<HTTP::ResponseFrame> ServerNode::InternalCall(const std::string_view& Location, const std::string_view& Method, const HTTP::FetchFrame& Options)
		{
			return HTTP::Fetch(Location, Method, Options);
		}
		ExpectsPromiseRT<Mediator::OutgoingTransaction> ServerNode::SubmitTransaction(const uint256_t& ExternalId, const Algorithm::AssetId& Asset, Mediator::DynamicWallet&& Wallet, Vector<Mediator::Transferer>&& To, Option<Mediator::BaseFee>&& Fee)
		{
			if (!ControlSys.IsActive())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException::Shutdown());

			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (Connections.find(Blockchain) == Connections.end())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException(Stringify::Text("%s blockchain operations are disabled", Algorithm::Asset::HandleOf(Asset).c_str())));

			TransactionParams* Params = Memory::New<TransactionParams>();
			Params->Asset = std::move(Asset);
			Params->Wallet = std::move(Wallet);
			Params->To = std::move(To);
			Params->Fee = std::move(Fee);
			Params->ExternalId = ExternalId;

			auto& State = States[Blockchain];
			if (!State)
			{
				State = Memory::New<TransactionQueueState>();
				State->Blockchain = Blockchain;
			}

			auto Future = Params->Future;
			State->Queue.push(Params);
			DispatchTransactionQueue(*State, Params);
			Unique.Negate();
			Coreturn Coawait(std::move(Future));
		}
		ExpectsPromiseRT<void> ServerNode::BroadcastTransaction(const Algorithm::AssetId& Asset, const uint256_t& ExternalId, const Mediator::OutgoingTransaction& TxData)
		{
			if (!Algorithm::Asset::IsValid(Asset) || TxData.Transaction.Asset != Asset)
				Coreturn ExpectsRT<void>(RemoteException("asset not found"));

			if (!TxData.IsValid())
				Coreturn ExpectsRT<void>(RemoteException("transaction not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<void>(RemoteException("chain not found"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			auto DuplicateTransaction = State.GetTransaction(TxData.Transaction.TransactionId, ExternalId);
			if (DuplicateTransaction)
				Coreturn ExpectsRT<void>(Expectation::Met);

			auto NewTransaction = TxData.Transaction;
			NewTransaction.TransactionId = Implementation->GetChecksumHash(NewTransaction.TransactionId);
			NewTransaction.BlockId = 0;

			State.AddOutgoingTransaction(NewTransaction, ExternalId);
			Coreturn Coawait(Implementation->BroadcastTransaction(Asset, TxData));
		}
		ExpectsPromiseRT<void> ServerNode::ValidateTransaction(const Mediator::IncomingTransaction& Value)
		{
			if (!Value.IsValid())
				Coreturn ExpectsRT<void>(RemoteException("transaction not valid"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Value.Asset);
			if (State.GetTransaction(Value.TransactionId, 0))
				Coreturn ExpectsRT<void>(Expectation::Met);

			auto TransactionData = Coawait(GetBlockTransaction(Value.Asset, Value.BlockId, std::string_view(), Value.TransactionId));
			if (!TransactionData)
				Coreturn ExpectsRT<void>(std::move(TransactionData.Error()));

			auto Transactions = Coawait(GetAuthenticTransactions(Value.Asset, Value.BlockId, std::string_view(), *TransactionData));
			Memory::Release(*TransactionData);
			if (!Transactions)
				Coreturn ExpectsRT<void>(std::move(Transactions.Error()));

			auto Left = Value;
			for (auto& Item : Left.To)
				Item.AddressIndex = 0;
			for (auto& Item : Left.From)
				Item.AddressIndex = 0;

			uint256_t Hash = Left.AsHash();
			for (auto& Right : *Transactions)
			{
				for (auto& Item : Right.To)
					Item.AddressIndex = 0;
				for (auto& Item : Right.From)
					Item.AddressIndex = 0;
				if (Right.AsHash() == Hash)
					Coreturn ExpectsRT<void>(Expectation::Met);
			}
			Coreturn ExpectsRT<void>(RemoteException("transaction not valid"));
		}
		ExpectsPromiseRT<uint64_t> ServerNode::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<uint64_t>(RemoteException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<uint64_t>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->GetLatestBlockHeight(Asset));
		}
		ExpectsPromiseRT<Schema*> ServerNode::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Schema*>(RemoteException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Schema*>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->GetBlockTransactions(Asset, BlockHeight, BlockHash));
		}
		ExpectsPromiseRT<Schema*> ServerNode::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Schema*>(RemoteException("asset not found"));

			if (!BlockHeight || Stringify::IsEmptyOrWhitespace(TransactionId))
				Coreturn ExpectsRT<Schema*>(RemoteException("tx not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Schema*>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->GetBlockTransaction(Asset, BlockHeight, BlockHash, TransactionId));
		}
		ExpectsPromiseRT<Vector<Mediator::IncomingTransaction>> ServerNode::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Vector<Mediator::IncomingTransaction>>(RemoteException("asset not found"));

			if (!BlockHeight)
				Coreturn ExpectsRT<Vector<Mediator::IncomingTransaction>>(RemoteException("txs not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Vector<Mediator::IncomingTransaction>>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->GetAuthenticTransactions(Asset, BlockHeight, BlockHash, TransactionData));
		}
		ExpectsPromiseRT<Schema*> ServerNode::ExecuteRPC(const Algorithm::AssetId& Asset, const std::string_view& Method, SchemaList&& Args, Mediator::CachePolicy Cache)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Schema*>(RemoteException("asset not found"));

			if (Method.empty())
				Coreturn ExpectsRT<Schema*>(RemoteException("method not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Schema*>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->ExecuteRPC(Asset, Method, std::move(Args), Cache));
		}
		ExpectsPromiseRT<Mediator::OutgoingTransaction> ServerNode::NewTransaction(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, const Vector<Mediator::Transferer>& To, Option<Mediator::BaseFee>&& Fee)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("asset not found"));

			if (!Wallet.IsValid())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("wallet not found"));

			if (To.empty())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("to address not found"));

			for (auto& Address : To)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.Address))
					Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("receiver address not valid"));

				if (!Address.Value.IsPositive())
					Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("receiver quantity not valid"));
			}

			if (Fee && !Fee->IsValid())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("fee not valid"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("chain not found"));

			if (!Implementation->GetChainparams().SupportsBulkTransfer && To.size() > 1)
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException("only one receiver allowed"));

			Mediator::BaseFee ActualFee = Mediator::BaseFee(Decimal::NaN(), Decimal::NaN());
			if (!Fee)
			{
				auto EstimatedFee = Coawait(EstimateFee(Asset, Wallet, To));
				if (!EstimatedFee)
					Coreturn ExpectsRT<Mediator::OutgoingTransaction>(std::move(EstimatedFee.Error()));
				ActualFee = *EstimatedFee;
			}
			else
				ActualFee = *Fee;

			Decimal FeeValue = ActualFee.GetFee();
			if (!FeeValue.IsPositive())
				Coreturn ExpectsRT<Mediator::OutgoingTransaction>(RemoteException(Stringify::Text("fee not valid: %s", FeeValue.ToString().c_str())));

			Coreturn Coawait(Implementation->NewTransaction(Asset, Wallet, To, ActualFee));
		}
		ExpectsPromiseRT<Mediator::TransactionLogs> ServerNode::GetTransactionLogs(const Algorithm::AssetId& Asset, Mediator::ChainSupervisorOptions* Options)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Mediator::TransactionLogs>(RemoteException("asset not found"));

			if (!Options)
				Coreturn ExpectsRT<Mediator::TransactionLogs>(RemoteException("options not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Mediator::TransactionLogs>(RemoteException("chain not found"));

			auto* Provider = GetNode(Asset);
			if (!Provider)
				Coreturn ExpectsRT<Mediator::TransactionLogs>(RemoteException("node not found"));

			bool IsDryRun = !Options->HasLatestBlockHeight();
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			Implementation->Interact = [Options](Mediator::ServerRelay* Service) { Options->State.Interactions.insert(Service); };
			Options->State.Interactions.clear();

			auto TipCheckpoint = UPtr<Schema>(State.GetProperty("tip_checkpoint"));
			if (TipCheckpoint)
				Options->SetCheckpointFromBlock((uint64_t)std::max<int64_t>(1, TipCheckpoint->Value.GetInteger()) - 1);

			auto TipLatest = UPtr<Schema>(State.GetProperty("tip_latest"));
			if (TipLatest && (uint64_t)TipLatest->Value.GetInteger() > Options->State.LatestBlockHeight)
				Options->SetCheckpointFromBlock((uint64_t)TipLatest->Value.GetInteger());

			auto TipOverride = UPtr<Schema>(State.GetProperty("tip_override"));
			if (TipOverride)
			{
				uint64_t Tip = (uint64_t)TipOverride->Value.GetInteger();
				Options->State.StartingBlockHeight = Tip;
				Options->SetCheckpointFromBlock(Tip);
			}

			if (!Options->HasCurrentBlockHeight())
			{
			Retry:
				auto LatestBlockHeight = Coawait(Implementation->GetLatestBlockHeight(Asset));
				if (!LatestBlockHeight)
					Coreturn ExpectsRT<Mediator::TransactionLogs>(std::move(LatestBlockHeight.Error()));
				Options->SetCheckpointToBlock(*LatestBlockHeight);
			}

			if (!Options->HasNextBlockHeight())
			{
				if (IsDryRun)
					Coreturn ExpectsRT<Mediator::TransactionLogs>(Mediator::TransactionLogs());
				else if (!Coawait(Provider->YieldForDiscovery(Options)))
					Coreturn ExpectsRT<Mediator::TransactionLogs>(RemoteException::Retry());
				goto Retry;
			}

			Mediator::TransactionLogs Logs;
			Logs.BlockHeight = TipOverride ? (uint64_t)TipOverride->Value.GetInteger() : Options->GetNextBlockHeight();
			Logs.BlockHash = ToString(Logs.BlockHeight);

			auto Transactions = UPtr<Schema>(Coawait(Implementation->GetBlockTransactions(Asset, Logs.BlockHeight, &Logs.BlockHash)));
			if (Transactions)
			{
				for (auto& Item : Transactions->GetChilds())
				{
					if (!Item->Value.IsObject())
					{
						auto Details = UPtr<Schema>(Coawait(Implementation->GetBlockTransaction(Asset, Logs.BlockHeight, Logs.BlockHash, Item->Value.GetBlob())));
						if (!Details)
							continue;

						Memory::Release(Item);
						Item = *Details;
					}

					auto Authentics = Coawait(Implementation->GetAuthenticTransactions(Asset, Logs.BlockHeight, Logs.BlockHash, Item));
					if (Authentics)
					{
						for (auto& Next : *Authentics)
							Logs.Transactions.push_back(std::move(Next));
					}
				}
			}

			if (!TipCheckpoint || (uint64_t)TipCheckpoint->Value.GetInteger() != Logs.BlockHeight)
				State.SetProperty("tip_checkpoint", Var::Set::Integer(Logs.BlockHeight));
			if (!TipLatest || (uint64_t)TipLatest->Value.GetInteger() != Options->State.LatestBlockHeight)
				State.SetProperty("tip_latest", Var::Set::Integer(Options->State.LatestBlockHeight));
			if (TipOverride)
				State.SetProperty("tip_override", nullptr);

			UnorderedSet<String> TransactionIds;
			for (auto& NewTransaction : Logs.Transactions)
			{
				NewTransaction.BlockId = Logs.BlockHeight;
				NewTransaction.TransactionId = Implementation->GetChecksumHash(NewTransaction.TransactionId);
				State.AddIncomingTransaction(NewTransaction, Logs.BlockHeight);
				TransactionIds.insert(Algorithm::Asset::HandleOf(NewTransaction.Asset) + ":" + NewTransaction.TransactionId);
			}

			auto Approvals = State.ApproveTransactions(Logs.BlockHeight, Implementation->GetChainparams().SyncLatency);
			if (Approvals && !Approvals->empty())
			{
				Logs.Transactions.reserve(Logs.Transactions.size() + Approvals->size());
				for (auto& NewTransaction : *Approvals)
				{
					if (TransactionIds.find(Algorithm::Asset::HandleOf(NewTransaction.Asset) + ":" + NewTransaction.TransactionId) == TransactionIds.end())
						Logs.Transactions.push_back(std::move(NewTransaction));
				}
			}

			Coreturn ExpectsRT<Mediator::TransactionLogs>(std::move(Logs));
		}
		ExpectsPromiseRT<Mediator::BaseFee> ServerNode::EstimateFee(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, const Vector<Mediator::Transferer>& To, const Mediator::FeeSupervisorOptions& Options)
		{
			if (!Algorithm::Asset::IsValid(Asset) || !Options.MaxBlocks || !Options.MaxTransactions)
				Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("asset not found"));

			if (!Wallet.IsValid())
				Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("wallet not found"));

			if (To.empty())
				Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("to address not found"));

			for (auto& Address : To)
			{
				if (Stringify::IsEmptyOrWhitespace(Address.Address))
					Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("receiver address not valid"));

				if (!Address.Value.IsPositive())
					Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("receiver quantity not valid"));
			}

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("chain not found"));

			if (!Implementation->GetChainparams().SupportsBulkTransfer && To.size() > 1)
				Coreturn ExpectsRT<Mediator::BaseFee>(RemoteException("only one receiver allowed"));

			int64_t Time = time(nullptr);
			String FeeKey = Stringify::Text("%s:%i", Algorithm::Asset::BlockchainOf(Asset).c_str(), To.size());
			{
				UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
				auto It = Fees.find(FeeKey);
				if (It != Fees.end() && It->second.second >= Time)
					Coreturn ExpectsRT<Mediator::BaseFee>(It->second.first);
			}

			auto Estimate = Coawait(Implementation->EstimateFee(Asset, Wallet, To, Options));
			if (!Estimate)
				Coreturn ExpectsRT<Mediator::BaseFee>(std::move(Estimate.Error()));

			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			Fees[FeeKey] = std::make_pair(*Estimate, Time + (int64_t)Protocol::Now().User.NSS.FeeEstimationSeconds);
			Coreturn Estimate;
		}
		ExpectsPromiseRT<Decimal> ServerNode::CalculateBalance(const Algorithm::AssetId& Asset, const Mediator::DynamicWallet& Wallet, Option<String>&& Address)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				Coreturn ExpectsRT<Decimal>(RemoteException("asset not found"));

			auto Binding = Wallet.GetBinding();
			if (!Binding || Binding->empty())
				Coreturn ExpectsRT<Decimal>(RemoteException("binding not found"));

			if (Address && Stringify::IsEmptyOrWhitespace(*Address))
				Coreturn ExpectsRT<Decimal>(RemoteException("address not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				Coreturn ExpectsRT<Decimal>(RemoteException("chain not found"));

			Coreturn Coawait(Implementation->CalculateBalance(Asset, Wallet, std::move(Address)));
		}
		ExpectsLR<Mediator::MasterWallet> ServerNode::NewMasterWallet(const Algorithm::AssetId& Asset, const std::string_view& SeedingKey)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<Mediator::MasterWallet>(LayerException("asset not found"));

			String Seed = Format::Util::IsHexEncoding(SeedingKey) ? Codec::HexDecode(SeedingKey) : String(SeedingKey);
			if (Seed.empty())
				return ExpectsLR<Mediator::MasterWallet>(LayerException("seed not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<Mediator::MasterWallet>(LayerException("chain not found"));

			auto Result = Implementation->NewMasterWallet(Seed);
			if (Result)
			{
				Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
				auto Status = State.AddMasterWallet(*Result);
				if (!Status)
					return Status.Error();
			}
			return Result;
		}
		ExpectsLR<Mediator::MasterWallet> ServerNode::NewMasterWallet(const Algorithm::AssetId& Asset, const Algorithm::Seckey PrivateKey)
		{
			Format::Stream Message;
			Message.WriteInteger(Asset);
			Message.WriteString(*Crypto::HashRaw(Digests::SHA512(), std::string_view((char*)PrivateKey, sizeof(Algorithm::Seckey))));
			return NewMasterWallet(Asset, *Crypto::HashRaw(Digests::SHA512(), Message.Data));
		}
		ExpectsLR<Mediator::DerivedSigningWallet> ServerNode::NewSigningWallet(const Algorithm::AssetId& Asset, const Mediator::MasterWallet& Wallet, Option<uint64_t>&& AddressIndex)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("asset not found"));

			if (!Wallet.IsValid())
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("wallet not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("chain not found"));

			if (AddressIndex)
			{
				Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
				auto Result = State.GetDerivedWallet(Wallet.AsHash(), *AddressIndex);
				if (Result)
					return Result;
			}
			else
				AddressIndex = Wallet.MaxAddressIndex + 1;

			auto Result = Implementation->NewSigningWallet(Asset, Wallet, *AddressIndex);
			if (!Result || *AddressIndex <= Wallet.MaxAddressIndex)
				return Result;

			auto WalletCopy = Wallet;
			WalletCopy.MaxAddressIndex = *AddressIndex;

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			auto Status = State.AddDerivedWallet(WalletCopy, *Result);
			if (!Status)
				return Status.Error();

			return Result;
		}
		ExpectsLR<Mediator::DerivedSigningWallet> ServerNode::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKeyKey)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("asset not found"));

			if (SigningKeyKey.empty())
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("key not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<Mediator::DerivedSigningWallet>(LayerException("chain not found"));

			return Implementation->NewSigningWallet(Asset, SigningKeyKey);
		}
		ExpectsLR<Mediator::DerivedVerifyingWallet> ServerNode::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<Mediator::DerivedVerifyingWallet>(LayerException("asset not found"));

			if (VerifyingKey.empty())
				return ExpectsLR<Mediator::DerivedVerifyingWallet>(LayerException("key not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<Mediator::DerivedVerifyingWallet>(LayerException("chain not found"));

			return Implementation->NewVerifyingWallet(Asset, VerifyingKey);
		}
		ExpectsLR<String> ServerNode::NewPublicKeyHash(const Algorithm::AssetId& Asset, const std::string_view& Address)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<String>(LayerException("asset not found"));

			if (Address.empty())
				return ExpectsLR<String>(LayerException("address not found"));

			if (Format::Util::IsHexEncoding(Address))
				return ExpectsLR<String>(Codec::HexDecode(Address));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<String>(LayerException("chain not found"));

			return Implementation->NewPublicKeyHash(Address);
		}
		ExpectsLR<String> ServerNode::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<String>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<String>(LayerException("chain not found"));

			return Implementation->SignMessage(Asset, Message, SigningKey);
		}
		ExpectsLR<void> ServerNode::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			bool IsMessageHex = Format::Util::IsHexEncoding(Message);
			String MessageData1 = IsMessageHex ? Format::Util::Decode0xHex(Message) : String(Message);
			String MessageData2 = IsMessageHex ? String(Message) : Format::Util::Encode0xHex(Message);

			if (Format::Util::IsHexEncoding(Signature))
			{
				String SignatureData = Format::Util::Decode0xHex(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}

			if (Format::Util::IsBase64Encoding(Signature))
			{
				String SignatureData = Codec::Base64Decode(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}

			if (Format::Util::IsBase64URLEncoding(Signature))
			{
				String SignatureData = Codec::Base64URLDecode(Signature);
				auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, SignatureData);
				if (Status)
					return Status;

				Status = Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, SignatureData);
				if (Status)
					return Status;
			}

			auto Status = Implementation->VerifyMessage(Asset, MessageData1, VerifyingKey, Signature);
			if (Status)
				return Status;

			return Implementation->VerifyMessage(Asset, MessageData2, VerifyingKey, Signature);
		}
		ExpectsLR<void> ServerNode::EnableCheckpointHeight(const Algorithm::AssetId& Asset, uint64_t BlockHeight)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.SetProperty("tip_override", Var::Set::Integer(BlockHeight));
		}
		ExpectsLR<void> ServerNode::EnableContractAddress(const Algorithm::AssetId& Asset, const std::string_view& ContractAddress)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			if (ContractAddress.empty())
				return ExpectsLR<void>(LayerException("contract address not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			auto Key = "contract_address:" + Algorithm::Asset::TokenOf(Asset);
			auto Value = State.GetProperty(Key);
			if (!Value)
				Value = Var::Set::Array();

			UnorderedSet<String> Addresses;
			for (auto& Item : Value->GetChilds())
				Addresses.insert(Item->Value.GetBlob());

			auto Address = Implementation->GetChecksumHash(ContractAddress);
			if (Addresses.find(Address) != Addresses.end())
				return Expectation::Met;

			Value->Push(Var::Set::String(Address));
			return State.SetProperty(Key, *Value);
		}
		ExpectsLR<void> ServerNode::EnableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Binding, const std::string_view& Address, uint64_t AddressIndex)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			if (Stringify::IsEmptyOrWhitespace(Address))
				return ExpectsLR<void>(LayerException("address not found"));

			if (Binding.empty())
				return ExpectsLR<void>(LayerException("binding not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			String CanonicalAddress = Implementation->GetChecksumHash(Address);
			auto CandidateAddressIndex = State.GetAddressIndex(CanonicalAddress);
			if (!CandidateAddressIndex)
			{
				Mediator::IndexAddress NewAddressIndex;
				NewAddressIndex.Binding = Binding;
				NewAddressIndex.Address = Address;
				NewAddressIndex.AddressIndex = AddressIndex;

				auto Status = State.SetAddressIndex(CanonicalAddress, NewAddressIndex);
				if (!Status)
					return Status;
				goto Degrade;
			}
			else if (!CandidateAddressIndex->AddressIndex || AddressIndex != *CandidateAddressIndex->AddressIndex)
			{
				CandidateAddressIndex->AddressIndex = AddressIndex;
				auto Status = State.SetAddressIndex(CanonicalAddress, *CandidateAddressIndex);
				if (!Status)
					return Status;
				goto Degrade;
			}

			return Expectation::Met;
		Degrade:
			auto BlockHeight = GetLatestKnownBlockHeight(Asset);
			if (!BlockHeight || !*BlockHeight)
				return Expectation::Met;

			uint64_t Latency = Implementation->GetChainparams().SyncLatency * Protocol::Now().User.NSS.BlockReplayMultiplier;
			if (Latency > 0)
				EnableCheckpointHeight(Asset, Latency >= *BlockHeight ? 1 : *BlockHeight - Latency);

			return Expectation::Met;
		}
		ExpectsLR<void> ServerNode::DisableWalletAddress(const Algorithm::AssetId& Asset, const std::string_view& Address)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<void>(LayerException("asset not found"));

			if (Stringify::IsEmptyOrWhitespace(Address))
				return ExpectsLR<void>(LayerException("address not found"));

			auto* Implementation = GetChain(Asset);
			if (!Implementation)
				return ExpectsLR<void>(LayerException("chain not found"));

			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			String CanonicalAddress = Implementation->GetChecksumHash(Address);
			return State.ClearAddressIndex(CanonicalAddress);
		}
		ExpectsLR<uint64_t> ServerNode::GetLatestKnownBlockHeight(const Algorithm::AssetId& Asset)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return ExpectsLR<uint64_t>(LayerException("asset not found"));

			uint64_t BlockHeight = 0;
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			auto LatestBlockHeight = UPtr<Schema>(State.GetProperty("tip_latest"));
			if (LatestBlockHeight)
			{
				uint64_t PossibleBlockHeight = (uint64_t)LatestBlockHeight->Value.GetInteger();
				if (PossibleBlockHeight > BlockHeight)
					BlockHeight = PossibleBlockHeight;
			}

			auto CheckpointBlockHeight = UPtr<Schema>(State.GetProperty("tip_checkpoint"));
			if (CheckpointBlockHeight)
			{
				uint64_t PossibleBlockHeight = (uint64_t)CheckpointBlockHeight->Value.GetInteger();
				if (PossibleBlockHeight > BlockHeight)
					BlockHeight = PossibleBlockHeight;
			}

			if (!BlockHeight)
				return ExpectsLR<uint64_t>(LayerException("block not found"));

			return ExpectsLR<uint64_t>(BlockHeight);
		}
		ExpectsLR<Mediator::IndexAddress> ServerNode::GetAddressIndex(const Algorithm::AssetId& Asset, const std::string_view& Address)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetAddressIndex(Address);
		}
		ExpectsLR<UnorderedMap<String, Mediator::IndexAddress>> ServerNode::GetAddressIndices(const Algorithm::AssetId& Asset, const UnorderedSet<String>& Addresses)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetAddressIndices(Addresses);
		}
		ExpectsLR<Vector<String>> ServerNode::GetAddressIndices(const Algorithm::AssetId& Asset)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetAddressIndices();
		}
		ExpectsLR<void> ServerNode::AddUTXO(const Algorithm::AssetId& Asset, const Mediator::IndexUTXO& Value)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.AddUTXO(Value);
		}
		ExpectsLR<void> ServerNode::RemoveUTXO(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.RemoveUTXO(TransactionId, Index);
		}
		ExpectsLR<Mediator::IndexUTXO> ServerNode::GetUTXO(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetUTXO(TransactionId, Index);
		}
		ExpectsLR<Vector<Mediator::IndexUTXO>> ServerNode::GetUTXOs(const Algorithm::AssetId& Asset, const std::string_view& Binding, size_t Offset, size_t Count)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetUTXOs(Binding, Offset, Count);
		}
		ExpectsLR<Schema*> ServerNode::LoadCache(const Algorithm::AssetId& Asset, Mediator::CachePolicy Policy, const std::string_view& Key)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.GetCache(Policy, Key);
		}
		ExpectsLR<void> ServerNode::StoreCache(const Algorithm::AssetId& Asset, Mediator::CachePolicy Policy, const std::string_view& Key, UPtr<Schema>&& Value)
		{
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			return State.SetCache(Policy, Key, std::move(Value));
		}
		Option<String> ServerNode::GetContractAddress(const Algorithm::AssetId& Asset)
		{
			if (!Algorithm::Asset::IsValid(Asset))
				return Optional::None;

			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			auto Token = Algorithm::Asset::TokenOf(Asset);
			Storages::Mediatorstate State = Storages::Mediatorstate(__func__, Asset);
			auto Value = UPtr<Schema>(State.GetProperty("contract_address:" + Token));
			if (!Value || Value->Empty())
				return Optional::None;

			auto TargetChecksum = Algorithm::Asset::ChecksumOf(Asset);
			for (auto& Item : Value->GetChilds())
			{
				auto CandidateAddress = Item->Value.GetBlob();
				auto CandidateChecksum = Algorithm::Asset::ChecksumOf(Algorithm::Asset::IdOf(Blockchain, Token, CandidateAddress));
				if (CandidateChecksum == TargetChecksum)
					return CandidateAddress;
			}

			return Value->Get(0)->Value.GetBlob();
		}
		UnorderedMap<Algorithm::AssetId, Mediator::RelayBackend::Chainparams> ServerNode::GetChains()
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			UnorderedMap<Algorithm::AssetId, Mediator::RelayBackend::Chainparams> Result;
			Result.reserve(Chains.size());
			for (auto& Next : Chains)
				Result[Algorithm::Asset::IdOf(Next.first)] = Next.second->GetChainparams();
			return Result;
		}
		UnorderedMap<String, Mediator::MasterWallet> ServerNode::GetWallets(const Algorithm::Seckey PrivateKey)
		{
			UnorderedMap<String, Mediator::MasterWallet> Wallets;
			for (auto& Chain : GetAssets())
			{
				auto Wallet = NewMasterWallet(Chain, PrivateKey);
				if (Wallet)
					Wallets[Algorithm::Asset::HandleOf(Chain)] = std::move(*Wallet);
			}
			return Wallets;
		}
		UnorderedMap<String, InvocationCallback>& ServerNode::GetRegistrations()
		{
			if (!Registrations.empty())
				return Registrations;

			Registrations =
			{
				{ "ARB", Chain<Mediator::Backends::Arbitrum>(this) },
				{ "AVAX", Chain<Mediator::Backends::Avalanche>(this) },
				{ "BTC", Chain<Mediator::Backends::Bitcoin>(this) },
				{ "BCH", Chain<Mediator::Backends::BitcoinCash>(this) },
				{ "BTG", Chain<Mediator::Backends::BitcoinGold>(this) },
				{ "BSC", Chain<Mediator::Backends::BinanceSmartChain>(this) },
				{ "BSV", Chain<Mediator::Backends::BitcoinSV>(this) },
				{ "ADA", Chain<Mediator::Backends::Cardano>(this) },
				{ "CELO", Chain<Mediator::Backends::Celo>(this) },
				{ "DASH", Chain<Mediator::Backends::Dash>(this) },
				{ "DGB", Chain<Mediator::Backends::Digibyte>(this) },
				{ "DOGE", Chain<Mediator::Backends::Dogecoin>(this) },
				{ "ETH", Chain<Mediator::Backends::Ethereum>(this) },
				{ "ETC", Chain<Mediator::Backends::EthereumClassic>(this) },
				{ "FTM", Chain<Mediator::Backends::Fantom>(this) },
				{ "FUSE", Chain<Mediator::Backends::Fuse>(this) },
				{ "ONE", Chain<Mediator::Backends::Harmony>(this) },
				{ "LTC", Chain<Mediator::Backends::Litecoin>(this) },
				{ "GLMR", Chain<Mediator::Backends::Moonbeam>(this) },
				{ "OP", Chain<Mediator::Backends::Optimism>(this) },
				{ "MATIC", Chain<Mediator::Backends::Polygon>(this) },
				{ "XRP", Chain<Mediator::Backends::Ripple>(this) },
				{ "XEC", Chain<Mediator::Backends::ECash>(this) },
				{ "RIF", Chain<Mediator::Backends::Rootstock>(this) },
				{ "SOL", Chain<Mediator::Backends::Solana>(this) },
				{ "XLM", Chain<Mediator::Backends::Stellar>(this) },
				{ "TRX", Chain<Mediator::Backends::Tron>(this) },
				{ "ZEC", Chain<Mediator::Backends::ZCash>(this) },
			};
			return Registrations;
		}
		Vector<Algorithm::AssetId> ServerNode::GetAssets(bool ObservingOnly)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			Vector<Algorithm::AssetId> Currencies;
			if (ObservingOnly)
			{
				Currencies.reserve(Nodes.size());
				for (auto& Node : Nodes)
					Currencies.push_back(Algorithm::Asset::IdOf(Node.first));
			}
			else
			{
				Currencies.reserve(Chains.size());
				for (auto& Next : Chains)
					Currencies.push_back(Algorithm::Asset::IdOf(Next.first));
			}
			return Currencies;
		}
		Vector<UPtr<Mediator::ServerRelay>>* ServerNode::GetNodes(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto It = Nodes.find(Algorithm::Asset::BlockchainOf(Asset));
			if (It == Nodes.end() || It->second.empty())
				return nullptr;

			return &It->second;
		}
		const Mediator::RelayBackend::Chainparams* ServerNode::GetChainparams(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto It = Chains.find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Chains.end())
			{
				auto& Params = It->second->GetChainparams();
				return &Params;
			}

			return nullptr;
		}
		Mediator::ServerRelay* ServerNode::AddNode(const Algorithm::AssetId& Asset, const std::string_view& URL, double Throttling)
		{
			Mediator::ServerRelay* Instance = new Mediator::ServerRelay(URL, Throttling);
			AddNodeInstance(Asset, Instance);
			return Instance;
		}
		Mediator::ServerRelay* ServerNode::GetNode(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto It = Nodes.find(Algorithm::Asset::BlockchainOf(Asset));
			if (It == Nodes.end() || It->second.empty())
				return nullptr;

			if (It->second.size() == 1)
				return *It->second.front();

			size_t Index = ((size_t)Math<size_t>::Random()) % It->second.size();
			return *It->second[Index];
		}
		Mediator::RelayBackend* ServerNode::GetChain(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto It = Chains.find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Chains.end())
				return *It->second;

			return nullptr;
		}
		Schema* ServerNode::AddSpecifications(const Algorithm::AssetId& Asset, UPtr<Schema>&& Value)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto& Instance = Specifications[Algorithm::Asset::BlockchainOf(Asset)];
			Instance = std::move(Value);
			return *Instance;
		}
		Schema* ServerNode::GetSpecifications(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto It = Specifications.find(Algorithm::Asset::BlockchainOf(Asset));
			if (It != Specifications.end())
				return *It->second;

			return nullptr;
		}
		ServiceControl::ServiceNode ServerNode::GetEntrypoint()
		{
			if (!Protocol::Now().User.NSS.Server)
				return ServiceControl::ServiceNode();

			ServiceControl::ServiceNode Entrypoint;
			Entrypoint.Startup = std::bind(&ServerNode::Startup, this);
			Entrypoint.Shutdown = std::bind(&ServerNode::Shutdown, this);
			return Entrypoint;
		}
		Mediator::MultichainSupervisorOptions& ServerNode::GetOptions()
		{
			return Options;
		}
		SystemControl& ServerNode::GetControl()
		{
			return ControlSys;
		}
		void ServerNode::AddTransactionCallback(const std::string_view& Name, TransactionCallback&& Callback)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (Callback)
				Callbacks[String(Name)] = std::move(Callback);
			else
				Callbacks.erase(String(Name));
		}
		void ServerNode::AddNodeInstance(const Algorithm::AssetId& Asset, Mediator::ServerRelay* Instance)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			Nodes[Algorithm::Asset::BlockchainOf(Asset)].push_back(Instance);
		}
		void ServerNode::AddChainInstance(const Algorithm::AssetId& Asset, Mediator::RelayBackend* Instance)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			Chains[Algorithm::Asset::BlockchainOf(Asset)] = Instance;
		}
		void ServerNode::DispatchTransactionQueue(TransactionQueueState* State, TransactionParams* FromParams)
		{
			if (!ControlSys.Enqueue())
				return;

			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			if (State->IsBusy && FromParams != nullptr)
			{
				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s transaction 0x%p queued (position: %i)", State->Blockchain.c_str(), FromParams, (int)State->Transactions);

				++State->Transactions;
				ControlSys.Dequeue();
				return;
			}
			else if (State->Queue.empty())
			{
				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s transaction queue emptied (dispatches: %i)", State->Blockchain.c_str(), (int)State->Transactions);

				State->Transactions = 0;
				State->IsBusy = false;
				ControlSys.Dequeue();
				return;
			}
			else if (FromParams != nullptr)
				++State->Transactions;

			auto* Params = State->Queue.front();
			State->IsBusy = true;
			State->Queue.pop();

			if (Protocol::Now().User.NSS.Logging)
				VI_INFO("[observer] %s transaction 0x%p now dispatching (position: %i)", State->Blockchain.c_str(), Params, (int)(State->Transactions - State->Queue.size() - 1));

			Coasync<void>([this, State, Params]() -> Promise<void>
			{
				auto SignedTransaction = Coawait(NewTransaction(Params->Asset, Params->Wallet, Params->To, std::move(Params->Fee)));
				if (!SignedTransaction)
				{
					if (Protocol::Now().User.NSS.Logging)
						VI_ERR("[observer] %s transaction 0x%p sign failed (%s)", State->Blockchain.c_str(), Params, SignedTransaction.Error().what());

					FinalizeTransaction(State, Params, std::move(SignedTransaction));
					ControlSys.Dequeue();
					CoreturnVoid;
				}

				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s transaction 0x%p signed (sighash: %s, data: %s)",
					State->Blockchain.c_str(),
					Params,
					SignedTransaction->Transaction.TransactionId.c_str(),
					SignedTransaction->Data.c_str());

				auto Status = Coawait(BroadcastTransaction(Params->Asset, Params->ExternalId, *SignedTransaction));
				if (!Status)
				{
					if (Protocol::Now().User.NSS.Logging)
						VI_ERR("[observer] %s transaction 0x%p broadcast failed (%s)", State->Blockchain.c_str(), Params, Status.Error().what());

					FinalizeTransaction(State, Params, Status.Error());
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s transaction 0x%p broadcasted", State->Blockchain.c_str(), Params, SignedTransaction->Transaction.TransactionId.c_str());

				FinalizeTransaction(State, Params, std::move(SignedTransaction));
				ControlSys.Dequeue();
				CoreturnVoid;
			}, true);
		}
		void ServerNode::FinalizeTransaction(TransactionQueueState* State, UPtr<TransactionParams>&& Params, ExpectsRT<Mediator::OutgoingTransaction>&& Transaction)
		{
			if (Protocol::Now().User.NSS.Logging)
				VI_INFO("[observer] %s transaction 0x%p finalized (position: %i)", State->Blockchain.c_str(), *Params, (int)(State->Transactions - State->Queue.size() - 1));

			Params->Future.Set(std::move(Transaction));
			DispatchTransactionQueue(State, nullptr);
		}
		bool ServerNode::CallTransactionListener(TransactionListener* Listener)
		{
			if (Listener->Options.IsCancelled(Listener->Asset) || !ControlSys.Enqueue())
			{
				Listener->IsDead = true;
				return false;
			}
			else if (Listener->CooldownId != INVALID_TASK_ID)
			{
				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s server data collection: re-queued", Algorithm::Asset::HandleOf(Listener->Asset).c_str());
				Listener->CooldownId = INVALID_TASK_ID;
			}
			else if (Listener->IsDryRun)
			{
				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s server data collection: queued", Algorithm::Asset::HandleOf(Listener->Asset).c_str());
				Listener->IsDryRun = false;
			}
			else if (Listener->Options.WillWaitForTransactions())
			{
				if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s server data collection: waiting for updates in %is (total: %is)",
					Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
					(int)(Listener->Options.PollingFrequencyMs / 1000),
					(int)(Listener->Options.State.LatestTimeAwaited / 1000));
				Listener->Options.State.LatestTimeAwaited = 0;
			}

			Coasync<void>([this, Listener]() -> Promise<void>
			{
				auto Info = Coawait(GetTransactionLogs(Listener->Asset, &Listener->Options));
				if (!Info)
				{
					if (Info.Error().retry())
					{
						if (Protocol::Now().User.NSS.Logging)
							VI_INFO("[observer] %s server data collection: finalized", Algorithm::Asset::HandleOf(Listener->Asset).c_str());

						CallTransactionListener(Listener);
						ControlSys.Dequeue();
						CoreturnVoid;
					}

					UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
					if (ControlSys.IsActive() && !Listener->Options.IsCancelled(Listener->Asset))
					{
						Listener->CooldownId = Schedule::Get()->SetTimeout(Options.RetryWaitingTimeMs, [this, Listener]() { CallTransactionListener(Listener); });
						if (Protocol::Now().User.NSS.Logging)
							VI_ERR("[observer] %s server data collection: waiting for connection (%s)", Algorithm::Asset::HandleOf(Listener->Asset).c_str(), Info.Error().what());
					}
					else
						Listener->IsDead = true;
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Info->Transactions.empty())
				{
					if (!Info->BlockHash.empty())
					{
						if (Protocol::Now().User.NSS.Logging)
							VI_INFO("[observer] %s block %s accepted (height: %i, progress: %.2f%%, txns: 0)",
							Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
							Info->BlockHash.c_str(),
							(int)Info->BlockHeight,
							Listener->Options.GetCheckpointPercentage());
					}

					for (auto& Item : Callbacks)
						Coawait(Item.second(Listener->Options, std::move(*Info)));

					CallTransactionListener(Listener);
					ControlSys.Dequeue();
					CoreturnVoid;
				}
				else if (Protocol::Now().User.NSS.Logging)
					VI_INFO("[observer] %s block %s accepted (height: %i, progress: %.2f%%, txns: %i)",
					Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
					Info->BlockHash.c_str(),
					(int)Info->BlockHeight,
					Listener->Options.GetCheckpointPercentage(),
					(int)Info->Transactions.size());

				if (Protocol::Now().User.NSS.Logging)
				{
					for (auto& Tx : Info->Transactions)
					{
						auto Chain = GetChain(Tx.Asset);
						String TransferLogs = Stringify::Text(
							"%s transaction %s accepted (status: %s, cost: %s %s)\n",
							Algorithm::Asset::HandleOf(Listener->Asset).c_str(),
							Tx.TransactionId.c_str(), Tx.IsApproved() ? "confirmation" : "pending",
							Tx.Fee.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str());

						if (!Tx.IsApproved() || (Chain && !Chain->GetChainparams().SyncLatency))
						{
							for (auto& Item : Tx.From)
							{
								TransferLogs += Stringify::Text("  <== %s spends %s %s%s%s%s\n",
									Item.Address.empty() ? "coinbase" : Item.Address.c_str(), Item.Value.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str(),
									Item.AddressIndex ? " (index: " : "", Item.AddressIndex ? ToString(*Item.AddressIndex).c_str() : "", Item.AddressIndex ? ", status: spent)" : "");
							}
							for (auto& Item : Tx.To)
							{
								TransferLogs += Stringify::Text("  ==> %s receives %s %s%s%s%s\n",
									Item.Address.empty() ? "reward" : Item.Address.c_str(), Item.Value.ToString().c_str(), Algorithm::Asset::HandleOf(Tx.Asset).c_str(),
									Item.AddressIndex ? " (index: " : "", Item.AddressIndex ? ToString(*Item.AddressIndex).c_str() : "", Item.AddressIndex ? ", status: unspent)" : "");
							}
						}

						if (TransferLogs.back() == '\n')
							TransferLogs.erase(TransferLogs.end() - 1);

						VI_INFO("[observer] %s", TransferLogs.c_str());
					}
				}

				for (auto& Item : Callbacks)
					Coawait(Item.second(Listener->Options, std::move(*Info)));

				CallTransactionListener(Listener);
				ControlSys.Dequeue();
				CoreturnVoid;
			}, true);
			return true;
		}
		void ServerNode::Startup()
		{
			if (!Protocol::Now().User.NSS.Server)
				return;
			else if (!Options.RetryWaitingTimeMs || !ControlSys.ActivateAndEnqueue())
				return;

			if (Protocol::Now().User.NSS.Logging)
				VI_INFO("[nss] nss node startup");

			UnorderedSet<String> Blockchains;
			Blockchains.reserve(Nodes.size());
			for (auto& Implementation : Nodes)
				Blockchains.insert(Implementation.first);

			Listeners.reserve(Blockchains.size());
			for (auto& Blockchain : Blockchains)
			{
				TransactionListener* Listener = Memory::New<TransactionListener>();
				Listener->Asset = Algorithm::Asset::IdOf(Blockchain);
				Listeners.emplace_back(Listener);

				auto& Suboptions = *(Mediator::SupervisorOptions*)&Listener->Options;
				Suboptions = *(Mediator::SupervisorOptions*)&Options;

				auto It = Options.Specifics.find(Blockchain);
				if (It != Options.Specifics.end())
					Listener->Options = It->second;

				if (!CallTransactionListener(Listener))
				{
					ControlSys.Dequeue();
					return Shutdown();
				}

				Connections.insert(Algorithm::Asset::BlockchainOf(Listener->Asset));
			}
			ControlSys.Dequeue();
		}
		void ServerNode::Shutdown()
		{
			if (!ControlSys.Deactivate())
				return;

			if (Protocol::Now().User.NSS.Logging)
				VI_INFO("[nss] nss node shutdown requested");

			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			for (auto& Nodes : Nodes)
			{
				for (auto& Node : Nodes.second)
					Node->CancelActivities();
			}

			for (auto& Listener : Listeners)
			{
				if (Schedule::Get()->ClearTimeout(Listener->CooldownId))
					Listener->IsDead = true;
			}

			Unique.Unlock();
			ControlSys.Shutdown().Wait();
			Unique.Lock();

			for (auto& Nodes : Nodes)
			{
				for (auto& Node : Nodes.second)
					Node->AllowActivities();
			}
		}
		bool ServerNode::IsActive()
		{
			return ControlSys.IsActive();
		}
		bool ServerNode::HasNode(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto Target = Nodes.find(Algorithm::Asset::BlockchainOf(Asset));
			return Target != Nodes.end();
		}
		bool ServerNode::HasChain(const Algorithm::AssetId& Asset)
		{
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			auto Target = Chains.find(Algorithm::Asset::BlockchainOf(Asset));
			return Target != Chains.end();
		}
		bool ServerNode::HasObserver(const Algorithm::AssetId& Asset)
		{
			return GetChain(Asset) != nullptr && GetNode(Asset) != nullptr;
		}
		bool ServerNode::HasSupport(const Algorithm::AssetId& Asset)
		{
			if (!ControlSys.IsActive())
				return false;

			auto Blockchain = Algorithm::Asset::BlockchainOf(Asset);
			UMutex<std::recursive_mutex> Unique(ControlSys.Sync);
			return Connections.find(Blockchain) != Connections.end();
		}
	}
}