#include "stellar.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/chainparams.h"
#include "../internal/libbitcoin/ecc.h"
#include "../internal/libbitcoin/bip32.h"
extern "C"
{
#include "../internal/libstellar/stellar.h"
#include "../../internal/base32.h"
#include "../../internal/ed25519.h"
}
#include <sodium.h>

namespace Tangent
{
	namespace Mediator
	{
		namespace Backends
		{
			static void TxAppend(Vector<uint8_t>& Tx, const uint8_t* Data, size_t DataSize)
			{
				size_t Offset = Tx.size();
				Tx.resize(Tx.size() + DataSize);
				memcpy(&Tx[Offset], Data, DataSize);
			}
			static void TxAppendUint32(Vector<uint8_t>& Tx, uint32_t Data)
			{
				uint8_t Buffer[sizeof(uint32_t)];
				Buffer[0] = (uint8_t)((Data >> 24) & 0xFF);
				Buffer[1] = (uint8_t)((Data >> 16) & 0xFF);
				Buffer[2] = (uint8_t)((Data >> 8) & 0xFF);
				Buffer[3] = (uint8_t)((Data >> 0) & 0xFF);
				TxAppend(Tx, Buffer, sizeof(Buffer));
			}
			static void TxAppendUint64(Vector<uint8_t>& Tx, uint64_t Data)
			{
				uint8_t Buffer[sizeof(uint64_t)];
				Buffer[0] = (uint8_t)(Data >> 56);
				Buffer[1] = (uint8_t)(Data >> 48);
				Buffer[2] = (uint8_t)(Data >> 40);
				Buffer[3] = (uint8_t)(Data >> 32);
				Buffer[4] = (uint8_t)(Data >> 24);
				Buffer[5] = (uint8_t)(Data >> 16);
				Buffer[6] = (uint8_t)(Data >> 8);
				Buffer[7] = (uint8_t)(Data >> 0);
				TxAppend(Tx, Buffer, sizeof(Buffer));
			}
			static void TxAppendAddress(Vector<uint8_t>& Tx, const std::string_view& Data)
			{
				uint8_t PublicKey[STELLAR_KEY_SIZE];
				stellar_getAddressBytes((char*)String(Data).c_str(), PublicKey);
				TxAppendUint32(Tx, 0);
				TxAppend(Tx, PublicKey, sizeof(PublicKey));
			}
			static void TxAppendHash(Vector<uint8_t>& Tx, const std::string_view& Data)
			{
				String Hash = *Crypto::HashRaw(Digests::SHA256(), Data);
				TxAppend(Tx, (uint8_t*)Hash.data(), Hash.size());
			}
			static void TxAppendOpCreateAccount(Vector<uint8_t>& Tx, StellarCreateAccountOp& Data)
			{
				/* sourceAccount: */
				TxAppendUint32(Tx, 0);
				/* type: */
				TxAppendUint32(Tx, 0);
				/* destination: */
				TxAppendAddress(Tx, Data.new_account);
				/* startingBalance: */
				TxAppendUint64(Tx, (uint64_t)Data.starting_balance);
			}
			static void TxAppendOpPayment(Vector<uint8_t>& Tx, StellarPaymentOp& Data)
			{
				/* sourceAccount: */
				TxAppendUint32(Tx, 0);
				/* type: */
				TxAppendUint32(Tx, 1);
				/* destination: */
				TxAppendAddress(Tx, Data.destination_account);
				/* asset.type: */
				TxAppendUint32(Tx, Data.asset.type);
				/* asset.assetCode: */
				if (Data.asset.has_code)
					TxAppend(Tx, (uint8_t*)Data.asset.code, Data.asset.type == (uint32_t)Stellar::AssetType::ASSET_TYPE_CREDIT_ALPHANUM4 ? 4 : 12);
				/* asset.issuer: */
				if (Data.asset.has_issuer)
					TxAppendAddress(Tx, Data.asset.issuer);
				/* amount: */
				TxAppendUint64(Tx, (uint64_t)Data.amount);
			}
			static void TxAppendDecoratedSignature(Vector<uint8_t>& Tx, StellarSignedTx& Data)
			{
				/* hint: */
				TxAppend(Tx, Data.public_key.bytes + 28, 4);
				/* signature: */
				TxAppendUint32(Tx, Data.signature.size);
				TxAppend(Tx, Data.signature.bytes, 64);
			}
			static void TxAppendTransactionV0(Vector<uint8_t>& Tx, const StellarSignTx& Transaction, Vector<StellarCreateAccountOp>& Accounts, Vector<StellarPaymentOp>& Payments)
			{
				/* sourceAccountEd25519: */
				TxAppendAddress(Tx, Transaction.source_account);
				/* fee: */
				TxAppendUint32(Tx, Transaction.fee);
				/* seqNum: */
				TxAppendUint64(Tx, Transaction.sequence_number);
				/* timeBounds: */
				TxAppendUint32(Tx, 0);
				/* memo: */
				if (Transaction.memo_type == 2)
				{
					TxAppendUint32(Tx, Transaction.memo_type);
					TxAppendUint64(Tx, Transaction.memo_id);
				}
				else
					TxAppendUint32(Tx, 0);
				/* operations: */
				TxAppendUint32(Tx, Transaction.num_operations);
				for (auto& Item : Accounts)
					TxAppendOpCreateAccount(Tx, Item);
				for (auto& Item : Payments)
					TxAppendOpPayment(Tx, Item);
				/* ext: */
				TxAppendUint32(Tx, 0);
			}
			static void TxAppendTransactionSignaturePayload(Vector<uint8_t>& Tx, const StellarSignTx& Transaction, Vector<StellarCreateAccountOp>& Accounts, Vector<StellarPaymentOp>& Payments)
			{
				/* networkId: */
				TxAppendHash(Tx, Transaction.network_passphrase);
				/* type: (ENVELOPE_TYPE_TX) */
				TxAppendUint32(Tx, 2);
				/* tx: */
				TxAppendTransactionV0(Tx, Transaction, Accounts, Payments);
			}
			static void TxAppendTransactionV0Envelope(Vector<uint8_t>& Tx, const StellarSignTx& Transaction, Vector<StellarSignedTx>& Signatures, Vector<StellarCreateAccountOp>& Accounts, Vector<StellarPaymentOp>& Payments)
			{
				/* tx: */
				TxAppendTransactionV0(Tx, Transaction, Accounts, Payments);
				/* signatures: */
				TxAppendUint32(Tx, (uint32_t)Signatures.size());
				for (auto& Item : Signatures)
					TxAppendDecoratedSignature(Tx, Item);
			}
			static Vector<uint8_t> TxDataFromSignature(const StellarSignTx& Transaction, Vector<StellarCreateAccountOp>& Accounts, Vector<StellarPaymentOp>& Payments)
			{
				Vector<uint8_t> Tx;
				Tx.reserve(8192);
				TxAppendTransactionSignaturePayload(Tx, Transaction, Accounts, Payments);

				String Hash = *Crypto::HashRaw(Digests::SHA256(), String((char*)Tx.data(), Tx.size()));
				Tx.resize(Hash.size());
				memcpy(Tx.data(), Hash.data(), Hash.size());
				return Tx;
			}
			static Vector<uint8_t> TxDataFromEnvelope(const StellarSignTx& Transaction, Vector<StellarSignedTx>& Signatures, Vector<StellarCreateAccountOp>& Accounts, Vector<StellarPaymentOp>& Payments)
			{
				Vector<uint8_t> Tx; Tx.reserve(8192);
				TxAppendTransactionV0Envelope(Tx, Transaction, Signatures, Accounts, Payments);
				return Tx;
			}

			String Stellar::NdCall::GetLedger(uint64_t BlockHeight)
			{
				return Stringify::Text("/ledgers/%" PRIu64, (uint64_t)BlockHeight);
			}
			String Stellar::NdCall::GetLedgerOperations(uint64_t BlockHeight)
			{
				return Stringify::Text("/ledgers/%" PRIu64 "/operations?include_failed=false", (uint64_t)BlockHeight);
			}
			String Stellar::NdCall::GetOperations(const std::string_view& TxId)
			{
				return Stringify::Text("/transactions/%.*s/operations?include_failed=false", (int)TxId.size(), TxId.data());
			}
			String Stellar::NdCall::GetTransactions(const std::string_view& TxId)
			{
				return Stringify::Text("/transactions/%" PRIu64, (int)TxId.size(), TxId.data());
			}
			String Stellar::NdCall::GetAccounts(const std::string_view& Address)
			{
				return Stringify::Text("/accounts/%" PRIu64, (int)Address.size(), Address.data());
			}
			String Stellar::NdCall::GetAssets(const std::string_view& Issuer, const std::string_view& Code)
			{
				return Stringify::Text("/assets?asset_isser=%.*s&asset_code=%" PRIu64, (int)Issuer.size(), Issuer.data(), (int)Code.size(), Code.data());
			}
			const char* Stellar::NdCall::GetLastLedger()
			{
				return "/ledgers?order=desc&limit=1";
			}
			const char* Stellar::NdCall::SubmitTransaction()
			{
				return "/transactions";
			}

			Stellar::Stellar(ChainConfig* NewConfig) noexcept : RelayBackend()
			{
				if (NewConfig != nullptr)
					Config = *NewConfig;

				Netdata.Composition = Algorithm::Composition::Type::ED25519;
				Netdata.Routing = RoutingPolicy::Memo;
				Netdata.SyncLatency = 1;
				Netdata.Divisibility = Decimal(10000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer = "sac";
				Netdata.SupportsBulkTransfer = true;
			}
			ExpectsPromiseRT<Stellar::AssetInfo> Stellar::GetAssetInfo(const Algorithm::AssetId& Asset, const std::string_view& Address, const std::string_view& Code)
			{
				auto AssetData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetAssets(Address, Code), nullptr, CachePolicy::Persistent));
				if (!AssetData)
					Coreturn ExpectsRT<Stellar::AssetInfo>(std::move(AssetData.Error()));

				UPtr<Schema> AssetWrap = *AssetData;
				Schema* Records = AssetWrap->Fetch("_embedded.records");
				if (!Records)
					Coreturn ExpectsRT<Stellar::AssetInfo>(RemoteException("contract address not found"));

				for (auto& Asset : Records->GetChilds())
				{
					AssetInfo Info;
					Info.Code = Asset->GetVar("asset_code").GetBlob();
					Info.Issuer = Asset->GetVar("asset_isser").GetBlob();
					Info.Type = Asset->GetVar("asset_type").GetBlob();
					if (Info.Issuer == Address)
						Coreturn ExpectsRT<Stellar::AssetInfo>(std::move(Info));
				}

				Coreturn ExpectsRT<Stellar::AssetInfo>(RemoteException("contract address not found"));
			}
			ExpectsPromiseRT<Stellar::AccountInfo> Stellar::GetAccountInfo(const Algorithm::AssetId& Asset, const std::string_view& Address)
			{
				auto AccountData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetAccounts(Address), nullptr, CachePolicy::Lazy));
				if (!AccountData)
					Coreturn ExpectsRT<Stellar::AccountInfo>(std::move(AccountData.Error()));

				AccountInfo Info;
				Info.Sequence = AccountData->GetVar("sequence").GetInteger();
				if (AccountData->Has("balances"))
				{
					for (auto& Item : AccountData->Get("balances")->GetChilds())
					{
						AssetBalance Balance;
						Balance.Info.Type = Item->GetVar("asset_type").GetBlob();
						Balance.Info.Code = Item->GetVar("asset_code").GetBlob();
						Balance.Info.Issuer = Item->GetVar("asset_issuer").GetBlob();
						Balance.Balance = Item->GetVar("balance").GetDecimal();
						if (Balance.Info.Code.empty())
						{
							Balance.Info.Code = Algorithm::Asset::BlockchainOf(Asset);
							if (Balance.Info.Type != "native")
								continue;
						}
						Info.Balances[Balance.Info.Code] = Balance;
					}
				}

				Memory::Release(*AccountData);
				Coreturn ExpectsRT<Stellar::AccountInfo>(std::move(Info));
			}
			ExpectsPromiseRT<String> Stellar::GetTransactionMemo(const Algorithm::AssetId& Asset, const std::string_view& TxId)
			{
				auto TxData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetTransactions(Format::Util::Clear0xHex(TxId)), nullptr, CachePolicy::Shortened));
				if (!TxData)
					Coreturn ExpectsRT<String>(std::move(TxData.Error()));

				String Memo = TxData->GetVar("memo").GetBlob();
				if (Memo.empty())
					Coreturn ExpectsRT<String>(RemoteException("transaction memo not found"));

				Coreturn ExpectsRT<String>(std::move(Memo));
			}
			ExpectsPromiseRT<bool> Stellar::IsAccountExists(const Algorithm::AssetId& Asset, const std::string_view& Address)
			{
				auto AccountData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetAccounts(Address), nullptr, CachePolicy::Lazy));
				if (!AccountData && (AccountData.Error().retry() || AccountData.Error().shutdown()))
					Coreturn ExpectsRT<bool>(AccountData.Error());

				auto Account = UPtr<Schema>(AccountData.Or(nullptr));
				Coreturn ExpectsRT<bool>(Account && Account->Has("account_id"));
			}
			ExpectsPromiseRT<void> Stellar::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				UPtr<HTTP::Query> Args = new HTTP::Query();
				Args->Object->Set("tx", Var::String(TxData.Data));

				const char* Type = "application/x-www-form-urlencoded";
				String Body = Args->Encode(Type);
				auto HexData = Coawait(ExecuteHTTP(Asset, "POST", NdCall::SubmitTransaction(), Type, Body, CachePolicy::Greedy));
				if (!HexData)
					Coreturn ExpectsRT<void>(std::move(HexData.Error()));

				String Detail = HexData->GetVar("detail").GetBlob();
				if (!Detail.empty())
				{
					String Code = HexData->FetchVar("extras.result_codes.transaction").GetBlob();
					Coreturn ExpectsRT<void>(RemoteException(std::move(Code.empty() ? Detail : Code)));
				}

				Memory::Release(*HexData);
				Coreturn ExpectsRT<void>(Expectation::Met);
			}
			ExpectsPromiseRT<uint64_t> Stellar::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto LastBlockData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetLastLedger(), nullptr, CachePolicy::Lazy));
				if (!LastBlockData)
					Coreturn ExpectsRT<uint64_t>(std::move(LastBlockData.Error()));

				uint64_t BlockHeight = (uint64_t)LastBlockData->FetchVar("_embedded.records.0.sequence").GetInteger();
				Memory::Release(*LastBlockData);
				Coreturn ExpectsRT<uint64_t>(BlockHeight);
			}
			ExpectsPromiseRT<Schema*> Stellar::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				auto BlockData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetLedgerOperations(BlockHeight), nullptr, CachePolicy::Shortened));
				if (!BlockData)
					Coreturn ExpectsRT<Schema*>(std::move(BlockData.Error()));

				if (BlockHash != nullptr)
					*BlockHash = ToString(BlockHeight);

				Schema* Data = BlockData->Fetch("_embedded.records");
				if (!Data)
				{
					Memory::Release(*BlockData);
					Coreturn ExpectsRT<Schema*>(RemoteException("block not found"));
				}

				Data->Unlink();
				Memory::Release(*BlockData);
				Coreturn ExpectsRT<Schema*>(Data);
			}
			ExpectsPromiseRT<Schema*> Stellar::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				auto TxData = Coawait(ExecuteREST(Asset, "GET", NdCall::GetOperations(Format::Util::Clear0xHex(TransactionId)), nullptr, CachePolicy::Extended));
				Coreturn TxData;
			}
			ExpectsPromiseRT<Vector<IncomingTransaction>> Stellar::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				auto* Implementation = (Backends::Stellar*)NSS::ServerNode::Get()->GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsRT<Vector<IncomingTransaction>>(RemoteException("chain not found"));

				Algorithm::AssetId TokenAsset = Asset;
				String TxHash = TransactionData->GetVar("transaction_hash").GetBlob();
				String TxType = TransactionData->GetVar("type").GetBlob();
				Decimal FeeValue = Implementation->FromStroop(Implementation->GetBaseStroopFee());
				Decimal BaseValue = 0.0, TokenValue = 0.0;
				String From = String(), To = String();
				bool IsPayment = (TxType == "payment");
				bool IsCreateAccount = (!IsPayment && TxType == "create_account");
				bool IsNativeToken = (TransactionData->GetVar("asset_type").GetBlob() != "native");
				if (IsPayment)
				{
					From = TransactionData->GetVar("from").GetBlob();
					To = TransactionData->GetVar("to").GetBlob();
					TokenValue = TransactionData->GetVar("amount").GetDecimal();
					if (IsNativeToken)
					{
						String Token = TransactionData->GetVar("asset_code").GetBlob();
						String Issuer = TransactionData->GetVar("asset_issuer").GetBlob();
						TokenAsset = Algorithm::Asset::IdOf(Algorithm::Asset::BlockchainOf(Asset), Token, Issuer);
						if (!NSS::ServerNode::Get()->EnableContractAddress(TokenAsset, Issuer))
							Coreturn ExpectsRT<Vector<IncomingTransaction>>(RemoteException("tx not involved"));
					}
					else
					{
						BaseValue = TokenValue;
						TokenValue = 0.0;
					}
				}
				else if (IsCreateAccount)
				{
					From = TransactionData->GetVar("funder").GetBlob();
					To = TransactionData->GetVar("account").GetBlob();
					BaseValue = TransactionData->GetVar("starting_balance").GetDecimal();
				}

				auto Discovery = FindCheckpointAddresses(Asset, { From, To });
				if (!Discovery || Discovery->empty())
					Coreturn ExpectsRT<Vector<IncomingTransaction>>(RemoteException("tx not involved"));

				Option<uint64_t> ToAddressIndex = Optional::None;
				auto FromAddress = Discovery->find(From);
				auto ToAddress = Discovery->find(To);
				if (ToAddress != Discovery->end())
				{
					auto Memo = Coawait(GetTransactionMemo(Asset, TxHash));
					if (Memo && !Memo->empty())
						ToAddressIndex = FromString<uint64_t>(*Memo).Or(ToAddress->second);
					else
						ToAddressIndex = ToAddress->second;
				}

				Vector<IncomingTransaction> Transactions;
				if (FeeValue + BaseValue > 0.0)
				{
					IncomingTransaction Tx;
					Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, TxHash, std::move(FeeValue));
					Tx.SetOperations({ Transferer(From, FromAddress != Discovery->end() ? Option<uint64_t>(FromAddress->second) : Option<uint64_t>(Optional::None), Decimal(BaseValue)) }, { Transferer(To, ToAddressIndex ? Option<uint64_t>(*ToAddressIndex) : Option<uint64_t>(Optional::None), Decimal(BaseValue)) });
					Transactions.push_back(std::move(Tx));
				}
				if (TokenValue.IsPositive())
				{
					IncomingTransaction Tx;
					Tx.SetTransaction(TokenAsset, BlockHeight, TxHash, Decimal::Zero());
					Tx.SetOperations({ Transferer(From, FromAddress != Discovery->end() ? Option<uint64_t>(FromAddress->second) : Option<uint64_t>(Optional::None), Decimal(TokenValue)) }, { Transferer(To, ToAddressIndex ? Option<uint64_t>(*ToAddressIndex) : Option<uint64_t>(Optional::None), Decimal(TokenValue)) });
					Transactions.push_back(std::move(Tx));
				}
				Coreturn ExpectsRT<Vector<IncomingTransaction>>(std::move(Transactions));
			}
			ExpectsPromiseRT<BaseFee> Stellar::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				auto* Implementation = (Backends::Stellar*)NSS::ServerNode::Get()->GetChain(Asset);
				if (Algorithm::Asset::TokenOf(Asset).empty())
					Coreturn ExpectsRT<BaseFee>(BaseFee(Implementation->FromStroop(Implementation->GetBaseStroopFee() * To.size()), Decimal(1.0)));

				uint64_t Fee = Implementation->GetBaseStroopFee() * To.size();
				for (auto& Item : To)
				{
					auto Status = Coawait(IsAccountExists(Asset, Item.Address));
					if (!Status)
						Coreturn ExpectsRT<BaseFee>(Status.Error());
					else if (!*Status)
						Fee += Implementation->GetBaseStroopFee();
				}

				Coreturn ExpectsRT<BaseFee>(BaseFee(Implementation->FromStroop(Fee), Decimal(1.0)));
			}
			ExpectsPromiseRT<Decimal> Stellar::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
			{
				auto* Implementation = (Backends::Stellar*)NSS::ServerNode::Get()->GetChain(Asset);
				if (!Address)
				{
					ExpectsLR<DerivedVerifyingWallet> FromWallet = LayerException("signing wallet not found");
					if (Wallet.Parent)
					{
						auto SigningWallet = NSS::ServerNode::Get()->NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
						if (SigningWallet)
							FromWallet = *SigningWallet;
						else
							FromWallet = SigningWallet.Error();
					}
					else if (Wallet.VerifyingChild)
						FromWallet = *Wallet.VerifyingChild;
					else if (Wallet.SigningChild)
						FromWallet = *Wallet.SigningChild;
					if (!FromWallet)
						Coreturn ExpectsRT<Decimal>(RemoteException(std::move(FromWallet.Error().message())));

					Address = FromWallet->Addresses.begin()->second;
				}

				auto Account = Coawait(GetAccountInfo(Asset, *Address));
				if (!Account)
					Coreturn ExpectsRT<Decimal>(std::move(Account.Error()));

				auto Balance = Account->Balances.find(Algorithm::Asset::TokenOf(Asset));
				if (Balance == Account->Balances.end())
					Coreturn ExpectsRT<Decimal>(Decimal::Zero());

				auto ContractAddress = NSS::ServerNode::Get()->GetContractAddress(Asset);
				if (ContractAddress && Balance->second.Info.Issuer != *ContractAddress)
					Coreturn ExpectsRT<Decimal>(Decimal::Zero());

				Coreturn ExpectsRT<Decimal>(Balance->second.Balance);
			}
			ExpectsPromiseRT<OutgoingTransaction> Stellar::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> FromWallet = LayerException();
				if (Wallet.Parent)
					FromWallet = NSS::ServerNode::Get()->NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					FromWallet = *Wallet.SigningChild;
				if (!FromWallet)
					Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("signing wallet not found"));

				auto AccountInfo = Coawait(GetAccountInfo(Asset, FromWallet->Addresses.begin()->second));
				if (!AccountInfo)
					Coreturn ExpectsRT<OutgoingTransaction>(std::move(AccountInfo.Error()));

				auto& Params = GetParams();
				uint8_t DerivedPublicKey[256]; size_t DerivedPublicKeySize = sizeof(DerivedPublicKey);
				if (!DecodeKey(Params.Ed25519PublicKey, FromWallet->VerifyingKey, DerivedPublicKey, &DerivedPublicKeySize))
					Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("input private key invalid"));

				String Memo;
				for (auto& Item : To)
				{
					if (Item.AddressIndex)
					{
						if (Memo.empty())
							Memo = ToString(*Item.AddressIndex);
						else if (Memo != ToString(*Item.AddressIndex))
							Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("input memo invalid"));
					}
					else if (!Memo.empty())
						Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("input memo invalid"));
				}

				auto MemoId = FromString<uint64_t>(Memo);
				if (Memo.size() > 28 || (!Memo.empty() && !MemoId))
					Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("input memo invalid"));

				Vector<StellarCreateAccountOp> Accounts;
				Accounts.reserve(To.size());

				Vector<StellarPaymentOp> Payments;
				Payments.reserve(To.size());

				Decimal TotalValue = 0.0;
				auto Passphrase = GetNetworkPassphrase();
				auto ContractAddress = NSS::ServerNode::Get()->GetContractAddress(Asset);
				for (auto& Item : To)
				{
					auto Status = Coawait(IsAccountExists(Asset, Item.Address));
					if (!Status)
						Coreturn ExpectsRT<OutgoingTransaction>(Status.Error());

					TotalValue += Item.Value;
					if (!*Status)
					{
						StellarCreateAccountOp Account;
						memset(&Account, 0, sizeof(Account));
						strncpy(Account.new_account, Item.Address.c_str(), std::min<size_t>(sizeof(Account.new_account), Item.Address.size()));
						strncpy(Account.source_account, FromWallet->Addresses.begin()->second.c_str(), std::min<size_t>(sizeof(Account.source_account), FromWallet->Addresses.begin()->second.size()));
						Account.has_new_account = true;
						Account.has_source_account = true;
						Account.has_starting_balance = !ContractAddress;
						Account.starting_balance = Account.has_starting_balance ? (uint64_t)ToStroop(Item.Value) : 0;
						Accounts.push_back(Account);
						if (Account.has_starting_balance)
							continue;
					}

					StellarPaymentOp Payment;
					memset(&Payment, 0, sizeof(Payment));
					strncpy(Payment.destination_account, Item.Address.c_str(), std::min<size_t>(sizeof(Payment.destination_account), Item.Address.size()));
					strncpy(Payment.source_account, FromWallet->Addresses.begin()->second.c_str(), std::min<size_t>(sizeof(Payment.source_account), FromWallet->Addresses.begin()->second.size()));
					Payment.has_destination_account = true;
					Payment.has_source_account = true;
					Payment.has_amount = true;
					Payment.amount = (uint64_t)ToStroop(Item.Value);
					Payments.push_back(Payment);
				}

				StellarSignTx Transaction;
				memset(&Transaction, 0, sizeof(Transaction));
				strncpy(Transaction.source_account, FromWallet->Addresses.begin()->second.c_str(), std::min<size_t>(sizeof(Transaction.source_account), FromWallet->Addresses.begin()->second.size()));
				strncpy(Transaction.network_passphrase, Passphrase.c_str(), std::min<size_t>(sizeof(Transaction.network_passphrase), Passphrase.size()));
				Transaction.has_source_account = true;
				Transaction.has_network_passphrase = true;
				Transaction.has_sequence_number = true;
				Transaction.has_memo_type = true;
				Transaction.has_num_operations = true;
				Transaction.has_fee = true;
				Transaction.sequence_number = AccountInfo->Sequence + 1;
				Transaction.memo_type = Memo.empty() ? 0 : 2;
				Transaction.memo_id = MemoId.Or(0);
				Transaction.num_operations = (uint32_t)(Accounts.size() + Payments.size());
				Transaction.fee = (uint32_t)(Transaction.num_operations * GetBaseStroopFee());

				Decimal FeeValue = FromStroop(Transaction.fee);
				if (ContractAddress)
				{
					auto Native = AccountInfo->Balances.find(Algorithm::Asset::BlockchainOf(Asset));
					if (Native == AccountInfo->Balances.end() || Native->second.Balance < FeeValue)
						Coreturn ExpectsRT<OutgoingTransaction>(RemoteException(Stringify::Text("insufficient funds: %s < %s", (Native != AccountInfo->Balances.end() ? Native->second.Balance : Decimal(0.0)).ToString().c_str(), FeeValue.ToString().c_str())));
				}
				else
					TotalValue += FeeValue;

				auto Token = AccountInfo->Balances.find(ContractAddress ? Algorithm::Asset::TokenOf(Asset) : Algorithm::Asset::BlockchainOf(Asset));
				if (Token == AccountInfo->Balances.end() || Token->second.Balance < TotalValue)
					Coreturn ExpectsRT<OutgoingTransaction>(RemoteException(Stringify::Text("insufficient funds: %s < %s", (Token != AccountInfo->Balances.end() ? Token->second.Balance : Decimal(0.0)).ToString().c_str(), FeeValue.ToString().c_str())));

				StellarAssetType StellarAsset;
				memset(&StellarAsset, 0, sizeof(StellarAsset));
				if (ContractAddress)
				{
					strncpy(StellarAsset.code, Token->second.Info.Code.c_str(), std::min<size_t>(sizeof(StellarAsset.code), Token->second.Info.Code.size()));
					strncpy(StellarAsset.issuer, Token->second.Info.Issuer.c_str(), std::min<size_t>(sizeof(StellarAsset.issuer), Token->second.Info.Issuer.size()));
					if (Token->second.Info.Type == "credit_alphanum4")
						StellarAsset.type = (uint32_t)AssetType::ASSET_TYPE_CREDIT_ALPHANUM4;
					else if (Token->second.Info.Type == "credit_alphanum12")
						StellarAsset.type = (uint32_t)AssetType::ASSET_TYPE_CREDIT_ALPHANUM12;
					else
						Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("standard not supported"));
					StellarAsset.has_code = true;
					StellarAsset.has_issuer = true;
					StellarAsset.has_type = true;
				}
				else
				{
					StellarAsset.type = (uint32_t)AssetType::ASSET_TYPE_NATIVE;
					StellarAsset.has_code = false;
					StellarAsset.has_issuer = false;
					StellarAsset.has_type = true;
				}

				for (auto& Payment : Payments)
					Payment.asset = StellarAsset;

				String TransactionId;
				uint8_t Signature[crypto_sign_BYTES];
				{
					uint8_t DerivedPrivateKey[64];
					if (!DecodePrivateKey(FromWallet->SigningKey.ExposeToHeap(), DerivedPrivateKey))
						Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("private key invalid"));

					Vector<uint8_t> RawData = TxDataFromSignature(Transaction, Accounts, Payments);
					ed25519_signature Signature;
					ed25519_sign_ext((uint8_t*)&RawData[0], RawData.size(), DerivedPrivateKey, DerivedPrivateKey + 32, Signature);
					if (crypto_sign_verify_detached(Signature, (uint8_t*)&RawData[0], RawData.size(), DerivedPublicKey) != 0)
						Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("private key invalid"));

					TransactionId.assign((char*)RawData.data(), RawData.size());
					TransactionId = Codec::HexEncode(TransactionId);
				}

				Vector<StellarSignedTx> Signatures;
				{
					StellarSignedTx Sign;
					memset(&Sign, 0, sizeof(Sign));
					Sign.signature.size = (pb_size_t)std::min<size_t>(sizeof(Sign.signature.bytes), sizeof(Signature));
					Sign.public_key.size = (pb_size_t)std::min<size_t>(sizeof(Sign.public_key.bytes), DerivedPublicKeySize);
					memcpy(Sign.signature.bytes, Signature, Sign.signature.size);
					memcpy(Sign.public_key.bytes, DerivedPublicKey, Sign.public_key.size);
					Sign.has_public_key = true;
					Sign.has_signature = true;
					Signatures.push_back(std::move(Sign));
				}

				Vector<uint8_t> RawData = TxDataFromEnvelope(Transaction, Signatures, Accounts, Payments);
				String TransactionData = Codec::Base64Encode(std::string_view((char*)RawData.data(), RawData.size()));
				if (TransactionId.empty() || TransactionData.empty())
					Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("tx serialization error"));

				Decimal Value = ContractAddress ? TotalValue : TotalValue - FeeValue;
				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, TransactionId, std::move(FeeValue));
				Tx.SetOperations({ Transferer(FromWallet->Addresses.begin()->second, Option<uint64_t>(FromWallet->AddressIndex), std::move(Value)) }, Vector<Transferer>(To));
				Coreturn ExpectsRT<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData)));
			}
			ExpectsLR<MasterWallet> Stellar::NewMasterWallet(const std::string_view& Seed)
			{
				auto* Chain = GetChain();
				btc_hdnode RootNode;
				if (!btc_hdnode_from_seed((uint8_t*)Seed.data(), (int)Seed.size(), &RootNode))
					return ExpectsLR<MasterWallet>(LayerException("seed value invalid"));

				char PrivateKey[256];
				btc_hdnode_serialize_private(&RootNode, Chain, PrivateKey, sizeof(PrivateKey));

				char PublicKey[256];
				btc_hdnode_serialize_public(&RootNode, Chain, PublicKey, (int)sizeof(PublicKey));

				return ExpectsLR<MasterWallet>(MasterWallet(::PrivateKey(Codec::HexEncode(Seed)), ::PrivateKey(PrivateKey), PublicKey));
			}
			ExpectsLR<DerivedSigningWallet> Stellar::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				auto* Chain = GetChain();
				char DerivedPrivateKey[256];
				{
					auto Private = Wallet.SigningKey.Expose<KEY_LIMIT>();
					if (!hd_derive(Chain, Private.View.data(), GetDerivation(Protocol::Now().Account.RootAddressIndex).c_str(), DerivedPrivateKey, sizeof(DerivedPrivateKey)))
						return ExpectsLR<DerivedSigningWallet>(LayerException("input private key invalid"));
				}

				btc_hdnode Node;
				if (!btc_hdnode_deserialize(DerivedPrivateKey, Chain, &Node))
					return ExpectsLR<DerivedSigningWallet>(LayerException("input private key invalid"));

				auto Derived = NewSigningWallet(Asset, PrivateKey(std::string_view((char*)Node.private_key, sizeof(Node.private_key))));
				if (Derived)
					Derived->AddressIndex = AddressIndex;
				return Derived;
			}
			ExpectsLR<DerivedSigningWallet> Stellar::NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey)
			{
				uint8_t RawPrivateKey[64]; size_t RawPrivateKeySize = 0;
				if (SigningKey.Size() != 32 && SigningKey.Size() != 64)
				{
					auto Data = SigningKey.Expose<KEY_LIMIT>();
					if (!DecodePrivateKey(Data.View, RawPrivateKey))
					{
						if (!DecodeKey(GetParams().Ed25519SecretSeed, Data.View, RawPrivateKey, &RawPrivateKeySize) || RawPrivateKeySize != 32)
							return LayerException("bad private key");
					}
					else
						RawPrivateKeySize = 64;
				}
				else
				{
					RawPrivateKeySize = SigningKey.Size();
					SigningKey.ExposeToStack((char*)RawPrivateKey, RawPrivateKeySize);
				}

				uint8_t PrivateKey[64]; String SecretKey;
				if (RawPrivateKeySize == 32)
				{
					sha512_Raw(RawPrivateKey, RawPrivateKeySize, PrivateKey);
					Algorithm::Composition::ConvertToSecretKeyEd25519(PrivateKey);
					SecretKey = EncodeKey(GetParams().Ed25519SecretSeed, RawPrivateKey, RawPrivateKeySize);
				}
				else if (RawPrivateKeySize == 64)
					memcpy(PrivateKey, RawPrivateKey, RawPrivateKeySize);

				uint8_t PublicKey[32];
				ed25519_publickey_ext(PrivateKey, PublicKey);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicKey, sizeof(PublicKey)));
				if (!Derived)
					return Derived.Error();

				String DerivedPrivateKey = EncodePrivateKey(PrivateKey, sizeof(PrivateKey));
				if (!SecretKey.empty())
					DerivedPrivateKey.append(1, ':').append(SecretKey);
				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), ::PrivateKey(DerivedPrivateKey)));
			}
			ExpectsLR<DerivedVerifyingWallet> Stellar::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
			{
				String RawPublicKey = String(VerifyingKey);
				if (RawPublicKey.size() != 32)
				{
					uint8_t PublicKey[32]; size_t PublicKeySize = sizeof(PublicKey);
					if (!DecodeKey(GetParams().Ed25519PublicKey, RawPublicKey, PublicKey, &PublicKeySize) || PublicKeySize != sizeof(PublicKey))
						return LayerException("invalid public key");

					RawPublicKey = String((char*)PublicKey, sizeof(PublicKey));
				}

				String PublicKey = EncodeKey(GetParams().Ed25519PublicKey, (uint8_t*)RawPublicKey.data(), RawPublicKey.size());
				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, PublicKey } }, Optional::None, std::move(PublicKey)));
			}
			ExpectsLR<String> Stellar::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Data[128]; size_t DataSize = sizeof(Data);
				if (!DecodeKey(GetParams().Ed25519PublicKey, Address, Data, &DataSize))
					return LayerException("invalid address");

				return String((char*)Data, sizeof(Data));
			}
			ExpectsLR<String> Stellar::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
			{
				auto SigningWallet = NewSigningWallet(Asset, SigningKey);
				if (!SigningWallet)
					return SigningWallet.Error();

				uint8_t DerivedPrivateKey[64];
				auto Private = SigningWallet->SigningKey.Expose<KEY_LIMIT>();
				if (!DecodePrivateKey(Private.View, DerivedPrivateKey))
					return LayerException("private key invalid");

				ed25519_signature Signature;
				ed25519_sign_ext((uint8_t*)Message.data(), Message.size(), DerivedPrivateKey, DerivedPrivateKey + 32, Signature);
				return Codec::Base64Encode(std::string_view((char*)Signature, sizeof(Signature)));
			}
			ExpectsLR<void> Stellar::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
			{
				String SignatureData = Signature.size() == 64 ? String(Signature) : Codec::Base64Decode(Signature);
				if (SignatureData.size() != 64)
					return LayerException("signature not valid");

				auto VerifyingWallet = NewVerifyingWallet(Asset, VerifyingKey);
				if (!VerifyingWallet)
					return VerifyingWallet.Error();

				auto& Params = GetParams();
				uint8_t DerivedPublicKey[256]; size_t DerivedPublicKeySize = sizeof(DerivedPublicKey);
				if (!DecodeKey(Params.Ed25519PublicKey, VerifyingWallet->VerifyingKey, DerivedPublicKey, &DerivedPublicKeySize))
					return LayerException("public key invalid");

				if (crypto_sign_verify_detached((uint8_t*)SignatureData.data(), (uint8_t*)Message.data(), Message.size(), DerivedPublicKey) != 0)
					return LayerException("signature verification failed with used public key");

				return Expectation::Met;
			}
			String Stellar::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/148'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const Stellar::Chainparams& Stellar::GetChainparams() const
			{
				return Netdata;
			}
			String Stellar::GetNetworkPassphrase()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return "Standalone Network ; February 2017";
					case NetworkType::Testnet:
						return "Test SDF Network ; September 2015";
					case NetworkType::Mainnet:
						return "Public Global Stellar Network ; September 2015";
					default:
						VI_PANIC(false, "invalid network type");
						return String();
				}
			}
			Decimal Stellar::FromStroop(const uint256_t& Value)
			{
				return Decimal(Value.ToString()) / Netdata.Divisibility;
			}
			uint256_t Stellar::ToStroop(const Decimal& Value)
			{
				return uint256_t((Value * Netdata.Divisibility).Truncate(0).ToString());
			}
			uint64_t Stellar::GetBaseStroopFee()
			{
				return 100;
			}
			uint16_t Stellar::CalculateChecksum(const uint8_t* Value, size_t Size)
			{
				uint64_t Hash = 0x0; // CRC16 XMODEM
				for (size_t i = 0; i < Size; i++)
				{
					uint8_t Byte = Value[i];
					uint64_t Code = (Hash >> 8) & 0xff;
					Code ^= Byte & 0xff;
					Code ^= Code >> 4;
					Hash = (Hash << 8) & 0xffff;
					Hash ^= Code;
					Code = (Code << 5) & 0xffff;
					Hash ^= Code;
					Code = (Code << 7) & 0xffff;
					Hash ^= Code;
				}
				return (uint16_t)Hash;
			}
			String Stellar::EncodePrivateKey(uint8_t* PrivateKey, size_t PrivateKeySize)
			{
				return Codec::HexEncode(std::string_view((char*)PrivateKey, PrivateKeySize));
			}
			bool Stellar::DecodeKey(uint8_t Version, const std::string_view& Data, uint8_t* OutValue, size_t* OutSize)
			{
				Vector<uint8_t> Key(base32_decoded_length(Data.size()), 0);
				if (Key.size() < 3 || *OutSize < Key.size() - 3)
					return false;

				*OutSize = Key.size();
				if (!DecodeBase32(Data, &Key[0], OutSize))
					return false;

				uint8_t GivenVersion = Key[0];
				if (GivenVersion != Version)
					return false;

				uint16_t GivenChecksum = 0;
				uint16_t Checksum = CalculateChecksum(&Key[0], Key.size() - 2);
				memcpy(&GivenChecksum, &Key[Key.size() - 2], sizeof(uint8_t) * 2);
				if (GivenChecksum != Checksum)
					return false;

				*OutSize = Key.size() - 3;
				memcpy(OutValue, &Key[1], sizeof(uint8_t) * (*OutSize));
				return true;
			}
			bool Stellar::DecodeBase32(const std::string_view& Data, uint8_t* OutValue, size_t* OutSize)
			{
				size_t ExpectedSize = base32_decoded_length(Data.size());
				if (*OutSize < ExpectedSize)
					return false;

				*OutSize = ExpectedSize;
				return base32_decode(Data.data(), Data.size(), OutValue, *OutSize, BASE32_ALPHABET_RFC4648) != nullptr;
			}
			bool Stellar::DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[64])
			{
				auto Slice = Data.substr(0, Data.find(':'));
				String Result = Codec::HexDecode(Slice);
				if (Result.size() != 64)
					return false;

				memcpy(PrivateKey, Result.data(), Result.size());
				return true;
			}
			String Stellar::EncodeKey(uint8_t Version, const uint8_t* Value, size_t Size)
			{
				Vector<uint8_t> Key(1 + Size + 2, Version);
				memcpy(&Key[1], Value, sizeof(uint8_t) * Size);

				uint16_t Checksum = CalculateChecksum(&Key[0], Size + 1);
				memcpy(&Key[Key.size() - 2], &Checksum, sizeof(uint8_t) * 2);
				return EncodeBase32(&Key[0], Key.size());
			}
			String Stellar::EncodeBase32(const uint8_t* Value, size_t Size)
			{
				size_t ExpectedSize = std::max<size_t>(1, base32_encoded_length(Size));
				String Data(ExpectedSize, '\0');
				if (!base32_encode(Value, Size, (char*)Data.data(), Data.size() + 1, BASE32_ALPHABET_RFC4648))
					Data.clear();
				return Data;
			}
			Stellar::ChainInfo& Stellar::GetParams()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return Config.Regtest;
					case NetworkType::Testnet:
						return Config.Testnet;
					case NetworkType::Mainnet:
						return Config.Mainnet;
					default:
						VI_PANIC(false, "invalid network type");
						return Config.Regtest;
				}
			}
			const btc_chainparams_* Stellar::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &xlm_chainparams_regtest;
					case NetworkType::Testnet:
						return &xlm_chainparams_test;
					case NetworkType::Mainnet:
						return &xlm_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}