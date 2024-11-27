#include "ripple.h"
#include "../../utils/tiny-bitcoin/tool.h"
#include "../../utils/tiny-bitcoin/bip32.h"
#include "../../utils/tiny-bitcoin/ripemd160.h"
#include "../../utils/tiny-bitcoin/ecc.h"
#include "../../utils/tiny-xrp/libbase58.h"
extern "C"
{
#include "../../utils/trezor-crypto/ed25519.h"
}
#include <sodium.h>

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			static uint64_t GetExponent(const Decimal& Value)
			{
				String RawExponent = Value.ToExponent();
				size_t Index = RawExponent.rfind("e+");
				if (Index == std::string::npos)
					return 0;

				auto Exponent = FromString<uint64_t>(RawExponent.substr(Index + 2));
				return Exponent ? *Exponent : 0;
			}
			static void TxAppend(Vector<uint8_t>& Tx, const uint8_t* Data, size_t DataSize)
			{
				size_t Offset = Tx.size();
				Tx.resize(Tx.size() + DataSize);
				memcpy(&Tx[Offset], Data, DataSize);
			}
			static void TxAppendUint16(Vector<uint8_t>& Tx, uint16_t Data)
			{
				uint8_t Buffer[sizeof(uint16_t)];
				Buffer[0] = (uint8_t)(Data & 0xFF);
				Buffer[1] = (uint8_t)(Data >> 8);
				TxAppend(Tx, Buffer, sizeof(Buffer));
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
			static void TxAppendAmount(Vector<uint8_t>& Tx, Ripple* Implementation, const std::string_view& Asset, const std::string_view& Issuer, const Decimal& TokenValue, uint64_t BaseValue)
			{
				bool IsToken = (!Asset.empty() && !Issuer.empty());
				uint64_t Value = BaseValue, Exponent = GetExponent(TokenValue);
				if (IsToken)
				{
					String Multiplier(1 + (Exponent > 15 ? Exponent - 15 : 15 - Exponent), '0');
					Multiplier[0] = '1';

					Decimal AdjustedValue = TokenValue * Decimal(Multiplier);
					Value = AdjustedValue.Truncate(0).ToUInt64();
				}

				uint32_t Left = (Value >> 32);
				uint32_t Right = Value & 0x00000000ffffffff;
				TxAppendUint32(Tx, Left);
				TxAppendUint32(Tx, Right);

				size_t Offset = Tx.size() - sizeof(uint32_t) * 2;
				uint8_t& Bit1 = Tx[Offset + 0];
				if (!IsToken)
				{
					Bit1 |= 0x40;
					return;
				}

				uint8_t& Bit2 = Tx[Offset + 1];
				Bit1 |= 0x80;
				if (Value > 0)
					Bit1 |= 0x40;

				int8_t ExponentValue = (int8_t)Exponent - 15;
				uint8_t ExponentByte = 97 + ExponentValue;
				Bit1 |= ExponentByte >> 2;
				Bit2 |= (ExponentByte & 0x03) << 6;

				uint8_t AssetBuffer[20] = { 0 };
				if (Asset.size() != 3)
				{
					String AssetData = Codec::HexDecode(Asset);
					memcpy(AssetBuffer, AssetData.data(), std::min<size_t>(AssetData.size(), sizeof(AssetBuffer)));
				}
				else
					memcpy(AssetBuffer + 12, Asset.data(), Asset.size());
				TxAppend(Tx, AssetBuffer, sizeof(AssetBuffer));

				uint8_t PublicKeyHash[20];
				Implementation->DecodePublicKeyHash(Issuer, PublicKeyHash);
				TxAppend(Tx, PublicKeyHash, sizeof(PublicKeyHash));
			}
			static void TxAppendLength(Vector<uint8_t>& Tx, size_t Size)
			{
				uint8_t Length[3] = { 0, 0, 0 };
				if (Size <= 192)
				{
					Length[0] = (uint8_t)Size;
					TxAppend(Tx, Length, sizeof(uint8_t) * 1);
				}
				else if (Size <= 12480)
				{
					Size -= 193;
					Length[0] = (uint8_t)(193 + (Size >> 8));
					Length[1] = (uint8_t)(Size & 0xFF);
					TxAppend(Tx, Length, sizeof(uint8_t) * 2);
				}
				else if (Size <= 918744)
				{
					Size -= 12481;
					Length[0] = (uint8_t)(241 + (Size >> 16));
					Length[1] = (uint8_t)((Size >> 8) & 0xFF);
					Length[2] = (uint8_t)(Size & 0xFF);
					TxAppend(Tx, Length, sizeof(uint8_t) * 3);
				}
			}
			static void TxAppendBinary(Vector<uint8_t>& Tx, const uint8_t* Data, size_t DataSize)
			{
				TxAppendLength(Tx, DataSize);
				TxAppend(Tx, Data, DataSize);
			}
			static void TxAppendPublicKey(Vector<uint8_t>& Tx, Ripple* Implementation, const std::string_view& Data)
			{
				uint8_t PublicKey[33] = { 0 };
				Implementation->DecodePublicKey(Data, PublicKey);
				TxAppendBinary(Tx, PublicKey, sizeof(PublicKey));
			}
			static void TxAppendAddress(Vector<uint8_t>& Tx, Ripple* Implementation, const std::string_view& Data)
			{
				uint8_t PublicKeyHash[20] = { 0 };
				Implementation->DecodePublicKeyHash(Data, PublicKeyHash);
				TxAppendBinary(Tx, PublicKeyHash, sizeof(PublicKeyHash));
			}
			static void TxAppendSignature(Vector<uint8_t>& Tx, const std::string_view& Data)
			{
				String Binary = Codec::HexDecode(Data);
				TxAppendBinary(Tx, (uint8_t*)Binary.data(), Binary.size());
			}

			const char* Ripple::NdCall::Ledger()
			{
				return "ledger";
			}
			const char* Ripple::NdCall::Transaction()
			{
				return "tx";
			}
			const char* Ripple::NdCall::ServerInfo()
			{
				return "server_info";
			}
			const char* Ripple::NdCall::AccountInfo()
			{
				return "account_info";
			}
			const char* Ripple::NdCall::AccountObjects()
			{
				return "account_objects";
			}
			const char* Ripple::NdCall::SubmitTransaction()
			{
				return "submit";
			}

			Promise<ExpectsLR<Ripple::AccountInfo>> Ripple::GetAccountInfo(const Algorithm::AssetId& Asset, const std::string_view& Address)
			{
				auto* Implementation = (Chains::Ripple*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<Ripple::AccountInfo>(LayerException("chain not found"));

				Schema* Params = Var::Set::Object();
				Params->Set("account", Var::String(Address));
				Params->Set("ledger_index", Var::String("current"));

				SchemaList Map;
				Map.emplace_back(Params);

				auto AccountData = Coawait(ExecuteRPC(Asset, NdCall::AccountInfo(), std::move(Map), CachePolicy::Lazy));
				if (!AccountData)
					Coreturn ExpectsLR<Ripple::AccountInfo>(std::move(AccountData.Error()));

				AccountInfo Info;
				Info.Balance = Implementation->FromDrop(uint256_t(AccountData->FetchVar("account_data.Balance").GetBlob()));
				Info.Sequence = AccountData->FetchVar("account_data.Sequence").GetInteger();
				Memory::Release(*AccountData);
				Coreturn ExpectsLR<Ripple::AccountInfo>(std::move(Info));
			}
			Promise<ExpectsLR<Ripple::AccountTokenInfo>> Ripple::GetAccountTokenInfo(const Algorithm::AssetId& Asset, const std::string_view& Address)
			{
				AccountTokenInfo Info;
				Info.Balance = 0.0;

				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				size_t Marker = 0, Limit = 400;
				while (ContractAddress && Limit > 0)
				{
					Schema* Params = Var::Set::Object();
					Params->Set("account", Var::String(Address));
					Params->Set("ledger_index", Var::String("current"));
					Params->Set("deletion_blockers_only", Var::Boolean(false));
					Params->Set("marker", Var::Integer(Marker));
					Params->Set("limit", Var::Integer(Limit));

					SchemaList Map;
					Map.emplace_back(Params);

					auto AccountData = UPtr<Schema>(Coawait(ExecuteRPC(Asset, NdCall::AccountObjects(), std::move(Map), CachePolicy::Lazy)));
					if (!AccountData)
						break;

					auto* Objects = AccountData->Get("account_objects");
					if (!Objects || Objects->Empty())
						break;

					String IssuerChecksum = ContractAddress->substr(ContractAddress->size() - 6);
					for (auto& Object : Objects->GetChilds())
					{
						String Token = Object->FetchVar("Balance.currency").GetBlob();
						if (Token != Algorithm::Asset::TokenOf(Asset))
							continue;

						String Issuer = Object->FetchVar("Balance.issuer").GetBlob();
						if (Issuer.substr(Issuer.size() - 6) != IssuerChecksum)
							continue;

						Info.Balance = Object->FetchVar("Balance.value").GetDecimal();
						Limit = 0;
						break;
					}

					size_t Size = Objects->Size();
					Marker += Size;
					if (Size < Limit)
						break;
				}

				Coreturn ExpectsLR<Ripple::AccountTokenInfo>(std::move(Info));
			}
			Promise<ExpectsLR<Ripple::LedgerSequenceInfo>> Ripple::GetLedgerSequenceInfo(const Algorithm::AssetId& Asset)
			{
				Schema* Params = Var::Set::Object();
				Params->Set("ledger_index", Var::String("validated"));

				SchemaList Map;
				Map.emplace_back(Params);

				auto BlockData = Coawait(ExecuteRPC(Asset, NdCall::Ledger(), std::move(Map), CachePolicy::Lazy));
				if (!BlockData)
					Coreturn ExpectsLR<Ripple::LedgerSequenceInfo>(BlockData.Error());

				LedgerSequenceInfo Info;
				Info.Index = BlockData->GetVar("ledger_index").GetInteger();
				Info.Sequence = Info.Index + 20;
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<Ripple::LedgerSequenceInfo>(std::move(Info));
			}
			Promise<ExpectsLR<void>> Ripple::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				Schema* Params = Var::Set::Object();
				Params->Set("tx_blob", Var::String(Format::Util::Clear0xHex(TxData.Data, true)));
				Params->Set("fail_hard", Var::Boolean(true));

				SchemaList Map;
				Map.emplace_back(Params);

				auto HexData = Coawait(ExecuteRPC(Asset, NdCall::SubmitTransaction(), std::move(Map), CachePolicy::Greedy));
				if (!HexData)
					Coreturn ExpectsLR<void>(std::move(HexData.Error()));

				String ErrorMessage = HexData->GetVar("engine_result_message").GetBlob();
				bool IsAccepted = HexData->GetVar("accepted").GetBoolean();
				Memory::Release(*HexData);
				if (IsAccepted)
					Coreturn ExpectsLR<void>(Expectation::Met);
				else if (ErrorMessage.empty())
					ErrorMessage = "broadcast error";

				Coreturn ExpectsLR<void>(LayerException(std::move(ErrorMessage)));
			}
			Promise<ExpectsLR<uint64_t>> Ripple::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto LedgerSequenceInfo = Coawait(GetLedgerSequenceInfo(Asset));
				if (!LedgerSequenceInfo)
					Coreturn ExpectsLR<uint64_t>(LedgerSequenceInfo.Error());

				Coreturn ExpectsLR<uint64_t>(LedgerSequenceInfo->Index);
			}
			Promise<ExpectsLR<Schema*>> Ripple::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				Schema* Params = Var::Set::Object();
				Params->Set("ledger_index", Var::Integer(BlockHeight));
				Params->Set("transactions", Var::Boolean(true));
				Params->Set("expand", Var::Boolean(true));

				SchemaList Map;
				Map.emplace_back(Params);

				auto BlockData = Coawait(ExecuteRPC(Asset, NdCall::Ledger(), std::move(Map), CachePolicy::Shortened));
				if (!BlockData)
					Coreturn BlockData;

				if (BlockHash != nullptr)
					*BlockHash = BlockData->GetVar("ledger_hash").GetBlob();

				auto* Transactions = BlockData->Fetch("ledger.transactions");
				if (!Transactions)
				{
					Memory::Release(*BlockData);
					Coreturn ExpectsLR<Schema*>(LayerException("ledger.transactions field not found"));
				}

				Transactions->Unlink();
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<Schema*>(Transactions);
			}
			Promise<ExpectsLR<Schema*>> Ripple::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				Schema* Params = Var::Set::Object();
				Params->Set("transaction", Var::String(Format::Util::Clear0xHex(TransactionId, true)));
				Params->Set("binary", Var::Boolean(false));

				SchemaList Map;
				Map.emplace_back(Params);

				auto TxData = Coawait(ExecuteRPC(Asset, NdCall::Transaction(), std::move(Map), CachePolicy::Extended));
				Coreturn TxData;
			}
			Promise<ExpectsLR<Vector<IncomingTransaction>>> Ripple::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				auto* Implementation = (Chains::Ripple*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("chain not found"));

				String TxHash = TransactionData->GetVar("hash").GetBlob();
				String Type = TransactionData->GetVar("TransactionType").GetBlob();
				String From = TransactionData->GetVar("Account").GetBlob();
				String To = TransactionData->GetVar("Destination").GetBlob();
				Decimal FeeValue = Implementation->FromDrop(uint256_t(TransactionData->GetVar("Fee").GetBlob()));
				auto* Amount = TransactionData->Get("Amount");
				if (Type != "Payment" || !Amount)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				Decimal BaseValue = 0.0, TokenValue = 0.0;
				Algorithm::AssetId TokenAsset = Asset;
				if (Amount->Value.IsObject())
				{
					String Token = Amount->GetVar("currency").GetBlob();
					String Issuer = Amount->FetchVar("issuer").GetBlob();
					TokenValue = Amount->GetVar("value").GetDecimal();
					TokenAsset = Algorithm::Asset::IdOf(Algorithm::Asset::BlockchainOf(Asset), Token, Issuer);
					if (!Datamaster::EnableContractAddress(TokenAsset, Issuer))
						Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));
				}
				else
					BaseValue = Implementation->FromDrop(uint256_t(Amount->Value.GetBlob()));

				auto Discovery = FindCheckpointAddresses(Asset, { From, To });
				if (!Discovery || Discovery->empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				auto FromAddress = Discovery->find(From);
				auto ToAddress = Discovery->find(To);
				auto DestinationTag = TransactionData->GetVar("DestinationTag").GetBlob();
				auto ToAddressIndex = FromString<uint64_t>(DestinationTag);
				if (!ToAddressIndex && ToAddress != Discovery->end())
					ToAddressIndex = ToAddress->second;

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
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(std::move(Transactions));
			}
			Promise<ExpectsLR<BaseFee>> Ripple::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::Object());

				auto ServerInfo = Coawait(ExecuteRPC(Asset, NdCall::ServerInfo(), std::move(Map), CachePolicy::Lazy));
				if (!ServerInfo)
					Coreturn ExpectsLR<BaseFee>(std::move(ServerInfo.Error()));

				Decimal BaseConstantFee = ServerInfo->FetchVar("info.validated_ledger.base_fee_xrp").GetDecimal();
				if (!BaseConstantFee.IsPositive())
				{
					auto* Implementation = (Chains::Ripple*)Datamaster::GetChain(Asset);
					BaseConstantFee = Implementation->GetBaseFeeXRP();
				}

				Decimal LoadFactor = ServerInfo->FetchVar("info.load_factor").GetDecimal();
				if (!LoadFactor.IsPositive())
					LoadFactor = 1.0;

				Decimal FeeCushion = 1.2;
				Memory::Release(*ServerInfo);
				Coreturn ExpectsLR<BaseFee>(BaseFee(BaseConstantFee * LoadFactor * FeeCushion, 1.0));
			}
			Promise<ExpectsLR<Decimal>> Ripple::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
			{
				auto* Implementation = (Chains::Ripple*)Datamaster::GetChain(Asset);
				if (!Address)
				{
					ExpectsLR<DerivedVerifyingWallet> FromWallet = LayerException("signing wallet not found");
					if (Wallet.Parent)
					{
						auto SigningWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
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
						Coreturn ExpectsLR<Decimal>(std::move(FromWallet.Error()));

					Address = FromWallet->Addresses.begin()->second;
				}

				if (!Algorithm::Asset::TokenOf(Asset).empty())
				{
					auto Account = Coawait(GetAccountTokenInfo(Asset, *Address));
					if (!Account)
						Coreturn ExpectsLR<Decimal>(std::move(Account.Error()));

					Coreturn ExpectsLR<Decimal>(std::move(Account->Balance));
				}
				else
				{
					auto Account = Coawait(GetAccountInfo(Asset, *Address));
					if (!Account)
						Coreturn ExpectsLR<Decimal>(std::move(Account.Error()));

					Coreturn ExpectsLR<Decimal>(std::move(Account->Balance));
				}
			}
			Promise<ExpectsLR<OutgoingTransaction>> Ripple::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> FromWallet = LayerException();
				if (Wallet.Parent)
					FromWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					FromWallet = *Wallet.SigningChild;
				if (!FromWallet)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("signing wallet not found"));

				auto AccountInfo = Coawait(GetAccountInfo(Asset, FromWallet->Addresses.begin()->second));
				if (!AccountInfo)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(AccountInfo.Error()));

				auto LedgerInfo = Coawait(GetLedgerSequenceInfo(Asset));
				if (!LedgerInfo)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(LedgerInfo.Error()));

				auto& Subject = To.front();
				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				Decimal TotalValue = Subject.Value;
				Decimal FeeValue = Fee.GetFee();
				if (ContractAddress)
				{
					auto AccountTokenInfo = Coawait(GetAccountTokenInfo(Asset, FromWallet->Addresses.begin()->second));
					if (!AccountTokenInfo || AccountTokenInfo->Balance < TotalValue)
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", (AccountTokenInfo ? AccountTokenInfo->Balance : Decimal(0.0)).ToString().c_str(), TotalValue.ToString().c_str())));
					TotalValue = FeeValue;
				}
				else
					TotalValue += FeeValue;

				if (AccountInfo->Balance < TotalValue)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", AccountInfo->Balance.ToString().c_str(), TotalValue.ToString().c_str())));

				TransactionBuffer Buffer;
				Buffer.TransactionType = 0;
				Buffer.Flags = 0;
				Buffer.Sequence = (uint32_t)AccountInfo->Sequence;
				Buffer.DestinationTag = (uint32_t)Subject.AddressIndex.Or(0);
				Buffer.LastLedgerSequence = (uint32_t)LedgerInfo->Sequence;
				if (ContractAddress)
				{
					Buffer.Amount.TokenValue = Subject.Value;
					Buffer.Amount.Asset = Algorithm::Asset::TokenOf(Asset);
					Buffer.Amount.Issuer = *ContractAddress;
				}
				else
					Buffer.Amount.BaseValue = (uint64_t)ToDrop(Subject.Value);
				Buffer.Fee = (uint64_t)ToDrop(FeeValue);
				Buffer.SigningPubKey = FromWallet->VerifyingKey.ExposeToHeap();
				Buffer.Account = FromWallet->Addresses.begin()->first;
				Buffer.Destination = Subject.Address;
				if (!TxSignAndVerify(&Buffer, FromWallet->VerifyingKey, FromWallet->SigningKey))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid private key"));

				Vector<uint8_t> RawTransactionData = TxSerialize(&Buffer, false);
				String TransactionData = Codec::HexEncode(std::string_view((char*)&RawTransactionData[0], RawTransactionData.size()), true);
				String TransactionId = TxHash(RawTransactionData);
				if (TransactionId.empty() || TransactionData.empty())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));

				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, TransactionId, std::move(FeeValue));
				Tx.SetOperations({ Transferer(FromWallet->Addresses.begin()->second, Option<uint64_t>(FromWallet->AddressIndex), Decimal(Subject.Value)) }, Vector<Transferer>(To));
				Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData)));
			}
			ExpectsLR<MasterWallet> Ripple::NewMasterWallet(const std::string_view& Seed)
			{
				auto* Chain = GetChain();
				btc_hdnode RootNode;
				if (!btc_hdnode_from_seed((uint8_t*)Seed.data(), (int)Seed.size(), &RootNode))
					return ExpectsLR<MasterWallet>(LayerException("seed value invalid"));

				char PrivateKey[256];
				btc_hdnode_serialize_private(&RootNode, Chain, PrivateKey, sizeof(PrivateKey));

				char PublicKey[256];
				btc_hdnode_serialize_public(&RootNode, Chain, PublicKey, (int)sizeof(PublicKey));

				String HexSeed = Codec::HexEncode(Seed);
				return ExpectsLR<MasterWallet>(MasterWallet(::PrivateKey(std::move(HexSeed)), ::PrivateKey(PublicKey), ::PrivateKey(PrivateKey)));
			}
			ExpectsLR<DerivedSigningWallet> Ripple::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				auto* Chain = GetChain();
				char DerivedSeedKey[256];
				{
					auto Private = Wallet.SigningKey.Expose<2048>();
					if (!hd_derive(Chain, Private.Key, GetDerivation(Protocol::Now().Account.RootAddressIndex).c_str(), DerivedSeedKey, sizeof(DerivedSeedKey)))
						return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid"));
				}

				btc_hdnode Node;
				if (!btc_hdnode_deserialize(DerivedSeedKey, Chain, &Node))
					return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid"));

				auto Derived = NewSigningWallet(Asset, std::string_view((char*)Node.private_key, sizeof(Node.private_key)));
				if (Derived)
					Derived->AddressIndex = AddressIndex;
				return Derived;
			}
			ExpectsLR<DerivedSigningWallet> Ripple::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPrivateKey)
			{
				if (RawPrivateKey.size() != 32 && RawPrivateKey.size() != 33 && RawPrivateKey.size() != 64 && RawPrivateKey.size() != 65)
					return LayerException("invalid private key size");

				uint8_t PrivateKey[65]; String SecretKey;
				if (RawPrivateKey.size() == 32 || RawPrivateKey.size() == 33)
				{
					size_t Offset = RawPrivateKey.size() == 33 ? 1 : 0;
					uint8_t IntermediatePrivateKey[65];
					auto RawSecretKey = *Crypto::HashRaw(Digests::Shake128(), RawPrivateKey);
					sha512_Raw((uint8_t*)RawSecretKey.data() + Offset, RawSecretKey.size() - Offset, IntermediatePrivateKey);
					sha512_Raw(IntermediatePrivateKey, sizeof(IntermediatePrivateKey) / 2, PrivateKey + 1);
					Algorithm::Composition::ConvertToED25519Curve(PrivateKey + 1);
					SecretKey = EncodeSecretKey((uint8_t*)RawSecretKey.data(), RawSecretKey.size());
				}
				else if (RawPrivateKey.size() == 64 || RawPrivateKey.size() == 65)
				{
					size_t Offset = RawPrivateKey.size() == 65 ? 1 : 0;
					memcpy(PrivateKey + 1, RawPrivateKey.data() + Offset, RawPrivateKey.size() - Offset);
				}
				PrivateKey[0] = 0xED;

				uint8_t PublicKey[32];
				ed25519_publickey_ext(PrivateKey + 1, PublicKey);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicKey, sizeof(PublicKey)));
				if (!Derived)
					return Derived.Error();

				String DerivedPrivateKey = EncodePrivateKey(PrivateKey, sizeof(PrivateKey));
				if (!SecretKey.empty())
					DerivedPrivateKey.append(1, ':').append(SecretKey);
				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), ::PrivateKey(DerivedPrivateKey)));
			}
			ExpectsLR<DerivedVerifyingWallet> Ripple::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPublicKey)
			{
				if (RawPublicKey.size() != 32 && RawPublicKey.size() != 33)
					return LayerException("invalid public key size");

				uint8_t PublicKey[33];
				size_t Offset = RawPublicKey.size() == 33 ? 1 : 0;
				memcpy(PublicKey + 1, RawPublicKey.data() + Offset, RawPublicKey.size() - Offset);
				PublicKey[0] = 0xED;

				String DerivedPublicKey = EncodePublicKey(PublicKey, sizeof(PublicKey));
				String DerivedAddress = EncodeAndHashPublicKey(PublicKey, sizeof(PublicKey));
				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, DerivedAddress } }, Optional::None, ::PrivateKey(DerivedPublicKey)));
			}
			ExpectsLR<String> Ripple::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Data[20];
				if (!DecodePublicKeyHash(Address, Data))
					return LayerException("invalid address");

				return String((char*)Data, sizeof(Data));
			}
			ExpectsLR<String> Ripple::SignMessage(const Messages::Generic& Message, const DerivedSigningWallet& Wallet)
			{
				uint8_t PrivateKey[65];
				if (!DecodePrivateKey(Wallet.SigningKey.ExposeToHeap(), PrivateKey))
					return LayerException("private key invalid");

				auto MessageBlob = Message.AsMessage();
				ed25519_signature Signature;
				ed25519_sign_ext((uint8_t*)MessageBlob.Data.data(), MessageBlob.Data.size(), PrivateKey + 1, PrivateKey + 33, Signature);
				return String((char*)Signature, sizeof(Signature));
			}
			ExpectsLR<bool> Ripple::VerifyMessage(const Messages::Generic& Message, const std::string_view& Address, const std::string_view& PublicKey, const std::string_view& Signature)
			{
				if (Signature.size() < 64)
					return LayerException("signature invalid");

				uint8_t RawPublicKey[33];
				if (!DecodePublicKey(PublicKey, RawPublicKey))
					return LayerException("public key invalid");

				auto MessageBlob = Message.AsMessage();
				return crypto_sign_ed25519_verify_detached((uint8_t*)Signature.data(), (uint8_t*)MessageBlob.Data.data(), MessageBlob.Data.size(), RawPublicKey + 1) == 0;
			}
			String Ripple::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/144'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			Decimal Ripple::GetDivisibility() const
			{
				return 1000000;
			}
			Algorithm::Composition::Type Ripple::GetCompositionPolicy() const
			{
				return Algorithm::Composition::Type::ED25519;
			}
			RoutingPolicy Ripple::GetRoutingPolicy() const
			{
				return RoutingPolicy::Memo;
			}
			uint64_t Ripple::GetBlockLatency() const
			{
				return 1;
			}
			bool Ripple::HasBulkTransactions() const
			{
				return false;
			}
			bool Ripple::TxSignAndVerify(TransactionBuffer* TxData, const PrivateKey& Public, const PrivateKey& Private)
			{
				uint8_t PrivateKey[65];
				if (!DecodePrivateKey(Private.ExposeToHeap(), PrivateKey))
					return false;

				uint8_t PublicKey[33];
				if (!DecodePublicKey(Public.ExposeToHeap(), PublicKey))
					return false;

				Vector<uint8_t> TxBlob = TxSerialize(TxData, true);
				ed25519_signature Signature;
				ed25519_sign_ext(TxBlob.data(), TxBlob.size(), PrivateKey + 1, PrivateKey + 33, Signature);
				if (crypto_sign_ed25519_verify_detached(Signature, TxBlob.data(), TxBlob.size(), PublicKey) != 0)
					return false;

				TxData->TxnSignature = Codec::HexEncode(std::string_view((char*)Signature, sizeof(Signature)));
				return true;
			}
			Vector<uint8_t> Ripple::TxSerialize(TransactionBuffer* TxData, bool SigningData)
			{
				static const uint8_t TransactionType[1] = { 18 };
				static const uint8_t Flags[1] = { 34 };
				static const uint8_t Sequence[1] = { 36 };
				static const uint8_t DestinationTag[1] = { 46 };
				static const uint8_t LastLedgerSequence[2] = { 32, 27 };
				static const uint8_t Amount[1] = { 97 };
				static const uint8_t Fee[1] = { 104 };
				static const uint8_t SigningPubKey[1] = { 115 };
				static const uint8_t TxnSignature[1] = { 116 };
				static const uint8_t Account[1] = { 129 };
				static const uint8_t Destination[1] = { 131 };

				Vector<uint8_t> Tx;
				if (SigningData)
					TxAppendUint32(Tx, 0x53545800);
				TxAppend(Tx, TransactionType, sizeof(TransactionType));
				TxAppendUint16(Tx, TxData->TransactionType);
				TxAppend(Tx, Flags, sizeof(Flags));
				TxAppendUint32(Tx, TxData->Flags);
				TxAppend(Tx, Sequence, sizeof(Sequence));
				TxAppendUint32(Tx, TxData->Sequence);
				TxAppend(Tx, DestinationTag, sizeof(DestinationTag));
				TxAppendUint32(Tx, TxData->DestinationTag);
				TxAppend(Tx, LastLedgerSequence, sizeof(LastLedgerSequence));
				TxAppendUint32(Tx, TxData->LastLedgerSequence);
				TxAppend(Tx, Amount, sizeof(Amount));
				TxAppendAmount(Tx, this, TxData->Amount.Asset, TxData->Amount.Issuer, TxData->Amount.TokenValue, TxData->Amount.BaseValue);
				TxAppend(Tx, Fee, sizeof(Fee));
				TxAppendAmount(Tx, this, String(), String(), Decimal::NaN(), TxData->Fee);
				TxAppend(Tx, SigningPubKey, sizeof(SigningPubKey));
				TxAppendPublicKey(Tx, this, TxData->SigningPubKey);
				if (!SigningData)
				{
					TxAppend(Tx, TxnSignature, sizeof(TxnSignature));
					TxAppendSignature(Tx, TxData->TxnSignature);
				}
				TxAppend(Tx, Account, sizeof(Account));
				TxAppendAddress(Tx, this, TxData->Account);
				TxAppend(Tx, Destination, sizeof(Destination));
				TxAppendAddress(Tx, this, TxData->Destination);
				return Tx;
			}
			String Ripple::TxHash(const Vector<uint8_t>& TxBlob)
			{
				Vector<uint8_t> Tx;
				Tx.reserve(sizeof(uint32_t) + TxBlob.size());
				TxAppendUint32(Tx, 0x54584e00);
				TxAppend(Tx, TxBlob.data(), TxBlob.size());

				uint8_t Hash512[64];
				sha512_Raw(Tx.data(), Tx.size(), Hash512);
				return Codec::HexEncode(std::string_view((char*)Hash512, sizeof(Hash512) / 2), true);
			}
			Decimal Ripple::GetBaseFeeXRP()
			{
				return 0.00001;
			}
			Decimal Ripple::FromDrop(const uint256_t& Value)
			{
				return Decimal(Value.ToString()) / GetDivisibility().Truncate(Protocol::Now().Message.Precision);
			}
			uint256_t Ripple::ToDrop(const Decimal& Value)
			{
				return uint256_t((Value * GetDivisibility()).Truncate(0).ToString());
			}
			String Ripple::EncodeSecretKey(uint8_t* SecretKey, size_t SecretKeySize)
			{
				char Intermediate[256];
				size_t IntermediateSize = sizeof(Intermediate);
				uint8_t Versions[3] = { 0x01, 0xe1, 0x4b };
				xb58check_enc(Intermediate, &IntermediateSize, Versions, sizeof(Versions), SecretKey, SecretKeySize);
				return String(Intermediate);
			}
			String Ripple::EncodePrivateKey(uint8_t* PrivateKey, size_t PrivateKeySize)
			{
				return Codec::HexEncode(std::string_view((char*)PrivateKey, PrivateKeySize));
			}
			String Ripple::EncodePublicKey(uint8_t* PublicKey, size_t PublicKeySize)
			{
				return Codec::HexEncode(std::string_view((char*)PublicKey, PublicKeySize));
			}
			String Ripple::EncodeAndHashPublicKey(uint8_t* PublicKey, size_t PublicKeySize)
			{
				uint256 PublicKeyHash256;
				sha256_Raw(PublicKey, PublicKeySize, PublicKeyHash256);

				uint160 PublicKeyHash160;
				btc_ripemd160(PublicKeyHash256, sizeof(PublicKeyHash256), PublicKeyHash160);

				char Intermediate[256];
				size_t IntermediateSize = sizeof(Intermediate);
				uint8_t Versions = 0x0;
				xb58check_enc(Intermediate, &IntermediateSize, &Versions, sizeof(Versions), PublicKeyHash160, sizeof(PublicKeyHash160));
				return String(Intermediate);
			}
			bool Ripple::DecodeSecretKey(const std::string_view& Data, uint8_t SecretKey[16])
			{
				uint8_t Intermediate[128];
				size_t IntermediateSize = sizeof(Intermediate);
				if (!xb58check_dec(String(Data).c_str(), Intermediate, &IntermediateSize))
					return false;

				if (IntermediateSize != 19)
					return false;

				memcpy(SecretKey, Intermediate + 3, IntermediateSize);
				return true;
			}
			bool Ripple::DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[65])
			{
				auto Slice = Data.substr(0, Data.find(':'));
				String Result = Codec::HexDecode(Slice);
				if (Result.size() != 65)
					return false;

				memcpy(PrivateKey, Result.data(), Result.size());
				return true;
			}
			bool Ripple::DecodePublicKey(const std::string_view& Data, uint8_t PublicKey[33])
			{
				String Result = Codec::HexDecode(Data);
				if (Result.size() != 33)
					return false;

				memcpy(PublicKey, Result.data(), Result.size());
				return true;
			}
			bool Ripple::DecodePublicKeyHash(const std::string_view& Data, uint8_t PublicKeyHash[20])
			{
				uint8_t Intermediate[128];
				size_t IntermediateSize = sizeof(Intermediate);
				if (!xb58check_dec(String(Data).c_str(), Intermediate, &IntermediateSize))
					return false;

				if (IntermediateSize != 21)
					return false;

				memcpy(PublicKeyHash, Intermediate + 1, IntermediateSize);
				return true;
			}
			const btc_chainparams_* Ripple::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &xrp_chainparams_regtest;
					case NetworkType::Testnet:
						return &xrp_chainparams_test;
					case NetworkType::Mainnet:
						return &xrp_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}