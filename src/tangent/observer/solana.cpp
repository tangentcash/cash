#include "solana.h"
#include "../../utils/tiny-bitcoin/bip32.h"
#include "../../utils/tiny-bitcoin/tool.h"
#include "../../utils/tiny-bitcoin/utils.h"
#include "../../utils/tiny-bitcoin/ecc.h"
extern "C"
{
#include "../../utils/trezor-crypto/ed25519.h"
#include "../../utils/trezor-crypto/base58.h"
}
#include <sodium.h>

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			struct TransactionHeader
			{
				uint8_t RequiredSignatures;
				uint8_t ReadonlySignedAccounts;
				uint8_t ReadonlyUnsignedAccounts;
			};

			static void TxAppend(Vector<uint8_t>& Tx, const uint8_t* Data, size_t DataSize)
			{
				size_t Offset = Tx.size();
				Tx.resize(Tx.size() + DataSize);
				memcpy(&Tx[Offset], Data, DataSize);
			}

			String Solana::NdCall::GetTokenMetadata(const std::string_view& Mint)
			{
				return Stringify::Text("https://api.solana.fm/v1/tokens/%" PRIu64, (int)Mint.size(), Mint.data());
			}
			const char* Solana::NdCall::GetTokenBalance()
			{
				return "getTokenAccountsByOwner";
			}
			const char* Solana::NdCall::GetBalance()
			{
				return "getBalance";
			}
			const char* Solana::NdCall::GetBlockHash()
			{
				return "getLatestBlockhash";
			}
			const char* Solana::NdCall::GetBlockNumber()
			{
				return "getBlockHeight";
			}
			const char* Solana::NdCall::GetBlock()
			{
				return "getBlock";
			}
			const char* Solana::NdCall::GetTransaction()
			{
				return "getTransaction";
			}
			const char* Solana::NdCall::SendTransaction()
			{
				return "sendTransaction";
			}

			Solana::Solana() noexcept : Chainmaster()
			{
				Netdata.Composition = Algorithm::Composition::Type::ED25519;
				Netdata.Routing = RoutingPolicy::Account;
				Netdata.SyncLatency = 31;
				Netdata.Divisibility = Decimal(1000000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer = "spl";
				Netdata.SupportsBulkTransfer = false;
			}
			Promise<ExpectsLR<void>> Solana::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(TxData.Data));
				Map.emplace_back(Var::Set::Null());

				auto Status = Coawait(ExecuteRPC(Asset, NdCall::SendTransaction(), std::move(Map), CachePolicy::Greedy));
				if (!Status)
					Coreturn ExpectsLR<void>(std::move(Status.Error()));

				Memory::Release(*Status);
				Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Promise<ExpectsLR<uint64_t>> Solana::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto BlockHeight = Coawait(ExecuteRPC(Asset, NdCall::GetBlockNumber(), { }, CachePolicy::Lazy));
				if (!BlockHeight)
					Coreturn ExpectsLR<uint64_t>(std::move(BlockHeight.Error()));

				uint64_t Value = (uint64_t)BlockHeight->Value.GetInteger();
				Memory::Release(*BlockHeight);
				Coreturn ExpectsLR<uint64_t>(Value);
			}
			Promise<ExpectsLR<Schema*>> Solana::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				UPtr<Schema> Config = Var::Set::Object();
				Config->Set("encoding", Var::String("jsonParsed"));
				Config->Set("maxSupportedTransactionVersion", Var::Integer(0));
				Config->Set("transactionDetails", Var::String("accounts"));
				Config->Set("rewards", Var::Boolean(false));

				SchemaList Map;
				Map.emplace_back(Var::Set::Integer(BlockHeight));
				Map.emplace_back(std::move(Config));

				auto BlockData = Coawait(ExecuteRPC(Asset, NdCall::GetBlock(), std::move(Map), CachePolicy::Shortened));
				if (!BlockData)
					Coreturn BlockData;

				if (BlockHash != nullptr)
					*BlockHash = BlockData->GetVar("blockhash").GetBlob();

				auto* Transactions = BlockData->Get("transactions");
				if (!Transactions)
				{
					Memory::Release(*BlockData);
					Coreturn ExpectsLR<Schema*>(LayerException("transactions field not found"));
				}

				Transactions->Unlink();
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<Schema*>(Transactions);
			}
			Promise<ExpectsLR<Schema*>> Solana::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Format::Util::Assign0xHex(TransactionId)));
				Map.emplace_back(Var::Set::Null());

				auto TxData = Coawait(ExecuteRPC(Asset, NdCall::GetTransaction(), std::move(Map), CachePolicy::Extended));
				Coreturn TxData;
			}
			Promise<ExpectsLR<Vector<IncomingTransaction>>> Solana::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				auto* Error = TransactionData->Fetch("meta.status.Err");
				if (Error != nullptr)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				auto* PreBalances = TransactionData->Fetch("meta.preBalances");
				auto* PostBalances = TransactionData->Fetch("meta.postBalances");
				auto* AccountKeys = TransactionData->Fetch("transaction.accountKeys");
				if (!PreBalances || !PostBalances || PreBalances->Size() != PostBalances->Size() || PreBalances->Empty() || !AccountKeys)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				bool NonTransferring = true;
				for (size_t i = 0; i < PreBalances->Size(); i++)
				{
					if (PreBalances->Get(i)->Value.GetDecimal() != PostBalances->Get(i)->Value.GetDecimal())
					{
						NonTransferring = false;
						break;
					}
				}
				if (NonTransferring)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				UnorderedSet<String> Addresses;
				for (auto& AccountKey : AccountKeys->GetChilds())
				{
					if (AccountKey->GetVar("writable").GetBoolean() || AccountKey->GetVar("signer").GetBoolean())
						Addresses.insert(AccountKey->GetVar("pubkey").GetBlob());
				}

				auto Discovery = FindCheckpointAddresses(Asset, Addresses);
				if (!Discovery || Discovery->empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				auto* Instructions = TransactionData->Fetch("transaction.message.instructions");
				if (!Instructions || Instructions->Empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not valid"));

				Vector<IncomingTransaction> Transactions;
				UnorderedMap<String, UnorderedMap<String, Decimal>> Balances;
				auto Signature = TransactionData->FetchVar("transaction.signatures.0").GetBlob();
				auto FeeValue = TransactionData->FetchVar("meta.fee").GetDecimal() / Netdata.Divisibility;
				for (auto& Instruction : Instructions->GetChilds())
				{
					auto* Info = Instruction->Fetch("parsed.info");
					if (!Info)
						continue;

					auto Type = Info->GetVar("type").GetBlob();
					if (Type == "transfer" || Type == "transferWithSeed")
					{
						auto From = Info->GetVar("source").GetBlob();
						auto To = Info->GetVar("destination").GetBlob();
						auto Value = FeeValue + Info->GetVar("lamports").GetDecimal() / Netdata.Divisibility;
						if (!Addresses.count(From) && !Addresses.count(To))
							continue;

						IncomingTransaction Tx;
						Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal(FeeValue));
						Tx.SetOperations({ Transferer(From, Optional::None, Decimal(Value)) }, { Transferer(To, Optional::None, Decimal(Value)) });
						Transactions.push_back(std::move(Tx));
					}
					else if (Type == "createAccount" || Type == "createAccountWithSeed")
					{
						auto From = Info->GetVar("source").GetBlob();
						auto To = Info->GetVar("newAccount").GetBlob();
						auto Value = FeeValue + Info->GetVar("lamports").GetDecimal() / Netdata.Divisibility;
						if (!Addresses.count(From) && !Addresses.count(To))
							continue;

						IncomingTransaction Tx;
						Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal(FeeValue));
						Tx.SetOperations({ Transferer(From, Optional::None, Decimal(Value)) }, { Transferer(To, Optional::None, Decimal(Value)) });
						Transactions.push_back(std::move(Tx));
					}
					else if (Type == "withdrawFromNonce")
					{
						auto From = Info->GetVar("nonceAccount").GetBlob();
						auto To = Info->GetVar("destination").GetBlob();
						auto Value = FeeValue + Info->GetVar("lamports").GetDecimal() / Netdata.Divisibility;
						if (!Addresses.count(From) && !Addresses.count(To))
							continue;

						IncomingTransaction Tx;
						Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal(FeeValue));
						Tx.SetOperations({ Transferer(From, Optional::None, Decimal(Value)) }, { Transferer(To, Optional::None, Decimal(Value)) });
						Transactions.push_back(std::move(Tx));
					}
					else if (Type == "withdraw")
					{
						auto From = Info->GetVar("stakeAccount").GetBlob();
						auto To = Info->GetVar("destination").GetBlob();
						auto Value = FeeValue + Info->GetVar("lamports").GetDecimal() / Netdata.Divisibility;
						if (!Addresses.count(From) && !Addresses.count(To))
							continue;

						IncomingTransaction Tx;
						Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal(FeeValue));
						Tx.SetOperations({ Transferer(From, Optional::None, Decimal(Value)) }, { Transferer(To, Optional::None, Decimal(Value)) });
						Transactions.push_back(std::move(Tx));
					}
					else if (Type == "split")
					{
						auto From = Info->GetVar("stakeAccount").GetBlob();
						auto To = Info->GetVar("newSplitAccount").GetBlob();
						auto Value = FeeValue + Info->GetVar("lamports").GetDecimal() / Netdata.Divisibility;
						if (!Addresses.count(From) && !Addresses.count(To))
							continue;

						IncomingTransaction Tx;
						Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal(FeeValue));
						Tx.SetOperations({ Transferer(From, Optional::None, Decimal(Value)) }, { Transferer(To, Optional::None, Decimal(Value)) });
						Transactions.push_back(std::move(Tx));
					}
				}

				auto* PreTokenBalances = TransactionData->Fetch("meta.preTokenBalances");
				if (PreTokenBalances != nullptr && !PreTokenBalances->Empty())
				{
					for (auto& Balance : PreTokenBalances->GetChilds())
					{
						Decimal Value = Balance->FetchVar("uiTokenAmount.amount").GetDecimal();
						if (!Value.IsPositive())
							continue;

						uint64_t Subdivisions = 1;
						uint64_t Decimals = std::min<uint64_t>(Balance->FetchVar("uiTokenAmount.decimals").GetInteger(), Protocol::Now().Message.Precision);
						for (uint64_t i = 0; i < Decimals; i++)
							Subdivisions *= 10;
						
						String Mint = Balance->GetVar("mint").GetBlob();
						String Owner = Balance->GetVar("mint").GetBlob();
						auto& Change = Balances[Mint][Owner];
						Value /= Decimal(Subdivisions).Truncate(Protocol::Now().Message.Precision);
						Change = Change.IsNaN() ? Value : (Change + Value);
					}
				}

				auto* PostTokenBalances = TransactionData->Fetch("meta.postTokenBalances");
				if (PostTokenBalances != nullptr && !PostTokenBalances->Empty())
				{
					for (auto& Balance : PostTokenBalances->GetChilds())
					{
						Decimal Value = Balance->FetchVar("uiTokenAmount.amount").GetDecimal();
						if (!Value.IsPositive())
							continue;

						uint64_t Subdivisions = 1;
						uint64_t Decimals = std::min<uint64_t>(Balance->FetchVar("uiTokenAmount.decimals").GetInteger(), Protocol::Now().Message.Precision);
						for (uint64_t i = 0; i < Decimals; i++)
							Subdivisions *= 10;

						String Mint = Balance->GetVar("mint").GetBlob();
						String Owner = Balance->GetVar("mint").GetBlob();
						auto& Change = Balances[Mint][Owner];
						Value /= Decimal(Subdivisions).Truncate(Protocol::Now().Message.Precision);
						Change = Change.IsNaN() ? Value : (Value - Change);
					}
				}

				for (auto& Token : Balances)
				{
					size_t Index = Transactions.size();
					for (auto& A : Token.second)
					{
						if (A.second.IsPositive())
						{
							IncomingTransaction Tx;
							Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal::Zero());
							for (auto& B : Token.second)
							{
								if (!B.second.IsNegative())
									continue;

								Decimal Delta = std::min(A.second, -B.second);
								Tx.SetOperations({ Transferer(B.first, Optional::None, Decimal(Delta)) }, { Transferer(A.first, Optional::None, Decimal(Delta)) });
								A.second -= Delta;
								B.second += Delta;
								if (A.second.IsZero())
									break;
							}
							Transactions.push_back(std::move(Tx));
						}
						else if (A.second.IsNegative())
						{
							IncomingTransaction Tx;
							Tx.SetTransaction(Algorithm::Asset::BaseIdOf(Asset), BlockHeight, Signature, Decimal::Zero());
							for (auto& B : Token.second)
							{
								if (!B.second.IsPositive())
									continue;

								Decimal Delta = std::min(-A.second, B.second);
								Tx.SetOperations({ Transferer(A.first, Optional::None, Decimal(Delta)) }, { Transferer(B.first, Optional::None, Decimal(Delta)) });
								A.second += Delta;
								B.second -= Delta;
								if (A.second.IsZero())
									break;
							}
							Transactions.push_back(std::move(Tx));
						}
					}
					if (Index == Transactions.size())
						continue;

					auto Symbol = Coawait(GetTokenSymbol(Token.first));
					auto Replacement = Algorithm::Asset::IdOf(Algorithm::Asset::BlockchainOf(Asset), Symbol ? *Symbol : Token.first, Token.first);
					for (size_t i = Index - 1; i < Transactions.size(); i++)
						Transactions[i].Asset = Replacement;

					if (!Datamaster::EnableContractAddress(Replacement, Token.first))
						Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));
				}

				Addresses.clear();
				Addresses.reserve(Transactions.size() * 2);
				for (auto& Item : Transactions)
				{
					for (auto& Next : Item.From)
						Addresses.insert(Next.Address);
					for (auto& Next : Item.To)
						Addresses.insert(Next.Address);
				}

				Discovery = FindCheckpointAddresses(Asset, Addresses);
				if (!Discovery || Discovery->empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				for (auto& Item : Transactions)
				{
					for (auto& Next : Item.From)
					{
						auto Address = Discovery->find(Next.Address);
						if (Address != Discovery->end())
							Next.AddressIndex = Address->second;
					}
					for (auto& Next : Item.To)
					{
						auto Address = Discovery->find(Next.Address);
						if (Address != Discovery->end())
							Next.AddressIndex = Address->second;
					}
				}

				Coreturn ExpectsLR<Vector<IncomingTransaction>>(std::move(Transactions));
			}
			Promise<ExpectsLR<BaseFee>> Solana::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				Decimal Fee = 5000;
				if (!Algorithm::Asset::TokenOf(Asset).empty())
					Fee += Fee * 2;
				Fee /= Netdata.Divisibility;
				Coreturn ExpectsLR<BaseFee>(BaseFee(Fee, 1));
			}
			Promise<ExpectsLR<Decimal>> Solana::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
			{
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

				SchemaList Map;
				Map.emplace_back(Var::Set::String(*Address));
				Map.emplace_back(Var::Set::Null());

				auto Balance = Coawait(ExecuteRPC(Asset, NdCall::GetBalance(), std::move(Map), CachePolicy::Lazy));
				if (!Balance)
					Coreturn ExpectsLR<Decimal>(std::move(Balance.Error()));

				Decimal Value = Balance->GetVar("value").GetDecimal();
				Memory::Release(*Balance);
				Coreturn ExpectsLR<Decimal>(Value);
			}
			Promise<ExpectsLR<OutgoingTransaction>> Solana::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> FromWallet = LayerException();
				if (Wallet.Parent)
					FromWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					FromWallet = *Wallet.SigningChild;
				if (!FromWallet)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("signing wallet not found"));

				auto NativeBalance = Coawait(GetBalance(Asset, FromWallet->Addresses.begin()->second));
				if (!NativeBalance)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(NativeBalance.Error()));

				auto RecentBlockHash = Coawait(GetRecentBlockHash(Asset));
				if (!RecentBlockHash)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(RecentBlockHash.Error()));

				auto& Subject = To.front();
				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				Option<TokenAccount> FromToken = Optional::None;
				Option<TokenAccount> ToToken = Optional::None;
				Decimal TotalValue = Subject.Value;
				Decimal FeeValue = Fee.GetFee();
				if (ContractAddress)
				{
					auto FromTokenBalance = Coawait(GetTokenBalance(Asset, *ContractAddress, FromWallet->Addresses.begin()->second));
					if (!FromTokenBalance || FromTokenBalance->Balance < TotalValue)
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", (FromTokenBalance ? FromTokenBalance->Balance : Decimal(0.0)).ToString().c_str(), TotalValue.ToString().c_str())));

					auto ToTokenBalance = Coawait(GetTokenBalance(Asset, *ContractAddress, Subject.Address));
					if (!ToTokenBalance)
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("account %s does not have associated token account", Subject.Address.c_str())));

					TotalValue = FeeValue;
					FromToken = std::move(*FromTokenBalance);
					ToToken = std::move(*ToTokenBalance);
				}
				else
					TotalValue += FeeValue;

				if (*NativeBalance < TotalValue)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", NativeBalance->ToString().c_str(), TotalValue.ToString().c_str())));

				uint8_t FromTokenBuffer[32]; size_t FromTokenBufferSize = sizeof(FromTokenBuffer);
				if (FromToken && !b58dec(FromTokenBuffer, &FromTokenBufferSize, FromToken->Account.c_str(), FromToken->Account.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid sender token account"));

				uint8_t FromBuffer[32]; size_t FromBufferSize = sizeof(FromBuffer);
				if (!b58dec(FromBuffer, &FromBufferSize, FromWallet->Addresses.begin()->second.c_str(), FromWallet->Addresses.begin()->second.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid sender account"));

				uint8_t ToBuffer[32]; size_t ToBufferSize = sizeof(ToBuffer);
				if (ToToken && !b58dec(ToBuffer, &ToBufferSize, ToToken->Account.c_str(), ToToken->Account.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid receiver token account"));
				else if (!b58dec(ToBuffer, &ToBufferSize, Subject.Address.c_str(), Subject.Address.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid receiver account"));

				uint8_t ProgramId[32]; size_t ProgramIdSize = sizeof(ProgramId);
				String SystemProgramId = FromToken ? FromToken->ProgramId.c_str() : "11111111111111111111111111111111";
				if (!b58dec(ProgramId, &ProgramIdSize, SystemProgramId.c_str(), SystemProgramId.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid system program id"));

				uint8_t BlockHash[32]; size_t BlockHashSize = sizeof(BlockHash);
				if (!b58dec(BlockHash, &BlockHashSize, RecentBlockHash->c_str(), RecentBlockHash->size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid recent block hash"));

				uint64_t Value = (Subject.Value * (FromToken ? FromToken->Divisibility : Netdata.Divisibility)).ToUInt64();
				uint8_t Prefix = 1 << 7;
				uint8_t Signatures = 1;
				uint8_t AccountKeys = ContractAddress ? 4 : 3;
				uint8_t Instructions = 1;
				uint8_t Lookups = 0;

				TransactionHeader Header;
				Header.RequiredSignatures = 1;
				Header.ReadonlySignedAccounts = 0;
				Header.ReadonlyUnsignedAccounts = 1;

				Vector<uint8_t> MessageBuffer;
				TxAppend(MessageBuffer, (uint8_t*)&Prefix, sizeof(Prefix));
				TxAppend(MessageBuffer, (uint8_t*)&Header, sizeof(Header));
				TxAppend(MessageBuffer, (uint8_t*)&AccountKeys, sizeof(AccountKeys));
				TxAppend(MessageBuffer, FromBuffer, FromBufferSize);
				if (ContractAddress)
					TxAppend(MessageBuffer, FromTokenBuffer, FromTokenBufferSize);
				TxAppend(MessageBuffer, ToBuffer, ToBufferSize);
				TxAppend(MessageBuffer, ProgramId, ProgramIdSize);
				TxAppend(MessageBuffer, BlockHash, BlockHashSize);
				TxAppend(MessageBuffer, (uint8_t*)&Instructions, sizeof(Instructions));
				if (ContractAddress)
				{
					uint8_t Indices = 3, Size = 9, Instruction = 3;
					uint8_t ProgramIdIndex = 3, FromIndex = 0, ToIndex = 1, OwnerIndex = 2;
					TxAppend(MessageBuffer, (uint8_t*)&ProgramIdIndex, sizeof(ProgramIdIndex));
					TxAppend(MessageBuffer, (uint8_t*)&Indices, sizeof(Indices));
					TxAppend(MessageBuffer, (uint8_t*)&ToIndex, sizeof(ToIndex));
					TxAppend(MessageBuffer, (uint8_t*)&OwnerIndex, sizeof(OwnerIndex));
					TxAppend(MessageBuffer, (uint8_t*)&FromIndex, sizeof(FromIndex));
					TxAppend(MessageBuffer, (uint8_t*)&Size, sizeof(Size));
					TxAppend(MessageBuffer, (uint8_t*)&Instruction, sizeof(Instruction));
					TxAppend(MessageBuffer, (uint8_t*)&Value, sizeof(Value));
				}
				else
				{
					uint8_t Indices = 2, Size = 4 + 8;
					uint8_t ProgramIdIndex = 2, FromIndex = 0, ToIndex = 1;
					uint32_t Instruction = OS::CPU::ToEndianness<uint32_t>(OS::CPU::Endian::Little, 2);
					TxAppend(MessageBuffer, (uint8_t*)&ProgramIdIndex, sizeof(ProgramIdIndex));
					TxAppend(MessageBuffer, (uint8_t*)&Indices, sizeof(Indices));
					TxAppend(MessageBuffer, (uint8_t*)&FromIndex, sizeof(FromIndex));
					TxAppend(MessageBuffer, (uint8_t*)&ToIndex, sizeof(ToIndex));
					TxAppend(MessageBuffer, (uint8_t*)&Size, sizeof(Size));
					TxAppend(MessageBuffer, (uint8_t*)&Instruction, sizeof(Instruction));
					TxAppend(MessageBuffer, (uint8_t*)&Value, sizeof(Value));
				}
				TxAppend(MessageBuffer, (uint8_t*)&Lookups, sizeof(Lookups));

				uint8_t PrivateKey[64];
				if (!DecodePrivateKey(FromWallet->SigningKey.ExposeToHeap(), PrivateKey))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid private key"));

				uint8_t PublicKey[32]; size_t PublicKeySize = sizeof(PublicKey);
				if (!b58dec(PublicKey, &PublicKeySize, FromWallet->VerifyingKey.ExposeToHeap().c_str(), FromWallet->VerifyingKey.Size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid public key"));

				ed25519_signature Signature;
				ed25519_sign_ext(MessageBuffer.data(), MessageBuffer.size(), PrivateKey, PrivateKey + 32, Signature);
				if (crypto_sign_ed25519_verify_detached(Signature, MessageBuffer.data(), MessageBuffer.size(), PublicKey) != 0)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid private key"));

				Vector<uint8_t> TransactionBuffer;
				TxAppend(TransactionBuffer, (uint8_t*)&Signatures, sizeof(Signatures));
				TxAppend(TransactionBuffer, (uint8_t*)&Signature, sizeof(Signature));
				TransactionBuffer.insert(TransactionBuffer.end(), MessageBuffer.begin(), MessageBuffer.end());

				char TransactionId[256]; size_t TransactionIdSize = sizeof(TransactionId);
				if (!b58enc(TransactionId, &TransactionIdSize, &Signature, sizeof(Signature)))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid signature"));

				String TransactionData;
				TransactionData.resize(TransactionBuffer.size() * 4);

				size_t TransactionDataSize = TransactionData.size();
				if (!b58enc(TransactionData.data(), &TransactionDataSize, &TransactionBuffer[0], TransactionBuffer.size()))
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));

				TransactionData.resize(TransactionDataSize - 1);
				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, std::string_view(TransactionId, TransactionIdSize - 1), std::move(FeeValue));
				Tx.SetOperations({ Transferer(FromWallet->Addresses.begin()->second, Option<uint64_t>(FromWallet->AddressIndex), Decimal(FromToken ? Subject.Value : TotalValue)) }, Vector<Transferer>(To));
				Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData)));
			}
			Promise<ExpectsLR<String>> Solana::GetTokenSymbol(const std::string_view& Mint)
			{
				auto Metadata = Coawait(ExecuteHTTP(Algorithm::Asset::IdOf("SOL"), "GET", NdCall::GetTokenMetadata(Mint), std::string_view(), std::string_view(), CachePolicy::Persistent));
				if (!Metadata)
					Coreturn ExpectsLR<String>(std::move(Metadata.Error()));

				String Symbol1 = Metadata->FetchVar("tokenList.symbol").GetBlob();
				String Symbol2 = Metadata->FetchVar("tokenMetadata.onChainInfo.symbol").GetBlob();
				Memory::Release(*Metadata);
				if (!Symbol2.empty())
					Coreturn ExpectsLR<String>(std::move(Symbol2));

				if (!Symbol1.empty())
					Coreturn ExpectsLR<String>(std::move(Symbol1));

				Coreturn ExpectsLR<String>(LayerException("mint not found"));
			}
			Promise<ExpectsLR<Solana::TokenAccount>> Solana::GetTokenBalance(const Algorithm::AssetId& Asset, const std::string_view& Mint, const std::string_view& Owner)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Owner));
				Map.emplace_back(Var::Set::Object());
				Map.back()->Set("mint", Var::String(Mint));
				Map.emplace_back(Var::Set::Object());
				Map.back()->Set("encoding", Var::String("jsonParsed"));

				auto Balance = Coawait(ExecuteRPC(Asset, NdCall::GetTokenBalance(), std::move(Map), CachePolicy::Greedy));
				if (!Balance)
					Coreturn ExpectsLR<TokenAccount>(std::move(Balance.Error()));

				auto* Info = Balance->Fetch("value.0.account.data.parsed.info.tokenAmount");
				if (!Info)
				{
					Memory::Release(*Balance);
					Coreturn ExpectsLR<TokenAccount>(LayerException("invalid account"));
				}

				uint64_t Subdivisions = 1;
				uint64_t Decimals = std::min<uint64_t>(Info->GetVar("decimals").GetInteger(), Protocol::Now().Message.Precision);
				for (uint64_t i = 0; i < Decimals; i++)
					Subdivisions *= 10;

				String ProgramId = Balance->FetchVar("value.0.account.owner").GetBlob();
				String Account = Balance->FetchVar("value.0.pubkey").GetBlob();
				Decimal Value = Info->GetVar("amount").GetDecimal();
				Memory::Release(*Balance);
				if (Value.IsNaN())
					Coreturn ExpectsLR<TokenAccount>(LayerException("invalid account"));

				TokenAccount Result;
				Result.ProgramId = std::move(ProgramId);
				Result.Account = std::move(Account);
				Result.Divisibility = Decimal(Subdivisions).Truncate(Protocol::Now().Message.Precision);
				Result.Balance = Value / Result.Divisibility;
				Coreturn ExpectsLR<TokenAccount>(std::move(Result));
			}
			Promise<ExpectsLR<Decimal>> Solana::GetBalance(const Algorithm::AssetId& Asset, const std::string_view& Owner)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Owner));

				auto Balance = Coawait(ExecuteRPC(Asset, NdCall::GetBalance(), std::move(Map), CachePolicy::Greedy));
				if (!Balance)
					Coreturn ExpectsLR<Decimal>(std::move(Balance.Error()));

				Decimal Value = Balance->GetVar("value").GetDecimal();
				Memory::Release(*Balance);
				if (Value.IsNaN())
					Coreturn ExpectsLR<Decimal>(LayerException("invalid account"));

				Value /= Netdata.Divisibility;
				Coreturn ExpectsLR<Decimal>(std::move(Value));
			}
			Promise<ExpectsLR<String>> Solana::GetRecentBlockHash(const Algorithm::AssetId& Asset)
			{
				auto Hash = Coawait(ExecuteRPC(Asset, NdCall::GetBlockHash(), { }, CachePolicy::Greedy));
				if (!Hash)
					Coreturn ExpectsLR<String>(std::move(Hash.Error()));

				String Value = Hash->FetchVar("value.blockhash").GetBlob();
				Memory::Release(*Hash);
				if (Value.empty())
					Coreturn ExpectsLR<String>(LayerException("invalid hash"));

				Coreturn ExpectsLR<String>(std::move(Value));
			}
			ExpectsLR<MasterWallet> Solana::NewMasterWallet(const std::string_view& Seed)
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
			ExpectsLR<DerivedSigningWallet> Solana::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				auto* Chain = GetChain();
				char MasterPrivateKey[256];
				{
					auto Private = Wallet.SigningKey.Expose<2048>();
					if (!hd_derive(Chain, Private.Key, GetDerivation(Protocol::Now().Account.RootAddressIndex).c_str(), MasterPrivateKey, sizeof(MasterPrivateKey)))
						return ExpectsLR<DerivedSigningWallet>(LayerException("invalid private key"));
				}

				btc_hdnode Node;
				if (!btc_hdnode_deserialize(MasterPrivateKey, Chain, &Node))
					return ExpectsLR<DerivedSigningWallet>(LayerException("invalid private key"));

				auto Derived = NewSigningWallet(Asset, std::string_view((char*)Node.private_key, sizeof(Node.private_key)));
				if (Derived)
					Derived->AddressIndex = AddressIndex;
				return Derived;
			}
			ExpectsLR<DerivedSigningWallet> Solana::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey)
			{
				uint8_t TestPrivateKey[64]; String RawPrivateKey = String(SigningKey);
				if (DecodePrivateKey(SigningKey, TestPrivateKey))
					RawPrivateKey = String((char*)TestPrivateKey, sizeof(TestPrivateKey));
				else if (DecodeSecretOrPublicKey(SigningKey, TestPrivateKey))
					RawPrivateKey = String((char*)TestPrivateKey, 32);

				if (RawPrivateKey.size() != 32 && RawPrivateKey.size() != 64)
					return LayerException("invalid private key size");

				uint8_t PrivateKey[64]; String SecretKey;
				if (RawPrivateKey.size() == 32)
				{
					sha512_Raw((uint8_t*)RawPrivateKey.data(), RawPrivateKey.size(), PrivateKey);
					Algorithm::Composition::ConvertToED25519Curve(PrivateKey);

					char EncodedSecretKey[256]; size_t EncodedSecretKeySize = sizeof(EncodedSecretKey);
					if (!b58enc(EncodedSecretKey, &EncodedSecretKeySize, RawPrivateKey.data(), RawPrivateKey.size()))
						return LayerException("invalid private key");

					SecretKey.assign(EncodedSecretKey, EncodedSecretKeySize - 1);
				}
				else if (RawPrivateKey.size() == 64)
					memcpy(PrivateKey, RawPrivateKey.data(), RawPrivateKey.size());

				uint8_t PublicKey[32];
				ed25519_publickey_ext(PrivateKey, PublicKey);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicKey, sizeof(PublicKey)));
				if (!Derived)
					return Derived.Error();

				char EncodedPrivateKey[256]; size_t EncodedPrivateKeySize = sizeof(EncodedPrivateKey);
				if (!b58enc(EncodedPrivateKey, &EncodedPrivateKeySize, PrivateKey, sizeof(PrivateKey)))
					return LayerException("invalid private key");

				String DerivedPrivateKey = String(EncodedPrivateKey, EncodedPrivateKeySize - 1);
				if (!SecretKey.empty())
					DerivedPrivateKey.append(1, ':').append(SecretKey);
				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), ::PrivateKey(DerivedPrivateKey)));
			}
			ExpectsLR<DerivedVerifyingWallet> Solana::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
			{
				String RawPublicKey = String(VerifyingKey);
				if (RawPublicKey.size() != 32)
				{
					uint8_t PublicKey[32];
					if (!DecodeSecretOrPublicKey(RawPublicKey, PublicKey))
						return LayerException("invalid public key size");

					RawPublicKey = String((char*)PublicKey, sizeof(PublicKey));
				}

				char EncodedPublicKey[256]; size_t EncodedPublicKeySize = sizeof(EncodedPublicKey);
				if (!b58enc(EncodedPublicKey, &EncodedPublicKeySize, RawPublicKey.data(), RawPublicKey.size()))
					return LayerException("invalid public key");

				uint8_t DerivedPublicKey[256]; size_t DerivedPublicKeySize = sizeof(DerivedPublicKey);
				if (!b58dec(DerivedPublicKey, &DerivedPublicKeySize, EncodedPublicKey, EncodedPublicKeySize - 1))
					return LayerException("invalid public key");

				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, String(EncodedPublicKey, EncodedPublicKeySize - 1) } }, Optional::None, ::PrivateKey(std::string_view(EncodedPublicKey, EncodedPublicKeySize - 1))));
			}
			ExpectsLR<String> Solana::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Data[256]; size_t DataSize = sizeof(Data);
				if (!b58dec(Data, &DataSize, Address.data(), Address.size()))
					return LayerException("invalid address");

				return String((char*)Data, sizeof(Data));
			}
			ExpectsLR<String> Solana::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
			{
				auto SigningWallet = NewSigningWallet(Asset, SigningKey.ExposeToHeap());
				if (!SigningWallet)
					return SigningWallet.Error();

				uint8_t DerivedPrivateKey[64];
				auto Private = SigningWallet->SigningKey.Expose<2048>();
				if (!DecodePrivateKey(Private.Key, DerivedPrivateKey))
					return LayerException("private key invalid");

				ed25519_signature Signature;
				ed25519_sign_ext((uint8_t*)Message.data(), Message.size(), DerivedPrivateKey, DerivedPrivateKey + 32, Signature);
				return String((char*)Signature, sizeof(Signature));
			}
			ExpectsLR<void> Solana::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
			{
				VI_ASSERT(Stringify::IsCString(VerifyingKey), "verifying key must be c-string");
				if (Signature.size() < 64)
					return LayerException("signature invalid");

				auto VerifyingWallet = NewVerifyingWallet(Asset, VerifyingKey);
				if (!VerifyingWallet)
					return VerifyingWallet.Error();

				auto Public = VerifyingWallet->VerifyingKey.Expose<2048>();
				uint8_t DerivedPublicKey[256]; size_t DerivedPublicKeySize = sizeof(DerivedPublicKey);
				if (!b58dec(DerivedPublicKey, &DerivedPublicKeySize, Public.Key, (int)Public.Size))
					return LayerException("invalid public key");

				if (crypto_sign_verify_detached((uint8_t*)Signature.data(), (uint8_t*)Message.data(), Message.size(), DerivedPublicKey) != 0)
					return LayerException("signature verification failed with used public key");

				return Expectation::Met;
			}
			String Solana::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/501'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const Solana::Chainparams& Solana::GetChainparams() const
			{
				return Netdata;
			}
			bool Solana::DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[64])
			{
				auto Slice = String(Data.substr(0, Data.find(':')));
				uint8_t Key[64]; size_t KeySize = sizeof(Key);
				if (!b58dec(Key, &KeySize, Slice.c_str(), Slice.size()) || KeySize < 64)
					return false;

				memcpy(PrivateKey, Key, 64);
				return true;
			}
			bool Solana::DecodeSecretOrPublicKey(const std::string_view& Data, uint8_t SecretKey[32])
			{
				uint8_t Key[32]; size_t KeySize = sizeof(Key);
				if (!b58dec(Key, &KeySize, Data.data(), Data.size()) || KeySize < 32)
					return false;

				memcpy(SecretKey, Key, 32);
				return true;
			}
			const btc_chainparams_* Solana::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &sol_chainparams_regtest;
					case NetworkType::Testnet:
						return &sol_chainparams_test;
					case NetworkType::Mainnet:
						return &sol_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}