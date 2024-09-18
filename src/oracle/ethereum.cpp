#include "ethereum.h"
#include "../utils/tiny-bitcoin/bip32.h"
#include "../utils/tiny-bitcoin/tool.h"
#include "../utils/tiny-bitcoin/utils.h"
#include "../utils/tiny-bitcoin/ecc.h"
#include "../utils/tiny-ethereum/ecdsa.h"
#include "../utils/tiny-ethereum/rlp.h"
#include "../utils/tiny-ethereum/keccak256.h"
#include "../utils/tiny-ethereum/abi.h"
#include <secp256k1_recovery.h>
extern "C"
{
#include "../utils/trezor-crypto/sha3.h"
}

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			void eth_rlp_uint256(eth_rlp* Buffer, const uint256_t* Value)
			{
				String Hex = Value->ToString(16);
				char* HexData = (char*)Hex.data();
				int HexSize = (int)Hex.size();
				eth_rlp_hex(Buffer, &HexData, &HexSize);
			}
			void eth_rlp_address336(eth_rlp* Buffer, String* Value)
			{
				char* Data = (char*)Value->data();
				eth_rlp_address(Buffer, &Data);
			}
			void eth_rlp_binary(eth_rlp* Buffer, const String* Value)
			{
				if (!Value->empty())
				{
					uint8_t* Data = (uint8_t*)Value->data();
					size_t Size = Value->size();
					eth_rlp_bytes(Buffer, &Data, &Size);
				}
				else
				{
					uint8_t Zero = 0;
					eth_rlp_uint8(Buffer, &Zero);
				}
			}
			void eth_abi_uint256(eth_abi* Buffer, const uint256_t* Value)
			{
				mpz_t Numeric;
				mpz_init_set_str(Numeric, Value->ToString(16).c_str(), 16);
				eth_abi_mpint(Buffer, Numeric);
			}
			void eth_abi_address336(eth_abi* Buffer, const String* Value)
			{
				char* Data = (char*)Value->data();
				eth_abi_address(Buffer, &Data);
			}
			void eth_abi_call_begin(eth_abi* Buffer, const char* Value)
			{
				eth_abi_call(Buffer, (char**)&Value, nullptr);
			}
			void eth_abi_to_bytes(eth_abi* Buffer, String* Value)
			{
				char* Hex; size_t HexSize;
				eth_abi_to_hex(Buffer, &Hex, &HexSize);
				Value->assign(Hex, HexSize);
				*Value = Codec::HexDecode(*Value);
				free(Hex);
			}

			Ethereum::EvmSignature Ethereum::EvmTransaction::Sign(const binary_data_t& RawHash, const uint8_t PrivateKey[32])
			{
				eth_ecdsa_signature RawSignature;
				if (eth_ecdsa_sign(&RawSignature, PrivateKey, (uint8_t*)RawHash.c_str()) != 1)
					return EvmSignature();

				const uint32_t VChainId = (uint32_t)ChainId;
				const uint32_t VMultiplier = 2;
				const uint32_t VRecoveryId = (uint32_t)RawSignature.recid;
				const uint32_t VDerivation = 35;

				EvmSignature Signature;
				Signature.V = VChainId * VMultiplier + VRecoveryId + VDerivation;
				Signature.R = binary_data_t((char*)RawSignature.r, sizeof(RawSignature.r));
				Signature.S = binary_data_t((char*)RawSignature.s, sizeof(RawSignature.s));
				return Signature;
			}
			Ethereum::EvmSignedTransaction Ethereum::EvmTransaction::SerializeAndSign(const uint8_t PrivateKey[32])
			{
				EvmSignedTransaction Transaction;
				Transaction.Signature = Sign(Hash(Serialize()), PrivateKey);
				if (Transaction.Signature.R.empty() || Transaction.Signature.S.empty())
					return Transaction;

				Transaction.Data = Serialize(&Transaction.Signature);
				Transaction.Id = Hash(Transaction.Data);
				return Transaction;
			}
			Ethereum::binary_data_t Ethereum::EvmTransaction::Serialize(EvmSignature* Signature)
			{
				eth_rlp Buffer;
				eth_rlp_init(&Buffer, ETH_RLP_ENCODE);
				eth_rlp_array(&Buffer);
				eth_rlp_uint256(&Buffer, &Nonce);
				eth_rlp_uint256(&Buffer, &GasPrice);
				eth_rlp_uint256(&Buffer, &GasLimit);
				eth_rlp_address336(&Buffer, &Address);
				eth_rlp_uint256(&Buffer, &Value);
				eth_rlp_binary(&Buffer, &AbiData);
				if (Signature)
				{
					uint256_t V = Signature->V;
					eth_rlp_uint256(&Buffer, &V);
					eth_rlp_binary(&Buffer, &Signature->R);
					eth_rlp_binary(&Buffer, &Signature->S);
				}
				else
				{
					uint8_t Zero = 0;
					eth_rlp_uint256(&Buffer, &ChainId);
					eth_rlp_uint8(&Buffer, &Zero);
					eth_rlp_uint8(&Buffer, &Zero);
				}
				eth_rlp_array_end(&Buffer);

				uint8_t* Serialized; size_t SerializedSize;
				eth_rlp_to_bytes(&Serialized, &SerializedSize, &Buffer);
				eth_rlp_free(&Buffer);

				binary_data_t TxData = binary_data_t((const char*)Serialized, SerializedSize);
				free(Serialized);
				return TxData;
			}
			Ethereum::binary_data_t Ethereum::EvmTransaction::Hash(const binary_data_t& SerializedData)
			{
				size_t SerializedSize = SerializedData.size();
				uint8_t* Serialized = Memory::Allocate<uint8_t>(sizeof(uint8_t) * SerializedSize);
				memcpy(Serialized, SerializedData.data(), sizeof(uint8_t) * SerializedSize);

				uint8_t Hash[32];
				eth_keccak256(Hash, Serialized, SerializedSize);
				Memory::Deallocate(Serialized);

				return binary_data_t((char*)Hash, sizeof(Hash));
			}

			const char* Ethereum::ScFunction::Symbol()
			{
				return "symbol()";
			}
			const char* Ethereum::ScFunction::Decimals()
			{
				return "decimals()";
			}
			const char* Ethereum::ScFunction::BalanceOf()
			{
				return "balanceOf(address)";
			}
			const char* Ethereum::ScFunction::Transfer()
			{
				return "transfer(address,uint256)";
			}
			const char* Ethereum::ScFunction::TransferFrom()
			{
				return "transferFrom(address,address,uint256)";
			}

			Ethereum::binary_data_t Ethereum::ScCall::Symbol()
			{
				String RawData;
				struct eth_abi Evm;
				eth_abi_init(&Evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&Evm, ScFunction::Symbol());
				eth_abi_call_end(&Evm);
				eth_abi_to_bytes(&Evm, &RawData);
				eth_abi_free(&Evm);
				return RawData;
			}
			Ethereum::binary_data_t Ethereum::ScCall::Decimals()
			{
				String RawData;
				struct eth_abi Evm;
				eth_abi_init(&Evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&Evm, ScFunction::Decimals());
				eth_abi_call_end(&Evm);
				eth_abi_to_bytes(&Evm, &RawData);
				eth_abi_free(&Evm);
				return RawData;
			}
			Ethereum::binary_data_t Ethereum::ScCall::BalanceOf(const String& Address)
			{
				String RawData;
				struct eth_abi Evm;
				eth_abi_init(&Evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&Evm, ScFunction::BalanceOf());
				eth_abi_address336(&Evm, &Address);
				eth_abi_call_end(&Evm);
				eth_abi_to_bytes(&Evm, &RawData);
				eth_abi_free(&Evm);
				return RawData;
			}
			Ethereum::binary_data_t Ethereum::ScCall::Transfer(const String& Address, const uint256_t& Value)
			{
				String RawData;
				struct eth_abi Evm;
				eth_abi_init(&Evm, ETH_ABI_ENCODE);
				eth_abi_call_begin(&Evm, ScFunction::Transfer());
				eth_abi_address336(&Evm, &Address);
				eth_abi_uint256(&Evm, &Value);
				eth_abi_call_end(&Evm);
				eth_abi_to_bytes(&Evm, &RawData);
				eth_abi_free(&Evm);
				return RawData;
			}

			const char* Ethereum::NdCall::GetBlockByNumber()
			{
				return "eth_getBlockByNumber";
			}
			const char* Ethereum::NdCall::GetTransactionReceipt()
			{
				return "eth_getTransactionReceipt";
			}
			const char* Ethereum::NdCall::GetTransactionByHash()
			{
				return "eth_getTransactionByHash";
			}
			const char* Ethereum::NdCall::GetTransactionCount()
			{
				return "eth_getTransactionCount";
			}
			const char* Ethereum::NdCall::GetBalance()
			{
				return "eth_getBalance";
			}
			const char* Ethereum::NdCall::GetChainId()
			{
				return "eth_chainId";
			}
			const char* Ethereum::NdCall::BlockNumber()
			{
				return "eth_blockNumber";
			}
			const char* Ethereum::NdCall::EstimateGas()
			{
				return "eth_estimateGas";
			}
			const char* Ethereum::NdCall::GasPrice()
			{
				return "eth_gasPrice";
			}
			const char* Ethereum::NdCall::Call()
			{
				return "eth_call";
			}
			const char* Ethereum::NdCall::SendRawTransaction()
			{
				return "eth_sendRawTransaction";
			}

			Promise<ExpectsLR<Schema*>> Ethereum::GetTransactionReceipt(const Algorithm::AssetId& Asset, const std::string_view& TransactionId)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Format::Util::Assign0xHex(TransactionId)));

				auto TxData = Coawait(ExecuteRPC(Asset, NdCall::GetTransactionReceipt(), std::move(Map), CachePolicy::Shortened));
				Coreturn TxData;
			}
			Promise<ExpectsLR<uint256_t>> Ethereum::GetTransactionsCount(const Algorithm::AssetId& Asset, const std::string_view& Address)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<uint256_t>(LayerException("chain not found"));

				SchemaList LatestMap;
				LatestMap.emplace_back(Var::Set::String(Implementation->DecodeNonEthAddress(Address)));
				LatestMap.emplace_back(Var::Set::String("latest"));

				auto LatestTransactionCount = Coawait(ExecuteRPC(Asset, NdCall::GetTransactionCount(), std::move(LatestMap), CachePolicy::Lazy));
				if (!LatestTransactionCount)
					Coreturn ExpectsLR<uint256_t>(std::move(LatestTransactionCount.Error()));

				uint256_t TransactionsCount = Implementation->HexToUint256(LatestTransactionCount->Value.GetBlob());
				Memory::Release(*LatestTransactionCount);

				SchemaList PendingMap;
				PendingMap.emplace_back(Var::Set::String(Implementation->DecodeNonEthAddress(Address)));
				PendingMap.emplace_back(Var::Set::String("pending"));

				auto PendingTransactionCount = UPtr<Schema>(Coawait(ExecuteRPC(Asset, NdCall::GetTransactionCount(), std::move(PendingMap), CachePolicy::Lazy)));
				if (PendingTransactionCount)
				{
					uint256_t PendingTransactionsCount = Implementation->HexToUint256(PendingTransactionCount->Value.GetBlob());
					if (PendingTransactionsCount > TransactionsCount)
						TransactionsCount = PendingTransactionsCount;
				}

				Coreturn ExpectsLR<uint256_t>(std::move(TransactionsCount));
			}
			Promise<ExpectsLR<uint256_t>> Ethereum::GetChainId(const Algorithm::AssetId& Asset)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<uint256_t>(LayerException("chain not found"));

				auto HexChainId = Coawait(ExecuteRPC(Asset, NdCall::GetChainId(), { }, CachePolicy::Persistent));
				if (!HexChainId)
					Coreturn ExpectsLR<uint256_t>(std::move(HexChainId.Error()));

				uint256_t ChainId = Implementation->HexToUint256(HexChainId->Value.GetBlob());
				Memory::Release(*HexChainId);
				Coreturn ExpectsLR<uint256_t>(std::move(ChainId));
			}
			Promise<ExpectsLR<String>> Ethereum::GetContractSymbol(const Algorithm::AssetId& Asset, Chains::Ethereum* Implementation, const std::string_view& ContractAddress)
			{
				UPtr<Schema> Params = Var::Set::Object();
				Params->Set("to", Var::String(Implementation->DecodeNonEthAddress(ContractAddress)));
				Params->Set("data", Var::String(Implementation->GenerateUncheckedAddress(Chains::Ethereum::ScCall::Decimals())));

				SchemaList Map;
				Map.emplace_back(std::move(Params));
				Map.emplace_back(Var::Set::String("latest"));

				auto Symbol = Coawait(ExecuteRPC(Asset, NdCall::Call(), std::move(Map), CachePolicy::Persistent));
				if (!Symbol)
					Coreturn ExpectsLR<String>(std::move(Symbol.Error()));

				Coreturn ExpectsLR<String>(Symbol->Value.GetBlob());
			}
			Promise<ExpectsLR<Decimal>> Ethereum::GetContractDivisibility(const Algorithm::AssetId& Asset, Chains::Ethereum* Implementation, const std::string_view& ContractAddress)
			{
				UPtr<Schema> Params = Var::Set::Object();
				Params->Set("to", Var::String(Implementation->DecodeNonEthAddress(ContractAddress)));
				Params->Set("data", Var::String(Implementation->GenerateUncheckedAddress(Chains::Ethereum::ScCall::Decimals())));

				SchemaList Map;
				Map.emplace_back(std::move(Params));
				Map.emplace_back(Var::Set::String("latest"));

				auto Decimals = Coawait(ExecuteRPC(Asset, NdCall::Call(), std::move(Map), CachePolicy::Persistent));
				if (!Decimals)
					Coreturn ExpectsLR<Decimal>(std::move(Decimals.Error()));

				uint64_t Divisibility = 1;
				uint64_t Value = std::min<uint64_t>((uint64_t)Implementation->HexToUint256(Decimals->Value.GetBlob()), Protocol::Now().Message.Precision);
				for (uint64_t i = 0; i < Value; i++)
					Divisibility *= 10;
				Coreturn ExpectsLR<Decimal>(Decimal(Divisibility));
			}
			Promise<ExpectsLR<void>> Ethereum::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				auto Duplicate = Coawait(GetTransactionReceipt(Asset, Format::Util::Assign0xHex(TxData.Transaction.TransactionId)));
				if (Duplicate)
				{
					Memory::Release(*Duplicate);
					Coreturn ExpectsLR<void>(Expectation::Met);
				}

				SchemaList Map;
				Map.emplace_back(Var::Set::String(Format::Util::Assign0xHex(TxData.Data)));

				auto HexData = Coawait(ExecuteRPC(Asset, NdCall::SendRawTransaction(), std::move(Map), CachePolicy::Greedy));
				if (!HexData)
					Coreturn ExpectsLR<void>(std::move(HexData.Error()));

				Memory::Release(*HexData);
				Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Promise<ExpectsLR<uint64_t>> Ethereum::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<uint64_t>(LayerException("chain not found"));

				auto BlockCount = Coawait(ExecuteRPC(Asset, NdCall::BlockNumber(), { }, CachePolicy::Lazy));
				if (!BlockCount)
					Coreturn ExpectsLR<uint64_t>(std::move(BlockCount.Error()));

				uint64_t BlockHeight = (uint64_t)Implementation->HexToUint256(BlockCount->Value.GetBlob());
				Memory::Release(*BlockCount);
				Coreturn ExpectsLR<uint64_t>(BlockHeight);
			}
			Promise<ExpectsLR<Schema*>> Ethereum::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<Schema*>(LayerException("chain not found"));

				SchemaList Map;
				Map.emplace_back(Var::Set::String(((Chains::Ethereum*)Implementation)->Uint256ToHex(BlockHeight)));
				Map.emplace_back(Var::Set::Boolean(true));

				auto BlockData = Coawait(ExecuteRPC(Asset, NdCall::GetBlockByNumber(), std::move(Map), CachePolicy::Shortened));
				if (!BlockData)
					Coreturn BlockData;

				if (BlockHash != nullptr)
					*BlockHash = BlockData->GetVar("hash").GetBlob();

				auto* Transactions = BlockData->Get("transactions");
				if (!Transactions)
				{
					Memory::Release(*BlockData);
					Coreturn ExpectsLR<Schema*>(LayerException("transactions field not found"));
				}

				Transactions->Unlink();
				Memory::Release(*BlockData);
				if (!Legacy.GetLogs)
				{
					auto* Query = Var::Set::Array();
					auto* Cursor = Query->Push(Var::Set::Object());
					Cursor->Set("fromBlock", Var::Set::String(Implementation->Uint256ToHex(BlockHeight)));
					Cursor->Set("toBlock", Var::Set::String(Implementation->Uint256ToHex(BlockHeight)));
					Cursor->Set("topics", Var::Set::Array())->Push(Var::String(Implementation->GetTokenTransferSignature()));

					SchemaList Map;
					Map.emplace_back(Query);

					auto LogsData = Coawait(ExecuteRPC(Asset, NdCall::GetBlockByNumber(), std::move(Map), CachePolicy::Shortened));
					if (LogsData)
					{
						auto* Logs = LogsData->Get("result");
						if (Logs != nullptr && !Logs->Empty())
						{
							UnorderedMap<String, Schema*> Indices;
							for (auto& Item : Transactions->GetChilds())
							{
								String TxHash = Item->GetVar("hash").GetBlob();
								Indices[TxHash] = Item;
							}

							for (auto& Item : Logs->GetChilds())
							{
								String TxHash = Item->GetVar("transactionHash").GetBlob();
								auto It = Indices.find(TxHash);
								if (It != Indices.end())
									It->second->Set("logs", Item->Copy());
							}
						}
						Memory::Release(*LogsData);
					}
					else
						Legacy.GetLogs = 1;
				}
				Coreturn ExpectsLR<Schema*>(Transactions);
			}
			Promise<ExpectsLR<Schema*>> Ethereum::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Format::Util::Assign0xHex(TransactionId)));

				auto TxData = Coawait(ExecuteRPC(Asset, NdCall::GetTransactionByHash(), std::move(Map), CachePolicy::Extended));
				Coreturn TxData;
			}
			Promise<ExpectsLR<Vector<IncomingTransaction>>> Ethereum::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("chain not found"));

				auto* Chain = Implementation->GetChain();
				String Data = TransactionData->GetVar("input").GetBlob();
				if (Stringify::StartsWith(Data, Chain->bech32_hrp))
					Data.erase(0, strlen(Chain->bech32_hrp));

				String TxHash = TransactionData->GetVar("hash").GetBlob();
				String From = Implementation->EncodeEthAddress(TransactionData->GetVar("from").GetBlob());
				String To = Implementation->EncodeEthAddress(TransactionData->GetVar("to").GetBlob());
				Decimal GasPrice = Implementation->ToEth(Implementation->HexToUint256(TransactionData->GetVar("gasPrice").GetBlob()), Implementation->GetDivisibilityGwei());
				Decimal GasLimit = Implementation->ToEth(Implementation->HexToUint256(GetRawGasLimit(TransactionData)), Implementation->GetDivisibilityGwei());
				Decimal BaseValue = Implementation->ToEth(Implementation->HexToUint256(TransactionData->GetVar("value").GetBlob()), Implementation->GetDivisibility());;
				Decimal FeeValue = GasPrice * GasLimit;

				IncomingTransaction CoinTx;
				CoinTx.SetTransaction(Asset, BlockHeight, TxHash, Decimal(FeeValue));
				CoinTx.SetOperations({ Transferer(From, Optional::None, Decimal(BaseValue)) }, { Transferer(To, Optional::None, Decimal(BaseValue)) });

				Vector<IncomingTransaction> Results;
				Results.push_back(std::move(CoinTx));
				if (!Data.empty())
				{
					auto* Logs = TransactionData->Get("logs");
					if (!Logs)
					{
						auto TxReceipt = Coawait(GetTransactionReceipt(Asset, TransactionData->GetVar("hash").GetBlob()));
						if (TxReceipt)
						{
							Logs = TxReceipt->Get("logs");
							if (Logs != nullptr)
							{
								Logs->Unlink();
								TransactionData->Set("logs", Logs);
							}
							TransactionData->Set("receipt", *TxReceipt);
						}
						else
							TransactionData->Set("receipt", Var::Set::Null());
					}

					if (Logs != nullptr && !Logs->Empty())
					{
						for (auto& Invocation : Logs->GetChilds())
						{
							auto* Topics = Invocation->Get("topics");
							auto ContractAddress = Implementation->EncodeEthAddress(Invocation->GetVar("address").GetBlob());
							if (!Topics || (Topics->Size() != 2 && Topics->Size() != 3) || !Implementation->IsTokenTransfer(Topics->GetVar(0).GetBlob()))
								continue;

							auto Symbol = Coawait(GetContractSymbol(Asset, Implementation, ContractAddress));
							if (!Symbol)
								continue;

							auto TokenAsset = Algorithm::Asset::IdOf(Algorithm::Asset::BlockchainOf(Asset), *Symbol, ContractAddress);
							if (!Datamaster::EnableContractAddress(TokenAsset, ContractAddress))
								continue;

							Decimal Divisibility = Coawait(GetContractDivisibility(Asset, Implementation, ContractAddress)).Or(Implementation->GetDivisibility());
							Decimal TokenValue = Implementation->ToEth(Implementation->HexToUint256(Invocation->GetVar("data").GetBlob()), Divisibility);
							if (Topics->Size() == 3)
							{
								From = Implementation->EncodeEthAddress(Implementation->NormalizeTopicAddress(Topics->GetVar(1).GetBlob()));
								To = Implementation->EncodeEthAddress(Implementation->NormalizeTopicAddress(Topics->GetVar(2).GetBlob()));
							}
							else if (Topics->Size() == 2)
								To = Implementation->EncodeEthAddress(Topics->GetVar(1).GetBlob());

							IncomingTransaction TokenTx;
							TokenTx.SetTransaction(std::move(TokenAsset), BlockHeight, TxHash, Decimal::Zero());
							TokenTx.SetOperations({ Transferer(From, Optional::None, Decimal(TokenValue)) }, { Transferer(To, Optional::None, Decimal(TokenValue)) });
							Results.push_back(std::move(TokenTx));
						}
					}
				}
				Results.erase(std::remove_if(Results.begin(), Results.end(), [](IncomingTransaction& V)
				{
					return !V.GetOutputValue().IsPositive();
				}), Results.end());

				UnorderedSet<String> Addresses;
				Addresses.reserve(Results.size() * 2);
				for (auto& Item : Results)
				{
					for (auto& Next : Item.From)
						Addresses.insert(Next.Address);
					for (auto& Next : Item.To)
						Addresses.insert(Next.Address);
				}

				auto Discovery = FindCheckpointAddresses(Asset, Addresses);
				if (!Discovery || Discovery->empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				Schema* TxReceiptCache = TransactionData->Get("receipt");
				Schema* TxReceipt = TxReceiptCache ? TxReceiptCache : Coawait(GetTransactionReceipt(Asset, TxHash)).Or(nullptr);
				bool IsReverted = TxReceipt && TxReceipt->Value.IsObject() ? Implementation->HexToUint256(TxReceipt->GetVar("status").GetBlob()) < 1 : false;
				for (auto& Item : Results)
				{
					for (auto& Next : Item.From)
					{
						auto Address = Discovery->find(Next.Address);
						if (Address != Discovery->end())
							Next.AddressIndex = Address->second;
						if (IsReverted)
							Next.Value = 0.0;
					}
					for (auto& Next : Item.To)
					{
						auto Address = Discovery->find(Next.Address);
						if (Address != Discovery->end())
							Next.AddressIndex = Address->second;
						if (IsReverted)
							Next.Value = 0.0;
					}
				}
				Coreturn ExpectsLR<Vector<IncomingTransaction>>(Results);
			}
			Promise<ExpectsLR<BaseFee>> Ethereum::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
				auto GasPriceEstimate = Coawait(ExecuteRPC(Asset, NdCall::GasPrice(), { }, CachePolicy::Greedy));
				if (!GasPriceEstimate)
					Coreturn ExpectsLR<BaseFee>(std::move(GasPriceEstimate.Error()));

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
					Coreturn ExpectsLR<BaseFee>(std::move(FromWallet.Error()));

				auto& Subject = To.front();
				UPtr<Schema> Params = Var::Set::Object();
				Params->Set("gasPrice", Var::String(GasPriceEstimate->Value.GetBlob()));
				Params->Set("from", Var::String(Implementation->DecodeNonEthAddress(FromWallet->Addresses.begin()->second)));

				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				Decimal Divisibility = Implementation->GetDivisibility();
				if (ContractAddress)
				{
					auto ContractDivisibility = Coawait(GetContractDivisibility(Asset, Implementation, *ContractAddress));
					if (ContractDivisibility)
						Divisibility = *ContractDivisibility;
				}

				uint64_t DefaultGasLimit;
				uint256_t Value = Implementation->FromEth(Subject.Value, Divisibility);
				if (ContractAddress)
				{
					DefaultGasLimit = Implementation->GetErc20TransferGasLimitGwei();
					Params->Set("to", Var::String(Implementation->DecodeNonEthAddress(*ContractAddress)));
					Params->Set("value", Var::String(Implementation->Uint256ToHex(0)));
					Params->Set("gas", Var::String(Implementation->Uint256ToHex(DefaultGasLimit)));
					Params->Set("data", Var::String(Implementation->GenerateUncheckedAddress(Chains::Ethereum::ScCall::Transfer(Implementation->DecodeNonEthAddress(Subject.Address), Value))));
				}
				else
				{
					DefaultGasLimit = Implementation->GetEthTransferGasLimitGwei();
					Params->Set("to", Var::String(Implementation->DecodeNonEthAddress(Subject.Address)));
					Params->Set("value", Var::String(Implementation->Uint256ToHex(Value)));
					Params->Set("gas", Var::String(Implementation->Uint256ToHex(DefaultGasLimit)));
				}

				SchemaList Map;
				Map.emplace_back(std::move(Params));
				Map.emplace_back(Var::Set::String("latest"));

				auto GasLimitEstimate = UPtr<Schema>(Coawait(ExecuteRPC(Asset, NdCall::EstimateGas(), std::move(Map), CachePolicy::Greedy)));
				if (!GasLimitEstimate)
				{
					Decimal GasPrice = Implementation->ToEth(Implementation->HexToUint256(GasPriceEstimate->Value.GetBlob()), Implementation->GetDivisibilityGwei());
					Decimal GasLimit = Implementation->ToEth(DefaultGasLimit, Implementation->GetDivisibilityGwei());
					Memory::Release(*GasPriceEstimate);
					Coreturn ExpectsLR<BaseFee>(BaseFee(GasPrice, GasLimit));
				}

				uint256_t VGasLimit = Implementation->HexToUint256(GasLimitEstimate->Value.GetBlob());
				Decimal GasPrice = Implementation->ToEth(Implementation->HexToUint256(GasPriceEstimate->Value.GetBlob()), Implementation->GetDivisibilityGwei());
				Decimal GasLimit = Implementation->ToEth(VGasLimit, Implementation->GetDivisibilityGwei());
				Memory::Release(*GasPriceEstimate);
				Coreturn ExpectsLR<BaseFee>(BaseFee(GasPrice, GasLimit));
			}
			Promise<ExpectsLR<Decimal>> Ethereum::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
			{
				auto* Implementation = (Chains::Ethereum*)Datamaster::GetChain(Asset);
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

				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				Decimal Divisibility = Implementation->GetDivisibility();
				if (ContractAddress)
				{
					auto ContractDivisibility = Coawait(GetContractDivisibility(Asset, Implementation, *ContractAddress));
					if (ContractDivisibility)
						Divisibility = *ContractDivisibility;
				}

				const char* Method = nullptr;
				Schema* Params = nullptr;
				if (ContractAddress)
				{
					Method = NdCall::Call();
					Params = Var::Set::Object();
					Params->Set("to", Var::String(Implementation->DecodeNonEthAddress(*ContractAddress)));
					Params->Set("data", Var::String(Implementation->GenerateUncheckedAddress(Chains::Ethereum::ScCall::BalanceOf(Implementation->DecodeNonEthAddress(*Address)))));
				}
				else
				{
					Method = NdCall::GetBalance();
					Params = Var::Set::String(Implementation->DecodeNonEthAddress(*Address));
				}

				SchemaList Map;
				Map.emplace_back(Params);
				Map.emplace_back(Var::Set::String("latest"));

				auto ConfirmedBalance = Coawait(ExecuteRPC(Asset, Method, std::move(Map), CachePolicy::Lazy));
				if (!ConfirmedBalance)
					Coreturn ExpectsLR<Decimal>(std::move(ConfirmedBalance.Error()));

				Decimal Balance = Implementation->ToEth(Implementation->HexToUint256(ConfirmedBalance->Value.GetBlob()), Divisibility);
				Memory::Release(*ConfirmedBalance);
				Coreturn ExpectsLR<Decimal>(std::move(Balance));
			}
			Promise<ExpectsLR<OutgoingTransaction>> Ethereum::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> FromWallet = LayerException();
				if (Wallet.Parent)
					FromWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					FromWallet = *Wallet.SigningChild;
				if (!FromWallet)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("signing wallet not found"));

				auto ChainId = Coawait(GetChainId(Asset));
				if (!ChainId)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(ChainId.Error()));

				auto& Subject = To.front();
				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				Decimal FeeValue = Fee.GetFee();
				Decimal TotalValue = Subject.Value;
				if (ContractAddress)
				{
					auto Balance = Coawait(CalculateBalance(Algorithm::Asset::BaseIdOf(Asset), Wallet, FromWallet->Addresses.begin()->second));
					if (!Balance || *Balance < FeeValue)
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", (Balance ? *Balance : Decimal(0.0)).ToString().c_str(), FeeValue.ToString().c_str())));
				}
				else
					TotalValue += FeeValue;

				auto Balance = Coawait(CalculateBalance(Asset, Wallet, FromWallet->Addresses.begin()->second));
				if (!Balance || *Balance < TotalValue)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", (Balance ? *Balance : Decimal(0.0)).ToString().c_str(), TotalValue.ToString().c_str())));

				auto Nonce = Coawait(GetTransactionsCount(Asset, FromWallet->Addresses.begin()->second));
				if (!Nonce)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("nonce value invalid"));

				EvmTransaction Transaction;
				Transaction.ChainId = *ChainId;
				Transaction.Nonce = *Nonce;
				Transaction.GasPrice = FromEth(Fee.Price, GetDivisibilityGwei());
				Transaction.GasLimit = FromEth(Fee.Limit, GetDivisibilityGwei());

				Decimal Divisibility = GetDivisibility();
				if (ContractAddress)
				{
					auto ContractDivisibility = Coawait(GetContractDivisibility(Asset, this, *ContractAddress));
					if (ContractDivisibility)
						Divisibility = *ContractDivisibility;
				}

				uint256_t Value = FromEth(Subject.Value, Divisibility);
				if (ContractAddress)
				{
					Transaction.Address = DecodeNonEthAddress(*ContractAddress);
					Transaction.AbiData = ScCall::Transfer(Subject.Address, Value);
				}
				else
				{
					Transaction.Address = DecodeNonEthAddress(Subject.Address);
					Transaction.Value = Value;
				}

				uint8_t RawPrivateKey[256];
				auto PrivateKey = FromWallet->SigningKey.Expose<2048>();
				GeneratePrivateKeyDataFromPrivateKey(PrivateKey.Key, PrivateKey.Size, RawPrivateKey);

				EvmSignedTransaction Info = Transaction.SerializeAndSign(RawPrivateKey);
				if (Info.Signature.R.empty() || Info.Signature.S.empty())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid private key"));
				else if (Info.Id.empty() || Info.Data.empty())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));

				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, Info.Id, std::move(FeeValue));
				Tx.SetOperations({ Transferer(FromWallet->Addresses.begin()->second, Option<uint64_t>(FromWallet->AddressIndex), Decimal(Subject.Value)) }, Vector<Transferer>(To));
				Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(Info.Data)));
			}
			ExpectsLR<MasterWallet> Ethereum::NewMasterWallet(const std::string_view& Seed)
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
			ExpectsLR<DerivedSigningWallet> Ethereum::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
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
			ExpectsLR<DerivedSigningWallet> Ethereum::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPrivateKey)
			{
				btc_key PrivateKey;
				btc_privkey_init(&PrivateKey);
				memcpy(PrivateKey.privkey, RawPrivateKey.data(), std::min(RawPrivateKey.size(), sizeof(PrivateKey.privkey)));

				char PublicKeyData[128]; size_t PublicKeyDataSize = BTC_ECKEY_UNCOMPRESSED_LENGTH;
				btc_ecc_get_pubkey(PrivateKey.privkey, (uint8_t*)PublicKeyData, &PublicKeyDataSize, false);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicKeyData + 1, PublicKeyDataSize - 1));
				if (!Derived)
					return Derived.Error();

				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), 
					::PrivateKey(GenerateUncheckedAddress(std::string_view((char*)PrivateKey.privkey, sizeof(PrivateKey.privkey))))));
			}
			ExpectsLR<DerivedVerifyingWallet> Ethereum::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& RawPublicKey)
			{
				if (RawPublicKey.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1 && RawPublicKey.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH && RawPublicKey.size() != BTC_ECKEY_COMPRESSED_LENGTH)
					return LayerException("invalid public key size");

				uint8_t PublicKey[BTC_ECKEY_UNCOMPRESSED_LENGTH] = { 0 };
				if (RawPublicKey.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH - 1)
				{
					secp256k1_pubkey CandidatePublicKey;
					secp256k1_context* Context = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
					if (secp256k1_ec_pubkey_parse(Context, &CandidatePublicKey, (uint8_t*)RawPublicKey.data(), RawPublicKey.size()) != 1)
					{
						secp256k1_context_destroy(Context);
						return LayerException("invalid public key");
					}

					size_t PublicKeySize = sizeof(PublicKey);
					if (secp256k1_ec_pubkey_serialize(Context, PublicKey, &PublicKeySize, &CandidatePublicKey, SECP256K1_EC_UNCOMPRESSED) != 1)
					{
						secp256k1_context_destroy(Context);
						return LayerException("invalid public key");
					}

					secp256k1_context_destroy(Context);
				}
				else
					memcpy(PublicKey + 1, RawPublicKey.data(), RawPublicKey.size());

				char PublicKeyHash[20];
				GeneratePublicKeyHashFromPublicKey(PublicKey + 1, PublicKeyHash);
				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, EncodeEthAddress(GeneratePkhAddress(PublicKeyHash)) } }, Optional::None, ::PrivateKey(GenerateUncheckedAddress(std::string_view((char*)PublicKey + 1, sizeof(PublicKey) - 1)))));
			}
			ExpectsLR<String> Ethereum::NewPublicKeyHash(const std::string_view& Address)
			{
				auto Data = Codec::HexDecode(Address);
				if (Data.empty())
					return LayerException("invalid address");

				return Data;
			}
			ExpectsLR<String> Ethereum::SignMessage(const Messages::Generic& Message, const DerivedSigningWallet& Wallet)
			{
				uint256 Hash;
				GenerateMessageHash(Message.AsMessage().Data, Hash);

				uint8_t RawPrivateKey[256];
				auto PrivateKey = Wallet.SigningKey.Expose<2048>();
				GeneratePrivateKeyDataFromPrivateKey(PrivateKey.Key, PrivateKey.Size, RawPrivateKey);

				eth_ecdsa_signature RawSignature;
				if (eth_ecdsa_sign(&RawSignature, RawPrivateKey, Hash) != 1)
					return LayerException("private key not valid");

				uint8_t Signature[65];
				memcpy(Signature + 00, RawSignature.r, sizeof(RawSignature.r));
				memcpy(Signature + 32, RawSignature.s, sizeof(RawSignature.s));
				Signature[64] = RawSignature.recid;
				return String((char*)Signature, sizeof(Signature));
			}
			ExpectsLR<bool> Ethereum::VerifyMessage(const Messages::Generic& Message, const std::string_view& Address, const std::string_view& PublicKey, const std::string_view& Signature)
			{
				if (Signature.size() < 64)
					return LayerException("signature not valid");

				uint256 Hash;
				GenerateMessageHash(Message.AsMessage().Data, Hash);

				secp256k1_context* Context = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
				if (!Context)
					return LayerException("context not valid");

				bool CompactRetry = false;
				String RawSignature = String(Signature);
			Retry:
				for (int i = 0; i < 4; i++)
				{
					secp256k1_ecdsa_recoverable_signature EcdsaSignature;
					secp256k1_ecdsa_recoverable_signature_parse_compact(Context, &EcdsaSignature, (uint8_t*)RawSignature.data(), i);

					secp256k1_pubkey PubKey;
					if (secp256k1_ecdsa_recover(Context, &PubKey, &EcdsaSignature, Hash) != 1)
						continue;

					char SerializedPubKey[65]; size_t SerializedPubKeySize = sizeof(SerializedPubKey);
					if (secp256k1_ec_pubkey_serialize(Context, (uint8_t*)SerializedPubKey, &SerializedPubKeySize, &PubKey, SECP256K1_EC_UNCOMPRESSED) != 1)
						continue;

					char ActualPublicKeyHash1[20], ActualPublicKeyHash2[20];
					GeneratePublicKeyHashFromPublicKey((uint8_t*)SerializedPubKey, ActualPublicKeyHash1);
					GeneratePublicKeyHashFromPublicKey((uint8_t*)SerializedPubKey + 1, ActualPublicKeyHash2);
					String ActualAddress1 = GeneratePkhAddress(ActualPublicKeyHash1);
					String ActualAddress2 = GeneratePkhAddress(ActualPublicKeyHash2);
					String TargetAddress = GenerateChecksumAddress(DecodeNonEthAddress(Address));
					if (ActualAddress1 == TargetAddress || ActualAddress2 == TargetAddress)
					{
						secp256k1_context_destroy(Context);
						return true;
					}
				}

				if (!CompactRetry && RawSignature.size() == 64)
				{
					RawSignature[32] &= 0x7f;
					CompactRetry = true;
					goto Retry;
				}

				secp256k1_context_destroy(Context);
				return false;
			}
			String Ethereum::GetChecksumHash(const std::string_view& Value) const
			{
				String Copy = String(Value);
				return Stringify::ToLower(Copy);
			}
			String Ethereum::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			Decimal Ethereum::GetDivisibility() const
			{
				return Decimal("1000000000000000000");
			}
			Algorithm::Composition::Type Ethereum::GetCompositionPolicy() const
			{
				return Algorithm::Composition::Type::SECP256K1;
			}
			RoutingPolicy Ethereum::GetRoutingPolicy() const
			{
				return RoutingPolicy::Account;
			}
			uint64_t Ethereum::GetBlockLatency() const
			{
				return 15;
			}
			bool Ethereum::HasBulkTransactions() const
			{
				return false;
			}
			bool Ethereum::IsTokenTransfer(const std::string_view& FunctionSignature)
			{
				return FunctionSignature == GetTokenTransferSignature();
			}
			const char* Ethereum::GetTokenTransferSignature()
			{
				return "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
			}
			const btc_chainparams_* Ethereum::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &eth_chainparams_regtest;
					case NetworkType::Testnet:
						return &eth_chainparams_test;
					case NetworkType::Mainnet:
						return &eth_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			void Ethereum::GeneratePublicKeyHashFromPublicKey(const uint8_t PublicKey[64], char OutPublicKeyHash[20])
			{
				SHA3_CTX Context;
				sha3_256_Init(&Context);
				sha3_Update(&Context, PublicKey, 64);

				uint8_t PublicKeyHash[32];
				keccak_Final(&Context, PublicKeyHash);
				memcpy(OutPublicKeyHash, PublicKeyHash + 12, 20);
			}
			void Ethereum::GeneratePrivateKeyDataFromPrivateKey(const char* PrivateKey, size_t PrivateKeySize, uint8_t OutPrivateKeyHash[20])
			{
				auto* Chain = GetChain();
				size_t PrefixSize = strlen(Chain->bech32_hrp);
				if (!memcmp(PrivateKey, Chain->bech32_hrp, sizeof(char) * PrefixSize))
				{
					PrivateKey += PrefixSize;
					PrivateKeySize -= PrefixSize;
				}

				int OutSize = 20;
				utils_hex_to_bin(PrivateKey, OutPrivateKeyHash, (int)PrivateKeySize, &OutSize);
			}
			void Ethereum::GenerateMessageHash(const String& Input, uint8_t Output[32])
			{
				String Header = GetMessageMagic();
				String Payload = Stringify::Text("%c%s%i%s",
					(char)Header.size(), Header.c_str(),
					(int)Input.size(), Input.c_str());
				keccak_256((uint8_t*)Payload.data(), Payload.size(), Output);
			}
			String Ethereum::GetMessageMagic()
			{
				return "Ethereum Signed Message:\n";
			}
			String Ethereum::GeneratePkhAddress(const char* PublicKeyHash20)
			{
				return GenerateChecksumAddress(Codec::HexEncode(std::string_view(PublicKeyHash20, 20)));
			}
			String Ethereum::GenerateUncheckedAddress(const std::string_view& Data)
			{
				auto* Chain = GetChain();
				return Chain->bech32_hrp + Codec::HexEncode(Data);
			}
			String Ethereum::GenerateChecksumAddress(const std::string_view& AnyAddress)
			{
				String Address = String(AnyAddress);
				Stringify::ToLower(Address);

				auto* Chain = GetChain();
				if (Stringify::StartsWith(Address, Chain->bech32_hrp))
					Address.erase(0, strlen(Chain->bech32_hrp));

				uint8_t AddressRawHash[BTC_ECKEY_UNCOMPRESSED_LENGTH];
				keccak_256((uint8_t*)Address.c_str(), Address.size(), AddressRawHash);

				String AddressHash = Codec::HexEncode(std::string_view((const char*)AddressRawHash, 32));
				size_t AddressSize = std::min(Address.size(), AddressHash.size());
				for (size_t i = 0; i < AddressSize; i++)
				{
					uint8_t Offset = AddressHash[i] - '0';
					if (Offset >= 8)
						Address[i] = toupper(Address[i]);
				}

				return Chain->bech32_hrp + Address;
			}
			String Ethereum::EncodeEthAddress(const std::string_view& EthAddress)
			{
				return Format::Util::Assign0xHex(EthAddress);
			}
			String Ethereum::DecodeNonEthAddress(const std::string_view& NonEthAddress)
			{
				return Format::Util::Assign0xHex(NonEthAddress);
			}
			String Ethereum::NormalizeTopicAddress(const std::string_view& AnyAddress)
			{
				String Address = String(AnyAddress); auto* Chain = GetChain();
				if (Stringify::StartsWith(Address, Chain->bech32_hrp))
					Address.erase(0, strlen(Chain->bech32_hrp));
				while (Address.size() > 40 && Address.front() == '0')
					Address.erase(Address.begin());
				return Chain->bech32_hrp + Address;
			}
			String Ethereum::Uint256ToHex(const uint256_t& Data)
			{
				auto* Chain = GetChain();
				return Chain->bech32_hrp + Data.ToString(16);
			}
			String Ethereum::GetRawGasLimit(Schema* TxData)
			{
				if (TxData->Has("receipt.gasUsed"))
					return TxData->FetchVar("receipt.gasUsed").GetBlob();

				if (TxData->Has("gasUsed"))
					return TxData->GetVar("gasUsed").GetBlob();

				if (TxData->Has("gas"))
					return TxData->GetVar("gas").GetBlob();

				if (TxData->Has("gasLimit"))
					return TxData->GetVar("gasLimit").GetBlob();

				return "0";
			}
			uint256_t Ethereum::HexToUint256(const std::string_view& AnyData)
			{
				String Data = String(AnyData); auto* Chain = GetChain();
				if (Stringify::StartsWith(Data, Chain->bech32_hrp))
					Data.erase(0, strlen(Chain->bech32_hrp));

				return uint256_t(Data, 16);
			}
			uint256_t Ethereum::FromEth(const Decimal& Value, const Decimal& Divisibility)
			{
				return uint256_t((Value * Divisibility).Truncate(0).ToString());
			}
			Decimal Ethereum::ToEth(const uint256_t& Value, const Decimal& Divisibility)
			{
				return Value.ToDecimal() / Decimal(Divisibility).Truncate(Protocol::Now().Message.Precision);
			}
			Decimal Ethereum::GetDivisibilityGwei()
			{
				return Decimal("1000000000");
			}
			uint256_t Ethereum::GetEthTransferGasLimitGwei()
			{
				return 21000;
			}
			uint256_t Ethereum::GetErc20TransferGasLimitGwei()
			{
				return 63000;
			}
		}
	}
}