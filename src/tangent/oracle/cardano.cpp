#include "cardano.h"
#include "../../utils/tiny-cardano/include/cardanoplusplus.h"
#include "../../utils/tiny-cardano/include/cardanoplusplus/hash/bech32.hpp"
extern "C"
{
#include "../../utils/trezor-crypto/ed25519.h"
#include "../../utils/trezor-crypto/sha2.h"
}

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			const char* Cardano::NdCall::NetworkStatus()
			{
				return "/network/status";
			}
			const char* Cardano::NdCall::BlockData()
			{
				return "/block";
			}
			const char* Cardano::NdCall::TransactionData()
			{
				return "/block/transaction";
			}
			const char* Cardano::NdCall::SubmitTransaction()
			{
				return "submitTransaction";
			}

			Cardano::Cardano() noexcept : ChainmasterUTXO()
			{
				Netdata.Composition = Algorithm::Composition::Type::ED25519;
				Netdata.Routing = RoutingPolicy::UTXO;
				Netdata.SyncLatency = 12;
				Netdata.Divisibility = Decimal(1000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer = "native";
				Netdata.SupportsBulkTransfer = true;
			}
			Promise<ExpectsLR<void>> Cardano::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				Schema* Transaction = Var::Set::Object();
				Transaction->Set("cbor", Var::String(Format::Util::Clear0xHex(TxData.Data)));

				SchemaArgs Map;
				Map["transaction"] = Transaction;

				auto HexData = Coawait(ExecuteRPC3(Asset, NdCall::SubmitTransaction(), std::move(Map), CachePolicy::Lazy));
				if (!HexData)
					Coreturn ExpectsLR<void>(std::move(HexData.Error()));

				Memory::Release(*HexData);
				UpdateCoins(Asset, TxData);
				Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Promise<ExpectsLR<uint64_t>> Cardano::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				Schema* Args = Var::Set::Object();
				Schema* NetworkQuery = Args->Set("network_identifier", Var::Object());
				NetworkQuery->Set("blockchain", Var::String(GetBlockchain()));
				NetworkQuery->Set("network", Var::String(GetNetwork()));

				auto Netstat = Coawait(ExecuteREST(Asset, "POST", NdCall::NetworkStatus(), Args, CachePolicy::Lazy));
				if (!Netstat)
					Coreturn ExpectsLR<uint64_t>(Netstat.Error());

				uint64_t BlockHeight = Netstat->FetchVar("current_block_identifier.index").GetInteger();
				Memory::Release(*Netstat);
				Coreturn ExpectsLR<uint64_t>(BlockHeight);
			}
			Promise<ExpectsLR<Schema*>> Cardano::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				Schema* Args = Var::Set::Object();
				Schema* NetworkQuery = Args->Set("network_identifier", Var::Object());
				NetworkQuery->Set("blockchain", Var::String(GetBlockchain()));
				NetworkQuery->Set("network", Var::String(GetNetwork()));
				Schema* BlockQuery = Args->Set("block_identifier", Var::Object());
				BlockQuery->Set("index", Var::Integer(BlockHeight));

				auto BlockData = Coawait(ExecuteREST(Asset, "POST", NdCall::BlockData(), Args, CachePolicy::Shortened));
				if (!BlockData)
					Coreturn ExpectsLR<Schema*>(BlockData.Error());

				if (BlockHash)
					*BlockHash = BlockData->FetchVar("block.block_identifier.hash").GetBlob();

				auto* Transactions = BlockData->Fetch("block.transactions");
				if (!Transactions)
				{
					Memory::Release(*BlockData);
					Coreturn LayerException("block.transactions field not found");
				}

				Transactions->Unlink();
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<Schema*>(Transactions);
			}
			Promise<ExpectsLR<Schema*>> Cardano::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				String TargetBlockHash = Format::Util::Clear0xHex(BlockHash);
				if (TargetBlockHash.empty())
				{
					auto TransactionsData = Coawait(GetBlockTransactions(Asset, BlockHeight, &TargetBlockHash));
					if (!TransactionsData)
						Coreturn ExpectsLR<Schema*>(TransactionsData.Error());

					Memory::Release(*TransactionsData);
				}

				Schema* Args = Var::Set::Object();
				Schema* NetworkQuery = Args->Set("network_identifier", Var::Object());
				NetworkQuery->Set("blockchain", Var::String(GetBlockchain()));
				NetworkQuery->Set("network", Var::String(GetNetwork()));
				Schema* BlockQuery = Args->Set("block_identifier", Var::Object());
				BlockQuery->Set("index", Var::Integer(BlockHeight));
				BlockQuery->Set("hash", Var::String(TargetBlockHash));
				Schema* TransactionQuery = Args->Set("transaction_identifier", Var::Object());
				TransactionQuery->Set("hash", Var::String(Format::Util::Clear0xHex(TransactionId)));

				auto TransactionData = Coawait(ExecuteREST(Asset, "POST", NdCall::TransactionData(), Args, CachePolicy::Shortened));
				if (!TransactionData)
					Coreturn ExpectsLR<Schema*>(TransactionData.Error());

				auto* TransactionObject = TransactionData->Get("transaction");
				if (!TransactionObject)
				{
					Memory::Release(*TransactionData);
					Coreturn LayerException("transaction field not found");
				}

				TransactionObject->Unlink();
				Memory::Release(*TransactionData);
				Coreturn ExpectsLR<Schema*>(TransactionObject);
			}
			Promise<ExpectsLR<Vector<IncomingTransaction>>> Cardano::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				auto* BaseImplementation = (Cardano*)Datamaster::GetChain(Asset);
				if (!BaseImplementation)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("chain not found"));

				if (!TransactionData->Value.IsObject())
				{
					auto InternalInfo = UPtr<Schema>(Coawait(GetBlockTransaction(Asset, BlockHeight, BlockHash, TransactionData->Value.GetBlob())));
					if (!InternalInfo)
						Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not found"));

					TransactionData->Value = InternalInfo->Value;
					TransactionData->Join(*InternalInfo, true);
				}


				auto* OperationsData = TransactionData->Get("operations");
				if (!OperationsData || OperationsData->Empty())
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				UnorderedSet<String> Addresses;
				for (auto& TxOperation : OperationsData->GetChilds())
				{
					String Status = TxOperation->GetVar("status").GetBlob();
					if (Status == "success")
						Addresses.insert(TxOperation->FetchVar("account.address").GetBlob());
				}

				auto Discovery = FindCheckpointAddresses(Asset, Addresses);
				if (!Discovery)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, BlockHeight, TransactionData->FetchVar("transaction_identifier.hash").GetBlob(), Decimal::Zero());

				Decimal OutputValue = 0.0;
				Decimal InputValue = 0.0;
				for (auto& TxOperation : OperationsData->GetChilds())
				{
					String Status = TxOperation->GetVar("status").GetBlob();
					if (Status != "success")
						continue;

					auto Identifier = Stringify::Split(TxOperation->FetchVar("coin_change.coin_identifier.identifier").GetBlob(), ':');
					uint32_t Index = FromString<uint32_t>(Identifier.back()).Or(0);
					String TransactionId = Identifier.front();
					String Symbol = TxOperation->FetchVar("amount.currency.symbol").GetBlob();
					String Address = TxOperation->FetchVar("account.address").GetBlob();
					String Type = TxOperation->GetVar("type").GetBlob();
					Decimal Value = Math0::Abs(TxOperation->FetchVar("amount.value").GetDecimal()) / BaseImplementation->Netdata.Divisibility;
					if (Type == "output")
					{
						auto TargetAddress = Discovery->find(Address);
						if (TargetAddress != Discovery->end())
						{
							CoinUTXO Output;
							Output.TransactionId = TransactionId;
							Output.Address = TargetAddress->first;
							Output.AddressIndex = TargetAddress->second;
							Output.Value = Value;
							Output.Index = Index;

							Schema* TokenBundle = TxOperation->Fetch("metadata.tokenBundle");
							if (TokenBundle != nullptr)
							{
								for (auto& TokenOperation : TokenBundle->GetChilds())
								{
									Schema* Tokens = TokenOperation->Get("tokens");
									if (Tokens != nullptr)
									{
										String ContractAddress = TokenOperation->GetVar("policyId").GetBlob();
										for (auto& Item : Tokens->GetChilds())
										{
											String Symbol = Item->FetchVar("currency.symbol").GetBlob();
											auto TokenAsset = Algorithm::Asset::IdOf(Algorithm::Asset::BlockchainOf(Asset), Symbol, ContractAddress);
											if (!Datamaster::EnableContractAddress(TokenAsset, ContractAddress))
												continue;

											uint8_t Decimals = (uint8_t)Item->FetchVar("currency.decimals").GetInteger();
											Decimal Divisibility = Decimals > 0 ? Decimal("1" + String(Decimals, '0')) : Decimal(1);
											Decimal TokenValue = Math0::Abs(Item->GetVar("value").GetDecimal()) / Divisibility.Truncate(Protocol::Now().Message.Precision);
											Output.ApplyTokenValue(ContractAddress, Symbol, TokenValue, Decimals);
										}
									}
								}
							}

							AddCoins(Asset, Output);
							Tx.To.push_back(Transferer(std::move(Output.Address), std::move(Output.AddressIndex), Decimal(Value)));
						}
						else
							Tx.To.push_back(Transferer(Address, Optional::None, Decimal(Value)));
						OutputValue += Value;
					}
					else if (Type == "input")
					{
						auto Output = GetCoins(Asset, TransactionId, Index);
						if (!Output)
						{
							auto TargetAddress = Discovery->find(Address);
							Tx.From.push_back(Transferer(Address, TargetAddress != Discovery->end() ? Option<uint64_t>(TargetAddress->second) : Option<uint64_t>(Optional::None), Decimal(Value)));
						}
						else
						{
							Tx.From.push_back(Transferer(Address, Optional::None, Decimal(Value)));
							RemoveCoins(Asset, Output->TransactionId, Output->Index);
						}
						InputValue += Value;
					}
				}

				if (InputValue > OutputValue)
					Tx.Fee = InputValue - OutputValue;
				Coreturn ExpectsLR<Vector<IncomingTransaction>>({ std::move(Tx) });
			}
			Promise<ExpectsLR<BaseFee>> Cardano::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				auto* BaseImplementation = (Chains::Cardano*)Datamaster::GetChain(Asset);
				if (!BaseImplementation)
					Coreturn ExpectsLR<BaseFee>(LayerException("chain not found"));

				auto BlockHeight = Coawait(GetLatestBlockHeight(Asset));
				if (!BlockHeight)
					Coreturn ExpectsLR<BaseFee>(std::move(BlockHeight.Error()));

				if (!TxAnalytics.BlockHeight || *BlockHeight < TxAnalytics.BlockHeight || *BlockHeight - TxAnalytics.BlockHeight > GetTxFeeBlockDelta())
				{
					size_t Offset = 0, Count = 0;
					size_t MaxCount = std::min<size_t>(*BlockHeight - TxAnalytics.BlockHeight, GetTxFeeBlocks());
					TxAnalytics.BlockHeight = *BlockHeight;
					while (Count < MaxCount)
					{
						auto Transactions = UPtr<Schema>(Coawait(GetBlockTransactions(Asset, *BlockHeight - (Offset++), nullptr)));
						if (!Transactions || Transactions->Empty())
							continue;

						++Count;
						for (auto& TxData : Transactions->GetChilds())
						{
							TxAnalytics.TotalSize += (size_t)TxData->FetchVar("metadata.size").GetInteger();
							TxAnalytics.Transactions++;
						}
					}

					if (!TxAnalytics.Transactions)
						TxAnalytics.Transactions = 1;

					size_t Bottom = TxAnalytics.Transactions * GetTxFeeBaseSize();
					if (TxAnalytics.TotalSize < Bottom)
						TxAnalytics.TotalSize = Bottom;
				}

				Decimal FeeRateA = Decimal(BaseImplementation->GetMinProtocolFeeA()) / BaseImplementation->Netdata.Divisibility;
				Decimal FeeRateB = Decimal(BaseImplementation->GetMinProtocolFeeB()) / BaseImplementation->Netdata.Divisibility;
				size_t TxSize = (size_t)((double)TxAnalytics.TotalSize / (double)TxAnalytics.Transactions);

				const uint64_t ExpectedMaxTxSize = 1000;
				TxSize = std::min<size_t>(ExpectedMaxTxSize, (size_t)(std::ceil((double)TxSize / 100.0) * 100.0));
				Coreturn ExpectsLR<BaseFee>(BaseFee(FeeRateA * Decimal(TxSize) + FeeRateB, 1.0));
			}
			Promise<ExpectsLR<CoinUTXO>> Cardano::GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
			{
				return GetCoins(Asset, TransactionId, Index);
			}
			Promise<ExpectsLR<uint64_t>> Cardano::GetLatestBlockSlot(const Algorithm::AssetId& Asset)
			{
				auto BlockHeight = Coawait(Cardano::GetLatestBlockHeight(Asset));
				if (!BlockHeight)
					Coreturn ExpectsLR<uint64_t>(BlockHeight.Error());

				auto BlockData = Coawait(Cardano::GetBlockTransactions(Asset, *BlockHeight, nullptr));
				if (!BlockData)
					Coreturn ExpectsLR<uint64_t>(BlockData.Error());

                uint64_t BlockSlot = BlockData->FetchVar("metadata.slotNo").GetInteger();
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<uint64_t>(BlockSlot);
			}
			Promise<ExpectsLR<OutgoingTransaction>> Cardano::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> ChangeWallet = LayerException();
				if (Wallet.Parent)
					ChangeWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					ChangeWallet = *Wallet.SigningChild;
				if (!ChangeWallet)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid output change address"));

				auto BlockSlot = Coawait(GetLatestBlockSlot(Asset));
				if (!BlockSlot)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("latest block slot not found"));

				Option<BaseFee> ActualFee = Optional::None;
				Option<Vector<CoinUTXO>> Inputs = Optional::None;
				Decimal FeeValue = ActualFee ? ActualFee->GetFee() : Fee.GetFee();
				Decimal InputNativeValue = 0.0;
				Decimal InputTokenValue = 0.0;
				Decimal MinOutputValue = GetMinValuePerOutput();
			RetryWithActualFee:
				Decimal TotalValue = FeeValue + MinOutputValue;
				Decimal SpendingValue = 0.0;
				for (auto& Item : To)
				{
					SpendingValue += Item.Value;
					if (Item.Value < MinOutputValue)
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s (value is less than minimum required by protocol)", Item.Value.ToString().c_str(), MinOutputValue.ToString().c_str())));
				}

				auto ContractAddress = Datamaster::GetContractAddress(Asset);
				if (!ContractAddress)
					TotalValue += SpendingValue;

				if (!Inputs || (ActualFee ? FeeValue > ActualFee->GetFee() : true))
				{
					auto NewInputs = CalculateCoins(Asset, Wallet, TotalValue, ContractAddress ? Option<TokenUTXO>(TokenUTXO(*ContractAddress, SpendingValue)) : Option<TokenUTXO>(Optional::None));
					InputNativeValue = NewInputs ? GetCoinsValue(*NewInputs, Optional::None) : 0.0;
					InputTokenValue = NewInputs && ContractAddress ? GetCoinsValue(*NewInputs, *ContractAddress) : 0.0;
					if (!NewInputs || NewInputs->empty())
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", (ContractAddress ? SpendingValue : TotalValue).ToString().c_str(), (ContractAddress ? InputTokenValue : InputNativeValue).ToString().c_str())));
					Inputs = std::move(*NewInputs);
				}

				UnorderedMap<String, TokenUTXO> Tokens;
				for (auto& Item : *Inputs)
				{
					for (auto& Token : Item.Tokens)
					{
						auto& Next = Tokens[Token.ContractAddress];
						if (Next.IsCoinValid())
							Next.Value += Token.Value;
						else
							Next = Token;
					}
				}

				Vector<CoinUTXO> Outputs;
				Outputs.reserve(To.size() + 1);
				for (auto& Item : To)
				{
					auto Output = CoinUTXO(String(), Item.Address, Option<uint64_t>(Item.AddressIndex), Decimal(Item.Value), (uint32_t)Outputs.size());
					if (ContractAddress)
					{
						auto& Token = Tokens[*ContractAddress];
						if (!Token.IsCoinValid() || Token.Value < SpendingValue)
							Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", SpendingValue.ToString().c_str(), Token.Value.ToString().c_str())));
			
						Output.ApplyTokenValue(*ContractAddress, Token.Symbol, SpendingValue, Token.Decimals);
						Output.Value = Decimal::Zero();
						Token.Value -= SpendingValue;
					}
					Outputs.push_back(std::move(Output));
				}

				auto ChangeOutput = CoinUTXO(String(), ChangeWallet->Addresses.begin()->second, Option<uint64_t>(ChangeWallet->AddressIndex), Decimal(InputNativeValue - (TotalValue - MinOutputValue)), (uint32_t)Outputs.size());
				for (auto& Token : Tokens)
				{
					if (Token.second.IsCoinValid() && Token.second.Value.IsPositive())
						ChangeOutput.ApplyTokenValue(Token.second.ContractAddress, Token.second.Symbol, Token.second.Value, Token.second.Decimals);
				}
				if (ChangeOutput.Value.IsPositive() || !ChangeOutput.Tokens.empty())
					Outputs.push_back(std::move(ChangeOutput));

				try
				{
					::Cardano::Transaction Builder = ::Cardano::Transaction();
					for (auto& Input : *Inputs)
						Builder.Body.TransactionInput.addInput(Copy<std::string>(Input.TransactionId), Input.Index);
					for (auto& Output : Outputs)
					{
						Builder.Body.TransactionOutput.addOutput(Copy<std::string>(Output.Address), (uint64_t)ToLovelace(Output.Value));
						for (auto& Token : Output.Tokens)
							Builder.Body.TransactionOutput.addAsset(Copy<std::string>(Token.ContractAddress), Copy<std::string>(Token.Symbol), (uint64_t)uint256_t((Token.Value * Token.GetDivisibility()).Truncate(0).ToString()));
					}
					Builder.Body.addFee((uint64_t)ToLovelace(FeeValue));
					Builder.Body.addInvalidAfter(*BlockSlot + GetBlockSlotOffset());

					Vector<Transferer> From;
					for (auto& Input : *Inputs)
					{
						if (!Input.AddressIndex)
							Coreturn ExpectsLR<OutgoingTransaction>(LayerException("address " + Input.Address + " cannot be used to sign the transaction (wallet not found)"));

						ExpectsLR<DerivedSigningWallet> SigningWallet = LayerException();
						if (Wallet.Parent)
							SigningWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, *Input.AddressIndex);
						else if (Wallet.SigningChild)
							SigningWallet = *Wallet.SigningChild;
						if (!SigningWallet)
							throw std::invalid_argument("address " + Copy<std::string>(Input.Address) + " cannot be used to sign the transaction (wallet not valid)");

						auto Private = SigningWallet->SigningKey.Expose<2048>();
						uint8_t RawPrivateKey[XSK_LENGTH];
						if (!DecodePrivateKey(Private.Key, RawPrivateKey, nullptr))
							throw std::invalid_argument("could not get a valid private key for address " + Copy<std::string>(Input.Address));

						Builder.addExtendedSigningKey(RawPrivateKey);
						From.emplace_back(Input.Address, Option<uint64_t>(Input.AddressIndex), Decimal(Input.Value));
					}

					uint8_t RawTransactionId[BLAKE256_LENGTH];
					auto& RawBodyData = Builder.Body.Build();
					crypto_generichash_blake2b(RawTransactionId, sizeof(RawTransactionId), RawBodyData.data(), RawBodyData.size(), nullptr, 0);

					auto& RawTxData = Builder.Build();
					if (!ActualFee)
					{
						Decimal LovelaceFee = Builder.getFeeTransacion_PostBuild(0);
						ActualFee = BaseFee(LovelaceFee / Netdata.Divisibility, 1.0);
						FeeValue = ActualFee->GetFee();
						goto RetryWithActualFee;
					}

					String TransactionData = Codec::HexEncode(std::string_view((const char*)RawTxData.data(), RawTxData.size()));
					String TransactionId = Codec::HexEncode(std::string_view((const char*)RawTransactionId, sizeof(RawTransactionId)));
					for (auto& Output : Outputs)
						Output.TransactionId = TransactionId;

					if (TransactionId.empty() || TransactionData.empty() || Inputs->empty() || Outputs.empty())
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));

					IncomingTransaction Tx;
					Tx.SetTransaction(Asset, 0, TransactionId, std::move(FeeValue));
					Tx.SetOperations(std::move(From), Vector<Transferer>(To));
					Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData), std::move(*Inputs), std::move(Outputs)));
				}
				catch (const std::invalid_argument& Error)
				{
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error: " + String(Error.what())));
				}
				catch (...)
				{
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));
				}
			}
			ExpectsLR<MasterWallet> Cardano::NewMasterWallet(const std::string_view& Seed)
			{
				try
				{
					uint8_t PrivateKey[MASTERSECRETKEY_LENGTH];
					if (!::Cardano::getRawMasterKey((const uint8_t*)Seed.data(), Seed.size(), nullptr, 0, PrivateKey))
						return ExpectsLR<MasterWallet>(LayerException("seed value invalid"));

					uint8_t PublicKey[XVK_LENGTH];
					::Cardano::rawprivatekey_to_rawpublickey(PrivateKey, PublicKey);

					std::string EncodedPrivateKey, EncodedPublicKey;
					::Cardano::Hash::bech32_encode("xprv", PrivateKey, sizeof(PrivateKey), EncodedPrivateKey);
					::Cardano::Hash::bech32_encode("xpub", PublicKey, sizeof(PublicKey), EncodedPublicKey);

					String HexSeed = Codec::HexEncode(Seed);
					return ExpectsLR<MasterWallet>(MasterWallet(::PrivateKey(std::move(HexSeed)), ::PrivateKey(EncodedPublicKey), ::PrivateKey(EncodedPrivateKey)));
				}
				catch (const std::invalid_argument& Error)
				{
					return ExpectsLR<MasterWallet>(LayerException("seed value invalid: " + String(Error.what())));
				}
				catch (...)
				{
					return ExpectsLR<MasterWallet>(LayerException("seed value invalid"));
				}
			}
			ExpectsLR<DerivedSigningWallet> Cardano::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				const uint32_t AccountIndex = 0;
				const auto Network = (Protocol::Now().Is(NetworkType::Mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);

				try
				{
					auto Private = Wallet.SigningKey.Expose<2048>();
					uint8_t MasterKey[MASTERSECRETKEY_LENGTH]; uint16_t MasterKeySize = (uint16_t)sizeof(MasterKey);
					if (!::Cardano::Hash::bech32_decode_extended(Private.Key, MasterKey, &MasterKeySize, sizeof(MasterKey)))
						throw std::invalid_argument("could not get a valid master key");

					uint8_t RawDerivedPrivateKey[XSK_LENGTH];
					if (!::Cardano::getRawKey(::Cardano::InputKey::MasterKey, MasterKey, ::Cardano::Wallet::HD, ::Cardano::OutputKey::Private, AccountIndex, ::Cardano::Role::Extern, (uint32_t)AddressIndex, RawDerivedPrivateKey))
						throw std::invalid_argument("could not get a valid private key");

					auto Derived = NewSigningWallet(Asset, std::string_view((char*)RawDerivedPrivateKey, sizeof(RawDerivedPrivateKey)));
					if (Derived)
						Derived->AddressIndex = AddressIndex;
					return Derived;
				}
				catch (const std::invalid_argument& Error)
				{
					return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid: " + String(Error.what())));
				}
				catch (...)
				{
					return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid"));
				}
			}
			ExpectsLR<DerivedSigningWallet> Cardano::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey)
			{
				const auto Network = (Protocol::Now().Is(NetworkType::Mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);
				String RawPrivateKey = String(SigningKey);
				if (RawPrivateKey.size() != 32 && RawPrivateKey.size() != 64 && RawPrivateKey.size() != XSK_LENGTH)
				{
					uint8_t Xsk[XSK_LENGTH]; size_t XskSize = 0;
					if (!DecodePrivateKey(RawPrivateKey, Xsk, &XskSize))
						return LayerException("invalid private key");

					RawPrivateKey = String((char*)Xsk, XskSize);
				}

				try
				{
					if (RawPrivateKey.size() == XSK_LENGTH)
					{
						uint8_t RawDerivedPublicKey[XVK_LENGTH];
						if (!::Cardano::rawprivatekey_to_rawpublickey((uint8_t*)RawPrivateKey.data(), RawDerivedPublicKey))
							throw std::invalid_argument("could not get a valid public key");

						auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)RawDerivedPublicKey, sizeof(RawDerivedPublicKey)));
						if (!Derived)
							return Derived.Error();

						std::string DerivedPrivateKey;
						::Cardano::Hash::bech32_encode("addr_xsk", (uint8_t*)RawPrivateKey.data(), (uint16_t)RawPrivateKey.size(), DerivedPrivateKey);
						return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), PrivateKey(DerivedPrivateKey)));
					}
					else
					{
						uint8_t RawDerivedPublicKey[32];
						ed25519_publickey_ext((uint8_t*)RawPrivateKey.data(), RawDerivedPublicKey);

						auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)RawDerivedPublicKey, sizeof(RawDerivedPublicKey)));
						if (!Derived)
							return Derived.Error();

						std::string DerivedPrivateKey;
						::Cardano::Hash::bech32_encode("ed25519e_sk", (uint8_t*)RawPrivateKey.data(), (uint16_t)RawPrivateKey.size(), DerivedPrivateKey);
						return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), PrivateKey(DerivedPrivateKey)));
					}
				}
				catch (const std::invalid_argument& Error)
				{
					return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid: " + String(Error.what())));
				}
				catch (...)
				{
					return ExpectsLR<DerivedSigningWallet>(LayerException("private key invalid"));
				}
			}
			ExpectsLR<DerivedVerifyingWallet> Cardano::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
			{
				const auto Network = (Protocol::Now().Is(NetworkType::Mainnet) ? ::Cardano::Network::Mainnet : ::Cardano::Network::Testnet);
				String RawPublicKey = String(VerifyingKey);
				if (RawPublicKey.size() != 32 && RawPublicKey.size() != XVK_LENGTH)
				{
					uint8_t Xvk[XSK_LENGTH]; size_t XvkSize = 0;
					if (!DecodePublicKey(RawPublicKey, Xvk, &XvkSize))
						return LayerException("invalid public key");

					RawPublicKey = String((char*)Xvk, XvkSize);
				}

				try
				{
					if (RawPublicKey.size() == XVK_LENGTH)
					{
						std::string DerivedPublicKey;
						::Cardano::Hash::bech32_encode("addr_xvk", (uint8_t*)RawPublicKey.data(), (uint16_t)RawPublicKey.size(), DerivedPublicKey);

						std::string Address;
						::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, (uint8_t*)RawPublicKey.data(), Network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, Address);
						return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, Copy<String>(Address) } }, Optional::None, PrivateKey(DerivedPublicKey)));
					}
					else
					{
						std::string DerivedPublicKey;
						::Cardano::Hash::bech32_encode("ed25519_pk", (uint8_t*)RawPublicKey.data(), (uint16_t)RawPublicKey.size(), DerivedPublicKey);

						uint8_t ExtendedPublicKey[XVK_LENGTH] = { 0 };
						memcpy(ExtendedPublicKey, (uint8_t*)RawPublicKey.data(), RawPublicKey.size());

						std::string Address;
						::Cardano::getBech32Address(::Cardano::InputKey::AccountKey_xvk, ExtendedPublicKey, Network, ::Cardano::Wallet::HD, ::Cardano::Address::Enterprise_Extern, 0, 0, Address);
						return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, Copy<String>(Address) } }, Optional::None, PrivateKey(DerivedPublicKey)));
					}
				}
				catch (const std::invalid_argument& Error)
				{
					return ExpectsLR<DerivedVerifyingWallet>(LayerException("public key invalid: " + String(Error.what())));
				}
				catch (...)
				{
					return ExpectsLR<DerivedVerifyingWallet>(LayerException("public key invalid"));
				}
			}
			ExpectsLR<String> Cardano::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Data[256]; uint16_t DataSize = sizeof(Data);
				if (!::Cardano::Hash::bech32_decode("addr", Data, &DataSize))
				{
					if (!::Cardano::Hash::bech32_decode("stake", Data, &DataSize))
					{
						if (!::Cardano::Hash::bech32_decode("addr_test", Data, &DataSize))
						{
							if (!::Cardano::Hash::bech32_decode("stake_test", Data, &DataSize))
								return LayerException("invalid address");
						}
					}
				}

				return String((char*)Data, DataSize);
			}
			ExpectsLR<String> Cardano::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
			{
				auto SigningWallet = NewSigningWallet(Asset, SigningKey.ExposeToHeap());
				if (!SigningWallet)
					return SigningWallet.Error();

				uint8_t RawPrivateKey[XSK_LENGTH];
				auto Private = SigningWallet->SigningKey.Expose<2048>();
				if (!DecodePrivateKey(Private.Key, RawPrivateKey, nullptr))
					return ExpectsLR<String>(LayerException("input private key invalid"));

				uint8_t Hash[32];
				crypto_generichash_blake2b(Hash, sizeof(Hash), (uint8_t*)Message.data(), Message.size(), nullptr, 0);

				uint8_t Signature[64];
				if (!::Cardano::signature(RawPrivateKey, Hash, sizeof(Hash), Signature))
					return ExpectsLR<String>(LayerException("input private key invalid"));

				return String((char*)Signature, sizeof(Signature));
			}
			ExpectsLR<void> Cardano::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
			{
				if (Signature.size() < 64)
					return LayerException("signature invalid");

				auto VerifyingWallet = NewVerifyingWallet(Asset, VerifyingKey);
				if (!VerifyingWallet)
					return VerifyingWallet.Error();

				uint8_t RawPublicKey[XVK_LENGTH];
				auto Public = VerifyingWallet->VerifyingKey.Expose<2048>();
				if (!DecodePublicKey(Public.Key, RawPublicKey, nullptr))
					return LayerException("input public key invalid");

				uint8_t Hash[32];
				crypto_generichash_blake2b(Hash, sizeof(Hash), (uint8_t*)Message.data(), Message.size(), nullptr, 0);
				if (!::Cardano::verify(RawPublicKey, Hash, sizeof(Hash), (uint8_t*)Signature.data()))
					return LayerException("signature verification failed with used public key");

				return Expectation::Met;
			}
			ExpectsLR<void> Cardano::VerifyNodeCompatibility(Nodemaster* Node)
			{
				if (!Node->HasDistinctURL(Nodemaster::TransmitType::JSONRPC))
					return LayerException("cardano ogmios jsonrpc node is required");

				if (!Node->HasDistinctURL(Nodemaster::TransmitType::REST))
					return LayerException("cardano rosetta rest node is required");

				return Expectation::Met;
			}
			String Cardano::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/1852'/1815'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const Cardano::Chainparams& Cardano::GetChainparams() const
			{
				return Netdata;
			}
			bool Cardano::DecodePrivateKey(const std::string_view& Data, uint8_t PrivateKey[96], size_t* PrivateKeySize)
			{
				uint8_t DerivedPrivateKey[XSK_LENGTH]; uint16_t DerivedPrivateKeySize = sizeof(DerivedPrivateKey);
				if (!::Cardano::Hash::bech32_decode_extended(Data.data(), DerivedPrivateKey, &DerivedPrivateKeySize, sizeof(DerivedPrivateKey)))
					return false;

				if (PrivateKeySize != nullptr)
					*PrivateKeySize = (size_t)DerivedPrivateKeySize;

				memset(PrivateKey, 0, sizeof(DerivedPrivateKey));
				memcpy(PrivateKey, DerivedPrivateKey, DerivedPrivateKeySize);
				return DerivedPrivateKeySize == sizeof(DerivedPrivateKey) || DerivedPrivateKeySize == 64;
			}
			bool Cardano::DecodePublicKey(const std::string_view& Data, uint8_t PublicKey[64], size_t* PublicKeySize)
			{
				uint16_t DerivedPublicKeySize = 64;
				if (!::Cardano::Hash::bech32_decode_extended(Data.data(), PublicKey, &DerivedPublicKeySize, XVK_LENGTH))
					return false;

				if (PublicKeySize != nullptr)
					*PublicKeySize = (size_t)DerivedPublicKeySize;

				return DerivedPublicKeySize == XVK_LENGTH || DerivedPublicKeySize == 32;
			}
			Decimal Cardano::GetMinValuePerOutput()
			{
				return 1.0;
			}
			uint256_t Cardano::ToLovelace(const Decimal& Value)
			{
				return uint256_t((Value * Netdata.Divisibility).Truncate(0).ToString());
			}
			uint64_t Cardano::GetMinProtocolFeeA()
			{
				return PROTOCOL_FEE_A;
			}
			uint64_t Cardano::GetMinProtocolFeeB()
			{
				return PROTOCOL_FEE_B;
			}
			size_t Cardano::GetBlockSlotOffset()
			{
				return 300;
			}
			String Cardano::GetBlockchain()
			{
				return "cardano";
			}
			String Cardano::GetNetwork()
			{
				return Protocol::Now().Is(NetworkType::Mainnet) ? "mainnet" : "preview";
			}
			size_t Cardano::GetTxFeeBlocks()
			{
				return 6;
			}
			size_t Cardano::GetTxFeeBlockDelta()
			{
				return 32;
			}
			size_t Cardano::GetTxFeeBaseSize()
			{
				return 300;
			}
		}
	}
}
