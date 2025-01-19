#include "bitcoin.h"
#include "../../utils/tiny-bitcoincash/cashaddr.h"
#include "../../utils/tiny-bitcoin/tool.h"
#include "../../utils/tiny-bitcoin/chainparams.h"
#include "../../utils/tiny-bitcoin/ecc.h"
#include "../../utils/tiny-bitcoin/bip32.h"
#include "../../utils/tiny-bitcoin/base58.h"
#include "../../utils/tiny-bitcoin/ripemd160.h"
#include "../../utils/tiny-bitcoin/utils.h"
#include "../../utils/tiny-bitcoin/serialize.h"
#undef min
extern "C"
{
#include "../../utils/trezor-crypto/segwit_addr.h"
}

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			static bool CashAddressFromLegacyHash(const btc_chainparams_* Chain, const uint8_t* AddressHash, size_t AddressHashSize, char* OutAddress, size_t OutAddressSize)
			{
				uint8_t Type = (base58_prefix_check(Chain->b58prefix_pubkey_address, AddressHash) ? 0 : 1);
				if (Type == 1 && !base58_prefix_check(Chain->b58prefix_script_address, AddressHash))
					return false;

				std::vector<uint8_t> RawHash;
				RawHash.resize(sizeof(uint160));

				size_t Offset = base58_prefix_size(Type == 0 ? Chain->b58prefix_pubkey_address : Chain->b58prefix_script_address);
				memcpy(&RawHash[0], AddressHash + Offset, std::min<size_t>(RawHash.size(), AddressHashSize));

				std::vector<uint8_t> Hash = cashaddr::PackAddrData(RawHash, Type);
				if (Hash.empty())
					return false;

				std::string CashAddress = cashaddr::Encode(Chain->bech32_cashaddr, Hash);
				memcpy(OutAddress, CashAddress.c_str(), std::min(CashAddress.size() + 1, OutAddressSize));
				return true;
			}
			static bool LegacyHashFromCashAddress(const btc_chainparams_* Chain, const std::string_view& Address, uint8_t* OutAddressHash, size_t* OutAddressHashSize, size_t* OutPrefixSize, Bitcoin::AddressFormat* OutType)
			{
				auto DecodedAddress = cashaddr::Decode(Copy<std::string>(Address), Chain->bech32_cashaddr);
				auto& Prefix = DecodedAddress.first;
				auto& Hash = DecodedAddress.second;
				if (Hash.empty() || Prefix != Chain->bech32_cashaddr)
					return false;

				Vector<uint8_t> Data;
				Data.reserve(Hash.size() * 5 / 8);
				if (!cashaddr::ConvertBits<5, 8, false>([&](uint8_t V) { Data.push_back(V); }, std::begin(Hash), std::end(Hash)))
					return false;

				uint8_t Version = Data[0];
				if (Version & 0x80)
					return false;

				uint32_t HashSize = 20 + 4 * (Version & 0x03);
				if (Version & 0x04)
					HashSize *= 2;

				if (Data.size() != HashSize + 1)
					return false;

				uint8_t Type = (Version >> 3) & 0x1f;
				if (Type == 0)
				{
					*OutPrefixSize = base58_prefix_size(Chain->b58prefix_pubkey_address);
					if (*OutPrefixSize > 1)
						Data.insert(Data.begin(), 0);
					base58_prefix_dump(Chain->b58prefix_pubkey_address, &Data[0]);
					*OutType = Bitcoin::AddressFormat::Pay2PublicKeyHash;
				}
				else if (Type == 1)
				{
					*OutPrefixSize = base58_prefix_size(Chain->b58prefix_script_address);
					if (*OutPrefixSize > 1)
						Data.insert(Data.begin(), 0);
					base58_prefix_dump(Chain->b58prefix_script_address, &Data[0]);
					*OutType = Bitcoin::AddressFormat::Pay2ScriptHash;
				}
				else
					*OutType = Bitcoin::AddressFormat::Unknown;

				memcpy(OutAddressHash, Data.data(), std::min(Data.size(), *OutAddressHashSize));
				*OutAddressHashSize = Data.size();
				return true;
			}
			static bool BitcoinCashPublicKeyGetAddressP2PKH(const btc_pubkey* PublicKey, const btc_chainparams_* Chain, char* AddressOut, size_t AddressOutSize)
			{
				if (Chain->bech32_cashaddr[0] == '\0')
					return false;

				uint8_t PublicKeyHash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t PublicKeyHashOffset;
				if (btc_pubkey_getaddr_p2pkh_hash(PublicKey, Chain, PublicKeyHash, &PublicKeyHashOffset) != 1)
					return false;

				return CashAddressFromLegacyHash(Chain, PublicKeyHash, sizeof(uint160) + PublicKeyHashOffset, AddressOut, AddressOutSize);
			}
			static bool BitcoinCashPublicKeyGetAddressP2SH(const btc_pubkey* PublicKey, const btc_chainparams_* Chain, char* AddressOut, size_t AddressOutSize)
			{
				if (Chain->bech32_cashaddr[0] == '\0')
					return false;

				uint8_t ScriptHash[sizeof(uint160) + B58_PREFIX_MAX_SIZE]; size_t ScriptHashOffset;
				if (btc_pubkey_getaddr_p2sh_p2wpkh_hash(PublicKey, Chain, ScriptHash, &ScriptHashOffset) != 1)
					return false;

				return CashAddressFromLegacyHash(Chain, ScriptHash, sizeof(uint160) + ScriptHashOffset, AddressOut, AddressOutSize);
			}

			const char* Bitcoin::NdCall::GetBlockCount()
			{
				return "getblockcount";
			}
			const char* Bitcoin::NdCall::GetBlockHash()
			{
				return "getblockhash";
			}
			const char* Bitcoin::NdCall::GetBlockStats()
			{
				return "getblockstats";
			}
			const char* Bitcoin::NdCall::GetBlock()
			{
				return "getblock";
			}
			const char* Bitcoin::NdCall::GetRawTransaction()
			{
				return "getrawtransaction";
			}
			const char* Bitcoin::NdCall::SendRawTransaction()
			{
				return "sendrawtransaction";
			}

			Bitcoin::SighashContext::~SighashContext()
			{
				for (auto& Item : Scripts.Locking)
					cstr_free(Item, true);

				for (auto& Items : Scripts.Unlocking)
				{
					for (auto& Item : Items)
						cstr_free(Item, true);
				}
			}

			Bitcoin::Bitcoin() noexcept : ChainmasterUTXO()
			{
				btc_ecc_start();
				Netdata.Composition = Algorithm::Composition::Type::SECP256K1;
				Netdata.Routing = RoutingPolicy::UTXO;
				Netdata.SyncLatency = 2;
				Netdata.Divisibility = Decimal(100000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer.clear();
				Netdata.SupportsBulkTransfer = true;
			}
			Bitcoin::~Bitcoin()
			{
				btc_ecc_stop();
			}
			Promise<ExpectsLR<void>> Bitcoin::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				SchemaList Map;
				Map.emplace_back(Var::Set::String(Format::Util::Clear0xHex(TxData.Data)));

				auto HexData = Coawait(ExecuteRPC(Asset, NdCall::SendRawTransaction(), std::move(Map), CachePolicy::Greedy));
				if (!HexData)
				{
					auto Message = HexData.What();
					if (Stringify::Find(Message, "-27").Found || Stringify::Find(Message, "Transaction already in").Found)
						Coreturn ExpectsLR<void>(Expectation::Met);

					Coreturn ExpectsLR<void>(std::move(HexData.Error()));
				}

				Memory::Release(*HexData);
				UpdateCoins(Asset, TxData);
				Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Promise<ExpectsLR<uint64_t>> Bitcoin::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto BlockCount = Coawait(ExecuteRPC(Asset, NdCall::GetBlockCount(), { }, CachePolicy::Lazy));
				if (!BlockCount)
					Coreturn ExpectsLR<uint64_t>(std::move(BlockCount.Error()));

				uint64_t BlockHeight = (uint64_t)BlockCount->Value.GetInteger();
				Memory::Release(*BlockCount);
				Coreturn ExpectsLR<uint64_t>(BlockHeight);
			}
			Promise<ExpectsLR<Schema*>> Bitcoin::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				SchemaList HashMap;
				HashMap.emplace_back(Var::Set::Integer(BlockHeight));

				auto BlockId = Coawait(ExecuteRPC(Asset, NdCall::GetBlockHash(), std::move(HashMap), CachePolicy::Shortened));
				if (!BlockId)
					Coreturn BlockId;

				SchemaList BlockMap;
				BlockMap.emplace_back(Var::Set::String(BlockId->Value.GetBlob()));
				BlockMap.emplace_back(Legacy.GetBlock ? Var::Set::Boolean(true) : Var::Set::Integer(2));
				if (BlockHash != nullptr)
					*BlockHash = BlockId->Value.GetBlob();

				auto BlockData = Coawait(ExecuteRPC(Asset, NdCall::GetBlock(), std::move(BlockMap), CachePolicy::Shortened));
				if (!BlockData)
				{
					SchemaList LegacyBlockMap;
					LegacyBlockMap.emplace_back(Var::Set::String(BlockId->Value.GetBlob()));
					LegacyBlockMap.emplace_back(Var::Set::Boolean(true));

					BlockData = Coawait(ExecuteRPC(Asset, NdCall::GetBlock(), std::move(LegacyBlockMap), CachePolicy::Shortened));
					if (!BlockData)
					{
						Memory::Release(*BlockId);
						Coreturn BlockData;
					}
					else
						Legacy.GetBlock = 1;
				}

				Memory::Release(*BlockId);
				auto* Transactions = BlockData->Get("tx");
				if (!Transactions)
				{
					Memory::Release(*BlockData);
					Coreturn ExpectsLR<Schema*>(LayerException("tx field not found"));
				}

				Transactions->Unlink();
				Memory::Release(*BlockData);
				Coreturn ExpectsLR<Schema*>(Transactions);
			}
			Promise<ExpectsLR<Schema*>> Bitcoin::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				SchemaList TransactionMap;
				TransactionMap.emplace_back(Var::Set::String(Format::Util::Clear0xHex(TransactionId)));
				TransactionMap.emplace_back(Legacy.GetRawTransaction ? Var::Set::Boolean(true) : Var::Set::Integer(2));

				auto TxData = Coawait(ExecuteRPC(Asset, NdCall::GetRawTransaction(), std::move(TransactionMap), CachePolicy::Persistent));
				if (!TxData)
				{
					SchemaList LegacyTransactionMap;
					LegacyTransactionMap.emplace_back(Var::Set::String(Format::Util::Clear0xHex(TransactionId)));
					LegacyTransactionMap.emplace_back(Var::Set::Boolean(true));

					TxData = Coawait(ExecuteRPC(Asset, NdCall::GetRawTransaction(), std::move(LegacyTransactionMap), CachePolicy::Persistent));
					if (!TxData)
						Coreturn TxData;
					else
						Legacy.GetRawTransaction = 1;
				}

				Coreturn TxData;
			}
			Promise<ExpectsLR<Vector<IncomingTransaction>>> Bitcoin::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				UnorderedSet<String> Addresses;
				Schema* TxInputs = TransactionData->Get("vin");
				if (TxInputs != nullptr)
				{
					for (auto& Input : TxInputs->GetChilds())
					{
						if (Input->Has("txid") && Input->Has("vout"))
						{
							auto Output = GetCoins(Asset, Input->GetVar("txid").GetBlob(), (uint32_t)Input->GetVar("vout").GetInteger());
							if (Output && !Output->Address.empty())
								Addresses.insert(Output->Address);
						}
					}
				}

				Schema* TxOutputs = TransactionData->Get("vout");
				if (TxOutputs != nullptr)
				{
					for (auto& Output : TxOutputs->GetChilds())
					{
						bool IsAllowed = true;
						auto Input = GetOutputAddresses(Output, &IsAllowed);
						if (IsAllowed)
						{
							for (auto& Address : Input)
								Addresses.insert(Address);
						}
					}
				}

				if (!FindCheckpointAddresses(Asset, Addresses))
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				if (TxInputs != nullptr)
				{
					for (auto& Input : TxInputs->GetChilds())
					{
						if (Input->Has("txid") && Input->Has("vout"))
						{
							auto Output = Coawait(GetTransactionOutput(Asset, Input->GetVar("txid").GetBlob(), (uint32_t)Input->GetVar("vout").GetInteger()));
							if (Output && !Output->Address.empty())
								Addresses.insert(Output->Address);
						}
					}
				}

				auto Discovery = FindCheckpointAddresses(Asset, Addresses);
				if (!Discovery)
					Coreturn ExpectsLR<Vector<IncomingTransaction>>(LayerException("tx not involved"));

				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, BlockHeight, TransactionData->GetVar("txid").GetBlob(), Decimal::Zero());

				bool IsCoinbase = false;
				if (TxInputs != nullptr)
				{
					Tx.From.reserve(TxInputs->GetChilds().size());
					for (auto& Input : TxInputs->GetChilds())
					{
						if (Input->Has("coinbase"))
						{
							IsCoinbase = true;
							continue;
						}

						auto Output = Coawait(GetTransactionOutput(Asset, Input->GetVar("txid").GetBlob(), (uint32_t)Input->GetVar("vout").GetInteger()));
						if (Output)
						{
							RemoveCoins(Asset, Output->TransactionId, Output->Index);
							Tx.From.emplace_back(Output->Address, Option<uint64_t>(Output->AddressIndex), Decimal(Output->Value));
							Tx.Fee += Output->Value;
						}
					}
				}

				if (TxOutputs != nullptr)
				{
					size_t OutputIndex = 0;
					UnorderedSet<size_t> Resets;
					Tx.To.resize(TxOutputs->GetChilds().size());
					for (auto& Output : TxOutputs->GetChilds())
					{
						CoinUTXO NewOutput;
						NewOutput.TransactionId = Tx.TransactionId;
						NewOutput.Value = Output->GetVar("value").GetDecimal();
						NewOutput.Index = (uint32_t)(Output->Has("n") ? Output->GetVar("n").GetInteger() : OutputIndex);
						if (NewOutput.Index > (uint32_t)Tx.To.size())
							NewOutput.Index = (uint32_t)OutputIndex;

						bool IsAllowed = true;
						auto ReceiverAddresses = GetOutputAddresses(Output, &IsAllowed);
						NewOutput.Address = ReceiverAddresses.empty() ? String() : *ReceiverAddresses.begin();
						if (IsAllowed)
						{
							auto It = Discovery->find(NewOutput.Address);
							if (It != Discovery->end())
								NewOutput.AddressIndex = It->second;
						}
						else
							Resets.insert(NewOutput.Index);

						if (NewOutput.AddressIndex)
							AddCoins(Asset, NewOutput);

						Tx.To[(size_t)NewOutput.Index] = Transferer(NewOutput.Address, std::move(NewOutput.AddressIndex), Decimal(NewOutput.Value));
						Tx.Fee -= NewOutput.Value;
						++OutputIndex;
					}

					for (auto& Index : Resets)
						Tx.To[Index].Value = Decimal::NaN();

					for (auto It = Tx.To.begin(); It != Tx.To.end();)
					{
						if (It->Value.IsNaN())
							It = Tx.To.erase(It);
						else
							++It;
					}
				}

				if (Tx.Fee.IsNegative())
					Tx.Fee = 0.0;

				if (IsCoinbase && !Tx.To.empty())
					Tx.From.emplace_back(String("null"), Option<uint64_t>(Optional::None), Decimal(Tx.To.front().Value));

				Coreturn ExpectsLR<Vector<IncomingTransaction>>({ std::move(Tx) });
			}
			Promise<ExpectsLR<BaseFee>> Bitcoin::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				auto* Implementation = Datamaster::GetChain(Asset);
				if (!Implementation)
					Coreturn ExpectsLR<BaseFee>(LayerException("chain not found"));

				auto BlockHeight = Coawait(GetLatestBlockHeight(Asset));
				if (!BlockHeight)
					Coreturn ExpectsLR<BaseFee>(std::move(BlockHeight.Error()));

				SchemaList Map;
				Map.emplace_back(Var::Set::Integer(*BlockHeight));
				Map.emplace_back(Var::Set::Null());

				auto BlockStats = Coawait(ExecuteRPC(Asset, NdCall::GetBlockStats(), std::move(Map), CachePolicy::Greedy));
				if (!BlockStats)
					Coreturn ExpectsLR<BaseFee>(std::move(BlockStats.Error()));

				Decimal FeeRate = BlockStats->GetVar("avgfeerate").GetDecimal();
				size_t TxSize = (size_t)BlockStats->GetVar("avgtxsize").GetInteger();

				const size_t ExpectedMaxTxSize = 1000;
				TxSize = std::min<size_t>(ExpectedMaxTxSize, (size_t)(std::ceil((double)TxSize / 100.0) * 100.0));
				Coreturn ExpectsLR<BaseFee>(BaseFee(FeeRate / Netdata.Divisibility, Decimal(TxSize)));
			}
			Promise<ExpectsLR<CoinUTXO>> Bitcoin::GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
			{
				auto Output = GetCoins(Asset, TransactionId, Index);
				if (Output)
					Coreturn Output;

				auto TxData = Coawait(GetBlockTransaction(Asset, 0, std::string_view(), TransactionId));
				if (!TxData)
					Coreturn ExpectsLR<CoinUTXO>(std::move(TxData.Error()));

				if (!TxData->Has("vout"))
				{
					Memory::Release(*TxData);
					Coreturn ExpectsLR<CoinUTXO>(LayerException("transaction does not have any UTXO"));
				}

				auto* VOUT = TxData->Fetch("vout." + ToString(Index));
				if (!VOUT)
				{
					Memory::Release(*TxData);
					Coreturn ExpectsLR<CoinUTXO>(LayerException("transaction does not have specified UTXO"));
				}

				CoinUTXO Input;
				Input.TransactionId = TransactionId;
				Input.Value = VOUT->GetVar("value").GetDecimal();
				Input.Index = Index;

				bool IsAllowed = true;
				auto Addresses = GetOutputAddresses(VOUT, &IsAllowed);
				if (IsAllowed && !Addresses.empty())
				{
					Input.Address = *Addresses.begin();
					auto Discovery = FindCheckpointAddresses(Asset, Addresses);
					if (Discovery && !Discovery->empty())
						Input.AddressIndex = Discovery->begin()->second;
				}

				Memory::Release(*TxData);
				Coreturn ExpectsLR<CoinUTXO>(std::move(Input));
			}
			UnorderedSet<String> Bitcoin::GetOutputAddresses(Schema* TxOutput, bool* IsAllowed)
			{
				bool Allowance = true;
				UnorderedSet<String> Addresses;
				auto* ScriptPubKey = TxOutput->Get("scriptPubKey");
				if (ScriptPubKey != nullptr)
				{
					if (ScriptPubKey->Has("address"))
					{
						String Value = ScriptPubKey->GetVar("address").GetBlob();
						if (!Value.empty())
							Addresses.insert(Value);
					}

					if (ScriptPubKey->Has("addresses"))
					{
						for (auto& Item : ScriptPubKey->Get("addresses")->GetChilds())
						{
							String Value = Item->Value.GetBlob();
							if (!Value.empty())
								Addresses.insert(Value);
						}
					}

					if (ScriptPubKey->Has("type"))
					{
						String Type = ScriptPubKey->GetVar("type").GetBlob();
						if (Type == "pubkey")
						{
							String Asm = ScriptPubKey->GetVar("asm").GetBlob();
							size_t Index = Asm.find(' ');
							Allowance = Index != std::string::npos;
							if (Allowance)
							{
								auto PublicKey = Codec::HexDecode(Asm.substr(0, Index));
								Allowance = PublicKey.size() == BTC_ECKEY_COMPRESSED_LENGTH || PublicKey.size() == BTC_ECKEY_UNCOMPRESSED_LENGTH;
								if (Allowance)
									Addresses.insert(Format::Util::Encode0xHex(PublicKey));
							}
						}
						else if (Type != "nulldata" && Type != "pubkeyhash" && Type != "scripthash" && Type != "witness_v0_keyhash" && Type != "witness_v0_scripthash" && Type != "witness_v1_taproot")
							Allowance = false;
					}
				}

				if (IsAllowed)
					*IsAllowed = Allowance && !Addresses.empty();

				return Addresses;
			}
			Promise<ExpectsLR<OutgoingTransaction>> Bitcoin::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				ExpectsLR<DerivedSigningWallet> ChangeWallet = LayerException();
				if (Wallet.Parent)
					ChangeWallet = Datamaster::NewSigningWallet(Asset, *Wallet.Parent, Protocol::Now().Account.RootAddressIndex);
				else if (Wallet.SigningChild)
					ChangeWallet = *Wallet.SigningChild;
				if (!ChangeWallet)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("invalid output change address"));

				auto AppliedFee = Coawait(CalculateTransactionFeeFromFeeEstimate(Asset, Wallet, To, Fee, ChangeWallet->Addresses.begin()->second));
				Decimal FeeValue = AppliedFee ? AppliedFee->GetFee() : Fee.GetFee();
				Decimal TotalValue = FeeValue;
				for (auto& Item : To)
					TotalValue += Item.Value;

				auto Inputs = CalculateCoins(Asset, Wallet, TotalValue, Optional::None);
				Decimal InputValue = Inputs ? GetCoinsValue(*Inputs, Optional::None) : 0.0;
				if (!Inputs || Inputs->empty())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException(Stringify::Text("insufficient funds: %s < %s", InputValue.ToString().c_str(), TotalValue.ToString().c_str())));

				Vector<CoinUTXO> Outputs;
				Outputs.reserve(To.size() + 1);
				for (auto& Item : To)
					Outputs.push_back(CoinUTXO(String(), Item.Address, Option<uint64_t>(Item.AddressIndex), Decimal(Item.Value), (uint32_t)Outputs.size()));

				Decimal ChangeValue = InputValue - TotalValue;
				if (ChangeValue.IsPositive())
					Outputs.push_back(CoinUTXO(String(), ChangeWallet->Addresses.begin()->second, Option<uint64_t>(ChangeWallet->AddressIndex), Decimal(ChangeValue), (uint32_t)Outputs.size()));

				btc_tx* Builder = btc_tx_new();
				for (auto& Output : Outputs)
				{
					auto Status = AddTransactionOutput(Builder, Output.Address, Output.Value);
					if (Status)
					{
						btc_tx_free(Builder);
						Coreturn ExpectsLR<OutgoingTransaction>(std::move(*Status));
					}
				}

				SighashContext Context;
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
						Coreturn ExpectsLR<OutgoingTransaction>(LayerException("address " + Input.Address + " cannot be used to sign the transaction (wallet not valid)"));

					auto Private = SigningWallet->SigningKey.Expose<2048>();
					auto Status = AddTransactionInput(Builder, Input, Context, Private.Key);
					if (Status)
					{
						btc_tx_free(Builder);
						Coreturn ExpectsLR<OutgoingTransaction>(std::move(*Status));
					}
				}

				Vector<Transferer> From;
				for (auto& Input : *Inputs)
				{
					auto Status = SignTransactionInput(Builder, Input, Context, From.size());
					if (Status)
					{
						btc_tx_free(Builder);
						Coreturn ExpectsLR<OutgoingTransaction>(std::move(*Status));
					}
					From.emplace_back(Input.Address, Option<uint64_t>(Input.AddressIndex), Decimal(Input.Value));
				}

				String TransactionData = SerializeTransactionData(Builder);
				String TransactionId = SerializeTransactionId(Builder);
				for (auto& Output : Outputs)
					Output.TransactionId = TransactionId;

				btc_tx_free(Builder);
				if (TransactionId.empty() || TransactionData.empty() || Inputs->empty() || Outputs.empty())
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("tx serialization error"));

				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, TransactionId, std::move(FeeValue));
				Tx.SetOperations(std::move(From), Vector<Transferer>(To));
				Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData), std::move(*Inputs), std::move(Outputs)));
			}
			ExpectsLR<MasterWallet> Bitcoin::NewMasterWallet(const std::string_view& Seed)
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
			ExpectsLR<DerivedSigningWallet> Bitcoin::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				auto* Chain = GetChain();
				char MasterPrivateKey[256];
				{
					auto Private = Wallet.SigningKey.Expose<2048>();
					if (!hd_derive(Chain, Private.Key, GetDerivation(AddressIndex).c_str(), MasterPrivateKey, sizeof(MasterPrivateKey)))
						return ExpectsLR<DerivedSigningWallet>(LayerException("invalid private key"));
				}

				btc_hdnode Node;
				if (!btc_hdnode_deserialize(MasterPrivateKey, Chain, &Node))
					return LayerException("input address derivation invalid");

				auto Derived = NewSigningWallet(Asset, std::string_view((char*)Node.private_key, sizeof(Node.private_key)));
				if (Derived)
					Derived->AddressIndex = AddressIndex;
				return Derived;
			}
			ExpectsLR<DerivedSigningWallet> Bitcoin::NewSigningWallet(const Algorithm::AssetId& Asset, const std::string_view& SigningKey)
			{
				btc_key PrivateKey;
				btc_privkey_init(&PrivateKey);
				if (SigningKey.size() != sizeof(PrivateKey.privkey))
				{
					String Key = String(SigningKey);
					if (!btc_privkey_decode_wif(Key.c_str(), GetChain(), &PrivateKey))
						return LayerException("not a valid wif private key");
				}
				else
					memcpy(PrivateKey.privkey, SigningKey.data(), sizeof(PrivateKey.privkey));

				btc_pubkey PublicKey;
				btc_pubkey_from_key(&PrivateKey, &PublicKey);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicKey.pubkey, btc_pubkey_get_length(PublicKey.pubkey[0])));
				if (!Derived)
					return Derived.Error();

				auto* Chain = GetChain();
				char DerivedPrivateKey[256]; size_t DerivedPrivateKeySize = sizeof(DerivedPrivateKey);
				btc_privkey_encode_wif(&PrivateKey, Chain, DerivedPrivateKey, &DerivedPrivateKeySize);
				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), ::PrivateKey(DerivedPrivateKey)));
			}
			ExpectsLR<DerivedVerifyingWallet> Bitcoin::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
			{
				auto* Chain = GetChain();
				auto* Options = Datamaster::GetOptions(Asset);
				size_t Types = (size_t)GetAddressType();
				if (Options != nullptr && Options->Value.Is(VarType::Array))
				{
					Types = 0;
					for (auto& Type : Options->GetChilds())
					{
						std::string_view Typename = Type->Value.GetString();
						if (Typename == "p2pk")
							Types |= (size_t)AddressFormat::Pay2PublicKey;
						else if (Typename == "p2sh_p2wpkh")
							Types |= (size_t)AddressFormat::Pay2ScriptHash;
						else if (Typename == "p2pkh")
							Types |= (size_t)AddressFormat::Pay2PublicKeyHash;
						else if (Typename == "p2wsh_p2pkh")
							Types |= (size_t)AddressFormat::Pay2WitnessScriptHash;
						else if (Typename == "p2wpkh")
							Types |= (size_t)AddressFormat::Pay2WitnessPublicKeyHash;
						else if (Typename == "p2tr")
							Types |= (size_t)AddressFormat::Pay2Taproot;
					}
				}

				AddressMap Addresses;
				btc_pubkey PublicKey;
				btc_pubkey_init(&PublicKey);
				if (VerifyingKey.size() != BTC_ECKEY_COMPRESSED_LENGTH && VerifyingKey.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
				{
					auto Key = Format::Util::Decode0xHex(VerifyingKey);
					if (Key.size() != BTC_ECKEY_COMPRESSED_LENGTH && Key.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
						return LayerException("not a valid hex public key");

					memcpy(PublicKey.pubkey, Key.data(), std::min(Key.size(), sizeof(PublicKey.pubkey)));
				}
				else
					memcpy(PublicKey.pubkey, VerifyingKey.data(), std::min(VerifyingKey.size(), sizeof(PublicKey.pubkey)));
				PublicKey.compressed = btc_pubkey_get_length(PublicKey.pubkey[0]) == BTC_ECKEY_COMPRESSED_LENGTH;

				char DerivedAddress[128];
				if (Chain->bech32_cashaddr[0] == '\0')
				{
					if (Types & (size_t)AddressFormat::Pay2PublicKey && btc_pubkey_getaddr_p2pk(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2ScriptHash || Types & (size_t)AddressFormat::Pay2CashaddrScriptHash) && btc_pubkey_getaddr_p2sh_p2wpkh(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2PublicKeyHash || Types & (size_t)AddressFormat::Pay2CashaddrPublicKeyHash) && btc_pubkey_getaddr_p2pkh(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if (false && (Types & (size_t)AddressFormat::Pay2Tapscript) && btc_pubkey_getaddr_p2tr_p2pk(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2Taproot) && btc_pubkey_getaddr_p2tr(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2WitnessScriptHash) && btc_pubkey_getaddr_p2wsh_p2pkh(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2WitnessPublicKeyHash) && btc_pubkey_getaddr_p2wpkh(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;
				}
				else
				{
					if (Types & (size_t)AddressFormat::Pay2PublicKey && btc_pubkey_getaddr_p2pk(&PublicKey, Chain, DerivedAddress))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2ScriptHash || Types & (size_t)AddressFormat::Pay2CashaddrScriptHash) && BitcoinCashPublicKeyGetAddressP2SH(&PublicKey, Chain, DerivedAddress, sizeof(DerivedAddress)))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;

					if ((Types & (size_t)AddressFormat::Pay2PublicKeyHash || Types & (size_t)AddressFormat::Pay2CashaddrPublicKeyHash) && BitcoinCashPublicKeyGetAddressP2PKH(&PublicKey, Chain, DerivedAddress, sizeof(DerivedAddress)))
						Addresses[(uint8_t)Addresses.size() + 1] = DerivedAddress;
				}

				if (Addresses.empty())
					return ExpectsLR<DerivedVerifyingWallet>(LayerException("address generation not supported"));

				char DerivedPublicKey[256]; size_t DerivedPublicKeySize = sizeof(DerivedPublicKey);
				btc_pubkey_get_hex(&PublicKey, DerivedPublicKey, &DerivedPublicKeySize);
				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet(std::move(Addresses), Optional::None, ::PrivateKey(DerivedPublicKey)));
			}
			ExpectsLR<String> Bitcoin::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Data[256]; size_t DataSize = sizeof(Data);
				if (ParseAddress(Address, Data, &DataSize) == AddressFormat::Unknown)
					return LayerException("invalid address");

				return String((char*)Data, DataSize);
			}
			ExpectsLR<String> Bitcoin::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
			{
				auto SigningWallet = NewSigningWallet(Asset, SigningKey.ExposeToHeap());
				if (!SigningWallet)
					return SigningWallet.Error();

				btc_key PrivateKey;
				auto Private = SigningWallet->SigningKey.Expose<2048>();
				if (btc_privkey_decode_wif(Private.Key, GetChain(), &PrivateKey) != 1)
					return LayerException("private key not valid");

				uint256 Hash;
				GenerateMessageHash(Message, Hash);

				uint8_t RawSignature[64]; size_t RawSignatureSize = sizeof(RawSignature); int RecoveryId = 0;
				if (btc_key_sign_hash_compact_recoverable(&PrivateKey, Hash, RawSignature, &RawSignatureSize, &RecoveryId) != 1)
					return LayerException("private key not valid");

				uint8_t Signature[65];
				memcpy(Signature + 1, RawSignature, sizeof(RawSignature));
				Signature[0] = RecoveryId;
				return String((char*)Signature, sizeof(Signature));
			}
			ExpectsLR<void> Bitcoin::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
			{
				if (Signature.size() < 65)
					return LayerException("signature not valid");

				auto VerifyingWallet = NewVerifyingWallet(Asset, VerifyingKey);
				if (!VerifyingWallet)
					return VerifyingWallet.Error();

				uint256 Hash;
				GenerateMessageHash(Message, Hash);
				for (auto& Item : VerifyingWallet->Addresses)
				{
					const auto& Address = Item.second;
					uint8_t TargetProgram[256];
					size_t TargetProgramSize = sizeof(TargetProgram);
					if (ParseAddress(Address, TargetProgram, &TargetProgramSize) == AddressFormat::Unknown)
						continue;

					for (int i = 0; i < 4; i++)
					{
						btc_pubkey PublicKey;
						if (btc_key_sign_recover_pubkey((uint8_t*)Signature.data() + 1, Hash, i, &PublicKey) != 1)
							continue;

						if (!memcmp(PublicKey.pubkey, TargetProgram, std::min(TargetProgramSize, sizeof(PublicKey.pubkey))))
							return Expectation::Met;

						uint160 ActualProgram;
						btc_pubkey_get_hash160(&PublicKey, ActualProgram);
						if (memcmp(TargetProgram, ActualProgram, std::min(TargetProgramSize, sizeof(ActualProgram))) == 0)
							return Expectation::Met;

						char SignerAddress[256];
						if (btc_pubkey_getaddr_p2sh_p2wpkh(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (btc_pubkey_getaddr_p2pkh(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (btc_pubkey_getaddr_p2wsh_p2pkh(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (btc_pubkey_getaddr_p2wpkh(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (btc_pubkey_getaddr_p2tr_p2pk(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (btc_pubkey_getaddr_p2tr(&PublicKey, GetChain(), SignerAddress) && Address == SignerAddress)
							return Expectation::Met;
						else if (BitcoinCashPublicKeyGetAddressP2SH(&PublicKey, GetChain(), SignerAddress, sizeof(SignerAddress)) && Address == SignerAddress)
							return Expectation::Met;
						else if (BitcoinCashPublicKeyGetAddressP2PKH(&PublicKey, GetChain(), SignerAddress, sizeof(SignerAddress)) && Address == SignerAddress)
							return Expectation::Met;
					}
				}

				return LayerException("signature verification failed with used public key");
			}
			String Bitcoin::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/0'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const Bitcoin::Chainparams& Bitcoin::GetChainparams() const
			{
				return Netdata;
			}
			Promise<ExpectsLR<BaseFee>> Bitcoin::CalculateTransactionFeeFromFeeEstimate(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Estimate, const std::string_view& ChangeAddress)
			{
				Decimal BaselineFee = Estimate.GetFee();
				Decimal SendingValue = BaselineFee;
				for (auto& Destination : To)
					SendingValue += Destination.Value;

				auto Inputs = CalculateCoins(Asset, Wallet, SendingValue, Optional::None);
				Decimal InputValue = Inputs ? GetCoinsValue(*Inputs, Optional::None) : 0.0;
				if (!Inputs || Inputs->empty())
					Coreturn ExpectsLR<BaseFee>(LayerException(Stringify::Text("insufficient funds: %s < %s", InputValue.ToString().c_str(), SendingValue.ToString().c_str())));

				Vector<String> Outputs = { String(ChangeAddress) };
				Outputs.reserve(To.size() + 1);
				for (auto& Item : To)
					Outputs.push_back(Item.Address);

				bool HasWitness = false;
				double VirtualSize = 10;
				for (auto& Input : *Inputs)
				{
					switch (ParseAddress(Input.Address))
					{
						case AddressFormat::Pay2PublicKeyHash:
						case AddressFormat::Pay2CashaddrPublicKeyHash:
							VirtualSize += 148;
							break;
						case AddressFormat::Pay2ScriptHash:
						case AddressFormat::Pay2CashaddrScriptHash:
							VirtualSize = 153;
							break;
						case AddressFormat::Pay2WitnessPublicKeyHash:
						case AddressFormat::Pay2WitnessScriptHash:
							VirtualSize += 67.75;
							HasWitness = true;
							break;
						case AddressFormat::Pay2Taproot:
							VirtualSize += 57.25;
							HasWitness = true;
							break;
						default:
							Coreturn ExpectsLR<BaseFee>(LayerException("invalid input address"));
					}
				}

				for (auto& Output : Outputs)
				{
					switch (ParseAddress(Output))
					{
						case AddressFormat::Pay2PublicKeyHash:
						case AddressFormat::Pay2CashaddrPublicKeyHash:
							VirtualSize += 32;
							break;
						case AddressFormat::Pay2ScriptHash:
						case AddressFormat::Pay2CashaddrScriptHash:
							VirtualSize = 32;
							break;
						case AddressFormat::Pay2WitnessPublicKeyHash:
							VirtualSize += 31;
							break;
						case AddressFormat::Pay2WitnessScriptHash:
							VirtualSize += 32;
							break;
						case AddressFormat::Pay2Taproot:
							VirtualSize += 43;
							break;
						default:
							Coreturn ExpectsLR<BaseFee>(LayerException("invalid input address"));
					}
				}

				if (HasWitness)
					VirtualSize += 0.5 + (double)Inputs->size() / 4.0;
				VirtualSize = std::ceil(VirtualSize);

				Decimal FeePerVByte = Estimate.Price;
				if (Estimate.Limit <= 1.0)
					FeePerVByte /= Decimal(VirtualSize).Truncate(Protocol::Now().Message.Precision);
				Coreturn ExpectsLR<BaseFee>(BaseFee(FeePerVByte, VirtualSize));
			}
			Option<LayerException> Bitcoin::SignTransactionInput(btc_tx_* Transaction, const CoinUTXO& Output, const SighashContext& Context, size_t Index)
			{
				if (Index >= Context.Keys.size())
					return LayerException("invalid sighash keys data");
				else if (Index >= Context.Scripts.Locking.size())
					return LayerException("invalid sighash locking scripts data");
				else if (Index >= Context.Scripts.Unlocking.size())
					return LayerException("invalid sighash unlocking scripts data");
				else if (Index >= Context.Values.size())
					return LayerException("invalid sighash values data");
				else if (Index >= Context.Types.size())
					return LayerException("invalid sighash types data");

				auto& Key = Context.Keys[Index];
				auto& UnlockingScripts = Context.Scripts.Unlocking[Index];
				auto Type = (btc_tx_out_type)Context.Types[Index];

				btc_key PrivateKey;
				btc_privkey_init(&PrivateKey);
				memcpy(PrivateKey.privkey, Key.data(), std::min(Key.size(), sizeof(PrivateKey)));

				auto Status = btc_tx_sign_input(Transaction, &PrivateKey, GetSigHashType(), Type, UnlockingScripts.data(), UnlockingScripts.size(), Context.Scripts.Locking.data(), Context.Values.data(), (uint32_t)Index, nullptr, nullptr);
				if (Status != BTC_SIGN_OK)
					return LayerException(btc_tx_sign_result_to_str(Status));

				return Optional::None;
			}
			Option<LayerException> Bitcoin::AddTransactionInput(btc_tx_* Transaction, const CoinUTXO& Output, SighashContext& Context, const char* PrivateKeyWif)
			{
				btc_key PrivateKey;
				if (btc_privkey_decode_wif(PrivateKeyWif, GetChain(), &PrivateKey) != 1)
					return LayerException("input private key invalid");

				btc_pubkey PublicKey;
				btc_pubkey_init(&PublicKey);
				btc_pubkey_from_key(&PrivateKey, &PublicKey);
				if (!btc_pubkey_is_valid(&PublicKey))
					return LayerException("input public key invalid");

				btc_tx_out_type ScriptType = BTC_TX_INVALID;
				cstring* LockingScript = cstr_new_sz(256), *UnlockingScript = nullptr;
				uint8_t Program[256]; size_t ProgramSize = sizeof(Program);
				switch (ParseAddress(Output.Address, Program, &ProgramSize))
				{
					case AddressFormat::Pay2PublicKey:
						if (btc_script_build_p2pk(LockingScript, Program, ProgramSize))
							ScriptType = BTC_TX_PUBKEY;
						break;
					case AddressFormat::Pay2PublicKeyHash:
						if (btc_script_build_p2pkh(LockingScript, Program))
							ScriptType = BTC_TX_PUBKEYHASH;
						break;
					case AddressFormat::Pay2ScriptHash:
					{
						ProgramSize = sizeof(uint160);
						btc_pubkey_get_hash160(&PublicKey, Program);
						if (btc_script_build_p2pkh(LockingScript, Program))
						{
							uint8_t Version = 0;
							UnlockingScript = cstr_new_sz(256);
							ser_varlen(UnlockingScript, 22);
							ser_bytes(UnlockingScript, &Version, 1);
							ser_varlen(UnlockingScript, 20);
							ser_bytes(UnlockingScript, Program, 20);
							ScriptType = BTC_TX_WITNESS_V0_PUBKEYHASH;
						}
						break;
					}
					case AddressFormat::Pay2WitnessScriptHash:
					{
						ProgramSize = sizeof(uint160);
						btc_pubkey_get_hash160(&PublicKey, Program);
						if (btc_script_build_p2pkh(LockingScript, Program))
						{
							UnlockingScript = cstr_new_cstr(LockingScript);
							ScriptType = BTC_TX_WITNESS_V0_SCRIPTHASH;
						}
						break;
					}
					case AddressFormat::Pay2WitnessPublicKeyHash:
						if (btc_script_build_p2pkh(LockingScript, Program))
							ScriptType = BTC_TX_WITNESS_V0_PUBKEYHASH;
						break;
					case AddressFormat::Pay2Taproot:
					{
						uint256 KeypathProgram;
						btc_pubkey_get_taproot_pubkey(&PublicKey, nullptr, KeypathProgram);
						if (!btc_script_build_p2tr(LockingScript, Program))
							break;

						if (ProgramSize != sizeof(KeypathProgram) || memcmp(KeypathProgram, Program, ProgramSize) != 0)
						{
							if (false)
							{
								UnlockingScript = cstr_new_sz(256);
								if (btc_script_build_p2pk(UnlockingScript, KeypathProgram, sizeof(KeypathProgram)))
									ScriptType = BTC_TX_WITNESS_V1_TAPROOT_SCRIPTPATH;
							}
						}
						else 
							ScriptType = BTC_TX_WITNESS_V1_TAPROOT_KEYPATH;
						break;
					}
					default:
						break;
				}

				String RawTransactionId = Codec::HexDecode(Output.TransactionId);
				std::reverse(RawTransactionId.begin(), RawTransactionId.end());

				Context.Scripts.Unlocking.emplace_back();
				auto& UnlockingScripts = Context.Scripts.Unlocking.back();
				if (UnlockingScript != nullptr)
					UnlockingScripts.push_back(UnlockingScript);

				Context.Scripts.Locking.push_back(LockingScript);
				Context.Keys.push_back(String((char*)PrivateKey.privkey, sizeof(PrivateKey.privkey)));
				Context.Values.push_back((uint64_t)ToBaselineValue(Output.Value));
				Context.Types.push_back(ScriptType);

				btc_tx_in* Input = btc_tx_in_new();
				memcpy(Input->prevout.hash, RawTransactionId.c_str(), sizeof(Input->prevout.hash));
				Input->script_sig = cstr_new_sz(128);
				Input->prevout.n = Output.Index;
				vector_add(Transaction->vin, Input);
				return Optional::None;
			}
			Option<LayerException> Bitcoin::AddTransactionOutput(btc_tx_* Transaction, const std::string_view& Address, const Decimal& Value)
			{
				uint8_t Program[256];
				size_t ProgramSize = sizeof(Program);

				bool ScriptExists = false;
				switch (ParseAddress(Address, Program, &ProgramSize))
				{
					case AddressFormat::Pay2PublicKey:
						ScriptExists = btc_tx_add_p2pk_out(Transaction, (uint64_t)ToBaselineValue(Value), Program, ProgramSize);
						break;
					case AddressFormat::Pay2PublicKeyHash:
						ScriptExists = btc_tx_add_p2pkh_hash160_out(Transaction, (uint64_t)ToBaselineValue(Value), Program);
						break;
					case AddressFormat::Pay2ScriptHash:
						ScriptExists = btc_tx_add_p2sh_hash160_out(Transaction, (uint64_t)ToBaselineValue(Value), Program);
						break;
					case AddressFormat::Pay2WitnessScriptHash:
						ScriptExists = btc_tx_add_p2wsh_hash256_out(Transaction, (uint64_t)ToBaselineValue(Value), Program);
						break;
					case AddressFormat::Pay2WitnessPublicKeyHash:
						ScriptExists = btc_tx_add_p2wpkh_hash160_out(Transaction, (uint64_t)ToBaselineValue(Value), Program);
						break;
					case AddressFormat::Pay2Tapscript:
					case AddressFormat::Pay2Taproot:
						ScriptExists = btc_tx_add_p2tr_hash256_out(Transaction, (uint64_t)ToBaselineValue(Value), Program);
						break;
					default:
						return LayerException("output address type invalid");
				}

				if (!ScriptExists)
					return LayerException("output address script type invalid");

				return Optional::None;
			}
			String Bitcoin::SerializeTransactionData(btc_tx_* Transaction)
			{
				cstring* Data = cstr_new_sz(1024);
				btc_tx_serialize(Data, Transaction, true);

				String HexData(Data->len * 2, '\0');
				utils_bin_to_hex((uint8_t*)Data->str, Data->len, (char*)HexData.data());
				cstr_free(Data, true);
				return HexData;
			}
			String Bitcoin::SerializeTransactionId(btc_tx_* Transaction)
			{
				uint256 Hash;
				btc_tx_hash(Transaction, Hash);

				String Intermediate = String((char*)Hash, sizeof(Hash));
				std::reverse(Intermediate.begin(), Intermediate.end());
				return Codec::HexEncode(Intermediate);
			}
			Bitcoin::AddressFormat Bitcoin::ParseAddress(const std::string_view& Address, uint8_t* DataOut, size_t* DataSizeOut)
			{
				auto* Chain = GetChain();
				if (Address.empty())
					return AddressFormat::Unknown;

				uint8_t Data[256]; size_t DataSize = sizeof(Data);
				if (Chain->bech32_cashaddr[0] != '\0')
				{
					AddressFormat Type; size_t PrefixSize;
					if (LegacyHashFromCashAddress(Chain, Address, Data, &DataSize, &PrefixSize, &Type))
					{
						*DataSizeOut = std::min(DataSize - PrefixSize, *DataSizeOut);
						memcpy(DataOut, Data + PrefixSize, *DataSizeOut);
						return Type;
					}
				}
				if (Chain->bech32_hrp[0] == '\0' || Stringify::StartsWith(Address, Chain->bech32_hrp))
				{
					int32_t WitnessVersion = 0;
					if (segwit_addr_decode(&WitnessVersion, Data, &DataSize, Chain->bech32_hrp, String(Address).c_str()))
					{
						if (DataOut && DataSizeOut)
						{
							*DataSizeOut = std::min(DataSize, *DataSizeOut);
							memcpy(DataOut, Data, *DataSizeOut);
						}

						if (DataSize == 32)
						{
							if (WitnessVersion == 1)
								return AddressFormat::Pay2Taproot;

							return AddressFormat::Pay2WitnessScriptHash;
						}
						else if (DataSize == 20)
							return AddressFormat::Pay2WitnessPublicKeyHash;
					}
				}

				DataSize = sizeof(uint8_t) * Address.size() * 2;
				int NewSize = btc_base58_decode_check(String(Address).c_str(), Data, DataSize);
				if (!NewSize)
				{
				TryPublicKey:
					if (!Format::Util::IsHexEncoding(Address))
						return AddressFormat::Unknown;

					auto RawPublicKey = Codec::HexDecode(Address);
					if (RawPublicKey.size() != BTC_ECKEY_COMPRESSED_LENGTH && RawPublicKey.size() != BTC_ECKEY_UNCOMPRESSED_LENGTH)
						return AddressFormat::Unknown;

					btc_pubkey PublicKey;
					btc_pubkey_init(&PublicKey);
					memcpy(PublicKey.pubkey, RawPublicKey.data(), RawPublicKey.size());
					PublicKey.compressed = RawPublicKey.size() == BTC_ECKEY_COMPRESSED_LENGTH;
					if (!btc_pubkey_is_valid(&PublicKey))
						return AddressFormat::Unknown;

					memcpy(Data, RawPublicKey.data(), RawPublicKey.size());
					if (DataOut && DataSizeOut)
					{
						*DataSizeOut = std::min(RawPublicKey.size(), *DataSizeOut);
						memcpy(DataOut, RawPublicKey.data(), *DataSizeOut);
					}

					return AddressFormat::Pay2PublicKey;
				}

				DataSize = (size_t)(NewSize - 4);
				if (base58_prefix_check(Chain->b58prefix_pubkey_address, Data))
				{
					size_t PrefixSize = base58_prefix_size(Chain->b58prefix_pubkey_address);
					if (DataSize != sizeof(uint160) + PrefixSize)
						goto TryPublicKey;

					if (DataOut && DataSizeOut)
					{
						*DataSizeOut = std::min(DataSize - PrefixSize, *DataSizeOut);
						memcpy(DataOut, Data + PrefixSize, *DataSizeOut);
					}

					return AddressFormat::Pay2PublicKeyHash;
				}
				else if (base58_prefix_check(Chain->b58prefix_script_address, Data))
				{
					size_t PrefixSize = base58_prefix_size(Chain->b58prefix_script_address);
					if (DataSize != sizeof(uint160) + PrefixSize)
						goto TryPublicKey;

					if (DataOut && DataSizeOut)
					{
						*DataSizeOut = std::min(DataSize - PrefixSize, *DataSizeOut);
						memcpy(DataOut, Data + PrefixSize, *DataSizeOut);
					}

					return AddressFormat::Pay2ScriptHash;
				}

				goto TryPublicKey;
			}
			String Bitcoin::GetMessageMagic()
			{
				return "Bitcoin Signed Message:\n";
			}
			void Bitcoin::GenerateMessageHash(const std::string_view& Input, uint8_t Output[32])
			{
				String Size(1, (char)Input.size());
				if (Input.size() > 253)
				{
					uint16_t Size16 = OS::CPU::ToEndianness(OS::CPU::Endian::Little, (uint16_t)Input.size());
					Size.append((char*)&Size16, sizeof(Size16));
				}

				String Header = GetMessageMagic();
				String Payload = Stringify::Text("%c%s%.*s%.*s", (char)Header.size(), Header.c_str(), (int)Size.size(), Size.c_str(), (int)Input.size(), Input.data());
				btc_hash((uint8_t*)Payload.data(), Payload.size(), Output);
			}
			const btc_chainparams_* Bitcoin::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &btc_chainparams_regtest;
					case NetworkType::Testnet:
						return &btc_chainparams_test;
					case NetworkType::Mainnet:
						return &btc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Bitcoin::AddressFormat Bitcoin::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash | (size_t)AddressFormat::Pay2WitnessPublicKeyHash | (size_t)AddressFormat::Pay2Taproot);
			}
			uint32_t Bitcoin::GetSigHashType()
			{
				return SIGHASH_ALL;
			}
		}
	}
}