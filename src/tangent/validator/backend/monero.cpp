#include "monero.h"
#include "../service/nss.h"
#include "../internal/libbitcoin/tool.h"
#include "../internal/libbitcoin/bip32.h"
#include <sodium.h>
extern "C"
{
#include "../../internal/monero/base58.h"
#include "../../internal/monero/xmr.h"
#include "../../internal/monero/serialize.h"
#include "../../internal/monero/crypto.h"
#include "../../internal/sha3.h"
}

namespace Tangent
{
	namespace Mediator
	{
		namespace Backends
		{
			const char* Monero::NdCall::JsonRpc()
			{
				return "/json_rpc";
			}
			const char* Monero::NdCall::SendRawTransaction()
			{
				return "/send_raw_transaction";
			}
			const char* Monero::NdCall::GetTransactions()
			{
				return "/get_transactions";
			}
			const char* Monero::NdCall::GetHeight()
			{
				return "/get_height";
			}

			const char* Monero::NdCallRestricted::GetBlock()
			{
				return "get_block";
			}
			const char* Monero::NdCallRestricted::GetFeeEstimate()
			{
				return "get_fee_estimate";
			}

			Monero::Monero() noexcept : RelayBackendUTXO()
			{
				Netdata.Composition = Algorithm::Composition::Type::ED25519;
				Netdata.Routing = RoutingPolicy::UTXO;
				Netdata.SyncLatency = 5;
				Netdata.Divisibility = Decimal(1000000000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer.clear();
				Netdata.SupportsBulkTransfer = true;
			}
			ExpectsPromiseRT<void> Monero::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				Schema* Args = Var::Set::Object();
				Args->Set("tx_as_hex", Var::String(Format::Util::Clear0xHex(TxData.Data)));

				auto HexData = Coawait(ExecuteREST(Asset, "POST", NdCall::SendRawTransaction(), Args, CachePolicy::Lazy));
				if (!HexData)
					Coreturn ExpectsRT<void>(HexData.Error());

				bool DoubleSpend = HexData->GetVar("double_spend").GetBoolean();
				bool FeeTooLow = HexData->GetVar("fee_too_low").GetBoolean();
				bool InvalidInput = HexData->GetVar("invalid_input").GetBoolean();
				bool InvalidOutput = HexData->GetVar("invalid_output").GetBoolean();
				bool LowMixin = HexData->GetVar("low_mixin").GetBoolean();
				bool Overspend = HexData->GetVar("overspend").GetBoolean();
				bool TooBig = HexData->GetVar("too_big").GetBoolean();
				Memory::Release(*HexData);

				if (DoubleSpend)
					Coreturn ExpectsRT<void>(RemoteException("transaction double spends inputs"));
				else if (FeeTooLow)
					Coreturn ExpectsRT<void>(RemoteException("transaction fee is too low"));
				else if (InvalidInput)
					Coreturn ExpectsRT<void>(RemoteException("transaction uses invalid input"));
				else if (InvalidOutput)
					Coreturn ExpectsRT<void>(RemoteException("transaction uses invalid output"));
				else if (LowMixin)
					Coreturn ExpectsRT<void>(RemoteException("transaction mixin count is too low"));
				else if (Overspend)
					Coreturn ExpectsRT<void>(RemoteException("transaction overspends inputs"));
				else if (TooBig)
					Coreturn ExpectsRT<void>(RemoteException("transaction is too big"));

				UpdateCoins(Asset, TxData);
				Coreturn ExpectsRT<void>(Expectation::Met);
			}
			ExpectsPromiseRT<uint64_t> Monero::GetLatestBlockHeight(const Algorithm::AssetId& Asset)
			{
				auto Height = Coawait(ExecuteREST(Asset, "POST", NdCall::GetHeight(), nullptr, CachePolicy::Lazy));
				if (!Height)
					Coreturn ExpectsRT<uint64_t>(Height.Error());

				uint64_t BlockHeight = Height->GetVar("height").GetInteger();
				Memory::Release(*Height);
				Coreturn ExpectsRT<uint64_t>(BlockHeight);
			}
			ExpectsPromiseRT<Schema*> Monero::GetBlockTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, String* BlockHash)
			{
				SchemaArgs Args;
				Args["height"] = Var::Set::Integer(BlockHeight);

				auto BlockData = Coawait(ExecuteRPC3(Asset, NdCallRestricted::GetBlock(), std::move(Args), CachePolicy::Shortened, NdCall::JsonRpc()));
				if (!BlockData)
					Coreturn ExpectsRT<Schema*>(BlockData.Error());

				auto BlockBlob = Schema::FromJSON(BlockData->GetVar("json").GetBlob());
				Memory::Release(*BlockData);
				if (!BlockBlob)
					Coreturn ExpectsRT<Schema*>(RemoteException(std::move(BlockBlob.Error().message())));

				Schema* TransactionData = Var::Set::Array();
				auto Destructor = UPtr<Schema>(*BlockBlob);
				auto CoinbaseTx = BlockBlob->Get("miner_tx");
				if (CoinbaseTx != nullptr)
				{
					TransactionData->Push(CoinbaseTx);
					CoinbaseTx->Unlink();
				}

				auto TransactionHashes = BlockBlob->Get("tx_hashes");
				if (TransactionHashes != nullptr && !TransactionHashes->Empty())
				{
					Schema* Args = Var::Set::Object();
					Args->Set("tx_hashes", TransactionHashes);
					TransactionHashes->Unlink();

					auto Transactions = UPtr<Schema>(Coawait(ExecuteREST(Asset, "POST", NdCall::GetTransactions(), nullptr, CachePolicy::Shortened)));
					if (Transactions)
					{
						auto* List = Transactions->Get("txs");
						if (List != nullptr)
						{
							for (auto& Transaction : List->GetChilds())
							{
								auto TransactionBlob = Schema::FromJSON(Transaction->GetVar("as_json").GetBlob());
								if (TransactionBlob)
									TransactionData->Push(*TransactionBlob);
							}
						}
					}
				}

				Coreturn ExpectsRT<Schema*>(TransactionData);
			}
			ExpectsPromiseRT<Schema*> Monero::GetBlockTransaction(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, const std::string_view& TransactionId)
			{
				Schema* Args = Var::Set::Object();
				Schema* Hashes = Args->Set("tx_hashes", Var::Set::Array());
				Hashes->Push(Var::String(TransactionId));

				auto Transactions = Coawait(ExecuteREST(Asset, "POST", NdCall::GetTransactions(), nullptr, CachePolicy::Shortened));
				if (!Transactions)
					Coreturn ExpectsRT<Schema*>(Transactions.Error());

				auto Destructor = UPtr<Schema>(Transactions);
				auto* List = Transactions->Get("txs");
				if (!List || List->Empty())
					Coreturn ExpectsRT<Schema*>(RemoteException("transaction not found"));

				auto TransactionBlob = Schema::FromJSON(List->GetChilds().front()->GetVar("as_json").GetBlob());
				if (!TransactionBlob)
					Coreturn ExpectsRT<Schema*>(RemoteException(std::move(TransactionBlob.Error().message())));
		
				Coreturn ExpectsRT<Schema*>(*TransactionBlob);
			}
			ExpectsPromiseRT<Vector<IncomingTransaction>> Monero::GetAuthenticTransactions(const Algorithm::AssetId& Asset, uint64_t BlockHeight, const std::string_view& BlockHash, Schema* TransactionData)
			{
				Coreturn ExpectsRT<Vector<IncomingTransaction>>(RemoteException("not implemented"));
			}
			ExpectsPromiseRT<BaseFee> Monero::EstimateFee(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const FeeSupervisorOptions& Options)
			{
				SchemaArgs Args;
				Args["grace_blocks"] = Var::Set::Integer(10);

				auto Fee = Coawait(ExecuteRPC3(Asset, NdCallRestricted::GetFeeEstimate(), std::move(Args), CachePolicy::Greedy, NdCall::JsonRpc()));
				if (!Fee)
					Coreturn ExpectsRT<BaseFee>(Fee.Error());

				uint64_t FeeRate = Fee->GetVar("fee").GetInteger();
				const size_t ExpectedMaxTxSize = 1000;
				Coreturn ExpectsRT<BaseFee>(BaseFee(FeeRate / Netdata.Divisibility, Decimal(ExpectedMaxTxSize)));
			}
			ExpectsPromiseRT<CoinUTXO> Monero::GetTransactionOutput(const Algorithm::AssetId& Asset, const std::string_view& TransactionId, uint32_t Index)
			{
				auto Result = GetCoins(Asset, TransactionId, Index);
				if (Result)
					return ExpectsPromiseRT<CoinUTXO>(RemoteException(std::move(Result.Error().message())));

				return ExpectsPromiseRT<CoinUTXO>(std::move(*Result));
			}
			ExpectsPromiseRT<OutgoingTransaction> Monero::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
			{
				Coreturn ExpectsRT<OutgoingTransaction>(RemoteException("not implemented"));
			}
			ExpectsLR<MasterWallet> Monero::NewMasterWallet(const std::string_view& Seed)
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
			ExpectsLR<DerivedSigningWallet> Monero::NewSigningWallet(const Algorithm::AssetId& Asset, const MasterWallet& Wallet, uint64_t AddressIndex)
			{
				auto* Chain = GetChain();
				char MasterPrivateKey[256];
				{
					auto Private = Wallet.SigningKey.Expose<KEY_LIMIT>();
					if (!hd_derive(Chain, Private.View.data(), GetDerivation(AddressIndex).c_str(), MasterPrivateKey, sizeof(MasterPrivateKey)))
						return ExpectsLR<DerivedSigningWallet>(LayerException("invalid private key"));
				}

				btc_hdnode Node;
				if (!btc_hdnode_deserialize(MasterPrivateKey, Chain, &Node))
					return LayerException("input address derivation invalid");

				Algorithm::Composition::ConvertToScalarEd25519(Node.private_key);
				auto Derived = NewSigningWallet(Asset, PrivateKey(std::string_view((char*)Node.private_key, sizeof(Node.private_key))));
				if (Derived)
					Derived->AddressIndex = AddressIndex;
				return Derived;
			}
			ExpectsLR<DerivedSigningWallet> Monero::NewSigningWallet(const Algorithm::AssetId& Asset, const PrivateKey& SigningKey)
			{
				bool UsePubliclyKnownKeypair = false;
				auto SigningKeypair = SigningKey.Expose<KEY_LIMIT>();
				uint8_t PrivateSpendKey[32], PrivateViewKey[32];
				size_t Split = SigningKeypair.View.find(':');
				if (SigningKeypair.View.size() != 32 && SigningKeypair.View.size() != 64)
				{
					auto RawSpendKey = Codec::HexDecode(SigningKeypair.View.substr(0, Split));
					if (RawSpendKey.size() != 32)
						return LayerException("not a valid hex private spend-view keypair");

					memcpy(PrivateSpendKey, RawSpendKey.data(), sizeof(PrivateSpendKey));
					auto RawViewKey = Codec::HexDecode(SigningKeypair.View.substr(Split + 1));
					if (RawViewKey.size() == 32)
						memcpy(PrivateViewKey, RawViewKey.data(), sizeof(PrivateViewKey));
					else
						UsePubliclyKnownKeypair = true;
				}
				else
				{
					memcpy(PrivateSpendKey, SigningKeypair.View.data(), sizeof(PrivateSpendKey));
					if (SigningKeypair.View.size() == 64)
						memcpy(PrivateViewKey, SigningKeypair.View.data() + sizeof(PrivateSpendKey), sizeof(PrivateViewKey));
					else
						UsePubliclyKnownKeypair = true;
				}

				uint8_t PublicSpendKey[32];
				if (crypto_scalarmult_ed25519_base_noclamp(PublicSpendKey, PrivateSpendKey) != 0)
					return LayerException("not a valid private spend-view key");

				if (UsePubliclyKnownKeypair)
					DeriveKnownPrivateViewKey(PublicSpendKey, PrivateViewKey);

				auto Derived = NewVerifyingWallet(Asset, std::string_view((char*)PublicSpendKey, sizeof(PublicSpendKey)));
				if (!Derived)
					return Derived.Error();

				String PrivateSpendViewKey = Codec::HexEncode(std::string_view((char*)PrivateSpendKey, sizeof(PrivateSpendKey)));
				PrivateSpendViewKey.append(1, ':').append(Codec::HexEncode(std::string_view((char*)PrivateViewKey, sizeof(PrivateViewKey))));
				return ExpectsLR<DerivedSigningWallet>(DerivedSigningWallet(std::move(*Derived), ::PrivateKey(PrivateSpendViewKey)));
			}
			ExpectsLR<DerivedVerifyingWallet> Monero::NewVerifyingWallet(const Algorithm::AssetId& Asset, const std::string_view& VerifyingKey)
			{
				bool UsePubliclyKnownKeypair = false;
				uint8_t PublicSpendKey[32], PublicViewKey[32];
				size_t Split = VerifyingKey.find(':');
				if (VerifyingKey.size() != 32 && VerifyingKey.size() != 64)
				{
					auto RawSpendKey = Codec::HexDecode(VerifyingKey.substr(0, Split));
					if (RawSpendKey.size() != 32)
						return LayerException("not a valid hex public spend-view keypair");

					memcpy(PublicSpendKey, RawSpendKey.data(), sizeof(PublicSpendKey));
					auto RawViewKey = Codec::HexDecode(VerifyingKey.substr(Split + 1));
					if (RawViewKey.size() == 32)
						memcpy(PublicViewKey, RawViewKey.data(), sizeof(PublicViewKey));
					else
						UsePubliclyKnownKeypair = true;
				}
				else
				{
					memcpy(PublicSpendKey, VerifyingKey.data(), sizeof(PublicSpendKey));
					if (VerifyingKey.size() == 64)
						memcpy(PublicViewKey, VerifyingKey.data() + sizeof(PublicSpendKey), sizeof(PublicViewKey));
					else
						UsePubliclyKnownKeypair = true;
				}

				if (UsePubliclyKnownKeypair)
					DeriveKnownPublicViewKey(PublicSpendKey, PublicViewKey);

				uint8_t Buffer[64];
				memcpy((char*)Buffer, PublicSpendKey, sizeof(PublicSpendKey));
				memcpy((char*)Buffer + sizeof(PublicSpendKey), PublicViewKey, sizeof(PublicViewKey));

				char Address[256] = { 0 };
				if (xmr_base58_addr_encode_check(GetNetworkType(), Buffer, sizeof(Buffer), Address, sizeof(Address)) == 0)
					return LayerException("not a valid public spend key");

				String PublicSpendViewKey = Codec::HexEncode(std::string_view((char*)PublicSpendKey, sizeof(PublicSpendKey)));
				PublicSpendViewKey.append(1, ':').append(Codec::HexEncode(std::string_view((char*)PublicViewKey, sizeof(PublicViewKey))));
				return ExpectsLR<DerivedVerifyingWallet>(DerivedVerifyingWallet({ { (uint8_t)1, String(Address) } }, Optional::None, std::move(PublicSpendViewKey)));
			}
			ExpectsLR<String> Monero::NewPublicKeyHash(const std::string_view& Address)
			{
				uint8_t Buffer[128]; uint64_t Tag;
				if (xmr_base58_addr_decode_check(Address.data(), Address.size(), &Tag, Buffer, sizeof(Buffer)) == 0)
					return LayerException("not a valid address data");
				else if (Tag != GetNetworkType())
					return LayerException("not a valid address type");
				return String((char*)Buffer, 64);
			}
			ExpectsLR<String> Monero::SignMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const PrivateKey& SigningKey)
			{
				auto SigningWallet = NewSigningWallet(Asset, SigningKey);
				if (!SigningWallet)
					return SigningWallet.Error();

				auto PrivateKeypair = SigningWallet->SigningKey.Expose<KEY_LIMIT>();
				auto PrivateSpendKeyBuffer = Codec::HexDecode(PrivateKeypair.View.substr(0, PrivateKeypair.View.find(':')));
				auto PublicSplit = SigningWallet->VerifyingKey.find(':');
				auto PublicSpendKeyBuffer = Codec::HexDecode(SigningWallet->VerifyingKey.substr(0, PublicSplit));
				auto PublicViewKeyBuffer = Codec::HexDecode(SigningWallet->VerifyingKey.substr(PublicSplit + 1));
				if (PrivateSpendKeyBuffer.size() != 32 || PublicSpendKeyBuffer.size() != 32 || PublicViewKeyBuffer.size() != 32)
					return LayerException("bad signing/verifying keypair");

				uint8_t Body[96];
				uint8_t SignatureData[64];
				uint8_t* SignatureC = (uint8_t*)((char*)SignatureData + 00);
				uint8_t* SignatureR = (uint8_t*)((char*)SignatureData + 32);
				uint8_t* PrivateSpendKey = (uint8_t*)PrivateSpendKeyBuffer.data();
				uint8_t* PublicSpendKey = (uint8_t*)PublicSpendKeyBuffer.data();
				uint8_t* PublicViewKey = (uint8_t*)PublicViewKeyBuffer.data();
				memcpy((char*)Body + 32, PublicSpendKey, PublicSpendKeyBuffer.size());
				MessageHash(Body, (uint8_t*)Message.data(), Message.size(), PublicSpendKey, PublicViewKey, 1);
			Retry:
				ge_p3 Point3;
				uint8_t Scalar[32];
				Crypto::FillRandomBytes(Scalar, sizeof(Scalar));
				sc_reduce32(Scalar);
				ge_scalarmult_base(&Point3, Scalar);
				ge_p3_tobytes((uint8_t*)((char*)Body + 64), &Point3);
				xmr_fast_hash(SignatureC, Body, sizeof(Body));
				sc_reduce32(SignatureC);
				if (!sc_isnonzero(SignatureC))
					goto Retry;

				sc_mulsub(SignatureR, SignatureC, PrivateSpendKey, Scalar);
				if (!sc_isnonzero(SignatureR))
					goto Retry;

				char EncodedSignature[256];
				size_t EncodedSignatureSize = sizeof(EncodedSignature);
				if (!xmr_base58_encode(EncodedSignature, &EncodedSignatureSize, SignatureData, sizeof(SignatureData)))
					return LayerException("failed to encode the signature");

				String Result = "SigV2";
				Result.append(EncodedSignature, EncodedSignatureSize);
				return ExpectsLR<String>(std::move(Result));
			}
			ExpectsLR<void> Monero::VerifyMessage(const Algorithm::AssetId& Asset, const std::string_view& Message, const std::string_view& VerifyingKey, const std::string_view& Signature)
			{
				uint8_t SignatureData[64]; size_t SignatureSize = sizeof(SignatureData);
				uint8_t* SignatureC = (uint8_t*)((char*)SignatureData + 00);
				uint8_t* SignatureR = (uint8_t*)((char*)SignatureData + 32);
				if (Signature.size() != 64)
				{
					auto SignatureDigest = Signature.substr(5);
					if (!xmr_base58_decode(SignatureDigest.data(), SignatureDigest.size(), SignatureData, &SignatureSize))
						return LayerException("failed to decode the signature");
					else if (SignatureSize != 64)
						return LayerException("failed to decode the signature");
				}
				else
					memcpy(SignatureData, Signature.data(), Signature.size());

				auto VerifyingWallet = NewVerifyingWallet(Asset, VerifyingKey);
				if (!VerifyingWallet)
					return VerifyingWallet.Error();

				auto PublicSplit = VerifyingWallet->VerifyingKey.find(':');
				auto PublicSpendKeyBuffer = Codec::HexDecode(VerifyingWallet->VerifyingKey.substr(0, PublicSplit));
				auto PublicViewKeyBuffer = Codec::HexDecode(VerifyingWallet->VerifyingKey.substr(PublicSplit + 1));
				if (PublicSpendKeyBuffer.size() != 32 || PublicViewKeyBuffer.size() != 32)
					return LayerException("bad verifying keypair");

				uint8_t Body[96];
				uint8_t* BodyComm = (uint8_t*)((char*)Body + 64);
				uint8_t* PublicSpendKey = (uint8_t*)PublicSpendKeyBuffer.data();
				uint8_t* PublicViewKey = (uint8_t*)PublicViewKeyBuffer.data();
				memcpy((char*)Body + 32, PublicSpendKey, PublicSpendKeyBuffer.size());
				MessageHash(Body, (uint8_t*)Message.data(), Message.size(), PublicSpendKey, PublicViewKey, 1);

				ge_p2 Point2; ge_p3 Point3;
				if (ge_frombytes_vartime(&Point3, PublicSpendKey) != 0)
					return LayerException("bad signature");
				else if (sc_check(SignatureC) != 0 || sc_check(SignatureR) != 0 || !sc_isnonzero(SignatureC))
					return LayerException("bad signature");

				static uint8_t Infinity[32] = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
				ge_double_scalarmult_base_vartime(&Point2, SignatureC, &Point3, SignatureR);
				ge_tobytes(BodyComm, &Point2);
				if (memcmp(BodyComm, Infinity, sizeof(Infinity)) == 0)
					return LayerException("bad signature");

				uint8_t C[32];
				xmr_fast_hash(C, Body, sizeof(Body));
				sc_reduce32(C);
				sc_sub(C, C, SignatureC);
				if (sc_isnonzero(C) != 0)
					return LayerException("bad signature");

				return Expectation::Met;
			}
			String Monero::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/128'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Monero::GetChain()
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
			const Monero::Chainparams& Monero::GetChainparams() const
			{
				return Netdata;
			}
			uint64_t Monero::GetRetirementBlockNumber() const
			{
				return 0;
			}
			uint64_t Monero::GetNetworkType() const
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Mainnet:
					case NetworkType::Regtest:
						return 18;
					case NetworkType::Testnet:
						return 53;
					default:
						VI_PANIC(false, "invalid network type");
						return 24;
				}
			}
			bool Monero::MessageHash(uint8_t Hash[32], const uint8_t* Message, size_t MessageSize, const uint8_t PublicSpendKey[32], const uint8_t PublicViewKey[32], const uint8_t Mode)
			{
				static const char HASH_KEY_MESSAGE_SIGNING[] = "MoneroMessageSignature";

				SHA3_CTX Context;
				keccak_256_Init(&Context);
				keccak_Update(&Context, (const uint8_t*)HASH_KEY_MESSAGE_SIGNING, sizeof(HASH_KEY_MESSAGE_SIGNING));
				keccak_Update(&Context, PublicSpendKey, sizeof(uint8_t) * 32);
				keccak_Update(&Context, PublicViewKey, sizeof(uint8_t) * 32);
				keccak_Update(&Context, (const uint8_t*)&Mode, sizeof(uint8_t));

				uint8_t LengthBuffer[(sizeof(size_t) * 8 + 6) / 7];
				int LengthBufferSize = xmr_write_varint(LengthBuffer, sizeof(LengthBuffer), MessageSize);
				if (LengthBufferSize == -1)
					return false;

				keccak_Update(&Context, LengthBuffer, (size_t)LengthBufferSize);
				keccak_Update(&Context, Message, MessageSize);
				keccak_Final(&Context, Hash);
				return true;
			}
			void Monero::DeriveKnownPrivateViewKey(const uint8_t PublicSpendKey[32], uint8_t PrivateViewKey[32])
			{
				uint8_t Hash[32];
				xmr_fast_hash(Hash, PublicSpendKey, sizeof(Hash));
				memcpy(PrivateViewKey, Hash, sizeof(Hash));
				Algorithm::Composition::ConvertToScalarEd25519(PrivateViewKey);
			}
			void Monero::DeriveKnownPublicViewKey(const uint8_t PublicSpendKey[32], uint8_t PublicViewKey[32])
			{
				uint8_t PrivateViewKey[32];
				DeriveKnownPrivateViewKey(PublicSpendKey, PrivateViewKey);
				crypto_scalarmult_ed25519_base_noclamp(PublicViewKey, PrivateViewKey);
			}
		}
	}
}
