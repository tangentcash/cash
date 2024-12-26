#include "tron.h"
#include "../../utils/tiny-bitcoin/chainparams.h"
#include "../../utils/tiny-bitcoin/ecc_key.h"
#include "../../utils/tiny-bitcoin/base58.h"
#include "../../utils/tiny-bitcoin/utils.h"
#include "../../utils/protobuf/TronInternal.pb.h"
extern "C"
{
#include "../../utils/trezor-crypto/secp256k1.h"
#include "../../utils/trezor-crypto/ecdsa.h"
}
#include <secp256k1_recovery.h>

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			const char* Tron::TrxNdCall::BroadcastTransaction()
			{
				return "/wallet/broadcasttransaction";
			}
			const char* Tron::TrxNdCall::GetBlock()
			{
				return "/wallet/getblock";
			}

			Tron::Tron() noexcept : Ethereum()
			{
				Netdata.Composition = Algorithm::Composition::Type::SECP256K1;
				Netdata.Routing = RoutingPolicy::Account;
				Netdata.SyncLatency = 15;
				Netdata.Divisibility = Decimal(1000000).Truncate(Protocol::Now().Message.Precision);
				Netdata.SupportsTokenTransfer = "trc20";
				Netdata.SupportsBulkTransfer = false;
			}
			Promise<ExpectsLR<Tron::TrxTxBlockHeaderInfo>> Tron::GetBlockHeaderForTx(const Algorithm::AssetId& Asset)
			{
				Schema* Args = Var::Set::Object();
				Args->Set("detail", Var::Boolean(false));

				auto BlockData = Coawait(ExecuteREST(Asset, "POST", TrxNdCall::GetBlock(), Args, CachePolicy::Lazy));
				if (!BlockData)
					Coreturn ExpectsLR<Tron::TrxTxBlockHeaderInfo>(std::move(BlockData.Error()));

				TrxTxBlockHeaderInfo Info;
				Info.RefBlockBytes = uint128_t(BlockData->FetchVar("block_header.raw_data.number").GetInteger()).ToString(16);
				Info.RefBlockBytes = Info.RefBlockBytes.substr(Info.RefBlockBytes.size() - 4);
				Info.RefBlockHash = BlockData->GetVar("blockID").GetBlob().substr(16, 16);
				Info.Timestamp = BlockData->FetchVar("block_header.raw_data.timestamp").GetInteger();
				Info.Expiration = Info.Timestamp + 60 * 1000;
				Memory::Release(*BlockData);

				while (Info.RefBlockBytes.size() < 4)
					Info.RefBlockBytes.insert(Info.RefBlockBytes.begin(), '0');

				Coreturn ExpectsLR<Tron::TrxTxBlockHeaderInfo>(std::move(Info));
			}
			ExpectsLR<void> Tron::VerifyNodeCompatibility(Nodemaster* Node)
			{
				if (!Node->HasDistinctURL(Nodemaster::TransmitType::JSONRPC))
					return LayerException("trongrid jsonrpc node is required");

				if (!Node->HasDistinctURL(Nodemaster::TransmitType::HTTP))
					return LayerException("trongrid rest node is required");

				return Expectation::Met;
			}
			Promise<ExpectsLR<void>> Tron::BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData)
			{
				auto HexData = Coawait(ExecuteHTTP(Asset, "POST", TrxNdCall::BroadcastTransaction(), "application/json", TxData.Data, CachePolicy::Greedy));
				if (!HexData)
					Coreturn ExpectsLR<void>(std::move(HexData.Error()));

				bool Success = HexData->GetVar("result").GetBoolean();
				String Code = HexData->GetVar("code").GetBlob();
				String Message = HexData->GetVar("message").GetBlob();
				if (Code.empty())
					Code = HexData->GetVar("Error").GetBlob();

				Memory::Release(*HexData);
				if (!Success)
					Coreturn ExpectsLR<void>(LayerException(Message.empty() ? Code : Code + ": " + Codec::HexDecode(Message)));

				Coreturn ExpectsLR<void>(Expectation::Met);
			}
			Promise<ExpectsLR<Decimal>> Tron::CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, Option<String>&& Address)
			{
				auto* Implementation = (Chains::Tron*)Datamaster::GetChain(Asset);
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
				Decimal Divisibility = Implementation->Netdata.Divisibility;
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
			Promise<ExpectsLR<OutgoingTransaction>> Tron::NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee)
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

				auto BlockHeader = Coawait(GetBlockHeaderForTx(Asset));
				if (!BlockHeader)
					Coreturn ExpectsLR<OutgoingTransaction>(std::move(BlockHeader.Error()));

				Decimal Divisibility = Netdata.Divisibility;
				if (ContractAddress)
				{
					auto ContractDivisibility = Coawait(GetContractDivisibility(Asset, this, *ContractAddress));
					if (ContractDivisibility)
						Divisibility = *ContractDivisibility;
				}

				uint8_t RawPrivateKey[256];
				auto PrivateKey = FromWallet->SigningKey.Expose<2048>();
				GeneratePrivateKeyDataFromPrivateKey(PrivateKey.Key, PrivateKey.Size, RawPrivateKey);

				uint8_t RawPublicKey[256];
				auto PublicKey = Codec::HexDecode(FromWallet->VerifyingKey.ExposeToHeap());
				memcpy(RawPublicKey, PublicKey.data(), std::min(sizeof(RawPrivateKey), PublicKey.size()));

				protocol::Transaction Transaction;
				protocol::Transaction_raw* RawData = Transaction.mutable_raw_data();
				RawData->set_ref_block_bytes(Copy<std::string>(Codec::HexDecode(BlockHeader->RefBlockBytes)));
				RawData->set_ref_block_hash(Copy<std::string>(Codec::HexDecode(BlockHeader->RefBlockHash)));
				RawData->set_expiration(BlockHeader->Expiration);
				RawData->set_timestamp(BlockHeader->Timestamp);

				if (ContractAddress)
				{
					protocol::TriggerSmartContract Transfer;
					Transfer.set_data(Copy<std::string>(Ethereum::ScCall::Transfer(DecodeNonEthAddressPf(FromWallet->Addresses.begin()->second), FromEth(Subject.Value, Divisibility))));
					Transfer.set_token_id(0);
					Transfer.set_owner_address(Copy<std::string>(Codec::HexDecode(DecodeNonEthAddressPf(FromWallet->Addresses.begin()->second))));
					Transfer.set_call_token_value((uint64_t)FromEth(Subject.Value, Divisibility));
					Transfer.set_call_value(0);
					Transfer.set_contract_address(Copy<std::string>(Codec::HexDecode(DecodeNonEthAddressPf(*ContractAddress))));

					protocol::Transaction_Contract* Contract = RawData->add_contract();
					Contract->set_type(protocol::Transaction_Contract_ContractType_TriggerSmartContract);
					Contract->mutable_parameter()->PackFrom(Transfer);
				}
				else
				{
					protocol::TransferContract Transfer;
					Transfer.set_owner_address(Copy<std::string>(Codec::HexDecode(DecodeNonEthAddressPf(FromWallet->Addresses.begin()->second))));
					Transfer.set_to_address(Copy<std::string>(Codec::HexDecode(DecodeNonEthAddressPf(Subject.Address))));
					Transfer.set_amount((uint64_t)FromEth(Subject.Value, Divisibility));

					protocol::Transaction_Contract* Contract = RawData->add_contract();
					Contract->set_type(protocol::Transaction_Contract_ContractType_TransferContract);
					Contract->mutable_parameter()->PackFrom(Transfer);
				}

				String TransactionData = Copy<String>(Transaction.raw_data().SerializeAsString());
				String TransactionId = *Crypto::HashHex(Digests::SHA256(), TransactionData);
				String Message = Codec::HexDecode(TransactionId);

				uint8_t RawSignature[65];
				if (ecdsa_sign_digest(&secp256k1, RawPrivateKey, (uint8_t*)Message.data(), RawSignature, RawSignature + 64, nullptr) != 0)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("input private key invalid"));

				if (RawSignature[64] > 0)
					RawSignature[64] = 0x1c;
				else
					RawSignature[64] = 0x1b;

				String Signature = Codec::HexEncode(std::string_view((char*)RawSignature, sizeof(RawSignature)));
				if (ecdsa_verify_digest(&secp256k1, RawPublicKey, RawSignature, (uint8_t*)Message.data()) != 0)
					Coreturn ExpectsLR<OutgoingTransaction>(LayerException("input private key invalid"));

				UPtr<Schema> TransactionObject = Var::Set::Object();
				TransactionObject->Set("visible", Var::Boolean(false));
				TransactionObject->Set("txID", Var::String(TransactionId));
				TransactionObject->Set("raw_data_hex", Var::String(Codec::HexEncode(TransactionData)));

				Schema* RawDataObject = TransactionObject->Set("raw_data", Var::Set::Object());
				Schema* ContractObject = RawDataObject->Set("contract", Var::Set::Array())->Push(Var::Set::Object());
				Schema* ParameterObject = ContractObject->Set("parameter", Var::Set::Object());
				Schema* ValueObject = ParameterObject->Set("value", Var::Set::Object());
				ParameterObject->Set("type_url", Var::String(Copy<String>(RawData->contract().at(0).parameter().type_url())));
				ContractObject->Set("type", Var::String(Copy<String>(Transaction_Contract_ContractType_Name(RawData->contract().at(0).type()))));

				if (ContractAddress)
				{
					protocol::TriggerSmartContract Contract;
					RawData->contract().at(0).parameter().UnpackTo(&Contract);
					ValueObject->Set("data", Var::String(Codec::HexEncode(Copy<String>(Contract.data()))));
					if (Contract.token_id() > 0)
						ValueObject->Set("token_id", Var::Integer(Contract.token_id()));
					ValueObject->Set("owner_address", Var::String(Codec::HexEncode(Copy<String>(Contract.owner_address()))));
					if (Contract.call_token_value() > 0)
						ValueObject->Set("call_token_value", Var::Integer(Contract.call_token_value()));
					if (Contract.call_value() > 0)
						ValueObject->Set("call_value", Var::Integer(Contract.call_value()));
					ValueObject->Set("contract_address", Var::String(Codec::HexEncode(Copy<String>(Contract.contract_address()))));
				}
				else
				{
					protocol::TransferContract Contract;
					RawData->contract().at(0).parameter().UnpackTo(&Contract);
					ValueObject->Set("to_address", Var::String(Codec::HexEncode(Copy<String>(Contract.to_address()))));
					ValueObject->Set("owner_address", Var::String(Codec::HexEncode(Copy<String>(Contract.owner_address()))));
					if (Contract.amount() > 0)
						ValueObject->Set("amount", Var::Integer(Contract.amount()));
				}

				RawDataObject->Set("ref_block_bytes", Var::String(Codec::HexEncode(Copy<String>(RawData->ref_block_bytes()))));
				RawDataObject->Set("ref_block_hash", Var::String(Codec::HexEncode(Copy<String>(RawData->ref_block_hash()))));
				if (RawData->ref_block_num() > 0)
					RawDataObject->Set("ref_block_num", Var::Integer(RawData->ref_block_num()));
				RawDataObject->Set("expiration", Var::Integer(RawData->expiration()));
				RawDataObject->Set("timestamp", Var::Integer(RawData->timestamp()));
				if (RawData->fee_limit() > 0)
					RawDataObject->Set("fee_limit", Var::Integer(RawData->fee_limit()));

				Schema* SignatureObject = TransactionObject->Set("signature", Var::Array());
				SignatureObject->Push(Var::String(Signature));

				TransactionData = Schema::ToJSON(*TransactionObject);
				IncomingTransaction Tx;
				Tx.SetTransaction(Asset, 0, TransactionId, std::move(FeeValue));
				Tx.SetOperations({ Transferer(FromWallet->Addresses.begin()->second, Option<uint64_t>(FromWallet->AddressIndex), Decimal(Subject.Value)) }, Vector<Transferer>(To));
				Coreturn ExpectsLR<OutgoingTransaction>(OutgoingTransaction(std::move(Tx), std::move(TransactionData)));
			}
			ExpectsLR<String> Tron::NewPublicKeyHash(const std::string_view& Address)
			{
				return Ethereum::NewPublicKeyHash(DecodeNonEthAddress(Address));
			}
			String Tron::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/195'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String Tron::GetMessageMagic()
			{
				return "\x19TRON Signed Message:\n";
			}
			String Tron::EncodeEthAddress(const std::string_view& EthAddress)
			{
				auto* Chain = GetChain();
				if (!Stringify::StartsWith(EthAddress, "0x"))
					return String(EthAddress);

				uint8_t Hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
				int Offset = (int)base58_prefix_dump(Chain->b58prefix_pubkey_address, Hash160);
				int Hash160Size = sizeof(Hash160) - Offset;
				utils_hex_to_bin(EthAddress.data() + 2, Hash160 + Offset, (int)EthAddress.size() - 2, &Hash160Size);

				char Address[128];
				btc_base58_encode_check(Hash160, sizeof(uint160) + Offset, Address, 100);
				return Address;
			}
			String Tron::DecodeNonEthAddress(const std::string_view& NonEthAddress)
			{
				auto* Chain = GetChain();
				uint8_t Hash160[sizeof(uint160) + B58_PREFIX_MAX_SIZE];
				int PrefixSize = (int)base58_prefix_size(Chain->b58prefix_pubkey_address);
				int Size = btc_base58_decode_check(String(NonEthAddress).c_str(), Hash160, sizeof(Hash160)) - PrefixSize - 4;
				if (Size < 20)
					return String();

				return GeneratePkhAddress((char*)Hash160 + PrefixSize);
			}
			String Tron::DecodeNonEthAddressPf(const std::string_view& NonEthAddress)
			{
				String Address = DecodeNonEthAddress(NonEthAddress);
				return Stringify::ToLower(Stringify::Replace(Address, "0x", "41"));
			}
			Decimal Tron::GetDivisibilityGwei()
			{
				return Decimal("1000000");
			}
			void Tron::GenerateMessageHash(const String& Input, uint8_t Output[32])
			{
				String Header = GetMessageMagic();
				String Payload = Stringify::Text("%s%i%s",
					Header.c_str(),
					(int)Input.size(),
					Input.c_str());
				keccak_256((uint8_t*)Payload.data(), Payload.size(), Output);
			}
			const btc_chainparams_* Tron::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &trx_chainparams_regtest;
					case NetworkType::Testnet:
						return &trx_chainparams_test;
					case NetworkType::Mainnet:
						return &trx_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}