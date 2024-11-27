#include "rpc.h"
#include "p2p.h"
#include "../kernel/script.h"
#include "../policy/storages.h"
#include "../policy/transactions.h"

namespace Tangent
{
	namespace RPC
	{
		static ExpectsLR<String> AsAddress(const std::string_view& Type, const Format::Variable& Value)
		{
			if (Type == States::AccountSequence::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountSequence::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountWork::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountWork::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountProgram::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountProgram::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountStorage::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountStorage::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountReward::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountReward::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountDerivation::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountDerivation::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountBalance::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountBalance::AsInstanceAddress(Owner);
			}

			if (Type == States::AccountContribution::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountContribution::AsInstanceAddress(Owner);
			}

			if (Type == States::WitnessProgram::AsInstanceTypename())
				return States::WitnessProgram::AsInstanceAddress(Value.AsString());

			if (Type == States::WitnessEvent::AsInstanceTypename())
				return States::WitnessEvent::AsInstanceAddress(Value.AsUint256());

			if (Type == States::WitnessAddress::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::WitnessAddress::AsInstanceAddress(Owner);
			}

			if (Type == States::WitnessTransaction::AsInstanceTypename())
				return States::WitnessTransaction::AsInstanceAddress(Algorithm::Asset::IdOfHandle(Value.AsString()));

			return LayerException("invalid state type");
		}
		static ExpectsLR<String> AsStride(const std::string_view& Type, const Format::Variable& Value)
		{
			if (Type == States::AccountSequence::AsInstanceTypename())
				return States::AccountSequence::AsInstanceStride();

			if (Type == States::AccountWork::AsInstanceTypename())
				return States::AccountWork::AsInstanceStride();

			if (Type == States::AccountProgram::AsInstanceTypename())
				return States::AccountProgram::AsInstanceStride();

			if (Type == States::AccountStorage::AsInstanceTypename())
				return States::AccountStorage::AsInstanceStride(Value.AsString());

			if (Type == States::AccountReward::AsInstanceTypename())
				return States::AccountReward::AsInstanceStride(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountDerivation::AsInstanceTypename())
				return States::AccountDerivation::AsInstanceStride(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountBalance::AsInstanceTypename())
				return States::AccountBalance::AsInstanceStride(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountContribution::AsInstanceTypename())
				return States::AccountContribution::AsInstanceStride(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::WitnessProgram::AsInstanceTypename())
				return States::WitnessProgram::AsInstanceStride();

			if (Type == States::WitnessEvent::AsInstanceTypename())
				return States::WitnessEvent::AsInstanceStride();

			if (Type == States::WitnessAddress::AsInstanceTypename())
			{
				auto Data = Value.AsSchema();
				if (!Data)
					return LayerException("invalid value, expected { asset: string, address: string, derivation_index: uint64 }");

				return States::WitnessAddress::AsInstanceStride(Algorithm::Asset::IdOfHandle(Data->GetVar("asset").GetBlob()), Data->GetVar("address").GetBlob(), Data->GetVar("derivation_index").GetInteger());
			}

			if (Type == States::WitnessTransaction::AsInstanceTypename())
				return States::WitnessTransaction::AsInstanceStride(Value.AsString());

			return LayerException("invalid state type");
		}

		ServerResponse&& ServerResponse::Success(UPtr<Schema>&& Value)
		{
			Data = std::move(Value);
			return std::move(*this);
		}
		ServerResponse&& ServerResponse::Error(ErrorCodes Code, const std::string_view& Message)
		{
			ErrorMessage = Message;
			ErrorCode = Code;
			return std::move(*this);
		}
		UPtr<Schema> ServerResponse::Transform(Schema* Request)
		{
			auto* Id = Request ? Request->Get("id") : nullptr;
			UPtr<Schema> Response = Var::Set::Object();
			Response->Set("id", Id ? Id : Var::Set::Null());
			
			auto* Result = Response->Set("result", Data.Reset());
			if (ErrorCode != ErrorCodes::OK && !ErrorMessage.empty())
			{
				auto* Error = Response->Set("error", Var::Object());
				Error->Set("message", Var::String(ErrorMessage));
				Error->Set("code", Var::Integer((int64_t)ErrorCode));
			}
			return Response;
		}

		ServerNode::ServerNode(P2P::ServerNode* NewValidator) noexcept : ControlSys("rpc-node"), Node(new HTTP::Server()), Validator(NewValidator)
		{
		}
		ServerNode::~ServerNode() noexcept
		{
			Memory::Release(Validator);
		}
		void ServerNode::Startup()
		{
			if (!Protocol::Now().User.RPC.Server)
				return;

			AdminToken = HasAdminAuthorization() ? Codec::Base64Encode(Protocol::Now().User.RPC.AdminUsername + ":" + Protocol::Now().User.RPC.AdminPassword) : String();
			UserToken = HasUserAuthorization() ? Codec::Base64Encode(Protocol::Now().User.RPC.UserUsername + ":" + Protocol::Now().User.RPC.UserPassword) : String();

			HTTP::MapRouter* Router = new HTTP::MapRouter();
			Router->Listen(Protocol::Now().User.RPC.NodeAddress, ToString(Protocol::Now().User.RPC.NodePort)).Expect("listener binding error");
			Router->Post("/", std::bind(&ServerNode::Dispatch, this, std::placeholders::_1));
			Router->Base->Callbacks.Authorize = (AdminToken.empty() && UserToken.empty()) ? HTTP::AuthorizeCallback(nullptr) : std::bind(&ServerNode::Authorize, this, std::placeholders::_1, std::placeholders::_2);
			Router->Base->Auth.Type = "Basic";
			Router->Base->Auth.Realm = "Tangent RPC Node";
			Router->TemporaryDirectory.clear();
			Node->Configure(Router).Expect("configuration error");
			Node->Listen().Expect("listen queue error");
			if (Validator != nullptr)
				Validator->AddRef();

			VI_INFO("[rpc] rpc node listen (location: %s:%i)", Protocol::Now().User.RPC.NodeAddress.c_str(), (int)Protocol::Now().User.RPC.NodePort);
			Bind(AccessLevel::User, "utility", "encodeaddress", 1, 1, "(string hex_address) const", "encode hex address", std::bind(&ServerNode::UtilityEncodeAddress, this, std::placeholders::_1));
			Bind(AccessLevel::User, "utility", "decodeaddress", 1, 1, "(string address) const", "decode address", std::bind(&ServerNode::UtilityDecodeAddress, this, std::placeholders::_1));
			Bind(AccessLevel::User, "utility", "decodemessage", 1, 1, "(string message) const", "decode message", std::bind(&ServerNode::UtilityDecodeMessage, this, std::placeholders::_1));
			Bind(AccessLevel::User, "utility", "help", 0, 0, "() const", "get reference of all methods", std::bind(&ServerNode::UtilityHelp, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "chainstate", "prune", 2, 2, "(string types = 'statetrie' | 'blocktrie' | 'transactiontrie', uint64 number) const", "prune chainstate data using pruning level (types is '|' separated list)", std::bind(&ServerNode::ChainstatePrune, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "chainstate", "verify", 2, 3, "(uint64 number, uint64 count, bool? validate) const", "verify chain and possibly re-execute each block", std::bind(&ServerNode::ChainstateVerify, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "chainstate", "tracecall", 4, 32, "(string asset, string from_address, string to_address, string function, ...) const", "trace execution of mutable/immutable function of program assigned to to_address", std::bind(&ServerNode::ChainstateTraceCall, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "immutablecall", 4, 32, "(string asset, string from_address, string to_address, string function, ...) const", "execute of immutable function of program assigned to to_address", std::bind(&ServerNode::ChainstateImmutableCall, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocks", 2, 2, "(uint64 number, uint64 count) const", "get block hashes", std::bind(&ServerNode::ChainstateGetBlocks, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockcheckpointhash", 0, 0, "() const", "get block checkpoint hash", std::bind(&ServerNode::ChainstateGetBlockCheckpointHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockcheckpointnumber", 0, 0, "() const", "get block checkpoint number", std::bind(&ServerNode::ChainstateGetBlockCheckpointNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocktiphash", 0, 0, "() const", "get block tip hash", std::bind(&ServerNode::ChainstateGetBlockTipHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocktipnumber", 0, 0, "() const", "get block tip number", std::bind(&ServerNode::ChainstateGetBlockTipNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get block by hash", std::bind(&ServerNode::ChainstateGetBlockByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockbynumber", 1, 2, "(uint64 number, uint8? unrolling = 0) const", "get block by number", std::bind(&ServerNode::ChainstateGetBlockByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getrawblockbyhash", 1, 1, "(uint256 hash) const", "get block by hash", std::bind(&ServerNode::ChainstateGetRawBlockByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getrawblockbynumber", 1, 1, "(uint64 number) const", "get block by number", std::bind(&ServerNode::ChainstateGetRawBlockByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocktransactionsbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockTransactionsByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocktransactionsbynumber", 1, 2, "(uint64 number, uint8? unrolling = 0) const", "get block transactions by number", std::bind(&ServerNode::ChainstateGetBlockTransactionsByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockreceiptsbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockReceiptsByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockreceiptsbynumber", 1, 2, "(uint64 number, uint8? unrolling = 0) const", "get block transactions by number", std::bind(&ServerNode::ChainstateGetBlockReceiptsByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockstatesbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get block states by hash", std::bind(&ServerNode::ChainstateGetBlockStatesByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockstatesbynumber", 1, 2, "(uint64 number, uint8? unrolling = 0) const", "get block states by number", std::bind(&ServerNode::ChainstateGetBlockStatesByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockproofbyhash", 1, 4, "(uint256 hash, bool? transactions, bool? receipts, bool? states) const", "get block proof by hash", std::bind(&ServerNode::ChainstateGetBlockProofByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockproofbynumber", 1, 4, "(uint64 number, bool? transactions, bool? receipts, bool? states) const", "get block proof by number", std::bind(&ServerNode::ChainstateGetBlockProofByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblocknumberbyhash", 1, 1, "(uint256 hash) const", "get block number by hash", std::bind(&ServerNode::ChainstateGetBlockNumberByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockhashbynumber", 1, 1, "(uint64 number) const", "get block hash by number", std::bind(&ServerNode::ChainstateGetBlockHashByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockgaspricebyhash", 2, 3, "(uint256 hash, string asset, double? percentile = 0.5) const", "get gas price from percentile of block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockGasPriceByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockgaspricebynumber", 2, 3, "(uint64 number, string asset, double? percentile = 0.5) const", "get gas price from percentile of block transactions by number", std::bind(&ServerNode::ChainstateGetBlockGasPriceByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockassetpricebyhash", 3, 4, "(uint256 hash, string asset_from, string asset_to, double? percentile = 0.5) const", "get gas asset from percentile of block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockAssetPriceByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getblockassetpricebynumber", 3, 4, "(uint64 number, string asset_from, string asset_to, double? percentile = 0.5) const", "get gas asset from percentile of block transactions by number", std::bind(&ServerNode::ChainstateGetBlockAssetPriceByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getpendingtransactionsbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockTransactionsByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getpendingtransactionsbynumber", 1, 2, "(uint64 number, uint8? unrolling = 0) const", "get block transactions by number", std::bind(&ServerNode::ChainstateGetBlockTransactionsByNumber, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "gettransactionsbyowner", 3, 4, "(string owner_address, uint64 offset, uint64 count, uint8? unrolling = 0) const", "get transactions by owner", std::bind(&ServerNode::ChainstateGetTransactionsByOwner, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "gettransactionbyhash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get transaction by hash", std::bind(&ServerNode::ChainstateGetTransactionByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "gettransactionbyreceipthash", 1, 2, "(uint256 hash, uint8? unrolling = 0) const", "get transaction by receipt hash", std::bind(&ServerNode::ChainstateGetTransactionByReceiptHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getrawtransactionbyhash", 1, 1, "(uint256 hash) const", "get raw transaction by hash", std::bind(&ServerNode::ChainstateGetRawTransactionByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getrawtransactionbyreceipthash", 1, 1, "(uint256 hash) const", "get raw transaction by receipt hash", std::bind(&ServerNode::ChainstateGetRawTransactionByReceiptHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getreceiptbyhash", 1, 1, "(uint256 hash) const", "get receipt by hash", std::bind(&ServerNode::ChainstateGetReceiptByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getreceiptbytransactionhash", 1, 1, "(uint256 hash) const", "get receipt by transaction hash", std::bind(&ServerNode::ChainstateGetReceiptByTransactionHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatebycomposition", 3, 3, "(string type, any address, any stride) const", "get state by type, address and stride", std::bind(&ServerNode::ChainstateGetStateByComposition, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatebyaddress", 2, 3, "(string type, any address, uint64? offset) const", "get state by type and address", std::bind(&ServerNode::ChainstateGetStateByAddress, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatesbyaddress", 4, 4, "(string type, any address, uint64 offset, uint64 count) const", "get filtered state by type and address", std::bind(&ServerNode::ChainstateGetStatesByAddress, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatebystride", 2, 3, "(string type, any stride, uint64? offset) const", "get state by type and stride", std::bind(&ServerNode::ChainstateGetStateByStride, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatebystridequery", 7, 7, "(string type, any stride, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value, int8 weight_order, uint64 offset, uint64 count) const", "get filtered state by type stride", std::bind(&ServerNode::ChainstateGetStatesByStride, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getstatescountbystride", 4, 4, "(string type, any stride, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value) const", "get filtered state count by type and stride", std::bind(&ServerNode::ChainstateGetStatesCountByStride, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountsequence", 1, 1, "(string address) const", "get account sequence by address", std::bind(&ServerNode::ChainstateGetAccountSequence, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountwork", 1, 1, "(string address) const", "get account work by address", std::bind(&ServerNode::ChainstateGetAccountWork, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getbestaccountworkers", 3, 3, "(uint64 commitment, uint64 offset, uint64 count) const", "get best block proposers (zero commitment = offline proposers, non-zero commitment = online proposers threshold)", std::bind(&ServerNode::ChainstateGetBestAccountWorkers, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountprogram", 1, 1, "(string address) const", "get account program hashcode by address", std::bind(&ServerNode::ChainstateGetAccountProgram, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountstorage", 2, 2, "(string address, string location) const", "get account storage by address and location", std::bind(&ServerNode::ChainstateGetAccountStorage, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountreward", 2, 2, "(string address, string asset) const", "get account reward by address and asset", std::bind(&ServerNode::ChainstateGetAccountReward, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountrewards", 3, 3, "(string address, uint64 offset, uint64 count) const", "get account rewards by address", std::bind(&ServerNode::ChainstateGetAccountRewards, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getbestaccountrewards", 3, 3, "(string asset, uint64 offset, uint64 count) const", "get accounts with best rewards", std::bind(&ServerNode::ChainstateGetBestAccountRewards, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountderivation", 2, 2, "(string address, string asset) const", "get account derivation by address and asset", std::bind(&ServerNode::ChainstateGetAccountDerivation, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountderivations", 3, 3, "(string address, uint64 offset, uint64 count) const", "get account derivations by address", std::bind(&ServerNode::ChainstateGetAccountDerivations, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountbalance", 2, 2, "(string address, string asset) const", "get account balance by address and asset", std::bind(&ServerNode::ChainstateGetAccountBalance, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountbalances", 3, 3, "(string address, uint64 offset, uint64 count) const", "get account balances by address", std::bind(&ServerNode::ChainstateGetAccountBalances, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountcontribution", 2, 2, "(string address, string asset) const", "get account contribution by address and asset", std::bind(&ServerNode::ChainstateGetAccountContribution, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getaccountcontributions", 3, 3, "(string address, uint64 offset, uint64 count) const", "get account contributions by address", std::bind(&ServerNode::ChainstateGetAccountContributions, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getbestaccountcontributions", 3, 3, "(string asset, uint64 offset, uint64 count) const", "get accounts with best contribution", std::bind(&ServerNode::ChainstateGetBestAccountContributions, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getwitnessprogram", 1, 1, "(string hashcode) const", "get witness program by hashcode (512bit number)", std::bind(&ServerNode::ChainstateGetWitnessProgram, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getwitnessevent", 1, 1, "(uint256 transaction_hash) const", "get witness event by transaction hash", std::bind(&ServerNode::ChainstateGetWitnessEvent, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getwitnessaddress", 3, 4, "(string address, string asset, string wallet_address, uint64? derivation_index) const", "get witness address by owner address, asset, wallet address and derivation index", std::bind(&ServerNode::ChainstateGetWitnessAddress, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getwitnessaddresses", 3, 3, "(string address, uint64 offset, uint64 count) const", "get witness addresses by owner address", std::bind(&ServerNode::ChainstateGetWitnessAddresses, this, std::placeholders::_1));
			Bind(AccessLevel::User, "chainstate", "getwitnesstransaction", 2, 2, "(string asset, string transaction_id) const", "get witness transaction by asset and transaction id", std::bind(&ServerNode::ChainstateGetWitnessTransaction, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "mempoolstate", "addnode", 1, 1, "(string ip_address)", "add node ip address to seeds", std::bind(&ServerNode::MempoolAddNode, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "mempoolstate", "clearnode", 1, 1, "(string ip_address)", "remove associated node info by ip address", std::bind(&ServerNode::MempoolClearNode, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getclosestnode", 0, 1, "(uint64? offset) const", "get closest node info", std::bind(&ServerNode::MempoolGetClosestNode, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getclosestnodecount", 0, 0, "() const", "get closest node count", std::bind(&ServerNode::MempoolGetClosestNodeCounter, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getnode", 1, 1, "(string ip_address) const", "get associated node info by ip address", std::bind(&ServerNode::MempoolGetNode, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getseeds", 1, 1, "(uint64 count) const", "get node ip addresses", std::bind(&ServerNode::MempoolGetSeeds, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getgasprice", 1, 2, "(string asset, double? percentile = 0.5) const", "get gas price from percentile of pending transactions", std::bind(&ServerNode::MempoolGetGasPrice, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getassetprice", 2, 3, "(string asset_from, string asset_to, double? percentile = 0.5) const", "get gas asset from percentile of pending transactions", std::bind(&ServerNode::MempoolGetAssetPrice, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "mempoolstate", "getoptimaltransactiongas", 1, 1, "(string hex_message)", "execute transaction with block gas limit and return ceil of spent gas", std::bind(&ServerNode::MempoolGetOptimalTransactionGas, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "mempoolstate", "getestimatetransactiongas", 1, 1, "(string hex_message)", "get rough estimate of required gas limit than could be considerably lower or higher than actual required gas limit", std::bind(&ServerNode::MempoolGetEstimateTransactionGas, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "accepttransaction", 1, 2, "(string hex_message, bool? validate)", "try to accept and relay a mempool transaction from raw data and possibly validate over latest chainstate", std::bind(&ServerNode::MempoolAcceptTransaction, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "mempoolstate", "rejecttransaction", 1, 1, "(uint256 hash)", "remove mempool transaction by hash", std::bind(&ServerNode::MempoolRejectTransaction, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getmempooltransactionbyhash", 1, 1, "(uint256 hash) const", "get mempool transaction by hash", std::bind(&ServerNode::MempoolGetTransactionByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getrawmempooltransactionbyhash", 1, 1, "(uint256 hash) const", "get raw mempool transaction by hash", std::bind(&ServerNode::MempoolGetRawTransactionByHash, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getmempooltransactionsequence", 1, 1, "(string owner_address) const", "get mempool transaction sequence by owner", std::bind(&ServerNode::MempoolGetTransactionSequence, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getmempooltransactions", 2, 3, "(uint64 offset, uint64 count, uint8? unrolling) const", "get mempool transactions", std::bind(&ServerNode::MempoolGetTransactions, this, std::placeholders::_1));
			Bind(AccessLevel::User, "mempoolstate", "getcumulativemempooltransactions", 3, 4, "(uint256 hash, uint64 offset, uint64 count, uint8? unrolling) const", "get cumulative mempool transactions", std::bind(&ServerNode::MempoolGetCumulativeEventTransactions, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "validatorstate", "acceptnode", 0, 1, "(string? ip_address)", "try to accept and connect to a node possibly by ip address", std::bind(&ServerNode::ValidatorAcceptNode, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "validatorstate", "rejectnode", 1, 1, "(string ip_address)", "reject and disconnect from a node by ip address", std::bind(&ServerNode::ValidatorRejectNode, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "validatorstate", "getnode", 1, 1, "(string ip_address) const", "get a node by ip address", std::bind(&ServerNode::ValidatorGetNode, this, std::placeholders::_1));
			Bind(AccessLevel::Admin, "validatorstate", "status", 0, 0, "() const", "get validator status", std::bind(&ServerNode::ValidatorStatus, this, std::placeholders::_1));
		}
		void ServerNode::Shutdown()
		{
			if (!IsActive())
				return;

			VI_INFO("[rpc] rpc node shutdown requested");
			Node->Unlisten(false);
		}
		void ServerNode::Bind(AccessLevel Level, const std::string_view& Domain, const std::string_view& Method, size_t MinParams, size_t MaxParams, const std::string_view& Args, const std::string_view& Description, ServerFunction&& Function)
		{
			ServerRequest Item;
			Item.Level = Level;
			Item.MinParams = MinParams;
			Item.MaxParams = MaxParams;
			Item.Domain = Domain;
			Item.Args = Args;
			Item.Description = Description;
			Item.Function = std::move(Function);
			Methods[String(Method)] = std::move(Item);
		}
		bool ServerNode::HasAdminAuthorization()
		{
			return !Protocol::Now().User.RPC.AdminUsername.empty() || !Protocol::Now().User.RPC.AdminPassword.empty();
		}
		bool ServerNode::HasUserAuthorization()
		{
			return !Protocol::Now().User.RPC.UserUsername.empty() || !Protocol::Now().User.RPC.UserPassword.empty();
		}
		bool ServerNode::IsActive()
		{
			return Node->GetState() == ServerState::Working;
		}
		bool ServerNode::Authorize(HTTP::Connection* Base, HTTP::Credentials* Credentials)
		{
			if (HasAdminAuthorization() && Credentials->Token == AdminToken)
				return true;

			if (HasUserAuthorization() && Credentials->Token == UserToken)
				return true;

			return false;
		}
        bool ServerNode::Dispatch(HTTP::Connection* Base)
        {
			Base->Response.SetHeader("Content-Type", "application/json");
			return Base->Fetch([this](HTTP::Connection* Base, SocketPoll Event, const std::string_view&) -> bool
			{
				if (!Packet::IsDone(Event))
					return true;

				auto Data = Base->Request.Content.GetJSON();
				if (!Data)
				{
					Base->Response.Content.Assign(Schema::ToJSON(*ServerResponse().Error(ErrorCodes::BadRequest, Data.Error().message()).Transform(nullptr)));
					return Base->Next(200);
				}

				auto* Requests = *Data;
				if (!Requests->Value.Is(VarType::Array))
				{
					Requests = Var::Set::Array();
					Requests->Push(*Data);
				}

				Coasync<void>([this, Base, Requests]() -> Promise<void>
				{
					UPtr<Schema> Responses = nullptr;
					auto Reply = [&](Schema* Request, ServerResponse&& Response)
					{
						auto Next = Response.Transform(Request);
						if (Responses)
						{
							if (!Responses->Value.Is(VarType::Array))
							{
								auto* Prev = Responses.Reset();
								Responses = Var::Set::Array();
								Responses->Push(Prev);
								Responses->Push(Next.Reset());
							}
							else
								Responses->Push(Next.Reset());
						}
						else
							Responses = std::move(Next);
					};
					for (auto& Request : Requests->GetChilds())
					{
						auto* Version = Request->Get("jsonrpc");
						if (!Version || Version->Value.GetInteger() != 2)
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadVersion, "only version 2.0 is supported"));
							continue;
						}

						auto* Method = Request->Get("method");
						if (!Method || !Method->Value.Is(VarType::String))
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "method is not a string"));
							continue;
						}

						auto Context = Methods.find(Method->Value.GetBlob());
						if (Context == Methods.end())
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "method \"" + Method->Value.GetBlob() + "\" not found"));
							continue;
						}
						
						if (HasAdminAuthorization() && Context->second.Level == AccessLevel::Admin && Base->Request.User.Token != AdminToken)
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "admin level access required"));
							continue;
						}
						else if (HasUserAuthorization() && Context->second.Level == AccessLevel::User && Base->Request.User.Token != UserToken && Base->Request.User.Token != AdminToken)
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "user level access required"));
							continue;
						}

						auto* Params = Request->Get("params");
						if (!Params || !Params->Value.Is(VarType::Array))
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "params is not an array"));
							continue;
						}

						if (Params->Size() < Context->second.MinParams || Params->Size() > Context->second.MaxParams)
						{
							Reply(Request, ServerResponse().Error(ErrorCodes::BadMethod, "params is not an array[" + ToString(Context->second.MinParams) + ".." + ToString(Context->second.MinParams) + "]"));
							continue;
						}

						Format::Variables Args;
						Args.reserve(Params->Size());
						for (auto& Param : Params->GetChilds())
						{
							switch (Param->Value.GetType())
							{
								case VarType::Object:
								case VarType::Array:
									Args.push_back(Format::Variable(Param));
									break;
								case VarType::String:
								case VarType::Binary:
									Args.push_back(Format::Variable(Param->Value.GetBlob()));
									break;
								case VarType::Integer:
								{
									int64_t Value = Param->Value.GetInteger();
									if (Value >= 0)
										Args.push_back(Format::Variable((uint64_t)Value));
									else
										Args.push_back(Format::Variable(Decimal(Value)));
									break;
								}
								case VarType::Number:
									Args.push_back(Format::Variable(Decimal(Param->Value.GetNumber())));
									break;
								case VarType::Decimal:
									Args.push_back(Format::Variable(Param->Value.GetDecimal()));
								case VarType::Boolean:
									Args.push_back(Format::Variable(Param->Value.GetBoolean()));
									break;
								case VarType::Null:
								case VarType::Undefined:
								case VarType::Pointer:
								default:
									Args.push_back(Format::Variable((Schema*)nullptr));
									break;
							}
						}

						auto Response = Coawait(Context->second.Function(std::move(Args)));
						Reply(Request, std::move(Response));
					}
					if (!Responses)
						Base->Response.Content.Assign(Schema::ToJSON(*ServerResponse().Error(ErrorCodes::BadRequest, "request is empty").Transform(nullptr)));
					else
						Base->Response.Content.Assign(Schema::ToJSON(*Responses));
					Base->Next(200);
				});
				return true;
			});
        }
		ServiceControl::ServiceNode ServerNode::GetEntrypoint()
		{
			if (!Protocol::Now().User.RPC.Server)
				return ServiceControl::ServiceNode();

			ServiceControl::ServiceNode Entrypoint;
			Entrypoint.Startup = std::bind(&ServerNode::Startup, this);
			Entrypoint.Shutdown = std::bind(&ServerNode::Shutdown, this);
			return Entrypoint;
		}
		Promise<ServerResponse> ServerNode::UtilityEncodeAddress(Format::Variables&& Args)
		{
			auto Owner = Format::Util::Decode0xHex(Args[0].AsString());
			if (Owner.size() != sizeof(Algorithm::Pubkeyhash))
				return ServerResponse().Error(ErrorCodes::BadParams, "raw address not valid");

			String Address;
			Algorithm::Signing::EncodeAddress((uint8_t*)Owner.data(), Address);
			return ServerResponse().Success(Var::Set::String(Address));
		}
		Promise<ServerResponse> ServerNode::UtilityDecodeAddress(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			return ServerResponse().Success(Var::Set::String(Format::Util::Encode0xHex(std::string_view((char*)Owner, sizeof(Owner)))));
		}
		Promise<ServerResponse> ServerNode::UtilityDecodeMessage(Format::Variables&& Args)
		{
			Format::Variables Values;
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			if (!Format::VariablesUtil::DeserializeFlatFrom(Message, &Values))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			return ServerResponse().Success(Format::VariablesUtil::Serialize(Values));
		}
		Promise<ServerResponse> ServerNode::UtilityHelp(Format::Variables&& Args)
		{
			UPtr<Schema> Data = Var::Set::Object();
			for (auto& Method : Methods)
			{
				String Inline;
				switch (Method.second.Level)
				{
					case AccessLevel::User:
						Inline += "user.";
						break;
					case AccessLevel::Admin:
						Inline += "admin.";
						break;
					default:
						break;
				}
				Inline += Method.second.Domain + ".";
				Inline += Method.first;
				Inline += Method.second.Args;

				auto* Description = Data->Set(Method.first, Var::Set::Array());
				Description->Push(Var::String(Inline));
				Description->Push(Var::String(Method.second.Description));
			}
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstatePrune(Format::Variables&& Args)
		{
			uint32_t Types = 0;
			for (auto& Subtype : Stringify::Split(Args[0].AsString(), '|'))
			{
				if (Subtype == "blocktrie")
					Types |= (uint32_t)Storages::Pruning::Blocktrie;
				else if (Subtype == "transactiontrie")
					Types |= (uint32_t)Storages::Pruning::Transactiontrie;
				else if (Subtype == "statetrie")
					Types |= (uint32_t)Storages::Pruning::Statetrie;
			}
			
			if (Types == 0)
				return ServerResponse().Error(ErrorCodes::NotFound, "invalid type");

			uint64_t Number = Args[1].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto Status = Chain.Prune(Types, Number);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::NotFound, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateVerify(Format::Variables&& Args)
		{
			uint64_t Count = Args[1].AsUint64();
			uint64_t CurrentNumber = Args[0].AsUint64();
			uint64_t TargetNumber = CurrentNumber + Count;
			bool Validate = Args.size() > 2 ? Args[2].AsBoolean() : false;
			auto Chain = Storages::Chainstate(__func__);
			auto CheckpointNumber = Chain.GetCheckpointBlockNumber().Or(0);
			auto ParentBlock = CurrentNumber > 1 ? Chain.GetBlockHeaderByNumber(CurrentNumber - 1) : ExpectsLR<Ledger::BlockHeader>(LayerException());
			UPtr<Schema> Data = Var::Set::Array();
			while (CurrentNumber < TargetNumber)
			{
				auto Next = Chain.GetBlockByNumber(CurrentNumber);
				if (!Next)
					return ServerResponse().Error(ErrorCodes::NotFound, "block " + ToString(CurrentNumber) + (CheckpointNumber >= CurrentNumber ? " verification failed: block data pruned" : " verification failed: block not found"));

				if (CurrentNumber > 1 && CheckpointNumber >= CurrentNumber - 1 && !ParentBlock)
					return ServerResponse().Error(ErrorCodes::NotFound, "block " + ToString(CurrentNumber - 1) + " verification failed: parent block data pruned");

				if (Validate)
				{
					auto Validation = Next->Validate(ParentBlock.Address());
					if (!Validation)
						return ServerResponse().Error(ErrorCodes::NotFound, "block " + ToString(CurrentNumber) + " validation failed: " + Validation.Error().Info);
				}
				else
				{
					auto Verification = Next->Verify(ParentBlock.Address());
					if (!Verification)
						return ServerResponse().Error(ErrorCodes::NotFound, "block " + ToString(CurrentNumber) + " verification failed: " + Verification.Error().Info);
				}

				Data->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Next->AsHash())));
				ParentBlock = *Next;
				++CurrentNumber;
			}
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateCall(Format::Variables&& Args, bool Tracing)
		{
			Algorithm::Pubkeyhash From;
			if (!Algorithm::Signing::DecodeAddress(Args[1].AsString(), From))
				return ServerResponse().Error(ErrorCodes::BadParams, "from account address not valid");

			Algorithm::Pubkeyhash To;
			if (!Algorithm::Signing::DecodeAddress(Args[2].AsString(), To))
				return ServerResponse().Error(ErrorCodes::BadParams, "to account address not valid");

			Format::Variables Values;
			Values.reserve(Args.size() - 4);
			for (size_t i = 4; i < Args.size(); i++)
				Values.push_back(Args[i]);

			Transactions::Invocation Transaction;
			Transaction.Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			Transaction.Signature[0] = 0xFF;
			Transaction.SetCalldata(To, Args[3].AsString(), std::move(Values));
			Transaction.SetGas(Decimal::Zero(), Ledger::Block::GetGasLimit());

			auto Context = Ledger::TransactionContext();
			auto Sequence = Context.GetAccountSequence(From);
			Transaction.Sequence = Sequence ? Sequence->Sequence : 1;

			auto Script = Ledger::ScriptProgramTrace(&Transaction, From, Tracing);
			auto Execution = Script.TraceCall(Transaction.Function, Transaction.Args, Tracing ? -1 : 0);
			if (!Execution)
				return ServerResponse().Error(ErrorCodes::BadParams, Execution.Error().Info);

			return ServerResponse().Success(Script.AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateImmutableCall(Format::Variables&& Args)
		{
			return ChainstateCall(std::move(Args), false);
		}
		Promise<ServerResponse> ServerNode::ChainstateTraceCall(Format::Variables&& Args)
		{
			return ChainstateCall(std::move(Args), true);
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlocks(Format::Variables&& Args)
		{
			uint64_t Count = Args[1].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto Hashes = Chain.GetBlockHashset(Number, Count);
			if (!Hashes)
				return ServerResponse().Error(ErrorCodes::NotFound, "blocks not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *Hashes)
				Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockCheckpointHash(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetCheckpointBlockNumber();
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "checkpoint block not found");

			auto BlockHash = Chain.GetBlockHashByNumber(*BlockNumber);
			if (!BlockHash)
				return ServerResponse().Error(ErrorCodes::NotFound, "checkpoint block not found");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(*BlockHash)));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockCheckpointNumber(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetCheckpointBlockNumber();
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "checkpoint block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockTipHash(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockHeader = Chain.GetLatestBlockHeader();
			if (!BlockHeader)
				return ServerResponse().Error(ErrorCodes::NotFound, "tip block not found");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(BlockHeader->AsHash())));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockTipNumber(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetLatestBlockNumber();
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "tip block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto BlockHeader = Chain.GetBlockHeaderByHash(Hash);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				return ServerResponse().Success(BlockHeader->AsSchema());
			}
			else if (Unrolling == 1)
			{
				auto BlockHeader = Chain.GetBlockHeaderByHash(Hash);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				auto TransactionHashset = Chain.GetBlockTransactionHashset(BlockHeader->Number);
				if (TransactionHashset)
				{
					for (auto& Item : *TransactionHashset)
						Transactions->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				}

				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 2)
			{
				auto BlockHeader = Chain.GetBlockHeaderByHash(Hash);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				while (true)
				{
					auto List = Chain.GetTransactionsByNumber(BlockHeader->Number, Transactions->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Transactions->Push(Item->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 3)
			{
				auto BlockHeader = Chain.GetBlockHeaderByHash(Hash);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				while (true)
				{
					auto List = Chain.GetBlockTransactionsByNumber(BlockHeader->Number, Transactions->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Transactions->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				auto Block = Chain.GetBlockByHash(Hash);
				if (!Block)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				return ServerResponse().Success(Block->AsSchema());
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto BlockHeader = Chain.GetBlockHeaderByNumber(Number);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				return ServerResponse().Success(BlockHeader->AsSchema());
			}
			else if (Unrolling == 1)
			{
				auto BlockHeader = Chain.GetBlockHeaderByNumber(Number);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				auto TransactionHashset = Chain.GetBlockTransactionHashset(BlockHeader->Number);
				if (TransactionHashset)
				{
					for (auto& Item : *TransactionHashset)
						Transactions->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				}

				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 2)
			{
				auto BlockHeader = Chain.GetBlockHeaderByNumber(Number);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				while (true)
				{
					auto List = Chain.GetTransactionsByNumber(BlockHeader->Number, Transactions->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Transactions->Push(Item->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 3)
			{
				auto BlockHeader = Chain.GetBlockHeaderByNumber(Number);
				if (!BlockHeader)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Data = BlockHeader->AsSchema();
				auto* Transactions = Data->Set("transactions", Var::Set::Array());
				while (true)
				{
					auto List = Chain.GetBlockTransactionsByNumber(BlockHeader->Number, Transactions->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Transactions->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				auto Block = Chain.GetBlockByNumber(Number);
				if (!Block)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				return ServerResponse().Success(Block->AsSchema());
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetRawBlockByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Block = Chain.GetBlockByHash(Hash);
			if (!Block)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Block->AsMessage().Encode()));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetRawBlockByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto Block = Chain.GetBlockByNumber(Number);
			if (!Block)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Block->AsMessage().Encode()));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockTransactionsByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
				if (!BlockNumber)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Hashes = Chain.GetBlockTransactionHashset(*BlockNumber);
				if (!Hashes)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *Hashes)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 1)
			{
				auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
				if (!BlockNumber)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetTransactionsByNumber(*BlockNumber, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
				if (!BlockNumber)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockTransactionsByNumber(*BlockNumber, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockTransactionsByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto Hashes = Chain.GetBlockTransactionHashset(Number);
				if (!Hashes)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *Hashes)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 1)
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetTransactionsByNumber(Number, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockTransactionsByNumber(Number, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockReceiptsByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockReceiptsByNumber(*BlockNumber, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item.AsHash())));
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockReceiptsByNumber(*BlockNumber, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockReceiptsByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockReceiptsByNumber(Number, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item.AsHash())));
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockReceiptsByNumber(Number, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockStatesByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
				if (!BlockNumber)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				auto Hashes = Chain.GetBlockTransactionHashset(*BlockNumber);
				if (!Hashes)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *Hashes)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
				if (!BlockNumber)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockStatetrieByNumber(*BlockNumber, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.second->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockStatesByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto Hashes = Chain.GetBlockTransactionHashset(Number);
				if (!Hashes)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *Hashes)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				while (true)
				{
					auto List = Chain.GetBlockStatetrieByNumber(Number, Data->Size(), Protocol::Now().User.RPC.CursorSize);
					if (!List)
						return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

					for (auto& Item : *List)
						Data->Push(Item.second->AsSchema().Reset());
					if (List->size() < Protocol::Now().User.RPC.CursorSize)
						break;
				}

				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockProofByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockProof = Chain.GetBlockProofByHash(Hash);
			if (!BlockProof)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			bool Transactions = Args[1].AsBoolean();
			bool Receipts = Args[2].AsBoolean();
			bool States = Args[3].AsBoolean();
			if (Transactions)
				BlockProof->GetTransactionsTree();
			if (Receipts)
				BlockProof->GetReceiptsTree();
			if (States)
				BlockProof->GetStatesTree();

			auto Data = BlockProof->AsSchema();
			if (!Transactions)
				Data->Pop("transactions");
			if (!Receipts)
				Data->Pop("receipts");
			if (!States)
				Data->Pop("states");

			if (Data->Size() == 1)
			{
				UPtr<Schema> Root = std::move(Data);
				Data = Root->Get(0);
				Data->Unlink();
			}

			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockProofByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockProof = Chain.GetBlockProofByNumber(Number);
			if (!BlockProof)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			bool Transactions = Args[1].AsBoolean();
			bool Receipts = Args[2].AsBoolean();
			bool States = Args[3].AsBoolean();
			if (Transactions)
				BlockProof->GetTransactionsTree();
			if (Receipts)
				BlockProof->GetReceiptsTree();
			if (States)
				BlockProof->GetStatesTree();

			auto Data = BlockProof->AsSchema();
			if (!Transactions)
				Data->Pop("transactions");
			if (!Receipts)
				Data->Pop("receipts");
			if (!States)
				Data->Pop("states");

			if (Data->Size() == 1)
			{
				UPtr<Schema> Root = std::move(Data);
				Data = Root->Get(0);
				Data->Unlink();
			}

			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockNumberByHash(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockHash = Chain.GetBlockHashByNumber(Number);
			if (!BlockHash)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(*BlockHash)));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockHashByNumber(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockGasPriceByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			Algorithm::AssetId Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			double Percentile = Args.size() > 2 ? Args[2].AsDouble() : 0.50;
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			auto Price = Chain.GetBlockGasPrice(*BlockNumber, Asset, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "gas price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockGasPriceByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			Algorithm::AssetId Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			double Percentile = Args.size() > 2 ? Args[2].AsDouble() : 0.50;
			auto Chain = Storages::Chainstate(__func__);
			auto Price = Chain.GetBlockGasPrice(Number, Asset, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "gas price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockAssetPriceByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			Algorithm::AssetId Asset1 = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			Algorithm::AssetId Asset2 = Algorithm::Asset::IdOfHandle(Args[2].AsString());
			double Percentile = Args.size() > 3 ? Args[3].AsDouble() : 0.50;
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			auto Price = Chain.GetBlockAssetPrice(*BlockNumber, Asset1, Asset2, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "asset price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBlockAssetPriceByNumber(Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			Algorithm::AssetId Asset1 = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			Algorithm::AssetId Asset2 = Algorithm::Asset::IdOfHandle(Args[2].AsString());
			double Percentile = Args.size() > 3 ? Args[3].AsDouble() : 0.50;
			auto Chain = Storages::Chainstate(__func__);
			auto Price = Chain.GetBlockAssetPrice(Number, Asset1, Asset2, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "asset price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetPendingTransactions(Format::Variables&& Args)
		{
			uint64_t Offset = Args[0].AsUint64(), Count = Args[1].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Unrolling = Args.size() > 2 ? Args[2].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto List = Chain.GetPendingBlockTransactions(std::numeric_limits<int64_t>::max(), Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item.Receipt.TransactionHash)));
				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 1)
			{
				auto List = Chain.GetPendingBlockTransactions(std::numeric_limits<int64_t>::max(), Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *List)
					Data->Push(Item.Transaction->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				auto List = Chain.GetPendingBlockTransactions(std::numeric_limits<int64_t>::max(), Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

				UPtr<Schema> Data = Var::Set::Array();
				for (auto& Item : *List)
					Data->Push(Item.AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetTransactionsByOwner(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "owner address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Unrolling = Args.size() > 3 ? Args[3].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 1)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetBlockTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item.AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetTransactionByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto Transaction = Chain.GetTransactionByHash(Hash);
				if (!Transaction)
					return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

				return ServerResponse().Success((*Transaction)->AsSchema());
			}
			else
			{
				auto Transaction = Chain.GetBlockTransactionByHash(Hash);
				if (!Transaction)
					return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

				return ServerResponse().Success(Transaction->AsSchema());
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetTransactionByReceiptHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint8_t Unrolling = Args.size() > 1 ? Args[1].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				auto Transaction = Chain.GetTransactionByReceiptHash(Hash);
				if (!Transaction)
					return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

				return ServerResponse().Success((*Transaction)->AsSchema());
			}
			else
			{
				auto Transaction = Chain.GetBlockTransactionByReceiptHash(Hash);
				if (!Transaction)
					return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

				return ServerResponse().Success(Transaction->AsSchema());
			}
		}
		Promise<ServerResponse> ServerNode::ChainstateGetRawTransactionByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Transaction = Chain.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success(Var::Set::String((*Transaction)->AsMessage().Encode()));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetRawTransactionByReceiptHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Transaction = Chain.GetTransactionByReceiptHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success(Var::Set::String((*Transaction)->AsMessage().Encode()));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetReceiptByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Receipt = Chain.GetReceiptByHash(Hash);
			if (!Receipt)
				return ServerResponse().Error(ErrorCodes::NotFound, "receipt not found");

			return ServerResponse().Success(Receipt->AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetReceiptByTransactionHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Receipt = Chain.GetReceiptByTransactionHash(Hash);
			if (!Receipt)
				return ServerResponse().Error(ErrorCodes::NotFound, "receipt not found");

			return ServerResponse().Success(Receipt->AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStateByComposition(Format::Variables&& Args)
		{
			auto Address = AsAddress(Args[0].AsString(), Args[1]);
			if (!Address)
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid: " + Address.Error().Info);

			auto Stride = AsStride(Args[0].AsString(), Args[2]);
			if (!Stride)
				return ServerResponse().Error(ErrorCodes::BadParams, "stride not valid: " + Stride.Error().Info);

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, *Address, *Stride, 0);
			if (!State)
				return ServerResponse().Error(ErrorCodes::NotFound, "state not found");

			return ServerResponse().Success((*State)->AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStateByAddress(Format::Variables&& Args)
		{
			auto Address = AsAddress(Args[0].AsString(), Args[1]);
			if (!Address)
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid: " + Address.Error().Info);

			size_t Offset = Args.size() > 2 ? Args[2].AsUint64() : 0;
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByAddress(nullptr, *Address, 0, Offset);
			if (!State)
				return ServerResponse().Error(ErrorCodes::NotFound, "state not found");

			return ServerResponse().Success((*State)->AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStatesByAddress(Format::Variables&& Args)
		{
			auto Address = AsAddress(Args[0].AsString(), Args[1]);
			if (!Address)
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid: " + Address.Error().Info);

			uint64_t Offset = Args[2].AsUint64(), Count = Args[3].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, *Address, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "state not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStateByStride(Format::Variables&& Args)
		{
			auto Stride = AsStride(Args[0].AsString(), Args[1]);
			if (!Stride)
				return ServerResponse().Error(ErrorCodes::BadParams, "stride not valid: " + Stride.Error().Info);

			size_t Offset = Args.size() > 2 ? Args[2].AsUint64() : 0;
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByStride(nullptr, *Stride, 0, Offset);
			if (!State)
				return ServerResponse().Error(ErrorCodes::NotFound, "state not found");

			return ServerResponse().Success((*State)->AsSchema());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStatesByStride(Format::Variables&& Args)
		{
			auto Stride = AsStride(Args[0].AsString(), Args[1]);
			if (!Stride)
				return ServerResponse().Error(ErrorCodes::BadParams, "stride not valid: " + Stride.Error().Info);

			uint64_t Offset = Args[5].AsUint64(), Count = Args[6].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Weight = Storages::WeightQuery::From(Args[2].AsString(), Args[3].AsDecimal().ToInt64(), Args[4].AsDecimal().ToInt8());
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByStride(nullptr, *Stride, Weight, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "state not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetStatesCountByStride(Format::Variables&& Args)
		{
			auto Stride = AsStride(Args[0].AsString(), Args[1]);
			if (!Stride)
				return ServerResponse().Error(ErrorCodes::BadParams, "stride not valid: " + Stride.Error().Info);

			auto Weight = Storages::WeightQuery::From(Args[2].AsString(), Args[3].AsDecimal().ToInt64(), 0);
			auto Chain = Storages::Chainstate(__func__);
			auto Count = Chain.GetStatesCountByStride(*Stride, Weight, 0);
			if (!Count)
				return ServerResponse().Error(ErrorCodes::NotFound, "count not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*Count));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountSequence(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::AccountSequence::AsInstanceAddress(Owner), States::AccountSequence::AsInstanceStride(), 0);
			auto* Value = (States::AccountSequence*)(State ? **State : nullptr);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(Value ? Value->Sequence : 1));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountWork(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::AccountWork::AsInstanceAddress(Owner), States::AccountWork::AsInstanceStride(), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBestAccountWorkers(Format::Variables&& Args)
		{
			uint64_t Commitment = Args[0].AsUint64();
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Weight = Commitment > 0 ? Storages::WeightQuery::GreaterEqual(Commitment - 1, -1) : Storages::WeightQuery::Equal(-1, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByStride(nullptr, States::AccountWork::AsInstanceStride(), Weight, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountProgram(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::AccountProgram::AsInstanceAddress(Owner), States::AccountProgram::AsInstanceStride(), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountStorage(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::AccountStorage::AsInstanceAddress(Owner), States::AccountStorage::AsInstanceStride(Args[1].AsString()), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountReward(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetStateByComposition(nullptr, States::AccountReward::AsInstanceAddress(Owner), States::AccountReward::AsInstanceStride(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountRewards(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, States::AccountReward::AsInstanceAddress(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBestAccountRewards(Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Weight = Storages::WeightQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByStride(nullptr, States::AccountReward::AsInstanceStride(Asset), Weight, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountDerivation(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetStateByComposition(nullptr, States::AccountDerivation::AsInstanceAddress(Owner), States::AccountDerivation::AsInstanceStride(Asset), 0);
			auto* Value = (States::AccountDerivation*)(State ? **State : nullptr);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(Value ? Value->MaxAddressIndex : Protocol::Now().Account.RootAddressIndex));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountDerivations(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, States::AccountDerivation::AsInstanceAddress(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountBalance(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetStateByComposition(nullptr, States::AccountBalance::AsInstanceAddress(Owner), States::AccountBalance::AsInstanceStride(Asset), 0);
			auto* Value = (States::AccountBalance*)(State ? **State : nullptr);
			UPtr<Schema> Data = Var::Set::Object();
			Data->Set("supply", Value ? Var::Decimal(Value->Supply) : Var::Integer(0));
			Data->Set("reserve", Value ? Var::Decimal(Value->Reserve) : Var::Integer(0));
			Data->Set("balance", Value ? Var::Decimal(Value->GetBalance()) : Var::Integer(0));
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountBalances(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, States::AccountBalance::AsInstanceAddress(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountContribution(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetStateByComposition(nullptr, States::AccountContribution::AsInstanceAddress(Owner), States::AccountContribution::AsInstanceStride(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetAccountContributions(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, States::AccountContribution::AsInstanceAddress(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetBestAccountContributions(Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Weight = Storages::WeightQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByStride(nullptr, States::AccountContribution::AsInstanceStride(Asset), Weight, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetWitnessProgram(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::WitnessProgram::AsInstanceAddress(Args[0].AsString()), States::WitnessProgram::AsInstanceStride(), 0);
			if (!State)
				return ServerResponse().Success(Var::Set::Null());

			auto Code = ((States::WitnessProgram*)(**State))->AsCode();
			auto* Data = (*State)->AsSchema().Reset();
			Data->Set("storage", Code ? Var::String(*Code) : Var::Null());
			return ServerResponse().Success(Data);
		}
		Promise<ServerResponse> ServerNode::ChainstateGetWitnessEvent(Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::WitnessEvent::AsInstanceAddress(Args[0].AsUint256()), States::WitnessEvent::AsInstanceStride(), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetWitnessAddress(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::WitnessAddress::AsInstanceAddress(Owner), States::WitnessAddress::AsInstanceStride(Asset, Args[2].AsString(), Args.size() > 3 ? Args[3].AsUint64() : Protocol::Now().Account.RootAddressIndex), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ChainstateGetWitnessAddresses(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetStatesByAddress(nullptr, States::WitnessAddress::AsInstanceAddress(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::ChainstateGetWitnessTransaction(Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetStateByComposition(nullptr, States::WitnessTransaction::AsInstanceAddress(Asset), States::WitnessTransaction::AsInstanceStride(Args[1].AsString()), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::MempoolAddNode(Format::Variables&& Args)
		{
			auto Address = Args[0].AsString();
			auto Target = DNS::Get()->Lookup(Address, ToString(Protocol::Now().User.P2P.NodePort), DNSType::Listen);
			if (!Target)
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			auto IpAddress = Target->GetIpAddress();
			if (!IpAddress)
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.SetSeed(*IpAddress);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::MempoolClearNode(Format::Variables&& Args)
		{
			auto Address = Args[0].AsString();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.ClearValidator(Address);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::MempoolGetClosestNode(Format::Variables&& Args)
		{
			size_t Offset = Args.size() > 0 ? Args[0].AsUint64() : 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Validator = Mempool.GetValidatorByPreference(Offset);
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Validator->AsSchema().Reset());
		}
		Promise<ServerResponse> ServerNode::MempoolGetClosestNodeCounter(Format::Variables&& Args)
		{
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Count = Mempool.GetValidatorsCount();
			if (!Count)
				return ServerResponse().Error(ErrorCodes::BadRequest, "count not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*Count));
		}
		Promise<ServerResponse> ServerNode::MempoolGetNode(Format::Variables&& Args)
		{
			auto Address = Args[0].AsString();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Validator = Mempool.GetValidatorByAddress(Address);
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Validator->AsSchema().Reset());
		}
		Promise<ServerResponse> ServerNode::MempoolGetSeeds(Format::Variables&& Args)
		{
			uint64_t Count = Args[0].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Seeds = Mempool.GetSeeds(Count);
			if (!Seeds)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Seed : *Seeds)
				Data->Push(Var::String(Seed));
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::MempoolGetGasPrice(Format::Variables&& Args)
		{
			Algorithm::AssetId Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			double Percentile = Args.size() > 1 ? Args[1].AsDouble() : 0.50;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Price = Mempool.GetGasPrice(Asset, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "gas price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::MempoolGetAssetPrice(Format::Variables&& Args)
		{
			Algorithm::AssetId Asset1 = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			Algorithm::AssetId Asset2 = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			double Percentile = Args.size() > 2 ? Args[2].AsDouble() : 0.50;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Price = Mempool.GetAssetPrice(Asset1, Asset2, Percentile);
			if (!Price)
				return ServerResponse().Error(ErrorCodes::NotFound, "asset price not found");

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		Promise<ServerResponse> ServerNode::MempoolGetEstimateTransactionGas(Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(CandidateTx->GetGasEstimate()));
		}
		Promise<ServerResponse> ServerNode::MempoolGetOptimalTransactionGas(Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			CandidateTx->SetOptimalGas(CandidateTx->GasPrice);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(CandidateTx->GasLimit));
		}
		Promise<ServerResponse> ServerNode::MempoolAcceptTransaction(Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			auto CandidateHash = CandidateTx->AsHash();
			auto Chain = Storages::Chainstate(__func__);
			if (Chain.GetTransactionByHash(CandidateHash))
				return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(CandidateHash)));

			Algorithm::Pubkeyhash Owner;
			if (!CandidateTx->Recover(Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid signature");

			auto Prevalidation = Ledger::TransactionContext::PrevalidateTx(*CandidateTx, CandidateHash, Owner);
			if (!Prevalidation)
				return ServerResponse().Error(ErrorCodes::BadRequest, "prevalidation error: " + Prevalidation.Error().Info);

			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			bool Event = CandidateTx->GetType() != Ledger::TransactionLevel::OwnerAccount && !memcmp(Validator->Validator.Wallet.PublicKeyHash, Owner, sizeof(Owner));
			bool Validate = Event || (Args.size() > 1 ? Args[1].AsBoolean() : false);
			if (Validate)
			{
				Ledger::Block TempBlock;
				TempBlock.Number = std::numeric_limits<int64_t>::max() - 1;

				Ledger::EvaluationContext TempEnvironment;
				TempEnvironment.Validation.Proposal = true;
				memcpy(TempEnvironment.Proposer.PublicKeyHash, Validator->Validator.Wallet.PublicKeyHash, sizeof(Algorithm::Pubkeyhash));

				Ledger::BlockWork Cache;
				auto Validation = Ledger::TransactionContext::ValidateTx(&TempBlock, &TempEnvironment, *CandidateTx, CandidateHash, Cache);
				if (!Validation)
					return ServerResponse().Error(ErrorCodes::BadRequest, "validation error: " + Validation.Error().Info);
			}

			if (!Validator->BroacastTransaction(nullptr, std::move(CandidateTx)))
				return ServerResponse().Error(ErrorCodes::BadRequest, "mempool rejection");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(CandidateHash)));
		}
		Promise<ServerResponse> ServerNode::MempoolRejectTransaction(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.RemoveTransactions(Vector<uint256_t>({ Hash }));
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::MempoolGetTransactionByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Transaction = Mempool.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success((*Transaction)->AsSchema());
		}
		Promise<ServerResponse> ServerNode::MempoolGetRawTransactionByHash(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Transaction = Mempool.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success(Var::Set::String((*Transaction)->AsMessage().Encode()));
		}
		Promise<ServerResponse> ServerNode::MempoolGetTransactionSequence(Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "owner address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Lowest = Mempool.GetLowestTransactionSequence(Owner);
			auto Highest = Mempool.GetHighestTransactionSequence(Owner);
			UPtr<Schema> Data = Var::Set::Object();
			Data->Set("min", Lowest ? Algorithm::Encoding::SerializeUint256(*Lowest) : Var::Set::Null());
			Data->Set("max", Highest ? Algorithm::Encoding::SerializeUint256(*Highest) : Var::Set::Null());
			return ServerResponse().Success(std::move(Data));
		}
		Promise<ServerResponse> ServerNode::MempoolGetTransactions(Format::Variables&& Args)
		{
			uint64_t Offset = Args[0].AsUint64(), Count = Args[1].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Unrolling = Args.size() > 2 ? Args[2].AsUint8() : 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetTransactions(Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetTransactions(Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::MempoolGetCumulativeEventTransactions(Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Unrolling = Args.size() > 3 ? Args[3].AsUint8() : 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetCumulativeEventTransactions(Hash, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetCumulativeEventTransactions(Hash, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		Promise<ServerResponse> ServerNode::ValidatorAcceptNode(Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			bool Status = Args.size() > 0 ? Validator->Accept(SocketAddress(Args[0].AsString(), Protocol::Now().User.P2P.NodePort)) : Validator->Accept();
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ValidatorRejectNode(Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			auto* Node = Validator->Find(SocketAddress(Args[0].AsString(), Protocol::Now().User.P2P.NodePort));
			if (!Node || Node == (P2P::Relay*)Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			auto* User = Node->AsUser<Ledger::Edge>();
			Validator->Reject(Node);
			return ServerResponse().Success(Var::Set::Null());
		}
		Promise<ServerResponse> ServerNode::ValidatorGetNode(Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			auto* Node = Validator->Find(SocketAddress(Args[0].AsString(), Protocol::Now().User.P2P.NodePort));
			if (!Node || Node == (P2P::Relay*)Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");
			
			auto* User = Node->AsUser<Ledger::Edge>();
			auto Data = User->AsSchema();
			Data->Set("network", Node->AsSchema().Reset());
			return ServerResponse().Success(Data.Reset());
		}
		Promise<ServerResponse> ServerNode::ValidatorStatus(Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			auto Chain = Storages::Chainstate(__func__);
			auto BlockHeader = Chain.GetLatestBlockHeader();
			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			UPtr<Schema> Data = Var::Set::Object();
			Data->Set("seeds", Algorithm::Encoding::SerializeUint256(Validator->Seeds.size()));
			Data->Set("wallet", Validator->Validator.Wallet.AsPublicSchema().Reset());
			Data->Set("node", Validator->Validator.Node.AsSchema().Reset());
			Data->Set("checkpoint", Algorithm::Encoding::SerializeUint256(Chain.GetCheckpointBlockNumber().Or(0)));
			if (Validator->PendingTip.Hash > 0 && Validator->PendingTip.Block)
			{
				Schema* Tip = Data->Set("tip", Var::Object());
				Tip->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(Validator->PendingTip.Hash)));
				Tip->Set("number", Algorithm::Encoding::SerializeUint256(Validator->PendingTip.Block->Number));
				Tip->Set("sync", Var::Number(Validator->GetSyncProgress(Validator->PendingTip.Hash, BlockHeader ? BlockHeader->Number : 0)));
			}
			else if (BlockHeader)
			{
				auto BlockHash = BlockHeader->AsHash();
				Schema* Tip = Data->Set("tip", Var::Object());
				Tip->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(BlockHash)));
				Tip->Set("number", Algorithm::Encoding::SerializeUint256(BlockHeader->Number));
				Tip->Set("sync", Var::Number(Validator->GetSyncProgress(BlockHash, BlockHeader ? BlockHeader->Number : 0)));
			}
			else
				Data->Set("tip", Var::Null());

			auto* Connections = Data->Set("connections", Var::Set::Array());
			for (auto& Node : Validator->GetNodes())
			{
				auto* User = Node.second->AsUser<Ledger::Edge>();
				auto Data = User->AsSchema();
				Data->Set("network", Node.second->AsSchema().Reset());
				Connections->Push(Data.Reset());
			}

			auto* Candidates = Data->Set("candidates", Var::Set::Array());
			for (auto& Node : Validator->GetCandidateNodes())
			{
				auto& Address = Node->GetPeerAddress();
				auto IpAddress = Address.GetIpAddress();
				auto IpPort = Address.GetIpPort();
				Candidates->Push(Var::String(IpPort ? IpAddress.Or("[???]") + ":" + ToString(*IpPort) : IpAddress.Or("[???]")));
			}

			auto* Forks = Data->Set("forks", Var::Set::Array());
			for (auto& Fork : Validator->Forks)
			{
				Schema* Item = Forks->Push(Var::Set::Object());
				Item->Set("hash", Var::String(Algorithm::Encoding::Encode0xHex256(Fork.first)));
				Item->Set("number", Algorithm::Encoding::SerializeUint256(Fork.second.Number));
				Item->Set("sync", Var::Number(Validator->GetSyncProgress(Fork.first, BlockHeader ? BlockHeader->Number : 0)));
			}

			return ServerResponse().Success(Data.Reset());
		}
	}
}