#include "rpc.h"
#include "p2p.h"
#include "../kernel/script.h"
#include "../storage/mempoolstate.h"
#include "../storage/chainstate.h"
#include "../policy/transactions.h"

namespace Tangent
{
	namespace RPC
	{
		static ExpectsLR<String> AsIndex(const std::string_view& Type, const Format::Variable& Value1, const Format::Variable& Value2)
		{
			if (Type == States::AccountSequence::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value1.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountSequence::AsInstanceIndex(Owner);
			}

			if (Type == States::AccountProgram::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value1.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountProgram::AsInstanceIndex(Owner);
			}

			if (Type == States::AccountStorage::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value1.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountStorage::AsInstanceIndex(Owner, Value2.AsString());
			}

			if (Type == States::AccountDerivation::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value1.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountDerivation::AsInstanceIndex(Owner, Algorithm::Asset::IdOfHandle(Value2.AsString()));
			}

			if (Type == States::WitnessProgram::AsInstanceTypename())
				return States::WitnessProgram::AsInstanceIndex(Value1.AsString());

			if (Type == States::WitnessEvent::AsInstanceTypename())
				return States::WitnessEvent::AsInstanceIndex(Value1.AsUint256());

			if (Type == States::WitnessTransaction::AsInstanceTypename())
				return States::WitnessTransaction::AsInstanceIndex(Algorithm::Asset::IdOfHandle(Value1.AsString()), Value2.AsString());

			return LayerException("invalid uniform type");
		}
		static ExpectsLR<String> AsColumn(const std::string_view& Type, const Format::Variable& Value)
		{
			if (Type == States::AccountWork::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountWork::AsInstanceColumn(Owner);
			}

			if (Type == States::AccountObserver::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountObserver::AsInstanceColumn(Owner);
			}

			if (Type == States::AccountReward::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountReward::AsInstanceColumn(Owner);
			}

			if (Type == States::AccountBalance::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountBalance::AsInstanceColumn(Owner);
			}

			if (Type == States::AccountContribution::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::AccountContribution::AsInstanceColumn(Owner);
			}

			if (Type == States::WitnessAddress::AsInstanceTypename())
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Value.AsString(), Owner))
					return LayerException("invalid address");

				return States::WitnessAddress::AsInstanceColumn(Owner);
			}

			return LayerException("invalid multiform type");
		}
		static ExpectsLR<String> AsRow(const std::string_view& Type, const Format::Variable& Value)
		{
			if (Type == States::AccountWork::AsInstanceTypename())
				return States::AccountWork::AsInstanceRow();

			if (Type == States::AccountObserver::AsInstanceTypename())
				return States::AccountObserver::AsInstanceRow(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountReward::AsInstanceTypename())
				return States::AccountReward::AsInstanceRow(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountBalance::AsInstanceTypename())
				return States::AccountBalance::AsInstanceRow(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::AccountContribution::AsInstanceTypename())
				return States::AccountContribution::AsInstanceRow(Algorithm::Asset::IdOfHandle(Value.AsString()));

			if (Type == States::WitnessAddress::AsInstanceTypename())
			{
				auto Data = Value.AsSchema();
				if (!Data)
					return LayerException("invalid value, expected { asset: string, address: string, derivation_index: uint64 }");

				return States::WitnessAddress::AsInstanceRow(Algorithm::Asset::IdOfHandle(Data->GetVar("asset").GetBlob()), Data->GetVar("address").GetBlob(), Data->GetVar("derivation_index").GetInteger());
			}

			return LayerException("invalid multiform type");
		}
		static void FormResponse(HTTP::Connection* Base, Schema* Request, UPtr<Schema>& Responses, ServerResponse&& Response)
		{
			if (Protocol::Now().User.RPC.Logging)
			{
				auto* Params = Request->Get("params");
				String Method = Request->GetVar("method").GetBlob();
				String Id = Request->GetVar("id").GetBlob();
				VI_INFO("[rpc] on peer %s call %s: %s (params: %" PRIu64 ", time: %" PRId64 " ms)",
					Base->GetPeerIpAddress().Or("[bad_address]").c_str(),
					Method.empty() ? "[bad_method]" : Method.c_str(),
					Response.ErrorMessage.empty() ? (Response.Data ? (Response.Data->Value.IsObject() ? Stringify::Text("%" PRIu64 " rows", (uint64_t)Response.Data->Size()).c_str() : "[value]") : "[null]") : Response.ErrorMessage.c_str(),
					(uint64_t)(Params ? (Params->Value.IsObject() ? Params->Size() : 1) : 0),
					DateTime().Milliseconds() - Base->Info.Start);
			}

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

		ServerResponse&& ServerResponse::Success(UPtr<Schema>&& Value)
		{
			Data = std::move(Value);
			Status = ErrorCodes::Response;
			return std::move(*this);
		}
		ServerResponse&& ServerResponse::Notification(UPtr<Schema>&& Value)
		{
			Data = std::move(Value);
			Status = ErrorCodes::Notification;
			return std::move(*this);
		}
		ServerResponse&& ServerResponse::Error(ErrorCodes Code, const std::string_view& Message)
		{
			ErrorMessage = Message;
			Status = Code;
			return std::move(*this);
		}
		UPtr<Schema> ServerResponse::Transform(Schema* Request)
		{
			auto* Id = Request ? Request->Get("id") : nullptr;
			UPtr<Schema> Response = Var::Set::Object();
			Response->Set("id", Id ? Id : Var::Set::Null());

			auto* Result = Response->Set(Status == ErrorCodes::Notification ? "notification" : "result", Data.Reset());
			if (Status != ErrorCodes::Response && Status != ErrorCodes::Notification && !ErrorMessage.empty())
			{
				auto* Error = Response->Set("error", Var::Object());
				Error->Set("message", Var::String(ErrorMessage));
				Error->Set("code", Var::Integer((int64_t)Status));
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
			Router->Listen(Protocol::Now().User.RPC.Address, ToString(Protocol::Now().User.RPC.Port)).Expect("listener binding error");
			Router->Post("/", std::bind(&ServerNode::HttpRequest, this, std::placeholders::_1));
			Router->Base->Callbacks.Authorize = (AdminToken.empty() && UserToken.empty()) ? HTTP::AuthorizeCallback(nullptr) : std::bind(&ServerNode::Authorize, this, std::placeholders::_1, std::placeholders::_2);
			Router->Base->Callbacks.Headers = std::bind(&ServerNode::Headers, this, std::placeholders::_1, std::placeholders::_2);
			Router->Base->Callbacks.Options = std::bind(&ServerNode::Options, this, std::placeholders::_1);
			Router->Base->Auth.Type = "Basic";
			Router->Base->Auth.Realm = "rpc.tan";
			Router->TemporaryDirectory.clear();
			if (Protocol::Now().User.RPC.WebSockets)
			{
				Router->WebSocketReceive("/", std::bind(&ServerNode::WsReceive, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
				Router->WebSocketDisconnect("/", std::bind(&ServerNode::WsDisconnect, this, std::placeholders::_1));
				Router->Base->AllowWebSocket = true;
				Router->Base->WebSocketTimeout = 0;
			}

			Node->Configure(Router).Expect("configuration error");
			Node->Listen().Expect("listen queue error");
			if (Validator != nullptr)
			{
				Validator->AddRef();
				if (Protocol::Now().User.RPC.WebSockets)
				{
					Validator->Events.AcceptBlock = std::bind(&ServerNode::DispatchAcceptBlock, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
					Validator->Events.AcceptTransaction = std::bind(&ServerNode::DispatchAcceptTransaction, this, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3);
				}
			}

			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[rpc] rpc node listen (location: %s:%i)", Protocol::Now().User.RPC.Address.c_str(), (int)Protocol::Now().User.RPC.Port);

			Bind(0, "websocket", "subscribe", 1, 3, "string addresses, bool? blocks, bool? transactions", "uint64", "Subscribe to streams of incoming blocks and transactions optionally include blocks and transactions relevant to comma separated address list", std::bind(&ServerNode::WebSocketSubscribe, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "websocket", "unsubscribe", 1, 1, "", "", "Unsubscribe from all streams", std::bind(&ServerNode::WebSocketUnsubscribe, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "utility", "encodeaddress", 1, 1, "string hex_address", "string", "encode hex address", std::bind(&ServerNode::UtilityEncodeAddress, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "utility", "decodeaddress", 1, 1, "string address", "string", "decode address", std::bind(&ServerNode::UtilityDecodeAddress, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "utility", "decodemessage", 1, 1, "string message", "any[]", "decode message", std::bind(&ServerNode::UtilityDecodeMessage, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "utility", "decodetransaction", 1, 1, "string hex_message", "{ transaction: txn, signer_address: string }", "decode transaction message and convert to object", std::bind(&ServerNode::UtilityDecodeTransaction, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0, "utility", "help", 0, 0, "", "{ declaration: string, method: string, description: string }[]", "get reference of all methods", std::bind(&ServerNode::UtilityHelp, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblocks", 2, 2, "uint64 number, uint64 count", "uint256[]", "get block hashes", std::bind(&ServerNode::BlockstateGetBlocks, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockcheckpointhash", 0, 0, "", "uint256", "get block checkpoint hash", std::bind(&ServerNode::BlockstateGetBlockCheckpointHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockcheckpointnumber", 0, 0, "", "uint64", "get block checkpoint number", std::bind(&ServerNode::BlockstateGetBlockCheckpointNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblocktiphash", 0, 0, "", "uint256", "get block tip hash", std::bind(&ServerNode::BlockstateGetBlockTipHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblocktipnumber", 0, 0, "", "uint64", "get block tip number", std::bind(&ServerNode::BlockstateGetBlockTipNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "block", "get block by hash", std::bind(&ServerNode::BlockstateGetBlockByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "block", "get block by number", std::bind(&ServerNode::BlockstateGetBlockByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getrawblockbyhash", 1, 1, "uint256 hash", "string", "get block by hash", std::bind(&ServerNode::BlockstateGetRawBlockByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getrawblockbynumber", 1, 1, "uint64 number", "string", "get block by number", std::bind(&ServerNode::BlockstateGetRawBlockByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockproofbyhash", 1, 4, "uint256 hash, bool? transactions, bool? receipts, bool? states", "block::proof", "get block proof by hash", std::bind(&ServerNode::BlockstateGetBlockProofByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockproofbynumber", 1, 4, "uint64 number, bool? transactions, bool? receipts, bool? states", "block::proof", "get block proof by number", std::bind(&ServerNode::BlockstateGetBlockProofByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblocknumberbyhash", 1, 1, "uint256 hash", "uint64", "get block number by hash", std::bind(&ServerNode::BlockstateGetBlockNumberByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "blockstate", "getblockhashbynumber", 1, 1, "uint64 number", "uint256", "get block hash by number", std::bind(&ServerNode::BlockstateGetBlockHashByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getblocktransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by hash", std::bind(&ServerNode::TxnstateGetBlockTransactionsByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getblocktransactionsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by number", std::bind(&ServerNode::TxnstateGetBlockTransactionsByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getblockreceiptsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | receipt[]", "get block receipts by hash", std::bind(&ServerNode::TxnstateGetBlockReceiptsByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getblockreceiptsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | receipt[]", "get block receipts by number", std::bind(&ServerNode::TxnstateGetBlockReceiptsByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getpendingtransactionsbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by hash", std::bind(&ServerNode::TxnstateGetBlockTransactionsByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getpendingtransactionsbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get block transactions by number", std::bind(&ServerNode::TxnstateGetBlockTransactionsByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "gettransactionsbyowner", 3, 5, "string owner_address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling = 0", "uint256[] | txn[] | block::txn[]", "get transactions by owner", std::bind(&ServerNode::TxnstateGetTransactionsByOwner, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "gettransactionbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "txn | block::txn", "get transaction by hash", std::bind(&ServerNode::TxnstateGetTransactionByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getrawtransactionbyhash", 1, 1, "uint256 hash", "string", "get raw transaction by hash", std::bind(&ServerNode::TxnstateGetRawTransactionByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "txnstate", "getreceiptbytransactionhash", 1, 1, "uint256 hash", "receipt", "get receipt by transaction hash", std::bind(&ServerNode::TxnstateGetReceiptByTransactionHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "immutablecall", 4, 32, "string asset, string from_address, string to_address, string function, ...", "program_trace", "execute of immutable function of program assigned to to_address", std::bind(&ServerNode::ChainstateImmutableCall, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockstatesbyhash", 1, 2, "uint256 hash, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block states by hash", std::bind(&ServerNode::ChainstateGetBlockStatesByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockstatesbynumber", 1, 2, "uint64 number, uint8? unrolling = 0", "uint256[] | (uniform|multiform)[]", "get block states by number", std::bind(&ServerNode::ChainstateGetBlockStatesByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockgaspricebyhash", 2, 3, "uint256 hash, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockGasPriceByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockgaspricebynumber", 2, 3, "uint64 number, string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of block transactions by number", std::bind(&ServerNode::ChainstateGetBlockGasPriceByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockassetpricebyhash", 3, 4, "uint256 hash, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by hash", std::bind(&ServerNode::ChainstateGetBlockAssetPriceByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getblockassetpricebynumber", 3, 4, "uint64 number, string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of block transactions by number", std::bind(&ServerNode::ChainstateGetBlockAssetPriceByNumber, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getuniformbyindex", 2, 3, "string type, any argument1, any? argument2", "uniform", "get uniform by type, address and stride", std::bind(&ServerNode::ChainstateGetMultiformByComposition, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformbycomposition", 3, 3, "string type, any column, any row", "multiform", "get multiform by type, address and stride", std::bind(&ServerNode::ChainstateGetMultiformByComposition, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformbyaddress", 2, 3, "string type, any column, uint64? offset", "multiform", "get multiform by type and address", std::bind(&ServerNode::ChainstateGetMultiformByColumn, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformsbyaddress", 4, 4, "string type, any column, uint64 offset, uint64 count", "multiform[]", "get filtered multiform by type and address", std::bind(&ServerNode::ChainstateGetMultiformsByColumn, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformbystride", 2, 3, "string type, any row, uint64? offset", "multiform", "get multiform by type and stride", std::bind(&ServerNode::ChainstateGetMultiformByRow, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformbystridequery", 7, 7, "string type, any row, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value, int8 weight_order, uint64 offset, uint64 count", "multiform", "get filtered multiform by type stride", std::bind(&ServerNode::ChainstateGetMultiformsByRow, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getmultiformscountbystride", 4, 4, "string type, any row, string weight_condition = '>' | '>=' | '=' | '<>' | '<=' | '<', int64 weight_value", "uint64", "get filtered multiform count by type and stride", std::bind(&ServerNode::ChainstateGetMultiformsCountByRow, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountsequence", 1, 1, "string address", "uint64", "get account sequence by address", std::bind(&ServerNode::ChainstateGetAccountSequence, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountwork", 1, 1, "string address", "multiform", "get account work by address", std::bind(&ServerNode::ChainstateGetAccountWork, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountworkers", 3, 3, "uint64 commitment, uint64 offset, uint64 count", "multiform[]", "get best block proposers (zero commitment = offline proposers, non-zero commitment = online proposers threshold)", std::bind(&ServerNode::ChainstateGetBestAccountWorkers, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountobserver", 1, 1, "string asset, string address", "multiform", "get account observer by address and asset", std::bind(&ServerNode::ChainstateGetAccountObserver, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountobservers", 3, 3, "string asset, uint64 commitment, uint64 offset, uint64 count", "multiform[]", "get best account observers (zero commitment = offline observers, non-zero commitment = online observers threshold)", std::bind(&ServerNode::ChainstateGetBestAccountObservers, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountprogram", 1, 1, "string address", "uniform", "get account program hashcode by address", std::bind(&ServerNode::ChainstateGetAccountProgram, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountstorage", 2, 2, "string address, string location", "uniform", "get account storage by address and location", std::bind(&ServerNode::ChainstateGetAccountStorage, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountreward", 2, 2, "string address, string asset", "multiform", "get account reward by address and asset", std::bind(&ServerNode::ChainstateGetAccountReward, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountrewards", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account rewards by address", std::bind(&ServerNode::ChainstateGetAccountRewards, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountrewards", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best rewards", std::bind(&ServerNode::ChainstateGetBestAccountRewards, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountrewardswithcontributions", 3, 3, "string asset, uint64 offset, uint64 count", "{ contribution: multiform?, reward: multiform }[]", "get accounts with best rewards with contribution states", std::bind(&ServerNode::ChainstateGetBestAccountRewardsWithContributions, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountderivation", 2, 2, "string address, string asset", "uint64", "get account derivation by address and asset", std::bind(&ServerNode::ChainstateGetAccountDerivation, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountbalance", 2, 2, "string address, string asset", "multiform", "get account balance by address and asset", std::bind(&ServerNode::ChainstateGetAccountBalance, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountbalances", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account balances by address", std::bind(&ServerNode::ChainstateGetAccountBalances, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountcontribution", 2, 2, "string address, string asset", "multiform", "get account contribution by address and asset", std::bind(&ServerNode::ChainstateGetAccountContribution, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getaccountcontributions", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get account contributions by address", std::bind(&ServerNode::ChainstateGetAccountContributions, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountcontributions", 3, 3, "string asset, uint64 offset, uint64 count", "multiform[]", "get accounts with best contribution", std::bind(&ServerNode::ChainstateGetBestAccountContributions, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getbestaccountcontributionswithrewards", 3, 3, "string asset, uint64 offset, uint64 count", "{ contribution: multiform, reward: multiform? }[]", "get accounts with best contribution with reward policies", std::bind(&ServerNode::ChainstateGetBestAccountContributionsWithRewards, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getwitnessprogram", 1, 1, "string hashcode", "uniform", "get witness program by hashcode (512bit number)", std::bind(&ServerNode::ChainstateGetWitnessProgram, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getwitnessevent", 1, 1, "uint256 transaction_hash", "uniform", "get witness event by transaction hash", std::bind(&ServerNode::ChainstateGetWitnessEvent, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getwitnessaddress", 3, 4, "string address, string asset, string wallet_address, uint64? derivation_index", "multiform", "get witness address by owner address, asset, wallet address and derivation index", std::bind(&ServerNode::ChainstateGetWitnessAddress, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getwitnessaddresses", 3, 3, "string address, uint64 offset, uint64 count", "multiform[]", "get witness addresses by owner address", std::bind(&ServerNode::ChainstateGetWitnessAddresses, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "chainstate", "getwitnesstransaction", 2, 2, "string asset, string transaction_id", "uniform", "get witness transaction by asset and transaction id", std::bind(&ServerNode::ChainstateGetWitnessTransaction, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getclosestnode", 0, 1, "uint64? offset", "validator", "get closest node info", std::bind(&ServerNode::MempoolstateGetClosestNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getclosestnodecount", 0, 0, "", "uint64", "get closest node count", std::bind(&ServerNode::MempoolstateGetClosestNodeCounter, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getnode", 1, 1, "string uri_address", "validator", "get associated node info by ip address", std::bind(&ServerNode::MempoolstateGetNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getaddresses", 2, 3, "uint64 offset, uint64 count, string? services = 'consensus' | 'discovery' | 'interface' | 'proposer'", "string[]", "get best node ip addresses with optional comma separated list of services", std::bind(&ServerNode::MempoolstateGetAddresses, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getgasprice", 1, 2, "string asset, double? percentile = 0.5", "decimal", "get gas price from percentile of pending transactions", std::bind(&ServerNode::MempoolstateGetGasPrice, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getassetprice", 2, 3, "string asset_from, string asset_to, double? percentile = 0.5", "decimal", "get gas asset from percentile of pending transactions", std::bind(&ServerNode::MempoolstateGetAssetPrice, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getoptimaltransactiongas", 1, 1, "string hex_message", "uint256", "execute transaction with block gas limit and return ceil of spent gas", std::bind(&ServerNode::MempoolstateGetOptimalTransactionGas, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getestimatetransactiongas", 1, 1, "string hex_message", "uint256", "get rough estimate of required gas limit than could be considerably lower or higher than actual required gas limit", std::bind(&ServerNode::MempoolstateGetEstimateTransactionGas, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getmempooltransactionbyhash", 1, 1, "uint256 hash", "txn", "get mempool transaction by hash", std::bind(&ServerNode::MempoolstateGetTransactionByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getrawmempooltransactionbyhash", 1, 1, "uint256 hash", "string", "get raw mempool transaction by hash", std::bind(&ServerNode::MempoolstateGetRawTransactionByHash, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getnextaccountsequence", 1, 1, "string owner_address", "{ min: uint64, max: uint64 }", "get account sequence for next transaction by owner", std::bind(&ServerNode::MempoolstateGetNextAccountSequence, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getmempooltransactions", 2, 3, "uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions", std::bind(&ServerNode::MempoolstateGetTransactions, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getmempooltransactionsbyowner", 3, 5, "const string address, uint64 offset, uint64 count, uint8? direction = 1, uint8? unrolling", "uint256[] | txn[]", "get mempool transactions by signing address", std::bind(&ServerNode::MempoolstateGetTransactionsByOwner, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "mempoolstate", "getcumulativemempooltransactions", 3, 4, "uint256 hash, uint64 offset, uint64 count, uint8? unrolling", "uint256[] | txn[]", "get cumulative mempool transactions", std::bind(&ServerNode::MempoolstateGetCumulativeEventTransactions, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "validatorstate", "getnode", 1, 1, "string uri_address", "validator", "get a node by ip address", std::bind(&ServerNode::ValidatorstateGetNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "validatorstate", "getblockchains", 0, 0, "", "oracle::asset", "get supported blockchains", std::bind(&ServerNode::ValidatorstateGetBlockchains, this, std::placeholders::_1, std::placeholders::_2));
			Bind(0 | AccessType::R, "validatorstate", "status", 0, 0, "", "validator::status", "get validator status", std::bind(&ServerNode::ValidatorstateStatus, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::R | AccessType::A, "chainstate", "tracecall", 4, 32, "string asset, string from_address, string to_address, string function, ...", "program_trace", "trace execution of mutable / immutable function of program assigned to to_address", std::bind(&ServerNode::ChainstateTraceCall, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::R, "mempoolstate", "submittransaction", 1, 2, "string hex_message, bool? validate", "uint256", "try to accept and relay a mempool transaction from raw data and possibly validate over latest chainstate", std::bind(&ServerNode::MempoolstateSubmitTransaction, this, std::placeholders::_1, std::placeholders::_2, nullptr));
			Bind(AccessType::W | AccessType::A, "mempoolstate", "rejecttransaction", 1, 1, "uint256 hash", "", "remove mempool transaction by hash", std::bind(&ServerNode::MempoolstateRejectTransaction, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::A, "mempoolstate", "addnode", 1, 1, "string uri_address", "", "add node ip address to trial addresses", std::bind(&ServerNode::MempoolstateAddNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::A, "mempoolstate", "clearnode", 1, 1, "string uri_address", "", "remove associated node info by ip address", std::bind(&ServerNode::MempoolstateClearNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::R | AccessType::A, "validatorstate", "verify", 2, 3, "uint64 number, uint64 count, bool? validate", "uint256[]", "verify chain and possibly re-execute each block", std::bind(&ServerNode::ValidatorstateVerify, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::A, "validatorstate", "prune", 2, 2, "string types = 'statetrie' | 'blocktrie' | 'transactiontrie', uint64 number", "", "prune chainstate data using pruning level (types is '|' separated list)", std::bind(&ServerNode::ValidatorstatePrune, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::A, "validatorstate", "acceptnode", 0, 1, "string? uri_address", "", "try to accept and connect to a node possibly by ip address", std::bind(&ServerNode::ValidatorstateAcceptNode, this, std::placeholders::_1, std::placeholders::_2));
			Bind(AccessType::W | AccessType::A, "validatorstate", "rejectnode", 1, 1, "string uri_address", "", "reject and disconnect from a node by ip address", std::bind(&ServerNode::ValidatorstateRejectNode, this, std::placeholders::_1, std::placeholders::_2));
		}
		void ServerNode::Shutdown()
		{
			if (!IsActive())
				return;

			if (Protocol::Now().User.P2P.Logging)
				VI_INFO("[rpc] rpc node shutdown requested");

			Node->Unlisten(false);
		}
		void ServerNode::Bind(uint32_t AccessTypes, const std::string_view& Domain, const std::string_view& Method, size_t MinParams, size_t MaxParams, const std::string_view& Args, const std::string_view& Returns, const std::string_view& Description, ServerFunction&& Function)
		{
			ServerRequest Item;
			Item.AccessTypes = AccessTypes;
			Item.MinParams = MinParams;
			Item.MaxParams = MaxParams;
			Item.Domain = Domain;
			Item.Args = Args;
			Item.Returns = Returns;
			Item.Description = Description;
			Item.Function = std::move(Function);
			Methods[String(Method)] = std::move(Item);
		}
		bool ServerNode::HasAdminAuthorization()
		{
			return !Protocol::Now().User.RPC.AdminUsername.empty();
		}
		bool ServerNode::HasUserAuthorization()
		{
			return !Protocol::Now().User.RPC.UserUsername.empty();
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
		bool ServerNode::Headers(HTTP::Connection* Client, String& Content)
		{
			auto Headers = Client->Request.ComposeHeader("access-control-request-headers");
			if (Headers.empty())
				Headers = "Authorization";

			auto* Origin = Client->Request.GetHeaderBlob("origin");
			if (Origin != nullptr)
				Content.append("Access-Control-Allow-Origin: ").append(*Origin).append("\r\n");

			Content.append("Access-Control-Allow-Headers: *, ");
			Content.append(Headers);
			Content.append("\r\n");
			Content.append("Access-Control-Allow-Methods: POST\r\n");
			Content.append("Access-Control-Allow-Credentials: true\r\n");
			Content.append("Access-Control-Max-Age: 86400\r\n");
			return true;
		}
		bool ServerNode::Options(HTTP::Connection* Client)
		{
			char Date[64];
			String* Content = HTTP::HrmCache::Get()->Pop();
			Content->append(Client->Request.Version);
			Content->append(" 204 No Content\r\nDate: ");
			Content->append(DateTime::SerializeGlobal(Date, sizeof(Date), std::chrono::duration_cast<std::chrono::system_clock::duration>(std::chrono::milliseconds(Client->Info.Start)), DateTime::FormatWebTime())).append("\r\n", 2);
			Content->append("Allow: POST\r\n");

			HTTP::Utils::UpdateKeepAliveHeaders(Client, *Content);
			if (Client->Route && Client->Route->Callbacks.Headers)
				Client->Route->Callbacks.Headers(Client, *Content);

			Content->append("\r\n", 2);
			return !!Client->Stream->WriteQueued((uint8_t*)Content->c_str(), Content->size(), [Client, Content](SocketPoll Event)
			{
				HTTP::HrmCache::Get()->Push(Content);
				if (Packet::IsDone(Event))
					Client->Next(204);
				else if (Packet::IsError(Event))
					Client->Abort();
			}, false);
		}
		bool ServerNode::HttpRequest(HTTP::Connection* Base)
		{
			Base->Response.SetHeader("Content-Type", "application/json");
			return Base->Fetch([this](HTTP::Connection* Base, SocketPoll Event, const std::string_view&) -> bool
			{
				if (!Packet::IsDone(Event))
					return true;

				auto Request = Base->Request.Content.GetJSON();
				if (Request)
				{
					Cospawn(std::bind(&ServerNode::DispatchResponse, this, Base, *Request, nullptr, 0, [](HTTP::Connection* Base, UPtr<Schema>&& Responses)
					{
						auto Response = Schema::ToJSON(Responses ? *Responses : *ServerResponse().Error(ErrorCodes::BadRequest, "request is empty").Transform(nullptr));
						Base->Response.Content.Assign(Response);
						Base->Next(200);
					}));
				}
				else
				{
					Base->Response.Content.Assign(Schema::ToJSON(*ServerResponse().Error(ErrorCodes::BadRequest, Request.Error().message()).Transform(nullptr)));
					Base->Next(200);
				}
				return true;
			});
		}
		bool ServerNode::WsReceive(HTTP::WebSocketFrame* WebSocket, HTTP::WebSocketOp Opcode, const std::string_view& Buffer)
		{
			if (Opcode != HTTP::WebSocketOp::Binary && Opcode != HTTP::WebSocketOp::Text)
				return false;

			auto Request = Schema::FromJSON(Buffer);
			if (Request)
			{
				Cospawn(std::bind(&ServerNode::DispatchResponse, this, WebSocket->GetConnection(), *Request, nullptr, 0, [](HTTP::Connection* Base, UPtr<Schema>&& Responses)
				{
					auto Response = Schema::ToJSON(Responses ? *Responses : *ServerResponse().Error(ErrorCodes::BadRequest, "request is empty").Transform(nullptr));
					Base->WebSocket->Send(Response, HTTP::WebSocketOp::Text, [](HTTP::WebSocketFrame* WebSocket) { WebSocket->Next(); });
				}));
			}
			else
				WebSocket->Send(Schema::ToJSON(*ServerResponse().Error(ErrorCodes::BadRequest, Request.Error().message()).Transform(nullptr)), HTTP::WebSocketOp::Text, [](HTTP::WebSocketFrame* WebSocket) { WebSocket->Next(); });

			return true;
		}
		void ServerNode::WsDisconnect(HTTP::WebSocketFrame* WebSocket)
		{
			UMutex<std::mutex> Unique(Mutex);
			Listeners.erase(WebSocket->GetConnection());
			Unique.Unlock();
			WebSocket->Next();
		}
		bool ServerNode::DispatchResponse(HTTP::Connection* Base, UPtr<Schema>&& Requests, UPtr<Schema>&& Responses, size_t Index, std::function<void(HTTP::Connection*, UPtr<Schema>&&)>&& Callback)
		{
			if (!Requests->Value.Is(VarType::Array))
			{
				auto* Array = Var::Set::Array();
				Array->Push(Requests.Reset());
				Requests = Array;
			}

		NextRequest:
			auto* Request = Index < Requests->Size() ? Requests->Get(Index++) : (Schema*)nullptr;
			if (!Request)
			{
				Callback(Base, std::move(Responses));
				return true;
			}

			auto* Version = Request->Get("jsonrpc");
			if (!Version || Version->Value.GetInteger() != 2)
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadVersion, "only version 2.0 is supported"));
				goto NextRequest;
			}

			auto* Method = Request->Get("method");
			if (!Method || !Method->Value.Is(VarType::String))
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "method is not a string"));
				goto NextRequest;
			}

			auto Context = Methods.find(Method->Value.GetBlob());
			if (Context == Methods.end())
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "method \"" + Method->Value.GetBlob() + "\" not found"));
				goto NextRequest;
			}

			if (HasAdminAuthorization() && Context->second.AccessTypes & (uint32_t)AccessType::A && Base->Request.User.Token != AdminToken)
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "admin level access required"));
				goto NextRequest;
			}
			else if (HasUserAuthorization() && Base->Request.User.Token != UserToken && Base->Request.User.Token != AdminToken)
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "user level access required"));
				goto NextRequest;
			}

			auto* Params = Request->Get("params");
			if (!Params || !Params->Value.Is(VarType::Array))
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "params is not an array"));
				goto NextRequest;
			}

			if (Params->Size() < Context->second.MinParams || Params->Size() > Context->second.MaxParams)
			{
				FormResponse(Base, Request, Responses, ServerResponse().Error(ErrorCodes::BadMethod, "params is not an array[" + ToString(Context->second.MinParams) + ".." + ToString(Context->second.MinParams) + "]"));
				goto NextRequest;
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
						break;
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

			auto* RequestsRef = Requests.Reset();
			auto* ResponsesRef = Responses.Reset();
			Cospawn([this, Base, RequestsRef, ResponsesRef, Index, Callback = std::move(Callback), Request, Context, Args = std::move(Args)]() mutable
			{
				UPtr<Schema> Requests = RequestsRef;
				UPtr<Schema> Responses = ResponsesRef;
				auto Response = Context->second.Function(Base, std::move(Args));
				FormResponse(Base, Request, Responses, std::move(Response));
				if (Index < Requests->Size())
					DispatchResponse(Base, std::move(Requests), std::move(Responses), Index, std::move(Callback));
				else
					Callback(Base, std::move(Responses));
			});
			return true;
		}
		void ServerNode::DispatchAcceptBlock(const uint256_t& Hash, const Ledger::Block& Block, const Ledger::BlockCheckpoint& Checkpoint)
		{
			UMutex<std::mutex> Unique(Mutex);
			if (Listeners.empty())
				return;

			OrderedSet<String> Addresses;
			for (auto& Transaction : Block.Transactions)
			{
				Addresses.insert(String((char*)Transaction.Receipt.From, sizeof(Algorithm::Pubkeyhash)));
				Transaction.Transaction->RecoverAlt(Transaction.Receipt, Addresses);
			}

			UnorderedSet<HTTP::WebSocketFrame*> WebSockets;
			for (auto& Listener : Listeners)
			{
				if (!Listener.first->WebSocket)
					continue;

				if (!Listener.second.Blocks)
				{
					bool Found = false;
					for (auto& Address : Listener.second.Addresses)
					{
						Found = Addresses.find(Address) != Addresses.end();
						if (Found)
							break;
					}
					if (Found)
						WebSockets.insert(Listener.first->WebSocket);
				}
				else
					WebSockets.insert(Listener.first->WebSocket);
			}

			Unique.Unlock();
			if (WebSockets.empty())
				return;

			Cospawn([Hash, WebSockets = std::move(WebSockets)]() mutable
			{
				auto Notification = Var::Set::Object();
				Notification->Set("type", Var::String("block"));
				Notification->Set("result", Var::String(Algorithm::Encoding::Encode0xHex256(Hash)));

				auto Response = Schema::ToJSON(*ServerResponse().Notification(Notification).Transform(nullptr));
				for (auto& WebSocket : WebSockets)
					WebSocket->Send(Response, HTTP::WebSocketOp::Text, nullptr);
			});
		}
		void ServerNode::DispatchAcceptTransaction(const uint256_t& Hash, const Ledger::Transaction* Transaction, const Algorithm::Pubkeyhash Owner)
		{
			UMutex<std::mutex> Unique(Mutex);
			if (Listeners.empty())
				return;

			String Address = String((char*)Owner, sizeof(Algorithm::Pubkeyhash));
			UnorderedSet<HTTP::WebSocketFrame*> WebSockets;
			for (auto& Listener : Listeners)
			{
				if (!Listener.first->WebSocket)
					continue;
				else if (Listener.second.Transactions || Listener.second.Addresses.find(Address) != Listener.second.Addresses.end())
					WebSockets.insert(Listener.first->WebSocket);
			}

			Unique.Unlock();
			if (WebSockets.empty())
				return;

			Cospawn([Hash, WebSockets = std::move(WebSockets)]() mutable
			{
				auto Notification = Var::Set::Object();
				Notification->Set("type", Var::String("transaction"));
				Notification->Set("result", Var::String(Algorithm::Encoding::Encode0xHex256(Hash)));

				auto Response = Schema::ToJSON(*ServerResponse().Notification(Notification).Transform(nullptr));
				for (auto& WebSocket : WebSockets)
					WebSocket->Send(Response, HTTP::WebSocketOp::Text, nullptr);
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
		ServerResponse ServerNode::WebSocketSubscribe(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Base->WebSocket)
				return ServerResponse().Error(ErrorCodes::BadRequest, "requires protocol upgrade");

			WsListener Listener;
			Listener.Blocks = Args.size() > 1 ? Args[1].AsBoolean() : false;
			Listener.Transactions = Args.size() > 2 ? Args[2].AsBoolean() : false;

			size_t AddressIndex = 0;
			for (auto& Address : Stringify::Split(Args[0].AsString(), ','))
			{
				Algorithm::Pubkeyhash Owner;
				if (!Algorithm::Signing::DecodeAddress(Address, Owner))
					return ServerResponse().Error(ErrorCodes::BadParams, "address[" + ToString(AddressIndex) + "] not valid");

				Listener.Addresses.insert(String((char*)Owner, sizeof(Owner)));
				++AddressIndex;
			}

			UMutex<std::mutex> Unique(Mutex);
			Listeners[Base] = std::move(Listener);
			Unique.Unlock();
			return ServerResponse().Success(Var::Set::Integer(AddressIndex + (Listener.Blocks || Listener.Transactions ? 1 : 0)));
		}
		ServerResponse ServerNode::WebSocketUnsubscribe(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Base->WebSocket)
				return ServerResponse().Error(ErrorCodes::BadRequest, "requires protocol upgrade");

			UMutex<std::mutex> Unique(Mutex);
			Listeners.erase(Base);
			Unique.Unlock();
			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::UtilityEncodeAddress(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Owner = Format::Util::Decode0xHex(Args[0].AsString());
			if (Owner.size() != sizeof(Algorithm::Pubkeyhash))
				return ServerResponse().Error(ErrorCodes::BadParams, "raw address not valid");

			String Address;
			Algorithm::Signing::EncodeAddress((uint8_t*)Owner.data(), Address);
			return ServerResponse().Success(Var::Set::String(Address));
		}
		ServerResponse ServerNode::UtilityDecodeAddress(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			return ServerResponse().Success(Var::Set::String(Format::Util::Encode0xHex(std::string_view((char*)Owner, sizeof(Owner)))));
		}
		ServerResponse ServerNode::UtilityDecodeMessage(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Format::Variables Values;
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			if (!Format::VariablesUtil::DeserializeFlatFrom(Message, &Values))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			return ServerResponse().Success(Format::VariablesUtil::Serialize(Values));
		}
		ServerResponse ServerNode::UtilityDecodeTransaction(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			Algorithm::Pubkeyhash Owner = { 0 }, Null = { 0 };
			bool Successful = CandidateTx->Recover(Owner);
			UPtr<Schema> Result = Var::Set::Object();
			Result->Set("transaction", CandidateTx->AsSchema().Reset());
			Result->Set("signer_address", Successful ? Algorithm::Signing::SerializeAddress(Owner) : Var::Set::Null());
			return ServerResponse().Success(std::move(Result));
		}
		ServerResponse ServerNode::UtilityHelp(HTTP::Connection* Base, Format::Variables&& Args)
		{
			UPtr<Schema> Data = Var::Set::Object();
			for (auto& Method : Methods)
			{
				String Inline;
				if (Method.second.AccessTypes & (uint32_t)AccessType::A)
					Inline += "private ";
				else
					Inline += "public ";

				if (Method.second.AccessTypes & (uint32_t)AccessType::R)
					Inline += "view ";

				Inline += "function ";
				Inline += Method.second.Domain + "::";
				Inline += Method.first;
				Inline += '(';
				Inline += Method.second.Args;
				if (Method.second.AccessTypes & (uint32_t)AccessType::W)
					Inline += ") returns ";
				else
					Inline += ") const returns ";

				if (!Method.second.Returns.empty())
				{
					if (Method.second.Returns.find('|') != std::string::npos)
					{
						Inline += '(';
						Inline += Method.second.Returns;
						Inline += ')';
					}
					else
						Inline += Method.second.Returns;
				}
				else
					Inline += "null";

				auto* Domain = Data->Get(Method.second.Domain);
				if (!Domain)
					Domain = Data->Set(Method.second.Domain, Var::Set::Array());

				auto* Description = Domain->Push(Var::Set::Object());
				Description->Set("function", Var::String(Method.first));
				Description->Set("declaration", Var::String(Inline));
				Description->Set("description", Var::String(Method.second.Description));
			}
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::BlockstateGetBlocks(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetBlockCheckpointHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetBlockCheckpointNumber(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetCheckpointBlockNumber();
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "checkpoint block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		ServerResponse ServerNode::BlockstateGetBlockTipHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockHeader = Chain.GetLatestBlockHeader();
			if (!BlockHeader)
				return ServerResponse().Error(ErrorCodes::NotFound, "tip block not found");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(BlockHeader->AsHash())));
		}
		ServerResponse ServerNode::BlockstateGetBlockTipNumber(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetLatestBlockNumber();
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "tip block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		ServerResponse ServerNode::BlockstateGetBlockByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetBlockByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetRawBlockByHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Block = Chain.GetBlockByHash(Hash);
			if (!Block)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Block->AsMessage().Encode()));
		}
		ServerResponse ServerNode::BlockstateGetRawBlockByNumber(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto Block = Chain.GetBlockByNumber(Number);
			if (!Block)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Block->AsMessage().Encode()));
		}
		ServerResponse ServerNode::BlockstateGetBlockProofByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetBlockProofByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::BlockstateGetBlockNumberByHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint64_t Number = Args[0].AsUint64();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockHash = Chain.GetBlockHashByNumber(Number);
			if (!BlockHash)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(*BlockHash)));
		}
		ServerResponse ServerNode::BlockstateGetBlockHashByNumber(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto BlockNumber = Chain.GetBlockNumberByHash(Hash);
			if (!BlockNumber)
				return ServerResponse().Error(ErrorCodes::NotFound, "block not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*BlockNumber));
		}
		ServerResponse ServerNode::TxnstateGetBlockTransactionsByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetBlockTransactionsByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetBlockReceiptsByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetBlockReceiptsByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetPendingTransactions(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetTransactionsByOwner(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "owner address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Direction = Args.size() > 3 ? Args[3].AsUint8() : 1;
			uint8_t Unrolling = Args.size() > 4 ? Args[4].AsUint8() : 0;
			auto Chain = Storages::Chainstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Direction >= 1 ? 1 : -1, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				return ServerResponse().Success(std::move(Data));
			}
			else if (Unrolling == 1)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Direction >= 1 ? 1 : -1, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Chain.GetBlockTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, Direction >= 1 ? 1 : -1, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item.AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		ServerResponse ServerNode::TxnstateGetTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::TxnstateGetRawTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Transaction = Chain.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success(Var::Set::String((*Transaction)->AsMessage().Encode()));
		}
		ServerResponse ServerNode::TxnstateGetReceiptByTransactionHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Chain = Storages::Chainstate(__func__);
			auto Receipt = Chain.GetReceiptByTransactionHash(Hash);
			if (!Receipt)
				return ServerResponse().Error(ErrorCodes::NotFound, "receipt not found");

			return ServerResponse().Success(Receipt->AsSchema());
		}
		ServerResponse ServerNode::ChainstateCall(Format::Variables&& Args, bool Tracing)
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
		ServerResponse ServerNode::ChainstateImmutableCall(HTTP::Connection* Base, Format::Variables&& Args)
		{
			return ChainstateCall(std::move(Args), false);
		}
		ServerResponse ServerNode::ChainstateTraceCall(HTTP::Connection* Base, Format::Variables&& Args)
		{
			return ChainstateCall(std::move(Args), true);
		}
		ServerResponse ServerNode::ChainstateGetBlockStatesByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetBlockStatesByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetBlockGasPriceByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetBlockGasPriceByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetBlockAssetPriceByHash(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetBlockAssetPriceByNumber(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ChainstateGetUniformByIndex(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Index = AsIndex(Args[0].AsString(), Args[1], Args.size() > 2 ? Args[2] : Format::Variable());
			if (!Index)
				return ServerResponse().Error(ErrorCodes::BadParams, "index not valid: " + Index.Error().Info);

			auto Chain = Storages::Chainstate(__func__);
			auto Uniform = Chain.GetUniformByIndex(nullptr, *Index, 0);
			if (!Uniform)
				return ServerResponse().Error(ErrorCodes::NotFound, "uniform not found");

			return ServerResponse().Success((*Uniform)->AsSchema());
		}
		ServerResponse ServerNode::ChainstateGetMultiformByComposition(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Column = AsColumn(Args[0].AsString(), Args[1]);
			if (!Column)
				return ServerResponse().Error(ErrorCodes::BadParams, "column not valid: " + Column.Error().Info);

			auto Row = AsRow(Args[0].AsString(), Args[2]);
			if (!Row)
				return ServerResponse().Error(ErrorCodes::BadParams, "row not valid: " + Row.Error().Info);

			auto Chain = Storages::Chainstate(__func__);
			auto Multiform = Chain.GetMultiformByComposition(nullptr, *Column, *Row, 0);
			if (!Multiform)
				return ServerResponse().Error(ErrorCodes::NotFound, "multiform not found");

			return ServerResponse().Success((*Multiform)->AsSchema());
		}
		ServerResponse ServerNode::ChainstateGetMultiformByColumn(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Column = AsColumn(Args[0].AsString(), Args[1]);
			if (!Column)
				return ServerResponse().Error(ErrorCodes::BadParams, "column not valid: " + Column.Error().Info);

			size_t Offset = Args.size() > 2 ? Args[2].AsUint64() : 0;
			auto Chain = Storages::Chainstate(__func__);
			auto Multiform = Chain.GetMultiformByColumn(nullptr, *Column, 0, Offset);
			if (!Multiform)
				return ServerResponse().Error(ErrorCodes::NotFound, "multiform not found");

			return ServerResponse().Success((*Multiform)->AsSchema());
		}
		ServerResponse ServerNode::ChainstateGetMultiformsByColumn(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Column = AsColumn(Args[0].AsString(), Args[1]);
			if (!Column)
				return ServerResponse().Error(ErrorCodes::BadParams, "column not valid: " + Column.Error().Info);

			uint64_t Offset = Args[2].AsUint64(), Count = Args[3].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByColumn(nullptr, *Column, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "multiform not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetMultiformByRow(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Row = AsRow(Args[0].AsString(), Args[1]);
			if (!Row)
				return ServerResponse().Error(ErrorCodes::BadParams, "row not valid: " + Row.Error().Info);

			size_t Offset = Args.size() > 2 ? Args[2].AsUint64() : 0;
			auto Chain = Storages::Chainstate(__func__);
			auto Multiform = Chain.GetMultiformByRow(nullptr, *Row, 0, Offset);
			if (!Multiform)
				return ServerResponse().Error(ErrorCodes::NotFound, "multiform not found");

			return ServerResponse().Success((*Multiform)->AsSchema());
		}
		ServerResponse ServerNode::ChainstateGetMultiformsByRow(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Row = AsRow(Args[0].AsString(), Args[1]);
			if (!Row)
				return ServerResponse().Error(ErrorCodes::BadParams, "row not valid: " + Row.Error().Info);

			uint64_t Offset = Args[5].AsUint64(), Count = Args[6].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Storages::FactorQuery::From(Args[2].AsString(), Args[3].AsDecimal().ToInt64(), Args[4].AsDecimal().ToInt8());
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, *Row, Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "multiform not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetMultiformsCountByRow(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Row = AsRow(Args[0].AsString(), Args[1]);
			if (!Row)
				return ServerResponse().Error(ErrorCodes::BadParams, "row not valid: " + Row.Error().Info);

			auto Factor = Storages::FactorQuery::From(Args[2].AsString(), Args[3].AsDecimal().ToInt64(), 0);
			auto Chain = Storages::Chainstate(__func__);
			auto Count = Chain.GetMultiformsCountByRow(*Row, Factor, 0);
			if (!Count)
				return ServerResponse().Error(ErrorCodes::NotFound, "count not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*Count));
		}
		ServerResponse ServerNode::ChainstateGetAccountSequence(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountSequence::AsInstanceIndex(Owner), 0);
			auto* Value = (States::AccountSequence*)(State ? **State : nullptr);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(Value ? Value->Sequence : 1));
		}
		ServerResponse ServerNode::ChainstateGetAccountWork(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(nullptr, States::AccountWork::AsInstanceColumn(Owner), States::AccountWork::AsInstanceRow(), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetBestAccountWorkers(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint64_t Commitment = Args[0].AsUint64();
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Commitment > 0 ? Storages::FactorQuery::GreaterEqual(Commitment - 1, -1) : Storages::FactorQuery::Equal(-1, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountWork::AsInstanceRow(), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetAccountObserver(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			if (!Algorithm::Signing::DecodeAddress(Args[1].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(nullptr, States::AccountObserver::AsInstanceColumn(Owner), States::AccountObserver::AsInstanceRow(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetBestAccountObservers(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Commitment = Args[1].AsUint64();
			uint64_t Offset = Args[2].AsUint64(), Count = Args[3].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Commitment > 0 ? Storages::FactorQuery::Equal((int64_t)Ledger::WorkStatus::Online, -1) : Storages::FactorQuery::LessEqual((int64_t)Ledger::WorkStatus::Standby, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountObserver::AsInstanceRow(Asset), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetAccountProgram(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountProgram::AsInstanceIndex(Owner), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetAccountStorage(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountStorage::AsInstanceIndex(Owner, Args[1].AsString()), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetAccountReward(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetMultiformByComposition(nullptr, States::AccountReward::AsInstanceColumn(Owner), States::AccountReward::AsInstanceRow(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetAccountRewards(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByColumn(nullptr, States::AccountReward::AsInstanceColumn(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetBestAccountRewards(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Storages::FactorQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountReward::AsInstanceRow(Asset), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetBestAccountRewardsWithContributions(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Storages::FactorQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountReward::AsInstanceRow(Asset), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			auto AssetStride = States::AccountContribution::AsInstanceRow(Asset);
			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
			{
				auto* ParentState = (States::AccountReward*)*Item;
				auto ChildState = Chain.GetMultiformByComposition(nullptr, States::AccountContribution::AsInstanceColumn(ParentState->Owner), AssetStride, 0);
				auto* Next = Data->Push(Var::Set::Object());
				Next->Set("contribution", ChildState ? (*ChildState)->AsSchema().Reset() : Var::Set::Null());
				Next->Set("reward", ParentState->AsSchema().Reset());
			}
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetAccountDerivation(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountDerivation::AsInstanceIndex(Owner, Asset), 0);
			auto* Value = (States::AccountDerivation*)(State ? **State : nullptr);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(Value ? Value->MaxAddressIndex : Protocol::Now().Account.RootAddressIndex));
		}
		ServerResponse ServerNode::ChainstateGetAccountBalance(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetMultiformByComposition(nullptr, States::AccountBalance::AsInstanceColumn(Owner), States::AccountBalance::AsInstanceRow(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetAccountBalances(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByColumn(nullptr, States::AccountBalance::AsInstanceColumn(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetAccountContribution(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto State = Chain.GetMultiformByComposition(nullptr, States::AccountContribution::AsInstanceColumn(Owner), States::AccountContribution::AsInstanceRow(Asset), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetAccountContributions(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByColumn(nullptr, States::AccountContribution::AsInstanceColumn(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetBestAccountContributions(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Storages::FactorQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountContribution::AsInstanceRow(Asset), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetBestAccountContributionsWithRewards(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Factor = Storages::FactorQuery::GreaterEqual(0, -1);
			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByRow(nullptr, States::AccountContribution::AsInstanceRow(Asset), Factor, 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			auto AssetStride = States::AccountReward::AsInstanceRow(Asset);
			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
			{
				auto* ParentState = (States::AccountContribution*)*Item;
				auto ChildState = Chain.GetMultiformByComposition(nullptr, States::AccountReward::AsInstanceColumn(ParentState->Owner), AssetStride, 0);
				auto* Next = Data->Push(Var::Set::Object());
				Next->Set("contribution", ParentState->AsSchema().Reset());
				Next->Set("reward", ChildState ? (*ChildState)->AsSchema().Reset() : Var::Set::Null());
			}
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetWitnessProgram(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::WitnessProgram::AsInstanceIndex(Args[0].AsString()), 0);
			if (!State)
				return ServerResponse().Success(Var::Set::Null());

			auto Code = ((States::WitnessProgram*)(**State))->AsCode();
			auto* Data = (*State)->AsSchema().Reset();
			Data->Set("storage", Code ? Var::String(*Code) : Var::Null());
			return ServerResponse().Success(Data);
		}
		ServerResponse ServerNode::ChainstateGetWitnessEvent(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::WitnessEvent::AsInstanceIndex(Args[0].AsUint256()), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetWitnessAddress(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			auto Asset = Algorithm::Asset::IdOfHandle(Args[1].AsString());
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetMultiformByComposition(nullptr, States::WitnessAddress::AsInstanceColumn(Owner), States::WitnessAddress::AsInstanceRow(Asset, Args[2].AsString(), Args.size() > 3 ? Args[3].AsUint64() : Protocol::Now().Account.RootAddressIndex), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::ChainstateGetWitnessAddresses(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "account address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			auto Chain = Storages::Chainstate(__func__);
			auto List = Chain.GetMultiformsByColumn(nullptr, States::WitnessAddress::AsInstanceColumn(Owner), 0, Offset, Count);
			if (!List)
				return ServerResponse().Error(ErrorCodes::NotFound, "data not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Item : *List)
				Data->Push(Item->AsSchema().Reset());
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ChainstateGetWitnessTransaction(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::WitnessTransaction::AsInstanceIndex(Asset, Args[1].AsString()), 0);
			return ServerResponse().Success(State ? (*State)->AsSchema().Reset() : Var::Set::Null());
		}
		ServerResponse ServerNode::MempoolstateAddNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
			if (!Endpoint.IsValid())
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.ApplyTrialAddress(Endpoint.Address);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::MempoolstateClearNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
			if (!Endpoint.IsValid())
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.ClearValidator(Endpoint.Address);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::MempoolstateGetClosestNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			size_t Offset = Args.size() > 0 ? Args[0].AsUint64() : 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Validator = Mempool.GetValidatorByPreference(Offset);
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Validator->AsSchema().Reset());
		}
		ServerResponse ServerNode::MempoolstateGetClosestNodeCounter(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Count = Mempool.GetValidatorsCount();
			if (!Count)
				return ServerResponse().Error(ErrorCodes::BadRequest, "count not found");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(*Count));
		}
		ServerResponse ServerNode::MempoolstateGetNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
			if (!Endpoint.IsValid())
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Validator = Mempool.GetValidatorByAddress(Endpoint.Address);
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Validator->AsSchema().Reset());
		}
		ServerResponse ServerNode::MempoolstateGetAddresses(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint64_t Offset = Args[0].AsUint64(), Count = Args[1].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.CursorSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint32_t Services = 0;
			if (Args.size() > 2)
			{
				for (auto& Service : Stringify::Split(Args[2].AsString(), ','))
				{
					Service = Stringify::Trim(Service);
					if (Service == "consensus")
						Services |= (uint32_t)Storages::NodeServices::Consensus;
					else if (Service == "discovery")
						Services |= (uint32_t)Storages::NodeServices::Discovery;
					else if (Service == "interface")
						Services |= (uint32_t)Storages::NodeServices::Interface;
					else if (Service == "proposer")
						Services |= (uint32_t)Storages::NodeServices::Proposer;
					else if (Service == "public")
						Services |= (uint32_t)Storages::NodeServices::Public;
					else if (Service == "streaming")
						Services |= (uint32_t)Storages::NodeServices::Streaming;
				}
			}

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Seeds = Mempool.GetValidatorAddresses(Offset, Count, Services);
			if (!Seeds)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Seed : *Seeds)
				Data->Push(Var::String(Algorithm::Endpoint::ToURI(Seed)));
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::MempoolstateGetGasPrice(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::AssetId Asset = Algorithm::Asset::IdOfHandle(Args[0].AsString());
			double Percentile = Args.size() > 1 ? Args[1].AsDouble() : 0.50;
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Price = Mempool.GetGasPrice(Asset, Percentile);
			if (!Price)
			{
				auto Chain = Storages::Chainstate(__func__);
				auto Number = Chain.GetLatestBlockNumber();
				if (!Number)
					return ServerResponse().Error(ErrorCodes::NotFound, "gas price not found");

				Price = Chain.GetBlockGasPrice(*Number, Asset, Percentile);
				if (!Price)
					return ServerResponse().Error(ErrorCodes::NotFound, "gas price not found");
			}

			return ServerResponse().Success(Var::Set::Decimal(*Price));
		}
		ServerResponse ServerNode::MempoolstateGetAssetPrice(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::MempoolstateGetEstimateTransactionGas(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(CandidateTx->GetGasEstimate()));
		}
		ServerResponse ServerNode::MempoolstateGetOptimalTransactionGas(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Format::Stream Message = Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!CandidateTx || !CandidateTx->Load(Message))
				return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");

			CandidateTx->SetOptimalGas(CandidateTx->GasPrice);
			return ServerResponse().Success(Algorithm::Encoding::SerializeUint256(CandidateTx->GasLimit));
		}
		ServerResponse ServerNode::MempoolstateSubmitTransaction(HTTP::Connection* Base, Format::Variables&& Args, Ledger::Transaction* Prebuilt)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			Format::Stream Message = Prebuilt ? Format::Stream() : Format::Stream::Decode(Args[0].AsBlob());
			UPtr<Ledger::Transaction> CandidateTx = Prebuilt ? Prebuilt : Transactions::Resolver::New(Messages::Authentic::ResolveType(Message).Or(0));
			if (!Prebuilt)
			{
				if (!CandidateTx || !CandidateTx->Load(Message))
					return ServerResponse().Error(ErrorCodes::BadParams, "invalid message");
			}

			auto CandidateHash = CandidateTx->AsHash();
			auto DeepValidation = (Args.size() > 1 ? Args[1].AsBoolean() : false);
			auto Status = Validator->AcceptTransaction(nullptr, std::move(CandidateTx), DeepValidation);
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::String(Algorithm::Encoding::Encode0xHex256(CandidateHash)));
		}
		ServerResponse ServerNode::MempoolstateRejectTransaction(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Status = Mempool.RemoveTransactions(Vector<uint256_t>({ Hash }));
			if (!Status)
				return ServerResponse().Error(ErrorCodes::BadRequest, Status.Error().Info);

			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::MempoolstateGetTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Transaction = Mempool.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success((*Transaction)->AsSchema());
		}
		ServerResponse ServerNode::MempoolstateGetRawTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint256_t Hash = Args[0].AsUint256();
			auto Mempool = Storages::Mempoolstate(__func__);
			auto Transaction = Mempool.GetTransactionByHash(Hash);
			if (!Transaction)
				return ServerResponse().Error(ErrorCodes::NotFound, "transaction not found");

			return ServerResponse().Success(Var::Set::String((*Transaction)->AsMessage().Encode()));
		}
		ServerResponse ServerNode::MempoolstateGetNextAccountSequence(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "owner address not valid");

			auto Mempool = Storages::Mempoolstate(__func__);
			auto Chain = Storages::Chainstate(__func__);
			auto State = Chain.GetUniformByIndex(nullptr, States::AccountSequence::AsInstanceIndex(Owner), 0);
			auto* Value = (States::AccountSequence*)(State ? **State : nullptr);
			auto Lowest = Mempool.GetLowestTransactionSequence(Owner);
			auto Highest = Mempool.GetHighestTransactionSequence(Owner);
			if (!Lowest)
				Lowest = Value ? Value->Sequence : 1;
			if (!Highest)
				Highest = Value ? Value->Sequence : 1;
			else if (Value != nullptr && *Highest < Value->Sequence)
				Highest = Value->Sequence;
			else
				Highest = *Highest + 1;

			UPtr<Schema> Data = Var::Set::Object();
			Data->Set("min", Algorithm::Encoding::SerializeUint256(*Lowest));
			Data->Set("max", Algorithm::Encoding::SerializeUint256(*Highest));
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::MempoolstateGetTransactions(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::MempoolstateGetTransactionsByOwner(HTTP::Connection* Base, Format::Variables&& Args)
		{
			Algorithm::Pubkeyhash Owner;
			if (!Algorithm::Signing::DecodeAddress(Args[0].AsString(), Owner))
				return ServerResponse().Error(ErrorCodes::BadParams, "owner address not valid");

			uint64_t Offset = Args[1].AsUint64(), Count = Args[2].AsUint64();
			if (!Count || Count > Protocol::Now().User.RPC.PageSize)
				return ServerResponse().Error(ErrorCodes::BadParams, "count not valid");

			uint8_t Direction = Args.size() > 3 ? Args[3].AsUint8() : 1;
			uint8_t Unrolling = Args.size() > 4 ? Args[4].AsUint8() : 0;
			auto Mempool = Storages::Mempoolstate(__func__);
			if (Unrolling == 0)
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetTransactionsByOwner(Owner, Direction >= 1 ? 1 : -1, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				return ServerResponse().Success(std::move(Data));
			}
			else
			{
				UPtr<Schema> Data = Var::Set::Array();
				auto List = Mempool.GetTransactionsByOwner(Owner, Direction >= 1 ? 1 : -1, Offset, Count);
				if (!List)
					return ServerResponse().Error(ErrorCodes::NotFound, "transactions not found");

				for (auto& Item : *List)
					Data->Push(Item->AsSchema().Reset());
				return ServerResponse().Success(std::move(Data));
			}
		}
		ServerResponse ServerNode::MempoolstateGetCumulativeEventTransactions(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ValidatorstatePrune(HTTP::Connection* Base, Format::Variables&& Args)
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
		ServerResponse ServerNode::ValidatorstateVerify(HTTP::Connection* Base, Format::Variables&& Args)
		{
			uint64_t Count = Args[1].AsUint64();
			uint64_t CurrentNumber = Args[0].AsUint64();
			uint64_t TargetNumber = CurrentNumber + Count;
			bool Validate = Args.size() > 2 ? Args[2].AsBoolean() : false;
			auto Chain = Storages::Chainstate(__func__);
			auto CheckpointNumber = Chain.GetCheckpointBlockNumber().Or(0);
			auto TipNumber = Chain.GetLatestBlockNumber().Or(0);
			auto ParentBlock = CurrentNumber > 1 ? Chain.GetBlockHeaderByNumber(CurrentNumber - 1) : ExpectsLR<Ledger::BlockHeader>(LayerException());
			UPtr<Schema> Data = Var::Set::Array();
			while (CurrentNumber < TargetNumber)
			{
				auto Next = Chain.GetBlockByNumber(CurrentNumber);
				if (!Next)
				{
					if (CurrentNumber > TipNumber)
						break;

					return ServerResponse().Error(ErrorCodes::NotFound, "block " + ToString(CurrentNumber) + (CheckpointNumber >= CurrentNumber ? " verification failed: block data pruned" : " verification failed: block not found"));
				}

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
		ServerResponse ServerNode::ValidatorstateAcceptNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			if (!Args.empty())
			{
				auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
				if (!Endpoint.IsValid())
					return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

				if (!Validator->Accept(Endpoint.Address))
					return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");
			}
			else if (!Validator->Accept())
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::ValidatorstateRejectNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
			if (!Endpoint.IsValid())
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			auto* Node = Validator->Find(Endpoint.Address);
			if (!Node || Node == (P2P::Relay*)Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			auto* User = Node->AsUser<Ledger::Validator>();
			Validator->Reject(Node);
			return ServerResponse().Success(Var::Set::Null());
		}
		ServerResponse ServerNode::ValidatorstateGetNode(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			auto Endpoint = Algorithm::Endpoint(Args[0].AsString());
			if (!Endpoint.IsValid())
				return ServerResponse().Error(ErrorCodes::BadParams, "address not valid");

			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			auto* Node = Validator->Find(Endpoint.Address);
			if (!Node || Node == (P2P::Relay*)Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "node not found");

			auto* User = Node->AsUser<Ledger::Validator>();
			auto Data = User->AsSchema();
			Data->Set("network", Node->AsSchema().Reset());
			return ServerResponse().Success(Data.Reset());
		}
		ServerResponse ServerNode::ValidatorstateGetBlockchains(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Oracle::Datamaster::IsInitialized())
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			UPtr<Schema> Data = Var::Set::Array();
			for (auto& Asset : Oracle::Datamaster::GetChains())
			{
				auto* Next = Data->Push(Algorithm::Asset::Serialize(Asset.first));
				Next->Set("divisibility", Var::Decimal(Asset.second.Divisibility));
				Next->Set("sync_latency", Var::Integer(Asset.second.SyncLatency));
				switch (Asset.second.Composition)
				{
					case Algorithm::Composition::Type::ED25519:
						Next->Set("composition_policy", Var::String("ed25519"));
						break;
					case Algorithm::Composition::Type::SECP256K1:
						Next->Set("composition_policy", Var::String("secp256k1"));
						break;
					default:
						Next->Set("composition_policy", Var::Null());
						break;
				}
				switch (Asset.second.Routing)
				{
					case Tangent::Oracle::RoutingPolicy::Account:
						Next->Set("routing_policy", Var::String("account"));
						break;
					case Tangent::Oracle::RoutingPolicy::Memo:
						Next->Set("routing_policy", Var::String("memo"));
						break;
					case Tangent::Oracle::RoutingPolicy::UTXO:
						Next->Set("routing_policy", Var::String("utxo"));
						break;
					default:
						Next->Set("routing_policy", Var::Null());
						break;
				}

				auto* Supports = Next->Set("supports");
				Supports->Set("token_transfer", Var::String(Asset.second.SupportsTokenTransfer));
				Supports->Set("bulk_transfer", Var::Boolean(Asset.second.SupportsBulkTransfer));
			}
			return ServerResponse().Success(std::move(Data));
		}
		ServerResponse ServerNode::ValidatorstateStatus(HTTP::Connection* Base, Format::Variables&& Args)
		{
			if (!Validator)
				return ServerResponse().Error(ErrorCodes::BadRequest, "validator node disabled");

			auto Chain = Storages::Chainstate(__func__);
			auto BlockHeader = Chain.GetLatestBlockHeader();
			UMutex<std::recursive_mutex> Unique(Validator->GetMutex());
			UPtr<Schema> Data = Var::Set::Object();
			if (Protocol::Now().User.P2P.Server)
			{
				auto* P2P = Data->Set("p2p", Var::Set::Object());
				P2P->Set("port", Var::Integer(Protocol::Now().User.P2P.Port));
				P2P->Set("time_offset", Var::Integer(Protocol::Now().User.P2P.TimeOffset));
				P2P->Set("cursor_size", Var::Integer(Protocol::Now().User.P2P.CursorSize));
				P2P->Set("max_inbound_connection", Var::Integer(Protocol::Now().User.P2P.MaxInboundConnections));
				P2P->Set("max_outbound_connection", Var::Integer(Protocol::Now().User.P2P.MaxOutboundConnections));
				P2P->Set("proposer", Var::Boolean(Protocol::Now().User.P2P.Proposer));
			}

			if (Protocol::Now().User.RPC.Server)
			{
				auto* RPC = Data->Set("rpc", Var::Set::Object());
				RPC->Set("port", Var::Integer(Protocol::Now().User.RPC.Port));
				RPC->Set("admin_restriction", Var::Boolean(!Protocol::Now().User.RPC.AdminUsername.empty()));
				RPC->Set("user_restriction", Var::Boolean(!Protocol::Now().User.RPC.UserUsername.empty()));
				RPC->Set("cursor_size", Var::Integer(Protocol::Now().User.RPC.CursorSize));
				RPC->Set("page_size", Var::Integer(Protocol::Now().User.RPC.PageSize));
				RPC->Set("websockets", Var::Boolean(Protocol::Now().User.RPC.WebSockets));
			}

			if (Protocol::Now().User.NDS.Server)
			{
				auto* NDS = Data->Set("nds", Var::Set::Object());
				NDS->Set("port", Var::Integer(Protocol::Now().User.NDS.Port));
				NDS->Set("cursor_size", Var::Integer(Protocol::Now().User.NDS.CursorSize));
			}

			if (Protocol::Now().User.Oracle.Observer)
			{
				auto* Observer = Data->Set("oracle", Var::Set::Object());
				Observer->Set("block_relay_multiplier", Var::Integer(Protocol::Now().User.Oracle.BlockReplayMultiplier));
				Observer->Set("relaying_timeout", Var::Integer(Protocol::Now().User.Oracle.RelayingTimeout));
				Observer->Set("relaying_retry_timeout", Var::Integer(Protocol::Now().User.Oracle.RelayingRetryTimeout));
				Observer->Set("fee_estimation_seconds", Var::Integer(Protocol::Now().User.Oracle.FeeEstimationSeconds));
				Observer->Set("withdrawal_time", Var::Integer(Protocol::Now().User.Oracle.WithdrawalTime));
				if (Oracle::Datamaster::IsInitialized())
				{
					auto Array = Observer->Set("nodes", Var::Set::Array());
					for (auto& Asset : Oracle::Datamaster::GetAssets())
						Array->Push(Algorithm::Asset::Serialize(Asset));
				}
			}

			auto* TCP = Data->Set("tcp", Var::Set::Object());
			TCP->Set("timeout", Var::Integer(Protocol::Now().User.TCP.Timeout));

			auto* Storage = Data->Set("storage", Var::Set::Object());
			Storage->Set("checkpoint_size", Var::Integer(Protocol::Now().User.Storage.CheckpointSize));
			Storage->Set("transaction_to_account_index", Var::Boolean(Protocol::Now().User.Storage.TransactionToAccountIndex));
			Storage->Set("transaction_to_rollup_index", Var::Boolean(Protocol::Now().User.Storage.TransactionToRollupIndex));
			Storage->Set("full_block_history", Var::Boolean(Protocol::Now().User.Storage.FullBlockHistory));

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
				auto* User = Node.second->AsUser<Ledger::Validator>();
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

			switch (Protocol::Now().User.Network)
			{
				case NetworkType::Mainnet:
					Data->Set("network", Var::Set::String("mainnet"));
					break;
				case NetworkType::Testnet:
					Data->Set("network", Var::Set::String("testnet"));
					break;
				case NetworkType::Regtest:
					Data->Set("network", Var::Set::String("regtest"));
					break;
				default:
					Data->Set("network", Var::Set::String("unspecified"));
					break;
			}

			Data->Set("version", Var::String(Algorithm::Encoding::Encode0xHex128(Protocol::Now().Message.ProtocolVersion)));
			Data->Set("checkpoint", Algorithm::Encoding::SerializeUint256(Chain.GetCheckpointBlockNumber().Or(0)));
			return ServerResponse().Success(Data.Reset());
		}
	}
}