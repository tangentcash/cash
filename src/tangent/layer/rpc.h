#ifndef TAN_LAYER_RPC_H
#define TAN_LAYER_RPC_H
#include "format.h"
#include "control.h"

namespace Tangent
{
	namespace P2P
	{
		class ServerNode;
	}

	namespace RPC
	{
		using ServerFunction = std::function<Promise<struct ServerResponse>(Format::Variables&&)>;

		enum class AccessLevel
		{
			User,
			Admin
		};

		enum class ErrorCodes
		{
			OK,
			BadRequest,
			BadVersion,
			BadMethod,
			BadParams,
			NotFound
		};

		struct ServerResponse
		{
			UPtr<Schema> Data;
			String ErrorMessage;
			ErrorCodes ErrorCode = ErrorCodes::OK;

			ServerResponse&& Success(UPtr<Schema>&& Value);
			ServerResponse&& Error(ErrorCodes Code, const std::string_view& Message);
			UPtr<Schema> Transform(Schema* Request);
		};

		struct ServerRequest
		{
			AccessLevel Level;
			size_t MinParams = 0;
			size_t MaxParams = 0;
			ServerFunction Function;
			String Description;
			String Args;
			String Domain;
		};

		class ServerNode : public Reference<ServerNode>
		{
		private:
			UnorderedMap<String, ServerRequest> Methods;

		protected:
			SystemControl ControlSys;
			UPtr<HTTP::Server> Node;
			P2P::ServerNode* Validator;
			String AdminToken;
			String UserToken;

		public:
			ServerNode(P2P::ServerNode* NewValidator) noexcept;
			~ServerNode() noexcept;
			void Startup();
			void Shutdown();
			void Bind(AccessLevel Level, const std::string_view& Domain, const std::string_view& Method, size_t MinParams, size_t MaxParams, const std::string_view& Args, const std::string_view& Description, ServerFunction&& Function);
			bool HasAdminAuthorization();
			bool HasUserAuthorization();
			bool IsActive();
			ServiceControl::ServiceNode GetEntrypoint();

		private:
			bool Authorize(HTTP::Connection* Base, HTTP::Credentials* Credentials);
			bool Dispatch(HTTP::Connection* Base);
			Promise<ServerResponse> UtilityEncodeAddress(Format::Variables&& Args);
			Promise<ServerResponse> UtilityDecodeAddress(Format::Variables&& Args);
			Promise<ServerResponse> UtilityDecodeMessage(Format::Variables&& Args);
			Promise<ServerResponse> UtilityHelp(Format::Variables&& Args);
			Promise<ServerResponse> ChainstatePrune(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateVerify(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateCall(Format::Variables&& Args, bool Tracing);
			Promise<ServerResponse> ChainstateImmutableCall(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateTraceCall(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlocks(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockCheckpointHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockCheckpointNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockTipHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockTipNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetRawBlockByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetRawBlockByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockTransactionsByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockTransactionsByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockReceiptsByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockReceiptsByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockStatesByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockStatesByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockProofByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockProofByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockNumberByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockHashByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockGasPriceByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockGasPriceByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockAssetPriceByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBlockAssetPriceByNumber(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetPendingTransactions(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetTransactionsByOwner(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetTransactionByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetTransactionByReceiptHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetRawTransactionByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetRawTransactionByReceiptHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetReceiptByHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetReceiptByTransactionHash(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStateByComposition(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStateByAddress(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStatesByAddress(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStateByStride(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStatesByStride(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetStatesCountByStride(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountSequence(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountWork(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBestAccountWorkers(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountProgram(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountStorage(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountReward(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountRewards(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBestAccountRewards(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountDerivation(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountDerivations(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountBalance(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountBalances(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountContribution(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetAccountContributions(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetBestAccountContributions(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetWitnessProgram(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetWitnessEvent(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetWitnessAddress(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetWitnessAddresses(Format::Variables&& Args);
			Promise<ServerResponse> ChainstateGetWitnessTransaction(Format::Variables&& Args);
			Promise<ServerResponse> MempoolAddNode(Format::Variables&& Args);
			Promise<ServerResponse> MempoolClearNode(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetClosestNode(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetClosestNodeCounter(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetNode(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetSeeds(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetGasPrice(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetAssetPrice(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetOptimalTransactionGas(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetEstimateTransactionGas(Format::Variables&& Args);
			Promise<ServerResponse> MempoolAcceptTransaction(Format::Variables&& Args);
			Promise<ServerResponse> MempoolRejectTransaction(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetTransactionByHash(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetRawTransactionByHash(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetTransactionSequence(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetTransactions(Format::Variables&& Args);
			Promise<ServerResponse> MempoolGetCumulativeEventTransactions(Format::Variables&& Args);
			Promise<ServerResponse> ValidatorAcceptNode(Format::Variables&& Args);
			Promise<ServerResponse> ValidatorRejectNode(Format::Variables&& Args);
			Promise<ServerResponse> ValidatorGetNode(Format::Variables&& Args);
			Promise<ServerResponse> ValidatorStatus(Format::Variables&& Args);
		};	
	}
}
#endif