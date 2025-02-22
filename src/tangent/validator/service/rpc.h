#ifndef TAN_LAYER_RPC_H
#define TAN_LAYER_RPC_H
#include "../../layer/format.h"
#include "../../layer/control.h"
#include "../../kernel/block.h"

namespace Tangent
{
	namespace P2P
	{
		class ServerNode;
	}

	namespace RPC
	{
		using ServerFunction = std::function<struct ServerResponse(HTTP::Connection*, Format::Variables&&)>;

		enum class AccessType
		{
			R = (1 << 0),
			W = (1 << 1),
			A = (1 << 2)
		};

		enum class ErrorCodes
		{
			Response = 0,
			Notification = 1,
			BadRequest = -1,
			BadVersion = -2,
			BadMethod = -3,
			BadParams = -4,
			NotFound = -5
		};

		inline uint32_t operator |(AccessType A, AccessType B)
		{
			return static_cast<uint32_t>(A) | static_cast<uint32_t>(B);
		}
		inline uint32_t operator |(uint32_t, AccessType A)
		{
			return static_cast<uint32_t>(A);
		}

		struct TAN_OUT ServerResponse
		{
			UPtr<Schema> Data;
			String ErrorMessage;
			ErrorCodes Status = ErrorCodes::Response;

			ServerResponse&& Success(UPtr<Schema>&& Value);
			ServerResponse&& Notification(UPtr<Schema>&& Value);
			ServerResponse&& Error(ErrorCodes Code, const std::string_view& Message);
			UPtr<Schema> Transform(Schema* Request);
		};

		struct TAN_OUT ServerRequest
		{
			uint32_t AccessTypes = 0;
			size_t MinParams = 0;
			size_t MaxParams = 0;
			ServerFunction Function;
			String Description;
			String Args;
			String Domain;
			String Returns;
		};

		class TAN_OUT ServerNode : public Reference<ServerNode>
		{
		private:
			struct WsListener
			{
				UnorderedSet<String> Addresses;
				bool Transactions = false;
				bool Blocks = false;
			};

		private:
			UnorderedMap<HTTP::Connection*, WsListener> Listeners;
			UnorderedMap<String, ServerRequest> Methods;
			std::mutex Mutex;

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
			void Bind(uint32_t AccessTypes, const std::string_view& Domain, const std::string_view& Method, size_t MinParams, size_t MaxParams, const std::string_view& Args, const std::string_view& Returns, const std::string_view& Description, ServerFunction&& Function);
			bool HasAdminAuthorization();
			bool HasUserAuthorization();
			bool IsActive();
			ServiceControl::ServiceNode GetEntrypoint();

		private:
			bool Authorize(HTTP::Connection* Base, HTTP::Credentials* Credentials);
			bool Headers(HTTP::Connection* Base, String& Content);
			bool Options(HTTP::Connection* Base);
			bool HttpRequest(HTTP::Connection* Base);
			bool WsReceive(HTTP::WebSocketFrame* WebSocket, HTTP::WebSocketOp Opcode, const std::string_view& Buffer);
			void WsDisconnect(HTTP::WebSocketFrame* WebSocket);
			bool DispatchResponse(HTTP::Connection* Base, UPtr<Schema>&& Requests, UPtr<Schema>&& Responses, size_t Index, std::function<void(HTTP::Connection*, UPtr<Schema>&&)>&& Callback);
			void DispatchAcceptBlock(const uint256_t& Hash, const Ledger::Block& Block, const Ledger::BlockCheckpoint& Checkpoint);
			void DispatchAcceptTransaction(const uint256_t& Hash, const Ledger::Transaction* Transaction, const Algorithm::Pubkeyhash Owner);
			ServerResponse WebSocketSubscribe(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse WebSocketUnsubscribe(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse UtilityEncodeAddress(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse UtilityDecodeAddress(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse UtilityDecodeMessage(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse UtilityDecodeTransaction(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse UtilityHelp(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlocks(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockCheckpointHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockCheckpointNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockTipHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockTipNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetRawBlockByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetRawBlockByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockProofByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockProofByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockNumberByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse BlockstateGetBlockHashByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetBlockTransactionsByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetBlockTransactionsByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetBlockReceiptsByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetBlockReceiptsByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetPendingTransactions(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetTransactionsByOwner(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetRawTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse TxnstateGetReceiptByTransactionHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateCall(Format::Variables&& Args, bool Tracing);
			ServerResponse ChainstateImmutableCall(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateTraceCall(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockStatesByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockStatesByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockGasPriceByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockGasPriceByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockAssetPriceByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBlockAssetPriceByNumber(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetUniformByIndex(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformByComposition(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformByColumn(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformsByColumn(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformByRow(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformsByRow(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetMultiformsCountByRow(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountSequence(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountWork(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountWorkers(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountObserver(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountObservers(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountObservers(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountProgram(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountStorage(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountReward(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountRewards(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountRewards(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountRewardsForSelection(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountDerivation(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountBalance(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountBalances(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountDepository(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetAccountDepositories(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountDepositories(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetBestAccountDepositoriesForSelection(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessProgram(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessEvent(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessAddress(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessAddresses(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessAddressesByPurpose(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ChainstateGetWitnessTransaction(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateAddNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateClearNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetClosestNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetClosestNodeCounter(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetAddresses(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetGasPrice(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetAssetPrice(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetOptimalTransactionGas(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetEstimateTransactionGas(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateSubmitTransaction(HTTP::Connection* Base, Format::Variables&& Args, Ledger::Transaction* Prebuilt);
			ServerResponse MempoolstateRejectTransaction(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetRawTransactionByHash(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetNextAccountSequence(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetTransactions(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetTransactionsByOwner(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetCumulativeEventTransactions(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse MempoolstateGetCumulativeConsensus(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstatePrune(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateRevert(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateReorganize(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateVerify(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateAcceptNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateRejectNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateGetNode(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateGetBlockchains(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ValidatorstateStatus(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitBlock(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitCommitmentTransaction(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitContributionAllocation(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitContributionDeallocation(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitContributionWithdrawal(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitDepositoryAdjustment(HTTP::Connection* Base, Format::Variables&& Args);
			ServerResponse ProposerstateSubmitDepositoryMigration(HTTP::Connection* Base, Format::Variables&& Args);
		};	
	}
}
#endif