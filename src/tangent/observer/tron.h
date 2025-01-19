#ifndef TAN_OBSERVER_TRON_H
#define TAN_OBSERVER_TRON_H
#include "ethereum.h"

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			class Tron : public Ethereum
			{
			public:
				struct TrxTxBlockHeaderInfo
				{
					String RefBlockBytes;
					String RefBlockHash;
					int64_t Expiration;
					int64_t Timestamp;
				};

			public:
				class TrxNdCall
				{
				public:
					static const char* BroadcastTransaction();
					static const char* GetBlock();
				};

			public:
				Tron() noexcept;
				virtual ~Tron() override = default;
				virtual Promise<ExpectsLR<void>> BroadcastTransaction(const Algorithm::AssetId& Asset, const OutgoingTransaction& TxData) override;
				virtual Promise<ExpectsLR<Decimal>> CalculateBalance(const Algorithm::AssetId& Asset, const DynamicWallet& Seed, Option<String>&& Address) override;
				virtual Promise<ExpectsLR<OutgoingTransaction>> NewTransaction(const Algorithm::AssetId& Asset, const DynamicWallet& Wallet, const Vector<Transferer>& To, const BaseFee& Fee) override;
				virtual ExpectsLR<String> NewPublicKeyHash(const std::string_view& Address) override;
				virtual ExpectsLR<void> VerifyNodeCompatibility(Nodemaster* Node) override;
				virtual String GetMessageMagic() override;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const btc_chainparams_* GetChain() override;

			public:
				virtual Promise<ExpectsLR<TrxTxBlockHeaderInfo>> GetBlockHeaderForTx(const Algorithm::AssetId& Asset);
				virtual void GenerateMessageHash(const String& Input, uint8_t Output[32]);
				virtual String EncodeEthAddress(const std::string_view& EthAddress) override;
				virtual String DecodeNonEthAddress(const std::string_view& NonEthAddress) override;
				virtual String DecodeNonEthAddressPf(const std::string_view& NonEthAddress);
				virtual Decimal GetDivisibilityGwei() override;
			};
		}
	}
}
#endif