#ifndef TAN_ORACLE_FORKS_ETHEREUM_H
#define TAN_ORACLE_FORKS_ETHEREUM_H
#include "../ethereum.h"

namespace Tangent
{
    namespace Oracle
    {
        namespace Chains
        {
            class Arbitrum : public Ethereum
            {
            public:
                Arbitrum() noexcept = default;
                virtual ~Arbitrum() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Avalanche : public Ethereum
            {
            public:
                Avalanche() noexcept = default;
                virtual ~Avalanche() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class BinanceSmartChain : public Ethereum
            {
            public:
                BinanceSmartChain() noexcept = default;
                virtual ~BinanceSmartChain() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Celo : public Ethereum
            {
            public:
                Celo() noexcept = default;
                virtual ~Celo() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class EthereumClassic : public Ethereum
            {
            public:
                EthereumClassic() noexcept = default;
                virtual ~EthereumClassic() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Fantom : public Ethereum
            {
            public:
                Fantom() noexcept = default;
                virtual ~Fantom() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Fuse : public Ethereum
            {
            public:
                Fuse() noexcept = default;
                virtual ~Fuse() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Harmony : public Ethereum
            {
            public:
                Harmony() noexcept = default;
                virtual ~Harmony() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Heco : public Ethereum
            {
            public:
                Heco() noexcept = default;
                virtual ~Heco() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Kcc : public Ethereum
            {
            public:
                Kcc() noexcept = default;
                virtual ~Kcc() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Moonbeam : public Ethereum
            {
            public:
                Moonbeam() noexcept = default;
                virtual ~Moonbeam() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Optimism : public Ethereum
            {
            public:
                Optimism() noexcept = default;
                virtual ~Optimism() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Polygon : public Ethereum
            {
            public:
                Polygon() noexcept = default;
                virtual ~Polygon() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };

            class Rootstock : public Ethereum
            {
            public:
                Rootstock() noexcept = default;
                virtual ~Rootstock() override = default;
                virtual String GetDerivation(uint64_t AddressIndex) const override;
                virtual const btc_chainparams_* GetChain() override;
            };
        }
    }
}
#endif