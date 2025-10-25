#ifndef TAN_ORACLE_FORKS_ETHEREUM_H
#define TAN_ORACLE_FORKS_ETHEREUM_H
#include "../ethereum.h"

namespace tangent
{
    namespace oracle
    {
        namespace backends
        {
            namespace forks
            {
                class arbitrum : public ethereum
                {
                public:
                    arbitrum(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~arbitrum() override = default;
                };

                class avalanche : public ethereum
                {
                public:
                    avalanche(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~avalanche() override = default;
                };

                class base : public ethereum
                {
                public:
                    base(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~base() override = default;
                };

                class blast : public ethereum
                {
                public:
                    blast(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~blast() override = default;
                };

                class bnb : public ethereum
                {
                public:
                    bnb(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~bnb() override = default;
                };

                class celo : public ethereum
                {
                public:
                    celo(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~celo() override = default;
                };

                class ethereum_classic : public ethereum
                {
                public:
                    ethereum_classic(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~ethereum_classic() override = default;
                };

                class gnosis : public ethereum
                {
                public:
                    gnosis(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~gnosis() override = default;
                };

                class linea : public ethereum
                {
                public:
                    linea(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~linea() override = default;
                };

                class polygon : public ethereum
                {
                public:
                    polygon(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~polygon() override = default;
                };

                class optimism : public ethereum
                {
                public:
                    optimism(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~optimism() override = default;
                };

                class sonic : public ethereum
                {
                public:
                    sonic(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~sonic() override = default;
                };

                class zksync : public ethereum
                {
                public:
                    zksync(const algorithm::asset_id& new_asset) noexcept;
                    virtual ~zksync() override = default;
                };
            }
        }
    }
}
#endif