#ifndef TAN_WARDEN_FORKS_ETHEREUM_H
#define TAN_WARDEN_FORKS_ETHEREUM_H
#include "../ethereum.h"

namespace tangent
{
    namespace warden
    {
        namespace backends
        {
            class arbitrum : public ethereum
            {
            public:
                arbitrum(const algorithm::asset_id& new_asset) noexcept;
                virtual ~arbitrum() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class avalanche : public ethereum
            {
            public:
                avalanche(const algorithm::asset_id& new_asset) noexcept;
                virtual ~avalanche() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class celo : public ethereum
            {
            public:
                celo(const algorithm::asset_id& new_asset) noexcept;
                virtual ~celo() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class ethereum_classic : public ethereum
            {
            public:
                ethereum_classic(const algorithm::asset_id& new_asset) noexcept;
                virtual ~ethereum_classic() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class fantom : public ethereum
            {
            public:
                fantom(const algorithm::asset_id& new_asset) noexcept;
                virtual ~fantom() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class fuse : public ethereum
            {
            public:
                fuse(const algorithm::asset_id& new_asset) noexcept;
                virtual ~fuse() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class harmony : public ethereum
            {
            public:
                harmony(const algorithm::asset_id& new_asset) noexcept;
                virtual ~harmony() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class moonbeam : public ethereum
            {
            public:
                moonbeam(const algorithm::asset_id& new_asset) noexcept;
                virtual ~moonbeam() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class optimism : public ethereum
            {
            public:
                optimism(const algorithm::asset_id& new_asset) noexcept;
                virtual ~optimism() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class polygon : public ethereum
            {
            public:
                polygon(const algorithm::asset_id& new_asset) noexcept;
                virtual ~polygon() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class rootstock : public ethereum
            {
            public:
                rootstock(const algorithm::asset_id& new_asset) noexcept;
                virtual ~rootstock() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };

            class binance_smart_chain : public ethereum
            {
            public:
                binance_smart_chain(const algorithm::asset_id& new_asset) noexcept;
                virtual ~binance_smart_chain() override = default;
                virtual const btc_chainparams_* get_chain() override;
            };
        }
    }
}
#endif