#ifndef TAN_MEDIATOR_FORKS_ETHEREUM_H
#define TAN_MEDIATOR_FORKS_ETHEREUM_H
#include "../ethereum.h"

namespace tangent
{
    namespace mediator
    {
        namespace backends
        {
            class arbitrum : public ethereum
            {
            public:
                arbitrum() noexcept = default;
                virtual ~arbitrum() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class avalanche : public ethereum
            {
            public:
                avalanche() noexcept = default;
                virtual ~avalanche() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class celo : public ethereum
            {
            public:
                celo() noexcept = default;
                virtual ~celo() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class ethereum_classic : public ethereum
            {
            public:
                ethereum_classic() noexcept = default;
                virtual ~ethereum_classic() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class fantom : public ethereum
            {
            public:
                fantom() noexcept = default;
                virtual ~fantom() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class fuse : public ethereum
            {
            public:
                fuse() noexcept = default;
                virtual ~fuse() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class harmony : public ethereum
            {
            public:
                harmony() noexcept = default;
                virtual ~harmony() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class moonbeam : public ethereum
            {
            public:
                moonbeam() noexcept = default;
                virtual ~moonbeam() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class optimism : public ethereum
            {
            public:
                optimism() noexcept = default;
                virtual ~optimism() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class polygon : public ethereum
            {
            public:
                polygon() noexcept = default;
                virtual ~polygon() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class rootstock : public ethereum
            {
            public:
                rootstock() noexcept = default;
                virtual ~rootstock() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };

            class binance_smart_chain : public ethereum
            {
            public:
                binance_smart_chain() noexcept;
                virtual ~binance_smart_chain() override = default;
                virtual string get_derivation(uint64_t address_index) const override;
                virtual const btc_chainparams_* get_chain() override;
            };
        }
    }
}
#endif