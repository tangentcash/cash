#ifndef TAN_OBSERVER_FORKS_BITCOIN_H
#define TAN_OBSERVER_FORKS_BITCOIN_H
#include "../bitcoin.h"

namespace Tangent
{
    namespace Observer
    {
        namespace Chains
        {
			class BitcoinCash : public Bitcoin
			{
			public:
				BitcoinCash() noexcept;
				virtual ~BitcoinCash() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
				virtual uint32_t GetSigHashType() override;
			};

			class BitcoinGold : public Bitcoin
			{
			public:
				BitcoinGold() noexcept;
				virtual ~BitcoinGold() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class BitcoinSV : public Bitcoin
			{
			public:
				BitcoinSV() noexcept;
				virtual ~BitcoinSV() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class Dash : public Bitcoin
			{
			public:
				Dash() noexcept;
				virtual ~Dash() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class Digibyte : public Bitcoin
			{
			public:
				Digibyte() noexcept;
				virtual ~Digibyte() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class Dogecoin : public Bitcoin
			{
			public:
				Dogecoin() noexcept;
				virtual ~Dogecoin() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class ECash : public Bitcoin
			{
			public:
				ECash() noexcept;
				virtual ~ECash() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
				virtual uint32_t GetSigHashType() override;
			};

			class Litecoin : public Bitcoin
			{
			public:
				Litecoin() noexcept;
				virtual ~Litecoin() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual String GetMessageMagic() override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};

			class ZCash : public Bitcoin
			{
			public:
				ZCash() noexcept;
				virtual ~ZCash() override = default;
				virtual String GetDerivation(uint64_t AddressIndex) const override;
				virtual const btc_chainparams_* GetChain() override;
				virtual AddressFormat GetAddressType() override;
			};
        }
    }
}
#endif