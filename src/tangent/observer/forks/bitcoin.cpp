#include "bitcoin.h"
#include "../../../utils/tiny-bitcoin/chainparams.h"
#include "../../../utils/tiny-bitcoin/script.h"

namespace Tangent
{
	namespace Observer
	{
		namespace Chains
		{
			BitcoinCash::BitcoinCash() noexcept : Bitcoin()
			{
			}
			String BitcoinCash::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/145'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* BitcoinCash::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &bch_chainparams_regtest;
					case NetworkType::Testnet:
						return &bch_chainparams_test;
					case NetworkType::Mainnet:
						return &bch_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			BitcoinCash::AddressFormat BitcoinCash::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2CashaddrPublicKeyHash);
			}
			uint32_t BitcoinCash::GetSigHashType()
			{
				return SIGHASH_ALL | SIGHASH_FORKID;
			}

			BitcoinGold::BitcoinGold() noexcept : Bitcoin()
			{
			}
			String BitcoinGold::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/156'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String BitcoinGold::GetMessageMagic()
			{
				return "Bitcoin Gold Signed Message:\n";
			}
			const btc_chainparams_* BitcoinGold::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &btg_chainparams_regtest;
					case NetworkType::Testnet:
						return &btg_chainparams_test;
					case NetworkType::Mainnet:
						return &btg_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			BitcoinGold::AddressFormat BitcoinGold::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash | (size_t)AddressFormat::Pay2WitnessPublicKeyHash);
			}

			BitcoinSV::BitcoinSV() noexcept : Bitcoin()
			{
			}
			String BitcoinSV::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/236'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* BitcoinSV::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &bsv_chainparams_regtest;
					case NetworkType::Testnet:
						return &bsv_chainparams_test;
					case NetworkType::Mainnet:
						return &bsv_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			BitcoinSV::AddressFormat BitcoinSV::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash);
			}

			Dash::Dash() noexcept : Bitcoin()
			{
			}
			String Dash::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/5'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String Dash::GetMessageMagic()
			{
				return "DarkCoin Signed Message:\n";
			}
			const btc_chainparams_* Dash::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &dash_chainparams_regtest;
					case NetworkType::Testnet:
						return &dash_chainparams_test;
					case NetworkType::Mainnet:
						return &dash_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Dash::AddressFormat Dash::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash);
			}

			Digibyte::Digibyte() noexcept : Bitcoin()
			{
			}
			String Digibyte::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/20'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String Digibyte::GetMessageMagic()
			{
				return "DigiByte Signed Message:\n";
			}
			const btc_chainparams_* Digibyte::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &dgb_chainparams_regtest;
					case NetworkType::Testnet:
						return &dgb_chainparams_test;
					case NetworkType::Mainnet:
						return &dgb_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Digibyte::AddressFormat Digibyte::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash | (size_t)AddressFormat::Pay2WitnessPublicKeyHash);
			}

			Dogecoin::Dogecoin() noexcept : Bitcoin()
			{
			}
			String Dogecoin::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/3'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String Dogecoin::GetMessageMagic()
			{
				return "Dogecoin Signed Message:\n";
			}
			const btc_chainparams_* Dogecoin::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &doge_chainparams_regtest;
					case NetworkType::Testnet:
						return &doge_chainparams_test;
					case NetworkType::Mainnet:
						return &doge_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Dogecoin::AddressFormat Dogecoin::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash);
			}

			ECash::ECash() noexcept : Bitcoin()
			{
			}
			String ECash::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/145'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String ECash::GetMessageMagic()
			{
				return "eCash Signed Message:\n";
			}
			const btc_chainparams_* ECash::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &xec_chainparams_regtest;
					case NetworkType::Testnet:
						return &xec_chainparams_test;
					case NetworkType::Mainnet:
						return &xec_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Dogecoin::AddressFormat ECash::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2CashaddrPublicKeyHash);
			}
			uint32_t ECash::GetSigHashType()
			{
				return SIGHASH_ALL | SIGHASH_FORKID;
			}

			Litecoin::Litecoin() noexcept : Bitcoin()
			{
			}
			String Litecoin::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/2'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			String Litecoin::GetMessageMagic()
			{
				return "Litecoin Signed Message:\n";
			}
			const btc_chainparams_* Litecoin::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &ltc_chainparams_regtest;
					case NetworkType::Testnet:
						return &ltc_chainparams_test;
					case NetworkType::Mainnet:
						return &ltc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			Litecoin::AddressFormat Litecoin::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash | (size_t)AddressFormat::Pay2WitnessPublicKeyHash | (size_t)AddressFormat::Pay2Taproot);
			}

			ZCash::ZCash() noexcept : Bitcoin()
			{
			}
			String ZCash::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/133'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* ZCash::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &zec_chainparams_regtest;
					case NetworkType::Testnet:
						return &zec_chainparams_test;
					case NetworkType::Mainnet:
						return &zec_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
			ZCash::AddressFormat ZCash::GetAddressType()
			{
				return (AddressFormat)((size_t)AddressFormat::Pay2PublicKeyHash);
			}
		}
	}
}