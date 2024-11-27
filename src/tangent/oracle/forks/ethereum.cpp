#include "ethereum.h"
#include "../../../utils/tiny-bitcoin/chainparams.h"

namespace Tangent
{
	namespace Oracle
	{
		namespace Chains
		{
			String Arbitrum::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Arbitrum::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &arb_chainparams_regtest;
					case NetworkType::Testnet:
						return &arb_chainparams_test;
					case NetworkType::Mainnet:
						return &arb_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Avalanche::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Avalanche::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &avax_chainparams_regtest;
					case NetworkType::Testnet:
						return &avax_chainparams_test;
					case NetworkType::Mainnet:
						return &avax_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String BinanceSmartChain::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/714'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* BinanceSmartChain::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &bsc_chainparams_regtest;
					case NetworkType::Testnet:
						return &bsc_chainparams_test;
					case NetworkType::Mainnet:
						return &bsc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Celo::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/52752'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Celo::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &celo_chainparams_regtest;
					case NetworkType::Testnet:
						return &celo_chainparams_test;
					case NetworkType::Mainnet:
						return &celo_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String EthereumClassic::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/61'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* EthereumClassic::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &etc_chainparams_regtest;
					case NetworkType::Testnet:
						return &etc_chainparams_test;
					case NetworkType::Mainnet:
						return &etc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Fantom::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Fantom::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &ftm_chainparams_regtest;
					case NetworkType::Testnet:
						return &ftm_chainparams_test;
					case NetworkType::Mainnet:
						return &ftm_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Fuse::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Fuse::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &fuse_chainparams_regtest;
					case NetworkType::Testnet:
						return &fuse_chainparams_test;
					case NetworkType::Mainnet:
						return &fuse_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Harmony::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/1023'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Harmony::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &one_chainparams_regtest;
					case NetworkType::Testnet:
						return &one_chainparams_test;
					case NetworkType::Mainnet:
						return &one_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Heco::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Heco::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &heco_chainparams_regtest;
					case NetworkType::Testnet:
						return &heco_chainparams_test;
					case NetworkType::Mainnet:
						return &heco_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Kcc::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Kcc::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &kcc_chainparams_regtest;
					case NetworkType::Testnet:
						return &kcc_chainparams_test;
					case NetworkType::Mainnet:
						return &kcc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Moonbeam::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Moonbeam::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &glmr_chainparams_regtest;
					case NetworkType::Testnet:
						return &glmr_chainparams_test;
					case NetworkType::Mainnet:
						return &glmr_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Optimism::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Optimism::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &op_chainparams_regtest;
					case NetworkType::Testnet:
						return &op_chainparams_test;
					case NetworkType::Mainnet:
						return &op_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Polygon::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Polygon::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &matic_chainparams_regtest;
					case NetworkType::Testnet:
						return &matic_chainparams_test;
					case NetworkType::Mainnet:
						return &matic_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			String Rootstock::GetDerivation(uint64_t AddressIndex) const
			{
				return Stringify::Text(Protocol::Now().Is(NetworkType::Mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, AddressIndex);
			}
			const btc_chainparams_* Rootstock::GetChain()
			{
				switch (Protocol::Now().User.Network)
				{
					case NetworkType::Regtest:
						return &rsk_chainparams_regtest;
					case NetworkType::Testnet:
						return &rsk_chainparams_test;
					case NetworkType::Mainnet:
						return &rsk_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}