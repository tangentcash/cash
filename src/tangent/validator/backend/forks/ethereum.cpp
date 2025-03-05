#include "ethereum.h"
#include "../../internal/libbitcoin/chainparams.h"

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			string arbitrum::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* arbitrum::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &arb_chainparams_regtest;
					case network_type::testnet:
						return &arb_chainparams_test;
					case network_type::mainnet:
						return &arb_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string avalanche::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* avalanche::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &avax_chainparams_regtest;
					case network_type::testnet:
						return &avax_chainparams_test;
					case network_type::mainnet:
						return &avax_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string celo::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/52752'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* celo::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &celo_chainparams_regtest;
					case network_type::testnet:
						return &celo_chainparams_test;
					case network_type::mainnet:
						return &celo_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string ethereum_classic::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/61'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* ethereum_classic::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &etc_chainparams_regtest;
					case network_type::testnet:
						return &etc_chainparams_test;
					case network_type::mainnet:
						return &etc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string fantom::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* fantom::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &ftm_chainparams_regtest;
					case network_type::testnet:
						return &ftm_chainparams_test;
					case network_type::mainnet:
						return &ftm_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string fuse::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* fuse::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &fuse_chainparams_regtest;
					case network_type::testnet:
						return &fuse_chainparams_test;
					case network_type::mainnet:
						return &fuse_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string harmony::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/1023'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* harmony::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &one_chainparams_regtest;
					case network_type::testnet:
						return &one_chainparams_test;
					case network_type::mainnet:
						return &one_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string moonbeam::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* moonbeam::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &glmr_chainparams_regtest;
					case network_type::testnet:
						return &glmr_chainparams_test;
					case network_type::mainnet:
						return &glmr_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string optimism::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* optimism::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &op_chainparams_regtest;
					case network_type::testnet:
						return &op_chainparams_test;
					case network_type::mainnet:
						return &op_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string polygon::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* polygon::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &matic_chainparams_regtest;
					case network_type::testnet:
						return &matic_chainparams_test;
					case network_type::mainnet:
						return &matic_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			string rootstock::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/60'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* rootstock::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &rif_chainparams_regtest;
					case network_type::testnet:
						return &rif_chainparams_test;
					case network_type::mainnet:
						return &rif_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}

			binance_smart_chain::binance_smart_chain() noexcept : ethereum()
			{
				netdata.supports_token_transfer = "bep20";
			}
			string binance_smart_chain::get_derivation(uint64_t address_index) const
			{
				return stringify::text(protocol::now().is(network_type::mainnet) ? "m/44'/714'/0'/%" PRIu64 : "m/44'/1'/0'/%" PRIu64, address_index);
			}
			const btc_chainparams_* binance_smart_chain::get_chain()
			{
				switch (protocol::now().user.network)
				{
					case network_type::regtest:
						return &bsc_chainparams_regtest;
					case network_type::testnet:
						return &bsc_chainparams_test;
					case network_type::mainnet:
						return &bsc_chainparams_main;
					default:
						VI_PANIC(false, "invalid network type");
						return nullptr;
				}
			}
		}
	}
}