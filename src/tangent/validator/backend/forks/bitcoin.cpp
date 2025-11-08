#include "bitcoin.h"
#include "../../internal/libbitcoin/chainparams.h"
#include "../../internal/libbitcoin/script.h"

namespace tangent
{
	namespace oracle
	{
		namespace backends
		{
			namespace forks
			{
				bitcoin_cash::bitcoin_cash(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				const btc_chainparams_* bitcoin_cash::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &bch_chainparams_regtest;
						case network_type::testnet:
							return &bch_chainparams_test;
						case network_type::mainnet:
							return &bch_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				bitcoin_cash::address_format bitcoin_cash::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_cash_public_key_hash);
				}
				uint32_t bitcoin_cash::get_sig_hash_type()
				{
					return SIGHASH_ALL | SIGHASH_FORKID;
				}

				bitcoin_gold::bitcoin_gold(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				const btc_chainparams_* bitcoin_gold::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &btg_chainparams_regtest;
						case network_type::testnet:
							return &btg_chainparams_test;
						case network_type::mainnet:
							return &btg_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				bitcoin_gold::address_format bitcoin_gold::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_script_hash | (size_t)address_format::pay2_public_key_hash | (size_t)address_format::pay2_witness_public_key_hash);
				}

				bitcoin_sv::bitcoin_sv(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
					legacy.get_block_stats = 1;
					legacy.enormous_block_size = 1;
				}
				const btc_chainparams_* bitcoin_sv::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &bsv_chainparams_regtest;
						case network_type::testnet:
							return &bsv_chainparams_test;
						case network_type::mainnet:
							return &bsv_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				bitcoin_sv::address_format bitcoin_sv::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash);
				}
				uint32_t bitcoin_sv::get_sig_hash_type()
				{
					return SIGHASH_ALL | SIGHASH_FORKID;
				}

				dash::dash(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				const btc_chainparams_* dash::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &dash_chainparams_regtest;
						case network_type::testnet:
							return &dash_chainparams_test;
						case network_type::mainnet:
							return &dash_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				dash::address_format dash::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash);
				}

				digibyte::digibyte(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				const btc_chainparams_* digibyte::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &dgb_chainparams_regtest;
						case network_type::testnet:
							return &dgb_chainparams_test;
						case network_type::mainnet:
							return &dgb_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				digibyte::address_format digibyte::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash | (size_t)address_format::pay2_witness_public_key_hash);
				}

				dogecoin::dogecoin(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
					legacy.get_block_stats = 1;
				}
				const btc_chainparams_* dogecoin::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &doge_chainparams_regtest;
						case network_type::testnet:
							return &doge_chainparams_test;
						case network_type::mainnet:
							return &doge_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				dogecoin::address_format dogecoin::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash);
				}

				ecash::ecash(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
					netdata.divisibility = algorithm::arithmetic::fixed(100);
				}
				const btc_chainparams_* ecash::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &xec_chainparams_regtest;
						case network_type::testnet:
							return &xec_chainparams_test;
						case network_type::mainnet:
							return &xec_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				dogecoin::address_format ecash::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_cash_public_key_hash);
				}
				uint32_t ecash::get_sig_hash_type()
				{
					return SIGHASH_ALL | SIGHASH_FORKID;
				}

				litecoin::litecoin(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				const btc_chainparams_* litecoin::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &ltc_chainparams_regtest;
						case network_type::testnet:
							return &ltc_chainparams_test;
						case network_type::mainnet:
							return &ltc_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				litecoin::address_format litecoin::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash | (size_t)address_format::pay2_witness_public_key_hash | (size_t)address_format::pay2_taproot);
				}

				zcash::zcash(const algorithm::asset_id& new_asset) noexcept : bitcoin(new_asset)
				{
				}
				expects_promise_rt<computed_fee> zcash::estimate_transaction_fee(const wallet_link& from_link, const vector<value_transfer>& to)
				{
					decimal sending_value = decimal::zero();
					for (auto& destination : to)
						sending_value += destination.value;

					auto inputs = calculate_utxo(from_link, balance_query(sending_value, { }));
					decimal input_value = inputs ? get_utxo_value(*inputs, optional::none) : 0.0;
					if (!inputs || inputs->empty())
						return expects_promise_rt<computed_fee>(remote_exception(stringify::text("insufficient funds: %s < %s", input_value.to_string().c_str(), sending_value.to_string().c_str())));

					decimal satoshi = decimal(5000 * std::max<size_t>(2, std::max(inputs->size(), 1 + to.size())));
					return expects_promise_rt<computed_fee>(computed_fee::flat_fee(satoshi / netdata.divisibility));
				}
				const btc_chainparams_* zcash::get_chain()
				{
					switch (protocol::now().user.network)
					{
						case network_type::regtest:
							return &zec_chainparams_regtest;
						case network_type::testnet:
							return &zec_chainparams_test;
						case network_type::mainnet:
							return &zec_chainparams_main;
						default:
							VI_PANIC(false, "invalid network type");
							return nullptr;
					}
				}
				zcash::address_format zcash::get_address_type()
				{
					return (address_format)((size_t)address_format::pay2_public_key_hash | (size_t)address_format::pay2_unified_public_key_hash);
				}
			}
		}
	}
}