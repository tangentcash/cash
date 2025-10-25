#include "ethereum.h"
#include "../../internal/libbitcoin/chainparams.h"

namespace tangent
{
	namespace oracle
	{
		namespace backends
		{
			namespace forks
			{
				arbitrum::arbitrum(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				avalanche::avalanche(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				base::base(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				blast::blast(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				bnb::bnb(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				celo::celo(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				ethereum_classic::ethereum_classic(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
					legacy.eip_155 = 1;
				}

				gnosis::gnosis(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				linea::linea(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				polygon::polygon(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				optimism::optimism(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				sonic::sonic(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}

				zksync::zksync(const algorithm::asset_id& new_asset) noexcept : ethereum(new_asset)
				{
				}
			}
		}
	}
}