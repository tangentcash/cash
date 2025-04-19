#ifndef TAN_MEDIATOR_FORKS_BITCOIN_H
#define TAN_MEDIATOR_FORKS_BITCOIN_H
#include "../bitcoin.h"

namespace tangent
{
	namespace mediator
	{
		namespace backends
		{
			class bitcoin_cash : public bitcoin
			{
			public:
				bitcoin_cash(const algorithm::asset_id& new_asset) noexcept;
				virtual ~bitcoin_cash() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
				virtual uint32_t get_sig_hash_type() override;
			};

			class bitcoin_gold : public bitcoin
			{
			public:
				bitcoin_gold(const algorithm::asset_id& new_asset) noexcept;
				virtual ~bitcoin_gold() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class bitcoin_sv : public bitcoin
			{
			public:
				bitcoin_sv(const algorithm::asset_id& new_asset) noexcept;
				virtual ~bitcoin_sv() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class dash : public bitcoin
			{
			public:
				dash(const algorithm::asset_id& new_asset) noexcept;
				virtual ~dash() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class digibyte : public bitcoin
			{
			public:
				digibyte(const algorithm::asset_id& new_asset) noexcept;
				virtual ~digibyte() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class dogecoin : public bitcoin
			{
			public:
				dogecoin(const algorithm::asset_id& new_asset) noexcept;
				virtual ~dogecoin() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class ecash : public bitcoin
			{
			public:
				ecash(const algorithm::asset_id& new_asset) noexcept;
				virtual ~ecash() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
				virtual uint32_t get_sig_hash_type() override;
			};

			class litecoin : public bitcoin
			{
			public:
				litecoin(const algorithm::asset_id& new_asset) noexcept;
				virtual ~litecoin() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class zcash : public bitcoin
			{
			public:
				zcash(const algorithm::asset_id& new_asset) noexcept;
				virtual ~zcash() override = default;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};
		}
	}
}
#endif