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
				bitcoin_cash() noexcept;
				virtual ~bitcoin_cash() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
				virtual uint32_t get_sig_hash_type() override;
			};

			class bitcoin_gold : public bitcoin
			{
			public:
				bitcoin_gold() noexcept;
				virtual ~bitcoin_gold() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class bitcoin_sv : public bitcoin
			{
			public:
				bitcoin_sv() noexcept;
				virtual ~bitcoin_sv() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class dash : public bitcoin
			{
			public:
				dash() noexcept;
				virtual ~dash() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class digibyte : public bitcoin
			{
			public:
				digibyte() noexcept;
				virtual ~digibyte() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class dogecoin : public bitcoin
			{
			public:
				dogecoin() noexcept;
				virtual ~dogecoin() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class ecash : public bitcoin
			{
			public:
				ecash() noexcept;
				virtual ~ecash() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
				virtual uint32_t get_sig_hash_type() override;
			};

			class litecoin : public bitcoin
			{
			public:
				litecoin() noexcept;
				virtual ~litecoin() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual string get_message_magic() override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};

			class zcash : public bitcoin
			{
			public:
				zcash() noexcept;
				virtual ~zcash() override = default;
				virtual string get_derivation(uint64_t address_index) const override;
				virtual const btc_chainparams_* get_chain() override;
				virtual address_format get_address_type() override;
			};
		}
	}
}
#endif