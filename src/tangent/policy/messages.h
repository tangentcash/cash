#ifndef TAN_POLICY_MESSAGES_H
#define TAN_POLICY_MESSAGES_H
#include "../kernel/algorithm.h"

namespace Tangent
{
	namespace Messages
	{
		struct Generic
		{
			uint256_t Checksum;
			uint32_t Version;

			Generic();
			virtual ~Generic() = default;
			virtual bool Store(Format::Stream* Stream) const;
			virtual bool Load(Format::Stream& Stream);
			virtual bool StorePayload(Format::Stream* Stream) const = 0;
			virtual bool LoadPayload(Format::Stream& Stream) = 0;
			virtual uint256_t AsHash(bool Renew = false) const;
			virtual uint32_t AsType() const = 0;
			virtual std::string_view AsTypename() const = 0;
			virtual UPtr<Schema> AsSchema() const = 0;
			virtual Format::Stream AsMessage() const;
			virtual Format::Stream AsPayload() const;
			static Option<uint32_t> ResolveType(Format::Stream& Stream, uint32_t* Version = nullptr);
		};

		struct Authentic
		{
			Algorithm::Sighash Signature = { 0 };
			uint256_t Checksum;
			uint32_t Version;

			Authentic();
			virtual ~Authentic() = default;
			virtual bool Store(Format::Stream* Stream) const;
			virtual bool Load(Format::Stream& Stream);
			virtual bool StorePayload(Format::Stream* Stream) const = 0;
			virtual bool LoadPayload(Format::Stream& Stream) = 0;
			virtual bool Sign(const Algorithm::Seckey SecretKey);
			virtual bool Verify(const Algorithm::Pubkey PublicKey) const;
			virtual bool Recover(Algorithm::Pubkeyhash PublicKeyHash) const;
			virtual bool IsSignatureNull() const;
			virtual void SetSignature(const Algorithm::Sighash NewValue);
			virtual uint256_t AsHash(bool Renew = false) const;
			virtual uint32_t AsType() const = 0;
			virtual std::string_view AsTypename() const = 0;
			virtual UPtr<Schema> AsSchema() const = 0;
			virtual Format::Stream AsMessage() const;
			virtual Format::Stream AsPayload() const;
			static Option<uint32_t> ResolveType(Format::Stream& Stream, uint32_t* Version = nullptr);
		};
	}
}
#endif