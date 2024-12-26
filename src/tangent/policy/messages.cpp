#include "messages.h"
#include "../policy/typenames.h"

namespace Tangent
{
	namespace Messages
	{
		Generic::Generic() : Checksum(0), Version(Protocol::Now().Message.ProtocolVersion)
		{
		}
		bool Generic::Store(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Version);
			Stream->WriteInteger(AsType());
			return StorePayload(Stream);
		}
		bool Generic::Load(Format::Stream& Stream)
		{
			auto Type = ResolveType(Stream, &Version);
			if (!Type || *Type != AsType())
				return false;

			if (!LoadPayload(Stream))
				return false;

			return true;
		}
		uint256_t Generic::AsHash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			Format::Stream Message;
			((Generic*)this)->Checksum = Store(&Message) ? Message.Hash() : uint256_t(0);
			return Checksum;
		}
		Format::Stream Generic::AsMessage() const
		{
			Format::Stream Message;
			if (!Store(&Message))
				Message.Clear();
			return Message;
		}
		Format::Stream Generic::AsPayload() const
		{
			Format::Stream Message;
			if (!StorePayload(&Message))
				Message.Clear();
			return Message;
		}
		Option<uint32_t> Generic::ResolveType(Format::Stream& Stream, uint32_t* OutVersion)
		{
			uint32_t Version; size_t Seek = Stream.Seek;
			if (!Stream.ReadInteger(Stream.ReadType(), &Version))
			{
				if (!OutVersion)
					Stream.Seek = Seek;
				return Optional::None;
			}

			uint32_t Type;
			if (!Stream.ReadInteger(Stream.ReadType(), &Type))
				return Optional::None;

			if (OutVersion)
				*OutVersion = Version;
			else
				Stream.Seek = Seek;
			return Type;
		}

		Authentic::Authentic() : Checksum(0), Version(Protocol::Now().Message.ProtocolVersion)
		{
		}
		bool Authentic::Store(Format::Stream* Stream) const
		{
			VI_ASSERT(Stream != nullptr, "stream should be set");
			Stream->WriteInteger(Version);
			Stream->WriteInteger(AsType());
			Stream->WriteString(std::string_view((char*)Signature, sizeof(Signature)));
			return StorePayload(Stream);
		}
		bool Authentic::Load(Format::Stream& Stream)
		{
			auto Type = ResolveType(Stream, &Version);
			if (!Type || *Type != AsType())
				return false;

			String SignatureAssembly;
			if (!Stream.ReadString(Stream.ReadType(), &SignatureAssembly) || SignatureAssembly.size() != sizeof(Algorithm::Sighash))
				return false;

			memcpy(Signature, SignatureAssembly.data(), SignatureAssembly.size());
			if (!LoadPayload(Stream))
				return false;

			return true;
		}
		bool Authentic::Sign(const Algorithm::Seckey PrivateKey)
		{
			Format::Stream Message;
			if (!StorePayload(&Message))
				return false;

			return Algorithm::Signing::Sign(Message.Hash(), PrivateKey, Signature);
		}
		bool Authentic::Verify(const Algorithm::Pubkey PublicKey) const
		{
			Format::Stream Message;
			if (!StorePayload(&Message))
				return false;

			return Algorithm::Signing::Verify(Message.Hash(), PublicKey, Signature);
		}
		bool Authentic::Recover(Algorithm::Pubkeyhash PublicKeyHash) const
		{
			Format::Stream Message;
			if (!StorePayload(&Message))
				return false;

			return Algorithm::Signing::RecoverHash(Message.Hash(), PublicKeyHash, Signature);
		}
		void Authentic::SetSignature(const Algorithm::Sighash NewValue)
		{
			VI_ASSERT(NewValue != nullptr, "new value should be set");
			memcpy(Signature, NewValue, sizeof(Algorithm::Sighash));
		}
		bool Authentic::IsSignatureNull() const
		{
			Algorithm::Sighash Null = { 0 };
			return memcmp(Signature, Null, sizeof(Null)) == 0;
		}
		uint256_t Authentic::AsHash(bool Renew) const
		{
			if (!Renew && Checksum != 0)
				return Checksum;

			Format::Stream Message;
			((Authentic*)this)->Checksum = Store(&Message) ? Message.Hash() : uint256_t(0);
			return Checksum;
		}
		Format::Stream Authentic::AsMessage() const
		{
			Format::Stream Message;
			if (!Store(&Message))
				Message.Clear();
			return Message;
		}
		Format::Stream Authentic::AsPayload() const
		{
			Format::Stream Message;
			if (!StorePayload(&Message))
				Message.Clear();
			return Message;
		}
		Option<uint32_t> Authentic::ResolveType(Format::Stream& Stream, uint32_t* OutVersion)
		{
			uint32_t Version; size_t Seek = Stream.Seek;
			if (!Stream.ReadInteger(Stream.ReadType(), &Version))
			{
				if (!OutVersion)
					Stream.Seek = Seek;
				return Optional::None;
			}

			uint32_t Type;
			if (!Stream.ReadInteger(Stream.ReadType(), &Type))
				return Optional::None;

			if (OutVersion)
				*OutVersion = Version;
			else
				Stream.Seek = Seek;
			return Type;
		}
	}
}