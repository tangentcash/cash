#ifndef TAN_KERNEL_WALLET_H
#define TAN_KERNEL_WALLET_H
#include "../policy/messages.h"

namespace Tangent
{
	namespace Ledger
	{
		struct Wallet : Messages::Generic
		{
			Algorithm::Seckey SecretKey = { 0 };
			Algorithm::Pubkey SealingKey = { 0 };
			Algorithm::Pubkey PublicKey = { 0 };
			Algorithm::Pubkeyhash PublicKeyHash = { 0 };

			bool SetSecretKey(const Algorithm::Seckey Value);
			void SetPublicKey(const Algorithm::Pubkey Value);
			void SetPublicKeyHash(const Algorithm::Pubkeyhash Value);
			bool VerifySecretKey() const;
			bool VerifySealingKey() const;
			bool VerifyPublicKey() const;
			bool VerifyAddress() const;
			bool Verify(const Messages::Authentic& Message) const;
			bool Recover(Messages::Authentic& Message) const;
			bool Sign(Messages::Authentic& Message) const;
			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool HasSecretKey() const;
			bool HasSealingKey() const;
			bool HasPublicKey() const;
			bool HasPublicKeyHash() const;
			Option<String> SealMessage(const std::string_view& Plaintext, const Algorithm::Pubkey ForSealingKey) const;
			Option<String> OpenMessage(const std::string_view& Ciphertext) const;
			String GetSecretKey() const;
			String GetSealingKey() const;
			String GetPublicKey() const;
			String GetAddress() const;
			ExpectsLR<uint64_t> GetLatestSequence() const;
			UPtr<Schema> AsSchema() const override;
			UPtr<Schema> AsPublicSchema() const;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
			static Wallet FromMnemonic(const std::string_view& Mnemonic);
			static Wallet FromSeed(const std::string_view& Seed = std::string_view());
			static Wallet FromSecretKey(const Algorithm::Seckey Key);
			static Wallet FromPublicKey(const Algorithm::Pubkey Key);
			static Wallet FromPublicKeyHash(const Algorithm::Pubkeyhash Key);
		};

		struct Validator final : Messages::Generic
		{
			struct
			{
				uint64_t Latency = (uint64_t)std::numeric_limits<int64_t>::max();
				uint64_t Timestamp = 0;
				uint64_t Calls = 0;
				uint64_t Errors = 0;
			} Availability;

			struct
			{
				uint16_t P2P = 0;
				uint16_t NDS = 0;
				uint16_t RPC = 0;
			} Ports;

			struct
			{
				bool Consensus = false;
				bool Discovery = false;
				bool Interface = false;
				bool Proposer = false;
				bool Public = false;
				bool Streaming = false;
			} Services;

			SocketAddress Address;

			bool StorePayload(Format::Stream* Stream) const override;
			bool LoadPayload(Format::Stream& Stream) override;
			bool IsValid() const;
			uint64_t GetPreference() const;
			UPtr<Schema> AsSchema() const override;
			uint32_t AsType() const override;
			std::string_view AsTypename() const override;
			static uint32_t AsInstanceType();
			static std::string_view AsInstanceTypename();
		};
	}
}
#endif