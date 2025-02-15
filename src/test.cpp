#include "tangent/kernel/block.h"
#include "tangent/kernel/wallet.h"
#include "tangent/kernel/script.h"
#include "tangent/policy/transactions.h"
#include "tangent/validator/storage/chainstate.h"
#include "tangent/validator/storage/mempoolstate.h"
#include "tangent/validator/service/rpc.h"
#include "tangent/validator/service/p2p.h"
#include "tangent/validator/service/nds.h"
#include "tangent/validator/service/nss.h"
#include <sstream>

using namespace Tangent;

class Tests
{
public:
	struct Account
	{
		Ledger::Wallet Wallet;
		std::atomic<uint64_t> Sequence;

		Account() = default;
		Account(const Ledger::Wallet& NewWallet, uint64_t NewSequence) : Wallet(NewWallet), Sequence(NewSequence)
		{
		}
		Account(Account&&) = default;
		Account(const Account& Other) : Wallet(Other.Wallet), Sequence(Other.Sequence.load())
		{
		}
		Account& operator= (Account&&) = default;
		Account& operator= (const Account& Other)
		{
			if (&Other == this)
				return *this;

			Wallet = Other.Wallet;
			Sequence = Other.Sequence.load();
			return *this;
		}
	};

	class Generators
	{
	public:
		static void Adjustments(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User2, User2Sequence] = Users[1];
			auto* DepositoryAdjustmentEthereum = Memory::New<Transactions::DepositoryAdjustment>();
			DepositoryAdjustmentEthereum->SetAsset("ETH");
			DepositoryAdjustmentEthereum->SetEstimateGas(Decimal::Zero());
			DepositoryAdjustmentEthereum->SetIncomingFee(0.001, 0.0001);
			DepositoryAdjustmentEthereum->SetOutgoingFee(0.001, 0.0001);
			VI_PANIC(DepositoryAdjustmentEthereum->Sign(User2.SecretKey, User2Sequence++), "depository adjustment not signed");
			Transactions.push_back(DepositoryAdjustmentEthereum);

			auto* DepositoryAdjustmentRipple = Memory::New<Transactions::DepositoryAdjustment>();
			DepositoryAdjustmentRipple->SetAsset("XRP");
			DepositoryAdjustmentRipple->SetEstimateGas(Decimal::Zero());
			DepositoryAdjustmentRipple->SetIncomingFee(0.01, 0.0001);
			DepositoryAdjustmentRipple->SetOutgoingFee(0.01, 0.0001);
			VI_PANIC(DepositoryAdjustmentRipple->Sign(User2.SecretKey, User2Sequence++), "depository adjustment not signed");
			Transactions.push_back(DepositoryAdjustmentRipple);

			auto* DepositoryAdjustmentBitcoin = Memory::New<Transactions::DepositoryAdjustment>();
			DepositoryAdjustmentBitcoin->SetAsset("BTC");
			DepositoryAdjustmentBitcoin->SetEstimateGas(Decimal::Zero());
			DepositoryAdjustmentBitcoin->SetIncomingFee(0.00001, 0.0001);
			DepositoryAdjustmentBitcoin->SetOutgoingFee(0.00001, 0.0001);
			VI_PANIC(DepositoryAdjustmentBitcoin->Sign(User2.SecretKey, User2Sequence++), "depository adjustment not signed");
			Transactions.push_back(DepositoryAdjustmentBitcoin);
		}
		static void AddressAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* AddressAccountEthereum1 = Memory::New<Transactions::AddressAccount>();
			AddressAccountEthereum1->SetAsset("ETH");
			AddressAccountEthereum1->SetEstimateGas(Decimal::Zero());
			AddressAccountEthereum1->SetAddress("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5");
			VI_PANIC(AddressAccountEthereum1->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(AddressAccountEthereum1);

			auto* AddressAccountEthereum2 = Memory::New<Transactions::AddressAccount>();
			AddressAccountEthereum2->SetAsset("ETH");
			AddressAccountEthereum2->SetEstimateGas(Decimal::Zero());
			AddressAccountEthereum2->SetAddress("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE");
			VI_PANIC(AddressAccountEthereum2->Sign(User2.SecretKey, User2Sequence++), "account not signed");
			Transactions.push_back(AddressAccountEthereum2);

			auto* AddressAccountRipple1 = Memory::New<Transactions::AddressAccount>();
			AddressAccountRipple1->SetAsset("XRP");
			AddressAccountRipple1->SetEstimateGas(Decimal::Zero());
			AddressAccountRipple1->SetAddress("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok");
			VI_PANIC(AddressAccountRipple1->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(AddressAccountRipple1);

			auto* AddressAccountRipple2 = Memory::New<Transactions::AddressAccount>();
			AddressAccountRipple2->SetAsset("XRP");
			AddressAccountRipple2->SetEstimateGas(Decimal::Zero());
			AddressAccountRipple2->SetAddress("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG");
			VI_PANIC(AddressAccountRipple2->Sign(User2.SecretKey, User2Sequence++), "account not signed");
			Transactions.push_back(AddressAccountRipple2);

			auto* AddressAccountBitcoin1 = Memory::New<Transactions::AddressAccount>();
			AddressAccountBitcoin1->SetAsset("BTC");
			AddressAccountBitcoin1->SetEstimateGas(Decimal::Zero());
			AddressAccountBitcoin1->SetAddress("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS");
			VI_PANIC(AddressAccountBitcoin1->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(AddressAccountBitcoin1);

			auto* AddressAccountBitcoin2 = Memory::New<Transactions::AddressAccount>();
			AddressAccountBitcoin2->SetAsset("BTC");
			AddressAccountBitcoin2->SetEstimateGas(Decimal::Zero());
			AddressAccountBitcoin2->SetAddress("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v");
			VI_PANIC(AddressAccountBitcoin2->Sign(User2.SecretKey, User2Sequence++), "account not signed");
			Transactions.push_back(AddressAccountBitcoin2);
		}
		static void PubkeyAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto* Server = NSS::ServerNode::Get();
			auto& [User1, User1Sequence] = Users[0];
			auto EthereumSeed = *Crypto::HashRaw(Digests::SHA256(), String((char*)User1.PublicKeyHash, sizeof(User1.PublicKeyHash)) + "ETH");
			auto EthereumWallet = Server->NewSigningWallet(Algorithm::Asset::IdOf("ETH"), Server->NewMasterWallet(Algorithm::Asset::IdOf("ETH"), EthereumSeed).Expect("master wallet not derived")).Expect("signing wallet not derived");
			auto* PubkeyAccountEthereum = Memory::New<Transactions::PubkeyAccount>();
			PubkeyAccountEthereum->SetAsset("ETH");
			PubkeyAccountEthereum->SetEstimateGas(Decimal::Zero());
			PubkeyAccountEthereum->SetPubkey(EthereumWallet.VerifyingKey.ExposeToHeap());
			PubkeyAccountEthereum->SignPubkey(EthereumWallet.SigningKey).Expect("pubkey account not signed");
			VI_PANIC(PubkeyAccountEthereum->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(PubkeyAccountEthereum);

			auto RippleSeed = *Crypto::HashRaw(Digests::SHA256(), String((char*)User1.PublicKeyHash, sizeof(User1.PublicKeyHash)) + "XRP");
			auto RippleWallet = Server->NewSigningWallet(Algorithm::Asset::IdOf("XRP"), Server->NewMasterWallet(Algorithm::Asset::IdOf("XRP"), RippleSeed).Expect("master wallet not derived")).Expect("signing wallet not derived");
			auto* PubkeyAccountRipple = Memory::New<Transactions::PubkeyAccount>();
			PubkeyAccountRipple->SetAsset("XRP");
			PubkeyAccountRipple->SetEstimateGas(Decimal::Zero());
			PubkeyAccountRipple->SetPubkey(RippleWallet.VerifyingKey.ExposeToHeap());
			PubkeyAccountRipple->SignPubkey(RippleWallet.SigningKey).Expect("pubkey account not signed");
			VI_PANIC(PubkeyAccountRipple->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(PubkeyAccountRipple);

			auto BitcoinSeed = *Crypto::HashRaw(Digests::SHA256(), String((char*)User1.PublicKeyHash, sizeof(User1.PublicKeyHash)) + "BTC");
			auto BitcoinWallet = Server->NewSigningWallet(Algorithm::Asset::IdOf("BTC"), Server->NewMasterWallet(Algorithm::Asset::IdOf("BTC"), BitcoinSeed).Expect("master wallet not derived")).Expect("signing wallet not derived");
			auto* PubkeyAccountBitcoin = Memory::New<Transactions::PubkeyAccount>();
			PubkeyAccountBitcoin->SetAsset("BTC");
			PubkeyAccountBitcoin->SetEstimateGas(Decimal::Zero());
			PubkeyAccountBitcoin->SetPubkey(BitcoinWallet.VerifyingKey.ExposeToHeap());
			PubkeyAccountBitcoin->SignPubkey(BitcoinWallet.SigningKey).Expect("pubkey account not signed");
			VI_PANIC(PubkeyAccountBitcoin->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(PubkeyAccountBitcoin);
		}
		static void Commitments(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* CommitmentUser1 = Memory::New<Transactions::Commitment>();
			CommitmentUser1->SetAsset("BTC");
			CommitmentUser1->SetEstimateGas(Decimal::Zero());
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("ETH"));
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("XRP"));
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("BTC"));

			auto Context = Ledger::TransactionContext();
			auto User1Work = Context.GetAccountWork(User1.PublicKeyHash);
			if (!User1Work || !User1Work->IsOnline())
				CommitmentUser1->SetOnline();

			VI_PANIC(CommitmentUser1->Sign(User1.SecretKey, User1Sequence++), "commitment not signed");
			Transactions.push_back(CommitmentUser1);

			auto* CommitmentUser2 = Memory::New<Transactions::Commitment>();
			CommitmentUser2->SetAsset("BTC");
			CommitmentUser2->SetEstimateGas(Decimal::Zero());
			CommitmentUser2->SetOnline(Algorithm::Asset::IdOf("ETH"));
			CommitmentUser2->SetOnline(Algorithm::Asset::IdOf("XRP"));
			CommitmentUser2->SetOnline(Algorithm::Asset::IdOf("BTC"));

			auto User2Work = Context.GetAccountWork(User2.PublicKeyHash);
			if (!User2Work || !User2Work->IsOnline())
				CommitmentUser2->SetOnline();

			VI_PANIC(CommitmentUser2->Sign(User2.SecretKey, User2Sequence++), "commitment not signed");
			Transactions.push_back(CommitmentUser2);
		}
		static void CommitmentOnline(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users, size_t UserId)
		{
			auto& [User1, User1Sequence] = Users[UserId];
			auto* CommitmentUser1 = Memory::New<Transactions::Commitment>();
			CommitmentUser1->SetAsset("BTC");
			CommitmentUser1->SetEstimateGas(Decimal::Zero());
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("ETH"));
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("XRP"));
			CommitmentUser1->SetOnline(Algorithm::Asset::IdOf("BTC"));

			auto Context = Ledger::TransactionContext();
			auto User1Work = Context.GetAccountWork(User1.PublicKeyHash);
			if (!User1Work || !User1Work->IsOnline())
				CommitmentUser1->SetOnline();

			VI_PANIC(CommitmentUser1->Sign(User1.SecretKey, User1Sequence++), "commitment not signed");
			Transactions.push_back(CommitmentUser1);
		}
		static void CommitmentOffline(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users, size_t UserId)
		{
			auto& [User1, User1Sequence] = Users[UserId];
			auto* CommitmentUser1 = Memory::New<Transactions::Commitment>();
			CommitmentUser1->SetAsset("BTC");
			CommitmentUser1->SetEstimateGas(Decimal::Zero());
			CommitmentUser1->SetOffline(Algorithm::Asset::IdOf("ETH"));
			CommitmentUser1->SetOffline(Algorithm::Asset::IdOf("XRP"));
			CommitmentUser1->SetOffline(Algorithm::Asset::IdOf("BTC"));

			auto Context = Ledger::TransactionContext();
			auto User1Work = Context.GetAccountWork(User1.PublicKeyHash);
			if (!User1Work || User1Work->IsOnline())
				CommitmentUser1->SetOffline();

			VI_PANIC(CommitmentUser1->Sign(User1.SecretKey, User1Sequence++), "commitment not signed");
			Transactions.push_back(CommitmentUser1);
		}
		static void Allocations(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* ContributionAllocationEthereum1 = Memory::New<Transactions::ContributionAllocation>();
			ContributionAllocationEthereum1->SetAsset("ETH");
			ContributionAllocationEthereum1->SetEstimateGas(Decimal::Zero());
			VI_PANIC(ContributionAllocationEthereum1->Sign(User1.SecretKey, User1Sequence++), "depository allocation not signed");
			Transactions.push_back(ContributionAllocationEthereum1);

			auto* ContributionAllocationEthereum2 = Memory::New<Transactions::ContributionAllocation>();
			ContributionAllocationEthereum2->SetAsset("ETH");
			ContributionAllocationEthereum2->SetEstimateGas(Decimal::Zero());
			VI_PANIC(ContributionAllocationEthereum2->Sign(User2.SecretKey, User2Sequence++), "depository allocation not signed");
			Transactions.push_back(ContributionAllocationEthereum2);

			auto* ContributionAllocationRipple = Memory::New<Transactions::ContributionAllocation>();
			ContributionAllocationRipple->SetAsset("XRP");
			ContributionAllocationRipple->SetEstimateGas(Decimal::Zero());
			VI_PANIC(ContributionAllocationRipple->Sign(User2.SecretKey, User2Sequence++), "depository allocation not signed");
			Transactions.push_back(ContributionAllocationRipple);

			auto* ContributionAllocationBitcoin = Memory::New<Transactions::ContributionAllocation>();
			ContributionAllocationBitcoin->SetAsset("BTC");
			ContributionAllocationBitcoin->SetEstimateGas(Decimal::Zero());
			VI_PANIC(ContributionAllocationBitcoin->Sign(User2.SecretKey, User2Sequence++), "depository allocation not signed");
			Transactions.push_back(ContributionAllocationBitcoin);
		}
		static void Contributions(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto Addresses1 = *Context.GetWitnessAddressesByPurpose(User1.PublicKeyHash, States::AddressType::Contribution, 0, 128);
			auto Addresses2 = *Context.GetWitnessAddressesByPurpose(User2.PublicKeyHash, States::AddressType::Contribution, 0, 128);
			auto AddressEthereum1 = std::find_if(Addresses1.begin(), Addresses1.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
			auto AddressEthereum2 = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
			auto AddressRipple = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("XRP"); });
			auto AddressBitcoin = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("BTC"); });
			VI_PANIC(AddressEthereum1 != Addresses1.end(), "ethereum custodian address not found");
			VI_PANIC(AddressEthereum2 != Addresses2.end(), "ethereum custodian address not found");
			VI_PANIC(AddressRipple != Addresses2.end(), "ripple custodian address not found");
			VI_PANIC(AddressBitcoin != Addresses2.end(), "bitcoin custodian address not found");

			auto* IncomingClaimEthereum1 = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimEthereum1->SetAsset("ETH");
			IncomingClaimEthereum1->SetEstimateGas(Decimal::Zero());
			IncomingClaimEthereum1->SetWitness(14977180,
				"0x3bc2c98682f1b8feaacbde8f3f56494cd778da9d042da8439fb698d41bf060ea", 0.0,
				{ Mediator::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 150) },
				{ Mediator::Transferer(AddressEthereum1->Addresses.begin()->second, AddressEthereum1->AddressIndex, 150) });
			VI_PANIC(IncomingClaimEthereum1->Sign(User1.SecretKey, User1Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimEthereum1);

			auto* IncomingClaimEthereum2 = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimEthereum2->SetAsset("ETH");
			IncomingClaimEthereum2->SetEstimateGas(Decimal::Zero());
			IncomingClaimEthereum2->SetWitness(14977181,
				"0x7bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
				{ Mediator::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 110) },
				{ Mediator::Transferer(AddressEthereum2->Addresses.begin()->second, AddressEthereum2->AddressIndex, 110) });
			VI_PANIC(IncomingClaimEthereum2->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimEthereum2);

			auto* IncomingClaimRipple = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimRipple->SetAsset("XRP");
			IncomingClaimRipple->SetEstimateGas(Decimal::Zero());
			IncomingClaimRipple->SetWitness(88546831,
				"6618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
				{ Mediator::Transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", Optional::None, 1100) },
				{ Mediator::Transferer(AddressRipple->Addresses.begin()->second, AddressRipple->AddressIndex, 1100) });
			VI_PANIC(IncomingClaimRipple->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimRipple);

			auto* IncomingClaimBitcoin = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimBitcoin->SetAsset("BTC");
			IncomingClaimBitcoin->SetEstimateGas(Decimal::Zero());
			IncomingClaimBitcoin->SetWitness(846983,
				"17638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
				{ Mediator::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, 1.1) },
				{ Mediator::Transferer(AddressBitcoin->Addresses.begin()->second, AddressBitcoin->AddressIndex, 1.1) });
			VI_PANIC(IncomingClaimBitcoin->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimBitcoin);
		}
		static void DelegatedCustodianAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* DelegationAccountEthereum = Memory::New<Transactions::DelegationAccount>();
			DelegationAccountEthereum->SetAsset("ETH");
			DelegationAccountEthereum->SetEstimateGas(Decimal::Zero());
			DelegationAccountEthereum->SetProposer(User2.PublicKeyHash);
			VI_PANIC(DelegationAccountEthereum->Sign(User2.SecretKey, User2Sequence++), "account not signed");
			Transactions.push_back(DelegationAccountEthereum);

			auto* DelegationAccountRipple = Memory::New<Transactions::DelegationAccount>();
			DelegationAccountRipple->SetAsset("XRP");
			DelegationAccountRipple->SetEstimateGas(Decimal::Zero());
			DelegationAccountRipple->SetProposer(User2.PublicKeyHash);
			VI_PANIC(DelegationAccountRipple->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(DelegationAccountRipple);

			auto* DelegationAccountBitcoin = Memory::New<Transactions::DelegationAccount>();
			DelegationAccountBitcoin->SetAsset("BTC");
			DelegationAccountBitcoin->SetEstimateGas(Decimal::Zero());
			DelegationAccountBitcoin->SetProposer(User2.PublicKeyHash);
			VI_PANIC(DelegationAccountBitcoin->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(DelegationAccountBitcoin);
		}
		static void Claims(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto ProposerAddresses = *Context.GetWitnessAddressesByPurpose(User2.PublicKeyHash, States::AddressType::Custodian, 0, 128);
			auto OwnerAddresses = *Context.GetWitnessAddressesByPurpose(User1.PublicKeyHash, States::AddressType::Custodian, 0, 128);
			auto AddressEthereum = std::find_if(ProposerAddresses.begin(), ProposerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
			auto AddressRipple = std::find_if(OwnerAddresses.begin(), OwnerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("XRP"); });
			auto AddressBitcoin = std::find_if(OwnerAddresses.begin(), OwnerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("BTC"); });
			VI_PANIC(AddressEthereum != ProposerAddresses.end(), "ethereum custodian address not found");
			VI_PANIC(AddressRipple != OwnerAddresses.end(), "ripple custodian address not found");
			VI_PANIC(AddressBitcoin != OwnerAddresses.end(), "bitcoin custodian address not found");

			auto* IncomingClaimEthereum = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimEthereum->SetAsset("ETH");
			IncomingClaimEthereum->SetEstimateGas(Decimal::Zero());
			IncomingClaimEthereum->SetWitness(14977180,
				"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
				{ Mediator::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 100) },
				{ Mediator::Transferer(AddressEthereum->Addresses.begin()->second, AddressEthereum->AddressIndex, 100) });
			VI_PANIC(IncomingClaimEthereum->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimEthereum);

			auto* IncomingClaimRipple = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimRipple->SetAsset("XRP");
			IncomingClaimRipple->SetEstimateGas(Decimal::Zero());
			IncomingClaimRipple->SetWitness(88546830,
				"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
				{ Mediator::Transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", Optional::None, 1000) },
				{ Mediator::Transferer(AddressRipple->Addresses.begin()->second, AddressRipple->AddressIndex, 1000) });
			VI_PANIC(IncomingClaimRipple->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimRipple);

			auto* IncomingClaimBitcoin = Memory::New<Transactions::IncomingClaim>();
			IncomingClaimBitcoin->SetAsset("BTC");
			IncomingClaimBitcoin->SetEstimateGas(Decimal::Zero());
			IncomingClaimBitcoin->SetWitness(846982,
				"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
				{ Mediator::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, 1.0) },
				{ Mediator::Transferer(AddressBitcoin->Addresses.begin()->second, AddressBitcoin->AddressIndex, 1.0) });
			VI_PANIC(IncomingClaimBitcoin->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
			Transactions.push_back(IncomingClaimBitcoin);
		}
		static void Transfers(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* OmnitransferEthereum = Memory::New<Transactions::Omnitransfer>();
			OmnitransferEthereum->SetAsset("ETH");
			OmnitransferEthereum->SetTo(User2.PublicKeyHash, 0.1);
			OmnitransferEthereum->SetTo(User2.PublicKeyHash, 0.2);
			OmnitransferEthereum->SetTo(User2.PublicKeyHash, 0.3);
			OmnitransferEthereum->SetTo(User2.PublicKeyHash, 0.4);
			OmnitransferEthereum->SetTo(User2.PublicKeyHash, 0.5);
			OmnitransferEthereum->SetEstimateGas(std::string_view("0.00000001"));
			VI_PANIC(OmnitransferEthereum->Sign(User1.SecretKey, User1Sequence++), "omnitransfer not signed");
			Transactions.push_back(OmnitransferEthereum);

			auto* TransferRipple = Memory::New<Transactions::Transfer>();
			TransferRipple->SetAsset("XRP");
			TransferRipple->SetTo(User2.PublicKeyHash, 10.0);
			TransferRipple->SetEstimateGas(std::string_view("0.000068"));
			VI_PANIC(TransferRipple->Sign(User1.SecretKey, User1Sequence++), "transfer not signed");
			Transactions.push_back(TransferRipple);

			auto* TransferBitcoin = Memory::New<Transactions::Transfer>();
			TransferBitcoin->SetAsset("BTC");
			TransferBitcoin->SetTo(User2.PublicKeyHash, 0.1);
			TransferBitcoin->SetEstimateGas(std::string_view("0.0000000005"));
			VI_PANIC(TransferBitcoin->Sign(User1.SecretKey, User1Sequence++), "transfer not signed");
			Transactions.push_back(TransferBitcoin);
		}
		static void TransferToWallet(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users, size_t UserId, const Algorithm::AssetId& Asset, const std::string_view& Address, const Decimal& Value)
		{
			auto& [User1, User1Sequence] = Users[UserId];
			Algorithm::Pubkeyhash PublicKeyHash;
			Algorithm::Signing::DecodeAddress(Address, PublicKeyHash);

			auto* TransferAsset = Memory::New<Transactions::Transfer>();
			TransferAsset->Asset = Asset;
			TransferAsset->SetTo(PublicKeyHash, Value);
			TransferAsset->SetEstimateGas(std::string_view("0.0000000005"));
			VI_PANIC(TransferAsset->Sign(User1.SecretKey, User1Sequence++), "transfer not signed");
			Transactions.push_back(TransferAsset);
		}
		static void Rollups(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto* MultiAssetRollup = Memory::New<Transactions::Rollup>();
			MultiAssetRollup->SetAsset("ETH");

			auto TransferEthereum1 = Transactions::Transfer();
			TransferEthereum1.SetTo(User2.PublicKeyHash, 0.1);
			VI_PANIC(MultiAssetRollup->Merge(TransferEthereum1, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferEthereum2 = Transactions::Transfer();
			TransferEthereum2.SetTo(User2.PublicKeyHash, 0.2);
			VI_PANIC(MultiAssetRollup->Merge(TransferEthereum2, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferEthereum3 = Transactions::Transfer();
			TransferEthereum3.SetTo(User1.PublicKeyHash, 0.2);
			VI_PANIC(MultiAssetRollup->Merge(TransferEthereum3, User2.SecretKey, User2Sequence++), "transfer not signed");

			auto TransferRipple1 = Transactions::Transfer();
			TransferRipple1.SetAsset("XRP");
			TransferRipple1.SetTo(User2.PublicKeyHash, 1);
			VI_PANIC(MultiAssetRollup->Merge(TransferRipple1, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferRipple2 = Transactions::Transfer();
			TransferRipple2.SetAsset("XRP");
			TransferRipple2.SetTo(User2.PublicKeyHash, 2);
			VI_PANIC(MultiAssetRollup->Merge(TransferRipple2, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferRipple3 = Transactions::Transfer();
			TransferRipple3.SetAsset("XRP");
			TransferRipple3.SetTo(User1.PublicKeyHash, 2);
			VI_PANIC(MultiAssetRollup->Merge(TransferRipple3, User2.SecretKey, User2Sequence++), "transfer not signed");

			auto TransferBitcoin1 = Transactions::Transfer();
			TransferBitcoin1.SetAsset("BTC");
			TransferBitcoin1.SetTo(User2.PublicKeyHash, 0.001);
			VI_PANIC(MultiAssetRollup->Merge(TransferBitcoin1, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferBitcoin2 = Transactions::Transfer();
			TransferBitcoin2.SetAsset("BTC");
			TransferBitcoin2.SetTo(User2.PublicKeyHash, 0.002);
			VI_PANIC(MultiAssetRollup->Merge(TransferBitcoin2, User1.SecretKey, User1Sequence++), "transfer not signed");

			auto TransferBitcoin3 = Transactions::Transfer();
			TransferBitcoin3.SetAsset("BTC");
			TransferBitcoin3.SetTo(User1.PublicKeyHash, 0.002);
			VI_PANIC(MultiAssetRollup->Merge(TransferBitcoin3, User2.SecretKey, User2Sequence++), "transfer not signed");

			MultiAssetRollup->SetEstimateGas(std::string_view("0.00000001"));
			VI_PANIC(MultiAssetRollup->Sign(User1.SecretKey, User1Sequence++), "rollup not signed");
			Transactions.push_back(MultiAssetRollup);
		}
		static void Deployments(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			Ledger::Wallet TokenContract = Ledger::Wallet::FromSeed(String("token") + String((char*)User1.SecretKey, sizeof(User1.SecretKey)));
			std::string_view TokenProgram = VI_STRINGIFY(
				class token_info
			{
				address owner;
				string name;
				string symbol;
				uint8 decimals = 0;
				uint256 supply = 0;
			}

			class token_balance
			{
				address owner;
				uint256 value = 0;
			}

			class token_transfer
			{
				address from;
				address to;
				uint256 value = 0;
			}

			token_info initialize(program@ context, const uint256 & in value)
			{
				token_info token;
				token.owner = context.from();
				token.name = "USD Token";
				token.symbol = "USD";
				token.decimals = 2;
				token.supply = value;

				token_balance output;
				output.owner = token.owner;
				output.value = value;

				context.store(context.to(), token);
				context.store(output.owner, output);
				return token;
			}
			token_transfer transfer(program@ context, const address & in to, const uint256 & in value)
			{
				address from = context.from();
				token_balance input;
				if (!context.load(from, input))
					input.owner = from;

				token_balance output;
				if (!context.load(to, output))
					output.owner = to;

				uint256 from_delta = input.value - value;
				if (from_delta > input.value)
					throw exception_ptr("logical_error", "from balance will underflow (" + input.value.to_string() + " < " + value.to_string() + ")");

				uint256 to_delta = output.value + value;
				if (to_delta < output.value)
					throw exception_ptr("argument_error", "to balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				input.value = from_delta;
				output.value = to_delta;
				context.store(input.owner, input);
				context.store(output.owner, output);

				token_transfer event;
				event.from = input.owner;
				event.to = output.owner;
				event.value = value;
				return event;
			}
			uint256 mint(program@ context, const uint256 & in value)
			{
				token_info token;
				if (!context.load(context.to(), token) || token.owner != context.from())
					throw exception_ptr("logical_error", "from does not own the token");

				token_balance output;
				if (!context.load(token.owner, output))
					output.owner = token.owner;

				uint256 supply_delta = token.supply + value;
				if (supply_delta < token.supply)
					throw exception_ptr("argument_error", "token supply will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				uint256 to_delta = output.value + value;
				if (to_delta < output.value)
					throw exception_ptr("argument_error", "owner balance will overflow (" + output.value.to_string() + " + " + value.to_string() + " > uint256_max)");

				token.supply = supply_delta;
				output.value = to_delta;
				context.store(context.to(), token);
				context.store(output.owner, output);
				return output.value;
			}
			uint256 burn(program@ context, const uint256 & in value)
			{
				token_info token;
				if (!context.load(context.to(), token) || token.owner != context.from())
					throw exception_ptr("logical_error", "from does not own the token");

				token_balance output;
				if (!context.load(token.owner, output))
					output.owner = token.owner;

				uint256 supply_delta = token.supply - value;
				if (supply_delta > token.supply)
					throw exception_ptr("logical_error", "token supply will underflow (" + token.supply.to_string() + " < " + value.to_string() + ")");

				uint256 to_delta = output.value - value;
				if (to_delta > output.value)
					throw exception_ptr("argument_error", "owner balance will underflow (" + output.value.to_string() + " < " + value.to_string() + ")");

				token.supply = supply_delta;
				output.value = to_delta;
				context.store(context.to(), token);
				context.store(output.owner, output);
				return output.value;
			}
			uint256 balance_of(program@ const context, const address & in owner)
			{
				token_balance output;
				if (!context.load(owner, output))
					output.owner = owner;
				return output.value;
			}
			token_info info(program@ const context)
			{
				token_info token;
				if (!context.load(context.to(), token))
					throw exception_ptr("logical_error", "token info not found");

				return token;
			});

			auto* DeploymentEthereum1 = Memory::New<Transactions::Deployment>();
			DeploymentEthereum1->SetAsset("ETH");
			DeploymentEthereum1->SetCalldata(TokenProgram, { Format::Variable(1000000u) });
			DeploymentEthereum1->SignLocation(TokenContract.SecretKey);
			DeploymentEthereum1->SetEstimateGas(std::string_view("0.00000001"));
			VI_PANIC(DeploymentEthereum1->Sign(User1.SecretKey, User1Sequence++), "deployment not signed");
			Transactions.push_back(DeploymentEthereum1);

			Ledger::Wallet BridgeContract = Ledger::Wallet::FromSeed(String("bridge") + String((char*)User1.SecretKey, sizeof(User1.SecretKey)));
			std::string_view BridgeProgram = VI_STRINGIFY(
				class token_balance
			{
				address owner;
				uint256 value = 0;
			}

			uint256 my_balance(program@ const context)
			{
				uint256 from_balance = 0;
				context.call("%s", "balance_of", context.from(), from_balance);
				return from_balance;
			});

			auto* DeploymentEthereum2 = Memory::New<Transactions::Deployment>();
			DeploymentEthereum2->SetAsset("ETH");
			DeploymentEthereum2->SetCalldata(Stringify::Text(BridgeProgram.data(), TokenContract.GetAddress().c_str()), { });
			DeploymentEthereum2->SignLocation(BridgeContract.SecretKey);
			DeploymentEthereum2->SetEstimateGas(std::string_view("0.00000001"));
			VI_PANIC(DeploymentEthereum2->Sign(User1.SecretKey, User1Sequence++), "deployment not signed");
			Transactions.push_back(DeploymentEthereum2);
		}
		static void Invocations(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			Ledger::Wallet TokenContract = Ledger::Wallet::FromSeed(String("token") + String((char*)User1.SecretKey, sizeof(User1.SecretKey)));
			auto* InvocationEthereum1 = Memory::New<Transactions::Invocation>();
			InvocationEthereum1->SetAsset("ETH");
			InvocationEthereum1->SetCalldata(TokenContract.PublicKeyHash, "transfer", { Format::Variable(std::string_view((char*)User2.PublicKeyHash, sizeof(User2.PublicKeyHash))), Format::Variable(250000u) });
			InvocationEthereum1->SetEstimateGas(std::string_view("0.00000001"));
			VI_PANIC(InvocationEthereum1->Sign(User1.SecretKey, User1Sequence++), "invocation not signed");
			Transactions.push_back(InvocationEthereum1);

			Ledger::Wallet BridgeContract = Ledger::Wallet::FromSeed(String("bridge") + String((char*)User1.SecretKey, sizeof(User1.SecretKey)));
			auto* InvocationBitcoin = Memory::New<Transactions::Invocation>();
			InvocationBitcoin->SetAsset("BTC");
			InvocationBitcoin->SetCalldata(BridgeContract.PublicKeyHash, "my_balance", { });
			InvocationBitcoin->SetEstimateGas(std::string_view("0.0000000005"));
			VI_PANIC(InvocationBitcoin->Sign(User1.SecretKey, User1Sequence++), "invocation not signed");
			Transactions.push_back(InvocationBitcoin);
		}
		static void MigrationsStage1(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto Depository = Context.GetAccountDepository(Algorithm::Asset::IdOf("ETH"), User2.PublicKeyHash);
			if (!Depository)
				return;

			auto* CustodianAccountEthereum = Memory::New<Transactions::CustodianAccount>();
			CustodianAccountEthereum->SetAsset("ETH");
			CustodianAccountEthereum->SetEstimateGas(Decimal::Zero());
			CustodianAccountEthereum->SetWallet(&Context, User1, User1.PublicKeyHash).Expect("custodian address not deployed");
			VI_PANIC(CustodianAccountEthereum->Sign(User1.SecretKey, User1Sequence++), "account not signed");
			Transactions.push_back(CustodianAccountEthereum);
		}
		static void MigrationsStage2(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto Depository = Context.GetAccountDepository(Algorithm::Asset::IdOf("ETH"), User2.PublicKeyHash);
			if (!Depository)
				return;

			auto* DepositoryMigrationEthereum = Memory::New<Transactions::DepositoryMigration>();
			DepositoryMigrationEthereum->SetAsset("ETH");
			DepositoryMigrationEthereum->SetEstimateGas(Decimal::Zero());
			DepositoryMigrationEthereum->SetProposer(User1.PublicKeyHash, Depository->Custody);
			VI_PANIC(DepositoryMigrationEthereum->Sign(User2.SecretKey, User2Sequence++), "depository migration not signed");
			Transactions.push_back(DepositoryMigrationEthereum);
		}
		static void WithdrawalsStage1(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto* WithdrawalEthereum = Memory::New<Transactions::Withdrawal>();
			WithdrawalEthereum->SetAsset("ETH");
			WithdrawalEthereum->SetEstimateGas(Decimal::Zero());
			WithdrawalEthereum->SetTo("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Context.GetAccountBalance(Algorithm::Asset::IdOf("ETH"), User1.PublicKeyHash).Expect("user balance not valid").GetBalance());
			WithdrawalEthereum->SetProposer(User1.PublicKeyHash);
			VI_PANIC(WithdrawalEthereum->Sign(User1.SecretKey, User1Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalEthereum);

			auto* WithdrawalRipple = Memory::New<Transactions::Withdrawal>();
			WithdrawalRipple->SetAsset("XRP");
			WithdrawalRipple->SetEstimateGas(Decimal::Zero());
			WithdrawalRipple->SetTo("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", Context.GetAccountBalance(Algorithm::Asset::IdOf("XRP"), User1.PublicKeyHash).Expect("user balance not valid").GetBalance());
			WithdrawalRipple->SetProposer(User2.PublicKeyHash);
			VI_PANIC(WithdrawalRipple->Sign(User1.SecretKey, User1Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalRipple);

			auto* WithdrawalBitcoin = Memory::New<Transactions::Withdrawal>();
			WithdrawalBitcoin->SetAsset("BTC");
			WithdrawalBitcoin->SetEstimateGas(Decimal::Zero());
			WithdrawalBitcoin->SetTo("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Context.GetAccountBalance(Algorithm::Asset::IdOf("BTC"), User1.PublicKeyHash).Expect("user balance not valid").GetBalance());
			WithdrawalBitcoin->SetProposer(User2.PublicKeyHash);
			VI_PANIC(WithdrawalBitcoin->Sign(User1.SecretKey, User1Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalBitcoin);
		}
		static void WithdrawalsStage2(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Context = Ledger::TransactionContext();
			auto* WithdrawalEthereum = Memory::New<Transactions::Withdrawal>();
			WithdrawalEthereum->SetAsset("ETH");
			WithdrawalEthereum->SetEstimateGas(Decimal::Zero());
			WithdrawalEthereum->SetTo("0x89a0181659bd280836A2d33F57e3B5Dfa1a823CE", Context.GetAccountBalance(Algorithm::Asset::IdOf("ETH"), User2.PublicKeyHash).Expect("proposer balance not valid").GetBalance());
			WithdrawalEthereum->SetProposer(User1.PublicKeyHash);
			VI_PANIC(WithdrawalEthereum->Sign(User2.SecretKey, User2Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalEthereum);

			auto* WithdrawalRipple = Memory::New<Transactions::Withdrawal>();
			WithdrawalRipple->SetAsset("XRP");
			WithdrawalRipple->SetEstimateGas(Decimal::Zero());
			WithdrawalRipple->SetTo("rJGb4etn9GSwNHYVu7dNMbdiVgzqxaTSUG", Context.GetAccountBalance(Algorithm::Asset::IdOf("XRP"), User2.PublicKeyHash).Expect("proposer balance not valid").GetBalance());
			WithdrawalRipple->SetProposer(User2.PublicKeyHash);
			VI_PANIC(WithdrawalRipple->Sign(User2.SecretKey, User2Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalRipple);

			auto* WithdrawalBitcoin = Memory::New<Transactions::Withdrawal>();
			WithdrawalBitcoin->SetAsset("BTC");
			WithdrawalBitcoin->SetEstimateGas(Decimal::Zero());
			WithdrawalBitcoin->SetTo("bcrt1p2w7gkghj7arrjy4c45kh7450458hr8dv9pu9576lx08uuh4je7eqgskm9v", Context.GetAccountBalance(Algorithm::Asset::IdOf("BTC"), User2.PublicKeyHash).Expect("proposer balance not valid").GetBalance());
			WithdrawalBitcoin->SetProposer(User2.PublicKeyHash);
			VI_PANIC(WithdrawalBitcoin->Sign(User2.SecretKey, User2Sequence++), "withdrawal not signed");
			Transactions.push_back(WithdrawalBitcoin);
		}
		static void Deallocations(Vector<UPtr<Ledger::Transaction>>& Transactions, Vector<Account>& Users)
		{
			auto& [User1, User1Sequence] = Users[0];
			auto& [User2, User2Sequence] = Users[1];
			auto Chain = Storages::Chainstate(__func__);
			auto Operations = Chain.GetBlockTransactionsByOwner(std::numeric_limits<int64_t>::max(), User2.PublicKeyHash, 1, 0, 1024);
			if (!Operations)
				return;

			for (auto& Item : *Operations)
			{
				if (Item.Transaction->AsType() != Transactions::ContributionActivation::AsInstanceType())
					continue;

				OrderedSet<String> Parties;
				if (!Item.Transaction->RecoverMany(Item.Receipt, Parties))
					continue;

				auto* ContributionDeallocation = Memory::New<Transactions::ContributionDeallocation>();
				ContributionDeallocation->Asset = Item.Transaction->Asset;
				ContributionDeallocation->SetEstimateGas(Decimal::Zero());
				if (Parties.find(String((char*)User1.PublicKeyHash, sizeof(User1.PublicKeyHash))) == Parties.end())
				{
					ContributionDeallocation->SetWitness(User2.SecretKey, Item.Receipt.TransactionHash);
					VI_PANIC(ContributionDeallocation->Sign(User2.SecretKey, User2Sequence++), "depository deallocation not signed");
				}
				else
				{
					ContributionDeallocation->SetWitness(User1.SecretKey, Item.Receipt.TransactionHash);
					VI_PANIC(ContributionDeallocation->Sign(User1.SecretKey, User1Sequence++), "depository deallocation not signed");
				}
				Transactions.push_back(ContributionDeallocation);
			}
		}
	};

public:
	/* 256bit integer serialization */
	static void GenericIntegerSerialization()
	{
		auto* Term = Console::Get();
		Term->CaptureTime();

		size_t Samples = 1024 * 4;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Value = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(32));

			uint8_t Data1[32] = { 0 }; uint256_t Value1 = 0;
			Algorithm::Encoding::DecodeUint256(Value, Data1);
			Algorithm::Encoding::EncodeUint256(Data1, Value1);
			VI_PANIC(Value == Value1, "uint256 serialization failed");
		}

		double Time = Term->GetCapturedTime();
		Term->fWriteLine("uint256 serialization time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time);
	}
	/* 256bit => decimal conversion */
	static void GenericIntegerConversion()
	{
		auto* Term = Console::Get();
		size_t Samples = 100; double Time = 0;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Number;
			Algorithm::Encoding::EncodeUint256((uint8_t*)Crypto::RandomBytes(32)->data(), Number);

			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 256bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples * 5; i++)
		{
			uint256_t Number = Math64u::Random(0, std::numeric_limits<uint64_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 64bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples * 5; i++)
		{
			uint256_t Number = Math32u::Random(0, std::numeric_limits<uint32_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 32bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples * 10; i++)
		{
			uint256_t Number = Math32u::Random(0, std::numeric_limits<uint16_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 16bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
	}
	/* 256bit => decimal conversion */
	static void GenericMessageSerialization()
	{
		Algorithm::Pubkeyhash Owner;
		Algorithm::Hashing::Hash160((uint8_t*)"publickeyhash", 13, Owner);
		uint64_t BlockNumber = 1;
		uint64_t BlockNonce = 1;
		
		UPtr<Schema> Data = Var::Set::Object();
		NewSerializationComparison<Mediator::MasterWallet>(*Data);
		NewSerializationComparison<Mediator::DerivedVerifyingWallet>(*Data);
		NewSerializationComparison<Mediator::DerivedSigningWallet>(*Data);
		NewSerializationComparison<Mediator::IncomingTransaction>(*Data);
		NewSerializationComparison<Mediator::OutgoingTransaction>(*Data);
		NewSerializationComparison<Mediator::IndexAddress>(*Data);
		NewSerializationComparison<Mediator::IndexUTXO>(*Data);
		NewSerializationComparison<Ledger::Receipt>(*Data);
		NewSerializationComparison<Ledger::Wallet>(*Data);
		NewSerializationComparison<Ledger::Validator>(*Data);
		NewSerializationComparison<Ledger::BlockTransaction>(*Data);
		NewSerializationComparison<Ledger::BlockHeader>(*Data);
		NewSerializationComparison<Ledger::Block>(*Data);
		NewSerializationComparison<Ledger::BlockProof>(*Data, Ledger::BlockHeader(), (Ledger::BlockHeader*)nullptr);
		NewSerializationComparison<States::AccountSequence>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountWork>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountObserver>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountProgram>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountStorage>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountReward>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountDerivation>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountBalance>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::AccountDepository>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::WitnessProgram>(*Data, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::WitnessEvent>(*Data, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::WitnessAddress>(*Data, Owner, BlockNumber++, BlockNonce++);
		NewSerializationComparison<States::WitnessTransaction>(*Data, BlockNumber++, BlockNonce++);
		NewSerializationComparison<Transactions::Transfer>(*Data);
		NewSerializationComparison<Transactions::Omnitransfer>(*Data);
		NewSerializationComparison<Transactions::Deployment>(*Data);
		NewSerializationComparison<Transactions::Invocation>(*Data);
		NewSerializationComparison<Transactions::Withdrawal>(*Data);
		NewSerializationComparison<Transactions::Rollup>(*Data);
		NewSerializationComparison<Transactions::Commitment>(*Data);
		NewSerializationComparison<Transactions::IncomingClaim>(*Data);
		NewSerializationComparison<Transactions::OutgoingClaim>(*Data);
		NewSerializationComparison<Transactions::AddressAccount>(*Data);
		NewSerializationComparison<Transactions::PubkeyAccount>(*Data);
		NewSerializationComparison<Transactions::DelegationAccount>(*Data);
		NewSerializationComparison<Transactions::CustodianAccount>(*Data);
		NewSerializationComparison<Transactions::ContributionAllocation>(*Data);
		NewSerializationComparison<Transactions::ContributionSelection>(*Data);
		NewSerializationComparison<Transactions::ContributionActivation>(*Data);
		NewSerializationComparison<Transactions::ContributionDeallocation>(*Data);
		NewSerializationComparison<Transactions::ContributionDeselection>(*Data);
		NewSerializationComparison<Transactions::ContributionDeactivation>(*Data);
		NewSerializationComparison<Transactions::DepositoryAdjustment>(*Data);
		NewSerializationComparison<Transactions::ContributionSelection>(*Data);
		NewSerializationComparison<Transactions::DepositoryMigration>(*Data);

		auto* Term = Console::Get();
		Term->jWriteLine(*Data);
	}
	/* Prove and verify Nakamoto POW */
	static void CryptographyNakamoto()
	{
		auto* Term = Console::Get();
		Term->CaptureTime();

		auto Message = "Hello, World!";
		uint256_t Target = uint256_t(1) << uint256_t(244);
		uint256_t Nonce = 0;
		while (true)
		{
			auto Solution = Algorithm::NPOW::Evaluate(Nonce, Message);
			if (Algorithm::NPOW::Verify(Nonce, Message, Target, Solution))
			{
				UPtr<Schema> Data = Var::Set::Object();
				Data->Set("solution", Algorithm::Encoding::SerializeUint256(Solution));
				Data->Set("nonce", Algorithm::Encoding::SerializeUint256(Nonce));
				Data->Set("milliseconds", Var::Set::Number(Term->GetCapturedTime()));
				Term->jWriteLine(*Data);
				break;
			}
			else
				++Nonce;
		}
	}
	/* Prove and verify Wesolowski VDF signature */
	static void CryptographyWesolowski()
	{
		auto* Term = Console::Get();
		Term->CaptureTime();

		auto Message = "Hello, World!";
		auto Alg = Algorithm::WVDF::Parameters(); Alg.Pow *= 12;
		auto Signature = Algorithm::WVDF::Evaluate(Alg, Message);
		bool Proven = Algorithm::WVDF::Verify(Alg, Message, Signature);
		UPtr<Schema> Data = Var::Set::Object();
		Data->Set("solution", Var::String(Format::Util::Encode0xHex(Signature)));
		Data->Set("milliseconds", Var::Set::Number(Term->GetCapturedTime()));
		Term->jWriteLine(*Data);
		VI_PANIC(Proven, "wesolowki proof is not valid");
	}
	/* Cryptographic signatures */
	static void CryptographySignatures()
	{
		auto* Term = Console::Get();
		String Mnemonic = "chimney clerk liberty defense gesture risk disorder switch raven chapter document admit win swing forward please clerk vague online coil material tone sibling intact";
		Algorithm::Seckey SecretKey;
		Algorithm::Pubkey PublicKey;
		Algorithm::Pubkeyhash PublicKeyHash;
		Algorithm::Signing::DeriveSecretKeyFromMnemonic(Mnemonic, SecretKey);
		Algorithm::Signing::DerivePublicKey(SecretKey, PublicKey);
		Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);

		String EncodedSecretKey, EncodedPublicKey, EncodedPublicKeyHash;
		Algorithm::Signing::EncodeSecretKey(SecretKey, EncodedSecretKey);
		Algorithm::Signing::EncodePublicKey(PublicKey, EncodedPublicKey);
		Algorithm::Signing::EncodeAddress(PublicKeyHash, EncodedPublicKeyHash);

		String Message = "Hello, World!";
		uint256_t MessageHash = Algorithm::Hashing::Hash256i(Message);
		String EncodedMessageHash = Algorithm::Encoding::Encode0xHex256(MessageHash);
		Algorithm::Recsighash MessageSignature;
		Algorithm::Pubkey RecoverPublicKey;
		Algorithm::Pubkeyhash RecoverPublicKeyHash;
		bool Verifies = Algorithm::Signing::Sign(MessageHash, SecretKey, MessageSignature) && Algorithm::Signing::Verify(MessageHash, PublicKey, MessageSignature);
		bool RecoversPublicKey = Algorithm::Signing::Recover(MessageHash, RecoverPublicKey, MessageSignature);
		bool RecoversPublicKeyHash = Algorithm::Signing::RecoverHash(MessageHash, RecoverPublicKeyHash, MessageSignature);
		String EncodedMessageSignature = Format::Util::Encode0xHex(std::string_view((char*)MessageSignature, sizeof(MessageSignature)));
		String EncodedRecoverPublicKey, EncodedRecoverPublicKeyHash;
		Algorithm::Signing::EncodePublicKey(RecoverPublicKey, EncodedRecoverPublicKey);
		Algorithm::Signing::EncodeAddress(RecoverPublicKeyHash, EncodedRecoverPublicKeyHash);

		auto Info = UPtr<Schema>(Var::Set::Object());
		Info->Set("mnemonic", Var::String(Mnemonic));
		Info->Set("mnemonic_test", Var::String(Algorithm::Signing::VerifyMnemonic(Mnemonic) ? "passed" : "failed"));
		Info->Set("secret_key", Var::String(EncodedSecretKey));
		Info->Set("secret_key_test", Var::String(Algorithm::Signing::VerifySecretKey(SecretKey) ? "passed" : "failed"));
		Info->Set("public_key", Var::String(EncodedPublicKey));
		Info->Set("public_key_test", Var::String(Algorithm::Signing::VerifyPublicKey(PublicKey) ? "passed" : "failed"));
		Info->Set("address", Var::String(EncodedPublicKeyHash));
		Info->Set("address_test", Var::String(Algorithm::Signing::VerifyAddress(EncodedPublicKeyHash) ? "passed" : "failed"));
		Info->Set("message", Var::String(Message));
		Info->Set("message_hash", Var::String(EncodedMessageHash));
		Info->Set("signature", Var::String(EncodedMessageSignature));
		Info->Set("signature_test", Var::String(Verifies ? "passed" : "failed"));
		Info->Set("recover_public_key", Var::String(EncodedRecoverPublicKey));
		Info->Set("recover_public_key_test", Var::String(RecoversPublicKey && EncodedRecoverPublicKey == EncodedPublicKey ? "passed" : "failed"));
		Info->Set("recover_address", Var::String(EncodedRecoverPublicKeyHash));
		Info->Set("recover_address_test", Var::String(RecoversPublicKeyHash && EncodedRecoverPublicKeyHash == EncodedPublicKeyHash ? "passed" : "failed"));

		Term->jWriteLine(*Info);
		VI_PANIC(Schema::ToJSON(*Info).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Wallet cryptography */
	static void CryptographyWallet()
	{
		auto* Term = Console::Get();
		auto Wallet = Ledger::Wallet::FromSeed();
		auto WalletInfo = Wallet.AsSchema();
		WalletInfo->Set("secret_key_test", Var::String(Algorithm::Signing::VerifySecretKey(Wallet.SecretKey) ? "passed" : "failed"));
		WalletInfo->Set("public_key_test", Var::String(Algorithm::Signing::VerifyPublicKey(Wallet.PublicKey) ? "passed" : "failed"));
		WalletInfo->Set("address_test", Var::String(Algorithm::Signing::VerifyAddress(Wallet.GetAddress()) ? "passed" : "failed"));

		Term->jWriteLine(*WalletInfo);
		VI_PANIC(Schema::ToJSON(*WalletInfo).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Shared wallet cryptography */
	static void CryptographyWalletSharing()
	{
		auto* Term = Console::Get();
		auto* Server = NSS::ServerNode::Get();
		auto Id = Algorithm::Asset::IdOf("BTC");
		auto Alg = Algorithm::Composition::Type::SECP256K1;
		String Hash1 = *Crypto::HashRaw(Digests::SHA256(), "seed1");
		String Hash2 = *Crypto::HashRaw(Digests::SHA256(), "seed2");
		String Message = "Hello, World!";
		size_t PublicKeySize = 0;
		size_t SecretKeySize = 0;
		Algorithm::Composition::CPubkey PublicKey;
		Algorithm::Composition::CSeckey SecretKey;
		Algorithm::Composition::CSeed Seed1, Seed2;
		Algorithm::Composition::CSeckey SecretKey1, SecretKey2;
		Algorithm::Composition::CPubkey PublicKey1, PublicKey2;
		Algorithm::Composition::ConvertToSecretSeed((uint8_t*)Hash1.data(), *Crypto::RandomBytes(64), Seed1);
		Algorithm::Composition::ConvertToSecretSeed((uint8_t*)Hash2.data(), *Crypto::RandomBytes(64), Seed2);
		Algorithm::Composition::DeriveKeypair1(Alg, Seed1, SecretKey1, PublicKey1);
		Algorithm::Composition::DeriveKeypair2(Alg, Seed2, PublicKey1, SecretKey2, PublicKey2, PublicKey, &PublicKeySize);
		Algorithm::Composition::DeriveSecretKey(Alg, SecretKey1, SecretKey2, SecretKey, &SecretKeySize);
		auto SigningWallet = Server->NewSigningWallet(Id, std::string_view((char*)SecretKey, SecretKeySize)).Expect("wallet derivation failed");
		auto VerifyingWallet = Server->NewVerifyingWallet(Id, std::string_view((char*)PublicKey, PublicKeySize)).Expect("wallet derivation failed");
		auto Signature = Server->SignMessage(Id, Message, SigningWallet.SigningKey);
		auto Verification = Signature ? Server->VerifyMessage(Id, Message, SigningWallet.VerifyingKey.ExposeToHeap(), *Signature) : ExpectsLR<void>(LayerException("signature generation failed"));

		UPtr<Schema> Data = Var::Set::Object();
		Data->Set("secret_key_share_1", Var::String(Format::Util::Encode0xHex(std::string_view((char*)SecretKey1, sizeof(SecretKey1)))));
		Data->Set("secret_key_share_2", Var::String(Format::Util::Encode0xHex(std::string_view((char*)SecretKey2, sizeof(SecretKey2)))));
		Data->Set("secret_key_composition", Var::String(Format::Util::Encode0xHex(std::string_view((char*)SecretKey, SecretKeySize))));
		Data->Set("public_key_composition", Var::String(Format::Util::Encode0xHex(std::string_view((char*)PublicKey, PublicKeySize))));
		Data->Set("signing_wallet_secret_key", Var::String(SigningWallet.SigningKey.ExposeToHeap()));
		Data->Set("signing_wallet_public_key", Var::String(SigningWallet.VerifyingKey.ExposeToHeap()));
		Data->Set("signing_wallet_address", Var::String(SigningWallet.Addresses.begin()->second));
		Data->Set("verifying_wallet_public_key", Var::String(VerifyingWallet.VerifyingKey.ExposeToHeap()));
		Data->Set("verifying_wallet_address", Var::String(VerifyingWallet.Addresses.begin()->second));
		Data->Set("signature_payload", Var::String((Signature ? Format::Util::Encode0xHex(*Signature) : Signature.Error().message()) + String(Signature ? "" : " (failed)")));
		Data->Set("signature_verification", Var::String(String(Verification ? "passed" : Verification.Error().what()) + String(Verification ? "" : " (failed)")));
		Data->Set("blob_payload", Var::String(Message));
		Term->jWriteLine(*Data);
		VI_PANIC(Schema::ToJSON(*Data).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Wallet encryption cryptography */
	static void CryptographyWalletMessaging()
	{
		auto* Term = Console::Get();
		auto User1 = Ledger::Wallet::FromSeed();
		auto User2 = Ledger::Wallet::FromSeed();
		auto Nonce1 = uint256_t(110);
		auto Nonce2 = uint256_t(220);

		Algorithm::Seckey CipherSecretKey1, CipherSecretKey2;
		Algorithm::Pubkey CipherPublicKey1, CipherPublicKey2;
		Algorithm::Signing::DeriveCipherKeypair(User1.SecretKey, Nonce1, CipherSecretKey1, CipherPublicKey1);
		Algorithm::Signing::DeriveCipherKeypair(User2.SecretKey, Nonce2, CipherSecretKey2, CipherPublicKey2);

		auto MessageFromUser1 = "Hello, Alice!";
		auto MessageFromUser2 = "Hello, Bob!";
		auto Ciphertext1 = User1.SealMessage(MessageFromUser1, CipherPublicKey2, *Crypto::RandomBytes(64));
		auto Plaintext1 = Ciphertext1 ? User2.OpenMessage(Nonce2, *Ciphertext1) : Option<String>(Optional::None);
		auto Ciphertext2 = User2.SealMessage(MessageFromUser2, CipherPublicKey1, *Crypto::RandomBytes(64));
		auto Plaintext2 = Ciphertext2 ? User1.OpenMessage(Nonce1, *Ciphertext2) : Option<String>(Optional::None);

		UPtr<Schema> Data = Var::Set::Object();
		auto* User1WalletData = Data->Set("user1_wallet", User1.AsSchema().Reset());
		auto* User1WalletMessageData = User1WalletData->Set("message");
		User1WalletMessageData->Set("cipher_nonce", Algorithm::Encoding::SerializeUint256(Nonce1));
		User1WalletMessageData->Set("cipher_secret_key", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherSecretKey1, sizeof(CipherSecretKey1)))));
		User1WalletMessageData->Set("cipher_public_key", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherPublicKey1, sizeof(CipherPublicKey1)))));
		User1WalletMessageData->Set("ciphertext_to_user2_wallet", Var::String(Ciphertext1 ? Format::Util::Encode0xHex(*Ciphertext1).c_str() : "** encryption failed **"));
		User1WalletMessageData->Set("plaintext_from_user2_wallet", Var::String(Plaintext2 ? Plaintext2->c_str() : "** decryption failed **"));
		auto* User2WalletData = Data->Set("user2_wallet", User2.AsSchema().Reset());
		auto* User2WalletMessageData = User2WalletData->Set("message");
		User2WalletMessageData->Set("cipher_nonce", Algorithm::Encoding::SerializeUint256(Nonce2));
		User2WalletMessageData->Set("cipher_secret_key", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherSecretKey2, sizeof(CipherSecretKey2)))));
		User2WalletMessageData->Set("cipher_public_key", Var::String(Format::Util::Encode0xHex(std::string_view((char*)CipherPublicKey2, sizeof(CipherPublicKey2)))));
		User2WalletMessageData->Set("ciphertext_to_user2_wallet", Var::String(Ciphertext2 ? Format::Util::Encode0xHex(*Ciphertext2).c_str() : "** encryption failed **"));
		User2WalletMessageData->Set("plaintext_from_user2_wallet", Var::String(Plaintext1 ? Plaintext1->c_str() : "** decryption failed **"));
		Term->jWriteLine(*Data);
		VI_PANIC(Schema::ToJSON(*Data).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Transaction cryptography */
	static void CryptographyTransaction()
	{
		auto* Term = Console::Get();
		auto Wallet = Ledger::Wallet::FromSeed();
		Vector<UPtr<Ledger::Transaction>> Transactions;
		Vector<Account> Users =
		{
			Account(Wallet, 1),
			Account(Ledger::Wallet::FromSeed(), 1)
		};
		Generators::Transfers(Transactions, Users);
		auto& Tx = *(Transactions::Transfer*)*Transactions.back();
		auto TxBlob = Tx.AsMessage().Data;
		auto TxBody = Format::Stream(TxBlob);
		auto TxCopy = UPtr<Ledger::Transaction>(Transactions::Resolver::New(Messages::Authentic::ResolveType(TxBody).Or(0)));
		auto TxInfo = Tx.AsSchema();
		Algorithm::Pubkeyhash RecoverPublicKeyHash = { 0 };
		TxInfo->Set("recovery_test", Var::String(Tx.RecoverHash(RecoverPublicKeyHash) && !memcmp(Wallet.PublicKeyHash, RecoverPublicKeyHash, sizeof(RecoverPublicKeyHash)) ? "passed" : "failed"));
		TxInfo->Set("verification_test", Var::String(Tx.Verify(Wallet.PublicKey) ? "passed" : "failed"));
		TxInfo->Set("serialization_test", Var::String(TxCopy && TxCopy->Load(TxBody) && TxCopy->AsMessage().Data == TxBlob ? "passed" : "failed"));
		TxInfo->Set("raw_data_test", Var::String(Format::Util::Encode0xHex(TxBlob)));

		auto Stream = Tx.AsMessage();
		Format::Variables Vars;
		Format::VariablesUtil::DeserializeFlatFrom(Stream, &Vars);
		TxInfo->Set("var_data_test", Format::VariablesUtil::Serialize(Vars));
		TxInfo->Set("asset_test", Algorithm::Asset::Serialize(Algorithm::Asset::IdOf("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));

		Term->jWriteLine(*TxInfo);
		VI_PANIC(Schema::ToJSON(*TxInfo).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Merkle tree cryptography */
	static void CryptographyMerkleTree()
	{
		auto* Term = Console::Get();
		const size_t Hashes = 16;
		uint256_t Prev = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(16));
		uint256_t Next = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(16));
		Algorithm::MerkleTree Tree = Prev;
		for (size_t i = 0; i < Hashes; i++)
		{
			uint8_t Hash[32];
			Algorithm::Encoding::DecodeUint256(Next, Hash);

			Tree.Push(Next);
			Next = Algorithm::Hashing::Hash256i(std::string_view((char*)Hash, sizeof(Hash)));
		}

		auto& Nodes = Tree.GetTree();
		uint256_t Target = Nodes[Math64u::Random(1, Hashes + 1)];
		Term->fWriteLine("merkle tree (nodes = %i, target = %s):", (int)Nodes.size(), Algorithm::Encoding::Encode0xHex256(Target).c_str());
		for (size_t i = 0; i < Nodes.size(); i++)
			Term->WriteLine("  " + Algorithm::Encoding::Encode0xHex256(Nodes[i]));

		auto Path = Tree.CalculatePath(Target);
		auto ProposedRoot = Path.CalculateRoot(Target);
		auto ActualRoot = Tree.CalculateRoot();
		auto& Branch = Path.GetBranch();
		Branch.insert(Branch.begin(), Target);
		Branch.push_back(ProposedRoot);

		Term->fWriteLine("merkle tree path (index in tree = %i, nodes = %i):", (int)Path.GetIndex(), (int)Branch.size());
		for (size_t i = 0; i < Branch.size(); i++)
			Term->WriteLine("  " + Algorithm::Encoding::Encode0xHex256(Branch[i]));

		Term->fWriteLine("merkle tree (complexity = %i, nodes = %i, verification = %s):", (int)Tree.GetComplexity(), (int)Nodes.size(), ProposedRoot == ActualRoot ? "passed" : "failed");
		for (size_t i = 0; i < Nodes.size(); i++)
		{
			auto It = std::find(Branch.begin(), Branch.end(), Nodes[i]);
			if (It != Branch.end())
			{
				size_t Depth = It - Branch.begin() + 1;
				Term->WriteLine("  " + String(Depth, '>') + String(1 + Branch.size() - Depth, ' ') + Algorithm::Encoding::Encode0xHex256(Nodes[i]));
			}
			else
				Term->WriteLine("  " + String(1 + Branch.size(), ' ') + Algorithm::Encoding::Encode0xHex256(Nodes[i]));
		}
		VI_PANIC(ProposedRoot == ActualRoot, "cryptographic error");
	}
	/* Oracle wallets cryptography */
	static void CryptographyMultichain()
	{
		auto* Term = Console::Get();
		UPtr<Schema> Data = Var::Set::Array();
		auto User = Ledger::Wallet::FromSeed("0000000");
		for (auto& MasterWallet : NSS::ServerNode::Get()->GetWallets(User.SecretKey))
		{
			auto Asset = Algorithm::Asset::IdOf(MasterWallet.first);
			auto* Wallet = Data->Push(Var::Set::Object());
			Wallet->Set("asset", Algorithm::Asset::Serialize(Asset));
			Wallet->Set("master", MasterWallet.second.AsSchema().Reset());
			Wallet->Set("child", NSS::ServerNode::Get()->NewSigningWallet(Asset, MasterWallet.second, 0)->AsSchema().Reset());
		}
		Term->jWriteLine(*Data);
	}
	/* Blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static void BlockchainFullCoverage(Vector<Account>* Userdata)
	{
		auto* Term = Console::Get();
		auto& Params = Protocol::Change();
		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);
		Storages::Chainstate(__func__).ClearIndexerCache();

		UPtr<Schema> Data = Userdata ? nullptr : Var::Set::Array();
		Vector<Account> Users =
		{
			Account(Ledger::Wallet::FromSeed("000001"), 0),
			Account(Ledger::Wallet::FromSeed("000000"), 0),
			Account(Ledger::Wallet::FromSeed("000002"), 0)
		};
		NewBlockFromGenerator(*Data, &Generators::Adjustments, Users, "0xce0253e775378a9fb135ee52490c2a146f798ab9c96ebb13bae64e584211da7e");
		NewBlockFromGenerator(*Data, &Generators::AddressAccounts, Users, "0x4586dabd78c7d02d341a7aa05b6010bcf702e181f308a596e701831938e7eadf");
		NewBlockFromGenerator(*Data, &Generators::PubkeyAccounts, Users, "0x34c2271f3f360fe85e9ee057ca395a155230b2775d115bcd28e78a250a323e70");
		NewBlockFromGenerator(*Data, &Generators::Commitments, Users, "0x9fb7f0aeb6a73ceb37f6d630d4eadd190d6889a7f7ccdc92c052ed7f56b05526");
		NewBlockFromGenerator(*Data, std::bind(&Generators::CommitmentOnline, std::placeholders::_1, std::placeholders::_2, 2), Users, "0x51531804b3ede57f54dbab9da572c7ebaea6ed912b70d4f290d9f49b6f0faf69");
		NewBlockFromGenerator(*Data, &Generators::Allocations, Users, "0x6370b99e11fcad0e5bb735975c70cea9424dfb6c62c0b7c22363d563a6a39c6e");
		NewBlockFromGenerator(*Data, &Generators::Contributions, Users, "0x5d05c6d9be619d918f3dc33769ad232bb02b59714bccaf07eddc1ed4bddddb1b");
		NewBlockFromGenerator(*Data, &Generators::DelegatedCustodianAccounts, Users, "0xb17fa98296019c4cd9b0e7796fc9e2e1e60acc06e270ba786cc3cca9843bcc60");
		NewBlockFromGenerator(*Data, &Generators::Claims, Users, "0x4f8eb12916c5da7cfe7d737556827386897f2acb4a20d17ac8fdb1ce60774970");
		NewBlockFromGenerator(*Data, &Generators::Transfers, Users, "0xbe80af5bb766247a1d99f682dd18490b0725ba00489dd9755662362628225043");
		NewBlockFromGenerator(*Data, &Generators::Rollups, Users, "0x69aa87edeef910824c7959b01c5712dbd5786a7b412e4ee5dbe405aafd8d4c77");
		NewBlockFromGenerator(*Data, &Generators::Deployments, Users, "0x0546a8622acbe2ca5f54737f5c57f41a10551491dd38789d66eda2746eb737d0");
		NewBlockFromGenerator(*Data, &Generators::Invocations, Users, "0x05a30ffc87b46755b1812a0b772264d06e56494f924ba762c5a9e3373126cd2d");
		NewBlockFromGenerator(*Data, &Generators::MigrationsStage1, Users, "0x0550347c11f07e9f9215211535ac9c98501ef0451ad6b4b6d87893f5cafc345d");
		NewBlockFromGenerator(*Data, &Generators::MigrationsStage2, Users, "0x51383d365f56a98edb7ba66c9427e2cfeb46d50bdd85571e58b234c234186815");
		NewBlockFromGenerator(*Data, &Generators::WithdrawalsStage1, Users, "0x29a0e02975ccd8afe2dc6f4ba1de6e48bd4e9b48654a2ba8980d0a35751f4f22");
		NewBlockFromGenerator(*Data, &Generators::WithdrawalsStage2, Users, "0x544259fce1737d3d9bb524a028b2f5037a3345268db692df0f312adbc527c190");
		NewBlockFromGenerator(*Data, std::bind(&Generators::CommitmentOffline, std::placeholders::_1, std::placeholders::_2, 2), Users, "0x79d7399e6a5e4d3376d3928bfb6ebedc7f5d94e18ad6f5c2ca1b06258eca0943");
		NewBlockFromGenerator(*Data, &Generators::Deallocations, Users, "0xc03fabdcefddbf5522e1227b59b6e4f4dbf320bddce3351ccef8a73e522f9266");
		if (Userdata != nullptr)
			*Userdata = std::move(Users);
		else
			Term->jWriteLine(*Data);
	}
	/* Blockchain containing some transaction types (non-zero balance accounts, valid regtest chain) */
	static void BlockchainPartialCoverage(Vector<Account>* Userdata)
	{
		auto* Term = Console::Get();
		auto& Params = Protocol::Change();
		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);
		Storages::Chainstate(__func__).ClearIndexerCache();

		UPtr<Schema> Data = Userdata ? nullptr : Var::Set::Array();
		Vector<Account> Users =
		{
			Account(Ledger::Wallet::FromSeed("000000"), 0),
			Account(Ledger::Wallet::FromSeed("000001"), 0)
		};
		NewBlockFromGenerator(*Data, &Generators::Adjustments, Users, "0x90086b5fece5521b9b0d6d0a3d70e52cb93f1814797ce432c243fa52c3bc805e");
		NewBlockFromGenerator(*Data, &Generators::AddressAccounts, Users, "0x5c1f29ee2705095b4d5876837b136ce47a20719216b74fd75edaf3bbff263273");
		NewBlockFromGenerator(*Data, &Generators::DelegatedCustodianAccounts, Users, "0x6b7889011f9261873af9a02cb1029c7d9adf6129c4abb85aa08d214bdfcb4235");
		NewBlockFromGenerator(*Data, &Generators::Commitments, Users, "0x1dc429dc95f33155de8ea40c11573fc540b7227c86dab8d6fb9cd8b6c1f75fb4");
		NewBlockFromGenerator(*Data, &Generators::Claims, Users, "0x3ea665a58d2f1603362f2ed049e9730858b29029e4afb0bdf57c7aadcb6e95d8");
		NewBlockFromGenerator(*Data, &Generators::Transfers, Users, "0x055ac076751237767883c6f30ec692c0d555d884fcb3eccd8283a6fe55d52616");
		NewBlockFromGenerator(*Data, &Generators::Rollups, Users, "0xdd67763fdec81e91c80f29e75a4c5b767f3bce5f75b6bc65d6a06739f4fc3060");
		NewBlockFromGenerator(*Data, std::bind(&Generators::CommitmentOffline, std::placeholders::_1, std::placeholders::_2, 1), Users, "0x852649c5d6f6adff0aa5ca75d80e926fd3e3a6d04a5112171242127ccbeb1102");
		NewBlockFromGenerator(*Data, std::bind(&Generators::TransferToWallet, std::placeholders::_1, std::placeholders::_2, 1, Algorithm::Asset::IdOf("BTC"), "tcrt1xrzy5qh6vs7phqnrft5se2sps8wyvr4u8tphzwl", 0.1), Users, "0xa91b6795673c4a811969ad7182bcfdced437b0da3a5d0c31379ba4ace5e18f33");
		if (Userdata != nullptr)
			*Userdata = std::move(Users);
		else
			Term->jWriteLine(*Data);
	}
	/* Verify current blockchain */
	static void BlockchainVerification()
	{
		auto* Term = Console::Get();
		auto Chain = Storages::Chainstate(__func__);
		VI_PANIC(!Chain.GetCheckpointBlockNumber().Or(0), "blockchain cannot be validated without re-executing entire blockchain");

		uint64_t CurrentNumber = 1;
		UPtr<Schema> Data = Var::Set::Array();
		auto ParentBlock = Chain.GetBlockHeaderByNumber(CurrentNumber > 0 ? CurrentNumber - 1 : 0);
		while (true)
		{
			auto Next = Chain.GetBlockByNumber(CurrentNumber++);
			if (!Next)
				break;

			auto* Result = Data->Push(Var::Set::Object());
			Result->Set("block_number", Algorithm::Encoding::SerializeUint256(Next->Number));
			Result->Set("block_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Next->AsHash())));

			auto Validation = Next->Validate(ParentBlock.Address());
			if (!Validation)
			{
				Result->Set("status", Var::String("block validation test failed"));
				Result->Set("detail", Var::String(Validation.Error().message()));
				break;
			}

			auto Proof = Next->AsProof(ParentBlock.Address());
			for (auto& Tx : Next->Transactions)
			{
				if (!Proof.HasTransaction(Tx.Receipt.TransactionHash))
				{
					Result->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Tx.Receipt.TransactionHash)));
					Result->Set("status", Var::String("transaction merkle test failed"));
					goto StopVerification;
				}
				else if (!Proof.HasReceipt(Tx.Receipt.AsHash()))
				{
					Result->Set("transaction_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Tx.Receipt.TransactionHash)));
					Result->Set("status", Var::String("receipt merkle test failed"));
					goto StopVerification;
				}
			}

			size_t StateIndex = 0;
			for (auto& State : Next->States.At(Ledger::WorkCommitment::Finalized))
			{
				uint256_t Hash = State.second->AsHash();
				if (!Proof.HasState(Hash))
				{
					Result->Set("state_hash", Var::String(Algorithm::Encoding::Encode0xHex256(Hash)));
					Result->Set("status", Var::String("state merkle test failed"));
					goto StopVerification;
				}
			}

			Result->Set("status", Var::String("passed"));
			ParentBlock = *Next;
			if (Data->Size() > 32)
			{
				Term->jWriteLine(*Data);
				Data->Clear();
			}
		}
	StopVerification:
		Term->jWriteLine(*Data);
		VI_PANIC(Schema::ToJSON(*Data).find("failed") == std::string::npos, "cryptographic error");
	}
	/* Gas estimation */
	static void BlockchainGasEstimation()
	{
		auto* Term = Console::Get();
		Term->CaptureTime();

		Algorithm::Seckey From;
		Crypto::FillRandomBytes(From, sizeof(From));

		Algorithm::Pubkeyhash To;
		Crypto::FillRandomBytes(To, sizeof(To));

		UPtr<Transactions::Transfer> Transaction = Memory::New<Transactions::Transfer>();
		Transaction->SetAsset("BTC");
		Transaction->SetOptimalGas(Decimal::Zero());
		Transaction->SetTo(To, Mathd::Random());
		Transaction->Sign(From, 1);

		uint256_t EstimateGasLimit = Transaction->GetGasEstimate();
		uint256_t OptimalGasLimit = Transaction->GasLimit;
		uint256_t BlockGasLimit = Ledger::Block::GetGasLimit();
		UPtr<Schema> Data = Var::Set::Object();
		Data->Set("estimate_gas_limit", Algorithm::Encoding::SerializeUint256(EstimateGasLimit));
		Data->Set("optimal_gas_limit", Algorithm::Encoding::SerializeUint256(OptimalGasLimit));
		Data->Set("block_gas_limit", Algorithm::Encoding::SerializeUint256(BlockGasLimit));
		Term->jWriteLine(*Data);
	}

public:
	template <typename T, typename... Args>
	static void NewSerializationComparison(Schema* Data, Args... Arguments)
	{
		T Instance = T(Arguments...); Format::Stream Message;
		VI_PANIC(Instance.Store(&Message), "failed to store a message");

		T InstanceCopy = T(Arguments...);
		VI_PANIC(InstanceCopy.Load(Message.Rewind()), "failed to load a message");

		Format::Stream MessageCopy;
		VI_PANIC(InstanceCopy.Store(&MessageCopy), "failed to store a message");
		VI_PANIC(MessageCopy.Data == Message.Data, "serialization inconsistency found");

		Data->Set(T::AsInstanceTypename(), Var::String(Algorithm::Encoding::Encode0xHex256(Message.Hash())));
	}
	static Ledger::Block NewBlockFromGenerator(Schema* Results, std::function<void(Vector<UPtr<Ledger::Transaction>>&, Vector<Account>&)>&& TestCase, Vector<Account>& Users, const std::string_view& StateRootHash)
	{
		for (auto& User : Users)
			User.Sequence = User.Wallet.GetLatestSequence().Or(1);

		Vector<UPtr<Ledger::Transaction>> Transactions;
		TestCase(Transactions, Users);

		auto Block = NewBlockFromList(Results, std::move(Transactions), Users);
		auto Hash = Algorithm::Encoding::Encode0xHex256(Block.StateRoot);
		if (Results != nullptr)
			Console::Get()->WriteLine(Hash);

		VI_PANIC(StateRootHash.empty() || StateRootHash == Hash, "block state root deviation");
		return Block;
	}
	static Ledger::Block NewBlockFromList(Schema* Results, Vector<UPtr<Ledger::Transaction>>&& Transactions, Vector<Account>& Users)
	{
		Ledger::EvaluationContext Environment;
		uint64_t Priority = std::numeric_limits<uint64_t>::max();
		for (auto& User : Users)
		{
			Priority = Environment.Priority(User.Wallet.PublicKeyHash, User.Wallet.SecretKey).Or(std::numeric_limits<uint64_t>::max());
			if (!Priority)
				break;
		}

		VI_PANIC(Priority == 0, "block proposal not allowed");
		for (auto& Transaction : Transactions)
		{
			if (Transaction->GetType() != Ledger::TransactionLevel::Aggregation)
				continue;

			Algorithm::Pubkeyhash User;
			VI_PANIC(Transaction->RecoverHash(User), "transaction not recoverable");
			for (auto& [AttestationUser, AttestationUserSequence] : Users)
			{
				if (memcmp(AttestationUser.PublicKeyHash, User, sizeof(User)) != 0)
					VI_PANIC(((Ledger::AggregationTransaction*)*Transaction)->Attestate(AttestationUser.SecretKey), "transaction not attested");
			}
			Transaction->GasLimit = Ledger::TransactionContext::CalculateTxGas(*Transaction).Or(Transaction->GasLimit);
		}

		if (!Environment.Apply(std::move(Transactions)))
			VI_PANIC(false, "empty block not allowed");

		String Errors;
		auto Evaluation = Environment.Evaluate(&Errors);
		if (!Errors.empty())
			VI_PANIC(false, "block evaluation error: %s", Errors.c_str());

		auto Proposal = std::move(Evaluation.Expect("block evaluation failed"));
		Environment.Solve(Proposal).Expect("block solution failed");
		if (Results != nullptr)
			Environment.Verify(Proposal).Expect("block verification failed");

		Transactions = Vector<UPtr<Ledger::Transaction>>();
		Proposal.Checkpoint().Expect("block checkpoint failed");
		if (Results != nullptr)
			Results->Push(Proposal.AsSchema().Reset());

		Vector<Ledger::BlockDispatch> Dispatches;
		for (auto& [User, UserSequence] : Users)
		{
			auto UserDispatch = Proposal.DispatchSync(User);
			if (UserDispatch && !UserDispatch->Outputs.empty())
			{
				UserSequence = User.GetLatestSequence().Or(1);
				for (auto& Transaction : UserDispatch->Outputs)
				{
					if (Transaction->GetType() == Ledger::TransactionLevel::Aggregation)
					{
						VI_PANIC(Transaction->Sign(User.SecretKey), "dispatch transaction not signed");
						for (auto& [AttestationUser, AttestationUserSequence] : Users)
						{
							if (memcmp(AttestationUser.PublicKeyHash, User.PublicKeyHash, sizeof(User.PublicKeyHash)) != 0)
								VI_PANIC(((Ledger::AggregationTransaction*)*Transaction)->Attestate(AttestationUser.SecretKey), "dispatch transaction not attested");
						}
						Transaction->GasLimit = Ledger::TransactionContext::CalculateTxGas(*Transaction).Or(Transaction->GasLimit);
					}
					else
						VI_PANIC(Transaction->Sign(User.SecretKey, UserSequence++, Decimal::Zero()), "dispatch transaction not signed");
				}
				Transactions.insert(Transactions.end(), std::make_move_iterator(UserDispatch->Outputs.begin()), std::make_move_iterator(UserDispatch->Outputs.end()));
				Dispatches.push_back(std::move(*UserDispatch));
			}

			if (UserDispatch && !UserDispatch->Errors.empty())
			{
				for (auto& Transaction : UserDispatch->Errors)
					VI_PANIC(false, "%s", Transaction.second.c_str());
			}
		}

		for (auto& Dispatch : Dispatches)
			Dispatch.Checkpoint().Expect("dispatch checkpoint failed");

		if (!Transactions.empty())
			NewBlockFromList(Results, std::move(Transactions), Users);
		return Proposal;
	}
};

class Apps
{
public:
	/* NSS, NDS, P2P, NDS nodes */
	static int Consensus(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		String Config = argc > 1 ? argv[1] : TAN_CONFIG_PATH;
		String Number = Config.substr(Config.find('-') + 1);
		Protocol Params = Protocol(Config);
		uint32_t Index = FromString<uint32_t>(Number.substr(0, Number.find_first_not_of("0123456789"))).Or(1);

		Ledger::Wallet Wallet = Ledger::Wallet::FromSeed(Stringify::Text("00000%i", Index - 1));
		Ledger::Validator Node;
		Node.Address = SocketAddress(Params.User.P2P.Address, Params.User.P2P.Port);

		auto Mempool = Storages::Mempoolstate(__func__);
		Mempool.ApplyValidator(Node, Wallet);

		NDS::ServerNode Discovery;
		P2P::ServerNode Consensus;
		NSS::ServerNode& Synchronization = *NSS::ServerNode::Get();
		RPC::ServerNode Interface = RPC::ServerNode(&Consensus);

		ServiceControl Control;
		Control.Bind(Discovery.GetEntrypoint());
		Control.Bind(Consensus.GetEntrypoint());
		Control.Bind(Synchronization.GetEntrypoint());
		Control.Bind(Interface.GetEntrypoint());

		int ExitCode = Control.Launch();
		if (OS::Process::HasDebugger())
		{
			auto* Term = Console::Get();
			Term->Write("\n");
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  CONSENSUS TEST FINISHED  ");
			Term->ColorEnd();
			Term->Write("\n\n");
			Term->ReadChar();
		}

		return ExitCode;
	}
	/* Simplest blockchain explorer for debugging */
	static int Explorer(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Chain = Storages::Chainstate(__func__);
		auto Mempool = Storages::Mempoolstate(__func__);
		while (true)
		{
			auto Command = Term->Read(1024 * 1024);
			if (Command.empty())
				break;

			auto Args = Stringify::Split(Command, ' ');
			auto& Method = Args[0];
			if (Method == "account")
			{
				if (Args.size() < 3)
					goto NotValid;

				Algorithm::Pubkeyhash Owner = { 0 };
				if (!Algorithm::Signing::DecodeAddress(Args[2], Owner))
					goto NotValid;

				auto Index = String();
				auto Column = String();
				auto Row = String();
				auto& State = Args[1];
				if (State == "sequence")
				{
					Index = States::AccountSequence::AsInstanceIndex(Owner);
				}
				else if (State == "work")
				{
					Column = States::AccountWork::AsInstanceColumn(Owner);
					Row = States::AccountWork::AsInstanceRow();
				}
				else if (State == "observer")
				{
					if (Args.size() < 4)
						goto NotValid;

					Column = States::AccountObserver::AsInstanceColumn(Owner);
					Row = States::AccountObserver::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]));
				}
				else if (State == "program")
				{
					Index = States::AccountProgram::AsInstanceIndex(Owner);
				}
				else if (State == "storage")
				{
					if (Args.size() < 4)
						goto NotValid;

					Index = States::AccountStorage::AsInstanceIndex(Owner, Codec::HexDecode(Args[3]));
				}
				else if (State == "reward")
				{
					if (Args.size() < 4)
						goto NotValid;

					Column = States::AccountReward::AsInstanceColumn(Owner);
					Row = States::AccountReward::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]));
				}
				else if (State == "derivation")
				{
					if (Args.size() < 4)
						goto NotValid;

					Index = States::AccountDerivation::AsInstanceIndex(Owner, Algorithm::Asset::IdOfHandle(Args[3]));
				}
				else if (State == "balance")
				{
					if (Args.size() < 4)
						goto NotValid;

					Column = States::AccountBalance::AsInstanceColumn(Owner);
					Row = States::AccountBalance::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]));
				}
				else if (State == "depository")
				{
					if (Args.size() < 4)
						goto NotValid;

					Column = States::AccountDepository::AsInstanceColumn(Owner);
					Row = States::AccountDepository::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]));
				}

				auto Response = Index.empty() ? Chain.GetMultiformByComposition(nullptr, Column, Row, 0) : Chain.GetUniformByIndex(nullptr, Index, 0);
				if (!Response || !*Response)
					goto NotFound;

				auto Data = (*Response)->AsSchema();
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "witness")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Index = String();
				auto Column = String();
				auto Row = String();
				auto& State = Args[1];
				if (State == "program")
				{
					if (Args.size() < 3)
						goto NotValid;

					Index = States::WitnessProgram::AsInstanceIndex(Args[2]);
				}
				else if (State == "event")
				{
					if (Args.size() < 3)
						goto NotValid;

					auto Hash = uint256_t(Args[2], 16);
					Index = States::WitnessEvent::AsInstanceIndex(Hash);
				}
				else if (State == "address")
				{
					if (Args.size() < 5)
						goto NotValid;

					Algorithm::Pubkeyhash Owner = { 0 };
					if (!Algorithm::Signing::DecodeAddress(Args[2], Owner))
						goto NotValid;

					Column = States::WitnessAddress::AsInstanceColumn(Owner);
					Row = States::WitnessAddress::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]), Args[4], Args.size() > 5 ? uint64_t(uint256_t(Args[5], 10)) : Protocol::Now().Account.RootAddressIndex);
				}
				else if (State == "transaction")
				{
					if (Args.size() < 4)
						goto NotValid;

					Index = States::WitnessTransaction::AsInstanceIndex(Algorithm::Asset::IdOfHandle(Args[2]), Args[3]);
				}

				auto Response = Index.empty() ? Chain.GetMultiformByComposition(nullptr, Column, Row, 0) : Chain.GetUniformByIndex(nullptr, Index, 0);
				if (!Response || !*Response)
					goto NotFound;

				auto Data = (*Response)->AsSchema();
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "tx")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Hash = uint256_t(Args[1], 16);
				auto Context = Ledger::TransactionContext();
				auto FinalizedTransaction = Context.GetBlockTransactionInstance(Hash);
				if (!FinalizedTransaction)
				{
					auto StaleTransaction = Chain.GetTransactionByHash(Hash);
					if (!StaleTransaction)
					{
						auto PendingTransaction = Mempool.GetTransactionByHash(Hash);
						if (!PendingTransaction)
							goto NotFound;

						auto Data = (*PendingTransaction)->AsSchema();
						Term->jWriteLine(*Data);
					}
					else
					{
						auto Data = (*StaleTransaction)->AsSchema();
						Term->jWriteLine(*Data);
					}
				}
				else
				{
					auto Data = FinalizedTransaction->AsSchema();
					Term->jWriteLine(*Data);
				}
				continue;
			}
			else if (Method == "tx_message")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Hash = uint256_t(Args[1], 16);
				auto Context = Ledger::TransactionContext();
				auto FinalizedTransaction = Context.GetBlockTransactionInstance(Hash);
				if (!FinalizedTransaction)
				{
					auto StaleTransaction = Chain.GetTransactionByHash(Hash);
					if (!StaleTransaction)
					{
						auto PendingTransaction = Mempool.GetTransactionByHash(Hash);
						if (!PendingTransaction)
							goto NotFound;

						auto Data = Format::Util::Encode0xHex((*PendingTransaction)->AsMessage().Data);
						Term->WriteLine(Data);
					}
					else
					{
						auto Data = Format::Util::Encode0xHex((*StaleTransaction)->AsMessage().Data);
						Term->WriteLine(Data);
					}
				}
				else
				{
					auto Data = Format::Util::Encode0xHex(FinalizedTransaction->AsMessage().Data);
					Term->WriteLine(Data);
				}
				continue;
			}
			else if (Method == "txns")
			{
				if (Args.size() < 2)
					goto NotValid;

				Algorithm::Pubkeyhash Owner = { 0 };
				if (!Algorithm::Signing::DecodeAddress(Args[1], Owner))
					goto NotValid;

				auto Page = (uint64_t)uint256_t(Args.size() > 2 ? Args[2] : "0", 10);
				auto Response = Chain.GetBlockTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, 1, 512 * Page, 512);
				if (!Response)
					goto NotFound;

				auto Data = UPtr<Schema>(Var::Set::Array());
				for (auto& Item : *Response)
					Data->Push(Item.AsSchema().Reset());
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "txns_hashes")
			{
				if (Args.size() < 2)
					goto NotValid;

				Algorithm::Pubkeyhash Owner = { 0 };
				if (!Algorithm::Signing::DecodeAddress(Args[1], Owner))
					goto NotValid;

				auto Page = (uint64_t)uint256_t(Args.size() > 2 ? Args[2] : "0", 10);
				auto Response = Chain.GetTransactionsByOwner(std::numeric_limits<int64_t>::max(), Owner, 1, 512 * Page, 512);
				if (!Response)
					goto NotFound;

				auto Data = UPtr<Schema>(Var::Set::Array());
				for (auto& Item : *Response)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item->AsHash())));
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "block")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Number = uint64_t(uint256_t(Args[1], 10));
				auto Hash = uint256_t(Args[1], 16);
				auto Response = Chain.GetBlockByHash(Hash);
				if (!Response)
				{
					Response = Chain.GetBlockByNumber(Number);
					if (!Response)
						goto NotFound;
				}

				auto Data = Response->AsSchema();
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "block_message")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Number = uint64_t(uint256_t(Args[1], 10));
				auto Hash = uint256_t(Args[1], 16);
				auto Response = Chain.GetBlockByHash(Hash);
				if (!Response)
				{
					Response = Chain.GetBlockByNumber(Number);
					if (!Response)
						goto NotFound;
				}

				auto Data = Format::Util::Encode0xHex(Response->AsMessage().Data);
				Term->WriteLine(Data);
				continue;
			}
			else if (Method == "block_body")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Number = uint64_t(uint256_t(Args[1], 10));
				auto Hash = uint256_t(Args[1], 16);
				auto Response1 = Chain.GetBlockHeaderByHash(Hash);
				if (!Response1)
				{
					Response1 = Chain.GetBlockHeaderByNumber(Number);
					if (!Response1)
						goto NotFound;
				}

				auto Data = Response1->AsSchema();
				auto Response2 = Chain.GetBlockTransactionHashset(Response1->Number);
				if (Response2)
				{
					auto* Hashes = Data->Set("transactions", Var::Set::Array());
					for (auto& Item : *Response2)
						Hashes->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
				}
				auto Response3 = Chain.GetBlockStatetrieHashset(Response1->Number);
				if (Response3)
				{
					auto* Hashes = Data->Set("states", Var::Set::Array());
					for (auto& Item : *Response3)
						Hashes->Push(Var::String(Algorithm::Encoding::Encode0xHex256(Item)));
				}
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "block_header")
			{
				if (Args.size() < 2)
					goto NotValid;

				auto Number = uint64_t(uint256_t(Args[1], 10));
				auto Hash = uint256_t(Args[1], 16);
				auto Response1 = Chain.GetBlockHeaderByHash(Hash);
				if (!Response1)
				{
					Response1 = Chain.GetBlockHeaderByNumber(Number);
					if (!Response1)
						goto NotFound;
				}

				auto Data = Response1->AsSchema();
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "blocks")
			{
				if (Args.size() < 3)
					goto NotValid;

				UPtr<Schema> Data = Var::Set::Array();
				bool Validate = Args.size() > 3 ? (uint256_t(Args[3], 10) > 0) : false, Written = false;
				uint64_t BlockNumber = uint64_t(uint256_t(Args[1], 10));
				uint64_t BlockCount = uint64_t(uint256_t(Args[2], 10));
				uint64_t CurrentNumber = BlockNumber;
				auto Chain = Storages::Chainstate(__func__);
				if (CurrentNumber < Chain.GetCheckpointBlockNumber().Or(0))
				{
					Term->WriteLine("block cannot be validated without re-executing entire blockchain");
					continue;
				}

				auto ParentBlock = Chain.GetBlockHeaderByNumber(BlockNumber > 1 ? BlockNumber - 1 : 0);
				while (CurrentNumber < BlockNumber + BlockCount)
				{
					auto Next = Chain.GetBlockByNumber(CurrentNumber++);
					if (!Next)
						break;

					auto Target = *Data;
					auto Proof = Next->AsProof(ParentBlock.Address());
					auto BlockInfo = Next->AsSchema();
					size_t TxIndex = 0;
					for (auto& Item : BlockInfo->Get("transactions")->GetChilds())
					{
						auto& Tx = Next->Transactions[TxIndex++];
						auto* TxInfo = Item->Get("transaction");
						auto* ClaimInfo = Item->Get("receipt");
						TxInfo->Set("merkle_test", Var::String(Proof.HasTransaction(Tx.Receipt.TransactionHash) ? "passed" : "failed"));
						ClaimInfo->Set("merkle_test", Var::String(Proof.HasReceipt(Tx.Receipt.AsHash()) ? "passed" : "failed"));
					}

					size_t StateIndex = 0;
					for (auto& Item : BlockInfo->Get("states")->GetChilds())
						Item->Set("merkle_test", Var::String(Proof.HasState(Algorithm::Encoding::Decode0xHex256(Item->GetVar("hash").GetBlob())) ? "passed" : "failed"));

					auto Validity = Next->VerifyValidity(ParentBlock.Address());
					auto Integrity = Next->VerifyIntegrity(ParentBlock.Address());
					auto Validation = Validate ? Next->Validate(ParentBlock.Address()) : ExpectsLR<void>(Expectation::Met);
					BlockInfo->Set("validity_test", Var::String(Validity ? "passed" : Validity.Error().what()));
					BlockInfo->Set("integrity_test", Var::String(Integrity ? "passed" : Integrity.Error().what()));
					BlockInfo->Set("validation_test", Var::String(Validate ? (Validation ? "passed" : Validation.Error().what()) : "unchecked"));
					BlockInfo->Set("merkle_test", Proof.AsSchema().Reset());
					Target->Push(BlockInfo.Reset());
					ParentBlock = *Next;

					if (Data->Size() > 32)
					{
						Term->jWriteLine(*Data);
						Data->Clear();
					}
				}
				if (!Written || !Data->Empty())
				{
					UPtr<Stream> Stream = *OS::File::Open(*OS::Directory::GetModule() + "/test.json", FileMode::Binary_Write_Only); String Offset;
					Schema::ConvertToJSON(*Data, [&Term, &Stream, &Offset](VarForm Pretty, const std::string_view& Buffer)
					{
						if (!Buffer.empty())
						{
							Stream->Write((uint8_t*)Buffer.data(), Buffer.size());
							Term->Write(Buffer);
						}

						switch (Pretty)
						{
							case Vitex::Core::VarForm::Tab_Decrease:
								Offset.erase(Offset.size() - 2);
								break;
							case Vitex::Core::VarForm::Tab_Increase:
								Offset.append(2, ' ');
								break;
							case Vitex::Core::VarForm::Write_Space:
								Stream->Write((uint8_t*)" ", 1);
								Term->Write(" ");
								break;
							case Vitex::Core::VarForm::Write_Line:
								Stream->Write((uint8_t*)"\n", 1);
								Term->Write("\n");
								break;
							case Vitex::Core::VarForm::Write_Tab:
								Stream->Write((uint8_t*)Offset.data(), Offset.size());
								Term->Write(Offset);
								break;
							default:
								break;
						}
					});
					Term->WriteChar('\n');
				}
				continue;
			}
			else if (Method == "blocks_hashes")
			{
				if (Args.size() < 3)
					goto NotValid;

				uint64_t BlockNumber = uint64_t(uint256_t(Args[1], 10));
				uint64_t BlockCount = uint64_t(uint256_t(Args[2], 10));
				auto Chain = Storages::Chainstate(__func__);
				auto Response = Chain.GetBlockHashset(BlockNumber, BlockCount);
				if (!Response)
					goto NotFound;

				auto Data = UPtr<Schema>(Var::Set::Array());
				for (auto& Item : *Response)
					Data->Push(Var::Set::String(Algorithm::Encoding::Encode0xHex256(Item)));
				Term->jWriteLine(*Data);
				continue;
			}
			else if (Method == "parse")
			{
				if (Args.size() < 2)
					goto NotValid;

				Format::Variables Data;
				Format::Stream Message = Format::Stream(Args[1]);
				Format::VariablesUtil::DeserializeFlatFrom(Message, &Data);
				Term->WriteLine(Format::VariablesUtil::AsConstantJSON(Data));
				continue;
			}
		NotValid:
			Term->WriteLine("command is not valid");
			continue;
		NotFound:
			Term->WriteLine("value not found");
			continue;
		}

		if (OS::Process::HasDebugger())
		{
			auto* Term = Console::Get();
			Term->Write("\n");
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  EXPLORER TEST FINISHED  ");
			Term->ColorEnd();
			Term->Write("\n\n");
			Term->ReadChar();
		}

		return 0;
	}
	/* Mediator node for debugging */
	static int Mediator(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		static bool IsActive = true;
		OS::Process::BindSignal(Signal::SIG_INT, [](int) { IsActive = false; });

		Schedule::Desc Policy;
		Schedule* Queue = Schedule::Get();
		Queue->Start(Policy);

		auto* Server = NSS::ServerNode::Get();
		auto Asset = Algorithm::Asset::IdOf("BTC");
		auto Parent = Server->NewMasterWallet(Asset, String("123456"));
		auto Child = Mediator::DynamicWallet(*Server->NewSigningWallet(Asset, *Parent, 0));
		for (auto& Address : Child.SigningChild->Addresses)
			Server->EnableWalletAddress(Asset, *Child.GetBinding(), Address.second, *Child.SigningChild->AddressIndex);

		Coasync<void>([&]() -> Promise<void>
		{
			auto Balance = Coawait(Server->CalculateBalance(Asset, Child));
			auto Info = Parent->AsSchema();
			auto* WalletInfo = Info->Set("wallet", Child.SigningChild->AsSchema().Reset());
			WalletInfo->Set("balance", Var::String(Balance ? Balance->ToString().c_str() : "?"));

			Server->Startup();
			for (size_t i = 0; i < 0; i++)
			{
				uint256_t Hash;
				Algorithm::Encoding::EncodeUint256((uint8_t*)Crypto::RandomBytes(32)->data(), Hash);
				auto Transaction = Coawait(Server->SubmitTransaction(Hash, Asset, Mediator::DynamicWallet(Child), { Mediator::Transferer("bcrt1p5dy9ef2lngvmlx6edjgp88hemj03uszt3zlqrc252vlxp3jf27vq648qmh", Optional::None, 0.01) }, Mediator::BaseFee(0.000003, 1)));
				if (!Transaction)
					break;
			}

			while (IsActive)
			{
				Promise<void> Future;
				Queue->SetTimeout(200, [Future]() mutable { Future.Set(); });
				Coawait(std::move(Future));
			}

			Server->Shutdown();
			CoreturnVoid;
		}).Wait();

		while (Queue->Dispatch());
		Queue->Stop();

		if (OS::Process::HasDebugger())
		{
			auto* Term = Console::Get();
			Term->Write("\n");
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  MEDIATOR TEST FINISHED  ");
			Term->ColorEnd();
			Term->Write("\n\n");
			Term->ReadChar();
		}

		return 0;
	}
	/* Blockchain derived from partial coverage test with 1920 additional blocks filled with configurable entropy transactions (non-zero balance accounts, valid regtest chain, entropy 0 - low entropy, entropy 1 - medium entropy, entropy 2 - high entropy) */
	static int Benchmark(int argc, char* argv[], uint8_t Entropy)
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto* Queue = Schedule::Get();
		Queue->Start(Schedule::Desc());

		if (argc > 1 && !strcmp(argv[1], "calibrate"))
		{
			auto Alg = Algorithm::WVDF::Calibrate(4);
			Console::Get()->fWriteLine(
				"calibration alg:\n"
				"  length: %i\n"
				"  bits: %i\n"
				"  pow: %llu\n"
				"  difficulty: %s",
				Alg.Length, Alg.Bits, Alg.Pow,
				Alg.Difficulty().ToString().c_str());
			Algorithm::WVDF::SetDefault(Alg);
		}

		const size_t BlockCount = 1920;
		const size_t TransactionCount = (size_t)(uint64_t)(Ledger::Block::GetGasLimit() / Transactions::Transfer().GetGasEstimate());
		const Decimal StartingAccountBalance = Decimal(500).Truncate(12);
		auto Checkpoint = [&](Vector<UPtr<Ledger::Transaction>>&& Transactions, Vector<Tests::Account>& Users)
		{
			static uint64_t CumulativeTransactionCount = 0, CumulativeStateCount = 0;
			auto CumulativeQueryCount = (uint64_t)Ledger::StorageUtil::GetThreadQueries(); Term->CaptureTime();
			auto Block = Tests::NewBlockFromList(nullptr, std::move(Transactions), Users);
			auto Time = Term->GetCapturedTime();
			CumulativeTransactionCount += Block.TransactionCount;
			CumulativeStateCount += Block.StateCount;
			Term->fWriteLine("%s = (n: %" PRIu64 ", d: %s / %.2f ms, t: %" PRIu64 " / %.2f hz, s: %" PRIu64 " / %.2f hz, q: %" PRIu64 " / %.2f hz)",
				Algorithm::Encoding::Encode0xHex256(Block.AsHash()).c_str(), Block.Number,
				Block.Target.Difficulty().ToString().c_str(), Time,
				CumulativeTransactionCount, 1000.0 * (double)Block.TransactionCount / Time,
				CumulativeStateCount, 1000.0 * (double)Block.StateCount / Time,
				CumulativeQueryCount, 1000.0 * (double)((uint64_t)Ledger::StorageUtil::GetThreadQueries() - CumulativeQueryCount) / Time);
		};

		Vector<Tests::Account> Proposers;
		Tests::BlockchainPartialCoverage(&Proposers);

		auto& [User1, User1Sequence] = Proposers[0];
		auto& [User2, User2Sequence] = Proposers[1];
		auto Chain = Storages::Chainstate(__func__);
		auto Context = Ledger::TransactionContext();
		auto User1Addresses = *Context.GetWitnessAddressesByPurpose(User1.PublicKeyHash, States::AddressType::Custodian, 0, 128);
		auto User1CustodianAddress = std::find_if(User1Addresses.begin(), User1Addresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("BTC"); });
		VI_PANIC(User1CustodianAddress != User1Addresses.end(), "user 1 custodian address not found");

		if (Entropy == 0)
		{
			const Decimal OutgoingAccountBalance = StartingAccountBalance / Decimal(BlockCount * (TransactionCount + 64));
			const Decimal IncomingQuantity = StartingAccountBalance;
			auto* IncomingClaim = Memory::New<Transactions::IncomingClaim>();
			IncomingClaim->SetAsset("BTC");
			IncomingClaim->SetEstimateGas(Decimal::Zero());
			IncomingClaim->SetWitness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ Mediator::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, Decimal(IncomingQuantity)) },
				{ Mediator::Transferer(User1CustodianAddress->Addresses.begin()->second, User1CustodianAddress->AddressIndex, Decimal(IncomingQuantity)) });
			VI_PANIC(IncomingClaim->Sign(User2.SecretKey, User2Sequence++), "claim not signed");

			auto Genesis = Vector<UPtr<Ledger::Transaction>>();
			Genesis.push_back(IncomingClaim);
			Checkpoint(std::move(Genesis), Proposers);

			auto Receiver = Ledger::Wallet::FromSeed("000002");
			for (size_t i = 0; i < BlockCount; i++)
			{
				Vector<UPtr<Ledger::Transaction>> Transactions;
				Transactions.resize(TransactionCount);
				Parallel::WailAll(Parallel::ForEach(Transactions.begin(), Transactions.end(), ELEMENTS_FEW, [&](UPtr<Ledger::Transaction>& Item)
				{
					double Balance = (double)(std::max<uint64_t>(1000, Crypto::Random() % 10000)) / 10000.0;

					auto* Transaction = Memory::New<Transactions::Transfer>();
					Transaction->SetAsset("BTC");
					Transaction->SetEstimateGas(Decimal::Zero());
					Transaction->SetTo(Receiver.PublicKeyHash, Decimal(OutgoingAccountBalance).Truncate(12) * Decimal(Balance));
					VI_PANIC(Transaction->Sign(User1.SecretKey, User1Sequence++), "transfer not signed");
					Item = Transaction;
				}));
				std::sort(Transactions.begin(), Transactions.end(), [](const UPtr<Ledger::Transaction>& A, const UPtr<Ledger::Transaction>& B) { return A->Sequence < B->Sequence; });
				Checkpoint(std::move(Transactions), Proposers);
			}
		}
		else if (Entropy == 1)
		{
			const size_t SenderCount = 16;
			const size_t ReceiverCount = 32;
			const Decimal OutgoingAccountBalance = StartingAccountBalance / Decimal(BlockCount * (TransactionCount + 64) * SenderCount);
			const Decimal IncomingQuantity = StartingAccountBalance * SenderCount;
			auto* IncomingClaim = Memory::New<Transactions::IncomingClaim>();
			IncomingClaim->SetAsset("BTC");
			IncomingClaim->SetEstimateGas(Decimal::Zero());
			IncomingClaim->SetWitness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ Mediator::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, Decimal(IncomingQuantity)) },
				{ Mediator::Transferer(User1CustodianAddress->Addresses.begin()->second, User1CustodianAddress->AddressIndex, Decimal(IncomingQuantity)) });
			VI_PANIC(IncomingClaim->Sign(User2.SecretKey, User2Sequence++), "claim not signed");

			auto Genesis = Vector<UPtr<Ledger::Transaction>>();
			Genesis.push_back(IncomingClaim);
			Checkpoint(std::move(Genesis), Proposers);

			Vector<Tests::Account> Senders;
			Senders.reserve(SenderCount);
			for (size_t i = 0; i < SenderCount; i++)
				Senders.emplace_back(Tests::Account(Ledger::Wallet::FromSeed(Stringify::Text("00001%i", (int)i)), 1));

			Vector<Tests::Account> Receivers;
			Receivers.reserve(ReceiverCount);
			for (size_t i = 0; i < ReceiverCount; i++)
				Receivers.emplace_back(Tests::Account(Ledger::Wallet::FromSeed(Stringify::Text("00002%i", (int)i)), 1));

			auto* Omnitransfer = Memory::New<Transactions::Omnitransfer>();
			Omnitransfer->SetAsset("BTC");
			for (auto& Sender : Senders)
				Omnitransfer->SetTo(Sender.Wallet.PublicKeyHash, StartingAccountBalance);
			Omnitransfer->SetGas(Decimal::Zero(), Ledger::Block::GetGasLimit());
			VI_PANIC(Omnitransfer->Sign(User1.SecretKey, User1Sequence++), "omnitransfer not signed");

			Genesis = Vector<UPtr<Ledger::Transaction>>();
			Genesis.push_back(Omnitransfer);
			Checkpoint(std::move(Genesis), Proposers);

			for (size_t i = 0; i < BlockCount; i++)
			{
				Vector<UPtr<Ledger::Transaction>> Transactions;
				Transactions.resize(TransactionCount);
				Parallel::WailAll(Parallel::ForEach(Transactions.begin(), Transactions.end(), ELEMENTS_FEW, [&](UPtr<Ledger::Transaction>& Item)
				{
					double Balance = (double)(std::max<uint64_t>(1000, Crypto::Random() % 10000)) / 10000.0;
					auto& Sender = Senders[Crypto::Random() % Senders.size()];
					auto& Receiver = Receivers[Crypto::Random() % Receivers.size()];

					auto* Transaction = Memory::New<Transactions::Transfer>();
					Transaction->SetAsset("BTC");
					Transaction->SetEstimateGas(Decimal::Zero());
					Transaction->SetTo(Receiver.Wallet.PublicKeyHash, Decimal(OutgoingAccountBalance).Truncate(12) * Decimal(Balance));
					VI_PANIC(Transaction->Sign(Sender.Wallet.SecretKey, Sender.Sequence++), "transfer not signed");
					Item = Transaction;
				}));
				std::sort(Transactions.begin(), Transactions.end(), [](const UPtr<Ledger::Transaction>& A, const UPtr<Ledger::Transaction>& B) { return A->Sequence < B->Sequence; });
				Checkpoint(std::move(Transactions), Proposers);
			}
		}
		else
		{
			const size_t SenderCount = TransactionCount;
			const Decimal OutgoingAccountBalance = StartingAccountBalance / Decimal(BlockCount * (TransactionCount + 64) * SenderCount);
			const Decimal IncomingQuantity = StartingAccountBalance * SenderCount * 2;
			auto* IncomingClaim = Memory::New<Transactions::IncomingClaim>();
			IncomingClaim->SetAsset("BTC");
			IncomingClaim->SetEstimateGas(Decimal::Zero());
			IncomingClaim->SetWitness(883669,
				"222fc360affb804ad2c34bba2269b36a64a86f017d05a9a60b237e8587bfc52b", 0.0,
				{ Mediator::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, Decimal(IncomingQuantity)) },
				{ Mediator::Transferer(User1CustodianAddress->Addresses.begin()->second, User1CustodianAddress->AddressIndex, Decimal(IncomingQuantity)) });
			VI_PANIC(IncomingClaim->Sign(User2.SecretKey, User2Sequence++), "claim not signed");

			auto Genesis = Vector<UPtr<Ledger::Transaction>>();
			Genesis.push_back(IncomingClaim);
			Checkpoint(std::move(Genesis), Proposers);

			Vector<Tests::Account> Senders;
			Senders.reserve(SenderCount);
			for (size_t i = 0; i < SenderCount; i++)
				Senders.emplace_back(Tests::Account({ Ledger::Wallet::FromSeed(Stringify::Text("00001%i", (int)i)), 1 }));

			auto* Omnitransfer = Memory::New<Transactions::Omnitransfer>();
			Omnitransfer->SetAsset("BTC");
			for (auto& Sender : Senders)
				Omnitransfer->SetTo(Sender.Wallet.PublicKeyHash, StartingAccountBalance);
			Omnitransfer->SetGas(Decimal::Zero(), Ledger::Block::GetGasLimit());
			VI_PANIC(Omnitransfer->Sign(User1.SecretKey, User1Sequence++), "omnitransfer not signed");

			Genesis = Vector<UPtr<Ledger::Transaction>>();
			Genesis.push_back(Omnitransfer);
			Checkpoint(std::move(Genesis), Proposers);

			for (size_t i = 0; i < BlockCount; i++)
			{
				Vector<UPtr<Ledger::Transaction>> Transactions;
				Transactions.resize(TransactionCount);
				Parallel::WailAll(Parallel::ForEach(Transactions.begin(), Transactions.end(), ELEMENTS_FEW, [&](UPtr<Ledger::Transaction>& Item)
				{
					double Balance = (double)(std::max<uint64_t>(1000, Crypto::Random() % 10000)) / 10000.0;
					auto& Sender = Senders[Crypto::Random() % Senders.size()];

					uint8_t Receiver[20];
					Crypto::FillRandomBytes(Receiver, sizeof(Receiver));

					auto* Transaction = Memory::New<Transactions::Transfer>();
					Transaction->SetAsset("BTC");
					Transaction->SetEstimateGas(Decimal::Zero());
					Transaction->SetTo(Receiver, Decimal(OutgoingAccountBalance).Truncate(12) * Decimal(Balance));
					VI_PANIC(Transaction->Sign(Sender.Wallet.SecretKey, Sender.Sequence++), "transfer not signed");
					Item = Transaction;
				}));
				std::sort(Transactions.begin(), Transactions.end(), [](const UPtr<Ledger::Transaction>& A, const UPtr<Ledger::Transaction>& B) { return A->Sequence < B->Sequence; });
				Checkpoint(std::move(Transactions), Proposers);
			}
		}

		Queue->Stop();
		if (OS::Process::HasDebugger())
		{
			auto* Term = Console::Get();
			Term->Write("\n");
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  BENCHMARK TEST FINISHED  ");
			Term->ColorEnd();
			Term->Write("\n\n");
			Term->ReadChar();
		}

		return 0;
	}
	/* Test case runner for integration testing */
	static int Integration(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		size_t Executions = 0;
		Vector<std::pair<std::string_view, std::function<void()>>> Cases =
		{
			{ "generic / integer serialization", &Tests::GenericIntegerSerialization },
			{ "generic / integer conversion", &Tests::GenericIntegerConversion },
			{ "generic / message serialization", &Tests::GenericMessageSerialization },
			{ "cryptography / nakamoto pow 240bits", &Tests::CryptographyNakamoto },
			{ "cryptography / wesolowski pow 90x", &Tests::CryptographyWesolowski },
			{ "cryptography / signatures", &Tests::CryptographySignatures },
			{ "cryptography / wallet", &Tests::CryptographyWallet },
			{ "cryptography / wallet sharing", &Tests::CryptographyWalletSharing },
			{ "cryptography / wallet messaging", &Tests::CryptographyWalletMessaging },
			{ "cryptography / transaction", &Tests::CryptographyTransaction },
			{ "cryptography / merkle tree", &Tests::CryptographyMerkleTree },
			{ "cryptography / multichain", &Tests::CryptographyMultichain },
			{ "blockchain / full coverage", std::bind(&Tests::BlockchainFullCoverage, (Vector<Tests::Account>*)nullptr) },
			{ "blockchain / verification", &Tests::BlockchainVerification },
			{ "blockchain / partial coverage", std::bind(&Tests::BlockchainPartialCoverage, (Vector<Tests::Account>*)nullptr) },
			{ "blockchain / verification", &Tests::BlockchainVerification },
			{ "blockchain / gas estimation", &Tests::BlockchainGasEstimation },
		};
		for (size_t i = 0; i < Cases.size(); i++)
		{
			auto& Case = Cases[i];
			Term->ColorBegin(StdColor::Black, StdColor::Yellow);
			Term->fWrite("  ===>  %s  <===  ", Case.first.data());
			Term->ColorEnd();
			Term->WriteChar('\n');
			Term->CaptureTime();

			Case.second();

			double Time = Term->GetCapturedTime();
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  TEST PASS %.1fms %.2f%%  ", Time, 100.0 * (double)(i + 1) / (double)Cases.size());
			Term->ColorEnd();
			Term->Write("\n\n");
		}

		if (OS::Process::HasDebugger())
		{
			auto* Term = Console::Get();
			Term->ColorBegin(StdColor::White, StdColor::DarkGreen);
			Term->fWrite("  INTEGRATION TEST FINISHED  ");
			Term->ColorEnd();
			Term->Write("\n\n");
			Term->ReadChar();
		}

		return 0;
	}
};

int main(int argc, char* argv[])
{
    return Apps::Consensus(argc, argv);
}