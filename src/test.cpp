#include "tangent/kernel/block.h"
#include "tangent/kernel/wallet.h"
#include "tangent/kernel/script.h"
#include "tangent/policy/transactions.h"
#include "tangent/storage/chainstate.h"
#include "tangent/storage/mempoolstate.h"
#include "tangent/service/rpc.h"
#include "tangent/service/p2p.h"
#include "tangent/service/nds.h"
#include <sstream>

using namespace Tangent;

class Blocks
{
public:
	static void TestAllowances1Threshold(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		/* Basically no-op, 1.0 threshold is default */
		auto* ContributionAllowanceEthereum = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceEthereum->SetAsset("ETH");
		ContributionAllowanceEthereum->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceEthereum->SetThreshold(nullptr, 1.0);
		VI_PANIC(ContributionAllowanceEthereum->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceEthereum);

		auto* ContributionAllowanceRipple = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceRipple->SetAsset("XRP");
		ContributionAllowanceRipple->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceRipple->SetThreshold(nullptr, 1.0);
		VI_PANIC(ContributionAllowanceRipple->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceRipple);

		auto* ContributionAllowanceBitcoin = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceBitcoin->SetAsset("BTC");
		ContributionAllowanceBitcoin->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceBitcoin->SetThreshold(nullptr, 1.0);
		VI_PANIC(ContributionAllowanceBitcoin->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceBitcoin);
	}
	static void TestAllowances0Threshold(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto* ContributionAllowanceEthereum = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceEthereum->SetAsset("ETH");
		ContributionAllowanceEthereum->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceEthereum->SetThreshold(nullptr, 0.0);
		VI_PANIC(ContributionAllowanceEthereum->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceEthereum);

		auto* ContributionAllowanceRipple = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceRipple->SetAsset("XRP");
		ContributionAllowanceRipple->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceRipple->SetThreshold(nullptr, 0.0);
		VI_PANIC(ContributionAllowanceRipple->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceRipple);

		auto* ContributionAllowanceBitcoin = Memory::New<Transactions::ContributionAllowance>();
		ContributionAllowanceBitcoin->SetAsset("BTC");
		ContributionAllowanceBitcoin->SetEstimateGas(Decimal::Zero());
		ContributionAllowanceBitcoin->SetThreshold(nullptr, 0.0);
		VI_PANIC(ContributionAllowanceBitcoin->Sign(User2.SecretKey, User2Sequence++), "contribution allowance not signed");
		Transactions.push_back(ContributionAllowanceBitcoin);
	}
	static void TestAdjustments(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto* ContributionAdjustmentEthereum = Memory::New<Transactions::ContributionAdjustment>();
		ContributionAdjustmentEthereum->SetAsset("ETH");
		ContributionAdjustmentEthereum->SetEstimateGas(Decimal::Zero());
		ContributionAdjustmentEthereum->SetIncomingFee(0.001, 0.0001);
		ContributionAdjustmentEthereum->SetOutgoingFee(0.001, 0.0001);
		VI_PANIC(ContributionAdjustmentEthereum->Sign(User2.SecretKey, User2Sequence++), "contribution adjustment not signed");
		Transactions.push_back(ContributionAdjustmentEthereum);

		auto* ContributionAdjustmentRipple = Memory::New<Transactions::ContributionAdjustment>();
		ContributionAdjustmentRipple->SetAsset("XRP");
		ContributionAdjustmentRipple->SetEstimateGas(Decimal::Zero());
		ContributionAdjustmentRipple->SetIncomingFee(0.01, 0.0001);
		ContributionAdjustmentRipple->SetOutgoingFee(0.01, 0.0001);
		VI_PANIC(ContributionAdjustmentRipple->Sign(User2.SecretKey, User2Sequence++), "contribution adjustment not signed");
		Transactions.push_back(ContributionAdjustmentRipple);

		auto* ContributionAdjustmentBitcoin = Memory::New<Transactions::ContributionAdjustment>();
		ContributionAdjustmentBitcoin->SetAsset("BTC");
		ContributionAdjustmentBitcoin->SetEstimateGas(Decimal::Zero());
		ContributionAdjustmentBitcoin->SetIncomingFee(0.00001, 0.0001);
		ContributionAdjustmentBitcoin->SetOutgoingFee(0.00001, 0.0001);
		VI_PANIC(ContributionAdjustmentBitcoin->Sign(User2.SecretKey, User2Sequence++), "contribution adjustment not signed");
		Transactions.push_back(ContributionAdjustmentBitcoin);
	}
	static void TestAddressAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestPubkeyAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto EthereumWallet = Oracle::Datamaster::NewSigningWallet(Algorithm::Asset::IdOf("ETH"), Oracle::Datamaster::NewMasterWallet(Algorithm::Asset::IdOf("ETH"), "000001").Expect("master wallet not derived")).Expect("signing wallet not derived");
		auto* PubkeyAccountEthereum = Memory::New<Transactions::PubkeyAccount>();
		PubkeyAccountEthereum->SetAsset("ETH");
		PubkeyAccountEthereum->SetEstimateGas(Decimal::Zero());
		PubkeyAccountEthereum->SetPubkey(EthereumWallet.VerifyingKey.ExposeToHeap());
		PubkeyAccountEthereum->SignPubkey(EthereumWallet.SigningKey).Expect("pubkey account not signed");
		VI_PANIC(PubkeyAccountEthereum->Sign(User1.SecretKey, User1Sequence++), "account not signed");
		Transactions.push_back(PubkeyAccountEthereum);

		auto RippleWallet = Oracle::Datamaster::NewSigningWallet(Algorithm::Asset::IdOf("XRP"), Oracle::Datamaster::NewMasterWallet(Algorithm::Asset::IdOf("XRP"), "000002").Expect("master wallet not derived")).Expect("signing wallet not derived");
		auto* PubkeyAccountRipple = Memory::New<Transactions::PubkeyAccount>();
		PubkeyAccountRipple->SetAsset("XRP");
		PubkeyAccountRipple->SetEstimateGas(Decimal::Zero());
		PubkeyAccountRipple->SetPubkey(RippleWallet.VerifyingKey.ExposeToHeap());
		PubkeyAccountRipple->SignPubkey(RippleWallet.SigningKey).Expect("pubkey account not signed");
		VI_PANIC(PubkeyAccountRipple->Sign(User1.SecretKey, User1Sequence++), "account not signed");
		Transactions.push_back(PubkeyAccountRipple);

		auto BitcoinWallet = Oracle::Datamaster::NewSigningWallet(Algorithm::Asset::IdOf("BTC"), Oracle::Datamaster::NewMasterWallet(Algorithm::Asset::IdOf("BTC"), "000003").Expect("master wallet not derived")).Expect("signing wallet not derived");
		auto* PubkeyAccountBitcoin = Memory::New<Transactions::PubkeyAccount>();
		PubkeyAccountBitcoin->SetAsset("BTC");
		PubkeyAccountBitcoin->SetEstimateGas(Decimal::Zero());
		PubkeyAccountBitcoin->SetPubkey(BitcoinWallet.VerifyingKey.ExposeToHeap());
		PubkeyAccountBitcoin->SignPubkey(BitcoinWallet.SigningKey).Expect("pubkey account not signed");
		VI_PANIC(PubkeyAccountBitcoin->Sign(User1.SecretKey, User1Sequence++), "account not signed");
		Transactions.push_back(PubkeyAccountBitcoin);
	}
	static void TestCommitments(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestCommitmentAnti(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestAllocations(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto* ContributionAllocationEthereum1 = Memory::New<Transactions::ContributionAllocation>();
		ContributionAllocationEthereum1->SetAsset("ETH");
		ContributionAllocationEthereum1->SetEstimateGas(Decimal::Zero());
		ContributionAllocationEthereum1->SetShare1(User1.SecretKey);
		VI_PANIC(ContributionAllocationEthereum1->Sign(User1.SecretKey, User1Sequence++), "contribution allocation not signed");
		Transactions.push_back(ContributionAllocationEthereum1);

		auto* ContributionAllocationEthereum2 = Memory::New<Transactions::ContributionAllocation>();
		ContributionAllocationEthereum2->SetAsset("ETH");
		ContributionAllocationEthereum2->SetEstimateGas(Decimal::Zero());
		ContributionAllocationEthereum2->SetShare1(User2.SecretKey);
		VI_PANIC(ContributionAllocationEthereum2->Sign(User2.SecretKey, User2Sequence++), "contribution allocation not signed");
		Transactions.push_back(ContributionAllocationEthereum2);

		auto* ContributionAllocationRipple = Memory::New<Transactions::ContributionAllocation>();
		ContributionAllocationRipple->SetAsset("XRP");
		ContributionAllocationRipple->SetEstimateGas(Decimal::Zero());
		ContributionAllocationRipple->SetShare1(User2.SecretKey);
		VI_PANIC(ContributionAllocationRipple->Sign(User2.SecretKey, User2Sequence++), "contribution allocation not signed");
		Transactions.push_back(ContributionAllocationRipple);

		auto* ContributionAllocationBitcoin = Memory::New<Transactions::ContributionAllocation>();
		ContributionAllocationBitcoin->SetAsset("BTC");
		ContributionAllocationBitcoin->SetEstimateGas(Decimal::Zero());
		ContributionAllocationBitcoin->SetShare1(User2.SecretKey);
		VI_PANIC(ContributionAllocationBitcoin->Sign(User2.SecretKey, User2Sequence++), "contribution allocation not signed");
		Transactions.push_back(ContributionAllocationBitcoin);
	}
	static void TestContributions(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto Context = Ledger::TransactionContext();
		auto Addresses1 = *Context.GetWitnessAddressesByPurpose(User1.PublicKeyHash, States::WitnessAddress::Class::Contribution, 0, 128);
		auto Addresses2 = *Context.GetWitnessAddressesByPurpose(User2.PublicKeyHash, States::WitnessAddress::Class::Contribution, 0, 128);
		auto AddressEthereum1 = std::find_if(Addresses1.begin(), Addresses1.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
		auto AddressEthereum2 = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
		auto AddressRipple = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("XRP"); });
		auto AddressBitcoin = std::find_if(Addresses2.begin(), Addresses2.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("BTC"); });
		VI_PANIC(AddressEthereum1 != Addresses1.end(), "ethereum custodian address not found");
		VI_PANIC(AddressEthereum2 != Addresses2.end(), "ethereum custodian address not found");
		VI_PANIC(AddressRipple != Addresses2.end(), "ripple custodian address not found");
		VI_PANIC(AddressBitcoin != Addresses2.end(), "bitcoin custodian address not found");

		auto* ClaimEthereum1 = Memory::New<Transactions::Claim>();
		ClaimEthereum1->SetAsset("ETH");
		ClaimEthereum1->SetEstimateGas(Decimal::Zero());
		ClaimEthereum1->SetWitness(14977180,
			"0x3bc2c98682f1b8feaacbde8f3f56494cd778da9d042da8439fb698d41bf060ea", 0.0,
			{ Oracle::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 150) },
			{ Oracle::Transferer(AddressEthereum1->Addresses.begin()->second, AddressEthereum1->AddressIndex, 150) });
		VI_PANIC(ClaimEthereum1->Sign(User1.SecretKey, User1Sequence++), "claim not signed");
		VI_PANIC(ClaimEthereum1->Attestate(User2.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimEthereum1);

		auto* ClaimEthereum2 = Memory::New<Transactions::Claim>();
		ClaimEthereum2->SetAsset("ETH");
		ClaimEthereum2->SetEstimateGas(Decimal::Zero());
		ClaimEthereum2->SetWitness(14977181,
			"0x7bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
			{ Oracle::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 110) },
			{ Oracle::Transferer(AddressEthereum2->Addresses.begin()->second, AddressEthereum2->AddressIndex, 110) });
		VI_PANIC(ClaimEthereum2->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimEthereum2->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimEthereum2);

		auto* ClaimRipple = Memory::New<Transactions::Claim>();
		ClaimRipple->SetAsset("XRP");
		ClaimRipple->SetEstimateGas(Decimal::Zero());
		ClaimRipple->SetWitness(88546831,
			"6618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
			{ Oracle::Transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", Optional::None, 1100) },
			{ Oracle::Transferer(AddressRipple->Addresses.begin()->second, AddressRipple->AddressIndex, 1100) });
		VI_PANIC(ClaimRipple->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimRipple->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimRipple);

		auto* ClaimBitcoin = Memory::New<Transactions::Claim>();
		ClaimBitcoin->SetAsset("BTC");
		ClaimBitcoin->SetEstimateGas(Decimal::Zero());
		ClaimBitcoin->SetWitness(846983,
			"17638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
			{ Oracle::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, 1.1) },
			{ Oracle::Transferer(AddressBitcoin->Addresses.begin()->second, AddressBitcoin->AddressIndex, 1.1) });
		VI_PANIC(ClaimBitcoin->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimBitcoin->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimBitcoin);
	}
	static void TestDelegatedCustodianAccounts(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestClaims(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto Context = Ledger::TransactionContext();
		auto ProposerAddresses = *Context.GetWitnessAddressesByPurpose(User2.PublicKeyHash, States::WitnessAddress::Class::Custodian, 0, 128);
		auto OwnerAddresses = *Context.GetWitnessAddressesByPurpose(User1.PublicKeyHash, States::WitnessAddress::Class::Custodian, 0, 128);
		auto AddressEthereum = std::find_if(ProposerAddresses.begin(), ProposerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("ETH"); });
		auto AddressRipple = std::find_if(OwnerAddresses.begin(), OwnerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("XRP"); });
		auto AddressBitcoin = std::find_if(OwnerAddresses.begin(), OwnerAddresses.end(), [](States::WitnessAddress& Item) { return Item.Asset == Algorithm::Asset::IdOf("BTC"); });
		VI_PANIC(AddressEthereum != ProposerAddresses.end(), "ethereum custodian address not found");
		VI_PANIC(AddressRipple != OwnerAddresses.end(), "ripple custodian address not found");
		VI_PANIC(AddressBitcoin != OwnerAddresses.end(), "bitcoin custodian address not found");

		auto* ClaimEthereum = Memory::New<Transactions::Claim>();
		ClaimEthereum->SetAsset("ETH");
		ClaimEthereum->SetEstimateGas(Decimal::Zero());
		ClaimEthereum->SetWitness(14977180,
			"0x2bc2c98682f1b8fea2031e8f3f56494cd778da9d042da8439fb698d41bf061ea", 0.0,
			{ Oracle::Transferer("0xCa0dfDdBb1cBD7B5A08E9173D9bbE5722138d4d5", Optional::None, 100) },
			{ Oracle::Transferer(AddressEthereum->Addresses.begin()->second, AddressEthereum->AddressIndex, 100) });
		VI_PANIC(ClaimEthereum->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimEthereum->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimEthereum);

		auto* ClaimRipple = Memory::New<Transactions::Claim>();
		ClaimRipple->SetAsset("XRP");
		ClaimRipple->SetEstimateGas(Decimal::Zero());
		ClaimRipple->SetWitness(88546830,
			"2618D20B801AF96DD060B34228E2594E30AFB7B33E335A8C60199B6CF8B0A69F", 0.0,
			{ Oracle::Transferer("rUBqz2JiRCT3gYZBnm28y5ME7e5UpSm2ok", Optional::None, 1000) },
			{ Oracle::Transferer(AddressRipple->Addresses.begin()->second, AddressRipple->AddressIndex, 1000) });
		VI_PANIC(ClaimRipple->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimRipple->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimRipple);

		auto* ClaimBitcoin = Memory::New<Transactions::Claim>();
		ClaimBitcoin->SetAsset("BTC");
		ClaimBitcoin->SetEstimateGas(Decimal::Zero());
		ClaimBitcoin->SetWitness(846982,
			"57638131d9af3033a5e20b753af254e1e8321b2039f16dfd222f6b1117b5c69d", 0.0,
			{ Oracle::Transferer("mmtubFoJvXrBuBUQFf1RrowXUbsiPDYnYS", Optional::None, 1.0) },
			{ Oracle::Transferer(AddressBitcoin->Addresses.begin()->second, AddressBitcoin->AddressIndex, 1.0) });
		VI_PANIC(ClaimBitcoin->Sign(User2.SecretKey, User2Sequence++), "claim not signed");
		VI_PANIC(ClaimBitcoin->Attestate(User1.SecretKey), "claim not attestated");
		Transactions.push_back(ClaimBitcoin);
	}
	static void TestTransfers(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto* OmniTransferEthereum = Memory::New<Transactions::Omnitransfer>();
		OmniTransferEthereum->SetAsset("ETH");
		OmniTransferEthereum->SetTo(User2.PublicKeyHash, 0.1);
		OmniTransferEthereum->SetTo(User2.PublicKeyHash, 0.2);
		OmniTransferEthereum->SetTo(User2.PublicKeyHash, 0.3);
		OmniTransferEthereum->SetTo(User2.PublicKeyHash, 0.4);
		OmniTransferEthereum->SetTo(User2.PublicKeyHash, 0.5);
		OmniTransferEthereum->SetEstimateGas(std::string_view("0.00000001"));
		VI_PANIC(OmniTransferEthereum->Sign(User1.SecretKey, User1Sequence++), "omnitransfer not signed");
		Transactions.push_back(OmniTransferEthereum);

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
	static void TestTransferToWallet(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User, uint64_t UserSequence, const Algorithm::AssetId& Asset, const std::string_view& Address, const Decimal& Value)
	{
		Algorithm::Pubkeyhash PublicKeyHash;
		Algorithm::Signing::DecodeAddress(Address, PublicKeyHash);

		auto* TransferAsset = Memory::New<Transactions::Transfer>();
		TransferAsset->Asset = Asset;
		TransferAsset->SetTo(PublicKeyHash, Value);
		TransferAsset->SetEstimateGas(std::string_view("0.0000000005"));
		VI_PANIC(TransferAsset->Sign(User.SecretKey, UserSequence++), "transfer not signed");
		Transactions.push_back(TransferAsset);
	}
	static void TestRollups(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestDeployments(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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

			token_info initialize(program@ context, const uint256&in value)
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
			token_transfer transfer(program@ context, const address&in to, const uint256&in value)
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
			uint256 mint(program@ context, const uint256&in value)
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
			uint256 burn(program@ context, const uint256&in value)
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
			uint256 balance_of(program@ const context, const address&in owner)
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
	static void TestInvocations(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestMigrationsStage1(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto Context = Ledger::TransactionContext();
		auto Contribution = Context.GetAccountContribution(Algorithm::Asset::IdOf("ETH"), User2.PublicKeyHash);
		if (!Contribution)
			return;

		auto* CustodianAccountEthereum = Memory::New<Transactions::CustodianAccount>();
		CustodianAccountEthereum->SetAsset("ETH");
		CustodianAccountEthereum->SetEstimateGas(Decimal::Zero());
		CustodianAccountEthereum->SetWallet(User1, User1.PublicKeyHash).Expect("custodian address not deployed");
		VI_PANIC(CustodianAccountEthereum->Sign(User1.SecretKey, User1Sequence++), "account not signed");
		Transactions.push_back(CustodianAccountEthereum);
	}
	static void TestMigrationsStage2(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto Context = Ledger::TransactionContext();
		auto Contribution = Context.GetAccountContribution(Algorithm::Asset::IdOf("ETH"), User2.PublicKeyHash);
		if (!Contribution)
			return;

		auto* ContributionMigrationEthereum = Memory::New<Transactions::ContributionMigration>();
		ContributionMigrationEthereum->SetAsset("ETH");
		ContributionMigrationEthereum->SetEstimateGas(Decimal::Zero());
		ContributionMigrationEthereum->SetProposer(User1.PublicKeyHash, Contribution->Custody);
		VI_PANIC(ContributionMigrationEthereum->Sign(User2.SecretKey, User2Sequence++), "contribution migration not signed");
		Transactions.push_back(ContributionMigrationEthereum);
	}
	static void TestWithdrawalsStage1(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestWithdrawalsStage2(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
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
	static void TestDeallocations(Vector<UPtr<Ledger::Transaction>>& Transactions, const Ledger::Wallet& User1, uint64_t User1Sequence, const Ledger::Wallet& User2, uint64_t User2Sequence)
	{
		auto Chain = Storages::Chainstate(__func__);
		auto Operations = Chain.GetBlockTransactionsByOwner(std::numeric_limits<int64_t>::max(), User2.PublicKeyHash, 1, 0, 1024);
		if (!Operations)
			return;

		for (auto& Item : *Operations)
		{
			if (Item.Transaction->AsType() != Transactions::ContributionActivation::AsInstanceType())
				continue;

			OrderedSet<String> Parties;
			if (!Item.Transaction->RecoverAlt(Item.Receipt, Parties))
				continue;

			auto* ContributionDeallocation = Memory::New<Transactions::ContributionDeallocation>();
			ContributionDeallocation->Asset = Item.Transaction->Asset;
			ContributionDeallocation->SetEstimateGas(Decimal::Zero());
			ContributionDeallocation->SetWitness(Item.Receipt.TransactionHash);
			if (Parties.find(String((char*)User1.PublicKeyHash, sizeof(User1.PublicKeyHash))) == Parties.end())
			{
				VI_PANIC(ContributionDeallocation->Sign(User2.SecretKey, User2Sequence++), "contribution deallocation not signed");
			}
			else
			{
				VI_PANIC(ContributionDeallocation->Sign(User1.SecretKey, User1Sequence++), "contribution deallocation not signed");
			}
			Transactions.push_back(ContributionDeallocation);
		}
	}
	static Ledger::Block ProposeBlockUserOne(std::function<void(Vector<UPtr<Ledger::Transaction>>&, const Ledger::Wallet&, uint64_t)>&& TestCase, const Ledger::Wallet& User1, const Ledger::Wallet& User2)
	{
		Vector<UPtr<Ledger::Transaction>> Transactions;
		TestCase(Transactions, User1, User1.GetLatestSequence().Or(1));
		return ProposeBlock(std::move(Transactions), User1, User2);
	}
	static Ledger::Block ProposeBlockUserTuple(std::function<void(Vector<UPtr<Ledger::Transaction>>&, const Ledger::Wallet&, uint64_t, const Ledger::Wallet&, uint64_t)>&& TestCase, const Ledger::Wallet& User1, const Ledger::Wallet& User2)
	{
		Vector<UPtr<Ledger::Transaction>> Transactions;
		TestCase(Transactions, User1, User1.GetLatestSequence().Or(1), User2, User2.GetLatestSequence().Or(1));
		return ProposeBlock(std::move(Transactions), User1, User2);
	}
	static Ledger::Block ProposeBlock(Vector<UPtr<Ledger::Transaction>>&& Transactions, const Ledger::Wallet& User1, const Ledger::Wallet& User2, bool Timing = false)
	{
		Ledger::EvaluationContext Environment;
		auto Priority = Environment.Priority(User2.PublicKeyHash, User2.SecretKey);
		if (!Priority || *Priority != 0)
		{
			Priority = Environment.Priority(User1.PublicKeyHash, User1.SecretKey);
			if (!Priority)
				VI_PANIC(false, "block proposal not allowed");
		}

		if (!Environment.Apply(std::move(Transactions)))
			VI_PANIC(false, "empty block not allowed");

		String Errors;
		auto Evaluation = Environment.Evaluate(&Errors);
		if (!Errors.empty())
			VI_PANIC(false, "block evaluation error: %s", Errors.c_str());

		auto Proposal = std::move(Evaluation.Expect("block evaluation failed"));
		Environment.Solve(Proposal).Expect("block solution failed");
		if (!Timing)
			Environment.Verify(Proposal).Expect("block verification failed");

		Transactions = Vector<UPtr<Ledger::Transaction>>();
		Proposal.Checkpoint().Expect("block checkpoint failed");
		if (!Timing)
			Console::Get()->jWriteLine(*Proposal.AsSchema());

		auto User1Dispatch = memcmp(User1.PublicKeyHash, User2.PublicKeyHash, sizeof(User2.PublicKeyHash)) != 0 ? Proposal.DispatchSync(User1) : ExpectsLR<Ledger::BlockDispatch>(LayerException());
		if (User1Dispatch && !User1Dispatch->Outputs.empty())
		{
			auto User1Sequence = User1.GetLatestSequence().Or(1);
			for (auto& Transaction : User1Dispatch->Outputs)
			{
				VI_PANIC(Transaction->Sign(User1.SecretKey, User1Sequence++, Decimal::Zero()), "dispatch transaction not signed");
				if (Transaction->GetType() == Ledger::TransactionLevel::Aggregation)
					VI_PANIC(((Ledger::AggregationTransaction*)*Transaction)->Attestate(User2.SecretKey), "dispatch transaction not attested");
			}
			Transactions.insert(Transactions.end(), std::make_move_iterator(User1Dispatch->Outputs.begin()), std::make_move_iterator(User1Dispatch->Outputs.end()));
		}

		auto User2Dispatch = Proposal.DispatchSync(User2);
		if (User2Dispatch && !User2Dispatch->Outputs.empty())
		{
			auto User2Sequence = User2.GetLatestSequence().Or(1);
			for (auto& Transaction : User2Dispatch->Outputs)
			{
				VI_PANIC(Transaction->Sign(User2.SecretKey, User2Sequence++, Decimal::Zero()), "dispatch transaction not signed");
				if (Transaction->GetType() == Ledger::TransactionLevel::Aggregation)
					VI_PANIC(((Ledger::AggregationTransaction*)*Transaction)->Attestate(User1.SecretKey), "dispatch transaction not attested");
			}
			Transactions.insert(Transactions.end(), std::make_move_iterator(User2Dispatch->Outputs.begin()), std::make_move_iterator(User2Dispatch->Outputs.end()));
		}

		if (User1Dispatch)
			User1Dispatch->Checkpoint().Expect("dispatch checkpoint failed");
		else if (User2Dispatch)
			User2Dispatch->Checkpoint().Expect("dispatch checkpoint failed");

		if (!Transactions.empty())
			ProposeBlock(std::move(Transactions), User1, User2);
		return Proposal;
	}
};

class Tests
{
public:
	/* Blockchain containing all transaction types (zero balance accounts, valid regtest chain) */
	static int FullCoverage(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);

		auto User1 = Ledger::Wallet::FromSeed("000001");
		auto User2 = Ledger::Wallet::FromSeed("000000");
		Blocks::ProposeBlockUserTuple(&Blocks::TestAllowances1Threshold, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestAdjustments, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestAddressAccounts, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestPubkeyAccounts, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestCommitments, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestAllocations, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestContributions, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestDelegatedCustodianAccounts, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestClaims, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestTransfers, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestRollups, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestDeployments, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestInvocations, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestMigrationsStage1, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestMigrationsStage2, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestWithdrawalsStage1, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestWithdrawalsStage2, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestDeallocations, User1, User2);
		Term->ReadChar();
		return 0;
	}
	/* Blockchain containing some transaction types (non-zero balance accounts, valid regtest chain) */
	static int PartialCoverage(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);

		auto User1 = Ledger::Wallet::FromSeed("000001");
		auto User2 = Ledger::Wallet::FromSeed("000000");
		Blocks::ProposeBlockUserTuple(&Blocks::TestAllowances0Threshold, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestAdjustments, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestAddressAccounts, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestDelegatedCustodianAccounts, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestCommitments, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestClaims, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestTransfers, User1, User2);
		Blocks::ProposeBlockUserOne(std::bind(&Blocks::TestTransferToWallet, std::placeholders::_1, std::placeholders::_2, std::placeholders::_3, Algorithm::Asset::IdOf("BTC"), "tcrt1xq2lqn6589qmtcy78sxkf975jexq7jfa9rt4r3d", 0.1), User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestRollups, User1, User2);
		Blocks::ProposeBlockUserTuple(&Blocks::TestCommitmentAnti, User1, User2);
		Term->ReadChar();
		return 0;
	}
	/* Verify current blockchain */
	static int Verify(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto* Queue = Schedule::Get();
		Queue->Start(Schedule::Desc());

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
				Result->Set("detail", Var::String(Validation.Error().Info));
				goto StopVerification;
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
		Queue->Stop();
		Term->jWriteLine(*Data);
		Term->ReadChar();
		return 0;
	}
	/* Prove and verify Nakamoto POW */
	static int Nakamoto(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();
		Term->CaptureTime();

		auto Message = "Hello, World!";
		uint256_t Target = uint256_t(1) << uint256_t(240);
		uint256_t Nonce = 0;
		while (true)
		{
			auto Solution = Provability::NakamotoPOW::Evaluate(Nonce, Message);
			bool Proven = Provability::NakamotoPOW::Verify(Nonce, Message, Target, Solution);
			if (!Proven)
			{
				++Nonce;
				continue;
			}

			Term->fWriteLine("solution: %s (nonce: %s)", Algorithm::Encoding::Encode0xHex256(Solution).c_str(), Nonce.ToString().c_str());
			Term->fWriteLine("time: %.2f ms (%s)", Term->GetCapturedTime(), Proven ? "passed" : "failed");
			break;
		}

		Term->ReadChar();
		return 0;
	}
	/* Prove and verify Wesolowski VDF signature */
	static int Wesolowski(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();
		Term->CaptureTime();

		auto Message = "Hello, World!";
		Provability::WesolowskiVDF::Parameters Alg; Alg.Pow *= 20;
		auto Signature = Provability::WesolowskiVDF::Evaluate(Alg, Message);
		bool Proven = Provability::WesolowskiVDF::Verify(Alg, Message, Signature);

		Term->fWriteLine("solution: %s", Signature.c_str());
		Term->fWriteLine("time: %.2f ms (%s)", Term->GetCapturedTime(), Proven ? "passed" : "failed");
		Term->ReadChar();
		return 0;
	}
	/* Calibrate Wesolowski VDF difficulty based on host machine */
	static int Calibration(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();
		Term->CaptureTime();

		auto Alg = Provability::WesolowskiVDF::Calibrate(4);
		Console::Get()->fWriteLine(
			"calibration alg:\n"
			"  length: %i\n"
			"  bits: %i\n"
			"  pow: %llu\n"
			"  difficulty: %s",
			Alg.Length, Alg.Bits, Alg.Pow,
			Alg.Difficulty().ToString().c_str());
		Term->ReadChar();
		return 0;
	}
	/* Gas estimation */
	static int GasEstimation(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();
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
		Term->fWriteLine(
			"estimate gas limit: %s\n"
			"optimal gas limit: %s\n"
			"block gas limit: %s",
			EstimateGasLimit.ToString().c_str(),
			OptimalGasLimit.ToString().c_str(),
			BlockGasLimit.ToString().c_str());
		Term->ReadChar();
		return 0;
	}
	/* Generic cryptography */
	static int Cryptography(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		String Mnemonic = "chimney clerk liberty defense gesture risk disorder switch raven chapter document admit win swing forward please clerk vague online coil material tone sibling intact";
		Algorithm::Seckey SecretKey;
		Algorithm::Pubkey PublicKey;
		Algorithm::Pubkey TweakedPublicKey;
		Algorithm::Pubkeyhash PublicKeyHash;
		Algorithm::Pubkeyhash TweakedPublicKeyHash;
		Algorithm::Signing::DeriveSecretKey(Mnemonic, SecretKey);
		Algorithm::Signing::DerivePublicKey(SecretKey, PublicKey);
		Algorithm::Signing::DeriveTweakedPublicKey(SecretKey, PublicKey, TweakedPublicKey);
		Algorithm::Signing::DerivePublicKeyHash(PublicKey, PublicKeyHash);
		Algorithm::Signing::DerivePublicKeyHash(TweakedPublicKey, TweakedPublicKeyHash);

		String EncodedSecretKey, EncodedPublicKey, EncodedTweakedPublicKey, EncodedPublicKeyHash, EncodedTweakedPublicKeyHash;
		Algorithm::Signing::EncodeSecretKey(SecretKey, EncodedSecretKey);
		Algorithm::Signing::EncodePublicKey(PublicKey, EncodedPublicKey);
		Algorithm::Signing::EncodePublicKey(TweakedPublicKey, EncodedTweakedPublicKey);
		Algorithm::Signing::EncodeAddress(PublicKeyHash, EncodedPublicKeyHash);
		Algorithm::Signing::EncodeAddress(TweakedPublicKeyHash, EncodedTweakedPublicKeyHash);

		String Message = "Hello, World!";
		uint256_t MessageHash = Algorithm::Hashing::Hash256i(Message);
		String EncodedMessageHash = Algorithm::Encoding::Encode0xHex256(MessageHash);
		Algorithm::Sighash MessageSignature;
		Algorithm::Sighash MessageTweakedSignature;
		Algorithm::Pubkey RecoverPublicKey;
		Algorithm::Pubkey RecoverTweakedPublicKey;
		Algorithm::Pubkeyhash RecoverPublicKeyHash;
		Algorithm::Pubkeyhash RecoverTweakedPublicKeyHash;
		bool Verifies = Algorithm::Signing::SignNormal(MessageHash, SecretKey, MessageSignature) && Algorithm::Signing::VerifyNormal(MessageHash, PublicKey, MessageSignature);
		bool VerifiesTweaked = Algorithm::Signing::SignTweaked(MessageHash, SecretKey, MessageTweakedSignature) && Algorithm::Signing::VerifyTweaked(MessageHash, PublicKey, MessageTweakedSignature);
		bool RecoversPublicKey = Algorithm::Signing::RecoverNormal(MessageHash, RecoverPublicKey, MessageSignature);
		bool RecoversTweakedPublicKey = Algorithm::Signing::RecoverTweaked(MessageHash, RecoverTweakedPublicKey, MessageTweakedSignature);
		bool RecoversPublicKeyHash = Algorithm::Signing::RecoverNormalHash(MessageHash, RecoverPublicKeyHash, MessageSignature);
		bool RecoversTweakedPublicKeyHash = Algorithm::Signing::RecoverTweakedHash(MessageHash, RecoverTweakedPublicKeyHash, MessageTweakedSignature);
		String EncodedMessageSignature = Format::Util::Encode0xHex(std::string_view((char*)MessageSignature, sizeof(MessageSignature)));
		String EncodedMessageTweakedSignature = Format::Util::Encode0xHex(std::string_view((char*)MessageTweakedSignature, sizeof(MessageTweakedSignature)));
		String EncodedRecoverPublicKey, EncodedRecoverPublicKeyHash, EncodedRecoverTweakedPublicKey, EncodedRecoverTweakedPublicKeyHash;
		Algorithm::Signing::EncodePublicKey(RecoverPublicKey, EncodedRecoverPublicKey);
		Algorithm::Signing::EncodePublicKey(RecoverTweakedPublicKey, EncodedRecoverTweakedPublicKey);
		Algorithm::Signing::EncodeAddress(RecoverPublicKeyHash, EncodedRecoverPublicKeyHash);
		Algorithm::Signing::EncodeAddress(RecoverTweakedPublicKeyHash, EncodedRecoverTweakedPublicKeyHash);

		auto Info = UPtr<Schema>(Var::Set::Object());
		Info->Set("mnemonic", Var::String(Mnemonic));
		Info->Set("mnemonic_test", Var::String(Algorithm::Signing::VerifyMnemonic(Mnemonic) ? "passed" : "failed"));
		Info->Set("secret_key", Var::String(EncodedSecretKey));
		Info->Set("secret_key_test", Var::String(Algorithm::Signing::VerifySecretKey(SecretKey) ? "passed" : "failed"));
		Info->Set("message", Var::String(Message));
		Info->Set("message_hash", Var::String(EncodedMessageHash));

		auto* Normal = Info->Set("signature_normal", Var::Set::Object());
		Normal->Set("public_key", Var::String(EncodedPublicKey));
		Normal->Set("public_key_test", Var::String(Algorithm::Signing::VerifyPublicKey(PublicKey) ? "passed" : "failed"));
		Normal->Set("address", Var::String(EncodedPublicKeyHash));
		Normal->Set("address_test", Var::String(Algorithm::Signing::VerifyAddress(EncodedPublicKeyHash) ? "passed" : "failed"));
		Normal->Set("signature", Var::String(EncodedMessageSignature));
		Normal->Set("signature_test", Var::String(Verifies ? "passed" : "failed"));
		Normal->Set("recover_public_key", Var::String(EncodedRecoverPublicKey));
		Normal->Set("recover_public_key_test", Var::String(RecoversPublicKey && EncodedRecoverPublicKey == EncodedPublicKey ? "passed" : "failed"));
		Normal->Set("recover_address", Var::String(EncodedRecoverPublicKeyHash));
		Normal->Set("recover_address_test", Var::String(RecoversPublicKeyHash && EncodedRecoverPublicKeyHash == EncodedPublicKeyHash ? "passed" : "failed"));

		auto* Blinding = Info->Set("signature_blinding", Var::Set::Object());
		Blinding->Set("public_key", Var::String(EncodedTweakedPublicKey));
		Blinding->Set("public_key_test", Var::String(Algorithm::Signing::VerifyPublicKey(TweakedPublicKey) ? "passed" : "failed"));
		Blinding->Set("address", Var::String(EncodedTweakedPublicKeyHash));
		Blinding->Set("address_test", Var::String(Algorithm::Signing::VerifyAddress(EncodedTweakedPublicKeyHash) ? "passed" : "failed"));
		Blinding->Set("signature", Var::String(EncodedMessageTweakedSignature));
		Blinding->Set("signature_test", Var::String(Verifies ? "passed" : "failed"));
		Blinding->Set("recover_public_key", Var::String(EncodedRecoverTweakedPublicKey));
		Blinding->Set("recover_public_key_test", Var::String(RecoversTweakedPublicKey && EncodedRecoverTweakedPublicKey == EncodedTweakedPublicKey ? "passed" : "failed"));
		Blinding->Set("recover_address", Var::String(EncodedRecoverTweakedPublicKeyHash));
		Blinding->Set("recover_address_test", Var::String(RecoversTweakedPublicKeyHash && EncodedRecoverTweakedPublicKeyHash == EncodedTweakedPublicKeyHash ? "passed" : "failed"));

		Term->jWriteLine(*Info);
		Term->ReadChar();
		return 0;
	}
	/* Wallet cryptography */
	static int Wallet(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Wallet = Ledger::Wallet::FromSeed();
		auto WalletInfo = Wallet.AsSchema();
		WalletInfo->Set("secret_key_test", Var::String(Algorithm::Signing::VerifySecretKey(Wallet.SecretKey) ? "passed" : "failed"));
		WalletInfo->Set("public_key_test", Var::String(Algorithm::Signing::VerifyPublicKey(Wallet.PublicKey) ? "passed" : "failed"));
		WalletInfo->Set("address_test", Var::String(Algorithm::Signing::VerifyAddress(Wallet.GetAddress()) ? "passed" : "failed"));

		Term->jWriteLine(*WalletInfo);
		Term->ReadChar();
		return 0;
	}
	/* Transaction cryptography */
	static int Transaction(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Wallet = Ledger::Wallet::FromSeed();
		Vector<UPtr<Ledger::Transaction>> Transactions;
		Blocks::TestTransfers(Transactions, Ledger::Wallet::FromSeed(), 1, Wallet, 1);
		auto& Tx = *(Transactions::Transfer*)*Transactions.back();
		auto TxBlob = Tx.AsMessage().Data;
		auto TxBody = Format::Stream(TxBlob);
		auto TxCopy = UPtr<Ledger::Transaction>(Transactions::Resolver::New(Messages::Authentic::ResolveType(TxBody).Or(0)));
		auto TxInfo = Tx.AsSchema();
		Algorithm::Pubkeyhash RecoverPublicKeyHash = { 0 };
		TxInfo->Set("recovery_test", Var::String(Tx.Recover(RecoverPublicKeyHash) && !memcmp(Wallet.PublicKeyHash, RecoverPublicKeyHash, sizeof(RecoverPublicKeyHash)) ? "passed" : "failed"));
		TxInfo->Set("verification_test", Var::String(Tx.Verify(Wallet.PublicKey) ? "passed" : "failed"));
		TxInfo->Set("serialization_test", Var::String(TxCopy && TxCopy->Load(TxBody) && TxCopy->AsMessage().Data == TxBlob ? "passed" : "failed"));
		TxInfo->Set("raw_data_test", Var::String(Format::Util::Encode0xHex(TxBlob)));

		auto Stream = Tx.AsMessage();
		Format::Variables Vars;
		Format::VariablesUtil::DeserializeFlatFrom(Stream, &Vars);
		TxInfo->Set("var_data_test", Format::VariablesUtil::Serialize(Vars));
		TxInfo->Set("asset_test", Algorithm::Asset::Serialize(Algorithm::Asset::IdOf("ETH", "USDT", "0xdAC17F958D2ee523a2206206994597C13D831ec7")));

		Term->jWriteLine(*TxInfo);
		Term->ReadChar();
		return 0;
	}
	/* Merkle tree cryptography */
	static int MerkleTree(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		const size_t Hashes = 16;
		uint256_t Prev = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(16));
		uint256_t Next = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(16));
		Provability::MerkleTree Tree = Prev;
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

		Term->ReadChar();
		return 0;
	}
	/* Oracle wallets cryptography */
	static int OracleWallets(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto User = Ledger::Wallet::FromSeed("0000000");
		for (auto& MasterWallet : Oracle::Bridge::GetWallets(User.SecretKey))
		{
			auto Asset = Algorithm::Asset::IdOf(MasterWallet.first);
			UPtr<Schema> Wallet = Var::Set::Object();
			Wallet->Set("asset", Algorithm::Asset::Serialize(Asset));
			Wallet->Set("master", MasterWallet.second.AsSchema().Reset());
			Wallet->Set("child", Oracle::Datamaster::NewSigningWallet(Asset, MasterWallet.second, 0)->AsSchema().Reset());
			Term->jWriteLine(*Wallet);
		}

		Term->ReadChar();
		return 0;
	}
	/* Oracle chain watch and withdrawals */
	static int OracleOperations(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();
		Term->WriteLine("[ start of program ]");

		static bool IsActive = true;
		OS::Process::BindSignal(Signal::SIG_INT, [](int) { IsActive = false; });

		Schedule::Desc Policy;
		Schedule* Queue = Schedule::Get();
		Queue->Start(Policy);

		auto Asset = Algorithm::Asset::IdOf("BTC");
		auto Parent = Oracle::Datamaster::NewMasterWallet(Asset, String("123456"));
		auto Child = Oracle::DynamicWallet(*Oracle::Datamaster::NewSigningWallet(Asset, *Parent, 0));
		for (auto& Address : Child.SigningChild->Addresses)
			Oracle::Datamaster::EnableWalletAddress(Asset, *Child.GetBinding(), Address.second, *Child.SigningChild->AddressIndex);

		Coasync<void>([&]() -> Promise<void>
		{
			String Addresses;
			for (auto& Address : Child.SigningChild->Addresses)
				Addresses += Stringify::Text("      address v%i: %s\n", (int)Address.first, Address.second.c_str());

			auto Balance = Coawait(Oracle::Datamaster::CalculateBalance(Asset, Child));
			VI_INFO(
				"%s parent wallet:\n"
				"  seeding key: %s\n"
				"  signing key: %s\n"
				"  verifying key: %s\n"
				"  child wallet (index: %" PRIu64 "):\n"
				"    signing key: %s\n"
				"    verifying key: %s\n"
				"    addresses:\n%s"
				"  coins value: %s %s",
				Algorithm::Asset::HandleOf(Asset).c_str(),
				Parent->SeedingKey.ExposeToHeap().c_str(),
				Parent->SigningKey.ExposeToHeap().c_str(),
				Parent->VerifyingKey.ExposeToHeap().c_str(),
				*Child.SigningChild->AddressIndex,
				Child.SigningChild->SigningKey.ExposeToHeap().c_str(),
				Child.SigningChild->VerifyingKey.ExposeToHeap().c_str(),
				Addresses.c_str(),
				Balance ? Balance->ToString().c_str() : "?",
				Algorithm::Asset::HandleOf(Asset).c_str());

			Oracle::MultichainSupervisorOptions Options;
			Coawait(Oracle::Paymaster::Startup(Options));

			for (size_t i = 0; i < 0; i++)
			{
				uint256_t Hash;
				Algorithm::Encoding::EncodeUint256((uint8_t*)Crypto::RandomBytes(32)->data(), Hash);
				auto Transaction = Coawait(Oracle::Paymaster::SubmitTransaction(Hash, Asset, Oracle::DynamicWallet(Child),
					{
						Oracle::Transferer("bcrt1p5dy9ef2lngvmlx6edjgp88hemj03uszt3zlqrc252vlxp3jf27vq648qmh", Optional::None, 0.01)
					}, Oracle::BaseFee(0.000003, 1)));
				if (!Transaction)
					break;
			}

			while (IsActive)
			{
				Promise<void> Future;
				Queue->SetTimeout(200, [Future]() mutable { Future.Set(); });
				Coawait(std::move(Future));
			}

			Coawait(Oracle::Paymaster::Shutdown());
			CoreturnVoid;
		}).Wait();

		while (Queue->Dispatch());
		Queue->Stop();

		Term->WriteLine("[ end of program ]");
		Term->ReadChar();
		return 0;
	}
	/* Shared wallet cryptography */
	static int SharedWallet(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto Id = Algorithm::Asset::IdOf("BTC");
		auto Alg = Algorithm::Composition::Type::SECP256K1;
		String Message = "Hello, World!";
		size_t PublicKeySize = 0;
		size_t SecretKeySize = 0;
		Algorithm::Pubkey PublicKey;
		Algorithm::Composition::CSeckey SecretKey;
		Algorithm::Composition::CSeckey SecretKey1, SecretKey2;
		Algorithm::Composition::CPubkey PublicKey1, PublicKey2;
		Algorithm::Composition::DeriveKeypair1(Alg, SecretKey1, PublicKey1);
		Algorithm::Composition::DeriveKeypair2(Alg, PublicKey1, SecretKey2, PublicKey2, PublicKey, &PublicKeySize);
		Algorithm::Composition::DeriveSecretKey(Alg, SecretKey1, SecretKey2, SecretKey, &SecretKeySize);
		auto SigningWallet = Oracle::Datamaster::NewSigningWallet(Id, std::string_view((char*)SecretKey, SecretKeySize)).Expect("wallet derivation failed");
		auto VerifyingWallet = Oracle::Datamaster::NewVerifyingWallet(Id, std::string_view((char*)PublicKey, PublicKeySize)).Expect("wallet derivation failed");
		auto Signature = Oracle::Datamaster::SignMessage(Id, Message, SigningWallet.SigningKey);
		auto Verification = Signature ? Oracle::Datamaster::VerifyMessage(Id, Message, SigningWallet.VerifyingKey.ExposeToHeap(), *Signature) : ExpectsLR<void>(LayerException("signature generation failed"));
		Term->fWrite(
			"secret key share 1        : %s\n"
			"secret key share 2        : %s\n"
			"secret key composition    : %s\n"
			"public key composition     : %s\n\n"
			"signing wallet secret key : %s\n"
			"signing wallet public key  : %s\n"
			"signing wallet address     : %s\n\n"
			"veryfing wallet public key : %s\n"
			"veryfing wallet address    : %s\n\n"
			"signature payload          : %s%s\n"
			"signature verification     : %s%s\n"
			"blob payload               : %.*s\n",
			Codec::HexEncode(std::string_view((char*)SecretKey1, sizeof(SecretKey1))).c_str(),
			Codec::HexEncode(std::string_view((char*)SecretKey2, sizeof(SecretKey2))).c_str(),
			Codec::HexEncode(std::string_view((char*)SecretKey, SecretKeySize)).c_str(),
			Codec::HexEncode(std::string_view((char*)PublicKey, PublicKeySize)).c_str(),
			SigningWallet.SigningKey.ExposeToHeap().c_str(),
			SigningWallet.VerifyingKey.ExposeToHeap().c_str(),
			SigningWallet.Addresses.begin()->second.c_str(),
			VerifyingWallet.VerifyingKey.ExposeToHeap().c_str(),
			VerifyingWallet.Addresses.begin()->second.c_str(),
			Signature ? Codec::HexEncode(*Signature).c_str() : Signature.Error().what(), Signature ? "" : " (failed)",
			Verification ? "success" : Verification.Error().what(), Verification ? "" : " (failed)",
			(int)Message.size(), Message.data());

		Term->ReadChar();
		return 0;
	}
	/* Wallet encryption cryptography */
	static int WalletMessaging(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto User1 = Ledger::Wallet::FromSeed();
		auto User2 = Ledger::Wallet::FromSeed();
		auto MessageFromUser1 = "Hello, Alice!";
		auto MessageFromUser2 = "Hello, Bob!";
		auto Ciphertext1 = User1.SealMessage(MessageFromUser1, User2.SealingKey);
		auto Plaintext1 = Ciphertext1 ? User2.OpenMessage(*Ciphertext1) : Option<String>(Optional::None);
		auto Ciphertext2 = User2.SealMessage(MessageFromUser2, User1.SealingKey);
		auto Plaintext2 = Ciphertext2 ? User1.OpenMessage(*Ciphertext2) : Option<String>(Optional::None);
		Term->fWrite(
			"user1 wallet:\n"
			"  secret key: %s\n"
			"  public key: %s\n"
			"  address: %s\n"
			"  sealing key: %s\n"
			"    ciphertext to user2 wallet: %s\n"
			"    plaintext from user2 wallet: %s\n\n"
			"user2 wallet:\n"
			"  secret key: %s\n"
			"  public key: %s\n"
			"  address: %s\n"
			"  sealing key: %s\n"
			"    ciphertext to user1 wallet: %s\n"
			"    plaintext from user1 wallet: %s\n",
			User1.GetSecretKey().c_str(),
			User1.GetPublicKey().c_str(),
			User1.GetAddress().c_str(),
			User1.GetSealingKey().c_str(),
			Ciphertext1 ? Codec::HexEncode(*Ciphertext1).c_str() : "** encryption error **",
			Plaintext2 ? Plaintext2->c_str() : "** decryption error **",
			User2.GetSecretKey().c_str(),
			User2.GetPublicKey().c_str(),
			User2.GetAddress().c_str(),
			User2.GetSealingKey().c_str(),
			Ciphertext2 ? Codec::HexEncode(*Ciphertext2).c_str() : "** encryption error **",
			Plaintext1 ? Plaintext1->c_str() : "** decryption error **");

		Term->ReadChar();
		return 0;
	}
	/* 256bit integer serialization */
	static int IntegerSerialization(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		for (size_t i = 0; i < 1024 * 4; i++)
		{
			uint256_t Value = Algorithm::Hashing::Hash256i(*Crypto::RandomBytes(32));

			uint8_t Data1[32] = { 0 }; uint256_t Value1 = 0;
			Algorithm::Encoding::DecodeUint256(Value, Data1);
			Algorithm::Encoding::EncodeUint256(Data1, Value1);

			uint8_t Data2[32] = { 0 };
			auto Raw = Codec::HexDecode(Value.ToString(16, 64));
			memcpy((char*)Data2, Raw.data(), std::min(Raw.size(), sizeof(uint256_t)));
			uint256_t Value2 = uint256_t(Codec::HexEncode(std::string_view((char*)Data2, sizeof(uint256_t))), 16);
			VI_PANIC(memcmp(Data1, Data2, sizeof(Data2)) == 0, "uint256 decoding failed");
			VI_PANIC(Value1 == Value2 && Value1 == Value, "uint256 encoding failed");
		}

		Term->WriteLine("uint256 test passed");
		Term->ReadChar();
		return 0;
	}
};

class Benchmarks
{
public:
	/* Blockchain with 1536 + 1 blocks filled with low entropy transactions (non-zero balance accounts, invalid chain - bad genesis block, performance measurement) */
	static int LowEntropyThroughput(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto* Queue = Schedule::Get();
		Queue->Start(Schedule::Desc());

		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);

		if (argc > 1 && !strcmp(argv[1], "calibrate"))
		{
			auto Alg = Provability::WesolowskiVDF::Calibrate(4);
			Console::Get()->fWriteLine(
				"calibration alg:\n"
				"  length: %i\n"
				"  bits: %i\n"
				"  pow: %llu\n"
				"  difficulty: %s",
				Alg.Length, Alg.Bits, Alg.Pow,
				Alg.Difficulty().ToString().c_str());
			Provability::WesolowskiVDF::SetDefault(Alg);
		}

		const size_t BlockCount = 1536, TxCount = 40;
		auto Chain = Storages::Chainstate(__func__);
		auto Seed = Algorithm::Hashing::Hash256i("123456");
		auto Account = Ledger::Wallet::FromSeed("000001");
		auto Receiver = Ledger::Wallet::FromSeed("000000");
		auto Genesis = Ledger::Block();
		auto Balance = Memory::New<States::AccountBalance>(Account.PublicKeyHash, &Genesis);
		Balance->Asset = Algorithm::Asset::IdOf("BTC");
		Balance->Supply = 100;
		Genesis.Target = Provability::WesolowskiVDF::GetDefault();
		Genesis.States.MoveAny(Balance);
		Genesis.States.Commit();
		Genesis.SetParentBlock(nullptr);
		Genesis.Recalculate(nullptr);
		VI_PANIC(Genesis.Solve(Account.SecretKey), "genesis block solve failed");
		VI_PANIC(Genesis.Sign(Account.SecretKey), "genesis block sign failed");
		Genesis.Checkpoint().Expect("genesis block checkpoint failed");

		uint8_t Hash[32];
		Algorithm::Encoding::DecodeUint256(Genesis.AsHash(), Hash);
		uint64_t AccountNonce = Account.GetLatestSequence().Or(1);
		for (size_t i = 0; i < BlockCount; i++)
		{
			Vector<UPtr<Ledger::Transaction>> Transactions;
			Transactions.reserve(Protocol::Now().Policy.TransactionThroughput * Protocol::Now().Policy.ConsensusProofTime / 1000);
			uint256_t GasUse = 0, GasLimit = Ledger::Block::GetGasLimit();
			size_t Count = TxCount > 0 ? (size_t)(uint64_t)(Seed % 40 + 1) : std::numeric_limits<size_t>::max();
			Seed = Algorithm::Hashing::Hash256i(Seed.ToString());
			for (size_t j = 0; j < Count; j++)
			{
				auto* Transaction = Memory::New<Transactions::Transfer>();
				GasUse += Transaction->GetGasEstimate();
				if (GasUse > GasLimit)
					break;

				uint8_t ValueHash[32];
				Algorithm::Hashing::Hash256(Hash, sizeof(Hash), ValueHash);
				memcpy(Hash, ValueHash, sizeof(ValueHash));

				uint64_t Value;
				memcpy(&Value, ValueHash, sizeof(Value));
				Value = 1 + Value % 1500;

				Transaction->SetAsset("BTC");
				Transaction->SetEstimateGas(Decimal::Zero());
				Transaction->SetTo(Receiver.PublicKeyHash, Decimal(Value).Truncate(8) / 1000000.0);
				VI_PANIC(Transaction->Sign(Account.SecretKey, AccountNonce++), "transfer not signed");
				Transactions.push_back(Transaction);
			}

			uint64_t Queries = Ledger::StorageUtil::GetThreadQueries();
			Term->CaptureTime();
			auto Block = Blocks::ProposeBlock(std::move(Transactions), Account, Account, true);
			Queries = (Ledger::StorageUtil::GetThreadQueries() - Queries);
			double Time = Term->GetCapturedTime();
			double Tps = 1000.0 * (double)Block.TransactionsCount / Time;
			double Sps = 1000.0 * (double)Block.StatesCount / Time;
			double Qps = 1000.0 * (double)Queries / Time;
			Term->fWriteLine("block %s %.2f ms (number: %i, target: %s, txns: %i, states: %i, syncs: %i, tps: %.2f, sps: %.2f, qps: %.2f)",
				Algorithm::Encoding::Encode0xHex256(Block.AsHash()).c_str(), Time, (int)Block.Number, Block.Target.Difficulty().ToString().c_str(),
				(int)Block.TransactionsCount, (int)Block.StatesCount, (int)Queries,
				Tps, Sps, Qps);
		}

		Queue->Stop();
		Term->ReadChar();
		return 0;
	}
	/* Blockchain with 1536 + 1 blocks filled with high entropy transactions (non-zero balance accounts, invalid chain - bad genesis block, performance measurement) */
	static int HighEntropyThroughput(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto* Queue = Schedule::Get();
		Queue->Start(Schedule::Desc());

		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);

		if (argc > 1 && !strcmp(argv[1], "calibrate"))
		{
			auto Alg = Provability::WesolowskiVDF::Calibrate(4);
			Console::Get()->fWriteLine(
				"calibration alg:\n"
				"  length: %i\n"
				"  bits: %i\n"
				"  pow: %llu\n"
				"  difficulty: %s",
				Alg.Length, Alg.Bits, Alg.Pow,
				Alg.Difficulty().ToString().c_str());
			Provability::WesolowskiVDF::SetDefault(Alg);
		}

		const size_t BlockCount = 1536, TxCount = 40;
		auto Chain = Storages::Chainstate(__func__);
		auto Seed = Algorithm::Hashing::Hash256i("123456");
		auto Account = Ledger::Wallet::FromSeed("000001");
		auto Genesis = Ledger::Block();
		auto Balance = Memory::New<States::AccountBalance>(Account.PublicKeyHash, &Genesis);
		Balance->Asset = Algorithm::Asset::IdOf("BTC");
		Balance->Supply = 100;
		Genesis.Target = Provability::WesolowskiVDF::GetDefault();
		Genesis.States.MoveAny(Balance);
		Genesis.States.Commit();
		Genesis.SetParentBlock(nullptr);
		Genesis.Recalculate(nullptr);
		VI_PANIC(Genesis.Solve(Account.SecretKey), "genesis block solve failed");
		VI_PANIC(Genesis.Sign(Account.SecretKey), "genesis block sign failed");
		Genesis.Checkpoint().Expect("genesis block checkpoint failed");

		uint8_t Hash[32];
		Algorithm::Encoding::DecodeUint256(Genesis.AsHash(), Hash);
		uint64_t AccountNonce = Account.GetLatestSequence().Or(1);
		for (size_t i = 0; i < BlockCount; i++)
		{
			Vector<UPtr<Ledger::Transaction>> Transactions;
			Transactions.reserve(Protocol::Now().Policy.TransactionThroughput * Protocol::Now().Policy.ConsensusProofTime / 1000);
			uint256_t GasUse = 0, GasLimit = Ledger::Block::GetGasLimit();
			size_t Count = TxCount > 0 ? (size_t)(uint64_t)(Seed % 40 + 1) : std::numeric_limits<size_t>::max();
			Seed = Algorithm::Hashing::Hash256i(Seed.ToString());
			for (size_t j = 0; j < Count; j++)
			{
				auto* Transaction = Memory::New<Transactions::Transfer>();
				GasUse += Transaction->GetGasEstimate();
				if (GasUse > GasLimit)
					break;

				uint8_t PublicKeyHash[32];
				Algorithm::Hashing::Hash256(Hash, sizeof(Hash), PublicKeyHash);
				memcpy(Hash, PublicKeyHash, sizeof(PublicKeyHash));

				uint64_t Value;
				memcpy(&Value, PublicKeyHash + 20, sizeof(Value));
				Value = 1 + Value % 1500;

				Transaction->SetAsset("BTC");
				Transaction->SetEstimateGas(Decimal::Zero());
				Transaction->SetTo(PublicKeyHash, Decimal(Value).Truncate(8) / 1000000.0);
				VI_PANIC(Transaction->Sign(Account.SecretKey, AccountNonce++), "transfer not signed");
				Transactions.push_back(Transaction);
			}

			uint64_t Queries = Ledger::StorageUtil::GetThreadQueries();
			Term->CaptureTime();
			auto Block = Blocks::ProposeBlock(std::move(Transactions), Account, Account, true);
			Queries = (Ledger::StorageUtil::GetThreadQueries() - Queries);
			double Time = Term->GetCapturedTime();
			double Tps = 1000.0 * (double)Block.TransactionsCount / Time;
			double Sps = 1000.0 * (double)Block.StatesCount / Time;
			double Qps = 1000.0 * (double)Queries / Time;
			Term->fWriteLine("block %s %.2f ms (number: %i, target: %s, txns: %i, states: %i, syncs: %i, tps: %.2f, sps: %.2f, qps: %.2f)",
				Algorithm::Encoding::Encode0xHex256(Block.AsHash()).c_str(), Time, (int)Block.Number, Block.Target.Difficulty().ToString().c_str(),
				(int)Block.TransactionsCount, (int)Block.StatesCount, (int)Queries,
				Tps, Sps, Qps);
		}

		Queue->Stop();
		Term->ReadChar();
		return 0;
	}
	/* Blockchain with 1536 + 1 blocks filled with highest possible entropy transactions (non-zero balance accounts, invalid chain - bad genesis block, performance measurement) */
	static int AbnormalEntropyThroughput(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		auto* Queue = Schedule::Get();
		Queue->Start(Schedule::Desc());

		auto Path = Params.Database.Location();
		Params.Database.Reset();
		OS::Directory::Remove(Path);

		if (argc > 1 && !strcmp(argv[1], "calibrate"))
		{
			auto Alg = Provability::WesolowskiVDF::Calibrate(4);
			Console::Get()->fWriteLine(
				"calibration alg:\n"
				"  length: %i\n"
				"  bits: %i\n"
				"  pow: %llu\n"
				"  difficulty: %s",
				Alg.Length, Alg.Bits, Alg.Pow,
				Alg.Difficulty().ToString().c_str());
			Provability::WesolowskiVDF::SetDefault(Alg);
		}

		const size_t BlockCount = 1536;
		auto Chain = Storages::Chainstate(__func__);
		size_t AccountsCount = (size_t)(uint64_t)(Ledger::Block::GetGasLimit() / Transactions::Transfer().GetGasEstimate());
		Vector<std::pair<Ledger::Wallet, uint64_t>> Accounts;
		Accounts.reserve(AccountsCount);
		for (size_t i = 0; i < AccountsCount; i++)
		{
			auto Account = Ledger::Wallet::FromSeed(Stringify::Text("00000%i", (int)i));
			Accounts.push_back(std::make_pair(std::move(Account), 1));
		}

		auto& Proposer = Accounts.front().first;
		auto Genesis = Ledger::Block();
		for (auto& Account : Accounts)
		{
			auto Balance = Memory::New<States::AccountBalance>(Account.first.PublicKeyHash, &Genesis);
			Balance->Asset = Algorithm::Asset::IdOf("BTC");
			Balance->Supply = 100;
			Genesis.States.MoveAny(Balance);
		}
		Genesis.Target = Provability::WesolowskiVDF::GetDefault();
		Genesis.States.Commit();
		Genesis.SetParentBlock(nullptr);
		Genesis.Recalculate(nullptr);
		VI_PANIC(Genesis.Solve(Proposer.SecretKey), "genesis block solve failed");
		VI_PANIC(Genesis.Sign(Proposer.SecretKey), "genesis block sign failed");
		Genesis.Checkpoint().Expect("genesis block checkpoint failed");

		uint8_t Hash[32];
		Algorithm::Encoding::DecodeUint256(Genesis.AsHash(), Hash);
		for (size_t i = 0; i < BlockCount; i++)
		{
			Vector<UPtr<Ledger::Transaction>> Transactions;
			Transactions.reserve(Protocol::Now().Policy.TransactionThroughput * Protocol::Now().Policy.ConsensusProofTime / 1000);
			uint256_t GasUse = 0, GasLimit = Ledger::Block::GetGasLimit();
			while (true)
			{
				auto* Transaction = Memory::New<Transactions::Transfer>();
				GasUse += Transaction->GetGasEstimate();
				if (GasUse > GasLimit)
					break;

				uint8_t PublicKeyHash[32];
				Algorithm::Hashing::Hash256(Hash, sizeof(Hash), PublicKeyHash);
				memcpy(Hash, PublicKeyHash, sizeof(PublicKeyHash));

				uint64_t Value;
				memcpy(&Value, PublicKeyHash + 20, sizeof(Value));
				Value = 1 + Value % 1500;

				uint64_t AccountIndex;
				memcpy(&AccountIndex, PublicKeyHash + 4, sizeof(AccountIndex));
				AccountIndex = Value % Accounts.size();

				auto& Account = Accounts[AccountIndex];
				Transaction->SetAsset("BTC");
				Transaction->SetEstimateGas(Decimal::Zero());
				Transaction->SetTo(PublicKeyHash, Decimal(Value).Truncate(12) / 100000000.0);
				VI_PANIC(Transaction->Sign(Account.first.SecretKey, Account.second++), "transfer not signed");
				Transactions.push_back(Transaction);
			}

			uint64_t Queries = Ledger::StorageUtil::GetThreadQueries();
			Term->CaptureTime();
			auto Block = Blocks::ProposeBlock(std::move(Transactions), Proposer, Proposer, true);
			Queries = (Ledger::StorageUtil::GetThreadQueries() - Queries);
			double Time = Term->GetCapturedTime();
			double Tps = 1000.0 * (double)Block.TransactionsCount / Time;
			double Sps = 1000.0 * (double)Block.StatesCount / Time;
			double Qps = 1000.0 * (double)Queries / Time;
			Term->fWriteLine("block %s %.2f ms (number: %i, target: %s, txns: %i, states: %i, syncs: %i, tps: %.2f, sps: %.2f, qps: %.2f)",
				Algorithm::Encoding::Encode0xHex256(Block.AsHash()).c_str(), Time, (int)Block.Number, Block.Target.Difficulty().ToString().c_str(),
				(int)Block.TransactionsCount, (int)Block.StatesCount, (int)Queries,
				Tps, Sps, Qps);
		}

		Queue->Stop();
		Term->ReadChar();
		return 0;
	}
	/* 256bit => decimal conversion */
	static int IntegerConversion(int argc, char* argv[])
	{
		Vitex::Runtime Scope;
		Protocol Params = Protocol(argc > 1 ? std::string_view(argv[1]) : TAN_CONFIG_PATH);

		auto* Term = Console::Get();
		Term->Show();

		size_t Samples = 10000; double Time = 0;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Number;
			Algorithm::Encoding::EncodeUint256((uint8_t*)Crypto::RandomBytes(32)->data(), Number);

			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 256bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Number = Math64u::Random(0, std::numeric_limits<uint64_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 64bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Number = Math32u::Random(0, std::numeric_limits<uint32_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 32bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		for (size_t i = 0; i < Samples; i++)
		{
			uint256_t Number = Math32u::Random(0, std::numeric_limits<uint16_t>::max());
			Term->CaptureTime();
			Decimal Test = Number.ToDecimal();
			Time += Term->GetCapturedTime();
		}

		Term->fWriteLine("uint256 to 16bit decimal conversion time: %.2f ms (cps: %.2f)", Time, 1000.0 * (double)Samples / Time); Time = 0;
		Term->ReadChar();
		return 0;
	}
};

class Apps
{
public:
	/* P2P, NDS and RPC node */
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

		UPtr<P2P::ServerNode> Consensus = new P2P::ServerNode();
		UPtr<NDS::ServerNode> Discovery = new NDS::ServerNode();
		UPtr<RPC::ServerNode> Interface = new RPC::ServerNode(*Consensus);

		ServiceControl Control;
		Control.Bind(Consensus->GetEntrypoint());
		Control.Bind(Discovery->GetEntrypoint());
		Control.Bind(Interface->GetEntrypoint());
		return Control.Launch();
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
				else if (State == "contribution")
				{
					if (Args.size() < 4)
						goto NotValid;

					Column = States::AccountContribution::AsInstanceColumn(Owner);
					Row = States::AccountContribution::AsInstanceRow(Algorithm::Asset::IdOfHandle(Args[3]));
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

		return 0;
	}
};

int main(int argc, char* argv[])
{
    return Apps::Consensus(argc, argv);
}
